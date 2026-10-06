//! Môi trường LiteSVM cho test program `scaas`: nạp `.so` của `cargo build-sbf`, gán upgrade authority, dựng
//! precompile Ed25519/Secp256r1 (mọi chỉ số instruction = u16::MAX), mint SPL / Token-2022, ký ed25519 và WebAuthn.
#![allow(dead_code)]
use anchor_lang::prelude::Pubkey;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use anchor_spl::token_2022::spl_token_2022 as t22;
use scaas::auth::{self as A, Auth};
use scaas::state::AuthKey;
use ed25519_dalek::{Signer as _, SigningKey};
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use litesvm::LiteSVM;
use solana_clock::Clock;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

#[path = "../vectors.rs"]
pub mod vectors;
pub mod flows;

pub const SO: &[u8] = include_bytes!("../../../../target/deploy/scaas.so");
pub const NOW: i64 = 500;
pub const ED25519: Pubkey = A::ED25519_PROGRAM;
pub const SECP256R1: Pubkey = A::SECP256R1_PROGRAM;
pub const TOKEN: Pubkey = anchor_spl::token::ID;
pub const TOKEN22: Pubkey = anchor_spl::token_2022::ID;
pub const ATA: Pubkey = anchor_spl::associated_token::ID;
pub const SYSTEM: Pubkey = anchor_lang::solana_program::system_program::ID;
pub const IXS: Pubkey = scaas::INSTRUCTIONS_ID;
pub const ORIGIN: &str = "https://pay.scaas.test";
pub const RP_ID: &str = "pay.scaas.test";

pub fn sha(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    parts.iter().for_each(|p| h.update(p));
    h.finalize().into()
}

pub fn pk(s: &str) -> Pubkey {
    s.parse().unwrap()
}

pub fn hexd(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

pub fn code(e: scaas::ScaasError) -> u32 {
    e as u32 + anchor_lang::error::ERROR_CODE_OFFSET
}

pub fn pda(seeds: &[&[u8]]) -> Pubkey {
    Pubkey::find_program_address(seeds, &scaas::ID).0
}

pub fn account_of(owner: &[u8; 32]) -> Pubkey {
    pda(&[b"acct", owner])
}

pub fn ata(owner: &Pubkey, mint: &Pubkey, tp: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[owner.as_ref(), tp.as_ref(), mint.as_ref()], &ATA).0
}

pub fn event_authority() -> Pubkey {
    pda(&[b"__event_authority"])
}

// ------------------------------------------------------------------ keys

/// Khoá ed25519 của chủ thể (seed = sha256(tên)).
pub struct Ed {
    pub sk: SigningKey,
}

impl Ed {
    pub fn new(name: &str) -> Self {
        Self { sk: SigningKey::from_bytes(&sha(&[name.as_bytes()])) }
    }
    pub fn pk(&self) -> [u8; 32] {
        self.sk.verifying_key().to_bytes()
    }
    pub fn pubkey(&self) -> Pubkey {
        Pubkey::new_from_array(self.pk())
    }
    pub fn key(&self) -> AuthKey {
        AuthKey::ed25519(self.pk())
    }
    pub fn kp(&self) -> Keypair {
        Keypair::new_from_array(self.sk.to_bytes())
    }
    pub fn account(&self) -> Pubkey {
        account_of(&self.pk())
    }
    pub fn raw(&self, msg: &[u8]) -> Vec<u8> {
        self.sk.sign(msg).to_bytes().to_vec()
    }
    /// (pk, sig, message) cho precompile — `kind 0` (raw) hoặc `kind 1` (OCMS).
    pub fn sign(&self, kind: u8, label: &str, digest: &[u8; 32]) -> Entry {
        let t = A::text(label, digest);
        let msg = if kind == A::KIND_RAW { t } else { A::ocms(&self.pk(), &t) };
        Entry { pk: self.pk().to_vec(), sig: self.sk.sign(&msg).to_bytes().to_vec(), msg }
    }
}

/// Passkey phần mềm P-256 (WebAuthn), rpId `pay.scaas.test`.
pub struct Passkey {
    pub sk: p256::ecdsa::SigningKey,
}

impl Passkey {
    pub fn new(name: &str) -> Self {
        Self { sk: p256::ecdsa::SigningKey::from_slice(&sha(&[name.as_bytes()])).unwrap() }
    }
    pub fn pk33(&self) -> [u8; 33] {
        let p = self.sk.verifying_key().to_encoded_point(true);
        p.as_bytes().try_into().unwrap()
    }
    pub fn rp_id_hash() -> [u8; 32] {
        sha(&[RP_ID.as_bytes()])
    }
    pub fn key(&self) -> AuthKey {
        AuthKey { scheme: scaas::state::SCHEME_P256, pubkey: self.pk33(), rp_id_hash: Self::rp_id_hash() }
    }
    pub fn owner(&self) -> [u8; 32] {
        scaas::p256_owner(&self.pk33())
    }
    pub fn account(&self) -> Pubkey {
        account_of(&self.owner())
    }
    /// Assertion trên `challenge`: (Entry cho precompile, clientDataJSON). `high_s` = để nguyên S cao (precompile chặn).
    pub fn assert(&self, challenge: &[u8; 32], origin: &str, flags: u8, high_s: bool) -> (Entry, Vec<u8>) {
        use p256::ecdsa::signature::Signer as _;
        let mut ad = Self::rp_id_hash().to_vec();
        ad.push(flags);
        ad.extend_from_slice(&7u32.to_be_bytes());
        let ch = String::from_utf8(A::b64url(challenge)).unwrap();
        let cdj = format!(r#"{{"type":"webauthn.get","challenge":"{ch}","origin":"{origin}","crossOrigin":false}}"#).into_bytes();
        let mut msg = ad.clone();
        msg.extend_from_slice(&sha(&[&cdj]));
        let sig: p256::ecdsa::Signature = self.sk.sign(&msg);
        let sig = sig.normalize_s().unwrap_or(sig);
        let mut bytes = sig.to_bytes().to_vec();
        if high_s {
            // s' = n - s: cùng chữ ký về toán học, nhưng precompile ép low-S.
            let n = hexd("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
            let mut s = [0u8; 32];
            let mut borrow = 0i16;
            for i in (0..32).rev() {
                let d = n[i] as i16 - bytes[32 + i] as i16 - borrow;
                s[i] = d.rem_euclid(256) as u8;
                borrow = (d < 0) as i16;
            }
            bytes[32..].copy_from_slice(&s);
        }
        (Entry { pk: self.pk33().to_vec(), sig: bytes, msg }, cdj)
    }
}

/// Một chữ ký trong instruction precompile.
#[derive(Clone)]
pub struct Entry {
    pub pk: Vec<u8>,
    pub sig: Vec<u8>,
    pub msg: Vec<u8>,
}

/// Instruction precompile: `num, pad, offsets×n`, rồi `pk ‖ sig ‖ msg` mỗi chữ ký; mọi chỉ số instruction = `index`
/// (u16::MAX = chính nó).
pub fn precompile_ix(program: Pubkey, entries: &[Entry], index: u16) -> Instruction {
    let mut head = vec![entries.len() as u8, 0];
    let mut body = Vec::new();
    let base = 2 + 14 * entries.len();
    for e in entries {
        let pk_off = base + body.len();
        body.extend_from_slice(&e.pk);
        let sig_off = base + body.len();
        body.extend_from_slice(&e.sig);
        let msg_off = base + body.len();
        body.extend_from_slice(&e.msg);
        for v in [sig_off as u16, index, pk_off as u16, index, msg_off as u16, e.msg.len() as u16, index] {
            head.extend_from_slice(&v.to_le_bytes());
        }
    }
    head.extend_from_slice(&body);
    Instruction { program_id: program, accounts: vec![], data: head }
}

pub fn ed_ix(entries: &[Entry]) -> Instruction {
    precompile_ix(ED25519, entries, u16::MAX)
}

pub fn r1_ix(entries: &[Entry]) -> Instruction {
    precompile_ix(SECP256R1, entries, u16::MAX)
}

pub fn auth(kind: u8, key_index: u8, precompile_ix: u8, sig_index: u8) -> Auth {
    Auth { kind, key_index, precompile_ix, sig_index, cdj: vec![] }
}

// ------------------------------------------------------------------ env

pub struct Env {
    pub svm: LiteSVM,
    pub admin: Keypair,
    pub lane: Keypair,
    pub network: [u8; 32],
}

pub type Res = Result<TransactionMetadata, FailedTransactionMetadata>;

impl Env {
    pub fn new() -> Self {
        let mut svm = LiteSVM::new();
        svm.add_program(scaas::ID, SO).unwrap();
        let admin = Keypair::new();
        let lane = Ed::new("lane0").kp();
        svm.airdrop(&admin.pubkey(), 100_000_000_000).unwrap();
        svm.airdrop(&lane.pubkey(), 100_000_000_000).unwrap();
        let network = pk(vectors::NETWORK).to_bytes();
        let mut env = Self { svm, admin, lane, network };
        env.set_upgrade_authority(&env.admin.pubkey());
        env.set_time(NOW);
        let a = env.admin.insecure_clone();
        env.send(&[env.initialize_ix(&a.pubkey())], &[&a]).unwrap();
        env
    }

    pub fn programdata() -> Pubkey {
        Pubkey::find_program_address(&[scaas::ID.as_ref()], &anchor_lang::solana_program::bpf_loader_upgradeable::ID).0
    }

    /// LiteSVM nạp program với upgrade authority = None; ghi lại metadata ProgramData (bincode: tag 3, slot, Option).
    pub fn set_upgrade_authority(&mut self, who: &Pubkey) {
        let addr = Self::programdata();
        let mut acc = self.svm.get_account(&addr).unwrap();
        acc.data[12] = 1;
        acc.data[13..45].copy_from_slice(who.as_ref());
        self.svm.set_account(addr, acc).unwrap();
    }

    pub fn initialize_ix(&self, authority: &Pubkey) -> Instruction {
        Instruction {
            program_id: scaas::ID,
            accounts: scaas::accounts::Initialize {
                authority: *authority,
                config: self.config(),
                program: scaas::ID,
                program_data: Self::programdata(),
                system_program: SYSTEM,
            }
            .to_account_metas(None),
            data: scaas::instruction::Initialize { network: self.network, admin: self.admin.pubkey() }.data(),
        }
    }

    pub fn config(&self) -> Pubkey {
        pda(&[b"config"])
    }

    pub fn set_time(&mut self, t: i64) {
        let mut c: Clock = self.svm.get_sysvar();
        c.unix_timestamp = t;
        self.svm.set_sysvar(&c);
    }

    /// Lane (fee payer) + `extra` ký; blockhash mới mỗi lần (cùng ix gửi lại không bị coi là trùng chữ ký).
    pub fn send(&mut self, ixs: &[Instruction], extra: &[&Keypair]) -> Res {
        self.send_as(&self.lane.insecure_clone(), ixs, extra)
    }

    pub fn send_as(&mut self, payer: &Keypair, ixs: &[Instruction], extra: &[&Keypair]) -> Res {
        self.svm.expire_blockhash();
        let mut signers: Vec<&Keypair> = vec![payer];
        signers.extend_from_slice(extra);
        let msg = Message::new(ixs, Some(&payer.pubkey()));
        let tx = Transaction::new(&signers, msg, self.svm.latest_blockhash());
        self.svm.send_transaction(tx)
    }

    pub fn account<T: AccountDeserialize>(&self, addr: &Pubkey) -> Option<T> {
        let a = self.svm.get_account(addr)?;
        if a.data.is_empty() {
            return None;
        }
        T::try_deserialize(&mut &a.data[..]).ok()
    }

    pub fn exists(&self, addr: &Pubkey) -> bool {
        self.svm.get_account(addr).is_some_and(|a| a.lamports > 0)
    }

    pub fn lamports(&self, addr: &Pubkey) -> u64 {
        self.svm.get_balance(addr).unwrap_or(0)
    }

    // -------------------------------------------------------------- tokens

    pub fn create_mint(&mut self, kp: &Keypair, tp: Pubkey, decimals: u8, ext: &[Instruction], ext_types: &[t22::extension::ExtensionType]) {
        let space = if tp == TOKEN { 82 } else { t22::extension::ExtensionType::try_calculate_account_len::<t22::state::Mint>(ext_types).unwrap() };
        let rent = self.svm.minimum_balance_for_rent_exemption(space);
        let admin = self.admin.pubkey();
        let mut ixs = vec![solana_system_interface::instruction::create_account(&admin, &kp.pubkey(), rent, space as u64, &tp)];
        ixs.extend_from_slice(ext);
        ixs.push(t22::instruction::initialize_mint2(&tp, &kp.pubkey(), &admin, None, decimals).unwrap());
        let a = self.admin.insecure_clone();
        self.send_as(&a, &ixs, &[kp]).unwrap();
    }

    pub fn mint(&mut self, tp: Pubkey, decimals: u8) -> Pubkey {
        let kp = Keypair::new();
        self.create_mint(&kp, tp, decimals, &[], &[]);
        kp.pubkey()
    }

    /// ATA của `owner` (tạo nếu chưa có) + mint `amount` vào đó.
    pub fn fund(&mut self, owner: &Pubkey, mint: &Pubkey, tp: Pubkey, amount: u64) -> Pubkey {
        let a = ata(owner, mint, &tp);
        let admin = self.admin.insecure_clone();
        let mut ixs = vec![anchor_spl::associated_token::spl_associated_token_account::instruction::create_associated_token_account_idempotent(
            &admin.pubkey(), owner, mint, &tp,
        )];
        if amount > 0 {
            ixs.push(t22::instruction::mint_to(&tp, mint, &a, &admin.pubkey(), &[], amount).unwrap());
        }
        self.send_as(&admin, &ixs, &[]).unwrap();
        a
    }

    /// Token account KHÔNG phải ATA, owner = `owner` (L7).
    pub fn side_account(&mut self, owner: &Pubkey, mint: &Pubkey, tp: Pubkey, amount: u64) -> Pubkey {
        let kp = Keypair::new();
        let space = if tp == TOKEN { 165 } else { 170 };
        let rent = self.svm.minimum_balance_for_rent_exemption(space);
        let admin = self.admin.insecure_clone();
        let ixs = vec![
            solana_system_interface::instruction::create_account(&admin.pubkey(), &kp.pubkey(), rent, space as u64, &tp),
            t22::instruction::initialize_account3(&tp, &kp.pubkey(), mint, owner).unwrap(),
            t22::instruction::mint_to(&tp, mint, &kp.pubkey(), &admin.pubkey(), &[], amount).unwrap(),
        ];
        self.send_as(&admin, &ixs, &[&kp]).unwrap();
        kp.pubkey()
    }

    pub fn balance(&self, token_account: &Pubkey) -> u64 {
        let Some(a) = self.svm.get_account(token_account) else { return 0 };
        if a.data.is_empty() {
            return 0;
        }
        use t22::extension::StateWithExtensions;
        StateWithExtensions::<t22::state::Account>::unpack(&a.data).map(|s| s.base.amount).unwrap_or(0)
    }

    // -------------------------------------------------------------- scaas ixs

    pub fn open_ix(&self, owner: &Pubkey) -> Instruction {
        Instruction {
            program_id: scaas::ID,
            accounts: scaas::accounts::Open { payer: self.lane.pubkey(), owner: *owner, subject: account_of(&owner.to_bytes()), system_program: SYSTEM }
                .to_account_metas(None),
            data: scaas::instruction::Open {}.data(),
        }
    }

    /// `relay_pay` (Account readonly nếu đã mở — RS12-2; writable chỉ khi mở lười).
    pub fn pay_ix(&self, owner: &[u8; 32], mint: &Pubkey, tp: Pubkey, source: Pubkey, args: &scaas::PayArgs, auth: Auth) -> Instruction {
        let subject = account_of(owner);
        let to = Pubkey::new_from_array(args.to);
        let mut metas = scaas::accounts::RelayPay {
            lane: self.lane.pubkey(),
            config: self.config(),
            subject,
            lane_pda: pda(&[b"lane", subject.as_ref(), &args.lane]),
            source,
            recipient: to,
            destination: ata(&to, mint, &tp),
            mint: *mint,
            token_program: tp,
            associated_token_program: ATA,
            system_program: SYSTEM,
            instructions: IXS,
            event_authority: event_authority(),
            program: scaas::ID,
        }
        .to_account_metas(None);
        if !self.exists(&subject) {
            metas[2].is_writable = true;
        }
        Instruction {
            program_id: scaas::ID,
            accounts: metas,
            data: scaas::instruction::RelayPay { owner: *owner, args: args.clone(), auth }.data(),
        }
    }

    pub fn args(&self, to: &Pubkey, amount: u64, pay_ref: u8, lane: u8, nonce: u64, valid_until: u64) -> scaas::PayArgs {
        scaas::PayArgs {
            to: to.to_bytes(),
            amount,
            pay_ref: [pay_ref; 32],
            lane: [lane; 32],
            nonce,
            valid_until,
            relayer: [0; 32],
            extra: [0; 32],
        }
    }

    pub fn metaop_digest(&self, contract: &Pubkey, asset: &Pubkey, op: u8, from: &[u8; 32], a: &scaas::PayArgs) -> [u8; 32] {
        a.metaop(self.network, *contract, *asset, op, *from).digest()
    }

    /// Ký + gửi một `relay_pay` của ví ed25519 `who` (khoá 0, kind 0).
    pub fn pay(&mut self, who: &Ed, mint: &Pubkey, tp: Pubkey, args: &scaas::PayArgs) -> Res {
        let source = ata(&who.account(), mint, &tp);
        let dg = self.metaop_digest(&who.account(), mint, A::OP_PAY, &who.pk(), args);
        let e = who.sign(A::KIND_RAW, A::METAOP_LABEL, &dg);
        let ix = self.pay_ix(&who.pk(), mint, tp, source, args, auth(A::KIND_RAW, 0, 0, 0));
        self.send(&[ed_ix(&[e]), ix], &[])
    }

    pub fn subject(&self, addr: &Pubkey) -> scaas::state::SubjectAccount {
        self.account(addr).expect("subject account")
    }

    pub fn manage_ix(&self, subject: &Pubkey, op: &scaas::KeyOp, auth: Auth, to: Option<Pubkey>) -> Instruction {
        Instruction {
            program_id: scaas::ID,
            accounts: scaas::accounts::ManageSigned {
                lane: self.lane.pubkey(),
                config: self.config(),
                subject: *subject,
                to,
                instructions: IXS,
                system_program: SYSTEM,
            }
            .to_account_metas(None),
            data: scaas::instruction::ManageSigned { op: op.clone(), auth }.data(),
        }
    }

    pub fn keyop_digest(&self, subject: &Pubkey, op: &scaas::KeyOp) -> [u8; 32] {
        sha(&[&op.bytes(&self.network, subject)])
    }

    /// KeyOp ký bởi khoá ed25519 `signer` (chỉ số `key_index` trong Account).
    pub fn manage(&mut self, subject: &Pubkey, signer: &Ed, key_index: u8, op: scaas::KeyOp, to: Option<Pubkey>) -> Res {
        let e = signer.sign(A::KIND_RAW, A::KEYOP_LABEL, &self.keyop_digest(subject, &op));
        let ix = self.manage_ix(subject, &op, auth(A::KIND_RAW, key_index, 0, 0), to);
        self.send(&[ed_ix(&[e]), ix], &[])
    }

    pub fn keyop(&self, subject: &Pubkey, action: u8) -> scaas::KeyOp {
        let nonce = self.subject(subject).key_nonce;
        scaas::KeyOp {
            action,
            key: AuthKey::ed25519([0; 32]),
            origin: String::new(),
            guardian: [0; 32],
            policy: 0,
            to: [0; 32],
            nonce,
            valid_until: 1000,
        }
    }
}

pub fn custom(res: &Res) -> Option<u32> {
    use solana_transaction::{InstructionError, TransactionError};
    let Err(f) = res else { return None };
    match &f.err {
        TransactionError::InstructionError(_, InstructionError::Custom(c)) => Some(*c),
        _ => None,
    }
}

/// Lỗi Anchor của program `scaas` (instruction bất kỳ).
#[track_caller]
pub fn expect_err(res: Res, e: scaas::ScaasError) {
    let want = code(e);
    match custom(&res) {
        Some(c) if c == want => {}
        _ => panic!("expected {want} ({:?}), got {:?}", want, res.map(|m| m.logs).map_err(|f| (f.err, f.meta.logs))),
    }
}

#[track_caller]
pub fn ok(res: Res) -> TransactionMetadata {
    match res {
        Ok(m) => m,
        Err(f) => panic!("tx failed: {:?}\n{}", f.err, f.meta.logs.join("\n")),
    }
}

pub fn meta(addr: Pubkey, writable: bool) -> AccountMeta {
    if writable { AccountMeta::new(addr, false) } else { AccountMeta::new_readonly(addr, false) }
}
