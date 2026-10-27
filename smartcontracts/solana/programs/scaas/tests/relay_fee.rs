//! CTR-MTX-27 `relay_fee`: the call first (CPI to the target), then the payment bound to it (`ref` commits to the
//! chain, the target program, its accounts with their flags, its data and the payer-signed salt `args.extra`); the
//! router marker PDA `[b"relayfee"]` as the payment's relayer; open mode pays the lane signer; any failure reverts both.
mod common;

use anchor_lang::prelude::Pubkey;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use scaas::auth::{self as A};
use scaas::ScaasError as E;
use common::vectors as V;
use common::*;
use solana_signer::Signer;

const TOKEN_FUNDS: u64 = 1_000;

struct T {
    env: Env,
    alice: Ed,
    usd: Pubkey,
    target: Pubkey,
    record: Pubkey,
}

fn key(hex: &str) -> Pubkey {
    Pubkey::new_from_array(hexd(hex).try_into().unwrap())
}

fn marker() -> Pubkey {
    pda(&[b"relayfee"])
}

fn setup() -> T {
    let mut env = Env::new();
    let usd = env.mint(TOKEN, 6);
    let alice = Ed::new("alice");
    env.fund(&alice.account(), &usd, TOKEN, TOKEN_FUNDS);
    let (target, record) = (key(V::RELAY_TARGET), key(V::RELAY_RECORD));
    env.svm.add_program(target, RELAY_TARGET_SO).unwrap();
    let rent = env.svm.minimum_balance_for_rent_exemption(64);
    let acc = solana_account::Account { lamports: rent, data: vec![0; 64], owner: target, executable: false, rent_epoch: 0 };
    env.svm.set_account(record, acc).unwrap();
    T { env, alice, usd, target, record }
}

fn rec_metas(t: &T) -> Vec<AccountMeta> {
    vec![AccountMeta::new(t.record, false)]
}

/// The payment for `(target, metas, data)` under `salt`: `pay_ref = ref`, `lane = payLane(ref)`, nonce 0, relayer =
/// the marker, `extra = salt`.
fn fee_args(env: &Env, to: Pubkey, amount: u64, target: &Pubkey, metas: &[AccountMeta], data: &[u8], salt: [u8; 32]) -> scaas::PayArgs {
    let r = scaas::relay_ref(&env.network, target, &scaas::relay_call(target, metas, data), &salt);
    scaas::PayArgs { to: to.to_bytes(), amount, pay_ref: r, lane: scaas::pay_lane(&r), nonce: 0, valid_until: 1000, relayer: marker().to_bytes(), extra: salt }
}

/// Signs `args` as `who` and sends `[ed25519 precompile, relay_fee]`.
fn relay(env: &mut Env, who: &Ed, usd: &Pubkey, args: &scaas::PayArgs, recipient: Pubkey, target: Pubkey, metas: &[AccountMeta], data: &[u8]) -> Res {
    let ix = relay_ix(env, who, usd, args, recipient, target, metas, data);
    let dg = env.metaop_digest(&who.account(), usd, A::OP_PAY, &who.pk(), args);
    env.send(&[ed_ix(&[who.sign(A::KIND_RAW, A::METAOP_LABEL, &dg)]), ix], &[])
}

#[allow(clippy::too_many_arguments)]
fn relay_ix(env: &Env, who: &Ed, usd: &Pubkey, args: &scaas::PayArgs, recipient: Pubkey, target: Pubkey, metas: &[AccountMeta], data: &[u8]) -> Instruction {
    let src = ata(&who.account(), usd, &TOKEN);
    env.relay_fee_ix(&who.pk(), usd, TOKEN, src, args, recipient, target, metas, data, auth(A::KIND_RAW, 0, 0, 0))
}

fn record(t: &T) -> Vec<u8> {
    t.env.svm.get_account(&t.record).unwrap().data[..8].to_vec()
}

fn events(m: &litesvm::types::TransactionMetadata) -> Vec<Vec<u8>> {
    m.inner_instructions.iter().flatten().map(|i| i.instruction.data.clone())
        .filter(|d| d.starts_with(&anchor_lang::event::EVENT_IX_TAG_LE)).collect()
}

/// `RelayFeePaid { contract: mint, relay_ref, target, payer, payee, amount }` (Borsh), payer / payee the 32-byte keys.
fn fee_paid(mint: &Pubkey, r: &[u8; 32], target: &Pubkey, payer: &Pubkey, payee: &Pubkey, amount: u64) -> Vec<u8> {
    let mut d = anchor_lang::event::EVENT_IX_TAG_LE.to_vec();
    d.extend_from_slice(<scaas::RelayFeePaid as anchor_lang::Discriminator>::DISCRIMINATOR);
    for k in [mint.as_ref(), r.as_ref(), target.as_ref(), payer.as_ref(), payee.as_ref()] {
        d.extend_from_slice(k);
    }
    d.extend_from_slice(&amount.to_le_bytes());
    d
}

#[test]
fn relay_ref_vectors() {
    let (target, record) = (key(V::RELAY_TARGET), key(V::RELAY_RECORD));
    let metas = [AccountMeta::new(record, false)];
    let call = scaas::relay_call(&target, &metas, &hexd(V::RELAY_DATA));
    assert_eq!(call, hexd(V::RELAY_CALL));
    let network = pk(V::NETWORK).to_bytes();
    let salt: [u8; 32] = hexd(V::RELAY_SALT).try_into().unwrap();
    let r = scaas::relay_ref(&network, &target, &call, &salt);
    assert_eq!(r.to_vec(), hexd(V::RELAY_REF));
    assert_eq!(scaas::pay_lane(&r).to_vec(), hexd(V::RELAY_LANE));
    // every part of the preimage counts: salt, flags, account count, chain
    assert_ne!(scaas::relay_ref(&network, &target, &call, &[8; 32]), r);
    assert_ne!(scaas::relay_call(&target, &[AccountMeta::new_readonly(record, false)], &hexd(V::RELAY_DATA)), call);
    assert_ne!(scaas::relay_call(&target, &[], &[&record.to_bytes()[..], &[0, 1], &hexd(V::RELAY_DATA)].concat()), call);
    assert_ne!(scaas::relay_ref(&[7; 32], &target, &call, &salt), r);
    // the marker (pinned in the scaas-node adapter test too)
    assert_eq!(scaas::relay_fee_marker(), marker());
    assert_eq!(marker().to_string(), "9wtnhXbQazahGQXbNLD5ZAERPfzmvFvC2mYwCRjPvT5t");
}

/// Open mode (`args.to == marker`): the lane signer's ATA is paid; the target ran; a second relay of the same `ref`
/// is refused (pay lane), and the marker never holds tokens.
#[test]
fn relay_fee_open_mode_pays_lane() {
    let mut t = setup();
    let lane = t.env.lane.pubkey();
    let metas = rec_metas(&t);
    let data = b"\x01open".to_vec();
    let args = fee_args(&t.env, marker(), 25, &t.target, &metas, &data, [3; 32]);
    // the recipient in open mode is the lane, never `args.to`
    expect_err(relay(&mut t.env, &t.alice, &t.usd, &args, marker(), t.target, &metas, &data), E::WrongRecipient);
    let m = ok(relay(&mut t.env, &t.alice, &t.usd, &args, lane, t.target, &metas, &data));
    eprintln!("relay_fee open mode (lazy Account open, lane ATA created): {} CU", m.compute_units_consumed);
    assert!(m.compute_units_consumed < 200_000);
    assert_eq!(&record(&t)[..5], &data[..]);
    assert_eq!(t.env.balance(&ata(&lane, &t.usd, &TOKEN)), 25);
    assert_eq!(t.env.balance(&ata(&t.alice.account(), &t.usd, &TOKEN)), TOKEN_FUNDS - 25);
    assert!(!t.env.exists(&ata(&marker(), &t.usd, &TOKEN)));
    let ev = events(&m);
    assert_eq!(ev.len(), 3);
    assert_eq!(&ev[0][8..16], <scaas::MetaTransactionExecuted as anchor_lang::Discriminator>::DISCRIMINATOR);
    assert_eq!(&ev[1][8..16], <scaas::PaymentSettled as anchor_lang::Discriminator>::DISCRIMINATOR);
    assert_eq!(ev[2], fee_paid(&t.usd, &args.pay_ref, &t.target, &t.alice.pubkey(), &lane, 25));
    expect_err(relay(&mut t.env, &t.alice, &t.usd, &args, lane, t.target, &metas, &data), E::BadNonce);
    let again = fee_args(&t.env, marker(), 5, &t.target, &metas, &data, [4; 32]);
    let m = ok(relay(&mut t.env, &t.alice, &t.usd, &again, lane, t.target, &metas, &data));
    eprintln!("relay_fee open mode (warm): {} CU", m.compute_units_consumed);
    assert_eq!(t.env.balance(&ata(&lane, &t.usd, &TOKEN)), 30, "same call, another salt: a new intent");
}

/// Bound payee: `args.to` is paid directly; the lane as recipient is refused.
#[test]
fn relay_fee_bound_payee() {
    let mut t = setup();
    let bob = Ed::new("bob").pubkey();
    let metas = rec_metas(&t);
    let data = b"\x02bound".to_vec();
    let args = fee_args(&t.env, bob, 9, &t.target, &metas, &data, [5; 32]);
    let lane = t.env.lane.pubkey();
    expect_err(relay(&mut t.env, &t.alice, &t.usd, &args, lane, t.target, &metas, &data), E::WrongRecipient);
    let m = ok(relay(&mut t.env, &t.alice, &t.usd, &args, bob, t.target, &metas, &data));
    assert_eq!(t.env.balance(&ata(&bob, &t.usd, &TOKEN)), 9);
    assert!(!t.env.exists(&ata(&lane, &t.usd, &TOKEN)));
    assert_eq!(*events(&m).last().unwrap(), fee_paid(&t.usd, &args.pay_ref, &t.target, &t.alice.pubkey(), &bob, 9));
}

/// Rule 9: the call runs first, then the payment; a target failure leaves no payment, and a payment failure (over
/// the balance, a bad signature) rolls the call back.
#[test]
fn relay_fee_target_failure_reverts() {
    let mut t = setup();
    let lane = t.env.lane.pubkey();
    let metas = rec_metas(&t);
    let src = ata(&t.alice.account(), &t.usd, &TOKEN);
    let fail = b"\xffboom".to_vec();
    let args = fee_args(&t.env, marker(), 25, &t.target, &metas, &fail, [6; 32]);
    let res = relay(&mut t.env, &t.alice, &t.usd, &args, lane, t.target, &metas, &fail);
    assert_eq!(custom(&res), Some(7), "the target's own error");
    assert_eq!((t.env.balance(&src), t.env.exists(&pda(&[b"lane", t.alice.account().as_ref(), &args.lane]))), (TOKEN_FUNDS, false));
    // the payment fails after the call ran: the call is rolled back
    let data = b"\x03undo".to_vec();
    let too_much = fee_args(&t.env, marker(), TOKEN_FUNDS + 1, &t.target, &metas, &data, [6; 32]);
    assert!(relay(&mut t.env, &t.alice, &t.usd, &too_much, lane, t.target, &metas, &data).is_err());
    assert_eq!(record(&t), vec![0; 8]);
    let args = fee_args(&t.env, marker(), 25, &t.target, &metas, &data, [6; 32]);
    let ix = relay_ix(&t.env, &t.alice, &t.usd, &args, lane, t.target, &metas, &data);
    let dg = t.env.metaop_digest(&t.alice.account(), &t.usd, A::OP_PAY, &t.alice.pk(), &args);
    let stranger = Ed::new("stranger").sign(A::KIND_RAW, A::METAOP_LABEL, &dg);
    expect_err(t.env.send(&[ed_ix(&[stranger]), ix], &[]), E::BadSignature);
    assert_eq!((record(&t), t.env.balance(&src)), (vec![0; 8], TOKEN_FUNDS));
    ok(relay(&mut t.env, &t.alice, &t.usd, &args, lane, t.target, &metas, &data));
    assert_eq!(&record(&t)[..5], &data[..]);
}

/// `scaas` as its own target (the runtime allows direct self-recursion) is refused: `RelayFeeShape`.
#[test]
fn relay_fee_self_target_refused() {
    let mut t = setup();
    let lane = t.env.lane.pubkey();
    let metas = vec![AccountMeta::new(t.alice.account(), false)];
    let data = scaas_data("finish_recovery");
    let args = fee_args(&t.env, marker(), 1, &scaas::ID, &metas, &data, [7; 32]);
    expect_err(relay(&mut t.env, &t.alice, &t.usd, &args, lane, scaas::ID, &metas, &data), E::RelayFeeShape);
}

fn scaas_data(name: &str) -> Vec<u8> {
    sha(&[format!("global:{name}").as_bytes()])[..8].to_vec()
}

/// scaas → `cpi_wrapper` → scaas: the runtime refuses the indirect re-entry, so no target call can run another
/// scaas instruction (e.g. a pay of another router-bound payment); nothing moves.
#[test]
fn relay_fee_indirect_reentry_refused() {
    let mut t = setup();
    let wrapper = Pubkey::new_unique();
    t.env.svm.add_program(wrapper, CPI_WRAPPER_SO).unwrap();
    let lane = t.env.lane.pubkey();
    let metas = vec![AccountMeta::new_readonly(scaas::ID, false), AccountMeta::new(t.alice.account(), false)];
    let data = scaas_data("finish_recovery");
    let args = fee_args(&t.env, marker(), 1, &wrapper, &metas, &data, [8; 32]);
    let res = relay(&mut t.env, &t.alice, &t.usd, &args, lane, wrapper, &metas, &data);
    use solana_transaction::{InstructionError, TransactionError};
    match &res {
        Err(f) => assert_eq!(f.err, TransactionError::InstructionError(1, InstructionError::ReentrancyNotAllowed), "{:?}", f.meta.logs),
        Ok(_) => panic!("re-entry ran"),
    }
    assert_eq!(t.env.balance(&ata(&t.alice.account(), &t.usd, &TOKEN)), TOKEN_FUNDS);
}

/// Rule 2: the target must be an executable program at relay time (a data account, an address with nothing, a
/// wallet) —
/// refused before any token moves.
#[test]
fn relay_fee_target_must_be_executable() {
    let mut t = setup();
    let lane = t.env.lane.pubkey();
    let data = b"\x04x".to_vec();
    for target in [t.record, Pubkey::new_unique(), lane] {
        let args = fee_args(&t.env, marker(), 1, &target, &[], &data, [9; 32]);
        expect_err(relay(&mut t.env, &t.alice, &t.usd, &args, lane, target, &[], &data), E::RelayTargetNoCode);
    }
    assert_eq!(t.env.balance(&ata(&t.alice.account(), &t.usd, &TOKEN)), TOKEN_FUNDS);
}

/// Shape: the payment must commit to exactly this call (`ref`), on `payLane(ref)`, nonce 0, relayer = the marker,
/// with exactly `target_accounts` accounts after the target.
#[test]
fn relay_fee_shape_refused() {
    let mut t = setup();
    let lane = t.env.lane.pubkey();
    let metas = rec_metas(&t);
    let data = b"\x05shape".to_vec();
    let good = fee_args(&t.env, marker(), 2, &t.target, &metas, &data, [1; 32]);
    let mut cases = Vec::new();
    let mut a = good.clone();
    a.extra = [2; 32]; // another salt: another ref
    cases.push(a);
    let mut a = good.clone();
    a.lane = [0xa1; 32];
    cases.push(a);
    let mut a = good.clone();
    a.nonce = 1;
    cases.push(a);
    for relayer in [[0; 32], lane.to_bytes()] {
        let mut a = good.clone();
        a.relayer = relayer;
        cases.push(a);
    }
    for a in cases {
        expect_err(relay(&mut t.env, &t.alice, &t.usd, &a, lane, t.target, &metas, &data), E::RelayFeeShape);
    }
    // other data / other account flags than signed
    expect_err(relay(&mut t.env, &t.alice, &t.usd, &good, lane, t.target, &metas, b"\x05shapE"), E::RelayFeeShape);
    expect_err(relay(&mut t.env, &t.alice, &t.usd, &good, lane, t.target, &[AccountMeta::new_readonly(t.record, false)], &data), E::RelayFeeShape);
    // an extra remaining account / a wrong count
    let mut ix = relay_ix(&t.env, &t.alice, &t.usd, &good, lane, t.target, &metas, &data);
    ix.accounts.push(AccountMeta::new_readonly(t.alice.pubkey(), false));
    let dg = t.env.metaop_digest(&t.alice.account(), &t.usd, A::OP_PAY, &t.alice.pk(), &good);
    let e = t.alice.sign(A::KIND_RAW, A::METAOP_LABEL, &dg);
    expect_err(t.env.send(&[ed_ix(std::slice::from_ref(&e)), ix], &[]), E::RelayFeeShape);
    let mut ix = relay_ix(&t.env, &t.alice, &t.usd, &good, lane, t.target, &metas, &data);
    let n = ix.data.len();
    ix.data[n - 9] = 0; // target_accounts (before the 8 Auth bytes: kind, key, ix, sig, u32 cdj len)
    expect_err(t.env.send(&[ed_ix(&[e]), ix], &[]), E::RelayFeeShape);
    ok(relay(&mut t.env, &t.alice, &t.usd, &good, lane, t.target, &metas, &data));
}

/// Review focus 3: a payment bound to the router (relayer = marker) never settles through `relay_pay` or
/// `relay_pay_meta` (a PDA never signs: `relayer == lane` fails), only through `relay_fee`.
#[test]
fn solana_router_bound_pay_refused_direct() {
    let mut t = setup();
    let bob = Ed::new("bob").pubkey();
    let metas = rec_metas(&t);
    let data = b"\x06bound".to_vec();
    let args = fee_args(&t.env, bob, 4, &t.target, &metas, &data, [1; 32]);
    expect_err(t.env.pay(&t.alice, &t.usd, TOKEN, &args), E::WrongRelayer);
    let mut meta_args = args.clone();
    let meta = b"note".to_vec();
    meta_args.pay_ref = scaas::meta_pay_id(&[1; 32], &meta);
    meta_args.lane = scaas::pay_lane(&meta_args.pay_ref);
    expect_err(t.env.pay_meta(&t.alice, &t.usd, TOKEN, &meta_args, [1; 32], &meta), E::WrongRelayer);
    assert_eq!(t.env.balance(&ata(&bob, &t.usd, &TOKEN)), 0);
    ok(relay(&mut t.env, &t.alice, &t.usd, &args, bob, t.target, &metas, &data));
    assert_eq!(t.env.balance(&ata(&bob, &t.usd, &TOKEN)), 4);
}

/// Rule 6: the pay lane is the payer's (keyed by its Account), so someone paying for the same call and salt (the same
/// `ref`) never blocks the payer.
#[test]
fn relay_fee_ref_is_per_payer() {
    let mut t = setup();
    let lane = t.env.lane.pubkey();
    let mallory = Ed::new("mallory");
    t.env.fund(&mallory.account(), &t.usd, TOKEN, 10);
    let metas = rec_metas(&t);
    let data = b"\x07mine".to_vec();
    let theirs = fee_args(&t.env, marker(), 1, &t.target, &metas, &data, [1; 32]);
    ok(relay(&mut t.env, &mallory, &t.usd, &theirs, lane, t.target, &metas, &data));
    let mine = fee_args(&t.env, marker(), 20, &t.target, &metas, &data, [1; 32]);
    assert_eq!(mine.pay_ref, theirs.pay_ref);
    ok(relay(&mut t.env, &t.alice, &t.usd, &mine, lane, t.target, &metas, &data));
    assert_eq!(t.env.balance(&ata(&lane, &t.usd, &TOKEN)), 21);
}

/// Rule 7: the relayer is a signer of the transaction (`lane: Signer`); the same instruction with the lane unsigned
/// (another fee payer) is refused.
#[test]
fn relay_fee_relayer_must_sign() {
    let mut t = setup();
    let lane = t.env.lane.pubkey();
    let metas = rec_metas(&t);
    let data = b"\x08sign".to_vec();
    let args = fee_args(&t.env, marker(), 1, &t.target, &metas, &data, [1; 32]);
    let mut ix = relay_ix(&t.env, &t.alice, &t.usd, &args, lane, t.target, &metas, &data);
    ix.accounts[0].is_signer = false;
    let dg = t.env.metaop_digest(&t.alice.account(), &t.usd, A::OP_PAY, &t.alice.pk(), &args);
    let e = t.alice.sign(A::KIND_RAW, A::METAOP_LABEL, &dg);
    let payer = t.env.admin.insecure_clone();
    let res = t.env.send_as(&payer, &[ed_ix(&[e]), ix], &[]);
    assert_eq!(custom(&res), Some(anchor_lang::error::ErrorCode::AccountNotSigner as u32));
    assert_eq!(t.env.balance(&ata(&t.alice.account(), &t.usd, &TOKEN)), TOKEN_FUNDS);
}

/// The node builds these instructions by hand (`scaas-node/src/adapters/solana.rs`): the same inputs give the same
/// Anchor Borsh bytes (sha256 pinned on both sides). Alice → Bob 100, `relay_pay_meta` under `paymeta.json` row 0;
/// `relay_fee` for the vector call in open mode. Auth: raw ed25519, key 0, precompile instruction 1, entry 0.
#[test]
fn adapter_ix_data_vectors() {
    use anchor_lang::InstructionData;
    let rows: Vec<serde_json::Value> = serde_json::from_str(include_str!("../../../../vectors/metatx/paymeta.json")).unwrap();
    let h = |v: &serde_json::Value| hexd(v.as_str().unwrap().trim_start_matches("0x"));
    let a = scaas::Auth { kind: A::KIND_RAW, key_index: 0, precompile_ix: 1, sig_index: 0, cdj: vec![] };
    let base = scaas::PayArgs { to: pk(V::BOB).to_bytes(), amount: 100, pay_ref: [0; 32], lane: [0; 32], nonce: 0, valid_until: 1000, relayer: [0; 32], extra: [0; 32] };
    let args = scaas::PayArgs { pay_ref: h(&rows[0]["payId"]).try_into().unwrap(), lane: h(&rows[0]["payLane"]).try_into().unwrap(), ..base.clone() };
    let salt: [u8; 32] = h(&rows[0]["salt"]).try_into().unwrap();
    let d = scaas::instruction::RelayPayMeta { owner: pk(V::ALICE).to_bytes(), args, salt, meta: h(&rows[0]["meta"]), auth: a.clone() }.data();
    assert_eq!(hex(&sha(&[&d])), "ba205082adb76c44a6f3937e80ab6d9686d99756e0423ddb071425ed25fd3e15");
    let m = marker().to_bytes();
    let args = scaas::PayArgs { to: m, pay_ref: hexd(V::RELAY_REF).try_into().unwrap(), lane: hexd(V::RELAY_LANE).try_into().unwrap(),
                                relayer: m, extra: hexd(V::RELAY_SALT).try_into().unwrap(), ..base };
    let d = scaas::instruction::RelayFee { owner: pk(V::ALICE).to_bytes(), args, target_data: hexd(V::RELAY_DATA), target_accounts: 1, auth: a }.data();
    assert_eq!(hex(&sha(&[&d])), "d33e8ca18314c4cda621124ad04b154060820f1b8acf66b78fcca807e09b216b");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
