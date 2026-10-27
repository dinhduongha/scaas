//! `relay_pay`: vector chéo Python = program, replay, hạn, miền, relayer, khoá, phong bì, introspection, Token-2022.
mod common;

use anchor_lang::solana_program::instruction::Instruction;
use anchor_spl::token_2022::spl_token_2022 as t22;
use scaas::auth::{self as A, Auth, MetaOp};
use scaas::ScaasError as E;
use common::vectors as V;
use common::*;
use solana_keypair::Keypair;
use solana_signer::Signer;

fn vector_env() -> (Env, Ed, Pubkey) {
    let mut env = Env::new();
    let usd = Ed::new("mint-usd").kp();
    env.create_mint(&usd, TOKEN, 6, &[], &[]);
    let alice = Ed::new("alice");
    env.fund(&alice.account(), &usd.pubkey(), TOKEN, 1_000);
    (env, alice, usd.pubkey())
}

use anchor_lang::prelude::Pubkey;

#[test]
fn payload_digest_and_addresses_match_python() {
    let op = MetaOp {
        network: pk(V::NETWORK).to_bytes(),
        contract: pk(V::ALICE_ACCOUNT).to_bytes(),
        asset: pk(V::USD).to_bytes(),
        op: A::OP_PAY,
        from: pk(V::ALICE).to_bytes(),
        to: pk(V::BOB).to_bytes(),
        amount: 100,
        pay_ref: [1; 32],
        lane: [0xa1; 32],
        nonce: 0,
        valid_until: 1000,
        relayer: [0; 32],
        extra: [0; 32],
    };
    assert_eq!(op.bytes(), hexd(V::PAYLOAD));
    assert_eq!(op.bytes().len(), MetaOp::LEN);
    assert_eq!(op.digest().to_vec(), hexd(V::DIGEST));
    assert_eq!(A::text(A::METAOP_LABEL, &op.digest()), V::TEXT.as_bytes());
    assert_eq!(A::ocms(&pk(V::ALICE).to_bytes(), V::TEXT.as_bytes()), hexd(V::OCMS));
    assert_eq!(scaas::ID, pk(V::PROGRAM));
    assert_eq!(Ed::new("alice").pubkey(), pk(V::ALICE));
    assert_eq!(account_of(&pk(V::ALICE).to_bytes()), pk(V::ALICE_ACCOUNT));
    assert_eq!(pda(&[b"lane", pk(V::ALICE_ACCOUNT).as_ref(), &[0xa1; 32]]), pk(V::ALICE_LANE_PDA));
    assert_eq!(pda(&[b"mandate", pk(V::ALICE_ACCOUNT).as_ref(), &[0x0d; 32]]), pk(V::ALICE_MANDATE));
    assert_eq!(pda(&[b"mkt", pk(V::USD).as_ref(), pk(V::EUR).as_ref()]), pk(V::MARKET));
    assert_eq!(pda(&[b"fill", pk(V::MARKET).as_ref(), &sha(&[b"order"])]), pk(V::FILL));
    assert_eq!(ata(&pk(V::BOB), &pk(V::USD), &TOKEN), pk(V::BOB_ATA_USD));
    assert_eq!(ata(&pk(V::ALICE_ACCOUNT), &pk(V::EUR), &TOKEN22), pk(V::ALICE_ACCOUNT_ATA_EUR_2022));
    let dave = Passkey::new("dave");
    assert_eq!(dave.pk33().to_vec(), hexd(V::DAVE_PK));
    assert_eq!(Pubkey::new_from_array(dave.owner()), pk(V::DAVE_OWNER));
    assert_eq!(dave.account(), pk(V::DAVE_ACCOUNT));
}

/// Chữ ký Python thật (raw rồi OCMS) mở lười Account và trả; phát lại ⇒ nonce lane đã dùng.
#[test]
fn python_signatures_pay_and_replay_is_refused() {
    for (kind, sig, msg) in [(A::KIND_RAW, V::SIG_RAW, V::TEXT.as_bytes().to_vec()), (A::KIND_OCMS, V::SIG_OCMS, hexd(V::OCMS))] {
        let (mut env, alice, usd) = vector_env();
        assert!(!env.exists(&alice.account()));
        let args = env.args(&pk(V::BOB), 100, 1, 0xa1, 0, 1000);
        let e = Entry { pk: alice.pk().to_vec(), sig: hexd(sig), msg };
        let src = ata(&alice.account(), &usd, &TOKEN);
        let ix = env.pay_ix(&alice.pk(), &usd, TOKEN, src, &args, auth(kind, 0, 0, 0));
        let m = ok(env.send(&[ed_ix(std::slice::from_ref(&e)), ix], &[]));
        assert_eq!(env.balance(&pk(V::BOB_ATA_USD)), 100);
        assert_eq!(m.fee, 10_000, "base fee counts the lane signature AND the precompile signature");
        assert_eq!(env.subject(&alice.account()).keys, vec![alice.key()]);
        // events: MetaTransactionExecuted then PaymentSettled through the event authority self-CPI
        let ev: Vec<Vec<u8>> = m.inner_instructions.iter().flatten().map(|i| i.instruction.data.clone())
            .filter(|d| d.starts_with(&anchor_lang::event::EVENT_IX_TAG_LE)).collect();
        assert_eq!(ev.len(), 2);
        assert_eq!(&ev[0][8..16], <scaas::MetaTransactionExecuted as anchor_lang::Discriminator>::DISCRIMINATOR);
        assert!(ev[0].windows(32).any(|w| w == hexd(V::DIGEST).as_slice()));
        assert_eq!(&ev[1][8..16], <scaas::PaymentSettled as anchor_lang::Discriminator>::DISCRIMINATOR);
        let ix = env.pay_ix(&alice.pk(), &usd, TOKEN, src, &args, auth(kind, 0, 0, 0));
        expect_err(env.send(&[ed_ix(&[e]), ix], &[]), E::BadNonce);
        assert_eq!(env.balance(&pk(V::BOB_ATA_USD)), 100);
    }
}

#[test]
fn deadline_amount_and_relayer_binding() {
    let (mut env, alice, usd) = vector_env();
    let bob = pk(V::BOB);
    env.set_time(1001);
    expect_err(env.pay(&alice, &usd, TOKEN, &env.args(&bob, 1, 1, 1, 0, 1000)), E::Expired);
    env.set_time(NOW);
    expect_err(env.pay(&alice, &usd, TOKEN, &env.args(&bob, 0, 1, 1, 0, 1000)), E::ZeroAmount);
    let mut a = env.args(&bob, 1, 1, 1, 0, 1000);
    a.relayer = [9; 32];
    expect_err(env.pay(&alice, &usd, TOKEN, &a), E::WrongRelayer);
    a.relayer = env.lane.pubkey().to_bytes();
    ok(env.pay(&alice, &usd, TOKEN, &a));
}

/// Chữ ký cho miền/contract/tài sản/op khác không qua.
#[test]
fn signature_for_another_domain_contract_asset_or_op_is_refused() {
    let (mut env, alice, usd) = vector_env();
    let eur = env.mint(TOKEN, 6);
    let bob = pk(V::BOB);
    let args = env.args(&bob, 5, 1, 1, 0, 1000);
    let src = ata(&alice.account(), &usd, &TOKEN);
    let digests = [
        args.metaop([7; 32], alice.account(), usd, A::OP_PAY, alice.pk()).digest(),
        args.metaop(env.network, Ed::new("bob").account(), usd, A::OP_PAY, alice.pk()).digest(),
        args.metaop(env.network, alice.account(), eur, A::OP_PAY, alice.pk()).digest(),
        args.metaop(env.network, alice.account(), usd, A::OP_MANDATE_PAY, alice.pk()).digest(),
    ];
    for dg in digests {
        let e = alice.sign(A::KIND_RAW, A::METAOP_LABEL, &dg);
        let ix = env.pay_ix(&alice.pk(), &usd, TOKEN, src, &args, auth(A::KIND_RAW, 0, 0, 0));
        expect_err(env.send(&[ed_ix(&[e]), ix], &[]), E::BadSignature);
    }
    // label of another domain over the right digest
    let dg = env.metaop_digest(&alice.account(), &usd, A::OP_PAY, &alice.pk(), &args);
    let e = alice.sign(A::KIND_RAW, A::KEYOP_LABEL, &dg);
    let ix = env.pay_ix(&alice.pk(), &usd, TOKEN, src, &args, auth(A::KIND_RAW, 0, 0, 0));
    expect_err(env.send(&[ed_ix(&[e]), ix], &[]), E::BadSignature);
}

/// Introspection (RS12-10): pk ∉ keys, OCMS của signer khác, thông điệp lệch một byte, chỉ số instruction ≠ u16::MAX,
/// instruction không phải precompile, precompile sau instruction của ta, sig_index ngoài tầm, chữ ký sai.
#[test]
fn precompile_introspection_is_strict() {
    let (mut env, alice, usd) = vector_env();
    let bob = Ed::new("bob");
    let args = env.args(&bob.pubkey(), 5, 1, 1, 0, 1000);
    let src = ata(&alice.account(), &usd, &TOKEN);
    let dg = env.metaop_digest(&alice.account(), &usd, A::OP_PAY, &alice.pk(), &args);
    let good = alice.sign(A::KIND_RAW, A::METAOP_LABEL, &dg);
    let pay = |env: &Env, a: Auth| env.pay_ix(&alice.pk(), &usd, TOKEN, src, &args, a);

    // key index outside the Account / a stranger's key at index 0
    expect_err(env.send(&[ed_ix(std::slice::from_ref(&good)), pay(&env, auth(A::KIND_RAW, 1, 0, 0))], &[]), E::UnknownKey);
    let stranger = bob.sign(A::KIND_RAW, A::METAOP_LABEL, &dg);
    expect_err(env.send(&[ed_ix(&[stranger]), pay(&env, auth(A::KIND_RAW, 0, 0, 0))], &[]), E::BadSignature);
    // OCMS naming another signer
    let t = A::text(A::METAOP_LABEL, &dg);
    let other = A::ocms(&bob.pk(), &t);
    let e = Entry { pk: alice.pk().to_vec(), sig: alice.raw(&other), msg: other };
    expect_err(env.send(&[ed_ix(&[e]), pay(&env, auth(A::KIND_OCMS, 0, 0, 0))], &[]), E::BadSignature);
    // raw text claimed as OCMS and vice versa
    expect_err(env.send(&[ed_ix(std::slice::from_ref(&good)), pay(&env, auth(A::KIND_OCMS, 0, 0, 0))], &[]), E::BadSignature);
    // one byte off
    let mut msg = good.msg.clone();
    msg[20] ^= 1;
    let e = Entry { pk: alice.pk().to_vec(), sig: alice.raw(&msg), msg };
    expect_err(env.send(&[ed_ix(&[e]), pay(&env, auth(A::KIND_RAW, 0, 0, 0))], &[]), E::BadSignature);
    // offsets pointing at another instruction (index 1 = our own ix data)
    let ix = precompile_ix(ED25519, std::slice::from_ref(&good), 0);
    expect_err(env.send(&[ix, pay(&env, auth(A::KIND_RAW, 0, 0, 0))], &[]), E::BadPrecompile);
    // not a precompile: a memo-less no-op instruction of another program at index 0
    let noop = Instruction { program_id: SECP256R1, accounts: vec![], data: ed_ix(std::slice::from_ref(&good)).data };
    assert!(env.send(&[noop, pay(&env, auth(A::KIND_RAW, 0, 0, 0))], &[]).is_err());
    let transfer = solana_system_interface::instruction::transfer(&env.lane.pubkey(), &bob.pubkey(), 1);
    expect_err(env.send(&[transfer, pay(&env, auth(A::KIND_RAW, 0, 0, 0))], &[]), E::BadPrecompile);
    // precompile index must be BEFORE our instruction
    expect_err(env.send(&[pay(&env, auth(A::KIND_RAW, 0, 1, 0)), ed_ix(std::slice::from_ref(&good))], &[]), E::BadPrecompile);
    expect_err(env.send(&[ed_ix(std::slice::from_ref(&good)), pay(&env, auth(A::KIND_RAW, 0, 0, 1))], &[]), E::BadPrecompile);
    // a forged signature fails in the precompile itself
    let mut bad = good.clone();
    bad.sig[0] ^= 1;
    assert!(env.send(&[ed_ix(&[bad]), pay(&env, auth(A::KIND_RAW, 0, 0, 0))], &[]).is_err());
    // a second entry in the same precompile instruction is fine
    ok(env.send(&[ed_ix(&[bob.sign(A::KIND_RAW, "x", &dg), good]), pay(&env, auth(A::KIND_RAW, 0, 0, 1))], &[]));
    assert_eq!(env.balance(&ata(&bob.pubkey(), &usd, &TOKEN)), 5);
}

/// Người nhận phải là `to` đã ký; đích phải đúng ATA của nó (chương trình ATA kiểm dẫn xuất).
#[test]
fn recipient_and_destination_are_bound_to_the_signed_to() {
    let (mut env, alice, usd) = vector_env();
    let bob = Ed::new("bob");
    let mallory = Ed::new("mallory");
    env.fund(&mallory.pubkey(), &usd, TOKEN, 0);
    let args = env.args(&bob.pubkey(), 5, 1, 1, 0, 1000);
    let src = ata(&alice.account(), &usd, &TOKEN);
    let dg = env.metaop_digest(&alice.account(), &usd, A::OP_PAY, &alice.pk(), &args);
    let e = alice.sign(A::KIND_RAW, A::METAOP_LABEL, &dg);
    let mut ix = env.pay_ix(&alice.pk(), &usd, TOKEN, src, &args, auth(A::KIND_RAW, 0, 0, 0));
    ix.accounts[5].pubkey = mallory.pubkey();
    ix.accounts[6].pubkey = ata(&mallory.pubkey(), &usd, &TOKEN);
    expect_err(env.send(&[ed_ix(std::slice::from_ref(&e)), ix], &[]), E::WrongRecipient);
    let mut ix = env.pay_ix(&alice.pk(), &usd, TOKEN, src, &args, auth(A::KIND_RAW, 0, 0, 0));
    ix.accounts[6].pubkey = ata(&mallory.pubkey(), &usd, &TOKEN);
    assert!(env.send(&[ed_ix(std::slice::from_ref(&e)), ix], &[]).is_err());
    assert_eq!(env.balance(&ata(&mallory.pubkey(), &usd, &TOKEN)), 0);
}

/// Review L5: `to` dán nhầm là token account (hay mint) ⇒ từ chối, không tạo ATA mà không ai ký được; ví chưa có SOL
/// (chưa tồn tại) và PDA của program khác vẫn nhận được.
#[test]
fn a_token_account_or_mint_is_not_a_recipient() {
    let (mut env, alice, usd) = vector_env();
    let bob = Ed::new("bob").pubkey();
    let bob_ata = env.fund(&bob, &usd, TOKEN, 0);
    expect_err(env.pay(&alice, &usd, TOKEN, &env.args(&bob_ata, 5, 1, 1, 0, 1000)), E::TokenAccountRecipient);
    expect_err(env.pay(&alice, &usd, TOKEN, &env.args(&usd, 5, 1, 1, 0, 1000)), E::TokenAccountRecipient);
    ok(env.pay(&alice, &usd, TOKEN, &env.args(&bob, 5, 1, 1, 0, 1000)));
    let vault = pda(&[b"some-vault"]);
    ok(env.pay(&alice, &usd, TOKEN, &env.args(&vault, 5, 2, 1, 1, 1000)));
    assert_eq!(env.balance(&bob_ata), 5);
}

/// L7: tiền gửi vào token account KHÔNG phải ATA của PDA vẫn chi được; Account chưa mở vẫn nhận được.
#[test]
fn any_token_account_of_the_pda_is_spendable() {
    let mut env = Env::new();
    let usd = env.mint(TOKEN, 6);
    let carol = Ed::new("carol");
    let side = env.side_account(&carol.account(), &usd, TOKEN, 70);
    let bob = Ed::new("bob");
    let args = env.args(&bob.pubkey(), 70, 1, 1, 0, 1000);
    let dg = env.metaop_digest(&carol.account(), &usd, A::OP_PAY, &carol.pk(), &args);
    let e = carol.sign(A::KIND_RAW, A::METAOP_LABEL, &dg);
    let ix = env.pay_ix(&carol.pk(), &usd, TOKEN, side, &args, auth(A::KIND_RAW, 0, 0, 0));
    ok(env.send(&[ed_ix(&[e]), ix], &[]));
    assert_eq!((env.balance(&side), env.balance(&ata(&bob.pubkey(), &usd, &TOKEN))), (0, 70));
    // someone else's token account as source is refused by the token::authority constraint
    let dave_side = env.side_account(&bob.pubkey(), &usd, TOKEN, 10);
    let args = env.args(&bob.pubkey(), 1, 2, 1, 1, 1000);
    let dg = env.metaop_digest(&carol.account(), &usd, A::OP_PAY, &carol.pk(), &args);
    let e = carol.sign(A::KIND_RAW, A::METAOP_LABEL, &dg);
    let ix = env.pay_ix(&carol.pk(), &usd, TOKEN, dave_side, &args, auth(A::KIND_RAW, 0, 0, 0));
    assert!(env.send(&[ed_ix(&[e]), ix], &[]).is_err());
}

fn t22_mint(env: &mut Env, ext: &[Instruction], types: &[t22::extension::ExtensionType], kp: &Keypair) {
    env.create_mint(kp, TOKEN22, 6, ext, types);
}

/// RS12-7 / owner OQ3: Token-2022 phí > 0, transfer hook có program, NonTransferable ⇒ từ chối; phí 0, hook rỗng,
/// permanent delegate ⇒ chuyển được.
#[test]
fn token_2022_extension_policy() {
    use t22::extension::ExtensionType as X;
    let mut env = Env::new();
    let alice = Ed::new("alice");
    let bob = Ed::new("bob");
    let admin = env.admin.pubkey();
    let cases: Vec<(&str, Vec<X>, Box<dyn Fn(&Pubkey) -> Vec<Instruction>>, Option<E>)> = vec![
        ("plain", vec![], Box::new(|_| vec![]), None),
        ("fee>0", vec![X::TransferFeeConfig], Box::new(move |m| vec![
            t22::extension::transfer_fee::instruction::initialize_transfer_fee_config(&TOKEN22, m, Some(&admin), Some(&admin), 50, 1_000).unwrap()]), Some(E::MintNotAllowed)),
        ("fee=0", vec![X::TransferFeeConfig], Box::new(move |m| vec![
            t22::extension::transfer_fee::instruction::initialize_transfer_fee_config(&TOKEN22, m, Some(&admin), Some(&admin), 0, 0).unwrap()]), None),
        ("hook", vec![X::TransferHook], Box::new(move |m| vec![
            t22::extension::transfer_hook::instruction::initialize(&TOKEN22, m, Some(admin), Some(Pubkey::new_unique())).unwrap()]), Some(E::MintNotAllowed)),
        ("hook-none", vec![X::TransferHook], Box::new(move |m| vec![
            t22::extension::transfer_hook::instruction::initialize(&TOKEN22, m, Some(admin), None).unwrap()]), None),
        ("non-transferable", vec![X::NonTransferable], Box::new(|m| vec![
            t22::instruction::initialize_non_transferable_mint(&TOKEN22, m).unwrap()]), Some(E::MintNotAllowed)),
        ("permanent-delegate", vec![X::PermanentDelegate], Box::new(move |m| vec![
            t22::instruction::initialize_permanent_delegate(&TOKEN22, m, &admin).unwrap()]), None),
    ];
    for (i, (name, types, ext, want)) in cases.into_iter().enumerate() {
        let kp = Keypair::new();
        let ixs = ext(&kp.pubkey());
        t22_mint(&mut env, &ixs, &types, &kp);
        let mint = kp.pubkey();
        let src = env.fund(&alice.account(), &mint, TOKEN22, 100);
        let args = env.args(&bob.pubkey(), 10, 1, i as u8 + 1, 0, 1000);
        let res = env.pay(&alice, &mint, TOKEN22, &args);
        match want {
            Some(e) => expect_err(res, e),
            None => {
                ok(res);
                assert_eq!(env.balance(&ata(&bob.pubkey(), &mint, &TOKEN22)), 10, "{name}");
                assert_eq!(env.balance(&src), 90, "{name}");
            }
        }
    }
}

/// `initialize` chỉ upgrade authority, và chỉ một lần.
#[test]
fn initialize_is_upgrade_authority_only_and_once() {
    let mut env = Env::new();
    let a = env.admin.pubkey();
    assert!(env.send(&[env.initialize_ix(&a)], &[&env.admin.insecure_clone()]).is_err(), "second initialize");
    let mut fresh = litesvm::LiteSVM::new();
    fresh.add_program(scaas::ID, SO).unwrap();
    let mut env2 = Env { svm: fresh, admin: Keypair::new(), lane: Keypair::new(), network: [1; 32] };
    env2.svm.airdrop(&env2.lane.pubkey(), 1_000_000_000).unwrap();
    let auth_kp = Keypair::new();
    env2.set_upgrade_authority(&auth_kp.pubkey());
    let lane = env2.lane.pubkey();
    expect_err(env2.send(&[env2.initialize_ix(&lane)], &[]), E::NotUpgradeAuthority);
    env2.svm.airdrop(&auth_kp.pubkey(), 1_000_000_000).unwrap();
    let k = auth_kp.pubkey();
    ok(env2.send(&[env2.initialize_ix(&k)], &[&auth_kp]));
}

// ------------------------------------------------------------------ CTR-MTX-26: relay_pay_meta

/// `smartcontracts/vectors/metatx/paymeta.json`, shared with the EVM forge test, `clientkeys` and every family.
fn meta_rows() -> Vec<serde_json::Value> {
    serde_json::from_str(include_str!("../../../../vectors/metatx/paymeta.json")).unwrap()
}

fn h(v: &serde_json::Value) -> Vec<u8> {
    hexd(v.as_str().unwrap().trim_start_matches("0x"))
}

fn h32(v: &serde_json::Value) -> [u8; 32] {
    h(v).try_into().unwrap()
}

/// A pay-meta pay of `amount` to `to` for the vector row (`pay_ref = payId`, `lane = payLane(payId)`, nonce 0).
fn meta_args(to: &Pubkey, amount: u64, row: &serde_json::Value) -> scaas::PayArgs {
    scaas::PayArgs {
        to: to.to_bytes(),
        amount,
        pay_ref: h32(&row["payId"]),
        lane: h32(&row["payLane"]),
        nonce: 0,
        valid_until: 1000,
        relayer: [0; 32],
        extra: [0; 32],
    }
}

fn events(m: &litesvm::types::TransactionMetadata) -> Vec<Vec<u8>> {
    m.inner_instructions.iter().flatten().map(|i| i.instruction.data.clone())
        .filter(|d| d.starts_with(&anchor_lang::event::EVENT_IX_TAG_LE)).collect()
}

fn disc<E: anchor_lang::Discriminator>() -> &'static [u8] {
    E::DISCRIMINATOR
}

/// Rule 1: every row's `payId` / `payLane` byte for byte (the program's keccak), and every row that fits a
/// transaction pays on chain under it (`long_body_4096` is a hash vector only).
#[test]
fn pay_meta_vectors_match() {
    let rows = meta_rows();
    assert_eq!(rows.len(), 6);
    for r in &rows {
        let (salt, meta) = (h32(&r["salt"]), h(&r["meta"]));
        assert_eq!(scaas::meta_pay_id(&salt, &meta), h32(&r["payId"]), "{}", r["name"]);
        assert_eq!(scaas::pay_lane(&h32(&r["payId"])), h32(&r["payLane"]), "{}", r["name"]);
    }
    let (mut env, alice, usd) = vector_env();
    let bob = pk(V::BOB);
    for r in rows.iter().filter(|r| r["name"] != "long_body_4096") {
        let m = ok(env.pay_meta(&alice, &usd, TOKEN, &meta_args(&bob, 1, r), h32(&r["salt"]), &h(&r["meta"])));
        assert!(events(&m).iter().any(|e| e.windows(32).any(|w| w == h(&r["payId"]).as_slice())), "{}", r["name"]);
    }
    assert_eq!(env.balance(&pk(V::BOB_ATA_USD)), 5);
}

/// Events: `MetaTransactionExecuted`, `PaymentMeta { contract: mint, pay_id, meta }`, then `PaymentSettled`.
#[test]
fn pay_meta_emits_meta_then_settled() {
    let (mut env, alice, usd) = vector_env();
    let r = &meta_rows()[0];
    let (salt, meta) = (h32(&r["salt"]), h(&r["meta"]));
    let m = ok(env.pay_meta(&alice, &usd, TOKEN, &meta_args(&pk(V::BOB), 40, r), salt, &meta));
    eprintln!("relay_pay_meta ({} B meta, lazy open): {} CU", meta.len(), m.compute_units_consumed);
    assert_eq!(env.balance(&pk(V::BOB_ATA_USD)), 40);
    let ev = events(&m);
    assert_eq!(ev.len(), 3);
    assert_eq!(&ev[0][8..16], disc::<scaas::MetaTransactionExecuted>());
    assert_eq!(&ev[1][8..16], disc::<scaas::PaymentMeta>());
    assert_eq!(&ev[2][8..16], disc::<scaas::PaymentSettled>());
    let mut want = usd.to_bytes().to_vec();
    want.extend_from_slice(&h(&r["payId"]));
    want.extend_from_slice(&(meta.len() as u32).to_le_bytes());
    want.extend_from_slice(&meta);
    assert_eq!(&ev[1][16..], want.as_slice());
    assert!(ev[2].ends_with(&h(&r["payId"])), "PaymentSettled.pay_ref = payId");
    let plain = ok(env.pay(&alice, &usd, TOKEN, &env.args(&pk(V::BOB), 1, 1, 0xa1, 0, 1000)));
    eprintln!("relay_pay (warm, same accounts): {} CU", plain.compute_units_consumed);
    let r = &meta_rows()[4];
    let m = ok(env.pay_meta(&alice, &usd, TOKEN, &meta_args(&pk(V::BOB), 1, r), h32(&r["salt"]), &h(&r["meta"])));
    eprintln!("relay_pay_meta (warm, {} B meta): {} CU", h(&r["meta"]).len(), m.compute_units_consumed);
}

/// Review focus 4: `(salt, meta)` that does not hash to `pay_ref`, a lane that is not `payLane(pay_ref)`, a nonce
/// other than 0, and a second pay of the same `(payer, payId)` (pay-meta or plain) are refused.
#[test]
fn solana_pay_meta_mismatch_and_replay() {
    let (mut env, alice, usd) = vector_env();
    let bob = pk(V::BOB);
    let r = &meta_rows()[1];
    let (salt, meta) = (h32(&r["salt"]), h(&r["meta"]));
    let good = meta_args(&bob, 5, r);
    let mut other = meta.clone();
    other[40] ^= 1;
    expect_err(env.pay_meta(&alice, &usd, TOKEN, &good, salt, &other), E::PayMetaShape);
    expect_err(env.pay_meta(&alice, &usd, TOKEN, &good, [0; 32], &meta), E::PayMetaShape);
    let mut a = good.clone();
    a.lane = [0xa1; 32];
    expect_err(env.pay_meta(&alice, &usd, TOKEN, &a, salt, &meta), E::PayMetaShape);
    let mut a = good.clone();
    a.nonce = 1;
    expect_err(env.pay_meta(&alice, &usd, TOKEN, &a, salt, &meta), E::PayMetaShape);
    ok(env.pay_meta(&alice, &usd, TOKEN, &good, salt, &meta));
    expect_err(env.pay_meta(&alice, &usd, TOKEN, &good, salt, &meta), E::BadNonce);
    expect_err(env.pay(&alice, &usd, TOKEN, &good), E::BadNonce);
    assert_eq!(env.balance(&pk(V::BOB_ATA_USD)), 5);
    // plain pay first, then the pay-meta of the same payId
    let r = &meta_rows()[2];
    ok(env.pay(&alice, &usd, TOKEN, &meta_args(&bob, 2, r)));
    expect_err(env.pay_meta(&alice, &usd, TOKEN, &meta_args(&bob, 2, r), h32(&r["salt"]), &h(&r["meta"])), E::BadNonce);
    assert_eq!(env.balance(&pk(V::BOB_ATA_USD)), 7);
}

/// Rule 6: the once-set is per payer (the lane PDA is keyed by the payer's Account): someone else paying under the
/// victim's `(salt, meta)` / `payId` uses their own lane and never blocks the victim.
#[test]
fn pay_meta_id_is_per_payer() {
    let (mut env, alice, usd) = vector_env();
    let mallory = Ed::new("mallory");
    env.fund(&mallory.account(), &usd, TOKEN, 10);
    let bob = pk(V::BOB);
    let r = &meta_rows()[0];
    let (salt, meta) = (h32(&r["salt"]), h(&r["meta"]));
    expect_err(env.pay_meta(&mallory, &usd, TOKEN, &meta_args(&mallory.pubkey(), 0, r), salt, &meta), E::ZeroAmount);
    ok(env.pay_meta(&mallory, &usd, TOKEN, &meta_args(&mallory.pubkey(), 1, r), salt, &meta));
    ok(env.pay_meta(&alice, &usd, TOKEN, &meta_args(&bob, 30, r), salt, &meta));
    assert_eq!(env.balance(&pk(V::BOB_ATA_USD)), 30);
}

// ------------------------------------------------------------------ RelayPay PDAs checked in `settle` (T11 fix 2/3)

/// `RelayPay` derives `subject` and `lane_pda` in the body: a substituted Account (with its own token account) or
/// lane PDA is `BadAccounts`; a program-owned account with another discriminator at the lane PDA address is
/// `AccountDiscriminatorMismatch`; a foreign-owned account there is `BadOwner`; an address only pre-funded with
/// lamports (no data) is topped up and created.
#[test]
fn relay_pay_pdas_are_checked_in_the_body() {
    let (mut env, alice, usd) = vector_env();
    let bob = Ed::new("bob");
    let kp = bob.kp();
    ok(env.send(&[env.open_ix(&bob.pubkey())], &[&kp]));
    env.fund(&bob.account(), &usd, TOKEN, 100);
    let to = pk(V::BOB);
    let args = env.args(&to, 5, 1, 0x21, 0, 1000);
    let dg = env.metaop_digest(&alice.account(), &usd, A::OP_PAY, &alice.pk(), &args);
    let e = alice.sign(A::KIND_RAW, A::METAOP_LABEL, &dg);
    let src = ata(&alice.account(), &usd, &TOKEN);
    let ix0 = env_pay_ix(&env, &alice, &usd, src, &args);
    let base = || ix0.clone();
    // another Account (and its token account, so the token constraint holds)
    let mut ix = base();
    ix.accounts[2].pubkey = bob.account();
    ix.accounts[4].pubkey = ata(&bob.account(), &usd, &TOKEN);
    expect_err(env.send(&[ed_ix(std::slice::from_ref(&e)), ix], &[]), E::BadAccounts);
    // another lane PDA (of another lane id)
    let mut ix = base();
    ix.accounts[3].pubkey = pda(&[b"lane", alice.account().as_ref(), &[0x22; 32]]);
    expect_err(env.send(&[ed_ix(std::slice::from_ref(&e)), ix], &[]), E::BadAccounts);
    let lp = pda(&[b"lane", alice.account().as_ref(), &args.lane]);
    let rent = env.svm.minimum_balance_for_rent_exemption(56);
    // a program-owned account with another discriminator
    let mut data = <scaas::state::MandateRef as anchor_lang::Discriminator>::DISCRIMINATOR.to_vec();
    data.resize(56, 0);
    env.svm.set_account(lp, solana_account::Account { lamports: rent, data, owner: scaas::ID, executable: false, rent_epoch: 0 }).unwrap();
    let res = env.send(&[ed_ix(std::slice::from_ref(&e)), base()], &[]);
    assert_eq!(custom(&res), Some(anchor_lang::error::ErrorCode::AccountDiscriminatorMismatch as u32));
    // a foreign-owned account with data
    env.svm.set_account(lp, solana_account::Account { lamports: rent, data: vec![0; 56], owner: TOKEN, executable: false, rent_epoch: 0 }).unwrap();
    expect_err(env.send(&[ed_ix(std::slice::from_ref(&e)), base()], &[]), E::BadOwner);
    // pre-funded with lamports only: topped up to rent and created
    env.svm.set_account(lp, solana_account::Account { lamports: 1_000, data: vec![], owner: SYSTEM, executable: false, rent_epoch: 0 }).unwrap();
    ok(env.send(&[ed_ix(&[e]), base()], &[]));
    let lane: scaas::state::LanePda = env.account(&lp).unwrap();
    assert_eq!((lane.next, lane.rent_payer), (1, env.lane.pubkey()));
    assert_eq!(env.balance(&pk(V::BOB_ATA_USD)), 5);
}

fn env_pay_ix(env: &Env, who: &Ed, usd: &Pubkey, src: Pubkey, args: &scaas::PayArgs) -> Instruction {
    env.pay_ix(&who.pk(), usd, TOKEN, src, args, auth(A::KIND_RAW, 0, 0, 0))
}
