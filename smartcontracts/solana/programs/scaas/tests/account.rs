//! Account: passkey (vector Python thật, high-S, origin, UV, add_origin cùng rpId), KeyOp, guardian/khôi phục,
//! chính sách backup, rút lamports, `open`, `prune`.
mod common;

use anchor_lang::prelude::Pubkey;
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::{InstructionData, ToAccountMetas};
use scaas::auth::{self as A, Auth};
use scaas::state::{AuthKey, POLICY_BACKUP_REQUIRED};
use scaas::ScaasError as E;
use scaas::{ADD_KEY, ADD_ORIGIN, CANCEL_RECOVERY, REMOVE_KEY, REMOVE_ORIGIN, SET_GUARDIAN, SET_POLICY, WITHDRAW_LAMPORTS};
use common::vectors as V;
use common::*;
use solana_keypair::Keypair;
use solana_signer::Signer;

fn open_passkey_ix(env: &Env, owner: [u8; 32], pk33: [u8; 33], auth: Auth) -> Instruction {
    Instruction {
        program_id: scaas::ID,
        accounts: scaas::accounts::OpenPasskey { payer: env.lane.pubkey(), subject: account_of(&owner), instructions: IXS, system_program: SYSTEM }
            .to_account_metas(None),
        data: scaas::instruction::OpenPasskey { owner, pk33, auth }.data(),
    }
}

fn pk_auth(cdj: Vec<u8>) -> Auth {
    Auth { kind: A::KIND_PASSKEY, key_index: 0, precompile_ix: 0, sig_index: 0, cdj }
}

/// Mở Account passkey-first (assertion trên challenge mở).
fn open_dave(env: &mut Env, p: &Passkey, origin: &str) {
    let ch = sha(&[b"scaas.open.v1", scaas::ID.as_ref(), &p.pk33()]);
    let (e, cdj) = p.assert(&ch, origin, 5, false);
    ok(env.send(&[r1_ix(&[e]), open_passkey_ix(env, p.owner(), p.pk33(), pk_auth(cdj))], &[]));
}

fn pay_passkey(env: &mut Env, p: &Passkey, mint: &Pubkey, args: &scaas::PayArgs, origin: &str, flags: u8, high_s: bool) -> Res {
    let dg = env.metaop_digest(&p.account(), mint, A::OP_PAY, &p.owner(), args);
    let (e, cdj) = p.assert(&dg, origin, flags, high_s);
    let ix = env.pay_ix(&p.owner(), mint, TOKEN, ata(&p.account(), mint, &TOKEN), args, pk_auth(cdj));
    env.send(&[r1_ix(&[e]), ix], &[])
}

/// Vector Python (P-256 tất định, low-S): mở Account rồi trả 100 USD cho Bob.
#[test]
fn python_passkey_vector_opens_and_pays() {
    let mut env = Env::new();
    let usd = Ed::new("mint-usd").kp();
    env.create_mint(&usd, TOKEN, 6, &[], &[]);
    let pk33: [u8; 33] = hexd(V::DAVE_PK).try_into().unwrap();
    let owner = pk(V::DAVE_OWNER).to_bytes();
    let msg = |ad: &str, cdj: &str| [hexd(ad), sha(&[cdj.as_bytes()]).to_vec()].concat();
    let e = Entry { pk: pk33.to_vec(), sig: hexd(V::OPEN_SIG), msg: msg(V::OPEN_AUTH_DATA, V::OPEN_CDJ) };
    ok(env.send(&[r1_ix(&[e]), open_passkey_ix(&env, owner, pk33, pk_auth(V::OPEN_CDJ.as_bytes().to_vec()))], &[]));
    let s = env.subject(&pk(V::DAVE_ACCOUNT));
    assert_eq!((s.origins.clone(), s.keys[0].rp_id_hash), (vec![ORIGIN.to_string()], Passkey::rp_id_hash()));
    env.fund(&pk(V::DAVE_ACCOUNT), &usd.pubkey(), TOKEN, 1000);
    let args = env.args(&pk(V::BOB), 100, 1, 0xa1, 0, 1000);
    let e = Entry { pk: pk33.to_vec(), sig: hexd(V::DAVE_SIG), msg: msg(V::DAVE_AUTH_DATA, V::DAVE_CDJ) };
    let ix = env.pay_ix(&owner, &usd.pubkey(), TOKEN, ata(&pk(V::DAVE_ACCOUNT), &usd.pubkey(), &TOKEN), &args, pk_auth(V::DAVE_CDJ.as_bytes().to_vec()));
    ok(env.send(&[r1_ix(&[e]), ix], &[]));
    assert_eq!(env.balance(&pk(V::BOB_ATA_USD)), 100);
}

#[test]
fn passkey_rules_high_s_origin_uv_and_tampering() {
    let mut env = Env::new();
    let usd = env.mint(TOKEN, 6);
    let dave = Passkey::new("dave");
    open_dave(&mut env, &dave, ORIGIN);
    env.fund(&dave.account(), &usd, TOKEN, 1000);
    let bob = Ed::new("bob").pubkey();
    let args = env.args(&bob, 10, 1, 1, 0, 1000);
    assert!(pay_passkey(&mut env, &dave, &usd, &args, ORIGIN, 5, true).is_err(), "high-S refused by the precompile");
    expect_err(pay_passkey(&mut env, &dave, &usd, &args, "https://evil.test", 5, false), E::UnknownOrigin);
    expect_err(pay_passkey(&mut env, &dave, &usd, &args, ORIGIN, 1, false), E::BadWebAuthn);
    // clientDataJSON edited after signing: its hash no longer matches the signed message
    let dg = env.metaop_digest(&dave.account(), &usd, A::OP_PAY, &dave.owner(), &args);
    let (e, cdj) = dave.assert(&dg, ORIGIN, 5, false);
    let forged = String::from_utf8(cdj).unwrap().replace("pay.scaas", "pay.bambo0").into_bytes();
    let ix = env.pay_ix(&dave.owner(), &usd, TOKEN, ata(&dave.account(), &usd, &TOKEN), &args, pk_auth(forged));
    expect_err(env.send(&[r1_ix(&[e]), ix], &[]), E::BadWebAuthn);
    // an ed25519 envelope against a P-256 key
    let ix = env.pay_ix(&dave.owner(), &usd, TOKEN, ata(&dave.account(), &usd, &TOKEN), &args, auth(A::KIND_RAW, 0, 0, 0));
    expect_err(env.send(&[ed_ix(&[Ed::new("x").sign(A::KIND_RAW, A::METAOP_LABEL, &dg)]), ix], &[]), E::BadSignature);
    ok(pay_passkey(&mut env, &dave, &usd, &args, ORIGIN, 5, false));
    assert_eq!(env.balance(&ata(&bob, &usd, &TOKEN)), 10);
}

/// `open_passkey`: owner phải là id của pk; challenge phải là challenge mở; mở một lần.
#[test]
fn open_passkey_binds_owner_challenge_and_origin() {
    let mut env = Env::new();
    let dave = Passkey::new("dave");
    let ch = sha(&[b"scaas.open.v1", scaas::ID.as_ref(), &dave.pk33()]);
    let (e, cdj) = dave.assert(&ch, ORIGIN, 5, false);
    let other = Passkey::new("erin").owner();
    expect_err(env.send(&[r1_ix(std::slice::from_ref(&e)), open_passkey_ix(&env, other, dave.pk33(), pk_auth(cdj.clone()))], &[]), E::BadOwner);
    let (e2, cdj2) = dave.assert(&[9; 32], ORIGIN, 5, false);
    expect_err(env.send(&[r1_ix(&[e2]), open_passkey_ix(&env, dave.owner(), dave.pk33(), pk_auth(cdj2))], &[]), E::BadWebAuthn);
    ok(env.send(&[r1_ix(std::slice::from_ref(&e)), open_passkey_ix(&env, dave.owner(), dave.pk33(), pk_auth(cdj.clone()))], &[]));
    expect_err(env.send(&[r1_ix(&[e]), open_passkey_ix(&env, dave.owner(), dave.pk33(), pk_auth(cdj))], &[]), E::AlreadyOpen);
}

fn manage_passkey(env: &mut Env, p: &Passkey, op: scaas::KeyOp, origin: &str) -> Res {
    let dg = env.keyop_digest(&p.account(), &op);
    let (e, cdj) = p.assert(&dg, origin, 5, false);
    let ix = env.manage_ix(&p.account(), &op, pk_auth(cdj), None);
    env.send(&[r1_ix(&[e]), ix], &[])
}

/// L6: đổi domain trong cùng rpId không gạch Account — passkey tự thêm origin mới; origin lạ khác không đi kèm được.
#[test]
fn passkey_adds_a_new_origin_of_its_rp_id() {
    let mut env = Env::new();
    let usd = env.mint(TOKEN, 6);
    let dave = Passkey::new("dave");
    open_dave(&mut env, &dave, ORIGIN);
    let shop = "https://shop.scaas.test";
    let mut op = env.keyop(&dave.account(), ADD_ORIGIN);
    op.origin = shop.into();
    expect_err(manage_passkey(&mut env, &dave, op.clone(), "https://other.scaas.test"), E::UnknownOrigin);
    ok(manage_passkey(&mut env, &dave, op, shop));
    assert_eq!(env.subject(&dave.account()).origins, vec![ORIGIN.to_string(), shop.to_string()]);
    env.fund(&dave.account(), &usd, TOKEN, 5);
    let bob = Ed::new("bob").pubkey();
    let args = env.args(&bob, 5, 1, 1, 0, 1000);
    ok(pay_passkey(&mut env, &dave, &usd, &args, shop, 5, false));
    // removing origins: never the last one while a P-256 key remains
    let mut op = env.keyop(&dave.account(), REMOVE_ORIGIN);
    op.origin = ORIGIN.into();
    ok(manage_passkey(&mut env, &dave, op, shop));
    let mut op = env.keyop(&dave.account(), REMOVE_ORIGIN);
    op.origin = shop.into();
    expect_err(manage_passkey(&mut env, &dave, op, shop), E::WouldBrick);
}

fn open_ed(env: &mut Env, who: &Ed) {
    let kp = who.kp();
    ok(env.send(&[env.open_ix(&who.pubkey())], &[&kp]));
}

#[test]
fn keys_are_added_used_removed_and_never_all_gone() {
    let mut env = Env::new();
    let usd = env.mint(TOKEN, 6);
    let alice = Ed::new("alice");
    let seed = Ed::new("alice-seed");
    open_ed(&mut env, &alice);
    let acct = alice.account();
    let mut op = env.keyop(&acct, ADD_KEY);
    op.key = seed.key();
    ok(env.manage(&acct, &alice, 0, op.clone(), None));
    expect_err(env.manage(&acct, &alice, 0, op, None), E::BadNonce);
    assert_eq!(env.subject(&acct).keys, vec![alice.key(), seed.key()]);
    // the added key signs a payment (key index 1)
    env.fund(&acct, &usd, TOKEN, 10);
    let bob = Ed::new("bob").pubkey();
    let args = env.args(&bob, 4, 1, 1, 0, 1000);
    let dg = env.metaop_digest(&acct, &usd, A::OP_PAY, &alice.pk(), &args);
    let ix = env.pay_ix(&alice.pk(), &usd, TOKEN, ata(&acct, &usd, &TOKEN), &args, auth(A::KIND_OCMS, 1, 0, 0));
    ok(env.send(&[ed_ix(&[seed.sign(A::KIND_OCMS, A::METAOP_LABEL, &dg)]), ix], &[]));
    // the seed key removes the wallet key; then the last key cannot go
    let mut op = env.keyop(&acct, REMOVE_KEY);
    op.key = alice.key();
    ok(env.manage(&acct, &seed, 1, op, None));
    let mut op = env.keyop(&acct, REMOVE_KEY);
    op.key = seed.key();
    expect_err(env.manage(&acct, &seed, 0, op, None), E::WouldBrick);
    // a removed key signs nothing any more
    let op = env.keyop(&acct, CANCEL_RECOVERY);
    expect_err(env.manage(&acct, &alice, 0, op, None), E::BadSignature);
    // malformed keys are refused
    let mut op = env.keyop(&acct, ADD_KEY);
    op.key = AuthKey { scheme: 9, ..alice.key() };
    expect_err(env.manage(&acct, &seed, 0, op, None), E::BadKey);
}

fn guardian_ixs(env: &Env, guardian: &Pubkey, subject: &Pubkey, key: AuthKey) -> (Instruction, Instruction) {
    let start = Instruction {
        program_id: scaas::ID,
        accounts: scaas::accounts::StartRecovery { guardian: *guardian, subject: *subject, system_program: SYSTEM }.to_account_metas(None),
        data: scaas::instruction::StartRecovery { key, origin: String::new() }.data(),
    };
    let finish = Instruction {
        program_id: scaas::ID,
        accounts: scaas::accounts::FinishRecovery { subject: *subject }.to_account_metas(None),
        data: scaas::instruction::FinishRecovery {}.data(),
    };
    let _ = env;
    (start, finish)
}

/// Guardian khởi động khôi phục (tx native), chờ 2 ngày; khoá hiện có huỷ được; sau trễ khoá mới được THÊM, không khoá
/// nào bị xoá (CTR-ACC-03, owner ruling 2026-10-28, như EVM / Sui / Aptos): chủ vẫn ký được và thấy khoá mới.
#[test]
fn guardian_recovery_waits_and_can_be_cancelled() {
    let mut env = Env::new();
    let alice = Ed::new("alice");
    let guardian = Keypair::new();
    env.svm.airdrop(&guardian.pubkey(), 1_000_000_000).unwrap();
    open_ed(&mut env, &alice);
    let acct = alice.account();
    let mut op = env.keyop(&acct, SET_GUARDIAN);
    op.guardian = guardian.pubkey().to_bytes();
    ok(env.manage(&acct, &alice, 0, op, None));
    let fresh = Ed::new("alice-new");
    let (start, finish) = guardian_ixs(&env, &guardian.pubkey(), &acct, fresh.key());
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), 1_000_000_000).unwrap();
    let (bad_start, _) = guardian_ixs(&env, &stranger.pubkey(), &acct, fresh.key());
    expect_err(env.send_as(&stranger, &[bad_start], &[]), E::NotGuardian);
    ok(env.send_as(&guardian, &[start.clone()], &[]));
    expect_err(env.send(&[finish.clone()], &[]), E::TooEarly);
    ok(env.manage(&acct, &alice, 0, env.keyop(&acct, CANCEL_RECOVERY), None));
    env.set_time(NOW + 3 * 86_400);
    expect_err(env.send(&[finish.clone()], &[]), E::NoRecovery);
    ok(env.send_as(&guardian, &[start], &[]));
    expect_err(env.send(&[finish.clone()], &[]), E::TooEarly);
    env.set_time(NOW + 5 * 86_400 + 1);
    ok(env.send(&[finish], &[]));
    assert_eq!(env.subject(&acct).keys, vec![alice.key(), fresh.key()], "recovery adds a key and removes none");
    // the owner's key still signs (at the bumped key nonce: a lifecycle op signed before the recovery is void)
    let later = |env: &Env| scaas::KeyOp { valid_until: (NOW + 6 * 86_400) as u64, ..env.keyop(&acct, SET_GUARDIAN) };
    ok(env.manage(&acct, &alice, 0, later(&env), None));
    ok(env.manage(&acct, &fresh, 1, later(&env), None));
}

/// Owner OQ1 (mặc định TẮT): bật khi chưa có backup ⇒ từ chối; bật rồi thì không xoá được backup cuối, nhưng thay
/// guardian (kể cả guardian bị lộ) vẫn được.
#[test]
fn backup_policy_is_opt_in_and_guards_removal() {
    let mut env = Env::new();
    let alice = Ed::new("alice");
    open_ed(&mut env, &alice);
    let acct = alice.account();
    assert_eq!(env.subject(&acct).policy, 0, "off by default");
    let mut on = env.keyop(&acct, SET_POLICY);
    on.policy = POLICY_BACKUP_REQUIRED;
    expect_err(env.manage(&acct, &alice, 0, on.clone(), None), E::NoBackup);
    let g1 = Keypair::new();
    let mut op = env.keyop(&acct, SET_GUARDIAN);
    op.guardian = g1.pubkey().to_bytes();
    ok(env.manage(&acct, &alice, 0, op, None));
    on.nonce += 1;
    ok(env.manage(&acct, &alice, 0, on, None));
    let mut op = env.keyop(&acct, SET_GUARDIAN);
    expect_err(env.manage(&acct, &alice, 0, op.clone(), None), E::NoBackup);
    op.guardian = Keypair::new().pubkey().to_bytes();
    ok(env.manage(&acct, &alice, 0, op, None));
    let mut bad = env.keyop(&acct, SET_POLICY);
    bad.policy = 2;
    expect_err(env.manage(&acct, &alice, 0, bad, None), E::BadPolicy);
    let off = env.keyop(&acct, SET_POLICY);
    ok(env.manage(&acct, &alice, 0, off, None));
    ok(env.manage(&acct, &alice, 0, env.keyop(&acct, SET_GUARDIAN), None));
}

/// L7: lamports gửi nhầm vào PDA rút được (giữ mức rent-exempt).
#[test]
fn stray_lamports_are_withdrawn_by_keyop() {
    let mut env = Env::new();
    let alice = Ed::new("alice");
    open_ed(&mut env, &alice);
    let acct = alice.account();
    let before = env.lamports(&acct);
    env.svm.airdrop(&acct, 5_000_000).unwrap();
    let to = Keypair::new().pubkey();
    let mut op = env.keyop(&acct, WITHDRAW_LAMPORTS);
    op.to = to.to_bytes();
    expect_err(env.manage(&acct, &alice, 0, op.clone(), Some(Keypair::new().pubkey())), E::WrongRecipient);
    ok(env.manage(&acct, &alice, 0, op, Some(to)));
    assert_eq!((env.lamports(&acct), env.lamports(&to)), (before, 5_000_000));
}

/// `open` chỉ do chính ví ký: không ai mở trước được id passkey bằng một khoá ed25519 (gạch Account passkey).
#[test]
fn open_needs_the_wallet_signature() {
    let mut env = Env::new();
    let alice = Ed::new("alice");
    let mut ix = env.open_ix(&alice.pubkey());
    ix.accounts[1].is_signer = false;
    assert!(env.send(&[ix], &[]).is_err());
    open_ed(&mut env, &alice);
    let kp = alice.kp();
    expect_err(env.send(&[env.open_ix(&alice.pubkey())], &[&kp]), E::AlreadyOpen);
}

fn prune_ix(target: Pubkey, rent_payer: Pubkey) -> Instruction {
    Instruction {
        program_id: scaas::ID,
        accounts: scaas::accounts::Prune { target, rent_payer }.to_account_metas(None),
        data: scaas::instruction::Prune {}.data(),
    }
}

/// RS12-6 + review C1: prune không cần quyền, chỉ sau `valid_until + PRUNE_DELAY_S`, rent về đúng `rent_payer`.
#[test]
fn prune_returns_rent_to_the_lane_after_the_delay_only() {
    let mut env = Env::new();
    let usd = env.mint(TOKEN, 6);
    let alice = Ed::new("alice");
    env.fund(&alice.account(), &usd, TOKEN, 100);
    let bob = Ed::new("bob").pubkey();
    let args = env.args(&bob, 10, 1, 7, 0, 900);
    ok(env.pay(&alice, &usd, TOKEN, &args));
    let lane_pda = pda(&[b"lane", alice.account().as_ref(), &[7; 32]]);
    let rent = env.lamports(&lane_pda);
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), 1_000_000_000).unwrap();
    expect_err(env.send_as(&stranger, &[prune_ix(lane_pda, env.lane.pubkey())], &[]), E::TooEarly);
    env.set_time(901);
    expect_err(env.send_as(&stranger, &[prune_ix(lane_pda, env.lane.pubkey())], &[]), E::TooEarly);
    let due = 900 + scaas::PRUNE_DELAY_S;
    env.set_time(due);
    expect_err(env.send_as(&stranger, &[prune_ix(lane_pda, env.lane.pubkey())], &[]), E::TooEarly);
    env.set_time(due + 1);
    expect_err(env.send_as(&stranger, &[prune_ix(lane_pda, stranger.pubkey())], &[]), E::WrongRentPayer);
    let lane_before = env.lamports(&env.lane.pubkey());
    ok(env.send_as(&stranger, &[prune_ix(lane_pda, env.lane.pubkey())], &[]));
    assert!(!env.exists(&lane_pda));
    assert_eq!(env.lamports(&env.lane.pubkey()), lane_before + rent);
    expect_err(env.pay(&alice, &usd, TOKEN, &args), E::Expired);
    // nothing else is prunable
    expect_err(env.send_as(&stranger, &[prune_ix(env.config(), env.lane.pubkey())], &[]), E::NotPrunable);
}

/// Review C1: Odoo re-issues terms for ONE request on the same lane, nonce 0, with a later `valid_until` (≤ creation +
/// LANE_HORIZON_S). Only one of the two signed ops can ever run — while the lane PDA lives (BadNonce) and after it is
/// pruned (op2 expired by then, since PRUNE_DELAY_S ≥ the horizon).
#[test]
fn two_signed_ops_for_one_request_pay_once_before_and_after_prune() {
    assert_eq!(scaas::PRUNE_DELAY_S, 2_592_000, "must stay >= Odoo LANE_HORIZON_S");
    let mut env = Env::new();
    let usd = env.mint(TOKEN, 6);
    let alice = Ed::new("alice");
    let src = env.fund(&alice.account(), &usd, TOKEN, 100);
    let bob = Ed::new("bob").pubkey();
    let op1 = env.args(&bob, 10, 1, 7, 0, 900);
    // worst case: op2 issued at the very end of the horizon, measured from op1's own deadline
    let op2 = env.args(&bob, 10, 1, 7, 0, 900 + scaas::PRUNE_DELAY_S as u64);
    ok(env.pay(&alice, &usd, TOKEN, &op1));
    expect_err(env.pay(&alice, &usd, TOKEN, &op2), E::BadNonce);
    let lane_pda = pda(&[b"lane", alice.account().as_ref(), &[7; 32]]);
    let lane = env.lane.pubkey();
    for t in [901, 900 + scaas::PRUNE_DELAY_S] {
        env.set_time(t);
        expect_err(env.send(&[prune_ix(lane_pda, lane)], &[]), E::TooEarly);
        expect_err(env.pay(&alice, &usd, TOKEN, &op2), E::BadNonce);
    }
    env.set_time(901 + scaas::PRUNE_DELAY_S);
    ok(env.send(&[prune_ix(lane_pda, lane)], &[]));
    expect_err(env.pay(&alice, &usd, TOKEN, &op2), E::Expired);
    assert_eq!(env.balance(&src), 90, "paid exactly once");
}

/// CTR-ACC-11 (P4): the account type is `SmartKeyAccount`; Anchor's discriminator follows the name. A deployed program
/// is immutable (upgrade authority None, NET-SOL-20), so no `SubjectAccount` data ever meets this code: a new build is
/// a new deployment. The PDA (`["acct", owner]`) and its layout are unchanged.
#[test]
fn smart_key_account_discriminator_follows_the_name() {
    use sha2::{Digest, Sha256};
    let d = <scaas::state::SmartKeyAccount as anchor_lang::Discriminator>::DISCRIMINATOR;
    assert_eq!(d, &Sha256::digest(b"account:SmartKeyAccount")[..8]);
    assert_ne!(d, &Sha256::digest(b"account:SubjectAccount")[..8]);
}
