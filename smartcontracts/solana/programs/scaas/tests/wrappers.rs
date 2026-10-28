//! CTR-MTX-27 static wrappers `relay_fee_<entry>` (owner 2026-10-27, as Sui / Aptos): for each fee-less signed entry
//! of `scaas`, the entry runs in-process, then the router-bound payment; `ref` commits to the entry's call as if sent
//! alone (declared accounts, discriminator ‖ Borsh arguments, its `auth` included) and the salt `args.extra`.
mod common;

use anchor_lang::prelude::Pubkey;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::{InstructionData, ToAccountMetas};
use scaas::auth::{self as A, Auth};
use scaas::ScaasError as E;
use common::flows::*;
use common::vectors as V;
use common::*;
use solana_keypair::Keypair;
use solana_signer::Signer;

const FUNDS: u64 = 1_000;
const MANDATE_SEED: [u8; 32] = [0x0d; 32];

struct W {
    env: Env,
    alice: Ed,
    delegate: Ed,
    usd: Pubkey,
    market: Pubkey,
    mandate: Pubkey,
}

/// Alice (Account open, 1,000 USD), a USD/EUR market, a mandate of Alice holding 5 USD.
fn world() -> W {
    let mut env = Env::new();
    let (usd, eur) = (env.mint(TOKEN, 6), env.mint(TOKEN, 6));
    let (alice, delegate) = (Ed::new("alice"), Ed::new("delegate"));
    let kp = alice.kp();
    ok(env.send(&[env.open_ix(&alice.pubkey())], &[&kp]));
    env.fund(&alice.account(), &usd, TOKEN, FUNDS);
    ok(env.list_market(&usd, &eur, 0, &Keypair::new().pubkey()));
    let init = env.mandate_init(&alice.account(), MANDATE_SEED, &usd, &delegate, vec![]);
    ok(env.mandate_open(&alice, &init));
    let mandate = mandate_addr(&alice.account(), MANDATE_SEED);
    env.fund(&mandate, &usd, TOKEN, 5);
    W { env, alice, delegate, usd, market: market_addr(&usd, &eur), mandate }
}

/// The inner entry's call as if sent alone: data (discriminator ‖ Borsh args, `auth` = precompile 0, entry 1),
/// declared accounts (`n` of the struct, then its remaining accounts), the inner signature.
struct Inner {
    name: &'static str,
    data: Vec<u8>,
    metas: Vec<AccountMeta>,
    n: usize,
    sig: Entry,
}

fn inner_auth() -> Auth {
    auth(A::KIND_RAW, 0, 0, 1)
}

type Effect = Box<dyn Fn(&W) -> bool>;

fn manage(w: &W, signer: &Ed) -> (Inner, Effect) {
    let acct = w.alice.account();
    let mut op = w.env.keyop(&acct, scaas::ADD_KEY);
    op.key = Ed::new("bob").key();
    let metas = scaas::accounts::ManageSigned { lane: w.env.lane.pubkey(), config: w.env.config(), subject: acct, to: None, instructions: IXS, system_program: SYSTEM }
        .to_account_metas(None);
    let sig = signer.sign(A::KIND_RAW, A::KEYOP_LABEL, &w.env.keyop_digest(&acct, &op));
    let data = scaas::instruction::ManageSigned { op, auth: inner_auth() }.data();
    (Inner { name: "manage_signed", data, n: metas.len(), metas, sig }, Box::new(|w: &W| w.env.subject(&w.alice.account()).keys.len() == 2))
}

fn mandate_open_call(w: &W, signer: &Ed) -> (Inner, Effect) {
    let acct = w.alice.account();
    let init = w.env.mandate_init(&acct, [0x0e; 32], &w.usd, &w.delegate, vec![]);
    let m = mandate_addr(&acct, [0x0e; 32]);
    let metas = scaas::accounts::MandateOpen { lane: w.env.lane.pubkey(), config: w.env.config(), subject: acct, mandate: m, instructions: IXS, system_program: SYSTEM }
        .to_account_metas(None);
    let sig = signer.sign(A::KIND_RAW, A::MANDATE_LABEL, &sha(&[&init.bytes(&w.env.network, &acct, &m)]));
    let data = scaas::instruction::MandateOpen { init, auth: inner_auth() }.data();
    (Inner { name: "mandate_open", data, n: metas.len(), metas, sig }, Box::new(move |w: &W| w.env.exists(&m)))
}

fn revoke(w: &W, signer: &Ed) -> (Inner, Effect) {
    let op = scaas::auth::MetaOp {
        network: w.env.network,
        contract: w.mandate.to_bytes(),
        asset: [0; 32],
        op: A::OP_REVOKE,
        from: w.alice.pk(),
        to: [0; 32],
        amount: 0,
        pay_ref: [0; 32],
        lane: [0; 32],
        nonce: w.env.generation(&w.mandate),
        valid_until: 1000,
        relayer: [0; 32],
        extra: [0; 32],
    };
    let metas = scaas::accounts::MandateRevoke { lane: w.env.lane.pubkey(), config: w.env.config(), mandate: w.mandate, instructions: IXS }.to_account_metas(None);
    let sig = signer.sign(A::KIND_RAW, A::METAOP_LABEL, &op.digest());
    let data = scaas::instruction::MandateRevokeSigned { valid_until: 1000, auth: inner_auth() }.data();
    let effect = |w: &W| w.env.account::<scaas::state::Mandate>(&w.mandate).is_some_and(|m| m.revoked);
    (Inner { name: "mandate_revoke_signed", data, n: metas.len(), metas, sig }, Box::new(effect))
}

fn close(w: &W, signer: &Ed) -> (Inner, Effect) {
    let acct = w.alice.account();
    let nonce = w.env.subject(&acct).key_nonce;
    let dg = sha(&[A::MCLOSE_LABEL.as_bytes(), &w.env.network, acct.as_ref(), w.mandate.as_ref(), &nonce.to_le_bytes(), &1000u64.to_le_bytes()]);
    let mut metas = scaas::accounts::MandateClose {
        lane: w.env.lane.pubkey(),
        config: w.env.config(),
        subject: acct,
        mandate: w.mandate,
        rent_payer: w.env.account::<scaas::state::Mandate>(&w.mandate).unwrap().rent_payer,
        instructions: IXS,
    }
    .to_account_metas(None);
    let n = metas.len();
    let (src, dst) = (ata(&w.mandate, &w.usd, &TOKEN), ata(&acct, &w.usd, &TOKEN));
    metas.extend([AccountMeta::new(src, false), AccountMeta::new_readonly(w.usd, false), AccountMeta::new(dst, false), AccountMeta::new_readonly(TOKEN, false)]);
    let sig = signer.sign(A::KIND_RAW, A::MCLOSE_LABEL, &dg);
    let data = scaas::instruction::MandateCloseSigned { nonce, valid_until: 1000, auth: inner_auth() }.data();
    (Inner { name: "mandate_close_signed", data, n, metas, sig }, Box::new(|w: &W| !w.env.exists(&w.mandate)))
}

fn cancel(w: &W, signer: &Ed) -> (Inner, Effect) {
    cancel_nonce(w, signer, 1)
}

fn cancel_nonce(w: &W, signer: &Ed, nonce: u64) -> (Inner, Effect) {
    let o = order(&w.alice, &w.usd, &market_quote(w), 10, 10, nonce);
    let h = w.env.order_hash(&w.market, &o);
    let fill = pda(&[b"fill", w.market.as_ref(), &h]);
    let metas = scaas::accounts::CancelSigned {
        lane: w.env.lane.pubkey(),
        config: w.env.config(),
        market: w.market,
        subject: w.alice.account(),
        fill,
        instructions: IXS,
        system_program: SYSTEM,
    }
    .to_account_metas(None);
    let sig = signer.sign(A::KIND_RAW, A::CANCEL_LABEL, &sha(&[A::CANCEL_LABEL.as_bytes(), &w.env.network, w.market.as_ref(), &h]));
    let data = scaas::instruction::CancelSigned { order: o, order_hash: h, auth: inner_auth() }.data();
    let effect = move |w: &W| w.env.account::<scaas::state::Fill>(&fill).is_some_and(|f| f.filled == 10);
    (Inner { name: "cancel_signed", data, n: metas.len(), metas, sig }, Box::new(effect))
}

fn market_quote(w: &W) -> Pubkey {
    w.env.account::<scaas::state::Market>(&w.market).unwrap().quote_mint
}

fn invalidate(w: &W, signer: &Ed) -> (Inner, Effect) {
    invalidate_n(w, signer, 5)
}

fn invalidate_n(w: &W, signer: &Ed, n: u64) -> (Inner, Effect) {
    let acct = w.alice.account();
    let mn = pda(&[b"minnonce", w.market.as_ref(), acct.as_ref()]);
    let metas = scaas::accounts::InvalidateNonces {
        lane: w.env.lane.pubkey(),
        config: w.env.config(),
        market: w.market,
        subject: acct,
        min_nonce: mn,
        instructions: IXS,
        system_program: SYSTEM,
    }
    .to_account_metas(None);
    let dg = sha(&[A::MINNONCE_LABEL.as_bytes(), &w.env.network, w.market.as_ref(), acct.as_ref(), &n.to_le_bytes()]);
    let sig = signer.sign(A::KIND_RAW, A::MINNONCE_LABEL, &dg);
    let data = scaas::instruction::InvalidateNoncesSigned { min_nonce: n, auth: inner_auth() }.data();
    let effect = move |w: &W| w.env.account::<scaas::state::MinNonce>(&mn).is_some_and(|m| m.min_nonce == n);
    (Inner { name: "invalidate_nonces_signed", data, n: metas.len(), metas, sig }, Box::new(effect))
}

type Mk = fn(&W, &Ed) -> (Inner, Effect);

/// Every wrapper with the inner signer of its entry (Alice, or the delegate for the revoke) and the exact error of a
/// replay: the entry's own replay guard when it has one (KeyOp / min-nonce `BadNonce`, the mandate PDA already in use
/// (System `AccountAlreadyInUse` = 0), the closed mandate (`AccountNotInitialized`)), and for the revoke and cancel,
/// idempotent entries, the wrapper's no-op refusal (`RelayCallNoOp`: no fee for a no-op, owner ruling 2026-10-28).
fn cases() -> Vec<(Mk, bool, u32)> {
    let bad_nonce = code(E::BadNonce);
    let not_init = anchor_lang::error::ErrorCode::AccountNotInitialized as u32;
    let no_op = code(E::RelayCallNoOp);
    vec![(manage, false, bad_nonce), (mandate_open_call, false, 0), (revoke, true, no_op), (close, false, not_init),
         (cancel, false, no_op), (invalidate, false, bad_nonce)]
}

/// One rule (owner ruling 2026-10-28, as Sui / Aptos `ECALL_REFUSED` and TON's refund): no fee for a no-op. A revoke of
/// a mandate already revoked, or a cancel of an order already closed (here: by an earlier relay; a front-run is the
/// same state), is refused by the wrapper with a fresh payment too, and the payer is not charged.
#[test]
fn wrapper_noop_refused_payer_not_charged() {
    for (mk, delegate_signs) in [(revoke as Mk, true), (cancel as Mk, false)] {
        let mut w = world();
        let signer = if delegate_signs { Ed::new("delegate") } else { Ed::new("alice") };
        let (inner, effect) = mk(&w, &signer);
        let lane = w.env.lane.pubkey();
        let first = pay_args(&w, &inner, 7, None, [1; 32]);
        ok(send(&mut w, &inner, &Ed::new("alice"), &first, lane));
        assert!(effect(&w), "{}: the real call ran and was paid", inner.name);
        let before = payer_balance(&w);
        let again = pay_args(&w, &inner, 7, None, [2; 32]);
        expect_err(send(&mut w, &inner, &Ed::new("alice"), &again, lane), E::RelayCallNoOp);
        assert_eq!(payer_balance(&w), before, "{}: the no-op is not charged", inner.name);
        assert!(!w.env.exists(&pda(&[b"lane", w.alice.account().as_ref(), &again.lane])), "{}", inner.name);
    }
}

fn marker() -> Pubkey {
    pda(&[b"relayfee"])
}

/// The payment for `inner` (open mode unless `to` is given), `ref` over the inner call.
fn pay_args(w: &W, inner: &Inner, amount: u64, to: Option<Pubkey>, salt: [u8; 32]) -> scaas::PayArgs {
    let mut metas = inner.metas.clone();
    metas[0].pubkey = marker(); // the lane slot hashes as the marker: any lane may submit
    let call = scaas::relay_call(&scaas::ID, &metas, &inner.data);
    let r = scaas::relay_ref(&w.env.network, &scaas::ID, &call, &salt);
    let m = marker().to_bytes();
    scaas::PayArgs { to: to.map_or(m, |t| t.to_bytes()), amount, pay_ref: r, lane: scaas::pay_lane(&r), nonce: 0, valid_until: 1000, relayer: m, extra: salt }
}

/// `relay_fee_<entry>`: data = discriminator ‖ the entry's Borsh args ‖ owner ‖ args ‖ pay auth; accounts = the
/// entry's struct, `relay_pay`'s, the entry's remaining.
fn wrapper_ix(w: &W, inner: &Inner, payer: &Ed, args: &scaas::PayArgs, recipient: Pubkey) -> Instruction {
    use anchor_lang::prelude::borsh;
    let mut data = sha(&[format!("global:relay_fee_{}", inner.name).as_bytes()])[..8].to_vec();
    data.extend_from_slice(&inner.data[8..]);
    data.extend_from_slice(&payer.pk());
    data.extend(borsh::to_vec(args).unwrap());
    data.extend(borsh::to_vec(&auth(A::KIND_RAW, 0, 0, 0)).unwrap());
    let mut accounts = inner.metas[..inner.n].to_vec();
    let src = ata(&payer.account(), &w.usd, &TOKEN);
    accounts.extend(w.env.pay_accounts(&payer.pk(), &w.usd, TOKEN, src, &args.lane, recipient).to_account_metas(None));
    accounts.extend_from_slice(&inner.metas[inner.n..]);
    Instruction { program_id: scaas::ID, accounts, data }
}

fn send(w: &mut W, inner: &Inner, payer: &Ed, args: &scaas::PayArgs, recipient: Pubkey) -> Res {
    let ix = wrapper_ix(w, inner, payer, args, recipient);
    let dg = w.env.metaop_digest(&payer.account(), &w.usd, A::OP_PAY, &payer.pk(), args);
    let pay_sig = payer.sign(A::KIND_RAW, A::METAOP_LABEL, &dg);
    w.env.send(&[ed_ix(&[pay_sig, inner.sig.clone()]), ix], &[])
}

fn payer_balance(w: &W) -> u64 {
    w.env.balance(&ata(&w.alice.account(), &w.usd, &TOKEN))
}

#[test]
fn wrapper_settles_and_pays() {
    for (mk, delegate_signs, replay) in cases() {
        let mut w = world();
        let signer = if delegate_signs { Ed::new("delegate") } else { Ed::new("alice") };
        let (inner, effect) = mk(&w, &signer);
        let lane = w.env.lane.pubkey();
        let args = pay_args(&w, &inner, 7, None, [1; 32]);
        let before = payer_balance(&w);
        let m = match send(&mut w, &inner, &Ed::new("alice"), &args, lane) {
            Ok(m) => m,
            Err(f) => panic!("{}: {:?}\n{}", inner.name, f.err, f.meta.logs.join("\n")),
        };
        eprintln!("relay_fee_{}: {} CU", inner.name, m.compute_units_consumed);
        assert!(effect(&w), "{}", inner.name);
        assert_eq!(w.env.balance(&ata(&lane, &w.usd, &TOKEN)), 7, "{}", inner.name);
        // the mandate close sweeps 5 USD into the payer's account in the same transaction
        let swept = if inner.name == "mandate_close_signed" { 5 } else { 0 };
        assert_eq!(payer_balance(&w), before + swept - 7, "{}", inner.name);
        let ev = m.inner_instructions.iter().flatten().map(|i| i.instruction.data.clone())
            .filter(|d| d.starts_with(&anchor_lang::event::EVENT_IX_TAG_LE)).collect::<Vec<_>>();
        let last = ev.last().unwrap();
        assert_eq!(&last[8..16], <scaas::RelayFeePaid as anchor_lang::Discriminator>::DISCRIMINATOR);
        assert_eq!(&last[16 + 32..16 + 64], &args.pay_ref[..], "{}", inner.name);
        assert_eq!(&last[16 + 64..16 + 96], scaas::ID.as_ref(), "target = scaas");
        // replay of the same transaction: refused, nothing moves
        let res = send(&mut w, &inner, &Ed::new("alice"), &args, lane);
        assert_eq!(custom(&res), Some(replay), "{} replayed: {:?}", inner.name, res.map(|m| m.logs));
        assert_eq!(w.env.balance(&ata(&lane, &w.usd, &TOKEN)), 7);
    }
}

#[test]
fn wrapper_bound_payee() {
    let mut w = world();
    let bob = Ed::new("bob").pubkey();
    let (inner, effect) = invalidate(&w, &Ed::new("alice"));
    let args = pay_args(&w, &inner, 3, Some(bob), [2; 32]);
    let lane = w.env.lane.pubkey();
    expect_err(send(&mut w, &inner, &Ed::new("alice"), &args, lane), E::WrongRecipient);
    ok(send(&mut w, &inner, &Ed::new("alice"), &args, bob));
    assert!(effect(&w));
    assert_eq!(w.env.balance(&ata(&bob, &w.usd, &TOKEN)), 3);
}

/// The inner entry fails (another key signed it): no payment, no pay lane.
#[test]
fn wrapper_inner_failure_leaves_no_payment() {
    for (mk, _, _) in cases() {
        let mut w = world();
        let (inner, effect) = mk(&w, &Ed::new("stranger"));
        let lane = w.env.lane.pubkey();
        let args = pay_args(&w, &inner, 7, None, [3; 32]);
        let res = send(&mut w, &inner, &Ed::new("alice"), &args, lane);
        assert!(custom(&res).is_some(), "{}: {:?}", inner.name, res.map(|m| m.logs));
        assert!(!effect(&w), "{}", inner.name);
        assert_eq!(payer_balance(&w), FUNDS, "{}", inner.name);
        assert!(!w.env.exists(&pda(&[b"lane", w.alice.account().as_ref(), &args.lane])), "{}", inner.name);
    }
}

/// The payment fails after the inner entry ran (over the balance, a stranger's payment signature): the entry is
/// rolled back.
#[test]
fn wrapper_payment_failure_rolls_back_the_call() {
    for (mk, delegate_signs, _) in cases() {
        let mut w = world();
        let signer = if delegate_signs { Ed::new("delegate") } else { Ed::new("alice") };
        let (inner, effect) = mk(&w, &signer);
        let lane = w.env.lane.pubkey();
        let args = pay_args(&w, &inner, FUNDS + 100, None, [4; 32]);
        assert!(send(&mut w, &inner, &Ed::new("alice"), &args, lane).is_err(), "{}", inner.name);
        assert!(!effect(&w), "{}", inner.name);
        let args = pay_args(&w, &inner, 7, None, [4; 32]);
        let ix = wrapper_ix(&w, &inner, &Ed::new("alice"), &args, lane);
        let dg = w.env.metaop_digest(&w.alice.account(), &w.usd, A::OP_PAY, &w.alice.pk(), &args);
        let stranger = Ed::new("stranger").sign(A::KIND_RAW, A::METAOP_LABEL, &dg);
        expect_err(w.env.send(&[ed_ix(&[stranger, inner.sig.clone()]), ix], &[]), E::BadSignature);
        assert!(!effect(&w), "{}", inner.name);
        assert_eq!(payer_balance(&w), FUNDS, "{}", inner.name);
    }
}

/// A wrapper's router-bound payment never settles through `relay_pay` / `relay_pay_meta`; a payment bound to
/// another call (salt, inner arguments) is refused by the wrapper.
#[test]
fn wrapper_router_bound_pay_refused_direct() {
    let mut w = world();
    let (inner, _) = cancel(&w, &Ed::new("alice"));
    let args = pay_args(&w, &inner, 7, Some(Ed::new("bob").pubkey()), [5; 32]);
    expect_err(w.env.pay(&Ed::new("alice"), &w.usd, TOKEN, &args), E::WrongRelayer);
    let meta = b"note".to_vec();
    let mut ma = args.clone();
    ma.pay_ref = scaas::meta_pay_id(&[5; 32], &meta);
    ma.lane = scaas::pay_lane(&ma.pay_ref);
    let usd = w.usd;
    expect_err(w.env.pay_meta(&Ed::new("alice"), &usd, TOKEN, &ma, [5; 32], &meta), E::WrongRelayer);
    let lane = w.env.lane.pubkey();
    let mut other = args.clone();
    other.extra = [6; 32];
    expect_err(send(&mut w, &inner, &Ed::new("alice"), &other, lane), E::RelayFeeShape);
    let (inv, _) = invalidate(&w, &Ed::new("alice"));
    let wrong = pay_args(&w, &inv, 7, None, [5; 32]);
    expect_err(send(&mut w, &inner, &Ed::new("alice"), &wrong, lane), E::RelayFeeShape);
    assert_eq!(payer_balance(&w), FUNDS);
}

/// Vector: the wrapper `ref` preimage (`gen_vectors.py` `relay_fee_vectors`) and the declared flags it uses; the
/// hand-built wrapper data equals Anchor's (sha256 pinned in the scaas-node adapter test too).
#[test]
fn wrapper_ref_vectors() {
    let k = |name: &str| Pubkey::new_from_array(sha(&[name.as_bytes()]));
    let metas = scaas::accounts::InvalidateNonces {
        lane: k("wrap.lane"),
        config: k("wrap.config"),
        market: k("wrap.market"),
        subject: k("wrap.subject"),
        min_nonce: k("wrap.min_nonce"),
        instructions: IXS,
        system_program: SYSTEM,
    }
    .to_account_metas(None);
    let data = scaas::instruction::InvalidateNoncesSigned { min_nonce: 5, auth: auth(A::KIND_RAW, 0, 2, 0) }.data();
    let call = scaas::wrapper_call(&metas, &data);
    assert_eq!(call, hexd(V::WRAP_CALL));
    // the lane slot is the marker whatever lane is passed (flags as declared)
    let mut with_marker = metas.clone();
    with_marker[0].pubkey = marker();
    assert_eq!(scaas::relay_call(&scaas::ID, &with_marker, &data), call);
    assert!(metas[0].is_signer && metas[0].is_writable);
    let salt: [u8; 32] = hexd(V::WRAP_SALT).try_into().unwrap();
    let r = scaas::relay_ref(&pk(V::NETWORK).to_bytes(), &scaas::ID, &call, &salt);
    assert_eq!((r.to_vec(), scaas::pay_lane(&r).to_vec()), (hexd(V::WRAP_REF), hexd(V::WRAP_LANE)));
    // the wrapper's instruction data as the node builds it
    let m = marker().to_bytes();
    let args = scaas::PayArgs { to: m, amount: 100, pay_ref: r, lane: scaas::pay_lane(&r), nonce: 0, valid_until: 1000, relayer: m, extra: salt };
    let d = scaas::instruction::RelayFeeInvalidateNoncesSigned {
        min_nonce: 5,
        auth: auth(A::KIND_RAW, 0, 2, 0),
        owner: pk(V::ALICE).to_bytes(),
        args,
        pay_auth: auth(A::KIND_RAW, 0, 1, 0),
    }
    .data();
    let hex: String = sha(&[&d]).iter().map(|x| format!("{x:02x}")).collect();
    assert_eq!(hex, "20f4568ccb15c76a7fbdad15b2cf6d2117adfd3a407be9d016f61877af60796a");
}

/// Fix 3: the wrapper `ref` is lane-agnostic. A payment signed once (open mode) settles when a second lane submits
/// it, and that lane is paid.
#[test]
fn wrapper_any_lane_may_submit() {
    for (mk, delegate_signs, _) in cases() {
        let mut w = world();
        let signer = if delegate_signs { Ed::new("delegate") } else { Ed::new("alice") };
        let (first, _) = mk(&w, &signer);
        let args = pay_args(&w, &first, 7, None, [9; 32]);
        let other = Keypair::new();
        w.env.svm.airdrop(&other.pubkey(), 10_000_000_000).unwrap();
        w.env.lane = other;
        let (inner, effect) = mk(&w, &signer);
        assert_eq!(pay_args(&w, &inner, 7, None, [9; 32]), args, "{}: same signed payment", inner.name);
        let lane = w.env.lane.pubkey();
        ok(send(&mut w, &inner, &Ed::new("alice"), &args, lane));
        assert!(effect(&w), "{}", inner.name);
        assert_eq!(w.env.balance(&ata(&w.env.lane.pubkey(), &w.usd, &TOKEN)), 7, "{}", inner.name);
    }
}

/// The same entry, another instance than the payment's: a min-nonce payment for 5 sent with 6, a cancel payment for
/// one order sent with another order (and its own fill) — `RelayFeeShape`.
#[test]
fn wrapper_other_instance_refused() {
    let mut w = world();
    let alice = Ed::new("alice");
    let lane = w.env.lane.pubkey();
    let (five, _) = invalidate_n(&w, &alice, 5);
    let (six, six_done) = invalidate_n(&w, &alice, 6);
    let args = pay_args(&w, &five, 7, None, [1; 32]);
    expect_err(send(&mut w, &six, &alice, &args, lane), E::RelayFeeShape);
    assert!(!six_done(&w));
    let (one, _) = cancel_nonce(&w, &alice, 1);
    let (two, two_done) = cancel_nonce(&w, &alice, 2);
    let args = pay_args(&w, &one, 7, None, [1; 32]);
    expect_err(send(&mut w, &two, &alice, &args, lane), E::RelayFeeShape);
    assert!(!two_done(&w));
    assert_eq!(payer_balance(&w), FUNDS);
}
