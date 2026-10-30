//! T6: the mandate with native and UA holders (spec §5.2, SOR-D9) against the real `UaRegistry`, the real token,
//! in-test ed25519 UAs and the `ua-ops.json` mandate rows. No `mock_all_auths`: a native authority is mocked for
//! exactly one address and invocation (`allow`), a UA signs for real.
extern crate std;
use std::vec::Vec as StdVec;

use super::*;
use ed25519_dalek::Signer as _;
use scaas_token::{Token, TokenClient};
use scaas_ua_common::{h32, UaAttrs, PURPOSE_POP_V2};
use scaas_ua_registry::{UaRegistry, UaRegistryClient as RegClient};
use serde_json::Value;
use soroban_sdk::testutils::{Address as _, Ledger as _, MockAuth, MockAuthInvoke};
use soroban_sdk::xdr::{Limits, ReadXdr as _, ScVal};
use soroban_sdk::{IntoVal, String, Symbol, TryFromVal, Val, Vec as SVec};

const OPS: &str = include_str!("../../../vectors/ua-ops.json");
const NOW: u64 = 1_800_000_000;
const ED25519: u32 = 0x0102;
/// `keccak256("scaas.ua.msg.v1")` and `TAG(ed25519)` (CTR-UA-12, `kinds.json`).
const MSG_TAG: [u8; 32] = h32("30a5cfd6b1d0889ef4a90d8488fa5e6e615322735899e23243d69087b6b66349");
const ED_TAG: [u8; 32] = h32("65ca73d2d290503a4785188712dd0b971b5fbf3113c1dc87185a46021b5131bc");

// ---------- setup ----------

fn hx(v: &Value) -> StdVec<u8> {
    let s = v.as_str().unwrap().trim_start_matches("0x");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn n(env: &Env, a: [u8; 32]) -> BytesN<32> {
    BytesN::from_array(env, &a)
}

fn ops() -> Value {
    serde_json::from_str(OPS).unwrap()
}

/// Mocks exactly `who`'s authorisation of `contract.f(args)` for the next call.
fn allow(env: &Env, who: &Address, contract: &Address, f: &str, args: SVec<Val>) {
    env.mock_auths(&[MockAuth { address: who, invoke: &MockAuthInvoke { contract, fn_name: f, args, sub_invokes: &[] } }]);
}

type Res = Result<(), soroban_sdk::Error>;

/// A failed call with this contract error.
fn ce(e: Error) -> Res {
    Err(e.into())
}

/// The contract error of a failed call.
fn err<V: core::fmt::Debug, C: core::fmt::Debug>(r: Result<V, Result<soroban_sdk::Error, C>>) -> Error {
    match r {
        Err(Ok(e)) => Error::try_from(e).unwrap_or_else(|_| panic!("host error {e:?}")),
        other => panic!("not a contract error: {other:?}"),
    }
}

fn no_attrs(env: &Env) -> UaAttrs {
    UaAttrs { pqz_key: Bytes::new(env), pqz_pop_hash: n(env, [0; 32]), kem_version: 0, kem_pk: Bytes::new(env) }
}

fn keccak(env: &Env, parts: &[&[u8]]) -> [u8; 32] {
    let mut b = Bytes::new(env);
    for p in parts {
        b.extend_from_slice(p);
    }
    env.crypto().keccak256(&b).to_array()
}

/// An in-test ed25519 UA, registered by its real `pop` (CTR-UA-07).
struct Ua {
    sk: ed25519_dalek::SigningKey,
    id: BytesN<32>,
}

impl Ua {
    fn h(&self) -> Holder {
        Holder::Ua(self.id.clone())
    }
}

/// A signer of a mandate entry: a native address (host auth, empty `auth`) or a UA (signature over the op digest).
enum Who<'a> {
    Native(&'a Address),
    Ua(&'a Ua),
}

struct T {
    env: Env,
    t: TokenClient<'static>,
    reg: RegClient<'static>,
    admin: Address,
}

/// The registry, the token (bound to it) at `ua-ops.json`'s ids and network id.
fn base() -> T {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let o = ops();
    env.ledger().with_mut(|l| {
        l.sequence_number = 100;
        l.timestamp = NOW;
        l.network_id = hx(&o["network"]["networkId"]).try_into().unwrap();
    });
    let id = |k: &str| Address::from_str(&env, o["contracts"][k].as_str().unwrap());
    let reg = RegClient::new(&env, &env.register_at(&id("registry"), UaRegistry, (SVec::<Address>::new(&env),)));
    let admin = Address::generate(&env);
    let s = |x: &str| String::from_str(&env, x);
    let t = env.register_at(&id("token"), Token, (admin.clone(), 7u32, s("SCaaS"), s("BMB"), Some(reg.address.clone())));
    T { t: TokenClient::new(&env, &t), reg, admin, env }
}

impl T {
    fn ua(&self, seed: u8) -> Ua {
        let env = &self.env;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let kd = Bytes::from_array(env, &sk.verifying_key().to_bytes());
        let id = self.reg.ua_of(&ED25519, &kd);
        let z = [0u8; 32];
        let reg_digest = keccak(env, &[&keccak(env, &[&PURPOSE_POP_V2, &id.to_array(), &z, &z]), &z]);
        let pop = sk.sign(&keccak(env, &[&MSG_TAG, &ED_TAG, &PURPOSE_POP_V2, &reg_digest])).to_bytes();
        self.reg.register(&ED25519, &kd, &no_attrs(env), &Bytes::from_array(env, &pop), &Bytes::new(env), &None);
        Ua { sk, id }
    }

    /// The mandate at `ua-ops.json`'s id, owned by `owner`, holding `funds` of the token.
    fn mandate(&self, owner: &Holder, funds: i128) -> MandateWalletClient<'static> {
        let env = &self.env;
        let at = Address::from_str(env, ops()["contracts"]["mandate"].as_str().unwrap());
        let w = MandateWalletClient::new(env, &env.register_at(&at, MandateWallet, (owner.clone(), Some(self.reg.address.clone()))));
        allow(env, &self.admin, &self.t.address, "mint", (&w.address, funds).into_val(env));
        self.t.mint(&w.address, &funds);
        w
    }

    /// Calls `w.f(args ‖ auth)` as `who`: a native address by a host-auth mock of exactly that call with an empty
    /// `auth`, a UA by its signature over `op_digest(mandate, f, args)` under `metatx`.
    fn call(&self, w: &MandateWalletClient, who: Who, f: &str, args: SVec<Val>) -> Res {
        let env = &self.env;
        let auth = match who {
            Who::Native(a) => {
                let mut all = args.clone();
                all.push_back(Bytes::new(env).into_val(env));
                allow(env, a, &w.address, f, all);
                Bytes::new(env)
            }
            Who::Ua(u) => {
                let d = scaas_ua_common::op_digest(env, &w.address, f, args.clone()).to_array();
                Bytes::from_array(env, &u.sk.sign(&keccak(env, &[&MSG_TAG, &ED_TAG, &PURPOSE_METATX, &d])).to_bytes())
            }
        };
        let mut all = args;
        all.push_back(auth.into_val(env));
        match env.try_invoke_contract::<(), soroban_sdk::Error>(&w.address, &Symbol::new(env, f), all) {
            Ok(Ok(())) => Ok(()),
            Err(Ok(e)) => Err(e),
            other => panic!("{f}: {other:?}"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn set_mandate(&self, w: &MandateWalletClient, who: Who, delegate: &Holder, per_pay: i128, per_period: i128, period: u64, expiry: u64, lane: u8, nonce: u64) -> Res {
        let a = (&self.t.address, delegate, per_pay, per_period, period, expiry, n(&self.env, [lane; 32]), nonce, NOW + 60, None::<Address>);
        self.call(w, who, "mtx_set_mandate", a.into_val(&self.env))
    }

    fn set_payee(&self, w: &MandateWalletClient, who: Who, payee: &Holder, allowed: bool, lane: u8, nonce: u64) -> Res {
        let a = (&self.t.address, payee, allowed, n(&self.env, [lane; 32]), nonce, NOW + 60, None::<Address>);
        self.call(w, who, "mtx_set_payee", a.into_val(&self.env))
    }

    fn revoke(&self, w: &MandateWalletClient, who: Who, by: &Holder, lane: u8, nonce: u64) -> Res {
        let a = (&self.t.address, by, n(&self.env, [lane; 32]), nonce, NOW + 60, None::<Address>);
        self.call(w, who, "mtx_revoke", a.into_val(&self.env))
    }

    fn withdraw(&self, w: &MandateWalletClient, who: Who, to: &Holder, amount: i128, lane: u8, nonce: u64) -> Res {
        let a = (&self.t.address, to, amount, n(&self.env, [lane; 32]), nonce, NOW + 60, None::<Address>);
        self.call(w, who, "mtx_withdraw", a.into_val(&self.env))
    }

    fn pay(&self, w: &MandateWalletClient, who: Who, payee: &Holder, amount: i128, pay_ref: u8, vu: u64) -> Res {
        let a = (&self.t.address, payee, amount, n(&self.env, [pay_ref; 32]), vu, None::<Address>);
        self.call(w, who, "mtx_mandate_pay", a.into_val(&self.env))
    }
}

// ---------- native holders ----------

/// The pre-UA mandate tests on the new names with native holders: caps, period, payee list, signature expiry,
/// mandate expiry, revoke by owner or delegate only, bad mandates, withdraw, an unbounded period; plus SOR-D9's
/// native rules (a non-empty `auth` is `BadAuth`, the lane is not consumed).
#[test]
fn mandate_native_owner_unchanged_semantics() {
    let s = base();
    let e = &s.env;
    let (owner, delegate, payee) = (Address::generate(e), Address::generate(e), Address::generate(e));
    let (o, d, p) = (Holder::Addr(owner.clone()), Holder::Addr(delegate.clone()), Holder::Addr(payee.clone()));
    let w = s.mandate(&o, 1_000);
    assert_eq!(w.owner(), o);
    s.set_mandate(&w, Who::Native(&owner), &d, 100, 150, 3600, NOW + 86_400, 1, 0).unwrap();
    s.set_payee(&w, Who::Native(&owner), &p, true, 1, 0).unwrap();
    // Caps, ref once, payee list.
    s.pay(&w, Who::Native(&delegate), &p, 100, 1, NOW + 60).unwrap();
    assert_eq!(e.auths()[0].0, delegate, "the delegate authorises, not the owner");
    assert_eq!(s.t.balance(&payee), 100);
    assert!(s.t.ref_used(&w.address, &n(e, [1; 32])) && w.paid(&n(e, [1; 32])));
    assert_eq!(s.pay(&w, Who::Native(&delegate), &p, 101, 2, NOW + 60), ce(Error::OverPaymentCap));
    assert_eq!(s.pay(&w, Who::Native(&delegate), &p, 60, 2, NOW + 60), ce(Error::OverPeriodCap));
    assert_eq!(s.pay(&w, Who::Native(&delegate), &p, 10, 1, NOW + 60), ce(Error::RefAlreadyPaid));
    let stranger = Address::generate(e);
    assert_eq!(s.pay(&w, Who::Native(&delegate), &Holder::Addr(stranger.clone()), 10, 3, NOW + 60), ce(Error::PayeeNotAllowed));
    // Only the delegate pays: the owner's host auth is not the delegate's.
    assert!(s.pay(&w, Who::Native(&owner), &p, 10, 3, NOW + 60).is_err());
    // The period resets.
    e.ledger().with_mut(|l| l.timestamp = NOW + 3600);
    s.pay(&w, Who::Native(&delegate), &p, 60, 2, NOW + 3700).unwrap();
    assert_eq!(s.t.balance(&payee), 160);
    // Signature expiry (`valid_until`) is checked by the mandate itself.
    assert_eq!(s.pay(&w, Who::Native(&delegate), &p, 1, 4, NOW + 10), ce(Error::Expired));
    e.ledger().with_mut(|l| l.timestamp = NOW + 86_401);
    assert_eq!(s.pay(&w, Who::Native(&delegate), &p, 1, 5, NOW + 90_000), ce(Error::MandateExpired));
    e.ledger().with_mut(|l| l.timestamp = NOW);

    // SOR-D9: a native holder's `auth` must be empty; its lane is not consumed (same lane and nonce again).
    let a = (&s.t.address, &p, false, n(e, [1; 32]), 0u64, NOW + 60, None::<Address>, Bytes::from_array(e, &[1]));
    allow(e, &owner, &w.address, "mtx_set_payee", a.clone().into_val(e));
    assert_eq!(err(w.try_mtx_set_payee(a.0, a.1, &a.2, &a.3, &a.4, &a.5, &a.6, &a.7)), Error::BadAuth);
    s.set_payee(&w, Who::Native(&owner), &p, false, 1, 0).unwrap();
    assert_eq!(s.pay(&w, Who::Native(&delegate), &p, 1, 6, NOW + 60), ce(Error::PayeeNotAllowed));
    assert_eq!(w.ua_nonce(&n(e, [0; 32]), &n(e, [1; 32])), 0);

    // Revoke: a stranger no, the delegate yes (kill switch), then the owner.
    assert_eq!(s.revoke(&w, Who::Native(&stranger), &Holder::Addr(stranger.clone()), 1, 0), ce(Error::NotAllowed));
    s.revoke(&w, Who::Native(&delegate), &d, 1, 0).unwrap();
    assert_eq!(w.mandate(&s.t.address), None);
    assert_eq!(s.pay(&w, Who::Native(&delegate), &p, 1, 7, NOW + 60), ce(Error::NoMandate));
    s.set_mandate(&w, Who::Native(&owner), &d, 10, 10, 60, NOW + 60, 1, 0).unwrap();
    s.revoke(&w, Who::Native(&owner), &o, 1, 0).unwrap();
    assert_eq!(e.auths()[0].0, owner);
    // The delegate cannot set a mandate.
    assert!(s.set_mandate(&w, Who::Native(&delegate), &d, 10, 10, 60, NOW + 60, 1, 0).is_err());

    // Bad mandates.
    assert_eq!(s.set_mandate(&w, Who::Native(&owner), &d, 10, 10, 0, NOW + 60, 1, 0), ce(Error::BadMandate));
    assert_eq!(s.set_mandate(&w, Who::Native(&owner), &d, 11, 10, 60, NOW + 60, 1, 0), ce(Error::BadMandate));

    // Withdraw by the owner only.
    assert!(s.withdraw(&w, Who::Native(&delegate), &d, 1, 1, 0).is_err());
    s.withdraw(&w, Who::Native(&owner), &o, 400, 1, 0).unwrap();
    assert_eq!((s.t.balance(&owner), s.t.balance(&w.address)), (400, 1_000 - 160 - 400));

    // An unbounded period never overflows.
    s.set_mandate(&w, Who::Native(&owner), &d, 100, 150, u64::MAX, NOW + 86_400, 1, 0).unwrap();
    s.set_payee(&w, Who::Native(&owner), &p, true, 1, 0).unwrap();
    s.pay(&w, Who::Native(&delegate), &p, 100, 8, NOW + 60).unwrap();
    e.ledger().with_mut(|l| l.timestamp = NOW + 80_000);
    assert_eq!(s.pay(&w, Who::Native(&delegate), &p, 60, 9, NOW + 80_060), ce(Error::OverPeriodCap));
}

// ---------- UA holders ----------

/// A UA owner sets a mandate for a UA delegate and a UA payee; the delegate pays; the payee's `ua_balance` rises.
#[test]
fn mandate_ua_owner_delegate_payee() {
    let s = base();
    let e = &s.env;
    let (owner, delegate, payee) = (s.ua(1), s.ua(2), s.ua(3));
    let w = s.mandate(&owner.h(), 1_000);
    assert_eq!(w.owner(), owner.h());
    s.set_mandate(&w, Who::Ua(&owner), &delegate.h(), 100, 150, 3600, NOW + 86_400, 1, 0).unwrap();
    s.set_payee(&w, Who::Ua(&owner), &payee.h(), true, 1, 1).unwrap();
    assert_eq!(w.ua_nonce(&owner.id, &n(e, [1; 32])), 2);
    assert_eq!(w.mandate(&s.t.address).unwrap().delegate, delegate.h());
    // Only the delegate's signature pays: the owner's is refused by the registry.
    assert!(s.pay(&w, Who::Ua(&owner), &payee.h(), 100, 1, NOW + 60).is_err());
    s.pay(&w, Who::Ua(&delegate), &payee.h(), 100, 1, NOW + 60).unwrap();
    assert_eq!(s.t.ua_balance(&payee.id), 100);
    assert_eq!(s.t.balance(&w.address), 900);
    assert!(w.paid(&n(e, [1; 32])) && s.t.ref_used(&w.address, &n(e, [1; 32])));
    // Caps hold for a UA delegate too; a payee not on the list is refused.
    assert_eq!(s.pay(&w, Who::Ua(&delegate), &payee.h(), 60, 2, NOW + 60), ce(Error::OverPeriodCap));
    assert_eq!(s.pay(&w, Who::Ua(&delegate), &owner.h(), 10, 2, NOW + 60), ce(Error::PayeeNotAllowed));
    // A UA signer with a non-matching nonce or an expired signature is refused before its signature is checked.
    assert_eq!(s.set_payee(&w, Who::Ua(&owner), &owner.h(), true, 1, 5), ce(Error::BadNonce));
    let a = (&s.t.address, owner.h(), true, n(e, [1; 32]), 2u64, NOW - 1, None::<Address>);
    assert_eq!(s.call(&w, Who::Ua(&owner), "mtx_set_payee", a.into_val(e)), ce(Error::Expired));
    // The UA delegate revokes its own mandate (kill switch) on its own lane; a third UA cannot.
    let stranger = s.ua(4);
    assert_eq!(s.revoke(&w, Who::Ua(&stranger), &stranger.h(), 1, 0), ce(Error::NotAllowed));
    s.revoke(&w, Who::Ua(&delegate), &delegate.h(), 7, 0).unwrap();
    assert_eq!((w.ua_nonce(&delegate.id, &n(e, [7; 32])), w.mandate(&s.t.address)), (1, None));
    // The UA owner's lane is the mandate's own, not the token's.
    assert_eq!(s.t.ua_nonce(&owner.id, &n(e, [1; 32])), 0);
}

/// Each UA owner signature runs once: the mandate's own lane `UaNonce(ua, lane)`; lanes are independent; a bound
/// relayer must authorise (S8).
#[test]
fn mandate_ua_owner_lane_replay_refused() {
    let s = base();
    let e = &s.env;
    let (owner, delegate) = (s.ua(1), s.ua(2));
    let w = s.mandate(&owner.h(), 1_000);
    let a = (&s.t.address, delegate.h(), 100i128, 150i128, 3600u64, NOW + 86_400, n(e, [1; 32]), 0u64, NOW + 60, None::<Address>);
    let args: SVec<Val> = a.into_val(e);
    s.call(&w, Who::Ua(&owner), "mtx_set_mandate", args.clone()).unwrap();
    // The same signed call again: refused, the mandate unchanged in between.
    s.revoke(&w, Who::Ua(&owner), &owner.h(), 2, 0).unwrap();
    assert_eq!(s.call(&w, Who::Ua(&owner), "mtx_set_mandate", args), ce(Error::BadNonce));
    assert_eq!(w.mandate(&s.t.address), None);
    assert_eq!((w.ua_nonce(&owner.id, &n(e, [1; 32])), w.ua_nonce(&owner.id, &n(e, [2; 32]))), (1, 1));
    // A signature over different arguments (another nonce) does not authorise this call: the digest differs.
    let d1 = scaas_ua_common::op_digest(e, &w.address, "mtx_revoke", (&s.t.address, owner.h(), n(e, [2; 32]), 1u64, NOW + 61, None::<Address>).into_val(e));
    let sig = owner.sk.sign(&keccak(e, &[&MSG_TAG, &ED_TAG, &PURPOSE_METATX, &d1.to_array()])).to_bytes();
    s.set_mandate(&w, Who::Ua(&owner), &delegate.h(), 10, 10, 60, NOW + 60, 3, 0).unwrap();
    assert!(w.try_mtx_revoke(&s.t.address, &owner.h(), &n(e, [2; 32]), &1, &(NOW + 60), &None, &Bytes::from_array(e, &sig)).is_err());
    assert_eq!(w.ua_nonce(&owner.id, &n(e, [2; 32])), 1);
    // A bound relayer: without its authorisation refused, with it the entry runs.
    let r = Address::generate(e);
    let ra = (&s.t.address, owner.h(), n(e, [2; 32]), 1u64, NOW + 60, Some(r.clone()));
    let d = scaas_ua_common::op_digest(e, &w.address, "mtx_revoke", ra.clone().into_val(e));
    let sig = Bytes::from_array(e, &owner.sk.sign(&keccak(e, &[&MSG_TAG, &ED_TAG, &PURPOSE_METATX, &d.to_array()])).to_bytes());
    assert!(w.try_mtx_revoke(ra.0, &ra.1, &ra.2, &ra.3, &ra.4, &ra.5, &sig).is_err());
    let mut full: SVec<Val> = ra.clone().into_val(e);
    full.push_back(sig.into_val(e));
    allow(e, &r, &w.address, "mtx_revoke", full);
    w.mtx_revoke(ra.0, &ra.1, &ra.2, &ra.3, &ra.4, &ra.5, &sig);
    assert_eq!(e.auths()[0].0, r);
    assert_eq!(w.mandate(&s.t.address), None);
}

/// `pay_ref` once per mandate, for a UA and a native payee, across payees and delegates.
#[test]
fn mandate_pay_ref_once() {
    let s = base();
    let e = &s.env;
    let (owner, delegate, payee) = (s.ua(1), s.ua(2), s.ua(3));
    let native = Address::generate(e);
    let w = s.mandate(&owner.h(), 1_000);
    s.set_mandate(&w, Who::Ua(&owner), &delegate.h(), 100, 1_000, 3600, NOW + 86_400, 1, 0).unwrap();
    s.set_payee(&w, Who::Ua(&owner), &payee.h(), true, 1, 1).unwrap();
    s.set_payee(&w, Who::Ua(&owner), &Holder::Addr(native.clone()), true, 1, 2).unwrap();
    assert!(!w.paid(&n(e, [9; 32])));
    s.pay(&w, Who::Ua(&delegate), &payee.h(), 10, 9, NOW + 60).unwrap();
    assert!(w.paid(&n(e, [9; 32])));
    // The identical signed call again, another payee, another delegate: the ref is spent.
    assert_eq!(s.pay(&w, Who::Ua(&delegate), &payee.h(), 10, 9, NOW + 60), ce(Error::RefAlreadyPaid));
    assert_eq!(s.pay(&w, Who::Ua(&delegate), &Holder::Addr(native.clone()), 10, 9, NOW + 60), ce(Error::RefAlreadyPaid));
    let other = Address::generate(e);
    s.set_mandate(&w, Who::Ua(&owner), &Holder::Addr(other.clone()), 100, 1_000, 3600, NOW + 86_400, 1, 3).unwrap();
    assert_eq!(s.pay(&w, Who::Native(&other), &payee.h(), 10, 9, NOW + 60), ce(Error::RefAlreadyPaid));
    // A native payee through `token.pay` with a fresh ref.
    s.pay(&w, Who::Native(&other), &Holder::Addr(native.clone()), 15, 10, NOW + 60).unwrap();
    assert_eq!((s.t.ua_balance(&payee.id), s.t.balance(&native), s.t.balance(&w.address)), (10, 15, 975));
}

/// A UA owner withdraws to a UA (`transfer_to_ua`) and to a native address; a native owner to a UA too.
#[test]
fn mandate_withdraw_to_ua() {
    let s = base();
    let e = &s.env;
    let (owner, other) = (s.ua(1), s.ua(2));
    let w = s.mandate(&owner.h(), 1_000);
    s.withdraw(&w, Who::Ua(&owner), &owner.h(), 300, 1, 0).unwrap();
    assert_eq!((s.t.ua_balance(&owner.id), s.t.balance(&w.address)), (300, 700));
    let a = Address::generate(e);
    s.withdraw(&w, Who::Ua(&owner), &Holder::Addr(a.clone()), 200, 1, 1).unwrap();
    assert_eq!((s.t.balance(&a), s.t.balance(&w.address)), (200, 500));
    // Only the owner: another UA's signature is refused, nothing moves.
    assert!(s.withdraw(&w, Who::Ua(&other), &other.h(), 1, 1, 0).is_err());
    // A replay of the first withdrawal: its lane moved on.
    assert_eq!(s.withdraw(&w, Who::Ua(&owner), &owner.h(), 300, 1, 0), ce(Error::BadNonce));
    assert_eq!(s.t.balance(&w.address), 500);

    let s = base();
    let (u, native) = (s.ua(1), Address::generate(&s.env));
    let w = s.mandate(&Holder::Addr(native.clone()), 100);
    s.withdraw(&w, Who::Native(&native), &u.h(), 40, 1, 0).unwrap();
    assert_eq!((s.t.ua_balance(&u.id), s.t.balance(&w.address)), (40, 60));
}

/// T6 review m1 / m2: every entry extends the instance TTL, also one that writes nothing persistent (`mtx_revoke`);
/// `registry()` names the bound registry.
#[test]
fn mandate_instance_ttl_on_every_entry() {
    use soroban_sdk::testutils::storage::Instance as _;
    let s = base();
    let e = &s.env;
    let owner = Address::generate(e);
    let o = Holder::Addr(owner.clone());
    let w = s.mandate(&o, 0);
    assert_eq!(w.registry(), Some(s.reg.address.clone()));
    s.set_mandate(&w, Who::Native(&owner), &o, 10, 100, 3600, NOW + 86_400, 1, 0).unwrap();
    e.ledger().with_mut(|l| l.sequence_number += 35 * DAY);
    let ttl = || e.as_contract(&w.address, || e.storage().instance().get_ttl());
    assert_eq!(ttl(), TTL_BUMP - 35 * DAY);
    s.revoke(&w, Who::Native(&owner), &o, 1, 0).unwrap();
    assert_eq!(ttl(), TTL_BUMP);
}

/// A UA owner needs a registry (a native owner does not: every other test of the native path could run without one).
#[test]
#[should_panic(expected = "Error(Contract, #12)")]
fn mandate_ua_owner_needs_registry() {
    let env = Env::default();
    env.register(MandateWallet, (Holder::Ua(n(&env, [0x42; 32])), None::<Address>));
}

// ---------- ua-ops.json ----------

fn arg_vals(env: &Env, p: &Value) -> SVec<Val> {
    let mut v = SVec::new(env);
    for a in p["args"].as_array().unwrap() {
        let sc = ScVal::from_xdr(hx(&a["xdr"]), Limits::none()).unwrap();
        v.push_back(Val::try_from_val(env, &sc).unwrap());
    }
    v
}

/// SOR-D12: the mandate at `ua-ops.json`'s id and network id; each `mtx_set_mandate` / `mtx_mandate_pay` row's digest
/// is recomputed and its `auth` runs as the call it signs: `mtx_set_mandate` with that kind's UA as the owner,
/// `mtx_mandate_pay` with that kind's UA as the delegate (set by a native owner).
#[test]
fn ua_ops_vectors_mandate_rows() {
    let o = ops();
    let mandate = o["contracts"]["mandate"].as_str().unwrap();
    let (mut digests, mut calls) = (0, 0);
    for e in o["entries"].as_array().unwrap() {
        if e["contract"] != mandate {
            continue;
        }
        let f = e["fn"].as_str().unwrap();
        assert!(["mtx_set_mandate", "mtx_mandate_pay"].contains(&f), "{f}");
        for p in e["perKind"].as_array().unwrap() {
            let s = base();
            let env = &s.env;
            let mut ua = None;
            for r in o["registrations"].as_array().unwrap() {
                let kind = r["kind"].as_u64().unwrap() as u32;
                let id = s.reg.register(&kind, &Bytes::from_slice(env, &hx(&r["keyData"])), &no_attrs(env), &Bytes::from_slice(env, &hx(&r["pop"])), &Bytes::new(env), &None);
                if r["ua"] == p["ua"] {
                    ua = Some(id);
                }
            }
            let ua = Holder::Ua(ua.unwrap());
            let args = arg_vals(env, p);
            let native = Address::generate(env);
            let w = if f == "mtx_set_mandate" {
                s.mandate(&ua, 0)
            } else {
                let w = s.mandate(&Holder::Addr(native.clone()), 1_000_000);
                s.set_mandate(&w, Who::Native(&native), &ua, 1_000_000, 1_000_000, 3600, NOW + 86_400, 1, 0).unwrap();
                let payee = Holder::try_from_val(env, &args.get(1).unwrap()).unwrap();
                s.set_payee(&w, Who::Native(&native), &payee, true, 1, 0).unwrap();
                w
            };
            assert_eq!(scaas_ua_common::op_digest(env, &w.address, f, args.clone()).to_array().to_vec(), hx(&p["digest"]), "{f} {}", p["kind"]);
            digests += 1;
            let mut all = args.clone();
            all.push_back(Bytes::from_slice(env, &hx(&p["auth"])).into_val(env));
            let r = env.try_invoke_contract::<(), soroban_sdk::Error>(&w.address, &Symbol::new(env, f), all);
            assert!(r.is_ok(), "{f} {}: {r:?}", p["kind"]);
            calls += 1;
            if f == "mtx_set_mandate" {
                let delegate = Holder::try_from_val(env, &args.get(1).unwrap()).unwrap();
                assert_eq!(w.mandate(&s.t.address).unwrap().delegate, delegate);
            } else {
                let pay_ref = BytesN::<32>::try_from_val(env, &args.get(3).unwrap()).unwrap();
                assert!(w.paid(&pay_ref));
            }
        }
    }
    assert_eq!((digests, calls), (2 * 7, 2 * 7));
}
