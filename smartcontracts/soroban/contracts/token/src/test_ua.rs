//! T5: the token's UA ledger (spec §5.1, §5.5) against the real `UaRegistry`, in-test ed25519 UAs and the
//! `ua-ops.json` rows. No `mock_all_auths`: a native authority is mocked for exactly one address and invocation
//! (`allow`), a UA signs for real.
extern crate std;
use std::{vec, vec::Vec as StdVec};

use ed25519_dalek::Signer as _;
use scaas_ua_common::{h32, meta_pay_id, pay_lane, Holder, Order, UaAttrs, PURPOSE_METATX, PURPOSE_METATX_CANCEL, PURPOSE_POP_V2, PURPOSE_TRADE};
use scaas_ua_registry::{UaRegistry, UaRegistryClient as RegClient};
use serde_json::Value;
use soroban_sdk::testutils::{storage::Persistent as _, Address as _, Events as _, Ledger as _, MockAuth, MockAuthInvoke};
use soroban_sdk::xdr::{self, Limits, ReadXdr as _, ScVal};
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, IntoVal, MuxedAddress, String, Symbol, TryFromVal, Val, Vec as SVec};

use crate::{op_digest, Error, Key, Token, TokenClient};

const OPS: &str = include_str!("../../../vectors/ua-ops.json");
const PORTABLE: &str = include_str!("../../../../vectors/ua/portable.json");
const NOW: u64 = 1_800_000_000;
const DAY: u32 = 17_280;
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

struct T {
    env: Env,
    t: TokenClient<'static>,
    reg: RegClient<'static>,
    admin: Address,
}

/// The token and the registry at `ua-ops.json`'s ids and network id; `registry = None` when `on` is false.
fn setup_with(on: bool) -> T {
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
    let r = if on { Some(reg.address.clone()) } else { None };
    let s = |x: &str| String::from_str(&env, x);
    let t = env.register_at(&id("token"), Token, (admin.clone(), 7u32, s("SCaaS"), s("BMB"), r));
    T { t: TokenClient::new(&env, &t), reg, admin, env }
}

fn setup() -> T {
    setup_with(true)
}

/// Mocks exactly `who`'s authorisation of `contract.f(args)` for the next call.
fn allow(env: &Env, who: &Address, contract: &Address, f: &str, args: SVec<Val>) {
    env.mock_auths(&[MockAuth { address: who, invoke: &MockAuthInvoke { contract, fn_name: f, args, sub_invokes: &[] } }]);
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

    /// The UA's signature over `op_digest(token, f, args)` under `purpose`.
    fn sign(&self, u: &Ua, purpose: [u8; 32], f: &str, args: SVec<Val>) -> Bytes {
        let d = op_digest(&self.env, &self.t.address, f, args).to_array();
        Bytes::from_array(&self.env, &u.sk.sign(&keccak(&self.env, &[&MSG_TAG, &ED_TAG, &purpose, &d])).to_bytes())
    }

    fn mint(&self, to: &Address, amount: i128) {
        allow(&self.env, &self.admin, &self.t.address, "mint", (to, amount).into_val(&self.env));
        self.t.mint(to, &amount);
    }

    fn mint_ua(&self, to: &BytesN<32>, amount: i128) {
        allow(&self.env, &self.admin, &self.t.address, "mint_to_ua", (to, amount).into_val(&self.env));
        self.t.mint_to_ua(to, &amount);
    }

    #[allow(clippy::too_many_arguments)]
    fn transfer(&self, u: &Ua, to: &Holder, amount: i128, lane: [u8; 32], nonce: u64, vu: u64, relayer: &Option<Address>) -> Result<(), Error> {
        let (env, lane) = (&self.env, n(&self.env, lane));
        let auth = self.sign(u, PURPOSE_METATX, "ua_transfer", (&u.id, to, amount, &lane, nonce, vu, relayer).into_val(env));
        match self.t.try_ua_transfer(&u.id, to, &amount, &lane, &nonce, &vu, relayer, &auth) {
            Ok(_) => Ok(()),
            Err(e) => Err(err::<(), _>(Err(e))),
        }
    }

    fn pay(&self, u: &Ua, to: &Holder, amount: i128, pay_ref: [u8; 32], vu: u64) -> Result<(), Error> {
        let (env, r) = (&self.env, n(&self.env, pay_ref));
        let auth = self.sign(u, PURPOSE_METATX, "ua_pay", (&u.id, to, amount, &r, vu, None::<Address>).into_val(env));
        match self.t.try_ua_pay(&u.id, to, &amount, &r, &vu, &None, &auth) {
            Ok(_) => Ok(()),
            Err(e) => Err(err::<(), _>(Err(e))),
        }
    }

    fn burn(&self, u: &Ua, amount: i128, lane: [u8; 32], nonce: u64, vu: u64) -> Result<(), Error> {
        let (env, lane) = (&self.env, n(&self.env, lane));
        let auth = self.sign(u, PURPOSE_METATX, "ua_burn", (&u.id, amount, &lane, nonce, vu, None::<Address>).into_val(env));
        match self.t.try_ua_burn(&u.id, &amount, &lane, &nonce, &vu, &None, &auth) {
            Ok(_) => Ok(()),
            Err(e) => Err(err::<(), _>(Err(e))),
        }
    }

    fn cancel(&self, u: &Ua, lane: [u8; 32], vu: u64, purpose: [u8; 32]) -> bool {
        let lane = n(&self.env, lane);
        let auth = self.sign(u, purpose, "ua_cancel_nonce", (&u.id, &lane, vu).into_val(&self.env));
        self.t.try_ua_cancel_nonce(&u.id, &lane, &vu, &auth).is_ok()
    }

    fn transfer_to_ua(&self, from: &Address, to: &BytesN<32>, amount: i128) {
        allow(&self.env, from, &self.t.address, "transfer_to_ua", (from, to, amount).into_val(&self.env));
        self.t.transfer_to_ua(from, to, &amount);
    }

    /// The topic-0 names of the token's events of the last call.
    fn event_names(&self) -> StdVec<std::string::String> {
        self.env
            .events()
            .all()
            .filter_by_contract(&self.t.address)
            .events()
            .iter()
            .map(|e| {
                let xdr::ContractEventBody::V0(b) = &e.body;
                match &b.topics[0] {
                    ScVal::Symbol(s) => s.to_utf8_string_lossy(),
                    _ => panic!(),
                }
            })
            .collect()
    }
}

// ---------- the entries ----------

#[test]
fn transfer_to_ua_then_ua_transfer() {
    let s = setup();
    let env = &s.env;
    let (u1, u2) = (s.ua(1), s.ua(2));
    let (a, b) = (Address::generate(env), Address::generate(env));
    s.mint(&a, 500);
    s.transfer_to_ua(&a, &u1.id, 100);
    assert_eq!(env.auths()[0].0, a, "transfer_to_ua needs from");
    assert_eq!(s.event_names(), ["transfer", "UaTransfer"]);
    assert_eq!((s.t.balance(&a), s.t.balance(&s.t.address), s.t.ua_balance(&u1.id)), (400, 100, 100));
    assert_eq!(s.t.registry(), Some(s.reg.address.clone()));

    s.transfer(&u1, &Holder::Ua(u2.id.clone()), 30, [9; 32], 0, NOW + 10, &None).unwrap();
    assert_eq!(s.event_names(), ["UaTransfer", "UaMetaTransactionExecuted"]);
    s.transfer(&u1, &Holder::Addr(b.clone()), 20, [9; 32], 1, NOW + 10, &None).unwrap();
    assert_eq!(s.event_names(), ["transfer", "UaTransfer", "UaMetaTransactionExecuted"]);
    assert_eq!((s.t.ua_balance(&u1.id), s.t.ua_balance(&u2.id), s.t.balance(&b), s.t.balance(&s.t.address)), (50, 30, 20, 80));
    assert_eq!(s.t.ua_nonce(&u1.id, &n(env, [9; 32])), 2);
    assert_eq!(s.transfer(&u1, &Holder::Ua(u2.id.clone()), 51, [9; 32], 2, NOW + 10, &None), Err(Error::InsufficientBalance));
    assert_eq!(s.transfer(&u1, &Holder::Ua(u2.id.clone()), -1, [9; 32], 2, NOW + 10, &None), Err(Error::NegativeAmount));
}

#[test]
fn ua_transfer_replay_refused() {
    let s = setup();
    let env = &s.env;
    let (u1, u2) = (s.ua(1), s.ua(2));
    s.mint_ua(&u1.id, 100);
    let to = Holder::Ua(u2.id.clone());
    let lane = n(env, [3; 32]);
    let args = (&u1.id, &to, 10i128, &lane, 0u64, NOW + 10, None::<Address>);
    let auth = s.sign(&u1, PURPOSE_METATX, "ua_transfer", args.into_val(env));
    s.t.ua_transfer(&u1.id, &to, &10, &lane, &0, &(NOW + 10), &None, &auth);
    // The same signed entry again: its nonce is spent.
    assert_eq!(err(s.t.try_ua_transfer(&u1.id, &to, &10, &lane, &0, &(NOW + 10), &None, &auth)), Error::BadNonce);
    // A nonce ahead of the lane.
    assert_eq!(s.transfer(&u1, &to, 1, [3; 32], 2, NOW + 10, &None), Err(Error::BadNonce));
    // The old signature over other arguments, and another UA's signature, are refused by the registry.
    assert!(s.t.try_ua_transfer(&u1.id, &to, &11, &lane, &1, &(NOW + 10), &None, &auth).is_err());
    let other = s.sign(&u2, PURPOSE_METATX, "ua_transfer", (&u1.id, &to, 1i128, &lane, 1u64, NOW + 10, None::<Address>).into_val(env));
    assert!(s.t.try_ua_transfer(&u1.id, &to, &1, &lane, &1, &(NOW + 10), &None, &other).is_err());
    // A signature under another purpose.
    let cancel = s.sign(&u1, PURPOSE_METATX_CANCEL, "ua_transfer", (&u1.id, &to, 1i128, &lane, 1u64, NOW + 10, None::<Address>).into_val(env));
    assert!(s.t.try_ua_transfer(&u1.id, &to, &1, &lane, &1, &(NOW + 10), &None, &cancel).is_err());
    assert_eq!((s.t.ua_nonce(&u1.id, &lane), s.t.ua_balance(&u1.id), s.t.ua_balance(&u2.id)), (1, 90, 10));
    // Other lanes are independent.
    s.transfer(&u1, &to, 1, [4; 32], 0, NOW + 10, &None).unwrap();
}

#[test]
fn ua_pay_once_per_ref() {
    let s = setup();
    let env = &s.env;
    let (u1, u2) = (s.ua(1), s.ua(2));
    s.mint_ua(&u1.id, 100);
    let r = n(env, [0x11; 32]);
    assert!(!s.t.ua_ref_used(&u1.id, &r));
    s.pay(&u1, &Holder::Ua(u2.id.clone()), 40, [0x11; 32], NOW + 10).unwrap();
    assert_eq!(s.event_names(), ["UaTransfer", "UaPaymentSettled", "UaMetaTransactionExecuted"]);
    assert!(s.t.ua_ref_used(&u1.id, &r));
    assert!(!s.t.ua_ref_used(&u2.id, &r), "per payer");
    assert_eq!(s.t.ua_nonce(&u1.id, &pay_lane(env, &r)), 1);
    // A fresh signature for the same ref (other amount): the pay lane is past nonce 0.
    assert_eq!(s.pay(&u1, &Holder::Ua(u2.id.clone()), 1, [0x11; 32], NOW + 10), Err(Error::BadNonce));
    // Another ref pays a native receiver out of the pool.
    let b = Address::generate(env);
    s.pay(&u1, &Holder::Addr(b.clone()), 25, [0x12; 32], NOW + 10).unwrap();
    assert_eq!((s.t.ua_balance(&u1.id), s.t.ua_balance(&u2.id), s.t.balance(&b), s.t.balance(&s.t.address)), (35, 40, 25, 75));
    // A self-pay (the `ua-ops.json` p256 row's form) settles and changes nothing but the lane.
    s.pay(&u2, &Holder::Ua(u2.id.clone()), 5, [0x13; 32], NOW + 10).unwrap();
    assert_eq!(s.t.ua_balance(&u2.id), 40);
}

#[test]
fn pay_to_ua_ref_once_per_payer() {
    let s = setup();
    let env = &s.env;
    let u = s.ua(1);
    let a = Address::generate(env);
    s.mint(&a, 100);
    let r = n(env, [0x21; 32]);
    let call = |amount: i128| {
        allow(env, &a, &s.t.address, "pay_to_ua", (&a, &u.id, amount, &r, NOW + 10).into_val(env));
        s.t.try_pay_to_ua(&a, &u.id, &amount, &r, &(NOW + 10))
    };
    call(30).unwrap().unwrap();
    assert_eq!(s.event_names(), ["transfer", "UaTransfer", "UaPaymentSettled", "MetaTransactionExecuted"]);
    assert!(s.t.ref_used(&a, &r));
    assert_eq!((s.t.balance(&a), s.t.ua_balance(&u.id), s.t.balance(&s.t.address)), (70, 30, 30));
    assert_eq!(err(call(1)), Error::RefUsed);
    // Without the payer's authorisation.
    assert!(s.t.try_pay_to_ua(&a, &u.id, &1, &n(env, [0x22; 32]), &(NOW + 10)).is_err());
}

#[test]
fn ua_pay_meta_emits_meta_first() {
    let s = setup();
    let env = &s.env;
    let (u1, u2) = (s.ua(1), s.ua(2));
    s.mint_ua(&u1.id, 100);
    let (salt, meta) = (n(env, [0x5a; 32]), Bytes::from_slice(env, b"{\"invoice\":\"INV-1\"}"));
    let to = Holder::Ua(u2.id.clone());
    let args = (&u1.id, &to, 40i128, &salt, &meta, NOW + 10, None::<Address>);
    let auth = s.sign(&u1, PURPOSE_METATX, "ua_pay_meta", args.into_val(env));
    s.t.ua_pay_meta(&u1.id, &to, &40, &salt, &meta, &(NOW + 10), &None, &auth);
    assert_eq!(s.event_names(), ["PaymentMeta", "UaTransfer", "UaPaymentSettled", "UaMetaTransactionExecuted"]);
    let id = meta_pay_id(env, &salt, &meta);
    assert!(s.t.ua_ref_used(&u1.id, &id));
    assert_eq!((s.t.ua_balance(&u1.id), s.t.ua_balance(&u2.id)), (60, 40));
    // The same (salt, meta) again, and a plain ua_pay of the committed id: one pay lane.
    assert_eq!(err(s.t.try_ua_pay_meta(&u1.id, &to, &40, &salt, &meta, &(NOW + 10), &None, &auth)), Error::BadNonce);
    assert_eq!(s.pay(&u1, &to, 1, id.to_array(), NOW + 10), Err(Error::BadNonce));
}

#[test]
fn ua_burn_and_cancel_nonce() {
    let s = setup();
    let env = &s.env;
    let u = s.ua(1);
    s.mint_ua(&u.id, 100);
    s.burn(&u, 30, [7; 32], 0, NOW + 10).unwrap();
    assert_eq!(s.event_names(), ["burn", "UaTransfer", "UaMetaTransactionExecuted"]);
    assert_eq!((s.t.ua_balance(&u.id), s.t.balance(&s.t.address), s.t.ua_nonce(&u.id, &n(env, [7; 32]))), (70, 70, 1));
    assert_eq!(s.burn(&u, 71, [7; 32], 1, NOW + 10), Err(Error::InsufficientBalance));

    // Cancel lane 8 at nonce 0: a transfer signed at nonce 0 can no longer run.
    let to = Holder::Ua(s.ua(2).id);
    let lane = n(env, [8; 32]);
    let pending = s.sign(&u, PURPOSE_METATX, "ua_transfer", (&u.id, &to, 5i128, &lane, 0u64, NOW + 10, None::<Address>).into_val(env));
    assert!(!s.cancel(&u, [8; 32], NOW + 10, PURPOSE_METATX), "cancel needs purpose metatx-cancel");
    assert!(s.cancel(&u, [8; 32], NOW + 10, PURPOSE_METATX_CANCEL));
    assert_eq!(s.event_names(), ["UaNonceCancelled", "UaMetaTransactionExecuted"]);
    let last = env.events().all().filter_by_contract(&s.t.address).events()[0].clone();
    let xdr::ContractEventBody::V0(b) = last.body;
    assert_eq!(b.data, ScVal::U64(1), "new_nonce");
    assert_eq!(s.t.ua_nonce(&u.id, &lane), 1);
    assert_eq!(err(s.t.try_ua_transfer(&u.id, &to, &5, &lane, &0, &(NOW + 10), &None, &pending)), Error::BadNonce);
    // The cancel signature names no nonce: replayed, it is refused (EVM `cancelUsed`), the lane stays at 1.
    let again = s.sign(&u, PURPOSE_METATX_CANCEL, "ua_cancel_nonce", (&u.id, &lane, NOW + 10).into_val(env));
    assert_eq!(err(s.t.try_ua_cancel_nonce(&u.id, &lane, &(NOW + 10), &again)), Error::BadNonce);
    assert_eq!(s.t.ua_nonce(&u.id, &lane), 1);
    // Another valid_until is another digest: a second cancel.
    assert!(s.cancel(&u, [8; 32], NOW + 11, PURPOSE_METATX_CANCEL));
    assert_eq!(s.t.ua_nonce(&u.id, &lane), 2);
}

#[test]
fn ua_expired_refused() {
    let s = setup();
    let env = &s.env;
    let (u, v) = (s.ua(1), s.ua(2));
    s.mint_ua(&u.id, 100);
    let to = Holder::Ua(v.id.clone());
    assert_eq!(s.transfer(&u, &to, 1, [1; 32], 0, NOW - 1, &None), Err(Error::Expired));
    assert_eq!(s.pay(&u, &to, 1, [2; 32], NOW - 1), Err(Error::Expired));
    assert_eq!(s.burn(&u, 1, [1; 32], 0, NOW - 1), Err(Error::Expired));
    assert!(!s.cancel(&u, [1; 32], NOW - 1, PURPOSE_METATX_CANCEL));
    let (salt, meta) = (n(env, [3; 32]), Bytes::new(env));
    let auth = s.sign(&u, PURPOSE_METATX, "ua_pay_meta", (&u.id, &to, 1i128, &salt, &meta, NOW - 1, None::<Address>).into_val(env));
    assert_eq!(err(s.t.try_ua_pay_meta(&u.id, &to, &1, &salt, &meta, &(NOW - 1), &None, &auth)), Error::Expired);
    // valid_until == now still runs.
    s.transfer(&u, &to, 1, [1; 32], 0, NOW, &None).unwrap();
    assert_eq!(s.t.ua_nonce(&u.id, &n(env, [1; 32])), 1);
}

/// S7, §7: the lane entry is persistent; past its TTL it is archived, never read as absent. The testutils emulate the
/// network's automatic restore: the spent nonce stays spent and the lane continues from the stored value.
#[test]
fn ua_entry_archived_nonce_restored_not_reset() {
    let s = setup();
    let env = &s.env;
    let (u, v) = (s.ua(1), s.ua(2));
    s.mint_ua(&u.id, 100);
    let to = Holder::Ua(v.id.clone());
    for nonce in 0..3 {
        s.transfer(&u, &to, 1, [5; 32], nonce, u64::MAX, &None).unwrap();
    }
    let k = Key::UaNonce(u.id.clone(), n(env, [5; 32]));
    let ttl = env.as_contract(&s.t.address, || env.storage().persistent().get_ttl(&k));
    assert_eq!(ttl, 60 * DAY);
    env.ledger().with_mut(|l| {
        l.sequence_number += ttl + 1;
        l.timestamp += (ttl as u64 + 1) * 5;
    });
    // Archived now; the spent nonce 0 (and 2) is refused after the restore, not accepted as a fresh lane.
    assert_eq!(s.transfer(&u, &to, 1, [5; 32], 0, u64::MAX, &None), Err(Error::BadNonce));
    assert_eq!(s.transfer(&u, &to, 1, [5; 32], 2, u64::MAX, &None), Err(Error::BadNonce));
    assert_eq!(s.t.ua_nonce(&u.id, &n(env, [5; 32])), 3);
    s.transfer(&u, &to, 1, [5; 32], 3, u64::MAX, &None).unwrap();
    assert_eq!(s.t.ua_nonce(&u.id, &n(env, [5; 32])), 4);
    assert_eq!(env.as_contract(&s.t.address, || env.storage().persistent().get_ttl(&k)), 60 * DAY);
}

/// Spec §5.1: no native path pays the token's own address, and no UA entry names it as receiver.
#[test]
fn pool_address_not_payable() {
    let s = setup();
    let env = &s.env;
    let (pool, a) = (s.t.address.clone(), Address::generate(env));
    s.mint(&a, 100);
    let u = s.ua(1);
    s.mint_ua(&u.id, 50);

    allow(env, &a, &pool, "transfer", (&a, &pool, 1i128).into_val(env));
    assert_eq!(err(s.t.try_transfer(&a, &MuxedAddress::from(pool.clone()), &1)), Error::UaPoolNotPayable);
    let r = n(env, [1; 32]);
    allow(env, &a, &pool, "pay", (&a, &pool, 1i128, &r, NOW + 10).into_val(env));
    assert_eq!(err(s.t.try_pay(&a, &pool, &1, &r, &(NOW + 10))), Error::UaPoolNotPayable);
    let meta = Bytes::new(env);
    allow(env, &a, &pool, "pay_meta", (&a, &pool, 1i128, &r, &meta, NOW + 10).into_val(env));
    assert_eq!(err(s.t.try_pay_meta(&a, &pool, &1, &r, &meta, &(NOW + 10))), Error::UaPoolNotPayable);
    allow(env, &s.admin, &pool, "mint", (&pool, 1i128).into_val(env));
    assert_eq!(err(s.t.try_mint(&pool, &1)), Error::UaPoolNotPayable);
    // transfer_from to the pool, through a contract spender.
    let spender = env.register(Token, (s.admin.clone(), 7u32, String::from_str(env, "X"), String::from_str(env, "X"), None::<Address>));
    allow(env, &a, &pool, "approve", (&a, &spender, 10i128, 200u32).into_val(env));
    s.t.approve(&a, &spender, &10, &200);
    allow(env, &spender, &pool, "transfer_from", (&spender, &a, &pool, 1i128).into_val(env));
    assert_eq!(err(s.t.try_transfer_from(&spender, &a, &pool, &1)), Error::UaPoolNotPayable);
    // transfer_to_ua from the pool (refused before any authorisation: no contract authorises itself).
    assert_eq!(err(s.t.try_transfer_to_ua(&pool, &u.id, &1)), Error::UaPoolNotPayable);
    // A UA entry naming the pool as receiver.
    let to = Holder::Addr(pool.clone());
    assert_eq!(s.transfer(&u, &to, 1, [1; 32], 0, NOW + 10, &None), Err(Error::UaPoolNotPayable));
    assert_eq!(s.pay(&u, &to, 1, [2; 32], NOW + 10), Err(Error::UaPoolNotPayable));
    assert_eq!((s.t.balance(&a), s.t.balance(&pool), s.t.ua_balance(&u.id)), (100, 50, 50));
}

/// Spec §5.1: replaying the SEP-41 `transfer` / `mint` / `burn` events gives every `balance()`, the pool included, and
/// `balance(token) == Σ ua_balance`.
#[test]
fn sep41_events_match_balance_with_ua_moves() {
    let s = setup();
    let env = &s.env;
    let (u1, u2) = (s.ua(1), s.ua(2));
    let (a, b) = (Address::generate(env), Address::generate(env));
    let mut book: StdVec<(ScVal, i128)> = vec![];
    let mut replay = |env: &Env| {
        let mut add = |k: &ScVal, d: i128| match book.iter_mut().find(|(x, _)| x == k) {
            Some((_, v)) => *v += d,
            None => book.push((k.clone(), d)),
        };
        for e in env.events().all().filter_by_contract(&s.t.address).events() {
            let xdr::ContractEventBody::V0(body) = &e.body;
            let ScVal::Symbol(name) = &body.topics[0] else { panic!() };
            let amount = || i128::try_from_val(env, &Val::try_from_val(env, &body.data).unwrap()).unwrap();
            match name.to_utf8_string_lossy().as_str() {
                "transfer" => {
                    add(&body.topics[1], -amount());
                    add(&body.topics[2], amount());
                }
                "mint" => add(&body.topics[1], amount()),
                "burn" => add(&body.topics[1], -amount()),
                _ => {}
            }
        }
    };
    s.mint(&a, 1_000);
    replay(env);
    s.transfer_to_ua(&a, &u1.id, 300);
    replay(env);
    let r = n(env, [0x31; 32]);
    allow(env, &a, &s.t.address, "pay_to_ua", (&a, &u2.id, 50i128, &r, NOW + 10).into_val(env));
    s.t.pay_to_ua(&a, &u2.id, &50, &r, &(NOW + 10));
    replay(env);
    s.mint_ua(&u1.id, 70);
    replay(env);
    s.transfer(&u1, &Holder::Ua(u2.id.clone()), 40, [1; 32], 0, NOW + 10, &None).unwrap();
    replay(env);
    s.transfer(&u1, &Holder::Addr(b.clone()), 60, [1; 32], 1, NOW + 10, &None).unwrap();
    replay(env);
    s.pay(&u2, &Holder::Addr(a.clone()), 25, [0x32; 32], NOW + 10).unwrap();
    replay(env);
    s.burn(&u1, 10, [2; 32], 0, NOW + 10).unwrap();
    replay(env);
    allow(env, &a, &s.t.address, "transfer", (&a, &b, 5i128).into_val(env));
    s.t.transfer(&a, &MuxedAddress::from(b.clone()), &5);
    replay(env);
    allow(env, &b, &s.t.address, "burn", (&b, 1i128).into_val(env));
    s.t.burn(&b, &1);
    replay(env);

    let pool_key = ScVal::try_from_val(env, &s.t.address.to_val()).unwrap();
    assert!(book.iter().any(|(k, _)| *k == pool_key), "the pool appears in the events");
    assert_eq!(book.len(), 3);
    for (k, v) in &book {
        let addr = Address::try_from_val(env, &Val::try_from_val(env, k).unwrap()).unwrap();
        assert_eq!(s.t.balance(&addr), *v);
    }
    let (b1, b2) = (s.t.ua_balance(&u1.id), s.t.ua_balance(&u2.id));
    assert_eq!((b1, b2), (300 + 70 - 40 - 60 - 10, 50 + 40 - 25));
    assert_eq!(s.t.balance(&s.t.address), b1 + b2);
}

/// S8: `Some(r)` needs `r`'s authorisation of exactly this call; `None` needs none.
#[test]
fn relayer_bound_needs_auth() {
    let s = setup();
    let env = &s.env;
    let (u, v) = (s.ua(1), s.ua(2));
    s.mint_ua(&u.id, 100);
    let (r, other) = (Some(Address::generate(env)), Address::generate(env));
    let to = Holder::Ua(v.id.clone());
    let lane = n(env, [1; 32]);
    let auth = s.sign(&u, PURPOSE_METATX, "ua_transfer", (&u.id, &to, 5i128, &lane, 0u64, NOW + 10, &r).into_val(env));
    let all: SVec<Val> = (&u.id, &to, 5i128, &lane, 0u64, NOW + 10, &r, &auth).into_val(env);
    assert!(s.t.try_ua_transfer(&u.id, &to, &5, &lane, &0, &(NOW + 10), &r, &auth).is_err(), "no relayer auth");
    allow(env, &other, &s.t.address, "ua_transfer", all.clone());
    assert!(s.t.try_ua_transfer(&u.id, &to, &5, &lane, &0, &(NOW + 10), &r, &auth).is_err(), "another address's auth");
    assert_eq!(s.t.ua_nonce(&u.id, &lane), 0);
    allow(env, r.as_ref().unwrap(), &s.t.address, "ua_transfer", all);
    s.t.ua_transfer(&u.id, &to, &5, &lane, &0, &(NOW + 10), &r, &auth);
    assert_eq!(env.auths()[0].0, r.clone().unwrap());
    // The signature binds the relayer: the same entry with None is another digest.
    assert!(s.t.try_ua_transfer(&u.id, &to, &5, &lane, &1, &(NOW + 10), &None, &auth).is_err());
    s.transfer(&u, &to, 5, [1; 32], 1, NOW + 10, &None).unwrap();
    assert!(env.auths().is_empty(), "None asks nobody");
    assert_eq!(s.t.ua_balance(&v.id), 10);
}

#[test]
fn ua_ledger_off_refused() {
    let s = setup_with(false);
    let env = &s.env;
    assert_eq!(s.t.registry(), None);
    let u = s.ua(1);
    let a = Address::generate(env);
    s.mint(&a, 100);
    let pool = &s.t.address;
    let (r, z) = (n(env, [1; 32]), Bytes::new(env));
    let to = Holder::Ua(u.id.clone());
    allow(env, &a, pool, "transfer_to_ua", (&a, &u.id, 1i128).into_val(env));
    assert_eq!(err(s.t.try_transfer_to_ua(&a, &u.id, &1)), Error::UaLedgerOff);
    allow(env, &a, pool, "pay_to_ua", (&a, &u.id, 1i128, &r, NOW + 10).into_val(env));
    assert_eq!(err(s.t.try_pay_to_ua(&a, &u.id, &1, &r, &(NOW + 10))), Error::UaLedgerOff);
    allow(env, &s.admin, pool, "mint_to_ua", (&u.id, 1i128).into_val(env));
    assert_eq!(err(s.t.try_mint_to_ua(&u.id, &1)), Error::UaLedgerOff);
    assert_eq!(s.transfer(&u, &to, 1, [1; 32], 0, NOW + 10, &None), Err(Error::UaLedgerOff));
    assert_eq!(s.pay(&u, &to, 1, [1; 32], NOW + 10), Err(Error::UaLedgerOff));
    assert_eq!(err(s.t.try_ua_pay_meta(&u.id, &to, &1, &r, &z, &(NOW + 10), &None, &z)), Error::UaLedgerOff);
    assert_eq!(s.burn(&u, 1, [1; 32], 0, NOW + 10), Err(Error::UaLedgerOff));
    assert_eq!(err(s.t.try_ua_cancel_nonce(&u.id, &r, &(NOW + 10), &z)), Error::UaLedgerOff);
    let dex = Address::generate(env);
    let o = order(env, &u.id, pool, 10);
    allow(env, &dex, pool, "ua_trade", (&dex, &o, &z, 1i128).into_val(env));
    assert_eq!(err(s.t.try_ua_trade(&dex, &o, &z, &1)), Error::UaLedgerOff);
    assert_eq!(s.t.balance(&a), 100);
}

/// S9 / SOR-D15: an unregistered id is `UaNotRegistered`, a registered but unspendable one `UaNotReceivable`.
#[test]
fn ua_receiver_not_registered_or_not_receivable() {
    let s = setup();
    let env = &s.env;
    let p: Value = serde_json::from_str(PORTABLE).unwrap();
    let row = |name: &str| p["registrations"].as_array().unwrap().iter().find(|r| r["name"] == name).unwrap().clone();
    let on = |r: &Value| {
        let kind = r["kind"].as_u64().unwrap() as u32;
        s.reg.register(&kind, &Bytes::from_slice(env, &hx(&r["keyData"])), &no_attrs(env), &Bytes::from_slice(env, &hx(&r["pop"])), &Bytes::new(env), &None)
    };
    on(&row("mldsa65#1"));
    let unspendable = on(&row("msig-pq-native"));
    assert!(!s.reg.receivable(&unspendable));
    let ghost = n(env, [0x42; 32]);
    let u = s.ua(1);
    s.mint_ua(&u.id, 100);
    let a = Address::generate(env);
    s.mint(&a, 100);
    for (id, want) in [(&ghost, Error::UaNotRegistered), (&unspendable, Error::UaNotReceivable)] {
        assert_eq!(s.transfer(&u, &Holder::Ua(id.clone()), 1, [1; 32], 0, NOW + 10, &None), Err(want));
        assert_eq!(s.pay(&u, &Holder::Ua(id.clone()), 1, [2; 32], NOW + 10), Err(want));
        allow(env, &s.admin, &s.t.address, "mint_to_ua", (id, 1i128).into_val(env));
        assert_eq!(err(s.t.try_mint_to_ua(id, &1)), want);
        allow(env, &a, &s.t.address, "transfer_to_ua", (&a, id, 1i128).into_val(env));
        assert_eq!(err(s.t.try_transfer_to_ua(&a, id, &1)), want);
        let r = n(env, [3; 32]);
        allow(env, &a, &s.t.address, "pay_to_ua", (&a, id, 1i128, &r, NOW + 10).into_val(env));
        assert_eq!(err(s.t.try_pay_to_ua(&a, id, &1, &r, &(NOW + 10))), want);
    }
    assert_eq!((s.t.ua_balance(&u.id), s.t.balance(&a), s.t.balance(&s.t.address)), (100, 100, 100));
}

#[test]
fn mint_to_ua_admin_only() {
    let s = setup();
    let env = &s.env;
    let u = s.ua(1);
    assert!(s.t.try_mint_to_ua(&u.id, &10).is_err(), "no auth");
    let other = Address::generate(env);
    allow(env, &other, &s.t.address, "mint_to_ua", (&u.id, 10i128).into_val(env));
    assert!(s.t.try_mint_to_ua(&u.id, &10).is_err(), "not the admin");
    s.mint_ua(&u.id, 10);
    assert_eq!(env.auths()[0].0, s.admin);
    assert_eq!(s.event_names(), ["mint", "UaTransfer"]);
    assert_eq!((s.t.ua_balance(&u.id), s.t.balance(&s.t.address)), (10, 10));
    allow(env, &s.admin, &s.t.address, "mint_to_ua", (&u.id, -1i128).into_val(env));
    assert_eq!(err(s.t.try_mint_to_ua(&u.id, &-1)), Error::NegativeAmount);
}

/// S11: `UaBalance` and `UaNonce` are persistent and extended to 60 days on each write and each read.
#[test]
fn ua_entries_extend_ttl() {
    let s = setup();
    let env = &s.env;
    let (u, v) = (s.ua(1), s.ua(2));
    s.mint_ua(&u.id, 100);
    s.mint_ua(&v.id, 1);
    s.transfer(&u, &Holder::Ua(v.id.clone()), 1, [1; 32], 0, u64::MAX, &None).unwrap();
    let ttl = |k: &Key| env.as_contract(&s.t.address, || env.storage().persistent().get_ttl(k));
    let (bu, bv, nu) = (Key::UaBalance(u.id.clone()), Key::UaBalance(v.id.clone()), Key::UaNonce(u.id.clone(), n(env, [1; 32])));
    for k in [&bu, &bv, &nu] {
        assert_eq!(ttl(k), 60 * DAY);
    }
    env.ledger().with_mut(|l| l.sequence_number += 31 * DAY);
    for k in [&bu, &bv, &nu] {
        assert_eq!(ttl(k), 29 * DAY);
    }
    // A burn reads and writes `UaBalance(u)` and the lane; `UaBalance(v)` is not touched.
    s.burn(&u, 1, [1; 32], 1, u64::MAX).unwrap();
    assert_eq!((ttl(&bu), ttl(&nu), ttl(&bv)), (60 * DAY, 60 * DAY, 29 * DAY));
    // A read inside a transaction extends the entry too.
    env.as_contract(&s.t.address, || {
        let _ = Token::ua_balance(env.clone(), v.id.clone());
    });
    assert_eq!(ttl(&bv), 60 * DAY);
}

// ---------- ua_trade ----------

fn order(env: &Env, maker: &BytesN<32>, sell_token: &Address, sell_amount: i128) -> Order {
    Order {
        maker: Holder::Ua(maker.clone()),
        destination: Holder::Ua(maker.clone()),
        relayer: Address::generate(env),
        sell_token: sell_token.clone(),
        sell_amount,
        buy_token: Address::generate(env),
        buy_amount: 1,
        max_fee_ppm: 0,
        expiry: NOW + 100,
        salt: 1,
    }
}

/// A stand-in DEX: calls `token.ua_trade(dex, …)` as the direct invoker.
#[contract]
pub struct FakeDex;

#[contractimpl]
impl FakeDex {
    pub fn take(env: Env, token: Address, dex: Address, order: Order, auth: Bytes, amount: i128) {
        TokenClient::new(&env, &token).ua_trade(&dex, &order, &auth, &amount);
    }
}

#[test]
fn ua_trade_only_named_dex() {
    let s = setup();
    let env = &s.env;
    let u = s.ua(1);
    s.mint_ua(&u.id, 100);
    let (dex, dex2) = (env.register(FakeDex, ()), env.register(FakeDex, ()));
    let (d1, d2) = (FakeDexClient::new(env, &dex), FakeDexClient::new(env, &dex2));
    let o = order(env, &u.id, &s.t.address, 60);
    let auth = s.sign(&u, PURPOSE_TRADE, "ua_order", (&dex, &o).into_val(env));
    // Another DEX naming the signed one (no authority as it), or naming itself (another digest).
    assert!(d2.try_take(&s.t.address, &dex, &o, &auth, &10).is_err());
    assert!(d2.try_take(&s.t.address, &dex2, &o, &auth, &10).is_err());
    // A direct call naming the DEX, without its authority.
    assert!(s.t.try_ua_trade(&dex, &o, &auth, &10).is_err());
    // The named DEX fills partially, twice, with one signature.
    d1.take(&s.t.address, &dex, &o, &auth, &25);
    d1.take(&s.t.address, &dex, &o, &auth, &35);
    assert_eq!((s.t.ua_balance(&u.id), s.t.balance(&dex), s.t.balance(&s.t.address)), (40, 60, 40));
    // Purpose metatx over the same digest is not a trade signature.
    let wrong = s.sign(&u, PURPOSE_METATX, "ua_order", (&dex, &o).into_val(env));
    assert!(d1.try_take(&s.t.address, &dex, &o, &wrong, &1).is_err());
    // A native maker, another sell token, an expired order.
    let mut native = o.clone();
    native.maker = Holder::Addr(Address::generate(env));
    assert!(d1.try_take(&s.t.address, &dex, &native, &auth, &1).is_err());
    allow(env, &dex, &s.t.address, "ua_trade", (&dex, &native, &auth, 1i128).into_val(env));
    assert_eq!(err(s.t.try_ua_trade(&dex, &native, &auth, &1)), Error::BadOrder);
    let mut other = o.clone();
    other.sell_token = Address::generate(env);
    allow(env, &dex, &s.t.address, "ua_trade", (&dex, &other, &auth, 1i128).into_val(env));
    assert_eq!(err(s.t.try_ua_trade(&dex, &other, &auth, &1)), Error::BadOrder);
    env.ledger().with_mut(|l| l.timestamp = o.expiry + 1);
    allow(env, &dex, &s.t.address, "ua_trade", (&dex, &o, &auth, 1i128).into_val(env));
    assert_eq!(err(s.t.try_ua_trade(&dex, &o, &auth, &1)), Error::Expired);
}

/// Review I1 + controller ruling 2026-10-30 (EVM `DexNotContract` / `pulled[h]` parity): the token bounds what the named
/// DEX pulls. A UA with 1 000, a 60-unit order signed for a `FakeDex`.
fn trade_fixture() -> (T, Ua, Address, Order, Bytes) {
    let s = setup();
    let u = s.ua(1);
    s.mint_ua(&u.id, 1_000);
    let dex = s.env.register(FakeDex, ());
    let o = order(&s.env, &u.id, &s.t.address, 60);
    let auth = s.sign(&u, PURPOSE_TRADE, "ua_order", (&dex, &o).into_val(&s.env));
    (s, u, dex, o, auth)
}

/// (a) `amount > sell_amount` in one call.
#[test]
fn ua_trade_over_pull_one_call_refused() {
    let (s, u, dex, o, auth) = trade_fixture();
    let d = FakeDexClient::new(&s.env, &dex);
    assert_eq!(err(d.try_take(&s.t.address, &dex, &o, &auth, &61)), Error::BadOrder);
    assert_eq!(s.t.ua_balance(&u.id), 1_000);
}

/// (c) the running `UaPulled(order digest)` total: two pulls over `sell_amount` refused, exactly `sell_amount` accepted.
#[test]
fn ua_trade_pulled_total_bounded() {
    let (s, u, dex, o, auth) = trade_fixture();
    let env = &s.env;
    let d = FakeDexClient::new(env, &dex);
    d.take(&s.t.address, &dex, &o, &auth, &40);
    assert_eq!(err(d.try_take(&s.t.address, &dex, &o, &auth, &21)), Error::BadOrder);
    d.take(&s.t.address, &dex, &o, &auth, &20);
    assert_eq!(err(d.try_take(&s.t.address, &dex, &o, &auth, &1)), Error::BadOrder);
    assert_eq!((s.t.ua_balance(&u.id), s.t.balance(&dex)), (940, 60));
    let k = Key::UaPulled(op_digest(env, &s.t.address, "ua_order", (&dex, &o).into_val(env)));
    env.as_contract(&s.t.address, || {
        assert_eq!(env.storage().persistent().get::<_, i128>(&k), Some(60));
        assert_eq!(env.storage().persistent().get_ttl(&k), 60 * DAY);
    });
}

/// (b) `dex` must be a deployed contract: a `G…` account (it signs for itself) or an empty `C…` id is refused.
#[test]
fn ua_trade_dex_must_be_contract() {
    let (s, u, _, _, _) = trade_fixture();
    let env = &s.env;
    for acct in [Address::from_str(env, "GAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTHCM6"), Address::generate(env)] {
        let o = order(env, &u.id, &s.t.address, 60);
        let auth = s.sign(&u, PURPOSE_TRADE, "ua_order", (&acct, &o).into_val(env));
        // Refused before its authorisation is asked for.
        assert_eq!(err(s.t.try_ua_trade(&acct, &o, &auth, &10)), Error::BadOrder);
    }
    assert_eq!(s.t.ua_balance(&u.id), 1_000);
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

/// SOR-D12: the token at `ua-ops.json`'s id and network id; every token row's digest is recomputed, and each `perKind`
/// `auth` of `ua_transfer` / `ua_pay` / `ua_pay_meta` / `ua_burn` / `ua_cancel_nonce` runs as the call it signs.
#[test]
fn ua_ops_vectors_token_rows() {
    let s = setup();
    let env = &s.env;
    let o = ops();
    for r in o["registrations"].as_array().unwrap() {
        let kind = r["kind"].as_u64().unwrap() as u32;
        let ua = s.reg.register(&kind, &Bytes::from_slice(env, &hx(&r["keyData"])), &no_attrs(env), &Bytes::from_slice(env, &hx(&r["pop"])), &Bytes::new(env), &None);
        assert_eq!(ua.to_array().to_vec(), hx(&r["ua"]), "{}", r["name"]);
        s.mint_ua(&ua, 1_000_000);
    }
    let token = o["contracts"]["token"].as_str().unwrap();
    let (mut digests, mut calls) = (0, 0);
    for e in o["entries"].as_array().unwrap() {
        if e["contract"] != token {
            continue;
        }
        let f = e["fn"].as_str().unwrap();
        let run = e["name"] == f && ["ua_transfer", "ua_pay", "ua_pay_meta", "ua_burn", "ua_cancel_nonce"].contains(&f);
        for p in e["perKind"].as_array().unwrap() {
            let args = arg_vals(env, p);
            assert_eq!(op_digest(env, &s.t.address, f, args.clone()).to_array().to_vec(), hx(&p["digest"]), "{} {}", e["name"], p["kind"]);
            digests += 1;
            if run {
                let mut all = args;
                all.push_back(Bytes::from_slice(env, &hx(&p["auth"])).into_val(env));
                let r = env.try_invoke_contract::<(), soroban_sdk::Error>(&s.t.address, &Symbol::new(env, f), all);
                assert!(r.is_ok(), "{} {}: {r:?}", e["name"], p["kind"]);
                calls += 1;
            }
        }
    }
    assert_eq!((digests, calls), (7 * 7, 5 * 7));
}
