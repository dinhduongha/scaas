//! Auth THẬT (không `mock_all_auths`): auth entry ký bằng ed25519 / passkey P-256 WebAuthn, host kiểm nonce/hạn.
extern crate std;

use super::*;
use scaas_token::{Token, TokenClient};
use ed25519_dalek::Signer as _;
use p256::ecdsa::{Signature as P256Sig, SigningKey as P256Key};
use sha2::{Digest, Sha256};
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::xdr::{
    self, HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limits, ScVal,
    SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, WriteXdr,
};
use soroban_sdk::{Address, IntoVal, String as SStr, TryFromVal, Val};

const NOW: u64 = 1_800_000_000;
const ORIGIN: &str = "https://shop.example";

struct T {
    env: Env,
    account: Address,
    ed: ed25519_dalek::SigningKey,
    t1: TokenClient<'static>,
    t2: TokenClient<'static>,
    payee: Address,
}

fn setup() -> T {
    let env = Env::default();
    env.ledger().with_mut(|l| {
        l.sequence_number = 100;
        l.timestamp = NOW;
        l.network_id = Sha256::digest(b"Standalone Network ; February 2017").into();
    });
    let ed = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let pk = BytesN::from_array(&env, &ed.verifying_key().to_bytes());
    let account = env.register(Account, (Key::Ed25519(pk),));
    let admin = Address::generate(&env);
    let mk = |env: &Env| {
        let id = env.register(Token, (admin.clone(), 7u32, SStr::from_str(env, "SCaaS"), SStr::from_str(env, "BMB")));
        TokenClient::new(env, &id)
    };
    let (t1, t2) = (mk(&env), mk(&env));
    env.mock_all_auths();
    t1.mint(&account, &1_000);
    t2.mint(&account, &1_000);
    let payee = Address::generate(&env);
    T { env, account, ed, t1, t2, payee }
}

pub fn invocation(env: &Env, contract: &Address, func: &str, args: soroban_sdk::Vec<Val>) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: contract.into(),
            function_name: func.try_into().unwrap(),
            args: args.iter().map(|v| ScVal::try_from_val(env, &v).unwrap()).collect::<std::vec::Vec<_>>().try_into().unwrap(),
        }),
        sub_invocations: Default::default(),
    }
}

/// Bytes chủ thể ký (trước sha256) — đúng như Odoo `fam_soroban.preimage` và Freighter `signAuthEntry`.
pub fn preimage(env: &Env, nonce: i64, exp: u32, inv: &SorobanAuthorizedInvocation) -> std::vec::Vec<u8> {
    HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: xdr::Hash(env.ledger().network_id().to_array()),
        nonce,
        signature_expiration_ledger: exp,
        invocation: inv.clone(),
    })
    .to_xdr(Limits::none())
    .unwrap()
}

fn entry(addr: &Address, nonce: i64, exp: u32, inv: SorobanAuthorizedInvocation, sig: ScVal) -> SorobanAuthorizationEntry {
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: addr.into(),
            nonce,
            signature_expiration_ledger: exp,
            signature: sig,
        }),
        root_invocation: inv,
    }
}

impl T {
    fn pay_args(&self, token: &TokenClient, amount: i128, r: u8) -> soroban_sdk::Vec<Val> {
        let _ = token;
        (self.account.clone(), self.payee.clone(), amount, BytesN::from_array(&self.env, &[r; 32]), NOW + 300).into_val(&self.env)
    }

    /// Auth entry ký bằng khoá ed25519 (id 0) của account.
    fn signed_pay(&self, token: &TokenClient, amount: i128, r: u8, nonce: i64) -> SorobanAuthorizationEntry {
        let inv = invocation(&self.env, &token.address, "pay", self.pay_args(token, amount, r));
        let payload: [u8; 32] = Sha256::digest(preimage(&self.env, nonce, 200, &inv)).into();
        let sig = self.ed.sign(&payload).to_bytes();
        let s: Val = Signature::Ed25519(0, BytesN::from_array(&self.env, &sig)).into_val(&self.env);
        entry(&self.account, nonce, 200, inv, ScVal::try_from_val(&self.env, &s).unwrap())
    }

    fn pay(&self, token: &TokenClient, amount: i128, r: u8, e: SorobanAuthorizationEntry) -> bool {
        self.env.set_auths(&[e]);
        token
            .try_pay(&self.account, &self.payee, &amount, &BytesN::from_array(&self.env, &[r; 32]), &(NOW + 300))
            .is_ok()
    }
}

#[test]
fn ed25519_key_pays_and_nonce_cannot_replay() {
    let t = setup();
    let e = t.signed_pay(&t.t1, 10, 1, 42);
    assert!(t.pay(&t.t1, 10, 1, e.clone()));
    assert_eq!(t.t1.balance(&t.payee), 10);
    assert!(!t.pay(&t.t1, 10, 1, e), "same (address, nonce) is spent");
    // Other payload (amount) under the same signature: refused.
    let mut forged = t.signed_pay(&t.t1, 10, 2, 43);
    if let SorobanAuthorizedFunction::ContractFn(ref mut f) = forged.root_invocation.function {
        let mut a: std::vec::Vec<ScVal> = f.args.to_vec();
        a[2] = ScVal::try_from_val(&t.env, &IntoVal::<Env, Val>::into_val(&999i128, &t.env)).unwrap();
        f.args = a.try_into().unwrap();
    }
    assert!(!t.pay(&t.t1, 999, 2, forged));
}

#[test]
fn signature_for_token_1_does_not_open_token_2() {
    let t = setup();
    let mut e = t.signed_pay(&t.t1, 10, 1, 7);
    e.root_invocation = invocation(&t.env, &t.t2.address, "pay", t.pay_args(&t.t2, 10, 1));
    assert!(!t.pay(&t.t2, 10, 1, e), "cross-contract replay");
}

/// R62 anti-lock: X trên contract 1 bị giữ lại, Y trên contract 2 vẫn chạy, rồi X vẫn chạy.
#[test]
fn anti_lock_withheld_op_does_not_block_another_contract() {
    let t = setup();
    let x = t.signed_pay(&t.t1, 10, 1, 1001);
    let y = t.signed_pay(&t.t2, 20, 2, 1002);
    assert!(t.pay(&t.t2, 20, 2, y));
    t.env.ledger().with_mut(|l| l.sequence_number += 50);
    assert!(t.pay(&t.t1, 10, 1, x));
    assert_eq!((t.t1.balance(&t.payee), t.t2.balance(&t.payee)), (10, 20));
}

#[test]
fn expired_signature_ledger_is_refused() {
    let t = setup();
    let e = t.signed_pay(&t.t1, 10, 1, 5);
    t.env.ledger().with_mut(|l| l.sequence_number = 201);
    assert!(!t.pay(&t.t1, 10, 1, e));
}

// ---------------------------------------------------------------- passkey

fn p256_key() -> P256Key {
    P256Key::from_slice(&[9u8; 32]).unwrap()
}

fn rp_hash() -> [u8; 32] {
    Sha256::digest(b"shop.example").into()
}

fn add_passkey(t: &T) -> u32 {
    let pk = p256_key().verifying_key().to_encoded_point(false);
    let key = Key::Passkey(Passkey {
        public_key: BytesN::from_array(&t.env, pk.as_bytes().try_into().unwrap()),
        rp_id_hash: BytesN::from_array(&t.env, &rp_hash()),
        origin: Bytes::from_slice(&t.env, ORIGIN.as_bytes()),
    });
    t.env.mock_all_auths();
    AccountClient::new(&t.env, &t.account).add_key(&key)
}

struct Assertion {
    flags: u8,
    origin: &'static str,
    kind: &'static str,
    rp: [u8; 32],
}

const GOOD: Assertion = Assertion { flags: 0x05, origin: ORIGIN, kind: "webauthn.get", rp: [0; 32] };

fn webauthn(t: &T, key_id: u32, challenge: [u8; 32], proof: std::vec::Vec<[u8; 32]>, a: &Assertion) -> ScVal {
    let mut b64 = [0u8; 43];
    base64url(&challenge, &mut b64);
    let cd = std::format!(
        r#"{{"type":"{}","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
        a.kind, core::str::from_utf8(&b64).unwrap(), a.origin
    );
    let mut ad = if a.rp == [0; 32] { rp_hash().to_vec() } else { a.rp.to_vec() };
    ad.push(a.flags);
    ad.extend_from_slice(&[0, 0, 0, 1]);
    let mut msg = ad.clone();
    msg.extend_from_slice(&Sha256::digest(cd.as_bytes()));
    let sig: P256Sig = p256_key().sign(&msg);
    let sig = sig.normalize_s().unwrap_or(sig);
    let mut pr = soroban_sdk::Vec::new(&t.env);
    for p in proof {
        pr.push_back(BytesN::from_array(&t.env, &p));
    }
    let s: Val = Signature::WebAuthn(WebAuthnSig {
        key_id,
        authenticator_data: Bytes::from_slice(&t.env, &ad),
        client_data_json: Bytes::from_slice(&t.env, cd.as_bytes()),
        signature: BytesN::from_array(&t.env, &sig.to_bytes().into()),
        proof: pr,
    })
    .into_val(&t.env);
    ScVal::try_from_val(&t.env, &s).unwrap()
}

fn passkey_pay(t: &T, key_id: u32, r: u8, nonce: i64, a: &Assertion) -> bool {
    let inv = invocation(&t.env, &t.t1.address, "pay", t.pay_args(&t.t1, 5, r));
    let payload: [u8; 32] = Sha256::digest(preimage(&t.env, nonce, 200, &inv)).into();
    let sig = webauthn(t, key_id, payload, std::vec![], a);
    t.pay(&t.t1, 5, r, entry(&t.account, nonce, 200, inv, sig))
}

#[test]
fn passkey_pays_and_bad_assertions_are_refused() {
    let t = setup();
    let id = add_passkey(&t);
    assert_eq!(id, 1);
    assert!(passkey_pay(&t, id, 1, 1, &GOOD));
    assert!(!passkey_pay(&t, id, 2, 2, &Assertion { origin: "https://evil.example", ..GOOD }));
    assert!(!passkey_pay(&t, id, 3, 3, &Assertion { kind: "webauthn.create", ..GOOD }));
    assert!(!passkey_pay(&t, id, 4, 4, &Assertion { flags: 0x01, ..GOOD }), "UV required");
    assert!(!passkey_pay(&t, id, 5, 5, &Assertion { rp: [1; 32], ..GOOD }));
    assert!(!passkey_pay(&t, 0, 6, 6, &GOOD), "key 0 is ed25519");
    assert_eq!(t.t1.balance(&t.payee), 5);
}

#[test]
fn passkey_challenge_must_be_this_payload() {
    let t = setup();
    let id = add_passkey(&t);
    let inv = invocation(&t.env, &t.t1.address, "pay", t.pay_args(&t.t1, 5, 1));
    let sig = webauthn(&t, id, [0xAB; 32], std::vec![], &GOOD);
    assert!(!t.pay(&t.t1, 5, 1, entry(&t.account, 9, 200, inv, sig)));
}

/// R31 gom lô: một assertion trên gốc Merkle của hai payload, mỗi auth entry mang proof của nó.
#[test]
fn passkey_batch_merkle() {
    let t = setup();
    let id = add_passkey(&t);
    let inv1 = invocation(&t.env, &t.t1.address, "pay", t.pay_args(&t.t1, 5, 1));
    let inv2 = invocation(&t.env, &t.t1.address, "pay", t.pay_args(&t.t1, 5, 2));
    let p1: [u8; 32] = Sha256::digest(preimage(&t.env, 11, 200, &inv1)).into();
    let p2: [u8; 32] = Sha256::digest(preimage(&t.env, 12, 200, &inv2)).into();
    let leaf = |p: [u8; 32]| -> [u8; 32] {
        let mut v = std::vec![0u8];
        v.extend_from_slice(&p);
        Sha256::digest(Sha256::digest(&v)).into()
    };
    let (l1, l2) = (leaf(p1), leaf(p2));
    let (a, b) = if l1 < l2 { (l1, l2) } else { (l2, l1) };
    let root: [u8; 32] = Sha256::digest([a, b].concat()).into();
    let s1 = webauthn(&t, id, root, std::vec![l2], &GOOD);
    let s2 = webauthn(&t, id, root, std::vec![l1], &GOOD);
    assert!(t.pay(&t.t1, 5, 1, entry(&t.account, 11, 200, inv1.clone(), s1.clone())));
    assert!(t.pay(&t.t1, 5, 2, entry(&t.account, 12, 200, inv2, s2)));
    // proof for payload 1 cannot authorise payload 2's invocation.
    let inv3 = invocation(&t.env, &t.t1.address, "pay", t.pay_args(&t.t1, 5, 3));
    assert!(!t.pay(&t.t1, 5, 3, entry(&t.account, 13, 200, inv3, s1)));
}

#[test]
fn last_key_cannot_be_removed() {
    let t = setup();
    t.env.mock_all_auths();
    let c = AccountClient::new(&t.env, &t.account);
    assert!(c.try_remove_key(&0).is_err());
    let id = add_passkey(&t);
    c.remove_key(&0);
    assert_eq!(c.keys().keys().len(), 1);
    assert!(c.try_remove_key(&id).is_err());
}

#[test]
fn adding_a_key_needs_an_existing_key() {
    let t = setup();
    let c = AccountClient::new(&t.env, &t.account);
    let other = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let key = Key::Ed25519(BytesN::from_array(&t.env, &other.verifying_key().to_bytes()));
    let args: soroban_sdk::Vec<Val> = (key.clone(),).into_val(&t.env);
    let inv = invocation(&t.env, &t.account, "add_key", args);
    let payload: [u8; 32] = Sha256::digest(preimage(&t.env, 77, 200, &inv)).into();
    // Signed by a key the account does not hold: refused.
    let s: Val = Signature::Ed25519(0, BytesN::from_array(&t.env, &other.sign(&payload).to_bytes())).into_val(&t.env);
    t.env.set_auths(&[entry(&t.account, 77, 200, inv.clone(), ScVal::try_from_val(&t.env, &s).unwrap())]);
    assert!(c.try_add_key(&key).is_err());
    let s: Val = Signature::Ed25519(0, BytesN::from_array(&t.env, &t.ed.sign(&payload).to_bytes())).into_val(&t.env);
    t.env.set_auths(&[entry(&t.account, 77, 200, inv, ScVal::try_from_val(&t.env, &s).unwrap())]);
    assert_eq!(c.add_key(&key), 1);
}

// ---------------------------------------------------------------- DEX under real auth (R8-3)

fn ed_entry(env: &Env, account: &Address, key: &ed25519_dalek::SigningKey, inv: SorobanAuthorizedInvocation, nonce: i64) -> SorobanAuthorizationEntry {
    let payload: [u8; 32] = Sha256::digest(preimage(env, nonce, 200, &inv)).into();
    let s: Val = Signature::Ed25519(0, BytesN::from_array(env, &key.sign(&payload).to_bytes())).into_val(env);
    entry(account, nonce, 200, inv, ScVal::try_from_val(env, &s).unwrap())
}

/// `require_auth_for_args((order,))` khớp auth entry thật của cả hai maker; một auth entry = một lần settle.
#[test]
fn dex_settles_on_real_signatures_once_per_signature() {
    use scaas_dex::{Dex, DexClient, Market, Order};
    let t = setup();
    let e = &t.env;
    let bob_key = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let bob = e.register(Account, (Key::Ed25519(BytesN::from_array(e, &bob_key.verifying_key().to_bytes())),));
    let admin = Address::generate(e);
    let dex = DexClient::new(e, &e.register(Dex, (admin, Address::generate(e))));
    e.mock_all_auths();
    t.t2.mint(&bob, &1_000);
    dex.set_market(&t.t1.address, &t.t2.address, &Market { maker_fee_ppm: 0, taker_fee_ppm: 0, fee_on: false });
    t.t1.approve(&t.account, &dex.address, &1_000, &1_000);
    t.t2.approve(&bob, &dex.address, &1_000, &1_000);
    let ask = Order { maker: t.account.clone(), sell_token: t.t1.address.clone(), sell_amount: 100,
                      buy_token: t.t2.address.clone(), buy_amount: 200, max_fee_ppm: 0, expiry: NOW + 60, salt: 1 };
    let bid = Order { maker: bob.clone(), sell_token: t.t2.address.clone(), sell_amount: 300,
                      buy_token: t.t1.address.clone(), buy_amount: 100, max_fee_ppm: 0, expiry: NOW + 60, salt: 2 };
    let a = ed_entry(e, &t.account, &t.ed, invocation(e, &dex.address, "settle", (ask.clone(),).into_val(e)), 501);
    let b = ed_entry(e, &bob, &bob_key, invocation(e, &dex.address, "settle", (bid.clone(),).into_val(e)), 502);
    e.set_auths(&[a.clone(), b.clone()]);
    dex.settle(&ask, &bid, &40);
    assert_eq!((t.t1.balance(&bob), t.t2.balance(&t.account)), (40, 1_080));
    // Same signatures again: nonces are spent — the maker must re-sign the rest (R8-3).
    e.set_auths(&[a, b]);
    assert!(dex.try_settle(&ask, &bid, &40).is_err());
    // A taker signature over a different order cannot be used for this one.
    let bid2 = Order { salt: 3, ..bid.clone() };
    let a2 = ed_entry(e, &t.account, &t.ed, invocation(e, &dex.address, "settle", (ask.clone(),).into_val(e)), 503);
    let b2 = ed_entry(e, &bob, &bob_key, invocation(e, &dex.address, "settle", (bid2,).into_val(e)), 504);
    e.set_auths(&[a2.clone(), b2]);
    assert!(dex.try_settle(&ask, &bid, &40).is_err());
    // Re-signed copies of the same orders fill the remainder; filled[] still bounds the total.
    let b3 = ed_entry(e, &bob, &bob_key, invocation(e, &dex.address, "settle", (bid.clone(),).into_val(e)), 505);
    e.set_auths(&[a2, b3]);
    dex.settle(&ask, &bid, &60);
    assert_eq!(dex.filled(&dex.order_hash(&ask)), 100);
}
