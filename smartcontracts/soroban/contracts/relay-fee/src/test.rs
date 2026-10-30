extern crate std;

use super::*;
use ed25519_dalek::Signer as _;
use scaas_mandate::{Holder, MandateWallet, MandateWalletClient};
use scaas_relay_executor::{RelayExecutor, RelayExecutorClient};
use scaas_ua_common::{h32, op_digest, UaAttrs, PURPOSE_METATX, PURPOSE_METATX_CANCEL, PURPOSE_POP_V2};
use scaas_ua_registry::{UaRegistry, UaRegistryClient as RegClient};
use scaas_token::{Token, TokenClient};
use sha2::{Digest, Sha256};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger, MockAuth, MockAuthInvoke};
use soroban_sdk::xdr::{
    self, AccountId, HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limits, PublicKey,
    ScAddress, ScErrorCode, ScErrorType, ScMap, ScMapEntry, ScSymbol, ScVal, SorobanAddressCredentials,
    ReadXdr as _, SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials,
    Uint256, WriteXdr,
};
use soroban_sdk::{IntoVal, String, Symbol, TryFromVal, Val};

const NOW: u64 = 1_800_000_000;
const NETWORK: [u8; 32] = [7; 32];
pub const TOKEN: &str = "CARCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEVQO";
pub const OWNER: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";
pub const WALLET: &str = "CAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGGJH";
/// A real account strkey (no contract, no code behind it).
pub const ACCOUNT: &str = "GAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTHCM6";
/// `relay_ref(WALLET, "revoke", (TOKEN, OWNER), salt 0x09 x 32)` on `NETWORK`; the node adapter pins the same value.
pub const VEC_REF: &str = "ce0e8797ad9aa168b64b32821f51bea8a931dbb5e8e15e0044cb94ca9dd4f106";

struct T {
    env: Env,
    token: TokenClient<'static>,
    wallet: MandateWalletClient<'static>,
    router: RelayFeeClient<'static>,
    owner: Address,
    relayer: Address,
}

/// The router at `at` and its executor (bound both ways by their constructors).
fn deploy_router(env: &Env, at: &Address) -> RelayFeeClient<'static> {
    let x = env.register(RelayExecutor, (at.clone(),));
    RelayFeeClient::new(env, &env.register_at(at, RelayFee, (x,)))
}

/// A router whose executor is bound to another router fails at deploy (`BadExecutor`), not at the first relay.
#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn constructor_refuses_a_foreign_executor() {
    let env = Env::default();
    let x = env.register(RelayExecutor, (Address::generate(&env),));
    env.register(RelayFee, (x,));
}

fn setup() -> T {
    setup_with(Env::default())
}

fn setup_with(env: Env) -> T {
    env.ledger().with_mut(|l| {
        l.sequence_number = 100;
        l.timestamp = NOW;
        l.network_id = NETWORK;
    });
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let tid = env.register_at(
        &Address::from_str(&env, TOKEN),
        Token,
        (admin, 7u32, String::from_str(&env, "SCaaS"), String::from_str(&env, "BMB"), None::<Address>),
    );
    let token = TokenClient::new(&env, &tid);
    let owner = Address::generate(&env);
    let wid = env.register_at(&Address::from_str(&env, WALLET), MandateWallet, (Holder::Addr(owner.clone()), None::<Address>));
    let wallet = MandateWalletClient::new(&env, &wid);
    // The mandate is the target's state: the fee-less call revokes it.
    set_mandate(&env, &wallet, &tid);
    let router = deploy_router(&env, &Address::generate(&env));
    token.mint(&owner, &100);
    T { env: env.clone(), token, wallet, router, owner, relayer: Address::generate(&env) }
}

type Res = Result<(), soroban_sdk::Error>;

/// A native owner's `mtx_*` tail: lane 0x01 x 32, nonce 0 (not consumed for a native holder), no relayer, empty auth.
fn tail(env: &Env) -> (BytesN<32>, u64, u64, Option<Address>, Bytes) {
    (BytesN::from_array(env, &[1; 32]), 0, NOW + 60, None, Bytes::new(env))
}

/// `wallet.mtx_revoke(token, by, epoch 0, tail)` arguments (`by` is the owner: its epoch is not checked).
fn revoke_args(env: &Env, token: &Address, by: &Address) -> soroban_sdk::Vec<Val> {
    let (lane, nonce, vu, relayer, auth) = tail(env);
    (token.clone(), Holder::Addr(by.clone()), 0u64, lane, nonce, vu, relayer, auth).into_val(env)
}

/// A native owner sets a mandate for a fresh native delegate (host auth mocked by the caller).
fn set_mandate(env: &Env, wallet: &MandateWalletClient, token: &Address) {
    let (lane, nonce, vu, relayer, auth) = tail(env);
    let d = Holder::Addr(Address::generate(env));
    wallet.mtx_set_mandate(token, &d, &100, &150, &3600, &(NOW + 86_400), &lane, &nonce, &vu, &relayer, &auth);
}

impl T {
    fn args(&self) -> soroban_sdk::Vec<Val> {
        revoke_args(&self.env, &self.token.address, &self.owner)
    }
    fn func(&self) -> Symbol {
        Symbol::new(&self.env, "mtx_revoke")
    }
    fn salt(&self, n: u8) -> BytesN<32> {
        BytesN::from_array(&self.env, &[n; 32])
    }
    fn rf(&self, n: u8) -> BytesN<32> {
        self.router.relay_ref(&self.wallet.address, &self.func(), &self.args(), &self.salt(n))
    }
    fn relay(&self, to: &Address, amount: i128) -> Res {
        self.relay_call(&self.wallet.address, &self.func(), &self.args(), 1, to, amount)
    }
    fn relay_call(&self, target: &Address, f: &Symbol, a: &soroban_sdk::Vec<Val>, salt: u8, to: &Address, amount: i128) -> Res {
        match self.router.try_relay(
            &self.owner, target, f, a, &self.salt(salt), &self.token.address, to, &amount, &(NOW + 60), &self.relayer,
        ) {
            Ok(r) => Ok(r.unwrap()),
            Err(e) => Err(e.unwrap()),
        }
    }
}

fn err<E: Into<soroban_sdk::Error>>(e: E) -> Res {
    Err(e.into())
}

fn hex(b: &[u8]) -> std::string::String {
    b.iter().map(|x| std::format!("{x:02x}")).collect()
}

/// A `Holder` as the event data carries it.
fn hv(env: &Env, h: Holder) -> ScVal {
    ScVal::try_from_val(env, &IntoVal::<Env, Val>::into_val(&h, env)).unwrap()
}

fn auth_err() -> soroban_sdk::Error {
    soroban_sdk::Error::from_type_and_code(ScErrorType::Context, ScErrorCode::InvalidAction)
}

fn event_data(all: &soroban_sdk::testutils::ContractEvents, name: &str) -> std::vec::Vec<ScVal> {
    let ev: std::vec::Vec<_> = all
        .events()
        .iter()
        .filter(|e| {
            let xdr::ContractEventBody::V0(b) = &e.body;
            matches!(&b.topics[0], ScVal::Symbol(s) if s.to_utf8_string_lossy() == name)
        })
        .collect();
    assert_eq!(ev.len(), 1);
    let xdr::ContractEventBody::V0(b) = &ev[0].body;
    let ScVal::Vec(Some(d)) = &b.data else { panic!() };
    d.to_vec()
}

#[test]
fn relay_open_mode_pays_relayer() {
    let t = setup();
    let rf = t.rf(1);
    t.relay(&t.router.address, 7).unwrap();
    let all = t.env.events().all();
    assert!(t.wallet.mandate(&t.token.address).is_none(), "the target call ran");
    assert_eq!((t.token.balance(&t.owner), t.token.balance(&t.relayer), t.token.balance(&t.router.address)), (93, 7, 0));
    assert!(t.token.ref_used(&t.owner, &rf));
    // RelayFeePaid names the relayer, not the router, as payee (SOR-D11: both as a `Holder`).
    let d = event_data(&all, "RelayFeePaid");
    assert_eq!(d[0], hv(&t.env, Holder::Addr(t.owner.clone())));
    assert_eq!(d[1], hv(&t.env, Holder::Addr(t.relayer.clone())));
}

#[test]
fn relay_bound_payee() {
    let t = setup();
    let treasury = Address::generate(&t.env);
    t.relay(&treasury, 7).unwrap();
    assert_eq!((t.token.balance(&t.owner), t.token.balance(&treasury), t.token.balance(&t.relayer)), (93, 7, 0));
    assert!(t.wallet.mandate(&t.token.address).is_none());
}

/// controller call 2026-10-27: a payer-signed salt enters `ref`, so an identical call can be fee-paid again; the
/// same (call, salt) cannot be paid twice.
#[test]
fn relay_same_call_with_different_salts_and_replay() {
    let t = setup();
    let payee = Address::generate(&t.env);
    let (lane, nonce, vu, relayer, auth) = tail(&t.env);
    let a = (t.token.address.clone(), Holder::Addr(payee), true, lane, nonce, vu, relayer, auth).into_val(&t.env);
    let f = Symbol::new(&t.env, "mtx_set_payee");
    t.relay_call(&t.wallet.address, &f, &a, 1, &t.router.address, 5).unwrap();
    t.relay_call(&t.wallet.address, &f, &a, 2, &t.router.address, 5).unwrap();
    assert_eq!((t.token.balance(&t.owner), t.token.balance(&t.relayer)), (90, 10));
    assert_ne!(
        t.router.relay_ref(&t.wallet.address, &f, &a, &t.salt(1)),
        t.router.relay_ref(&t.wallet.address, &f, &a, &t.salt(2))
    );
    // Same call, same salt: the (payer, ref) is spent, nothing moves.
    assert_eq!(t.relay_call(&t.wallet.address, &f, &a, 1, &t.router.address, 5), err(scaas_token::Error::RefUsed));
    assert_eq!(t.token.balance(&t.relayer), 10);
}

/// controller call 2026-10-27: an attacker's 0-amount pay with the victim's ref cannot block the victim.
#[test]
fn relay_attacker_cannot_pre_burn_the_ref() {
    let t = setup();
    let attacker = Address::generate(&t.env);
    let rf = t.rf(1);
    t.token.pay(&attacker, &attacker, &0, &rf, &(NOW + 60));
    t.relay(&t.router.address, 7).unwrap();
    assert_eq!(t.token.balance(&t.relayer), 7);
}

#[test]
fn relay_target_failure_reverts_all() {
    let t = setup();
    // The call fails (a revoke by a stranger): the payment must not happen.
    let stranger = Address::generate(&t.env);
    let bad = revoke_args(&t.env, &t.token.address, &stranger);
    assert_eq!(t.relay_call(&t.wallet.address, &t.func(), &bad, 1, &t.router.address, 7), err(scaas_mandate::Error::NotAllowed));
    assert_eq!((t.token.balance(&t.owner), t.token.balance(&t.relayer)), (100, 0));
    assert!(!t.token.ref_used(&t.owner, &t.router.relay_ref(&t.wallet.address, &t.func(), &bad, &t.salt(1))));
    assert!(t.wallet.mandate(&t.token.address).is_some());
    // The payment fails (too little balance) on a fresh mandate: the call is rolled back.
    assert_eq!(t.relay(&t.router.address, 1_000), err(scaas_token::Error::InsufficientBalance));
    assert!(t.wallet.mandate(&t.token.address).is_some(), "the target call is rolled back with the payment");
    assert!(!t.token.ref_used(&t.owner, &t.rf(1)));
}

/// Carried router rule 1: the target must be an instantiated contract, refused before any token call.
#[test]
fn relay_refuses_target_without_contract() {
    let t = setup();
    // A contract id with nothing deployed, an account address built from a G strkey, and the payer's account.
    for ghost in [Address::generate(&t.env), Address::from_str(&t.env, ACCOUNT), Address::from_str(&t.env, OWNER)] {
        assert_eq!(
            t.relay_call(&ghost, &t.func(), &t.args(), 1, &t.router.address, 7),
            err(Error::TargetNoCode)
        );
        assert!(!t.token.ref_used(&t.owner, &t.router.relay_ref(&ghost, &t.func(), &t.args(), &t.salt(1))));
    }
    assert_eq!((t.token.balance(&t.owner), t.token.balance(&t.relayer)), (100, 0));
}

/// Review focus 3: a payment signed for the router (auth entry rooted at `relay`) never settles through the
/// plain `token.pay`.
#[test]
fn soroban_router_bound_pay_refused_direct() {
    let t = setup();
    let rf = t.rf(1);
    let to = t.router.address.clone();
    let pay_args: soroban_sdk::Vec<Val> = (t.owner.clone(), to.clone(), 7i128, rf.clone(), NOW + 60).into_val(&t.env);
    let signed: soroban_sdk::Vec<Val> = (
        t.wallet.address.clone(), t.func(), t.args(), t.salt(1), t.token.address.clone(), to.clone(), 7i128, NOW + 60,
    )
        .into_val(&t.env);
    let relay_args: soroban_sdk::Vec<Val> = (
        t.owner.clone(), t.wallet.address.clone(), t.func(), t.args(), t.salt(1), t.token.address.clone(), to.clone(),
        7i128, NOW + 60, t.relayer.clone(),
    )
        .into_val(&t.env);
    let (pay, revoke) = (
        MockAuthInvoke { contract: &t.token.address, fn_name: "pay", args: pay_args.clone(), sub_invokes: &[] },
        MockAuthInvoke { contract: &t.wallet.address, fn_name: "mtx_revoke", args: t.args(), sub_invokes: &[] },
    );
    let relay_root = MockAuthInvoke {
        contract: &t.router.address, fn_name: "relay", args: signed, sub_invokes: &[revoke, pay],
    };
    let relayer_root = MockAuthInvoke { contract: &t.router.address, fn_name: "relay", args: relay_args, sub_invokes: &[] };
    t.env.mock_auths(&[
        MockAuth { address: &t.owner, invoke: &relay_root },
        MockAuth { address: &t.relayer, invoke: &relayer_root },
    ]);
    // The payer's signature (rooted at `relay`) does not authorise a direct pay.
    let r = t.token.try_pay(&t.owner, &to, &7, &rf, &(NOW + 60));
    assert_eq!(r.err().unwrap().unwrap(), auth_err());
    assert_eq!(t.token.balance(&t.router.address), 0);
    assert!(!t.token.ref_used(&t.owner, &rf));
    // The same signature settles through the router.
    t.relay(&to, 7).unwrap();
    assert_eq!(t.token.balance(&t.relayer), 7);
    // A relay whose signed amount differs from the executed one has no matching auth: refused.
    let r = t.router.try_relay(
        &t.owner, &t.wallet.address, &t.func(), &t.args(), &t.salt(1), &t.token.address, &to, &8, &(NOW + 60), &t.relayer,
    );
    assert_eq!(r.err().unwrap().unwrap(), auth_err());
}

#[test]
fn relay_ref_vectors() {
    let t = setup();
    let args: soroban_sdk::Vec<Val> =
        (t.token.address.clone(), Address::from_str(&t.env, OWNER)).into_val(&t.env);
    // Independent construction:
    // keccak256("scaas.relayfee" || network id || xdr(target) || keccak256(xdr((func, args))) || salt).
    let e = &t.env;
    // A pure ref computation over the pinned call: the router never runs it here.
    let func = Symbol::new(e, "revoke");
    let call = (func.clone(), args.clone()).to_xdr(e);
    let mut b = Bytes::from_slice(e, b"scaas.relayfee");
    b.append(&Bytes::from_array(e, &NETWORK));
    b.append(&t.wallet.address.clone().to_xdr(e));
    b.append(&e.crypto().keccak256(&call).to_bytes().into());
    b.append(&Bytes::from_array(e, &[9; 32]));
    let want = e.crypto().keccak256(&b).to_array();
    let rf = |a: &soroban_sdk::Vec<Val>, s: u8| t.router.relay_ref(&t.wallet.address, &func, a, &t.salt(s));
    assert_eq!(rf(&args, 9).to_array(), want);
    std::println!("ref {}", hex(&want));
    assert_eq!(hex(&want), VEC_REF);
    // The ref commits to the target, the function, every argument, the salt and the chain.
    let other: soroban_sdk::Vec<Val> = (t.token.address.clone(), t.relayer.clone()).into_val(e);
    assert_ne!(rf(&other, 9).to_array(), want);
    assert_ne!(rf(&args, 8).to_array(), want);
    assert_ne!(t.router.relay_ref(&t.token.address, &func, &args, &t.salt(9)).to_array(), want);
    assert_ne!(t.router.relay_ref(&t.wallet.address, &Symbol::new(e, "pay"), &args, &t.salt(9)).to_array(), want);
    e.ledger().with_mut(|l| l.network_id = [8; 32]);
    assert_ne!(rf(&args, 9).to_array(), want);
}

// ------------------------------------------------- real signed auth entries (no mock_all_auths)

fn account(env: &Env, pk: [u8; 32]) -> Address {
    let sc = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk))));
    Address::try_from_val(env, &ScVal::Address(sc)).unwrap()
}

fn inv(env: &Env, contract: &Address, f: &str, args: soroban_sdk::Vec<Val>, subs: std::vec::Vec<SorobanAuthorizedInvocation>) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: contract.into(),
            function_name: f.try_into().unwrap(),
            args: args.iter().map(|v| ScVal::try_from_val(env, &v).unwrap()).collect::<std::vec::Vec<_>>().try_into().unwrap(),
        }),
        sub_invocations: subs.try_into().unwrap(),
    }
}

fn signed_entry(sk: &ed25519_dalek::SigningKey, nonce: i64, root: SorobanAuthorizedInvocation) -> SorobanAuthorizationEntry {
    let pre = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: xdr::Hash(NETWORK),
        nonce,
        signature_expiration_ledger: 200,
        invocation: root.clone(),
    })
    .to_xdr(Limits::none())
    .unwrap();
    let sig = sk.sign(&Sha256::digest(pre)).to_bytes();
    let pk = sk.verifying_key().to_bytes();
    let kv = |k: &str, v: &[u8]| ScMapEntry { key: ScVal::Symbol(ScSymbol(k.try_into().unwrap())), val: ScVal::Bytes(v.to_vec().try_into().unwrap()) };
    let map = ScMap(std::vec![kv("public_key", &pk), kv("signature", &sig)].try_into().unwrap());
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk)))),
            nonce,
            signature_expiration_ledger: 200,
            signature: ScVal::Vec(Some(std::vec![ScVal::Map(Some(map))].try_into().unwrap())),
        }),
        root_invocation: root,
    }
}

/// A G-account payer and a G-account relayer with REAL signed entries rooted at `relay`: settles through the router,
/// and the same signature does not authorise a direct `token.pay`.
#[test]
fn relay_g_account_payer_real_signed_entries() {
    let (psk, rsk) = (ed25519_dalek::SigningKey::from_bytes(&[3; 32]), ed25519_dalek::SigningKey::from_bytes(&[4; 32]));
    let (ppk, rpk) = (psk.verifying_key().to_bytes(), rsk.verifying_key().to_bytes());
    // Both accounts must exist in the ledger: the host loads their signers to check the entries.
    let ledger_account = |pk: [u8; 32]| {
        let id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk)));
        (
            std::boxed::Box::new(xdr::LedgerKey::Account(xdr::LedgerKeyAccount { account_id: id.clone() })),
            (
                std::boxed::Box::new(xdr::LedgerEntry {
                    last_modified_ledger_seq: 0,
                    data: xdr::LedgerEntryData::Account(xdr::AccountEntry {
                        account_id: id,
                        balance: 1_000_000_000,
                        seq_num: xdr::SequenceNumber(0),
                        num_sub_entries: 0,
                        inflation_dest: None,
                        flags: 0,
                        home_domain: Default::default(),
                        thresholds: xdr::Thresholds([1, 0, 0, 0]),
                        signers: Default::default(),
                        ext: xdr::AccountEntryExt::V0,
                    }),
                    ext: xdr::LedgerEntryExt::V0,
                }),
                None,
            ),
        )
    };
    let mut snap: soroban_ledger_snapshot::LedgerSnapshot = Env::default().to_ledger_snapshot();
    snap.ledger_entries.extend([ledger_account(ppk), ledger_account(rpk)]);
    let t = setup_with(Env::from_ledger_snapshot(snap));
    let e = &t.env;
    let (payer, relayer) = (account(e, ppk), account(e, rpk));
    let wallet = MandateWalletClient::new(e, &e.register(MandateWallet, (Holder::Addr(payer.clone()), None::<Address>)));
    set_mandate(e, &wallet, &t.token.address);
    t.token.mint(&payer, &100);
    let (f, to, salt) = (Symbol::new(e, "mtx_revoke"), t.router.address.clone(), t.salt(5));
    let args = revoke_args(e, &t.token.address, &payer);
    let rf = t.router.relay_ref(&wallet.address, &f, &args, &salt);
    let signed: soroban_sdk::Vec<Val> = (wallet.address.clone(), f.clone(), args.clone(), salt.clone(), t.token.address.clone(), to.clone(), 7i128, NOW + 60).into_val(e);
    let pay_args: soroban_sdk::Vec<Val> = (payer.clone(), to.clone(), 7i128, rf.clone(), NOW + 60).into_val(e);
    let tree = |nonce: i64| {
        let subs = std::vec![
            inv(e, &wallet.address, "mtx_revoke", args.clone(), std::vec![]),
            inv(e, &t.token.address, "pay", pay_args.clone(), std::vec![]),
        ];
        signed_entry(&psk, nonce, inv(e, &t.router.address, "relay", signed.clone(), subs))
    };
    let relay_args: soroban_sdk::Vec<Val> = (payer.clone(), wallet.address.clone(), f.clone(), args.clone(), salt.clone(), t.token.address.clone(), to.clone(), 7i128, NOW + 60, relayer.clone()).into_val(e);
    let relayer_entry = |nonce: i64| signed_entry(&rsk, nonce, inv(e, &t.router.address, "relay", relay_args.clone(), std::vec![]));
    // Direct pay with the router-rooted signature: refused.
    e.set_auths(&[tree(10)]);
    let r = t.token.try_pay(&payer, &to, &7, &rf, &(NOW + 60));
    assert!(r.is_err());
    assert!(!t.token.ref_used(&payer, &rf));
    // Through the router with both signatures.
    e.set_auths(&[tree(11), relayer_entry(12)]);
    t.router.relay(&payer, &wallet.address, &f, &args, &salt, &t.token.address, &to, &7, &(NOW + 60), &relayer);
    assert!(wallet.mandate(&t.token.address).is_none());
    assert_eq!((t.token.balance(&payer), t.token.balance(&relayer)), (93, 7));
    // Without the relayer's entry the router refuses (source auth is not implicit).
    e.mock_all_auths();
    set_mandate(e, &wallet, &t.token.address);
    let salt2 = t.salt(6);
    let rf2 = t.router.relay_ref(&wallet.address, &f, &args, &salt2);
    let signed2: soroban_sdk::Vec<Val> = (wallet.address.clone(), f.clone(), args.clone(), salt2.clone(), t.token.address.clone(), to.clone(), 7i128, NOW + 60).into_val(e);
    let pay2: soroban_sdk::Vec<Val> = (payer.clone(), to.clone(), 7i128, rf2, NOW + 60).into_val(e);
    let subs = std::vec![inv(e, &wallet.address, "mtx_revoke", args.clone(), std::vec![]), inv(e, &t.token.address, "pay", pay2, std::vec![])];
    e.set_auths(&[signed_entry(&psk, 13, inv(e, &t.router.address, "relay", signed2, subs))]);
    let r = t.router.try_relay(&payer, &wallet.address, &f, &args, &salt2, &t.token.address, &to, &7, &(NOW + 60), &relayer);
    assert!(r.is_err());
}

// ------------------------------------------------- UA payer: `ua_relay` (spec §5.4, §5.5; SOR-D11)
// The real `UaRegistry` and token at `ua-ops.json`'s ids and network id, in-test ed25519 UAs. No `mock_all_auths`: a
// native authority (the relayer, the token admin) is mocked for exactly one address and invocation, a UA signs for real.

const OPS: &str = include_str!("../../../vectors/ua-ops.json");
const ED25519: u32 = 0x0102;
/// `keccak256("scaas.ua.msg.v1")` and `TAG(ed25519)` (CTR-UA-12, `kinds.json`).
const MSG_TAG: [u8; 32] = h32("30a5cfd6b1d0889ef4a90d8488fa5e6e615322735899e23243d69087b6b66349");
const ED_TAG: [u8; 32] = h32("65ca73d2d290503a4785188712dd0b971b5fbf3113c1dc87185a46021b5131bc");
/// The fee-less target call of these tests: the payer cancels one of its own UA nonce lanes on the token.
const CANCEL: &str = "ua_cancel_nonce";

fn ops() -> serde_json::Value {
    serde_json::from_str(OPS).unwrap()
}

fn hx(v: &serde_json::Value) -> std::vec::Vec<u8> {
    let s = v.as_str().unwrap().trim_start_matches("0x");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn arg_vals(env: &Env, p: &serde_json::Value) -> soroban_sdk::Vec<Val> {
    let mut v = soroban_sdk::Vec::new(env);
    for a in p["args"].as_array().unwrap() {
        let sc = ScVal::from_xdr(hx(&a["xdr"]), Limits::none()).unwrap();
        v.push_back(Val::try_from_val(env, &sc).unwrap());
    }
    v
}

fn keccak(env: &Env, parts: &[&[u8]]) -> [u8; 32] {
    let mut b = Bytes::new(env);
    for p in parts {
        b.extend_from_slice(p);
    }
    env.crypto().keccak256(&b).to_array()
}

fn b32(env: &Env, n: u8) -> BytesN<32> {
    BytesN::from_array(env, &[n; 32])
}

/// An in-test ed25519 UA, registered by its real `pop` (CTR-UA-07).
struct Ua {
    sk: ed25519_dalek::SigningKey,
    id: BytesN<32>,
}

struct U {
    env: Env,
    token: TokenClient<'static>,
    reg: RegClient<'static>,
    router: RelayFeeClient<'static>,
    admin: Address,
    relayer: Address,
}

fn ua_setup() -> U {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let o = ops();
    env.ledger().with_mut(|l| {
        l.sequence_number = 100;
        l.timestamp = NOW;
        l.network_id = hx(&o["network"]["networkId"]).try_into().unwrap();
    });
    let id = |k: &str| Address::from_str(&env, o["contracts"][k].as_str().unwrap());
    let reg = RegClient::new(&env, &env.register_at(&id("registry"), UaRegistry, (soroban_sdk::Vec::<Address>::new(&env),)));
    let admin = Address::generate(&env);
    let s = |x: &str| String::from_str(&env, x);
    let tid = env.register_at(&id("token"), Token, (admin.clone(), 7u32, s("SCaaS"), s("BMB"), Some(reg.address.clone())));
    let router = deploy_router(&env, &id("router"));
    U { token: TokenClient::new(&env, &tid), reg, router, admin, relayer: Address::generate(&env), env }
}

impl U {
    /// Mocks exactly `who`'s authorisation of `contract.f(args)` for the next call.
    fn allow(&self, who: &Address, contract: &Address, f: &str, args: soroban_sdk::Vec<Val>) {
        self.env.mock_auths(&[MockAuth { address: who, invoke: &MockAuthInvoke { contract, fn_name: f, args, sub_invokes: &[] } }]);
    }

    fn mint_ua(&self, ua: &BytesN<32>, amount: i128) {
        self.allow(&self.admin, &self.token.address, "mint_to_ua", (ua, amount).into_val(&self.env));
        self.token.mint_to_ua(ua, &amount);
    }

    /// A registered ed25519 UA holding `funds` in the token's UA ledger.
    fn ua(&self, seed: u8, funds: i128) -> Ua {
        let env = &self.env;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let kd = Bytes::from_array(env, &sk.verifying_key().to_bytes());
        let id = self.reg.ua_of(&ED25519, &kd);
        let z = [0u8; 32];
        let reg_digest = keccak(env, &[&keccak(env, &[&PURPOSE_POP_V2, &id.to_array(), &z, &z]), &z]);
        let pop = sk.sign(&keccak(env, &[&MSG_TAG, &ED_TAG, &PURPOSE_POP_V2, &reg_digest])).to_bytes();
        let attrs = UaAttrs { pqz_key: Bytes::new(env), pqz_pop_hash: b32(env, 0), kem_version: 0, kem_pk: Bytes::new(env) };
        self.reg.register(&ED25519, &kd, &attrs, &Bytes::from_array(env, &pop), &Bytes::new(env), &None);
        if funds > 0 {
            self.mint_ua(&id, funds);
        }
        Ua { sk, id }
    }

    /// The UA's signature over `op_digest(token, f, args)` under `purpose`.
    fn sign(&self, u: &Ua, purpose: [u8; 32], f: &str, args: soroban_sdk::Vec<Val>) -> Bytes {
        let d = op_digest(&self.env, &self.token.address, f, args).to_array();
        Bytes::from_array(&self.env, &u.sk.sign(&keccak(&self.env, &[&MSG_TAG, &ED_TAG, &purpose, &d])).to_bytes())
    }

    /// `token.ua_cancel_nonce(u, lane, …, auth)` arguments, signed by `u`.
    fn cancel_args(&self, u: &Ua, lane: u8) -> soroban_sdk::Vec<Val> {
        let (e, lane) = (&self.env, b32(&self.env, lane));
        let auth = self.sign(u, PURPOSE_METATX_CANCEL, CANCEL, (&u.id, &lane, NOW + 60).into_val(e));
        (&u.id, &lane, NOW + 60, auth).into_val(e)
    }

    fn rf(&self, args: &soroban_sdk::Vec<Val>, salt: u8) -> BytesN<32> {
        self.router.relay_ref(&self.token.address, &Symbol::new(&self.env, CANCEL), args, &b32(&self.env, salt))
    }

    /// The payer's UA signature of the inner `token.ua_pay` of a `ua_relay` with `ref = rf` (`relayer = Some(router)`).
    fn fee_auth(&self, u: &Ua, to: &Holder, amount: i128, rf: &BytesN<32>) -> Bytes {
        let a = (&u.id, to, amount, rf, NOW + 60, Some(self.router.address.clone()));
        self.sign(u, PURPOSE_METATX, "ua_pay", a.into_val(&self.env))
    }

    /// `router.ua_relay(payer, token, f, args, salt, token, to, amount, valid_until, relayer, auth)`; the relayer's
    /// host auth is mocked for exactly that call.
    #[allow(clippy::too_many_arguments)]
    fn relay_ua(&self, payer: &BytesN<32>, f: &str, args: &soroban_sdk::Vec<Val>, salt: &BytesN<32>, to: &Holder, amount: i128, vu: u64, auth: &Bytes) -> Res {
        let (e, tk) = (&self.env, &self.token.address);
        let f = Symbol::new(e, f);
        let mut all: soroban_sdk::Vec<Val> = (payer, tk, &f, args, salt, tk, to, amount, vu, &self.relayer).into_val(e);
        all.push_back(auth.into_val(e));
        self.allow(&self.relayer, &self.router.address, "ua_relay", all);
        match self.router.try_ua_relay(payer, tk, &f, args, salt, tk, to, &amount, &vu, &self.relayer, auth) {
            Ok(r) => Ok(r.unwrap()),
            Err(e) => Err(e.unwrap()),
        }
    }

    /// `relay_ua` of `u`'s cancel of `lane` with salt `salt`.
    fn relay_cancel(&self, u: &Ua, args: &soroban_sdk::Vec<Val>, salt: u8, to: &Holder, amount: i128, auth: &Bytes) -> Res {
        self.relay_ua(&u.id, CANCEL, args, &b32(&self.env, salt), to, amount, NOW + 60, auth)
    }

    fn open(&self) -> Holder {
        Holder::Addr(self.router.address.clone())
    }

    fn mint(&self, to: &Address, amount: i128) {
        self.allow(&self.admin, &self.token.address, "mint", (to, amount).into_val(&self.env));
        self.token.mint(to, &amount);
    }

    /// Native `router.relay(payer, token, f, args, salt, token, to, amount, NOW + 60, relayer)` with exactly the
    /// payer's entry (rooted at this `relay`, `token.pay` its sub-invocation) and the relayer's.
    fn relay_native(&self, payer: &Address, f: &str, args: &soroban_sdk::Vec<Val>, salt: &BytesN<32>, to: &Address, amount: i128) -> Res {
        let (e, tk, vu) = (&self.env, &self.token.address, NOW + 60);
        let f = Symbol::new(e, f);
        let rf = self.router.relay_ref(tk, &f, args, salt);
        let signed: soroban_sdk::Vec<Val> = (tk, &f, args, salt, tk, to, amount, vu).into_val(e);
        let all: soroban_sdk::Vec<Val> = (payer, tk, &f, args, salt, tk, to, amount, vu, &self.relayer).into_val(e);
        let pay = MockAuthInvoke { contract: tk, fn_name: "pay", args: (payer, to, amount, &rf, vu).into_val(e), sub_invokes: &[] };
        let pay = [pay];
        let root = MockAuthInvoke { contract: &self.router.address, fn_name: "relay", args: signed, sub_invokes: &pay };
        let rroot = MockAuthInvoke { contract: &self.router.address, fn_name: "relay", args: all, sub_invokes: &[] };
        e.mock_auths(&[MockAuth { address: payer, invoke: &root }, MockAuth { address: &self.relayer, invoke: &rroot }]);
        match self.router.try_relay(payer, tk, &f, args, salt, tk, to, &amount, &vu, &self.relayer) {
            Ok(r) => Ok(r.unwrap()),
            Err(e) => Err(e.unwrap()),
        }
    }

    /// A victim's router-bound fee: `token.ua_pay(u, open, 7, ref(u's cancel of lane 3), …, Some(router), auth)` args.
    fn victim_ua_pay(&self, u: &Ua) -> (soroban_sdk::Vec<Val>, BytesN<32>) {
        let (open, rf) = (self.open(), self.rf(&self.cancel_args(u, 3), 1));
        let auth = self.fee_auth(u, &open, 7, &rf);
        ((&u.id, &open, 7i128, &rf, NOW + 60, Some(self.router.address.clone()), auth).into_val(&self.env), rf)
    }
}

/// Spec §5.4: the payer's UA signature names `relayer = Some(router)`, so the same `ua_pay` auth submitted directly to
/// the token is refused (`router.require_auth()` unmet: only the router, as the direct invoker, satisfies it).
#[test]
fn ua_relay_router_only() {
    let s = ua_setup();
    let u = s.ua(1, 100);
    let args = s.cancel_args(&u, 3);
    let (rf, open) = (s.rf(&args, 1), s.open());
    let auth = s.fee_auth(&u, &open, 7, &rf);
    let r = s.token.try_ua_pay(&u.id, &open, &7, &rf, &(NOW + 60), &Some(s.router.address.clone()), &auth);
    assert_eq!(r.err().unwrap().unwrap(), auth_err());
    assert!(!s.token.ua_ref_used(&u.id, &rf));
    assert_eq!((s.token.ua_balance(&u.id), s.token.balance(&s.router.address)), (100, 0));
    // The same signature settles through the router.
    s.relay_cancel(&u, &args, 1, &open, 7, &auth).unwrap();
    assert_eq!((s.token.ua_balance(&u.id), s.token.balance(&s.relayer)), (93, 7));
}

/// Open mode (`to == Holder::Addr(router)`): the fee reaches the submitting relayer, never rests on the router.
#[test]
fn ua_relay_open_mode_pays_submitter() {
    let s = ua_setup();
    let e = &s.env;
    let u = s.ua(1, 100);
    let args = s.cancel_args(&u, 3);
    let (rf, open) = (s.rf(&args, 1), s.open());
    s.relay_cancel(&u, &args, 1, &open, 7, &s.fee_auth(&u, &open, 7, &rf)).unwrap();
    let all = e.events().all();
    assert_eq!(s.token.ua_nonce(&u.id, &b32(e, 3)), 1, "the target call ran");
    assert_eq!((s.token.ua_balance(&u.id), s.token.balance(&s.relayer), s.token.balance(&s.router.address)), (93, 7, 0));
    assert_eq!(s.token.balance(&s.router.executor()), 0);
    assert!(s.token.ua_ref_used(&u.id, &rf));
    let d = event_data(&all, "RelayFeePaid");
    assert_eq!((d[0].clone(), d[1].clone()), (hv(e, Holder::Ua(u.id.clone())), hv(e, Holder::Addr(s.relayer.clone()))));
}

/// A bound UA payee is credited in the UA ledger; a relayer cannot redirect it to itself.
#[test]
fn ua_relay_bound_ua_payee() {
    let s = ua_setup();
    let e = &s.env;
    let (u, p) = (s.ua(1, 100), s.ua(2, 0));
    let args = s.cancel_args(&u, 3);
    let (rf, to) = (s.rf(&args, 1), Holder::Ua(p.id.clone()));
    let auth = s.fee_auth(&u, &to, 7, &rf);
    // The relayer names itself (or the open marker) as payee with the payer's signature: refused, nothing moves.
    for other in [Holder::Addr(s.relayer.clone()), s.open()] {
        assert_eq!(s.relay_cancel(&u, &args, 1, &other, 7, &auth), Err(auth_err()));
    }
    assert_eq!((s.token.ua_balance(&u.id), s.token.ua_nonce(&u.id, &b32(e, 3))), (100, 0));
    s.relay_cancel(&u, &args, 1, &to, 7, &auth).unwrap();
    let all = e.events().all();
    assert_eq!((s.token.ua_balance(&u.id), s.token.ua_balance(&p.id), s.token.balance(&s.relayer)), (93, 7, 0));
    assert_eq!(s.token.balance(&s.router.address), 0);
    assert_eq!(event_data(&all, "RelayFeePaid")[1], hv(e, to));
}

/// CTR-MTX-27: the router recomputes `ref` from the call it runs, so the payer's fee signature binds the call, its
/// salt and its amount; another call or salt makes the UA signature fail and the target call is rolled back.
#[test]
fn ua_relay_ref_commits_to_call() {
    let s = ua_setup();
    let e = &s.env;
    let u = s.ua(1, 100);
    let (a3, a4, open) = (s.cancel_args(&u, 3), s.cancel_args(&u, 4), s.open());
    let auth = s.fee_auth(&u, &open, 7, &s.rf(&a3, 1));
    // Other args (a valid cancel of lane 4), another salt, another amount.
    assert_eq!(s.relay_cancel(&u, &a4, 1, &open, 7, &auth), Err(auth_err()));
    assert_eq!(s.relay_cancel(&u, &a3, 2, &open, 7, &auth), Err(auth_err()));
    assert_eq!(s.relay_cancel(&u, &a3, 1, &open, 8, &auth), Err(auth_err()));
    assert_eq!((s.token.ua_nonce(&u.id, &b32(e, 3)), s.token.ua_nonce(&u.id, &b32(e, 4))), (0, 0), "the target rolled back");
    assert_eq!((s.token.ua_balance(&u.id), s.token.balance(&s.relayer)), (100, 0));
    // The call it was signed for.
    s.relay_cancel(&u, &a3, 1, &open, 7, &auth).unwrap();
    assert_eq!(s.token.balance(&s.relayer), 7);
}

/// SOR-D11 (controller ruling F4 / 4B-D11): one `RelayFeePaid` shape, `payer` and `payee` as `Holder`, for `relay`
/// and `ua_relay`.
#[test]
fn relay_fee_paid_holder_fields() {
    let amount = |e: &Env| ScVal::try_from_val(e, &IntoVal::<Env, Val>::into_val(&7i128, e)).unwrap();
    // `relay`: a native payer, a bound native payee.
    let t = setup();
    let treasury = Address::generate(&t.env);
    t.relay(&treasury, 7).unwrap();
    let d = event_data(&t.env.events().all(), "RelayFeePaid");
    assert_eq!(d, std::vec![hv(&t.env, Holder::Addr(t.owner.clone())), hv(&t.env, Holder::Addr(treasury)), amount(&t.env)]);
    // `ua_relay`: a UA payer, a bound native payee.
    let s = ua_setup();
    let e = &s.env;
    let u = s.ua(1, 100);
    let args = s.cancel_args(&u, 3);
    let to = Holder::Addr(Address::generate(e));
    s.relay_cancel(&u, &args, 1, &to, 7, &s.fee_auth(&u, &to, 7, &s.rf(&args, 1))).unwrap();
    let d = event_data(&e.events().all(), "RelayFeePaid");
    assert_eq!(d, std::vec![hv(e, Holder::Ua(u.id.clone())), hv(e, to), amount(e)]);
}

/// SOR-D12: `ua-ops.json`'s `ua_relay` row. The router at the row's id recomputes `relay.ref` from the row's call; each
/// kind's inner `ua_pay` digest is recomputed and its `auth` settles through `ua_relay` (open mode).
#[test]
fn ua_ops_vectors_ua_relay_row() {
    let s = ua_setup();
    let (e, o) = (&s.env, ops());
    for r in o["registrations"].as_array().unwrap() {
        let kind = r["kind"].as_u64().unwrap() as u32;
        let attrs = UaAttrs { pqz_key: Bytes::new(e), pqz_pop_hash: b32(e, 0), kem_version: 0, kem_pk: Bytes::new(e) };
        let ua = s.reg.register(&kind, &Bytes::from_slice(e, &hx(&r["keyData"])), &attrs, &Bytes::from_slice(e, &hx(&r["pop"])), &Bytes::new(e), &None);
        assert_eq!(ua.to_array().to_vec(), hx(&r["ua"]), "{}", r["name"]);
        s.mint_ua(&ua, 1_000);
    }
    let row = o["entries"].as_array().unwrap().iter().find(|x| x["name"] == "ua_relay").unwrap();
    let rl = &row["relay"];
    assert_eq!((&row["contract"], &row["fn"]), (&o["contracts"]["token"], &serde_json::json!("ua_pay")));
    assert_eq!((&rl["router"], &rl["target"]), (&o["contracts"]["router"], &o["contracts"]["token"]));
    let (f, call) = (rl["func"].as_str().unwrap(), arg_vals(e, rl));
    let salt = BytesN::from_array(e, &hx(&rl["salt"]).try_into().unwrap());
    let rf = s.router.relay_ref(&s.token.address, &Symbol::new(e, f), &call, &salt);
    assert_eq!(rf.to_array().to_vec(), hx(&rl["ref"]));
    let mut n = 0;
    for p in row["perKind"].as_array().unwrap() {
        let a = arg_vals(e, p);
        assert_eq!(op_digest(e, &s.token.address, "ua_pay", a.clone()).to_array().to_vec(), hx(&p["digest"]), "{}", p["kind"]);
        let from = BytesN::<32>::try_from_val(e, &a.get(0).unwrap()).unwrap();
        let to = Holder::try_from_val(e, &a.get(1).unwrap()).unwrap();
        let amount = i128::try_from_val(e, &a.get(2).unwrap()).unwrap();
        let vu = u64::try_from_val(e, &a.get(4).unwrap()).unwrap();
        assert_eq!(BytesN::<32>::try_from_val(e, &a.get(3).unwrap()).unwrap(), rf);
        assert_eq!(Option::<Address>::try_from_val(e, &a.get(5).unwrap()).unwrap(), Some(s.router.address.clone()));
        assert_eq!(to, s.open());
        let r = s.relay_ua(&from, f, &call, &salt, &to, amount, vu, &Bytes::from_slice(e, &hx(&p["auth"])));
        assert!(r.is_ok(), "{}: {r:?}", p["kind"]);
        assert!(s.token.ua_ref_used(&from, &rf));
        n += 1;
    }
    assert_eq!((n, s.token.balance(&s.relayer), s.token.balance(&s.router.address)), (7, 700, 0));
}

/// T8 review (critical; controller ruling 2026-10-31): a relayer makes a victim's router-bound `ua_pay` the target of
/// its own `ua_relay`. The router never calls a target as itself, so the victim's fee is not paid without the
/// victim's call; nor does a target call reach a balance the router holds.
#[test]
fn ua_relay_victim_ua_pay_as_target_refused() {
    let s = ua_setup();
    let e = &s.env;
    let (u, a, open) = (s.ua(1, 100), s.ua(2, 100), s.open());
    let (vargs, vref) = s.victim_ua_pay(&u);
    let (f, salt) = (Symbol::new(e, "ua_pay"), b32(e, 9));
    let aauth = s.fee_auth(&a, &open, 1, &s.router.relay_ref(&s.token.address, &f, &vargs, &salt));
    assert_eq!(s.relay_ua(&a.id, "ua_pay", &vargs, &salt, &open, 1, NOW + 60, &aauth), Err(auth_err()));
    assert!(!s.token.ua_ref_used(&u.id, &vref));
    assert_eq!((s.token.ua_balance(&u.id), s.token.ua_balance(&a.id)), (100, 100));
    assert_eq!((s.token.balance(&s.router.address), s.token.balance(&s.relayer)), (0, 0));
    // A balance on the router (sent by mistake) is not drained by a target `transfer(router, …)`.
    s.mint(&s.router.address, 5);
    let (targs, salt): (soroban_sdk::Vec<Val>, _) = ((&s.router.address, &s.relayer, 5i128).into_val(e), b32(e, 10));
    let tauth = s.fee_auth(&a, &open, 1, &s.router.relay_ref(&s.token.address, &Symbol::new(e, "transfer"), &targs, &salt));
    assert_eq!(s.relay_ua(&a.id, "transfer", &targs, &salt, &open, 1, NOW + 60, &tauth), Err(auth_err()));
    assert_eq!((s.token.balance(&s.router.address), s.token.balance(&s.relayer)), (5, 0));
}

/// The same attack through native `relay` (any payer may front it): refused, the victim's fee untouched.
#[test]
fn relay_victim_ua_pay_as_target_refused() {
    let s = ua_setup();
    let e = &s.env;
    let u = s.ua(1, 100);
    let attacker = Address::generate(e);
    s.mint(&attacker, 10);
    let (vargs, vref) = s.victim_ua_pay(&u);
    assert_eq!(s.relay_native(&attacker, "ua_pay", &vargs, &b32(e, 9), &s.router.address, 1), Err(auth_err()));
    assert!(!s.token.ua_ref_used(&u.id, &vref));
    assert_eq!((s.token.ua_balance(&u.id), s.token.balance(&attacker)), (100, 10));
    assert_eq!((s.token.balance(&s.router.address), s.token.balance(&s.relayer)), (0, 0));
}

/// Controller ruling 2026-10-31: `exec` serves only its router; anyone else calling it directly is refused, so a
/// router-bound authority is never reachable through the executor either.
#[test]
fn executor_exec_refuses_all_but_router() {
    let s = ua_setup();
    let e = &s.env;
    let x = RelayExecutorClient::new(e, &s.router.executor());
    assert_eq!(x.router(), s.router.address);
    let u = s.ua(1, 100);
    let (vargs, vref) = s.victim_ua_pay(&u);
    let r = x.try_exec(&s.token.address, &Symbol::new(e, "ua_pay"), &vargs);
    assert_eq!(r.err().unwrap().unwrap(), auth_err());
    assert!(!s.token.ua_ref_used(&u.id, &vref));
    // A caller that authorises itself does not stand in for the router.
    let other = Address::generate(e);
    let (f, bargs): (_, soroban_sdk::Vec<Val>) = (Symbol::new(e, "balance"), (&other,).into_val(e));
    s.allow(&other, &x.address, "exec", (&s.token.address, &f, &bargs).into_val(e));
    assert_eq!(x.try_exec(&s.token.address, &f, &bargs).err().unwrap().unwrap(), auth_err());
}

/// Controller ruling 2026-10-31: the fee never rests on the router or the executor; a `to` naming the executor is
/// refused before any call, for `relay` and `ua_relay` (`to == router` is open mode).
#[test]
fn relay_payee_never_router_or_executor() {
    let s = ua_setup();
    let e = &s.env;
    let (u, x) = (s.ua(1, 100), s.router.executor());
    let args = s.cancel_args(&u, 3);
    let to = Holder::Addr(x.clone());
    assert_eq!(s.relay_cancel(&u, &args, 1, &to, 7, &s.fee_auth(&u, &to, 7, &s.rf(&args, 1))), err(Error::BadPayee));
    let payer = Address::generate(e);
    s.mint(&payer, 10);
    assert_eq!(s.relay_native(&payer, CANCEL, &args, &b32(e, 1), &x, 1), err(Error::BadPayee));
    // Open mode with the router or the executor as the relayer cannot happen: neither has `__check_auth`, so
    // `relayer.require_auth()` fails first (the `BadPayee` check still covers it).
    assert_eq!((s.token.ua_balance(&u.id), s.token.balance(&payer), s.token.balance(&x)), (100, 10, 0));
}
