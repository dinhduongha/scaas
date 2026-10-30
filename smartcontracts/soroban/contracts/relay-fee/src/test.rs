extern crate std;

use super::*;
use ed25519_dalek::Signer as _;
use scaas_mandate::{Holder, MandateWallet, MandateWalletClient};
use scaas_token::{Token, TokenClient};
use sha2::{Digest, Sha256};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger, MockAuth, MockAuthInvoke};
use soroban_sdk::xdr::{
    self, AccountId, HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limits, PublicKey,
    ScAddress, ScErrorCode, ScErrorType, ScMap, ScMapEntry, ScSymbol, ScVal, SorobanAddressCredentials,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, Uint256,
    WriteXdr,
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
    let router = RelayFeeClient::new(&env, &env.register(RelayFee, ()));
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
    // RelayFeePaid names the relayer, not the router, as payee (the Address as the event carries it).
    let d = event_data(&all, "RelayFeePaid");
    assert_eq!(d[0], ScVal::try_from_val(&t.env, &t.owner.to_val()).unwrap());
    assert_eq!(d[1], ScVal::try_from_val(&t.env, &t.relayer.to_val()).unwrap());
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
