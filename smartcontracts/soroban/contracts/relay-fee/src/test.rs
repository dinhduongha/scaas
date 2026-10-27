extern crate std;

use super::*;
use scaas_mandate::{MandateWallet, MandateWalletClient};
use scaas_token::{Token, TokenClient};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger, MockAuth, MockAuthInvoke};
use soroban_sdk::xdr::{self, ScVal};
use soroban_sdk::{IntoVal, String, Symbol, TryFromVal, Val};

const NOW: u64 = 1_800_000_000;
const NETWORK: [u8; 32] = [7; 32];
pub const TOKEN: &str = "CARCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEVQO";
pub const OWNER: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";
pub const WALLET: &str = "CAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGGJH";
/// `relay_ref(WALLET, "revoke", (TOKEN, OWNER))` on `NETWORK` = 0x07 x 32; the node adapter pins the same value.
pub const VEC_REF: &str = "1fbf24f83d5c9aa7018ee18b9b29e29a110909eb48a671afc8e086cc8e99efb2";

struct T {
    env: Env,
    token: TokenClient<'static>,
    wallet: MandateWalletClient<'static>,
    router: RelayFeeClient<'static>,
    owner: Address,
    relayer: Address,
}

fn setup() -> T {
    let env = Env::default();
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
        (admin, 7u32, String::from_str(&env, "SCaaS"), String::from_str(&env, "BMB")),
    );
    let token = TokenClient::new(&env, &tid);
    let owner = Address::generate(&env);
    let wid = env.register_at(&Address::from_str(&env, WALLET), MandateWallet, (owner.clone(),));
    let wallet = MandateWalletClient::new(&env, &wid);
    // The mandate is the target's state: the fee-less call revokes it.
    wallet.set_mandate(&tid, &Address::generate(&env), &100, &150, &3600, &(NOW + 86_400));
    let router = RelayFeeClient::new(&env, &env.register(RelayFee, ()));
    token.mint(&owner, &100);
    T { env: env.clone(), token, wallet, router, owner, relayer: Address::generate(&env) }
}

impl T {
    fn args(&self) -> soroban_sdk::Vec<Val> {
        (self.token.address.clone(), self.owner.clone()).into_val(&self.env)
    }
    fn func(&self) -> Symbol {
        Symbol::new(&self.env, "revoke")
    }
    fn rf(&self) -> BytesN<32> {
        self.router.relay_ref(&self.wallet.address, &self.func(), &self.args())
    }
    fn rf_of(&self, args: &soroban_sdk::Vec<Val>) -> BytesN<32> {
        self.router.relay_ref(&self.wallet.address, &self.func(), args)
    }
    fn relay(&self, to: &Address, amount: i128) -> Result<(), ()> {
        match self.router.try_relay(
            &self.owner, &self.wallet.address, &self.func(), &self.args(), &self.token.address, to, &amount,
            &(NOW + 60), &self.relayer,
        ) {
            Ok(r) => Ok(r.unwrap()),
            Err(_) => Err(()),
        }
    }
}

fn hex(b: &[u8]) -> std::string::String {
    b.iter().map(|x| std::format!("{x:02x}")).collect()
}

#[test]
fn relay_open_mode_pays_relayer() {
    let t = setup();
    let rf = t.rf();
    t.relay(&t.router.address, 7).unwrap();
    let all = t.env.events().all();
    assert!(t.wallet.mandate(&t.token.address).is_none(), "the target call ran");
    assert_eq!((t.token.balance(&t.owner), t.token.balance(&t.relayer), t.token.balance(&t.router.address)), (93, 7, 0));
    assert!(t.token.ref_used(&rf));
    // RelayFeePaid names the relayer, not the router, as payee.
    let ev: std::vec::Vec<_> = all
        .events()
        .iter()
        .filter(|e| {
            let xdr::ContractEventBody::V0(b) = &e.body;
            matches!(&b.topics[0], ScVal::Symbol(s) if s.to_utf8_string_lossy() == "RelayFeePaid")
        })
        .collect();
    assert_eq!(ev.len(), 1);
    let xdr::ContractEventBody::V0(b) = &ev[0].body;
    let ScVal::Vec(Some(d)) = &b.data else { panic!() };
    assert_eq!(d[0], ScVal::try_from_val(&t.env, &t.owner.to_val()).unwrap());
    assert_eq!(d[1], ScVal::try_from_val(&t.env, &t.relayer.to_val()).unwrap());
    // Second submission of the same payment: the PayRef is used, nothing moves twice.
    assert!(t.relay(&t.router.address, 7).is_err());
    assert_eq!(t.token.balance(&t.relayer), 7);
}

#[test]
fn relay_bound_payee() {
    let t = setup();
    let treasury = Address::generate(&t.env);
    t.relay(&treasury, 7).unwrap();
    assert_eq!((t.token.balance(&t.owner), t.token.balance(&treasury), t.token.balance(&t.relayer)), (93, 7, 0));
    assert!(t.wallet.mandate(&t.token.address).is_none());
}

#[test]
fn relay_target_failure_reverts_all() {
    let t = setup();
    // The call fails (a revoke by a stranger): the payment must not happen.
    let stranger = Address::generate(&t.env);
    let bad: soroban_sdk::Vec<Val> = (t.token.address.clone(), stranger).into_val(&t.env);
    let r = t.router.try_relay(
        &t.owner, &t.wallet.address, &t.func(), &bad, &t.token.address, &t.router.address, &7, &(NOW + 60), &t.relayer,
    );
    assert!(r.is_err());
    assert_eq!((t.token.balance(&t.owner), t.token.balance(&t.relayer)), (100, 0));
    assert!(!t.token.ref_used(&t.router.relay_ref(&t.wallet.address, &t.func(), &bad)));
    assert!(t.wallet.mandate(&t.token.address).is_some());
    // The payment fails (too little balance, expired): the call is rolled back.
    assert!(t.relay(&t.router.address, 1_000).is_err());
    assert!(t.wallet.mandate(&t.token.address).is_some(), "the target call is rolled back with the payment");
    assert!(!t.token.ref_used(&t.rf()));
}

/// Carried router rule 1: the target must be an instantiated contract, refused before any token call.
#[test]
fn relay_refuses_target_without_contract() {
    let t = setup();
    for ghost in [Address::generate(&t.env), t.owner.clone()] {
        let r = t.router.try_relay(
            &t.owner, &ghost, &t.func(), &t.args(), &t.token.address, &t.router.address, &7, &(NOW + 60), &t.relayer,
        );
        assert_eq!(r.err().unwrap().unwrap(), Error::TargetNoCode.into());
        assert!(!t.token.ref_used(&t.router.relay_ref(&ghost, &t.func(), &t.args())));
    }
    assert_eq!((t.token.balance(&t.owner), t.token.balance(&t.relayer)), (100, 0));
}

/// Review focus 3: a payment signed for the router (auth entry rooted at `relay`) never settles through the
/// plain `token.pay`.
#[test]
fn soroban_router_bound_pay_refused_direct() {
    let t = setup();
    let rf = t.rf();
    let to = t.router.address.clone();
    let revoke_args = t.args();
    let pay_args: soroban_sdk::Vec<Val> = (t.owner.clone(), to.clone(), 7i128, rf.clone(), NOW + 60).into_val(&t.env);
    let signed: soroban_sdk::Vec<Val> = (
        t.wallet.address.clone(), t.func(), t.args(), t.token.address.clone(), to.clone(), 7i128, NOW + 60,
    )
        .into_val(&t.env);
    let relay_args: soroban_sdk::Vec<Val> = (
        t.owner.clone(), t.wallet.address.clone(), t.func(), t.args(), t.token.address.clone(), to.clone(), 7i128,
        NOW + 60, t.relayer.clone(),
    )
        .into_val(&t.env);
    let (pay, revoke) = (
        MockAuthInvoke { contract: &t.token.address, fn_name: "pay", args: pay_args.clone(), sub_invokes: &[] },
        MockAuthInvoke { contract: &t.wallet.address, fn_name: "revoke", args: revoke_args, sub_invokes: &[] },
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
    assert!(t.token.try_pay(&t.owner, &to, &7, &rf, &(NOW + 60)).is_err());
    assert_eq!(t.token.balance(&t.router.address), 0);
    assert!(!t.token.ref_used(&rf));
    // The same signature settles through the router.
    t.relay(&to, 7).unwrap();
    assert_eq!(t.token.balance(&t.relayer), 7);
    // A relay whose signed `to`/amount differ from the executed payment has no matching auth: refused.
    let r = t.router.try_relay(
        &t.owner, &t.wallet.address, &t.func(), &t.args(), &t.token.address, &to, &8, &(NOW + 60), &t.relayer,
    );
    assert!(r.is_err());
}

#[test]
fn relay_ref_vectors() {
    let t = setup();
    let args: soroban_sdk::Vec<Val> =
        (t.token.address.clone(), Address::from_str(&t.env, OWNER)).into_val(&t.env);
    // Independent construction: keccak256("scaas.relayfee" ‖ network id ‖ xdr(target) ‖ keccak256(xdr((func, args)))).
    let e = &t.env;
    let call = (t.func(), args.clone()).to_xdr(e);
    let mut b = Bytes::from_slice(e, b"scaas.relayfee");
    b.append(&Bytes::from_array(e, &NETWORK));
    b.append(&t.wallet.address.clone().to_xdr(e));
    b.append(&e.crypto().keccak256(&call).to_bytes().into());
    let want = e.crypto().keccak256(&b).to_array();
    assert_eq!(t.router.relay_ref(&t.wallet.address, &t.func(), &args).to_array(), want);
    std::println!("ref {}", hex(&want));
    assert_eq!(hex(&want), VEC_REF);
    // The ref commits to the target, the function, every argument and the chain.
    let other: soroban_sdk::Vec<Val> = (t.token.address.clone(), t.relayer.clone()).into_val(e);
    assert_ne!(t.router.relay_ref(&t.wallet.address, &t.func(), &other), t.rf_of(&args));
    assert_ne!(t.router.relay_ref(&t.token.address, &t.func(), &args), t.rf_of(&args));
    assert_ne!(t.router.relay_ref(&t.wallet.address, &Symbol::new(e, "pay"), &t.args()), t.rf());
    e.ledger().with_mut(|l| l.network_id = [8; 32]);
    assert_ne!(t.rf_of(&args).to_array(), want);
}
