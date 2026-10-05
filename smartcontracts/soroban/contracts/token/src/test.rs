extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Events as _, Ledger};
use soroban_sdk::xdr::{
    self, HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limits, ScVal,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, WriteXdr,
};
use soroban_sdk::{IntoVal, TryFromVal, Val};

pub const NETWORK: &str = "Standalone Network ; February 2017";
pub const CONTRACT: &str = "CARCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEVQO";
pub const FROM: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";
pub const TO: &str = "GAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTHCM6";
const NOW: u64 = 1_800_000_000;

/// Vector chéo (Python `test_fam_soroban`, adapter Rust): pay(FROM, TO, 12345, 0x11×32, 1_800_000_300),
/// nonce 42, hạn ledger 1000.
pub const VEC_PREIMAGE_SHA256: &str = "0a2127bfdc94f6062f0ec27f6db966ae719dafaca90bc537666eab606b901103";
pub const VEC_DIGEST: &str = "f139c7370f61e89454576f261dadca37127da46a9b9bc8ce650d6e47485f96ad";

fn sha256(b: &[u8]) -> [u8; 32] {
    let env = Env::default();
    env.crypto().sha256(&soroban_sdk::Bytes::from_slice(&env, b)).to_array()
}

fn setup() -> (Env, TokenClient<'static>, Address) {
    let env = Env::default();
    env.ledger().with_mut(|l| {
        l.sequence_number = 100;
        l.timestamp = NOW;
        l.network_id = sha256(NETWORK.as_bytes());
    });
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register_at(
        &Address::from_str(&env, CONTRACT),
        Token,
        (admin.clone(), 7u32, String::from_str(&env, "Bamboo"), String::from_str(&env, "BMB")),
    );
    (env.clone(), TokenClient::new(&env, &id), admin)
}

fn hex(b: &[u8]) -> std::string::String {
    b.iter().map(|x| std::format!("{x:02x}")).collect()
}

#[test]
fn cross_implementation_vector() {
    let (env, t, _) = setup();
    let (from, to) = (Address::from_str(&env, FROM), Address::from_str(&env, TO));
    let r = BytesN::from_array(&env, &[0x11; 32]);
    t.mint(&from, &20_000);
    t.pay(&from, &to, &12_345, &r, &(NOW + 300));
    let last = env.events().all().events().last().unwrap().clone();
    let args: soroban_sdk::Vec<Val> = (from.clone(), to.clone(), 12_345i128, r.clone(), NOW + 300).into_val(&env);
    let inv = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: (&t.address).into(),
            function_name: "pay".try_into().unwrap(),
            args: args.iter().map(|v| ScVal::try_from_val(&env, &v).unwrap()).collect::<std::vec::Vec<_>>().try_into().unwrap(),
        }),
        sub_invocations: Default::default(),
    };
    let pre = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: xdr::Hash(sha256(NETWORK.as_bytes())),
        nonce: 42,
        signature_expiration_ledger: 1000,
        invocation: inv,
    })
    .to_xdr(Limits::none())
    .unwrap();
    let digest = env.as_contract(&t.address, || op_digest(&env, "pay", args.clone()));
    std::println!("preimage {}\npreimage_sha256 {}\ndigest {}", hex(&pre), hex(&sha256(&pre)), hex(&digest.to_array()));
    assert_eq!(hex(&sha256(&pre)), VEC_PREIMAGE_SHA256);
    assert_eq!(hex(&digest.to_array()), VEC_DIGEST);
    // The event carries exactly this digest.
    let xdr::ContractEventBody::V0(body) = last.body;
    assert_eq!(body.data, ScVal::Bytes(digest.to_array().to_vec().try_into().unwrap()));
}

#[test]
fn pay_moves_funds_once_per_ref_and_respects_expiry() {
    let (env, t, _) = setup();
    let (a, b) = (Address::generate(&env), Address::generate(&env));
    t.mint(&a, &100);
    let r = BytesN::from_array(&env, &[1; 32]);
    t.pay(&a, &b, &40, &r, &(NOW + 10));
    assert_eq!((t.balance(&a), t.balance(&b)), (60, 40));
    assert!(t.ref_used(&r));
    assert_eq!(t.try_pay(&a, &b, &1, &r, &(NOW + 10)).err().unwrap().unwrap(), Error::RefUsed.into());
    let r2 = BytesN::from_array(&env, &[2; 32]);
    assert_eq!(t.try_pay(&a, &b, &1, &r2, &(NOW - 1)).err().unwrap().unwrap(), Error::Expired.into());
    assert_eq!(t.try_pay(&a, &b, &1000, &r2, &(NOW + 10)).err().unwrap().unwrap(), Error::InsufficientBalance.into());
    assert_eq!(t.try_pay(&a, &b, &-1, &r2, &(NOW + 10)).err().unwrap().unwrap(), Error::NegativeAmount.into());
    // A failed pay leaves the ref unused.
    assert!(!t.ref_used(&r2));
}

#[test]
fn pay_requires_the_payer() {
    let (env, t, _) = setup();
    let (a, b) = (Address::generate(&env), Address::generate(&env));
    t.mint(&a, &100);
    t.pay(&a, &b, &1, &BytesN::from_array(&env, &[3; 32]), &(NOW + 10));
    let auths = env.auths();
    assert_eq!(auths[0].0, a);
}

/// R26: allowance chỉ cho contract.
#[test]
fn approve_only_to_contracts() {
    let (env, t, admin) = setup();
    let a = Address::generate(&env);
    t.mint(&a, &100);
    let account = Address::from_str(&env, TO);
    assert_eq!(t.try_approve(&a, &account, &10, &200).err().unwrap().unwrap(), Error::SpenderNotContract.into());
    let ghost = Address::generate(&env); // contract address with nothing deployed
    assert_eq!(t.try_approve(&a, &ghost, &10, &200).err().unwrap().unwrap(), Error::SpenderNotContract.into());
    let spender = env.register(Token, (admin, 7u32, String::from_str(&env, "X"), String::from_str(&env, "X")));
    t.approve(&a, &spender, &10, &200);
    assert_eq!(t.allowance(&a, &spender), 10);
    t.transfer_from(&spender, &a, &account, &4);
    assert_eq!((t.allowance(&a, &spender), t.balance(&account)), (6, 4));
    assert!(t.try_transfer_from(&spender, &a, &account, &7).is_err());
    env.ledger().with_mut(|l| l.sequence_number = 201);
    assert_eq!(t.allowance(&a, &spender), 0, "expired allowance");
    assert!(t.try_transfer_from(&spender, &a, &account, &1).is_err());
}

#[test]
fn sep41_basics() {
    let (env, t, _) = setup();
    let (a, b) = (Address::generate(&env), Address::generate(&env));
    t.mint(&a, &100);
    t.transfer(&a, &b, &30);
    t.burn(&b, &5);
    assert_eq!((t.balance(&a), t.balance(&b), t.decimals()), (70, 25, 7));
    assert_eq!(t.symbol(), String::from_str(&env, "BMB"));
    assert!(t.try_transfer(&a, &b, &71).is_err());
}
