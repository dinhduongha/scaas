extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Events as _, Ledger};
use soroban_sdk::xdr::{
    self, HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limits, ScVal,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, WriteXdr,
};
use soroban_sdk::{Bytes, IntoVal, Symbol, TryFromVal, Val};

pub const NETWORK: &str = "Standalone Network ; February 2017";
pub const CONTRACT: &str = "CARCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEVQO";
pub const FROM: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";
pub const TO: &str = "GAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTHCM6";
const NOW: u64 = 1_800_000_000;

/// Vector chéo (Python `test_fam_soroban`, adapter Rust): pay(FROM, TO, 12345, 0x11×32, 1_800_000_300),
/// nonce 42, hạn ledger 1000.
pub const VEC_PREIMAGE_SHA256: &str = "0a2127bfdc94f6062f0ec27f6db966ae719dafaca90bc537666eab606b901103";
pub const VEC_DIGEST: &str = "0bb4e9123b86f99303e03cfd8aacb1eecd3b8ccb10d572907e1228a715369b00";

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
        (admin.clone(), 7u32, String::from_str(&env, "SCaaS"), String::from_str(&env, "BMB")),
    );
    (env.clone(), TokenClient::new(&env, &id), admin)
}

fn hex(b: &[u8]) -> std::string::String {
    b.iter().map(|x| std::format!("{x:02x}")).collect()
}

#[test]
fn env_default_protocol_30() {
    assert_eq!(Env::default().ledger().protocol_version(), 30);
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
    let digest = op_digest(&env, &t.address, "pay", args.clone());
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
    assert!(t.ref_used(&a, &r));
    assert_eq!(t.try_pay(&a, &b, &1, &r, &(NOW + 10)).err().unwrap().unwrap(), Error::RefUsed.into());
    let r2 = BytesN::from_array(&env, &[2; 32]);
    assert_eq!(t.try_pay(&a, &b, &1, &r2, &(NOW - 1)).err().unwrap().unwrap(), Error::Expired.into());
    assert_eq!(t.try_pay(&a, &b, &1000, &r2, &(NOW + 10)).err().unwrap().unwrap(), Error::InsufficientBalance.into());
    assert_eq!(t.try_pay(&a, &b, &-1, &r2, &(NOW + 10)).err().unwrap().unwrap(), Error::NegativeAmount.into());
    // A failed pay leaves the ref unused.
    assert!(!t.ref_used(&a, &r2));
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

// ---------------------------------------------------------------- CTR-MTX-26 (pay_meta)

fn unhex(s: &str) -> std::vec::Vec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// Shared vectors (`smartcontracts/vectors/metatx/paymeta.json`), the EVM suite's file.
fn paymeta_rows() -> std::vec::Vec<serde_json::Value> {
    serde_json::from_str(include_str!("../../../../vectors/metatx/paymeta.json")).unwrap()
}

fn row(env: &Env, r: &serde_json::Value) -> (BytesN<32>, Bytes, BytesN<32>, [u8; 32]) {
    let g = |k: &str| unhex(r[k].as_str().unwrap());
    (
        BytesN::from_array(env, &g("salt").try_into().unwrap()),
        Bytes::from_slice(env, &g("meta")),
        BytesN::from_array(env, &g("payId").try_into().unwrap()),
        g("payLane").try_into().unwrap(),
    )
}

#[test]
fn pay_meta_vectors_match() {
    let (env, t, _) = setup();
    let rows = paymeta_rows();
    assert_eq!(rows.len(), 6);
    for r in &rows {
        let (salt, meta, pay_id, lane) = row(&env, r);
        assert_eq!(t.meta_pay_id(&salt, &meta), pay_id, "payId of {}", r["name"]);
        let mut b = Bytes::from_slice(&env, b"scaas.pay.lane");
        b.append(&pay_id.clone().into());
        assert_eq!(env.crypto().keccak256(&b).to_array(), lane, "payLane of {}", r["name"]);
    }
}

#[test]
fn pay_meta_settles_and_emits_meta_first() {
    let (env, t, _) = setup();
    let (a, b) = (Address::generate(&env), Address::generate(&env));
    t.mint(&a, &100);
    let rows0 = paymeta_rows()[0].clone();
    let r = &rows0;
    let (salt, meta, pay_id, _) = row(&env, r);
    t.pay_meta(&a, &b, &40, &salt, &meta, &(NOW + 10));
    let (auths, all) = (env.auths(), env.events().all()); // each later client call resets both
    assert_eq!((t.balance(&a), t.balance(&b)), (60, 40));
    assert!(t.ref_used(&a, &pay_id));
    assert_eq!(auths[0].0, a);
    // The auth entry covers pay_meta's own arguments, `meta` included.
    let want: soroban_sdk::Vec<Val> = (a.clone(), b.clone(), 40i128, salt.clone(), meta.clone(), NOW + 10).into_val(&env);
    let args = &auths[0].1.function;
    let soroban_sdk::testutils::AuthorizedFunction::Contract((_, name, got)) = args else { panic!() };
    assert_eq!((name.clone(), got.clone()), (Symbol::new(&env, "pay_meta"), want));
    // PaymentMeta, then PaymentSettled, then MetaTransactionExecuted.
    let names: std::vec::Vec<std::string::String> = all
        .events()
        .iter()
        .map(|e| {
            let xdr::ContractEventBody::V0(b) = &e.body;
            match &b.topics[0] {
                ScVal::Symbol(s) => s.to_utf8_string_lossy(),
                _ => panic!(),
            }
        })
        .collect();
    assert_eq!(names, ["PaymentMeta", "PaymentSettled", "MetaTransactionExecuted"]);
    let xdr::ContractEventBody::V0(m) = &all.events()[0].body;
    assert_eq!(m.data, ScVal::Bytes(unhex(rows0["meta"].as_str().unwrap()).try_into().unwrap()));
    assert_eq!(m.topics[1], ScVal::Bytes(pay_id.to_array().to_vec().try_into().unwrap()));
}

#[test]
fn soroban_pay_meta_mismatch_and_replay() {
    let (env, t, _) = setup();
    let (a, b) = (Address::generate(&env), Address::generate(&env));
    t.mint(&a, &100);
    let rows = paymeta_rows();
    let (salt, meta, pay_id, _) = row(&env, &rows[0]);
    t.pay_meta(&a, &b, &10, &salt, &meta, &(NOW + 10));
    // Same (salt, meta) again: RefUsed.
    assert_eq!(t.try_pay_meta(&a, &b, &10, &salt, &meta, &(NOW + 10)).err().unwrap().unwrap(), Error::RefUsed.into());
    // A plain pay with the committed id is refused as well (one PayRef set per payer).
    assert_eq!(t.try_pay(&a, &b, &10, &pay_id, &(NOW + 10)).err().unwrap().unwrap(), Error::RefUsed.into());
    // The id is derived, so altered meta can never settle under the committed id: it pays under its own.
    let (salt2, meta2, id2, _) = row(&env, &rows[1]);
    assert_ne!(id2, pay_id);
    let mut tampered = meta.clone();
    tampered.push_back(1);
    assert_ne!(t.meta_pay_id(&salt, &tampered), pay_id);
    t.pay_meta(&a, &b, &10, &salt2, &meta2, &(NOW + 10));
    assert!(t.ref_used(&a, &id2));
    // A plain pay first, then pay_meta of the same id: RefUsed.
    let (salt3, meta3, id3, _) = row(&env, &rows[2]);
    t.pay(&a, &b, &10, &id3, &(NOW + 10));
    assert_eq!(t.try_pay_meta(&a, &b, &10, &salt3, &meta3, &(NOW + 10)).err().unwrap().unwrap(), Error::RefUsed.into());
    // Expired.
    let (salt4, meta4, _, _) = row(&env, &rows[3]);
    assert_eq!(t.try_pay_meta(&a, &b, &10, &salt4, &meta4, &(NOW - 1)).err().unwrap().unwrap(), Error::Expired.into());
}

/// controller call 2026-10-27: the PayRef set is per payer, so nobody can pre-burn another payer's ref / payId.
#[test]
fn pay_ref_is_per_payer_nobody_can_pre_burn_it() {
    let (env, t, _) = setup();
    let (victim, attacker, b) = (Address::generate(&env), Address::generate(&env), Address::generate(&env));
    t.mint(&victim, &100);
    let (salt, meta, pay_id, _) = row(&env, &paymeta_rows()[0]);
    // The attacker burns the victim's payId and a plain ref under the attacker's own name.
    t.pay_meta(&attacker, &attacker, &0, &salt, &meta, &(NOW + 10));
    let plain = BytesN::from_array(&env, &[5; 32]);
    t.pay(&attacker, &attacker, &0, &plain, &(NOW + 10));
    assert!(t.ref_used(&attacker, &pay_id) && !t.ref_used(&victim, &pay_id));
    t.pay_meta(&victim, &b, &10, &salt, &meta, &(NOW + 10));
    t.pay(&victim, &b, &10, &plain, &(NOW + 10));
    assert_eq!((t.balance(&victim), t.balance(&b)), (80, 20));
    // The same payer is still once-only.
    assert_eq!(t.try_pay(&victim, &b, &1, &plain, &(NOW + 10)).err().unwrap().unwrap(), Error::RefUsed.into());
}
