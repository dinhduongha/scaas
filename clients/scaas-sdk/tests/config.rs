// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T1: error names, `Sdk::open`'s checks (each with a valid profile as its control), credentials out of `Debug`, the
//! feature bits, `api_version`.

use scaas_rpc::{Class, EndpointAuth, Policy, Secret};
use scaas_sdk::error::{OWN_CODES, SHARED_CODES};
use scaas_sdk::{
    bits, ChainProfile, EndpointConfig, Family, Finality, GasTable, Limits, RuntimeChoice, Sdk,
    SdkConfig, SdkError,
};
use std::collections::BTreeSet;
use std::path::Path;

const UID: &str = "0x6e7f0a3c7c1f4a4e9c2d1b0a99887766554433221100ffeeddccbbaa00112233";
const MARK: &str = "s3cr3t-marker-7f1e";

fn endpoint(url: &str) -> EndpointConfig {
    EndpointConfig {
        url: url.into(),
        class: Class::Named,
        label: Some("a".into()),
        auth: None,
    }
}

fn profile(key: &str) -> ChainProfile {
    ChainProfile {
        key: key.into(),
        family: Family::Evm,
        chain_id: Some(7622),
        chain_uid: UID.into(),
        rpc: vec![
            endpoint("http://127.0.0.1:1/"),
            endpoint("http://127.0.0.1:2/"),
        ],
        rpc_policy: Policy::Failover,
        gateways: vec![],
        registry: None,
        factory: None,
        router: None,
        finality: Finality::Depth(12),
        tx_gas_cap: Some(1 << 24),
        gas: Default::default(),
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        gas_opt_in: vec![],
        dexes: vec![],
        wrappers: vec![],
        tokens: vec![],
    }
}

fn config(profiles: Vec<ChainProfile>) -> SdkConfig {
    SdkConfig {
        profiles,
        store: scaas_sdk::vault::MemoryStore::new(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits::default(),
        clock: None,
        gas_tables: vec![],
    }
}

async fn open(profiles: Vec<ChainProfile>) -> Result<(), SdkError> {
    Sdk::open(config(profiles)).await.map(|_| ())
}

fn code(r: Result<(), SdkError>) -> &'static str {
    match r {
        Ok(()) => "Ok",
        Err(e) => e.code(),
    }
}

/// The `=> "Name"` codes of a lower layer's `code()` functions, read from its source (never copied).
fn codes_in(rel: &str) -> BTreeSet<String> {
    let src = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)).unwrap();
    src.split("=> \"")
        .skip(1)
        .filter_map(|t| t.split('"').next())
        .filter(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_alphanumeric()))
        .map(String::from)
        .collect()
}

#[test]
fn error_codes_are_names() {
    let variants = SdkError::own_variants();
    assert_eq!(variants.len(), OWN_CODES.len());
    for (v, name) in variants.iter().zip(OWN_CODES) {
        assert_eq!(v.code(), *name);
        assert_eq!(v.to_string(), *name);
        assert_eq!(format!("{v:?}"), *name, "Debug is the bare name");
    }
    let own: BTreeSet<_> = OWN_CODES.iter().map(|s| s.to_string()).collect();
    assert_eq!(own.len(), OWN_CODES.len(), "a code declared twice");
    let mut lower = codes_in("../ua-rs/src/wallet/mod.rs");
    lower.extend(codes_in("../ua-rs/src/lib.rs"));
    let rpc = codes_in("../scaas-rpc/src/error.rs");
    assert!(
        rpc.contains("EndpointAllFailed") && lower.contains("VaultOpen"),
        "the lists were read"
    );
    lower.extend(rpc);
    let clash: Vec<_> = own
        .intersection(&lower)
        .filter(|c| !SHARED_CODES.contains(&c.as_str()))
        .collect();
    assert!(
        clash.is_empty(),
        "own codes with a lower layer's name: {clash:?}"
    );
    for s in SHARED_CODES {
        assert!(own.contains(*s) && lower.contains(*s), "{s} is shared");
    }
    // spec §15: the names the app contract also uses, each produced by the SDK or passed through
    for name in [
        "VaultOpen",
        "VaultParams",
        "VaultVersion",
        "VaultFormat",
        "VaultIo",
        "MnemonicInvalid",
        "ChainUnknown",
        "EndpointScheme",
        "EndpointAllFailed",
        "EndpointNoMajority",
        "AbiMismatch",
        "Internal",
    ] {
        assert!(own.contains(name) || lower.contains(name), "{name} missing");
    }
    // pass-through keeps the lower code
    assert_eq!(
        SdkError::from(scaas_ua::wallet::Error::VaultOpen).code(),
        "VaultOpen"
    );
    assert_eq!(
        SdkError::from(scaas_rpc::RpcError::EndpointListEmpty).code(),
        "EndpointListEmpty"
    );
}

#[test]
fn broadcast_rejected_is_not_an_error() {
    assert!(!OWN_CODES.contains(&"BroadcastRejected"));
    assert!(
        OWN_CODES.contains(&"Internal"),
        "control: the list is the variants'"
    );
}

#[test]
fn api_version_is_1() {
    assert_eq!(Sdk::api_version(), 1);
}

fn gas_table(name: &str, family: &str) -> GasTable {
    GasTable {
        name: name.into(),
        family: family.into(),
        rows: Default::default(),
    }
}

/// The gas-table rulings (owner 2026-11-19): a profile opts in only to tables the SDK holds (the reference table, a module
/// table of the configuration; the reference table only in a build with `wallet`, which quotes), once each; a module table may not take the reference table's name or another table's, and is
/// EVM (the only family with a table today). Each refusal beside its control.
#[tokio::test]
async fn open_checks_gas_tables_and_opt_ins() {
    let with = |opt: &[&str], tables: Vec<GasTable>| {
        let mut p = profile("a");
        p.gas_opt_in = opt.iter().map(|s| s.to_string()).collect();
        let mut c = config(vec![p]);
        c.gas_tables = tables;
        Sdk::open(c)
    };
    let ok = |r: Result<std::sync::Arc<Sdk>, SdkError>| code(r.map(|_| ()));
    assert_eq!(
        ok(with(&["vault"], vec![gas_table("vault", "evm")]).await),
        "Ok"
    );
    // the reference table is data of the quote (`op`, feature `wallet`): a build without it holds no reference table, so an
    // opt-in to it names a table the SDK does not hold
    assert_eq!(
        ok(with(&["reference", "vault"], vec![gas_table("vault", "evm")]).await),
        if cfg!(feature = "wallet") {
            "Ok"
        } else {
            "Argument"
        }
    );
    assert_eq!(
        ok(with(&["missing"], vec![gas_table("vault", "evm")]).await),
        "Argument"
    );
    assert_eq!(
        ok(with(&["vault", "vault"], vec![gas_table("vault", "evm")]).await),
        "Argument"
    );
    assert_eq!(
        ok(with(&[], vec![gas_table("reference", "evm")]).await),
        "Argument"
    );
    assert_eq!(
        ok(with(
            &[],
            vec![gas_table("vault", "evm"), gas_table("vault", "evm")]
        )
        .await),
        "Argument"
    );
    assert_eq!(
        ok(with(&[], vec![gas_table("vault", "soroban")]).await),
        "Argument"
    );
}

#[tokio::test]
async fn open_refuses_a_profile_without_chain_uid() {
    assert_eq!(code(open(vec![profile("a")]).await), "Ok");
    for bad in ["", "0x", &UID[..65], &format!("{}g", &UID[..65]), &UID[2..]] {
        let mut p = profile("a");
        p.chain_uid = bad.to_string();
        assert_eq!(code(open(vec![p]).await), "Argument", "{bad:?}");
    }
}

#[tokio::test]
async fn open_refuses_two_profiles_one_key() {
    assert_eq!(code(open(vec![profile("a"), profile("b")]).await), "Ok");
    assert_eq!(
        code(open(vec![profile("a"), profile("a")]).await),
        "Argument"
    );
}

#[tokio::test]
async fn open_refuses_an_empty_rpc_list() {
    let mut p = profile("a");
    p.rpc.truncate(1);
    assert_eq!(code(open(vec![p.clone()]).await), "Ok");
    p.rpc.clear();
    assert_eq!(code(open(vec![p]).await), "EndpointListEmpty");
}

#[tokio::test]
async fn open_refuses_strict_majority_with_one_endpoint() {
    let mut p = profile("a");
    p.rpc_policy = Policy::StrictMajority;
    assert_eq!(code(open(vec![p.clone()]).await), "Ok");
    p.rpc.truncate(1);
    assert_eq!(code(open(vec![p]).await), "Argument");
}

#[tokio::test]
async fn open_refuses_a_gateway_list_that_is_not_http() {
    let mut p = profile("a");
    p.gateways = vec![endpoint("https://127.0.0.1:3/")];
    assert_eq!(code(open(vec![p.clone()]).await), "Ok");
    p.gateways = vec![endpoint("ftp://127.0.0.1:3/")];
    assert_eq!(code(open(vec![p]).await), "EndpointScheme");
}

#[tokio::test]
async fn own_runtime_opens_and_drops_inside_async() {
    let mut c = config(vec![profile("a")]);
    c.runtime = RuntimeChoice::Own;
    let sdk = Sdk::open(c).await.unwrap();
    drop(sdk); // an owned runtime dropped from an async context must not panic
}

#[tokio::test]
async fn credentials_never_in_debug() {
    let mut p = profile("a");
    p.rpc[0].url = format!("http://127.0.0.1:1/{MARK}-path?key={MARK}");
    p.rpc[0].auth = Some(EndpointAuth::Bearer(Secret::new(MARK)));
    p.gateways = vec![EndpointConfig {
        url: "http://127.0.0.1:9/".into(),
        class: Class::Named,
        label: None,
        auth: Some(EndpointAuth::Hmac(Secret::new(MARK))),
    }];
    let c = config(vec![p.clone()]);
    let dbg = format!("{c:?}");
    assert!(
        dbg.contains("Bearer") || dbg.contains("<secret>"),
        "control: the endpoint is printed: {dbg}"
    );
    assert!(!dbg.contains(MARK), "{dbg}");
}

#[tokio::test]
async fn errors_carry_no_input() {
    let mut p = profile("a");
    p.rpc[0].url = format!("http://127.0.0.1:1/{MARK}-path?key={MARK}");
    p.rpc[0].auth = Some(EndpointAuth::Bearer(Secret::new(MARK)));
    // the errors of every refusal on that profile
    let mut errs = vec![];
    let mut q = p.clone();
    q.chain_uid = MARK.into();
    errs.push(open(vec![q]).await);
    let mut q = p.clone();
    q.rpc[1].url = format!("ftp://{MARK}/");
    errs.push(open(vec![q]).await);
    let mut q = p.clone();
    q.rpc[1].url = q.rpc[0].url.clone();
    errs.push(open(vec![q]).await);
    errs.push(open(vec![p.clone(), p]).await);
    for e in errs {
        let e = e.unwrap_err();
        assert!(!format!("{e:?} {e}").contains(MARK), "{e:?}");
    }
}

#[test]
fn features_bits_match_the_build() {
    let f = Sdk::features();
    assert_eq!(f & bits::VAULT, bits::VAULT);
    assert_eq!(f & (1 << 12), 0, "bit 12 is never reused");
    let expect = [
        (cfg!(feature = "account"), bits::ACCOUNT),
        (cfg!(feature = "wallet"), bits::WALLET),
        (cfg!(feature = "zether"), bits::ZETHER),
        (cfg!(feature = "pqz"), bits::PQZ),
        (cfg!(feature = "dex"), bits::DEX),
        (cfg!(feature = "admin"), bits::ADMIN),
        (cfg!(feature = "file-store"), bits::FILE_STORE),
        (cfg!(feature = "mlock"), bits::MLOCK),
        (cfg!(feature = "classical-roots"), bits::CLASSICAL_ROOTS),
    ];
    for (on, bit) in expect {
        assert_eq!(f & bit != 0, on, "bit {bit:#x}");
    }
    // spec §3.3's numbers, by name
    assert_eq!(
        [
            bits::VAULT,
            bits::ACCOUNT,
            bits::WALLET,
            bits::ZETHER,
            bits::PQZ,
            bits::DEX,
            bits::ADMIN,
            bits::MLOCK,
            bits::FILE_STORE,
            bits::CLASSICAL_ROOTS
        ],
        [
            1 << 0,
            1 << 1,
            1 << 2,
            1 << 4,
            1 << 5,
            1 << 10,
            1 << 11,
            1 << 13,
            1 << 22,
            1 << 24
        ]
    );
    let sets = [
        bits::PQZ_SET_N2048_KMAX1024,
        bits::PQZ_SET_N2304_KMAX4096,
        bits::PQZ_SET_N2560_KMAX16384,
        bits::PQZ_SET_N2816_KMAX65536,
    ];
    assert_eq!(sets, [1 << 6, 1 << 7, 1 << 8, 1 << 9]);
    let full = bits::VAULT
        | bits::ACCOUNT
        | bits::WALLET
        | bits::ZETHER
        | bits::PQZ
        | bits::PQZ_SET_N2304_KMAX4096
        | bits::DEX
        | bits::ADMIN;
    // the plan's two builds: `--no-default-features --features vault` and F (plus the defaults F runs with)
    if cfg!(all(
        feature = "zether",
        feature = "pqz-set-n2304-kmax4096",
        feature = "dex",
        feature = "admin"
    )) {
        assert_eq!(f & full, full);
    }
    if !cfg!(feature = "account")
        && !cfg!(feature = "file-store")
        && !cfg!(feature = "mlock")
        && !cfg!(feature = "pqz")
    {
        assert_eq!(f, bits::VAULT);
    }
}
