// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Profiles, the overlay and the data directory (CLI-SDK-17, R17). A release build takes the profiles compiled into it and no
//! other; a `dev-profiles` build may take `--profiles <file>` and says so on every run. The overlay (JSON, unknown fields
//! refused) may only add a credential by file or by an environment variable's name and lower the caps: it has no field for a
//! `chain_uid`, a contract or an endpoint list.
use crate::{Fail, Globals};
use scaas_rpc::{Class, EndpointAuth, Policy, Secret};
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, FamilyParams, Finality, Limits, ListedDex, ListedToken,
    Sdk, SdkConfig,
};
use serde::Deserialize;
use std::sync::Arc;

/// The release's chain profiles, compiled in (CLI-TUI-11's first form): `profiles/release.json`.
pub const RELEASE_PROFILES: &str = include_str!("../profiles/release.json");
/// The largest profile or overlay file (64 KiB).
const FILE_MAX: u64 = 64 * 1024;

/// A file of at most [`FILE_MAX`] bytes, as text.
pub fn read_bounded(path: &str) -> Result<String, Fail> {
    use std::io::Read;
    let f = std::fs::File::open(path).map_err(|_| Fail::cli("FileUnreadable", path))?;
    let mut s = String::new();
    f.take(FILE_MAX + 1)
        .read_to_string(&mut s)
        .map_err(|_| Fail::cli("FileUnreadable", path))?;
    if s.len() as u64 > FILE_MAX {
        return Err(Fail::cli("FileTooLarge", path));
    }
    Ok(s)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profiles {
    profiles: Vec<Profile>,
}

#[derive(Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Pol {
    #[default]
    Failover,
    StrictMajority,
}

#[derive(Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Cls {
    #[default]
    Named,
    Default,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ep {
    url: String,
    #[serde(default)]
    class: Cls,
    label: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    key: String,
    family: Family,
    chain_id: Option<u64>,
    chain_uid: String,
    rpc: Vec<Ep>,
    #[serde(default)]
    rpc_policy: Pol,
    #[serde(default)]
    gateways: Vec<Ep>,
    registry: Option<String>,
    factory: Option<String>,
    router: Option<String>,
    finality: Finality,
    tx_gas_cap: Option<u64>,
    #[serde(default)]
    tokens: Vec<ListedToken>,
    /// the chain's measured gas rows, release data (spec §13.3)
    #[serde(default)]
    gas: scaas_sdk::GasRows,
    #[serde(default)]
    gas_opt_in: Vec<String>,
    max_valid_secs: Option<u64>,
    #[serde(default)]
    verifiers: Vec<Ep>,
    #[serde(default)]
    verifier_policy: Pol,
    #[serde(default)]
    dexes: Vec<ListedDex>,
    #[serde(default)]
    wrappers: Vec<String>,
    /// a non-EVM family's own data (spec §8.7 rule 2), by its family's name; its fields' forms checked at `Sdk::open`
    family_params: Option<Fam>,
    /// the chain's L1 data fee model (plan T38): `"OpStack"` on Base, Celo and OP; absent: none
    #[serde(default)]
    l1_fee: Option<scaas_sdk::L1Fee>,
    /// the kinds the chain cannot carry, disabled by the owner (2026-11-22): UA kind names and `pqz`
    #[serde(default)]
    disabled_kinds: Vec<String>,
    /// whether a read pinned by block hash is trusted (decisions ARCH-POS-20 (2)): false on Moonbeam and Moonbase; absent: true
    #[serde(default = "yes")]
    pinned_reads: bool,
}

fn yes() -> bool {
    true
}

/// [`scaas_sdk::FamilyParams`] by name, one family per profile.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Fam {
    Cosmos(CosmosFam),
    Aptos(AptosFam),
    Solana(SolanaFam),
    Soroban(SorobanFam),
    Sui(SuiFam),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuiFam {
    graphql: Vec<Ep>,
    #[serde(default)]
    graphql_policy: Pol,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SorobanFam {
    passphrase: String,
    xlm_sac: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SolanaFam {
    program: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CosmosFam {
    chain_id: String,
    rest: Vec<Ep>,
    #[serde(default)]
    rest_policy: Pol,
    denom: String,
    prefix: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AptosFam {
    chain_id: u8,
    package: String,
}

fn fam(f: Fam) -> FamilyParams {
    match f {
        Fam::Cosmos(c) => FamilyParams::Cosmos {
            chain_id: c.chain_id,
            rest: eps(c.rest),
            rest_policy: pol(c.rest_policy),
            denom: c.denom,
            prefix: c.prefix,
        },
        Fam::Aptos(a) => FamilyParams::Aptos {
            chain_id: a.chain_id,
            package: a.package,
        },
        Fam::Solana(s) => FamilyParams::Solana { program: s.program },
        Fam::Soroban(s) => FamilyParams::Soroban {
            passphrase: s.passphrase,
            xlm_sac: s.xlm_sac,
        },
        Fam::Sui(s) => FamilyParams::Sui {
            graphql: eps(s.graphql),
            graphql_policy: pol(s.graphql_policy),
        },
    }
}

fn pol(p: Pol) -> Policy {
    match p {
        Pol::Failover => Policy::Failover,
        Pol::StrictMajority => Policy::StrictMajority,
    }
}

fn eps(v: Vec<Ep>) -> Vec<EndpointConfig> {
    v.into_iter()
        .map(|e| EndpointConfig {
            url: e.url,
            class: match e.class {
                Cls::Named => Class::Named,
                Cls::Default => Class::Default,
            },
            label: e.label,
            auth: None,
        })
        .collect()
}

/// The profiles of a profile file's text.
pub fn parse_profiles(text: &str) -> Result<Vec<ChainProfile>, Fail> {
    let p: Profiles =
        serde_json::from_str(text).map_err(|e| Fail::cli("ProfilesRefused", e.to_string()))?;
    Ok(p.profiles
        .into_iter()
        .map(|p| ChainProfile {
            key: p.key,
            family: p.family,
            chain_id: p.chain_id,
            chain_uid: p.chain_uid,
            rpc: eps(p.rpc),
            rpc_policy: pol(p.rpc_policy),
            gateways: eps(p.gateways),
            registry: p.registry,
            factory: p.factory,
            router: p.router,
            finality: p.finality,
            tx_gas_cap: p.tx_gas_cap,
            tokens: p.tokens,
            gas: p.gas,
            gas_opt_in: p.gas_opt_in,
            max_valid_secs: p.max_valid_secs,
            verifiers: eps(p.verifiers),
            verifier_policy: pol(p.verifier_policy),
            dexes: p.dexes,
            wrappers: p.wrappers,
            l1_fee: p.l1_fee,
            disabled_kinds: p.disabled_kinds,
            pinned_reads: p.pinned_reads,
            family_params: p.family_params.map(fam),
        })
        .collect())
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Overlay {
    #[serde(default)]
    limits: Caps,
    #[serde(default)]
    credentials: Vec<Cred>,
}

/// Lower caps only (CLI-TUI-12).
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Caps {
    max_fee_per_gas: Option<String>,
    max_gas: Option<u64>,
    max_cost: Option<String>,
}

#[derive(Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
enum List {
    Rpc,
    Gateways,
    Verifiers,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Bearer,
    Hmac,
    Header(String),
}

/// A credential for one endpoint of a profile, by its label: from a file (refused when group- or world-readable) or an
/// environment variable named here; never its value.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cred {
    profile: String,
    list: List,
    label: String,
    kind: Kind,
    file: Option<String>,
    env: Option<String>,
}

fn lower(build: &str, asked: &Option<String>, what: &str) -> Result<Option<String>, Fail> {
    let Some(a) = asked else { return Ok(None) };
    let (b, x) = (build.parse::<u128>(), a.parse::<u128>());
    match (b, x) {
        (Ok(b), Ok(x)) if x <= b => Ok(Some(a.clone())),
        (Ok(_), Ok(_)) => Err(Fail::cli("CapRaised", what)),
        _ => Err(Fail::cli("OverlayRefused", what)),
    }
}

fn secret_of(c: &Cred) -> Result<Secret, Fail> {
    match (&c.file, &c.env) {
        (Some(f), None) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let m =
                    std::fs::metadata(f).map_err(|_| Fail::cli("FileUnreadable", f.as_str()))?;
                if m.permissions().mode() & 0o077 != 0 {
                    return Err(Fail::cli("CredentialFileReadable", f.as_str()));
                }
            }
            Ok(Secret::new(read_bounded(f)?.trim_end_matches(['\n', '\r'])))
        }
        (None, Some(name)) => std::env::var(name)
            .map(Secret::new)
            .map_err(|_| Fail::cli("CredentialMissing", name.as_str())),
        _ => Err(Fail::cli(
            "OverlayRefused",
            "a credential names one file or one environment variable",
        )),
    }
}

/// Applies an overlay's text to the profiles and the limits.
pub fn apply_overlay(
    text: &str,
    profiles: &mut [ChainProfile],
    limits: &mut Limits,
) -> Result<(), Fail> {
    let o: Overlay =
        serde_json::from_str(text).map_err(|e| Fail::cli("OverlayRefused", e.to_string()))?;
    let build = Limits::default();
    if let Some(v) = lower(
        &build.max_fee_per_gas,
        &o.limits.max_fee_per_gas,
        "max_fee_per_gas",
    )? {
        limits.max_fee_per_gas = v;
    }
    if let Some(v) = lower(&build.max_cost, &o.limits.max_cost, "max_cost")? {
        limits.max_cost = v;
    }
    if let Some(g) = o.limits.max_gas {
        if g > build.max_gas {
            return Err(Fail::cli("CapRaised", "max_gas"));
        }
        limits.max_gas = g;
    }
    for c in &o.credentials {
        let p = profiles
            .iter_mut()
            .find(|p| p.key == c.profile)
            .ok_or_else(|| Fail::cli("OverlayRefused", format!("no profile {}", c.profile)))?;
        let list = match c.list {
            List::Rpc => &mut p.rpc,
            List::Gateways => &mut p.gateways,
            List::Verifiers => &mut p.verifiers,
        };
        let e = list
            .iter_mut()
            .find(|e| e.label.as_deref() == Some(c.label.as_str()))
            .ok_or_else(|| {
                Fail::cli(
                    "OverlayRefused",
                    format!("no endpoint labelled {}", c.label),
                )
            })?;
        let s = secret_of(c)?;
        e.auth = Some(match &c.kind {
            Kind::Bearer => EndpointAuth::Bearer(s),
            Kind::Hmac => EndpointAuth::Hmac(s),
            Kind::Header(name) => EndpointAuth::Header {
                name: name.clone(),
                value: s,
            },
        });
    }
    Ok(())
}

fn home_dir(var: &str, fallback: &str) -> Option<String> {
    std::env::var(var)
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| format!("{h}/{fallback}"))
        })
        .map(|d| format!("{d}/scaas"))
}

/// The development banner, on every run of a `dev-profiles` build.
pub fn banner(g: &Globals) {
    if cfg!(feature = "dev-profiles") {
        let digest = g
            .profiles
            .as_deref()
            .and_then(|p| read_bounded(p).ok())
            .map(|t| {
                use sha2::Digest;
                sha2::Sha256::digest(t.as_bytes())
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            });
        match digest {
            Some(d) => {
                eprintln!("DEVELOPMENT BUILD (dev-profiles): profiles from a file, sha256 {d}")
            }
            None => eprintln!("DEVELOPMENT BUILD (dev-profiles): the release profiles"),
        }
    }
}

/// The SDK over the data directory, the profiles and the overlay.
pub async fn open(g: &Globals) -> Result<Arc<Sdk>, Fail> {
    let text = match &g.profiles {
        Some(f) if cfg!(feature = "dev-profiles") => read_bounded(f)?,
        Some(_) => {
            return Err(Fail::cli(
                "ProfilesPinned",
                "--profiles exists only in a dev-profiles build",
            ))
        }
        None => RELEASE_PROFILES.to_string(),
    };
    let mut profiles = parse_profiles(&text)?;
    let mut limits = Limits::default();
    let overlay = g.overlay.clone().or_else(|| {
        home_dir("XDG_CONFIG_HOME", ".config")
            .map(|d| format!("{d}/overlay.json"))
            .filter(|f| std::path::Path::new(f).exists())
    });
    if let Some(f) = overlay {
        apply_overlay(&read_bounded(&f)?, &mut profiles, &mut limits)?;
    }
    let dir = g
        .data_dir
        .clone()
        .or_else(|| home_dir("XDG_DATA_HOME", ".local/share"))
        .ok_or_else(|| Fail::cli("DataDirMissing", "--data-dir"))?;
    let store = scaas_sdk::vault::FileStore::new(dir)
        .map_err(|_| Fail::cli("DataDirUnusable", "the data directory"))?;
    Ok(Sdk::open(SdkConfig {
        profiles,
        store,
        authenticator: None,
        rp_id: None,
        runtime: scaas_sdk::RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits,
        clock: None,
        gas_tables: vec![],
    })
    .await?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;

    const P: &str = r#"{"profiles":[{"key":"local","family":"Evm","chain_id":31337,"chain_uid":"0x0000000000000000000000000000000000000000000000000000000000000001","rpc":[{"url":"http://127.0.0.1:1","label":"a"}],"finality":"Finalized","tx_gas_cap":null,"registry":null,"factory":null,"router":null,"max_valid_secs":null}]}"#;

    fn code<T>(r: Result<T, Fail>) -> &'static str {
        match r {
            Ok(_) => "Ok",
            Err(Fail::Cli(c, _)) => c,
            Err(Fail::Sdk(e)) => e.code(),
        }
    }

    #[test]
    fn overlay_lowers_caps_and_adds_credentials_only() {
        let mut p = parse_profiles(P).unwrap();
        let mut l = Limits::default();
        assert_eq!(
            code(apply_overlay(
                r#"{"limits":{"max_gas":1000,"max_cost":"5"}}"#,
                &mut p,
                &mut l
            )),
            "Ok"
        );
        assert_eq!((l.max_gas, l.max_cost.as_str()), (1000, "5"));
        // raising a cap, one change at a time
        assert_eq!(
            code(apply_overlay(
                r#"{"limits":{"max_gas":99999999999}}"#,
                &mut p,
                &mut l
            )),
            "CapRaised"
        );
        assert_eq!(
            code(apply_overlay(
                r#"{"limits":{"max_cost":"99999999999999999999"}}"#,
                &mut p,
                &mut l
            )),
            "CapRaised"
        );
        assert_eq!(
            code(apply_overlay(
                r#"{"limits":{"max_fee_per_gas":"99999999999999"}}"#,
                &mut p,
                &mut l
            )),
            "CapRaised"
        );
        // what the overlay cannot hold: a chain_uid, a contract, an endpoint list
        for bad in [
            r#"{"chain_uid":"0x00"}"#,
            r#"{"registry":"0x00"}"#,
            r#"{"rpc":[]}"#,
            r#"{"profiles":[]}"#,
        ] {
            assert_eq!(
                code(apply_overlay(bad, &mut p, &mut l)),
                "OverlayRefused",
                "{bad}"
            );
        }
        // a credential by an environment variable's name, never a value
        std::env::set_var("SCAAS_CLI_TEST_TOKEN", "t");
        let ok = r#"{"credentials":[{"profile":"local","list":"rpc","label":"a","kind":"bearer","env":"SCAAS_CLI_TEST_TOKEN"}]}"#;
        assert_eq!(code(apply_overlay(ok, &mut p, &mut l)), "Ok");
        assert!(p[0].rpc[0].auth.is_some());
        let value = r#"{"credentials":[{"profile":"local","list":"rpc","label":"a","kind":"bearer","value":"t"}]}"#;
        assert_eq!(code(apply_overlay(value, &mut p, &mut l)), "OverlayRefused");
        let both =
            r#"{"credentials":[{"profile":"local","list":"rpc","label":"a","kind":"bearer"}]}"#;
        assert_eq!(code(apply_overlay(both, &mut p, &mut l)), "OverlayRefused");
    }

    /// A Cosmos and an Aptos profile with their family params (the family data a non-EVM read needs, spec §8.7 rule 2).
    fn fam(params: &str, family: &str) -> String {
        format!(
            r#"{{"profiles":[{{"key":"f","family":"{family}","chain_uid":"0x0000000000000000000000000000000000000000000000000000000000000002","rpc":[{{"url":"http://127.0.0.1:1","label":"a"}}],"finality":"Finalized","family_params":{params}}}]}}"#
        )
    }
    const COSMOS: &str = r#"{"cosmos":{"chain_id":"scaas-local-1","rest":[{"url":"http://127.0.0.1:1","label":"r"},{"url":"http://127.0.0.1:2","label":"s"}],"rest_policy":"strict_majority","denom":"uscaas","prefix":"wasm"}}"#;
    const APTOS: &str = r#"{"aptos":{"chain_id":4,"package":"0x00000000000000000000000000000000000000000000000000000000000000aa"}}"#;
    const SOLANA: &str = r#"{"solana":{"program":"7DYCAhqwQSKqqL1h8V1XmY1BTcMWxrASQYKNMy87jeg3"}}"#;
    const SUI: &str = r#"{"sui":{"graphql":[{"url":"http://127.0.0.1:1","label":"g"},{"url":"http://127.0.0.1:2","label":"h"}],"graphql_policy":"strict_majority"}}"#;

    /// A profile states its finality, the tag or a depth (owner 2026-11-22, ETC dropped, decisions CLI-SDK-32: no chain without
    /// one): none, or a depth without its number, is `ProfilesRefused` (fail closed). Control: the tag and a depth load.
    #[test]
    fn a_profile_without_a_finality_depth_is_refused() {
        assert_eq!(code(parse_profiles(P)), "Ok");
        let depth = P.replace(r#""finality":"Finalized""#, r#""finality":{"Depth":12}"#);
        assert_eq!(code(parse_profiles(&depth)), "Ok");
        for bad in [
            P.replace(r#""finality":"Finalized","#, ""),
            P.replace(r#""finality":"Finalized""#, r#""finality":{"Depth":null}"#),
            P.replace(r#""finality":"Finalized""#, r#""finality":{"depth":null}"#),
        ] {
            assert_eq!(code(parse_profiles(&bad)), "ProfilesRefused", "{bad}");
        }
    }

    #[test]
    fn family_params_are_read_by_name() {
        let p = parse_profiles(&fam(COSMOS, "Cosmos")).unwrap();
        match &p[0].family_params {
            Some(scaas_sdk::FamilyParams::Cosmos {
                chain_id,
                rest,
                rest_policy,
                denom,
                prefix,
            }) => {
                assert_eq!(
                    (chain_id.as_str(), denom.as_str(), prefix.as_str()),
                    ("scaas-local-1", "uscaas", "wasm")
                );
                assert_eq!((rest.len(), rest[1].label.as_deref()), (2, Some("s")));
                assert!(matches!(rest_policy, Policy::StrictMajority));
            }
            _ => panic!("no Cosmos params"),
        }
        let p = parse_profiles(&fam(APTOS, "Aptos")).unwrap();
        assert!(matches!(
            &p[0].family_params,
            Some(scaas_sdk::FamilyParams::Aptos { chain_id: 4, package }) if package.ends_with("aa")
        ));
        let p = parse_profiles(&fam(SUI, "Sui")).unwrap();
        assert!(matches!(
            &p[0].family_params,
            Some(scaas_sdk::FamilyParams::Sui { graphql, graphql_policy: Policy::StrictMajority })
                if graphql.len() == 2 && graphql[1].label.as_deref() == Some("h")
        ));
        // without the field: none (an EVM profile)
        assert!(parse_profiles(P).unwrap()[0].family_params.is_none());
        // an unknown field, an unknown family, two families at once: refused by name, each beside the controls above
        for bad in [
            COSMOS.replace("\"prefix\"", "\"prefix\":\"wasm\",\"extra\""),
            r#"{"solana_x":{}}"#.to_string(),
            format!(
                "{{{},{}}}",
                &COSMOS[1..COSMOS.len() - 1],
                &APTOS[1..APTOS.len() - 1]
            ),
        ] {
            assert_eq!(
                code(parse_profiles(&fam(&bad, "Cosmos"))),
                "ProfilesRefused",
                "{bad}"
            );
        }
    }

    /// The CLI's SDK reads the families (their features are on): a Cosmos and an Aptos profile reach their endpoints (none
    /// answers here) instead of `FeatureMissing`; params out of their form are `Argument` at `Sdk::open`.
    #[tokio::test(flavor = "multi_thread")]
    async fn family_profiles_open_and_read() {
        for (params, family) in [
            (COSMOS, "Cosmos"),
            (APTOS, "Aptos"),
            (SOLANA, "Solana"),
            (SUI, "Sui"),
        ] {
            let sdk = open_with(&fam(params, family)).await.unwrap();
            let id = match family {
                "Solana" => "US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx",
                _ => "0x0000000000000000000000000000000000000000000000000000000000000003",
            }
            .to_string();
            let r = sdk.wallet().balances(id, "f".into()).await;
            assert_ne!(code(r.map_err(Fail::Sdk)), "FeatureMissing", "{family}");
        }
        // Soroban: the passphrase's SHA-256 is the profile's chain_uid
        use sha2::Digest;
        let pass = "Standalone Network ; February 2017";
        let uid: String = sha2::Sha256::digest(pass)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let sor = fam(
            &format!(r#"{{"soroban":{{"passphrase":"{pass}","xlm_sac":"CCJSG6X7HADWBAWWDQVBUOJJYIMMCTSW7UMWKPJPTZ5GKOBLZ77E4WQA"}}}}"#),
            "Soroban",
        )
        .replace(&"0".repeat(63), "")
        .replace("0x2", &format!("0x{uid}"));
        let sdk = open_with(&sor).await.unwrap();
        let r = sdk
            .wallet()
            .balances(
                "GCJU3TGRU2M7V3DQTULG3A5DPHFPMTQIPAVP22UQW5F55D4ABTF2W7HU".into(),
                "f".into(),
            )
            .await;
        assert_ne!(code(r.map_err(Fail::Sdk)), "FeatureMissing", "Soroban");
        // TON: no family params (the profile's rpc are its TON Center endpoints)
        let sdk = open_with(&fam("null", "Ton")).await.unwrap();
        let r = sdk
            .wallet()
            .balances(format!("0:{}", "0".repeat(64)), "f".into())
            .await;
        assert_ne!(code(r.map_err(Fail::Sdk)), "FeatureMissing", "Ton");
        let zero = APTOS.replace("\"chain_id\":4", "\"chain_id\":0");
        assert_eq!(code(open_with(&fam(&zero, "Aptos")).await), "Argument");
        // the family named by the params is the profile's
        assert_eq!(code(open_with(&fam(APTOS, "Cosmos")).await), "Argument");
    }

    async fn open_with(text: &str) -> Result<Arc<Sdk>, Fail> {
        let d = std::env::temp_dir().join(format!(
            "scaas-cli-fam-{}-{}",
            std::process::id(),
            text.len()
        ));
        let store = scaas_sdk::vault::FileStore::new(d.to_string_lossy().into_owned()).unwrap();
        Ok(Sdk::open(SdkConfig {
            profiles: parse_profiles(text)?,
            store,
            authenticator: None,
            rp_id: None,
            runtime: scaas_sdk::RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
            limits: Limits::default(),
            clock: None,
            gas_tables: vec![],
        })
        .await?)
    }

    #[cfg(unix)]
    #[test]
    fn credential_file_readable_by_others_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("scaas-cli-cred-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("token");
        std::fs::write(&f, "t\n").unwrap();
        let ov = format!(
            r#"{{"credentials":[{{"profile":"local","list":"rpc","label":"a","kind":"bearer","file":"{}"}}]}}"#,
            f.display()
        );
        let mut p = parse_profiles(P).unwrap();
        let mut l = Limits::default();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(code(apply_overlay(&ov, &mut p, &mut l)), "Ok");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            code(apply_overlay(&ov, &mut p, &mut l)),
            "CredentialFileReadable"
        );
        std::fs::remove_dir_all(&d).unwrap();
    }
}
