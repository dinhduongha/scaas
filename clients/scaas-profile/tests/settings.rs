// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! User profiles (spec docs/superpowers/specs/2026-11-27-user-profiles.md, plan docs/superpowers/plans/2026-11-27-user-profiles.md),
//! UP10: the settings (§5, §7.7; §17 "settings (R2-C-3)"): the weakening rule, `set_settings` on a protected profile, the
//! import's filter, and the migration of the CLI's overlay into "default"'s `settings` (§12 step 2).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use scaas_profile::settings::{
    filter, review, weakens, Caps, ChainSettings, CredentialKind, CredentialRef, Endpoint,
    EndpointList, Setting,
};
#[cfg(feature = "test-hooks")]
use scaas_profile::Error;
use scaas_profile::{uuid7, ProfileSettings, Profiles, ProfilesConfig};
use std::path::PathBuf;

fn rnd(n: u8) -> [u8; 10] {
    use std::hash::{BuildHasher, RandomState};
    let s = RandomState::new();
    let mut r = [0u8; 10];
    r[..8].copy_from_slice(&s.hash_one(n).to_le_bytes());
    r[8..].copy_from_slice(&s.hash_one(n ^ 0xff).to_le_bytes()[..2]);
    r
}

fn tmp() -> PathBuf {
    std::env::temp_dir().join(format!(
        "scaas-profile-up10s-{}-{}",
        std::process::id(),
        uuid7(0, &rnd(3))
    ))
}

#[cfg(feature = "test-hooks")]
fn code<T>(r: Result<T, Error>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "ok")
}

fn endpoint(label: &str, first: bool) -> Endpoint {
    Endpoint {
        list: EndpointList::Rpc,
        label: label.into(),
        url: format!("https://{label}.example:8545/v1"),
        first,
    }
}

fn cred(label: &str) -> CredentialRef {
    CredentialRef {
        chain_profile: "scaas-testnet".into(),
        list: EndpointList::Rpc,
        label: label.into(),
        kind: CredentialKind::Bearer,
        file: None,
        env: Some("SCAAS_TOKEN".into()),
    }
}

/// One endpoint, an idle lock of 300 s, the clipboard off, one credential reference.
fn base() -> ProfileSettings {
    let mut s = ProfileSettings::default();
    s.chains.insert(
        "scaas-testnet".into(),
        ChainSettings {
            endpoints: vec![endpoint("a", false)],
            ..ChainSettings::default()
        },
    );
    s.idle_lock_s = Some(300);
    s.credentials.push(cred("a"));
    s
}

type Change = fn(&mut ProfileSettings);

fn chain(s: &mut ProfileSettings) -> &mut ChainSettings {
    s.chains.get_mut("scaas-testnet").unwrap()
}

/// The weakening changes of spec §7.7, one at a time.
const WEAKEN: [(&str, Change); 7] = [
    ("an added endpoint", |s| {
        chain(s).endpoints.push(endpoint("b", false))
    }),
    ("an endpoint's URL changed", |s| {
        chain(s).endpoints[0].url = "https://elsewhere.example".into()
    }),
    ("a first mark", |s| chain(s).endpoints[0].first = true),
    ("a credential reference", |s| s.credentials.push(cred("b"))),
    ("the idle lock off", |s| s.idle_lock_s = None),
    ("the idle lock longer", |s| s.idle_lock_s = Some(301)),
    ("the clipboard on", |s| s.clipboard = true),
];

/// The changes that only strengthen (or pick the default chain profile).
const STRENGTHEN: [(&str, Change); 7] = [
    ("a lowered cap", |s| s.caps.max_gas = Some(1000)),
    ("a chain's lowered cap", |s| {
        chain(s).caps.max_cost = Some("5".into())
    }),
    ("a stronger policy", |s| chain(s).strict_majority = true),
    ("a shorter idle lock", |s| s.idle_lock_s = Some(60)),
    ("an endpoint removed", |s| chain(s).endpoints.clear()),
    ("a credential reference removed", |s| s.credentials.clear()),
    ("the default chain profile", |s| {
        s.default_chain = Some("scaas-testnet".into())
    }),
];

/// Spec §7.7: each weakening change is one, each strengthening change none (the pure rule).
#[test]
fn weakening_rule() {
    let b = base();
    assert!(!weakens(&b, &b), "no change");
    for (what, f) in WEAKEN {
        let mut n = b.clone();
        f(&mut n);
        assert!(weakens(&b, &n), "{what}");
    }
    for (what, f) in STRENGTHEN {
        let mut n = b.clone();
        f(&mut n);
        assert!(!weakens(&b, &n), "{what}");
    }
    let mut on = b.clone();
    on.clipboard = true;
    assert!(!weakens(&on, &b), "the clipboard off");
    let mut first = b.clone();
    first.chains.get_mut("scaas-testnet").unwrap().endpoints[0].first = true;
    assert!(!weakens(&first, &b), "a first mark removed");
}

/// Spec §10.1: the review lists every setting by item id (credential references never), the kept ones marked; the filter
/// keeps those, and the confirmed ones each by itself; a credential reference never.
#[test]
fn import_filter() {
    let mut s = base();
    s.rev = 7;
    s.caps.max_gas = Some(1000);
    s.default_chain = Some("scaas-testnet".into());
    s.clipboard = true;
    {
        let c = chain(&mut s);
        c.strict_majority = true;
        c.endpoints.push(endpoint("b", true));
    }
    let r = review(&s);
    let kinds: Vec<(u32, bool, &str)> = r
        .iter()
        .map(|i| {
            let k = match &i.setting {
                Setting::Caps { .. } => "caps",
                Setting::DefaultChain(_) => "default",
                Setting::StrictMajority(_) => "strict",
                Setting::Endpoint { .. } => "endpoint",
                Setting::First { .. } => "first",
                Setting::IdleLock(_) => "idle",
                Setting::Clipboard => "clipboard",
            };
            (i.id, i.kept, k)
        })
        .collect();
    assert_eq!(
        kinds,
        [
            (0, true, "caps"),
            (1, true, "default"),
            (2, true, "strict"),
            (3, false, "endpoint"),
            (4, false, "endpoint"),
            (5, false, "first"),
            (6, false, "idle"),
            (7, false, "clipboard"),
        ]
    );
    match &r[3].setting {
        Setting::Endpoint { label, host, .. } => {
            assert_eq!(
                (label.as_str(), host.as_deref()),
                ("a", Some("a.example:8545"))
            )
        }
        _ => panic!("endpoint"),
    }
    // nothing confirmed: what cannot weaken is kept
    let none = filter(&s, &[]);
    let c = &none.chains["scaas-testnet"];
    assert!(c.endpoints.is_empty() && c.strict_majority);
    assert_eq!(none.caps.max_gas, Some(1000));
    assert_eq!(none.default_chain.as_deref(), Some("scaas-testnet"));
    assert!(none.idle_lock_s.is_none() && !none.clipboard && none.credentials.is_empty());
    assert_eq!(none.rev, 1);
    // the second endpoint without its first mark, the idle lock
    let some = filter(&s, &[4, 6]);
    let c = &some.chains["scaas-testnet"];
    assert_eq!(c.endpoints.len(), 1);
    assert!(c.endpoints[0].label == "b" && !c.endpoints[0].first);
    assert!(some.idle_lock_s == Some(300) && !some.clipboard);
    // every item confirmed: still no credential reference
    let all = filter(&s, &(0..8).collect::<Vec<_>>());
    let c = &all.chains["scaas-testnet"];
    assert!(c.endpoints.len() == 2 && c.endpoints[1].first);
    assert!(all.clipboard && all.idle_lock_s == Some(300));
    assert!(
        all.credentials.is_empty(),
        "a credential reference is never imported"
    );
}

/// A fresh root, its "default" opened (unprotected).
fn default_open() -> (Profiles, scaas_profile::OpenProfile, PathBuf) {
    let root = tmp();
    let p = Profiles::new(ProfilesConfig::new(root.clone())).unwrap();
    let id = p.list().unwrap()[0].id.clone();
    let o = p.open(&id, None).unwrap();
    (p, o, root)
}

#[cfg(feature = "test-hooks")]
const PASS: &[u8] = b"correct horse battery staple";

/// §17 settings (R2-C-3): on a protected profile each weakening change without the typed passphrase is `Argument`, with a
/// wrong one `ProfileOpen`, nothing written; with it, written. A lowered cap and a stronger policy pass without it. The rev is
/// the store's.
#[cfg(feature = "test-hooks")]
#[test]
fn set_settings_needs_the_passphrase_to_weaken() {
    let (_p, o, _) = default_open();
    o.set_passphrase(
        PASS,
        Some(scaas_profile::KdfParams { m_kib: 8192, t: 1 }),
        None,
        None,
    )
    .unwrap();
    assert!(o.settings().unwrap() == ProfileSettings::default());
    assert_eq!(code(o.set_settings(&base(), None)), "Argument");
    o.set_settings(&base(), Some(PASS)).unwrap();
    let stored = o.settings().unwrap();
    assert_eq!(stored.rev, 1);
    for (what, f) in WEAKEN {
        let mut n = stored.clone();
        f(&mut n);
        assert_eq!(code(o.set_settings(&n, None)), "Argument", "{what}");
        assert_eq!(
            code(o.set_settings(&n, Some(b"a wrong passphrase"))),
            "ProfileOpen",
            "{what}"
        );
        assert!(o.settings().unwrap() == stored, "{what}: nothing written");
    }
    let mut n = stored.clone();
    n.caps.max_gas = Some(1000);
    chain(&mut n).strict_majority = true;
    o.set_settings(&n, None).unwrap();
    let got = o.settings().unwrap();
    assert!(got.rev == 2 && got.caps.max_gas == Some(1000));
    let mut w = got.clone();
    w.clipboard = true;
    o.set_settings(&w, Some(PASS)).unwrap();
    assert!(o.settings().unwrap().clipboard);
}

/// An unprotected profile has no passphrase to check: its settings are written as given (shown again at `set_passphrase`).
#[test]
fn unprotected_settings_written() {
    let (_p, o, _) = default_open();
    o.set_settings(&base(), None).unwrap();
    assert!(o.settings().unwrap().credentials.len() == 1);
}

/// Spec §12 step 2: the CLI's overlay moves into "default"'s `settings` (its caps, its credentials by reference) and is gone
/// at the source; an overlay that does not parse is reported and left; an overlay alone migrates nothing.
#[test]
fn overlay_migrated_into_settings() {
    let (root, src) = (tmp(), tmp());
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("keystore"), br#"{"rev":1,"seeds":[]}"#).unwrap();
    let ov = src.join("overlay.json");
    std::fs::write(
        &ov,
        br#"{"limits":{"max_gas":1000,"max_cost":"5"},"credentials":[{"profile":"local","list":"rpc","label":"a","kind":{"header":"X-Key"},"env":"SCAAS_TOKEN"}]}"#,
    )
    .unwrap();
    let mut c = ProfilesConfig::new(root.clone());
    c.legacy = Some(src.clone());
    c.legacy_overlay = Some(ov.clone());
    let p = Profiles::new(c).unwrap();
    let id = p.list().unwrap()[0].id.clone();
    let s = p.open(&id, None).unwrap().settings().unwrap();
    assert!(
        s.caps
            == Caps {
                max_fee_per_gas: None,
                max_gas: Some(1000),
                max_cost: Some("5".into()),
            }
    );
    assert_eq!(s.credentials.len(), 1);
    let r = &s.credentials[0];
    assert!(
        r.chain_profile == "local" && r.label == "a" && r.env.as_deref() == Some("SCAAS_TOKEN")
    );
    assert!(r.kind == CredentialKind::Header("X-Key".into()));
    assert!(!ov.exists(), "moved");
    // an overlay that does not parse: reported, left, the items migrated
    let (root, src) = (tmp(), tmp());
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("keystore"), br#"{"rev":1,"seeds":[]}"#).unwrap();
    let ov = src.join("overlay.json");
    std::fs::write(&ov, br#"{"rpc":[]}"#).unwrap();
    let mut c = ProfilesConfig::new(root.clone());
    c.legacy = Some(src.clone());
    c.legacy_overlay = Some(ov.clone());
    let p = Profiles::new(c).unwrap();
    assert!(p
        .drain_events()
        .contains(&scaas_profile::ProfileEvent::ProfileDamaged));
    assert!(ov.exists() && !src.join("keystore").exists());
    // an overlay alone: nothing migrated, the first run's "default" with no settings
    let (root, src) = (tmp(), tmp());
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("overlay.json"), br#"{"limits":{"max_gas":1}}"#).unwrap();
    let mut c = ProfilesConfig::new(root.clone());
    c.legacy = Some(src.clone());
    c.legacy_overlay = Some(src.join("overlay.json"));
    let p = Profiles::new(c).unwrap();
    let id = p.list().unwrap()[0].id.clone();
    assert!(p.open(&id, None).unwrap().settings().unwrap() == ProfileSettings::default());
    assert!(src.join("overlay.json").exists() && !src.join("keystore.lock").exists());
}
