// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! A profile's settings (spec §5, §7.7, §10.1; CLI-UPR-26, CLI-TUI-06, CLI-TUI-12, CLI-TUI-14): [`ProfileSettings`], the item
//! `settings` of part `sdk`, as plain data. This crate holds its storage, the §7.7 rule ([`weakens`]) and the import's filter
//! ([`review`], [`filter`]), so an app's build without the SDK has them; what the settings mean for a chain profile (and the
//! refusals of CLI-TUI-06 when they are applied) is the SDK's.
//!
//! - **Canonical JSON**, the fields in the struct's order, `rev` first (the store's revision, `rev_of`); a missing field takes
//!   its default; an unknown field is refused.
//! - **Weakening** (spec §7.7): adding an endpoint (a new label, list, chain profile or URL), marking one `first`, adding a
//!   credential reference, turning the idle lock off or lengthening it, turning the clipboard on. Nothing else needs the
//!   passphrase.
//! - **Import** (spec §10.1): a stronger policy, lowered caps and the default chain profile kept; each endpoint, each `first`
//!   mark, the idle lock and the clipboard choice kept only when confirmed by its item id; credential references always
//!   dropped, never offered.
use crate::names::check_name;
use crate::profile::{read_envelope, OpenProfile};
use crate::store::ProfilePart;
use crate::Error;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The item's name in part `sdk`.
pub(crate) const ITEM: &str = "settings";
/// The settings' largest form (an export's settings JSON too).
pub(crate) const MAX: usize = 1 << 20;

/// A profile's settings. No `Debug`: endpoints, environment variable names and file paths.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSettings {
    /// the stored revision (set by the store; ignored in [`crate::OpenProfile::set_settings`]'s input)
    #[serde(default)]
    pub rev: u64,
    /// per chain-profile key
    #[serde(default)]
    pub chains: BTreeMap<String, ChainSettings>,
    /// lowered caps of every chain profile: the SDK's `Limits` (the CLI overlay's `limits`)
    #[serde(default)]
    pub caps: Caps,
    /// the chain profile a session starts on
    #[serde(default)]
    pub default_chain: Option<String>,
    /// the idle lock in seconds; `None`: off
    #[serde(default)]
    pub idle_lock_s: Option<u64>,
    /// the clipboard opt-in (CLI-TUI-14), off by default
    #[serde(default)]
    pub clipboard: bool,
    /// credentials by reference (a file or an environment variable, never a value; CLI-TUI-06); never exported
    #[serde(default)]
    pub credentials: Vec<CredentialRef>,
}

/// One chain profile's settings (CLI-TUI-06).
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainSettings {
    /// named endpoints appended to the profile's lists (`first`: put before them, "decides")
    #[serde(default)]
    pub endpoints: Vec<Endpoint>,
    /// the RPC policy strengthened from `failover` to `strict_majority` (CLI-RPC-05); `false`: the build's
    #[serde(default)]
    pub strict_majority: bool,
    /// lowered caps of this chain profile
    #[serde(default)]
    pub caps: Caps,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub list: EndpointList,
    pub label: String,
    pub url: String,
    #[serde(default)]
    pub first: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointList {
    Rpc,
    Gateways,
    Verifiers,
}

/// Caps lowered below the build's, as decimal strings (wei) and a gas count (CLI-TUI-12); `None`: the build's.
#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Caps {
    pub max_fee_per_gas: Option<String>,
    pub max_gas: Option<u64>,
    pub max_cost: Option<String>,
}

/// A credential of one endpoint by its label: a file or an environment variable named here, never its value (CLI-TUI-06).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRef {
    pub chain_profile: String,
    pub list: EndpointList,
    pub label: String,
    pub kind: CredentialKind,
    pub file: Option<String>,
    pub env: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Bearer,
    Hmac,
    Header(String),
}

impl ProfileSettings {
    /// The canonical bytes, in a wiped buffer reserved at the settings' bound (no reallocation leaves a copy below it).
    pub fn json(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
        let mut out = zeroize::Zeroizing::new(Vec::with_capacity(MAX + 1));
        serde_json::to_writer(&mut *out, self).map_err(|_| Error::Argument)?;
        Ok(out)
    }

    /// From bytes: bounded (1 MiB, depth 6), the forms of [`ProfileSettings::check`]; else `VaultFormat`.
    pub fn parse(bytes: &[u8]) -> Result<ProfileSettings, Error> {
        if bytes.len() > MAX || scaas_ua::json::depth_within(bytes, 6).is_err() {
            return Err(Error::VaultFormat);
        }
        let s: ProfileSettings = serde_json::from_slice(bytes).map_err(|_| Error::VaultFormat)?;
        s.check()?;
        Ok(s)
    }

    /// The forms beyond the JSON (review A-4 / G-7, G-6), else `VaultFormat`: each cap 1 to 78 ASCII digits (a wei amount; a
    /// `u256` has 78); each endpoint URL `http://` or `https://`, then printable ASCII without `\`, its authority (up to the
    /// first `/`, `?` or `#`) not empty and without userinfo (`@`): what a URL parser reads as the host is what is shown.
    fn check(&self) -> Result<(), Error> {
        let cap = |c: &Option<String>| {
            c.as_deref().is_none_or(|v| {
                (1..=78).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_digit())
            })
        };
        let caps = |c: &Caps| cap(&c.max_fee_per_gas) && cap(&c.max_cost);
        let url = |u: &str| {
            let rest = u.strip_prefix("https://").or_else(|| u.strip_prefix("http://"));
            rest.is_some_and(|r| {
                let auth = r.split(['/', '?', '#']).next().unwrap_or_default();
                r.bytes().all(|b| b.is_ascii_graphic() && b != b'\\')
                    && !auth.is_empty()
                    && !auth.contains('@')
            })
        };
        let ok = caps(&self.caps)
            && self
                .chains
                .values()
                .all(|c| caps(&c.caps) && c.endpoints.iter().all(|e| url(&e.url)));
        match ok {
            true => Ok(()),
            false => Err(Error::VaultFormat),
        }
    }

    /// Every string an import review shows passes the name helper (spec §10.1): the chain-profile keys, the endpoints'
    /// labels, the default chain profile. Else `ProfileNameInvalid`.
    pub(crate) fn check_shown(&self) -> Result<(), Error> {
        let shown = |s: &str| match check_name(s)? == s {
            true => Ok(()),
            false => Err(Error::ProfileNameInvalid),
        };
        for (k, c) in &self.chains {
            shown(k)?;
            for e in &c.endpoints {
                shown(&e.label)?;
            }
        }
        self.default_chain.as_deref().map_or(Ok(()), shown)
    }
}

/// Whether `new` could weaken the profile against `old` (spec §7.7): an endpoint of `new` that `old` does not hold (by chain
/// profile, list, label and URL) or holds without its `first` mark; a credential reference `old` does not hold; the idle lock
/// off or longer; the clipboard turned on.
pub fn weakens(old: &ProfileSettings, new: &ProfileSettings) -> bool {
    let held = |k: &str, e: &Endpoint| {
        old.chains.get(k).is_some_and(|c| {
            c.endpoints.iter().any(|o| {
                o.list == e.list && o.label == e.label && o.url == e.url && (o.first || !e.first)
            })
        })
    };
    let endpoint = new
        .chains
        .iter()
        .any(|(k, c)| c.endpoints.iter().any(|e| !held(k, e)));
    let credential = new.credentials.iter().any(|c| !old.credentials.contains(c));
    let idle = match (old.idle_lock_s, new.idle_lock_s) {
        (Some(_), None) => true,
        (Some(a), Some(b)) => b > a,
        (None, _) => false,
    };
    endpoint || credential || idle || (new.clipboard && !old.clipboard)
}

/// One setting of an import review (spec §10.1); every string passed the name helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Setting {
    /// kept without a confirm: lowered caps (`chain` `None`: every chain profile's)
    Caps {
        chain: Option<String>,
        caps: Caps,
    },
    /// kept without a confirm
    DefaultChain(String),
    /// kept without a confirm: a chain profile's policy strengthened to `strict_majority`
    StrictMajority(String),
    /// an endpoint by its label and host (the host only when it passes the name helper; never the URL)
    Endpoint {
        chain: String,
        list: EndpointList,
        label: String,
        host: Option<String>,
    },
    /// an endpoint's `first` mark, confirmed by itself
    First {
        chain: String,
        list: EndpointList,
        label: String,
    },
    IdleLock(u64),
    Clipboard,
}

/// A setting of a review, its item id and whether it is kept without a confirm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewItem {
    pub id: u32,
    pub kept: bool,
    pub setting: Setting,
}

/// An endpoint's host for the review: the URL's authority without its userinfo, when it is ASCII and passes the name helper.
fn host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let auth = rest.split(['/', '?', '#']).next()?;
    let h = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
    check_name(h).ok().filter(|c| c.is_ascii() && c == h)
}

/// Walks `s` in the review's order, item ids from 0: `keep(id, setting, kept)` says whether that item is kept; the settings
/// it keeps, at rev 1.
fn walk(s: &ProfileSettings, mut keep: impl FnMut(u32, Setting, bool) -> bool) -> ProfileSettings {
    let mut id = 0u32;
    let mut ask = |setting: Setting, kept: bool| {
        let r = keep(id, setting, kept);
        id = id.saturating_add(1);
        r
    };
    if s.caps != Caps::default() {
        ask(
            Setting::Caps {
                chain: None,
                caps: s.caps.clone(),
            },
            true,
        );
    }
    if let Some(k) = &s.default_chain {
        ask(Setting::DefaultChain(k.clone()), true);
    }
    let mut chains = BTreeMap::new();
    for (k, c) in &s.chains {
        if c.strict_majority {
            ask(Setting::StrictMajority(k.clone()), true);
        }
        if c.caps != Caps::default() {
            ask(
                Setting::Caps {
                    chain: Some(k.clone()),
                    caps: c.caps.clone(),
                },
                true,
            );
        }
        let mut endpoints = Vec::new();
        for e in &c.endpoints {
            let yes = ask(
                Setting::Endpoint {
                    chain: k.clone(),
                    list: e.list,
                    label: e.label.clone(),
                    host: host(&e.url),
                },
                false,
            );
            let first = e.first
                && ask(
                    Setting::First {
                        chain: k.clone(),
                        list: e.list,
                        label: e.label.clone(),
                    },
                    false,
                );
            if yes {
                endpoints.push(Endpoint { first, ..e.clone() });
            }
        }
        chains.insert(
            k.clone(),
            ChainSettings {
                endpoints,
                strict_majority: c.strict_majority,
                caps: c.caps.clone(),
            },
        );
    }
    let idle_lock_s = s.idle_lock_s.filter(|t| ask(Setting::IdleLock(*t), false));
    let clipboard = s.clipboard && ask(Setting::Clipboard, false);
    ProfileSettings {
        rev: 1,
        chains,
        caps: s.caps.clone(),
        default_chain: s.default_chain.clone(),
        idle_lock_s,
        clipboard,
        // spec §10.1: a credential reference in a file is always dropped, never offered for confirm
        credentials: Vec::new(),
    }
}

/// Every setting of `s` an import review lists, with its item id; credential references are not listed.
pub fn review(s: &ProfileSettings) -> Vec<ReviewItem> {
    let mut out = Vec::new();
    walk(s, |id, setting, kept| {
        out.push(ReviewItem { id, kept, setting });
        kept
    });
    out
}

/// What an import keeps of `s` (spec §10.1): the items kept without a confirm, and the ones `confirmed` names by item id.
pub fn filter(s: &ProfileSettings, confirmed: &[u32]) -> ProfileSettings {
    walk(s, |id, _, kept| kept || confirmed.contains(&id))
}

/// The CLI's overlay (`overlay.json`, CLI-TUI-06): lowered caps and credentials by reference.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Overlay {
    #[serde(default)]
    limits: Caps,
    #[serde(default)]
    credentials: Vec<OverlayCred>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OverlayCred {
    profile: String,
    list: EndpointList,
    label: String,
    kind: CredentialKind,
    file: Option<String>,
    env: Option<String>,
}

/// The overlay's text as settings at rev 1 (spec §5, §12 step 2): its `limits` the caps of every chain profile, each
/// credential a reference of its chain profile. Every field of the overlay maps; one that does not parse is `VaultFormat`.
pub(crate) fn from_overlay(bytes: &[u8]) -> Result<ProfileSettings, Error> {
    if scaas_ua::json::depth_within(bytes, 6).is_err() {
        return Err(Error::VaultFormat);
    }
    let o: Overlay = serde_json::from_slice(bytes).map_err(|_| Error::VaultFormat)?;
    let s = ProfileSettings {
        rev: 1,
        caps: o.limits,
        credentials: o
            .credentials
            .into_iter()
            .map(|c| CredentialRef {
                chain_profile: c.profile,
                list: c.list,
                label: c.label,
                kind: c.kind,
                file: c.file,
                env: c.env,
            })
            .collect(),
        ..ProfileSettings::default()
    };
    s.check()?;
    Ok(s)
}

impl OpenProfile {
    /// The profile's settings (the item `settings` of part `sdk`); none stored: the defaults at rev 0.
    pub fn settings(&self) -> Result<ProfileSettings, Error> {
        match self.core.get(ProfilePart::Sdk, ITEM)? {
            Some((pt, _)) => ProfileSettings::parse(&pt),
            None => Ok(ProfileSettings::default()),
        }
    }

    /// Replaces the settings with `s` (its `rev` ignored: the stored one plus 1; `StoreConflict` when another write landed
    /// meanwhile); settings `parse` would refuse (above 1 MiB, a cap or a URL of no allowed form) are `Argument`, nothing
    /// written. On a protected profile a change that could weaken it (spec §7.7, [`weakens`]) needs `passphrase`, typed
    /// (`Argument` without it), checked against the `pass` wrap (`ProfileOpen`); a change that only strengthens needs none.
    /// An unprotected profile has no passphrase to check (its settings are plain; `set_passphrase` shows them before it seals
    /// them).
    pub fn set_settings(
        &self,
        s: &ProfileSettings,
        passphrase: Option<&[u8]>,
    ) -> Result<(), Error> {
        let (old, prev) = match self.core.get(ProfilePart::Sdk, ITEM)? {
            Some((pt, rev)) => (ProfileSettings::parse(&pt)?, Some(rev)),
            None => (ProfileSettings::default(), None),
        };
        let new = ProfileSettings {
            rev: prev.unwrap_or(0).checked_add(1).ok_or(Error::Argument)?,
            ..s.clone()
        };
        // never written in a form `parse` refuses (review E-4): the settings would be unreadable after
        let bytes = new.json()?;
        ProfileSettings::parse(&bytes).map_err(|_| Error::Argument)?;
        if self.core.protected() && weakens(&old, s) {
            let pass = passphrase.ok_or(Error::Argument)?;
            let id = self.info().id;
            let (env, _) = read_envelope(self.core.dir(), &id)?.ok_or(Error::ProfileFormat)?;
            self.check_pass(&env, pass)?;
        }
        self.core.put_if(ProfilePart::Sdk, ITEM, prev, &bytes)
    }
}
