// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The profile's anchor (spec §7.2, plan pinned format 8, CLI-UPR-28): `{"gen":N,"envelope":{"rev":R,"sha256":"…"},"parts":
//! {"<part>":{"rev":M,"sha256":"…"},…}}`, parts sorted by name, `sha256` the first 16 bytes of SHA-256 of the file (the
//! envelope; each part's manifest item), lower-case hex. Written to `profile.head` and, with a keychain, to
//! `scaas.profile.<id>.head`; both compared by [`Anchor::compare`]. The hash is `scaas-ua`'s (no hashing here).
use std::collections::BTreeMap;

/// The anchor's largest form (a keychain item, spec §11).
pub(crate) const MAX: usize = 2560;

/// A file's revision and the first 16 bytes of SHA-256 of its bytes, hex.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub rev: u64,
    pub sha256: String,
}

impl Head {
    pub fn of(rev: u64, file: &[u8]) -> Head {
        let h = scaas_ua::sha256(file);
        Head {
            rev,
            sha256: h.iter().take(16).map(|b| format!("{b:02x}")).collect(),
        }
    }
}

/// The anchor, or what is stored on disk in its form (a part absent: its manifest missing).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    pub gen: u64,
    pub envelope: Head,
    pub parts: BTreeMap<String, Head>,
}

/// CLI-UPR-28's verdict, ordered: the worst component decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Same,
    /// a value ahead of the anchor: a crash before the anchor's write, or another client's write; the anchor follows
    Follow,
    /// a value below the anchor, another hash at its rev, or a part it names whose manifest is missing
    Rollback,
}

impl Anchor {
    /// The canonical bytes (pinned format 2: no whitespace, the fields in order).
    pub fn json(&self) -> Result<Vec<u8>, crate::Error> {
        serde_json::to_vec(self).map_err(|_| crate::Error::Argument)
    }

    /// An anchor read back (at most 2,560 bytes, depth 3); `None` for anything else.
    pub fn parse(bytes: &[u8]) -> Option<Anchor> {
        if bytes.len() > MAX || scaas_ua::json::depth_within(bytes, 3).is_err() {
            return None;
        }
        serde_json::from_slice(bytes).ok()
    }

    /// What is stored (`self`) against `anchor`, per component (gen, envelope, each part the anchor names; a part on disk the
    /// anchor does not name follows).
    pub fn compare(&self, anchor: &Anchor) -> Verdict {
        fn one(stored: Option<&Head>, a: &Head) -> Verdict {
            match stored {
                Some(s) if s.rev > a.rev => Verdict::Follow,
                Some(s) if s.rev == a.rev && s.sha256 == a.sha256 => Verdict::Same,
                _ => Verdict::Rollback,
            }
        }
        let gen = match self.gen.cmp(&anchor.gen) {
            std::cmp::Ordering::Greater => Verdict::Follow,
            std::cmp::Ordering::Equal => Verdict::Same,
            std::cmp::Ordering::Less => Verdict::Rollback,
        };
        let named = anchor.parts.iter().map(|(p, a)| one(self.parts.get(p), a));
        let new = self
            .parts
            .keys()
            .filter(|p| !anchor.parts.contains_key(*p))
            .map(|_| Verdict::Follow);
        [gen, one(Some(&self.envelope), &anchor.envelope)]
            .into_iter()
            .chain(named)
            .chain(new)
            .max()
            .unwrap_or(Verdict::Same)
    }
}
