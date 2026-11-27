// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The index `profiles.json` (spec §6): a cache of the visible profiles' ids and names, never the truth;
//! `{"format":"scaas.profiles","v":1,"rev":N,"last":<id or null>,"profiles":[{"id":…,"name":…},…]}`, bounded (64 KiB, depth 4,
//! 32 rows) before parsing, canonical, unknown fields refused; anything else does not parse (and is rebuilt from the
//! envelopes). The journal `p/.journal` of a create (spec §10) is here too.
use crate::names::{check_name, is_id};
use crate::Error;
use serde::{Deserialize, Serialize};

pub(crate) const FILE: &str = "profiles.json";
pub(crate) const MAX: usize = 64 << 10;
pub(crate) const ROWS: usize = 32;
const FORMAT: &str = "scaas.profiles";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Row {
    pub id: String,
    pub name: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Index {
    format: String,
    v: u64,
    pub rev: u64,
    pub last: Option<String>,
    pub profiles: Vec<Row>,
}

impl Index {
    pub fn new(profiles: Vec<Row>) -> Index {
        Index {
            format: FORMAT.into(),
            v: 1,
            rev: 0,
            last: None,
            profiles,
        }
    }

    pub fn json(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(self).map_err(|_| Error::Argument)
    }

    /// The index, or `None` for anything that is not one: above its bounds, not canonical, an unknown field, a row's id not
    /// a UUID or twice, a name not as stored.
    pub fn parse(bytes: &[u8]) -> Option<Index> {
        if bytes.len() > MAX || scaas_ua::json::depth_within(bytes, 4).is_err() {
            return None;
        }
        let ix: Index = serde_json::from_slice(bytes).ok()?;
        let mut ids: Vec<&str> = ix.profiles.iter().map(|r| r.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        let ok = ix.format == FORMAT
            && ix.v == 1
            && ix.profiles.len() <= ROWS
            && ids.len() == ix.profiles.len()
            && ix.last.as_deref().is_none_or(is_id)
            && ix
                .profiles
                .iter()
                .all(|r| is_id(&r.id) && check_name(&r.name).is_ok_and(|n| n == r.name))
            && ix.json().ok()? == bytes;
        ok.then_some(ix)
    }
}

pub(crate) const JOURNAL: &str = ".journal";

/// `p/.journal` (spec §10): `{"op":"create","id":…}`, present only during a create's commit.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Journal {
    pub op: String,
    pub id: String,
}
