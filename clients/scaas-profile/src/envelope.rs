// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The envelope `profile.envelope` (spec §7.1, §7.5; plan pinned formats 2 to 5): canonical JSON, its fields in the spec's
//! order (`format`, `v`, `id`, `state`, `rev`, `gen`, `migration`, `name`, `kdf`, `pass`, `platform`, `label`), absent ones
//! left out; parsed bounded (4 KiB, depth 2), unknown fields and any non-canonical form refused; the refusals by state; the
//! KDF's general bounds (`ProfileFormat`) and this device's maximum (`ProfileKdfTooLarge`), both before any KDF; the wraps'
//! public JSON (`format`, `v`, `id`, `state`, `gen`, `kdf`). Rows: smartcontracts/vectors/profile/envelope.json.
use crate::names::check_name;
use crate::Error;
use base64::Engine;
use scaas_ua::wallet::{Argon2Params, ProfileKeys};
use serde::{Deserialize, Serialize};

pub(crate) const FILE: &str = "profile.envelope";
const FORMAT: &str = "scaas.profile";
/// The envelope's largest form (a name hint, a platform wrap and a label fit well below it).
pub(crate) const MAX: usize = 4096;
pub(crate) const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Argon2id parameters a caller chooses (spec §7.5): memory in KiB and passes; lanes are fixed at 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
}

impl KdfParams {
    /// 64 MiB, 3 passes (owner Q-UP2).
    pub const DEFAULT: KdfParams = KdfParams {
        m_kib: 65_536,
        t: 3,
    };
    /// The general bound of `m` and the desktop's maximum: 1 GiB.
    pub const MAX_KIB: u32 = 1_048_576;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Unprotected,
    Protected,
}

/// The envelope's `kdf`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kdf {
    pub alg: String,
    pub v: u64,
    pub m: u64,
    pub t: u64,
    pub p: u64,
    pub salt: String,
}

impl Kdf {
    /// The parameters and salt after the general bounds (`ProfileFormat`) and this device's maximum `max_kib`
    /// (`ProfileKdfTooLarge`), in that order; no KDF runs here.
    pub fn check(&self, max_kib: u32) -> Result<(Argon2Params, Vec<u8>), Error> {
        let n = |x: u64| u32::try_from(x).map_err(|_| Error::ProfileFormat);
        let a = Argon2Params {
            m_kib: n(self.m)?,
            t: n(self.t)?,
            p: n(self.p)?,
        };
        let salt = B64.decode(&self.salt).map_err(|_| Error::ProfileFormat)?;
        if self.alg != "argon2id" || self.v != 1 {
            return Err(Error::ProfileFormat);
        }
        ProfileKeys::kdf_check(a, &salt).map_err(|_| Error::ProfileFormat)?;
        if a.m_kib > max_kib {
            return Err(Error::ProfileKdfTooLarge);
        }
        Ok((a, salt))
    }
}

/// The envelope's `platform`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Platform {
    pub salt: String,
    pub wrap: String,
}

/// `profile.envelope`. No `Debug`: it holds the id and the name.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub format: String,
    pub v: u64,
    pub id: String,
    pub state: State,
    pub rev: u64,
    pub gen: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<Kdf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Serialize)]
struct Public<'a> {
    format: &'a str,
    v: u64,
    id: &'a str,
    state: State,
    gen: u64,
    kdf: &'a Kdf,
}

/// The sealed label's plaintext (pinned format 5).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Label {
    pub name: String,
    pub hidden: bool,
}

impl Envelope {
    /// A new unprotected, visible profile's envelope at rev 1.
    pub fn unprotected(id: &str, name: &str) -> Envelope {
        Envelope {
            format: FORMAT.into(),
            v: 1,
            id: id.into(),
            state: State::Unprotected,
            rev: 1,
            gen: 0,
            migration: None,
            name: Some(name.into()),
            kdf: None,
            pass: None,
            platform: None,
            label: None,
        }
    }

    /// The canonical bytes.
    pub fn json(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(self).map_err(|_| Error::Argument)
    }

    /// The envelope of directory `id`: bounded, canonical, `format` `scaas.profile` (else `ProfileFormat`), `v` 1 (else
    /// `ProfileVersion`), its `id` the directory's, a valid name hint, and the fields its state allows (spec §7.1): an
    /// unprotected one has `gen` 0, a name and no key field; a protected one `gen` above 0, `kdf` within the general bounds,
    /// `pass` and `label`. Else `ProfileFormat`.
    pub fn parse(bytes: &[u8], id: &str) -> Result<Envelope, Error> {
        if bytes.len() > MAX || scaas_ua::json::depth_within(bytes, 2).is_err() {
            return Err(Error::ProfileFormat);
        }
        let e: Envelope = serde_json::from_slice(bytes).map_err(|_| Error::ProfileFormat)?;
        if e.format != FORMAT {
            return Err(Error::ProfileFormat);
        }
        if e.v != 1 {
            return Err(Error::ProfileVersion);
        }
        if e.json()? != bytes || e.id != id {
            return Err(Error::ProfileFormat);
        }
        let name_ok = e
            .name
            .as_ref()
            .is_none_or(|n| check_name(n).is_ok_and(|c| &c == n));
        let migration_ok = e.migration.as_ref().is_none_or(|m| m == "pending");
        let state_ok = match e.state {
            State::Unprotected => {
                e.gen == 0
                    && e.name.is_some()
                    && e.kdf.is_none()
                    && e.pass.is_none()
                    && e.platform.is_none()
                    && e.label.is_none()
            }
            State::Protected => {
                e.gen > 0
                    && e.pass.is_some()
                    && e.label.is_some()
                    && e.kdf.as_ref().is_some_and(|k| k.check(u32::MAX).is_ok())
            }
        };
        if !(name_ok && migration_ok && state_ok) {
            return Err(Error::ProfileFormat);
        }
        Ok(e)
    }

    /// The wraps' public JSON (pinned format 4); `ProfileFormat` without a `kdf`.
    pub fn public_json(&self) -> Result<Vec<u8>, Error> {
        let kdf = self.kdf.as_ref().ok_or(Error::ProfileFormat)?;
        serde_json::to_vec(&Public {
            format: &self.format,
            v: self.v,
            id: &self.id,
            state: self.state,
            gen: self.gen,
            kdf,
        })
        .map_err(|_| Error::Argument)
    }
}
