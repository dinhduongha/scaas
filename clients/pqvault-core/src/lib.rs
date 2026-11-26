// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `pqvault-core`: PqVault's app core above `scaas-sdk` (CLI-PQV-01; spec docs/superpowers/specs/2026-11-17-pqvault.md §7).
//! It builds, encrypts, verifies, opens and merges vault records; every signature, verification, KEM, HKDF, Argon2id, AEAD
//! and random key runs in `scaas-ua` through the SDK's app-core surface on key handles (C1, CLI-PQV-12), every record is
//! signed by the SDK's PqVault calls `prepare_pqvault_record` and `AppPrepared::sign` (C2, CLI-PQV-13), every chain read is the SDK's `read_app` as a
//! read that feeds a decryption (ARCH-POS-15), and every write is a call of the contract the SDK prepares and quotes for the
//! user to review (`AppCore::prepare_app_call`, sent by `Wallet::submit_native_send`). It opens no connection and holds no
//! key byte. **UNAUDITED: test data only (CLI-PQV-08).**
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

pub mod content;
pub mod keys;
pub mod records;
pub mod vault;

pub use content::Merge;
pub use records::{Addr, Signed, B32};
pub use vault::*;

use records::UaSig;
use scaas_sdk::app_core::{
    AppCall, AppCore, AppDesc, AppKey, AppPath, AppSigned, AppWrap, MsigVersion,
};
use scaas_sdk::op::KeyRef;
use scaas_sdk::{Sdk, SdkError};
use serde_json::Value;
use std::sync::Arc;

/// PqVault's id in the registry's open app namespace: `keccak256("scaas.pqvault.v1")` (CTR-UA-46).
pub const APP_ID_STRING: &str = "scaas.pqvault.v1";
pub const DOMAIN_NAME: &str = "SCaaS PqVault";
/// The wallet index of the per-vault UAs (spec §6.1, V8; pinned by `records.json` `pqvAccount`).
pub const PQV_ACCOUNT: u32 = 0x7071_7600;
/// FN-DSA-512, the per-vault UA's kind by default.
pub const FNDSA512: u16 = 0x0132;
/// The factory class of PqVault's contracts (CTR-PQV-13).
pub const CLASS: u16 = 4;

pub fn app_id() -> [u8; 32] {
    alloy::primitives::keccak256(APP_ID_STRING).0
}

/// `pqvault-core`'s errors (spec §7). None carries a key, a plaintext or a passphrase; `PassphraseWrong`, `EpochUnopenable`
/// and `Unreadable` are local values, never sent (ARCH-POS-13).
#[derive(Debug)]
pub enum Error {
    /// CLI-PQV-06 (P1): the account is not a UA of a verified, full-class, 24-word seed set; before any other work.
    SeedNotPqRooted,
    /// The user's own vault UA is not of a PQ kind (spec §6.1).
    UaKindNotPq,
    PassphraseWrong,
    /// The epoch has a passphrase and none was given.
    PassphraseRequired,
    /// A user-chosen passphrase under 16 characters (VC19).
    PassphraseTooShort,
    /// A shared vault's passphrase equal to an unlocked personal vault's (spec §6.5).
    PassphraseReused,
    /// Empty or a control character after RFC 8265's OpaqueString (CLI-PQV-07).
    PassphraseInvalid,
    PassKdfUnknown,
    /// "epoch N by <author> cannot be opened" (spec §6.5): older items stay readable.
    EpochUnopenable {
        epoch: u64,
        author: B32,
    },
    /// The signature chain of spec §6.9 does not verify, or the state read is not the vault's (another instance in mode 1, a
    /// `vaultRef` of another mode, an epoch whose `shared` differs from its parent's).
    ChainUnverified,
    /// A vault the user did not create and has not accepted (VC18).
    Pending,
    /// A version or a wrap that does not open (one class for every open failure, ARCH-POS-13).
    Unreadable,
    /// A node answered fewer versions or epochs than seen before (spec §7 "Recovery").
    Rollback,
    /// What a writer may not write (an item's bounds, a size, a list).
    Shape,
    NotAdmin,
    NotMember,
    /// The version the edit started from is not the latest any more: the merge against the latest.
    Conflict(Merge),
    Sdk(SdkError),
}

impl From<SdkError> for Error {
    fn from(e: SdkError) -> Error {
        Error::Sdk(e)
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The SDK calls that reach a chain or a signer (the seam a test replaces with one that records or lies): reads that feed a
/// decryption, PqVault's signing and verifying calls, the KEM wrap to a key read from the registry, and the prepared call.
#[async_trait::async_trait]
pub trait Net: Send + Sync {
    /// `sig` a human-readable view (`function f(bytes32 x) view returns (...)`, every parameter named), `args` its named
    /// arguments; the answer's named JSON (`AppCore::read_app`, `trusted`: `Purpose::FeedsDecryption`).
    async fn read(
        &self,
        chain: &str,
        contract: Addr,
        sig: &str,
        args: Value,
    ) -> Result<Value, SdkError>;
    /// `AppCore::prepare_pqvault_record`, then `AppPrepared::sign` (pqvault-core builds the typed data from its own named fields);
    /// `chain` the instance's profile (where an `msig` signer's records are read on the
    /// portable path: the SDK's explicit `records`).
    async fn sign(
        &self,
        chain: &str,
        account: &KeyRef,
        path: AppPath,
        typed: String,
    ) -> Result<AppSigned, SdkError>;
    /// `AppCore::verify_pqvault_record_versions`: on a pass every `(msig, version)` the signature names (CTR-UA-74 step 6), `None`
    /// on a refusal.
    async fn verify(
        &self,
        chain: &str,
        ua: B32,
        path: AppPath,
        typed: String,
        sig: UaSig,
    ) -> Result<Option<Vec<MsigVersion>>, SdkError>;
    /// `AppCore::kem_wrap`: `key` wrapped to `recipient`'s KEM key at `version`, read from `chain`'s registry.
    async fn kem_wrap(
        &self,
        chain: &str,
        recipient: B32,
        version: u64,
        key: Arc<AppKey>,
        label: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<AppWrap, SdkError>;
    /// `AppCore::prepare_app_call`: the entry `sig` with `args`, paid by `payer`, quoted and reviewed.
    async fn call(
        &self,
        chain: &str,
        contract: Addr,
        sig: &str,
        args: Value,
        payer: KeyRef,
    ) -> Result<AppCall, SdkError>;
}

/// The JSON ABI item of a human-readable function, every parameter and tuple component named: `function name(<params>)
/// [view] [returns (<params>)]`, a param `<type> <name>` with a tuple type `(<params>)` and `[]` / `[N]` suffixes (alloy's
/// parser takes no tuple component names, the SDK's entries need them).
pub fn entry(sig: &str) -> Result<String, SdkError> {
    fn params(s: &str) -> Option<Vec<Value>> {
        let s = s.trim();
        if s.is_empty() {
            return Some(vec![]);
        }
        let mut out = vec![];
        let (mut depth, mut start) = (0i32, 0usize);
        for (i, c) in s.char_indices().chain(std::iter::once((s.len(), ','))) {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                ',' if depth == 0 => {
                    out.push(param(s.get(start..i)?)?);
                    start = i + 1;
                }
                _ => {}
            }
            if depth < 0 {
                return None;
            }
        }
        (depth == 0).then_some(out)
    }
    fn param(p: &str) -> Option<Value> {
        let p = p.trim();
        let (ty, name) = p.rsplit_once(' ')?;
        let (ty, name) = (ty.trim(), name.trim());
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return None;
        }
        if let Some(rest) = ty.strip_prefix('(') {
            let close = rest.rfind(')')?;
            let suffix = rest.get(close + 1..)?;
            let comps = params(rest.get(..close)?)?;
            return Some(
                serde_json::json!({"name": name, "type": format!("tuple{suffix}"), "components": comps}),
            );
        }
        (!ty.contains(['(', ')', ' '])).then(|| serde_json::json!({"name": name, "type": ty}))
    }
    let bad = || SdkError::Argument;
    let rest = sig.trim().strip_prefix("function ").ok_or_else(bad)?;
    let open = rest.find('(').ok_or_else(bad)?;
    let name = rest.get(..open).ok_or_else(bad)?.trim();
    // the inputs' closing parenthesis: the one that brings the depth back to 0
    let mut depth = 0;
    let mut close = None;
    for (i, c) in rest.char_indices().skip(open) {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let close = close.ok_or_else(bad)?;
    let inputs = params(rest.get(open + 1..close).ok_or_else(bad)?).ok_or_else(bad)?;
    let tail = rest.get(close + 1..).ok_or_else(bad)?.trim();
    let (view, tail) = match tail.strip_prefix("view") {
        Some(t) => (true, t.trim()),
        None => (false, tail),
    };
    let outputs = match tail.strip_prefix("returns") {
        Some(t) => {
            let t = t.trim();
            let inner = t
                .strip_prefix('(')
                .and_then(|x| x.strip_suffix(')'))
                .ok_or_else(bad)?;
            params(inner).ok_or_else(bad)?
        }
        None if tail.is_empty() => vec![],
        None => return Err(bad()),
    };
    let f = serde_json::json!({
        "type": "function",
        "name": name,
        "inputs": inputs,
        "outputs": outputs,
        "stateMutability": if view { "view" } else { "nonpayable" },
    });
    // the SDK parses the item with alloy's JSON ABI; parse it here too, so a bad item fails at its source
    let parsed: alloy::json_abi::Function = serde_json::from_value(f.clone()).map_err(|_| bad())?;
    let _ = parsed;
    Ok(f.to_string())
}

/// [`Net`] over the SDK's app-core scope.
pub struct SdkNet(pub Arc<AppCore>);

#[async_trait::async_trait]
impl Net for SdkNet {
    async fn read(
        &self,
        chain: &str,
        contract: Addr,
        sig: &str,
        args: Value,
    ) -> Result<Value, SdkError> {
        let out = self
            .0
            .read_app(
                chain.into(),
                records::hex(&contract.0),
                entry(sig)?,
                args.to_string(),
            )
            .await?;
        serde_json::from_str(&out).map_err(|_| SdkError::Argument)
    }
    async fn sign(
        &self,
        chain: &str,
        account: &KeyRef,
        path: AppPath,
        typed: String,
    ) -> Result<AppSigned, SdkError> {
        let records = (matches!(account, KeyRef::Msig { .. }) && matches!(path, AppPath::Portable))
            .then(|| chain.to_string());
        self.0
            .prepare_pqvault_record(account.clone(), path, records, typed)
            .await?
            .sign()
            .await
    }
    async fn verify(
        &self,
        chain: &str,
        ua: B32,
        path: AppPath,
        typed: String,
        sig: UaSig,
    ) -> Result<Option<Vec<MsigVersion>>, SdkError> {
        self.0
            .verify_pqvault_record_versions(chain.into(), records::hex(&ua.0), path, typed, sig)
            .await
    }
    async fn kem_wrap(
        &self,
        chain: &str,
        recipient: B32,
        version: u64,
        key: Arc<AppKey>,
        label: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<AppWrap, SdkError> {
        self.0
            .kem_wrap(
                chain.into(),
                records::hex(&recipient.0),
                version,
                key,
                label,
                aad,
            )
            .await
    }
    async fn call(
        &self,
        chain: &str,
        contract: Addr,
        sig: &str,
        args: Value,
        payer: KeyRef,
    ) -> Result<AppCall, SdkError> {
        self.0
            .prepare_app_call(
                chain.into(),
                records::hex(&contract.0),
                entry(sig)?,
                args.to_string(),
                payer,
            )
            .await
    }
}

/// PqVault's scope over one SDK: the app core (its `app_id`, class 4, the label prefix `scaas/pqvault/v1/`) and the seam.
pub struct PqVault {
    pub sdk: Arc<Sdk>,
    pub core: Arc<AppCore>,
    pub net: Arc<dyn Net>,
    seen: std::sync::Mutex<vault::Seen>,
}

impl PqVault {
    /// The scope over `sdk`, reaching chains through the SDK itself.
    pub fn new(sdk: Arc<Sdk>) -> Result<PqVault> {
        let core = Self::scope(&sdk)?;
        let net = Arc::new(SdkNet(core.clone()));
        Ok(Self::with_net(sdk, core, net))
    }

    /// PqVault's app-core scope (one per process: a second live one is `AppLabelRefused`).
    pub fn scope(sdk: &Arc<Sdk>) -> Result<Arc<AppCore>> {
        Ok(AppCore::new(
            sdk.clone(),
            AppDesc {
                app_id: Some(records::hex(&app_id())),
                name: DOMAIN_NAME.into(),
                class: Some(CLASS),
                labels: vec![keys::PREFIX.into()],
            },
        )?)
    }

    /// The scope over `sdk` with another seam (a test's).
    pub fn with_net(sdk: Arc<Sdk>, core: Arc<AppCore>, net: Arc<dyn Net>) -> PqVault {
        PqVault {
            sdk,
            core,
            net,
            seen: std::sync::Mutex::new(vault::Seen::default()),
        }
    }

    /// P1 (CLI-PQV-06): `account` a UA key of a PQ kind whose seed set the SDK's authenticated index lists as verified,
    /// `full` class, 24 words and without the `below-24-words` warning; else `SeedNotPqRooted` (`UaKindNotPq` for a classical
    /// kind), before any other work, any network call or any signature.
    pub async fn p1(&self, account: &KeyRef) -> Result<String> {
        let KeyRef::Ua { seed, kind, .. } = account else {
            return Err(Error::SeedNotPqRooted);
        };
        let seeds = self
            .sdk
            .vault()
            .seeds()
            .await
            .map_err(|_| Error::SeedNotPqRooted)?;
        let ok = seeds.iter().any(|s| {
            s.id == *seed
                && s.verified
                && s.class == "full"
                && s.words == 24
                && !s.warnings.iter().any(|w| w == "below-24-words")
        });
        if !ok {
            return Err(Error::SeedNotPqRooted);
        }
        if !is_pq_kind(*kind) {
            return Err(Error::UaKindNotPq);
        }
        Ok(seed.clone())
    }

    /// The UA of `account` (derived, no read).
    pub fn ua(&self, account: &KeyRef) -> Result<B32> {
        Ok(B32(self.core.account_ua(account)?))
    }

    /// The per-vault UA key of `seed` at `index` (spec §6.1, V8): FN-DSA-512 at wallet `PQV_ACCOUNT`; index 0 the index vault.
    pub fn vault_key(seed: &str, index: u32) -> KeyRef {
        KeyRef::Ua {
            seed: seed.into(),
            kind: FNDSA512,
            account: PQV_ACCOUNT,
            index,
        }
    }
}

/// ML-DSA-44/65/87, FN-DSA-512/1024, SLH-DSA (`UAKinds` 0x0130–0x0135).
pub fn is_pq_kind(kind: u16) -> bool {
    (0x0130..=0x0135).contains(&kind)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    #[test]
    fn entries_parse() {
        let e = super::entry(
            "function f((bytes32 a,(uint16 index,bytes sig)[] members)[] xs, uint8 m) view returns ((address factory,bool ok) info)",
        )
        .unwrap_or_default();
        let f: alloy::json_abi::Function =
            serde_json::from_str(&e).unwrap_or_else(|_| unreachable!());
        assert_eq!(f.signature(), "f((bytes32,(uint16,bytes)[])[],uint8)");
        assert_eq!(f.inputs[0].components[1].components[1].name, "sig");
        assert_eq!(f.outputs[0].components[0].name, "factory");
        assert!(matches!(
            f.state_mutability,
            alloy::json_abi::StateMutability::View
        ));
        assert!(
            super::entry("function f(uint8) view").is_err(),
            "a parameter without a name"
        );
        assert!(super::entry("function f((uint8 a x) view").is_err());
    }
}
