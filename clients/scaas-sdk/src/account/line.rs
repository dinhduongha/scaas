// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The registry line's targets and reads on a chain's bound registry (spec 2026-11-19-registry-verify-only-kinds §12,
//! CTR-UA-65; [`crate::line`]). UNAUDITED.
use super::Account;
use crate::line::UaLine;
use crate::SdkError;

/// A UA id: `0x` + 64 hex.
fn ua_id(s: &str) -> Result<[u8; 32], SdkError> {
    if !crate::config::is_word_hex(s) {
        return Err(SdkError::Argument);
    }
    let mut out = [0u8; 32];
    alloy::hex::decode_to_slice(&s[2..], &mut out).map_err(|_| SdkError::Argument)?;
    Ok(out)
}

impl Account {
    /// Where UA `ua` (`0x` + 64 hex) lives on chain `chain`'s line: one `holderOf(ua)` on the profile's registry (§11.1); the
    /// record is read at [`UaLine::holder`], a key write goes there ([`UaLine::key_target`]), the PQZ attachment is read and
    /// written at its home ([`UaLine::pqz_target`]). `UaUnregistered` where no generation holds it; `Argument` without a
    /// registry or for a malformed id.
    pub async fn ua_line(&self, chain: String, ua: String) -> Result<UaLine, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let ua = ua_id(&ua)?;
                let (registry, pool) = crate::line::bound(&sdk, &chain)?;
                crate::line::ua_line(&pool, registry, ua).await
            })
            .await
    }

    /// The registry a registration of `kind` on chain `chain` goes to (§12): `kindHome(kind)` of the profile's registry,
    /// which must be that registry; `RegistrationVerifyOnly` where it carries the kind verify-only (the home is another
    /// generation), `RegistrationKindDisabled` where no generation registers it.
    pub async fn register_target(&self, chain: String, kind: u16) -> Result<String, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let (registry, pool) = crate::line::bound(&sdk, &chain)?;
                let to = crate::line::register_target(&pool, registry, kind).await?;
                Ok(format!("{to:#x}"))
            })
            .await
    }

    /// The PQZ decoy candidates of chain `chain`'s token registry (the profile's; owner P19): the `0x0142` lists of every
    /// enabling generation on its walk, concatenated, distinct by key hash ([`crate::line`]). The draw itself is `scaas-ua`'s
    /// `pickDecoys` over these.
    pub async fn pqz_decoy_candidates(&self, chain: String) -> Result<Vec<String>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let (registry, pool) = crate::line::bound(&sdk, &chain)?;
                let c = crate::line::decoy_candidates(&pool, registry).await?;
                Ok(c.iter().map(|u| super::hex(u)).collect())
            })
            .await
    }
}
