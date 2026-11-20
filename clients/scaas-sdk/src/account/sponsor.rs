// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Sponsored registration (spec §7.1, R16; plan T13b). The receiver's app makes a blob of public data (`registration_blob`:
//! the registration's named arguments with the PoP, which binds no caller, CTR-UA-07, and the KEM key of version 0 when the
//! arguments commit to it); the sender's app checks it before anything is sent and prepares the registry writes its payer
//! pays for (`prepare_submit_registration`): the UA is the one the user means and the one its key data gives
//! (`RegistrationUaMismatch`), the kind is enabled on the chain (`RegistrationKindDisabled`), the PoP verifies locally by
//! `scaas-ua` (`RegistrationPopInvalid`), a committed KEM key is present and is the committed one (`RegistrationKemMissing`);
//! an already registered UA is skipped, its KEM key added when missing. The blob is the named-field JSON clientkeys'
//! `registrationBlob` writes (`smartcontracts/vectors/ua/registration_blobs.json`), read into the typed [`RegistrationBlob`]
//! (`RegistrationBlob::from_json`: at most [`BLOB_MAX`], depth 4, unknown fields refused; owner 2026-11-19, R1, R2). The
//! payment follows only after the registration's `Landed` (the app's order; `wallet` refuses a pay to an unregistered derived
//! UA, `ReceiverUnregistered`). UNAUDITED.
use super::register::{build_key, registry_of, writes, RegisterAttrs, RegistryWrite};
use super::Account;
use crate::op::{evm, hex, sim, unhex, KeyRef};
use crate::SdkError;
use alloy::network::TransactionBuilder;
use alloy::primitives::{Bytes, U256};
use alloy::rpc::types::TransactionRequest;
use scaas_ua::ua_portable::{check_registration, KemKey, UAAttrs, WebAuthnKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

/// The blob's bounds (spec §7.1; owner 2026-11-19, R1): the largest registration any parameter set allows, as JSON, with
/// headroom. An upper bound, part by part, as compact JSON hex (`0x` + 2 per byte): a `pqzPop` at the largest proof any set's
/// precompile takes (`MAX_PROOF_PQZH` 327,680 B: 655,362 characters; PQZL's is 98,304 B), a `pqzKey` of the largest set's
/// `PK` (`n2816-kmax65536`, 22,528 B: 45,058), the largest signing kind's key data and PoP of the vectors (`slhdsa128s`:
/// 15,780), and the rest of the vectors' largest blob (`mldsa65/n2816-kmax65536/kem-commit`, 130,241 characters, less those
/// four parts: 3,697, the KEM record's `kemPk` among it): 719,897. The cap, 768 KiB (786,432), leaves 66,535 (9 %).
pub const BLOB_MAX: usize = 768 * 1024;
const BLOB_DEPTH: usize = 4;

/// The KEM key of version 0 a hash-commit registration carries beside its arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KemRecord {
    pub version: u64,
    /// `0x` hex: `mlkemEk ‖ x25519` (`scaas-ua` `kem_pk`)
    pub kem_pk: String,
}

/// A `registerWebAuthn` key, named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WebAuthnArgs {
    pub x: String,
    pub y: String,
    pub rp_id_hash: String,
}

/// `KemKey`, named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KemArgs {
    pub scheme: u8,
    pub mlkem_ek: String,
    pub x25519: String,
}

/// `UAAttrs`, named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AttrsArgs {
    pub pqz_key: String,
    pub pqz_pop_hash: String,
    pub kem: KemArgs,
    pub kem_pk_hash: String,
}

/// A single-key registration's arguments by name, as `scaas-ua`'s `registration_args` gives them: `register` (`kind`,
/// `keyData`) or `registerWebAuthn` (`key`); bytes as `0x` hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RegisterArgs {
    pub entry: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<WebAuthnArgs>,
    pub attrs: AttrsArgs,
    pub pqz_pop: String,
    pub pop: String,
}

/// The sponsored registration's blob (spec §7.1; owner 2026-11-19, R2): public data only, every field named. Its text form is
/// clientkeys' `registrationBlob` (`smartcontracts/vectors/ua/registration_blobs.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationBlob {
    pub v: u32,
    pub ua: String,
    pub kind: u16,
    pub args: RegisterArgs,
    pub kem: Option<KemRecord>,
}

impl RegistrationBlob {
    /// The blob from its JSON text (passed out of band): `Argument` above [`BLOB_MAX`] bytes, deeper than 4, with an unknown
    /// or missing field at any level, or of a version other than 1.
    pub fn from_json(text: &str) -> Result<RegistrationBlob, SdkError> {
        if text.len() > BLOB_MAX
            || scaas_ua::json::depth_within(text.as_bytes(), BLOB_DEPTH).is_err()
        {
            return Err(SdkError::Argument);
        }
        let b: RegistrationBlob = serde_json::from_str(text).map_err(|_| SdkError::Argument)?;
        if b.v != 1 {
            return Err(SdkError::Argument);
        }
        Ok(b)
    }

    /// The JSON text (compact; clientkeys' form).
    pub fn to_json(&self) -> Result<String, SdkError> {
        serde_json::to_string(self).map_err(|_| SdkError::Internal)
    }
}

fn b32(s: &str) -> Result<[u8; 32], SdkError> {
    unhex(s)?.try_into().map_err(|_| SdkError::Argument)
}

/// The key data and kind the arguments register (single-key entries only: `register`, `registerWebAuthn`).
fn key_of(a: &RegisterArgs) -> Result<(u16, Vec<u8>), SdkError> {
    match (a.entry.as_str(), a.kind, &a.key_data, &a.key) {
        ("register", Some(kind), Some(kd), None) => Ok((kind, unhex(kd)?)),
        ("registerWebAuthn", None, None, Some(k)) => {
            let key = WebAuthnKey {
                x: b32(&k.x)?,
                y: b32(&k.y)?,
                rp_id_hash: b32(&k.rp_id_hash)?,
            };
            Ok((0x0100, key.key_data()))
        }
        _ => Err(SdkError::Argument),
    }
}

/// `UAAttrs` from the arguments' named `attrs`.
fn attrs_of(a: &AttrsArgs) -> Result<UAAttrs, SdkError> {
    Ok(UAAttrs {
        pqz_key: unhex(&a.pqz_key)?,
        pqz_pop_hash: b32(&a.pqz_pop_hash)?,
        kem: KemKey {
            scheme: a.kem.scheme,
            mlkem_ek: unhex(&a.kem.mlkem_ek)?,
            x25519: b32(&a.kem.x25519)?,
        },
        kem_pk_hash: b32(&a.kem_pk_hash)?,
    })
}

impl Account {
    /// The receiver's blob (spec §7.1): the registration of `key` (a seed's UA key) as `prepare_register` builds it, named,
    /// with no secret. `WalletLocked`; `Argument` and `FeatureMissing` as `prepare_register`.
    pub async fn registration_blob(
        &self,
        key: KeyRef,
        attrs: RegisterAttrs,
    ) -> Result<RegistrationBlob, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let (ua, r) = build_key(&sdk, &key, attrs).await?;
                let args: RegisterArgs =
                    serde_json::from_value(r.get("args").cloned().ok_or(SdkError::Internal)?)
                        .map_err(|_| SdkError::Internal)?;
                let kem = match r.get("kemFill").filter(|f| !f.is_null()) {
                    Some(_) => {
                        let crate::op::Key::Ua(_, k) = crate::op::key(&sdk, &key)? else {
                            return Err(SdkError::Argument);
                        };
                        Some(KemRecord {
                            version: 0,
                            kem_pk: hex(&k.kem_key(0)?.kem_pk()),
                        })
                    }
                    None => None,
                };
                Ok(RegistrationBlob {
                    v: 1,
                    ua: hex(&ua),
                    kind: args.kind.unwrap_or(0x0100),
                    args,
                    kem,
                })
            })
            .await
    }

    /// The sender's side (spec §7.1): every check of the module doc on `blob` before anything is sent, then the registry
    /// writes `payer` (a native `evm` key) pays for: the registration (split as `prepare_register`'s), then `setKemKey` when
    /// the KEM key is committed and not yet stored; none for a UA registered with its KEM key. Quote, submit and follow each
    /// as `prepare_register`'s; prepare the payment only after the last one's `Landed`. `Argument` (another version, an
    /// entry other than `register` / `registerWebAuthn`, a field that does not decode), `RegistrationUaMismatch`,
    /// `RegistrationKindDisabled`, `RegistrationPopInvalid`, `RegistrationKemMissing`, `GasAboveTxCap`.
    pub async fn prepare_submit_registration(
        &self,
        blob: RegistrationBlob,
        chain: String,
        expected_ua: String,
        payer: KeyRef,
    ) -> Result<Vec<Arc<RegistryWrite>>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let b = blob;
                if b.v != 1 {
                    return Err(SdkError::Argument);
                }
                // the receiver the user means, and the one the key data gives
                let ua = b32(&b.ua.to_ascii_lowercase())?;
                if !b.ua.eq_ignore_ascii_case(&expected_ua) {
                    return Err(SdkError::RegistrationUaMismatch);
                }
                let (kind, key_data) = key_of(&b.args)?;
                if kind != b.kind
                    || scaas_ua::derive_ua(kind, &key_data, false).map_err(|_| SdkError::RegistrationUaMismatch)? != ua
                {
                    return Err(SdkError::RegistrationUaMismatch);
                }
                // the kind enabled on the target chain
                let (_, _, pool) = evm(&sdk, &chain)?;
                let registry = registry_of(&sdk, &chain)?;
                let mut d = scaas_ua::keccak256(b"kindEnabled(uint16)")
                    .get(..4)
                    .unwrap_or_default()
                    .to_vec();
                d.extend_from_slice(&U256::from(kind).to_be_bytes::<32>());
                let tx = TransactionRequest::default()
                    .with_to(registry)
                    .with_input(Bytes::from(d));
                let out = pool.call_tx(tx).await.map_err(sim)?;
                if out.len() != 32 || U256::from_be_slice(&out) != U256::from(1) {
                    return Err(SdkError::RegistrationKindDisabled);
                }
                // the PoP, locally (and the arguments well formed: the calldata builds)
                let attrs = attrs_of(&b.args.attrs)?;
                let pop = unhex(&b.args.pop)?;
                let pqz_pop = unhex(&b.args.pqz_pop)?;
                let args = serde_json::to_value(&b.args).map_err(|_| SdkError::Internal)?;
                scaas_ua::wallet::entries::registry_call(&b.args.entry, &args)?;
                check_registration(kind, &key_data, &attrs, &pop, &pqz_pop, &|_| None)
                    .map_err(|_| SdkError::RegistrationPopInvalid)?;
                // a committed KEM key: present, the committed one; the fill after the registration
                let fill = match (attrs.kem_pk_hash == [0; 32], &b.kem) {
                    (true, None) => None,
                    (true, Some(_)) => return Err(SdkError::Argument),
                    (false, None) => return Err(SdkError::RegistrationKemMissing),
                    (false, Some(k)) => {
                        let kem_pk = unhex(&k.kem_pk).map_err(|_| SdkError::RegistrationKemMissing)?;
                        let kem = KemKey::from_kem_pk(&kem_pk).map_err(|_| SdkError::RegistrationKemMissing)?;
                        if k.version != 0
                            || scaas_ua::keccak256(&kem_pk) != attrs.kem_pk_hash
                            || kem.scheme != attrs.kem.scheme
                        {
                            return Err(SdkError::RegistrationKemMissing);
                        }
                        Some(json!({
                            "ua": hex(&ua), "version": 0,
                            "kem": {"scheme": kem.scheme, "mlkemEk": hex(&kem.mlkem_ek), "x25519": hex(&kem.x25519)},
                            "sig": {"keyData": "0x", "signature": "0x", "members": []},
                        }))
                    }
                };
                writes(&sdk, &chain, &payer, ua, &args, fill.as_ref()).await
            })
            .await
    }
}
