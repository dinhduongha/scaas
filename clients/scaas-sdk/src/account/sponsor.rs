// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Sponsored registration (spec §7.1, R16; plan T13b). The receiver's app makes a blob of public data (`registration_blob`:
//! the registration's named arguments with the PoP, which binds no caller, CTR-UA-07, and the KEM key of version 0 when the
//! arguments commit to it); the sender's app checks it before anything is sent and prepares the registry writes its payer
//! pays for (`prepare_submit_registration`): the UA is the one the user means and the one its key data gives
//! (`RegistrationUaMismatch`), the kind is enabled on the chain (`RegistrationKindDisabled`), the PoP verifies locally by
//! `scaas-ua` (`RegistrationPopInvalid`), a committed KEM key is present and is the committed one (`RegistrationKemMissing`);
//! an already registered UA is skipped, its KEM key added when missing. The blob is the named-field JSON clientkeys'
//! `registrationBlob` writes (`smartcontracts/vectors/ua/registration_blobs.json`): at most 64 KiB, depth 4, unknown fields
//! refused. The payment follows only after the registration's `Landed` (the app's order; `wallet` refuses a pay to an
//! unregistered derived UA, `ReceiverUnregistered`). UNAUDITED.
use super::register::{build, registry_of, writes, RegisterAttrs, RegistryWrite};
use super::Account;
use crate::op::{evm, hex, sim, unhex, KeyRef};
use crate::SdkError;
use alloy::network::TransactionBuilder;
use alloy::primitives::{Bytes, U256};
use alloy::rpc::types::TransactionRequest;
use scaas_ua::ua_portable::{check_registration, KemKey, UAAttrs, WebAuthnKey};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

/// The blob's bounds (spec §7.1).
const BLOB_MAX: usize = 64 * 1024;
const BLOB_DEPTH: usize = 4;

/// The KEM key of version 0 a hash-commit registration carries beside its arguments.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct KemRecord {
    version: u64,
    kem_pk: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Blob {
    v: u32,
    ua: String,
    kind: u16,
    args: Value,
    kem: Option<KemRecord>,
}

fn b32(v: &Value) -> Result<[u8; 32], SdkError> {
    unhex(v.as_str().ok_or(SdkError::Argument)?)?
        .try_into()
        .map_err(|_| SdkError::Argument)
}

fn bytes(v: &Value) -> Result<Vec<u8>, SdkError> {
    unhex(v.as_str().ok_or(SdkError::Argument)?)
}

/// The key data and kind the arguments register (single-key entries only: `register`, `registerWebAuthn`).
fn key_of(args: &Value) -> Result<(u16, Vec<u8>), SdkError> {
    match args.get("entry").and_then(Value::as_str) {
        Some("register") => Ok((
            args.get("kind")
                .and_then(Value::as_u64)
                .and_then(|k| u16::try_from(k).ok())
                .ok_or(SdkError::Argument)?,
            bytes(args.get("keyData").ok_or(SdkError::Argument)?)?,
        )),
        Some("registerWebAuthn") => {
            let k = args.get("key").ok_or(SdkError::Argument)?;
            let at = |n: &str| b32(k.get(n).ok_or(SdkError::Argument)?);
            let key = WebAuthnKey {
                x: at("x")?,
                y: at("y")?,
                rp_id_hash: at("rpIdHash")?,
            };
            Ok((0x0100, key.key_data()))
        }
        _ => Err(SdkError::Argument),
    }
}

/// `UAAttrs` from the arguments' named `attrs`.
fn attrs_of(args: &Value) -> Result<UAAttrs, SdkError> {
    let a = args.get("attrs").ok_or(SdkError::Argument)?;
    let k = a.get("kem").ok_or(SdkError::Argument)?;
    fn at<'a>(v: &'a Value, n: &str) -> Result<&'a Value, SdkError> {
        v.get(n).ok_or(SdkError::Argument)
    }
    Ok(UAAttrs {
        pqz_key: bytes(at(a, "pqzKey")?)?,
        pqz_pop_hash: b32(at(a, "pqzPopHash")?)?,
        kem: KemKey {
            scheme: at(k, "scheme")?
                .as_u64()
                .and_then(|s| u8::try_from(s).ok())
                .ok_or(SdkError::Argument)?,
            mlkem_ek: bytes(at(k, "mlkemEk")?)?,
            x25519: b32(at(k, "x25519")?)?,
        },
        kem_pk_hash: b32(at(a, "kemPkHash")?)?,
    })
}

impl Account {
    /// The receiver's blob (spec §7.1): the registration of `key` (a seed's UA key) as `prepare_register` builds it, as
    /// named-field JSON with no secret: `{v: 1, ua, kind, args, kem}`. `WalletLocked`; `Argument` and `FeatureMissing` as
    /// `prepare_register`.
    pub async fn registration_blob(&self, key: KeyRef, attrs: RegisterAttrs) -> Result<String, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let (ua, r) = build(&sdk, &key, attrs)?;
                let args = r.get("args").ok_or(SdkError::Internal)?;
                let kind = args
                    .get("kind")
                    .and_then(Value::as_u64)
                    .unwrap_or(0x0100);
                let kem = match r.get("kemFill").filter(|f| !f.is_null()) {
                    Some(_) => {
                        let crate::op::Key::Ua(_, k) = crate::op::key(&sdk, &key)? else {
                            return Err(SdkError::Argument);
                        };
                        json!({"version": 0, "kemPk": hex(&k.kem_key(0)?.kem_pk())})
                    }
                    None => Value::Null,
                };
                Ok(json!({"v": 1, "ua": hex(&ua), "kind": kind, "args": args, "kem": kem}).to_string())
            })
            .await
    }

    /// The sender's side (spec §7.1): every check of the module doc on `blob` before anything is sent, then the registry
    /// writes `payer` (a native `evm` key) pays for: the registration (split as `prepare_register`'s), then `setKemKey` when
    /// the KEM key is committed and not yet stored; none for a UA registered with its KEM key. Quote, submit and follow each
    /// as `prepare_register`'s; prepare the payment only after the last one's `Landed`. `Argument` (a blob above 64 KiB, deeper
    /// than 4, with an unknown field, of another version, an entry other than `register` / `registerWebAuthn`),
    /// `RegistrationUaMismatch`, `RegistrationKindDisabled`, `RegistrationPopInvalid`, `RegistrationKemMissing`,
    /// `GasAboveTxCap`.
    pub async fn prepare_submit_registration(
        &self,
        blob: String,
        chain: String,
        expected_ua: String,
        payer: KeyRef,
    ) -> Result<Vec<Arc<RegistryWrite>>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                if blob.len() > BLOB_MAX
                    || scaas_ua::json::depth_within(blob.as_bytes(), BLOB_DEPTH).is_err()
                {
                    return Err(SdkError::Argument);
                }
                let b: Blob = serde_json::from_str(&blob).map_err(|_| SdkError::Argument)?;
                if b.v != 1 {
                    return Err(SdkError::Argument);
                }
                // the receiver the user means, and the one the key data gives
                let ua: [u8; 32] = unhex(&b.ua.to_ascii_lowercase())?
                    .try_into()
                    .map_err(|_| SdkError::Argument)?;
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
                let attrs = attrs_of(&b.args)?;
                let pop = bytes(b.args.get("pop").ok_or(SdkError::Argument)?)?;
                let pqz_pop = bytes(b.args.get("pqzPop").ok_or(SdkError::Argument)?)?;
                let entry = b.args.get("entry").and_then(Value::as_str).ok_or(SdkError::Argument)?;
                scaas_ua::wallet::entries::registry_call(entry, &b.args)?;
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
                writes(&sdk, &chain, &payer, ua, &b.args, fill.as_ref()).await
            })
            .await
    }
}
