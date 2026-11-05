// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! EVM transactions (spec §5.5; T5): [`EvmTx`] with named fields per EIP-2718 type, 0 (legacy, EIP-155: `chainId` required),
//! 1 (EIP-2930), 2 (EIP-1559), 3 (EIP-4844: the signed fields only, never the sidecar). **No type 4**: there is no variant,
//! so an EIP-7702 transaction cannot be built (CLI-SGN-40); chain id 0 is refused. RLP by `alloy-rlp`; the sighash is
//! `keccak256(rlp([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]))` for type 0 and `keccak256(type ‖ rlp(fields))`
//! otherwise; [`NativeKey::sign_transaction`] signs it with a secp256k1 native key (RFC 6979, low-s) and returns the envelope
//! and `(r, s, yParity)`, byte for byte as clientkeys `signTransaction`. The JSON form (clientkeys `evmTransaction`'s input:
//! every field of the type and no other, integers as decimal strings or numbers, `to: null` for a create) is read through
//! `bounded::json` at 16 KiB, depth 4 (spec §9.3). UNAUDITED.
//!
//! The four types are all there is (an exhaustive match, no wildcard):
//! ```
//! fn ty(t: &scaas_ua::wallet::EvmTx) -> u8 {
//!     use scaas_ua::wallet::EvmTx::*;
//!     match t {
//!         Legacy { .. } => 0,
//!         Eip2930 { .. } => 1,
//!         Eip1559 { .. } => 2,
//!         Eip4844 { .. } => 3,
//!     }
//! }
//! ```
//! ```compile_fail,E0599
//! let _ = scaas_ua::wallet::EvmTx::Eip7702 { chain_id: 1 };
//! ```
//! A transaction request is read, never built, outside `ua-rs`:
//! ```
//! use scaas_ua::wallet::SignRequest;
//! fn sighash_of(r: &SignRequest) -> Option<(u8, [u8; 32])> {
//!     match r {
//!         SignRequest::Transaction { tx_type, sighash, tx, .. } => Some((*tx_type, *sighash)).filter(|_| tx.tx_type() == *tx_type),
//!         _ => None,
//!     }
//! }
//! ```
//! ```compile_fail,E0639
//! let _ = scaas_ua::wallet::SignRequest::Transaction { tx_type: 2, sighash: [0; 32], tx: todo!() };
//! ```
use super::eip712::{from_hex, u256_dec, u256_from, U256};
use super::signer::{SignRequest, Signer};
use super::{bounded, Error, NativeKey, Result};
use crate::keccak256;
use alloy_rlp::Header;
use serde_json::{Map, Value};

const MAX_LEN: usize = 16 * 1024;
const MAX_DEPTH: usize = 4;

/// One entry of an EIP-2930 access list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessListItem {
    pub address: [u8; 20],
    pub storage_keys: Vec<[u8; 32]>,
}

/// An EVM transaction's signed fields. 256-bit integers are big-endian; `to: None` is a create (not on type 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvmTx {
    Legacy { chain_id: u64, nonce: u64, gas_price: U256, gas_limit: u64, to: Option<[u8; 20]>, value: U256, data: Vec<u8> },
    Eip2930 {
        chain_id: u64,
        nonce: u64,
        gas_price: U256,
        gas_limit: u64,
        to: Option<[u8; 20]>,
        value: U256,
        data: Vec<u8>,
        access_list: Vec<AccessListItem>,
    },
    Eip1559 {
        chain_id: u64,
        nonce: u64,
        max_priority_fee_per_gas: U256,
        max_fee_per_gas: U256,
        gas_limit: u64,
        to: Option<[u8; 20]>,
        value: U256,
        data: Vec<u8>,
        access_list: Vec<AccessListItem>,
    },
    Eip4844 {
        chain_id: u64,
        nonce: u64,
        max_priority_fee_per_gas: U256,
        max_fee_per_gas: U256,
        gas_limit: u64,
        to: [u8; 20],
        value: U256,
        data: Vec<u8>,
        access_list: Vec<AccessListItem>,
        max_fee_per_blob_gas: U256,
        /// At least one.
        blob_versioned_hashes: Vec<[u8; 32]>,
    },
}

/// A signed transaction: the envelope to broadcast (`raw`) and the signature parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTx {
    pub tx_type: u8,
    pub sighash: [u8; 32],
    pub y_parity: u8,
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub raw: Vec<u8>,
}

// --- RLP: each item encoded on its own, lists assembled from encoded items ---

fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    alloy_rlp::encode(b)
}
/// A 256-bit integer: its minimal big-endian bytes (0 is the empty string).
fn rlp_uint(x: &U256) -> Vec<u8> {
    rlp_bytes(x.get(x.iter().position(|b| *b != 0).unwrap_or(32)..).unwrap_or_default())
}
fn rlp_u64(x: u64) -> Vec<u8> {
    alloy_rlp::encode(x)
}
fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_length = items.iter().map(Vec::len).sum();
    let mut out = Vec::with_capacity(payload_length + 9);
    Header { list: true, payload_length }.encode(&mut out);
    for i in items {
        out.extend_from_slice(i);
    }
    out
}
fn rlp_to(to: &Option<[u8; 20]>) -> Vec<u8> {
    rlp_bytes(to.as_ref().map_or(&[][..], |a| &a[..]))
}
fn rlp_access_list(l: &[AccessListItem]) -> Vec<u8> {
    let entries: Vec<Vec<u8>> = l
        .iter()
        .map(|e| rlp_list(&[rlp_bytes(&e.address), rlp_list(&e.storage_keys.iter().map(|k| rlp_bytes(k)).collect::<Vec<_>>())]))
        .collect();
    rlp_list(&entries)
}

impl EvmTx {
    /// The EIP-2718 type, 0-3.
    pub fn tx_type(&self) -> u8 {
        match self {
            EvmTx::Legacy { .. } => 0,
            EvmTx::Eip2930 { .. } => 1,
            EvmTx::Eip1559 { .. } => 2,
            EvmTx::Eip4844 { .. } => 3,
        }
    }

    fn chain_id(&self) -> u64 {
        match self {
            EvmTx::Legacy { chain_id, .. }
            | EvmTx::Eip2930 { chain_id, .. }
            | EvmTx::Eip1559 { chain_id, .. }
            | EvmTx::Eip4844 { chain_id, .. } => *chain_id,
        }
    }

    /// The RLP items of the signed fields in their order (type 0: without the EIP-155 tail); `Argument` for chain id 0 or a
    /// type-3 transaction with no blob hash.
    fn items(&self) -> Result<Vec<Vec<u8>>> {
        if self.chain_id() == 0 {
            return Err(Error::Argument);
        }
        Ok(match self {
            EvmTx::Legacy { nonce, gas_price, gas_limit, to, value, data, .. } => {
                vec![rlp_u64(*nonce), rlp_uint(gas_price), rlp_u64(*gas_limit), rlp_to(to), rlp_uint(value), rlp_bytes(data)]
            }
            EvmTx::Eip2930 { chain_id, nonce, gas_price, gas_limit, to, value, data, access_list } => vec![
                rlp_u64(*chain_id),
                rlp_u64(*nonce),
                rlp_uint(gas_price),
                rlp_u64(*gas_limit),
                rlp_to(to),
                rlp_uint(value),
                rlp_bytes(data),
                rlp_access_list(access_list),
            ],
            EvmTx::Eip1559 {
                chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list,
            } => vec![
                rlp_u64(*chain_id),
                rlp_u64(*nonce),
                rlp_uint(max_priority_fee_per_gas),
                rlp_uint(max_fee_per_gas),
                rlp_u64(*gas_limit),
                rlp_to(to),
                rlp_uint(value),
                rlp_bytes(data),
                rlp_access_list(access_list),
            ],
            EvmTx::Eip4844 {
                chain_id,
                nonce,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                gas_limit,
                to,
                value,
                data,
                access_list,
                max_fee_per_blob_gas,
                blob_versioned_hashes,
            } => {
                if blob_versioned_hashes.is_empty() {
                    return Err(Error::Argument);
                }
                vec![
                    rlp_u64(*chain_id),
                    rlp_u64(*nonce),
                    rlp_uint(max_priority_fee_per_gas),
                    rlp_uint(max_fee_per_gas),
                    rlp_u64(*gas_limit),
                    rlp_bytes(to),
                    rlp_uint(value),
                    rlp_bytes(data),
                    rlp_access_list(access_list),
                    rlp_uint(max_fee_per_blob_gas),
                    rlp_list(&blob_versioned_hashes.iter().map(|h| rlp_bytes(h)).collect::<Vec<_>>()),
                ]
            }
        })
    }

    /// `items` followed by `tail`, as the type's envelope: `rlp(list)` for type 0, `type ‖ rlp(list)` otherwise.
    fn envelope(&self, tail: Vec<Vec<u8>>) -> Result<Vec<u8>> {
        let mut items = self.items()?;
        items.extend(tail);
        let list = rlp_list(&items);
        Ok(match self.tx_type() {
            0 => list,
            t => [&[t][..], &list].concat(),
        })
    }

    /// The bytes the sighash hashes (type 0: EIP-155 `[…, chainId, 0, 0]`).
    pub fn unsigned(&self) -> Result<Vec<u8>> {
        let tail = match self {
            EvmTx::Legacy { chain_id, .. } => vec![rlp_u64(*chain_id), rlp_bytes(&[]), rlp_bytes(&[])],
            _ => vec![],
        };
        self.envelope(tail)
    }

    /// `keccak256(unsigned)`.
    pub fn sighash(&self) -> Result<[u8; 32]> {
        Ok(keccak256(&self.unsigned()?))
    }

    /// The signed envelope from `r ‖ s ‖ v` (`v = 27 + yParity`, as `sign_scheme` returns it): type 0 `rlp([…, v, r, s])`
    /// with `v = chainId · 2 + 35 + yParity`, else `type ‖ rlp([…, yParity, r, s])`.
    fn signed(&self, sighash: [u8; 32], sig: &[u8]) -> Result<SignedTx> {
        let (Some(r), Some(s), Some(v), 65) = (sig.get(..32), sig.get(32..64), sig.get(64), sig.len()) else {
            return Err(Error::Argument);
        };
        let r: [u8; 32] = r.try_into().map_err(|_| Error::Argument)?;
        let s: [u8; 32] = s.try_into().map_err(|_| Error::Argument)?;
        let y_parity = v.checked_sub(27).filter(|y| *y <= 1).ok_or(Error::Argument)?;
        let v_item = match self {
            EvmTx::Legacy { chain_id, .. } => alloy_rlp::encode(u128::from(*chain_id) * 2 + 35 + u128::from(y_parity)),
            _ => rlp_u64(u64::from(y_parity)),
        };
        let raw = self.envelope(vec![v_item, rlp_uint(&r), rlp_uint(&s)])?;
        Ok(SignedTx { tx_type: self.tx_type(), sighash, y_parity, r, s, raw })
    }

    /// The JSON form of clientkeys `evmTransaction`: `type` 0-3 (a number), every field of the type and no other, integers as
    /// decimal strings or numbers (`nonce`, `gasLimit`, `chainId` below 2^64, the rest below 2^256), `chainId` non-zero, `to`
    /// 20 bytes or `null` for a create (not on type 3), `data` hex, `accessList` `[{address, storageKeys}]`, at least one blob
    /// hash on type 3. Anything else is `Argument`.
    pub fn from_json(json: &[u8]) -> Result<EvmTx> {
        let Value::Object(o) = bounded::json(json, MAX_LEN, MAX_DEPTH)? else { return Err(Error::Argument) };
        let ty = o.get("type").and_then(Value::as_u64).ok_or(Error::Argument)?;
        let names: &[&str] = match ty {
            0 => &["chainId", "nonce", "gasPrice", "gasLimit", "to", "value", "data"],
            1 => &["chainId", "nonce", "gasPrice", "gasLimit", "to", "value", "data", "accessList"],
            2 => &["chainId", "nonce", "maxPriorityFeePerGas", "maxFeePerGas", "gasLimit", "to", "value", "data", "accessList"],
            3 => &["chainId", "nonce", "maxPriorityFeePerGas", "maxFeePerGas", "gasLimit", "to", "value", "data", "accessList",
                "maxFeePerBlobGas", "blobVersionedHashes"],
            _ => return Err(Error::Argument), // never EIP-7702
        };
        // a missing field is refused where it is read
        if o.keys().any(|k| k != "type" && !names.contains(&k.as_str())) {
            return Err(Error::Argument);
        }
        let f = Fields(&o);
        let tx = match ty {
            0 => EvmTx::Legacy {
                chain_id: f.u64("chainId")?,
                nonce: f.u64("nonce")?,
                gas_price: f.uint("gasPrice")?,
                gas_limit: f.u64("gasLimit")?,
                to: f.to()?,
                value: f.uint("value")?,
                data: f.data()?,
            },
            1 => EvmTx::Eip2930 {
                chain_id: f.u64("chainId")?,
                nonce: f.u64("nonce")?,
                gas_price: f.uint("gasPrice")?,
                gas_limit: f.u64("gasLimit")?,
                to: f.to()?,
                value: f.uint("value")?,
                data: f.data()?,
                access_list: f.access_list()?,
            },
            2 => EvmTx::Eip1559 {
                chain_id: f.u64("chainId")?,
                nonce: f.u64("nonce")?,
                max_priority_fee_per_gas: f.uint("maxPriorityFeePerGas")?,
                max_fee_per_gas: f.uint("maxFeePerGas")?,
                gas_limit: f.u64("gasLimit")?,
                to: f.to()?,
                value: f.uint("value")?,
                data: f.data()?,
                access_list: f.access_list()?,
            },
            _ => EvmTx::Eip4844 {
                chain_id: f.u64("chainId")?,
                nonce: f.u64("nonce")?,
                max_priority_fee_per_gas: f.uint("maxPriorityFeePerGas")?,
                max_fee_per_gas: f.uint("maxFeePerGas")?,
                gas_limit: f.u64("gasLimit")?,
                to: f.to()?.ok_or(Error::Argument)?,
                value: f.uint("value")?,
                data: f.data()?,
                access_list: f.access_list()?,
                max_fee_per_blob_gas: f.uint("maxFeePerBlobGas")?,
                blob_versioned_hashes: f.list("blobVersionedHashes")?.iter().map(fixed).collect::<Result<_>>()?,
            },
        };
        tx.items()?; // chain id 0, no blob hash
        Ok(tx)
    }
}

/// `N` bytes of hex.
fn fixed<const N: usize>(v: &Value) -> Result<[u8; N]> {
    v.as_str().and_then(from_hex).and_then(|b| b.try_into().ok()).ok_or(Error::Argument)
}

/// The fields of a transaction's JSON object; a missing one is `Argument`.
struct Fields<'a>(&'a Map<String, Value>);

impl Fields<'_> {
    fn get(&self, k: &str) -> Result<&Value> {
        self.0.get(k).ok_or(Error::Argument)
    }
    /// A JSON number (u64) or a string of decimal digits.
    fn uint(&self, k: &str) -> Result<U256> {
        match self.get(k)? {
            Value::Number(n) => n.as_u64().map(u256_from),
            Value::String(s) => u256_dec(s),
            _ => None,
        }
        .ok_or(Error::Argument)
    }
    fn u64(&self, k: &str) -> Result<u64> {
        let w = self.uint(k)?;
        let (hi, lo) = w.split_at(24);
        if hi.iter().any(|b| *b != 0) {
            return Err(Error::Argument);
        }
        Ok(u64::from_be_bytes(lo.try_into().map_err(|_| Error::Argument)?))
    }
    fn to(&self) -> Result<Option<[u8; 20]>> {
        match self.get("to")? {
            Value::Null => Ok(None),
            v => fixed(v).map(Some),
        }
    }
    fn data(&self) -> Result<Vec<u8>> {
        self.get("data")?.as_str().and_then(from_hex).ok_or(Error::Argument)
    }
    fn list(&self, k: &str) -> Result<&Vec<Value>> {
        self.get(k)?.as_array().ok_or(Error::Argument)
    }
    fn access_list(&self) -> Result<Vec<AccessListItem>> {
        self.list("accessList")?
            .iter()
            .map(|e| {
                let e = e.as_object().filter(|e| e.len() == 2).ok_or(Error::Argument)?;
                let keys = e.get("storageKeys").and_then(Value::as_array).ok_or(Error::Argument)?;
                Ok(AccessListItem {
                    address: fixed(e.get("address").ok_or(Error::Argument)?)?,
                    storage_keys: keys.iter().map(fixed).collect::<Result<_>>()?,
                })
            })
            .collect()
    }
}

/// The request of a transaction: its type, its sighash and the transaction itself (readable for a clear-signing device).
fn request(tx: &EvmTx) -> Result<SignRequest> {
    Ok(SignRequest::Transaction { tx_type: tx.tx_type(), sighash: tx.sighash()?, tx: Box::new(tx.clone()) })
}

impl NativeKey {
    /// The transaction signed by this key (a secp256k1 native key; the ed25519 networks are `Argument`): RFC 6979, low-s,
    /// the envelope and `(r, s, yParity)`.
    pub fn sign_transaction(&self, tx: &EvmTx) -> Result<SignedTx> {
        let req = request(tx)?;
        let SignRequest::Transaction { sighash, .. } = req else { return Err(Error::Argument) };
        tx.signed(sighash, &self.sign_request(&req)?)
    }
}

#[cfg(feature = "vectors")]
impl EvmTx {
    /// Test-only (feature `vectors`): the transaction signed with a raw secp256k1 `secret` (the EIP-155 published example).
    pub fn vectors_sign_with_secret(&self, secret: &[u8]) -> Result<SignedTx> {
        let sighash = self.sighash()?;
        self.signed(sighash, &super::sign::sign_raw(0x0001, secret, &sighash, None)?)
    }
}
