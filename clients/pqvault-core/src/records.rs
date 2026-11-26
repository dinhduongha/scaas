// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! PqVault's records (spec §5.2), their ids and nonce scopes (§5.3), the wrap hash, the item AAD (§6.4) and the typed data each
//! record is signed as (CTR-PQV-03, CTR-PQV-17): the byte formats of `smartcontracts/vectors/pqvault/records.json`, reproduced
//! by `tests/vectors.rs`. The JSON of a record is the contract's named fields (`0x` hex, an integer as a decimal string), the
//! form the SDK's `read_app` answers and `prepare_app_call` takes. No key here. UNAUDITED.
use alloy::primitives::keccak256;
use alloy::sol_types::SolValue;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};

/// A 32-byte word as `0x` + 64 lower-case hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct B32(pub [u8; 32]);
/// An address as `0x` + 40 lower-case hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Addr(pub [u8; 20]);
/// A byte string as `0x` hex.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Bytes(pub Vec<u8>);
/// An unsigned integer: written as a decimal string, read from a string or a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Num(pub u64);

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(2 + 2 * b.len());
    s.push_str("0x");
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// `0x` hex of at most `max` bytes.
pub fn unhex(s: &str, max: usize) -> Option<Vec<u8>> {
    let h = s.strip_prefix("0x")?;
    if h.len() % 2 != 0 || h.len() / 2 > max {
        return None;
    }
    (0..h.len())
        .step_by(2)
        .map(|i| h.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect()
}

/// The largest byte string a record field holds: a ciphertext (16,416 B), `sealedInfo` (16,412 B), an ML-KEM ciphertext, a
/// signature or an `msig`'s key data (spec §5.4).
const BYTES_MAX: usize = 1 << 16;

macro_rules! fixed {
    ($t:ident, $n:expr) => {
        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&hex(&self.0))
            }
        }
        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                let v = unhex(&s, $n).ok_or_else(|| serde::de::Error::custom("hex"))?;
                Ok($t(v
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("length"))?))
            }
        }
    };
}
fixed!(B32, 32);
fixed!(Addr, 20);

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex(&self.0))
    }
}
impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        unhex(&s, BYTES_MAX)
            .map(Bytes)
            .ok_or_else(|| serde::de::Error::custom("hex"))
    }
}
impl Serialize for Num {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}
impl<'de> Deserialize<'de> for Num {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match Value::deserialize(d)? {
            Value::Number(n) => n.as_u64(),
            Value::String(s)
                if !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()) =>
            {
                s.parse().ok()
            }
            _ => None,
        }
        .map(Num)
        .ok_or_else(|| serde::de::Error::custom("uint"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemberKey {
    pub ua: B32,
    pub key_id: Num,
    /// the `msig` this member is wrapped for, else 0 (PqChat's `via`)
    pub via: B32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Wrap {
    pub member: B32,
    pub key_id: Num,
    pub mlkem_ct: Bytes,
    pub x25519_eph: B32,
    pub sealed_key: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultCreate {
    pub creator: B32,
    pub nonce: Num,
    pub mode: Num,
    pub home_chain: B32,
    pub home_vault_contract: Addr,
    pub admins: Vec<B32>,
    pub members: Vec<MemberKey>,
    pub wrap_hashes: Vec<B32>,
    pub pass_kdf: Num,
    pub pass_salt: B32,
    pub sealed_info: Bytes,
    /// owner 2026-11-23 (controller call for PqVault, CTR-PQV-18): 0 flat wraps, the only mode this release accepts; last
    pub group_mode: Num,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultEpoch {
    pub vault_id: B32,
    pub author: B32,
    pub nonce: Num,
    pub epoch: Num,
    pub parent_epoch_id: B32,
    pub admins: Vec<B32>,
    pub members: Vec<MemberKey>,
    pub wrap_hashes: Vec<B32>,
    pub pass_kdf: Num,
    pub pass_salt: B32,
    pub sealed_info: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultLeave {
    pub vault_id: B32,
    pub epoch_id: B32,
    pub member: B32,
    pub nonce: Num,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultRemove {
    pub vault_id: B32,
    pub epoch_id: B32,
    pub next_epoch: Num,
    pub members: Vec<B32>,
    pub admin: B32,
    pub nonce: Num,
}

/// `PqVaultItem`: a new item, version 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ItemRecord {
    pub vault_id: B32,
    pub epoch_id: B32,
    pub author: B32,
    pub nonce: Num,
    pub ciphertext: Bytes,
}

/// `PqVaultEdit`: version `version` (2 or more) of an item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EditRecord {
    pub item_id: B32,
    pub epoch_id: B32,
    pub author: B32,
    pub nonce: Num,
    pub version: Num,
    pub ciphertext: Bytes,
}

/// `PqVaultBatch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchRecord {
    pub vault_id: B32,
    pub epoch_id: B32,
    pub author: B32,
    pub nonce: Num,
    pub items: Vec<ItemRecord>,
}

/// A `UASig` in its named fields (the SDK's).
pub use scaas_sdk::app_core::{
    AppInnerSig as InnerSig, AppMemberSig as MemberSig, AppUaSig as UaSig,
};

/// A record and the full `UASig` that signs it (spec §7: the signature from `scaas-ua` through the SDK, never built here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed<T> {
    pub record: T,
    pub sig: UaSig,
}

/// One of PqVault's seven signed records (spec §5.2): its struct name, its argument name in the contract's entry, the entry.
pub trait Record: Serialize {
    const NAME: &'static str;
}
macro_rules! record {
    ($t:ty, $n:expr) => {
        impl Record for $t {
            const NAME: &'static str = $n;
        }
    };
}
record!(VaultCreate, "PqVaultCreate");
record!(VaultEpoch, "PqVaultEpoch");
record!(VaultLeave, "PqVaultLeave");
record!(VaultRemove, "PqVaultRemove");
record!(ItemRecord, "PqVaultItem");
record!(EditRecord, "PqVaultEdit");
record!(BatchRecord, "PqVaultBatch");

/// `encodeType`'s field lists (`PqVaultTypes.sol`, clientkeys `TYPE_STRINGS`).
const FIELDS: [(&str, &str); 9] = [
    ("MemberKey", "bytes32 ua,uint64 keyId,bytes32 via"),
    ("Wrap", "bytes32 member,uint64 keyId,bytes mlkemCt,bytes32 x25519Eph,bytes sealedKey"),
    (
        "PqVaultCreate",
        "bytes32 creator,uint64 nonce,uint8 mode,bytes32 homeChain,address homeVaultContract,bytes32[] admins,\
         MemberKey[] members,bytes32[] wrapHashes,uint16 passKdf,bytes32 passSalt,bytes sealedInfo,uint8 groupMode",
    ),
    (
        "PqVaultEpoch",
        "bytes32 vaultId,bytes32 author,uint64 nonce,uint64 epoch,bytes32 parentEpochId,bytes32[] admins,\
         MemberKey[] members,bytes32[] wrapHashes,uint16 passKdf,bytes32 passSalt,bytes sealedInfo",
    ),
    ("PqVaultLeave", "bytes32 vaultId,bytes32 epochId,bytes32 member,uint64 nonce"),
    (
        "PqVaultRemove",
        "bytes32 vaultId,bytes32 epochId,uint64 nextEpoch,bytes32[] members,bytes32 admin,uint64 nonce",
    ),
    ("PqVaultItem", "bytes32 vaultId,bytes32 epochId,bytes32 author,uint64 nonce,bytes ciphertext"),
    (
        "PqVaultEdit",
        "bytes32 itemId,bytes32 epochId,bytes32 author,uint64 nonce,uint32 version,bytes ciphertext",
    ),
    (
        "PqVaultBatch",
        "bytes32 vaultId,bytes32 epochId,bytes32 author,uint64 nonce,PqVaultItem[] items",
    ),
];

fn fields(name: &str) -> &'static str {
    FIELDS
        .iter()
        .find(|(n, _)| *n == name)
        .map_or("", |(_, f)| f)
}

/// `name`'s type string (`encodeType`): its fields, then the structs it references, by name.
pub fn encode_type(name: &str) -> String {
    let own = format!("{name}({})", fields(name));
    let refs: Vec<&str> = ["MemberKey", "PqVaultItem"]
        .into_iter()
        .filter(|r| *r != name && fields(name).contains(&format!("{r}[]")))
        .collect();
    refs.iter()
        .fold(own, |s, r| format!("{s}{r}({})", fields(r)))
}

/// The domain of a vault (spec §5.15): mode 0 `DS_V` (no chain, no address, `salt = PQVAULT_APP_ID`), mode 1 `DS_B` of the
/// chain id and the home instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    Portable,
    ChainBound { chain_id: u64, instance: Addr },
}

/// The EIP-712 JSON of `r` in `domain` (what `sign_pqvault_record` and `verify_pqvault_record` take; the SDK's typed-data
/// parser holds it to 64 KiB, so a batch is sized by it too: `batch` below).
pub fn typed_json<R: Record>(r: &R, domain: Domain) -> Result<String, serde_json::Error> {
    let mut types = serde_json::Map::new();
    let s = |n: &str| json!({"name": n, "type": "string"});
    let (dt, d) = match domain {
        Domain::Portable => (
            json!([s("name"), s("version"), {"name": "salt", "type": "bytes32"}]),
            json!({"name": crate::DOMAIN_NAME, "version": "1", "salt": hex(&crate::app_id())}),
        ),
        Domain::ChainBound { chain_id, instance } => (
            json!([s("name"), s("version"), {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}]),
            json!({"name": crate::DOMAIN_NAME, "version": "1", "chainId": chain_id.to_string(),
                "verifyingContract": hex(&instance.0)}),
        ),
    };
    types.insert("EIP712Domain".into(), dt);
    for (n, f) in FIELDS {
        if n == R::NAME || (n != "Wrap" && encode_type(R::NAME).contains(&format!("{n}("))) {
            let list: Vec<Value> = f
                .split(',')
                .map(|p| {
                    let (t, name) = p.split_once(' ').unwrap_or((p, ""));
                    json!({"name": name, "type": t})
                })
                .collect();
            types.insert(n.into(), Value::Array(list));
        }
    }
    serde_json::to_string(&json!({
        "types": types,
        "primaryType": R::NAME,
        "domain": d,
        "message": r,
    }))
}

// ------------------------------------------------------------------ ids and scopes (spec §5.3)

fn tag(t: &str) -> [u8; 32] {
    keccak256(format!("scaas/pqvault/v1/{t}")).0
}

/// Epoch 0's id too; binds the mode and the home (review r2 R5).
pub fn vault_id(creator: B32, nonce: u64, mode: u8, home_chain: B32, home: Addr) -> B32 {
    let enc = (
        alloy::primitives::B256::from(tag("vault")),
        alloy::primitives::B256::from(creator.0),
        nonce,
        alloy::primitives::U256::from(mode),
        alloy::primitives::B256::from(home_chain.0),
        alloy::primitives::Address::from(home.0),
    )
        .abi_encode();
    B32(keccak256(enc).0)
}

fn id3(t: &str, vault: B32, author: B32, nonce: u64) -> B32 {
    let enc = (
        alloy::primitives::B256::from(tag(t)),
        alloy::primitives::B256::from(vault.0),
        alloy::primitives::B256::from(author.0),
        nonce,
    )
        .abi_encode();
    B32(keccak256(enc).0)
}

pub fn epoch_id(vault: B32, author: B32, nonce: u64) -> B32 {
    id3("epoch", vault, author, nonce)
}
pub fn item_id(vault: B32, author: B32, nonce: u64) -> B32 {
    id3("item", vault, author, nonce)
}
pub fn batch_id(vault: B32, author: B32, nonce: u64) -> B32 {
    id3("batch", vault, author, nonce)
}

fn words(t: &str, w: &[B32]) -> B32 {
    let mut enc = tag(t).to_vec();
    for x in w {
        enc.extend_from_slice(&x.0);
    }
    B32(keccak256(enc).0)
}
pub fn scope_vault(creator: B32) -> B32 {
    words("scope/vault", &[creator])
}
/// Rekeys, leaves and removals.
pub fn scope_epoch(vault: B32, author: B32) -> B32 {
    words("scope/epoch", &[vault, author])
}
/// Items, edits and batches.
pub fn scope_item(vault: B32, author: B32) -> B32 {
    words("scope/item", &[vault, author])
}

/// `hashStruct(Wrap)`: what an epoch's `wrapHashes` sign (PqChat's `hashWrap`).
pub fn wrap_hash(w: &Wrap) -> B32 {
    let enc = (
        alloy::primitives::B256::from(keccak256(format!("Wrap({})", fields("Wrap"))).0),
        alloy::primitives::B256::from(w.member.0),
        w.key_id.0,
        keccak256(&w.mlkem_ct.0),
        alloy::primitives::B256::from(w.x25519_eph.0),
        keccak256(&w.sealed_key.0),
    )
        .abi_encode();
    B32(keccak256(enc).0)
}

/// The item AAD (spec §6.4): `abi.encode(vaultId, epochId, itemId, uint32 version, author, homeChain, homeVaultContract)`.
pub fn item_aad(
    vault: B32,
    epoch: B32,
    item: B32,
    version: u32,
    author: B32,
    home_chain: B32,
    home: Addr,
) -> Vec<u8> {
    (
        alloy::primitives::B256::from(vault.0),
        alloy::primitives::B256::from(epoch.0),
        alloy::primitives::B256::from(item.0),
        version,
        alloy::primitives::B256::from(author.0),
        alloy::primitives::B256::from(home_chain.0),
        alloy::primitives::Address::from(home.0),
    )
        .abi_encode()
}

/// `keccak256(abi.encode(UASig))`, the contract's `sigHash` of an item, an edit or a batch.
pub fn sig_hash(s: &UaSig) -> B32 {
    use alloy::primitives::Bytes as AB;
    type Member = (u16, Vec<(u16, AB)>, AB);
    let members: Vec<Member> = s
        .members
        .iter()
        .map(|m| {
            (
                m.index,
                m.members
                    .iter()
                    .map(|i| (i.index, AB::from(i.sig.clone())))
                    .collect(),
                AB::from(m.sig.clone()),
            )
        })
        .collect();
    let v = (
        AB::from(s.key_data.clone()),
        AB::from(s.signature.clone()),
        members,
    );
    B32(keccak256(v.abi_encode()).0)
}

/// A `UASig` as the contract's argument JSON.
pub fn sig_json(s: &UaSig) -> Value {
    json!({
        "keyData": hex(&s.key_data),
        "signature": hex(&s.signature),
        "members": s.members.iter().map(|m| json!({
            "index": m.index,
            "members": m.members.iter().map(|i| json!({"index": i.index, "sig": hex(&i.sig)})).collect::<Vec<_>>(),
            "sig": hex(&m.sig),
        })).collect::<Vec<_>>(),
    })
}

/// A `UASig` from a view's JSON (bounded: 16 members per level, CTR-UA-37's structure caps).
pub fn sig_of(v: &Value) -> Option<UaSig> {
    let b = |x: &Value| unhex(x.as_str()?, BYTES_MAX);
    let n = |x: &Value| {
        x.as_str()
            .and_then(|s| s.parse::<u16>().ok())
            .or_else(|| u16::try_from(x.as_u64()?).ok())
    };
    let ms = v.get("members")?.as_array()?;
    if ms.len() > 16 {
        return None;
    }
    let members = ms
        .iter()
        .map(|m| {
            let inner = m.get("members")?.as_array()?;
            if inner.len() > 16 {
                return None;
            }
            Some(MemberSig {
                index: n(m.get("index")?)?,
                members: inner
                    .iter()
                    .map(|i| {
                        Some(InnerSig {
                            index: n(i.get("index")?)?,
                            sig: b(i.get("sig")?)?,
                        })
                    })
                    .collect::<Option<_>>()?,
                sig: b(m.get("sig")?)?,
            })
        })
        .collect::<Option<_>>()?;
    Some(UaSig {
        key_data: b(v.get("keyData")?)?,
        signature: b(v.get("signature")?)?,
        members,
    })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn encode_types_name_their_references() {
        assert_eq!(
            encode_type("PqVaultBatch"),
            "PqVaultBatch(bytes32 vaultId,bytes32 epochId,bytes32 author,uint64 nonce,PqVaultItem[] items)\
             PqVaultItem(bytes32 vaultId,bytes32 epochId,bytes32 author,uint64 nonce,bytes ciphertext)"
        );
        assert!(encode_type("PqVaultCreate")
            .ends_with("MemberKey(bytes32 ua,uint64 keyId,bytes32 via)"));
        assert!(!encode_type("PqVaultLeave").contains("MemberKey"));
    }

    #[test]
    fn num_reads_strings_and_numbers_only_in_range() {
        let ok: Num = serde_json::from_str("\"18446744073709551615\"").unwrap_or_default();
        assert_eq!(ok, Num(u64::MAX));
        assert!(serde_json::from_str::<Num>("\"18446744073709551616\"").is_err());
        assert!(serde_json::from_str::<Num>("\"-1\"").is_err());
        assert!(serde_json::from_str::<Num>("\"0x10\"").is_err());
        assert_eq!(serde_json::from_str::<Num>("7").ok(), Some(Num(7)));
    }
}
