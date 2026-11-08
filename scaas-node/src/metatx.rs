//! Wire format (strings, as clients and the gateway send them) ↔ the two signed structs, and their canonical digests
//! (CTR-MTX-15): `MetaTransaction` (`struct = "call"`, an allowlisted self-call) and `MetaTransfer`
//! (`struct = "transfer"`, a token transfer or payment), one lane space, in the salted domain
//! `(name, version, chainId, contract, salt = chain_uid)`. Canonical zeroing is `MetaTxLib.canon` bit for bit.
use std::str::FromStr;

use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy::sol_types::{Eip712Domain, SolCall, SolStruct};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use crate::abi::{MetaTransaction, MetaTransfer, UAMetaTransaction, UAMetaTransfer, UASig};
use crate::abi::{IMtxIds, IToken};

pub const MODE_RESTRICT_RELAYER: u32 = 0x01;
pub const MODE_RESTRICT_FEE_RECIPIENT: u32 = 0x02;
pub const MODE_FEE_MASK: u32 = 0xF0;
pub const MODE_KNOWN_MASK: u32 = 0xF3;

/// pay-meta-tax spec §3.1 (CTR-MTX-26 Change): `metaPayId(m) = keccak256("scaas.pay.meta.v2" ‖ salt ‖ keccak256(abi.encode(
/// string payNo, uint16 schema, bytes body)))`. The old `(salt, meta)` form is in `legacy/ua-mtx-merge/3e/metatx.rs`; the
/// non-EVM adapters keep their own until their family round (spec §8).
pub fn meta_pay_id(m: &crate::abi::PayMeta) -> B256 {
    use alloy::sol_types::SolValue;
    let inner = (m.payNo.clone(), m.schema, m.body.clone()).abi_encode_params();
    keccak256([&b"scaas.pay.meta.v2"[..], m.salt.as_slice(), keccak256(inner).as_slice()].concat())
}

/// `payNo`'s bound (spec §3.1, owner 2026-11-06).
pub const PAY_NO_MAX: usize = 256;

/// The contract's `_payMeta` shape (spec §3.2), by name before any encoding or simulation: a non-zero salt, `schema == 0` iff
/// the body is empty (`PAY_META_SHAPE`), `payNo` at most 256 bytes (`PAY_NO_TOO_LONG`).
pub fn check_pay_meta(m: &crate::abi::PayMeta) -> Result<()> {
    if m.salt.is_zero() || (m.schema == 0) != m.body.is_empty() {
        bail!("PAY_META_SHAPE: a non-zero salt, schema 0 iff the body is empty");
    }
    if m.payNo.len() > PAY_NO_MAX {
        bail!("PAY_NO_TOO_LONG: payNo is {} B, above {PAY_NO_MAX}", m.payNo.len());
    }
    Ok(())
}

/// CTR-MTX-10: `payLane(payId) = uint256(keccak256("scaas.pay.lane" ‖ payId))`.
pub fn pay_lane(p: &B256) -> U256 {
    U256::from_be_bytes(keccak256([&b"scaas.pay.lane"[..], p.as_slice()].concat()).0)
}

/// CTR-MTX-27: `relayRef(target, callData) = keccak256("scaas.relayfee" ‖ uint256 chainid ‖ target ‖ keccak256(callData))`.
pub fn relay_ref(chain_id: u64, target: Address, call: &[u8]) -> B256 {
    keccak256([&b"scaas.relayfee"[..], &U256::from(chain_id).to_be_bytes::<32>(), target.as_slice(), keccak256(call).as_slice()].concat())
}

/// The 9 fields of `MetaTransaction` (camelCase, decimal strings).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WireMetaTx {
    pub from: String,
    pub data: String,
    pub batch: String,
    pub nonce: String,
    pub valid_until: String,
    pub mode: u32,
    pub relayer: String,
    pub fee: String,
    pub fee_recipient: String,
}

/// The 11 fields of `MetaTransfer`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WireMetaTransfer {
    pub from: String,
    pub to: String,
    pub value: String,
    pub entry_ref: String,
    pub batch: String,
    pub nonce: String,
    pub valid_until: String,
    pub mode: u32,
    pub relayer: String,
    pub fee: String,
    pub fee_recipient: String,
}

/// EIP-712 domain of a SCaaS contract; `salt` is the chain's `chain_uid` (NET-ALL-22), never optional.
#[derive(Debug, Clone)]
pub struct Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: Address,
    pub salt: B256,
}

impl Domain {
    pub fn eip712(&self) -> Eip712Domain {
        Eip712Domain::new(
            Some(self.name.clone().into()),
            Some(self.version.clone().into()),
            Some(U256::from(self.chain_id)),
            Some(self.verifying_contract),
            Some(self.salt),
        )
    }
}

/// One signed meta-transaction, either struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mtx {
    Call(MetaTransaction),
    Transfer(MetaTransfer),
}

pub(crate) fn addr(s: &str) -> Result<Address> {
    if s.len() != 42 || !s.starts_with("0x") {
        bail!("not an address: {s}");
    }
    Address::from_str(s).map_err(|e| anyhow!("not an address {s}: {e}"))
}

pub(crate) fn uint(s: &str) -> Result<U256> {
    let canonical = !s.is_empty()
        && s.len() <= 78
        && s.bytes().all(|b| b.is_ascii_digit())
        && !(s.len() > 1 && s.starts_with('0'));
    if !canonical {
        bail!("not a canonical uint256: {s}");
    }
    U256::from_str_radix(s, 10).map_err(|e| anyhow!("uint256 {s}: {e}"))
}

pub(crate) fn b32(s: &str) -> Result<B256> {
    if s.len() != 66 || !s.starts_with("0x") {
        bail!("not a bytes32: {s}");
    }
    B256::from_str(s).map_err(|e| anyhow!("bytes32 {s}: {e}"))
}

pub(crate) fn check_mode(mode: u32) -> Result<()> {
    if mode & !MODE_KNOWN_MASK != 0 || (mode & MODE_FEE_MASK) >> 4 > 2 {
        bail!("unknown mode bits {mode:#x}");
    }
    Ok(())
}

impl WireMetaTx {
    pub fn to_sol(&self) -> Result<MetaTransaction> {
        let hex = self.data.strip_prefix("0x").ok_or_else(|| anyhow!("data must be 0x-hex"))?;
        let data = alloy::hex::decode(hex).map_err(|e| anyhow!("data: {e}"))?;
        check_mode(self.mode)?;
        Ok(MetaTransaction {
            from: addr(&self.from)?,
            data: Bytes::from(data),
            batch: uint(&self.batch)?,
            nonce: uint(&self.nonce)?,
            validUntil: uint(&self.valid_until)?,
            mode: self.mode,
            relayer: addr(&self.relayer)?,
            fee: uint(&self.fee)?,
            feeRecipient: addr(&self.fee_recipient)?,
        })
    }

    pub fn from_sol(m: &MetaTransaction) -> Self {
        Self {
            from: format!("{:#x}", m.from),
            data: format!("0x{}", alloy::hex::encode(&m.data)),
            batch: m.batch.to_string(),
            nonce: m.nonce.to_string(),
            valid_until: m.validUntil.to_string(),
            mode: m.mode,
            relayer: format!("{:#x}", m.relayer),
            fee: m.fee.to_string(),
            fee_recipient: format!("{:#x}", m.feeRecipient),
        }
    }
}

impl WireMetaTransfer {
    pub fn to_sol(&self) -> Result<MetaTransfer> {
        check_mode(self.mode)?;
        Ok(MetaTransfer {
            from: addr(&self.from)?,
            to: addr(&self.to)?,
            value: uint(&self.value)?,
            entryRef: b32(&self.entry_ref)?,
            batch: uint(&self.batch)?,
            nonce: uint(&self.nonce)?,
            validUntil: uint(&self.valid_until)?,
            mode: self.mode,
            relayer: addr(&self.relayer)?,
            fee: uint(&self.fee)?,
            feeRecipient: addr(&self.fee_recipient)?,
        })
    }

    pub fn from_sol(t: &MetaTransfer) -> Self {
        Self {
            from: format!("{:#x}", t.from),
            to: format!("{:#x}", t.to),
            value: t.value.to_string(),
            entry_ref: format!("{:#x}", t.entryRef),
            batch: t.batch.to_string(),
            nonce: t.nonce.to_string(),
            valid_until: t.validUntil.to_string(),
            mode: t.mode,
            relayer: format!("{:#x}", t.relayer),
            fee: t.fee.to_string(),
            fee_recipient: format!("{:#x}", t.feeRecipient),
        }
    }
}

impl Mtx {
    /// `kind` = the job's or request's `struct`: `call` | `transfer`; absent = `transfer` (node/gateway.md). The wire
    /// structs refuse unknown fields, so a body of the other struct never parses as this one.
    pub fn from_wire(kind: Option<&str>, m: &Value) -> Result<Self> {
        match kind.unwrap_or("transfer") {
            "call" => Ok(Self::Call(serde_json::from_value::<WireMetaTx>(m.clone())?.to_sol()?)),
            "transfer" => Ok(Self::Transfer(serde_json::from_value::<WireMetaTransfer>(m.clone())?.to_sol()?)),
            k => bail!("unknown struct {k:?} (call | transfer)"),
        }
    }

    /// `(struct, wire)`, the inverse of `from_wire`.
    pub fn to_wire(&self) -> (&'static str, Value) {
        match self {
            Self::Call(m) => ("call", serde_json::to_value(WireMetaTx::from_sol(m)).expect("plain struct")),
            Self::Transfer(t) => ("transfer", serde_json::to_value(WireMetaTransfer::from_sol(t)).expect("plain struct")),
        }
    }

    pub fn from(&self) -> Address {
        match self {
            Self::Call(m) => m.from,
            Self::Transfer(t) => t.from,
        }
    }

    pub fn batch(&self) -> U256 {
        match self {
            Self::Call(m) => m.batch,
            Self::Transfer(t) => t.batch,
        }
    }

    pub fn nonce(&self) -> U256 {
        match self {
            Self::Call(m) => m.nonce,
            Self::Transfer(t) => t.nonce,
        }
    }

    pub fn valid_until(&self) -> U256 {
        match self {
            Self::Call(m) => m.validUntil,
            Self::Transfer(t) => t.validUntil,
        }
    }

    pub fn mode(&self) -> u32 {
        match self {
            Self::Call(m) => m.mode,
            Self::Transfer(t) => t.mode,
        }
    }

    pub fn relayer(&self) -> Address {
        match self {
            Self::Call(m) => m.relayer,
            Self::Transfer(t) => t.relayer,
        }
    }

    pub fn fee(&self) -> U256 {
        match self {
            Self::Call(m) => m.fee,
            Self::Transfer(t) => t.fee,
        }
    }

    pub fn fee_recipient(&self) -> Address {
        match self {
            Self::Call(m) => m.feeRecipient,
            Self::Transfer(t) => t.feeRecipient,
        }
    }

    /// The selector a self-call runs (first 4 bytes of `data`); `None` for a `MetaTransfer`.
    pub fn selector(&self) -> Option<[u8; 4]> {
        match self {
            Self::Call(m) => m.data.get(..4).map(|s| s.try_into().expect("4 bytes")),
            Self::Transfer(_) => None,
        }
    }

    /// What the contract hashes: the unbound `relayer` / `feeRecipient` as 0.
    pub fn canonical(&self) -> Self {
        let mut c = self.clone();
        let mode = self.mode();
        c.set_unbound(if mode & MODE_RESTRICT_RELAYER == 0 { Some(Address::ZERO) } else { None },
            if mode & MODE_RESTRICT_FEE_RECIPIENT == 0 { Some(Address::ZERO) } else { None });
        c
    }

    fn set_unbound(&mut self, relayer: Option<Address>, fee_recipient: Option<Address>) {
        let (r, f) = match self {
            Self::Call(m) => (&mut m.relayer, &mut m.feeRecipient),
            Self::Transfer(t) => (&mut t.relayer, &mut t.feeRecipient),
        };
        if let Some(x) = relayer {
            *r = x;
        }
        if let Some(x) = fee_recipient {
            *f = x;
        }
    }

    /// R84: a field the mode does not bind is not signed, anyone could overwrite it (the token pays the fee to a
    /// non-zero `feeRecipient`) ⇒ never send the wire value. `fee_recipient` None ⇒ 0: the contract pays `msg.sender`.
    /// The digest is unchanged.
    pub fn normalize(&mut self, fee_recipient: Option<Address>) {
        let mode = self.mode();
        self.set_unbound(if mode & MODE_RESTRICT_RELAYER == 0 { Some(Address::ZERO) } else { None },
            if mode & MODE_RESTRICT_FEE_RECIPIENT == 0 { Some(fee_recipient.unwrap_or(Address::ZERO)) } else { None });
    }

    pub fn digest(&self, domain: &Domain) -> B256 {
        let d = domain.eip712();
        match self.canonical() {
            Self::Call(m) => m.eip712_signing_hash(&d),
            Self::Transfer(t) => t.eip712_signing_hash(&d),
        }
    }

    pub fn struct_hash(&self) -> B256 {
        match self.canonical() {
            Self::Call(m) => m.eip712_hash_struct(),
            Self::Transfer(t) => t.eip712_hash_struct(),
        }
    }

    /// The relayed calldata: `mtxExecute(m, sig)` or `mtxExecuteTransfer(t, sig)`.
    pub fn calldata(&self, signature: Bytes) -> Bytes {
        match self.clone() {
            Self::Call(m) => IToken::mtxExecuteCall { m, signature }.abi_encode().into(),
            Self::Transfer(t) => IToken::mtxExecuteTransferCall { t, signature }.abi_encode().into(),
        }
    }

    /// Inverse of `calldata`: `(mtx, signature)`, `None` for any other call.
    pub fn from_calldata(data: &[u8]) -> Option<(Self, Bytes)> {
        if let Ok(c) = IToken::mtxExecuteCall::abi_decode(data) {
            return Some((Self::Call(c.m), c.signature));
        }
        IToken::mtxExecuteTransferCall::abi_decode(data).ok().map(|c| (Self::Transfer(c.t), c.signature))
    }
}

/// `MetaTxLib.UA_POOL`: the one ERC-20 holder of every derived UA's balance.
pub fn ua_pool() -> Address {
    Address::from_word(keccak256("scaas.ua.pool.v1"))
}

/// A native id (accounts.md §1.3: the top 96 bits zero) as its address; `None` for a derived UA.
pub fn native(id: &B256) -> Option<Address> {
    (id[..12] == [0; 12]).then(|| Address::from_word(*id))
}

/// `WireUAMetaTransaction` / `WireUAMetaTransfer` (job-api.md `ua_metatx`): the address structs' wire fields with `from`
/// (and `to`) as `bytes32`.
pub type WireUAMetaTx = WireMetaTx;
pub type WireUAMetaTransfer = WireMetaTransfer;

impl WireMetaTx {
    pub fn to_ua_sol(&self) -> Result<UAMetaTransaction> {
        let m = Self { from: format!("{:#x}", Address::ZERO), ..self.clone() }.to_sol()?;
        Ok(UAMetaTransaction { from: b32(&self.from)?, data: m.data, batch: m.batch, nonce: m.nonce, validUntil: m.validUntil,
            mode: m.mode, relayer: m.relayer, fee: m.fee, feeRecipient: m.feeRecipient })
    }
}

impl WireMetaTransfer {
    pub fn to_ua_sol(&self) -> Result<UAMetaTransfer> {
        let z = format!("{:#x}", Address::ZERO);
        let t = Self { from: z.clone(), to: z, ..self.clone() }.to_sol()?;
        Ok(UAMetaTransfer { from: b32(&self.from)?, to: b32(&self.to)?, value: t.value, entryRef: t.entryRef, batch: t.batch,
            nonce: t.nonce, validUntil: t.validUntil, mode: t.mode, relayer: t.relayer, fee: t.fee, feeRecipient: t.feeRecipient })
    }
}

/// One signed meta-transaction on ids (CTR-UA-26, CTR-MTX-30), either struct: `UAMetaTransaction` (`struct = call`, a
/// self-call on the contract's allowlist: `_uaAllowed` for a derived id, `_mtxRule` for a native one) or `UAMetaTransfer`
/// (`struct = transfer`), on the one nonce map of the token, digest `mtxDigest` / `mtxTransferDigest` in the token's salted
/// domain. A native id (an address zero-padded) signs with its own key, no registry (ua-mtx-merge C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UaMtx {
    Call(UAMetaTransaction),
    Transfer(UAMetaTransfer),
}

macro_rules! ua_field {
    ($s:expr, $f:ident) => {
        match $s {
            UaMtx::Call(m) => m.$f,
            UaMtx::Transfer(t) => t.$f,
        }
    };
}

impl UaMtx {
    /// As [`Mtx::from_wire`]; `from` (and `to`) are `bytes32` ids.
    pub fn from_wire(kind: Option<&str>, m: &Value) -> Result<Self> {
        match kind.unwrap_or("transfer") {
            "call" => Ok(Self::Call(serde_json::from_value::<WireMetaTx>(m.clone())?.to_ua_sol()?)),
            "transfer" => Ok(Self::Transfer(serde_json::from_value::<WireMetaTransfer>(m.clone())?.to_ua_sol()?)),
            k => bail!("unknown struct {k:?} (call | transfer)"),
        }
    }

    pub fn to_wire(&self) -> (&'static str, Value) {
        let id = |b: &B256| format!("{b:#x}");
        match self {
            Self::Call(m) => ("call", serde_json::to_value(WireMetaTx {
                from: id(&m.from), data: format!("0x{}", alloy::hex::encode(&m.data)), batch: m.batch.to_string(),
                nonce: m.nonce.to_string(), valid_until: m.validUntil.to_string(), mode: m.mode,
                relayer: format!("{:#x}", m.relayer), fee: m.fee.to_string(), fee_recipient: format!("{:#x}", m.feeRecipient),
            }).expect("plain struct")),
            Self::Transfer(t) => ("transfer", serde_json::to_value(WireMetaTransfer {
                from: id(&t.from), to: id(&t.to), value: t.value.to_string(), entry_ref: id(&t.entryRef),
                batch: t.batch.to_string(), nonce: t.nonce.to_string(), valid_until: t.validUntil.to_string(), mode: t.mode,
                relayer: format!("{:#x}", t.relayer), fee: t.fee.to_string(), fee_recipient: format!("{:#x}", t.feeRecipient),
            }).expect("plain struct")),
        }
    }

    pub fn from(&self) -> B256 {
        ua_field!(self, from)
    }

    pub fn batch(&self) -> U256 {
        ua_field!(self, batch)
    }

    pub fn nonce(&self) -> U256 {
        ua_field!(self, nonce)
    }

    pub fn valid_until(&self) -> U256 {
        ua_field!(self, validUntil)
    }

    pub fn mode(&self) -> u32 {
        ua_field!(self, mode)
    }

    pub fn relayer(&self) -> Address {
        ua_field!(self, relayer)
    }

    pub fn fee(&self) -> U256 {
        ua_field!(self, fee)
    }

    pub fn fee_recipient(&self) -> Address {
        ua_field!(self, feeRecipient)
    }

    fn unbound(&mut self, relayer: Option<Address>, fee_recipient: Option<Address>) {
        let mode = ua_field!(self, mode);
        let (r, f) = match self {
            Self::Call(m) => (&mut m.relayer, &mut m.feeRecipient),
            Self::Transfer(t) => (&mut t.relayer, &mut t.feeRecipient),
        };
        if mode & MODE_RESTRICT_RELAYER == 0 {
            *r = relayer.unwrap_or(Address::ZERO);
        }
        if mode & MODE_RESTRICT_FEE_RECIPIENT == 0 {
            *f = fee_recipient.unwrap_or(Address::ZERO);
        }
    }

    /// R84 as [`Mtx::normalize`]: an unbound `relayer` is sent as 0, an unbound `feeRecipient` as `fee_recipient`.
    pub fn normalize(&mut self, fee_recipient: Option<Address>) {
        self.unbound(None, fee_recipient);
    }

    /// The digest the token computes (`MetaTxLib.hashStruct` zeroes the unbound fields).
    pub fn digest(&self, domain: &Domain) -> B256 {
        let mut c = self.clone();
        c.unbound(None, None);
        let d = domain.eip712();
        match c {
            Self::Call(m) => m.eip712_signing_hash(&d),
            Self::Transfer(t) => t.eip712_signing_hash(&d),
        }
    }

    /// The struct hash the digest is over (`MetaTxLib.hashStruct`, unbound fields zero).
    pub fn struct_hash(&self) -> B256 {
        let mut c = self.clone();
        c.unbound(None, None);
        match c {
            Self::Call(m) => m.eip712_hash_struct(),
            Self::Transfer(t) => t.eip712_hash_struct(),
        }
    }

    /// The relayed calldata: `mtxExecute(m, auth)` / `mtxExecuteTransfer(t, auth)`, `auth` the `UASig` (R47: no packed bytes).
    pub fn calldata(&self, auth: UASig) -> Bytes {
        match self.clone() {
            Self::Call(m) => IMtxIds::mtxExecuteCall { m, auth }.abi_encode().into(),
            Self::Transfer(t) => IMtxIds::mtxExecuteTransferCall { t, auth }.abi_encode().into(),
        }
    }

    /// Inverse of `calldata`, and of a pay entry's `mtxPay(t, auth, meta)` (pay-meta-tax spec §2.1: its `UAMetaTransfer` is
    /// the transfer): `(mtx, auth)`, `None` for any other call.
    pub fn from_calldata(data: &[u8]) -> Option<(Self, UASig)> {
        if let Ok(c) = IMtxIds::mtxExecuteCall::abi_decode(data) {
            return Some((Self::Call(c.m), c.auth));
        }
        if let Ok(c) = IMtxIds::mtxPayCall::abi_decode(data) {
            return Some((Self::Transfer(c.t), c.auth));
        }
        IMtxIds::mtxExecuteTransferCall::abi_decode(data).ok().map(|c| (Self::Transfer(c.t), c.auth))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn kat(name: &str) -> Value {
        let p = format!("{}/../smartcontracts/evm/test/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(p).expect("KAT file")).expect("KAT json")
    }

    fn domain_of(k: &Value) -> Domain {
        let s = |f: &str| k[f].as_str().expect(f).to_string();
        Domain {
            name: s("domain_name"),
            version: s("domain_version"),
            chain_id: s("chain_id").parse().unwrap(),
            verifying_contract: s("verifying_contract").parse().unwrap(),
            salt: s("salt").parse().unwrap(),
        }
    }

    fn sig_of(k: &Value) -> Bytes {
        alloy::hex::decode(&k["signature"].as_str().unwrap()[2..]).unwrap().into()
    }

    /// Byte-identical with forge (`TokenKat.t.sol`): struct hash, digest and the relayed `mtxExecute` calldata.
    /// ua-mtx-merge T2: the address KATs are in the vectors' legacy place (the token takes the UA structs; T14 moves
    /// the node's token jobs to them).
    #[test]
    fn call_digest_and_calldata_match_forge_kat() {
        let k = kat("legacy/ua-mtx-merge/metatx_kat.json");
        let s = |f: &str| k[f].as_str().expect(f).to_string();
        let wire = json!({"from": s("from"), "data": s("data"), "batch": s("batch"), "nonce": s("nonce"),
            "validUntil": s("valid_until"), "mode": s("mode").parse::<u32>().unwrap(), "relayer": s("relayer"),
            "fee": s("fee"), "feeRecipient": s("fee_recipient")});
        let m = Mtx::from_wire(Some("call"), &wire).unwrap();
        assert_eq!(format!("{:#x}", m.struct_hash()), s("struct_hash").to_lowercase());
        assert_eq!(format!("{:#x}", m.digest(&domain_of(&k))), s("digest").to_lowercase());
        assert_eq!(format!("0x{}", alloy::hex::encode(m.calldata(sig_of(&k)))), s("calldata").to_lowercase());
        assert_eq!(Mtx::from_calldata(&m.calldata(sig_of(&k))), Some((m.clone(), sig_of(&k))));
        assert_eq!(m.selector(), Some([0xcf, 0xdd, 0x7a, 0xea]), "cancelNonce(uint256)");
    }

    #[test]
    fn transfer_digest_and_calldata_match_forge_kat() {
        let k = kat("legacy/ua-mtx-merge/metatransfer_kat.json");
        let s = |f: &str| k[f].as_str().expect(f).to_string();
        let wire = json!({"from": s("from"), "to": s("to"), "value": s("value"), "entryRef": s("entry_ref"),
            "batch": s("batch"), "nonce": s("nonce"), "validUntil": s("valid_until"),
            "mode": s("mode").parse::<u32>().unwrap(), "relayer": s("relayer"), "fee": s("fee"),
            "feeRecipient": s("fee_recipient")});
        let t = Mtx::from_wire(None, &wire).unwrap();
        assert!(matches!(t, Mtx::Transfer(_)), "absent struct = transfer");
        assert_eq!(format!("{:#x}", t.struct_hash()), s("struct_hash").to_lowercase());
        assert_eq!(format!("{:#x}", t.digest(&domain_of(&k))), s("digest").to_lowercase());
        assert_eq!(format!("0x{}", alloy::hex::encode(t.calldata(sig_of(&k)))), s("calldata").to_lowercase());
        assert_eq!(t.selector(), None);
    }

    fn call() -> Mtx {
        Mtx::Call(MetaTransaction {
            from: Address::repeat_byte(0xab),
            data: Bytes::from_static(&[1, 2, 3, 4]),
            batch: U256::from(7),
            nonce: U256::ZERO,
            validUntil: U256::from(1_800_000_300u64),
            mode: MODE_RESTRICT_RELAYER,
            relayer: Address::repeat_byte(0x02),
            fee: U256::ZERO,
            feeRecipient: Address::ZERO,
        })
    }

    fn domain() -> Domain {
        Domain { name: "SCaaS MetaToken".into(), version: "1".into(), chain_id: 7622,
                 verifying_contract: Address::repeat_byte(0xcd), salt: B256::repeat_byte(0x24) }
    }

    #[test]
    fn unflagged_fields_do_not_change_the_digest_and_the_salt_does() {
        let d = domain();
        let a = call().digest(&d);
        let Mtx::Call(mut m) = call() else { unreachable!() };
        m.feeRecipient = Address::repeat_byte(0x11);
        assert_eq!(a, Mtx::Call(m.clone()).digest(&d));
        m.mode |= MODE_RESTRICT_FEE_RECIPIENT;
        assert_ne!(a, Mtx::Call(m).digest(&d));
        assert_ne!(a, call().digest(&Domain { salt: B256::repeat_byte(0x25), ..d }), "chain_uid is signed");
    }

    #[test]
    fn normalize_zeroes_unbound_fields_and_keeps_the_digest() {
        let d = domain();
        let Mtx::Call(mut m) = call() else { unreachable!() };
        m.mode = 0x20;
        m.relayer = Address::repeat_byte(0x66);
        m.feeRecipient = Address::repeat_byte(0x77);
        let wire = Mtx::Call(m.clone());
        let mut x = wire.clone();
        x.normalize(Some(Address::repeat_byte(0x99)));
        assert_eq!((x.relayer(), x.fee_recipient()), (Address::ZERO, Address::repeat_byte(0x99)));
        assert_eq!(x.digest(&d), wire.digest(&d));
        let mut bound = Mtx::Call(MetaTransaction { mode: 0x23, ..m });
        let before = bound.clone();
        bound.normalize(Some(Address::repeat_byte(0x99)));
        assert_eq!(bound, before, "bound fields are untouched");
    }

    #[test]
    fn wire_rejects_garbage_and_the_other_struct() {
        let (_, good) = call().to_wire();
        let bad = |f: &str, v: Value| {
            let mut w = good.clone();
            w[f] = v;
            Mtx::from_wire(Some("call"), &w).is_err()
        };
        assert!(bad("batch", json!("01")));
        assert!(bad("from", json!("0x12")));
        assert!(bad("mode", json!(4)));
        assert!(bad("mode", json!(0x30)), "fee nibble 3 (ModeFeeInvalid)");
        assert!(bad("data", json!("zz")));
        assert!(bad("value", json!("1")), "a transfer field in a call");
        assert!(Mtx::from_wire(None, &good).is_err(), "a call body is not a transfer");
        assert!(Mtx::from_wire(Some("ua"), &good).is_err());
        let (_, mut transfer) = Mtx::Transfer(MetaTransfer {
            from: Address::repeat_byte(0xab), to: Address::repeat_byte(0x5e), value: U256::from(1), entryRef: B256::ZERO,
            batch: U256::ZERO, nonce: U256::ZERO, validUntil: U256::from(1), mode: 0, relayer: Address::ZERO,
            fee: U256::ZERO, feeRecipient: Address::ZERO,
        }).to_wire();
        assert!(Mtx::from_wire(None, &transfer).is_ok());
        transfer["data"] = json!("0x");
        assert!(Mtx::from_wire(None, &transfer).is_err(), "a call field in a transfer (N1, the reverse)");
    }

    #[test]
    fn wire_round_trips() {
        let (kind, w) = call().to_wire();
        assert_eq!(Mtx::from_wire(Some(kind), &w).unwrap(), call());
    }

    /// `ua_metatx` (CTR-UA-26): the node's UA digests are the clientkeys vectors' (`vectors/ua/metatx3.json`, every
    /// signer kind, both structs), the wire round-trips, and the relayed calldata decodes back to its struct.
    #[test]
    fn ua_digests_match_the_metatx3_vectors() {
        let v: Value = serde_json::from_str(include_str!("../../smartcontracts/vectors/ua/metatx3.json")).unwrap();
        let s = |k: &Value| k.as_str().unwrap().to_string();
        let d = Domain { name: "SCaaS MetaToken".into(), version: "1".into(), chain_id: v["chainId"].as_u64().unwrap(),
            verifying_contract: s(&v["token"]).parse().unwrap(), salt: s(&v["chainUid"]).parse().unwrap() };
        let mut n = 0;
        for (sec, kind) in [("call", "call"), ("transfer", "transfer")] {
            for x in v[sec].as_array().unwrap() {
                let m = UaMtx::from_wire(Some(kind), &x["typedData"]["message"]).unwrap();
                assert_eq!(format!("{:#x}", m.digest(&d)), s(&x["digest"]), "{sec} {}", x["name"]);
                assert_eq!(m.from(), s(&x["from"]).parse::<B256>().unwrap());
                let (k, w) = m.to_wire();
                assert_eq!((k, UaMtx::from_wire(Some(k), &w).unwrap()), (kind, m.clone()), "wire round-trip");
                let auth = UASig { keyData: Bytes::new(), signature: alloy::hex::decode(&s(&x["auth"])[2..]).unwrap().into(), members: vec![] };
                assert_eq!(format!("{:#x}", m.struct_hash()), s(&x["structHash"]), "{sec} {}", x["name"]);
                assert_eq!(UaMtx::from_calldata(&m.calldata(auth.clone())), Some((m, auth)));
                n += 1;
            }
        }
        assert_eq!(n, 22, "11 signer kinds x 2 structs");
    }

    /// A UA body names ids: an address `from` is refused (the address structs' wire is not the UA one), as is the other
    /// struct; unbound fields are normalized as on the address path and leave the digest alone.
    #[test]
    fn ua_wire_needs_bytes32_ids_and_normalizes() {
        let v: Value = serde_json::from_str(include_str!("../../smartcontracts/vectors/ua/metatx3.json")).unwrap();
        let msg = v["transfer"][0]["typedData"]["message"].clone();
        let mut addr_from = msg.clone();
        addr_from["from"] = json!("0xfc7e9498d8035077f1705eb85be95d66f31a89f9");
        assert!(UaMtx::from_wire(None, &addr_from).is_err(), "from is a bytes32 id");
        assert!(UaMtx::from_wire(Some("call"), &msg).is_err(), "a transfer body is no call");
        assert!(UaMtx::from_wire(Some("ua"), &msg).is_err());
        let UaMtx::Transfer(t) = UaMtx::from_wire(None, &msg).unwrap() else { panic!() };
        assert_eq!(native(&t.from), Some("0xfc7e9498d8035077f1705eb85be95d66f31a89f9".parse().unwrap()));
        assert_eq!(native(&B256::repeat_byte(1)), None, "a derived id");
        let d = domain();
        let mut free = UaMtx::Transfer(UAMetaTransfer { mode: 0x20, relayer: Address::repeat_byte(6), feeRecipient: Address::repeat_byte(7), ..t });
        let before = free.digest(&d);
        free.normalize(Some(Address::repeat_byte(9)));
        let UaMtx::Transfer(n) = &free else { unreachable!() };
        assert_eq!((n.relayer, n.feeRecipient), (Address::ZERO, Address::repeat_byte(9)));
        assert_eq!(free.digest(&d), before, "the digest is unchanged");
    }

    /// pay-meta-tax T42: `mtxPay(t, auth, meta)` decodes to its `UAMetaTransfer`; `metaPayId` v2 of the paymeta.json rows; the
    /// shape and `payNo` bound refused by name.
    #[test]
    fn mtx_pay_decodes_and_meta_pay_id_v2_rows() {
        let t = UAMetaTransfer { from: B256::repeat_byte(0xaa), to: B256::repeat_byte(0x5e), value: U256::from(10), entryRef: B256::ZERO,
            batch: U256::from(7), nonce: U256::ZERO, validUntil: U256::from(1_800_000_300u64), mode: MODE_RESTRICT_RELAYER,
            relayer: Address::repeat_byte(2), fee: U256::ZERO, feeRecipient: Address::ZERO };
        let auth = UASig { keyData: Bytes::new(), signature: Bytes::from_static(&[7; 65]), members: vec![] };
        let meta = crate::abi::PayMeta { salt: B256::repeat_byte(0x51), payNo: "INV-1".into(), schema: 0, body: Bytes::new() };
        let cd = IMtxIds::mtxPayCall { t: t.clone(), auth: auth.clone(), meta: meta.clone() }.abi_encode();
        assert_eq!(UaMtx::from_calldata(&cd), Some((UaMtx::Transfer(t), auth)));
        let rows: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../../smartcontracts/vectors/metatx/paymeta.json")).unwrap();
        assert_eq!(rows.len(), 9);
        for r in &rows {
            let h = |k: &str| alloy::hex::decode(r[k].as_str().unwrap().trim_start_matches("0x")).unwrap();
            let m = crate::abi::PayMeta { salt: B256::from_slice(&h("salt")), payNo: r["payNo"].as_str().unwrap().into(),
                schema: r["schema"].as_u64().unwrap() as u16, body: h("body").into() };
            if r["accepted"].as_bool().unwrap() {
                check_pay_meta(&m).unwrap();
                assert_eq!(meta_pay_id(&m), B256::from_slice(&h("payId")), "{}", r["name"]);
            } else {
                assert!(check_pay_meta(&m).unwrap_err().to_string().starts_with("PAY_NO_TOO_LONG"), "{}", r["name"]);
            }
        }
        assert!(check_pay_meta(&crate::abi::PayMeta { salt: B256::ZERO, ..meta.clone() }).unwrap_err().to_string().starts_with("PAY_META_SHAPE"));
        assert!(check_pay_meta(&crate::abi::PayMeta { body: Bytes::from_static(b"x"), ..meta }).unwrap_err().to_string().starts_with("PAY_META_SHAPE"));
    }
}
