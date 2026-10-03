//! Định dạng dây (chuỗi, như Odoo và gateway gửi) ↔ struct Solidity, và digest canonical.
//! Quy tắc canonical-zeroing phải giống `MetaTxLib.canon` từng bit (spec §6).
use std::str::FromStr;

use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::sol_types::{Eip712Domain, SolStruct};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

pub use crate::abi::MetaTransaction;

pub const MODE_RESTRICT_RELAYER: u32 = 0x01;
pub const MODE_RESTRICT_FEE_RECIPIENT: u32 = 0x02;
pub const MODE_FEE_MASK: u32 = 0xF0;
pub const MODE_KNOWN_MASK: u32 = 0xF3;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WireMetaTx {
    pub from: String,
    pub to: String,
    pub value: String,
    pub data: String,
    pub batch: String,
    pub nonce: String,
    pub valid_until: String,
    pub mode: u32,
    pub relayer: String,
    pub fee: String,
    pub fee_recipient: String,
}

#[derive(Debug, Clone)]
pub struct Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: Address,
}

fn addr(s: &str) -> Result<Address> {
    if s.len() != 42 || !s.starts_with("0x") {
        bail!("not an address: {s}");
    }
    Address::from_str(s).map_err(|e| anyhow!("not an address {s}: {e}"))
}

fn uint(s: &str) -> Result<U256> {
    let canonical = !s.is_empty()
        && s.len() <= 78
        && s.bytes().all(|b| b.is_ascii_digit())
        && !(s.len() > 1 && s.starts_with('0'));
    if !canonical {
        bail!("not a canonical uint256: {s}");
    }
    U256::from_str_radix(s, 10).map_err(|e| anyhow!("uint256 {s}: {e}"))
}

impl WireMetaTx {
    pub fn to_sol(&self) -> Result<MetaTransaction> {
        let hex = self.data.strip_prefix("0x").ok_or_else(|| anyhow!("data must be 0x-hex"))?;
        let data = alloy::hex::decode(hex).map_err(|e| anyhow!("data: {e}"))?;
        if self.mode & !MODE_KNOWN_MASK != 0 || (self.mode & MODE_FEE_MASK) >> 4 > 2 {
            bail!("unknown mode bits {:#x}", self.mode);
        }
        Ok(MetaTransaction {
            from: addr(&self.from)?,
            to: addr(&self.to)?,
            value: uint(&self.value)?,
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
            to: format!("{:#x}", m.to),
            value: m.value.to_string(),
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

impl Domain {
    pub fn eip712(&self) -> Eip712Domain {
        Eip712Domain::new(
            Some(self.name.clone().into()),
            Some(self.version.clone().into()),
            Some(U256::from(self.chain_id)),
            Some(self.verifying_contract),
            None,
        )
    }
}

/// Bản đã canonical-zero hoá: cái MetaTxLib thực sự băm.
pub fn canonical(m: &MetaTransaction) -> MetaTransaction {
    let mut c = m.clone();
    if m.mode & MODE_RESTRICT_RELAYER == 0 {
        c.relayer = Address::ZERO;
    }
    if m.mode & MODE_RESTRICT_FEE_RECIPIENT == 0 {
        c.feeRecipient = Address::ZERO;
    }
    c
}

pub fn digest(domain: &Domain, m: &MetaTransaction) -> B256 {
    canonical(m).eip712_signing_hash(&domain.eip712())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kat() -> serde_json::Value {
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/test/vectors/metatx_kat.json");
        serde_json::from_str(&std::fs::read_to_string(p).expect("KAT file")).expect("KAT json")
    }

    fn sample() -> WireMetaTx {
        WireMetaTx {
            from: format!("{:#x}", Address::repeat_byte(0xab)),
            to: format!("{:#x}", Address::repeat_byte(0x01)),
            value: "100".into(),
            data: "0x".into(),
            batch: "7".into(),
            nonce: "0".into(),
            valid_until: "1800000300".into(),
            mode: MODE_RESTRICT_RELAYER,
            relayer: format!("{:#x}", Address::repeat_byte(0x02)),
            fee: "0".into(),
            fee_recipient: format!("{:#x}", Address::ZERO),
        }
    }

    fn sample_domain() -> Domain {
        Domain {
            name: "Bamboo MetaToken".into(),
            version: "1".into(),
            chain_id: 9000,
            verifying_contract: Address::repeat_byte(0xcd),
        }
    }

    #[test]
    fn digest_matches_forge_kat() {
        let k = kat();
        let s = |f: &str| k[f].as_str().expect(f).to_string();
        let wire = WireMetaTx {
            from: s("from"),
            to: s("to"),
            value: s("value"),
            data: s("data"),
            batch: s("batch"),
            nonce: s("nonce"),
            valid_until: s("valid_until"),
            mode: s("mode").parse().unwrap(),
            relayer: s("relayer"),
            fee: s("fee"),
            fee_recipient: s("fee_recipient"),
        };
        let domain = Domain {
            name: s("domain_name"),
            version: s("domain_version"),
            chain_id: s("chain_id").parse().unwrap(),
            verifying_contract: Address::from_str(&s("verifying_contract")).unwrap(),
        };
        let m = wire.to_sol().unwrap();
        assert_eq!(format!("{:#x}", canonical(&m).eip712_hash_struct()), s("struct_hash").to_lowercase());
        assert_eq!(format!("{:#x}", digest(&domain, &m)), s("digest").to_lowercase());
    }

    #[test]
    fn unflagged_fee_recipient_does_not_change_the_digest() {
        let mut m = sample().to_sol().unwrap();
        let d = sample_domain();
        let a = digest(&d, &m);
        m.feeRecipient = Address::repeat_byte(0x11);
        assert_eq!(a, digest(&d, &m));
        m.mode |= MODE_RESTRICT_FEE_RECIPIENT;
        assert_ne!(a, digest(&d, &m));
    }

    #[test]
    fn wire_rejects_garbage() {
        let mut w = sample();
        w.value = "01".into();
        assert!(w.to_sol().is_err());
        let mut w = sample();
        w.from = "0x12".into();
        assert!(w.to_sol().is_err());
        let mut w = sample();
        w.mode = 0x04;
        assert!(w.to_sol().is_err());
        let mut w = sample();
        w.data = "zz".into();
        assert!(w.to_sol().is_err());
    }

    #[test]
    fn wire_round_trips() {
        let m = sample().to_sol().unwrap();
        assert_eq!(WireMetaTx::from_sol(&m).to_sol().unwrap(), m);
    }
}
