//! `intent_id` (R78) và trường định tuyến theo họ (spec mesh §4.4), giải mã từ payload ĐÃ KÝ bằng đúng các
//! decoder của adapter — không có bộ mã hoá họ mới. Mới duy nhất: struct JSON `MetaOp` của Cosmos (adapter Cosmos
//! để contract tự parse) và công thức `derived_object` của Sui (`fam_sui.derive_account`).
use alloy::primitives::{Address, Bytes, Signature, B256, U256};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::accept::ChainInfo;
use super::envelope::Envelope;
use super::Code;
use crate::adapters::{aptos, solana, sui, ton};
use crate::metatx::{native, Domain, Mtx, UASig, UaMtx, MODE_FEE_MASK, MODE_RESTRICT_FEE_RECIPIENT, MODE_RESTRICT_RELAYER};

const METAOP_DOMAIN: &str = "scaas.metaop.v1";

/// The signed struct of an EVM body (R45): a token's or a mandate wallet's UA struct with its `UASig` (`evm.ua_meta_tx`,
/// NODE-MESH-18), or `SmartKeyAccount`'s address `MetaTransaction` (`evm.meta_tx`, Q6).
#[derive(Debug, Clone)]
pub enum Meta {
    Address(Mtx),
    Ua(UaMtx, UASig),
}

macro_rules! both {
    ($m:expr, $f:ident $(, $a:expr)?) => {
        match $m {
            Meta::Address(m) => m.$f($($a)?),
            Meta::Ua(m, _) => m.$f($($a)?),
        }
    };
}

/// Phần EVM mà L2 còn kiểm sau hạn (§7.2) và submitter dùng để dựng `Work`.
#[derive(Debug, Clone)]
pub struct Evm {
    pub meta: Meta,
    /// Who signs: the address body's `from`, the UA body's native id as its address (MD-10: no derived `from`).
    pub signer: Address,
    /// The address body's `signature`, the UA body's `auth.signature`.
    pub signature: Bytes,
    pub eoa: bool,
}

impl Evm {
    /// R84: the struct the submitter encodes, as its wire JSON: an unbound `relayer` 0, an unbound `feeRecipient`
    /// `fee_recipient` (NODE-LANE-10); the digest is unchanged.
    pub fn submit_wire(&self, fee_recipient: Option<Address>) -> (&'static str, Value) {
        match self.meta.clone() {
            Meta::Address(mut m) => {
                m.normalize(fee_recipient);
                m.to_wire()
            }
            Meta::Ua(mut m, _) => {
                m.normalize(fee_recipient);
                m.to_wire()
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Decoded {
    pub intent_id: [u8; 32],
    pub from: String,
    /// EVM: `batch` thập phân; họ khác: `0x` + hex của lane.
    pub lane: String,
    pub nonce: String,
    pub valid_until: u64,
    /// `None` = không ràng buộc relayer.
    pub relayer: Option<String>,
    /// EVM, chỉ khi `MODE_RESTRICT_FEE_RECIPIENT`.
    pub fee_recipient: Option<String>,
    pub fee_effective: U256,
    pub selector: String,
    /// `token_of` (R86).
    pub token: String,
    /// Kiểm dẫn xuất account §4.4 (`contract` là account của chính `from` dưới `token`); luôn đúng ở EVM/Cosmos.
    pub account_ok: bool,
    pub evm: Option<Evm>,
}

#[derive(Deserialize)]
struct EvmName {
    name: String,
    version: String,
}

/// `evm` body (mesh.md §3.3): `struct` = `call` | `transfer` (absent = `transfer`) and either the UA body (`ua_meta_tx`, the
/// wire `UAMetaTransaction` / `UAMetaTransfer` with `from` / `to` as ids, and `auth`, the `UASig` JSON; R45) or the address
/// body (`meta_tx`, the wire `MetaTransaction`, and `signature`; `SmartKeyAccount`), never both.
#[derive(Deserialize)]
struct EvmBody {
    domain: EvmName,
    #[serde(default, rename = "struct")]
    struct_: Option<String>,
    #[serde(default)]
    meta_tx: Option<Value>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    ua_meta_tx: Option<Value>,
    #[serde(default)]
    auth: Option<Value>,
    sig_kind: String,
}

#[derive(Deserialize)]
struct OpBody {
    op_kind: String,
    payload: String,
    #[serde(default)]
    extra: Value,
}

/// `chains/cosmos/metaop` `MetaOp` (cùng `deny_unknown_fields` với contract). `amount` là `Uint128` (chuỗi).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CosmosMetaOp {
    pub amount: String,
    pub contract: String,
    pub domain: String,
    pub extra: String,
    pub from: String,
    pub lane: String,
    pub network: String,
    pub nonce: u64,
    pub op: String,
    pub pay_ref: String,
    pub relayer: String,
    pub to: String,
    pub valid_until: u64,
}

const BAD: Code = Code::BadEnvelope;

fn hex0x(b: &[u8]) -> String {
    format!("0x{}", alloy::hex::encode(b))
}

fn bytes0x(s: &str) -> Result<Vec<u8>, Code> {
    let h = s.strip_prefix("0x").ok_or(BAD)?;
    if h.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(BAD);
    }
    alloy::hex::decode(h).map_err(|_| BAD)
}

/// `FeePolicy.compute` (NONE ⇒ 0, PERCENT ⇒ value × fee / 10^6, FIXED ⇒ fee); chặn trên khi tràn — mô phỏng phân xử.
/// A PERCENT `MetaTransaction`'s basis is an argument of its selector (`mtxSelectors()`, NODE-JOB-20), which this pure
/// layer does not read: it counts 0, so a `min_fee` floor never over-admits it.
/// `value` is a transfer's (`None` for a call).
pub fn fee_effective(mode: u32, value: Option<U256>, fee: U256) -> U256 {
    match ((mode & MODE_FEE_MASK) >> 4, value) {
        (1, Some(v)) => v.saturating_mul(fee) / U256::from(1_000_000u64),
        (2, _) => fee,
        _ => U256::ZERO,
    }
}

/// Sui `derived_object::derive_address(registry, owner)` — `Account<T>` của `owner` (`fam_sui.derive_account`).
pub fn sui_account(registry: &str, owner: &str) -> anyhow::Result<String> {
    let (r, o) = (sui::parse_addr(registry)?, sui::parse_addr(owner)?);
    let mut b = vec![0xf0];
    b.extend_from_slice(&r);
    b.extend_from_slice(&32u64.to_le_bytes());
    b.extend_from_slice(&o);
    // TypeTag BCS của `0x2::derived_object::DerivedObjectKey<address>`.
    b.push(7);
    b.extend_from_slice(&sui::parse_addr("0x2")?);
    b.extend_from_slice(b"\x0ederived_object\x10DerivedObjectKey\x01\x04");
    Ok(sui::addr_hex(&crate::signer::blake2b256(&b)))
}

fn nonzero(a: &[u8; 32], show: impl Fn(&[u8; 32]) -> String) -> Option<String> {
    (a != &[0; 32]).then(|| show(a))
}

/// L2 phần giải mã: tính lại `intent_id` và đọc trường định tuyến; `network`/`contract` trong payload phải khớp
/// `chain_key`/`contract` của envelope.
pub fn decode(env: &Envelope, chain: &ChainInfo) -> Result<Decoded, Code> {
    match env.family.as_str() {
        "evm" | "hedera" => evm(env, chain),
        _ => {
            let body: OpBody = serde_json::from_value(env.body().clone()).map_err(|_| BAD)?;
            if body.op_kind != "pay" {
                return Err(BAD); // v1: chỉ `pay` (R77, M6)
            }
            let payload = bytes0x(&body.payload)?;
            let extra = |k: &str| body.extra.get(k).and_then(Value::as_str);
            match env.family.as_str() {
                "cosmos" => cosmos(env, &payload),
                "sui" => sui_op(env, &payload, extra("registry")),
                "aptos" => aptos_op(env, &payload, chain),
                "ton" => ton_op(env, &payload, extra("jetton_master"), chain),
                "solana" => solana_op(env, &payload, extra("asset"), chain),
                _ => Err(Code::FamilyNotSupported),
            }
        }
    }
}

fn evm(env: &Envelope, chain: &ChainInfo) -> Result<Decoded, Code> {
    let b: EvmBody = serde_json::from_value(env.body().clone()).map_err(|_| BAD)?;
    // The salt is the receiver's own `chain_uid`, never a value from the envelope (NODE-MESH-08).
    let salt = chain.chain_uid.ok_or(Code::UnknownChain)?;
    let contract: Address = env.contract.parse().map_err(|_| BAD)?;
    if format!("{contract:#x}") != env.contract {
        return Err(BAD);
    }
    // MODE_KNOWN_MASK, nibble phí ≤ 2 (`from_wire`)
    let (meta, signer, signature) = match (b.meta_tx, b.signature, b.ua_meta_tx, b.auth) {
        (None, None, Some(m), Some(auth)) => {
            if env.minor() < 3 {
                return Err(BAD); // NODE-MESH-18: the UA body is scaas-intent/1.3
            }
            let m = UaMtx::from_wire(b.struct_.as_deref(), &m).map_err(|_| BAD)?;
            let signer = native(&m.from()).ok_or(Code::DerivedFromUnsupported)?; // MD-10
            let auth = crate::dex::ua_sig(&auth).map_err(|_| BAD)?; // bounded: the type's depth, 16 slots a level
            if !auth.keyData.is_empty() || !auth.members.is_empty() {
                return Err(Code::BadSignature); // R17: a native id signs with its own key, its signature only
            }
            let sig = auth.signature.clone();
            (Meta::Ua(m, auth), signer, sig)
        }
        (Some(m), Some(sig), None, None) => {
            let m = Mtx::from_wire(b.struct_.as_deref(), &m).map_err(|_| BAD)?;
            // R45: no contract has an address `MetaTransfer` entry, a token no address entry (CTR-MTX-30)
            if matches!(m, Mtx::Transfer(_)) || chain.tokens.contains(&env.contract) {
                return Err(Code::OpKindMismatch);
            }
            let from = m.from();
            (Meta::Address(m), from, bytes0x(&sig)?.into())
        }
        _ => return Err(BAD),
    };
    let eoa = match b.sig_kind.as_str() {
        "eoa" => true,
        "erc1271" => false,
        _ => return Err(BAD),
    };
    let domain = Domain {
        name: b.domain.name,
        version: b.domain.version,
        chain_id: env.network().parse().map_err(|_| BAD)?,
        verifying_contract: contract,
        salt,
    };
    let (data, transfer) = match &meta {
        Meta::Address(Mtx::Call(c)) => (Some(&c.data), None),
        Meta::Ua(UaMtx::Call(c), _) => (Some(&c.data), None),
        Meta::Address(Mtx::Transfer(t)) => (None, Some((t.value, t.entryRef))),
        Meta::Ua(UaMtx::Transfer(t), _) => (None, Some((t.value, t.entryRef))),
    };
    let selector = match (data, transfer) {
        (Some(d), _) => hex0x(&d[..d.len().min(4)]),
        (_, Some((_, r))) if r.is_zero() => "transfer".into(),
        _ => "pay".into(),
    };
    let mode = both!(&meta, mode);
    Ok(Decoded {
        intent_id: both!(&meta, digest, &domain).0,
        from: format!("{signer:#x}"),
        lane: both!(&meta, batch).to_string(),
        nonce: both!(&meta, nonce).to_string(),
        valid_until: u64::try_from(both!(&meta, valid_until)).unwrap_or(u64::MAX),
        relayer: (mode & MODE_RESTRICT_RELAYER != 0).then(|| format!("{:#x}", both!(&meta, relayer))),
        fee_recipient: (mode & MODE_RESTRICT_FEE_RECIPIENT != 0).then(|| format!("{:#x}", both!(&meta, fee_recipient))),
        fee_effective: fee_effective(mode, transfer.map(|t| t.0), both!(&meta, fee)),
        selector,
        token: env.contract.clone(),
        account_ok: true,
        evm: Some(Evm { meta, signer, signature, eoa }),
    })
}

/// L2 EVM sau kiểm hạn (§4.4): relayer ràng buộc mà bằng 0 là intent chết; `eoa` ⇒ `ecrecover == from`, low-s,
/// `v ∈ {27, 28}` như `ECDSA.tryRecover` của contract.
pub fn check_evm(e: &Evm, intent_id: &[u8; 32]) -> Result<(), Code> {
    if both!(&e.meta, mode) & MODE_RESTRICT_RELAYER != 0 && both!(&e.meta, relayer) == Address::ZERO {
        return Err(Code::RelayerBoundZero);
    }
    if !e.eoa {
        return Ok(()); // ERC-1271: ví hợp đồng, không khôi phục cục bộ; hub.sig ràng buộc chữ ký qua body_hash
    }
    let s = &e.signature;
    let ok = s.len() == 65
        && matches!(s[64], 27 | 28)
        && Signature::try_from(s.as_ref()).is_ok_and(|sig| {
            sig.normalize_s().is_none() && sig.recover_address_from_prehash(&B256::from(*intent_id)).ok() == Some(e.signer)
        });
    ok.then_some(()).ok_or(Code::BadSignature)
}

fn cosmos(env: &Envelope, payload: &[u8]) -> Result<Decoded, Code> {
    let op: CosmosMetaOp = serde_json::from_slice(payload).map_err(|_| BAD)?;
    let lane = super::envelope::hex_n(&op.lane, 32, false).ok_or(BAD)?;
    if op.domain != METAOP_DOMAIN || op.network != env.network() || op.contract != env.contract || op.op != "pay" {
        return Err(BAD);
    }
    Ok(Decoded {
        intent_id: Sha256::digest(payload).into(),
        from: op.from,
        lane: hex0x(&lane),
        nonce: op.nonce.to_string(),
        valid_until: op.valid_until,
        relayer: (!op.relayer.is_empty()).then_some(op.relayer),
        fee_recipient: None,
        fee_effective: U256::ZERO,
        selector: "pay".into(),
        token: op.contract,
        account_ok: true,
        evm: None,
    })
}

#[allow(clippy::too_many_arguments)]
fn op_fields(intent_id: [u8; 32], from: String, lane: &[u8], nonce: u64, valid_until: u64, relayer: Option<String>, token: String, account_ok: bool) -> Decoded {
    Decoded {
        intent_id,
        from,
        lane: hex0x(lane),
        nonce: nonce.to_string(),
        valid_until,
        relayer,
        fee_recipient: None,
        fee_effective: U256::ZERO,
        selector: "pay".into(),
        token,
        account_ok,
        evm: None,
    }
}

fn sui_op(env: &Envelope, payload: &[u8], registry: Option<&str>) -> Result<Decoded, Code> {
    let op = sui::MetaOp::decode(payload).map_err(|_| BAD)?;
    if op.op != 0 || op.network != env.network().as_bytes() || sui::addr_hex(&op.contract) != env.contract {
        return Err(BAD);
    }
    let from = sui::addr_hex(&op.from);
    let token = registry.and_then(|r| sui::parse_addr(r).ok()).map(|r| sui::addr_hex(&r)).unwrap_or_default();
    let account_ok = !token.is_empty() && sui_account(&token, &from).is_ok_and(|a| a == env.contract);
    let relayer = nonzero(&op.relayer, |a| sui::addr_hex(a));
    Ok(op_fields(sui::personal_digest(payload), from, &op.lane, op.nonce, op.valid_until, relayer, token, account_ok))
}

fn aptos_op(env: &Envelope, payload: &[u8], chain: &ChainInfo) -> Result<Decoded, Code> {
    let op = aptos::MetaOp::decode(payload).map_err(|_| BAD)?;
    if op.op != 0 || op.chain_id.to_string() != env.network() || aptos::addr_hex(&op.contract) != env.contract {
        return Err(BAD);
    }
    let package = chain.program.as_deref().and_then(|p| aptos::parse_addr(p).ok());
    let account_ok = package.is_some_and(|p| aptos::account_of(&p, &op.from) == op.contract);
    let relayer = nonzero(&op.relayer, |a| aptos::addr_hex(a));
    Ok(op_fields(aptos::sha3(payload), aptos::addr_hex(&op.from), &op.lane, op.nonce, op.valid_until, relayer, aptos::addr_hex(&op.asset), account_ok))
}

fn ton_op(env: &Envelope, payload: &[u8], master: Option<&str>, chain: &ChainInfo) -> Result<Decoded, Code> {
    let m = ton::boc_parse(payload).and_then(|c| ton::parse_metaop(&c)).map_err(|_| BAD)?;
    if m.op != 1 || m.network.to_string() != env.network() || m.contract.raw() != env.contract {
        return Err(BAD);
    }
    let master = master.and_then(|s| ton::Addr::parse(s).ok());
    let token = master.map(|a| a.raw()).unwrap_or_default();
    let account_ok = master.is_some_and(|ma| {
        chain.wallet_codes.get(&token).is_some_and(|(h, d)| ton::jetton_wallet_address(&m.from, &ma, h, *d).ok() == Some(m.contract))
    });
    Ok(op_fields(m.digest, m.from.raw(), &m.lane, m.nonce, m.valid_until, m.relayer.map(|a| a.raw()), token, account_ok))
}

fn solana_op(env: &Envelope, payload: &[u8], asset: Option<&str>, chain: &ChainInfo) -> Result<Decoded, Code> {
    let op = solana::MetaOp::decode(payload).map_err(|_| BAD)?;
    if op.op != 0 || solana::b58(&op.network) != env.network() || solana::b58(&op.contract) != env.contract {
        return Err(BAD);
    }
    let token = solana::b58(&op.asset);
    let program = chain.program.as_deref().and_then(|p| solana::key(p).ok());
    let account_ok = asset == Some(token.as_str()) && program.is_some_and(|p| solana::account_of(&p, &op.from) == op.contract);
    let relayer = nonzero(&op.relayer, |a| solana::b58(a));
    Ok(op_fields(Sha256::digest(payload).into(), solana::b58(&op.from), &op.lane, op.nonce, op.valid_until, relayer, token, account_ok))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn sui_account_matches_python_and_move() {
        // dms_blockchain/tests/test_fam_sui.py: REG_SUI, ALICE → ALICE_ACCOUNT.
        let a = sui_account("0x7c9575082976f063e7bfa16aa86ca20e1675b50efa7d5a64d1fa66ce127f5fdf",
                            "0x6a749c33bda66662e3709eea404a27dbb2b27d7a58bc0a1248d12436fb2fae71").unwrap();
        assert_eq!(a, "0xd4793a1919a40ebfe5587a3a49fe89bb64c54bd49c75ab2a08ac0d5636706382");
    }

    #[test]
    fn effective_fee_per_mode() {
        let z = format!("{:#x}", Address::ZERO);
        let w = |mode: u32| serde_json::json!({"from": z, "to": z, "value": "2000000",
            "entryRef": format!("{:#x}", B256::ZERO), "batch": "0", "nonce": "0", "validUntil": "1", "mode": mode,
            "relayer": z, "fee": if mode == 0 { "1000000000000000000000000000000" } else { "2500" }, "feeRecipient": z});
        let t = |mode| match Mtx::from_wire(Some("transfer"), &w(mode)).unwrap() {
            Mtx::Transfer(t) => fee_effective(t.mode, Some(t.value), t.fee),
            _ => unreachable!(),
        };
        assert_eq!(t(0), U256::ZERO, "NONE ignores fee");
        assert_eq!(t(0x10), U256::from(5000u64), "PERCENT: 2e6 × 2500 / 1e6");
        assert_eq!(t(0x20), U256::from(2500u64));
        let call = |mode: u32| fee_effective(mode, None, U256::from(2500u64));
        assert_eq!(call(0x10), U256::ZERO, "a PERCENT call's basis is not read here");
        assert_eq!(call(0x20), U256::from(2500u64));
    }

    proptest! {
        #[test]
        fn cosmos_decoder_never_panics(b in proptest::collection::vec(any::<u8>(), 0..400), s in "\\PC{0,300}") {
            let _ = serde_json::from_slice::<CosmosMetaOp>(&b);
            let _ = serde_json::from_str::<CosmosMetaOp>(&s);
        }
    }
}
