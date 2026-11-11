//! Typed EIP-712 digests of every Zether op a Zether key signs or relays (typed-signing C7, TS-D14 / TS-D17 / TS-D19): the
//! struct of a merged entry (`UAZetherTransferSingle`, `UAZetherUnshield`, `UARollOver`, ...; ua-mtx-merge CTR-MTX-30: one
//! signed entry per operation, the address forms in legacy/ua-mtx-merge/), the wraps' address structs and the owner statements
//! (`ZetherRollOver`, `ZetherSetRollOverMode`), hashed in the token's own domain ("SCaaS ZetherToken", "1", chainId, token, chainUid). `args` and `proof` enter the struct
//! as the contract hashes them: a nested struct by its struct hash, `bytes` by its keccak.
//!
//! One table, [`OPS`]: every op's type string, nested types appended as `encodeType` has them. The hashing is generic over a
//! type string (no per-op code), so a row added to the table is a row hashed. `tests/typed_ops.rs` compares every Zether row of
//! `smartcontracts/vectors/typed/typed_ops.json` with it.

use crate::abi;
use crate::curve::keccak256;
use crate::envelope::{domain_separator, MODE_RESTRICT_FEE_RECIPIENT, MODE_RESTRICT_RELAYER};
use serde_json::{json, Value};
use std::collections::BTreeSet;

type R<T> = Result<T, String>;

/// Every typed op the Zether token kinds take (the rows of `typed_ops.json` with a `zether` domain).
pub const OPS: [(&str, &str); 28] = [
    ("UABurn", "UABurn(bytes32 from,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
    ("Wrap", "Wrap(address from,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
    ("WrapLeg", "WrapLeg(address from,address underlying,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
    ("UAUnwrap", "UAUnwrap(bytes32 from,uint256 wrapped,address recipient,uint256 minOut,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
    ("UAUnwrapLeg", "UAUnwrapLeg(bytes32 from,address underlying,uint256 wrapped,address recipient,uint256 minOut,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
    ("AddReserve", "AddReserve(address from,address underlying,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
    ("WrapToUA", "WrapToUA(address from,address underlying,uint256 amount,bytes32 to,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
    ("UAUnwrapToUA", "UAUnwrapToUA(bytes32 from,address underlying,uint256 wrapped,bytes32 to,uint256 minOut,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
    ("UAShield", "UAShield(bytes32 from,bytes32 toUA,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
    ("WrapShield", "WrapShield(address from,address underlying,uint256 amountIn,bytes32 toUA,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
    ("UARollOver", "UARollOver(bytes32 from,bytes32 ua,uint256 n,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
    ("UAZetherTransferSingle", "UAZetherTransferSingle(bytes32 from,ZetherSingle args,bytes proof,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)G1(bytes32 x0,bytes32 x1,bytes32 y0,bytes32 y1)ZetherSingle(uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes16 salt,bytes32 beneficiaryUA,G1 yFrom,G1 yTo,G1 cOut,G1 dOut,G1 cDeb,G1 cAud)"),
    ("UAZetherTransfer", "UAZetherTransfer(bytes32 from,ZetherMulti args,bytes proof,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)G1(bytes32 x0,bytes32 x1,bytes32 y0,bytes32 y1)ZetherLeg(G1 yTo,G1 cOut,G1 cAud,G1 dAud)ZetherMulti(uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes16 salt,bytes32 beneficiaryUA,uint256 decoyFee,G1 yFrom,G1 dOut,G1 cDeb,ZetherLeg[] legs,bytes sealedMemo)"),
    ("UAZetherTransferCompact", "UAZetherTransferCompact(bytes32 from,ZetherMulti args,bytes proof,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)G1(bytes32 x0,bytes32 x1,bytes32 y0,bytes32 y1)ZetherLeg(G1 yTo,G1 cOut,G1 cAud,G1 dAud)ZetherMulti(uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes16 salt,bytes32 beneficiaryUA,uint256 decoyFee,G1 yFrom,G1 dOut,G1 cDeb,ZetherLeg[] legs,bytes sealedMemo)"),
    ("UAZetherUnshield", "UAZetherUnshield(bytes32 from,ZetherBurn args,uint256 amount,bytes32 recipient,bytes proof,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)G1(bytes32 x0,bytes32 x1,bytes32 y0,bytes32 y1)ZetherBurn(uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes32 beneficiaryUA,G1 yFrom)"),
    ("UAZetherUnshieldUnwrap", "UAZetherUnshieldUnwrap(bytes32 from,ZetherBurn args,Unwrap unwrap,bytes proof,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)G1(bytes32 x0,bytes32 x1,bytes32 y0,bytes32 y1)Unwrap(address underlying,bytes32 recipient,uint256 amount,uint256 minOut)ZetherBurn(uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes32 beneficiaryUA,G1 yFrom)"),
    ("UARollOverSigned", "UARollOverSigned(bytes32 from,bytes32 ua,uint64 expectedPendingSeq,uint64 validUntilBlock,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
    ("UASetRollOverMode", "UASetRollOverMode(bytes32 from,bytes32 ua,uint8 rollOverMode,uint64 validUntilBlock,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
    ("UARollOverBatch", "UARollOverBatch(bytes32 from,bytes32[] uas,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
    ("UAReceiverFee", "UAReceiverFee(UAMetaTransfer payment,uint256 fee,address feeRecipient,uint256 validUntil)UAMetaTransfer(bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
    // pay-meta-tax T38 / T41: the payer's own lane (O4)
    ("UARelayFee", "UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 batch,uint256 nonce,uint256 validUntil,address relayer)"),
    // pay-meta-tax T40 / T41: a public payment with its tax on the regulated Zether kinds 10, 11 (spec §5.2)
    ("UAPayWithTax", "UAPayWithTax(UAMetaTransfer payment,uint8 taxMode,uint256 tax)UAMetaTransfer(bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
    ("UAWrapOrder", "UAWrapOrder(bytes32 from,address wrappedToken,uint256 amount,uint256 minMinted,uint256 minFill,uint256 fee,address relayer,bytes32 destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)"),
    ("CancelUAOrder", "CancelUAOrder(UATradeOrder order)UATradeOrder(bytes32 from,address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,uint256 fee,address relayer,address dex,bytes32 destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)"),
    ("CancelUAWrapOrder", "CancelUAWrapOrder(UAWrapOrder order)UAWrapOrder(bytes32 from,address wrappedToken,uint256 amount,uint256 minMinted,uint256 minFill,uint256 fee,address relayer,bytes32 destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)"),
    ("UACancelNonce", "UACancelNonce(bytes32 from,uint256 lane,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
    ("ZetherRollOver", "ZetherRollOver(bytes32 ua,uint64 accSeq,uint64 expectedPendingSeq,uint64 validUntilBlock)"),
    ("ZetherSetRollOverMode", "ZetherSetRollOverMode(bytes32 ua,uint8 mode,uint64 modeNonce,uint64 validUntilBlock)"),
];

/// `(type, name)` fields of the struct definitions of a type string.
struct Defs(Vec<(String, Vec<(String, String)>)>);

impl Defs {
    fn parse(ts: &str) -> R<Defs> {
        let mut defs = vec![];
        let mut rest = ts;
        while !rest.is_empty() {
            let (name, tail) = rest.split_once('(').ok_or("bad type string")?;
            let (body, tail) = tail.split_once(')').ok_or("bad type string")?;
            let fields = body
                .split(',')
                .map(|f| f.split_once(' ').map(|(t, n)| (t.to_string(), n.to_string())).ok_or("bad type string"))
                .collect::<Result<Vec<_>, _>>()?;
            defs.push((name.to_string(), fields));
            rest = tail;
        }
        Ok(Defs(defs))
    }

    fn get(&self, name: &str) -> Option<&Vec<(String, String)>> {
        self.0.iter().find(|d| d.0 == name).map(|d| &d.1)
    }

    fn deps(&self, name: &str, seen: &mut BTreeSet<String>) {
        for (t, _) in self.get(name).into_iter().flatten() {
            let base = t.trim_end_matches("[]");
            if self.get(base).is_some() && seen.insert(base.to_string()) {
                self.deps(base, seen);
            }
        }
    }

    /// EIP-712 `encodeType`: the struct, then its dependencies by name.
    fn encode_type(&self, name: &str) -> String {
        let line = |n: &str| format!("{n}({})", self.get(n).unwrap().iter().map(|(t, f)| format!("{t} {f}")).collect::<Vec<_>>().join(","));
        let mut seen = BTreeSet::new();
        self.deps(name, &mut seen);
        seen.remove(name);
        std::iter::once(line(name)).chain(seen.iter().map(|n| line(n))).collect()
    }

    fn struct_hash(&self, name: &str, v: &Value) -> R<[u8; 32]> {
        let fields = self.get(name).ok_or_else(|| format!("unknown type `{name}`"))?;
        if let Some(extra) = v.as_object().and_then(|o| o.keys().find(|k| !fields.iter().any(|f| &f.1 == *k))) {
            return Err(format!("`{name}` has no field `{extra}`"));
        }
        // `MetaTxLib.canon`, one place for an envelope and a nested payment: a struct with `mode`, `relayer` and `feeRecipient`
        // hashes the fields its mode does not bind as 0, as the contract, clientkeys and the node do
        let canon = ["relayer", "feeRecipient"].iter().all(|n| fields.iter().any(|f| f.1 == *n));
        let mode = fields.iter().find(|f| canon && f.1 == "mode").and_then(|(t, f)| v.get(f).map(|x| self.value(t, f, x)));
        let mode = mode.transpose()?.map(|w| u32::from_be_bytes(w[28..].try_into().unwrap()));
        let mut b = keccak256(self.encode_type(name).as_bytes()).to_vec();
        for (t, f) in fields {
            let x = v.get(f).filter(|x| !x.is_null()).ok_or_else(|| format!("missing field `{f}`"))?;
            let word = self.value(t, f, x)?;
            let unbound = mode.is_some_and(|m| {
                (f == "relayer" && m & MODE_RESTRICT_RELAYER == 0) || (f == "feeRecipient" && m & MODE_RESTRICT_FEE_RECIPIENT == 0)
            });
            b.extend(if unbound { [0; 32] } else { word });
        }
        Ok(keccak256(&b))
    }

    fn value(&self, t: &str, f: &str, x: &Value) -> R<[u8; 32]> {
        if let Some(el) = t.strip_suffix("[]") {
            let a = x.as_array().ok_or_else(|| format!("`{f}` must be an array"))?;
            let w = a.iter().map(|e| self.value(el, f, e)).collect::<R<Vec<_>>>()?;
            return Ok(keccak256(&w.concat()));
        }
        if self.get(t).is_some() {
            return self.struct_hash(t, x);
        }
        let hexv = |n: Option<usize>| -> R<Vec<u8>> {
            let s = x.as_str().ok_or_else(|| format!("`{f}` must be a hex string"))?;
            let b = hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|_| format!("`{f}` is not hex"))?;
            match n {
                Some(n) if b.len() != n => Err(format!("`{f}` must be {n} bytes")),
                _ => Ok(b),
            }
        };
        let word = |b: &[u8], left: bool| {
            let mut o = [0u8; 32];
            if left { o[32 - b.len()..].copy_from_slice(b) } else { o[..b.len()].copy_from_slice(b) }
            o
        };
        match t {
            "bytes" => Ok(keccak256(&hexv(None)?)),
            "string" => Ok(keccak256(x.as_str().ok_or_else(|| format!("`{f}` must be a string"))?.as_bytes())),
            "address" => Ok(word(&hexv(Some(20))?, true)),
            "bool" => Ok(abi::u256(u64::from(x.as_bool().ok_or_else(|| format!("`{f}` must be a bool"))?))),
            _ if t.starts_with("uint") => {
                let bits: usize = t[4..].parse().map_err(|_| format!("bad type `{t}`"))?;
                let w = match x {
                    Value::Number(n) => abi::u256(n.as_u64().ok_or_else(|| format!("`{f}` must be a u64"))?),
                    Value::String(s) => dec256(s).ok_or_else(|| format!("`{f}` must be a decimal below 2^256"))?,
                    _ => return Err(format!("`{f}` must be a number")),
                };
                if w[..32 - bits / 8].iter().any(|b| *b != 0) {
                    return Err(format!("`{f}` does not fit {t}"));
                }
                Ok(w)
            }
            _ if t.starts_with("bytes") => {
                let n: usize = t[5..].parse().map_err(|_| format!("bad type `{t}`"))?;
                Ok(word(&hexv(Some(n))?, false))
            }
            _ => Err(format!("unsupported type `{t}`")),
        }
    }
}

/// A decimal string as a 256-bit big-endian word.
fn dec256(s: &str) -> Option<[u8; 32]> {
    let mut w = [0u8; 32];
    if s.is_empty() {
        return None;
    }
    for c in s.bytes() {
        let mut carry = u32::from(c.checked_sub(b'0').filter(|d| *d < 10)?);
        for b in w.iter_mut().rev() {
            let t = u32::from(*b) * 10 + carry;
            (*b, carry) = (t as u8, t >> 8);
        }
        if carry != 0 {
            return None;
        }
    }
    Some(w)
}

/// The typed digest of op `op` with `message`: `{typehash, structHash, domainSeparator, digest}` as hex strings.
pub fn typed_digest(op: &str, chain_id: u64, chain_uid: &[u8; 32], token: &[u8; 20], message: &Value) -> R<Value> {
    let ts = OPS.iter().find(|o| o.0 == op).ok_or_else(|| format!("unknown typed op `{op}`"))?.1;
    let defs = Defs::parse(ts)?;
    let sh = defs.struct_hash(op, message)?;
    let ds = domain_separator(chain_id, chain_uid, token);
    let digest = keccak256(&[&[0x19, 0x01][..], &ds, &sh].concat());
    let hx = |b: &[u8]| format!("0x{}", hex::encode(b));
    Ok(json!({
        "typehash": hx(&keccak256(defs.encode_type(op).as_bytes())), "structHash": hx(&sh),
        "domainSeparator": hx(&ds), "digest": hx(&digest),
    }))
}

// ---------------------------------------------------------------------------------------------
// The merged relayed entry of a prover build (TS-D14, R35): the struct a wallet signs and the entry's calldata
// ---------------------------------------------------------------------------------------------

use crate::abi::Tok;
use crate::envelope::{self, InnerSig, MemberSig, UASig};

fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn g1(p: &[u8]) -> Value {
    json!({"x0": hx(&p[..32]), "x1": hx(&p[32..64]), "y0": hx(&p[64..96]), "y1": hx(&p[96..128])})
}

fn head(p: &[u8]) -> R<Value> {
    let w = |i: usize| abi::word_u64(p, 32 * i).map(|x| x.to_string()).ok_or("`payload`: a head word is not a u64");
    Ok(json!({"accSeq": w(0)?, "sendCounter": w(1)?, "validUntilBlock": w(2)?}))
}

fn with(mut base: Value, more: Value) -> Value {
    base.as_object_mut().unwrap().extend(more.as_object().unwrap().clone());
    base
}

/// `ZetherSingle` as the typed struct, from the packed `payload` of `proveTransfer`.
fn single_args(p: &[u8], ben: &[u8; 32]) -> R<Value> {
    if p.len() != 96 + 16 + 6 * 128 {
        return Err("`payload` is not a single transfer's".into());
    }
    let pt = |i: usize| g1(&p[112 + 128 * i..240 + 128 * i]);
    Ok(with(head(p)?, json!({"salt": hx(&p[96..112]), "beneficiaryUA": hx(ben), "yFrom": pt(0), "yTo": pt(1), "cOut": pt(2),
        "dOut": pt(3), "cDeb": pt(4), "cAud": pt(5)})))
}

/// `ZetherMulti` from the packed `payload` of `proveTransferMulti`.
fn multi_args(p: &[u8], ben: &[u8; 32]) -> R<Value> {
    let bad = || "`payload` is not a multi transfer's";
    let (m, legs_end) = envelope::multi_legs(p).ok_or_else(bad)?;
    let pts = 176 + 3 * 128;
    let decoy = abi::word_u64(p, 144).ok_or_else(bad)?;
    let legs: Vec<Value> = (0..m)
        .map(|j| {
            let l = |i: usize| g1(&p[pts + 512 * j + 128 * i..pts + 512 * j + 128 * i + 128]);
            json!({"yTo": l(0), "cOut": l(1), "cAud": l(2), "dAud": l(3)})
        })
        .collect();
    let sealed = if p.len() > legs_end { &p[legs_end + 16..] } else { &[][..] };
    Ok(with(head(p)?, json!({"salt": hx(&p[96..112]), "beneficiaryUA": hx(ben), "decoyFee": decoy.to_string(),
        "yFrom": g1(&p[176..304]), "dOut": g1(&p[304..432]), "cDeb": g1(&p[432..560]), "legs": legs, "sealedMemo": hx(sealed)})))
}

/// `ZetherBurn` from the packed `payload` of `proveBurn`.
fn burn_args(p: &[u8], ben: &[u8; 32]) -> R<Value> {
    if p.len() != 96 + 128 {
        return Err("`payload` is not a burn's".into());
    }
    Ok(with(head(p)?, json!({"beneficiaryUA": hx(ben), "yFrom": g1(&p[96..224])})))
}

fn field<'a>(v: &'a Value, k: &str) -> R<&'a Value> {
    v.get(k).filter(|x| !x.is_null()).ok_or_else(|| format!("missing field `{k}`"))
}

fn raw(v: &Value, k: &str, n: Option<usize>) -> R<Vec<u8>> {
    let s = field(v, k)?.as_str().ok_or_else(|| format!("`{k}` must be a hex string"))?;
    let b = hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|_| format!("`{k}` is not hex"))?;
    match n {
        Some(n) if b.len() != n => Err(format!("`{k}` must be {n} bytes")),
        _ => Ok(b),
    }
}

fn word(v: &Value, k: &str, n: usize) -> R<[u8; 32]> {
    let b = raw(v, k, Some(n))?;
    let mut w = [0u8; 32];
    w[32 - n..].copy_from_slice(&b);
    Ok(w)
}

/// A decimal-or-number field as its 32-byte word (`dec256`).
fn num_word(v: &Value, k: &str) -> R<[u8; 32]> {
    match field(v, k)? {
        Value::Number(n) => n.as_u64().map(abi::u256).ok_or_else(|| format!("`{k}` must be a u64")),
        Value::String(s) => dec256(s).ok_or_else(|| format!("`{k}` must be a decimal below 2^256")),
        _ => Err(format!("`{k}` must be a number")),
    }
}

/// `sig` as the entry's `UASig`: a hex string is a native id's own signature (`UASig{signature}`); an object
/// `{keyData?, signature?, members?: [{index, members: [{index, sig}], sig}]}` the explicit form (a derived or `msig` subject).
/// An empty one is refused: no entry verifies it.
fn ua_sig(v: &Value) -> R<UASig> {
    let s = field(v, "sig")?;
    if s.is_string() {
        return Ok(UASig { signature: raw(v, "sig", None)?, ..Default::default() });
    }
    let opt = |o: &Value, k: &str| if o.get(k).is_some_and(|x| !x.is_null()) { raw(o, k, None) } else { Ok(vec![]) };
    let index = |o: &Value| -> R<u16> {
        field(o, "index")?.as_u64().and_then(|n| u16::try_from(n).ok()).ok_or_else(|| "`index` must be a uint16".to_string())
    };
    let list = |o: &Value| -> R<Vec<Value>> {
        match o.get("members").filter(|x| !x.is_null()) {
            None => Ok(vec![]),
            Some(a) => a.as_array().cloned().ok_or_else(|| "`members` must be an array".to_string()),
        }
    };
    let members = list(s)?
        .iter()
        .map(|m| {
            let inner = list(m)?.iter().map(|i| Ok(InnerSig { index: index(i)?, sig: raw(i, "sig", None)? })).collect::<R<Vec<_>>>()?;
            Ok(MemberSig { index: index(m)?, members: inner, sig: opt(m, "sig")? })
        })
        .collect::<R<Vec<_>>>()?;
    let sig = UASig { key_data: opt(s, "keyData")?, signature: opt(s, "signature")?, members };
    if sig.signature.is_empty() && sig.members.is_empty() {
        return Err("`sig` is required: a signature or members".into());
    }
    Ok(sig)
}

/// A merged relayed entry of a prover build (R35): `op` is one of `UAZetherTransferSingle`, `UAZetherTransfer`,
/// `UAZetherTransferCompact`, `UAZetherUnshield`, `UAZetherUnshieldUnwrap`; `env` the signed fields `{from, batch, nonce,
/// validUntil, mode, relayer, fee, feeRecipient}` (the `UAEnvelope`, `from` the subject's 32-byte id: a padded native address or a
/// derived UA; the same the build's `envelopeBinding` was taken over, `uaEnvelope`'s `binding`); `payload`, `proof`, `beneficiary`
/// the build's; an unshield adds `recipient` (32-byte id) and `amount`, an unshield-unwrap `unwrap {underlying, recipient, amount,
/// minOut}`. Returns the typed `message`, its digest (what the subject signs) and, once `sig` is given (see [`ua_sig`]), the entry's
/// `calldata`, `UASig auth` last.
pub fn named_call(v: &Value) -> R<Value> {
    let op = field(v, "op")?.as_str().ok_or("`op` must be a string")?;
    let env = field(v, "env")?;
    let (payload, proof, ben) = (raw(v, "payload", None)?, raw(v, "proof", None)?, word(v, "beneficiary", 32)?);
    let env_toks: Vec<Tok> = [
        word(env, "from", 32)?, num_word(env, "batch")?, num_word(env, "nonce")?, num_word(env, "validUntil")?,
        num_word(env, "mode")?, word(env, "relayer", 20)?, num_word(env, "fee")?, word(env, "feeRecipient", 20)?,
    ]
    .map(Tok::Word)
    .into();
    let sig = v.get("sig").filter(|x| !x.is_null()).map(|_| ua_sig(v)).transpose()?;
    let lanes = json!({"batch": field(env, "batch")?, "nonce": field(env, "nonce")?, "validUntil": field(env, "validUntil")?,
        "mode": field(env, "mode")?, "relayer": field(env, "relayer")?, "fee": field(env, "fee")?, "feeRecipient": field(env, "feeRecipient")?});
    let (from, proof_h) = (field(env, "from")?, json!(hx(&proof)));
    let sg = sig.clone().unwrap_or_default();
    let (message, calldata) = match op {
        "UAZetherTransferSingle" => (
            json!({"from": from, "args": single_args(&payload, &ben)?, "proof": proof_h}),
            envelope::named_transfer_single_call(&env_toks, &payload, &proof, &ben, &sg),
        ),
        "UAZetherTransfer" | "UAZetherTransferCompact" => {
            let name = if op == "UAZetherTransfer" { "mtxConfidentialTransfer" } else { "mtxConfidentialTransferCompact" };
            (
                json!({"from": from, "args": multi_args(&payload, &ben)?, "proof": proof_h}),
                envelope::named_transfer_multi_call(name, &env_toks, &payload, &proof, &ben, &sg),
            )
        }
        "UAZetherUnshield" => {
            let (to, amount) = (word(v, "recipient", 32)?, num_word(v, "amount")?);
            let amt = abi::word_u64(&amount, 0).ok_or("`amount` must be a u64")?;
            (
                json!({"from": from, "args": burn_args(&payload, &ben)?, "amount": field(v, "amount")?, "recipient": hx(&to), "proof": proof_h}),
                envelope::named_unshield_call(&env_toks, &payload, &proof, &ben, &to, amt, &sg),
            )
        }
        "UAZetherUnshieldUnwrap" => {
            let x = field(v, "unwrap")?;
            let w = [word(x, "underlying", 20)?, word(x, "recipient", 32)?, num_word(x, "amount")?, num_word(x, "minOut")?];
            (
                json!({"from": from, "args": burn_args(&payload, &ben)?, "unwrap": x, "proof": proof_h}),
                envelope::named_unshield_unwrap_call(&env_toks, &payload, &proof, &ben, w, &sg),
            )
        }
        _ => return Err(format!("`{op}` has no merged call builder (typedDigest takes any typed op)")),
    };
    let message = with(message, lanes);
    let d = typed_digest(op, num_u64(v, "chainId")?, &word20_32(v, "chainUid")?, &raw20(v, "token")?, &message)?;
    let mut out = with(d, json!({"message": message}));
    if sig.is_some() {
        out["calldata"] = json!(hx(&calldata));
    }
    Ok(out)
}

fn num_u64(v: &Value, k: &str) -> R<u64> {
    abi::word_u64(&num_word(v, k)?, 0).ok_or_else(|| format!("`{k}` must be a u64"))
}
fn word20_32(v: &Value, k: &str) -> R<[u8; 32]> {
    word(v, k, 32)
}
fn raw20(v: &Value, k: &str) -> R<[u8; 20]> {
    raw(v, k, Some(20))?.try_into().map_err(|_| format!("`{k}` must be 20 bytes"))
}
