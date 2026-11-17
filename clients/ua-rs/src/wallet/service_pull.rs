// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Service pull (spec `2026-11-09-service-pull.md` §3, §10; CLI-SGN-48; ua-rs-sign T20e2), clientkeys `buildServicePull`: the
//! payer signs one `UAMetaTransfer` in the pulled token's domain, `to` = `relayer` = the service, `MODE_RESTRICT_RELAYER`, fee
//! `NONE`, fee 0, no fee recipient, and `entryRef` = the EIP-712 digest of the service's operation `op` (its typed data in the
//! service's own domain; shown, never signed itself, §3.1). The builder refuses an operation outside C3 (more than 16 fields, an
//! array, a nested struct, an `int`, a first field other than `bytes32 payer`, a field missing or extra), `op.payer` other than
//! `from`, an operation for another chain, a zero amount. Then the entry's selector and calldata `<entry>(op, t, UASig)` (`op`'s
//! `bytes` / `string` raw, as the ABI passes them; EIP-712 hashed them), the node job's named fields, the prompt; with a fee,
//! the relay-fee wrap (open mode, clientkeys `buildRelayFee`). Vectors `smartcontracts/vectors/metatx/servicepull.json`. The
//! service and the token decide; nothing here is a check of record. UNAUDITED.
use super::eip712::{abi_atom, pull_atom, scaas_typed_data, to_hex, u256_from, u256_to_dec, uint_value, Abi, TypedData, U256};
use super::{Error, Result};
use crate::ua8::UASig;
use crate::{keccak256, relay_ref, word};
use serde_json::{json, Value};

const MAX_OP_FIELDS: usize = 16;
const UMT_FIELDS: [(&str, &str); 11] = [
    ("from", "bytes32"), ("to", "bytes32"), ("value", "uint256"), ("entryRef", "bytes32"), ("batch", "uint256"), ("nonce", "uint256"),
    ("validUntil", "uint256"), ("mode", "uint32"), ("relayer", "address"), ("fee", "uint256"), ("feeRecipient", "address"),
];
const UMT: &str = "(bytes32,bytes32,uint256,bytes32,uint256,uint256,uint256,uint32,address,uint256,address)";
const UASIG: &str = "(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])";
const MODE_RESTRICT_RELAYER: u64 = 1;

/// One ABI value: a head word, raw `bytes`, a tuple or a dynamic array.
enum V {
    W([u8; 32]),
    B(Vec<u8>),
    T(Vec<V>),
    A(Vec<V>),
}
impl V {
    fn dynamic(&self) -> bool {
        match self {
            V::W(_) => false,
            V::B(_) | V::A(_) => true,
            V::T(x) => x.iter().any(V::dynamic),
        }
    }
    fn enc(&self) -> Vec<u8> {
        match self {
            V::W(w) => w.to_vec(),
            V::B(b) => {
                let mut o = word(b.len() as u64).to_vec();
                o.extend_from_slice(b);
                o.resize(32 + b.len().div_ceil(32) * 32, 0);
                o
            }
            V::T(x) => seq(x),
            V::A(x) => [word(x.len() as u64).to_vec(), seq(x)].concat(),
        }
    }
}
fn seq(xs: &[V]) -> Vec<u8> {
    let encs: Vec<Vec<u8>> = xs.iter().map(V::enc).collect();
    let mut off: usize = xs.iter().zip(&encs).map(|(x, e)| if x.dynamic() { 32 } else { e.len() }).sum();
    let (mut head, mut tail) = (Vec::new(), Vec::new());
    for (x, e) in xs.iter().zip(encs) {
        if x.dynamic() {
            head.extend_from_slice(&word(off as u64));
            off += e.len();
            tail.extend(e);
        } else {
            head.extend(e);
        }
    }
    [head, tail].concat()
}
fn sig_v(s: &UASig) -> V {
    let inner = |m: &crate::ua8::InnerSig| V::T(vec![V::W(word(m.index.into())), V::B(m.sig.clone())]);
    let member = |m: &crate::ua8::MemberSig| {
        V::T(vec![V::W(word(m.index.into())), V::A(m.members.iter().map(inner).collect()), V::B(m.sig.clone())])
    };
    V::T(vec![V::B(s.key_data.clone()), V::B(s.signature.clone()), V::A(s.members.iter().map(member).collect())])
}
fn atom_v(ty: &str, v: Option<&Value>) -> Result<V> {
    Ok(match abi_atom(ty, v)? {
        Abi::Word(w) => V::W(w),
        Abi::Raw(b) => V::B(b),
    })
}
fn selector(sig: &str) -> [u8; 4] {
    let h = keccak256(sig.as_bytes());
    [h[0], h[1], h[2], h[3]]
}
fn pad(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}
fn addr_of(w: &[u8; 32]) -> Result<[u8; 20]> {
    if w[..12] != [0; 12] {
        return Err(Error::Argument);
    }
    w[12..].try_into().map_err(|_| Error::Argument)
}
fn get<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.get(k).filter(|x| !x.is_null())
}
fn word_of(ty: &str, v: Option<&Value>) -> Result<[u8; 32]> {
    match abi_atom(ty, Some(v.ok_or(Error::Argument)?))? {
        Abi::Word(w) => Ok(w),
        Abi::Raw(_) => Err(Error::Argument),
    }
}
fn uint_of(v: &Value, k: &str) -> Result<U256> {
    uint_value(Some(get(v, k).ok_or(Error::Argument)?))
}
fn u64_of(v: &Value, k: &str) -> Result<u64> {
    let w = uint_of(v, k)?;
    if w[..24] != [0; 24] {
        return Err(Error::Argument);
    }
    Ok(w[24..].iter().fold(0u64, |a, b| a << 8 | u64::from(*b)))
}
/// `from` as a 32-byte id, or `address` / `bytes32` per `ty` (a hex string, exact length).
fn fixed<const N: usize>(v: &Value, k: &str) -> Result<[u8; N]> {
    let s = get(v, k).and_then(Value::as_str).ok_or(Error::Argument)?;
    super::eip712::from_hex(s).and_then(|b| b.try_into().ok()).ok_or(Error::Argument)
}

/// A built service pull: what the payer is shown and signs (`transfer`), and what is sent once signed.
#[derive(Clone, Debug)]
pub struct ServicePull {
    pub service: [u8; 20],
    pub entry_ref: [u8; 32],
    /// The `UAMetaTransfer` in the token's domain, canonical (`MetaTxLib.canon`).
    pub transfer: TypedData,
    pub digest: [u8; 32],
    pub selector: [u8; 4],
    /// `<entry>(<op tuple>,<UAMetaTransfer tuple>,<UASig tuple>)`.
    pub abi_signature: String,
    pub entry: String,
    pub token: [u8; 20],
    pub chain_id: u64,
    pub chain_uid: [u8; 32],
    /// `op`'s message as given (the job's `args.op`) and its ABI values.
    op_message: Value,
    op_values: Vec<(String, String)>,
    /// What the signer shows (§10): the service's domain name and address, every field, the token, the amount, `validUntil`.
    pub prompt: Value,
}

/// clientkeys `buildServicePull`: `{name?, token, chainId, chainUid, entry, op, from, amount, batch, nonce, validUntil}`, `op` the
/// operation's typed data `{domain, types, primaryType, message}` in the service's domain, `name` the token's domain name
/// (`SCaaS MetaToken` when absent). `Argument` for every refusal of the module doc.
pub fn service_pull(input: &Value) -> Result<ServicePull> {
    const KEYS: [&str; 11] = ["name", "token", "chainId", "chainUid", "entry", "op", "from", "amount", "batch", "nonce", "validUntil"];
    if input.as_object().is_none_or(|o| o.keys().any(|k| !KEYS.contains(&k.as_str()))) {
        return Err(Error::Argument);
    }
    let entry = get(input, "entry").and_then(Value::as_str).ok_or(Error::Argument)?;
    let mut c = entry.chars();
    if !c.next().is_some_and(|f| f.is_ascii_alphabetic() || f == '_') || !c.all(|x| x.is_ascii_alphanumeric() || x == '_') {
        return Err(Error::Argument);
    }
    let name = match get(input, "name") {
        None => "SCaaS MetaToken",
        Some(n) => n.as_str().ok_or(Error::Argument)?,
    };
    let (token, chain_uid, from) = (fixed::<20>(input, "token")?, fixed::<32>(input, "chainUid")?, fixed::<32>(input, "from")?);
    let chain_id = u64_of(input, "chainId")?;
    let op = TypedData::from_value(get(input, "op").ok_or(Error::Argument)?.clone())?;
    let d = op.domain();
    let service = addr_of(&word_of("address", d.get("verifyingContract"))?)?;
    if word_of("uint256", d.get("chainId"))? != u256_from(chain_id) {
        return Err(Error::Argument); // the operation is for another chain
    }
    let primary = op.primary_type().to_string();
    let fields = op.fields_of(&primary).ok_or(Error::Argument)?;
    if fields.is_empty() || fields.len() > MAX_OP_FIELDS || op.struct_count() != 1 || !fields.iter().all(|(_, t)| pull_atom(t)) {
        return Err(Error::Argument); // C3: at most 16 atomic, `bytes` or `string` fields, no nested struct, no array
    }
    if fields.first().is_none_or(|(n, t)| n != "payer" || t != "bytes32") {
        return Err(Error::Argument);
    }
    let m = op.message().clone();
    let mo = m.as_object().ok_or(Error::Argument)?;
    if mo.len() != fields.len() || fields.iter().any(|(n, _)| get(&m, n).is_none()) {
        return Err(Error::Argument); // the operation's fields are not its type's
    }
    if word_of("bytes32", mo.get("payer"))? != from {
        return Err(Error::Argument); // the operation is not the payer's
    }
    let value = uint_of(input, "amount")?;
    if value == [0; 32] {
        return Err(Error::Argument);
    }
    let entry_ref = op.digest()?;
    let message = json!({
        "from": to_hex(&from), "to": to_hex(&pad(&service)), "value": u256_to_dec(&value), "entryRef": to_hex(&entry_ref),
        "batch": u256_to_dec(&uint_of(input, "batch")?), "nonce": u256_to_dec(&uint_of(input, "nonce")?),
        "validUntil": u256_to_dec(&uint_of(input, "validUntil")?), "mode": MODE_RESTRICT_RELAYER, "relayer": to_hex(&service),
        "fee": "0", "feeRecipient": super::eip712::ZERO_ADDRESS,
    });
    let transfer = scaas_typed_data("UAMetaTransfer", Some(name), &token, chain_id, &chain_uid, &message)?;
    let types = fields.iter().map(|(_, t)| t.as_str()).collect::<Vec<_>>().join(",");
    let abi_signature = format!("{entry}(({types}),{UMT},{UASIG})");
    let prompt = json!({
        "service": to_hex(&service), "serviceName": d.get("name").cloned().unwrap_or(Value::Null), "op": primary, "message": m,
        "token": to_hex(&token), "amount": u256_to_dec(&value), "validUntil": message.get("validUntil"),
    });
    Ok(ServicePull {
        service,
        entry_ref,
        digest: transfer.digest()?,
        transfer,
        selector: selector(&abi_signature),
        abi_signature,
        entry: entry.to_string(),
        token,
        chain_id,
        chain_uid,
        op_values: fields.clone(),
        op_message: m,
        prompt,
    })
}

/// The relay-fee wrap of a pull (§2.4 (b), clientkeys `buildRelayFee` in open mode): `UARelayFee {from, target = the service,
/// callDataHash, payee = pad(router), value, batch, nonce, validUntil, relayer = router}` in the fee token's domain.
#[derive(Clone, Debug)]
pub struct RelayFeeWrap {
    pub relay_ref: [u8; 32],
    pub call_data_hash: [u8; 32],
    pub fee: TypedData,
    pub digest: [u8; 32],
    fee_token: [u8; 20],
    call_data: Vec<u8>,
}

impl ServicePull {
    fn t_value(&self) -> Result<V> {
        let m = self.transfer.message();
        UMT_FIELDS.iter().map(|(n, t)| atom_v(t, m.get(*n))).collect::<Result<Vec<_>>>().map(V::T)
    }
    /// `<entry>(op, t, auth)`: the call the relayer sends to the service.
    pub fn calldata(&self, auth: &UASig) -> Result<Vec<u8>> {
        let op = self.op_values.iter().map(|(n, t)| atom_v(t, self.op_message.get(n))).collect::<Result<Vec<_>>>()?;
        Ok([self.selector.to_vec(), seq(&[V::T(op), self.t_value()?, sig_v(auth)])].concat())
    }
    /// The node job's named fields (spec §8): `{entry, contract: "service", token: the service, args: {op, pullToken, t, auth}}`.
    pub fn job(&self, auth: &Value) -> Value {
        json!({"entry": self.entry, "contract": "service", "token": to_hex(&self.service),
            "args": {"op": self.op_message, "pullToken": to_hex(&self.token), "t": self.transfer.message(), "auth": auth}})
    }
    /// The relay-fee wrap `{name?, feeToken, router, executor, value, batch, nonce, validUntil}` over `calldata(auth)`. Refused: the
    /// service is the router or its executor; the fee in the pulled token on the pull's own lane and nonce (the pull runs first
    /// and spends it, §2.4: the fee takes `nonce + 1`); a zero fee.
    pub fn relay_fee(&self, auth: &UASig, f: &Value) -> Result<RelayFeeWrap> {
        const KEYS: [&str; 8] = ["name", "feeToken", "router", "executor", "value", "batch", "nonce", "validUntil"];
        if f.as_object().is_none_or(|o| o.keys().any(|k| !KEYS.contains(&k.as_str()))) {
            return Err(Error::Argument);
        }
        let (fee_token, router, executor) = (fixed::<20>(f, "feeToken")?, fixed::<20>(f, "router")?, fixed::<20>(f, "executor")?);
        let (value, batch, nonce) = (uint_of(f, "value")?, uint_of(f, "batch")?, uint_of(f, "nonce")?);
        let t = self.transfer.message();
        if self.service == router || self.service == executor || value == [0; 32] {
            return Err(Error::Argument);
        }
        if fee_token == self.token && batch == uint_value(t.get("batch"))? && nonce == uint_value(t.get("nonce"))? {
            return Err(Error::Argument);
        }
        let name = match get(f, "name") {
            None => "SCaaS MetaToken",
            Some(n) => n.as_str().ok_or(Error::Argument)?,
        };
        let call_data = self.calldata(auth)?;
        let call_data_hash = keccak256(&call_data);
        let message = json!({
            "from": t.get("from"), "target": to_hex(&self.service), "callDataHash": to_hex(&call_data_hash),
            "payee": to_hex(&pad(&router)), "value": u256_to_dec(&value), "batch": u256_to_dec(&batch), "nonce": u256_to_dec(&nonce),
            "validUntil": u256_to_dec(&uint_of(f, "validUntil")?), "relayer": to_hex(&router),
        });
        let fee = scaas_typed_data("UARelayFee", Some(name), &fee_token, self.chain_id, &self.chain_uid, &message)?;
        Ok(RelayFeeWrap {
            relay_ref: relay_ref(self.chain_id, &self.service, &call_data),
            call_data_hash,
            digest: fee.digest()?,
            fee,
            fee_token,
            call_data,
        })
    }
}

impl RelayFeeWrap {
    /// The router's `relay(target, callData, feeToken, from, payee, value, batch, nonce, validUntil, feeAuth)`.
    pub fn calldata(&self, fee_auth: &UASig) -> Result<Vec<u8>> {
        let m = self.fee.message();
        let w = |n: &str, t: &str| atom_v(t, m.get(n));
        let sig = format!("relay(address,bytes,address,bytes32,bytes32,uint256,uint256,uint256,uint256,{UASIG})");
        let args = [
            w("target", "address")?, V::B(self.call_data.clone()), V::W(pad(&self.fee_token)), w("from", "bytes32")?,
            w("payee", "bytes32")?, w("value", "uint256")?, w("batch", "uint256")?, w("nonce", "uint256")?,
            w("validUntil", "uint256")?, sig_v(fee_auth),
        ];
        Ok([selector(&sig).to_vec(), seq(&args)].concat())
    }
}
