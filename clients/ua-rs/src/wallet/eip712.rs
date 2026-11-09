// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! EIP-712 (spec §5.3; T4): [`TypedData`] `{types, primaryType, domain, message}` as `eth_signTypedData_v4`, read through
//! `bounded::json` with the caps of spec §9.3 (64 KiB, JSON depth 8, ≤ 32 struct types, ≤ 64 fields each, type references acyclic
//! and ≤ 8 deep, arrays ≤ 1,024), and one generic hasher (`encodeType` with the referenced types sorted, `hashStruct`,
//! `0x1901 ‖ domain ‖ struct`). **The hasher is faithful** (clientkeys `hashTypedData`): it hashes the values supplied, never
//! rewrites one; a field missing from `message` is its zero value, a field not in its type is refused, `int` is two's complement,
//! `bytesN` exact, `T[k]` of length k; the `EIP712Domain` type is the fields present in `domain` in EIP-712 order (a supplied one
//! must be exactly that). Stricter than the JS where a value cannot be what it claims (a `uintN` past 2^N, a string as a number, a
//! number as a bool): refused, never coerced.
//!
//! **Canonical form, SCaaS records only** ([`scaas_typed_data`], clientkeys `opTypedData` / `canonical`): a step of the SCaaS
//! builders, never of the hasher, of `Any` or of the checked path (`policy`): every struct value with the fields `mode`, `relayer`
//! and `feeRecipient` gets `relayer = 0` unless `mode & 1` and `feeRecipient = 0` unless `mode & 2` (`MetaTxLib.canon`), nested
//! structs and arrays too. The builders know the SCaaS structs by the op table below (clientkeys `STRUCTS` / `OPS`, every row held
//! to `vectors/typed/typed_ops.json` by `tests/wallet_typed.rs`). UNAUDITED.
use super::signer::SignRequest;
use super::{bounded, Error, Result};
use crate::{keccak256, Domain, REGISTRY_NAME};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const MAX_LEN: usize = 64 * 1024;
const MAX_JSON_DEPTH: usize = 8;
const MAX_TYPES: usize = 32;
const MAX_FIELDS: usize = 64;
const MAX_TYPE_DEPTH: usize = 8;
const MAX_ARRAY: usize = 1024;

const DOMAIN: &str = "EIP712Domain";
/// The `EIP712Domain` fields in EIP-712 order.
const DOMAIN_FIELDS: [(&str, &str); 5] =
    [("name", "string"), ("version", "string"), ("chainId", "uint256"), ("verifyingContract", "address"), ("salt", "bytes32")];
pub(crate) const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

/// `(name, type)` in declaration order.
pub(crate) type Fields = Vec<(String, String)>;

/// A typed-data value as `eth_signTypedData_v4` takes it, checked against the caps; the hashes come from [`TypedData::digest`] and
/// its parts, the value itself (for a clear-signing screen) from [`TypedData::to_value`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedData {
    /// The structs, `EIP712Domain` apart (it follows `domain`).
    types: BTreeMap<String, Fields>,
    primary_type: String,
    domain: Map<String, Value>,
    message: Value,
}

fn ident(s: &str) -> bool {
    let mut c = s.chars();
    c.next().is_some_and(|f| f.is_ascii_alphabetic() || f == '_' || f == '$') && c.all(|x| x.is_ascii_alphanumeric() || x == '_' || x == '$')
}

/// `T[k]` / `T[]` → `(T, Some(k) / None)` (the outer dimension); not an array → `Ok(None)`.
fn outer(ty: &str) -> Result<Option<(&str, Option<usize>)>> {
    let Some(body) = ty.strip_suffix(']') else { return Ok(None) };
    let i = body.rfind('[').ok_or(Error::Argument)?;
    let (elem, k) = (body.get(..i).ok_or(Error::Argument)?, body.get(i + 1..).ok_or(Error::Argument)?);
    if k.is_empty() {
        return Ok(Some((elem, None)));
    }
    let n: usize = k.parse().map_err(|_| Error::Argument)?;
    if n.to_string() != k || n > MAX_ARRAY {
        return Err(Error::Argument);
    }
    Ok(Some((elem, Some(n))))
}

/// The struct or atom under every array dimension, and the number of dimensions.
fn base(ty: &str) -> Result<(&str, usize)> {
    let (mut t, mut dims) = (ty, 0);
    while let Some((elem, _)) = outer(t)? {
        t = elem;
        dims += 1;
    }
    Ok((t, dims))
}

/// `N` of `bytesN` (1–32), `uintN` / `intN` (8–256, a multiple of 8).
fn size_of(ty: &str, prefix: &str, ok: impl Fn(usize) -> bool) -> Option<usize> {
    let d = ty.strip_prefix(prefix)?;
    let n: usize = d.parse().ok()?;
    (n.to_string() == d && ok(n)).then_some(n)
}
fn bytes_n(ty: &str) -> Option<usize> {
    size_of(ty, "bytes", |n| (1..=32).contains(&n))
}
fn uint_bits(ty: &str) -> Option<usize> {
    size_of(ty, "uint", |n| n.is_multiple_of(8) && (8..=256).contains(&n))
}
fn int_bits(ty: &str) -> Option<usize> {
    size_of(ty, "int", |n| n.is_multiple_of(8) && (8..=256).contains(&n))
}
fn atom(ty: &str) -> bool {
    matches!(ty, "string" | "bytes" | "address" | "bool") || bytes_n(ty).is_some() || uint_bits(ty).is_some() || int_bits(ty).is_some()
}
/// A service-pull operation's field type (spec 2026-11-09-service-pull C3, clientkeys `OP_FIELD`): an atom but `intN` (C3's too, not
/// in the reference builder: refused, never mis-encoded).
pub(crate) fn pull_atom(ty: &str) -> bool {
    atom(ty) && int_bits(ty).is_none()
}

/// An atom's ABI form: its head word, or the raw bytes of a `bytes` / `string` (EIP-712 hashes those, the ABI passes them).
pub(crate) enum Abi {
    Word([u8; 32]),
    Raw(Vec<u8>),
}
pub(crate) fn abi_atom(ty: &str, v: Option<&Value>) -> Result<Abi> {
    match (ty, v) {
        ("string", Some(Value::String(s))) => Ok(Abi::Raw(s.as_bytes().to_vec())),
        ("string", _) => Err(Error::Argument),
        ("bytes", _) => hex_of(v)?.map(Abi::Raw).ok_or(Error::Argument),
        _ => encode_atom(ty, v).map(Abi::Word),
    }
}

// --- 256-bit unsigned integers, big-endian bytes (array order is numeric order) ---

pub(crate) type U256 = [u8; 32];

pub(crate) fn u256_from(v: u64) -> U256 {
    let mut w = [0u8; 32];
    for (o, b) in w.iter_mut().rev().zip(v.to_le_bytes()) {
        *o = b;
    }
    w
}
/// `x · m + a`, `None` past 2^256.
pub(crate) fn u256_mul_add(x: &U256, m: u64, a: u64) -> Option<U256> {
    let (mut out, mut carry) = ([0u8; 32], u128::from(a));
    for (o, b) in out.iter_mut().rev().zip(x.iter().rev()) {
        let v = u128::from(*b) * u128::from(m) + carry;
        *o = v as u8;
        carry = v >> 8;
    }
    (carry == 0).then_some(out)
}
pub(crate) fn u256_add(x: &U256, y: &U256) -> Option<U256> {
    let (mut out, mut carry) = ([0u8; 32], 0u16);
    for ((o, a), b) in out.iter_mut().rev().zip(x.iter().rev()).zip(y.iter().rev()) {
        let v = u16::from(*a) + u16::from(*b) + carry;
        *o = v as u8;
        carry = v >> 8;
    }
    (carry == 0).then_some(out)
}
/// `(x / d, x % d)`, `d > 0`.
pub(crate) fn u256_div(x: &U256, d: u64) -> (U256, u64) {
    let (mut q, mut rem) = ([0u8; 32], 0u128);
    for (o, b) in q.iter_mut().zip(x) {
        let cur = (rem << 8) | u128::from(*b);
        *o = (cur / u128::from(d)) as u8;
        rem = cur % u128::from(d);
    }
    (q, rem as u64)
}
fn bit_len(x: &U256) -> usize {
    x.iter().position(|b| *b != 0).map_or(0, |i| (32 - i) * 8 - x.get(i).map_or(0, |b| b.leading_zeros() as usize))
}
/// Decimal digits only.
pub(crate) fn u256_dec(s: &str) -> Option<U256> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.bytes().try_fold([0u8; 32], |x, c| u256_mul_add(&x, 10, u64::from(c - b'0')))
}
fn u256_hex(s: &str) -> Option<U256> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    s.bytes().try_fold([0u8; 32], |x, c| u256_mul_add(&x, 16, u64::from((c as char).to_digit(16)?)))
}
pub(crate) fn u256_to_dec(x: &U256) -> String {
    let (mut x, mut digits) = (*x, Vec::new());
    loop {
        let (q, r) = u256_div(&x, 10);
        digits.push(char::from(b'0' + r as u8));
        x = q;
        if x == [0; 32] {
            break;
        }
    }
    digits.iter().rev().collect()
}

/// A JSON number (u64) or a string of decimal digits or `0x` hex, as clientkeys `word` takes it; missing is 0.
pub(crate) fn uint_value(v: Option<&Value>) -> Result<U256> {
    match v {
        None | Some(Value::Null) => Ok([0; 32]),
        Some(Value::Number(n)) => n.as_u64().map(u256_from).ok_or(Error::Argument),
        Some(Value::String(s)) => match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            Some(h) => u256_hex(h),
            None => u256_dec(s),
        }
        .ok_or(Error::Argument),
        _ => Err(Error::Argument),
    }
}

/// `intN` as its 32-byte two's-complement word; a number or a decimal string with an optional `-`.
fn int_word(v: Option<&Value>, bits: usize) -> Result<U256> {
    let (neg, mag) = match v {
        Some(Value::Number(n)) => match (n.as_u64(), n.as_i64()) {
            (Some(u), _) => (false, u256_from(u)),
            (None, Some(i)) => (true, u256_from(i.unsigned_abs())),
            _ => return Err(Error::Argument),
        },
        Some(Value::String(s)) => match s.strip_prefix('-') {
            Some(d) => (true, u256_dec(d).ok_or(Error::Argument)?),
            None => (false, uint_value(v)?),
        },
        other => (false, uint_value(other)?),
    };
    // a positive value below 2^(N-1), a negative one at most 2^(N-1) in magnitude
    let limit = bits - 1;
    let ok = if neg { mag == [0; 32] || bit_len(&u256_sub_one(&mag)) <= limit } else { bit_len(&mag) <= limit };
    if !ok {
        return Err(Error::Argument);
    }
    if !neg || mag == [0; 32] {
        return Ok(mag);
    }
    let mut w = mag.map(|b| !b);
    for b in w.iter_mut().rev() {
        let (v, carry) = b.overflowing_add(1);
        *b = v;
        if !carry {
            break;
        }
    }
    Ok(w)
}
fn u256_sub_one(x: &U256) -> U256 {
    let mut w = *x;
    for b in w.iter_mut().rev() {
        let (v, borrow) = b.overflowing_sub(1);
        *b = v;
        if !borrow {
            break;
        }
    }
    w
}

/// Hex with an optional `0x` / `0X` (clientkeys `fromHex`): even length, hex digits.
pub(crate) fn from_hex(s: &str) -> Option<Vec<u8>> {
    let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if !h.len().is_multiple_of(2) {
        return None;
    }
    (0..h.len() / 2).map(|i| h.get(2 * i..2 * i + 2).and_then(|p| u8::from_str_radix(p, 16).ok())).collect()
}
pub(crate) fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(2 + 2 * b.len());
    s.push_str("0x");
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}
fn hex_of(v: Option<&Value>) -> Result<Option<Vec<u8>>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => from_hex(s).map(Some).ok_or(Error::Argument),
        _ => Err(Error::Argument),
    }
}

fn encode_atom(ty: &str, v: Option<&Value>) -> Result<[u8; 32]> {
    let mut w = [0u8; 32];
    match ty {
        "string" => match v {
            None | Some(Value::Null) => Ok(keccak256(b"")),
            Some(Value::String(s)) => Ok(keccak256(s.as_bytes())),
            _ => Err(Error::Argument),
        },
        "bytes" => Ok(keccak256(&hex_of(v)?.unwrap_or_default())),
        "address" => {
            let a = hex_of(v)?.unwrap_or_else(|| vec![0; 20]);
            w.get_mut(12..).filter(|_| a.len() == 20).ok_or(Error::Argument)?.copy_from_slice(&a);
            Ok(w)
        }
        "bool" => match v {
            None | Some(Value::Null) | Some(Value::Bool(false)) => Ok(w),
            Some(Value::Bool(true)) => Ok(u256_from(1)),
            _ => Err(Error::Argument),
        },
        _ => {
            if let Some(n) = bytes_n(ty) {
                let b = hex_of(v)?.unwrap_or_else(|| vec![0; n]);
                w.get_mut(..n).filter(|_| b.len() == n).ok_or(Error::Argument)?.copy_from_slice(&b);
                Ok(w)
            } else if let Some(bits) = uint_bits(ty) {
                let x = uint_value(v)?;
                if bit_len(&x) > bits {
                    return Err(Error::Argument);
                }
                Ok(x)
            } else if let Some(bits) = int_bits(ty) {
                int_word(v, bits)
            } else {
                Err(Error::Argument)
            }
        }
    }
}

/// The present domain fields in EIP-712 order.
fn domain_fields(domain: &Map<String, Value>) -> Fields {
    DOMAIN_FIELDS.iter().filter(|(n, _)| domain.contains_key(*n)).map(|(n, t)| (n.to_string(), t.to_string())).collect()
}
fn type_string(name: &str, fields: &Fields) -> String {
    format!("{name}({})", fields.iter().map(|(n, t)| format!("{t} {n}")).collect::<Vec<_>>().join(","))
}
/// `"t1 n1,t2 n2"` → fields.
fn parse_fields(list: &str) -> Result<Fields> {
    list.split(',')
        .filter(|f| !f.is_empty())
        .map(|f| f.split_once(' ').map(|(t, n)| (n.to_string(), t.to_string())).ok_or(Error::Argument))
        .collect()
}

impl TypedData {
    /// The typed data of `json` (`eth_signTypedData_v4`'s object), within the caps of spec §9.3; `Argument` otherwise.
    pub fn from_json(json: &[u8]) -> Result<TypedData> {
        TypedData::from_value(bounded::json(json, MAX_LEN, MAX_JSON_DEPTH)?)
    }

    pub(crate) fn from_value(v: Value) -> Result<TypedData> {
        let Value::Object(mut o) = v else { return Err(Error::Argument) };
        let (Some(Value::Object(types)), Some(Value::String(primary_type)), Some(Value::Object(domain)), Some(message)) =
            (o.remove("types"), o.remove("primaryType"), o.remove("domain"), o.remove("message"))
        else {
            return Err(Error::Argument);
        };
        if !o.is_empty() || types.len() > MAX_TYPES {
            return Err(Error::Argument);
        }
        let (mut structs, mut domain_type) = (BTreeMap::new(), None);
        for (name, fields) in types {
            let Value::Array(fields) = fields else { return Err(Error::Argument) };
            if !ident(&name) || fields.len() > MAX_FIELDS {
                return Err(Error::Argument);
            }
            let mut list = Fields::new();
            for f in fields {
                let Value::Object(mut f) = f else { return Err(Error::Argument) };
                let (Some(Value::String(n)), Some(Value::String(t))) = (f.remove("name"), f.remove("type")) else {
                    return Err(Error::Argument);
                };
                if !f.is_empty() || !ident(&n) || list.iter().any(|(m, _)| *m == n) {
                    return Err(Error::Argument);
                }
                list.push((n, t));
            }
            if name == DOMAIN {
                domain_type = Some(list);
            } else {
                structs.insert(name, list);
            }
        }
        if domain.keys().any(|k| !DOMAIN_FIELDS.iter().any(|(n, _)| n == k)) || domain_type.is_some_and(|t| t != domain_fields(&domain)) {
            return Err(Error::Argument);
        }
        let td = TypedData { types: structs, primary_type, domain, message };
        td.validate()?;
        Ok(td)
    }

    /// The primary type is a struct; every field type an atom or a struct of `types` under array dimensions of at most 1,024;
    /// references acyclic and at most 8 deep (a struct of atoms is 1 deep, each struct or array level adds 1).
    fn validate(&self) -> Result<()> {
        if !self.types.contains_key(&self.primary_type) {
            return Err(Error::Argument);
        }
        let mut memo = BTreeMap::new();
        for name in self.types.keys() {
            self.depth(name, &mut memo)?;
        }
        Ok(())
    }
    fn depth(&self, name: &str, memo: &mut BTreeMap<String, Option<usize>>) -> Result<usize> {
        match memo.get(name) {
            Some(Some(d)) => return Ok(*d),
            Some(None) => return Err(Error::Argument), // a cycle
            None => {}
        }
        memo.insert(name.to_string(), None);
        let mut d = 1;
        for (_, ty) in self.types.get(name).ok_or(Error::Argument)? {
            let (b, dims) = base(ty)?;
            let inner = if self.types.contains_key(b) {
                self.depth(b, memo)?
            } else if atom(b) {
                0
            } else {
                return Err(Error::Argument);
            };
            d = d.max(1 + inner + dims);
        }
        if d > MAX_TYPE_DEPTH {
            return Err(Error::Argument);
        }
        memo.insert(name.to_string(), Some(d));
        Ok(d)
    }

    pub fn primary_type(&self) -> &str {
        &self.primary_type
    }

    /// `{types, primaryType, domain, message}` as hashed (`EIP712Domain` the fields present in `domain`).
    pub fn to_value(&self) -> Value {
        let mut types: Map<String, Value> = Map::new();
        let list = |f: &Fields| Value::Array(f.iter().map(|(n, t)| serde_json::json!({"name": n, "type": t})).collect());
        types.insert(DOMAIN.to_string(), list(&domain_fields(&self.domain)));
        for (n, f) in &self.types {
            types.insert(n.clone(), list(f));
        }
        serde_json::json!({"types": types, "primaryType": self.primary_type, "domain": self.domain, "message": self.message})
    }

    /// EIP-712 `encodeType` of the primary type: it, then every struct it references, sorted by name.
    pub fn encode_type(&self) -> String {
        self.encode_type_of(&self.primary_type)
    }
    fn encode_type_of(&self, primary: &str) -> String {
        let mut deps = BTreeSet::new();
        self.walk(primary, primary, &mut deps);
        std::iter::once(primary)
            .chain(deps.iter().map(String::as_str))
            .filter_map(|t| self.types.get(t).map(|f| type_string(t, f)))
            .collect()
    }
    fn walk(&self, t: &str, primary: &str, deps: &mut BTreeSet<String>) {
        for (_, ty) in self.types.get(t).map_or(&[][..], |f| f.as_slice()) {
            if let Ok((b, _)) = base(ty) {
                if self.types.contains_key(b) && b != primary && deps.insert(b.to_string()) {
                    self.walk(b, primary, deps);
                }
            }
        }
    }

    fn hash_struct(&self, name: &str, v: Option<&Value>) -> Result<[u8; 32]> {
        let fields = self.types.get(name).ok_or(Error::Argument)?;
        let empty = Map::new();
        let o = match v {
            None | Some(Value::Null) => &empty,
            Some(Value::Object(o)) => o,
            _ => return Err(Error::Argument),
        };
        if o.keys().any(|k| !fields.iter().any(|(n, _)| n == k)) {
            return Err(Error::Argument);
        }
        let mut enc = keccak256(self.encode_type_of(name).as_bytes()).to_vec();
        for (n, ty) in fields {
            enc.extend_from_slice(&self.encode_value(ty, o.get(n))?);
        }
        Ok(keccak256(&enc))
    }

    fn encode_value(&self, ty: &str, v: Option<&Value>) -> Result<[u8; 32]> {
        if let Some((elem, len)) = outer(ty)? {
            let items = items(v, len)?;
            let mut enc = Vec::with_capacity(32 * items.len());
            for x in items {
                enc.extend_from_slice(&self.encode_value(elem, x)?);
            }
            return Ok(keccak256(&enc));
        }
        if self.types.contains_key(ty) {
            return self.hash_struct(ty, v);
        }
        encode_atom(ty, v)
    }

    /// `hashStruct(EIP712Domain, domain)` over the fields present.
    pub fn domain_separator(&self) -> Result<[u8; 32]> {
        let fields = domain_fields(&self.domain);
        let mut enc = keccak256(type_string(DOMAIN, &fields).as_bytes()).to_vec();
        for (n, ty) in &fields {
            enc.extend_from_slice(&encode_atom(ty, self.domain.get(n))?);
        }
        Ok(keccak256(&enc))
    }
    /// `hashStruct(primaryType, message)`.
    pub fn struct_hash(&self) -> Result<[u8; 32]> {
        self.hash_struct(&self.primary_type, Some(&self.message))
    }
    /// `keccak256(0x1901 ‖ domain separator ‖ struct hash)`: the digest a signature is over.
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(eip712_digest(&self.domain_separator()?, &self.struct_hash()?))
    }

    /// The domain's `name` and `verifyingContract` as given (the policy's checks read them).
    pub(crate) fn domain(&self) -> &Map<String, Value> {
        &self.domain
    }
    pub(crate) fn message(&self) -> &Value {
        &self.message
    }
    /// The fields of struct `name` (`EIP712Domain` apart), and how many structs the value declares.
    pub(crate) fn fields_of(&self, name: &str) -> Option<&Fields> {
        self.types.get(name)
    }
    pub(crate) fn struct_count(&self) -> usize {
        self.types.len()
    }

    /// clientkeys `canonical` (the SCaaS builders only): every field present (missing: its zero), `uint` ≤ 32 bits as a JSON number,
    /// wider as a decimal string, `bytes` / `bytesN` lower-case hex, and in each struct with `mode`, `relayer` and `feeRecipient`
    /// the unbound ones zeroed. No `int` field in a SCaaS struct: refused.
    fn canonical(&self, ty: &str, v: Option<&Value>) -> Result<Value> {
        if let Some((elem, len)) = outer(ty)? {
            return items(v, len)?.into_iter().map(|x| self.canonical(elem, x)).collect::<Result<Vec<_>>>().map(Value::Array);
        }
        if let Some(fields) = self.types.get(ty) {
            let empty = Map::new();
            let o = match v {
                None | Some(Value::Null) => &empty,
                Some(Value::Object(o)) => o,
                _ => return Err(Error::Argument),
            };
            if o.keys().any(|k| !fields.iter().any(|(n, _)| n == k)) {
                return Err(Error::Argument);
            }
            let mut m = Map::new();
            for (n, t) in fields {
                m.insert(n.clone(), self.canonical(t, o.get(n))?);
            }
            if ["mode", "relayer", "feeRecipient"].iter().all(|k| m.contains_key(*k)) {
                let mode = uint_value(m.get("mode"))?.last().copied().unwrap_or(0);
                if mode & 1 == 0 {
                    m.insert("relayer".into(), ZERO_ADDRESS.into());
                }
                if mode & 2 == 0 {
                    m.insert("feeRecipient".into(), ZERO_ADDRESS.into());
                }
            }
            return Ok(Value::Object(m));
        }
        encode_atom(ty, v)?; // the value checks
        Ok(match ty {
            "address" => v.filter(|x| !x.is_null()).cloned().unwrap_or_else(|| ZERO_ADDRESS.into()),
            "bool" => Value::Bool(matches!(v, Some(Value::Bool(true)))),
            "string" => v.filter(|x| !x.is_null()).cloned().unwrap_or_else(|| "".into()),
            "bytes" => to_hex(&hex_of(v)?.unwrap_or_default()).into(),
            _ => {
                if let Some(n) = bytes_n(ty) {
                    to_hex(&hex_of(v)?.unwrap_or_else(|| vec![0; n])).into()
                } else if let Some(bits) = uint_bits(ty) {
                    let x = uint_value(v)?;
                    if bits <= 32 {
                        Value::from(u64::from(u32::from_be_bytes(x.get(28..).and_then(|b| b.try_into().ok()).ok_or(Error::Argument)?)))
                    } else {
                        u256_to_dec(&x).into()
                    }
                } else {
                    return Err(Error::Argument);
                }
            }
        })
    }
}

/// An array value's items: missing is `[]` (dynamic) or k zeros (`T[k]`); at most 1,024; `T[k]` exactly k.
fn items(v: Option<&Value>, len: Option<usize>) -> Result<Vec<Option<&Value>>> {
    let items: Vec<Option<&Value>> = match v {
        None | Some(Value::Null) => vec![None; len.unwrap_or(0)],
        Some(Value::Array(a)) => a.iter().map(Some).collect(),
        _ => return Err(Error::Argument),
    };
    if items.len() > MAX_ARRAY || len.is_some_and(|k| k != items.len()) {
        return Err(Error::Argument);
    }
    Ok(items)
}

pub(crate) fn eip712_digest(domain_separator: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    keccak256(&[&[0x19, 0x01][..], domain_separator, struct_hash].concat())
}

/// The request for `td`'s digest, the value carried for a clear-signing screen.
pub(crate) fn request(td: &TypedData) -> Result<SignRequest> {
    Ok(SignRequest::Eip712 { domain_separator: td.domain_separator()?, struct_hash: td.struct_hash()?, typed_data: Box::new(td.clone()) })
}

/// `UAAuth(ua, purpose, digest)` under the registry's domain `("SCaaS UARegistry", generation, chainId, registry, chainUid)`: what a
/// native signer behind the registry signs (CTR-UA-24, CTR-MTX-14); its digest is `crate::ua_auth_digest`.
pub(crate) fn ua_auth(d: &Domain, ua: &[u8; 32], purpose: &[u8; 32], digest: &[u8; 32]) -> Result<TypedData> {
    let b32 = |n: &str| serde_json::json!({"name": n, "type": "bytes32"});
    TypedData::from_value(serde_json::json!({
        "types": {"UAAuth": [b32("ua"), b32("purpose"), b32("digest")]},
        "primaryType": "UAAuth",
        "domain": {"name": REGISTRY_NAME, "version": d.generation.to_string(), "chainId": d.chain_id.to_string(),
            "verifyingContract": to_hex(&d.registry), "salt": to_hex(&d.chain_uid)},
        "message": {"ua": to_hex(ua), "purpose": to_hex(purpose), "digest": to_hex(digest)},
    }))
}

/// `UAMembership{ua, member}` in the portable domain (CTR-UA-37): what a native member signs to accept its slot.
pub(crate) fn membership(ua: &[u8; 32], member: &[u8; 32]) -> Result<TypedData> {
    let b32 = |n: &str| serde_json::json!({"name": n, "type": "bytes32"});
    TypedData::from_value(serde_json::json!({
        "types": {"UAMembership": [b32("ua"), b32("member")]},
        "primaryType": "UAMembership",
        "domain": {"name": crate::ua8::PORTABLE_DOMAIN_NAME, "version": crate::ua8::PORTABLE_DOMAIN_VERSION},
        "message": {"ua": to_hex(ua), "member": to_hex(member)},
    }))
}

// --- the SCaaS structs (clientkeys `STRUCTS`, `OPS`; plan Part C, Appendix X.4 of typed signing) ---

macro_rules! envelope {
    () => {
        "uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient"
    };
}
const E: &str = envelope!();
macro_rules! order {
    ($id:literal) => {
        concat!($id, " from,address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,uint256 fee,address relayer,",
            "address dex,", $id, " destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil")
    };
}
macro_rules! wrap_order {
    ($id:literal) => {
        concat!($id, " from,address wrappedToken,uint256 amount,uint256 minMinted,uint256 minFill,uint256 fee,address relayer,",
            $id, " destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil")
    };
}
macro_rules! relay_fee {
    ($id:literal) => {
        concat!($id, " from,address target,bytes32 callDataHash,", $id, " payee,uint256 value,uint256 batch,uint256 nonce,",
            "uint256 validUntil,address relayer")
    };
}

/// Every struct a signed type nests, and the builder-only structs of the generic path (`MetaTransaction`, `UAMetaTransfer`, the
/// orders, the nonce invalidations). ua-mtx-merge (CTR-MTX-30, R12, R39, R46): the token's address `MetaTransfer`, `TradeOrder`
/// and `WrapOrder` left; `TradeOrder` stays nested in the DEX's `DexOrder`. Group 3g (KV-8): `keyVersion` after `fromUA`. Group 3h
/// (proof-path spec §3.2, PP-3): `bytes32 ownTag` after `salt` (`PqzTransferArgs`, `PqzMultiArgs`) and after `beneficiaryUA`
/// (`PqzBurnArgs`).
const STRUCTS: &[(&str, &str)] = &[
    ("TradeOrder", order!("address")),
    ("UATradeOrder", order!("bytes32")),
    ("DexOrder", "address sellToken,TradeOrder order"),
    ("UAWrapOrder", wrap_order!("bytes32")),
    ("UAMetaTransfer", concat!("bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,", envelope!())),
    ("MetaTransaction", concat!("address from,bytes data,", envelope!())),
    ("UAMetaTransaction", concat!("bytes32 from,bytes data,", envelope!())),
    ("InvalidateNonces", "address from,uint256 batch,uint256 minNonce"),
    ("UAInvalidateNonces", "bytes32 from,uint256 batch,uint256 minNonce"),
    ("PqzTransferArgs", "uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 toUA,bytes32 beneficiaryUA,bytes16 salt,bytes32 ownTag,bytes u,bytes vTo,bytes vFrom,bytes vAuditor,bytes sealedMemo"),
    ("PqzLeg", "bytes32 ua,bytes v,bytes vAuditor"),
    ("PqzMultiArgs", "uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 beneficiaryUA,uint256 decoyFee,bytes16 salt,bytes32 ownTag,bytes[] u,PqzLeg[] legs,bytes vFrom,bytes sealedMemo"),
    ("PqzBurnArgs", "uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 beneficiaryUA,bytes32 ownTag,bytes u,bytes vFrom"),
    ("Unwrap", "address underlying,bytes32 recipient,uint256 amount,uint256 minOut"),
    ("G1", "bytes32 x0,bytes32 x1,bytes32 y0,bytes32 y1"),
    ("ZetherSingle", "uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes16 salt,bytes32 beneficiaryUA,G1 yFrom,G1 yTo,G1 cOut,G1 dOut,G1 cDeb,G1 cAud"),
    ("ZetherLeg", "G1 yTo,G1 cOut,G1 cAud,G1 dAud"),
    ("ZetherMulti", "uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes16 salt,bytes32 beneficiaryUA,uint256 decoyFee,G1 yFrom,G1 dOut,G1 cDeb,ZetherLeg[] legs,bytes sealedMemo"),
    ("ZetherBurn", "uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes32 beneficiaryUA,G1 yFrom"),
    ("GrantTerms", "uint128 min,uint128 max,uint128 total,uint128 perWindow,uint32 window,uint64 validUntil,uint32 maxUses,bool delegable,bytes32 scope"),
    // group 3f (PQZ verifier mode spec §5.1): what a PQZ verifier UA signs in the token's domain ([`pqz_verdict_typed_data`])
    ("PqzVerdict", "address token,uint256 chainId,bytes32 proofSystemId,bytes32 statementHash,bytes32 proofHash,uint32 pqzVerifierEpoch,uint64 validUntil"),
];

const M: &str = "SCaaS MetaToken";
const Z: &str = "SCaaS ZetherToken";
const P: &str = "SCaaS PqzToken";
const WALLET: &str = "SCaaS MandateWallet";
const ACCOUNT: &str = "SCaaS SmartKeyAccount";
const DEX: &str = "SCaaS Dex";
const ROUTER: &str = "SCaaS GovernanceRouter";
/// The domains of clientkeys' contract groups, by name: `TOKENS` = `NORMAL` = `WRAPPED` = `REGULATED`, `CONFIDENTIAL` =
/// `WRAPPED_CONFIDENTIAL`, `ZETHER`, `PQZ`.
const TOKENS: &[&str] = &[M, Z, P];
const CONFIDENTIAL: &[&str] = &[Z, P];

/// One signed struct (clientkeys `OPS`), by its row name `name`: the struct `primary` (the row name but for `UAPqzRollOver`, the
/// PQZ `UARollOver`), `fields` the op's own (`<primary>(bytes32 from,<fields>,E)` for a `UA` name, else `address from`), or
/// with `raw` the whole struct; `on` its domains; `amount` the field of an AMOUNT fee class.
struct Op {
    name: &'static str,
    primary: &'static str,
    fields: &'static str,
    raw: bool,
    on: &'static [&'static str],
    amount: Option<&'static str>,
}
const fn op(name: &'static str, fields: &'static str, on: &'static [&'static str], amount: Option<&'static str>) -> Op {
    Op { name, primary: name, fields, raw: false, on, amount }
}
const fn raw(name: &'static str, fields: &'static str, on: &'static [&'static str]) -> Op {
    Op { name, primary: name, fields, raw: true, on, amount: None }
}
/// ua-mtx-merge (CTR-MTX-30): one signed entry per operation, `UA<Op>` the merged entry on ids; an address struct only where the op
/// has no merged entry (the five wraps, every op of `SmartKeyAccount`).
const OPS: &[Op] = &[
    op("CancelNonce", "uint256 lane", &[ACCOUNT], None),
    op("UACancelNonce", "uint256 lane", &[M, Z, P, WALLET, ROUTER], None),
    op("UABurn", "uint256 amount", TOKENS, Some("amount")),
    op("Wrap", "uint256 amount", TOKENS, None),
    op("WrapLeg", "address underlying,uint256 amount", TOKENS, None),
    op("UAUnwrap", "uint256 wrapped,address recipient,uint256 minOut", TOKENS, Some("wrapped")),
    op("UAUnwrapLeg", "address underlying,uint256 wrapped,address recipient,uint256 minOut", TOKENS, Some("wrapped")),
    op("AddReserve", "address underlying,uint256 amount", TOKENS, None),
    op("WrapToUA", "address underlying,uint256 amount,bytes32 to", TOKENS, None),
    op("UAUnwrapToUA", "address underlying,uint256 wrapped,bytes32 to,uint256 minOut", TOKENS, Some("wrapped")),
    op("UAShield", "bytes32 toUA,uint256 amount", CONFIDENTIAL, None),
    op("WrapShield", "address underlying,uint256 amountIn,bytes32 toUA", CONFIDENTIAL, None),
    // group 3g (KV-10): Zether keeps `UARollOver(…,bytes32 ua,uint256 n,…)`; the PQZ rollover and prepare name the key version
    op("UARollOver", "bytes32 ua,uint256 n", &[Z], None),
    Op { name: "UAPqzRollOver", primary: "UARollOver", fields: "bytes32 ua,uint64 keyVersion,uint256 n", raw: false, on: &[P], amount: None },
    op("UAPrepareAcc", "bytes32 ua,uint64 keyVersion,uint256 half", &[P], None),
    op("UASetMandate", "address token,bytes32 delegate,uint128 maxPerPayment,uint128 maxPerPeriod,uint64 periodSeconds,uint64 expiry", &[WALLET], None),
    op("UASetPayee", "address token,bytes32 payee,bool allowed", &[WALLET], None),
    op("UARevokeMandate", "address token", &[WALLET], None),
    op("UAPayUnderMandate", "address token,bytes32 payee,uint256 amount,bytes32 entryRef,uint64 epoch", &[WALLET], None),
    op("UADelegateRevoke", "address token,uint64 epoch", &[WALLET], None),
    op("UAExecute", "address target,uint256 value,bytes data", &[WALLET], None),
    op("AddKey", "uint8 kind,bytes32 x,bytes32 y,bytes32 rpIdHash,bytes32 originHash", &[ACCOUNT], None),
    op("RemoveKey", "uint256 index", &[ACCOUNT], None),
    op("RotateKey", "uint256 index,uint8 kind,bytes32 x,bytes32 y,bytes32 rpIdHash,bytes32 originHash", &[ACCOUNT], None),
    op("SetGuardian", "address guardian", &[ACCOUNT], None),
    op("CancelRecovery", "", &[ACCOUNT], None),
    op("Execute", "address target,uint256 value,bytes data", &[ACCOUNT], None),
    op("UAPqzTransferSingle", "PqzTransferArgs args,bytes proof,bytes accHint", &[P], None),
    op("UAPqzTransferSingleCompact", "PqzTransferArgs args,bytes proof,bytes accHint", &[P], None),
    op("UAPqzTransfer", "PqzMultiArgs args,bytes proof,bytes accHint", &[P], None),
    op("UAPqzTransferCompact", "PqzMultiArgs args,bytes proof,bytes accHint", &[P], None),
    op("UAPqzUnshield", "PqzBurnArgs args,uint256 amount,bytes32 recipient,bytes proof,bytes accHint", &[P], None),
    op("UAPqzUnshieldUnwrap", "PqzBurnArgs args,Unwrap unwrap,bytes proof,bytes accHint", &[P], None),
    op("UAZetherTransferSingle", "ZetherSingle args,bytes proof", &[Z], None),
    op("UAZetherTransfer", "ZetherMulti args,bytes proof", &[Z], None),
    op("UAZetherTransferCompact", "ZetherMulti args,bytes proof", &[Z], None),
    op("UAZetherUnshield", "ZetherBurn args,uint256 amount,bytes32 recipient,bytes proof", &[Z], None),
    op("UAZetherUnshieldUnwrap", "ZetherBurn args,Unwrap unwrap,bytes proof", &[Z], None),
    op("UARollOverSigned", "bytes32 ua,uint64 expectedPendingSeq,uint64 validUntilBlock", &[Z], None),
    op("UASetRollOverMode", "bytes32 ua,uint8 rollOverMode,uint64 validUntilBlock", &[Z], None),
    op("UARollOverBatch", "bytes32[] uas", &[Z], None),
    raw("UAReceiverFee", "UAMetaTransfer payment,uint256 fee,address feeRecipient,uint256 validUntil", TOKENS),
    // pay-meta-tax spec §5.2: the regulated kinds 8-13 sign in the base kinds' domains
    raw("UAPayWithTax", "UAMetaTransfer payment,uint8 taxMode,uint256 tax", TOKENS),
    raw("UARelayFee", relay_fee!("bytes32"), TOKENS),
    raw("UAWrapOrder", wrap_order!("bytes32"), TOKENS),
    raw("CancelUAOrder", "UATradeOrder order", TOKENS),
    raw("CancelUAWrapOrder", "UAWrapOrder order", TOKENS),
    raw("CancelDexOrder", "DexOrder order", &[DEX]),
    raw("ZetherRollOver", "bytes32 ua,uint64 accSeq,uint64 expectedPendingSeq,uint64 validUntilBlock", &[Z]),
    raw("ZetherSetRollOverMode", "bytes32 ua,uint8 mode,uint64 modeNonce,uint64 validUntilBlock", &[Z]),
    op("UAGrantRole", "address target,uint8 bit,bytes32 account", &[ROUTER], None),
    op("UARevokeRole", "address target,uint8 bit,bytes32 account", &[ROUTER], None),
    op("UASetGrant", "address target,uint8 bit,bytes32 holder,GrantTerms terms", &[ROUTER], None),
    op("UACancelGrant", "address target,uint8 bit,bytes32 account", &[ROUTER], None),
    op("UADisableFeature", "address target,uint8 bit", &[ROUTER], None),
    op("UATransferOwnership", "address target,bytes32 newOwner", &[ROUTER], None),
    op("UAAcceptOwnership", "address target", &[ROUTER], None),
    op("UARenounceOwnership", "address target", &[ROUTER], None),
    op("UARenounceRole", "address target,uint8 bit", &[ROUTER], None),
    op("UAMint", "address target,address to,uint256 amount", &[ROUTER], None),
    op("UAMintToUA", "address target,bytes32 to,uint256 amount", &[ROUTER], None),
    op("UADisableWrap", "address target,address leg,bytes32 reason", &[ROUTER], None),
    op("UAProposeRate", "address target,address leg,uint96 num,uint96 den", &[ROUTER], None),
    op("UACancelRate", "address target", &[ROUTER], None),
    op("UAExecuteRate", "address target", &[ROUTER], None),
    op("UASetMarket", "address target,address base,address quote,bool listed", &[ROUTER], None),
    op("UASetExchangeTarget", "address target,address exchangeTarget,bool listed", &[ROUTER], None),
    op("UASetListedOnly", "address target,bool on", &[ROUTER], None),
    op("UASetFeeSplit", "address target,uint32 relayerSharePpm,address treasury", &[ROUTER], None),
    // the factory's creations through the router (chain-neutral spec §4.4, S3; ua-mtx-merge T76): `target` the chain's
    // `OpenFactory`, the signing UA the creator, `initHash = keccak256(initArgs)` (`initCall` for an instance) signed
    op("UACreateToken", "address target,uint8 kind,uint64 version,bytes32 initHash,bytes32 salt", &[ROUTER], None),
    op("UACreateDex", "address target,uint64 version,bytes32 initHash,bytes32 salt", &[ROUTER], None),
    op("UACreateInstance", "address target,uint16 contractClass,uint16 kind,uint64 version,bytes32 initHash,bytes32 salt", &[ROUTER], None),
    // the regulated kinds' controls (regulated-kinds spec §3.1) and bit 23 `TAX` (pay-meta-tax spec §6.2)
    op("UAFreeze", "address target,bytes32 account,bytes32 ref,bytes32 recordId", &[ROUTER], None),
    op("UAUnfreeze", "address target,bytes32 account,bytes32 ref", &[ROUTER], None),
    op("UAForceTransfer", "address target,bytes32 recordId,uint256 amount", &[ROUTER], None),
    op("UAPause", "address target,bytes32 ref,uint64 until", &[ROUTER], None),
    op("UAUnpause", "address target,bytes32 ref", &[ROUTER], None),
    op("UARecordOrder", "address target,bytes32 orderId,bytes32 documentHash,bytes32 subject,bytes32 beneficiary,uint256 maxAmount,uint64 freezeUntil", &[ROUTER], None),
    op("UARevokeOrder", "address target,bytes32 recordId,bytes32 reasonRef", &[ROUTER], None),
    op("UAOperatorTransfer", "address target,bytes32 account,bytes32 to,uint256 amount,bytes32 ref", &[ROUTER], None),
    op("UASetTaxRate", "address target,uint32 ratePpm", &[ROUTER], None),
    op("UASetTaxRecipient", "address target,bytes32 taxRecipient", &[ROUTER], None),
    // the PQZ verifier UA of the PQZ kinds 4, 5, 12, 13 (group 3f, PQZ verifier mode spec §4.2, §4.3): the owner's, no bit
    op("UAPqzSetVerifier", "address target,bytes32 next", &[ROUTER], None),
    op("UAPqzCancelVerifier", "address target", &[ROUTER], None),
    op("UAPqzRevokeVerifier", "address target", &[ROUTER], None),
    // group 3h (proof-path spec §5, PP-5): bit 24 `PQZ_PROOF`'s router op, the token's `proofStore` from its next debit
    op("UASetProofStore", "address target,uint8 next", &[ROUTER], None),
    raw("PqzAuth", "uint8 op,bytes32 opTag,bytes32 psid,uint256 chainId,address token,address registry,bytes32 from,bytes32 to,bytes32 beneficiary,uint256 fee,uint256 amount,bytes32 recipient,uint64 sendCounter,uint64 p,uint256 validUntilBlock,bool auditorOn,uint256 shieldIn,bytes32 chainUid,bytes32 binding,uint128 salt,bytes32 memoHash,bytes32 bodyHash", &[P]),
];
/// The generic path's builders (clientkeys `metaTxTypedData`, `uaMetaTxTypedData`, `uaMetaTransferTypedData`,
/// `uaTradeOrderTypedData`, `tradeOrderTypedData` (a `DexOrder`), `invalidateNoncesTypedData`, `uaInvalidateNoncesTypedData`):
/// any domain name, this one when none is given (`MetaTransaction`: none, a name is required).
const FREE: &[(&str, Option<&str>)] = &[
    ("MetaTransaction", None),
    ("UAMetaTransaction", Some(M)),
    ("UAMetaTransfer", Some(M)),
    ("UATradeOrder", Some(M)),
    ("DexOrder", Some(DEX)),
    ("InvalidateNonces", Some(M)),
    ("UAInvalidateNonces", Some(M)),
];

/// A SCaaS struct: its primary type and own fields, its domains (empty: a generic-path struct, any name), its default domain name,
/// whether it closes with the envelope `E`, and its amount field.
pub(crate) struct Def {
    pub(crate) primary: &'static str,
    own: String,
    domains: &'static [&'static str],
    default_name: Option<&'static str>,
    pub(crate) envelope: bool,
    pub(crate) amount: Option<&'static str>,
}
fn op_def(o: &Op) -> Def {
    let own = if o.raw {
        o.fields.to_string()
    } else {
        let from = if o.primary.starts_with("UA") { "bytes32 from" } else { "address from" };
        [from, o.fields, E].iter().filter(|f| !f.is_empty()).copied().collect::<Vec<_>>().join(",")
    };
    let default_name = match o.on {
        [one] => Some(*one),
        _ => None,
    };
    Def { primary: o.primary, own, domains: o.on, default_name, envelope: !o.raw, amount: o.amount }
}
fn free_def(name: &str) -> Option<Def> {
    let (primary, default_name) = FREE.iter().find(|(n, _)| *n == name)?;
    let (_, own) = STRUCTS.iter().find(|(n, _)| n == primary)?;
    Some(Def { primary, own: own.to_string(), domains: &[], default_name: *default_name, envelope: false, amount: None })
}
/// The SCaaS struct of row `name` (clientkeys `TYPED_OPS[name]`), or a generic-path struct.
pub(crate) fn def(name: &str) -> Option<Def> {
    OPS.iter().find(|o| o.name == name).map(op_def).or_else(|| free_def(name))
}
/// A row of the op table only (clientkeys `TYPED_OPS[name]`; `checkOp` takes no generic-path struct).
pub(crate) fn op_row(name: &str) -> Option<Def> {
    OPS.iter().find(|o| o.name == name).map(op_def)
}
/// The SCaaS struct of primary type `primary` signed in the domain `name` (omitted: the only struct of that primary type).
fn def_in(primary: &str, name: Option<&str>) -> Result<Def> {
    let mut of = OPS.iter().filter(|o| o.primary == primary).peekable();
    if of.peek().is_none() {
        return free_def(primary).ok_or(Error::Argument);
    }
    let found: Vec<&Op> = of.filter(|o| name.is_none_or(|n| o.on.contains(&n))).collect();
    match found.as_slice() {
        [o] => Ok(op_def(o)),
        _ => Err(Error::Argument),
    }
}

/// The SCaaS struct of row `name` (or a generic-path struct) and every struct it nests, keyed by type.
pub(crate) fn op_types(name: &str) -> Result<BTreeMap<String, Fields>> {
    types_of(&def(name).ok_or(Error::Argument)?)
}
fn types_of(d: &Def) -> Result<BTreeMap<String, Fields>> {
    let mut types = BTreeMap::new();
    types.insert(d.primary.to_string(), parse_fields(&d.own)?);
    let mut todo = vec![d.primary.to_string()];
    while let Some(t) = todo.pop() {
        for (_, ty) in types.get(&t).cloned().unwrap_or_default() {
            let (b, _) = base(&ty)?;
            if !atom(b) && !types.contains_key(b) {
                let (_, list) = STRUCTS.iter().find(|(n, _)| *n == b).ok_or(Error::Argument)?;
                types.insert(b.to_string(), parse_fields(list)?);
                todo.push(b.to_string());
            }
        }
    }
    Ok(types)
}

/// clientkeys `opTypedData` and the generic builders: the SCaaS struct `primary_type` of the contract `contract` in its salted
/// domain `(name, "1", chain_id, contract, chain_uid)`, its message `message` in the canonical form (unbound `relayer` /
/// `feeRecipient` zeroed, nested too; spec §5.3). `name` must be one of the struct's domains (omitted: its only one); a primary type
/// signed as two structs (`UARollOver`: Zether's, and the PQZ row `UAPqzRollOver` with `keyVersion`) is the one of the domain named,
/// never chosen without one; a generic-path struct takes any name. `Argument`: no SCaaS struct of that name, another domain, a value
/// its type refuses.
pub fn scaas_typed_data(
    primary_type: &str, name: Option<&str>, contract: &[u8; 20], chain_id: u64, chain_uid: &[u8; 32], message: &Value,
) -> Result<TypedData> {
    typed_data_of(&def_in(primary_type, name)?, name, contract, chain_id, chain_uid, message)
}

/// clientkeys `pqzVerdictTypedData` (group 3f, PQZ verifier mode spec §5.1): the `PqzVerdict` a PQZ verifier UA signs, in the PQZ
/// token's salted domain `("SCaaS PqzToken", "1", chain_id, contract, chain_uid)`, under the purpose `pqz-verdict` (a native verifier
/// over the registry's `uaAuthDigest`, a derived one over `uaMessage`). `message.token` and `message.chainId` repeat the domain (the
/// token checks them equal): another value is `Argument`, as is a value its type refuses.
pub fn pqz_verdict_typed_data(contract: &[u8; 20], chain_id: u64, chain_uid: &[u8; 32], message: &Value) -> Result<TypedData> {
    let (primary, own) = STRUCTS.iter().find(|(n, _)| *n == "PqzVerdict").ok_or(Error::Argument)?;
    let d = Def { primary, own: own.to_string(), domains: &[P], default_name: Some(P), envelope: false, amount: None };
    let td = typed_data_of(&d, None, contract, chain_id, chain_uid, message)?;
    let field = |f: &str, ty: &str| encode_atom(ty, td.message.get(f));
    if field("token", "address")? != encode_atom("address", Some(&to_hex(contract).into()))?
        || field("chainId", "uint256")? != encode_atom("uint256", Some(&chain_id.into()))?
    {
        return Err(Error::Argument);
    }
    Ok(td)
}

/// [`scaas_typed_data`] of one struct (a row of the op table: `checkOp` builds the op it was asked for, never another struct of the
/// same primary type).
pub(crate) fn typed_data_of(
    d: &Def, name: Option<&str>, contract: &[u8; 20], chain_id: u64, chain_uid: &[u8; 32], message: &Value,
) -> Result<TypedData> {
    let name = match name {
        Some(n) if d.domains.is_empty() || d.domains.contains(&n) => n,
        None => d.default_name.ok_or(Error::Argument)?,
        Some(_) => return Err(Error::Argument),
    };
    let types = types_of(d)?;
    let mut domain = Map::new();
    domain.insert("name".into(), name.into());
    domain.insert("version".into(), "1".into());
    domain.insert("chainId".into(), chain_id.to_string().into());
    domain.insert("verifyingContract".into(), to_hex(contract).into());
    domain.insert("salt".into(), to_hex(chain_uid).into());
    let mut td = TypedData { types, primary_type: d.primary.to_string(), domain, message: Value::Null };
    td.validate()?;
    td.message = td.canonical(d.primary, Some(message))?;
    Ok(td)
}
