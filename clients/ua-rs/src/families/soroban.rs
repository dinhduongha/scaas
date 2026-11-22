// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Soroban (plan 2026-11-17-scaas-sdk T27.soroban; CLI-SGN-22, CLI-SGN-27; NET-SOR-01, NET-SOR-16): a `G…` subject's op
//! envelope, the host authorization of a token entry (`transfer`, `pay`, `burn`), from named fields. [`check_terms`] rebuilds
//! the `HashIdPreimage::SorobanAuthorization` XDR from the terms and checks them against what was shown; the subject's key
//! signs only that result's `sha256` ([`crate::wallet::NativeKey::sign_soroban_auth`]). Byte-equal to clientkeys
//! `src/fam/soroban.js` (`checkTerms`, `packSignature`, `signedOp`) and its rows in `smartcontracts/vectors/families/soroban.json`;
//! the node rebuilds the same bytes from the same named `payload` (`adapters/soroban.rs` `auth_entry`). UNAUDITED.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::wallet::{Error, Result};

/// strkey version bytes: `G…` (ed25519 account) and `C…` (contract).
const ACCOUNT_VERSION: u8 = 6 << 3;
const CONTRACT_VERSION: u8 = 2 << 3;
/// `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION`.
const ENVELOPE_TYPE_SOROBAN_AUTHORIZATION: u32 = 9;

/// `sha256(passphrase)`, a Soroban network's id.
pub fn network_id(passphrase: &str) -> [u8; 32] {
    Sha256::digest(passphrase.as_bytes()).into()
}

/// A strkey's payload: an account (`G…`) or a contract (`C…`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Address {
    Account([u8; 32]),
    Contract([u8; 32]),
}

fn crc16(b: &[u8]) -> u16 {
    b.iter().fold(0u16, |mut c, &x| {
        c ^= u16::from(x) << 8;
        for _ in 0..8 {
            c = if c & 0x8000 != 0 {
                (c << 1) ^ 0x1021
            } else {
                c << 1
            };
        }
        c
    })
}

impl Address {
    /// A `G…` or `C…` of 56 characters (base32, upper case, no padding), its checksum and padding bits checked.
    pub fn parse(s: &str) -> Option<Address> {
        if s.len() != 56 {
            return None;
        }
        let (mut raw, mut acc, mut bits) = (Vec::with_capacity(35), 0u32, 0);
        for c in s.bytes() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'2'..=b'7' => c - b'2' + 26,
                _ => return None,
            };
            acc = (acc << 5) | u32::from(v);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                raw.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        let (body, crc) = (raw.get(..33)?, raw.get(33..35)?);
        if acc != 0 || crc16(body).to_le_bytes() != crc {
            return None;
        }
        let k: [u8; 32] = body.get(1..)?.try_into().ok()?;
        match *body.first()? {
            ACCOUNT_VERSION => Some(Address::Account(k)),
            CONTRACT_VERSION => Some(Address::Contract(k)),
            _ => None,
        }
    }

    /// Its strkey.
    pub fn text(&self) -> String {
        let (v, k) = match self {
            Address::Account(k) => (ACCOUNT_VERSION, k),
            Address::Contract(k) => (CONTRACT_VERSION, k),
        };
        let mut body = vec![v];
        body.extend_from_slice(k);
        let crc = crc16(&body);
        body.extend_from_slice(&crc.to_le_bytes());
        let (mut out, mut acc, mut bits) = (String::with_capacity(56), 0u32, 0);
        const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        for b in body {
            acc = (acc << 8) | u32::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(char::from(A[((acc >> bits) & 31) as usize]));
            }
        }
        out
    }

    /// The 32-byte key or contract id.
    pub fn key(&self) -> [u8; 32] {
        match self {
            Address::Account(k) | Address::Contract(k) => *k,
        }
    }

    /// `ScAddress` XDR: an account `SC_ADDRESS_TYPE_ACCOUNT ‖ PUBLIC_KEY_TYPE_ED25519 ‖ key`, a contract `SC_ADDRESS_TYPE_CONTRACT ‖ id`.
    pub fn sc_address(&self, out: &mut Vec<u8>) {
        match self {
            Address::Account(k) => {
                u32be(out, 0);
                u32be(out, 0);
                out.extend_from_slice(k);
            }
            Address::Contract(k) => {
                u32be(out, 1);
                out.extend_from_slice(k);
            }
        }
    }
}

/// `0x` + lowercase hex.
fn hex0x(b: &[u8]) -> String {
    let mut s = String::from("0x");
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

pub(crate) fn u32be(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_be_bytes());
}

/// XDR `opaque<>` / `string<>`: length, bytes, zero padding to 4.
pub(crate) fn opaque(out: &mut Vec<u8>, b: &[u8]) {
    u32be(out, b.len() as u32);
    out.extend_from_slice(b);
    out.resize(out.len() + (4 - b.len() % 4) % 4, 0);
}

/// The entries a `G…` subject signs (smartcontracts/soroban/contracts/token), each with its arguments by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    /// `transfer(from, to, amount)` (SEP-41)
    Transfer,
    /// `pay(from, to, amount, pay_ref, valid_until)` (NET-SOR-09)
    Pay,
    /// `burn(from, amount)`
    Burn,
}

impl OpKind {
    pub fn name(self) -> &'static str {
        match self {
            OpKind::Transfer => "transfer",
            OpKind::Pay => "pay",
            OpKind::Burn => "burn",
        }
    }
    pub fn from_name(s: &str) -> Option<OpKind> {
        [OpKind::Transfer, OpKind::Pay, OpKind::Burn]
            .into_iter()
            .find(|k| k.name() == s)
    }
    /// It names a recipient (`to`).
    pub fn has_payee(self) -> bool {
        !matches!(self, OpKind::Burn)
    }
}

/// An op's named fields as the terms give them. `extra`: any other field named (always refused).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OpFields {
    pub from: String,
    pub to: Option<String>,
    /// decimal
    pub amount: String,
    pub pay_ref: Option<Vec<u8>>,
    pub valid_until: Option<u64>,
    pub extra: Vec<String>,
}

/// What the subject is asked to sign (CLI-SGN-27's `terms`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Terms {
    pub network_id: [u8; 32],
    pub contract: String,
    pub kind: String,
    pub fields: OpFields,
    /// the host nonce, an `i64` (wider here so that a value out of range is refused, never wrapped)
    pub nonce: i128,
    /// `signature_expiration_ledger`, a `u32` (wider, as `nonce`)
    pub expiry: i64,
    /// the current ledger and the expiry window above it
    pub ledger: u32,
    pub window: u32,
}

/// What was shown to the user (its own input): the network's passphrase, the token, the entry and its parties and amount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown {
    pub passphrase: String,
    pub contract: String,
    pub kind: String,
    pub from: String,
    pub to: Option<String>,
    pub amount: String,
}

/// A [`check_terms`] result: the op's checked fields and the bytes signed. Made only by `check_terms`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    kind: OpKind,
    contract: Address,
    from: [u8; 32],
    to: Option<Address>,
    amount: i128,
    pay_ref: Option<[u8; 32]>,
    valid_until: Option<u64>,
    nonce: i64,
    expiry: u32,
    network_id: [u8; 32],
    preimage: Vec<u8>,
}

fn refuse<T>() -> Result<T> {
    Err(Error::Argument)
}

/// CLI-SGN-27: the op rebuilt from `t` and checked against `s`, in clientkeys `checkTerms`' order: the entry is known and the
/// one shown; the contract a `C…` and the token shown; no field the entry does not take; `from` the `G…` shown; `to` the
/// recipient shown; the amount the positive `i128` shown; a pay's `pay_ref` 32 bytes and its `valid_until` a time; the network
/// id the shown passphrase's; the expiry ledger within `[ledger, ledger + window]`; the nonce an `i64`. `Argument` for each.
pub fn check_terms(t: &Terms, s: &Shown) -> Result<Checked> {
    let Some(kind) = OpKind::from_name(&t.kind) else {
        return refuse();
    };
    if t.kind != s.kind {
        return refuse();
    }
    let contract = match Address::parse(&t.contract) {
        Some(c @ Address::Contract(_)) if t.contract == s.contract => c,
        _ => return refuse(),
    };
    let f = &t.fields;
    if !f.extra.is_empty()
        || (!kind.has_payee() && f.to.is_some())
        || (kind != OpKind::Pay && (f.pay_ref.is_some() || f.valid_until.is_some()))
    {
        return refuse();
    }
    let from = match Address::parse(&f.from) {
        Some(Address::Account(k)) if f.from == s.from => k,
        _ => return refuse(),
    };
    let to = if kind.has_payee() {
        match (&f.to, &s.to) {
            (Some(a), Some(b)) if a == b => Some(Address::parse(a).ok_or(Error::Argument)?),
            _ => return refuse(),
        }
    } else {
        None
    };
    // a canonical decimal: digits only, no leading zero (the node's job value and clientkeys' row are this text)
    let amount = match f.amount.parse::<i128>() {
        Ok(a) if a > 0 && a.to_string() == f.amount && f.amount == s.amount => a,
        _ => return refuse(),
    };
    let (pay_ref, valid_until) = if kind == OpKind::Pay {
        let r: [u8; 32] = match f.pay_ref.as_deref().map(<[u8; 32]>::try_from) {
            Some(Ok(r)) => r,
            _ => return refuse(),
        };
        match f.valid_until {
            Some(v) if v > 0 => (Some(r), Some(v)),
            _ => return refuse(),
        }
    } else {
        (None, None)
    };
    if t.network_id != network_id(&s.passphrase) {
        return refuse();
    }
    let expiry = match u32::try_from(t.expiry) {
        Ok(e) if e >= t.ledger && u64::from(e) <= u64::from(t.ledger) + u64::from(t.window) => e,
        _ => return refuse(),
    };
    let Ok(nonce) = i64::try_from(t.nonce) else {
        return refuse();
    };
    let mut c = Checked {
        kind,
        contract,
        from,
        to,
        amount,
        pay_ref,
        valid_until,
        nonce,
        expiry,
        network_id: t.network_id,
        preimage: vec![],
    };
    let mut p = vec![];
    u32be(&mut p, ENVELOPE_TYPE_SOROBAN_AUTHORIZATION);
    p.extend_from_slice(&c.network_id);
    p.extend_from_slice(&nonce.to_be_bytes());
    u32be(&mut p, expiry);
    c.invocation(&mut p);
    c.preimage = p;
    Ok(c)
}

/// NET-SOR-02's deterministic host nonce of a `pay`: `i64(sha256("scaas.soroban.nonce" ‖ pay_ref ‖ be64(valid_until))[0..8])`.
pub fn pay_nonce(pay_ref: &[u8; 32], valid_until: u64) -> i64 {
    let mut h = Sha256::new();
    h.update(b"scaas.soroban.nonce");
    h.update(pay_ref);
    h.update(valid_until.to_be_bytes());
    let d: [u8; 32] = h.finalize().into();
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    i64::from_be_bytes(b)
}

impl Checked {
    pub fn kind(&self) -> OpKind {
        self.kind
    }
    /// The token (`C…`).
    pub fn contract(&self) -> String {
        self.contract.text()
    }
    /// The subject (`G…`).
    pub fn from(&self) -> String {
        Address::Account(self.from).text()
    }
    pub(crate) fn subject_key(&self) -> [u8; 32] {
        self.from
    }
    /// The recipient, for a kind with one.
    pub fn to(&self) -> Option<String> {
        self.to.map(|a| a.text())
    }
    pub fn amount(&self) -> i128 {
        self.amount
    }
    pub fn pay_ref(&self) -> Option<[u8; 32]> {
        self.pay_ref
    }
    pub fn valid_until(&self) -> Option<u64> {
        self.valid_until
    }
    pub fn nonce(&self) -> i64 {
        self.nonce
    }
    pub fn expiry(&self) -> u32 {
        self.expiry
    }
    pub fn network_id(&self) -> [u8; 32] {
        self.network_id
    }
    /// The `HashIdPreimage::SorobanAuthorization` XDR.
    pub fn preimage(&self) -> &[u8] {
        &self.preimage
    }
    /// What the subject signs: `sha256(preimage)`.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.preimage).into()
    }

    /// `InvokeContractArgs` XDR: the contract, the function, the arguments.
    pub(crate) fn call(&self, out: &mut Vec<u8>) {
        self.contract.sc_address(out);
        opaque(out, self.kind.name().as_bytes());
        let addr = |out: &mut Vec<u8>, a: &Address| {
            u32be(out, 18);
            a.sc_address(out);
        };
        let n = match self.kind {
            OpKind::Transfer => 3,
            OpKind::Pay => 5,
            OpKind::Burn => 2,
        };
        u32be(out, n);
        addr(out, &Address::Account(self.from));
        if let Some(to) = &self.to {
            addr(out, to);
        }
        u32be(out, 10);
        out.extend_from_slice(&self.amount.to_be_bytes());
        if let (Some(r), Some(v)) = (&self.pay_ref, self.valid_until) {
            u32be(out, 13);
            opaque(out, r);
            u32be(out, 5);
            out.extend_from_slice(&v.to_be_bytes());
        }
    }

    /// `SorobanAuthorizedInvocation` XDR: the contract function, no sub-invocation.
    pub(crate) fn invocation(&self, out: &mut Vec<u8>) {
        u32be(out, 0);
        self.call(out);
        u32be(out, 0);
    }

    /// The node's named `invocation` (docs/node/job-api.md#soroban-signed-op).
    fn invocation_json(&self) -> Value {
        let mut args = vec![json!({"type": "Address", "value": self.from()})];
        if let Some(to) = self.to() {
            args.push(json!({"type": "Address", "value": to}));
        }
        args.push(json!({"type": "i128", "value": self.amount.to_string()}));
        if let (Some(r), Some(v)) = (&self.pay_ref, self.valid_until) {
            args.push(json!({"type": "BytesN<32>", "value": hex0x(r)}));
            args.push(json!({"type": "u64", "value": v}));
        }
        json!({"contract": self.contract(), "function": self.kind.name(), "args": args, "sub_invocations": []})
    }

    /// The named `payload` of a `signed_op`: `{nonce, expiry, invocation}`, the nonce a decimal string.
    pub fn payload_json(&self) -> Value {
        json!({"nonce": self.nonce.to_string(), "expiry": self.expiry, "invocation": self.invocation_json()})
    }
}

/// The node's `signed_op` of `POST /v1/ops` from a checked op and the subject's 64-byte signature (clientkeys `signedOp`): every
/// field named, `valid_until` the transaction's deadline (unix seconds).
pub fn signed_op(c: &Checked, signature: &[u8; 64], valid_until: u64) -> Value {
    json!({
        "family": "soroban",
        "payload": c.payload_json(),
        "from": c.from(),
        "signature": hex0x(signature),
        "contract": c.contract(),
        "valid_until": valid_until,
    })
}
