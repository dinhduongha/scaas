// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Soroban's balances (spec §8.7, Soroban row; docs/networks/soroban.md NET-SOR-22): through the profile's Soroban RPC
//! endpoints, each named by the network passphrase of `FamilyParams::Soroban` (whose SHA-256, `ua-rs`'s, is `chain_uid`). A
//! read set is **one** `getLedgerEntries` of every key, so its answer is one ledger, `latestLedger` (SCP: a closed ledger is
//! final): a `G…` holder's account entry (native stroops), a `C…` holder's `Balance(Address)` entry of the params' XLM SAC
//! (`{amount, authorized, clawback}`), and per listed token (`C…`) the holder's `Balance(Address)` or, for a `0x` UA id,
//! `UaBalance(BytesN<32>)` entry (an `I128`). The keys are built here from the holder and the contracts (XDR: an encoding, no
//! hash; their bytes are clientkeys' rows), each answer entry matched by its key; an absent entry is 0 (the contract never
//! wrote it), an archived one (`liveUntilLedgerSeq` below `latestLedger`) is that endpoint's failure, never 0 (NET-SOR-22).
//! The entry's XDR is read by fixed templates: the key's own bytes, then exactly the value's form, nothing after it (an
//! account entry: its fixed head, the rest within [`ACCOUNT_MAX`]). Soroban reads no past ledger, so under
//! `strict_majority` another endpoint's set, at its own `latestLedger` not below the answering one's, is compared
//! (decisions CLI-SDK-15's Change of 2026-11-21, T24.soroban). A UA id has no native balance (`None`).
use super::{malformed, read_set};
use crate::wallet::{Balances, TokenBalance};
use crate::{Chain, SdkError};
use base64::Engine;
use scaas_rpc::family::FamilyError;
use scaas_rpc::pool::ReadError;
use scaas_rpc::soroban::Soroban;
use scaas_rpc::{EndpointFailure, FailureKind};
use serde_json::{json, Value};

/// The largest account entry read (its signers, home domain and extensions within it).
pub(crate) const ACCOUNT_MAX: usize = 4096;
/// strkey version bytes: `G…` (ed25519 account) and `C…` (contract)
const ACCOUNT_VERSION: u8 = 6 << 3;
const CONTRACT_VERSION: u8 = 2 << 3;

/// A balance holder: an account, a contract, a UA id.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Holder {
    Account([u8; 32]),
    Contract([u8; 32]),
    Ua([u8; 32]),
}

/// CRC16-XModem (strkey's checksum: an encoding's check, no cryptography).
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

/// A strkey of 56 characters (RFC 4648 base32, upper case, no padding): its version byte and 32-byte payload, the checksum
/// and the zero padding bits checked.
pub(crate) fn strkey(s: &str) -> Option<(u8, [u8; 32])> {
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
    // 56 chars = 280 bits = 35 bytes exactly
    let (body, crc) = (raw.get(..33)?, raw.get(33..35)?);
    if acc != 0 || crc16(body).to_le_bytes() != crc {
        return None;
    }
    Some((*body.first()?, body.get(1..)?.try_into().ok()?))
}

/// The holder of a `G…`, a `C…` or a `0x` + 64 lowercase hex UA id.
pub(crate) fn holder(s: &str) -> Option<Holder> {
    if let Some(h) = s.strip_prefix("0x") {
        if h.len() != 64
            || !h
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        let mut id = [0u8; 32];
        for (k, d) in id.iter_mut().enumerate() {
            *d = u8::from_str_radix(h.get(2 * k..2 * k + 2)?, 16).ok()?;
        }
        return Some(Holder::Ua(id));
    }
    match strkey(s)? {
        (ACCOUNT_VERSION, k) => Some(Holder::Account(k)),
        (CONTRACT_VERSION, k) => Some(Holder::Contract(k)),
        _ => None,
    }
}

fn u32be(v: &mut Vec<u8>, n: u32) {
    v.extend_from_slice(&n.to_be_bytes());
}

/// `ScVal::Symbol`.
fn sym(v: &mut Vec<u8>, s: &str) {
    u32be(v, 15);
    u32be(v, s.len() as u32);
    v.extend_from_slice(s.as_bytes());
    v.resize(v.len() + (4 - s.len() % 4) % 4, 0);
}

/// `ScAddress` of an account or a contract.
fn sc_address(v: &mut Vec<u8>, h: &Holder) {
    match h {
        Holder::Account(k) => {
            u32be(v, 0);
            u32be(v, 0);
            v.extend_from_slice(k);
        }
        Holder::Contract(k) | Holder::Ua(k) => {
            u32be(v, 1);
            v.extend_from_slice(k);
        }
    }
}

/// `LedgerKey::Account` of an account.
pub(crate) fn account_key(k: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(40);
    u32be(&mut v, 0);
    u32be(&mut v, 0);
    v.extend_from_slice(k);
    v
}

/// `LedgerKey::ContractData` of `contract`'s persistent balance entry of `h`: `Balance(Address)` or `UaBalance(BytesN<32>)`.
pub(crate) fn balance_key(contract: &[u8; 32], h: &Holder) -> Vec<u8> {
    let mut v = Vec::with_capacity(112);
    u32be(&mut v, 6);
    sc_address(&mut v, &Holder::Contract(*contract));
    u32be(&mut v, 16); // ScVal::Vec, present, two items
    u32be(&mut v, 1);
    u32be(&mut v, 2);
    match h {
        Holder::Ua(id) => {
            sym(&mut v, "UaBalance");
            u32be(&mut v, 13); // ScVal::Bytes of 32
            u32be(&mut v, 32);
            v.extend_from_slice(id);
        }
        _ => {
            sym(&mut v, "Balance");
            u32be(&mut v, 18); // ScVal::Address
            sc_address(&mut v, h);
        }
    }
    u32be(&mut v, 1); // persistent
    v
}

/// An `I128` of 16 big-endian bytes that is not negative, as a decimal string.
fn i128_amount(b: &[u8]) -> Option<String> {
    let v = i128::from_be_bytes(b.try_into().ok()?);
    (v >= 0).then(|| v.to_string())
}

/// What a key's entry holds.
#[derive(Clone, Copy)]
enum Form {
    Account,
    Token,
    Sac,
}

/// The amount in entry data `x` of `key`, read by `form`'s template.
fn read_entry(x: &[u8], key: &[u8], form: Form) -> Option<String> {
    match form {
        Form::Account => {
            // LedgerEntryData::Account: the key's 40 bytes (type, key type, key), the balance (int64, not negative), the rest
            if x.len() > ACCOUNT_MAX || x.get(..40)? != key {
                return None;
            }
            let b = i64::from_be_bytes(x.get(40..48)?.try_into().ok()?);
            (b >= 0).then(|| b.to_string())
        }
        Form::Token | Form::Sac => {
            // LedgerEntryData::ContractData: type 6, ext 0, then the key's contract, key and durability, then the value
            let head = [&[0, 0, 0, 6, 0, 0, 0, 0][..], key.get(4..)?].concat();
            let val = x.strip_prefix(head.as_slice())?;
            match form {
                Form::Token => {
                    // exactly 16 bytes after the tag (`i128_amount` refuses any other length)
                    i128_amount(val.strip_prefix(&[0, 0, 0, 10][..])?)
                }
                _ => {
                    // {amount: I128, authorized: bool, clawback: bool}, keys sorted
                    let mut t = vec![];
                    for n in [17, 1, 3] {
                        u32be(&mut t, n);
                    }
                    sym(&mut t, "amount");
                    u32be(&mut t, 10);
                    let rest = val.strip_prefix(t.as_slice())?;
                    let (amount, rest) = (rest.get(..16)?, rest.get(16..)?);
                    let mut a = vec![];
                    sym(&mut a, "authorized");
                    u32be(&mut a, 0);
                    let rest = rest.strip_prefix(a.as_slice())?;
                    let (auth, rest) = (rest.get(..4)?, rest.get(4..)?);
                    let mut c = vec![];
                    sym(&mut c, "clawback");
                    u32be(&mut c, 0);
                    let claw = rest.strip_prefix(c.as_slice())?;
                    let bools = [auth, claw]
                        .iter()
                        .all(|b| *b == [0, 0, 0, 0] || *b == [0, 0, 0, 1]);
                    (bools && claw.len() == 4).then_some(())?;
                    i128_amount(amount)
                }
            }
        }
    }
}

/// A family error as endpoint `i`'s failure.
fn failed(i: usize, e: FamilyError) -> ReadError {
    match e {
        FamilyError::Failure(f) => ReadError::Failure(f),
        e => ReadError::Failure(EndpointFailure::new(
            i,
            FailureKind::Transport,
            &e.to_string(),
        )),
    }
}

/// A set: the native amount (none for a UA id) and each token's.
type Set = (Option<String>, Vec<String>);

/// The set on endpoint `i`: one `getLedgerEntries`, at its `latestLedger` (at least `floor`).
async fn set_at(
    sor: &Soroban,
    i: usize,
    keys: &[(Vec<u8>, Form)],
    native: bool,
    floor: u64,
) -> Result<(u64, Set), ReadError> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let text: Vec<String> = keys.iter().map(|(k, _)| b64.encode(k)).collect();
    let r = sor
        .call(i, "getLedgerEntries", json!({"keys": text}))
        .await
        .map_err(|e| failed(i, e))?;
    let ledger = r
        .get("latestLedger")
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed(i, "getLedgerEntries without latestLedger"))?;
    if ledger < floor {
        return Err(malformed(i, "a ledger behind the set's"));
    }
    let entries = match r.get("entries") {
        Some(Value::Array(a)) => a.as_slice(),
        None | Some(Value::Null) => &[],
        _ => return Err(malformed(i, "entries that are not a list")),
    };
    let mut amounts: Vec<Option<String>> = vec![None; keys.len()];
    for e in entries {
        let k = e.get("key").and_then(Value::as_str);
        let slot = text.iter().position(|t| Some(t.as_str()) == k);
        let Some(n) = slot.filter(|n| amounts.get(*n).is_some_and(Option::is_none)) else {
            return Err(malformed(i, "an entry not asked, or twice"));
        };
        if e.get("liveUntilLedgerSeq")
            .and_then(Value::as_u64)
            .is_some_and(|l| l < ledger)
        {
            return Err(malformed(i, "an archived entry"));
        }
        let x = e
            .get("xdr")
            .and_then(Value::as_str)
            .and_then(|x| b64.decode(x).ok())
            .ok_or_else(|| malformed(i, "an entry without its xdr"))?;
        let (key, form) = keys
            .get(n)
            .ok_or_else(|| malformed(i, "an entry not asked"))?;
        let a =
            read_entry(&x, key, *form).ok_or_else(|| malformed(i, "an entry out of its form"))?;
        if let Some(s) = amounts.get_mut(n) {
            *s = Some(a);
        }
    }
    let mut it = amounts.into_iter().map(|a| a.unwrap_or_else(|| "0".into()));
    let n = if native { it.next() } else { None };
    Ok((ledger, (n, it.collect())))
}

pub(crate) async fn balances(c: &Chain, id: &str) -> Result<Balances, SdkError> {
    let Some((sor, sac)) = c.soroban.as_ref() else {
        return Err(SdkError::Argument);
    };
    let sor = sor.as_ref();
    let h = holder(id).ok_or(SdkError::Argument)?;
    let mut keys = vec![];
    match &h {
        Holder::Account(k) => keys.push((account_key(k), Form::Account)),
        Holder::Contract(_) => keys.push((balance_key(sac, &h), Form::Sac)),
        Holder::Ua(_) => {}
    }
    let native = !keys.is_empty();
    for t in &c.profile.tokens {
        match strkey(&t.address) {
            Some((CONTRACT_VERSION, k)) => keys.push((balance_key(&k, &h), Form::Token)),
            _ => return Err(SdkError::Argument),
        }
    }
    // a UA id with no listed token holds nothing to read
    if keys.is_empty() {
        return Err(SdkError::Argument);
    }
    let keys = keys.as_slice();
    let (block, (native, amounts)) = read_set(
        &sor.client,
        sor,
        |i| async move { set_at(sor, i, keys, native, 0).await },
        |j, l| async move { set_at(sor, j, keys, native, l).await.map(|(_, v)| v) },
    )
    .await?;
    Ok(Balances {
        block,
        native,
        tokens: c
            .profile
            .tokens
            .iter()
            .zip(amounts)
            .map(|(t, amount)| TokenBalance {
                address: t.address.clone(),
                display: t.symbol.clone(),
                decimals: t.decimals,
                amount,
            })
            .collect(),
    })
}
