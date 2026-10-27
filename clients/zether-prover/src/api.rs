//! JSON-in / JSON-out surface shared by the CLI and the WASM bindings. Hex is `0x…`, points
//! and scalars use the wire encodings of zether-design §2, integers are JSON numbers or
//! decimal strings on input; amounts on output are decimal strings (balances reach 2^54 and
//! values 2^64, past JavaScript's 2^53).
//!
//! A `key` is `{"x": hex}` or `{"mnemonic": words, "passphrase"?: s, "coin": n, "account": n}`
//! or `{"seed": hex, "coin": n, "account": n}` (R33, `<use> = 7`).

use ark_ff::{UniformRand, Zero};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::abi::{self, Tok};
use crate::bulletproofs::Gens;
use crate::curve::{
    decode_point, decode_scalar, encode_point, encode_scalar, generator, keccak256, point_len, ua_of, zether_kind,
    Bls12381, Fr, ZCurve, G,
};
#[cfg(feature = "bn254")]
use crate::curve::Bn254;
use crate::elgamal::{
    cached_table, cached_table_bits, check_balance, check_ram, encrypt, mem_available, BsgsParams, Ciphertext,
};

/// Largest wasm table without `allowLargeTable` (2^24 entries, 256 MiB).
const WASM_TABLE_BITS_DEFAULT_MAX: u32 = 24;
use crate::envelope::{self, MetaTx};
use crate::keys::{seed_from_mnemonic, ZetherKey};
use crate::schnorr;
use crate::zether::{
    self, Binding, BurnStatement, Header, MultiTransferProof, MultiTransferStatement, TransferMode, TransferProof,
    TransferStatement,
};

type R<T> = Result<T, String>;

fn e<E: std::fmt::Display>(x: E) -> String {
    x.to_string()
}

pub fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn get<'a>(v: &'a Value, k: &str) -> R<&'a Value> {
    v.get(k).filter(|x| !x.is_null()).ok_or_else(|| format!("missing field `{k}`"))
}

fn bytes(v: &Value, k: &str) -> R<Vec<u8>> {
    let s = get(v, k)?.as_str().ok_or_else(|| format!("`{k}` must be a hex string"))?;
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|_| format!("`{k}` is not hex"))
}

fn fixed<const N: usize>(v: &Value, k: &str) -> R<[u8; N]> {
    bytes(v, k)?.try_into().map_err(|_| format!("`{k}` must be {N} bytes"))
}

fn opt_fixed<const N: usize>(v: &Value, k: &str) -> R<[u8; N]> {
    if v.get(k).is_none_or(|x| x.is_null()) {
        Ok([0u8; N])
    } else {
        fixed(v, k)
    }
}

/// JS loses precision above 2^53 − 1 before the request is even built, so a larger JSON Number is
/// refused rather than trusted (review L1): amounts and balances that big come as decimal strings.
const MAX_SAFE_JSON_INT: u64 = (1 << 53) - 1;

fn num(v: &Value, k: &str) -> R<u64> {
    match get(v, k)? {
        Value::Number(n) => match n.as_u64() {
            Some(x) if x <= MAX_SAFE_JSON_INT => Ok(x),
            Some(_) => Err(format!("`{k}` above 2^53 - 1 must be a decimal string")),
            None => Err(format!("`{k}` must be a u64")),
        },
        Value::String(s) => s.parse::<u64>().map_err(|_| format!("`{k}` must be a decimal u64")),
        _ => Err(format!("`{k}` must be a number")),
    }
}

fn num32(v: &Value, k: &str) -> R<u32> {
    u32::try_from(num(v, k)?).map_err(|_| format!("`{k}` must fit in u32"))
}

fn opt_bits(v: &Value, k: &str, default: u32) -> R<u32> {
    if v.get(k).is_none_or(|x| x.is_null()) {
        Ok(default)
    } else {
        num32(v, k)
    }
}

fn opt_num(v: &Value, k: &str) -> R<u64> {
    if v.get(k).is_none_or(|x| x.is_null()) {
        Ok(0)
    } else {
        num(v, k)
    }
}

fn point<C: ZCurve>(v: &Value, k: &str) -> R<G<C>> {
    decode_point::<C>(&bytes(v, k)?).map_err(|x| format!("`{k}`: {x}"))
}

/// The `key` field of a request (see the module doc).
pub fn key<C: ZCurve>(v: &Value) -> R<ZetherKey<C>> {
    let k = get(v, "key")?;
    if k.get("x").is_some() {
        let x = Zeroizing::new(bytes(k, "x")?);
        return ZetherKey::from_secret(decode_scalar::<C>(&x).map_err(e)?).map_err(e);
    }
    let seed: Zeroizing<Vec<u8>> = Zeroizing::new(if k.get("mnemonic").is_some() {
        let pass = match k.get("passphrase") {
            None | Some(Value::Null) => "",
            Some(p) => p.as_str().ok_or("passphrase must be a string")?,
        };
        seed_from_mnemonic(get(k, "mnemonic")?.as_str().ok_or("mnemonic must be a string")?, pass)
            .map_err(e)?
            .to_vec()
    } else {
        bytes(k, "seed")?
    });
    ZetherKey::conf(&seed, num32(k, "coin")?, num32(k, "account")?).map_err(e)
}

fn ct<C: ZCurve>(v: &Value, k: &str) -> R<Ciphertext<C>> {
    let c = get(v, k)?;
    Ok(Ciphertext { c: point::<C>(c, "C")?, d: point::<C>(c, "D")? })
}

fn ct_json<C: ZCurve>(c: &Ciphertext<C>) -> Value {
    json!({"C": hx(&encode_point::<C>(&c.c)), "D": hx(&encode_point::<C>(&c.d))})
}

/// `envelopeBinding` (relayed), or `unwrapBinding` (a direct `mtxUnshieldUnwrap`, burns only), or direct.
/// Both at once, or `unwrapBinding` on a transfer, is refused: the token never builds such a statement. The memo word
/// is the prove functions' (0 on a burn). `validUntilBlock` (required): the last block the token accepts the proof in
/// (review C0-9, `TransferExpired`).
fn header(v: &Value, amount: u64, recipient: [u8; 32], burn: bool) -> R<Header> {
    let has = |k: &str| v.get(k).is_some_and(|x| !x.is_null());
    let binding = match (has("envelopeBinding"), has("unwrapBinding")) {
        (true, true) => return Err("`envelopeBinding` and `unwrapBinding` are exclusive".into()),
        (true, false) => Binding::Relayed(fixed(v, "envelopeBinding")?),
        (false, true) if burn => Binding::Unwrap(fixed(v, "unwrapBinding")?),
        (false, true) => return Err("`unwrapBinding` is for `proveBurn` only".into()),
        (false, false) => Binding::Direct,
    };
    Ok(Header {
        chain_id: num(v, "chainId")?,
        chain_uid: fixed(v, "chainUid")?,
        token: fixed(v, "token")?,
        binding,
        send_counter: num(v, "sendCounter")?,
        acc_seq: num(v, "accSeq")?,
        fee: opt_num(v, "fee")?,
        beneficiary: opt_fixed(v, "beneficiary")?,
        amount,
        recipient,
        salt: [0; 16],
        memo_hash: [0; 32],
        valid_until_block: num(v, "validUntilBlock")?,
    })
}

/// Secrets (x, s, blinding factors) leave the call only when the request asks for them
/// (`"includeWitness": true`, used for test vectors).
fn include_witness(v: &Value) -> bool {
    v.get("includeWitness").and_then(Value::as_bool) == Some(true)
}

fn sc<C: ZCurve>(s: &Fr<C>) -> String {
    hx(&encode_scalar::<C>(s))
}

/// `mtxConfidentialTransferSingle` — a direct call has no outer fee; relayed, the same bytes are the envelope's `data`.
const TRANSFER_SINGLE: &str = "mtxConfidentialTransferSingle(bytes,bytes,bytes,bytes32,bytes)";

fn opt_str<'a>(v: &'a Value, k: &str) -> R<Option<&'a str>> {
    match v.get(k).filter(|x| !x.is_null()) {
        None => Ok(None),
        Some(x) => x.as_str().map(Some).ok_or_else(|| format!("`{k}` must be a string")),
    }
}

/// The token's `disclosureMode()` (CTR-ZTH-48): `"bundle"` (the default) or `"compact"` (commit-reveal only).
fn compact_token(v: &Value) -> R<bool> {
    match opt_str(v, "disclosureMode")? {
        None | Some("bundle") => Ok(false),
        Some("compact") => Ok(true),
        _ => Err("`disclosureMode` must be \"bundle\" or \"compact\"".into()),
    }
}

/// `yAud` (absent or null: the auditor left out, every `C_aud = O`), checked against the token's `auditorMode()`
/// when the request names it (CTR-ZTH-42): `"full"` needs it, `"none"` refuses it, `"optional"` takes either; the
/// token would revert `AuditorRequired` / `AuditorForbidden` after the proving work.
fn y_aud<C: ZCurve>(v: &Value) -> R<G<C>> {
    let y = if v.get("yAud").is_some_and(|x| !x.is_null()) { point::<C>(v, "yAud")? } else { G::<C>::zero() };
    match (opt_str(v, "auditorMode")?, y.is_zero()) {
        (None | Some("optional"), _) | (Some("full"), false) | (Some("none"), true) => Ok(y),
        (Some("full"), true) => Err("a FULL auditor token needs `yAud` (AuditorRequired)".into()),
        (Some("none"), false) => Err("a token without auditor takes no `yAud` (AuditorForbidden)".into()),
        _ => Err("`auditorMode` must be \"none\", \"full\" or \"optional\"".into()),
    }
}

/// The entry of a stored form (CTR-ZTH-38): `mtxConfidentialTransfer` is the token's default (BUNDLE, or commit-reveal
/// on a COMPACT token), `mtxConfidentialTransferCompact` commit-reveal on every token, (NONE and `…NoBundle` retired, review C0-3).
fn transfer_multi_sig(mode: TransferMode, compact: bool) -> &'static str {
    match mode {
        TransferMode::Bundle => "mtxConfidentialTransfer(bytes,bytes,bytes,bytes32,bytes)",
        TransferMode::Hash if compact => "mtxConfidentialTransfer(bytes,bytes,bytes,bytes32,bytes)",
        TransferMode::Hash => "mtxConfidentialTransferCompact(bytes,bytes,bytes,bytes32,bytes)",
    }
}

pub fn prove_transfer_json<C: ZCurve, Rn: RngCore + CryptoRng>(gens: &Gens<C>, v: &Value, rng: &mut Rn) -> R<Value> {
    if compact_token(v)? {
        return Err("a COMPACT token refuses the single format (TransferEntryDisabled)".into());
    }
    let k = key::<C>(v)?;
    let h = header(v, 0, [0; 32], false)?;
    let y_aud = y_aud::<C>(v)?;
    let (st, p, w) = zether::prove_transfer(
        gens,
        &k,
        h.clone(),
        point::<C>(v, "yTo")?,
        y_aud,
        ct::<C>(v, "acc")?,
        num(v, "balance")?,
        num(v, "amount")?,
        rng,
    )
    .map_err(e)?;
    let (stmt, proof, payload) = (st.encode(), p.encode(), st.payload());
    let mut out = json!({
        "curve": C::NAME,
        "statement": hx(&stmt),
        "proof": hx(&proof),
        "payload": hx(&payload),
        "entryRef": hx(&schnorr::entry_ref(h.chain_id, &h.chain_uid, &h.token, &k.ua(), h.send_counter)),
        "salt": hx(&st.header.salt),
        "record": hx(&st.record()),
        "directCalldata": hx(&envelope::transfer_call(TRANSFER_SINGLE, &payload, &proof, &h.beneficiary)),
    });
    if include_witness(v) {
        out["witness"] = json!({"x": sc::<C>(&w.x), "v": sc::<C>(&w.v), "s": sc::<C>(&w.s), "b": sc::<C>(&w.b),
            "bPrime": sc::<C>(&w.b_prime), "gammaV": sc::<C>(&w.gamma_v), "gammaB": sc::<C>(&w.gamma_b)});
    }
    Ok(out)
}

/// `recipients`: `[{"yTo", "amount"}, …]` (decoys with amount 0); `fee` the txFee (`confidentialFee` with a
/// `beneficiary`), `decoyFee` the per-leg fee the token pays to every leg (default 0; `minDecoyFee`, the token's, checked
/// when given): the statement's fee is `fee + M · decoyFee` (owner 2026-10-20); `mode`, the stored form: `bundle` | `compact`, by default the token's (`disclosureMode` `"bundle"`, the default: `bundle`; `"compact"`: `compact`, the only
/// form it takes), so the calldata calls `mtxConfidentialTransfer` unless a gas-saving form is asked for. `yAud` absent or null leaves the auditor out (statement `Y_a = O`, every `C_aud = O`): required on a token
/// without auditor, refused on a `FULL` one, the sender's choice on an `OPTIONAL` one (`auditorMode`, checked when
/// given); the same holds for `proveTransfer`. Relayed like the single format (`envelopeBinding`, CTR-ZTH-34); a relayed build requires `uaSigner` (`"ecdsa"` | `"fndsa512"` | `"mldsa65"` | `"mldsa44"` | `"slhdsa128s"` | `"ed25519"` | `"p256"` | `"webauthn-p256"`, caps from accounts.md; or a numeric `uaSignerGas` for any other kind such as an msig; review2 C3-2) so the gas check counts `_uaAuthorize`.
pub fn prove_transfer_multi_json<C: ZCurve, Rn: RngCore + CryptoRng>(gens: &Gens<C>, v: &Value, rng: &mut Rn) -> R<Value> {
    let k = key::<C>(v)?;
    let h = header(v, 0, [0; 32], false)?;
    let compact = compact_token(v)?;
    let mode = match v.get("mode").filter(|x| !x.is_null()) {
        None if compact => TransferMode::Hash,
        None => TransferMode::Bundle,
        Some(m) => m.as_str().and_then(TransferMode::from_name).ok_or("`mode` must be \"bundle\" or \"compact\"")?,
    };
    if compact && mode != TransferMode::Hash {
        return Err("a COMPACT token takes commit-reveal only (TransferEntryDisabled)".into());
    }
    let recipients = get(v, "recipients")?
        .as_array()
        .ok_or("`recipients` must be an array")?
        .iter()
        .map(|r| Ok((point::<C>(r, "yTo")?, num(r, "amount")?)))
        .collect::<R<Vec<_>>>()?;
    let y_aud = y_aud::<C>(v)?;
    let d = opt_num(v, "decoyFee")?;
    if d < opt_num(v, "minDecoyFee")? {
        return Err("`decoyFee` below the token's `minDecoyFee` (DecoyFeeOutOfRange)".into());
    }
    // C3-2: a relayed build names the signer kind of the envelope it is relayed through (`ecdsa`: `mtxExecute`, adds 0;
    // `fndsa512` / `mldsa65`: `uaExecute`, `_uaAuthorize` adds the kind's verify cap), so the gas check never uses the
    // `mtxExecute` figures for a UA relay. Direct builds take none.
    let kind = v.get("uaSigner").filter(|x| !x.is_null());
    let custom = v.get("uaSignerGas").filter(|x| !x.is_null());
    let signer_gas = match (kind.or(custom), matches!(h.binding, Binding::Relayed(_))) {
        (None, false) => 0,
        (None, true) => return Err("a relayed build needs `uaSigner` (\"ecdsa\" = mtxExecute; uaExecute: \"fndsa512\", \"mldsa65\", \"mldsa44\", \"slhdsa128s\", \"ed25519\", \"p256\", \"webauthn-p256\") or a numeric `uaSignerGas` (e.g. an msig)".into()),
        (Some(_), false) => return Err("`uaSigner` needs an `envelopeBinding`".into()),
        (Some(_), true) => match (kind, custom) {
            (Some(_), Some(_)) => return Err("give `uaSigner` or `uaSignerGas`, not both".into()),
            (Some(k), None) => k.as_str().and_then(zether::ua_signer_gas).ok_or("`uaSigner` must be a known kind (use `uaSignerGas` for any other)")?,
            (None, _) => opt_num(v, "uaSignerGas")?,
        },
    };
    let (st, p, w) = zether::prove_transfer_multi_ua(
        gens, &k, h.clone(), d, mode, &recipients, y_aud, ct::<C>(v, "acc")?, num(v, "balance")?, signer_gas, rng,
    )
    .map_err(e)?;
    let (stmt, proof, payload) = (st.encode(), p.encode(), st.payload(w.decoy_fee, &w.memo));
    let mut out = json!({
        "curve": C::NAME,
        "mode": mode.name(),
        "statement": hx(&stmt),
        "proof": hx(&proof),
        "payload": hx(&payload),
        "bundles": hx(&st.bundles()),
        "entryRef": hx(&schnorr::entry_ref(h.chain_id, &h.chain_uid, &h.token, &k.ua(), h.send_counter)),
        "salt": hx(&st.header.salt),
        "memo": hx(&w.memo),
        "directCalldata": hx(&envelope::transfer_call(transfer_multi_sig(mode, compact), &payload, &proof, &h.beneficiary)),
    });
    if include_witness(v) {
        out["witness"] = json!({"x": sc::<C>(&w.x), "s": sc::<C>(&w.s), "b": sc::<C>(&w.b), "bPrime": sc::<C>(&w.b_prime),
            "v": w.v.iter().map(sc::<C>).collect::<Vec<_>>(), "t": w.t.iter().map(sc::<C>).collect::<Vec<_>>(),
            "gammaV": w.gamma_v.iter().map(sc::<C>).collect::<Vec<_>>(),
            "gammaB": sc::<C>(&w.gamma_b)});
    }
    Ok(out)
}

/// `recipient`: a 20-byte address (its padded id) or a 32-byte id, a derived SIGNING UA (CTR-ZTH-51; the statement's
/// word 12 either way).
fn recipient_id(v: &Value) -> R<[u8; 32]> {
    let b = bytes(v, "recipient")?;
    let mut o = [0u8; 32];
    match b.len() {
        20 => o[12..].copy_from_slice(&b),
        32 => o.copy_from_slice(&b),
        _ => return Err("`recipient` must be a 20-byte address or a 32-byte UA id".into()),
    }
    Ok(o)
}

pub fn prove_burn_json<C: ZCurve, Rn: RngCore + CryptoRng>(gens: &Gens<C>, v: &Value, rng: &mut Rn) -> R<Value> {
    let k = key::<C>(v)?;
    let amount = num(v, "amount")?;
    let recipient = recipient_id(v)?;
    let h = header(v, amount, recipient, true)?;
    let (st, p, w) =
        zether::prove_burn(gens, &k, h.clone(), ct::<C>(v, "acc")?, num(v, "balance")?, rng).map_err(e)?;
    let (stmt, proof, payload) = (st.encode(), p.encode(), st.payload());
    let mut out = json!({
        "curve": C::NAME,
        "statement": hx(&stmt),
        "proof": hx(&proof),
        "payload": hx(&payload),
    });
    // An unwrap-bound proof fits only `mtxUnshieldUnwrap` (no builder yet, K15): `mtxUnshield` would refuse it.
    if !matches!(h.binding, Binding::Unwrap(_)) {
        out["directCalldata"] = hx(&envelope::unshield_call(&payload, &proof, &h.beneficiary, &recipient, amount)).into();
    }
    if include_witness(v) {
        out["witness"] = json!({"x": sc::<C>(&w.x), "b": sc::<C>(&w.b), "amount": amount.to_string(),
            "bPrime": sc::<C>(&w.b_prime), "gammaB": sc::<C>(&w.gamma_b)});
    }
    Ok(out)
}

/// A recovery source: the counter, `R` when the source carries it, the memo when it has one, and
/// whether it is the single format (`B = Y_t ‖ C_out ‖ D_out ‖ C_aud`, 4 points) or the multi-recipient one (`B_j = Y_tj ‖
/// C_out_j ‖ D_out ‖ C_aud_j ‖ D_aud_j`, 5 points, review C0-1).
struct Source {
    send_counter: u64,
    rec: Vec<u8>,
    memo: Option<Vec<u8>>,
    single: bool,
}

/// The source of a recovery: `payload` (the transfer's calldata argument, any entry) or `entry` =
/// `transferEntry(entryRef)` with `sendCounter`: the record `R` (single: `16 + 4P` bytes exactly, multi `16 + 5P·M`; every
/// form keeps `R` in state, review C0-3) and, for a commit-reveal entry, `memo` = `transferMemo(entryRef)` (`49 + 40·M`).
fn recovery_source<C: ZCurve>(v: &Value) -> R<Source> {
    let p = point_len::<C>();
    if v.get("payload").is_some_and(|x| !x.is_null()) {
        let b = bytes(v, "payload")?;
        let (rec, memo) = payload_record::<C>(&b)?;
        let single = b.len() == 112 + 6 * p;
        let send_counter = abi::word_u64(&b, 32).ok_or("payload: sendCounter")?;
        return Ok(Source { send_counter, rec, memo, single });
    }
    let e = bytes(v, "entry")?;
    let send_counter = num(v, "sendCounter")?;
    let single = e.len() == 16 + 4 * p;
    if !single && !(e.len() > 16 && (e.len() - 16) % (5 * p) == 0) {
        return Err("`entry`: not a record R (an unknown entry)".into());
    }
    let memo = if v.get("memo").is_some_and(|x| !x.is_null()) { Some(bytes(v, "memo")?) } else { None };
    Ok(Source { send_counter, rec: e, memo, single })
}

/// What `s`, the memo key and the openings need: `chainId`, `chainUid`, `token` and the counter.
fn recovery_header(v: &Value, send_counter: u64) -> R<Header> {
    Ok(Header {
        chain_id: num(v, "chainId")?,
        chain_uid: fixed(v, "chainUid")?,
        token: fixed(v, "token")?,
        binding: Binding::Direct,
        send_counter,
        acc_seq: 0,
        fee: 0,
        beneficiary: [0; 32],
        amount: 0,
        recipient: [0; 32],
        salt: [0; 16],
        memo_hash: [0; 32],
        valid_until_block: 0,
    })
}

/// Step 1 of a storage-only recovery (CTR-ZTH-50): open the memo of a commit-reveal entry (`entry` =
/// `transferEntry(entryRef)`, `memo` = `transferMemo(entryRef)`, `sendCounter`, `chainId`, `chainUid`, `token`). Returns the `salt`, `auditorIncluded`
/// (the flag) and the legs (`toUA`, `amount`). `recoverTransfer` takes no keys (the entry blob holds `R`). Unverified: a wrong key or a tampered memo gives
/// garbage here, which `recoverTransfer` then refuses against the stored record.
pub fn open_memo_json<C: ZCurve>(v: &Value) -> R<Value> {
    let k = key::<C>(v)?;
    let Source { send_counter, memo, .. } = recovery_source::<C>(v)?;
    let memo = memo.ok_or("`entry`/`payload` carries no memo (not commit-reveal): `recoverTransfer` needs no keys")?;
    let h = recovery_header(v, send_counter)?;
    let (salt, aud, legs) = zether::open_memo::<C>(&k.x, &h, &k.ua(), &memo).map_err(e)?;
    Ok(json!({
        "salt": hx(&salt), "auditorIncluded": aud,
        "legs": legs.iter().map(|l| json!({"toUA": hx(&l.to_ua), "amount": l.amount.to_string()})).collect::<Vec<_>>(),
    }))
}

/// Recovery of one of the sender's transfers from its key and chain data only (CTR-ZTH-30, CTR-ZTH-50; disclosure
/// review G1/R7): no amount, recipient or log remembered. The source is either
/// - `entry` = `transferEntry(entryRef)` with `sendCounter` (the sender walks `0 … sendCounter(fromUA) − 1`): the record
///   `R`, in state for every form (review C0-3), and, on a commit-reveal entry, `memo` = `transferMemo(entryRef)`: the
///   memo gives the amounts and the recipient UAs, which must be `R`'s `Y_tj` (`yAud` = `auditorKey()` when its flag
///   says so); the sender's rebuilt `R` must equal the stored one;
/// - `payload`, the transfer's calldata argument (any entry): it carries every `Y_tj`; its memo, if any, gives the amounts.
///
/// Without a memo the amounts come by BSGS on `C_out_j − [s]Y_tj` (`tableBits`, `boundBits` as `decrypt`). Returns `s`,
/// `salt`, `entryRef`, the legs (`toUA`, `yTo`, `amount`), `bundles` (= `R`), `commitment` (`keccak256(R)`, the hash the
/// events give an indexer), `auditorIncluded`, and the sender's openings `senderS` (every leg) and `senderCp[j]` (leg
/// `j`). Needs `chainId`, `chainUid`, `token`.
pub fn recover_transfer_json<C: ZCurve, Rn: RngCore + CryptoRng>(v: &Value, rng: &mut Rn) -> R<Value> {
    let k = key::<C>(v)?;
    let p = point_len::<C>();
    let Source { send_counter, rec, memo, single } = recovery_source::<C>(v)?;
    let h = recovery_header(v, send_counter)?;
    let salt: [u8; 16] = rec[..16].try_into().unwrap();
    let s = zether::derive_s::<C>(&k.x, &h, &k.ua(), &salt);
    let g = generator::<C>();
    let d_out = g * s;
    let stride = if single { 4 * p } else { 5 * p };
    let ys = |r: &[u8]| (16..r.len()).step_by(stride).map(|o| decode_point::<C>(&r[o..o + p]).map_err(e)).collect::<R<Vec<_>>>();
    let (legs, aud): (Vec<(G<C>, u64)>, bool) = match (&rec, &memo) {
        (r, Some(m)) => {
            // calldata, commit-reveal: the keys from the payload, the amounts from the memo
            let (_, aud, ml) = zether::open_memo::<C>(&k.x, &h, &k.ua(), m).map_err(e)?;
            let ys = ys(r)?;
            if ys.len() != ml.len() || ys.iter().zip(&ml).any(|(y, l)| ua_of::<C>(y) != l.to_ua) {
                return Err("the memo's recipients are not the payload's (another key, chainUid, token or a tampered memo)".into());
            }
            (ys.into_iter().zip(ml.iter().map(|l| l.amount)).collect(), aud)
        }
        (r, None) => {
            let bsgs = BsgsParams::for_target();
            let bp = BsgsParams::new(opt_bits(v, "tableBits", bsgs.table_bits)?, opt_bits(v, "boundBits", bsgs.bound_bits)?)
                .map_err(e)?;
            if !cfg!(target_arch = "wasm32") && cached_table_bits::<C>() != Some(bp.table_bits) {
                check_ram(bp.table_bits, mem_available()).map_err(e)?;
            }
            let pt = |o: usize| decode_point::<C>(&r[o..o + p]).map_err(e);
            let mut legs = Vec::new();
            let mut aud = false;
            for o in (16..r.len()).step_by(stride) {
                let (y, c_out, d, c_aud) = (pt(o)?, pt(o + p)?, pt(o + 2 * p)?, pt(o + 3 * p)?);
                if d != d_out {
                    return Err("D_out != [s]G: not this key's transfer (or another chainUid / token)".into());
                }
                let a = cached_table::<C>(bp.table_bits).map_err(e)?.decrypt(&Ciphertext { c: c_out, d: y }, &s, bp.bound_bits);
                legs.push((y, a.map_err(e)?));
                aud |= !c_aud.is_zero();
            }
            (legs, aud)
        }
    };
    let y_a = if aud { point::<C>(v, "yAud")? } else { G::<C>::zero() };
    // The auditor copy `(C_aud, D_aud)` of leg `j`: under `s` on the single format (`D_aud = D_out`, not in its record),
    // under its own `t_j` on a multi-recipient leg (review C0-1); `O` when the auditor is off.
    let aud_ct = |j: usize, a: u64| {
        let t = if single { s } else { zether::derive_t::<C>(&k.x, &h, &k.ua(), &salt, j) };
        if y_a.is_zero() {
            (G::<C>::zero(), if single { d_out } else { G::<C>::zero() })
        } else {
            (g * Fr::<C>::from(a) + y_a * t, g * t)
        }
    };
    let mut bundles = salt.to_vec();
    for (j, (y, a)) in legs.iter().enumerate() {
        let (c_aud, d_aud) = aud_ct(j, *a);
        let b = [*y, g * Fr::<C>::from(*a) + *y * s, d_out, c_aud, d_aud];
        for pt in &b[..if single { 4 } else { 5 }] {
            bundles.extend(encode_point::<C>(pt));
        }
    }
    if rec != bundles {
        return Err("the rebuilt record misses the chain's (another key, chainUid, token or counter, a tampered memo, or a wrong `yAud`/`keys`)".into());
    }
    let entry_ref = schnorr::entry_ref(h.chain_id, &h.chain_uid, &h.token, &k.ua(), send_counter);
    let mut cps = Vec::new();
    for (j, (y, a)) in legs.iter().enumerate() {
        let (c_aud, d_aud) = aud_ct(j, *a);
        let entry = schnorr::Entry {
            chain_id: h.chain_id,
            chain_uid: h.chain_uid,
            token: h.token,
            entry_ref,
            index: j as u64,
            y_t: *y,
            c_out: g * Fr::<C>::from(*a) + *y * s,
            d_out,
            y_a,
            c_aud,
            d_aud,
        };
        cps.push(hx(&schnorr::open_sender_cp(&entry, *a, &s, rng).map_err(e)?));
    }
    let legs: Vec<Value> = legs
        .iter()
        .map(|(y, a)| json!({"toUA": hx(&ua_of::<C>(y)), "yTo": hx(&encode_point::<C>(y)), "amount": a.to_string()}))
        .collect();
    Ok(json!({
        "s": sc::<C>(&s), "salt": hx(&salt), "sendCounter": send_counter, "entryRef": hx(&entry_ref), "legs": legs,
        "auditorIncluded": !y_a.is_zero(), "bundles": hx(&bundles), "commitment": hx(&keccak256(&bundles)),
        "senderS": hx(&schnorr::open_sender::<C>(&s)), "senderCp": cps,
    }))
}

/// `R = salt ‖ B_1 ‖ … ‖ B_M` as a transfer payload carries it, and its memo (commit-reveal) if any. Every payload starts
/// `be32(accSeq) ‖ be32(sendCounter) ‖ be32(validUntilBlock) ‖ salt(16)`.
fn payload_record<C: ZCurve>(b: &[u8]) -> R<(Vec<u8>, Option<Vec<u8>>)> {
    let p = point_len::<C>();
    let salt = b.get(96..112).ok_or("payload: too short")?;
    let cut = |o: usize| &b[o..o + p];
    let mut r = salt.to_vec();
    if b.len() == 112 + 6 * p {
        for o in [112 + p, 112 + 2 * p, 112 + 3 * p, 112 + 5 * p] {
            r.extend_from_slice(cut(o));
        }
        return Ok((r, None));
    }
    let m = abi::word_u64(b, 112).ok_or("payload: M")? as usize;
    // … ‖ be32(M) ‖ be32(decoyFee) ‖ Y_f ‖ D_out ‖ C_deb ‖ (Y_tj ‖ C_out_j ‖ C_aud_j ‖ D_aud_j)_j
    let end = 176 + 3 * p + 4 * p * m;
    if m == 0 || m > zether::MAX_RECIPIENTS || (b.len() != end && b.len() != end + zether::memo_len(m)) {
        return Err("payload: neither format".into());
    }
    for j in 0..m {
        let o = 176 + 3 * p + 4 * p * j;
        for at in [o, o + p, 176 + p, o + 2 * p, o + 3 * p] {
            r.extend_from_slice(cut(at));
        }
    }
    Ok((r, (b.len() > end).then(|| b[end..].to_vec())))
}

fn verify_multi_json<C: ZCurve>(gens: &Gens<C>, v: &Value) -> R<Value> {
    let (stmt, proof) = (bytes(v, "statement")?, bytes(v, "proof")?);
    let r = MultiTransferStatement::<C>::decode(&stmt).and_then(|st| {
        zether::verify_transfer_multi(gens, &st, &MultiTransferProof::<C>::decode(&proof, st.legs.len())?)
    });
    Ok(match r {
        Ok(_) => json!({"ok": true}),
        Err(x) => json!({"ok": false, "error": x.to_string()}),
    })
}

fn verify_json<C: ZCurve>(gens: &Gens<C>, v: &Value, burn: bool) -> R<Value> {
    let (stmt, proof) = (bytes(v, "statement")?, bytes(v, "proof")?);
    let r = if burn {
        BurnStatement::<C>::decode(&stmt)
            .and_then(|st| zether::verify_burn(gens, &st, &zether::BurnProof::<C>::decode(&proof)?))
    } else {
        TransferStatement::<C>::decode(&stmt)
            .and_then(|st| zether::verify_transfer(gens, &st, &TransferProof::<C>::decode(&proof)?))
    };
    Ok(match r {
        Ok(_) => json!({"ok": true}),
        Err(x) => json!({"ok": false, "error": x.to_string()}),
    })
}

fn meta(v: &Value) -> R<MetaTx> {
    let m = get(v, "meta")?;
    Ok(MetaTx {
        from: fixed(m, "from")?,
        data: if m.get("data").is_some() { bytes(m, "data")? } else { vec![] },
        batch: fixed(m, "batch")?,
        nonce: num(m, "nonce")?,
        valid_until: num(m, "validUntil")?,
        mode: num32(m, "mode")?,
        relayer: opt_fixed(m, "relayer")?,
        fee: opt_num(m, "fee")? as u128,
        fee_recipient: opt_fixed(m, "feeRecipient")?,
    })
}

fn by_curve<C: ZCurve>(cmd: &str, v: &Value, rng: &mut OsRng) -> R<Value> {
    let gens = || Gens::<C>::new();
    match cmd {
        "keygen" => {
            let k = key::<C>(v)?;
            let mut out = json!({"curve": C::NAME, "Y": hx(&k.encoded_y()), "UA": hx(&k.ua())});
            if v.get("revealSecret").and_then(Value::as_bool) == Some(true) {
                out["x"] = json!(sc::<C>(&k.x));
            }
            Ok(out)
        }
        "encrypt" => {
            let r = Fr::<C>::rand(rng);
            Ok(ct_json::<C>(&encrypt(&point::<C>(v, "Y")?, num(v, "amount")?, &r)))
        }
        // BSGS on `ct` (zether-limits §4): `tableBits`/`boundBits` default to the target's
        // (wasm 22/44, native 24–26/54 by RAM). `decryptPending` defaults to 22/44 everywhere.
        "decrypt" | "decryptPending" => {
            let k = key::<C>(v)?;
            let d = if cmd == "decrypt" { BsgsParams::for_target() } else { BsgsParams::MOBILE };
            let p = BsgsParams::new(opt_bits(v, "tableBits", d.table_bits)?, opt_bits(v, "boundBits", d.bound_bits)?)
                .map_err(e)?;
            // Review L4: a caller-chosen table must fit. Native checks free RAM; a browser tab stays at
            // <= 2^24 (256 MiB) unless the caller explicitly opts in with `allowLargeTable`.
            if cfg!(target_arch = "wasm32") {
                if p.table_bits > WASM_TABLE_BITS_DEFAULT_MAX && v.get("allowLargeTable") != Some(&Value::Bool(true)) {
                    return Err("tableBits above 24 in wasm needs \"allowLargeTable\": true".into());
                }
            } else if cached_table_bits::<C>() != Some(p.table_bits) {
                // a same-size table already in memory needs nothing more (review N4)
                check_ram(p.table_bits, mem_available()).map_err(e)?;
            }
            let field = if cmd == "decrypt" { "ct" } else { "pending" };
            let amount = cached_table::<C>(p.table_bits).map_err(e)?.decrypt(&ct::<C>(v, field)?, &k.x, p.bound_bits);
            Ok(json!({"amount": amount.map_err(e)?.to_string()}))
        }
        // Cache validation (limits §5): `[balance]G == C − [x]D`, no BSGS.
        "checkBalance" => {
            let k = key::<C>(v)?;
            Ok(json!({"ok": check_balance(&ct::<C>(v, "acc")?, &k.x, num(v, "balance")?)}))
        }
        "proveTransfer" => prove_transfer_json::<C, _>(&gens(), v, rng),
        "proveTransferMulti" => prove_transfer_multi_json::<C, _>(&gens(), v, rng),
        "proveBurn" => prove_burn_json::<C, _>(&gens(), v, rng),
        "openMemo" => open_memo_json::<C>(v),
        "recoverTransfer" => recover_transfer_json::<C, _>(v, rng),
        "verifyTransfer" => verify_json::<C>(&gens(), v, false),
        "verifyTransferMulti" => verify_multi_json::<C>(&gens(), v),
        "verifyBurn" => verify_json::<C>(&gens(), v, true),
        // The `register` PoP (CTR-UA-07): `chainId`, `chainUid`, `registry` (a Zether UA holds no PQZ key: the digest's last word is 0).
        "pop" => {
            let k = key::<C>(v)?;
            let (chain, uid, reg) = (num(v, "chainId")?, fixed::<32>(v, "chainUid")?, fixed::<20>(v, "registry")?);
            let d = schnorr::pop_digest(chain, &uid, &reg, &k.ua(), &[0u8; 32]);
            Ok(json!({
                "kind": zether_kind::<C>(), "Y": hx(&k.encoded_y()), "UA": hx(&k.ua()),
                "popDigest": hx(&d), "uaMsg": hx(&schnorr::ua_message::<C>(&schnorr::purpose_tag("pop"), &d)),
                "pop": hx(&schnorr::zether_pop(&k, chain, &uid, &reg, rng)),
            }))
        }
        // A self account's owner op (roll-over, mode): `sig` for `mtxRollOverSigned` / `mtxSetRollOverMode`.
        "ownerAuth" => {
            let k = key::<C>(v)?;
            let d = fixed::<32>(v, "digest")?;
            Ok(json!({
                "uaMsg": hx(&schnorr::ua_message::<C>(&schnorr::purpose_tag("zether-owner"), &d)),
                "auth": hx(&schnorr::owner_auth(&k, &d, rng)),
            }))
        }
        // The Zether UA signs every UA-ledger write (UA-6): `sig` = Schnorr by x over `ua_message(purpose, digest)`.
        "uaSig" => {
            let k = key::<C>(v)?;
            let (purpose, d) = (get(v, "purpose")?.as_str().ok_or("`purpose` must be a string")?, fixed::<32>(v, "digest")?);
            // the purposes a Zether UA signs (no `member`: the kind is SIGNING, not MEMBER; no `zether-auth`: no PQZ key); `pop` has its own command. `sig` is the raw R‖z; `requireAuthorized` wants abi.encode(bytes(""), sig)
            const PURPOSES: [&str; 8] = ["metatx", "metatx-cancel", "zether-owner", "keyop", "receiver-fee", "vp", "vc-anchor", "trade"];
            if !PURPOSES.contains(&purpose) {
                return Err(format!("`purpose` must be one of {PURPOSES:?} (the PoP has its own command `pop`)"));
            }
            let m = schnorr::ua_message::<C>(&schnorr::purpose_tag(purpose), &d);
            Ok(json!({"uaMsg": hx(&m), "sig": hx(&schnorr::sign(&k, &m, rng))}))
        }
        "shieldCalldata" => {
            // `mtxShield(bytes32 toUA, uint256 amount)`: the Zether key is the UA (CTR-UA-30)
            let mut d = envelope::selector("mtxShield(bytes32,uint256)").to_vec();
            d.extend(abi::encode(&[Tok::Word(ua_of::<C>(&point::<C>(v, "Y")?)), Tok::Word(abi::u256(num(v, "amount")?))]));
            Ok(json!({"calldata": hx(&d)}))
        }
        _ => Err(format!("unknown command `{cmd}`")),
    }
}

/// Dispatch one command. `input` is a JSON object; curve-specific commands need `"curve"`.
pub fn call(cmd: &str, input: &str) -> R<String> {
    let v: Value = serde_json::from_str(input).map_err(e)?;
    let out = match cmd {
        "envelope" => {
            let (chain, uid, token) = (num(&v, "chainId")?, fixed::<32>(&v, "chainUid")?, fixed::<20>(&v, "token")?);
            let m = meta(&v)?;
            json!({"binding": hx(&envelope::envelope_binding(chain, &uid, &token, &m)),
                   "digest": hx(&envelope::digest(chain, &uid, &token, &m))})
        }
        _ => match get(&v, "curve")?.as_str() {
            #[cfg(feature = "bn254")]
            Some("bn254") => by_curve::<Bn254>(cmd, &v, &mut OsRng)?,
            Some("bls12381") => by_curve::<Bls12381>(cmd, &v, &mut OsRng)?,
            _ => return Err("curve must be \"bls12381\" (bn254 is a legacy build feature)".into()),
        },
    };
    Ok(out.to_string())
}
