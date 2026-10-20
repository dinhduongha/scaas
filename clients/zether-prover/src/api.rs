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
/// is the prove functions' (0 on a burn).
fn header(v: &Value, amount: u64, recipient: [u8; 20], burn: bool) -> R<Header> {
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
/// on a COMPACT token), `mtxConfidentialTransferCompact` commit-reveal on every token, `…NoBundle` NONE.
fn transfer_multi_sig(mode: TransferMode, compact: bool) -> &'static str {
    match mode {
        TransferMode::Bundle => "mtxConfidentialTransfer(bytes,bytes,bytes,bytes32,bytes)",
        TransferMode::Hash if compact => "mtxConfidentialTransfer(bytes,bytes,bytes,bytes32,bytes)",
        TransferMode::Hash => "mtxConfidentialTransferCompact(bytes,bytes,bytes,bytes32,bytes)",
        TransferMode::NoBundle => "mtxConfidentialTransferNoBundle(bytes,bytes,bytes,bytes32,bytes)",
    }
}

pub fn prove_transfer_json<C: ZCurve, Rn: RngCore + CryptoRng>(gens: &Gens<C>, v: &Value, rng: &mut Rn) -> R<Value> {
    if compact_token(v)? {
        return Err("a COMPACT token refuses the single format (TransferEntryDisabled)".into());
    }
    let k = key::<C>(v)?;
    let h = header(v, 0, [0; 20], false)?;
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
/// when given): the statement's fee is `fee + M · decoyFee` (owner 2026-10-20); `mode`, the stored form: `bundle` | `compact` |
/// `none`, by default the token's (`disclosureMode` `"bundle"`, the default: `bundle`; `"compact"`: `compact`, the only
/// form it takes), so the calldata calls `mtxConfidentialTransfer` unless a gas-saving form is asked for. `yAud` absent or null leaves the auditor out (statement `Y_a = O`, every `C_aud = O`): required on a token
/// without auditor, refused on a `FULL` one, the sender's choice on an `OPTIONAL` one (`auditorMode`, checked when
/// given); the same holds for `proveTransfer`. Relayed like the single format (`envelopeBinding`, CTR-ZTH-34).
pub fn prove_transfer_multi_json<C: ZCurve, Rn: RngCore + CryptoRng>(gens: &Gens<C>, v: &Value, rng: &mut Rn) -> R<Value> {
    let k = key::<C>(v)?;
    let h = header(v, 0, [0; 20], false)?;
    let compact = compact_token(v)?;
    let mode = match v.get("mode").filter(|x| !x.is_null()) {
        None if compact => TransferMode::Hash,
        None => TransferMode::Bundle,
        Some(m) => m.as_str().and_then(TransferMode::from_name).ok_or("`mode` must be \"bundle\", \"compact\" or \"none\"")?,
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
    let (st, p, w) = zether::prove_transfer_multi(
        gens, &k, h.clone(), d, mode, &recipients, y_aud, ct::<C>(v, "acc")?, num(v, "balance")?, rng,
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
            "v": w.v.iter().map(sc::<C>).collect::<Vec<_>>(), "gammaV": w.gamma_v.iter().map(sc::<C>).collect::<Vec<_>>(),
            "gammaB": sc::<C>(&w.gamma_b)});
    }
    Ok(out)
}

pub fn prove_burn_json<C: ZCurve, Rn: RngCore + CryptoRng>(gens: &Gens<C>, v: &Value, rng: &mut Rn) -> R<Value> {
    let k = key::<C>(v)?;
    let amount = num(v, "amount")?;
    let recipient: [u8; 20] = fixed(v, "recipient")?;
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

/// The source of a recovery: `payload` (the transfer's calldata argument, any entry) or `entry` =
/// `transferEntry(entryRef)` with `sendCounter`: the record `R` (BUNDLE, single) or `keccak256(R) ‖ memo` (commit-reveal).
/// Returns the counter, `R` when the source carries it, the memo and the commitment when it has them.
fn recovery_source<C: ZCurve>(v: &Value) -> R<(u64, Option<Vec<u8>>, Option<Vec<u8>>, Option<[u8; 32]>)> {
    if v.get("payload").is_some_and(|x| !x.is_null()) {
        let b = bytes(v, "payload")?;
        let (rec, memo) = payload_record::<C>(&b)?;
        return Ok((abi::word_u64(&b, 32).ok_or("payload: sendCounter")?, Some(rec), memo, None));
    }
    let e = bytes(v, "entry")?;
    let p = point_len::<C>();
    if e.len() > 16 && (e.len() - 16) % (4 * p) == 0 {
        Ok((num(v, "sendCounter")?, Some(e), None, None))
    } else if e.len() >= 32 + zether::memo_len(1) {
        Ok((num(v, "sendCounter")?, None, Some(e[32..].to_vec()), Some(e[..32].try_into().unwrap())))
    } else {
        Err("`entry`: neither a record nor a commitment with its memo (an unknown or no-bundle entry)".into())
    }
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
        recipient: [0; 20],
        salt: [0; 16],
        memo_hash: [0; 32],
    })
}

/// Step 1 of a storage-only recovery (CTR-ZTH-50): open the memo of a commit-reveal entry (`entry` =
/// `transferEntry(entryRef)`, `sendCounter`, `chainId`, `chainUid`, `token`). Returns the `salt`, `auditorIncluded`
/// (the flag), the legs (`toUA`, `amount`) and `needKeys`, the UAs to look up with `registry.keyOf(toUA)` (and
/// `auditorKey()` when the flag is set) before `recoverTransfer`. Unverified: a wrong key or a tampered memo gives
/// garbage here, which `recoverTransfer` then refuses against the commitment.
pub fn open_memo_json<C: ZCurve>(v: &Value) -> R<Value> {
    let k = key::<C>(v)?;
    let (send_counter, _, memo, _) = recovery_source::<C>(v)?;
    let memo = memo.ok_or("`entry`/`payload` carries no memo (not commit-reveal): `recoverTransfer` needs no keys")?;
    let h = recovery_header(v, send_counter)?;
    let (salt, aud, legs) = zether::open_memo::<C>(&k.x, &h, &k.ua(), &memo).map_err(e)?;
    Ok(json!({
        "salt": hx(&salt), "auditorIncluded": aud,
        "legs": legs.iter().map(|l| json!({"toUA": hx(&l.to_ua), "amount": l.amount.to_string()})).collect::<Vec<_>>(),
        "needKeys": legs.iter().map(|l| hx(&l.to_ua)).collect::<Vec<_>>(),
    }))
}

/// Recovery of one of the sender's transfers from its key and chain data only (CTR-ZTH-30, CTR-ZTH-50; disclosure
/// review G1/R7): no amount, recipient or log remembered. `keys` (optional) are the recipients' `encodedY`; see
/// [`recover_transfer_with`]. A storage-only commit-reveal recovery is `openMemo`, then `registry.keyOf(toUA)` for each
/// of its `needKeys`, then this call with those `keys`.
pub fn recover_transfer_json<C: ZCurve, Rn: RngCore + CryptoRng>(v: &Value, rng: &mut Rn) -> R<Value> {
    recover_transfer_with::<C, Rn>(v, &mut |_| None, rng)
}

/// [`recover_transfer_json`] with a key-lookup source, `key_of(toUA)` = the registry's `keyOf(toUA)` (`encodedY`; `None`
/// or empty: not registered), asked for each recipient of a memo that `keys` does not cover. The source is either
/// - `entry` = `transferEntry(entryRef)` with `sendCounter` (the sender walks `0 … sendCounter(fromUA) − 1`): the record
///   `R` (BUNDLE, single) or `keccak256(R) ‖ memo` (commit-reveal). A memo gives the amounts and the recipient UAs, their
///   keys (`keys`, else `key_of`) and, when its flag says so, `yAud` (`auditorKey()`) rebuild `R`, which must hash to
///   the commitment;
/// - `payload`, the transfer's calldata argument (any entry, the no-bundle one included): it carries every `Y_tj`, so no
///   key is needed; its memo, if any, gives the amounts.
///
/// Without a memo the amounts come by BSGS on `C_out_j − [s]Y_tj` (`tableBits`, `boundBits` as `decrypt`). Returns `s`,
/// `salt`, `entryRef`, the legs (`toUA`, `yTo`, `amount`), `bundles` (= `R`, the argument of a disclosure on a
/// commitment), `commitment` (`keccak256(R)`), `auditorIncluded`, and the sender's openings `senderS` (every leg) and
/// `senderCp[j]` (leg `j`). Needs `chainId`, `chainUid`, `token`.
pub fn recover_transfer_with<C: ZCurve, Rn: RngCore + CryptoRng>(
    v: &Value,
    key_of: &mut dyn FnMut(&[u8; 32]) -> Option<Vec<u8>>,
    rng: &mut Rn,
) -> R<Value> {
    let k = key::<C>(v)?;
    let p = point_len::<C>();
    let (send_counter, rec, memo, commitment) = recovery_source::<C>(v)?;
    let h = recovery_header(v, send_counter)?;
    let salt: [u8; 16] = rec.as_ref().or(memo.as_ref()).ok_or("no record")?[..16].try_into().unwrap();
    let s = zether::derive_s::<C>(&k.x, &h, &k.ua(), &salt);
    let g = generator::<C>();
    let d_out = g * s;
    let ys = |r: &[u8]| (16..r.len()).step_by(4 * p).map(|o| decode_point::<C>(&r[o..o + p]).map_err(e)).collect::<R<Vec<_>>>();
    let (legs, aud): (Vec<(G<C>, u64)>, bool) = match (&rec, &memo) {
        (Some(r), Some(m)) => {
            // calldata, commit-reveal: the keys from the payload, the amounts from the memo
            let (_, aud, ml) = zether::open_memo::<C>(&k.x, &h, &k.ua(), m).map_err(e)?;
            let ys = ys(r)?;
            if ys.len() != ml.len() || ys.iter().zip(&ml).any(|(y, l)| ua_of::<C>(y) != l.to_ua) {
                return Err("the memo's recipients are not the payload's (another key, chainUid, token or a tampered memo)".into());
            }
            (ys.into_iter().zip(ml.iter().map(|l| l.amount)).collect(), aud)
        }
        (None, Some(m)) => {
            let (_, aud, ml) = zether::open_memo::<C>(&k.x, &h, &k.ua(), m).map_err(e)?;
            let mut given = std::collections::HashMap::new();
            let keys = match v.get("keys").filter(|x| !x.is_null()) {
                None => &[][..],
                Some(x) => x.as_array().ok_or("`keys` must be an array")?.as_slice(),
            };
            for y in keys {
                let s = y.as_str().ok_or("`keys` must be hex strings")?;
                let pt = decode_point::<C>(&hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(e)?).map_err(e)?;
                given.insert(ua_of::<C>(&pt), pt);
            }
            let mut missing = Vec::new();
            let mut legs = Vec::new();
            for l in &ml {
                let fetched = || key_of(&l.to_ua).and_then(|b| decode_point::<C>(&b).ok()).filter(|y| ua_of::<C>(y) == l.to_ua);
                match given.get(&l.to_ua).copied().or_else(fetched) {
                    Some(y) => legs.push((y, l.amount)),
                    None => missing.push(hx(&l.to_ua)),
                }
            }
            if !missing.is_empty() {
                return Err(format!("`keys`: no key for {} (`openMemo` lists them; `registry.keyOf(toUA)` returns each)", missing.join(", ")));
            }
            (legs, aud)
        }
        (Some(r), None) => {
            let bsgs = BsgsParams::for_target();
            let bp = BsgsParams::new(opt_bits(v, "tableBits", bsgs.table_bits)?, opt_bits(v, "boundBits", bsgs.bound_bits)?)
                .map_err(e)?;
            if !cfg!(target_arch = "wasm32") && cached_table_bits::<C>() != Some(bp.table_bits) {
                check_ram(bp.table_bits, mem_available()).map_err(e)?;
            }
            let pt = |o: usize| decode_point::<C>(&r[o..o + p]).map_err(e);
            let mut legs = Vec::new();
            let mut aud = false;
            for o in (16..r.len()).step_by(4 * p) {
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
        (None, None) => return Err("no record".into()),
    };
    let y_a = if aud { point::<C>(v, "yAud")? } else { G::<C>::zero() };
    let c_aud = |a: u64| if y_a.is_zero() { G::<C>::zero() } else { g * Fr::<C>::from(a) + y_a * s };
    let mut bundles = salt.to_vec();
    for (y, a) in &legs {
        for pt in [*y, g * Fr::<C>::from(*a) + *y * s, d_out, c_aud(*a)] {
            bundles.extend(encode_point::<C>(&pt));
        }
    }
    if rec.as_ref().is_some_and(|r| *r != bundles) || commitment.is_some_and(|c| c != keccak256(&bundles)) {
        return Err("the rebuilt record misses the chain's (another key, chainUid, token or counter, a tampered memo, or a wrong `yAud`/`keys`)".into());
    }
    let entry_ref = schnorr::entry_ref(h.chain_id, &h.chain_uid, &h.token, &k.ua(), send_counter);
    let mut cps = Vec::new();
    for (j, (y, a)) in legs.iter().enumerate() {
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
            c_aud: c_aud(*a),
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

/// `R = salt ‖ B_1 ‖ … ‖ B_M` as a transfer payload carries it, and its memo (commit-reveal) if any.
fn payload_record<C: ZCurve>(b: &[u8]) -> R<(Vec<u8>, Option<Vec<u8>>)> {
    let p = point_len::<C>();
    let salt = b.get(64..80).ok_or("payload: too short")?;
    let cut = |o: usize| &b[o..o + p];
    let mut r = salt.to_vec();
    if b.len() == 80 + 6 * p {
        for o in [80 + p, 80 + 2 * p, 80 + 3 * p, 80 + 5 * p] {
            r.extend_from_slice(cut(o));
        }
        return Ok((r, None));
    }
    let m = abi::word_u64(b, 80).ok_or("payload: M")? as usize;
    let end = 144 + 3 * p * (1 + m); // … ‖ be32(M) ‖ be32(decoyFee) ‖ Y_f ‖ D_out ‖ C_deb ‖ legs
    if m == 0 || m > zether::MAX_RECIPIENTS || (b.len() != end && b.len() != end + zether::memo_len(m)) {
        return Err("payload: neither format".into());
    }
    for j in 0..m {
        let o = 144 + 3 * p * (j + 1);
        for at in [o, o + p, 144 + p, o + 2 * p] {
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
