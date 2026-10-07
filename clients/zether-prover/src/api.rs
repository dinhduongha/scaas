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
use crate::curve::{decode_point, decode_scalar, encode_point, encode_scalar, Bls12381, Bn254, Fr, ZCurve, G};
use crate::elgamal::{
    cached_table, cached_table_bits, check_balance, check_ram, encrypt, mem_available, BsgsParams, Ciphertext,
};

/// Largest wasm table without `allowLargeTable` (2^24 entries, 256 MiB).
const WASM_TABLE_BITS_DEFAULT_MAX: u32 = 24;
use crate::envelope::{self, MetaTx};
use crate::keys::{seed_from_mnemonic, ZetherKey};
use crate::schnorr;
use crate::zether::{self, Binding, BurnStatement, Header, TransferProof, TransferStatement};

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

fn header(v: &Value, amount: u64, recipient: [u8; 20]) -> R<Header> {
    let binding = if v.get("envelopeBinding").is_some_and(|x| !x.is_null()) {
        Binding::Relayed(fixed(v, "envelopeBinding")?)
    } else {
        Binding::Direct
    };
    Ok(Header {
        chain_id: num(v, "chainId")?,
        token: fixed(v, "token")?,
        binding,
        send_counter: num(v, "sendCounter")?,
        acc_seq: num(v, "accSeq")?,
        fee: opt_num(v, "fee")?,
        beneficiary: opt_fixed(v, "beneficiary")?,
        amount,
        recipient,
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

/// `transferConfidential(bytes,bytes,bytes,bytes32)` — direct call has no outer fee (S2 RS2-14).
fn direct_transfer(payload: &[u8], proof: &[u8], beneficiary: &[u8; 32]) -> Vec<u8> {
    let mut d = envelope::selector("transferConfidential(bytes,bytes,bytes,bytes32)").to_vec();
    d.extend_from_slice(&envelope::transfer_data(payload, proof, &[], beneficiary)[4..]);
    d
}

fn direct_burn(payload: &[u8], amount: u64, recipient: &[u8; 20], beneficiary: &[u8; 32], proof: &[u8]) -> Vec<u8> {
    let mut d = envelope::selector("burn(bytes,uint256,address,bytes32,bytes,bytes)").to_vec();
    d.extend_from_slice(&envelope::burn_data(payload, amount, recipient, beneficiary, proof, &[])[4..]);
    d
}

pub fn prove_transfer_json<C: ZCurve, Rn: RngCore + CryptoRng>(gens: &Gens<C>, v: &Value, rng: &mut Rn) -> R<Value> {
    let k = key::<C>(v)?;
    let h = header(v, 0, [0; 20])?;
    let y_aud = if v.get("yAud").is_some_and(|x| !x.is_null()) { point::<C>(v, "yAud")? } else { G::<C>::zero() };
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
        "authDigest": hx(&zether::auth_digest(&stmt)),
        "entryRef": hx(&schnorr::entry_ref(h.chain_id, &h.token, &k.ua(), h.send_counter)),
        "opData": hx(&envelope::transfer_data(&payload, &proof, &[], &h.beneficiary)),
        "directCalldata": hx(&direct_transfer(&payload, &proof, &h.beneficiary)),
    });
    if include_witness(v) {
        out["witness"] = json!({"x": sc::<C>(&w.x), "v": sc::<C>(&w.v), "s": sc::<C>(&w.s), "b": sc::<C>(&w.b),
            "bPrime": sc::<C>(&w.b_prime), "gammaV": sc::<C>(&w.gamma_v), "gammaB": sc::<C>(&w.gamma_b)});
    }
    Ok(out)
}

pub fn prove_burn_json<C: ZCurve, Rn: RngCore + CryptoRng>(gens: &Gens<C>, v: &Value, rng: &mut Rn) -> R<Value> {
    let k = key::<C>(v)?;
    let amount = num(v, "amount")?;
    let recipient: [u8; 20] = fixed(v, "recipient")?;
    let h = header(v, amount, recipient)?;
    let (st, p, w) =
        zether::prove_burn(gens, &k, h.clone(), ct::<C>(v, "acc")?, num(v, "balance")?, rng).map_err(e)?;
    let (stmt, proof, payload) = (st.encode(), p.encode(), st.payload());
    let mut out = json!({
        "curve": C::NAME,
        "statement": hx(&stmt),
        "proof": hx(&proof),
        "payload": hx(&payload),
        "authDigest": hx(&zether::auth_digest(&stmt)),
        "opData": hx(&envelope::burn_data(&payload, amount, &recipient, &h.beneficiary, &proof, &[])),
        "directCalldata": hx(&direct_burn(&payload, amount, &recipient, &h.beneficiary, &proof)),
    });
    if include_witness(v) {
        out["witness"] = json!({"x": sc::<C>(&w.x), "b": sc::<C>(&w.b), "amount": amount.to_string(),
            "bPrime": sc::<C>(&w.b_prime), "gammaB": sc::<C>(&w.gamma_b)});
    }
    Ok(out)
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
        to: opt_fixed(m, "to")?,
        value: opt_num(m, "value")? as u128,
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
        "proveBurn" => prove_burn_json::<C, _>(&gens(), v, rng),
        "verifyTransfer" => verify_json::<C>(&gens(), v, false),
        "verifyBurn" => verify_json::<C>(&gens(), v, true),
        "pop" => {
            let k = key::<C>(v)?;
            let (reg, acct) = (fixed::<20>(v, "registry")?, fixed::<20>(v, "account")?);
            let pop = schnorr::schnorr_pop(&k, &reg, &acct, rng);
            Ok(json!({
                "Y": hx(&k.encoded_y()), "UA": hx(&k.ua()),
                "c": hx(&schnorr::pop_message::<C>(&reg, &k.y, &acct)),
                "schnorrPop": hx(&pop),
                "popSignature": hx(&schnorr::pop_signature(&pop, &[])),
            }))
        }
        "fundCalldata" => {
            let mut d = envelope::selector("fund(bytes,uint256)").to_vec();
            d.extend(abi::encode(&[Tok::Bytes(encode_point::<C>(&point::<C>(v, "Y")?)), Tok::Word(abi::u256(num(v, "amount")?))]));
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
            let (chain, token) = (num(&v, "chainId")?, fixed::<20>(&v, "token")?);
            let m = meta(&v)?;
            json!({"binding": hx(&envelope::envelope_binding(chain, &token, &m)),
                   "digest": hx(&envelope::digest(chain, &token, &m))})
        }
        _ => match get(&v, "curve")?.as_str() {
            Some("bn254") => by_curve::<Bn254>(cmd, &v, &mut OsRng)?,
            Some("bls12381") => by_curve::<Bls12381>(cmd, &v, &mut OsRng)?,
            _ => return Err("curve must be \"bn254\" or \"bls12381\"".into()),
        },
    };
    Ok(out.to_string())
}
