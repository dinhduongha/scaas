//! Deterministic vector files for S2 (zether-design §14) and S4 (R33 keys). Regenerate with
//! `zether-cli vectors vectors/`; `tests/vectors.rs` fails when the committed files drift.

use ark_ff::BigInteger;
use ark_ff::PrimeField;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::{json, Value};

use crate::api::{hx, prove_burn_json, prove_transfer_json};
use crate::bulletproofs::Gens;
use crate::curve::{decode_scalar, encode_point, encode_scalar, Bls12381, Bn254, Fr, ZCurve};
use crate::elgamal::encrypt;
use crate::keys::{derive_child_sk, derive_master_sk, seed_from_mnemonic, ZetherKey, USE_CONF, USE_DISCLOSURE};
use crate::schnorr::{self, entry_ref, open_chaum_pedersen, open_sender, Entry, OpeningKind};
use crate::transcript::{hash_to_scalar, Op, Transcript};
use crate::zether::{self, BurnProof, BurnStatement, TransferProof, TransferStatement};

pub const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const CHAIN: u64 = 31337;
const TOKEN: &str = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
const BAL: u64 = 1_000_000;

fn h32(b: &[u8; 32]) -> String {
    hx(b)
}

fn transcript_json<C: ZCurve>(t: &Transcript) -> Value {
    let mut ops = vec![];
    let mut challenges = vec![];
    for (op, st) in t.ops.iter().zip(&t.states) {
        match op {
            Op::Absorb { label, data } => ops.push(json!({"absorb": label, "data": hx(data)})),
            Op::Challenge { label } => {
                ops.push(json!({"challenge": label}));
                challenges.push(hx(&encode_scalar::<C>(&hash_to_scalar::<C>(st))));
            }
        }
    }
    json!({
        "curve": C::NAME,
        "init": h32(&Transcript::new().state()),
        "ops": ops,
        "states": t.states.iter().map(|s| h32(s)).collect::<Vec<_>>(),
        "challenges": challenges,
    })
}

fn seed() -> [u8; 64] {
    seed_from_mnemonic(MNEMONIC, "").unwrap()
}

fn key_json(account: u32, key_use: u32) -> Value {
    json!({"seed": hx(&seed()), "coin": 60, "account": account, "use": key_use})
}

fn conf<C: ZCurve>(account: u32) -> ZetherKey<C> {
    ZetherKey::<C>::conf(&seed(), 60, account).unwrap()
}

fn per_curve<C: ZCurve>(files: &mut Vec<(String, Value)>, transcripts: &mut Vec<Value>) {
    let gens = Gens::<C>::new();
    let mut rng = ChaCha20Rng::seed_from_u64(0x5a37_4e72);
    let (from, to) = (conf::<C>(0), conf::<C>(1));
    let aud = ZetherKey::<C>::conf(&seed_from_mnemonic(MNEMONIC, "auditor").unwrap(), 60, 0).unwrap();
    let acc = encrypt(&from.y, BAL, &Fr::<C>::from(0x1234_5678_9abc_def0u64));
    let acc_j = json!({"C": hx(&encode_point::<C>(&acc.c)), "D": hx(&encode_point::<C>(&acc.d))});
    let base = json!({
        "curve": C::NAME, "key": key_json(0, USE_CONF), "chainId": CHAIN, "token": TOKEN,
        "sendCounter": 3, "accSeq": 5, "acc": acc_j, "balance": BAL, "includeWitness": true,
    });
    let with = |extra: Value| {
        let mut v = base.clone();
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        v
    };

    // transfer: auditor on, relayed, inner fee to a beneficiary.
    let req = with(json!({
        "yTo": hx(&to.encoded_y()), "yAud": hx(&aud.encoded_y()), "amount": 250_000, "fee": 300,
        "beneficiary": hx(&[0x22; 32]), "envelopeBinding": hx(&[0x33; 32]),
    }));
    let mut tv = prove_transfer_json::<C, _>(&gens, &req, &mut rng).unwrap();
    tv["expect"] = json!(true);
    tv["request"] = req;
    let st = TransferStatement::<C>::decode(&hex::decode(&tv["statement"].as_str().unwrap()[2..]).unwrap()).unwrap();
    let p = TransferProof::<C>::decode(&hex::decode(&tv["proof"].as_str().unwrap()[2..]).unwrap()).unwrap();
    let t = zether::verify_transfer(&gens, &st, &p).unwrap();
    transcripts.push(json!({"name": format!("transfer_{}", C::NAME), "case": transcript_json::<C>(&t)}));

    // disclosure of that transfer, three kinds.
    let s = decode_scalar::<C>(&hex::decode(&tv["witness"]["s"].as_str().unwrap()[2..]).unwrap()).unwrap();
    let token: [u8; 20] = hex::decode(&TOKEN[2..]).unwrap().try_into().unwrap();
    let e = Entry {
        chain_id: CHAIN,
        token,
        entry_ref: entry_ref(CHAIN, &token, &from.ua(), 3),
        y_t: st.y_t,
        c_out: st.c_out,
        d_out: st.d_out,
        y_a: st.y_a,
        c_aud: st.c_aud,
    };
    let amount = 250_000u64;
    let openings = [
        (OpeningKind::SenderS, open_sender::<C>(&s)),
        (OpeningKind::ReceiverX, open_chaum_pedersen(&e, amount, OpeningKind::ReceiverX, &to, &mut rng).unwrap()),
        (OpeningKind::Auditor, open_chaum_pedersen(&e, amount, OpeningKind::Auditor, &aud, &mut rng).unwrap()),
    ];
    let cases: Vec<Value> = openings
        .iter()
        .map(|(kind, opening)| {
            schnorr::verify_opening(&e, amount, *kind, opening).unwrap();
            json!({
                "entryRef": hx(&e.entry_ref), "chainId": CHAIN, "token": TOKEN, "amount": amount, "kind": *kind as u8,
                "Yt": hx(&encode_point::<C>(&e.y_t)), "Cout": hx(&encode_point::<C>(&e.c_out)),
                "Dout": hx(&encode_point::<C>(&e.d_out)), "Ya": hx(&encode_point::<C>(&e.y_a)),
                "Caud": hx(&encode_point::<C>(&e.c_aud)), "opening": hx(opening), "expect": true,
            })
        })
        .collect();
    files.push((format!("disclosure_{}.json", C::NAME), json!({"curve": C::NAME, "cases": cases})));
    files.push((format!("transfer_{}.json", C::NAME), tv));

    // transfer: auditor off, direct, no inner fee.
    let req = with(json!({"yTo": hx(&to.encoded_y()), "amount": 1, "fee": 0}));
    let mut tv = prove_transfer_json::<C, _>(&gens, &req, &mut rng).unwrap();
    tv["expect"] = json!(true);
    tv["request"] = req;
    files.push((format!("transfer_noaud_{}.json", C::NAME), tv));

    // burn.
    let req = with(json!({
        "amount": 400_000, "recipient": "0x4444444444444444444444444444444444444444", "fee": 300,
        "beneficiary": hx(&[0x22; 32]), "envelopeBinding": hx(&[0x33; 32]),
    }));
    let mut bv = prove_burn_json::<C, _>(&gens, &req, &mut rng).unwrap();
    bv["expect"] = json!(true);
    bv["request"] = req;
    let st = BurnStatement::<C>::decode(&hex::decode(&bv["statement"].as_str().unwrap()[2..]).unwrap()).unwrap();
    let p = BurnProof::<C>::decode(&hex::decode(&bv["proof"].as_str().unwrap()[2..]).unwrap()).unwrap();
    let t = zether::verify_burn(&gens, &st, &p).unwrap();
    transcripts.push(json!({"name": format!("burn_{}", C::NAME), "case": transcript_json::<C>(&t)}));
    files.push((format!("burn_{}.json", C::NAME), bv));

    // Schnorr over the registry PoP message, fixed k.
    let (registry, account) = ([0xaa_u8; 20], [0xbb_u8; 20]);
    let msg = schnorr::pop_message::<C>(&registry, &from.y, &account);
    let k = Fr::<C>::from(0xcafe_f00d_u64);
    let (r, e, z) = schnorr::sign_with_k::<C>(&from.x, &msg, &k);
    let mut sig = encode_point::<C>(&r);
    sig.extend(encode_scalar::<C>(&z));
    schnorr::verify::<C>(&from.y, &msg, &sig).unwrap();
    files.push((
        format!("schnorr_{}.json", C::NAME),
        json!({
            "x": hx(&encode_scalar::<C>(&from.x)), "Y": hx(&from.encoded_y()), "msg": hx(&msg),
            "k": hx(&encode_scalar::<C>(&k)), "R": hx(&encode_point::<C>(&r)), "e": hx(&encode_scalar::<C>(&e)),
            "z": hx(&encode_scalar::<C>(&z)), "sig": hx(&sig),
        }),
    ));
}

fn r33_curve<C: ZCurve>() -> Value {
    let mut rng = ChaCha20Rng::seed_from_u64(33);
    let s = seed();
    let mut keys = vec![];
    for account in [0u32, 1] {
        for key_use in [USE_CONF, USE_DISCLOSURE] {
            let k = ZetherKey::<C>::derive(&s, 60, account, key_use).unwrap();
            let mut v = json!({
                "path": format!("m/{}/60/{}/{}", C::PATH_ROOT, account, key_use),
                "x": hx(&encode_scalar::<C>(&k.x)), "Y": hx(&k.encoded_y()), "UA": hx(&k.ua()),
            });
            if key_use == USE_CONF {
                let (registry, acct) = ([0xaa_u8; 20], [0xbb_u8; 20]);
                let pop = schnorr::schnorr_pop(&k, &registry, &acct, &mut rng);
                schnorr::verify_pop(&registry, &k.y, &acct, &pop).unwrap();
                v["pop"] = json!({
                    "registry": hx(&registry), "account": hx(&acct),
                    "c": hx(&schnorr::pop_message::<C>(&registry, &k.y, &acct)),
                    "schnorrPop": hx(&pop), "popSignature": hx(&schnorr::pop_signature(&pop, &[])),
                });
            }
            keys.push(v);
        }
    }
    json!({"curve": C::NAME, "salt": String::from_utf8_lossy(C::KEYGEN_SALT), "keys": keys})
}

fn dec(b: &[u8]) -> String {
    let mut v = b.to_vec();
    let mut out = Vec::new();
    while v.iter().any(|&x| x != 0) {
        let mut rem = 0u32;
        for x in v.iter_mut() {
            let cur = (rem << 8) | *x as u32;
            *x = (cur / 10) as u8;
            rem = cur % 10;
        }
        out.push(b'0' + rem as u8);
    }
    out.reverse();
    if out.is_empty() {
        "0".into()
    } else {
        String::from_utf8(out).unwrap()
    }
}

fn eip2333_bn254() -> Value {
    let cases = [
        ("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04", 0u32),
        ("3141592653589793238462643383279502884197169399375105820974944592", 3141592653),
        ("0099ff991111002299dd7744ee3355bbdd8844115566cc55663355668888cc00", 4294967295),
        ("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3", 42),
    ];
    let out: Vec<Value> = cases
        .iter()
        .map(|(s, i)| {
            let m = derive_master_sk::<Bn254>(&hex::decode(s).unwrap()).unwrap();
            let c = derive_child_sk::<Bn254>(&m, *i);
            json!({"seed": format!("0x{s}"), "master_SK": dec(&m.into_bigint().to_bytes_be()),
                   "child_index": i, "child_SK": dec(&c.into_bigint().to_bytes_be())})
        })
        .collect();
    json!(out)
}

/// All vector files, `(file name, content)`.
pub fn generate() -> Vec<(String, Value)> {
    let mut files = vec![];
    let mut transcripts = vec![];
    per_curve::<Bn254>(&mut files, &mut transcripts);
    per_curve::<Bls12381>(&mut files, &mut transcripts);
    files.push(("transcript_s3.json".into(), json!({"cases": transcripts})));
    files.push((
        "r33_keys.json".into(),
        json!({
            "mnemonic": MNEMONIC, "passphrase": "", "seed": hx(&seed()), "coin": 60,
            "uses": {"conf": USE_CONF, "disclosure": USE_DISCLOSURE},
            "bn254": r33_curve::<Bn254>(), "bls12381": r33_curve::<Bls12381>(),
            "eip2333_bn254_variant": eip2333_bn254(),
        }),
    ));
    files
}
