// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T14b (ARCH-POS-13, Codex C6; spec no-decryption-oracle §4.7): every multiplication by `x` of a point the words
//! supplied, and of the nonce over `x` in a proof, runs through `scaas_ct::secret_mul` (the blinded fixed-width ladder):
//! decrypt, check, the transfer, multi-recipient and burn proofs, the receiver's and the auditor's openings. The ladder's
//! test-only record (`scaas-ct` feature `vectors`, a dev-dependency) gives each call's blinded integer `k' = k + ρ·r`, so
//! `k' mod r` is the secret: per path, the number of ladder runs on `x` and the total. A multiplication left to arkworks'
//! variable-time `P * x` drops a run. UNAUDITED.
use ark_ff::PrimeField;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::{json, Value};
use zether_prover::curve::{decode_scalar, encode_point, Bls12381, Fr};
use zether_prover::keys::ZetherKey;
use zether_prover::state;

type K = ZetherKey<Bls12381>;

fn rows() -> Value {
    let p = format!("{}/../../smartcontracts/vectors/zether/state.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn key(x: &str) -> K {
    ZetherKey::from_secret(decode_scalar::<Bls12381>(&hex::decode(x).unwrap()).unwrap()).unwrap()
}

/// This thread's ladder runs since the last call: `(runs on x, all runs)`.
fn runs(x: &Fr<Bls12381>) -> (usize, usize) {
    let t = scaas_ct::trace::take();
    let on_x = t
        .iter()
        .filter(|e| Fr::<Bls12381>::from_le_bytes_mod_order(&e.k.iter().flat_map(|l| l.to_le_bytes()).collect::<Vec<_>>()) == *x)
        .count();
    (on_x, t.len())
}

#[test]
fn every_x_multiplication_on_a_supplied_point_is_secret_mul() {
    let rows = rows();
    let alice = key("67c93b3838eb86a76ead85bd6be7ca97ad82758b4ccd30ec58bff013a3392074");
    let bob = key("63a37d32de25c85eafe97a566343e5cae9bf7b957229c247f3ab2c8dc20b1c5a");
    let aud = key("25f771eaad146dd5c0a479073adf0bdcef837123e5e61770d13bd5f8a9e3e1d9");
    let hx = |b: &[u8]| format!("0x{}", hex::encode(b));
    let base = |k: &K| json!({"family": "evm", "chainId": rows["chainId"], "chainUid": rows["chainUid"], "token": rows["token"],
        "block": rows["block"], "psid": rows["psid"], "ua": hx(&k.ua())});
    let with = |mut v: Value, e: Value| {
        for (k, x) in e.as_object().unwrap() {
            v[k] = x.clone();
        }
        v
    };
    let a = &rows["accounts"][0];
    let acct = with(base(&alice), json!({"account": a["account"], "accountData": a["accountData"]}));
    let bsgs = json!({"tableBits": 18, "boundBits": 20});
    let y_bob = hx(&encode_point::<Bls12381>(&bob.y));
    let debit = json!({"validUntilBlock": 1000, "balance": 843});
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let mut run = |cmd: &str, v: Value, k: &K| {
        runs(&k.x);
        state::call_with_key(cmd, &v, k, &mut rng).unwrap_or_else(|e| panic!("{cmd}: {e}"));
        runs(&k.x)
    };
    // decrypt: [x]D once; check: once; a debit: the balance check on x, the nonce k_x on D (E5's A_bal)
    assert_eq!(run("balance", with(acct.clone(), bsgs.clone()), &alice), (1, 1), "balance");
    assert_eq!(run("checkBalance", with(acct.clone(), json!({"balance": 843})), &alice), (1, 1), "checkBalance");
    assert_eq!(run("proveTransfer", with(with(acct.clone(), debit.clone()), json!({"yTo": y_bob, "amount": 1})), &alice), (1, 2), "proveTransfer");
    assert_eq!(run("proveTransferMulti", with(with(acct.clone(), debit.clone()), json!({"mode": "bundle",
        "recipients": [{"yTo": y_bob, "amount": 1}]})), &alice), (1, 2), "proveTransferMulti");
    assert_eq!(run("proveBurn", with(with(acct.clone(), debit.clone()), json!({"amount": 1,
        "recipient": "0x00000000000000000000000000000000000b0c00"})), &alice), (1, 2), "proveBurn");
    // openings: the decrypt, the check of the amount, the nonce on B (A2)
    let e = &rows["entries"][0];
    let ent = |k: &K| with(with(base(k), json!({"fromUA": e["fromUA"], "sendCounter": e["sendCounter"], "entryWords": e["entryWords"],
        "entryPtr": e["entryPtr"], "index": 0})), bsgs.clone());
    assert_eq!(run("openDisclosure", with(ent(&bob), json!({"kind": "receiver"})), &bob), (2, 3), "receiver opening");
    assert_eq!(run("openDisclosure", with(ent(&aud), json!({"kind": "auditor", "modes": rows["modes"],
        "auditorKeyWords": rows["auditorKeyWords"]})), &aud), (2, 3), "auditor opening");
}
