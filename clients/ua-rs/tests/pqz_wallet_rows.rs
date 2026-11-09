// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T15i (ARCH-POS-13; spec no-decryption-oracle §4.3–§4.5): PQZ words rows for a real wallet key, so every binding
//! decrypts a PQZ `balance` through its own call path (the forge rows' keys are mocked: no wallet holds them). The rows
//! `smartcontracts/vectors/pqz/n2304-kmax4096/wallet_state.json` are written by `write_wallet_rows` (feature `vectors`, fixed
//! draws; `smartcontracts/vectors/pqz/gen_wallet_state.sh`) from the `pq_kat` mnemonic of `smartcontracts/vectors/ua/keys.json`
//! on the simulated chain of `tests/pqz_chain` (`PqzCore`'s stored form, tied to the contract by the forge rows): `A` =
//! `pqz_key(0, 0)` shields 1,000 and pays `B` = `pqz_key(0, 1)` 250 (op 1, verified with the precompile before settling), `B`
//! shields 7; then (group 3g, T15o) `A` rotates to key version 1 (`pqz_key_version(0, 0, 1)`) and migrates 700 from its stale
//! version 0 (op 1 to itself, verified). Row `A v0`: `acc` the reference into the migration's blob (`v_f`), 50; row `A v1`: the
//! migrated credit pending, 700; row `B`: a pending credit and a TRIVIAL entry, 257. Each row names its `account`, `index` and
//! `version`. `wallet_rows_decrypt` reads the committed file as every binding does. T20d9 (C-PP-8): the debits are LOG (their
//! P in history, the model's `proofs`) and carry their real `ownTag`, so the same state gives path (B)'s rows: `proven` (each
//! `{open, add, value, kinds}`: `provenOpen`'s words, `provenAdd`'s `{blobs, credits}` without the session, the value and the
//! parts' kinds; `A v1`'s migration credit by re-encryption, `A v0`'s own `v_f` by its tag, `B`'s credit by its P) and `check`
//! (`checkProven`'s request for `B` as a quorum, with no handle, and its answer). Default set only (the bindings' set). UNAUDITED.
#[cfg(feature = "vectors")]
mod pqz_chain;
use pqz_ffi::stmt as st;
use scaas_ua::facade::pqz::PqzKey;
use scaas_ua::wallet::{Error, Wallet};
use serde_json::Value;

const SET: &str = "n2304-kmax4096";

fn path(rel: &str) -> String {
    format!("{}/../../{rel}", env!("CARGO_MANIFEST_DIR"))
}
fn rows_path() -> String {
    path(&format!("smartcontracts/vectors/pqz/{SET}/wallet_state.json"))
}

fn unlock() {
    #[cfg(feature = "vectors")]
    scaas_ua::facade::vectors_unlock(scaas_ua::facade::TestOnly);
}

/// The `pq_kat` wallet of `smartcontracts/vectors/ua/keys.json`.
fn wallet() -> Wallet {
    let keys: Value = serde_json::from_str(&std::fs::read_to_string(path("smartcontracts/vectors/ua/keys.json")).unwrap()).unwrap();
    let m = keys["mnemonics"].as_array().unwrap().iter().find(|m| m["id"] == "pq_kat").unwrap();
    Wallet::from_mnemonic(m["words"].as_str().unwrap(), m["passphrase"].as_str().unwrap()).unwrap()
}

fn balance(k: &PqzKey, req: &Value) -> Result<u64, Error> {
    k.call("balance", req.to_string().as_bytes()).map(|s| serde_json::from_str::<Value>(&s).unwrap()["value"].as_u64().unwrap())
}

/// The generator (feature `vectors`, ignored; `gen_wallet_state.sh` runs it): fixed draws, so two runs write the same bytes.
#[cfg(feature = "vectors")]
#[test]
#[ignore]
fn write_wallet_rows() {
    use pqz_chain::*;
    use scaas_ua::facade::pqz::Draw;
    use serde_json::json;
    const A: [u8; 32] = [0xA1; 32];
    const B: [u8; 32] = [0xB0; 32];
    assert_eq!(st::SET, SET, "the bindings' set");
    unlock();
    let w = wallet();
    let (ka, kb, ka1) = (w.pqz_key(0, 0).unwrap(), w.pqz_key(0, 1).unwrap(), w.pqz_key_version(0, 0, 1).unwrap());
    let mut c = Chain::new();
    c.register(A, &ka.pk());
    c.register(B, &kb.pk());
    c.shield(&A, 1000);
    // path (B)'s history: LOG debits, their P noted, their real tags in the blobs (T20d9)
    c.proof_store = 1;
    let req = merge(
        merge(c.own(&A, 16), c.debit_fields()),
        json!({"toUA": hx(&B), "pkT": hx(&kb.pk()), "amount": 250, "mode": "BUNDLE"}),
    );
    let p: Value = serde_json::from_str(
        &ka.vectors_call("proveTransfer", req.to_string().as_bytes(), &Draw::vectors([0x71; 32], Some([0x72; 32]), Some([0x73; 16]), None))
            .unwrap(),
    )
    .unwrap();
    let (stmt, proof) = (h(&p["stmt"]), h(&p["proof"]));
    assert_eq!(pqz_ffi::precompile(&st::input(1, &stmt, &proof)), Ok(pqz_ffi::VALID), "op 1 verifies");
    c.own_tag = h(&p["ownTag"]).try_into().unwrap();
    c.note_proof(1, &stmt, &proof, json!({}));
    c.settle1(&stmt, None);
    c.shield(&B, 7);
    // A's key version 1, current at once; the migration of 700 from version 0 (stale: op 1 to itself only), its encryption
    // seed CTR-PQZ-19's from version 0's seed (T20d9: path (B) checks the migration credit by re-encryption)
    c.add_version(A, &ka1.pk(), true);
    let req = merge(
        merge(c.own_at(&A, 0, 16), c.debit_fields()),
        json!({"toUA": hx(&A), "pkT": hx(&ka1.pk()), "amount": 700, "mode": "BUNDLE"}),
    );
    let p: Value = serde_json::from_str(
        &ka.vectors_call("proveTransfer", req.to_string().as_bytes(), &Draw::vectors([0x74; 32], None, Some([0x76; 16]), None))
            .unwrap(),
    )
    .unwrap();
    let (stmt, proof) = (h(&p["stmt"]), h(&p["proof"]));
    assert_eq!(pqz_ffi::precompile(&st::input(1, &stmt, &proof)), Ok(pqz_ffi::VALID), "the migration verifies");
    c.own_tag = h(&p["ownTag"]).try_into().unwrap();
    c.note_proof(1, &stmt, &proof, json!({}));
    c.settle1(&stmt, None);
    let row = |name: &str, index: u32, version: u64, ua: &[u8; 32], value: u64| {
        let request = merge(c.own_at(ua, version, 16), json!({"forOp7": false}));
        json!({"name": name, "account": 0, "index": index, "version": version, "command": "balance", "request": request, "value": value})
    };
    // path (B): each row's words, its credits, its value and parts (checked here through the facade, as every binding does)
    let proven = |name: &str, index: u32, version: u64, ua: &[u8; 32], value: u64| {
        let open = c.proven_open(ua, version);
        let k = w.pqz_key_version(0, index, version).unwrap();
        let o: Value = serde_json::from_str(&k.call("provenOpen", open.to_string().as_bytes()).unwrap()).unwrap();
        let cs: Vec<_> = o["need"].as_array().unwrap().iter().map(|i| c.proven_credit(ua, version, i.as_u64().unwrap())).collect();
        let mut add = c.add_request(&o["session"], &cs);
        add.as_object_mut().unwrap().remove("session");
        let mut a = add.clone();
        a["session"] = o["session"].clone();
        k.call("provenAdd", a.to_string().as_bytes()).unwrap();
        let b: Value = serde_json::from_str(&k.call("balanceProven", json!({"session": o["session"]}).to_string().as_bytes()).unwrap()).unwrap();
        assert_eq!(b["value"], value, "{name}");
        let kinds: Vec<Value> = b["parts"].as_array().unwrap().iter().map(|p| p["kind"].clone()).collect();
        json!({"name": name, "account": 0, "index": index, "version": version, "open": open, "add": add, "value": value, "kinds": kinds})
    };
    let cs: Vec<_> = c.window_credits(&B, 0).iter().map(|i| c.proven_credit(&B, 0, *i)).collect();
    let check_req = c.check_request(&B, 0, &kb.pk(), None, &cs);
    let check_out: Value =
        serde_json::from_str(&scaas_ua::facade::pqz::check_proven(check_req.to_string().as_bytes()).unwrap()).unwrap();
    let out = json!({
        "set": SET,
        "mnemonic": "pq_kat",
        "generator": "smartcontracts/vectors/pqz/gen_wallet_state.sh (clients/ua-rs tests/pqz_wallet_rows.rs write_wallet_rows)",
        "note": "PQZ balance words for wallet keys (pqz_key_version(account, index, version) of the pq_kat mnemonic) on ua-rs's \
                 simulated chain (tests/pqz_chain: PqzCore's stored form, accounts per key version); every binding decrypts each \
                 row's request to its value. UNAUDITED.",
        "rows": [
            row("A v0: acc the reference into the migration's blob (v_f)", 0, 0, &A, 50),
            row("A v1: the migrated credit pending", 0, 1, &A, 700),
            row("B: a pending credit and a TRIVIAL entry", 1, 0, &B, 257),
        ],
        "proven": [
            proven("A v0 by the proof path: its own v_f by its tag", 0, 0, &A, 50),
            proven("A v1 by the proof path: the migration credit by re-encryption", 0, 1, &A, 700),
            proven("B by the proof path: a credit by its P and a TRIVIAL entry", 1, 0, &B, 257),
        ],
        "check": [{"name": "B as an MPC quorum (checkProven, no handle): its credit by its P", "request": check_req, "answer": check_out}],
    });
    std::fs::write(rows_path(), serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
}

/// T20d9: the committed path (B) rows through each row's own handle (`provenOpen`, `provenAdd` with the session, `balanceProven`:
/// every credit accepted, the value and kinds the row's), and the quorum's row through `check_proven` (no handle: the answer).
#[test]
fn proven_rows_through_the_facade() {
    use serde_json::json;
    if st::SET != SET {
        return;
    }
    unlock();
    let v: Value = serde_json::from_str(&std::fs::read_to_string(rows_path()).unwrap()).unwrap();
    let w = wallet();
    let call = |k: &PqzKey, cmd: &str, r: &Value| -> Value { serde_json::from_str(&k.call(cmd, r.to_string().as_bytes()).unwrap()).unwrap() };
    let rows = v["proven"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    for r in rows {
        let k = w.pqz_key_version(0, r["index"].as_u64().unwrap() as u32, r["version"].as_u64().unwrap()).unwrap();
        let o = call(&k, "provenOpen", &r["open"]);
        let mut add = r["add"].clone();
        add["session"] = o["session"].clone();
        assert_eq!(call(&k, "provenAdd", &add)["accepted"], o["need"], "{}", r["name"]);
        let b = call(&k, "balanceProven", &json!({"session": o["session"]}));
        let kinds: Vec<Value> = b["parts"].as_array().unwrap().iter().map(|p| p["kind"].clone()).collect();
        assert_eq!((&b["value"], json!(kinds)), (&r["value"], r["kinds"].clone()), "{}", r["name"]);
    }
    for r in v["check"].as_array().unwrap() {
        let got: Value = serde_json::from_str(&scaas_ua::facade::pqz::check_proven(r["request"].to_string().as_bytes()).unwrap()).unwrap();
        assert_eq!(got, r["answer"], "{}", r["name"]);
    }
}

/// The committed rows decrypt to their values through each row's own handle; the other holder's handle refuses the same words.
#[test]
fn wallet_rows_decrypt() {
    if st::SET != SET {
        return;
    }
    unlock();
    let rows: Value = serde_json::from_str(&std::fs::read_to_string(rows_path()).unwrap()).unwrap();
    let w = wallet();
    let rows = rows["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    for r in rows {
        let (index, version) = (r["index"].as_u64().unwrap() as u32, r["version"].as_u64().unwrap());
        let k = w.pqz_key_version(0, index, version).unwrap();
        assert_eq!(balance(&k, &r["request"]), Ok(r["value"].as_u64().unwrap()), "{}", r["name"]);
        for other in [w.pqz_key_version(0, 1 - index, version).unwrap(), w.pqz_key_version(0, index, 1 - version).unwrap()] {
            assert_eq!(balance(&other, &r["request"]), Err(Error::Argument), "{}: another handle", r["name"]);
        }
    }
}
