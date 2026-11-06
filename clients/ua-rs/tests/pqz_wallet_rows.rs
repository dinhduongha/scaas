// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T15i (ARCH-POS-13; spec no-decryption-oracle §4.3–§4.5): PQZ words rows for a real wallet key, so every binding
//! decrypts a PQZ `balance` through its own call path (the forge rows' keys are mocked: no wallet holds them). The rows
//! `smartcontracts/vectors/pqz/n2304-kmax4096/wallet_state.json` are written by `write_wallet_rows` (feature `vectors`, fixed
//! draws; `smartcontracts/vectors/pqz/gen_wallet_state.sh`) from the `pq_kat` mnemonic of `smartcontracts/vectors/ua/keys.json`
//! on the simulated chain of `tests/pqz_chain` (`PqzCore`'s stored form, tied to the contract by the forge rows): `A` =
//! `pqz_key(0, 0)` shields 1,000 and pays `B` = `pqz_key(0, 1)` 250 (op 1, verified with the precompile before settling), `B`
//! shields 7. Row `A`: `acc` the reference into op 1's blob (`v_f`), 750; row `B`: a pending credit and a TRIVIAL entry, 257.
//! `wallet_rows_decrypt` reads the committed file as every binding does. Default set only (the bindings' set). UNAUDITED.
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
    let (ka, kb) = (w.pqz_key(0, 0).unwrap(), w.pqz_key(0, 1).unwrap());
    let mut c = Chain::new();
    c.register(A, &ka.pk());
    c.register(B, &kb.pk());
    c.shield(&A, 1000);
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
    c.settle1(&stmt, None);
    c.shield(&B, 7);
    let row = |name: &str, index: u32, ua: &[u8; 32], value: u64| {
        json!({"name": name, "account": 0, "index": index, "command": "balance", "request": c.own(ua, 16), "value": value})
    };
    let out = json!({
        "set": SET,
        "mnemonic": "pq_kat",
        "generator": "smartcontracts/vectors/pqz/gen_wallet_state.sh (clients/ua-rs tests/pqz_wallet_rows.rs write_wallet_rows)",
        "note": "PQZ balance words for wallet keys (pqz_key(account, index) of the pq_kat mnemonic) on ua-rs's simulated chain \
                 (tests/pqz_chain: PqzCore's stored form); every binding decrypts each row's request to its value. UNAUDITED.",
        "rows": [row("A: acc the reference into op 1's blob (v_f)", 0, &A, 750), row("B: a pending credit and a TRIVIAL entry", 1, &B, 257)],
    });
    std::fs::write(rows_path(), serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
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
    assert_eq!(rows.len(), 2);
    for r in rows {
        let index = r["index"].as_u64().unwrap() as u32;
        let k = w.pqz_key(0, index).unwrap();
        assert_eq!(balance(&k, &r["request"]), Ok(r["value"].as_u64().unwrap()), "{}", r["name"]);
        let other = w.pqz_key(0, 1 - index).unwrap();
        assert_eq!(balance(&other, &r["request"]), Err(Error::Argument), "{}: another handle", r["name"]);
    }
}
