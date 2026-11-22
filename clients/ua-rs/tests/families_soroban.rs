// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan 2026-11-17-scaas-sdk T27.soroban and T41.soroban: `families::soroban` (the op envelope) and `wallet::soroban_tx` (the
//! native transaction) against every row of smartcontracts/vectors/families/soroban.json and native/soroban-tx.json (written
//! by clientkeys), byte for byte; the seed's keys sign only their own builders' output; each refusal beside its control.
use scaas_ua::families::soroban::{
    check_terms, network_id, pay_nonce, signed_op, OpFields, Shown, Terms,
};
use scaas_ua::wallet::soroban_tx::{InvokeAuth, SorobanData, SorobanTx, TxOp};
use scaas_ua::wallet::{Network, Wallet};
use serde_json::Value;

fn file(p: &str) -> Value {
    let p = format!(
        "{}/../../smartcontracts/vectors/{p}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn hexb(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn b32(v: &Value) -> [u8; 32] {
    hexb(v).try_into().unwrap()
}
fn s(v: &Value) -> String {
    v.as_str().unwrap().to_string()
}
fn opt(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string)
}
fn u(v: &Value) -> u64 {
    v.as_u64()
        .unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
}

fn terms(t: &Value) -> Terms {
    let f = &t["fields"];
    let known = ["from", "to", "amount", "pay_ref", "valid_until"];
    Terms {
        network_id: b32(&t["networkId"]),
        contract: s(&t["contract"]),
        kind: s(&t["kind"]),
        fields: OpFields {
            from: s(&f["from"]),
            to: opt(&f["to"]),
            amount: f["amount"].as_str().unwrap_or_default().to_string(),
            pay_ref: f["pay_ref"].as_str().map(|x| hex::decode(&x[2..]).unwrap()),
            valid_until: f["valid_until"].as_u64(),
            extra: f
                .as_object()
                .unwrap()
                .keys()
                .filter(|k| !known.contains(&k.as_str()))
                .cloned()
                .collect(),
        },
        nonce: t["nonce"].as_str().unwrap().parse::<i128>().unwrap(),
        expiry: u(&t["expiry"]) as i64,
        ledger: u(&t["ledger"]) as u32,
        window: u(&t["window"]) as u32,
    }
}
fn shown(v: &Value) -> Shown {
    Shown {
        passphrase: s(&v["passphrase"]),
        contract: s(&v["contract"]),
        kind: s(&v["kind"]),
        from: s(&v["from"]),
        to: opt(&v["to"]),
        amount: s(&v["amount"]),
    }
}

/// The wallet of the rows' mnemonic.
fn wallet(v: &Value) -> Wallet {
    Wallet::from_mnemonic(v["mnemonic"].as_str().unwrap(), "").unwrap()
}

#[test]
fn op_rows_byte_for_byte_and_signed_by_the_subject_only() {
    let v = file("families/soroban.json");
    let w = wallet(&v);
    let subject = w.native_key(Network::Stellar, 0, None).unwrap();
    let other = w.native_key(Network::Stellar, 1, None).unwrap();
    assert_eq!(v["ops"].as_array().unwrap().len(), 3);
    for o in v["ops"].as_array().unwrap() {
        let c = check_terms(&terms(&o["terms"]), &shown(&o["shown"])).unwrap();
        assert_eq!(
            c.preimage(),
            hexb(&o["preimage"]).as_slice(),
            "{}",
            o["kind"]
        );
        assert_eq!(c.digest().to_vec(), hexb(&o["digest"]));
        let sig = subject.sign_soroban_auth(&c).unwrap();
        assert_eq!(
            sig.to_vec(),
            hexb(&o["signature"]),
            "ed25519 is deterministic"
        );
        let vu = o["signed_op"]["valid_until"].as_u64().unwrap();
        assert_eq!(signed_op(&c, &sig, vu), o["signed_op"]);
        // another key of the seed is not the subject: refused, nothing signed
        assert!(other.sign_soroban_auth(&c).is_err());
    }
}

#[test]
fn refused_op_rows_each_refused_beside_their_control() {
    let v = file("families/soroban.json");
    let refused = v["refusedOps"].as_array().unwrap();
    assert!(refused.len() >= 17);
    for r in refused {
        assert!(
            check_terms(&terms(&r["terms"]), &shown(&r["shown"])).is_err(),
            "{}",
            r["why"]
        );
        let k = r["shown"]["kind"].as_str().unwrap();
        let control = v["ops"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["kind"] == k)
            .unwrap_or(&v["ops"][0]);
        assert!(check_terms(&terms(&control["terms"]), &shown(&control["shown"])).is_ok());
    }
}

#[test]
fn pay_nonces() {
    let v = file("families/soroban.json");
    for r in v["payNonces"].as_array().unwrap() {
        let n = pay_nonce(&b32(&r["pay_ref"]), u(&r["valid_until"]));
        assert_eq!(n.to_string(), s(&r["nonce"]));
    }
    assert_eq!(
        network_id(v["ops"][0]["shown"]["passphrase"].as_str().unwrap()),
        b32(&v["ops"][0]["terms"]["networkId"])
    );
}

fn b64(v: &Value) -> Vec<u8> {
    use base64ct::{Base64, Encoding};
    Base64::decode_vec(v.as_str().unwrap()).unwrap()
}

/// A native row's transaction, its op's auth entry rebuilt through `check_terms` from the row's named payload.
fn tx(r: &Value, fam: &Value) -> SorobanTx {
    let op = if let Some(p) = r["op"].get("payment") {
        TxOp::Payment {
            destination: s(&p["destination"]),
            amount: p["amount"].as_str().unwrap().parse::<i128>().unwrap(),
        }
    } else {
        let i = &r["op"]["invoke"];
        let a = &i["auth"][0];
        // the pay of T27's rows that this entry carries (by its function: a SourceAccount entry names no payload)
        let pay = fam["ops"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| {
                o["signed_op"]["payload"]["invocation"]["function"] == i["invocation"]["function"]
            })
            .unwrap();
        let mut t = terms(&pay["terms"]);
        if !i["invocation"]["sub_invocations"]
            .as_array()
            .unwrap()
            .is_empty()
        {
            t.fields.extra.push("sub_invocations".into());
        }
        let d = &i["data"];
        let keys = |k: &str| d[k].as_array().unwrap().iter().map(b64).collect();
        TxOp::Invoke {
            op: check_terms(&t, &shown(&pay["shown"])).ok(),
            auth: if a["source"] == true {
                InvokeAuth::SourceAccount
            } else {
                InvokeAuth::Address(hexb(&a["signature"]).try_into().unwrap())
            },
            data: Some(SorobanData {
                read_only: keys("readOnly"),
                read_write: keys("readWrite"),
                instructions: u(&d["instructions"]) as u32,
                disk_read_bytes: u(&d["diskReadBytes"]) as u32,
                write_bytes: u(&d["writeBytes"]) as u32,
                resource_fee: u(&d["resourceFee"]) as i64,
                archived: d["archived"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_u64().unwrap() as u32)
                    .collect(),
            }),
        }
    };
    SorobanTx {
        source: s(&r["source"]),
        fee: u(&r["fee"]),
        seq: r["seq"].as_str().unwrap().parse::<i128>().unwrap(),
        min_time: u(&r["minTime"]),
        max_time: u(&r["maxTime"]),
        op,
    }
}

#[test]
fn native_rows_byte_for_byte_and_signed_by_the_source_only() {
    let n = file("native/soroban-tx.json");
    let fam = file("families/soroban.json");
    let w = wallet(&fam);
    let payer = w.native_key(Network::Stellar, 2, None).unwrap();
    let subject = w.native_key(Network::Stellar, 0, None).unwrap();
    let nid = b32(&n["networkId"]);
    assert_eq!(n["rows"].as_array().unwrap().len(), 5);
    for r in n["rows"].as_array().unwrap() {
        let t = tx(r, &fam);
        assert_eq!(t.xdr().unwrap(), hexb(&r["tx"]), "{}", r["what"]);
        assert_eq!(t.hash(&nid).unwrap().to_vec(), hexb(&r["hash"]));
        // the row's source signs (the payer, or the subject of a self-paid op); the other key is refused
        assert_eq!(r["signer"], r["source"]);
        let (signer, other) = if r["source"] == n["payer"] {
            (&payer, &subject)
        } else {
            (&subject, &payer)
        };
        let signed = signer.sign_soroban_tx(&nid, &t).unwrap();
        assert_eq!(signed.signature.to_vec(), hexb(&r["signature"]));
        assert_eq!(signed.envelope, hexb(&r["envelope"]));
        assert_eq!(signed.tx, hexb(&r["tx"]));
        assert!(other.sign_soroban_tx(&nid, &t).is_err());
    }
}

#[test]
fn refused_native_rows_each_refused_beside_their_control() {
    let n = file("native/soroban-tx.json");
    let fam = file("families/soroban.json");
    for r in n["refused"].as_array().unwrap() {
        assert!(tx(r, &fam).xdr().is_err(), "{}", r["why"]);
        let kind = r["op"].as_object().unwrap().keys().next().unwrap().clone();
        let control = n["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["op"].get(&kind).is_some())
            .unwrap();
        assert!(tx(control, &fam).xdr().is_ok());
    }
}

#[test]
fn a_transaction_signs_only_with_its_data_and_auth() {
    let n = file("native/soroban-tx.json");
    let fam = file("families/soroban.json");
    let w = wallet(&fam);
    let payer = w.native_key(Network::Stellar, 2, None).unwrap();
    let nid = b32(&n["networkId"]);
    let full = tx(&n["rows"][0], &fam);
    assert!(payer.sign_soroban_tx(&nid, &full).is_ok(), "control");
    // the simulation's form: no data (ext v0) and no auth (recording), never signed
    let TxOp::Invoke { op, auth, data } = full.op.clone() else {
        panic!()
    };
    for (s, d) in [(InvokeAuth::None, data.clone()), (auth, None)] {
        let t = SorobanTx {
            op: TxOp::Invoke {
                op: op.clone(),
                auth: s,
                data: d,
            },
            ..full.clone()
        };
        assert!(t.unsigned_envelope().is_ok(), "simulated");
        assert!(payer.sign_soroban_tx(&nid, &t).is_err(), "never signed");
    }
}

/// Owner 2026-11-22: a SourceAccount entry only when the transaction's source is the op's subject; the self-paid row under the
/// payer's source is refused, the row itself the control.
#[test]
fn a_source_account_entry_only_under_its_subject() {
    let n = file("native/soroban-tx.json");
    let fam = file("families/soroban.json");
    let row = n["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["op"]["invoke"]["auth"][0]["source"] == true)
        .unwrap();
    let t = tx(row, &fam);
    assert!(t.xdr().is_ok(), "control");
    let moved = SorobanTx {
        source: n["payer"].as_str().unwrap().into(),
        ..t
    };
    assert!(moved.xdr().is_err());
}
