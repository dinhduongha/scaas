// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! scaas-sdk T10 (spec §13.2): `sign_scaas`, the one call that signs a typed SCaaS struct for its entry under the check of what
//! the user confirmed: a native EVM key's `UASig{"", r‖s‖v over the digest, []}` (the `typed_ops.json` row's signature), a UA
//! key's `UASig` over `uaMessage(kind, purpose, digest)` with the entry's purpose (`metatx`, `payee-fee`, `trade`); anything the
//! check refuses signs nothing. UNAUDITED.
use scaas_ua::purpose_tag;
use scaas_ua::ua_portable::UASig;
use scaas_ua::wallet::{
    scaas_purpose, scaas_typed_data, sign_scaas, ua_sig, Error, Expect, ExternalKey, NativeKey,
    Network, SignRequest, Signer, Wallet,
};
use serde_json::Value;

fn ops() -> Value {
    let p = format!(
        "{}/../../smartcontracts/vectors/typed/typed_ops.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn hexb(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

struct Row {
    contract: [u8; 20],
    chain_id: u64,
    uid: [u8; 32],
    message: Value,
    digest: Vec<u8>,
    signature: Vec<u8>,
}
fn row(name: &str, kind: &str) -> Row {
    let o = &ops()["ops"][name];
    let d = &o["domains"][kind];
    Row {
        contract: hexb(&d["domain"]["verifyingContract"]).try_into().unwrap(),
        chain_id: d["domain"]["chainId"].as_str().unwrap().parse().unwrap(),
        uid: hexb(&d["domain"]["salt"]).try_into().unwrap(),
        message: o["message"].clone(),
        digest: hexb(&d["digest"]),
        signature: hexb(&d["signature"]),
    }
}
fn op(r: &Row, name: &str, message: &Value) -> Expect {
    Expect::Op {
        op: name.into(),
        contract: r.contract,
        chain_id: r.chain_id,
        chain_uid: r.uid,
        message: message.clone(),
        max_fee: "1000000000000000000000".into(),
        fee_recipient: None,
        relayer: None,
        now: 1,
        max_window: u64::MAX / 2,
    }
}
const WORDS: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
/// The wallet stays alive beside its key (a dropped wallet revokes its handles).
fn native() -> (Wallet, NativeKey) {
    let w = Wallet::from_mnemonic(WORDS, "").unwrap();
    let k = w.native_key(Network::Evm, 0, None).unwrap();
    (w, k)
}

#[test]
fn native_key_signs_the_rows_digest() {
    let r = row("UACancelNonce", "token");
    let td = scaas_typed_data(
        "UACancelNonce",
        Some("SCaaS MetaToken"),
        &r.contract,
        r.chain_id,
        &r.uid,
        &r.message,
    )
    .unwrap();
    assert_eq!(td.digest().unwrap().to_vec(), r.digest);
    let (_w, n) = native();
    let s = sign_scaas(&n, &td, op(&r, "UACancelNonce", &r.message)).unwrap();
    let want = n
        .sign_typed(&td, op(&r, "UACancelNonce", &r.message))
        .unwrap();
    assert_eq!(
        s,
        UASig {
            key_data: vec![],
            signature: want,
            members: vec![]
        },
        "r || s || v over the row's digest, no key data"
    );
    assert_eq!(r.signature.len(), s.signature.len());
    // a check of another value refuses: nothing signed
    let mut other = r.message.clone();
    other["lane"] = "8".into();
    assert_eq!(
        sign_scaas(&n, &td, op(&r, "UACancelNonce", &other)).unwrap_err(),
        Error::PolicyRefused
    );
}

#[test]
fn ua_key_signs_under_the_entrys_purpose() {
    let w = Wallet::from_mnemonic(WORDS, "").unwrap();
    let key = w.ua_key(0x0101, 0, 0).unwrap(); // p256: RFC 6979, one signature per message
    for (name, purpose) in [
        ("UACancelNonce", "metatx"),
        ("UAPayeeFee", "payee-fee"),
        ("CancelUAOrder", "trade"),
    ] {
        let r = row(name, "token");
        let td = scaas_typed_data(
            name,
            Some("SCaaS MetaToken"),
            &r.contract,
            r.chain_id,
            &r.uid,
            &r.message,
        )
        .unwrap();
        let want = ua_sig(
            &key,
            None,
            &purpose_tag(purpose).unwrap(),
            &td.digest().unwrap(),
        )
        .unwrap();
        assert_eq!(
            scaas_purpose(&td).unwrap(),
            purpose_tag(purpose).unwrap(),
            "{name}"
        );
        assert_eq!(
            sign_scaas(&key, &td, op(&r, name, &r.message)).unwrap(),
            want,
            "{name}: {purpose}"
        );
        assert_eq!(
            key.key_ref(),
            scaas_ua::wallet::KeyRef::Ua {
                kind: 0x0101,
                key_data: want.key_data.clone()
            }
        );
    }
    let r = row("UACancelNonce", "token");
    let td = scaas_typed_data(
        "UACancelNonce",
        Some("SCaaS MetaToken"),
        &r.contract,
        r.chain_id,
        &r.uid,
        &r.message,
    )
    .unwrap();
    let mut other = r.message.clone();
    other["fee"] = "1".into();
    assert_eq!(
        sign_scaas(&key, &td, op(&r, "UACancelNonce", &other)).unwrap_err(),
        Error::PolicyRefused
    );
}

/// Owner 2026-11-19, ruling C3: the Zether owner statements sign under `zether-owner` (`ZetherLib`'s `requireAuthorized`), not
/// `metatx`; the same class by the contracts: `PqzRollOver` under `zether-auth` (`PqzStateLib`, CTR-PQZ-41), `AuditorConsent`
/// under `auditor-consent` (CTR-PQZ-43), and `PqzAuth` under `zether-auth` (`PqzCore.requireHolder`; P-T16-1). Each row's signature equals `ua_sig` under that purpose and differs from `metatx`'s.
#[test]
fn owner_statements_sign_under_their_contract_purpose() {
    let w = Wallet::from_mnemonic(WORDS, "").unwrap();
    let key = w.ua_key(0x0101, 0, 0).unwrap();
    for (name, kind, purpose) in [
        ("ZetherRollOver", "zether", "zether-owner"),
        ("ZetherSetRollOverMode", "zether", "zether-owner"),
        ("PqzRollOver", "pqz", "zether-auth"),
        // P-T16-1: the debit's `pqzAuth` (`PqzCore.requireHolder`, `PURPOSE_ZETHER_AUTH`)
        ("PqzAuth", "pqz", "zether-auth"),
        ("AuditorConsent", "pqz", "auditor-consent"),
    ] {
        let r = row(name, kind);
        let dn = ops()["ops"][name]["domains"][kind]["domain"]["name"]
            .as_str()
            .unwrap()
            .to_string();
        let td =
            scaas_typed_data(name, Some(&dn), &r.contract, r.chain_id, &r.uid, &r.message).unwrap();
        assert_eq!(
            td.digest().unwrap().to_vec(),
            r.digest,
            "{name}: the row's digest"
        );
        assert_eq!(
            scaas_purpose(&td).unwrap(),
            purpose_tag(purpose).unwrap(),
            "{name}"
        );
        let got = sign_scaas(&key, &td, op(&r, name, &r.message)).unwrap();
        let sig =
            |p: &str| ua_sig(&key, None, &purpose_tag(p).unwrap(), &td.digest().unwrap()).unwrap();
        assert_eq!(got, sig(purpose), "{name}: {purpose}");
        assert_ne!(got, sig("metatx"), "{name}: not metatx");
    }
}

/// Owner 2026-11-19, ruling C (closing review P2-11): a mandate wallet's `UAExecute` under `Expect::Execute` signs only the
/// decoded call: `ua-rs` rebuilds `target`, `value` and `data` from it. No byte format moves: the typed data and its digest are
/// `scaas_typed_data`'s (the `typed_ops.json` row's domain and envelope), and the signature equals the one `Expect::Op` gives
/// over the same message (the control).
#[test]
fn execute_signs_only_the_decoded_call() {
    use scaas_ua::wallet::DecodedCall;
    let r = row("UAExecute", "wallet");
    let token = [0xa1u8; 20];
    let call = DecodedCall::Erc20Transfer {
        token,
        to: [0x22; 20],
        amount: "77".into(),
    };
    let (target, _, data) = call.encode().unwrap();
    assert_eq!(
        &data[..4],
        &scaas_ua::keccak256(b"transfer(address,uint256)")[..4]
    );
    let mut m = r.message.clone();
    m["target"] = format!("0x{}", hex::encode(target)).into();
    m["value"] = "0".into();
    m["data"] = format!("0x{}", hex::encode(&data)).into();
    let td = scaas_typed_data(
        "UAExecute",
        Some("SCaaS MandateWallet"),
        &r.contract,
        r.chain_id,
        &r.uid,
        &m,
    )
    .unwrap();
    let exec = |call: DecodedCall, msg: &Value| Expect::Execute {
        wallet: r.contract,
        chain_id: r.chain_id,
        chain_uid: r.uid,
        message: msg.clone(),
        call,
        max_fee: "0".into(),
        fee_recipient: None,
        relayer: Some(
            [0; 18]
                .iter()
                .chain(&[0xbe, 0xef])
                .copied()
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap(),
        ),
        now: 1,
        max_window: u64::MAX / 2,
    };
    let (_w, n) = native();
    let s = sign_scaas(&n, &td, exec(call.clone(), &r.message)).unwrap();
    assert_eq!(
        s,
        sign_scaas(&n, &td, op(&r, "UAExecute", &m)).unwrap(),
        "the same bytes as Expect::Op over the message"
    );
    // the typed data carries another amount, another recipient, a value, or the row's filler data: refused, nothing signed
    for (k, v) in [
        (
            "data",
            Value::from(format!("0x{}", hex::encode(&call_with("78")[..]))),
        ),
        ("value", "1".into()),
        ("data", r.message["data"].clone()),
    ] {
        let mut x = m.clone();
        x[k] = v;
        let td = scaas_typed_data(
            "UAExecute",
            Some("SCaaS MandateWallet"),
            &r.contract,
            r.chain_id,
            &r.uid,
            &x,
        )
        .unwrap();
        assert_eq!(
            sign_scaas(&n, &td, exec(call.clone(), &r.message)).unwrap_err(),
            Error::PolicyRefused,
            "{k}"
        );
    }
    fn call_with(amount: &str) -> Vec<u8> {
        DecodedCall::Erc20Transfer {
            token: [0xa1; 20],
            to: [0x22; 20],
            amount: amount.into(),
        }
        .encode()
        .unwrap()
        .2
    }
}

/// scaas-sdk T13: a `SmartKeyAccount`'s `Execute` under `Expect::Execute` signs only the decoded call, here a guardian's
/// `initiateRecovery(key)` on the account it guards (CTR-ACC-03): the same bytes as `Expect::Op` over the rebuilt message (the
/// control); another key, account or value in the typed data is refused.
#[test]
fn account_execute_signs_only_the_decoded_recovery() {
    use scaas_ua::wallet::{DecodedCall, SubjectKey};
    let r = row("Execute", "account");
    let key = SubjectKey {
        kind: 2,
        x: {
            let mut x = [0u8; 32];
            x[12..].copy_from_slice(&[0x33; 20]);
            x
        },
        y: [0; 32],
        rp_id_hash: [0; 32],
        origin_hash: [0; 32],
    };
    let call = DecodedCall::InitiateRecovery {
        account: [0x44; 20],
        key: key.clone(),
    };
    let (target, _, data) = call.encode().unwrap();
    assert_eq!(target, [0x44; 20]);
    assert_eq!(
        &data[..4],
        &scaas_ua::keccak256(b"initiateRecovery((uint8,bytes32,bytes32,bytes32,bytes32))")[..4]
    );
    assert_eq!(data.len(), 4 + 5 * 32);
    let typed = |m: &Value| {
        scaas_typed_data(
            "Execute",
            Some("SCaaS SmartKeyAccount"),
            &r.contract,
            r.chain_id,
            &r.uid,
            m,
        )
        .unwrap()
    };
    let mut m = r.message.clone();
    m["target"] = format!("0x{}", hex::encode(target)).into();
    m["value"] = "0".into();
    m["data"] = format!("0x{}", hex::encode(&data)).into();
    let exec = |msg: &Value| Expect::Execute {
        wallet: r.contract,
        chain_id: r.chain_id,
        chain_uid: r.uid,
        message: msg.clone(),
        call: call.clone(),
        max_fee: "0".into(),
        fee_recipient: None,
        relayer: None,
        now: 1,
        max_window: u64::MAX / 2,
    };
    let (_w, n) = native();
    let canon = typed(&m).to_value()["message"].clone();
    let s = sign_scaas(&n, &typed(&m), exec(&canon)).unwrap();
    assert_eq!(
        s,
        sign_scaas(&n, &typed(&m), op(&r, "Execute", &canon)).unwrap(),
        "the control"
    );
    let other = DecodedCall::InitiateRecovery {
        account: [0x44; 20],
        key: SubjectKey { y: [1; 32], ..key },
    };
    for (k, v) in [
        (
            "data",
            Value::from(format!("0x{}", hex::encode(other.encode().unwrap().2))),
        ),
        (
            "target",
            Value::from(format!("0x{}", hex::encode([0x45u8; 20]))),
        ),
        ("value", "1".into()),
    ] {
        let mut x = m.clone();
        x[k] = v;
        assert_eq!(
            sign_scaas(&n, &typed(&x), exec(&canon)).unwrap_err(),
            Error::PolicyRefused,
            "{k}"
        );
    }
}

/// Owner 2026-11-19, ruling D: a plain transfer on ids under `Expect::Transfer`: `entryRef = 0` on the lane the caller names, the
/// lane's nonce; a payment's `entryRef` or another lane is refused. The typed data is `UAMetaTransfer`'s (`metatx3.json`'s
/// domain), the same bytes as an unchecked signature of it (the control).
#[test]
fn transfer_is_entry_ref_zero_on_the_named_lane() {
    let p = format!(
        "{}/../../smartcontracts/vectors/ua/metatx3.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let row = v["transfer"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "native")
        .unwrap();
    let d = &row["typedData"]["domain"];
    let token: [u8; 20] = hexb(&d["verifyingContract"]).try_into().unwrap();
    let uid: [u8; 32] = hexb(&d["salt"]).try_into().unwrap();
    let chain_id: u64 = d["chainId"]
        .as_u64()
        .or_else(|| d["chainId"].as_str().and_then(|s| s.parse().ok()))
        .unwrap();
    let mut m = row["typedData"]["message"].clone();
    m["entryRef"] = format!("0x{}", "00".repeat(32)).into();
    m["batch"] = "9".into();
    m["nonce"] = "4".into();
    let (_w, n) = native();
    let from: [u8; 32] = hexb(&m["from"]).try_into().unwrap();
    let to: [u8; 32] = hexb(&m["to"]).try_into().unwrap();
    let expect = |batch: &str| Expect::Transfer {
        account: from,
        chain_id,
        chain_uid: uid,
        amount: m["value"]
            .as_str()
            .map(String::from)
            .unwrap_or_else(|| m["value"].to_string()),
        decimals: 0,
        payee: to,
        batch: batch.into(),
        expected_token: token,
        max_fee: "1000000000000000000000".into(),
        // the row binds both (mode 0x23)
        fee_recipient: Some(hexb(&m["feeRecipient"]).try_into().unwrap()),
        relayer: Some(hexb(&m["relayer"]).try_into().unwrap()),
        now: 1,
        max_window: u64::MAX / 2,
    };
    let td = |m: &Value| {
        scaas_typed_data(
            "UAMetaTransfer",
            Some("SCaaS MetaToken"),
            &token,
            chain_id,
            &uid,
            m,
        )
        .unwrap()
    };
    let s = sign_scaas(&n, &td(&m), expect("9")).unwrap();
    // the control: the key's signature over the same typed data with no SCaaS check (the bytes are `scaas_typed_data`'s)
    let any = n
        .sign_typed(&td(&m), Expect::Any(scaas_ua::wallet::AllowAnyTypedData))
        .unwrap();
    assert_eq!(
        s.signature, any,
        "the same bytes as the unchecked signature of the typed data"
    );
    assert_eq!(
        sign_scaas(&n, &td(&m), expect("8")).unwrap_err(),
        Error::PolicyRefused,
        "another lane"
    );
    let mut paid = m.clone();
    paid["entryRef"] = row["typedData"]["message"]["entryRef"].clone();
    assert_eq!(
        sign_scaas(&n, &td(&paid), expect("9")).unwrap_err(),
        Error::PolicyRefused,
        "a payment's entryRef"
    );
}

/// scaas-sdk closing review P2-4: `fee_due` is the amount the check charges: a PERCENT row (`UABurn`, mode 0x13, rate 5000 on
/// 135000) pays 675, which signs as `max_fee` and one less is refused; FIXED pays its `fee`, NONE 0.
#[test]
fn fee_due_is_the_amount_the_check_charges() {
    use scaas_ua::wallet::fee_due;
    let r = row("UABurn", "token");
    assert_eq!(r.message["mode"], 19);
    assert_eq!(fee_due("UABurn", &r.message).unwrap(), "675");
    let td = scaas_typed_data(
        "UABurn",
        Some("SCaaS MetaToken"),
        &r.contract,
        r.chain_id,
        &r.uid,
        &r.message,
    )
    .unwrap();
    let (_w, n) = native();
    let with = |max: &str| {
        let mut e = op(&r, "UABurn", &r.message);
        if let Expect::Op {
            max_fee,
            fee_recipient,
            relayer,
            ..
        } = &mut e
        {
            *max_fee = max.into();
            *fee_recipient = Some(hexb(&r.message["feeRecipient"]).try_into().unwrap());
            *relayer = Some(hexb(&r.message["relayer"]).try_into().unwrap());
        }
        e
    };
    assert!(sign_scaas(&n, &td, with("675")).is_ok());
    assert_eq!(
        sign_scaas(&n, &td, with("674")).unwrap_err(),
        Error::PolicyRefused,
        "one less than the amount due"
    );
    let mut fixed = r.message.clone();
    fixed["mode"] = 0x23.into();
    assert_eq!(fee_due("UABurn", &fixed).unwrap(), "5000");
    let mut none = r.message.clone();
    (none["mode"], none["fee"]) = (0.into(), "0".into());
    assert_eq!(fee_due("UABurn", &none).unwrap(), "0");
}

/// Owner 2026-11-19, P1 (S1): an external key's caller dry-runs `sign_scaas` through an `ExternalKey` that only refuses, so the
/// policy check passes before the user is asked (a value not confirmed is `PolicyRefused` and the device is never asked); it
/// then computes the `ua_msg` from `scaas_purpose(td)` and the digest, asks the device, and signs through an `ExternalKey`
/// whose device returns that answer: the same `UASig` as the internal key's. The request the dry run would have sent is that
/// `ua_msg`.
#[test]
fn external_key_dry_run_then_answer() {
    let w = Wallet::from_mnemonic(WORDS, "").unwrap();
    let key = w.ua_key(0x0101, 0, 0).unwrap(); // p256: RFC 6979, one signature per message
    let name = "UAPayeeFee";
    let r = row(name, "token");
    let td = scaas_typed_data(
        name,
        Some("SCaaS MetaToken"),
        &r.contract,
        r.chain_id,
        &r.uid,
        &r.message,
    )
    .unwrap();
    let seen = std::sync::Mutex::new(None);
    let refuse = ExternalKey::new(key.key_ref(), |q: &SignRequest| {
        *seen.lock().unwrap() = Some(q.clone());
        Err(Error::ExternalSignature)
    });
    let mut other = r.message.clone();
    other["fee"] = "1".into();
    assert_eq!(
        sign_scaas(&refuse, &td, op(&r, name, &other)).unwrap_err(),
        Error::PolicyRefused
    );
    assert!(seen.lock().unwrap().is_none(), "refused before the device");
    assert_eq!(
        sign_scaas(&refuse, &td, op(&r, name, &r.message)).unwrap_err(),
        Error::ExternalSignature
    );
    let asked = seen.lock().unwrap().clone().unwrap();
    let ua_msg =
        scaas_ua::ua_message(0x0101, &scaas_purpose(&td).unwrap(), &td.digest().unwrap()).unwrap();
    assert!(matches!(&asked, SignRequest::UaMsg { ua_msg: m, .. } if *m == ua_msg));
    let answer = key.sign_request(&asked).unwrap();
    let device = ExternalKey::new(key.key_ref(), move |_: &SignRequest| Ok(answer.clone()));
    assert_eq!(
        sign_scaas(&device, &td, op(&r, name, &r.message)).unwrap(),
        sign_scaas(&key, &td, op(&r, name, &r.message)).unwrap()
    );
}

/// Owner ruling G6 (2026-11-19): a struct without the envelope (`UAWrapOrder`, its `fee` the DEX fee rate the order caps, no
/// fee mode) pays its relayer no envelope fee: `fee_due` is 0 at any `fee`, never `PolicyRefused` for the missing mode (the
/// SDK's prepare and quote call it on every struct with a lane). An enveloped struct without its mode is still refused.
#[test]
fn fee_due_of_a_struct_without_the_envelope_is_zero() {
    use scaas_ua::wallet::fee_due;
    let order = |fee: &str| {
        serde_json::json!({"from": format!("0x{}", "11".repeat(32)), "wrappedToken": format!("0x{}", "22".repeat(20)),
            "amount": "1000", "minMinted": "1", "minFill": "1000", "fee": fee, "relayer": format!("0x{}", "00".repeat(20)),
            "destination": format!("0x{}", "00".repeat(32)), "flags": 0, "batch": "1", "nonce": "1", "validUntil": "9999999999"})
    };
    for fee in ["0", "5", "10000"] {
        assert_eq!(
            fee_due("UAWrapOrder", &order(fee)).unwrap(),
            "0",
            "fee {fee}"
        );
    }
    let mut burn = row("UABurn", "token").message;
    burn.as_object_mut().unwrap().remove("mode");
    assert_eq!(
        fee_due("UABurn", &burn).unwrap_err(),
        Error::PolicyRefused,
        "an envelope without its mode"
    );
}

/// bls-multi Task 17 (spec 2026-11-19-bls12381-multi §5.4): a `bls12381-multi` member key signs its partial of a typed SCaaS
/// struct only under the struct's check, over `memberDigest(ua, uaMessage(0x0121, purpose, digest))`; the partials of the
/// group aggregate to a signature the verifier accepts. A refused check, `Expect::Any` and a key the group does not list sign
/// nothing. Each beside its control.
#[test]
fn bls_multi_member_signs_under_the_check() {
    use scaas_ua::bls_multi;
    use scaas_ua::wallet::{scaas_bls_multi_message, sign_scaas_bls_multi, AllowAnyTypedData};
    let r = row("UACancelNonce", "token");
    let td = scaas_typed_data(
        "UACancelNonce",
        Some("SCaaS MetaToken"),
        &r.contract,
        r.chain_id,
        &r.uid,
        &r.message,
    )
    .unwrap();
    let w = Wallet::from_mnemonic(WORDS, "").unwrap();
    let ks: Vec<_> = (0..3).map(|a| w.ua_key(0x0121, a, 0).unwrap()).collect(); // EIP-2333: index 0
    let pk = |i: usize| -> [u8; 256] { ks[i].key_data().try_into().unwrap() };
    let (d, map) = bls_multi::build_key_data_unweighted(&[pk(0), pk(1)], 2).unwrap();
    let ua_msg = scaas_bls_multi_message(&td).unwrap();
    assert_eq!(
        ua_msg,
        scaas_ua::ua_message(
            0x0121,
            &purpose_tag("metatx").unwrap(),
            &td.digest().unwrap()
        )
        .unwrap()
    );
    let parts: Vec<(u8, [u8; 128])> = (0..2)
        .map(|i| {
            let s =
                sign_scaas_bls_multi(&ks[i], &d, &td, op(&r, "UACancelNonce", &r.message)).unwrap();
            assert!(bls_multi::part_ok(&d, &pk(i), &ua_msg, false, &s));
            (map[i] as u8, s.try_into().unwrap())
        })
        .collect();
    let agg = bls_multi::aggregate(&d, &ua_msg, &parts, false).unwrap();
    assert!(scaas_ua::verify::verify(
        0x0121,
        &d,
        &ua_msg,
        &agg.to_abi(),
        false,
        true
    ));
    // the check refuses another message: nothing signed
    let mut other = r.message.clone();
    other["nonce"] = Value::String("99".into());
    assert!(matches!(
        sign_scaas_bls_multi(&ks[0], &d, &td, op(&r, "UACancelNonce", &other)),
        Err(Error::PolicyRefused)
    ));
    assert!(matches!(
        sign_scaas_bls_multi(&ks[0], &d, &td, Expect::Any(AllowAnyTypedData)),
        Err(Error::Argument)
    ));
    // a key the group does not list
    assert!(matches!(
        sign_scaas_bls_multi(&ks[2], &d, &td, op(&r, "UACancelNonce", &r.message)),
        Err(Error::Argument)
    ));
    // sign_scaas itself does not sign for a member key (no single-key UASig of 0x0121)
    assert!(sign_scaas(&ks[0], &td, op(&r, "UACancelNonce", &r.message)).is_err());
}
