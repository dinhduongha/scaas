// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T15: the PQZ facade (spec §10.2, §8.2, §8.4; feature `pqz`). The PQZ key is the UA PQ rule with
//! `utf8("scaas.ua.pqz-mlwe.v1")` (CTR-PQZ-13); `seed32` lives in the wallet's arena, so `lock()` revokes the handle; command
//! JSON is read through the bounded reader (1 MiB, depth 8) and an allow-list of fields per command, so no key field reaches
//! pqz-core; every proof made here verifies through pqz-ffi's precompile, and two proofs of one statement differ (`rnd32` from
//! the OS RNG); a `proofSystemId` or deployed set of another build is `PqzSetMismatch`. Under feature `vectors` the vector
//! files of this build's set (`smartcontracts/vectors/pqz/<set>/`) are rebuilt through the facade at the generator's keys and
//! randomness: the same statements, memos and proofs, PQZL and PQZH, so pqz-core's transcripts are the facade's. UNAUDITED.
#![allow(non_snake_case)]
use pqz_ffi::stmt::{self as st, Disclose, Form, Stmt, Word, PQZH_ID, PQZL_ID};
use scaas_ua::facade::pqz::{check_set, pqz_set, AllowSecretExport, PqzCmd, PqzKey, PqzSet, COMMANDS};
use scaas_ua::wallet::{aead_open, hkdf_sha256, Alg, Error, Wallet};
use serde_json::{json, Value};

const WORDS: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}
fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn wallet() -> Wallet {
    Wallet::from_mnemonic(WORDS, "").unwrap()
}
fn call(k: &PqzKey, cmd: &str, v: &Value) -> Result<Value, Error> {
    k.call(cmd, v.to_string().as_bytes()).map(|s| {
        assert!(s.len() <= scaas_ua::facade::pqz::OUT_MAX, "{cmd}: {} B past OUT_MAX", s.len());
        serde_json::from_str(&s).unwrap()
    })
}
fn verify(op: u8, stmt: &[u8], proof: &[u8]) -> bool {
    pqz_ffi::precompile(&st::input(op, stmt, proof)) == Ok(pqz_ffi::VALID)
}
fn merge(mut a: Value, b: Value) -> Value {
    for (k, v) in b.as_object().unwrap() {
        a[k] = v.clone();
    }
    a
}
/// `f` is refused with `Argument` before pqz-core's prover runs (feature `vectors`: the prover-call counter; without it the
/// refusal alone).
#[cfg(feature = "vectors")]
fn refused_before_the_prover<T: std::fmt::Debug>(what: &str, f: impl FnOnce() -> Result<T, Error>) {
    #[cfg(feature = "vectors")]
    let before = scaas_ua::facade::pqz::vectors_prover_calls();
    assert_eq!(f().err(), Some(Error::Argument), "{what}");
    #[cfg(feature = "vectors")]
    assert_eq!(scaas_ua::facade::pqz::vectors_prover_calls(), before, "{what}: refused before the prover");
}
/// A debit header as a caller gives it (counter `ctr`, fee 7).
fn header(ctr: u64) -> Value {
    json!({"chainId": 7622, "token": hx(&[0x11; 20]), "registry": hx(&[0x22; 20]), "fromUA": hx(&[0xA1; 32]),
        "beneficiaryUA": hx(&[0xA3; 32]), "fee": 7, "sendCounter": ctr, "p": 5, "validUntilBlock": 1_000_000, "plainUsed": 0,
        "chainUid": hx(&[0xC1; 32]), "envelopeBinding": hx(&[0xE1; 32])})
}
/// `T` = Enc(`k`'s pk, `value`) through the facade's `enc`.
fn balance(k: &PqzKey, value: u64) -> Vec<u8> {
    let e = call(k, "enc", &json!({"pks": [hx(&k.pk())], "values": [value]})).unwrap();
    [h(&e["u"]), h(&e["vs"][0])].concat()
}
#[cfg(feature = "vectors")]
fn dec(k: &PqzKey, ct: &[u8], window: u64) -> Result<u64, Error> {
    call(k, "dec", &json!({"ct": hx(ct), "window": window})).map(|v| v["value"].as_u64().unwrap())
}
/// The §7.9 disclosure statement a token's `disclosureStatement` view gives.
fn disclosure(form: Form, id: &Word, kind: u64, amount: u64, pk: &[u8], u: &[u8], v: &[u8]) -> Vec<u8> {
    let mut w = Disclose::words(form, id);
    w[2] = st::u64_word(7622);
    w[3] = [0xC1; 32];
    w[4] = { let mut a = [0u8; 32]; a[12..].copy_from_slice(&[0x11; 20]); a };
    w[5] = { let mut a = [0u8; 32]; a[12..].copy_from_slice(&[0x22; 20]); a };
    w[6] = [0xEE; 32];
    w[7] = st::u64_word(amount);
    w[8] = st::u64_word(kind);
    Stmt::Disclose(Disclose { form, words: w, pk, u, v }).encode().unwrap()
}
/// Another set's PQZL id (a live one, not this build's).
fn foreign_id() -> Word {
    let other = if st::SET == "n2048-kmax1024" { "ef1ffbcbd05394f8276e50a6c254022edf53bbd08a56e22aadddac2b9b90336e" } else {
        "c752e7f57778114dbfaac5d43843577b54e13e3ed162517145a37b5a3ec6cdfe"
    };
    hex::decode(other).unwrap().try_into().unwrap()
}

/// CTR-PQZ-13 / spec §10.2: `seed32 = HKDF-SHA256(seed, "scaas.ua.pq.v1", utf8("scaas.ua.pqz-mlwe.v1") ‖ be32(account) ‖
/// be32(index))`, recomputed here with the tag spelled out; `pk = pqzl::keygen(seed32).pk`.
#[test]
fn pqz_key_is_the_ua_pq_rule() {
    let w = wallet();
    let seed = bip39::Mnemonic::parse(WORDS).unwrap().to_seed("");
    for (a, i) in [(0u32, 0u32), (0, 1), (1, 0), (7, 3)] {
        let mut want = [0u8; 32];
        let info = [&b"scaas.ua.pqz-mlwe.v1"[..], &a.to_be_bytes(), &i.to_be_bytes()].concat();
        hkdf::Hkdf::<sha2::Sha256>::new(Some(b"scaas.ua.pq.v1"), &seed).expand(&info, &mut want).unwrap();
        let leaf = w.export_pqz_leaf_raw(a, i, AllowSecretExport).unwrap();
        assert_eq!(*leaf, want, "leaf {a}/{i}");
        let k = w.pqz_key(a, i).unwrap();
        assert_eq!(k.pk(), pqz_ffi::pqzl::keygen(&want).unwrap().pk.to_vec(), "pk {a}/{i}");
        assert_eq!((k.account(), k.index(), k.pk().len()), (a, i, pqz_set().pk_len));
    }
    for (a, i) in [(1u32 << 31, 0u32), (0, 1 << 31)] {
        assert_eq!(w.pqz_key(a, i).err(), Some(Error::Argument), "{a}/{i}");
        assert_eq!(w.export_pqz_leaf_raw(a, i, AllowSecretExport).err(), Some(Error::Argument));
    }
}

/// `rnd32` comes from the OS RNG: the same statement and witness proved twice give two different proofs, each valid.
#[test]
fn two_proofs_differ() {
    let w = wallet();
    let k = w.pqz_key(0, 0).unwrap();
    let ua = scaas_ua::derive_ua(0x0131, &w.ua_key(0x0131, 0, 0).unwrap().key_data(), false).unwrap();
    let req = json!({"proofSystemId": hx(&PQZL_ID), "kind": 0x0131, "ua": hx(&ua)});
    let a = call(&k, "proveRegister", &req).unwrap();
    let b = call(&k, "proveRegister", &req).unwrap();
    assert_eq!(a["stmt"], b["stmt"]);
    assert_eq!(a["message"], hx(&scaas_ua::pqz_reg_message(0x0131, &ua, &k.pk(), None).unwrap()));
    assert_ne!(a["proof"], b["proof"], "rnd32 is not fixed");
    for p in [&a, &b] {
        assert!(verify(3, &h(&p["stmt"]), &h(&p["proof"])));
    }
}

/// One set per build: another set's `proofSystemId` on any proving command, another deployed set, or a statement of
/// another id is `PqzSetMismatch`; this build's ids and set pass (positive controls).
#[test]
fn set_mismatch_refused() {
    let s = pqz_set();
    assert_eq!((s.name.as_str(), s.pk_len, s.pqzl_id), (st::SET, st::PK_BYTES, PQZL_ID));
    assert_eq!(s.pqzh_id, pqz_ffi::PQZH.then_some(PQZH_ID));
    assert_eq!(check_set(&s), Ok(()));
    assert_eq!(PqzSet::from_json(s.to_json().as_bytes()).unwrap(), s);
    for other in [
        PqzSet { name: "n2560-kmax16384".into(), ..s.clone() },
        PqzSet { pk_len: s.pk_len + 2048, ..s.clone() },
        PqzSet { pqzl_id: foreign_id(), ..s.clone() },
        PqzSet { pqzh_id: Some(foreign_id()), ..s.clone() },
    ] {
        assert_eq!(check_set(&other), Err(Error::PqzSetMismatch), "{other:?}");
        assert_eq!(check_set(&PqzSet::from_json(other.to_json().as_bytes()).unwrap()), Err(Error::PqzSetMismatch));
    }
    let w = wallet();
    let k = w.pqz_key(0, 0).unwrap();
    #[cfg_attr(not(feature = "vectors"), allow(unused_mut))]
    let mut cmds = vec![("proveRegister", json!({"kind": 0x0131, "ua": hx(&[1; 32])})), ("proveKeyRecord", json!({"ua": hx(&[1; 32])}))];
    #[cfg(feature = "vectors")]
    let t = balance(&k, 1000);
    #[cfg(feature = "vectors")]
    cmds.extend([
        ("proveBurn", merge(header(1), json!({"amount": 1, "recipient": hx(&[3; 32]), "T": hx(&t), "memoHash": hx(&[0; 32])}))),
        ("proveRefresh", merge(header(1), json!({"T": hx(&t), "memoHash": hx(&[0; 32])}))),
        ("proveTransfer", merge(header(1), json!({"toUA": hx(&[2; 32]), "pkT": hx(&k.pk()), "T": hx(&t), "amount": 1, "memoHash": hx(&[0; 32])}))),
        ("proveTransferMulti", merge(header(1), json!({"legs": [{"pk": hx(&k.pk()), "ua": hx(&[2; 32]), "amount": 1}], "T": hx(&t), "mode": "HASH"}))),
    ]);
    for (cmd, base) in &cmds {
        let ok = merge(base.clone(), json!({"proofSystemId": hx(&PQZL_ID)}));
        assert!(PqzCmd::from_json(cmd, ok.to_string().as_bytes()).is_ok(), "{cmd}: positive control");
        let bad = merge(base.clone(), json!({"proofSystemId": hx(&foreign_id())}));
        assert_eq!(PqzCmd::from_json(cmd, bad.to_string().as_bytes()).err(), Some(Error::PqzSetMismatch), "{cmd}");
        assert_eq!(call(&k, cmd, &bad).err(), Some(Error::PqzSetMismatch), "{cmd}: call");
    }
    // a disclosure statement of another id
    let (u, v) = (vec![0u8; st::PK_BYTES], vec![0u8; 128]);
    for (form, cmd, extra) in [
        #[cfg(feature = "vectors")]
        (Form::DiscloseReceiver, "proveDisclose", json!({})),
        (Form::DiscloseSender, "proveDiscloseSender", json!({"fromUA": hx(&[0xA1; 32]), "sendCounter": 1, "salt": hx(&[5; 16]), "auditorOn": false})),
    ] {
        let mut stmt = disclosure(form, &PQZL_ID, 0, 1, &k.pk(), &u, &v);
        stmt[32..64].copy_from_slice(&foreign_id());
        assert_eq!(call(&k, cmd, &merge(json!({"stmt": hx(&stmt)}), extra)).err(), Some(Error::PqzSetMismatch), "{cmd}");
    }
}

/// Spec §8.2: `seed32` is in the wallet's arena; after `lock()` (and after the wallet is dropped) every secret operation of
/// the handle is `KeyRevoked`, the public key stays readable, a new key or export is `WalletLocked`.
#[test]
fn pqz_handle_KeyRevoked_after_lock() {
    let w = wallet();
    let k = w.pqz_key(0, 0).unwrap();
    let reg = json!({"proofSystemId": hx(&PQZL_ID), "kind": 0x0131, "ua": hx(&[1; 32])});
    assert!(call(&k, "proveRegister", &reg).is_ok(), "positive control");
    #[cfg(feature = "vectors")]
    let t = balance(&k, 1000);
    #[cfg(feature = "vectors")]
    assert_eq!(dec(&k, &t, 0), Ok(1000), "positive control");
    let cache = k.seal_balance_cache(b"{}").unwrap();
    w.lock();
    assert_eq!(call(&k, "proveRegister", &reg).err(), Some(Error::KeyRevoked));
    #[cfg(feature = "vectors")]
    {
        assert_eq!(dec(&k, &t, 0).err(), Some(Error::KeyRevoked));
        let memo = json!({"chainUid": hx(&[1; 32]), "token": hx(&[2; 20]), "fromUA": hx(&[3; 32]), "sendCounter": 1, "memo": hx(&[0; 58])});
        assert_eq!(call(&k, "openMemo", &memo).err(), Some(Error::KeyRevoked));
    }
    assert_eq!(k.seal_balance_cache(b"{}").err(), Some(Error::KeyRevoked));
    assert_eq!(k.open_balance_cache(cache.as_bytes()).err(), Some(Error::KeyRevoked));
    assert_eq!(w.pqz_key(0, 0).err(), Some(Error::WalletLocked));
    assert_eq!(w.export_pqz_leaf_raw(0, 0, AllowSecretExport).err(), Some(Error::WalletLocked));
    assert_eq!(k.pk().len(), st::PK_BYTES, "the public key stays readable");
    // `enc` is public: no key needed
    assert!(call(&k, "enc", &json!({"pks": [hx(&k.pk())], "values": [1]})).is_ok());
    let w2 = wallet();
    let k2 = w2.pqz_key(0, 1).unwrap();
    drop(w2);
    assert_eq!(call(&k2, "proveRegister", &reg).err(), Some(Error::KeyRevoked));
}

#[cfg(feature = "vectors")]
#[test]
fn unlock_does_not_revive_a_pqz_handle() {
    let w = wallet();
    let k = w.pqz_key(0, 0).unwrap();
    let t = balance(&k, 5);
    w.lock();
    w.vectors_unlock(WORDS, "").unwrap();
    assert_eq!(dec(&k, &t, 0).err(), Some(Error::KeyRevoked));
    assert_eq!(dec(&w.pqz_key(0, 0).unwrap(), &t, 0), Ok(5), "a new handle works");
}

/// Every command of the vectors build (the release one's and the raw ones): a minimal well-formed request for `k`.
fn base_request(k: &PqzKey, cmd: &str) -> Value {
    let (pk, t) = (hx(&k.pk()), hx(&balance(k, 1000)));
    let id = hx(&PQZL_ID);
    let stmt = hx(&disclosure(Form::DiscloseReceiver, &PQZL_ID, 1, 1, &k.pk(), &vec![0u8; st::PK_BYTES], &[0u8; 128]));
    let sstmt = hx(&disclosure(Form::DiscloseSender, &PQZL_ID, 0, 1, &k.pk(), &vec![0u8; st::PK_BYTES], &[0u8; 128]));
    let leg = json!({"pk": pk, "ua": hx(&[2; 32]), "amount": 1});
    match cmd {
        "enc" => json!({"pks": [pk], "values": [1]}),
        "dec" => json!({"ct": t}),
        "proveRegister" => json!({"proofSystemId": id, "kind": 0x0131, "ua": hx(&[1; 32])}),
        "proveKeyRecord" => json!({"proofSystemId": id, "ua": hx(&[1; 32])}),
        "proveTransfer" => merge(header(1), json!({"proofSystemId": id, "toUA": hx(&[2; 32]), "pkT": pk, "T": t, "amount": 1, "memoHash": hx(&[0; 32])})),
        "proveBurn" => merge(header(1), json!({"proofSystemId": id, "amount": 1, "recipient": hx(&[3; 32]), "T": t, "memoHash": hx(&[0; 32])})),
        "proveRefresh" => merge(header(1), json!({"proofSystemId": id, "T": t, "memoHash": hx(&[0; 32])})),
        "proveTransferMulti" => merge(header(1), json!({"proofSystemId": id, "legs": [leg], "T": t, "mode": "BUNDLE"})),
        "proveDiscloseSender" => json!({"stmt": sstmt, "fromUA": hx(&[1; 32]), "sendCounter": 1, "salt": hx(&[5; 16]), "auditorOn": true}),
        "proveDisclose" => json!({"stmt": stmt}),
        "openMemo" => json!({"chainUid": hx(&[1; 32]), "token": hx(&[2; 20]), "fromUA": hx(&[3; 32]), "sendCounter": 1, "memo": hx(&[0; 58])}),
        _ => panic!("{cmd}: no base request"),
    }
}

/// The raw commands ARCH-POS-13 keeps out of a release build (T15c): each decrypts or opens a ciphertext, statement or `T`
/// its caller chose.
const RAW: [&str; 7] = ["dec", "proveTransfer", "proveBurn", "proveRefresh", "proveTransferMulti", "proveDisclose", "openMemo"];

/// ARCH-POS-13 (T15c, F1 / F2 / F3 / F8): a release build lists none of the raw commands and refuses each, with a well-formed
/// request, as `Argument` (an unknown command, before the key); under `vectors` they are there (the vector files' hooks).
#[test]
fn release_has_no_raw_decrypt() {
    let release = ["enc", "proveRegister", "proveKeyRecord", "proveDiscloseSender"];
    let want: Vec<&str> = if cfg!(feature = "vectors") {
        ["enc", "dec", "proveRegister", "proveKeyRecord", "proveTransfer", "proveBurn", "proveRefresh", "proveTransferMulti",
            "proveDiscloseSender", "proveDisclose", "openMemo"].to_vec()
    } else {
        release.to_vec()
    };
    assert_eq!(COMMANDS, &want[..]);
    let w = wallet();
    let k = w.pqz_key(0, 0).unwrap();
    for cmd in RAW {
        let req = base_request(&k, cmd);
        let got = (PqzCmd::from_json(cmd, req.to_string().as_bytes()).err(), call(&k, cmd, &req).err());
        if cfg!(feature = "vectors") {
            assert_eq!(got.0, None, "{cmd}: a vectors build has it");
        } else {
            assert_eq!(got, (Some(Error::Argument), Some(Error::Argument)), "{cmd}: refused in a release build");
        }
    }
    for cmd in release {
        assert!(PqzCmd::from_json(cmd, base_request(&k, cmd).to_string().as_bytes()).is_ok(), "{cmd}: positive control");
    }
}

/// Every command, positive control first: a minimal well-formed request passes the decoder; with a `key` (or `seed32`, `s`,
/// `e`, `wit`) field at the top, or a `key` inside a leg, it is refused before anything reaches pqz-core.
#[test]
fn a_key_field_in_command_json_is_refused() {
    let w = wallet();
    let k = w.pqz_key(0, 0).unwrap();
    let (pk, t, id) = (hx(&k.pk()), hx(&balance(&k, 1000)), hx(&PQZL_ID));
    let leg = json!({"pk": pk, "ua": hx(&[2; 32]), "amount": 1});
    let secret = json!({"seed32": hx(&[0x11; 32]), "account": 0});
    for cmd in COMMANDS {
        let base = base_request(&k, cmd);
        assert!(PqzCmd::from_json(cmd, base.to_string().as_bytes()).is_ok(), "{cmd}: positive control");
        for field in ["key", "seed32", "s", "e", "wit", "witness"] {
            let mut top = base.clone();
            top[field] = secret.clone();
            assert_eq!(PqzCmd::from_json(cmd, top.to_string().as_bytes()).err(), Some(Error::Argument), "{cmd}: top-level {field}");
            assert_eq!(call(&k, cmd, &top).err(), Some(Error::Argument), "{cmd}: call with {field}");
        }
    }
    let mut nested = merge(header(1), json!({"proofSystemId": id, "legs": [leg.clone()], "T": t, "mode": "HASH"}));
    nested["legs"][0]["key"] = secret.clone();
    assert_eq!(PqzCmd::from_json("proveTransferMulti", nested.to_string().as_bytes()).err(), Some(Error::Argument), "key inside a leg");
    #[cfg(feature = "vectors")]
    {
        nested["legs"][0].as_object_mut().unwrap().remove("key");
        assert!(PqzCmd::from_json("proveTransferMulti", nested.to_string().as_bytes()).is_ok(), "positive control: without the key");
    }
    // a field of one command on another, an unknown command
    let reg = json!({"proofSystemId": id, "kind": 0x0131, "ua": hx(&[1; 32]), "T": t});
    assert_eq!(PqzCmd::from_json("proveRegister", reg.to_string().as_bytes()).err(), Some(Error::Argument), "T on proveRegister");
    assert_eq!(PqzCmd::from_json("prove", b"{}").err(), Some(Error::Argument));
}

/// Spec §9.3: 1 MiB and depth 8; only `u64` numbers; keys and ciphertexts of this set's length and canonical.
#[test]
fn command_json_is_bounded_and_typed() {
    let w = wallet();
    let k = w.pqz_key(0, 0).unwrap();
    let pk = hx(&k.pk());
    let mut ok = json!({"pks": [pk], "values": [1]}).to_string().into_bytes();
    assert!(PqzCmd::from_json("enc", &ok).is_ok());
    ok.resize(1 << 20, b' ');
    assert!(PqzCmd::from_json("enc", &ok).is_ok(), "at 1 MiB");
    ok.push(b' ');
    assert_eq!(PqzCmd::from_json("enc", &ok).err(), Some(Error::Argument), "1 MiB + 1");
    let deep = format!("{{\"pks\": [{pk:?}], \"values\": [1], \"x\": {}1{}}}", "[".repeat(7), "]".repeat(7));
    assert_eq!(PqzCmd::from_json("enc", deep.as_bytes()).err(), Some(Error::Argument), "depth 8 parses, x not allowed");
    let deeper = format!("{{\"values\": {}1{}}}", "[".repeat(8), "]".repeat(8));
    assert_eq!(PqzCmd::from_json("enc", deeper.as_bytes()).err(), Some(Error::Argument), "depth 9");
    for bad in [json!(1.5), json!(-1), json!("1"), json!(1e20)] {
        assert_eq!(PqzCmd::from_json("enc", json!({"pks": [pk], "values": [bad]}).to_string().as_bytes()).err(), Some(Error::Argument));
    }
    let short = hx(&k.pk()[1..]);
    assert_eq!(PqzCmd::from_json("enc", json!({"pks": [short], "values": [1]}).to_string().as_bytes()).err(), Some(Error::Argument));
    let mut big = k.pk();
    big[..8].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(PqzCmd::from_json("enc", json!({"pks": [hx(&big)], "values": [1]}).to_string().as_bytes()).err(), Some(Error::Argument), "coefficient ≥ q");
    #[cfg(feature = "vectors")]
    assert_eq!(PqzCmd::from_json("dec", json!({"ct": hx(&balance(&k, 1)), "window": 4}).to_string().as_bytes()).err(), Some(Error::Argument));
}

/// Op 1 end to end: Alice pays Bob 300 with fee 7 from a balance of 1,000, the auditor Carol copied; the proof verifies,
/// Bob, Alice and Carol each decrypt their part; the encryption seed is CTR-PQZ-19's (recomputed here from the exported leaf
/// and the statement's salt); `SENDER_S`, `RECEIVER_X` and `AUDITOR` disclosures verify; an overdraft is refused.
#[cfg(feature = "vectors")]
#[test]
fn transfer_and_disclosures_verify() {
    let w = wallet();
    let (a, b, c) = (w.pqz_key(0, 0).unwrap(), w.pqz_key(1, 0).unwrap(), w.pqz_key(2, 0).unwrap());
    let t = balance(&a, 1000);
    let req = merge(header(3), json!({"proofSystemId": hx(&PQZL_ID), "toUA": hx(&[0xB0; 32]), "pkT": hx(&b.pk()), "pkA": hx(&c.pk()),
        "T": hx(&t), "amount": 300, "memoHash": hx(&[0xD1; 32])}));
    let p = call(&a, "proveTransfer", &req).unwrap();
    let (stmt, proof) = (h(&p["stmt"]), h(&p["proof"]));
    assert!(verify(1, &stmt, &proof));
    let Stmt::Debit(d) = st::parse(1, &stmt).unwrap() else { panic!() };
    assert_eq!((d.form, d.t, d.fee(), d.header[st::H_MEMO_HASH]), (Form::Transfer, &t[..], 7, [0xD1; 32]));
    let ct = |v: &[u8]| [d.u, v].concat();
    assert_eq!(dec(&b, &ct(d.v_t.unwrap()), 0), Ok(300));
    assert_eq!(dec(&a, &ct(d.v_f), 0), Ok(693));
    assert_eq!(dec(&c, &ct(d.v_a.unwrap()), 0), Ok(300));
    // CTR-PQZ-19
    let salt: [u8; 16] = d.header[st::H_SALT][16..].try_into().unwrap();
    let leaf = w.export_pqz_leaf_raw(0, 0, AllowSecretExport).unwrap();
    let info = [&[0xC1; 32][..], &[0x11; 20], &[0xA1; 32], &3u32.to_be_bytes(), &salt].concat();
    let mut seed = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(b"SCAAS-PQZ-ENC-V2"), &*leaf).expand(&info, &mut seed).unwrap();
    let dg = pqz_ffi::selftest::digits;
    let (bp, ap, cp) = (b.pk(), a.pk(), c.pk());
    let e = pqz_ffi::pqzl::enc(&[(&bp[..]).try_into().unwrap(), (&ap[..]).try_into().unwrap(), (&cp[..]).try_into().unwrap()],
        &[dg(300), dg(693), dg(300)], &seed).unwrap();
    assert_eq!((&e.u[..], &e.vs[0][..], &e.vs[1][..]), (d.u, d.v_t.unwrap(), d.v_f), "seed_enc = HKDF(seed32, SCAAS-PQZ-ENC-V2, …)");
    // a second build at the same counter draws a fresh salt: another u
    let p2 = call(&a, "proveTransfer", &req).unwrap();
    assert_ne!(h(&p2["stmt"]), stmt);
    // disclosures
    let ss = disclosure(Form::DiscloseSender, &PQZL_ID, 0, 300, &b.pk(), d.u, d.v_t.unwrap());
    let origin = json!({"stmt": hx(&ss), "fromUA": hx(&[0xA1; 32]), "sendCounter": 3, "salt": hx(&salt), "auditorOn": true});
    let s = call(&a, "proveDiscloseSender", &origin).unwrap();
    assert!(verify(4, &ss, &h(&s["proof"])));
    let wrong = merge(origin.clone(), json!({"sendCounter": 4}));
    refused_before_the_prover("another counter: another seed", || call(&a, "proveDiscloseSender", &wrong));
    let rx = disclosure(Form::DiscloseReceiver, &PQZL_ID, 1, 300, &b.pk(), d.u, d.v_t.unwrap());
    assert!(verify(5, &rx, &h(&call(&b, "proveDisclose", &json!({"stmt": hx(&rx)})).unwrap()["proof"])));
    refused_before_the_prover("not Alice's key", || call(&a, "proveDisclose", &json!({"stmt": hx(&rx)})));
    let au = disclosure(Form::DiscloseAuditor, &PQZL_ID, 2, 300, &c.pk(), d.u, d.v_a.unwrap());
    assert!(verify(5, &au, &h(&call(&c, "proveDisclose", &json!({"stmt": hx(&au)})).unwrap()["proof"])));
    // overdraft: 994 + 7 > 1,000
    let over = merge(req, json!({"amount": 994}));
    refused_before_the_prover("overdraft", || call(&a, "proveTransfer", &over));
}

/// Op 2: burn and refresh verify; the new balance decrypts.
#[cfg(feature = "vectors")]
#[test]
fn burn_and_refresh_verify() {
    let w = wallet();
    let k = w.pqz_key(0, 0).unwrap();
    let t = balance(&k, 1000);
    let burn = merge(header(4), json!({"proofSystemId": hx(&PQZL_ID), "amount": 100, "recipient": hx(&[3; 32]), "T": hx(&t), "memoHash": hx(&[0xD1; 32])}));
    let p = call(&k, "proveBurn", &burn).unwrap();
    let stmt = h(&p["stmt"]);
    assert!(verify(2, &stmt, &h(&p["proof"])));
    let Stmt::Debit(d) = st::parse(2, &stmt).unwrap() else { panic!() };
    assert_eq!((d.form, d.amount(), d.header[st::H_RECIPIENT]), (Form::Burn, 100, [3; 32]));
    assert_eq!(dec(&k, &[d.u, d.v_f].concat(), 0), Ok(893));
    // CTR-PQZ-19: a burn's randomness is fresh on every build (never fixed by the counter)
    let again = h(&call(&k, "proveBurn", &burn).unwrap()["stmt"]);
    let Stmt::Debit(d2) = st::parse(2, &again).unwrap() else { panic!() };
    assert_ne!(d2.u, d.u, "a second burn of the same balance at the same counter: another u");
    let refresh = merge(header(5), json!({"proofSystemId": hx(&PQZL_ID), "T": hx(&t), "memoHash": hx(&[0xD1; 32])}));
    let p = call(&k, "proveRefresh", &refresh).unwrap();
    let stmt = h(&p["stmt"]);
    assert!(verify(2, &stmt, &h(&p["proof"])));
    let Stmt::Debit(d) = st::parse(2, &stmt).unwrap() else { panic!() };
    assert_eq!(d.form, Form::Refresh);
    assert_eq!(dec(&k, &[d.u, d.v_f].concat(), 0), Ok(993));
}

/// Op 7 with the auditor: two legs (Bob 250, a decoy 0); the proof verifies; the memo opens under the sender's key to the
/// legs; the auditor decrypts each copy at its window; the sender discloses leg 0 (`SENDER_S`, re-derived).
#[cfg(feature = "vectors")]
#[test]
fn transfer_multi_memo_and_sender_disclosure() {
    let w = wallet();
    let (a, b, c, z) = (w.pqz_key(0, 0).unwrap(), w.pqz_key(1, 0).unwrap(), w.pqz_key(2, 0).unwrap(), w.pqz_key(3, 0).unwrap());
    let t = balance(&a, 1000);
    let legs = json!([{"pk": hx(&b.pk()), "ua": hx(&[0xB0; 32]), "amount": 250}, {"pk": hx(&z.pk()), "ua": hx(&[0xB1; 32]), "amount": 0}]);
    let req = merge(header(9), json!({"proofSystemId": hx(&PQZL_ID), "legs": legs, "pkA": hx(&c.pk()), "T": hx(&t), "mode": "HASH"}));
    let p = call(&a, "proveTransferMulti", &req).unwrap();
    let (stmt, memo) = (h(&p["stmt"]), h(&p["memo"]));
    assert!(verify(7, &stmt, &h(&p["proof"])));
    let Stmt::Multi(m) = st::parse(7, &stmt).unwrap() else { panic!() };
    assert_eq!(m.header[st::H_MEMO_HASH], scaas_ua::keccak256(&memo));
    assert_eq!(m.header[st::H_RECIPIENTS_HASH], scaas_ua::keccak256(&[[0xB0; 32], [0xB1; 32]].concat()));
    assert_eq!(dec(&b, &[m.u(0), m.v(0)].concat(), 0), Ok(250));
    assert_eq!(dec(&a, &[m.u(0), m.v_f].concat(), 0), Ok(743));
    for j in 0..2 {
        assert_eq!(dec(&c, &[m.u(0), m.v_a(j).unwrap()].concat(), j as u64), Ok([250, 0][j]), "auditor copy {j}");
    }
    let salt: [u8; 16] = m.header[st::H_SALT][16..].try_into().unwrap();
    let mref = json!({"chainUid": hx(&[0xC1; 32]), "token": hx(&[0x11; 20]), "fromUA": hx(&[0xA1; 32]), "sendCounter": 9, "memo": hx(&memo)});
    let o = call(&a, "openMemo", &mref).unwrap();
    assert_eq!(o, json!({"auditorOn": true, "legs": [{"amount": 250, "ua": hx(&[0xB0; 32])}, {"amount": 0, "ua": hx(&[0xB1; 32])}]}));
    assert_eq!(call(&b, "openMemo", &mref).err(), Some(Error::Argument), "another key's memo");
    let ss = disclosure(Form::DiscloseSender, &PQZL_ID, 0, 250, &b.pk(), m.u(0), m.v(0));
    let origin = json!({"stmt": hx(&ss), "fromUA": hx(&[0xA1; 32]), "sendCounter": 9, "salt": hx(&salt), "auditorOn": true, "M": 2, "leg": 0});
    assert!(verify(4, &ss, &h(&call(&a, "proveDiscloseSender", &origin).unwrap()["proof"])));
    refused_before_the_prover("leg 1 is not Bob's", || call(&a, "proveDiscloseSender", &merge(origin, json!({"leg": 1}))));
    // M not built (3), and a leg past M
    let three = merge(req, json!({"legs": [legs[0], legs[1], legs[1]]}));
    assert_eq!(call(&a, "proveTransferMulti", &three).err(), Some(Error::Argument));
}

/// T15b (F10, owner 2026-11-06): an op 7 request for `M` legs of `mode`, from a balance of 1,000.
#[cfg(feature = "vectors")]
fn multi_req(a: &PqzKey, b: &PqzKey, mode: &str) -> Value {
    let legs = json!([{"pk": hx(&b.pk()), "ua": hx(&[0xB0; 32]), "amount": 250}]);
    merge(header(9), json!({"proofSystemId": hx(&PQZL_ID), "legs": legs, "T": hx(&balance(a, 1000)), "mode": mode}))
}

/// `PqzCore._parseMulti` on BUNDLE: no memo (`sealedMemo` empty) and `memoHash` 0. The facade's statement has word
/// `H_MEMO_HASH` 0, the answer no `memo`, and the proof verifies.
#[cfg(feature = "vectors")]
#[test]
fn multi_bundle_memo_hash_is_zero() {
    let w = wallet();
    let (a, b) = (w.pqz_key(0, 0).unwrap(), w.pqz_key(1, 0).unwrap());
    let p = call(&a, "proveTransferMulti", &multi_req(&a, &b, "BUNDLE")).unwrap();
    let stmt = h(&p["stmt"]);
    assert!(verify(7, &stmt, &h(&p["proof"])));
    let Stmt::Multi(m) = st::parse(7, &stmt).unwrap() else { panic!() };
    assert_eq!(m.header[st::H_MEMO_HASH], [0; 32], "BUNDLE: memoHash 0");
    assert_eq!(p.get("memo"), None, "BUNDLE: no memo");
}

/// `PqzCore._parseMulti` on HASH: `memoHash = keccak256(abi.encodePacked(t.salt, t.sealedMemo))`, `salt` the header's
/// low 16 bytes and `sealedMemo` `2 + 40·M` bytes. The facade's `memo` is `salt ‖ sealedMemo`.
#[cfg(feature = "vectors")]
#[test]
fn multi_hash_memo_hash_matches_contract() {
    let w = wallet();
    let (a, b) = (w.pqz_key(0, 0).unwrap(), w.pqz_key(1, 0).unwrap());
    let p = call(&a, "proveTransferMulti", &multi_req(&a, &b, "HASH")).unwrap();
    let (stmt, memo) = (h(&p["stmt"]), h(&p["memo"]));
    assert!(verify(7, &stmt, &h(&p["proof"])));
    let Stmt::Multi(m) = st::parse(7, &stmt).unwrap() else { panic!() };
    let salt = &m.header[st::H_SALT][16..];
    let sealed = &memo[16..];
    assert_eq!((&memo[..16], sealed.len()), (salt, 2 + 40), "memo = salt ‖ sealedMemo");
    assert_eq!(m.header[st::H_MEMO_HASH], scaas_ua::keccak256(&[salt, sealed].concat()), "keccak256(salt ‖ sealedMemo)");
}

/// No default mode: a request without `mode`, or with any other value, is refused before the key is used.
#[cfg(feature = "vectors")]
#[test]
fn multi_without_mode_refused() {
    let w = wallet();
    let (a, b) = (w.pqz_key(0, 0).unwrap(), w.pqz_key(1, 0).unwrap());
    let req = multi_req(&a, &b, "HASH");
    assert!(PqzCmd::from_json("proveTransferMulti", req.to_string().as_bytes()).is_ok(), "positive control");
    let mut none = req.clone();
    none.as_object_mut().unwrap().remove("mode");
    refused_before_the_prover("no mode", || call(&a, "proveTransferMulti", &none));
    for bad in [json!("hash"), json!("NONE"), json!("COMPACT"), json!(0), json!(1), json!(null), json!(["HASH"])] {
        let r = merge(req.clone(), json!({"mode": bad}));
        refused_before_the_prover(&format!("mode {bad}"), || call(&a, "proveTransferMulti", &r));
    }
}

/// The `setPqzKey` `R_REG` (`ua_message(0x0142, PURPOSE_PQZ_KEY, pqzKeyDigest(ua, pqzKeyHash))`, ua8's `pqz_reg_message`
/// field) verifies.
#[test]
fn key_record_register_verifies() {
    let w = wallet();
    let k = w.pqz_key(0, 0).unwrap();
    let ua = [0x42; 32];
    let p = call(&k, "proveKeyRecord", &json!({"proofSystemId": hx(&PQZL_ID), "ua": hx(&ua)})).unwrap();
    let rec = scaas_ua::ua8::pqz_key_record_message(0x0131, &ua, &w.ua_key(0x0131, 0, 0).unwrap().key_data(), &k.pk(), None, Some(&[9; 32]), false).unwrap();
    assert_eq!(p["message"], hx(&rec.pqz_reg_message));
    assert!(verify(3, &h(&p["stmt"]), &h(&p["proof"])));
}

/// The cache box: AES-256-GCM under `HKDF-SHA256(seed32, no salt, "scaas-pqz-balance-cache-v1", 32)`, AAD `pqz-cache:<set>`,
/// recomputed here from the exported leaf; another key's box does not open.
#[test]
fn cache_box_key_and_label() {
    let w = wallet();
    let k = w.pqz_key(0, 0).unwrap();
    let entries = br#"{"T":"0x01","value":1000}"#;
    let b = k.seal_balance_cache(entries).unwrap();
    assert_eq!(&k.open_balance_cache(b.as_bytes()).unwrap()[..], entries);
    let v: Value = serde_json::from_str(&b).unwrap();
    let un = |s: &Value| base64ct::Base64UrlUnpadded::decode_vec(s.as_str().unwrap()).unwrap();
    use base64ct::Encoding;
    let leaf = w.export_pqz_leaf_raw(0, 0, AllowSecretExport).unwrap();
    let key = hkdf_sha256(&*leaf, &[], b"scaas-pqz-balance-cache-v1", 32).unwrap();
    let aad = format!("pqz-cache:{}", st::SET);
    let iv: [u8; 12] = un(&v["iv"]).try_into().unwrap();
    assert_eq!(&aead_open(Alg::Aes256Gcm, &key[..].try_into().unwrap(), &iv, aad.as_bytes(), &un(&v["ct"])).unwrap()[..], entries);
    assert_eq!(w.pqz_key(0, 1).unwrap().open_balance_cache(b.as_bytes()).err(), Some(Error::Aead));
    assert_eq!(k.open_balance_cache(br#"{"iv":"AA"}"#).err(), Some(Error::Argument));
}

// ---------------------------------------------------------------------------------------------------------------------------
// The vector files of this build's set, through the facade (feature `vectors`: the generator's keys and randomness).
// ---------------------------------------------------------------------------------------------------------------------------

#[cfg(feature = "vectors")]
mod vectors {
    use super::*;
    use scaas_ua::facade::pqz::Draw;

    fn pv(name: &str) -> Value {
        let dir = if st::SET == "n2048-kmax1024" { String::new() } else { format!("{}/", st::SET) };
        let p = format!("{}/../../smartcontracts/vectors/pqz/{dir}{name}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|_| panic!("{p}"))).unwrap()
    }
    fn s32(v: &Value) -> [u8; 32] {
        h(v).try_into().unwrap()
    }
    fn key(v: &Value) -> PqzKey {
        PqzKey::vectors_from_seed32(&s32(&v["keygen"])).unwrap()
    }
    fn pk_of(v: &Value) -> Vec<u8> {
        pqz_ffi::pqzl::keygen(&s32(&v["keygen"])).unwrap().pk.to_vec()
    }
    /// 20-byte values as words (the generator left-pads every field).
    fn word(v: &Value) -> String {
        let b = h(v);
        hx(&[vec![0u8; 32 - b.len()], b].concat())
    }
    fn with_id(stmt: &[u8], id: &Word) -> Vec<u8> {
        let mut s = stmt.to_vec();
        s[32..64].copy_from_slice(id);
        s
    }
    /// A vector row's header as a caller sends it.
    fn header_of(r: &Value) -> Value {
        let f = &r["header"];
        let mut o = json!({});
        for k in ["chainId", "fee", "sendCounter", "p", "validUntilBlock", "plainUsed"] {
            o[k] = f[k].clone();
        }
        for k in ["token", "registry"] {
            o[k] = json!(hx(&h(&f[k])));
        }
        for k in ["fromUA", "beneficiaryUA", "chainUid", "envelopeBinding"] {
            if !f[k].is_null() {
                o[k] = json!(word(&f[k]));
            }
        }
        o
    }
    fn salt(r: &Value) -> Option<[u8; 16]> {
        r["header"]["salt"].as_str().map(|_| h(&r["header"]["salt"]).try_into().unwrap())
    }
    fn row(file: &Value, f: impl Fn(&Value) -> bool) -> &Value {
        file["rows"].as_array().unwrap().iter().find(|r| f(r)).unwrap()
    }

    #[test]
    fn keygen_rows_through_the_facade() {
        let rows = pv("keygen.json")["rows"].as_array().unwrap().clone();
        assert!(!rows.is_empty());
        for r in rows {
            let k = PqzKey::vectors_from_seed32(&s32(&r["seed"])).unwrap();
            assert_eq!(hx(&scaas_ua::keccak256(&k.pk())), hx(&h(&r["pk_keccak"])), "{}", r["seed"]);
        }
    }

    /// `memo_open`: the sender's memo (and its edits: resize, flip) opened under the row's key seed through `openMemo`; a
    /// `"none"` result is `Argument`.
    #[test]
    fn memo_open_rows_through_the_facade() {
        let f = pv("statement_transfer_multi.json");
        let mut n = 0;
        for r in f["memo_open"].as_array().unwrap() {
            let case = row(&f, |x| x["case"] == r["case"]);
            let hd = &case["header"];
            let mut memo = h(&case["memo"]["memo"]);
            for e in r["edits"].as_array().unwrap() {
                if let Some(l) = e["resize"].as_u64() {
                    memo.resize(l as usize, 0);
                } else {
                    memo[e["flip"][0].as_u64().unwrap() as usize] ^= 1 << e["flip"][1].as_u64().unwrap();
                }
            }
            let k = PqzKey::vectors_from_seed32(&s32(&r["key_seed"])).unwrap();
            let req = json!({"chainUid": word(&hd["chainUid"]), "token": hx(&h(&hd["token"])), "fromUA": word(&hd["fromUA"]),
                "sendCounter": hd["sendCounter"], "memo": hx(&memo)});
            let o = call(&k, "openMemo", &req);
            let name = r["name"].as_str().unwrap();
            if r["result"] == "none" {
                assert_eq!(o.err(), Some(Error::Argument), "{name}");
            } else {
                let o = o.unwrap();
                assert_eq!(o["auditorOn"], r["result"]["auditorOn"], "{name}");
                let want: Vec<Value> =
                    r["result"]["legs"].as_array().unwrap().iter().map(|l| json!({"amount": l[0], "ua": word(&l[1])})).collect();
                assert_eq!(o["legs"], json!(want), "{name}");
            }
            n += 1;
        }
        assert_eq!(n, f["memo_open"].as_array().unwrap().len());
        assert!(n > 0);
    }

    /// T15b (F10): every op 7 statement row at the generator's randomness, per `mode`: HASH gives the row's statement (its
    /// `memoHash` is `keccak256(salt ‖ sealedMemo)`, the contract's) and its memo; BUNDLE gives the same statement with
    /// `memoHash` 0 (`PqzCore._parseMulti` leaves it unset) and no memo. No other word or byte depends on the mode.
    #[test]
    fn multi_rows_per_mode() {
        let f = pv("statement_transfer_multi.json");
        let mut n = 0;
        for st_row in f["rows"].as_array().unwrap() {
            let want = h(&st_row["stmt"]);
            let Stmt::Multi(mut m) = st::parse(7, &want).unwrap() else { panic!() };
            let o = &st_row["objects"];
            let legs: Vec<Value> = (0..m.m)
                .map(|j| json!({"pk": hx(&pk_of(&o["pks"][j])), "ua": word(&o["uas"][j]), "amount": o["out"]["values"][j]}))
                .collect();
            let mut req = merge(header_of(st_row), json!({"proofSystemId": hx(&PQZL_ID), "legs": legs, "T": hx(m.t)}));
            if m.pk_a.is_some() {
                req["pkA"] = json!(hx(&pk_of(&o["pk_a"])));
            }
            let k = key(&o["pk_f"]);
            let d = Draw::vectors([7; 32], Some(s32(&o["out"]["seed_enc"])), salt(st_row), Some(s32(&st_row["memo"]["key_seed"])));
            let run = |mode: &str| -> Value {
                serde_json::from_str(&k.vectors_call("proveTransferMulti", merge(req.clone(), json!({"mode": mode})).to_string().as_bytes(), &d).unwrap())
                    .unwrap()
            };
            let case = st_row["case"].as_str().unwrap();
            let hash = run("HASH");
            assert_eq!(h(&hash["stmt"]), with_id(&want, &PQZL_ID), "{case}: HASH statement");
            let memo = h(&hash["memo"]);
            assert_eq!(memo, h(&st_row["memo"]["memo"]), "{case}: HASH memo");
            assert_eq!(m.header[st::H_MEMO_HASH], scaas_ua::keccak256(&memo), "{case}: the row's memoHash");
            let bundle = run("BUNDLE");
            m.header[st::H_MEMO_HASH] = [0; 32];
            assert_eq!(h(&bundle["stmt"]), with_id(&m.encode().unwrap(), &PQZL_ID), "{case}: BUNDLE statement");
            assert_eq!(bundle.get("memo"), None, "{case}: BUNDLE memo");
            n += 1;
        }
        assert!(n > 0);
    }

    /// One proof row: its statement rebuilt through the facade equals the statement file's, and the proof equals the row's.
    fn check(sys: &str, id: &Word, r: &Value, got: &Value, want_stmt: &[u8]) {
        let name = format!("{sys} {} {}", r["form"], r["statement"]);
        assert_eq!(h(&got["stmt"]), with_id(want_stmt, id), "{name}: statement");
        assert_eq!(scaas_ua::keccak256(&h(&got["proof"])).to_vec(), h(&r["proof_keccak"]), "{name}: proof");
    }

    /// Every row of `proof_pqzl.json` and `proof_pqzh.json` (where this set has PQZH): statement and proof through the facade.
    #[test]
    fn proof_rows_through_the_facade() {
        let files = [
            ("statement_transfer.json", pv("statement_transfer.json")),
            ("statement_burn.json", pv("statement_burn.json")),
            ("statement_refresh.json", pv("statement_refresh.json")),
            ("statement_register.json", pv("statement_register.json")),
            ("statement_disclose.json", pv("statement_disclose.json")),
            ("statement_transfer_multi.json", pv("statement_transfer_multi.json")),
        ];
        let file = |n: &Value| &files.iter().find(|f| f.0 == n.as_str().unwrap()).unwrap().1;
        let mut systems = vec![("pqzl", PQZL_ID, pv("proof_pqzl.json"))];
        if pqz_ffi::PQZH {
            systems.push(("pqzh", PQZH_ID, pv("proof_pqzh.json")));
        }
        let mut n = 0;
        for (sys, id, proofs) in &systems {
            for r in proofs["rows"].as_array().unwrap() {
                let s = &r["statement"];
                let f = file(&s["file"]);
                let rnd: [u8; 32] = s32(&r["rnd32"]);
                let d = |seed: &Value, salt: Option<[u8; 16]>, memo: Option<[u8; 32]>| {
                    Draw::vectors(rnd, seed.as_str().map(|_| s32(seed)), salt, memo)
                };
                let idh = hx(id);
                let (got, want) = if let Some(c) = s["case"].as_str() {
                    // op 7
                    let st_row = row(f, |x| x["case"] == c);
                    let want = h(&st_row["stmt"]);
                    let Stmt::Multi(m) = st::parse(7, &want).unwrap() else { panic!() };
                    let o = &st_row["objects"];
                    let legs: Vec<Value> = (0..m.m)
                        .map(|j| json!({"pk": hx(&pk_of(&o["pks"][j])), "ua": word(&o["uas"][j]), "amount": o["out"]["values"][j]}))
                        .collect();
                    let mut req = merge(header_of(st_row), json!({"proofSystemId": idh, "legs": legs, "T": hx(m.t), "mode": "HASH"}));
                    if m.pk_a.is_some() {
                        req["pkA"] = json!(hx(&pk_of(&o["pk_a"])));
                    }
                    let k = key(&o["pk_f"]);
                    let got: Value = serde_json::from_str(
                        &k.vectors_call("proveTransferMulti", req.to_string().as_bytes(),
                            &d(&o["out"]["seed_enc"], salt(st_row), Some(s32(&st_row["memo"]["key_seed"]))))
                        .unwrap(),
                    )
                    .unwrap();
                    assert_eq!(h(&got["memo"]), h(&st_row["memo"]["memo"]), "{c}: memo");
                    (got, want)
                } else if let Some(c) = s["disclosure"].as_str() {
                    let dr = f["disclosures"].as_array().unwrap().iter().find(|x| x["case"] == c).unwrap();
                    let want = h(&dr["stmt"]);
                    let k = key(&dr["objects"]["pk"]);
                    let got = k.vectors_call("proveDisclose", json!({"stmt": hx(&with_id(&want, id))}).to_string().as_bytes(), &d(&Value::Null, None, None));
                    (serde_json::from_str(&got.unwrap()).unwrap(), want)
                } else {
                    let form = s["form"].as_str().unwrap();
                    let st_row = row(f, |x| x["form"] == form);
                    let want = h(&st_row["stmt"]);
                    let o = &st_row["objects"];
                    let got = match form {
                        "REGISTER" => {
                            let (stmt, proof) =
                                key(&o["pk"]).vectors_register_message(id, &s32(&st_row["words"]["message"]), &rnd).unwrap();
                            json!({"stmt": hx(&stmt), "proof": hx(&proof)})
                        }
                        "DISCLOSE-SENDER" | "DISCLOSE-RECEIVER" | "DISCLOSE-AUDITOR" => {
                            let (k, cmd, req) = if form == "DISCLOSE-SENDER" {
                                let req = json!({"stmt": hx(&with_id(&want, id)), "fromUA": hx(&[0xA1; 32]), "sendCounter": 3,
                                    "salt": hx(&[0x5A; 16]), "auditorOn": o["ct"]["recipients"].as_array().unwrap().len() == 3});
                                // any sender handle: the witness is the encryption's; pk_f stands in for the other recipients
                                (PqzKey::vectors_from_seed32(&s32(&o["ct"]["recipients"][1])).unwrap(), "proveDiscloseSender", req)
                            } else {
                                (key(&o["pk"]), "proveDisclose", json!({"stmt": hx(&with_id(&want, id))}))
                            };
                            serde_json::from_str(&k.vectors_call(cmd, req.to_string().as_bytes(), &d(&o["ct"]["seed_enc"], None, None)).unwrap()).unwrap()
                        }
                        _ => {
                            let op = r["op"].as_u64().unwrap() as u8;
                            let Stmt::Debit(db) = st::parse(op, &want).unwrap() else { panic!() };
                            let hd = &st_row["header"];
                            let mut req = merge(header_of(st_row), json!({"proofSystemId": idh, "T": hx(db.t), "memoHash": word(&hd["memoHash"])}));
                            let cmd = match form {
                                "TRANSFER" | "TRANSFER0" => {
                                    req["toUA"] = json!(word(&hd["toUA"]));
                                    req["pkT"] = json!(hx(db.pk_t.unwrap()));
                                    req["amount"] = o["out"]["values"][0].clone();
                                    if let Some(a) = db.pk_a {
                                        req["pkA"] = json!(hx(a));
                                    }
                                    "proveTransfer"
                                }
                                "BURN" => {
                                    req["amount"] = hd["amount"].clone();
                                    req["recipient"] = json!(word(&hd["recipient"]));
                                    "proveBurn"
                                }
                                "REFRESH" => "proveRefresh",
                                other => panic!("{other}"),
                            };
                            let k = key(&o["pk_f"]);
                            serde_json::from_str(&k.vectors_call(cmd, req.to_string().as_bytes(), &d(&o["out"]["seed_enc"], salt(st_row), None)).unwrap())
                                .unwrap()
                        }
                    };
                    (got, want)
                };
                check(sys, id, r, &got, &want);
                n += 1;
            }
        }
        let want_rows: usize = systems.iter().map(|s| s.2["rows"].as_array().unwrap().len()).sum();
        assert_eq!(n, want_rows);
        eprintln!("proof rows through the facade: {n}");
    }
}
