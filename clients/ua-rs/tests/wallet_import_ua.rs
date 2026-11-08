// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T20c (owner 2026-11-08, the CLI-SGN-29 Change): an imported native key registers its own derived kind
//! (`Wallet::imported_ua_key`), `secp256k1` 0x0108 for a secp256k1 secret, `ed25519` 0x0102 for an ed25519 seed, and no other;
//! against smartcontracts/vectors/ua/{keys,sign,seal}.json `imported` (written by clientkeys) and the both-ways fixture
//! rs_vault.json (tests/wallet_vault.rs writes its backup with an imported UA). Spec §8.3. UNAUDITED.
use scaas_ua::verify::{native_ecdsa, verify};
use scaas_ua::wallet::{
    scaas_typed_data, ContainerExpect, Error, Expect, ExpectedSender, ImportEntry, KemKeyPair, Manifest, Network, Recipient,
    SealedContainer, TypedData, Unlock, Wallet, PURPOSE_BACKUP,
};
use scaas_ua::{keccak256, purpose_tag};
use serde_json::Value;

fn path(f: &str) -> String {
    format!("{}/../../smartcontracts/vectors/ua/{f}", env!("CARGO_MANIFEST_DIR"))
}
fn load(f: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path(f)).unwrap()).unwrap()
}
fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array().unwrap()
}
fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn b32(v: &Value) -> [u8; 32] {
    h(v).try_into().unwrap()
}
fn num(v: &Value) -> u64 {
    v.as_u64().unwrap()
}
fn code<T>(r: Result<T, Error>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => e.code().into(),
    }
}
fn wallet(id: &str) -> Wallet {
    let k = load("keys.json");
    let m = arr(&k, "mnemonics").iter().find(|m| m["id"] == id).unwrap();
    Wallet::from_mnemonic(m["words"].as_str().unwrap(), m["passphrase"].as_str().unwrap()).unwrap()
}
fn row(network: &str) -> Value {
    arr(&load("keys.json")["imported"], "rows").iter().find(|r| r["network"] == network).unwrap().clone()
}
fn net(r: &Value) -> Network {
    Network::from_name(r["network"].as_str().unwrap()).unwrap()
}
/// A fresh wallet holding `r`'s secret as import 0, and its import number.
fn imported(r: &Value) -> (Wallet, u32) {
    let w = wallet("twelve_words");
    let n = w.import_native_key(net(r), &h(&r["secret"])).unwrap().index();
    (w, n)
}
/// The recipient's KEM key (pq_kat `0x0130` 0/0 version 0, seal.json's opener) and its wallet (kept: dropping it revokes the key).
fn opener() -> (Wallet, KemKeyPair) {
    let w = wallet("pq_kat");
    let kk = w.ua_key(0x0130, 0, 0).unwrap().kem_key(0).unwrap();
    (w, kk)
}
fn recipient() -> Recipient {
    let (w, kk) = opener();
    let k = w.ua_key(0x0130, 0, 0).unwrap();
    Recipient::ua(0x0130, &k.key_data(), 0, &kk.kem_pk()).unwrap()
}
fn none(_: [u8; 32]) -> Option<(u16, Vec<u8>)> {
    None
}
fn restore(c: &SealedContainer, sender: [u8; 32]) -> Result<Option<Wallet>, Error> {
    let (_w, kk) = opener();
    let s = [sender];
    let x = ContainerExpect { purpose: PURPOSE_BACKUP, sender: ExpectedSender::Set(&s), recipient: kk.recipient() };
    Wallet::restore_backup(&kk, c, &x, &none, None, None, None, "")
}

/// keys.json `imported`: per network, the imported key's UA equals the row (kind, key data, keccak256(TAG(kind) ‖ key data)),
/// a separate account from the native id; every refusal row's kind is `Argument`, the row's own kind (positive control) is not.
#[test]
fn keys_json_imported_rows() {
    let k = load("keys.json");
    let rows = arr(&k["imported"], "rows");
    assert_eq!(rows.len(), 9);
    for r in rows {
        let (w, n) = imported(r);
        let key = w.imported_ua_key(net(r), n, num(&r["kind"]) as u16).unwrap();
        assert_eq!(key.kind(), num(&r["kind"]) as u16, "{}", r["network"]);
        assert_eq!(key.kind(), net(r).scheme_kind());
        assert_eq!(key.key_data(), h(&r["keyData"]), "{}", r["network"]);
        assert_eq!(key.ua(), Some(b32(&r["ua"])), "{}", r["network"]);
        assert_eq!(scaas_ua::derive_ua(key.kind(), &key.key_data(), false).unwrap(), b32(&r["ua"]));
        assert_eq!((key.account(), key.index()), (u32::MAX, u32::MAX), "no UA-tree position");
        let native = w.imported_key(net(r), n).unwrap();
        assert_eq!(hex::encode(native.public_key()), r["native"]["publicKey"].as_str().unwrap().trim_start_matches("0x"));
        let native_id: Vec<u8> = match native.address() {
            Some(a) if key.kind() == 0x0108 && a.starts_with("0x") => [vec![0u8; 12], hex::decode(&a[2..]).unwrap()].concat(),
            _ => native.public_key(),
        };
        assert_ne!(native_id, h(&r["ua"]), "{}: a separate account", r["network"]);
        assert_ne!(&h(&r["ua"])[..12], &[0u8; 12], "not in the native space");
    }
    let refusals = arr(&k["imported"], "refusals");
    assert_eq!(refusals.len(), 6);
    for x in refusals {
        let r = row(x["network"].as_str().unwrap());
        let (w, n) = imported(&r);
        assert_eq!(code(w.imported_ua_key(net(&r), n, num(&x["kind"]) as u16)), "Argument", "{}", x["reason"]);
        assert!(w.imported_ua_key(net(&r), n, num(&r["kind"]) as u16).is_ok(), "positive control");
        assert!(w.manifest().imported_uas.len() == 1 && w.manifest().entries.is_empty(), "never in entries");
    }
    // another network or an unknown import number
    let r = row("evm");
    let (w, n) = imported(&r);
    assert_eq!(code(w.imported_ua_key(Network::Cosmos, n, 0x0108)), "Argument");
    assert_eq!(code(w.imported_ua_key(Network::Evm, n + 1, 0x0108)), "Argument");
}

/// The handle has no KEM key (not a holder, CTR-UA-32) and the wallet's own native keys stay their network's (no call
/// makes a UA of them).
#[test]
fn imported_ua_holds_no_kem_key() {
    for net_name in ["evm", "solana"] {
        let r = row(net_name);
        let (w, n) = imported(&r);
        let key = w.imported_ua_key(net(&r), n, num(&r["kind"]) as u16).unwrap();
        assert_eq!(code(key.kem_key(0)), "KemHolder", "{net_name}");
        assert!(w.manifest().kem.is_empty());
    }
}

/// sign.json `imported`: pop v2 (no KEM record, no PQZ key), a meta-transaction rebuilt from its input by the SCaaS builder
/// (non-zero unbound relayer / feeRecipient zeroed), a member slot; each byte-equal and verifying as the contract's verifier
/// checks it (`verify`, the port `signatures.json` pins to `Secp256k1Verifier` / `Ed25519Verifier`).
#[test]
fn sign_json_imported_rows() {
    let s = load("sign.json");
    let rows = arr(&s["imported"], "rows");
    assert_eq!(rows.len(), 6);
    for x in rows {
        let r = row(x["network"].as_str().unwrap());
        let (w, n) = imported(&r);
        let key = w.imported_ua_key(net(&r), n, num(&r["kind"]) as u16).unwrap();
        let ua = key.ua().unwrap();
        let purpose = b32(&x["purposeTag"]);
        let digest = match x["what"].as_str().unwrap() {
            "pop" => {
                let no_kem = scaas_ua::ua8::kem_record_hash(&ua, 0, &[]).unwrap();
                scaas_ua::ua8::registration_digest(&ua, key.kind(), &[0; 32], &no_kem, &[0; 32])
            }
            "metatx" => {
                let i = &x["input"];
                let contract: [u8; 20] = h(&i["contract"]).try_into().unwrap();
                let built = scaas_typed_data(x["primaryType"].as_str().unwrap(), i["name"].as_str(), &contract, num(&i["chainId"]),
                    &b32(&i["chainUid"]), &i["message"])
                .unwrap();
                assert_ne!(i["message"]["relayer"], "0x0000000000000000000000000000000000000000", "a non-zero relayer in");
                built.digest().unwrap()
            }
            _ => scaas_ua::member_digest(&b32(&x["structureUa"]), &b32(&x["structureUaMsg"])),
        };
        assert_eq!(digest, b32(&x["digest"]), "{}", x["id"]);
        let msg = scaas_ua::ua_message(key.kind(), &purpose, &digest).unwrap();
        assert_eq!(msg, b32(&x["uaMsg"]), "{}", x["id"]);
        let sig = if x["what"] == "member" {
            key.sign_member(&b32(&x["structureUa"]), &b32(&x["structureUaMsg"])).unwrap()
        } else {
            key.sign_ua(&purpose, &digest).unwrap()
        };
        assert_eq!(sig, h(&x["signature"]), "{}", x["id"]);
        assert!(verify(key.kind(), &key.key_data(), &msg, &sig, x["what"] == "pop"), "{}", x["id"]);
    }
}

fn ed25519_ok(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool {
    let (Ok(pk), Ok(sig)) = (<[u8; 32]>::try_from(pk), <[u8; 64]>::try_from(sig)) else { return false };
    ed25519_dalek::VerifyingKey::from_bytes(&pk)
        .is_ok_and(|k| k.verify_strict(digest, &ed25519_dalek::Signature::from_bytes(&sig)).is_ok())
}

/// sign.json `imported.separation`: the key's native signature over an operation's own digest (EIP-712, a transaction's
/// sighash, the key proof), made here by the import's `NativeKey`, is no UA signature; the UA signature over
/// `uaMessage(kind, metatx, digest)` fails the native check of that operation. Positive controls both ways.
#[test]
fn sign_json_imported_separation() {
    let s = load("sign.json");
    let rows = arr(&s["imported"], "separation");
    assert_eq!(rows.len(), 4);
    let metatx = purpose_tag("metatx").unwrap();
    for x in rows {
        let r = row(x["network"].as_str().unwrap());
        let (w, n) = imported(&r);
        let key = w.imported_ua_key(net(&r), n, num(&r["kind"]) as u16).unwrap();
        let native = w.imported_key(net(&r), n).unwrap();
        let digest = b32(&x["digest"]);
        let native_sig = match x["op"].as_str().unwrap() {
            "typed" => {
                let td = TypedData::from_json(&serde_json::to_vec(&x["td"]).unwrap()).unwrap();
                assert_eq!(td.digest().unwrap(), digest);
                let any = Expect::from_json(br#"{"check": "Any", "allowAnyTypedData": true}"#).unwrap();
                native.sign_typed(&td, any).unwrap()
            }
            "tx" => {
                let t = scaas_ua::wallet::EvmTx::from_json(&serde_json::to_vec(&x["tx"]).unwrap()).unwrap();
                let st = native.sign_transaction(&t).unwrap();
                [st.r.to_vec(), st.s.to_vec(), vec![27 + st.y_parity]].concat()
            }
            _ => {
                let c = x["challenge"].as_str().unwrap().as_bytes();
                assert_eq!(keccak256(&[b"scaas-subject-key-proof-v1".as_slice(), c].concat()), digest);
                native.sign_key_proof(c).unwrap()
            }
        };
        assert_eq!(native_sig, h(&x["nativeSignature"]), "{}", x["id"]);
        let native_ok = |sig: &[u8]| match key.kind() {
            0x0108 => {
                let a: [u8; 20] = hex::decode(native.address().unwrap().trim_start_matches("0x")).unwrap().try_into().unwrap();
                native_ecdsa(&a, &digest, sig)
            }
            _ => ed25519_ok(&native.public_key(), &digest, sig),
        };
        let msg = scaas_ua::ua_message(key.kind(), &metatx, &digest).unwrap();
        assert_eq!(msg, b32(&x["uaMsg"]));
        assert!(native_ok(&native_sig), "{}: native positive control", x["id"]);
        assert!(!verify(key.kind(), &key.key_data(), &msg, &native_sig, false), "{}: native as UA refused", x["id"]);
        let ua_sig = key.sign_ua(&metatx, &digest).unwrap();
        assert_eq!(ua_sig, h(&x["uaSignature"]), "{}", x["id"]);
        assert!(verify(key.kind(), &key.key_data(), &msg, &ua_sig, false), "{}: UA positive control", x["id"]);
        assert!(!native_ok(&ua_sig), "{}: UA as native refused", x["id"]);
    }
}

/// seal.json `imported`: a backup carrying `importedUas` restores with each entry's `source`; one secret under two sources is
/// two entries of one `ua`; the payload refusals (another `ua`, another `kind`, a source with no secret, one source twice, a
/// present empty list) are `Argument` after the container opens; the accepted payloads write back byte for byte.
#[test]
fn seal_json_imported_rows() {
    let s = load("seal.json");
    let rows = arr(&s, "imported");
    let (mut ok, mut refused) = (0, 0);
    for r in rows {
        let c = SealedContainer::from_json(r["container"].to_string().as_bytes()).unwrap();
        let sender = b32(&r["expect"]["sender"]["ua"]);
        let pt = h(&r["pt"]);
        if let Some(e) = r["error"].as_str() {
            assert_eq!(code(restore(&c, sender)), e, "{}", r["id"]);
            #[cfg(feature = "vectors")]
            assert_eq!(code(scaas_ua::wallet::vectors_backup_payload(&pt)), e, "{}", r["id"]);
            refused += 1;
            continue;
        }
        let w = restore(&c, sender).unwrap().unwrap();
        let m = w.manifest();
        let want: Vec<(u16, String, [u8; 32])> = arr(r, "importedUas")
            .iter()
            .map(|e| (num(&e["kind"]) as u16, e["source"].as_str().unwrap().to_owned(), b32(&e["ua"])))
            .collect();
        let got: Vec<(u16, String, [u8; 32])> = m
            .imported_uas
            .iter()
            .map(|e| (e.kind, format!("native-import:{}:{}", e.source.network.name(), e.source.n), e.ua))
            .collect();
        assert_eq!(got, want, "{}: the source survives the restore", r["id"]);
        assert!(m.entries.iter().all(|e| e.account != u32::MAX), "never in entries");
        for e in &m.imported_uas {
            let k = w.imported_ua_key(e.source.network, e.source.n, e.kind).unwrap();
            assert_eq!(k.ua(), Some(e.ua), "{}", r["id"]);
        }
        #[cfg(feature = "vectors")]
        assert_eq!(scaas_ua::wallet::vectors_backup_payload(&pt).unwrap().as_bytes(), &pt[..], "{}", r["id"]);
        ok += 1;
    }
    assert_eq!((ok, refused), (2, 5));
}

/// The wallet's own backup and link carry the imported UA: `importedUas` after `entries` with the id recomputed from the
/// secret; restored, it lists the same entry and the key gives the same id. A wallet without one writes no `importedUas`.
#[test]
fn backup_and_link_keep_the_imported_ua() {
    let r = row("evm");
    let (w, n) = imported(&r);
    let id = w.ua_key(0x0102, 0, 0).unwrap();
    let before = w.backup_seal(&id, &[recipient()]).unwrap().remove(0);
    let plain = restore(&before, id.ua().unwrap()).unwrap().unwrap();
    assert!(plain.manifest().imported_uas.is_empty(), "no imported UA yet: none written");
    let key = w.imported_ua_key(Network::Evm, n, 0x0108).unwrap();
    let c = w.backup_seal(&id, &[recipient()]).unwrap().remove(0);
    let back = restore(&c, id.ua().unwrap()).unwrap().unwrap();
    assert_eq!(back.manifest().imported_uas, w.manifest().imported_uas);
    assert_eq!(back.manifest().imported_uas[0].source, ImportEntry { network: Network::Evm, n });
    assert_eq!(back.imported_ua_key(Network::Evm, n, 0x0108).unwrap().ua(), key.ua());
    // link: the same payload
    let session = scaas_ua::wallet::LinkSession::new().unwrap();
    let l = w.link_seal(&id, &session.kem_pk(), &session.short_code()).unwrap();
    let s = [id.ua().unwrap()];
    let x = ContainerExpect { purpose: "scaas/link/v1", sender: ExpectedSender::Set(&s), recipient: session.recipient() };
    let linked = Wallet::from_link(session, &l, &x, &none, None, "").unwrap();
    assert_eq!(linked.manifest().imported_uas, w.manifest().imported_uas);
    assert_eq!(linked.imported_ua_key(Network::Evm, n, 0x0108).unwrap().ua(), key.ua());
}

/// An imported UA key is no backup or link sender (`Argument`), refused before anything is written: `entries` unchanged and
/// the wallet still unlocks (an entry of account u32::MAX first in `entries` would fail every later unlock).
#[test]
fn imported_ua_is_no_sender_and_entries_stay_readable() {
    let r = row("evm");
    let (w, n) = imported(&r);
    let vault = w.seal_vault("river-otter-7 import", None).unwrap();
    let key = w.imported_ua_key(Network::Evm, n, 0x0108).unwrap();
    let before = w.manifest();
    assert!(before.entries.is_empty());
    assert_eq!(code(w.backup_seal(&key, &[recipient()])), "Argument");
    let session = scaas_ua::wallet::LinkSession::new().unwrap();
    assert_eq!(code(w.link_seal(&key, &session.kem_pk(), &session.short_code())), "Argument");
    assert_eq!(w.manifest(), before, "nothing written");
    // positive control: a derived sender seals, written to entries after the refused attempts
    let id = w.ua_key(0x0102, 0, 0).unwrap();
    w.backup_seal(&id, &[recipient()]).unwrap();
    assert_eq!(w.manifest().entries.iter().map(|e| e.ua).collect::<Vec<_>>(), vec![id.ua().unwrap()]);
    w.lock();
    w.unlock(&vault, Unlock::VaultPassphrase("river-otter-7 import"), "").unwrap();
}

/// The handle's id is recomputed from the held secret: a manifest vault that lists a wrong `ua` for the import still yields
/// the key's true id, and the listed entry is replaced by it. `lock()` revokes the handle; after `unlock` the key is
/// `Argument` until the import's label vault is opened.
#[cfg(feature = "vectors")]
#[test]
fn manifest_listing_is_no_trust_anchor() {
    let r = row("evm");
    let (w, n) = imported(&r);
    let pass = "river-otter-7 import";
    let vault = w.seal_vault(pass, None).unwrap();
    let iv = w.seal_label_vault(&format!("native-import:evm:{n}"), pass, None).unwrap();
    let key = w.imported_ua_key(Network::Evm, n, 0x0108).unwrap();
    let truth = key.ua().unwrap();
    let wrong = keccak256(b"not the key's id");
    let forged = w.manifest().to_json().replace(&hex::encode(truth), &hex::encode(wrong));
    assert!(forged.contains(&hex::encode(wrong)));
    let m = Manifest::from_json(forged.as_bytes()).unwrap();
    assert_eq!(m.imported_uas[0].ua, wrong);
    w.open_label_vault(&scaas_ua::wallet::Vault::vectors_seal("manifest", forged.as_bytes(), pass).unwrap(), Unlock::VaultPassphrase(pass)).unwrap();
    assert_eq!(w.manifest().imported_uas[0].ua, wrong, "the forged listing is loaded");
    let again = w.imported_ua_key(Network::Evm, n, 0x0108).unwrap();
    assert_eq!(again.ua(), Some(truth), "the id is the secret's");
    assert_eq!(w.manifest().imported_uas[0].ua, truth, "the listing follows the key");
    // custody
    w.lock();
    assert_eq!(code(key.sign_ua(&purpose_tag("metatx").unwrap(), &[7; 32])), "KeyRevoked");
    w.unlock(&vault, Unlock::VaultPassphrase(pass), "").unwrap();
    assert_eq!(code(w.imported_ua_key(Network::Evm, n, 0x0108)), "Argument", "listed, not held");
    w.open_label_vault(&iv, Unlock::VaultPassphrase(pass)).unwrap();
    assert_eq!(w.imported_ua_key(Network::Evm, n, 0x0108).unwrap().ua(), Some(truth));
}

/// The manifest JSON round trip with `importedUas` (always written in the manifest vault); malformed entries `Argument`.
#[test]
fn manifest_json_imported_uas() {
    let r = row("solana");
    let (w, n) = imported(&r);
    w.imported_ua_key(Network::Solana, n, 0x0102).unwrap();
    let m = w.manifest();
    let j = m.to_json();
    assert!(j.contains(&format!("\"importedUas\":[{{\"kind\":258,\"source\":\"native-import:solana:{n}\",\"ua\":\"0x")));
    assert_eq!(Manifest::from_json(j.as_bytes()).unwrap(), m);
    let empty = Wallet::from_mnemonic(&bip39::Mnemonic::from_entropy(&[9; 16]).unwrap().to_string(), "").unwrap().manifest().to_json();
    assert!(empty.contains("\"importedUas\":[]"), "the manifest vault writes every list");
    for bad in [
        j.replace("\"kind\":258", "\"kind\":264"),
        j.replace("native-import:solana:", "native-import:solana:0"),
        j.replace("native-import:solana:", "frost-share:"),
        j.replace("\"importedUas\":[{", "\"importedUas\":[{\"x\":1,\"y\":{\"z\":[1]},"),
    ] {
        assert_eq!(code(Manifest::from_json(bad.as_bytes())), "Argument", "{bad}");
    }
}
