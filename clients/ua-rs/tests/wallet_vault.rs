// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T9: the clientkeys vault v1 (spec §8.1, C-10, C-12), the manifest, discovery and import (§8.3), `SeedBackup`,
//! `backup_seal` and `restore_backup` (§6.3, §8.4, C-03, C-11) against smartcontracts/vectors/ua/{vault,seal,keys}.json (written
//! by clientkeys) and the both-ways fixture rs_vault.json (written here, `--ignored regenerate`, read by clientkeys `npm test`).
//! Every pin envelope runs scrypt (N = 2^15 … 2^17, 128 MiB at 2^17). UNAUDITED.
use scaas_ua::wallet::{
    check_passphrase, AllowRollback, ContainerExpect, Error, ExpectedSender, KemKeyPair, Network, PrfEnvelope, Recipient,
    RecipientId, SealedContainer, Unlock, Vault, Wallet, PURPOSE_BACKUP,
};
use scaas_ua::keccak256;
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
fn h(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).unwrap()
}
fn b32(v: &Value) -> [u8; 32] {
    h(v.as_str().unwrap()).try_into().unwrap()
}
fn num(v: &Value) -> u64 {
    v.as_u64().unwrap()
}
fn words(id: &str) -> (String, String) {
    let k = load("keys.json");
    let m = arr(&k, "mnemonics").iter().find(|m| m["id"] == id).unwrap();
    (m["words"].as_str().unwrap().to_owned(), m["passphrase"].as_str().unwrap().to_owned())
}
fn wallet(id: &str) -> Wallet {
    let (w, p) = words(id);
    Wallet::from_mnemonic(&w, &p).unwrap()
}
fn vault(v: &Value) -> Result<Vault, Error> {
    Vault::from_json(v.to_string().as_bytes())
}
/// A row's `unlock`: `{pin}` or `{prfOutput}`.
fn with_unlock<R>(u: &Value, f: impl FnOnce(Unlock) -> R) -> R {
    match u.get("prfOutput") {
        Some(p) => f(Unlock::Prf(&b32(p))),
        None => f(Unlock::VaultPassphrase(u["pin"].as_str().unwrap())),
    }
}
fn code<T>(r: Result<T, Error>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => e.code().into(),
    }
}
/// The recipient's KEM key (pq_kat `0x0130` 0/0 version 0, seal.json's opener) and its wallet.
fn opener() -> (Wallet, KemKeyPair) {
    let w = wallet("pq_kat");
    let kk = w.ua_key(0x0130, 0, 0).unwrap().kem_key(0).unwrap();
    (w, kk)
}
fn recipient_of(kk: &KemKeyPair) -> Recipient {
    let RecipientId::Ua { ua, .. } = kk.recipient() else { panic!() };
    let w = wallet("pq_kat");
    let k = w.ua_key(0x0130, 0, 0).unwrap();
    assert_eq!(k.ua(), Some(ua));
    Recipient::ua(0x0130, &k.key_data(), 0, &kk.kem_pk()).unwrap()
}
fn expect_of<'a>(sender: &'a [[u8; 32]], kk: &KemKeyPair) -> ContainerExpect<'a> {
    ContainerExpect { purpose: PURPOSE_BACKUP, sender: ExpectedSender::Set(sender), recipient: kk.recipient() }
}
/// The wallet holds `e` as its entropy: the keys of its mnemonic (BIP-39 passphrase empty), and under `vectors` the bytes.
fn entropy_is(w: &Wallet, e: &[u8]) {
    #[cfg(feature = "vectors")]
    assert_eq!(*w.vectors_entropy().unwrap(), e);
    let m = bip39::Mnemonic::from_entropy(e).unwrap().to_string();
    let want = Wallet::from_mnemonic(&m, "").unwrap().ua_key(0x0101, 0, 0).unwrap().key_data();
    assert_eq!(w.ua_key(0x0101, 0, 0).unwrap().key_data(), want);
}
fn none(_: [u8; 32]) -> Option<(u16, Vec<u8>)> {
    None
}
/// `restore_backup` of `c` to `kk` from the expected `sender`, single-key sender (no lookups).
fn restore(
    kk: &KemKeyPair, c: &SealedContainer, sender: [u8; 32], current: Option<&Wallet>, rollback: Option<AllowRollback>, pass: &str,
) -> Result<Option<Wallet>, Error> {
    let s = [sender];
    Wallet::restore_backup(kk, c, &expect_of(&s, kk), &none, None, current, rollback, pass)
}

// --- vault v1 (spec §8.1) ---

/// vault.json `vaults`: every clientkeys vault opens here to its entropy (N = 2^15, 2^16, 2^17, 12 words, NFC sealed / NFD
/// opened, PRF); the 12-word row gives the same UA key and KEM key as keys.json / kem.json.
#[test]
fn vault_json_vaults_open() {
    let f = load("vault.json");
    assert_eq!(arr(&f, "vaults").len(), 6);
    for r in arr(&f, "vaults") {
        let v = vault(&r["vault"]).unwrap();
        let w = with_unlock(&r["unlock"], |u| Wallet::open_vault(&v, u, "")).unwrap();
        entropy_is(&w, &h(r["plaintext"].as_str().unwrap()));
        if let Some(k) = r.get("uaKey") {
            let key = w.ua_key(num(&k["kind"]) as u16, 0, 0).unwrap();
            assert_eq!(key.ua(), Some(b32(&k["ua"])));
            let kem = w.ua_key(num(&r["kemKey"]["kind"]) as u16, 0, 0).unwrap().kem_key(0).unwrap();
            assert_eq!(keccak256(&kem.kem_pk()), b32(&r["kemKey"]["kemPkHash"]));
            #[cfg(feature = "vectors")]
            assert_eq!(w.vectors_entropy().unwrap().len(), 16, "12 words: entropy kept at 16 bytes (C-10)");
        }
    }
}

/// vault.json `refusals`: wrong passphrase and altered AAD label `VaultOpen`; N = 2^31, N = 3, r = 16, p = 2 `VaultParams`
/// (before scrypt runs: N = 2^31 would ask 256 GiB); `v: 2` and its tombstone `VaultVersion`; payloads of 31 and 64 bytes
/// `VaultOpen`; a label other than `seed` `Argument`.
#[test]
fn vault_json_refusals() {
    let f = load("vault.json");
    assert_eq!(arr(&f, "refusals").len(), 11);
    for r in arr(&f, "refusals") {
        let got = vault(&r["vault"]).and_then(|v| with_unlock(&r["unlock"], |u| Wallet::open_vault(&v, u, "")));
        assert_eq!(code(got), r["error"].as_str().unwrap(), "{}", r["id"]);
    }
}

#[test]
fn seed_payload_of_31_bytes_refused() {
    let f = load("vault.json");
    let r = arr(&f, "refusals").iter().find(|r| r["id"] == "seed payload of 31 bytes").unwrap();
    let v = vault(&r["vault"]).unwrap();
    assert_eq!(code(Wallet::open_vault(&v, Unlock::VaultPassphrase(r["unlock"]["pin"].as_str().unwrap()), "")), "VaultOpen");
    // positive control: the same passphrase opens the 32-byte row
    let ok = arr(&f, "vaults").iter().find(|r| r["id"] == "seed N=2^15").unwrap();
    let v = vault(&ok["vault"]).unwrap();
    assert!(Wallet::open_vault(&v, Unlock::VaultPassphrase(ok["unlock"]["pin"].as_str().unwrap()), "").is_ok());
}

/// A vault of ua-rs: N = 2^17, r = 8, p = 1, the entropy at its own length (not the seed), label `seed`; it opens to the same
/// wallet, a wrong passphrase is `VaultOpen`, the JSON round trips.
#[test]
fn vault_seal_open_round_trip() {
    let (words12, _) = words("twelve_words");
    let w = Wallet::from_mnemonic(&words12, "").unwrap();
    let v = w.seal_vault("river-otter-7 ünï", None).unwrap();
    assert_eq!(v.label(), "seed");
    assert!(!v.needs_rewrap());
    let j: Value = serde_json::from_str(&v.to_json()).unwrap();
    assert_eq!((num(&j["v"]), j["pin"]["kdf"].as_str().unwrap()), (1, "scrypt"));
    assert_eq!((num(&j["pin"]["N"]), num(&j["pin"]["r"]), num(&j["pin"]["p"])), (1 << 17, 8, 1));
    assert_eq!(Vault::from_json(v.to_json().as_bytes()).unwrap(), v);
    let back = Wallet::open_vault(&v, Unlock::VaultPassphrase("river-otter-7 ünï"), "").unwrap();
    entropy_is(&back, &h("0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"));
    #[cfg(feature = "vectors")]
    assert_eq!(*back.vectors_entropy().unwrap(), *w.vectors_entropy().unwrap());
    assert_eq!(code(Wallet::open_vault(&v, Unlock::VaultPassphrase("river-otter-8 ünï"), "")), "VaultOpen");
    // a new passphrase follows the policy; a locked wallet seals nothing
    assert_eq!(code(w.seal_vault("1234567", None)), "Argument");
    w.lock();
    assert_eq!(code(w.seal_vault("river-otter-7 ünï", None)), "WalletLocked");
}

/// rs_vault.json (the both-ways fixture): ua-rs vaults open here too (clientkeys reads the same rows).
#[test]
fn rs_vault_json_rows_open() {
    let f = load("rs_vault.json");
    assert!(f["note"].as_str().unwrap().contains("never edit by hand"));
    assert!(arr(&f, "vaults").len() >= 3);
    for r in arr(&f, "vaults") {
        let v = vault(&r["vault"]).unwrap();
        let w = with_unlock(&r["unlock"], |u| Wallet::open_vault(&v, u, "")).unwrap();
        entropy_is(&w, &h(r["plaintext"].as_str().unwrap()));
    }
    let (_w, kk) = opener();
    for r in arr(&f, "backups") {
        let c = SealedContainer::from_json(r["container"].to_string().as_bytes()).unwrap();
        let w = restore(&kk, &c, b32(&r["senderUa"]), None, None, "").unwrap().unwrap();
        entropy_is(&w, &h(r["entropy"].as_str().unwrap()));
        assert_eq!(w.manifest().backup_generation, num(&r["generation"]));
    }
}

/// `needs_rewrap` on an old envelope (N = 2^15); `rewrap_pin` replaces the pin envelope only (the DEK and the data box stay:
/// KEK rotation, not DEK rotation, C-12), at today's parameters, and the old passphrase no longer opens it.
#[test]
fn rewrap_pin_keeps_the_dek() {
    let f = load("vault.json");
    let r = arr(&f, "vaults").iter().find(|r| r["id"] == "seed N=2^15").unwrap();
    let old = vault(&r["vault"]).unwrap();
    assert!(old.needs_rewrap());
    let pin = r["unlock"]["pin"].as_str().unwrap();
    assert_eq!(code(old.rewrap_pin(pin, "12345678")), "Argument");
    assert_eq!(code(old.rewrap_pin("wrong passphrase", "new-passphrase-1")), "VaultOpen");
    let new = old.rewrap_pin(pin, "new-passphrase-1").unwrap();
    assert!(!new.needs_rewrap());
    let (jo, jn): (Value, Value) = (serde_json::from_str(&old.to_json()).unwrap(), serde_json::from_str(&new.to_json()).unwrap());
    assert_eq!(jo["data"], jn["data"], "the data box is untouched");
    assert_ne!(jo["pin"]["salt"], jn["pin"]["salt"]);
    assert_eq!(num(&jn["pin"]["N"]), 1 << 17);
    let w = Wallet::open_vault(&new, Unlock::VaultPassphrase("new-passphrase-1"), "").unwrap();
    entropy_is(&w, &h(r["plaintext"].as_str().unwrap()));
    assert_eq!(code(Wallet::open_vault(&new, Unlock::VaultPassphrase(pin), "")), "VaultOpen");
}

/// `enable_prf` adds a PRF envelope (any 32-byte platform secret, HKDF to the KEK); `Unlock::Prf` opens without the
/// passphrase; a vault without one refuses a PRF unlock (`Argument`); a wrong PRF output is `VaultOpen`.
#[test]
fn prf_envelope() {
    let (words12, _) = words("twelve_words");
    let w = Wallet::from_mnemonic(&words12, "").unwrap();
    let v = w.seal_vault("river-otter-7", None).unwrap();
    let out = [7u8; 32];
    assert_eq!(code(Wallet::open_vault(&v, Unlock::Prf(&out), "")), "Argument");
    let prf = PrfEnvelope { output: &out, credential_id: "alias.ua-rs", salt: &[9; 32] };
    let p = v.enable_prf("river-otter-7", &prf).unwrap();
    let back = Wallet::open_vault(&p, Unlock::Prf(&out), "").unwrap();
    entropy_is(&back, &h("0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"));
    assert_eq!(code(Wallet::open_vault(&p, Unlock::Prf(&[8; 32]), "")), "VaultOpen");
    assert!(Wallet::open_vault(&p, Unlock::VaultPassphrase("river-otter-7"), "").is_ok(), "the pin envelope stays");
    let j: Value = serde_json::from_str(&p.to_json()).unwrap();
    assert_eq!(j["prf"]["credentialId"], "alias.ua-rs");
    // seal_vault with a PRF envelope at once
    let both = w.seal_vault("river-otter-7", Some(&prf)).unwrap();
    assert!(Wallet::open_vault(&both, Unlock::Prf(&out), "").is_ok());
}

/// The new-passphrase policy (`checkPassphrase`): NFKC, at least 8 characters, not only digits (and spaces).
#[test]
fn passphrase_policy() {
    for bad in ["", "1234567", "12345678", "123456789012", "abc", "   12  ", "１２３４５６７８"] {
        assert_eq!(code(check_passphrase(bad)), "Argument", "{bad:?}");
    }
    for ok in ["river-otter-7", "abcdefgh", "1234567a", "パスワードパスワード"] {
        assert!(check_passphrase(ok).is_ok(), "{ok:?}");
    }
}

// --- the BIP-39 passphrase is never stored (spec §8.1, §8.4) ---

#[test]
fn bip39_passphrase_absent_from_every_payload() {
    let (wd, pass) = words("non_ascii_passphrase");
    let w = Wallet::from_mnemonic(&wd, &pass).unwrap();
    let key = w.ua_key(0x0102, 0, 0).unwrap();
    let sender = key.ua().unwrap();
    #[allow(unused_mut)]
    let mut needles: Vec<Vec<u8>> = vec![pass.as_bytes().to_vec()];
    #[cfg(feature = "vectors")]
    needles.push(w.vectors_seed().unwrap().to_vec());
    // the vault holds the entropy: opened without the passphrase it is another wallet, with it the same one
    let v = w.seal_vault("river-otter-7", None).unwrap();
    assert_ne!(Wallet::open_vault(&v, Unlock::VaultPassphrase("river-otter-7"), "").unwrap().ua_key(0x0102, 0, 0).unwrap().ua(), Some(sender));
    let back = Wallet::open_vault(&v, Unlock::VaultPassphrase("river-otter-7"), &pass).unwrap();
    assert_eq!(back.ua_key(0x0102, 0, 0).unwrap().ua(), Some(sender));
    #[cfg(feature = "vectors")]
    assert_eq!(back.vectors_entropy().unwrap().len(), 32);
    // the backup payload: no passphrase, no seed
    let (_o, kk) = opener();
    let c = w.backup_seal(&key, &[recipient_of(&kk)]).unwrap().remove(0);
    let s = [sender];
    let pt = kk.open_container(&c, &expect_of(&s, &kk), &none, None).unwrap();
    let manifest = w.manifest().to_json();
    for n in &needles {
        for hay in [&pt[..], manifest.as_bytes(), v.to_json().as_bytes()] {
            assert!(!hay.windows(n.len()).any(|x| x == &n[..]));
        }
    }
    // restored without the passphrase the entropy does not derive the sender; with it, it does
    assert_eq!(code(restore(&kk, &c, sender, None, None, "")), "ContainerSender");
    assert!(restore(&kk, &c, sender, None, None, &pass).unwrap().is_some());
}

// --- import (spec §8.3, CLI-SGN-11) ---

#[test]
fn imported_key_refused_for_another_family() {
    let w = wallet("twelve_words");
    let secret = h("0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318");
    let k = w.import_native_key(Network::Evm, &secret).unwrap();
    assert_eq!(k.address().unwrap().to_lowercase(), "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23");
    assert_eq!(w.imported_key(Network::Evm, 0).unwrap().public_key(), k.public_key());
    assert_eq!(code(w.imported_key(Network::Cosmos, 0)), "Argument");
    assert_eq!(code(w.imported_key(Network::HederaEcdsa, 0)), "Argument");
    assert_eq!(code(w.imported_key(Network::Evm, 1)), "Argument");
    assert_eq!(code(w.import_native_key(Network::Evm, &[0xff; 32])), "Argument", "not a secp256k1 scalar");
    assert_eq!(code(w.import_native_key(Network::Stellar, &[1; 31])), "Argument");
    let s = w.import_native_key(Network::Stellar, &[1; 32]).unwrap();
    assert_eq!(s.network(), Network::Stellar);
    let m = w.manifest();
    assert_eq!(m.imports.iter().map(|i| (i.network, i.n)).collect::<Vec<_>>(), vec![(Network::Evm, 0), (Network::Stellar, 1)]);
}

/// An imported key goes into its own vault label `native-import:<network>:<n>` and comes back into another session of the
/// wallet; the manifest into `manifest`. A label the wallet does not hold: `Argument`.
#[test]
fn label_vaults_import_and_manifest() {
    let w = wallet("twelve_words");
    w.ua_key(0x0102, 0, 0).unwrap();
    let k = w.import_native_key(Network::Evm, &[3; 32]).unwrap();
    let vi = w.seal_label_vault("native-import:evm:0", "river-otter-7", None).unwrap();
    let vm = w.seal_label_vault("manifest", "river-otter-7", None).unwrap();
    assert_eq!(code(w.seal_label_vault("native-import:evm:1", "river-otter-7", None)), "Argument");
    assert_eq!(code(w.seal_label_vault("frost-share:00", "river-otter-7", None)), "Argument");
    assert_eq!(code(w.seal_label_vault("seed", "river-otter-7", None)), "Argument");
    let other = wallet("twelve_words");
    other.open_label_vault(&vm, Unlock::VaultPassphrase("river-otter-7")).unwrap();
    other.open_label_vault(&vi, Unlock::VaultPassphrase("river-otter-7")).unwrap();
    assert_eq!(other.imported_key(Network::Evm, 0).unwrap().public_key(), k.public_key());
    assert_eq!(other.manifest(), w.manifest());
    // the seed vault is not a label vault
    let vs = w.seal_vault("river-otter-7", None).unwrap();
    assert_eq!(code(other.open_label_vault(&vs, Unlock::VaultPassphrase("river-otter-7"))), "Argument");
}

// --- manifest and discovery (spec §8.3) ---

#[test]
fn manifest_records_first_use_and_survives_lock() {
    let w = wallet("pq_kat");
    let a = w.ua_key(0x0102, 0, 0).unwrap();
    w.ua_key(0x0102, 0, 0).unwrap();
    w.ua_key(0x0101, 1, 2).unwrap();
    w.native_key(Network::Evm, 3, None).unwrap();
    w.ua_key(0x0130, 0, 0).unwrap().kem_key(5).unwrap();
    w.add_backup_sender([4; 32]);
    let m = w.manifest();
    assert_eq!(
        m.entries.iter().map(|e| (e.kind, e.account, e.index)).collect::<Vec<_>>(),
        vec![(0x0102, 0, 0), (0x0101, 1, 2), (0x0130, 0, 0)]
    );
    assert_eq!(m.entries[0].ua, a.ua().unwrap());
    assert_eq!(m.natives.iter().map(|n| (n.network, n.index, n.coin_type)).collect::<Vec<_>>(), vec![(Network::Evm, 3, None)]);
    assert_eq!(m.kem.iter().map(|k| k.version).collect::<Vec<_>>(), vec![5]);
    assert_eq!(m.backup_senders, vec![[4; 32]]);
    assert_eq!(m.backup_generation, 0);
    let j = m.to_json();
    assert_eq!(scaas_ua::wallet::Manifest::from_json(j.as_bytes()).unwrap(), m);
    w.lock();
    assert_eq!(w.manifest(), m, "lock() keeps the manifest");
}

#[test]
fn discover_candidates_gap() {
    let w = wallet("pq_kat");
    let c = w.discover_candidates(0x0101, 1, 20).unwrap();
    assert_eq!(c.len(), 20);
    for (i, ua) in &c {
        assert_eq!(w.ua_key(0x0101, 1, *i).unwrap().ua(), Some(*ua));
    }
    assert_eq!(c.iter().map(|(i, _)| *i).collect::<Vec<_>>(), (0..20).collect::<Vec<_>>());
    for k in [0x0104, 0x0105, 0x0106, 0x0107] {
        let c = w.discover_candidates(k, 0, 20).unwrap();
        assert_eq!(c.len(), 1, "{k:#06x}: index 0 alone (EIP-2333)");
        assert_eq!(Some(c[0].1), w.ua_key(k, 0, 0).unwrap().ua());
    }
    assert_eq!(code(w.discover_candidates(0x0110, 0, 20)), "Argument", "a MuSig2 participant has no UA");
    assert_eq!(code(w.discover_candidates(0x0101, 1 << 31, 20)), "Argument");
    let fresh = wallet("pq_kat");
    fresh.discover_candidates(0x0101, 0, 5).unwrap();
    assert!(fresh.manifest().entries.is_empty(), "discovery writes nothing");
}

// --- SeedBackup (spec §8.4, CLI-SGN-11) ---

#[test]
fn seed_backup_shown_once_and_confirmed() {
    let (w, mut b) = Wallet::generate().unwrap();
    assert!(b.take().is_none(), "not before the words are confirmed");
    assert_eq!(code(b.challenge()), "Argument", "reveal first");
    let phrase = b.reveal().unwrap();
    let list: Vec<String> = phrase.split(' ').map(str::to_owned).collect();
    assert_eq!(list.len(), 24);
    assert_eq!(code(b.reveal()), "Argument", "shown once");
    let ask = b.challenge().unwrap();
    assert!(ask.iter().all(|i| (1..=24).contains(i)) && ask[0] < ask[1] && ask[1] < ask[2]);
    assert!(!b.verify(&["wrong", "words", "here"]).unwrap());
    assert!(b.take().is_none());
    let ask = b.challenge().unwrap();
    let answers: Vec<String> = ask.iter().map(|i| format!(" {} ", list[i - 1].to_uppercase())).collect();
    assert!(b.verify(&answers.iter().map(String::as_str).collect::<Vec<_>>()).unwrap());
    let e = b.take().unwrap();
    assert!(b.take().is_none());
    entropy_is(&w, &e);
    assert_eq!(bip39::Mnemonic::from_entropy(&e).unwrap().to_string(), *phrase);
}

// --- backup (spec §6.3, §8.4, C-03, C-11) ---

#[cfg(feature = "vectors")]
/// `BackupPayload` JSON, field order `{v, generation, entropy, secrets, manifest: {entries}}` (owner 2026-11-05): the
/// clientkeys payload of seal.json reads and writes back byte for byte; malformed payloads are `Argument`.
#[test]
fn backup_payload_json() {
    let s = load("seal.json");
    let pt = h(arr(&s, "containers")[0]["pt"].as_str().unwrap());
    assert_eq!(scaas_ua::wallet::vectors_backup_payload(&pt).unwrap().as_bytes(), &pt[..]);
    let good = String::from_utf8(pt.clone()).unwrap();
    for bad in [
        good.replace("\"v\":1", "\"v\":2"),
        good.replace("\"generation\":2", "\"generation\":-1"),
        good.replace("f39_f39_f39_f39_f39_fw", "f39_f39_f39_f39_f39_"),
        good.replace("\"manifest\":{\"entries\":", "\"manifest\":{\"entrees\":"),
        good.replace("0xc926", "0xC926"),
        good.replace("\"account\":0", "\"account\":2147483648"),
        good.replace("\"kind\":258", "\"kind\":65536"),
        good.replace("native-import:evm:0", "frost-share:x"),
        "[[[[[1]]]]]".into(),
        "not json".into(),
    ] {
        assert_eq!(code(scaas_ua::wallet::vectors_backup_payload(bad.as_bytes())), "Argument", "{bad}");
    }
}

/// seal.json's backup containers restore here: the 12-word wallet with its imported key; the restore refusals (another
/// registered UA's signature, an entropy that does not derive `sender.ua`) and the `replay` rollback rows, each `current` a
/// wallet that holds the row's UA at the row's generation.
#[test]
fn seal_json_restore_rows() {
    let s = load("seal.json");
    let (_o, kk) = opener();
    let c0 = &arr(&s, "containers")[0];
    let w = restore(&kk, &SealedContainer::from_json(c0["container"].to_string().as_bytes()).unwrap(), b32(&c0["expect"]["sender"]["ua"]), None, None, "")
        .unwrap()
        .unwrap();
    entropy_is(&w, &h("0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"));
    assert_eq!(w.manifest().backup_generation, 2);
    assert_eq!(w.manifest().imports.iter().map(|i| (i.network, i.n)).collect::<Vec<_>>(), vec![(Network::Evm, 0)]);
    assert!(w.imported_key(Network::Evm, 0).is_ok());
    let mut checked = 0;
    for r in arr(&s, "acceptance").iter().filter(|r| r["expect"]["purpose"] == PURPOSE_BACKUP && r["members"].is_null()) {
        checked += 1;
        let c = match SealedContainer::from_json(r["container"].to_string().as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                assert_eq!(e.code(), r["error"].as_str().unwrap(), "{}", r["id"]);
                continue;
            }
        };
        let e = &r["expect"];
        let set: Vec<[u8; 32]> = match e["sender"].get("ua") {
            Some(u) => vec![b32(u)],
            None => e["sender"]["set"].as_array().unwrap().iter().map(b32).collect(),
        };
        let rec = match e["recipient"].get("kemPkHash") {
            Some(k) => RecipientId::KemPkHash(b32(k)),
            None => RecipientId::Ua { ua: b32(&e["recipient"]["ua"]), version: num(&e["recipient"]["version"]) },
        };
        let x = ContainerExpect { purpose: PURPOSE_BACKUP, sender: ExpectedSender::Set(&set), recipient: rec };
        let o = &r["opener"]["kem"];
        let ow = wallet(o["mnemonic"].as_str().unwrap());
        let ok = ow.ua_key(num(&o["kind"]) as u16, num(&o["account"]) as u32, num(&o["index"]) as u32).unwrap().kem_key(num(&o["version"])).unwrap();
        let got = Wallet::restore_backup(&ok, &c, &x, &none, None, None, None, "");
        let want = r["error"].as_str().unwrap_or("ok");
        assert_eq!(code(got), want, "{}", r["id"]);
    }
    assert_eq!(checked, 12);
    let twelve = wallet("twelve_words");
    let key = twelve.ua_key(0x0102, 0, 0).unwrap();
    let rec = recipient_of(&kk);
    let mut rows = 0;
    for r in arr(&s, "replay").iter().filter(|r| r["kind"] == "backup") {
        let c = SealedContainer::from_json(r["container"].to_string().as_bytes()).unwrap();
        let cur = (!r["current"].is_null()).then(|| {
            let ua = b32(&r["current"]["ua"]);
            let w = if Some(ua) == key.ua() { wallet("twelve_words") } else { wallet("pq_kat") };
            let k = w.ua_key(0x0102, 0, 0).unwrap();
            assert_eq!(k.ua(), Some(ua));
            for _ in 0..num(&r["current"]["generation"]) {
                w.backup_seal(&k, std::slice::from_ref(&rec)).unwrap();
            }
            assert_eq!(w.manifest().backup_generation, num(&r["current"]["generation"]));
            w
        });
        let roll = r["allowRollback"].as_bool().unwrap_or(false).then_some(AllowRollback);
        let got = restore(&kk, &c, b32(&r["expect"]["sender"]["ua"]), cur.as_ref(), roll, "");
        match r["error"].as_str() {
            Some(e) => assert_eq!(code(got), e, "{}", r["id"]),
            None => assert_eq!(got.unwrap().is_some(), r["install"].as_bool().unwrap(), "{}", r["id"]),
        }
        rows += 1;
    }
    assert_eq!(rows, 6);
}

#[test]
fn backup_restores_manifest_and_secrets() {
    let w = wallet("twelve_words");
    let key = w.ua_key(0x0102, 0, 0).unwrap();
    w.ua_key(0x0101, 0, 1).unwrap();
    w.ua_key(0x0130, 0, 0).unwrap();
    let imp = w.import_native_key(Network::Solana, &[5; 32]).unwrap();
    let (_o, kk) = opener();
    assert_eq!(code(w.backup_seal(&key, &[])), "Argument");
    let other = wallet("pq_kat");
    assert_eq!(code(w.backup_seal(&other.ua_key(0x0102, 0, 0).unwrap(), &[recipient_of(&kk)])), "Argument", "another wallet's key");
    let c = w.backup_seal(&key, &[recipient_of(&kk), recipient_of(&kk)]).unwrap();
    assert_eq!(c.len(), 2);
    assert_eq!(c[0].purpose, PURPOSE_BACKUP);
    assert_eq!(w.manifest().backup_generation, 1);
    let r = restore(&kk, &c[1], key.ua().unwrap(), None, None, "").unwrap().unwrap();
    let (m, n) = (w.manifest(), r.manifest());
    assert_eq!(n.entries, m.entries);
    assert_eq!(n.imports, m.imports);
    assert_eq!(n.backup_generation, 1);
    assert_eq!(r.imported_key(Network::Solana, 0).unwrap().public_key(), imp.public_key());
    assert_eq!(r.ua_key(0x0101, 0, 1).unwrap().key_data(), w.ua_key(0x0101, 0, 1).unwrap().key_data());
    // the restored device seals the next generation
    let k2 = r.ua_key(0x0102, 0, 0).unwrap();
    r.backup_seal(&k2, &[recipient_of(&kk)]).unwrap();
    assert_eq!(r.manifest().backup_generation, 2);
    // a sender that is not the manifest's first entry: its own entry is the one derived
    let k3 = r.ua_key(0x0101, 0, 1).unwrap();
    let c3 = r.backup_seal(&k3, &[recipient_of(&kk)]).unwrap().remove(0);
    assert!(restore(&kk, &c3, k3.ua().unwrap(), None, None, "").unwrap().is_some());
}

#[test]
fn twelve_word_wallet_round_trips_vault_and_backup() {
    let (wd, _) = words("twelve_words");
    let w = Wallet::from_mnemonic(&wd, "").unwrap();
    let key = w.ua_key(0x0102, 0, 0).unwrap();
    let kem = keccak256(&w.ua_key(0x0130, 0, 0).unwrap().kem_key(0).unwrap().kem_pk());
    let v = w.seal_vault("river-otter-7", None).unwrap();
    let a = Wallet::open_vault(&v, Unlock::VaultPassphrase("river-otter-7"), "").unwrap();
    let (_o, kk) = opener();
    let c = w.backup_seal(&key, &[recipient_of(&kk)]).unwrap().remove(0);
    let b = restore(&kk, &c, key.ua().unwrap(), None, None, "").unwrap().unwrap();
    for x in [&a, &b] {
        entropy_is(x, &bip39::Mnemonic::parse(&wd).unwrap().to_entropy());
        assert_eq!(x.ua_key(0x0102, 0, 0).unwrap().ua(), key.ua());
        assert_eq!(keccak256(&x.ua_key(0x0130, 0, 0).unwrap().kem_key(0).unwrap().kem_pk()), kem);
    }
}

#[test]
fn older_backup_over_newer_refused_with_allow_rollback_accepted_equal_is_a_no_op() {
    let w = wallet("twelve_words");
    let key = w.ua_key(0x0102, 0, 0).unwrap();
    let ua = key.ua().unwrap();
    let (_o, kk) = opener();
    let rec = [recipient_of(&kk)];
    let c1 = w.backup_seal(&key, &rec).unwrap().remove(0);
    let c2 = w.backup_seal(&key, &rec).unwrap().remove(0);
    let d = restore(&kk, &c2, ua, None, None, "").unwrap().unwrap();
    assert_eq!(d.manifest().backup_generation, 2);
    // older_backup_over_newer_refused
    assert_eq!(code(restore(&kk, &c1, ua, Some(&d), None, "")), "BackupRollback");
    assert_eq!(code(restore(&kk, &c1, ua, Some(&w), None, "")), "BackupRollback");
    // with_AllowRollback_accepted
    let back = restore(&kk, &c1, ua, Some(&d), Some(AllowRollback), "").unwrap().unwrap();
    assert_eq!(back.manifest().backup_generation, 1);
    // equal_generation_is_a_no_op
    assert!(restore(&kk, &c2, ua, Some(&d), None, "").unwrap().is_none());
    assert!(restore(&kk, &c2, ua, Some(&w), None, "").unwrap().is_none());
    // newer over older, any over a device without this wallet
    assert!(restore(&kk, &c2, ua, Some(&back), None, "").unwrap().is_some());
    let other = wallet("pq_kat");
    other.ua_key(0x0102, 0, 0).unwrap();
    assert!(restore(&kk, &c1, ua, Some(&other), None, "").unwrap().is_some());
    // a locked current wallet keeps its manifest: the rollback check still holds
    d.lock();
    assert_eq!(code(restore(&kk, &c1, ua, Some(&d), None, "")), "BackupRollback");
}

#[test]
fn backup_signed_by_another_registered_ua_refused() {
    let a = wallet("twelve_words");
    let b = wallet("pq_kat");
    let ka = a.ua_key(0x0102, 0, 0).unwrap();
    let kb = b.ua_key(0x0102, 0, 0).unwrap();
    let (_o, kk) = opener();
    let c = a.backup_seal(&ka, &[recipient_of(&kk)]).unwrap().remove(0);
    assert_eq!(code(restore(&kk, &c, kb.ua().unwrap(), None, None, "")), "ContainerSender");
    assert!(restore(&kk, &c, ka.ua().unwrap(), None, None, "").is_ok());
    let s = load("seal.json");
    let r = arr(&s, "acceptance").iter().find(|r| r["id"] == "signed by a different registered UA").unwrap();
    let c = SealedContainer::from_json(r["container"].to_string().as_bytes()).unwrap();
    assert_eq!(code(restore(&kk, &c, b32(&r["expect"]["sender"]["ua"]), None, None, "")), "ContainerSender");
}

#[test]
fn backup_whose_entropy_does_not_derive_sender_refused() {
    let s = load("seal.json");
    let (_o, kk) = opener();
    let r = arr(&s, "acceptance").iter().find(|r| r["id"] == "backup entropy that does not derive sender.ua").unwrap();
    let c = SealedContainer::from_json(r["container"].to_string().as_bytes()).unwrap();
    let ua = b32(&r["expect"]["sender"]["ua"]);
    assert_eq!(code(restore(&kk, &c, ua, None, None, "")), "ContainerSender");
    // the container itself opens (the check is after decryption, before install)
    let set = [ua];
    assert!(kk.open_container(&c, &expect_of(&set, &kk), &none, None).is_ok());
    // a restore opens scaas/backup/v1 only
    let x = ContainerExpect { purpose: "scaas/link/v1", sender: ExpectedSender::Ua(ua), recipient: kk.recipient() };
    assert_eq!(code(Wallet::restore_backup(&kk, &c, &x, &none, None, None, None, "")), "Argument");
}

#[cfg(feature = "vectors")]
/// The link payload installs the manifest and the secrets too (the same `BackupPayload`).
#[test]
fn link_installs_manifest_and_secrets() {
    let s = load("seal.json");
    let l = &arr(&s, "containers")[1];
    let o = &l["opener"]["session"];
    let session = scaas_ua::wallet::LinkSession::vectors_new(
        &h(o["seed"].as_str().unwrap()).try_into().unwrap(),
        o["shortCode"].as_str().unwrap(),
        num(&o["start"]),
    )
    .unwrap();
    let c = SealedContainer::from_json(l["container"].to_string().as_bytes()).unwrap();
    let x = ContainerExpect { purpose: "scaas/link/v1", sender: ExpectedSender::Ua(b32(&l["expect"]["sender"]["ua"])), recipient: session.recipient() };
    let w = Wallet::from_link(session, &c, &x, &none, None, "").unwrap();
    let payload: Value = serde_json::from_slice(&h(l["pt"].as_str().unwrap())).unwrap();
    let entries = arr(&payload["manifest"], "entries");
    assert_eq!(w.manifest().entries.len(), entries.len());
    assert_eq!(w.manifest().entries[0].ua, b32(&entries[0]["ua"]));
    assert_eq!(w.manifest().imports.len(), arr(&payload, "secrets").len());
    assert_eq!(w.manifest().backup_generation, num(&payload["generation"]));
}

/// Test-only writer of the both-ways fixture (MD-7).
#[cfg(feature = "vectors")]
mod regen {
    use super::*;

    /// Writes rs_vault.json: vaults sealed by ua-rs (24 and 12 words, a PRF envelope, a rewrapped pin) and a backup container
    /// of ua-rs (`backup_seal`, with an imported key); clientkeys `npm test` opens each. A row that still opens is kept, so a
    /// second run leaves the file unchanged. `cargo test --features vectors --test wallet_vault -- --ignored regenerate`
    #[test]
    #[ignore]
    fn regenerate() {
        let old = std::fs::read_to_string(path("rs_vault.json")).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok());
        let kept = |sec: &str, id: &str| -> Option<Value> {
            let r = arr(old.as_ref()?, sec).iter().find(|r| r["id"] == id)?.clone();
            Some(r)
        };
        let pin = "river-otter-7 ünï";
        let prf_out = [0x5a; 32];
        let mut vaults = Vec::new();
        for (id, mn) in [("ua-rs 24 words", "pq_kat"), ("ua-rs 12 words", "twelve_words"), ("ua-rs PRF envelope", "pq_kat"), ("ua-rs rewrapped pin", "twelve_words")] {
            let w = wallet(mn);
            let entropy = format!("0x{}", hex::encode(&*w.vectors_entropy().unwrap()));
            let unlock = if id.contains("PRF") {
                serde_json::json!({"prfOutput": format!("0x{}", hex::encode(prf_out))})
            } else {
                serde_json::json!({"pin": pin})
            };
            let still = kept("vaults", id).filter(|r| {
                r["plaintext"] == entropy.as_str()
                    && vault(&r["vault"]).ok().and_then(|v| with_unlock(&r["unlock"], |u| Wallet::open_vault(&v, u, "").ok())).is_some()
            });
            let row = still.unwrap_or_else(|| {
                let v = match id {
                    "ua-rs PRF envelope" => {
                        let p = PrfEnvelope { output: &prf_out, credential_id: "ua-rs-credential", salt: &[0x33; 32] };
                        w.seal_vault(pin, Some(&p)).unwrap()
                    }
                    "ua-rs rewrapped pin" => w.seal_vault("old passphrase 1", None).unwrap().rewrap_pin("old passphrase 1", pin).unwrap(),
                    _ => w.seal_vault(pin, None).unwrap(),
                };
                let vj: Value = serde_json::from_str(&v.to_json()).unwrap();
                serde_json::json!({"id": id, "mnemonic": mn, "vault": vj, "unlock": unlock, "plaintext": entropy})
            });
            vaults.push(row);
        }
        let (_o, kk) = opener();
        let id = "ua-rs backup, 12 words, an imported evm key";
        let w = wallet("twelve_words");
        let key = w.ua_key(0x0102, 0, 0).unwrap();
        let sender = key.ua().unwrap();
        let still = kept("backups", id).filter(|r| {
            SealedContainer::from_json(r["container"].to_string().as_bytes())
                .ok()
                .and_then(|c| restore(&kk, &c, sender, None, None, "").ok().flatten())
                .is_some()
        });
        let backup = still.unwrap_or_else(|| {
            w.import_native_key(Network::Evm, &h("0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")).unwrap();
            let c = w.backup_seal(&key, &[recipient_of(&kk)]).unwrap().remove(0);
            let cj: Value = serde_json::from_str(&c.to_json()).unwrap();
            serde_json::json!({
                "id": id, "container": cj, "senderUa": format!("0x{}", hex::encode(sender)),
                "sender": {"mnemonic": "twelve_words", "kind": 0x0102, "account": 0, "index": 0},
                "opener": {"kem": {"mnemonic": "pq_kat", "kind": 0x0130, "account": 0, "index": 0, "version": 0}},
                "entropy": format!("0x{}", hex::encode(&*w.vectors_entropy().unwrap())), "generation": 1,
                "secrets": ["native-import:evm:0"],
            })
        });
        let out = serde_json::json!({
            "note": "Written by clients/ua-rs (tests/wallet_vault.rs, `cargo test --features vectors --test wallet_vault -- --ignored \
                     regenerate`; ua-rs-sign T9, MD-7); never edit by hand. Vaults sealed by ua-rs (Wallet::seal_vault: label seed, \
                     the BIP-39 entropy at its own length, scrypt N = 2^17, r = 8, p = 1, AES-256-GCM, AAD label|data / label|pin / \
                     label|prf; a PRF envelope by Vault::enable_prf's HKDF; a pin envelope replaced by rewrap_pin) and a backup \
                     container of Wallet::backup_seal (BackupPayload {v, generation, entropy, secrets, manifest: {entries}}, \
                     sealed to the opener's KEM key, signed by the sender's UA key); read by clientkeys (test/vault.test.js \
                     openSeedVault, test/seal.test.js restoreBackup), so a format both crates read the same wrong way cannot pass \
                     one-sided. A re-run keeps every row that still opens.",
            "vaults": vaults,
            "backups": [backup],
        });
        std::fs::write(path("rs_vault.json"), serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
    }
}
