// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T12 follow-ups (owner 2026-11-06): the existing device's link seal ([`Wallet::link_seal`]: the full payload, entropy,
//! imported keys, manifest entries and generation, purpose `scaas/link/v1`, the session's short code in the `aad`, as
//! [`Wallet::from_link`] opens it; byte-equal to clientkeys' link container of seal.json at its `created`, `m` and `e`), and the
//! `members_json` cap (512 KiB, depth 4, at most 64 UAs). UNAUDITED.
use scaas_ua::wallet::{ContainerExpect, Error, ExpectedSender, LinkSession, MembersJson, Network, SealedContainer, UaKey, Wallet};
use serde_json::Value;

fn load(f: &str) -> Value {
    let p = format!("{}/../../smartcontracts/vectors/ua/{f}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn wallet(id: &str) -> Wallet {
    let k = load("keys.json");
    let m = k["mnemonics"].as_array().unwrap().iter().find(|m| m["id"] == id).unwrap().clone();
    Wallet::from_mnemonic(m["words"].as_str().unwrap(), m["passphrase"].as_str().unwrap()).unwrap()
}
fn expect<'a>(key: &UaKey, session: &LinkSession) -> ContainerExpect<'a> {
    ContainerExpect { purpose: "scaas/link/v1", sender: ExpectedSender::Ua(key.ua().unwrap()), recipient: session.recipient() }
}
fn none(_: [u8; 32]) -> Option<(u16, Vec<u8>)> {
    None
}
fn reread(c: &SealedContainer) -> SealedContainer {
    SealedContainer::from_json(c.to_json().as_bytes()).unwrap()
}

#[test]
fn link_seal_then_from_link_installs() {
    let w = wallet("twelve_words");
    let key = w.ua_key(0x0102, 0, 0).unwrap();
    let imported = w.import_native_key(Network::Evm, &[7; 32]).unwrap();
    let session = LinkSession::new().unwrap();
    let x = expect(&key, &session);
    let c = w.link_seal(&key, &session.kem_pk(), &session.short_code()).unwrap();
    assert_eq!(c.purpose, "scaas/link/v1");
    assert_eq!(c.recipient, session.recipient());
    let linked = Wallet::from_link(session, &reread(&c), &x, &none, None, "").unwrap();
    assert_eq!(linked.ua_key(0x0102, 0, 0).unwrap().ua(), key.ua());
    assert_eq!(linked.imported_key(Network::Evm, 0).unwrap().public_key(), imported.public_key(), "the imported key travels");
    assert_eq!(linked.manifest().entries, w.manifest().entries);
    assert_eq!(linked.manifest().imports, w.manifest().imports);
    assert_eq!(linked.manifest().backup_generation, w.manifest().backup_generation, "a link raises no generation");
}

#[test]
fn link_seal_with_a_wrong_short_code_is_refused() {
    let w = wallet("twelve_words");
    let key = w.ua_key(0x0102, 0, 0).unwrap();
    let session = LinkSession::new().unwrap();
    let wrong = if session.short_code() == "00000000" { "00000001" } else { "00000000" };
    let x = expect(&key, &session);
    let c = w.link_seal(&key, &session.kem_pk(), wrong).unwrap();
    assert_eq!(Wallet::from_link(session, &reread(&c), &x, &none, None, "").err(), Some(Error::SealOpen));
}

#[test]
fn link_seal_takes_a_container_key_of_this_wallet() {
    let w = wallet("twelve_words");
    let session = LinkSession::new().unwrap();
    let (pk, code) = (session.kem_pk(), session.short_code());
    assert!(w.link_seal(&w.ua_key(0x0102, 0, 0).unwrap(), &pk, &code).is_ok(), "positive control");
    let other = wallet("pq_kat");
    assert_eq!(w.link_seal(&other.ua_key(0x0102, 0, 0).unwrap(), &pk, &code).err(), Some(Error::Argument), "another wallet's key");
    assert_eq!(w.link_seal(&w.ua_key(0x0110, 0, 0).unwrap(), &pk, &code).err(), Some(Error::Argument), "a MuSig2 participant");
    assert_eq!(w.link_seal(&w.ua_key(0x0102, 0, 0).unwrap(), &pk[..1600], &code).err(), Some(Error::KemCheck), "a short kemPk");
    assert_eq!(w.link_seal(&w.ua_key(0x0102, 0, 0).unwrap(), &pk, "").err(), Some(Error::Argument), "no short code");
    let key = w.ua_key(0x0102, 0, 0).unwrap();
    w.lock();
    assert_eq!(w.link_seal(&key, &pk, &code).err(), Some(Error::WalletLocked));
}

/// The members JSON of a container open (spec §9.3; owner 2026-11-06: 16 KiB -> 512 KiB): 64 ML-DSA-87 members fit, a 65th UA
/// does not.
#[test]
fn members_json_holds_64_mldsa87_members_and_no_more() {
    let members = |n: usize| {
        let entries: Vec<String> = (0..n)
            .map(|i| format!("\"0x{:064x}\":{{\"kind\":{},\"keyData\":\"0x{}\"}}", i + 1, 0x0134, "ab".repeat(2592)))
            .collect();
        format!("{{{}}}", entries.join(","))
    };
    let j = members(64);
    assert!(j.len() > 16 << 10 && j.len() <= 512 << 10, "{}", j.len());
    let m = MembersJson::from_json(j.as_bytes()).unwrap();
    let mut id = [0u8; 32];
    id[31] = 64;
    assert_eq!(m.lookup(id).map(|(k, d)| (k, d.len())), Some((0x0134, 2592)));
    assert_eq!(MembersJson::from_json(members(65).as_bytes()).err(), Some(Error::Argument), "65 UAs");
}

#[cfg(feature = "vectors")]
mod vectors {
    use super::*;
    use scaas_ua::wallet::LINK_WINDOW;

    fn h(v: &Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
    }

    #[test]
    #[allow(non_snake_case)]
    fn link_seal_outside_the_window_is_ContainerReplay() {
        let w = wallet("twelve_words");
        let key = w.ua_key(0x0102, 0, 0).unwrap();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let stale = LinkSession::vectors_new(&[9; 96], "12345678", now - LINK_WINDOW - 5).unwrap();
        let x = expect(&key, &stale);
        let c = w.link_seal(&key, &stale.kem_pk(), &stale.short_code()).unwrap();
        assert_eq!(Wallet::from_link(stale, &reread(&c), &x, &none, None, "").err(), Some(Error::ContainerReplay));
    }

    /// The wallet restored from seal.json's generation-2 backup holds exactly the link row's payload (its entropy, imported key,
    /// entry, generation 2): its link seal at the row's `created`, `m` and `e` is clientkeys' link container byte for byte.
    #[test]
    fn link_seal_equals_clientkeys_link_row() {
        let s = load("seal.json");
        let rows = s["containers"].as_array().unwrap();
        let (backup, link) = (&rows[0], &rows[1]);
        let k = &backup["opener"]["kem"];
        let r = wallet(k["mnemonic"].as_str().unwrap());
        let kk = r.ua_key(k["kind"].as_u64().unwrap() as u16, k["account"].as_u64().unwrap() as u32, k["index"].as_u64().unwrap() as u32).unwrap().kem_key(k["version"].as_u64().unwrap()).unwrap();
        let ua: [u8; 32] = h(&backup["expect"]["sender"]["ua"]).try_into().unwrap();
        let bx = ContainerExpect { purpose: "scaas/backup/v1", sender: ExpectedSender::Ua(ua), recipient: kk.recipient() };
        let bc = SealedContainer::from_json(backup["container"].to_string().as_bytes()).unwrap();
        let w = Wallet::restore_backup(&kk, &bc, &bx, &none, None, None, None, "").unwrap().unwrap();
        let o = &link["opener"]["session"];
        let session = LinkSession::vectors_new(&h(&o["seed"]).try_into().unwrap(), o["shortCode"].as_str().unwrap(), o["start"].as_u64().unwrap()).unwrap();
        let key = w.ua_key(0x0102, 0, 0).unwrap();
        let (m, e): ([u8; 32], [u8; 32]) = (h(&link["m"]).try_into().unwrap(), h(&link["e"]).try_into().unwrap());
        let c = w
            .vectors_link_seal(&key, &session.kem_pk(), &session.short_code(), link["container"]["created"].as_u64().unwrap(), &m, &e)
            .unwrap();
        assert_eq!(serde_json::from_str::<Value>(&c.to_json()).unwrap(), link["container"]);
    }
}
