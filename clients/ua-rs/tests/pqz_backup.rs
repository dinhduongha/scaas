// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T16a (owner 2026-11-06): the k-of-n backup of an `msig` holder's PQZ `seed32` (`facade::pqz_backup`). The operator
//! deals Shamir shares of `seed32` only, each sealed to one member's own single-key UA KEM key; any k rebuild the key, which must
//! hash to the registered `pqzKeyHash`, and the one who rebuilds holds it; k − 1 shares, a share of another `msig`, key or
//! version, mixed headers and repeated indices are refused before the shares are combined; a share carries no wallet entropy;
//! a missing backup is a warning, never a refusal. Under feature `vectors` the field and the split are pinned by known answers
//! computed by an independent implementation (exp / log tables). T16b (owner 2026-11-06): the rebuilt key persists in the
//! rebuilder's `pqz-held:` vault, manifest and backup, and is checked against `pqzKeyHash` when reopened. UNAUDITED.
#![allow(non_snake_case)]
use scaas_ua::facade::pqz::PqzKey;
use scaas_ua::facade::pqz_backup::{seed_backup_warning, PqzSeedBackup, PURPOSE_PQZ_SHARE, SEED_BACKUP_MISSING};
use scaas_ua::ua8::{MsigMember, MsigStructure};
use scaas_ua::wallet::{
    ContainerExpect, Error, ExpectedSender, KemKeyPair, Manifest, Recipient, SealedContainer, UaKey, Unlock, Vault, Wallet,
    PURPOSE_BACKUP,
};
use serde_json::Value;

/// Feature `vectors` (Codex C1, T15c2): key handles only after the test-only marker; every test here unlocks first.
fn unlock() {
    #[cfg(feature = "vectors")]
    scaas_ua::facade::vectors_unlock(scaas_ua::facade::TestOnly);
}

fn none(_: [u8; 32]) -> Option<(u16, Vec<u8>)> {
    None
}

const WORDS: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const PQ: u16 = 0x0130;
const MSIG: u16 = 0x0120;

/// The operator, three members (0x0130 UAs with KEM keys) and the `msig` of the three, threshold `t`.
struct Group {
    op: Wallet,
    op_key: UaKey,
    pqz: PqzKey,
    members: Vec<(Wallet, UaKey, KemKeyPair)>,
    msig_kd: Vec<u8>,
    msig_ua: [u8; 32],
}

fn group(t: u16) -> Group {
    let op = Wallet::from_mnemonic(WORDS, "").unwrap();
    let op_key = op.ua_key(PQ, 0, 0).unwrap();
    let pqz = op.pqz_key(7, 0).unwrap();
    let mut members: Vec<_> = (0..3)
        .map(|_| {
            let w = Wallet::generate().unwrap().0;
            let k = w.ua_key(PQ, 0, 0).unwrap();
            let kk = k.kem_key(0).unwrap();
            (w, k, kk)
        })
        .collect();
    members.sort_by_key(|(_, k, _)| k.ua().unwrap()); // CTR-UA-09: members in id order
    let st = MsigStructure {
        threshold: t,
        members: members.iter().map(|(_, k, _)| MsigMember { kind: PQ, id: k.ua().unwrap(), weight: 1 }).collect(),
    };
    let msig_kd = st.key_data();
    let msig_ua = scaas_ua::derive_ua(MSIG, &msig_kd, false).unwrap();
    Group { op, op_key, pqz, members, msig_kd, msig_ua }
}

impl Group {
    fn recipient(&self, i: usize) -> Recipient {
        let (_, k, kk) = &self.members[i];
        Recipient::ua(PQ, &k.key_data(), 0, &kk.kem_pk()).unwrap()
    }
    fn recipients(&self) -> Vec<Recipient> {
        (0..3).map(|i| self.recipient(i)).collect()
    }
    fn key_hash(&self) -> [u8; 32] {
        scaas_ua::key_hash_of(scaas_ua::PQZ_SCHEME, &self.pqz.pk()).unwrap().unwrap()
    }
    fn deal(&self, k: Option<u8>) -> PqzSeedBackup {
        self.pqz.seal_seed_backup(&self.op_key, &self.msig_kd, 0, k, &self.recipients()).unwrap()
    }
    /// The senders a share container may come from: the operator and the members.
    fn senders(&self) -> Vec<[u8; 32]> {
        std::iter::once(self.op_key.ua().unwrap()).chain(self.members.iter().map(|(_, k, _)| k.ua().unwrap())).collect()
    }
    /// Share `i` of `b` as member 0 (who rebuilds) receives it: its own as dealt, another member's sealed on by that member.
    fn to_rebuilder(&self, b: &PqzSeedBackup, i: usize) -> SealedContainer {
        let c = &b.shares[i];
        if i == 0 {
            return c.clone();
        }
        let (_, k, kk) = &self.members[i];
        let set = self.senders();
        let e = ContainerExpect { purpose: PURPOSE_PQZ_SHARE, sender: ExpectedSender::Set(&set), recipient: kk.recipient() };
        kk.reseal_pqz_share(c, &e, &none, None, &self.recipient(0), k).unwrap()
    }
    fn rebuild(&self, cs: &[SealedContainer], msig_ua: &[u8; 32], version: u64, kh: &[u8; 32]) -> Result<PqzKey, Error> {
        let (w, _, kk) = &self.members[0];
        let set = self.senders();
        let e = ContainerExpect { purpose: PURPOSE_PQZ_SHARE, sender: ExpectedSender::Set(&set), recipient: kk.recipient() };
        w.reconstruct_pqz_seed(kk, cs, &e, &none, None, msig_ua, version, kh)
    }
}

/// `f` is refused with `Argument` before the shares are combined (feature `vectors`: the combine counter; without it the
/// refusal alone: the key-hash check would also refuse a wrong combination, which hides the earlier checks).
fn refused_before_combining<T>(what: &str, f: impl FnOnce() -> Result<T, Error>) {
    #[cfg(feature = "vectors")]
    let before = scaas_ua::facade::pqz_backup::vectors_combined();
    assert_eq!(f().err(), Some(Error::Argument), "{what}");
    #[cfg(feature = "vectors")]
    assert_eq!(scaas_ua::facade::pqz_backup::vectors_combined(), before, "{what}: refused before combining");
}

/// k of n shares (every pair of a 2-of-3) rebuild a key of the registered `pqzKeyHash`, held by the rebuilder's wallet: it
/// opens what the operator's key sealed (its balance-cache box), its lock revokes it, and the new operator can deal new shares of it.
#[test]
fn k_shares_rebuild_a_key_matching_pqzKeyHash() {
    unlock();
    let g = group(2);
    let b = g.deal(None);
    assert_eq!((b.header.k, b.header.n, b.header.version, b.header.msig_ua), (2, 3, 0, g.msig_ua), "k = the threshold, n = 3");
    assert_eq!(b.header.pqz_key_hash, g.key_hash());
    let cs: Vec<SealedContainer> = (0..3).map(|i| g.to_rebuilder(&b, i)).collect();
    for (i, j) in [(0, 1), (0, 2), (1, 2)] {
        let k = g.rebuild(&[cs[i].clone(), cs[j].clone()], &g.msig_ua, 0, &g.key_hash()).unwrap();
        assert_eq!(k.pk(), g.pqz.pk(), "shares {i}, {j}");
        assert_eq!((k.account(), k.index()), (u32::MAX, u32::MAX));
    }
    let k = g.rebuild(&cs, &g.msig_ua, 0, &g.key_hash()).unwrap(); // all three
    assert_eq!(decrypts(&g, &k).unwrap(), 4242, "the new operator sees the balance");
    let again = k.seal_seed_backup(&g.members[0].1, &g.msig_kd, 0, None, &g.recipients()).unwrap();
    assert!(again.covers(&g.msig_ua, 0, &g.key_hash()), "the new operator deals new shares of the same key");
    g.members[0].0.lock();
    assert_eq!(decrypts(&g, &k).err(), Some(Error::KeyRevoked));
    drop(g.op);
}

/// k − 1 shares are refused (2-of-3 and 3-of-3), before combining; the positive control first.
#[test]
fn k_minus_1_shares_refused() {
    unlock();
    for t in [2u16, 3] {
        let g = group(t);
        let b = g.deal(None);
        let cs: Vec<SealedContainer> = (0..3).map(|i| g.to_rebuilder(&b, i)).collect();
        let k = usize::from(t);
        assert!(g.rebuild(&cs[..k], &g.msig_ua, 0, &g.key_hash()).is_ok(), "control: k = {k}");
        refused_before_combining(&format!("k − 1 of k = {k}"), || g.rebuild(&cs[..k - 1], &g.msig_ua, 0, &g.key_hash()));
        refused_before_combining("no share", || g.rebuild(&[], &g.msig_ua, 0, &g.key_hash()));
    }
}

/// A share of another `msig`, key or version is refused: the expected header must be the share's (each change alone), shares
/// of two backups do not mix, an index given twice counts once, and the rebuilt key must hash to the registered one.
#[test]
fn a_share_for_another_msig_key_or_version_refused() {
    unlock();
    let g = group(2);
    let b = g.deal(None);
    let cs: Vec<SealedContainer> = (0..3).map(|i| g.to_rebuilder(&b, i)).collect();
    let pair = [cs[0].clone(), cs[1].clone()];
    assert!(g.rebuild(&pair, &g.msig_ua, 0, &g.key_hash()).is_ok(), "control");
    let mut other = g.msig_ua;
    other[0] ^= 1;
    refused_before_combining("another msig", || g.rebuild(&pair, &other, 0, &g.key_hash()));
    refused_before_combining("another version", || g.rebuild(&pair, &g.msig_ua, 1, &g.key_hash()));
    let mut kh = g.key_hash();
    kh[31] ^= 1;
    refused_before_combining("another key hash", || g.rebuild(&pair, &g.msig_ua, 0, &kh));
    refused_before_combining("an index twice", || g.rebuild(&[cs[0].clone(), cs[0].clone()], &g.msig_ua, 0, &g.key_hash()));
    // a second backup of another key of the same msig (another index of the operator): its shares do not mix with the first's
    let pqz2 = g.op.pqz_key(7, 1).unwrap();
    let b2 = pqz2.seal_seed_backup(&g.op_key, &g.msig_kd, 0, None, &g.recipients()).unwrap();
    let c2 = g.to_rebuilder(&b2, 1);
    let kh2 = scaas_ua::key_hash_of(scaas_ua::PQZ_SCHEME, &pqz2.pk()).unwrap().unwrap();
    assert!(g.rebuild(&[cs[0].clone(), c2.clone()], &g.msig_ua, 0, &g.key_hash()).is_err(), "mixed: first header expected");
    refused_before_combining("mixed keys", || g.rebuild(&[cs[0].clone(), c2.clone()], &g.msig_ua, 0, &g.key_hash()));
    refused_before_combining("mixed keys, the second's hash", || g.rebuild(&[c2.clone(), cs[0].clone()], &g.msig_ua, 0, &kh2));
    // another version of the same key: the header binds it
    let bv = g.pqz.seal_seed_backup(&g.op_key, &g.msig_kd, 1, None, &g.recipients()).unwrap();
    let cv = g.to_rebuilder(&bv, 1);
    refused_before_combining("mixed versions", || g.rebuild(&[cs[0].clone(), cv.clone()], &g.msig_ua, 0, &g.key_hash()));
    // the key-hash check alone: a share whose index is right but whose value is another backup's (same header otherwise)
    let b3 = g.deal(None); // fresh coefficients, same header
    let c3 = g.to_rebuilder(&b3, 1);
    assert_eq!(g.rebuild(&[cs[0].clone(), c3], &g.msig_ua, 0, &g.key_hash()).err(), Some(Error::Argument), "points of two polynomials");
}

/// A share container carries exactly the header and 32 bytes of the share: no wallet entropy, no `seed32` (k ≥ 2).
#[test]
fn shares_never_carry_wallet_entropy() {
    unlock();
    let g = group(2);
    let b = g.deal(None);
    let seed32 = g.op.export_pqz_leaf_raw(7, 0, scaas_ua::facade::pqz::AllowSecretExport).unwrap();
    #[cfg(feature = "vectors")]
    let entropy = g.op.vectors_entropy().unwrap().to_vec();
    #[cfg(not(feature = "vectors"))]
    let entropy = vec![0x7fu8; 16]; // the phrase's entropy: legal winner thank … = 0x7f × 16
    let set = g.senders();
    for (i, c) in b.shares.iter().enumerate() {
        assert_eq!(c.purpose, PURPOSE_PQZ_SHARE);
        let (_, _, kk) = &g.members[i];
        let e = ContainerExpect { purpose: PURPOSE_PQZ_SHARE, sender: ExpectedSender::Set(&set), recipient: kk.recipient() };
        let pt = kk.open_container(c, &e, &none, None).unwrap();
        let v: Value = serde_json::from_slice(&pt).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["index", "k", "msigUa", "n", "pqzKeyHash", "share", "v", "version"]);
        assert_eq!(v["index"], i as u64 + 1);
        let share = hex::decode(v["share"].as_str().unwrap().trim_start_matches("0x")).unwrap();
        assert_eq!(share.len(), 32);
        assert_ne!(share, seed32.to_vec(), "k = 2: a share is not the seed");
        let text = String::from_utf8(pt.to_vec()).unwrap();
        for secret in [hex::encode(&entropy), hex::encode(*seed32)] {
            assert!(!text.contains(&secret), "share {i} carries a secret");
        }
        assert!(pt.len() < 400, "{} B", pt.len());
    }
}

/// The recipients: each a direct member, distinct, by its own single-key UA KEM key (MD-11: an `msig` holds none); k in 1..=n.
#[test]
fn recipients_and_k_checked() {
    unlock();
    let g = group(2);
    let ok = |k, rs: &[Recipient]| g.pqz.seal_seed_backup(&g.op_key, &g.msig_kd, 0, k, rs).map(|b| (b.header.k, b.header.n));
    assert_eq!(ok(None, &g.recipients()), Ok((2, 3)), "control");
    assert_eq!(ok(Some(1), &g.recipients()), Ok((1, 3)));
    assert_eq!(ok(Some(3), &g.recipients()), Ok((3, 3)));
    assert_eq!(ok(Some(0), &g.recipients()).err(), Some(Error::Argument));
    assert_eq!(ok(Some(4), &g.recipients()).err(), Some(Error::Argument));
    assert_eq!(ok(None, &g.recipients()[..1]).err(), Some(Error::Argument), "k = 2 > n = 1");
    assert_eq!(ok(None, &[]).err(), Some(Error::Argument));
    assert_eq!(ok(None, &[g.recipient(0), g.recipient(1), g.recipient(0)]).err(), Some(Error::Argument), "a member twice");
    let ow = Wallet::generate().unwrap().0;
    let outsider = ow.ua_key(PQ, 0, 0).unwrap();
    let r = Recipient::ua(PQ, &outsider.key_data(), 0, &outsider.kem_key(0).unwrap().kem_pk()).unwrap();
    assert_eq!(ok(None, &[g.recipient(0), r]).err(), Some(Error::Argument), "not a member");
    let eph = Recipient::ephemeral(&g.members[1].2.kem_pk());
    assert_eq!(ok(None, &[g.recipient(0), eph]).err(), Some(Error::Argument), "an ephemeral key");
    assert_eq!(Recipient::ua(MSIG, &g.msig_kd, 0, &g.members[0].2.kem_pk()).err(), Some(Error::KemHolder), "MD-11");
    assert_eq!(ok(None, &[]).err(), Some(Error::Argument));
}

/// A missing backup warns and never refuses (owner 2026-11-06): the `setPqzKey` arguments of the `msig` build while the warning
/// stands; a backup of the key at that version clears it, one of another version or key does not; a single key never warns.
#[test]
fn a_missing_backup_warns_and_never_refuses() {
    unlock();
    let g = group(2);
    let pk = g.pqz.pk();
    assert_eq!(seed_backup_warning(MSIG, &g.msig_ua, 0, &pk, &[]), Some(SEED_BACKUP_MISSING));
    let args = format!(
        "{{\"ua\":\"0x{}\",\"pqzKey\":\"0x{}\",\"pqzPopHash\":\"0x{}\",\"sig\":{{\"keyData\":\"0x{}\",\"signature\":\"0x\",\"members\":[]}}}}",
        hex::encode(g.msig_ua),
        hex::encode(&pk),
        hex::encode([0x11; 32]),
        hex::encode(&g.msig_kd)
    );
    assert!(scaas_ua::json::set_pqz_key_args_json(&args).is_ok(), "setPqzKey still builds without a backup");
    let b = g.deal(None);
    assert_eq!(seed_backup_warning(MSIG, &g.msig_ua, 0, &pk, std::slice::from_ref(&b)), None);
    assert_eq!(seed_backup_warning(MSIG, &g.msig_ua, 1, &pk, std::slice::from_ref(&b)), Some(SEED_BACKUP_MISSING), "another version");
    let mut other = g.msig_ua;
    other[0] ^= 1;
    assert_eq!(seed_backup_warning(MSIG, &other, 0, &pk, std::slice::from_ref(&b)), Some(SEED_BACKUP_MISSING), "another msig");
    let pk2 = g.op.pqz_key(7, 1).unwrap().pk();
    assert_eq!(seed_backup_warning(MSIG, &g.msig_ua, 0, &pk2, std::slice::from_ref(&b)), Some(SEED_BACKUP_MISSING), "another key");
    let mut short = b.clone();
    short.shares.pop();
    assert_eq!(seed_backup_warning(MSIG, &g.msig_ua, 0, &pk, &[short]), Some(SEED_BACKUP_MISSING), "a share missing");
    assert_eq!(seed_backup_warning(PQ, &g.members[0].1.ua().unwrap(), 0, &pk, &[]), None, "a single key needs none");
    // the record round-trips through its JSON; a malformed one is Argument
    let j = b.to_json();
    assert_eq!(PqzSeedBackup::from_json(j.as_bytes()).unwrap(), b);
    assert_eq!(PqzSeedBackup::from_json(j.replace("\"k\":2", "\"k\":4").as_bytes()).err(), Some(Error::Argument), "k > n");
    assert_eq!(PqzSeedBackup::from_json(j.replace("\"n\":3", "\"n\":2").as_bytes()).err(), Some(Error::Argument), "n ≠ shares");
}

/// A share is sealed on only from a share container: a container of another purpose is `Argument`.
#[test]
fn reseal_takes_share_containers_only() {
    unlock();
    let g = group(2);
    let (_, k1, kk1) = &g.members[1];
    let set = g.senders();
    let e = ContainerExpect { purpose: PURPOSE_PQZ_SHARE, sender: ExpectedSender::Set(&set), recipient: kk1.recipient() };
    let b = g.deal(None);
    assert!(kk1.reseal_pqz_share(&b.shares[1], &e, &none, None, &g.recipient(0), k1).is_ok(), "control");
    // a container of another purpose that carries a well-formed share: only the purpose refuses it
    let share_pt = kk1.open_container(&b.shares[1], &e, &none, None).unwrap();
    let other = scaas_ua::wallet::seal_container(
        &g.recipient(1),
        "scaas/backup/v1",
        &scaas_ua::wallet::ContainerSigner::Key(&g.op_key),
        1,
        &share_pt,
        None,
    )
    .unwrap();
    let e2 = ContainerExpect { purpose: "scaas/backup/v1", ..e };
    assert_eq!(kk1.reseal_pqz_share(&other, &e2, &none, None, &g.recipient(0), k1).err(), Some(Error::Argument));
    let bad = scaas_ua::wallet::seal_container(&g.recipient(1), PURPOSE_PQZ_SHARE, &scaas_ua::wallet::ContainerSigner::Key(&g.op_key), 1, b"{}", None).unwrap();
    assert_eq!(kk1.reseal_pqz_share(&bad, &e, &none, None, &g.recipient(0), k1).err(), Some(Error::Argument), "malformed payload");
}

/// The field (FIPS 197 §4.2) and a 3-of-5 split at fixed coefficients, against an independent exp / log implementation; the
/// dealt shares at those coefficients are those values, and any 3 of them rebuild.
#[cfg(feature = "vectors")]
#[test]
fn field_and_split_known_answers() {
    unlock();
    use scaas_ua::facade::pqz_backup::{vectors_gf_mul, vectors_split};
    assert_eq!(vectors_gf_mul(0x57, 0x83), 0xc1);
    assert_eq!(vectors_gf_mul(0x57, 0x13), 0xfe);
    let secret: [u8; 32] = core::array::from_fn(|i| i as u8);
    let c1: [u8; 32] = core::array::from_fn(|i| 0xA0 + i as u8);
    let c2: [u8; 32] = core::array::from_fn(|i| (0x5c * i as u32 + 7) as u8);
    let want = [
        "a7c31fbbd7738f2b47e33f5bf713afcb6783df7b97334feb07a3ff1bb7d36f8b",
        "47cf97329035ed48f2570f8708b675fd5ae48a2fbb1ef055d97c12ac23ab68d6",
        "e00d8a8a43436464bdbd3ad7f3a8d4392d7647473838a9a9c6c6f7ac88651942",
        "c6d9b91293386ec56cc7a7b88d4a706f22e55df6af048a2150fb4384b1ae9453",
        "611ba4aa404ee7e9232d92e87654d1ab5577909e2c22d3dd4f41a6841a60e5c7",
    ];
    let got: Vec<String> = vectors_split(&secret, &[c1, c2], 5).iter().map(hex::encode).collect();
    assert_eq!(got, want);
    assert_eq!(vectors_split(&secret, &[], 2), vec![secret; 2], "k = 1: every share is the secret");
    // the same through a dealt backup: share 2 of a 2-of-3 at coefficient c1 is seed32 ^ mul(c1, 2) per byte
    let g = group(2);
    let b = g.pqz.vectors_seal_seed_backup(&g.op_key, &g.msig_kd, 0, None, &g.recipients(), &[c1]).unwrap();
    let seed32 = g.op.export_pqz_leaf_raw(7, 0, scaas_ua::facade::pqz::AllowSecretExport).unwrap();
    let (_, _, kk) = &g.members[1];
    let set = g.senders();
    let e = ContainerExpect { purpose: PURPOSE_PQZ_SHARE, sender: ExpectedSender::Set(&set), recipient: kk.recipient() };
    let v: Value = serde_json::from_slice(&kk.open_container(&b.shares[1], &e, &none, None).unwrap()).unwrap();
    let want2: Vec<u8> = seed32.iter().zip(c1).map(|(s, c)| s ^ vectors_gf_mul(c, 2)).collect();
    assert_eq!(v["share"].as_str().unwrap(), format!("0x{}", hex::encode(want2)));
    let cs: Vec<SealedContainer> = (0..3).map(|i| g.to_rebuilder(&b, i)).collect();
    assert_eq!(g.rebuild(&cs[1..], &g.msig_ua, 0, &g.key_hash()).unwrap().pk(), g.pqz.pk());
}

/// A backup record is outside input (the client's storage, the C ABI's `backups_json`): past 1 MiB or deeper than 9 it is
/// refused before `serde_json` (spec §9.3); the positive control first.
#[cfg(feature = "vectors")]
#[test]
fn a_backup_record_past_its_caps_is_refused_unparsed() {
    unlock();
    use scaas_ua::wallet::bounded;
    let g = group(2);
    let j = g.deal(None).to_json().into_bytes();
    let before = bounded::vectors_parsed();
    assert!(PqzSeedBackup::from_json(&j).is_ok(), "control");
    assert!(bounded::vectors_parsed() > before);
    let mut long = j.clone();
    long.resize(1 << 20, b' ');
    assert!(PqzSeedBackup::from_json(&long).is_ok(), "1 MiB exactly");
    long.push(b' ');
    let before = bounded::vectors_parsed();
    assert_eq!(PqzSeedBackup::from_json(&long).err(), Some(Error::Argument));
    let deep = format!("{}{}{}", "[".repeat(10), "", "]".repeat(10)).into_bytes();
    assert_eq!(PqzSeedBackup::from_json(&deep).err(), Some(Error::Argument));
    assert_eq!(bounded::vectors_parsed(), before, "refused before serde_json");
}

// --- T16b (owner 2026-11-06): the rebuilt key persists in the rebuilder's vault and backup ---

const PIN: &str = "correct horse 9";

/// `pqz-held:<ua>:<version>:<pqzKeyHash>`.
fn held_label(ua: &[u8; 32], version: u64, kh: &[u8; 32]) -> String {
    format!("pqz-held:0x{}:{version}:0x{}", hex::encode(ua), hex::encode(kh))
}

/// `seed32` in hex and base64url: what a persisted copy in the clear would show.
fn clear_forms(seed32: &[u8; 32]) -> [String; 2] {
    use base64ct::{Base64UrlUnpadded, Encoding};
    [hex::encode(seed32), Base64UrlUnpadded::encode_string(seed32)]
}

/// The operator's balance-cache box of `4242` opened by `k` (the same `seed32`). Not `dec`: a release build has no raw decrypt
/// (ARCH-POS-13, T15c).
fn decrypts(g: &Group, k: &PqzKey) -> Result<Value, Error> {
    let b = g.pqz.seal_balance_cache(b"4242").unwrap();
    Ok(serde_json::from_slice(&k.open_balance_cache(b.as_bytes())?).unwrap())
}

/// Rebuild → lock → unlock: the key is listed in the manifest (public: the hash, never `seed32`), its vault (sealed under the
/// passphrase, its JSON exported and read back) holds it again once opened, checked against `pqzKeyHash`, and it opens what
/// the operator's key sealed. Between unlock and that open it is listed but not held: `pqz_held_key` and `backup_seal`
/// refuse (`Argument`), as for an imported key.
#[test]
fn a_rebuilt_key_survives_lock_and_unlock_through_its_vault() {
    unlock();
    let g = group(2);
    let b = g.deal(None);
    let kh = g.key_hash();
    let seed32 = g.op.export_pqz_leaf_raw(7, 0, scaas_ua::facade::pqz::AllowSecretExport).unwrap();
    let cs: Vec<SealedContainer> = (0..2).map(|i| g.to_rebuilder(&b, i)).collect();
    let k = g.rebuild(&cs, &g.msig_ua, 0, &kh).unwrap();
    let w = &g.members[0].0;
    let entry = scaas_ua::wallet::PqzHeldEntry { ua: g.msig_ua, version: 0, pqz_key_hash: kh };
    assert_eq!(w.manifest().pqz_held, [entry]);
    assert_eq!(w.pqz_held_key(&kh).unwrap().pk(), g.pqz.pk(), "by its key hash");
    assert_eq!(w.pqz_held_key(&[0; 32]).err(), Some(Error::Argument), "another hash");
    let label = held_label(&g.msig_ua, 0, &kh);
    let seed_v = w.seal_vault(PIN, None).unwrap();
    let held_v = Vault::from_json(w.seal_label_vault(&label, PIN, None).unwrap().to_json().as_bytes()).unwrap();
    assert_eq!(held_v.label(), label);
    assert_eq!(w.seal_label_vault(&held_label(&g.msig_ua, 1, &kh), PIN, None).err(), Some(Error::Argument), "another version: not held");
    for clear in clear_forms(&seed32) {
        assert!(!held_v.to_json().contains(&clear), "the vault holds seed32 sealed");
        assert!(!w.manifest().to_json().contains(&clear), "the manifest holds no seed32");
    }
    let mut m = Manifest::from_json(w.manifest().to_json().as_bytes()).unwrap();
    assert_eq!(m.pqz_held, [entry], "the manifest JSON round-trips the entry");
    m.pqz_held.clear();
    assert_eq!(Manifest::from_json(m.to_json().replace(",\"pqzHeld\":[]", "").as_bytes()).unwrap(), m, "absent: none");
    let bad = w.manifest().to_json().replace("\"version\":0,", "\"version\":\"0\",");
    assert_eq!(Manifest::from_json(bad.as_bytes()).err(), Some(Error::Argument), "a malformed entry");

    w.lock();
    assert_eq!(decrypts(&g, &k).err(), Some(Error::KeyRevoked), "lock revokes the handle");
    assert_eq!(w.pqz_held_key(&kh).err(), Some(Error::WalletLocked));
    assert_eq!(w.manifest().pqz_held, [entry], "lock keeps the manifest");
    w.unlock(&seed_v, Unlock::VaultPassphrase(PIN), "").unwrap();
    assert_eq!(w.pqz_held_key(&kh).err(), Some(Error::Argument), "listed, not held before its vault opens");
    let wk = w.ua_key(PQ, 0, 0).unwrap(); // the old handle is revoked
    assert!(w.seal_label_vault("manifest", PIN, None).is_ok(), "control: the new handle and the store work");
    assert_eq!(w.backup_seal(&wk, &[g.recipient(1)]).err(), Some(Error::Argument), "a backup without the listed key is refused");
    assert_eq!(w.open_label_vault(&held_v, Unlock::VaultPassphrase("wrong horse 9")).err(), Some(Error::VaultOpen));
    w.open_label_vault(&held_v, Unlock::VaultPassphrase(PIN)).unwrap();
    let k2 = w.pqz_held_key(&kh).unwrap();
    assert_eq!((k2.pk(), k2.account(), k2.index()), (g.pqz.pk(), u32::MAX, u32::MAX));
    assert_eq!(decrypts(&g, &k2).unwrap(), 4242, "the reopened key sees the balance");
    assert_eq!(w.manifest().pqz_held, [entry], "listed once");
    for clear in clear_forms(&seed32) {
        assert!(!w.manifest().to_json().contains(&clear), "the manifest holds no seed32 after the reopen");
    }
    assert!(w.backup_seal(&wk, &[g.recipient(1)]).is_ok(), "held again: the backup builds");
}

/// The rebuilder's backup (and so its link) carries the key under its label: the restored wallet holds and lists it.
#[test]
fn the_rebuilders_backup_carries_the_key() {
    unlock();
    let g = group(2);
    let b = g.deal(None);
    let kh = g.key_hash();
    let cs: Vec<SealedContainer> = (0..2).map(|i| g.to_rebuilder(&b, i)).collect();
    g.rebuild(&cs, &g.msig_ua, 0, &kh).unwrap();
    let (w, wk, _) = &g.members[0];
    let c = w.backup_seal(wk, &[g.recipient(1)]).unwrap().remove(0);
    let kk1 = &g.members[1].2;
    let s = [wk.ua().unwrap()];
    let e = ContainerExpect { purpose: PURPOSE_BACKUP, sender: ExpectedSender::Set(&s), recipient: kk1.recipient() };
    let pt: Value = serde_json::from_slice(&kk1.open_container(&c, &e, &none, None).unwrap()).unwrap();
    assert_eq!(pt["secrets"][0]["label"], held_label(&g.msig_ua, 0, &kh));
    let r = Wallet::restore_backup(kk1, &c, &e, &none, None, None, None, "").unwrap().unwrap();
    assert_eq!(r.manifest().pqz_held, w.manifest().pqz_held);
    assert_eq!(decrypts(&g, &r.pqz_held_key(&kh).unwrap()).unwrap(), 4242);
}

/// A `pqz-held:` vault is checked on reload: a `seed32` that does not give the label's `pqzKeyHash` is `Argument` and nothing
/// is held or listed; a label of another form is `Argument`. The positive control first.
#[cfg(feature = "vectors")]
#[test]
fn a_held_vault_is_checked_against_its_key_hash() {
    unlock();
    let g = group(2);
    let kh = g.key_hash();
    let seed32 = g.op.export_pqz_leaf_raw(7, 0, scaas_ua::facade::pqz::AllowSecretExport).unwrap();
    let other = g.op.export_pqz_leaf_raw(7, 1, scaas_ua::facade::pqz::AllowSecretExport).unwrap();
    let label = held_label(&g.msig_ua, 0, &kh);
    let w = Wallet::generate().unwrap().0;
    let open = |l: &str, s: &[u8]| w.open_label_vault(&Vault::vectors_seal(l, s, PIN).unwrap(), Unlock::VaultPassphrase(PIN));
    assert_eq!(open(&label, &*other).err(), Some(Error::Argument), "another key under this hash");
    assert_eq!(open(&label, &seed32[..31]).err(), Some(Error::Argument), "31 bytes");
    assert!(w.manifest().pqz_held.is_empty() && w.pqz_held_key(&kh).is_err(), "nothing held or listed");
    let hx = hex::encode(kh);
    for bad in [
        label.replace(&hx, &hx.to_uppercase()),
        label.replace(":0:", ":00:"),
        label.replace(":0:", "::"),
        format!("{label}:"),
        label.replacen("0x", "", 1),
    ] {
        assert_eq!(open(&bad, &*seed32).err(), Some(Error::Argument), "{bad}");
    }
    open(&label, &*seed32).unwrap();
    assert_eq!(w.pqz_held_key(&kh).unwrap().pk(), g.pqz.pk(), "control");
    assert_eq!(w.manifest().pqz_held, [scaas_ua::wallet::PqzHeldEntry { ua: g.msig_ua, version: 0, pqz_key_hash: kh }]);
}
