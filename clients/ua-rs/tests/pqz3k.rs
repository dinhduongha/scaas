// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `scaas_ua::pqz3k` against the shared rows: pq_kat.json `pqzScopedSeeds` and `memoHashOpening` (clientkeys), opening.json's
//! `openKemSeeds`, leg seeds and `rejects` (pqz-ffi), typed_ops.json's `PqzRollOver` row (clientkeys; the contract pins its
//! typehash), pqz3k_kat.json (clientkeys). The key handle (T21 O5 (b), feature `pqz`): made by `Wallet::pqz_scoped_key` in the
//! wallet's store (the release path, both cells), revoked by `lock()`, its leased entries waited for by `lock()` (`vectors`
//! pause hook), the debit entry's gates one change at a time, K3-7 on real pqz-ffi credits. The raw derivations and the test
//! constructors are `vectors` only (T21 O5).
#![cfg_attr(not(feature = "vectors"), allow(dead_code, unused_imports))]
use scaas_ua::{keccak256, pqz3k};
use serde_json::Value;

fn load(p: &str) -> Value {
    let path = format!(
        "{}/../../smartcontracts/vectors/{p}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn b(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn a<const N: usize>(v: &Value) -> [u8; N] {
    b(v).try_into().unwrap()
}
fn n(v: &Value) -> u64 {
    v.as_u64()
        .unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
}

/// BIP-39's seed: PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048), 64 bytes (one block), here for the KAT only.
fn bip39_seed(mnemonic: &str) -> [u8; 64] {
    use hmac::{Hmac, Mac};
    let prf = |parts: &[&[u8]]| {
        let mut m = <Hmac<sha2::Sha512> as Mac>::new_from_slice(mnemonic.as_bytes()).unwrap();
        for p in parts {
            m.update(p);
        }
        let o: [u8; 64] = m.finalize().into_bytes().into();
        o
    };
    let mut u = prf(&[b"mnemonic", &1u32.to_be_bytes()]);
    let mut t = u;
    for _ in 1..2048 {
        u = prf(&[&u]);
        for (x, y) in t.iter_mut().zip(u) {
            *x ^= y;
        }
    }
    t
}

const L: pqz3k::Layout = pqz3k::Layout::of(2304, 46);

/// pq_kat.json: the one raw export of a token without the opening, and the opening `memoHash`.
#[test]
#[cfg(feature = "vectors")] // the raw-seed entry points are `vectors` only (T21 O5)
fn raw_token_seed_and_memo_hash() {
    let k = load("ua/pq_kat.json");
    let seed = bip39_seed(k["mnemonic"].as_str().unwrap());
    for r in k["pqzScopedSeeds"].as_array().unwrap() {
        if let Some(t) = r.get("token").map(a::<20>) {
            let got = pqz3k::pqz_token_key_seed_without_opening(
                &seed,
                0,
                0,
                &a(&r["chainUid"]),
                &t,
                n(&r["version"]),
            );
            assert_eq!(*got, a::<32>(&r["seed32"]));
        }
    }
    for r in k["memoHashOpening"].as_array().unwrap() {
        let os: Vec<Vec<u8>> = r["openings"].as_array().unwrap().iter().map(b).collect();
        let refs: Vec<&[u8]> = os.iter().map(|o| &o[..]).collect();
        assert_eq!(
            pqz3k::opening_memo_hash(&b(&r["memo"]), &a(&r["ownTag"]), &refs),
            a::<32>(&r["memoHash"])
        );
    }
}

/// pqz3k_kat.json (clientkeys, Fable P2-2; forge PqzClientRows checks it against the contracts): `h(i)` and `entriesHash`, the
/// scoped record digests and messages, the opening blob's fields. (The handle rows: `handle::kat_rows`.)
#[test]
fn client_rows() {
    let k = load("ua/pqz3k_kat.json");
    let l = pqz3k::Layout {
        pkp: n(&k["layout"]["pkp"]) as usize,
        vp: n(&k["layout"]["vp"]) as usize,
    };
    assert_eq!(l, L);
    let code = b(&k["entries"]["code"]);
    let mut hs = vec![];
    for r in k["entries"]["rows"].as_array().unwrap() {
        let c = r["code"].as_bool().unwrap().then_some(&code[..]);
        let h = pqz3k::entry_hash(n(&r["index"]), &a(&r["slot"]), c);
        assert_eq!(h, a::<32>(&r["h"]), "{}", r["what"]);
        hs.push(h);
    }
    assert_eq!(
        pqz3k::entries_hash(&hs),
        a::<32>(&k["entries"]["entriesHash"])
    );
    for r in k["scopedKeyRecords"].as_array().unwrap() {
        let (u, cls, t, v) = (
            a::<32>(&r["ua"]),
            n(&r["keyClass"]) as u8,
            a::<20>(&r["token"]),
            n(&r["version"]),
        );
        let kd = pqz3k::scoped_key_digest(&u, cls, &a(&r["chainUid"]), &t, v, &a(&r["pqzKeyHash"]));
        let rd = pqz3k::scoped_key_record_digest(
            &u,
            cls,
            &a(&r["chainUid"]),
            &t,
            v,
            &a(&r["pqzKeyHash"]),
            &a(&r["pqzPopHash"]),
            &a(&r["openKemHash"]),
            n(&r["validUntilBlock"]),
        );
        assert_eq!(
            (kd, rd),
            (a::<32>(&r["keyDigest"]), a::<32>(&r["recordDigest"]))
        );
        let p = pqz3k::purpose_pqz_scoped_key();
        assert_eq!(
            scaas_ua::ua_message(n(&r["kind"]) as u16, &p, &rd).unwrap(),
            a::<32>(&r["message"])
        );
        assert_eq!(
            scaas_ua::ua_message(0x0142, &p, &kd).unwrap(),
            a::<32>(&r["regMessage"])
        );
    }
    let ob = &k["openingBlob"];
    let code = b(&ob["code"]);
    let blob = pqz3k::opening_blob(&code[1..], l).expect("the row's blob");
    let at = |f: &str| n(&ob["at"][f]) as usize;
    let d = &code[1..];
    assert_eq!(
        (
            blob.pu,
            blob.pva.unwrap(),
            blob.puf,
            blob.o_t,
            blob.o_a.unwrap()
        ),
        (
            &d[at("pu")..at("pvt")],
            &d[at("pva")..at("toUA")],
            &d[at("puf")..at("pvf")],
            &d[at("oT")..at("oA")],
            &d[at("oA")..at("ownTag")]
        )
    );
    assert_eq!(
        (blob.to_ua, blob.own_tag, blob.kv.clone()),
        (
            d[at("toUA")..at("puf")].try_into().unwrap(),
            d[at("ownTag")..at("kv")].try_into().unwrap(),
            vec![0, 2]
        )
    );
    assert_eq!(
        pqz3k::opening_blob(&d[..d.len() - 1], l),
        None,
        "one byte short"
    );
}

#[test]
#[cfg(feature = "vectors")] // the raw-seed entry points are `vectors` only (T21 O5)
fn open_kem_seeds_and_leg_seeds_equal_pqz_ffi() {
    let o = load("pqz/opening.json");
    let seed: [u8; 64] = a(&o["bip39_seed"]);
    for r in o["openKemSeeds"].as_array().unwrap() {
        let tok = b(&r["token"]);
        let t: Option<[u8; 20]> = (!tok.is_empty()).then(|| tok.try_into().unwrap());
        let got = pqz3k::open_kem_seed(
            &seed,
            &a(&r["ua"]),
            &a(&r["chainUid"]),
            t.as_ref(),
            n(&r["version"]),
        );
        assert_eq!(got.to_vec(), b(&r["openKemSeed"]));
    }
    for r in o["rows"].as_array().unwrap() {
        assert_eq!(
            pqz3k::leg_seed(&a(&r["seed_enc"]), &a(&r["toUA"]), &a(&r["pk_t_keccak"])),
            a::<32>(&r["seed_leg"])
        );
    }
}

#[test]
fn roll_over_struct_hash_equals_typed_ops() {
    let r = &load("typed/typed_ops.json")["ops"]["PqzRollOver"];
    assert_eq!(
        keccak256(pqz3k::ROLL_OVER_TYPE.as_bytes()),
        a::<32>(&r["typehash"])
    );
    let m = &r["message"];
    let skip: Vec<u64> = m["skip"].as_array().unwrap().iter().map(n).collect();
    let h = pqz3k::roll_over_struct_hash(
        &a(&m["ua"]),
        n(&m["keyVersion"]),
        n(&m["rollSeq"]),
        n(&m["rolled"]),
        n(&m["n"]),
        &skip,
        &a(&m["entriesHash"]),
        n(&m["validUntilBlock"]),
        &a(&m["chainUid"]),
    );
    assert_eq!(h, a::<32>(&r["structHash"]));
}

// ------------------------------------------------------------------ the key handle (T21 O5 (b); spec §14.1, §14.18, §14.19)

#[cfg(feature = "pqz")]
mod handle {
    use super::{a, b, bip39_seed, load, n};
    use pqz_ffi::opening::{self as op, AuditorOutcome, Party, Role};
    use pqz_ffi::pqzl;
    use pqz_ffi::stmt::{K_MAX, PK_BYTES};
    use scaas_ua::keccak256;
    use scaas_ua::pqz3k::{
        self, AuditorKeys, Checked, Credit, Debit, Own, PqzKeyHandle, Reads, Refused, Scope,
        WindowEntry, LAYOUT,
    };
    use scaas_ua::wallet::{Error, Unlock, Wallet};
    use serde_json::Value;

    const PASS: &str = "river-otter-7 custody";
    const READ1: Reads = Reads {
        block: 100,
        finalized: false,
        strict_majority: false,
    };
    const READF: Reads = Reads {
        block: 90,
        finalized: true,
        strict_majority: true,
    };

    fn unlock() {
        #[cfg(feature = "vectors")]
        scaas_ua::facade::vectors_unlock(scaas_ua::facade::TestOnly);
    }

    /// The build's set directory of the pqz vector files.
    fn set_dir() -> String {
        let s = pqz_ffi::stmt::SET;
        if s == "n2048-kmax1024" {
            String::new()
        } else {
            format!("{s}/")
        }
    }

    /// pqz3k_kat.json's wallet (the release path: the mnemonic, no raw seed) and its UA and chain.
    fn kat() -> (Value, Wallet, [u8; 32], [u8; 32]) {
        unlock();
        let k = load("ua/pqz3k_kat.json");
        assert_eq!(
            k["set"]["name"].as_str(),
            Some("n2304-kmax4096"),
            "pqz3k_kat.json's own rows are of one set"
        );
        let w = Wallet::from_mnemonic(k["mnemonic"].as_str().unwrap(), "").unwrap();
        let (ua, cu) = (a::<32>(&k["ua"]), a::<32>(&k["chainUid"]));
        (k, w, ua, cu)
    }
    fn scope(ua: [u8; 32], cu: [u8; 32], token: Option<[u8; 20]>, version: u64) -> Scope {
        Scope {
            account: 0,
            index: 0,
            ua,
            chain_uid: cu,
            token,
            version,
        }
    }

    fn digits(amount: u64) -> [u8; 16] {
        core::array::from_fn(|i| ((amount >> (4 * i)) & 15) as u8)
    }

    /// The parts of an opening op 1 blob (lanes, unpacked) and its code `STOP ‖ salt ‖ P(u) ‖ P(v_t) ‖ [P(v_a)] ‖ toUA ‖ P(u_f) ‖
    /// P(v_f) ‖ O_t ‖ [O_a] ‖ ownTag ‖ be64 kv[0..n) ‖ u8(n)`.
    struct Leg {
        u: Vec<u8>,
        v_t: Vec<u8>,
        v_a: Option<Vec<u8>>,
        u_f: Vec<u8>,
        v_f: Vec<u8>,
        o_t: Vec<u8>,
        o_a: Option<Vec<u8>>,
    }
    fn code_of(to: &[u8; 32], kv: &[u64], l: &Leg) -> Vec<u8> {
        let mut d = vec![0u8];
        d.extend([0x5a; 16]);
        d.extend(op::pack(&l.u));
        d.extend(op::pack(&l.v_t));
        if let Some(v) = &l.v_a {
            d.extend(op::pack(v));
        }
        d.extend(to);
        d.extend(op::pack(&l.u_f));
        d.extend(op::pack(&l.v_f));
        d.extend(&l.o_t);
        if let Some(o) = &l.o_a {
            d.extend(o);
        }
        d.extend([0x0e; 32]);
        for k in kv {
            d.extend(k.to_be_bytes());
        }
        d.push(kv.len() as u8);
        d
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Plant {
        Honest,
        Junk,
        WrongSeed,
        CraftedV,
    }

    /// An op 1 credit of `amount` to `h` (no auditor) by the sender side of pqz-ffi, the code of its blob; `plant` a bad one
    /// (spec §14.1: junk opening, a valid KEM ciphertext of a wrong seed, `v_t` moved off the lattice).
    fn credit_to(
        h: &PqzKeyHandle,
        ua: &[u8; 32],
        cu: &[u8; 32],
        token: &[u8; 20],
        amount: u64,
        plant: Plant,
        salt: u8,
    ) -> Vec<u8> {
        let kf = pqzl::keygen(&[0x46; 32]).unwrap();
        let pk_t: Box<[u8; PK_BYTES]> = h.pk().into_boxed_slice().try_into().unwrap();
        let s = op::enc_split(
            &kf.pk,
            [2; 16],
            ua,
            &pk_t,
            digits(amount),
            None,
            &[salt; 32],
        )
        .unwrap();
        let mut v_t = s.leg.vs[0];
        if plant == Plant::CraftedV {
            let x = u64::from_be_bytes(v_t[..8].try_into().unwrap());
            v_t[..8].copy_from_slice(&((x + 1) % pqz_ffi::stmt::Q).to_be_bytes());
        }
        let kem = h.open_kem_pk();
        let to = Party {
            ua,
            key_version: h.version(),
            pk: &pk_t,
            kem_pk: &kem,
            v: &v_t,
            opening: &[],
        };
        let c = op::Credit {
            chain_uid: cu,
            token,
            u: &s.leg.u,
            to,
            auditor: None,
        };
        let o_t = match plant {
            Plant::Junk => (0..op::OPENING)
                .map(|i| (i as u8).wrapping_mul(31) ^ 1)
                .collect(),
            Plant::WrongSeed => {
                op::seal(Role::Recipient, &c, &to, &op::keccak(&[&s.seed_leg[..]])).unwrap()
            }
            _ => op::seal(Role::Recipient, &c, &to, &s.seed_leg).unwrap(),
        };
        let leg = Leg {
            u: s.leg.u.to_vec(),
            v_t: v_t.to_vec(),
            v_a: None,
            u_f: s.own.u.to_vec(),
            v_f: s.own.vs[0].to_vec(),
            o_t,
            o_a: None,
        };
        code_of(ua, &[h.version()], &leg)
    }

    /// A credit's slot word `blob(160) ‖ uOff(16) ‖ vOff(16) ‖ block(64)` at the offsets an op 1 credit has (the review's F1).
    const fn slot_at(u_off: usize, v_off: usize) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[0] = 0x5e; // blob address high byte
        w[20] = (u_off >> 8) as u8;
        w[21] = u_off as u8;
        w[22] = (v_off >> 8) as u8;
        w[23] = v_off as u8;
        w[31] = 7; // block 7
        w
    }
    const SLOT: [u8; 32] = slot_at(16, 16 + LAYOUT.pkp);
    fn marked(s: [u8; 32]) -> [u8; 32] {
        let mut m = s;
        m[24] |= 0x80;
        m
    }
    const TRIVIAL: [u8; 32] = {
        let mut w = [0u8; 32];
        w[19] = 100; // amount 100 in the low 64 bits of the blob field, vOff 0
        w[31] = 9;
        w
    };

    fn credit(token: [u8; 20], index: u64, code: &[u8]) -> Credit<'_> {
        Credit {
            token,
            index,
            slot: SLOT,
            code,
            auditor: None,
            reads: READ1,
        }
    }
    fn we<'a>(
        token: [u8; 20],
        index: u64,
        slot: [u8; 32],
        code: Option<&'a [u8]>,
        accepted: Option<&'a pqz3k::Accepted>,
    ) -> WindowEntry<'a> {
        WindowEntry {
            token,
            index,
            slot,
            code,
            accepted,
        }
    }
    fn deb<'a>(
        token: [u8; 20],
        last_debit: u64,
        own: Option<Own<'a>>,
        window: &'a [WindowEntry<'a>],
    ) -> Debit<'a> {
        Debit {
            token,
            last_debit,
            own,
            window,
            shield_in: 0,
        }
    }
    fn balance(r: Result<pqz3k::OpenedDebit, Refused>) -> Result<u64, Refused> {
        r.map(|o| o.balance)
    }

    fn accepted(r: Result<Checked, Refused>, amount: u64) -> pqz3k::Accepted {
        match r {
            Ok(Checked::Accepted(acc, x)) if x == amount => acc,
            r => panic!("the honest credit: {r:?}"),
        }
    }

    /// pq_kat.json `pqzScopedSeeds` and pqz3k_kat.json `handles` through `Wallet::pqz_scoped_key` (the store derivation equals
    /// clientkeys' rows: the commitment and `keccak256(kemPk)`), and `ownTagOpening` through the debit's own-part gate (a release
    /// build opens the debit; the row's `P(u_f)` is no ciphertext of the key, so its balance is not asserted: the gate is).
    #[test]
    fn kat_rows() {
        if pqz_ffi::stmt::SET != "n2304-kmax4096" {
            return; // its own rows (`P(u_f)`, `P(v_f)`) are pqz3k_kat.json's set's; the other tests run at every set
        }
        unlock();
        let k = load("ua/pq_kat.json");
        let w = Wallet::from_mnemonic(k["mnemonic"].as_str().unwrap(), "").unwrap();
        let rows = k["pqzScopedSeeds"].as_array().unwrap();
        assert_eq!(rows.len(), 12);
        for r in rows {
            let s = Scope {
                account: n(&r["account"]) as u32,
                index: n(&r["index"]) as u32,
                ua: [0x11; 32],
                chain_uid: a(&r["chainUid"]),
                token: r.get("token").map(a::<20>),
                version: n(&r["version"]),
            };
            assert_eq!(
                w.pqz_scoped_key(&s).unwrap().seed_commitment(),
                Ok(keccak256(&a::<32>(&r["seed32"]))),
                "{}",
                r["keyClass"]
            );
        }
        let (k, w, ua, cu) = kat();
        for r in k["handles"].as_array().unwrap() {
            let h = w
                .pqz_scoped_key(&scope(
                    ua,
                    cu,
                    r.get("token").map(a::<20>),
                    n(&r["version"]),
                ))
                .unwrap();
            assert_eq!(h.seed_commitment(), Ok(a::<32>(&r["seedCommitment"])));
            assert_eq!(keccak256(&h.open_kem_pk()), a::<32>(&r["openKemHash"]));
        }
        for r in k["ownTagOpening"].as_array().unwrap() {
            let token = a::<20>(&r["token"]);
            let class3 = r["keyClass"] == "offchain-token";
            let h = w
                .pqz_scoped_key(&scope(ua, cu, class3.then_some(token), 0))
                .unwrap();
            let (puf, pvf, tag, last) = (
                b(&r["puf"]),
                b(&r["pvf"]),
                a::<32>(&r["ownTag"]),
                n(&r["sendCounter"]) + 1,
            );
            let own = |pu| {
                Some(Own {
                    pu,
                    pvf: &pvf,
                    own_tag: tag,
                })
            };
            let ok = h.open_debit(&deb(token, last, own(&puf[..]), &[]));
            assert!(
                !matches!(ok, Err(Refused::OwnTag)),
                "control: the own part alone passes the tag: {ok:?}"
            );
            assert_eq!(
                h.open_debit(&deb(token, last + 1, own(&puf[..]), &[]))
                    .err(),
                Some(Refused::OwnTag),
                "the counter off by one"
            );
            let other = w
                .pqz_scoped_key(&scope(ua, cu, class3.then_some(token), 1))
                .unwrap();
            assert_eq!(
                other
                    .open_debit(&deb(token, last, own(&puf[..]), &[]))
                    .err(),
                Some(Refused::OwnTag),
                "a foreign key's tag"
            );
            let acc1 = w
                .pqz_scoped_key(&Scope {
                    account: 1,
                    ..scope(ua, cu, class3.then_some(token), 0)
                })
                .unwrap();
            assert_eq!(
                acc1.open_debit(&deb(token, last, own(&puf[..]), &[])).err(),
                Some(Refused::OwnTag),
                "another account's tag"
            );
            let mut flipped = puf.clone();
            flipped[7] ^= 1;
            assert_eq!(
                h.open_debit(&deb(token, last, own(&flipped[..]), &[]))
                    .err(),
                Some(Refused::OwnTag),
                "u_f alone differs"
            );
            assert_eq!(
                (h.secret_loads(), other.secret_loads(), acc1.secret_loads()),
                (1, 0, 0)
            );
        }
    }

    /// §14.1 / §14.18 on a class-2 and a class-3 handle of the KAT wallet, real pqz-ffi credits: three planted variants skip and
    /// never load the PQZ seed; a window holding one unmarked is refused, marked it opens to the accepted amounts. The debit's
    /// gates one change at a time, each with its positive control; the acceptance is bound to the handle (its keys and
    /// derivation path), the token, the index and the bytes; the slot's offsets are an op 1 credit's.
    #[test]
    fn debit_gates_the_secret() {
        if pqz_ffi::stmt::SET != "n2304-kmax4096" {
            return; // its own rows (`P(u_f)`, `P(v_f)`) are pqz3k_kat.json's set's; the other tests run at every set
        }
        let (k, w, ua, cu) = kat();
        let t2 = [0xa2u8; 20];
        for r in k["ownTagOpening"].as_array().unwrap() {
            let t1 = a::<20>(&r["token"]);
            let class3 = r["keyClass"] == "offchain-token";
            let sc = scope(ua, cu, class3.then_some(t1), 0);
            let h = w.pqz_scoped_key(&sc).unwrap();
            let other = w
                .pqz_scoped_key(&scope(ua, cu, class3.then_some(t1), 1))
                .unwrap();
            let good = credit_to(&h, &ua, &cu, &t1, 0x1234, Plant::Honest, 1);
            let acc = accepted(h.check(&credit(t1, 0, &good)), 0x1234);
            assert_eq!(
                (acc.token(), acc.index(), acc.entry_hash()),
                (t1, 0, pqz3k::entry_hash(0, &SLOT, Some(&good)))
            );
            // F1: the slot's offsets bound (control: SLOT above)
            for (u_off, v_off, what) in [
                (17, 16 + LAYOUT.pkp, "uOff + 1"),
                (16, 17 + LAYOUT.pkp, "vOff + 1"),
                (16, 200, "vOff 200"),
            ] {
                let c = Credit {
                    slot: slot_at(u_off, v_off),
                    ..credit(t1, 0, &good)
                };
                assert!(matches!(h.check(&c), Err(Refused::Input(_))), "{what}");
            }
            let mut skips = vec![];
            let mut bad = vec![];
            for (i, p) in [Plant::Junk, Plant::WrongSeed, Plant::CraftedV]
                .into_iter()
                .enumerate()
            {
                bad = credit_to(&h, &ua, &cu, &t1, 0x99, p, 2 + i as u8);
                match h.check(&credit(t1, 1, &bad)) {
                    Ok(Checked::Skip(s)) => skips.push(s),
                    r => panic!("planted variant {i}: {r:?}"),
                }
            }
            let (good, bad) = (&good[..], &bad[..]);
            let win = |slot1| {
                [
                    we(t1, 0, SLOT, Some(good), Some(&acc)),
                    we(t1, 1, slot1, Some(bad), None),
                    we(t1, 2, TRIVIAL, None, None),
                ]
            };
            let (puf, pvf, tag, last) = (
                b(&r["puf"]),
                b(&r["pvf"]),
                a::<32>(&r["ownTag"]),
                n(&r["sendCounter"]) + 1,
            );
            let own = Some(Own {
                pu: &puf,
                pvf: &pvf,
                own_tag: tag,
            });
            let w0 = win(SLOT);
            assert_eq!(
                h.open_debit(&deb(t1, last, own, &w0)).err(),
                Some(Refused::Window),
                "an unaccepted unmarked credit"
            );
            assert_eq!(h.secret_loads(), 0, "the secret was never loaded");
            // a skip read from one node at an unfinalized block is no reason to mark (Fable P2-1)
            assert_eq!(PqzKeyHandle::marks(&skips), Err(Refused::Unconfirmed));
            let again: Vec<_> = skips
                .iter()
                .map(|s| pqz3k::Skip {
                    reads: READF,
                    ..s.clone()
                })
                .collect();
            assert_eq!(PqzKeyHandle::marks(&again), Ok(vec![1]));
            let wm = win(marked(SLOT));
            // the KAT's own part passes its tag but is no ciphertext of this key: that it opened is the seed's use (counted)
            let opens = |d: &Debit| {
                let n = h.secret_loads();
                let _ = h.open_debit(d);
                h.secret_loads() == n + 1
            };
            assert!(
                opens(&deb(t1, last, own, &wm)),
                "the mark landed: own part and window"
            );
            assert!(
                opens(&deb(t1, last, own, &[])),
                "control: the own part alone"
            );
            assert_eq!(
                balance(h.open_debit(&deb(t1, 0, None, &wm))),
                Ok(0x1234 + 100),
                "control: a first debit, the window alone"
            );
            assert_eq!(h.secret_loads(), 3);
            // the own part's gates (T21 L43): no empty-window bypass
            assert_eq!(
                h.open_debit(&deb(t1, last, None, &[])).err(),
                Some(Refused::OwnRequired),
                "lastDebit > 0, zero entries"
            );
            assert_eq!(
                h.open_debit(&deb(t1, last, None, &wm)).err(),
                Some(Refused::OwnRequired),
                "lastDebit > 0, no own part"
            );
            assert!(
                matches!(h.open_debit(&deb(t1, 0, own, &wm)), Err(Refused::Input(_))),
                "an own part at lastDebit 0"
            );
            assert_eq!(
                h.open_debit(&deb(t1, 0, None, &[])).err(),
                Some(Refused::EmptyDebit),
                "nothing gated"
            );
            let mut far = deb(t1, last, own, &[]);
            far.last_debit = (1 << 32) + 1;
            assert!(
                matches!(h.open_debit(&far), Err(Refused::Input(_))),
                "a counter at 2^32"
            );
            far.last_debit = 1 << 32;
            assert!(
                !matches!(h.open_debit(&far), Err(Refused::Input(_))),
                "control: counter 2^32 - 1 is no Input"
            );
            // owner 2026-11-16: a first debit of Trivial(shieldIn) alone
            let sh = Debit {
                shield_in: 7,
                ..deb(t1, 0, None, &[])
            };
            let o = h.open_debit(&sh).unwrap();
            assert_eq!(o.balance, 7, "a shielded-in-only first debit");
            assert_eq!(o.t.len(), pqzl::CT_BYTES);
            assert!(
                o.t[..PK_BYTES].iter().all(|x| *x == 0),
                "u of Trivial(shieldIn) is zero"
            );
            assert_eq!(
                balance(h.open_debit(&Debit {
                    shield_in: 7,
                    ..deb(t1, 0, None, &wm)
                })),
                Ok(0x1234 + 100 + 7),
                "and beside a window"
            );
            // the window's tokens (T21 L47), order and count (the review's F2)
            let mut e = wm;
            e[2].token = t2;
            assert_eq!(
                h.open_debit(&deb(t1, last, own, &e)).err(),
                Some(Refused::Window),
                "a TRIVIAL entry of another token"
            );
            let mut e = wm;
            e[0].token = t2;
            assert_eq!(
                h.open_debit(&deb(t1, last, own, &e)).err(),
                Some(Refused::Window),
                "an accepted entry of another token"
            );
            let dup = [wm[0], wm[0]];
            assert_eq!(
                h.open_debit(&deb(t1, 0, None, &dup)).err(),
                Some(Refused::Window),
                "an accepted entry twice"
            );
            let desc = [wm[2], wm[1]];
            assert_eq!(
                h.open_debit(&deb(t1, 0, None, &desc)).err(),
                Some(Refused::Window),
                "indexes descending"
            );
            let many: Vec<_> = (0..K_MAX as u64 - 1)
                .map(|i| we(t1, i, TRIVIAL, None, None))
                .collect();
            assert_eq!(
                h.open_debit(&deb(t1, 0, None, &many)).err(),
                Some(Refused::Window),
                "K_MAX - 1 entries"
            );
            let ok = h.open_debit(&deb(t1, 0, None, &many[..K_MAX - 2]));
            assert_eq!(
                balance(ok),
                Ok(100 * (K_MAX as u64 - 2)),
                "control: K_MAX - 2 entries"
            );
            // the acceptance is bound to the handle, the token, the index and the bytes
            assert_eq!(
                other.open_debit(&deb(t1, 0, None, &wm[..1])).err(),
                Some(Refused::Window),
                "another version's acceptance"
            );
            let a1 = w.pqz_scoped_key(&Scope { account: 1, ..sc }).unwrap();
            assert_eq!(
                a1.open_debit(&deb(t1, 0, None, &wm[..1])).err(),
                Some(Refused::Window),
                "account 1 given account 0's acceptance"
            );
            let w2 = Wallet::from_mnemonic(
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
                "",
            )
            .unwrap();
            let o2 = w2.pqz_scoped_key(&sc).unwrap();
            assert_eq!(
                o2.open_debit(&deb(t1, 0, None, &wm[..1])).err(),
                Some(Refused::Window),
                "another wallet's key, the same scope"
            );
            let short = Own {
                pu: &puf[1..],
                pvf: &pvf,
                own_tag: tag,
            };
            assert!(
                matches!(
                    h.open_debit(&deb(t1, last, Some(short), &[])),
                    Err(Refused::Input(_))
                ),
                "a short P(u_f)"
            );
            let i1 = w.pqz_scoped_key(&Scope { index: 1, ..sc }).unwrap();
            assert_eq!(
                i1.open_debit(&deb(t1, 0, None, &wm[..1])).err(),
                Some(Refused::Window),
                "index 1 given index 0's acceptance"
            );
            let g1 = credit_to(&a1, &ua, &cu, &t1, 0x31, Plant::Honest, 12);
            let acc_a1 = accepted(a1.check(&credit(t1, 0, &g1)), 0x31);
            let e = [we(t1, 0, SLOT, Some(&g1), Some(&acc_a1))];
            assert_eq!(
                balance(a1.open_debit(&deb(t1, 0, None, &e))),
                Ok(0x31),
                "control: account 1's own acceptance"
            );
            assert_eq!(
                h.open_debit(&deb(t1, 0, None, &e)).err(),
                Some(Refused::Window),
                "account 0 given account 1's acceptance"
            );
            let mut e = wm[0];
            e.index = 3;
            assert_eq!(
                h.open_debit(&deb(t1, 0, None, &[e])).err(),
                Some(Refused::Window),
                "another index"
            );
            let mut e = wm[0];
            e.code = Some(bad);
            assert_eq!(
                h.open_debit(&deb(t1, 0, None, &[e])).err(),
                Some(Refused::Window),
                "other bytes"
            );
            let mut e = wm[0];
            e.code = None;
            assert_eq!(
                h.open_debit(&deb(t1, 0, None, &[e])).err(),
                Some(Refused::Window),
                "no code"
            );
            if class3 {
                let d = Debit {
                    token: t2,
                    ..deb(t1, 0, None, &[])
                };
                assert_eq!(
                    h.open_debit(&d).err(),
                    Some(Refused::NotThisHandle),
                    "a class-3 debit of another token"
                );
                let c = Credit {
                    token: t2,
                    ..credit(t1, 0, good)
                };
                assert_eq!(
                    h.check(&c).err(),
                    Some(Refused::NotThisHandle),
                    "a class-3 handle given another token's credit"
                );
            } else {
                // a class-2 key serves every class-2 token; its acceptance names the token it was checked for
                let g2 = credit_to(&h, &ua, &cu, &t2, 0x55, Plant::Honest, 9);
                let acc2 = accepted(h.check(&credit(t2, 0, &g2)), 0x55);
                assert_eq!(acc2.token(), t2);
                let e = [WindowEntry {
                    token: t1,
                    index: 0,
                    slot: SLOT,
                    code: Some(&g2),
                    accepted: Some(&acc2),
                }];
                assert_eq!(
                    h.open_debit(&deb(t1, 0, None, &e)).err(),
                    Some(Refused::Window),
                    "an acceptance of another token"
                );
                let e = [WindowEntry { token: t2, ..e[0] }];
                assert_eq!(
                    balance(h.open_debit(&deb(t2, 0, None, &e))),
                    Ok(0x55),
                    "control: its own token"
                );
            }
            assert_eq!(
                h.secret_loads(),
                6 + u32::from(!class3),
                "no refusal loaded the secret"
            );
            // not this handle's credit, or incomplete inputs: refused before the check
            let to_other = credit_to(&h, &[0x22; 32], &cu, &t1, 1, Plant::Honest, 10);
            let other_kv = credit_to(&other, &ua, &cu, &t1, 1, Plant::Honest, 11);
            assert_eq!(
                h.check(&credit(t1, 0, &to_other)).err(),
                Some(Refused::NotThisHandle),
                "another recipient"
            );
            assert_eq!(
                h.check(&credit(t1, 0, &other_kv)).err(),
                Some(Refused::NotThisHandle),
                "another key version"
            );
            accepted(other.check(&credit(t1, 0, &other_kv)), 1);
            assert!(
                matches!(
                    h.check(&credit(t1, 0, &good[..good.len() - 1])),
                    Err(Refused::Input(_))
                ),
                "a short blob"
            );
            assert!(
                matches!(h.check(&credit(t1, 0, &good[1..])), Err(Refused::Input(_))),
                "no STOP byte"
            );
            assert!(
                matches!(
                    h.check(&Credit {
                        slot: TRIVIAL,
                        ..credit(t1, 0, good)
                    }),
                    Err(Refused::Input(_))
                ),
                "a TRIVIAL entry"
            );
            let d = format!("{h:?}");
            assert!(!d.contains("seed") && d.contains("PqzKeyHandle"), "{d}");
        }
    }

    /// Owner decision (a): the handle proves its own record's `R_REG` (the message from its own fields, the proof verified by
    /// pqz-ffi's verifier); another build's proof system is `Input`; counted in `keygens`.
    #[test]
    fn prove_reg_proves_the_handles_own_record() {
        let (k, w, ua, cu) = kat();
        let t1 = a::<20>(&k["ownTagOpening"][1]["token"]);
        for token in [None, Some(t1)] {
            let h = w.pqz_scoped_key(&scope(ua, cu, token, 1)).unwrap();
            let r = h.prove_reg(&pqz_ffi::PQZL_ID).unwrap();
            let kh = scaas_ua::key_hash_of(scaas_ua::PQZ_SCHEME, &h.pk())
                .unwrap()
                .unwrap();
            let kd = pqz3k::scoped_key_digest(
                &ua,
                if token.is_some() { 3 } else { 2 },
                &cu,
                &token.unwrap_or([0; 20]),
                1,
                &kh,
            );
            assert_eq!(
                (r.pqz_key_hash, r.message),
                (
                    kh,
                    scaas_ua::ua_message(0x0142, &pqz3k::purpose_pqz_scoped_key(), &kd).unwrap()
                )
            );
            assert_eq!(
                pqzl::verify_fast(3, &r.stmt, &r.proof).ok(),
                Some(true),
                "the R_REG proof verifies"
            );
            assert!(
                r.stmt.windows(32).any(|x| x == r.message),
                "over the handle's message"
            );
            assert!(
                matches!(h.prove_reg(&[0x77; 32]), Err(Refused::Input(_))),
                "another build's proof system"
            );
            assert_eq!(h.keygens(), 1);
        }
    }

    /// Spec §8.2 for the handle: a handle of `pqz_scoped_key` works, then `lock()` revokes every entry before its input is read
    /// (`KeyRevoked` first, even for an input it would refuse otherwise); a locked wallet makes none (`WalletLocked`); an
    /// unlock does not revive the old handle, and a new one has the same commitment.
    #[test]
    fn lock_revokes_the_handle() {
        let (k, w, ua, cu) = kat();
        let vault = w.seal_vault(PASS, None).unwrap();
        let t1 = a::<20>(&k["ownTagOpening"][0]["token"]);
        let h = w.pqz_scoped_key(&scope(ua, cu, None, 0)).unwrap();
        let good = credit_to(&h, &ua, &cu, &t1, 7, Plant::Honest, 1);
        let c = credit(t1, 0, &good);
        let acc = accepted(h.check(&c), 7);
        let win = [we(t1, 0, SLOT, Some(&good), Some(&acc))];
        let d = deb(t1, 0, None, &win);
        let before = h.seed_commitment().unwrap();
        assert_eq!(balance(h.open_debit(&d)), Ok(7), "control");
        w.lock();
        assert_eq!(h.open_debit(&d).err(), Some(Refused::KeyRevoked));
        assert_eq!(h.check(&c).err(), Some(Refused::KeyRevoked));
        assert_eq!(h.seed_commitment(), Err(Refused::KeyRevoked));
        assert_eq!(
            h.prove_reg(&pqz_ffi::PQZL_ID).err(),
            Some(Refused::KeyRevoked)
        );
        // KeyRevoked before any other refusal (the review, P3)
        assert_eq!(
            h.check(&Credit { slot: TRIVIAL, ..c }).err(),
            Some(Refused::KeyRevoked),
            "a TRIVIAL credit"
        );
        assert_eq!(
            h.check(&credit(t1, 0, &good[1..])).err(),
            Some(Refused::KeyRevoked),
            "a malformed blob"
        );
        assert_eq!(
            h.open_debit(&deb(t1, 0, None, &[])).err(),
            Some(Refused::KeyRevoked),
            "an empty debit"
        );
        assert_eq!(
            h.open_debit(&deb(t1, 5, None, &[])).err(),
            Some(Refused::KeyRevoked),
            "no own part"
        );
        assert_eq!(
            h.prove_reg(&[0x77; 32]).err(),
            Some(Refused::KeyRevoked),
            "another proof system"
        );
        assert_eq!((h.secret_loads(), h.keygens()), (1, 0));
        assert_eq!(
            w.pqz_scoped_key(&scope(ua, cu, None, 0)).err(),
            Some(Error::WalletLocked)
        );
        w.unlock(&vault, Unlock::VaultPassphrase(PASS), "").unwrap();
        assert_eq!(
            h.seed_commitment(),
            Err(Refused::KeyRevoked),
            "unlock does not revive the handle"
        );
        assert_eq!(
            w.pqz_scoped_key(&scope(ua, cu, None, 0))
                .unwrap()
                .seed_commitment(),
            Ok(before)
        );
    }

    /// T21 L82 for the handle: runs `op` on its own thread, paused (the `vectors` hook) where it holds its copy of the store's
    /// secret, before it uses the copy; `lock()` from a second thread meanwhile must not return (a bounded wait, no loop) until
    /// `op` ended. `op`'s result.
    #[cfg(feature = "vectors")]
    fn lock_during<R: Send>(w: &Wallet, op: impl FnOnce() -> R + Send) -> R {
        use std::sync::mpsc;
        let (in_tx, in_rx) = mpsc::channel();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let (locked_tx, locked_rx) = mpsc::channel();
        std::thread::scope(|s| {
            let a = s.spawn(move || {
                scaas_ua::wallet::vectors_pause_after_copy(move || {
                    in_tx.send(()).unwrap();
                    go_rx.recv().unwrap();
                });
                op()
            });
            in_rx.recv().expect("the operation reached no leased copy");
            let locker = s.spawn(move || {
                w.lock();
                locked_tx.send(()).unwrap();
            });
            let early = locked_rx
                .recv_timeout(std::time::Duration::from_millis(500))
                .is_ok();
            go_tx.send(()).unwrap();
            let r = a.join().unwrap();
            locker.join().unwrap();
            assert!(!early, "lock() returned while the operation used its copy");
            r
        })
    }

    /// `lock()` during a check (the opening KEM seed's copy) waits for it; afterwards it is `KeyRevoked`. The review's Codex 4:
    /// `lock()` while a debit's closure runs (inside the use of the seed, after the copy) does not return until the closure
    /// ends; the closure's result is whole; afterwards the debit is `KeyRevoked`.
    #[cfg(feature = "vectors")]
    #[test]
    fn lock_waits_for_a_leased_check_and_debit() {
        use std::sync::mpsc;
        let (k, w, ua, cu) = kat();
        let vault = w.seal_vault(PASS, None).unwrap();
        let t1 = a::<20>(&k["ownTagOpening"][0]["token"]);
        let h = w.pqz_scoped_key(&scope(ua, cu, None, 0)).unwrap();
        let good = credit_to(&h, &ua, &cu, &t1, 7, Plant::Honest, 1);
        let c = credit(t1, 0, &good);
        let acc = accepted(lock_during(&w, || h.check(&c)), 7);
        assert_eq!(h.check(&c).err(), Some(Refused::KeyRevoked));
        w.unlock(&vault, Unlock::VaultPassphrase(PASS), "").unwrap();
        let h2 = w.pqz_scoped_key(&scope(ua, cu, None, 0)).unwrap();
        let acc2 = accepted(h2.check(&c), 7);
        assert_eq!(acc.entry_hash(), acc2.entry_hash());
        let win = [we(t1, 0, SLOT, Some(&good), Some(&acc2))];
        let d = deb(t1, 0, None, &win);
        let want = h2.seed_commitment().unwrap();
        let (in_tx, in_rx) = mpsc::channel();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let (locked_tx, locked_rx) = mpsc::channel();
        let (early, r) = std::thread::scope(|s| {
            let (h2, d) = (&h2, &d);
            let op = s.spawn(move || {
                h2.with_secret_debit(d, |seed, _t| {
                    in_tx.send(()).unwrap(); // inside the closure: the seed in use
                    go_rx.recv().unwrap();
                    keccak256(seed)
                })
            });
            in_rx.recv().expect("the closure ran");
            let locker = s.spawn(|| {
                w.lock();
                locked_tx.send(()).unwrap();
            });
            let early = locked_rx
                .recv_timeout(std::time::Duration::from_millis(500))
                .is_ok();
            go_tx.send(()).unwrap();
            let r = op.join().unwrap();
            locker.join().unwrap();
            (early, r)
        });
        assert!(!early, "lock() returned while the closure used the seed");
        assert_eq!(r, Ok(want));
        assert_eq!(h2.open_debit(&d).err(), Some(Refused::KeyRevoked));
    }

    /// `open_debit` with a real own part (`Enc(pk, amount)`, its `ownTag` by the handle's key): the balance is the own amount plus
    /// the window plus `shieldIn`; `T` equals the closure's `T` (the same gated parts).
    #[cfg(feature = "vectors")]
    #[test]
    fn open_debit_sums_the_gated_parts() {
        use scaas_ua::wallet::{hkdf_sha256, hmac_sha256};
        let (k, w, ua, cu) = kat();
        let t1 = a::<20>(&k["ownTagOpening"][0]["token"]);
        let h = w.pqz_scoped_key(&scope(ua, cu, None, 0)).unwrap();
        let pk: Box<[u8; PK_BYTES]> = h.pk().into_boxed_slice().try_into().unwrap();
        let e = pqzl::enc(&[&pk], &[digits(1000)], &[0x31; 32]).unwrap();
        let (pu, pvf) = (op::pack(&e.u[..]), op::pack(&e.vs[0]));
        let seed32 = h.with_secret_keygen(|s| *s).unwrap();
        let ctr = 4u32;
        let k_tag = hkdf_sha256(&seed32, &[], b"PQZ/owntag/v1", 32).unwrap();
        let tag = hmac_sha256(
            &k_tag,
            &[
                &cu[..],
                &t1,
                &ua,
                &ctr.to_be_bytes(),
                &keccak256(&[&pu[..], &pvf[..]].concat()),
            ]
            .concat(),
        );
        let good = credit_to(&h, &ua, &cu, &t1, 0x20, Plant::Honest, 3);
        let acc = accepted(h.check(&credit(t1, 6, &good)), 0x20);
        let win = [
            we(t1, 5, TRIVIAL, None, None),
            we(t1, 6, SLOT, Some(&good), Some(&acc)),
        ];
        let d = Debit {
            shield_in: 3,
            ..deb(
                t1,
                u64::from(ctr) + 1,
                Some(Own {
                    pu: &pu,
                    pvf: &pvf,
                    own_tag: tag,
                }),
                &win,
            )
        };
        let o = h.open_debit(&d).unwrap();
        assert_eq!(o.balance, 1000 + 100 + 0x20 + 3);
        assert_eq!(h.with_secret_debit(&d, |_, t| t.to_vec()), Ok(o.t));
        let mut bad = tag;
        bad[0] ^= 1;
        assert_eq!(
            h.open_debit(&Debit {
                own: Some(Own {
                    pu: &pu,
                    pvf: &pvf,
                    own_tag: bad
                }),
                ..d
            })
            .err(),
            Some(Refused::OwnTag)
        );
    }

    /// The reader pieces of opening.json's audited row, rebuilt from its seeds by pqz-ffi's sender side.
    struct Row {
        token: [u8; 20],
        cu: [u8; 32],
        to_ua: [u8; 32],
        a_ua: [u8; 32],
        pk_t: Box<[u8; PK_BYTES]>,
        pk_a: Box<[u8; PK_BYTES]>,
        ok_t: [u8; 96],
        ok_a: [u8; 96],
        kem_t: Vec<u8>,
        kem_a: Vec<u8>,
        leg: Leg,
        digits: [u8; 16],
        seed_t: [u8; 32],
    }
    fn opening_row(o: &Value) -> Row {
        let r = o["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["auditorOn"] == true)
            .unwrap();
        let aad_t = b(&r["aad_t"]);
        let (token, cu): ([u8; 20], [u8; 32]) = (
            aad_t[32..52].try_into().unwrap(),
            aad_t[..32].try_into().unwrap(),
        );
        let (to_ua, a_ua) = (a::<32>(&r["toUA"]), [0xA0u8; 32]);
        let seeds = o["openKemSeeds"].as_array().unwrap();
        let ok_t: [u8; 96] = a(&seeds
            .iter()
            .find(|s| {
                a::<32>(&s["ua"]) == to_ua
                    && b(&s["token"]).is_empty()
                    && n(&s["version"]) == 0
                    && a::<32>(&s["chainUid"]) == cu
            })
            .unwrap()["openKemSeed"]);
        assert_eq!(
            op::open_kem_seed(&a(&o["bip39_seed"]), &to_ua, &cu, None, 0),
            ok_t
        );
        // the auditor's opening KEM seed (ua 0xA0..) is no row of its own: pqz-ffi's, from the file's BIP-39 seed
        let ok_a = op::open_kem_seed(&a(&o["bip39_seed"]), &a_ua, &cu, None, 0);
        let (kf, kt, ka) = (
            pqzl::keygen(&a(&r["seed_f"])).unwrap(),
            pqzl::keygen(&a(&r["seed_t"])).unwrap(),
            pqzl::keygen(&a(&r["seed_a"])).unwrap(),
        );
        let d: [u8; 16] = r["digits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| n(x) as u8)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let df: [u8; 16] = r["digits_f"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| n(x) as u8)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let s = op::enc_split(
            &kf.pk,
            df,
            &to_ua,
            &kt.pk,
            d,
            Some(&ka.pk),
            &a(&r["seed_enc"]),
        )
        .unwrap();
        assert_eq!(s.seed_leg, a::<32>(&r["seed_leg"]));
        assert_eq!(keccak256(&s.leg.u[..]), a::<32>(&r["u_keccak"]));
        assert_eq!(
            (s.leg.vs[0].to_vec(), s.leg.vs[1].to_vec()),
            (b(&r["v_t"]), b(&r["v_a"]))
        );
        let leg = Leg {
            u: s.leg.u.to_vec(),
            v_t: s.leg.vs[0].to_vec(),
            v_a: Some(s.leg.vs[1].to_vec()),
            u_f: s.own.u.to_vec(),
            v_f: s.own.vs[0].to_vec(),
            o_t: b(&r["opening_t"]),
            o_a: Some(b(&r["opening_a"])),
        };
        Row {
            token,
            cu,
            to_ua,
            a_ua,
            pk_t: kt.pk.clone(),
            pk_a: ka.pk.clone(),
            ok_t,
            ok_a,
            kem_t: op::open_kem_pk(&ok_t),
            kem_a: op::open_kem_pk(&ok_a),
            leg,
            digits: d,
            seed_t: a(&r["seed_t"]),
        }
    }

    fn outcome_recipient(x: Option<[u8; 16]>) -> String {
        x.map_or("skip".into(), |d| format!("accepted:{}", hex::encode(d)))
    }
    fn outcome_auditor(x: AuditorOutcome) -> String {
        match x {
            AuditorOutcome::Read(d) => format!("read:{}", hex::encode(d)),
            AuditorOutcome::RecipientUnreadable => "recipient-unreadable".into(),
            AuditorOutcome::Unreadable => "unreadable".into(),
        }
    }

    /// T21 L66a: ua-rs reads every `opening.json` rejection row (the build's set) through pqz-ffi `check_recipient` /
    /// `check_auditor`: the row's credit rebuilt from its seeds (the honest openings byte-equal), each row's one change applied,
    /// both outcomes the row's exactly; positive control: the unchanged credit is accepted and read with the row's digits.
    #[test]
    fn opening_rejects_through_pqz_ffi() {
        let o = load(&format!("pqz/{}opening.json", set_dir()));
        let x = opening_row(&o);
        let (o_t, o_a) = (x.leg.o_t.clone(), x.leg.o_a.clone().unwrap());
        let (v_t, v_a): ([u8; 128], [u8; 128]) = (
            x.leg.v_t.clone().try_into().unwrap(),
            x.leg.v_a.clone().unwrap().try_into().unwrap(),
        );
        let u: Box<[u8; PK_BYTES]> = x.leg.u.clone().into_boxed_slice().try_into().unwrap();
        let to = Party {
            ua: &x.to_ua,
            key_version: 0,
            pk: &x.pk_t,
            kem_pk: &x.kem_t,
            v: &v_t,
            opening: &o_t,
        };
        let au = Party {
            ua: &x.a_ua,
            key_version: 0,
            pk: &x.pk_a,
            kem_pk: &x.kem_a,
            v: &v_a,
            opening: &o_a,
        };
        let c = op::Credit {
            chain_uid: &x.cu,
            token: &x.token,
            u: &u,
            to,
            auditor: Some(au),
        };
        let r1 = o["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["auditorOn"] == true)
            .unwrap();
        assert_eq!(op::aad(&c, &c.to), b(&r1["aad_t"]));
        assert_eq!(op::aad(&c, &au), b(&r1["aad_a"]));
        assert_eq!(
            op::seal(Role::Recipient, &c, &to, &a(&r1["seed_leg"])).unwrap(),
            o_t,
            "the honest O_t is K3-6's"
        );
        let d = hex::encode(x.digits);
        assert_eq!(
            outcome_recipient(op::check_recipient(&x.ok_t, &c)),
            format!("accepted:{d}"),
            "control"
        );
        assert_eq!(
            outcome_auditor(op::check_auditor(&x.ok_a, &c)),
            format!("read:{d}"),
            "control"
        );
        let rejects = o["rejects"].as_array().unwrap();
        assert!(rejects.len() >= 22);
        let mut seen = std::collections::BTreeSet::new();
        for r in rejects {
            let (field, v, case) = (
                r["field"].as_str().unwrap(),
                b(&r["value"]),
                r["case"].as_str().unwrap(),
            );
            seen.insert(field);
            let chain: [u8; 32];
            let e = match field {
                "to.opening" => op::Credit {
                    to: Party { opening: &v, ..to },
                    ..c
                },
                "auditor.opening" => op::Credit {
                    auditor: Some(Party { opening: &v, ..au }),
                    ..c
                },
                "to.kemPk" => op::Credit {
                    to: Party { kem_pk: &v, ..to },
                    ..c
                },
                "auditor.kemPk" => op::Credit {
                    auditor: Some(Party { kem_pk: &v, ..au }),
                    ..c
                },
                "chainUid" => {
                    chain = v.clone().try_into().unwrap();
                    op::Credit {
                        chain_uid: &chain,
                        ..c
                    }
                }
                "to.keyVersion" => op::Credit {
                    to: Party {
                        key_version: u64::from_be_bytes(v.clone().try_into().unwrap()),
                        ..to
                    },
                    ..c
                },
                f => panic!("an unknown field {f}"),
            };
            assert_eq!(
                outcome_recipient(op::check_recipient(&x.ok_t, &e)),
                r["recipient"].as_str().unwrap(),
                "{case}"
            );
            assert_eq!(
                outcome_auditor(op::check_auditor(&x.ok_a, &e)),
                r["auditor"].as_str().unwrap(),
                "{case}"
            );
            if let Some(want) = r.get("aad") {
                assert_eq!(op::aad(&e, &e.to), b(want), "{case}");
            }
        }
        assert_eq!(
            seen.into_iter().collect::<Vec<_>>(),
            [
                "auditor.kemPk",
                "auditor.opening",
                "chainUid",
                "to.kemPk",
                "to.keyVersion",
                "to.opening"
            ]
        );
    }

    /// The same rows through `PqzKeyHandle::check` (the handle of the row's recipient from its two secrets): every row whose
    /// field the handle takes from the credit skips (a stored opening of another length is no op 1 blob: `Input`, never an
    /// acceptance); the unchanged credit is accepted with the row's amount. The `to.kemPk` rows do not apply (the handle's
    /// `kemPk` is its own derivation, equal to the row's reader key). The review's F6: an audited leg without the auditor's keys,
    /// and an auditor key of another length, are `Input` (never an acceptance with the auditor unchecked).
    #[cfg(feature = "vectors")]
    #[test]
    fn opening_rejects_through_the_handle() {
        let o = load(&format!("pqz/{}opening.json", set_dir()));
        let x = opening_row(&o);
        let handle = |cu: [u8; 32], v: u64| {
            PqzKeyHandle::vectors_from_secrets(
                &x.seed_t,
                &x.ok_t,
                &Scope {
                    account: 0,
                    index: 0,
                    ua: x.to_ua,
                    chain_uid: cu,
                    token: None,
                    version: v,
                },
            )
            .unwrap()
        };
        let h = handle(x.cu, 0);
        assert_eq!(
            (h.pk(), h.open_kem_pk()),
            (x.pk_t.to_vec(), x.kem_t.clone())
        );
        let pk_a: &'static [u8] = Box::leak(x.pk_a.to_vec().into_boxed_slice());
        let aud = |kem: &'static [u8]| AuditorKeys {
            ua: x.a_ua,
            pk: pk_a,
            kem_pk: kem,
        };
        let kem_a: &'static [u8] = Box::leak(x.kem_a.clone().into_boxed_slice());
        let check_with = |h: &PqzKeyHandle, leg: &Leg, kv: u64, a: Option<AuditorKeys>| {
            let code = code_of(&x.to_ua, &[kv, 0], leg);
            h.check(&Credit {
                token: x.token,
                index: 4,
                slot: SLOT,
                code: &code,
                auditor: a,
                reads: READ1,
            })
        };
        let check =
            |h: &PqzKeyHandle, leg: &Leg, kv: u64, a: AuditorKeys| check_with(h, leg, kv, Some(a));
        let amount = x
            .digits
            .iter()
            .enumerate()
            .map(|(i, d)| u64::from(*d) << (4 * i))
            .sum();
        accepted(check(&h, &x.leg, 0, aud(kem_a)), amount);
        assert!(
            matches!(check_with(&h, &x.leg, 0, None), Err(Refused::Input(_))),
            "an audited leg without the auditor's keys"
        );
        let short = AuditorKeys {
            pk: &pk_a[1..],
            ..aud(kem_a)
        };
        assert!(
            matches!(check(&h, &x.leg, 0, short), Err(Refused::Input(_))),
            "an auditor key one byte short"
        );
        let mut ran = 0;
        for r in o["rejects"].as_array().unwrap() {
            let (field, v, case) = (
                r["field"].as_str().unwrap(),
                b(&r["value"]),
                r["case"].as_str().unwrap(),
            );
            let got = match field {
                "to.opening" => check(
                    &h,
                    &Leg {
                        o_t: v.clone(),
                        ..clone_leg(&x.leg)
                    },
                    0,
                    aud(kem_a),
                ),
                "auditor.opening" => check(
                    &h,
                    &Leg {
                        o_a: Some(v.clone()),
                        ..clone_leg(&x.leg)
                    },
                    0,
                    aud(kem_a),
                ),
                "auditor.kemPk" => {
                    check(&h, &x.leg, 0, aud(Box::leak(v.clone().into_boxed_slice())))
                }
                "chainUid" => check(
                    &handle(v.clone().try_into().unwrap(), 0),
                    &x.leg,
                    0,
                    aud(kem_a),
                ),
                "to.keyVersion" => {
                    let kv = u64::from_be_bytes(v.clone().try_into().unwrap());
                    check(&handle(x.cu, kv), &x.leg, kv, aud(kem_a))
                }
                _ => continue,
            };
            ran += 1;
            match got {
                Ok(Checked::Skip(_)) => assert_eq!(r["recipient"], "skip", "{case}"),
                Err(Refused::Input(_)) => assert_ne!(
                    v.len(),
                    pqz3k::OPENING,
                    "{case}: a stored opening of 1,648 bytes is a blob"
                ),
                g => panic!("{case}: {g:?}"),
            }
        }
        assert_eq!(
            ran,
            o["rejects"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|r| r["field"] != "to.kemPk")
                .count()
        );
    }
    fn clone_leg(l: &Leg) -> Leg {
        Leg {
            u: l.u.clone(),
            v_t: l.v_t.clone(),
            v_a: l.v_a.clone(),
            u_f: l.u_f.clone(),
            v_f: l.v_f.clone(),
            o_t: l.o_t.clone(),
            o_a: l.o_a.clone(),
        }
    }

    /// The test constructor from the raw seed equals the wallet's derivation; the class seeds of two chains, two tokens and
    /// versions 0 and 1 are pairwise distinct (spec §14.7).
    #[cfg(feature = "vectors")]
    #[test]
    fn raw_seed_constructor_equals_the_wallet() {
        let (k, w, ua, cu) = kat();
        let seed = bip39_seed(k["mnemonic"].as_str().unwrap());
        let s = scope(ua, cu, Some([0xa1; 20]), 1);
        let (h, r) = (
            w.pqz_scoped_key(&s).unwrap(),
            PqzKeyHandle::vectors_from_seed(&seed, &s).unwrap(),
        );
        assert_eq!(
            (h.seed_commitment(), h.pk(), h.open_kem_pk()),
            (r.seed_commitment(), r.pk(), r.open_kem_pk())
        );
        let mut all = std::collections::HashSet::new();
        for cu in [[0xc1u8; 32], [0xc2; 32]] {
            for v in 0..2 {
                for t in [None, Some([0xa1u8; 20]), Some([0xa2; 20])] {
                    assert!(all.insert(
                        PqzKeyHandle::vectors_from_seed(&seed, &scope([1; 32], cu, t, v))
                            .unwrap()
                            .seed_commitment()
                            .unwrap()
                    ));
                }
            }
        }
    }
}
