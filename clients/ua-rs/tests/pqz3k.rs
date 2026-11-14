// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `scaas_ua::pqz3k` against the shared rows: pq_kat.json `pqzScopedSeeds` and `memoHashOpening` (clientkeys), opening.json's
//! `openKemSeeds` and leg seeds (pqz-ffi), typed_ops.json's `PqzRollOver` row (clientkeys; the contract pins its typehash).
use scaas_ua::{keccak256, pqz3k};
use serde_json::Value;

fn load(p: &str) -> Value {
    let path = format!("{}/../../smartcontracts/vectors/{p}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn b(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn a<const N: usize>(v: &Value) -> [u8; N] {
    b(v).try_into().unwrap()
}
fn n(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
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

/// pq_kat.json's scoped seeds through the handle (its commitment; the seed never leaves it) and, for a token without the opening,
/// the one raw export; the opening `memoHash`.
#[test]
fn scoped_seeds_and_memo_hash() {
    let k = load("ua/pq_kat.json");
    let seed = bip39_seed(k["mnemonic"].as_str().unwrap());
    let rows = k["pqzScopedSeeds"].as_array().unwrap();
    assert_eq!(rows.len(), 12);
    for r in rows {
        let tok = r.get("token").map(a::<20>);
        let (cu, v, want) = (a::<32>(&r["chainUid"]), n(&r["version"]), a::<32>(&r["seed32"]));
        let h = pqz3k::PqzKeyHandle::new(&seed, n(&r["account"]) as u32, n(&r["index"]) as u32, &[0x11; 32], &cu, tok.as_ref(), v, L);
        assert_eq!(h.seed_commitment(), keccak256(&want), "{}", r["keyClass"]);
        if let Some(t) = tok {
            assert_eq!(pqz3k::pqz_token_key_seed_without_opening(&seed, 0, 0, &cu, &t, v), want);
        }
    }
    for r in k["memoHashOpening"].as_array().unwrap() {
        let os: Vec<Vec<u8>> = r["openings"].as_array().unwrap().iter().map(b).collect();
        let refs: Vec<&[u8]> = os.iter().map(|o| &o[..]).collect();
        assert_eq!(pqz3k::opening_memo_hash(&b(&r["memo"]), &a(&r["ownTag"]), &refs), a::<32>(&r["memoHash"]));
    }
}

/// pqz3k_kat.json (clientkeys, Fable P2-2; forge PqzClientRows checks it against the contracts): the handle's commitments, `h(i)`
/// and `entriesHash`, the scoped record digests and messages, the opening blob's fields; `ownTag` over `u_f` opens
/// `with_secret_own` (and one changed byte of `P(u_f)` does not).
#[test]
fn client_rows() {
    let k = load("ua/pqz3k_kat.json");
    let seed = bip39_seed(k["mnemonic"].as_str().unwrap());
    let (cu, ua) = (a::<32>(&k["chainUid"]), a::<32>(&k["ua"]));
    let l = pqz3k::Layout { pkp: n(&k["layout"]["pkp"]) as usize, vp: n(&k["layout"]["vp"]) as usize };
    assert_eq!(l, L);
    for r in k["handles"].as_array().unwrap() {
        let tok = r.get("token").map(a::<20>);
        let h = pqz3k::PqzKeyHandle::new(&seed, 0, 0, &ua, &cu, tok.as_ref(), n(&r["version"]), l);
        assert_eq!(h.seed_commitment(), a::<32>(&r["seedCommitment"]));
    }
    for r in k["ownTagOpening"].as_array().unwrap() {
        let scope = (r["keyClass"] == "offchain-token").then(|| a::<20>(&r["token"]));
        let h = pqz3k::PqzKeyHandle::new(&seed, 0, 0, &ua, &cu, scope.as_ref(), 0, l);
        let (mut puf, pvf) = (b(&r["puf"]), b(&r["pvf"]));
        let own = |puf: &[u8]| pqz3k::Own { token: a(&r["token"]), send_counter: n(&r["sendCounter"]) as u32, pu: puf, pvf: &pvf,
            own_tag: a(&r["ownTag"]) };
        assert_eq!(h.with_secret_own(&own(&puf), |_| 1), Ok(1));
        puf[7] ^= 1;
        assert_eq!(h.with_secret_own(&own(&puf), |_| 2), Err(pqz3k::Refused::OwnTag), "u_f alone differs");
        assert_eq!(h.secret_loads(), 1);
    }
    let code = b(&k["entries"]["code"]);
    let mut hs = vec![];
    for r in k["entries"]["rows"].as_array().unwrap() {
        let c = r["code"].as_bool().unwrap().then_some(&code[..]);
        let h = pqz3k::entry_hash(n(&r["index"]), &a(&r["slot"]), c);
        assert_eq!(h, a::<32>(&r["h"]), "{}", r["what"]);
        hs.push(h);
    }
    assert_eq!(pqz3k::entries_hash(&hs), a::<32>(&k["entries"]["entriesHash"]));
    for r in k["scopedKeyRecords"].as_array().unwrap() {
        let (u, cls, t, v) = (a::<32>(&r["ua"]), n(&r["keyClass"]) as u8, a::<20>(&r["token"]), n(&r["version"]));
        let kd = pqz3k::scoped_key_digest(&u, cls, &a(&r["chainUid"]), &t, v, &a(&r["pqzKeyHash"]));
        let rd = pqz3k::scoped_key_record_digest(&u, cls, &a(&r["chainUid"]), &t, v, &a(&r["pqzKeyHash"]), &a(&r["pqzPopHash"]),
            &a(&r["openKemHash"]), n(&r["validUntilBlock"]));
        assert_eq!((kd, rd), (a::<32>(&r["keyDigest"]), a::<32>(&r["recordDigest"])));
        let p = pqz3k::purpose_pqz_scoped_key();
        assert_eq!(scaas_ua::ua_message(n(&r["kind"]) as u16, &p, &rd).unwrap(), a::<32>(&r["message"]));
        assert_eq!(scaas_ua::ua_message(0x0142, &p, &kd).unwrap(), a::<32>(&r["regMessage"]));
    }
    let ob = &k["openingBlob"];
    let code = b(&ob["code"]);
    let blob = pqz3k::opening_blob(&code[1..], l).expect("the row's blob");
    let at = |f: &str| n(&ob["at"][f]) as usize;
    let d = &code[1..];
    assert_eq!((blob.pu, blob.pva.unwrap(), blob.puf, blob.o_t, blob.o_a.unwrap()),
        (&d[at("pu")..at("pvt")], &d[at("pva")..at("toUA")], &d[at("puf")..at("pvf")], &d[at("oT")..at("oA")], &d[at("oA")..at("ownTag")]));
    assert_eq!((blob.to_ua, blob.own_tag, blob.kv.clone()), (d[at("toUA")..at("puf")].try_into().unwrap(),
        d[at("ownTag")..at("kv")].try_into().unwrap(), vec![0, 2]));
    assert_eq!(pqz3k::opening_blob(&d[..d.len() - 1], l), None, "one byte short");
}

#[test]
fn open_kem_seeds_and_leg_seeds_equal_pqz_ffi() {
    let o = load("pqz/opening.json");
    let seed: [u8; 64] = a(&o["bip39_seed"]);
    for r in o["openKemSeeds"].as_array().unwrap() {
        let tok = b(&r["token"]);
        let t: Option<[u8; 20]> = (!tok.is_empty()).then(|| tok.try_into().unwrap());
        let got = pqz3k::open_kem_seed(&seed, &a(&r["ua"]), &a(&r["chainUid"]), t.as_ref(), n(&r["version"]));
        assert_eq!(got.to_vec(), b(&r["openKemSeed"]));
    }
    for r in o["rows"].as_array().unwrap() {
        assert_eq!(pqz3k::leg_seed(&a(&r["seed_enc"]), &a(&r["toUA"]), &a(&r["pk_t_keccak"])), a::<32>(&r["seed_leg"]));
    }
    // the class seeds: two chains, two tokens, versions 0 and 1 pairwise distinct (by the handles' commitments)
    let mut s = std::collections::HashSet::new();
    for cu in [[0xc1u8; 32], [0xc2; 32]] {
        for v in 0..2 {
            assert!(s.insert(pqz3k::PqzKeyHandle::new(&seed, 0, 0, &[1; 32], &cu, None, v, L).seed_commitment()));
            for t in [[0xa1u8; 20], [0xa2; 20]] {
                assert!(s.insert(pqz3k::PqzKeyHandle::new(&seed, 0, 0, &[1; 32], &cu, Some(&t), v, L).seed_commitment()));
            }
        }
    }
}

#[test]
fn roll_over_struct_hash_equals_typed_ops() {
    let r = &load("typed/typed_ops.json")["ops"]["PqzRollOver"];
    assert_eq!(keccak256(pqz3k::ROLL_OVER_TYPE.as_bytes()), a::<32>(&r["typehash"]));
    let m = &r["message"];
    let skip: Vec<u64> = m["skip"].as_array().unwrap().iter().map(n).collect();
    let h = pqz3k::roll_over_struct_hash(&a(&m["ua"]), n(&m["keyVersion"]), n(&m["rollSeq"]), n(&m["rolled"]), n(&m["n"]), &skip,
        &a(&m["entriesHash"]), n(&m["validUntilBlock"]), &a(&m["chainUid"]));
    assert_eq!(h, a::<32>(&r["structHash"]));
}

// ------------------------------------------------------------------ the key handle (Fable P1-1, P2-1; spec §14.1, §14.18)

const SLOT_CREDIT: [u8; 32] = {
    let mut w = [0u8; 32];
    w[0] = 0x5e; // blob address high byte
    w[21] = 16; // offset 16
    w[23] = 200; // length 200
    w[31] = 7; // block 7
    w
};
fn marked(s: [u8; 32]) -> [u8; 32] {
    let mut m = s;
    m[24] |= 0x80;
    m
}
const TRIVIAL: [u8; 32] = {
    let mut w = [0u8; 32];
    w[19] = 100; // amount in the address field, length 0
    w[31] = 9;
    w
};

/// An opening op 1 blob's code for `to` at key version `kv0`, auditor on when `aud`.
fn blob_code(to: &[u8; 32], kv0: u64, aud: bool, fill: u8) -> Vec<u8> {
    let n = if aud { 2 } else { 1 };
    let mut d = vec![0u8]; // STOP
    d.extend(vec![fill; 16 + L.pkp + L.vp * n]);
    d.extend(to);
    d.extend(vec![fill; L.pkp + L.vp + pqz3k::OPENING * n + 32]);
    d.extend(kv0.to_be_bytes());
    if aud {
        d.extend(3u64.to_be_bytes());
    }
    d.push(n as u8);
    d
}

const READ1: pqz3k::Reads = pqz3k::Reads { block: 100, finalized: false, strict_majority: false };
const READF: pqz3k::Reads = pqz3k::Reads { block: 90, finalized: true, strict_majority: true };

/// §14.1 / §14.18 on a class-2 and a class-3 opening handle: a planted credit (the binding's check says skip, in the variants a
/// check sees: junk opening, a valid KEM ciphertext of a wrong seed, a crafted `u*`) never loads the PQZ seed: a window holding
/// it unmarked is refused, counter 0; marked, the next window loads it once. Control: an honest credit is accepted and its
/// window loads the seed. A window entry accepted by another handle, at another index or with other bytes is refused.
#[test]
fn key_handle_gates_the_secret() {
    use pqz3k::{Checked, Credit, PqzKeyHandle, Refused, WindowEntry};
    let seed = [7u8; 64];
    let (ua, cu, t1, t2) = ([0x11u8; 32], [0xc1u8; 32], [0xa1u8; 20], [0xa2u8; 20]);
    for scope in [None, Some(t1)] {
        let h = PqzKeyHandle::new(&seed, 0, 0, &ua, &cu, scope.as_ref(), 0, L);
        let other = PqzKeyHandle::new(&seed, 0, 0, &ua, &cu, scope.as_ref(), 1, L);
        let (good, bad) = (blob_code(&ua, 0, false, 1), blob_code(&ua, 0, false, 2));
        let credit = |i, code: &'static [u8]| Credit { token: t1, index: i, slot: SLOT_CREDIT, code, auditor: None, reads: READ1 };
        let good: &'static [u8] = Box::leak(good.into_boxed_slice());
        let bad: &'static [u8] = Box::leak(bad.into_boxed_slice());
        // the check gets this record's opening KEM seed and the handle's own aad
        let want_kem = pqz3k::open_kem_seed(&seed, &ua, &cu, scope.as_ref(), 0);
        let acc = match h.check(&credit(0, good), |k, inp| {
            assert_eq!(k, &want_kem);
            assert_eq!(inp.aad_recipient, pqz3k::opening_aad(&cu, &t1, &ua, 0, inp.blob.pu, inp.blob.pvt));
            Some(42u128)
        }) {
            Ok(Checked::Accepted(a, 42)) => a,
            r => panic!("the honest credit: {r:?}"),
        };
        assert_eq!(acc.entry_hash(), pqz3k::entry_hash(0, &SLOT_CREDIT, Some(good)));
        // three planted variants: the binding's check refuses each; the outcome is one skip
        let mut skips = vec![];
        for variant in ["junk opening", "valid KEM ciphertext, wrong seed", "crafted u*"] {
            match h.check(&credit(1, bad), |_, _| -> Option<u128> { None }) {
                Ok(Checked::Skip(s)) => skips.push(s),
                r => panic!("{variant}: {r:?}"),
            }
        }
        let w = |slot1: [u8; 32]| [
            WindowEntry { index: 0, slot: SLOT_CREDIT, code: Some(good), accepted: Some(&acc) },
            WindowEntry { index: 1, slot: slot1, code: Some(bad), accepted: None },
            WindowEntry { index: 2, slot: TRIVIAL, code: None, accepted: None },
        ];
        assert_eq!(h.with_secret_window(&w(SLOT_CREDIT), |_| ()), Err(Refused::Window), "an unaccepted unmarked credit");
        assert_eq!(h.secret_loads(), 0, "the secret was never loaded");
        // a skip read from one node at an unfinalized block is no reason to mark (Fable P2-1)
        assert_eq!(PqzKeyHandle::marks(&skips), Err(Refused::Unconfirmed));
        let again: Vec<_> = skips.iter().map(|s| pqz3k::Skip { reads: READF, ..s.clone() }).collect();
        assert_eq!(PqzKeyHandle::marks(&again), Ok(vec![1]));
        assert_eq!(h.with_secret_window(&w(marked(SLOT_CREDIT)), |s| s.len()), Ok(32), "the mark landed: the window proves");
        assert_eq!(h.secret_loads(), 1);
        // the acceptance is bound to the handle, the index and the bytes
        let only = |e: WindowEntry| [e];
        assert_eq!(other.with_secret_window(&only(w(SLOT_CREDIT)[0]), |_| ()), Err(Refused::Window), "another handle's acceptance");
        let mut e = w(SLOT_CREDIT)[0];
        e.index = 3;
        assert_eq!(h.with_secret_window(&only(e), |_| ()), Err(Refused::Window), "another index");
        let mut e = w(SLOT_CREDIT)[0];
        e.code = Some(bad);
        assert_eq!(h.with_secret_window(&only(e), |_| ()), Err(Refused::Window), "other bytes");
        assert_eq!(h.secret_loads(), 1);
        // not this handle's credit, or incomplete inputs: refused before the check runs
        let never = |_: &[u8; 96], _: &pqz3k::CheckInput| -> Option<u128> { panic!("the check ran") };
        let other_to: &'static [u8] = Box::leak(blob_code(&[0x22; 32], 0, false, 1).into_boxed_slice());
        let other_kv: &'static [u8] = Box::leak(blob_code(&ua, 1, false, 1).into_boxed_slice());
        let audited: &'static [u8] = Box::leak(blob_code(&ua, 0, true, 1).into_boxed_slice());
        assert_eq!(h.check(&credit(0, other_to), never).err(), Some(Refused::NotThisHandle), "another recipient");
        assert_eq!(h.check(&credit(0, other_kv), never).err(), Some(Refused::NotThisHandle), "another key version");
        assert!(matches!(h.check(&credit(0, audited), never), Err(Refused::Input(_))), "an audited leg without the auditor's keys");
        assert!(matches!(h.check(&credit(0, &good[..good.len() - 1]), never), Err(Refused::Input(_))), "a short blob");
        let mut c = credit(0, good);
        c.slot = TRIVIAL;
        assert!(matches!(h.check(&c, never), Err(Refused::Input(_))), "a TRIVIAL entry");
        let mut c = credit(0, good);
        c.token = t2;
        let r = h.check(&c, |_, _| Some(1u128));
        if scope.is_some() {
            assert_eq!(r.err(), Some(Refused::NotThisHandle), "a class-3 handle given another token's credit");
        } else {
            assert!(matches!(r, Ok(Checked::Accepted(..))), "a class-2 key serves every class-2 token");
        }
        // keygen is counted apart; Debug shows no secret
        assert_eq!(h.with_secret_keygen(|s| s.len()), 32);
        assert_eq!((h.keygens(), h.secret_loads()), (1, 1));
        let d = format!("{h:?}");
        assert!(!d.contains("seed") && d.contains("PqzKeyHandle"), "{d}");
    }
}
