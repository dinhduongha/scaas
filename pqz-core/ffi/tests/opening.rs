// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Opening tokens (spec three-key model §14 items 2, 13, 14, 19, 21): split randomness, the sealed opening, the holder
//! check and the auditor tool. Every negative changes one thing against the honest fixture, whose acceptance is the
//! positive control beside it; a ciphertext change is resealed honestly so that only the step under test fails.
//! Not constructible here (and why): a leg whose randomness is over the norm bound (the check re-expands `seed_leg`
//! with the resampling sampler, so no seed expands over the bound), `u_f == u` (a SHAKE256 collision), the counting
//! key handle (no function here takes the PQZ secret `s`: the check's inputs are public bytes and the opening KEM seed).
use pqz_ffi::opening::{
    self, check_auditor, check_recipient, coins, enc_split, leg_seed, open_kem_pk, open_kem_seed, seal, taken,
    AuditorOutcome as Ao, Credit, Party, Role, OPENING,
};
use pqz_ffi::pqzl::{self, PK_BYTES};
use pqz_ffi::stmt::{DELTA, Q};

const MNEMONIC_SEED: [u8; 64] = [0x42; 64];
const CHAIN: [u8; 32] = [0xC1; 32];
const TOKEN: [u8; 20] = [0x70; 20];
const TO: [u8; 32] = [0x11; 32];
const AUD: [u8; 32] = [0xA0; 32];

fn pk(seed: u8) -> Box<[u8; PK_BYTES]> {
    pqzl::keygen(&[seed; 32]).expect("keygen").pk.clone()
}

/// An honest op 1 leg with its openings, as the sender builds it.
#[derive(Clone)]
struct Fx {
    pk_t: Box<[u8; PK_BYTES]>,
    pk_a: Box<[u8; PK_BYTES]>,
    seed_t: [u8; 96],
    seed_a: [u8; 96],
    kem_t: Vec<u8>,
    kem_a: Vec<u8>,
    u: Box<[u8; PK_BYTES]>,
    v_t: [u8; 128],
    v_a: [u8; 128],
    o_t: Vec<u8>,
    o_a: Vec<u8>,
    aud: bool,
    token: [u8; 20],
    to: [u8; 32],
    d: [u8; 16],
    seed_leg: [u8; 32],
}

impl Fx {
    fn new(aud: bool) -> Fx {
        let (pk_f, pk_t, pk_a) = (pk(1), pk(2), pk(3));
        let seed_t = open_kem_seed(&MNEMONIC_SEED, &TO, &CHAIN, None, 0);
        let seed_a = open_kem_seed(&[0x43; 64], &AUD, &CHAIN, None, 0);
        let d: [u8; 16] = core::array::from_fn(|i| (i as u8 * 7 + 3) % 16);
        let s = enc_split(&pk_f, [1; 16], &TO, &pk_t, d, aud.then_some(&*pk_a), &[9; 32]).expect("enc_split");
        let mut f = Fx {
            kem_t: open_kem_pk(&seed_t),
            kem_a: open_kem_pk(&seed_a),
            pk_t,
            pk_a,
            seed_t,
            seed_a,
            u: s.leg.u.clone(),
            v_t: s.leg.vs[0],
            v_a: if aud { s.leg.vs[1] } else { [0; 128] },
            o_t: vec![],
            o_a: vec![],
            aud,
            token: TOKEN,
            to: TO,
            d,
            seed_leg: s.seed_leg,
        };
        f.reseal();
        f
    }

    fn party<'a>(&'a self, ua: &'a [u8; 32], pk: &'a [u8; PK_BYTES], kem: &'a [u8], v: &'a [u8; 128], o: &'a [u8]) -> Party<'a> {
        Party { ua, key_version: 0, pk, kem_pk: kem, v, opening: o }
    }

    fn credit(&self) -> Credit<'_> {
        Credit {
            chain_uid: &CHAIN,
            token: &self.token,
            u: &self.u,
            to: self.party(&self.to, &self.pk_t, &self.kem_t, &self.v_t, &self.o_t),
            auditor: self.aud.then(|| self.party(&AUD, &self.pk_a, &self.kem_a, &self.v_a, &self.o_a)),
        }
    }

    /// The honest openings of `seed_leg` over the current bytes (K3-6).
    fn reseal(&mut self) {
        let c = self.credit();
        let o_t = seal(Role::Recipient, &c, &c.to, &self.seed_leg).expect("seal O_t");
        let o_a = c.auditor.map(|a| seal(Role::Auditor, &c, &a, &self.seed_leg).expect("seal O_a"));
        self.o_t = o_t;
        self.o_a = o_a.unwrap_or_default();
    }

    fn recipient(&self) -> Option<[u8; 16]> {
        check_recipient(&self.seed_t, &self.credit())
    }

    fn auditor(&self) -> Ao {
        check_auditor(&self.seed_a, &self.credit())
    }
}

fn be8(v: &[u8], i: usize) -> u64 {
    u64::from_be_bytes(v[8 * i..8 * i + 8].try_into().unwrap())
}

fn set_be8(v: &mut [u8], i: usize, x: u64) {
    v[8 * i..8 * i + 8].copy_from_slice(&x.to_be_bytes());
}

#[test]
fn honest_accepted_both_roles() {
    let f = Fx::new(true);
    assert_eq!(f.o_t.len(), OPENING);
    assert_eq!(f.recipient(), Some(f.d));
    assert_eq!(f.auditor(), Ao::Read(f.d));
    let f = Fx::new(false);
    assert_eq!(f.recipient(), Some(f.d));
    assert_eq!(f.auditor(), Ao::Unreadable); // no auditor copy
}

/// §14 item 2: one change per K3-7 step, each the identical outcome `None`; with and without the auditor (with it, step 9's
/// digit comparison would also catch a step-7 fault, so each step-7 case must fail alone).
#[test]
fn holder_check_one_mutant_per_step() {
    for aud in [true, false] {
        holder_check_cases(Fx::new(aud));
    }
}

fn holder_check_cases(f: Fx) {
    assert_eq!(f.recipient(), Some(f.d)); // control
    let mut cases: Vec<(&str, Fx, Option<[u8; 96]>)> = vec![];
    // step 3: the opening KEM key of another version or chain
    cases.push(("other version's opening key", f.clone(), Some(open_kem_seed(&MNEMONIC_SEED, &TO, &CHAIN, None, 1))));
    cases.push(("other chain's opening key", f.clone(), Some(open_kem_seed(&MNEMONIC_SEED, &TO, &[0xC2; 32], None, 0))));
    cases.push(("offchain-token label's key", f.clone(), Some(open_kem_seed(&MNEMONIC_SEED, &TO, &CHAIN, Some(&TOKEN), 0))));
    // step 4: decapsulation and the tag
    for (name, at) in [("mlkemCt bit", 100usize), ("x25519Eph bit", 1568 + 5), ("tag bit", OPENING - 1)] {
        let mut g = f.clone();
        g.o_t[at] ^= 1;
        cases.push((name, g, None));
    }
    let mut g = f.clone();
    g.token = [0x71; 20]; // aad of another token
    cases.push(("aad token", g, None));
    let mut g = f.clone();
    g.to = [0x12; 32]; // aad of another UA
    cases.push(("aad ua", g, None));
    // aad of another ciphertext: an opening sealed over another v_t, then the honest v_t stored
    let mut g = f.clone();
    g.v_t[127] ^= 1;
    g.reseal();
    g.v_t = f.v_t;
    cases.push(("aad ciphertext", g, None));
    // step 5/6: the seed of another leg (a valid KEM ciphertext sealing a wrong seed)
    let mut g = f.clone();
    g.seed_leg = leg_seed(&[8; 32], &TO, &f.pk_t);
    g.reseal();
    cases.push(("seed of another leg", g, None));
    // step 6: u off by one coefficient (resealed)
    let mut g = f.clone();
    set_be8(&mut g.u[..], 0, (be8(&f.u[..], 0) + 1) % Q);
    g.reseal();
    cases.push(("u off by one", g, None));
    // step 6: u with a coefficient as c + q (same value mod q, not P(u))
    let mut g = f.clone();
    set_be8(&mut g.u[..], 3, be8(&f.u[..], 3) + Q);
    g.reseal();
    cases.push(("u not canonical", g, None));
    // step 7: v_t off by one e2, digit 16, v_t not canonical
    let mut g = f.clone();
    set_be8(&mut g.v_t, 2, (be8(&f.v_t, 2) + 1) % Q);
    g.reseal();
    cases.push(("v_t off by one e2", g, None));
    let mut g = f.clone();
    let i = f.d.iter().position(|&x| x == 15).expect("a digit 15");
    set_be8(&mut g.v_t, i, (be8(&f.v_t, i) + DELTA as u64) % Q); // d_i = 16
    g.reseal();
    cases.push(("digit 16", g, None));
    let mut g = f.clone();
    set_be8(&mut g.v_t, 4, be8(&f.v_t, 4) + Q);
    g.reseal();
    cases.push(("v_t not canonical", g, None));
    // step 8: O_t a valid opening of the right seed with other coins (role 1's)
    let mut g = f.clone();
    let c = g.credit();
    g.o_t = seal(Role::Auditor, &c, &c.to, &g.seed_leg).unwrap();
    cases.push(("O_t other coins", g, None));
    // step 9: junk O_a; v_a off by one e2; v_a of another digit
    if !f.aud {
        return run_cases(cases);
    }
    let mut g = f.clone();
    g.o_a[200] ^= 1;
    cases.push(("O_a junk", g, None));
    let mut g = f.clone();
    set_be8(&mut g.v_a, 0, (be8(&f.v_a, 0) + 1) % Q);
    g.reseal();
    cases.push(("v_a off by one e2", g, None));
    let mut g = f.clone();
    let j = f.d.iter().position(|&x| x < 15).unwrap();
    set_be8(&mut g.v_a, j, (be8(&f.v_a, j) + DELTA as u64) % Q);
    g.reseal();
    cases.push(("v_a another digit", g, None));
    run_cases(cases)
}

fn run_cases(cases: Vec<(&str, Fx, Option<[u8; 96]>)>) {
    for (name, g, key) in cases {
        let got = check_recipient(&key.unwrap_or(g.seed_t), &g.credit());
        assert_eq!(got, None, "{name} (auditor {})", g.aud);
    }
}

/// §14 item 13 and 19: the auditor's outcomes and the recipient's with them.
#[test]
fn auditor_outcomes() {
    let f = Fx::new(true);
    assert_eq!((f.recipient(), f.auditor()), (Some(f.d), Ao::Read(f.d))); // control
    let mut g = f.clone();
    g.o_a[1600] ^= 1; // junk O_a, valid O_t
    assert_eq!((g.recipient(), g.auditor()), (None, Ao::Unreadable));
    let mut g = f.clone();
    g.o_t[10] ^= 1; // junk O_t, valid O_a
    assert_eq!((g.recipient(), g.auditor()), (None, Ao::RecipientUnreadable));
    let mut g = f.clone();
    set_be8(&mut g.v_t, 0, (be8(&f.v_t, 0) + 1) % Q); // bad v_t, honest openings over it
    g.reseal();
    assert_eq!((g.recipient(), g.auditor()), (None, Ao::RecipientUnreadable));
    // O_a sealed with other coins than K3-6's (role 0's): a valid opening, not byte-equal
    let mut g = f.clone();
    let c = g.credit();
    g.o_a = seal(Role::Recipient, &c, &c.auditor.unwrap(), &g.seed_leg).unwrap();
    assert_eq!(g.recipient(), None);
    // the auditor's opening given to the recipient; an opening to another UA's KEM key
    let mut g = f.clone();
    g.o_t = f.o_a.clone();
    assert_eq!(g.recipient(), None);
    let mut g = f.clone();
    let other = open_kem_pk(&open_kem_seed(&[0x44; 64], &[0x13; 32], &CHAIN, None, 0));
    let c = g.credit();
    g.o_t = seal(Role::Recipient, &c, &Party { kem_pk: &other, ..c.to }, &g.seed_leg).unwrap();
    assert_eq!(g.recipient(), None);
}

/// A small-order X25519 point as E: skipped (the same outcome), and refused as a recipient key by seal.
#[test]
fn low_order_x25519() {
    let f = Fx::new(false);
    for e in [[0u8; 32], { let mut x = [0u8; 32]; x[0] = 1; x }] {
        let mut g = f.clone();
        g.o_t[1568..1600].copy_from_slice(&e);
        assert_eq!(g.recipient(), None);
    }
    let mut kem = f.kem_t.clone();
    kem[1569..].fill(0);
    let c = f.credit();
    assert!(seal(Role::Recipient, &c, &Party { kem_pk: &kem, ..c.to }, &f.seed_leg).is_none());
    assert!(seal(Role::Recipient, &c, &c.to, &f.seed_leg).is_some()); // control
}

/// §14 item 21 (the ffi part): the leg seed moves with seed_enc, the recipient UA and its key; u_f != u; equal keys refused.
#[test]
fn split_seeds() {
    let (pk_f, pk_t, pk_a) = (pk(1), pk(2), pk(3));
    let s0 = leg_seed(&[9; 32], &TO, &pk_t);
    assert_ne!(s0, leg_seed(&[10; 32], &TO, &pk_t));
    assert_ne!(s0, leg_seed(&[9; 32], &[0x12; 32], &pk_t));
    assert_ne!(s0, leg_seed(&[9; 32], &TO, &pk_a));
    let a = enc_split(&pk_f, [1; 16], &TO, &pk_t, [2; 16], Some(&pk_a), &[9; 32]).unwrap();
    let b = enc_split(&pk_f, [1; 16], &TO, &pk_t, [2; 16], Some(&pk_a), &[10; 32]).unwrap();
    assert_eq!(a.seed_leg, s0);
    assert_ne!(a.own.u, a.leg.u);
    assert!(a.own.u != b.own.u && a.leg.u != b.leg.u);
    // the sender's own part is today's Enc of pk_f alone under seed_enc; the leg's is Enc under seed_leg
    assert_eq!(a.own.u, pqzl::enc(&[&*pk_f], &[[1; 16]], &[9; 32]).unwrap().u);
    assert_eq!(a.leg.vs, pqzl::enc(&[&*pk_t, &*pk_a], &[[2; 16]; 2], &s0).unwrap().vs);
    assert!(enc_split(&pk_f, [1; 16], &TO, &pk_f, [2; 16], None, &[9; 32]).is_none());
    assert!(enc_split(&pk_f, [1; 16], &TO, &pk_t, [2; 16], Some(&pk_t), &[9; 32]).is_none());
    assert!(enc_split(&pk_f, [1; 16], &TO, &pk_t, [2; 16], Some(&pk_f), &[9; 32]).is_none());
}

/// K3-6b and §14 items 7, 14: openKemSeed rows pairwise distinct over class, chain, token and version; mnemonic only
/// restores the keys of versions 0 and 1, and each opens only its own version's openings.
#[test]
fn open_kem_seeds_and_restore() {
    let mut seen = std::collections::HashSet::new();
    for chain in [[0xC1u8; 32], [0xC2; 32]] {
        for token in [None, Some([0x70u8; 20]), Some([0x71; 20])] {
            for v in [0u64, 1] {
                let s = open_kem_seed(&MNEMONIC_SEED, &TO, &chain, token.as_ref(), v);
                assert!(seen.insert(s.to_vec()), "duplicate seed");
                assert_eq!(open_kem_pk(&s).len(), opening::KEM_PK);
            }
        }
    }
    let f = Fx::new(false);
    let k1 = open_kem_seed(&MNEMONIC_SEED, &TO, &CHAIN, None, 1);
    let mut g = f.clone();
    g.kem_t = open_kem_pk(&k1);
    g.reseal();
    assert_eq!(check_recipient(&open_kem_seed(&MNEMONIC_SEED, &TO, &CHAIN, None, 0), &f.credit()), Some(f.d));
    assert_eq!(check_recipient(&k1, &g.credit()), Some(g.d));
    assert_eq!(check_recipient(&k1, &f.credit()), None);
    assert_eq!(check_recipient(&f.seed_t, &g.credit()), None);
}

/// Coins: one-way in seed_leg, distinct per role and key.
#[test]
fn coins_distinct() {
    let f = Fx::new(true);
    let c = coins(&f.seed_leg, Role::Recipient, &f.kem_t);
    assert_ne!(c, coins(&f.seed_leg, Role::Auditor, &f.kem_t));
    assert_ne!(c, coins(&f.seed_leg, Role::Recipient, &f.kem_a));
    assert_ne!(c, coins(&[0; 32], Role::Recipient, &f.kem_t));
}

#[test]
fn unreadable_taken() {
    assert!(taken(3, 5, 0, false));
    assert!(taken(3, 0, 4, false));
    assert!(!taken(3, 5, 4, true)); // marked
    assert!(!taken(5, 5, 5, false)); // still pending
}

/// The sealed seed's `aad` binds the stored form (CTR-PQZ-40): `keccak256(P(u) ‖ P(v))` with `P` the contract's packing.
/// `pack` is checked against the contract itself: the first entry of the set's state.json (written by forge
/// PqzStateVectors from the contract's state; an audited op 1 leg) holds `P(u)` and `P(v_t)` in its op blob
/// `R = header(16) ‖ P(u) ‖ P(v_t) ‖ …` and the unpacked lanes in its `ct`. Then `aad` = the head ‖ keccak256 of the packed
/// parts, not of the unpacked lanes.
#[test]
fn aad_binds_the_stored_form() {
    let set = pqz_ffi::stmt::SET;
    let dir = if set == "n2048-kmax1024" { String::new() } else { format!("{set}/") };
    let t = std::fs::read_to_string(format!("{}/../../smartcontracts/vectors/pqz/{dir}state.json", env!("CARGO_MANIFEST_DIR"))).expect("state.json");
    let hexat = |from: usize, key: &str| -> (usize, Vec<u8>) {
        let pat = format!("\"{key}\": \"0x");
        let j = from + t[from..].find(&pat).expect(key) + pat.len();
        let h = &t[j..j + t[j..].find('"').unwrap()];
        (j, (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect())
    };
    let (j, code) = hexat(t.find("\"entries\"").expect("entries"), "code");
    let (_, ct) = hexat(j, "ct");
    let r = &code[1..]; // the SSTORE2 STOP byte
    let (pu, pv) = (opening::pack(&ct[..PK_BYTES]), opening::pack(&ct[PK_BYTES..]));
    assert_eq!((ct.len(), pu.len() * 64, pv.len() * 64), (PK_BYTES + 128, PK_BYTES * (64 - (Q - 1).leading_zeros() as usize), 128 * (64 - (Q - 1).leading_zeros() as usize)));
    assert_eq!(&r[16..16 + pu.len()], &pu[..], "{set}: P(u) = the op blob's");
    assert_eq!(&r[16 + pu.len()..16 + pu.len() + pv.len()], &pv[..], "{set}: P(v_t) = the op blob's");
    assert_ne!(&r[16..16 + 64], &ct[..64], "the blob does not hold the unpacked lanes");
    // aad over the packed parts, for both readers
    let f = Fx::new(true);
    let c = f.credit();
    for p in [c.to, c.auditor.unwrap()] {
        let a = opening::aad(&c, &p);
        let head = [&CHAIN[..], &f.token, p.ua, &0u64.to_be_bytes()].concat();
        assert_eq!(a, [&head[..], &opening::keccak(&[&opening::pack(&f.u[..]), &opening::pack(p.v)])].concat());
        assert_ne!(a[a.len() - 32..], opening::keccak(&[&f.u[..], p.v])[..], "not keccak256 over the unpacked lanes");
    }
    eprintln!("aad_binds_the_stored_form ({set}): P(u) {} B, P(v) {} B equal to state.json's op blob", pu.len(), pv.len());
}
