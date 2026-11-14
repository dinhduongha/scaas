// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The native side of the wasm = native differential (./run.sh, TODO 3zf): rebuilds the credits of `opening.json`'s rows
//! (pqz-vectors' `opening_file`: the same keys, seeds and digits), then one-change variants of each, and prints every case
//! with the outcome of `pqz_ffi::opening::check_recipient` / `check_auditor` run here, natively, as JSON on stdout. The
//! clientkeys test checks each row's fields against `opening.json` and runs every case through the wasm. UNAUDITED.
use pqz_ffi::opening::{self as op, AuditorOutcome, Credit, Party, Role};
use pqz_ffi::pqzl::{self, PK_BYTES};

#[derive(Clone)]
struct P {
    ua: [u8; 32],
    kv: u64,
    pk: Vec<u8>,
    kem: Vec<u8>,
    v: Vec<u8>,
    opening: Vec<u8>,
}

#[derive(Clone)]
struct C {
    chain: [u8; 32],
    token: [u8; 20],
    u: Vec<u8>,
    to: P,
    au: Option<P>,
}

fn arr<const L: usize>(b: &[u8]) -> &[u8; L] {
    b.try_into().expect("fixed field")
}

fn party(p: &P) -> Party<'_> {
    Party { ua: &p.ua, key_version: p.kv, pk: arr(&p.pk), kem_pk: &p.kem, v: arr(&p.v), opening: &p.opening }
}

fn credit(c: &C) -> Credit<'_> {
    Credit { chain_uid: &c.chain, token: &c.token, u: arr(&c.u), to: party(&c.to), auditor: c.au.as_ref().map(party) }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::from("\"0x");
    b.iter().for_each(|x| s += &format!("{x:02x}"));
    s + "\""
}

fn pj(p: &P) -> String {
    format!(
        "{{\"ua\":{},\"keyVersion\":{},\"pk\":{},\"kemPk\":{},\"v\":{},\"opening\":{}}}",
        hex(&p.ua),
        p.kv,
        hex(&p.pk),
        hex(&p.kem),
        hex(&p.v),
        hex(&p.opening)
    )
}

fn cj(c: &C) -> String {
    format!(
        "{{\"chainUid\":{},\"token\":{},\"u\":{},\"to\":{},\"auditor\":{}}}",
        hex(&c.chain),
        hex(&c.token),
        hex(&c.u),
        pj(&c.to),
        c.au.as_ref().map_or("null".into(), pj)
    )
}

fn outcome_r(o: Option<[u8; 16]>) -> String {
    o.map_or("\"skip\"".into(), |d| format!("\"accepted:{}\"", hex(&d).trim_matches('"')))
}

fn outcome_a(o: AuditorOutcome) -> String {
    match o {
        AuditorOutcome::Read(d) => format!("\"read:{}\"", hex(&d).trim_matches('"')),
        AuditorOutcome::RecipientUnreadable => "\"recipient-unreadable\"".into(),
        AuditorOutcome::Unreadable => "\"unreadable\"".into(),
    }
}

fn flip(b: &mut [u8], i: usize) {
    b[i] ^= 1;
}

fn main() {
    let set = pqz_ffi::stmt::SET;
    let (chain, token, to_ua, au_ua) = ([0xC1u8; 32], [0x70u8; 20], [0x11u8; 32], [0xA0u8; 32]);
    let bip39 = [0x4Du8; 64];
    let key = |s: u8| pqzl::keygen(&[s; 32]).expect("keygen").pk.to_vec();
    let (pk_f, pk_t, pk_a) = (key(0x46), key(0x54), key(0x41));
    let (seed_t, seed_a) = (op::open_kem_seed(&bip39, &to_ua, &chain, None, 0), op::open_kem_seed(&bip39, &au_ua, &chain, None, 0));
    // the twelve openKemSeeds of opening.json (recipient 0x11..): only (0xC1.., offchain-shared, 0) opens O_t
    let mut kem_seeds = vec![];
    for ch in [[0xC1u8; 32], [0xC2; 32]] {
        for tk in [None, Some([0x70u8; 20]), Some([0x71; 20])] {
            for v in [0u64, 1] {
                kem_seeds.push(op::open_kem_seed(&bip39, &to_ua, &ch, tk.as_ref(), v));
            }
        }
    }
    let q = pqz_ffi::stmt::Q;
    let (mut rows, mut cases) = (vec![], vec![]);
    let mut case = |name: String, check: &str, seed: &[u8; 96], c: &C| {
        let cr = credit(c);
        let native = match check {
            "recipient" => outcome_r(op::check_recipient(seed, &cr)),
            _ => outcome_a(op::check_auditor(seed, &cr)),
        };
        cases.push(format!(
            "{{\"name\":\"{name}\",\"check\":\"{check}\",\"openKemSeed\":{},\"credit\":{},\"native\":{native}}}",
            hex(seed),
            cj(c)
        ));
    };
    for aud in [false, true] {
        let d: [u8; 16] = core::array::from_fn(|i| (i as u8 * 5 + 1) % 16);
        let s = op::enc_split(arr(&pk_f), [2; 16], &to_ua, arr(&pk_t), d, aud.then_some(arr(&pk_a)), &[0x7E; 32]).expect("enc_split");
        let kem_t = op::open_kem_pk(&seed_t);
        let kem_a = op::open_kem_pk(&seed_a);
        let mut c = C {
            chain,
            token,
            u: s.leg.u.to_vec(),
            to: P { ua: to_ua, kv: 0, pk: pk_t.clone(), kem: kem_t, v: s.leg.vs[0].to_vec(), opening: vec![] },
            au: aud.then(|| P { ua: au_ua, kv: 0, pk: pk_a.clone(), kem: kem_a, v: s.leg.vs[1].to_vec(), opening: vec![] }),
        };
        let o_t = op::seal(Role::Recipient, &credit(&c), &party(&c.to), &s.seed_leg).expect("seal O_t");
        let o_a = c.au.as_ref().map(|a| op::seal(Role::Auditor, &credit(&c), &party(a), &s.seed_leg).expect("seal O_a"));
        c.to.opening = o_t;
        if let (Some(a), Some(o)) = (c.au.as_mut(), o_a) {
            a.opening = o;
        }
        rows.push(format!(
            "{{\"auditorOn\":{aud},\"seed_leg\":{},\"credit\":{},\"pu\":{},\"pvt\":{},\"pva\":{},\"openKemSeedT\":{},\"openKemSeedA\":{}}}",
            hex(&s.seed_leg),
            cj(&c),
            hex(&op::pack(&c.u)),
            hex(&op::pack(&c.to.v)),
            c.au.as_ref().map_or("null".into(), |a| hex(&op::pack(&a.v))),
            hex(&seed_t),
            hex(&seed_a)
        ));
        let r = if aud { "aud" } else { "plain" };
        // recipient: the control, then one change each
        case(format!("{r} recipient control"), "recipient", &seed_t, &c);
        for (i, ks) in kem_seeds.iter().enumerate() {
            case(format!("{r} recipient openKemSeeds[{i}]"), "recipient", ks, &c);
        }
        case(format!("{r} recipient the auditor's seed"), "recipient", &seed_a, &c);
        let mut wrong = seed_t;
        flip(&mut wrong, 65); // the X25519 half (byte 64 bit 0 is clamped away)
        case(format!("{r} recipient seed X25519 half flipped"), "recipient", &wrong, &c);
        let mut wrong = seed_t;
        flip(&mut wrong, 0); // the ML-KEM half: implicit rejection
        case(format!("{r} recipient seed ML-KEM half flipped"), "recipient", &wrong, &c);
        type M = (&'static str, fn(&mut C, u64));
        let muts: [M; 19] = [
            ("O_t tag flipped", |c, _| flip(&mut c.to.opening, op::OPENING - 1)),
            ("O_t mlkemCt flipped", |c, _| flip(&mut c.to.opening, 0)),
            ("O_t x25519Eph flipped", |c, _| flip(&mut c.to.opening, op::MLKEM_CT)),
            ("O_t sealedSeed flipped", |c, _| flip(&mut c.to.opening, op::MLKEM_CT + 32)),
            ("O_t x25519Eph small order (0)", |c, _| c.to.opening[op::MLKEM_CT..op::MLKEM_CT + 32].fill(0)),
            ("O_t short", |c, _| {
                c.to.opening.pop();
            }),
            ("O_t long", |c, _| c.to.opening.push(0)),
            ("O_t empty", |c, _| c.to.opening.clear()),
            ("kemPk short", |c, _| {
                c.to.kem.pop();
            }),
            ("kemPk scheme 2", |c, _| c.to.kem[0] = 2),
            ("u lane flipped", |c, _| flip(&mut c.u, 7)),
            ("v_t lane low bit flipped", |c, _| flip(&mut c.to.v, 7)),
            ("v_t lane = q", |c, q| c.to.v[..8].copy_from_slice(&q.to_be_bytes())),
            ("keyVersion 1", |c, _| c.to.kv = 1),
            ("chainUid flipped", |c, _| flip(&mut c.chain, 0)),
            ("token flipped", |c, _| flip(&mut c.token, 0)),
            ("recipient ua flipped", |c, _| flip(&mut c.to.ua, 0)),
            ("pk_t lane flipped", |c, _| flip(&mut c.to.pk, 7)),
            ("pk_t all 0xff", |c, _| c.to.pk.fill(0xFF)),
        ];
        let aud_muts: [M; 4] = [
            ("O_a tag flipped", |c, _| flip(&mut c.au.as_mut().expect("auditor").opening, op::OPENING - 1)),
            ("O_a short", |c, _| {
                c.au.as_mut().expect("auditor").opening.pop();
            }),
            ("v_a lane low bit flipped", |c, _| flip(&mut c.au.as_mut().expect("auditor").v, 7)),
            ("pk_a lane flipped", |c, _| flip(&mut c.au.as_mut().expect("auditor").pk, 7)),
        ];
        let all: Vec<&M> = muts.iter().chain(aud.then_some(&aud_muts[..]).into_iter().flatten()).collect();
        for (name, m) in &all {
            let mut x = c.clone();
            m(&mut x, q);
            case(format!("{r} recipient {name}"), "recipient", &seed_t, &x);
        }
        // the auditor: on the audited row its control and one change each; on the plain row no auditor copy
        case(format!("{r} auditor control"), "auditor", &seed_a, &c);
        case(format!("{r} auditor the recipient's seed"), "auditor", &seed_t, &c);
        if aud {
            for (name, m) in &all {
                let mut x = c.clone();
                m(&mut x, q);
                case(format!("{r} auditor {name}"), "auditor", &seed_a, &x);
            }
            let mut x = c.clone();
            x.au = None;
            case(format!("{r} recipient auditor dropped"), "recipient", &seed_t, &x);
            case(format!("{r} auditor auditor dropped"), "auditor", &seed_a, &x);
        }
    }
    println!(
        "{{\"set\":\"{set}\",\"pkBytes\":{PK_BYTES},\"q\":{q},\"rows\":[{}],\"cases\":[\n{}\n]}}",
        rows.join(","),
        cases.join(",\n")
    );
}
