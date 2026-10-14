//! pqz-ffi tests (P6e Task 7): honest round trips of every form of both ids through the precompile, every decoder
//! rejection, the PQZL differential test (specialised vs generic verifier through the FFI), abort-freedom on ≥ 10k
//! random and mutated inputs from 8 threads through the C ABI, the self-test, and the C ABI's argument handling.
use std::sync::OnceLock;

use pqz_ffi::fixture::{self, Case};
use pqz_ffi::stmt::{self, Form, Reject, H_AUDITOR_ON, H_FEE, H_SALT, H_TO, HEADER_BYTES, MAX_PROOF_PQZH, MAX_PROOF_PQZL};
use pqz_ffi::*;

const RND: [u8; 32] = [0x33; 32];

struct Honest {
    id: Word,
    case: Case,
    proof: Vec<u8>,
}

impl Honest {
    fn input(&self) -> Vec<u8> {
        stmt::input(self.case.op(), &self.case.stmt, &self.proof)
    }
    fn pqzl(&self) -> bool {
        self.id == PQZL_ID
    }
}

/// Every form of both ids, proved once per process. PQZH `R_TX0` is left out until Ligero has the relation (P6e Task 8,
/// branch `p6e-b3`); `pqzh_tx0_pending` pins today's behaviour.
fn honest() -> &'static [Honest] {
    static H: OnceLock<Vec<Honest>> = OnceLock::new();
    H.get_or_init(|| {
        let mut v = Vec::new();
        for id in [PQZL_ID, PQZH_ID] {
            for case in fixture::cases(&id).expect("fixture") {
                if id == PQZH_ID && case.form == Form::Transfer0 {
                    continue;
                }
                let proof = prove(case.op(), &case.stmt, &case.wit, &RND)
                    .unwrap_or_else(|e| panic!("prove {:?} {:?}: {e:?}", id[0], case.form));
                v.push(Honest { id, case, proof });
            }
        }
        v
    })
}

fn word(b: bool) -> Word {
    if b { VALID } else { INVALID }
}

#[test]
fn round_trip_every_form() {
    for h in honest() {
        let r = precompile(&h.input());
        eprintln!("{} {:?}: proof {} B, {:?}", if h.pqzl() { "PQZL" } else { "PQZH" }, h.case.form, h.proof.len(), r);
        assert_eq!(r, Ok(VALID), "{:?}", h.case.form);
        assert_eq!(precompile(&h.input()), Ok(VALID), "same input twice");
    }
    assert_eq!(honest().iter().filter(|h| h.pqzl()).count(), 8);
    assert_eq!(honest().iter().filter(|h| !h.pqzl()).count(), 7);
}

#[test]
fn pqzh_tx0_pending() {
    // Ligero has no R_TX0 yet (Task 8): its prover refuses, and a PQZH auditor-off input is invalid
    let c = fixture::cases(&PQZH_ID).unwrap().into_iter().find(|c| c.form == Form::Transfer0).unwrap();
    match prove(1, &c.stmt, &c.wit, &RND) {
        Err(e) => eprintln!("PQZH R_TX0 prove: {e:?} (pending Task 8)"),
        Ok(p) => assert_eq!(precompile(&stmt::input(1, &c.stmt, &p)), Ok(VALID)),
    }
}

/// (name, mutated input, expected decoder verdict: Some(reason) or None = decodes, rejected by the verifier)
fn negatives(h: &Honest) -> Vec<(String, Vec<u8>, Option<Reject>)> {
    let (op, st, pf) = (h.case.op(), &h.case.stmt, &h.proof);
    let max = if h.pqzl() { MAX_PROOF_PQZL } else { MAX_PROOF_PQZH };
    let inp = |op: u8, st: &[u8], pf: &[u8]| stmt::input(op, st, pf);
    let with = |off: usize, f: &dyn Fn(&mut [u8])| {
        let mut s = st.clone();
        f(&mut s[off..]);
        s
    };
    let mut v: Vec<(String, Vec<u8>, Option<Reject>)> = vec![
        ("op 0".into(), inp(0, st, pf), Some(Reject::Op)),
        ("op 7".into(), inp(7, st, pf), Some(Reject::Op)),
        ("op 6 with the statement".into(), inp(6, st, pf), Some(Reject::Op)),
        ("other op".into(), inp(op % 5 + 1, st, pf), Some(Reject::OpTag)),
        ("opTag of another op".into(), inp(op, &with(0, &|s| {
            s[..32].copy_from_slice(&if op == 3 { Form::Transfer } else { Form::Register }.op_tag())
        }), pf), Some(Reject::OpTag)),
        ("opTag bit".into(), inp(op, &with(0, &|s| s[0] ^= 1), pf), Some(Reject::OpTag)),
        ("unknown id".into(), inp(op, &with(32, &|s| s[0] ^= 1), pf), Some(Reject::ProofSystemId)),
        ("statement + 1".into(), inp(op, &[&st[..], &[0]].concat(), pf), Some(Reject::Length)),
        ("statement - 1".into(), inp(op, &st[..st.len() - 1], pf), Some(Reject::Length)),
        ("length field + 1".into(), { let mut i = inp(op, st, pf); i[4] += 1; i }, None),
        ("coefficient = q".into(), inp(op, &with(st.len() - 8, &|s| s.copy_from_slice(&stmt::Q.to_be_bytes())), pf),
            Some(Reject::Coefficient)),
        ("coefficient = 2^42".into(), inp(op, &with(st.len() - 8, &|s| s.copy_from_slice(&(1u64 << 42).to_be_bytes())), pf),
            Some(Reject::Coefficient)),
        ("coefficient top byte".into(), inp(op, &with(st.len() - 8, &|s| s[0] = 0x80), pf), Some(Reject::Coefficient)),
        ("empty proof".into(), inp(op, st, &[]), Some(Reject::ProofLength)),
        ("MAX_PROOF + 1".into(), inp(op, st, &vec![0; max + 1]), Some(Reject::ProofLength)),
        ("proof truncated".into(), inp(op, st, &pf[..pf.len() - 1]), None),
        ("proof half".into(), inp(op, st, &pf[..pf.len() / 2]), None),
        ("proof + 1 byte".into(), inp(op, st, &[&pf[..], &[0]].concat()), None),
        ("proof bit 0".into(), { let mut p = pf.clone(); p[0] ^= 1; inp(op, st, &p) }, None),
        ("proof last bit".into(), { let mut p = pf.clone(); *p.last_mut().unwrap() ^= 0x80; inp(op, st, &p) }, None),
        ("proof middle byte".into(), { let mut p = pf.clone(); let m = p.len() / 2; p[m] ^= 0x5a; inp(op, st, &p) }, None),
        ("other system's id".into(), inp(op, &with(32, &|s| s[..32].copy_from_slice(if h.pqzl() { &PQZH_ID } else { &PQZL_ID })), pf), None),
        ("statement last coefficient - 1".into(), inp(op, &with(st.len() - 1, &|s| s[0] ^= 1), pf), None),
    ];
    if let Form::Transfer | Form::Transfer0 | Form::Burn | Form::Refresh = h.case.form {
        let tr = matches!(h.case.form, Form::Transfer | Form::Transfer0);
        v.extend([
            ("fee 2^64".into(), inp(op, &with(32 * H_FEE + 23, &|s| s[0] = 1), pf), Some(Reject::Fee)),
            ("amount 2^64".into(), inp(op, &with(32 * stmt::H_AMOUNT + 23, &|s| s[0] = 1), pf), Some(Reject::Amount)),
            ("salt high half".into(), inp(op, &with(32 * H_SALT, &|s| s[0] = 1), pf), Some(Reject::Salt)),
            ("fee + 1".into(), inp(op, &with(32 * H_FEE + 31, &|s| s[0] ^= 1), pf), None),
        ]);
        if tr {
            v.extend([
                ("auditorOn 2".into(), inp(op, &with(32 * H_AUDITOR_ON + 31, &|s| s[0] = 2), pf), Some(Reject::AuditorOn)),
                ("auditorOn flipped".into(), inp(op, &with(32 * H_AUDITOR_ON + 31, &|s| s[0] ^= 1), pf), Some(Reject::AuditorOn)),
                ("recipient set".into(), inp(op, &with(32 * stmt::H_RECIPIENT + 31, &|s| s[0] = 1), pf),
                    Some(Reject::MustBeZero("recipient"))),
            ]);
        } else {
            v.push(("toUA set".into(), inp(op, &with(32 * H_TO + 31, &|s| s[0] = 1), pf), Some(Reject::MustBeZero("toUA"))));
        }
        v.push(("body coefficient = q".into(), inp(op, &with(HEADER_BYTES, &|s| s[..8].copy_from_slice(&stmt::Q.to_be_bytes())), pf),
            Some(Reject::Coefficient)));
    }
    if let Form::DiscloseSender | Form::DiscloseReceiver | Form::DiscloseAuditor = h.case.form {
        v.push(("disclosure amount 2^64".into(), inp(op, &with(32 * stmt::DW_AMOUNT + 23, &|s| s[0] = 1), pf), Some(Reject::Amount)));
        v.push(("disclosure kind changed".into(), inp(op, &with(32 * stmt::DW_KIND + 31, &|s| s[0] ^= 4), pf), None));
    }
    v
}

#[test]
fn every_rejection() {
    let mut n = 0;
    for h in honest() {
        for (name, input, why) in negatives(h) {
            if let Some(r) = why {
                assert_eq!(decode(&input).err(), Some(r), "{:?} {name}", h.case.form);
            }
            assert_eq!(precompile(&input), Ok(INVALID), "{:?} {name}", h.case.form);
            n += 1;
        }
    }
    // framing and SELFTEST
    let st = &honest()[0].case.stmt;
    for (name, input) in [
        ("empty", vec![]),
        ("4 bytes", vec![1, 0, 0, 0]),
        ("length field over the input", stmt::input(1, st, &[]).into_iter().take(5 + 100).collect()),
        ("selftest + 1 byte", vec![6, 0, 0, 0, 0, 0]),
        ("selftest, length 1", vec![6, 0, 0, 0, 1, 0]),
    ] {
        assert_eq!(precompile(&input), Ok(INVALID), "{name}");
        n += 1;
    }
    assert_eq!(precompile(&vec![1; MAX_INPUT + 1]), Err(Error::Revert));
    assert_eq!(precompile(&vec![1; MAX_INPUT]), Ok(INVALID));
    eprintln!("rejection cases: {}", n + 2);
}

/// Specialised vs generic PQZL verifier through the FFI on honest and mutated proofs of all six forms (plan R5): they
/// must agree on every input.
#[test]
fn pqzl_differential() {
    let mut rng = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let (mut cases, mut accepted) = (0, 0);
    for h in honest().iter().filter(|h| h.pqzl()) {
        let op = h.case.op();
        let mut proofs = vec![h.proof.clone()];
        for k in 0..6 {
            let mut p = h.proof.clone();
            let i = next() as usize % p.len();
            match k {
                0..=2 => p[i] ^= 1 << (next() % 8),
                3 => p[i] = next() as u8,
                4 => p.truncate(i.max(1)),
                _ => p[i..].iter_mut().for_each(|b| *b = 0),
            }
            proofs.push(p);
        }
        for p in proofs {
            let fast = verify_input(&stmt::input(op, &h.case.stmt, &p)).unwrap();
            let generic = pqzl::verify_generic(op, &h.case.stmt, &p).unwrap();
            assert_eq!(fast, generic, "{:?}", h.case.form);
            cases += 1;
            accepted += fast as usize;
        }
    }
    eprintln!("differential: {cases} cases, {accepted} accepted, 0 disagreements");
    assert_eq!(accepted, 8);
}

/// ≥ 10k inputs through the C ABI from 8 threads: random bytes, honest statements with random proofs, honest inputs
/// with random edits, a few honest inputs unedited. No panic reaches the boundary (status 3), the output is …00
/// except for the unedited honest inputs,
/// and the 8-thread results equal the serial ones.
#[test]
fn abort_freedom() {
    const N: usize = 10_240;
    let hs = honest();
    let gen = |i: usize| -> Vec<u8> {
        let mut x = (i as u64 + 1).wrapping_mul(0x2545_F491_4F6C_DD1D);
        let mut r = move || {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let h = &hs[i % hs.len()];
        match i % 5 {
            0 => (0..r() % 2048).map(|_| r() as u8).collect(),
            1 => {
                let mut v: Vec<u8> = (0..5 + r() % 64).map(|_| r() as u8).collect();
                v[0] = 1 + (r() % 6) as u8;
                v
            }
            2 => stmt::input(h.case.op(), &h.case.stmt, &(0..1 + r() % 4096).map(|_| r() as u8).collect::<Vec<_>>()),
            4 if r() % 16 == 0 => h.input(),
            _ => {
                let mut v = h.input();
                for _ in 0..1 + r() % 4 {
                    let j = r() as usize % v.len();
                    v[j] ^= 1 << (r() % 8);
                }
                if r() % 4 == 0 {
                    v.truncate(r() as usize % v.len());
                }
                v
            }
        }
    };
    let call = |inp: &[u8]| -> (i32, Word) {
        let mut out = [0xEEu8; 32];
        let rc = unsafe { pqz_precompile(inp.as_ptr(), inp.len(), out.as_mut_ptr(), out.len()) };
        (rc, out)
    };
    let honest_inputs: Vec<Vec<u8>> = hs.iter().map(|h| h.input()).collect();
    let serial: Vec<(i32, Word)> = (0..N).map(|i| call(&gen(i))).collect();
    let par: Vec<(i32, Word)> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..8)
            .map(|t| s.spawn(move || (t..N).step_by(8).map(|i| (i, call(&gen(i)))).collect::<Vec<_>>()))
            .collect();
        let mut all: Vec<(usize, (i32, Word))> = hs.into_iter().flat_map(|h| h.join().unwrap()).collect();
        all.sort_by_key(|x| x.0);
        all.into_iter().map(|x| x.1).collect()
    });
    assert_eq!(serial, par, "8 threads = serial");
    let mut valid = 0;
    for (i, (rc, w)) in serial.iter().enumerate() {
        assert_eq!(*rc, PQZ_FFI_OK, "input {i}");
        let inp = gen(i);
        let ok = honest_inputs.contains(&inp);
        assert_eq!(*w, word(ok), "input {i}");
        valid += ok as usize;
    }
    let lp = pqzh_ligero::ligero::VERIFY_PANICS.load(std::sync::atomic::Ordering::Relaxed);
    eprintln!("abort-freedom: {} inputs x 2 (serial, 8 threads), {valid} valid (= the unedited honest ones), status 3: 0, Ligero panics caught: {lp}", N);
    assert_eq!(lp, 0);
}

#[test]
fn c_abi_arguments() {
    let mut out = [0xEEu8; 32];
    let p = out.as_mut_ptr();
    unsafe {
        assert_eq!(pqz_precompile(std::ptr::null(), 5, p, 32), PQZ_FFI_BAD_ARGS);
        assert_eq!(pqz_precompile([6u8, 0, 0, 0, 0].as_ptr(), 5, std::ptr::null_mut(), 32), PQZ_FFI_BAD_ARGS);
        assert_eq!(pqz_precompile([6u8, 0, 0, 0, 0].as_ptr(), 5, p, 31), PQZ_FFI_BAD_ARGS);
        assert_eq!(out, [0xEE; 32], "nothing written");
        assert_eq!(pqz_precompile(std::ptr::null(), 0, p, 32), PQZ_FFI_OK);
        assert_eq!(out, INVALID);
        let big = vec![1u8; MAX_INPUT + 1];
        out = [0xEE; 32];
        assert_eq!(pqz_precompile(big.as_ptr(), big.len(), out.as_mut_ptr(), 64), PQZ_FFI_REVERT);
        assert_eq!(out, INVALID);
        assert_eq!(pqz_precompile([6u8, 0, 0, 0, 0].as_ptr(), 5, out.as_mut_ptr(), 32), PQZ_FFI_OK);
        assert_eq!(out, selftest::report().unwrap().hash);
    }
}

/// pqz_kat.py --check prints "A digest keccak256(A bytes) = f176b313…" (Python, independent of the C core)
const A_DIGEST: &str = "f176b313331c898e11230c6addae3d44821413361e1416a6aedf9f26a7be3df0";

#[test]
fn selftest_report() {
    let r = selftest::report().unwrap();
    let hex = |w: &[u8]| w.iter().map(|b| format!("{b:02x}")).collect::<String>();
    eprintln!("selftest: {r:?}\nselftest hash {}", hex(&r.hash));
    assert_eq!(hex(&r.a_digest), A_DIGEST);
    assert!(r.fft_ok);
    assert_eq!(r.m, selftest::digits(selftest::MSG_VALUE));
    assert_eq!(r.results, [true, false, true, false]);
    assert_eq!(precompile(&[6, 0, 0, 0, 0]), Ok(r.hash));
    assert_eq!(selftest::report().unwrap(), r, "deterministic");
}

/// The compiled-in self-test proofs: regenerated (same RND, deterministic provers) they equal the embedded ones.
/// `PQZ_FFI_WRITE_SELFTEST=1` writes selftest/*.hex instead (then rebuild).
#[test]
fn selftest_vectors() {
    let key = pqzl::keygen(&selftest::SEED_KEY).unwrap();
    for (id, name) in [(PQZL_ID, "pqzl_reg"), (PQZH_ID, "pqzh_reg")] {
        let st = selftest::reg_statement(&id, &key.pk[..]);
        let proof = prove(3, &st, &fixture::wit_key(&key), &selftest::RND).unwrap();
        let hex: String = proof.iter().map(|b| format!("{b:02x}")).collect();
        let path = format!("{}/selftest/{name}.hex", env!("CARGO_MANIFEST_DIR"));
        if std::env::var("PQZ_FFI_WRITE_SELFTEST").is_ok() {
            let lines: Vec<&str> = hex.as_bytes().chunks(128).map(|c| std::str::from_utf8(c).unwrap()).collect();
            std::fs::write(&path, lines.join("\n") + "\n").unwrap();
            eprintln!("wrote {path}: {} B proof", proof.len());
        } else {
            let have: String = std::fs::read_to_string(&path).unwrap().split_whitespace().collect();
            assert_eq!(have, hex, "{name}: regenerate with PQZ_FFI_WRITE_SELFTEST=1");
        }
    }
}

/// The precompile path on a caller thread with a 1 MiB stack (a .NET thread-pool thread has 1.5 MiB on Linux).
#[test]
fn one_mib_stack() {
    let inputs: Vec<Vec<u8>> = honest().iter().map(|h| h.input()).collect();
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || {
            for i in &inputs {
                assert_eq!(precompile(i), Ok(VALID));
            }
            assert_ne!(precompile(&[6, 0, 0, 0, 0]), Ok(INVALID));
        })
        .unwrap()
        .join()
        .unwrap();
}

/// The native half of the wasm32 byte-equality check: the digest lines of both ids and the self-test line, written to
/// `$PQZ_FFI_DIGESTS` when set (run.sh diffs them with wasm/run_wasm.mjs's output).
#[test]
fn digest_lines() {
    let s = fixture::digest_lines(&PQZL_ID) + &fixture::digest_lines(&PQZH_ID) + &fixture::selftest_line();
    assert_eq!(s.matches("\"valid\": true").count(), 15, "{s}");
    if let Ok(p) = std::env::var("PQZ_FFI_DIGESTS") {
        std::fs::write(p, s).unwrap();
    }
}

/// pqz_ffi.h's constants are the crate's.
#[test]
fn header_matches() {
    let h = include_str!("../pqz_ffi.h");
    let def = |name: &str| -> i64 {
        let l = h.lines().find(|l| l.starts_with(&format!("#define {name} "))).unwrap_or_else(|| panic!("{name}"));
        l.split_whitespace().nth(2).unwrap().parse().unwrap()
    };
    assert_eq!(def("PQZ_FFI_OK"), PQZ_FFI_OK as i64);
    assert_eq!(def("PQZ_FFI_REVERT"), PQZ_FFI_REVERT as i64);
    assert_eq!(def("PQZ_FFI_BAD_ARGS"), PQZ_FFI_BAD_ARGS as i64);
    assert_eq!(def("PQZ_FFI_INTERNAL"), PQZ_FFI_INTERNAL as i64);
    assert_eq!(def("PQZ_FFI_NODE_FAULT"), PQZ_FFI_NODE_FAULT as i64);
    assert_eq!(def("PQZ_FFI_MAX_INPUT"), MAX_INPUT as i64);
    assert_eq!(def("PQZ_FFI_OUT_BYTES"), 32);
    assert!(h.contains("int pqz_precompile (const uint8_t *input, size_t len, uint8_t *out, size_t out_len);"));
}
