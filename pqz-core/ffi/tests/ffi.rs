//! pqz-ffi tests (P6e Task 7): honest round trips of every form of both ids through the precompile, every decoder
//! rejection, the PQZL differential test (specialised vs generic verifier through the FFI), the self-test, the C
//! ABI's argument handling, the 1 MiB caller stack. Abort-freedom and the arena checks run in a fresh verify-only
//! process: `tests/verify_only.rs`.
mod common;

use std::sync::OnceLock;

use common::*;
use pqz_ffi::fixture;
use pqz_ffi::stmt;
use pqz_ffi::*;

/// Every form of both ids, proved once per process.
fn honest() -> &'static [Honest] {
    static H: OnceLock<Vec<Honest>> = OnceLock::new();
    H.get_or_init(prove_all)
}

#[test]
fn round_trip_every_form() {
    for h in honest() {
        let r = precompile(&h.input());
        eprintln!("{} {:?}: proof {} B, {:?}", if h.pqzl() { "PQZL" } else { "PQZH" }, h.form, h.proof.len(), r);
        assert_eq!(r, Ok(VALID), "{:?}", h.form);
        assert_eq!(precompile(&h.input()), Ok(VALID), "same input twice");
    }
    assert_eq!(honest().iter().filter(|h| h.pqzl()).count(), 8);
    assert_eq!(honest().iter().filter(|h| !h.pqzl()).count(), 8);
}

#[test]
fn every_rejection() {
    let mut n = 0;
    for h in honest() {
        for (name, input, why) in negatives(h) {
            if let Some(r) = why {
                assert_eq!(decode(&input).err(), Some(r), "{:?} {name}", h.form);
            }
            assert_eq!(precompile(&input), Ok(INVALID), "{:?} {name}", h.form);
            n += 1;
        }
    }
    // framing and SELFTEST
    for (name, input) in framing(honest()) {
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
        let op = h.op();
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
            let fast = verify_input(&stmt::input(op, &h.stmt, &p)).unwrap();
            let generic = pqzl::verify_generic(op, &h.stmt, &p).unwrap();
            assert_eq!(fast, generic, "{:?}", h.form);
            cases += 1;
            accepted += fast as usize;
        }
    }
    eprintln!("differential: {cases} cases, {accepted} accepted, 0 disagreements");
    assert_eq!(accepted, 8);
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
/// They are the REGISTER rows of smartcontracts/vectors/pqz/proof_*.json (build.rs); pqz-vectors rewrites them.
#[test]
fn selftest_vectors() {
    let key = pqzl::keygen(&selftest::SEED_KEY).unwrap();
    for (i, id) in [PQZL_ID, PQZH_ID].into_iter().enumerate() {
        let st = selftest::reg_statement(&id, &key.pk[..]);
        let proof = prove(3, &st, &fixture::wit_key(&key), &selftest::RND).unwrap();
        assert_eq!(proof, selftest::proofs()[i], "self-test proof {i}: regenerate the vectors (pqz-vectors), then rebuild");
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
    assert_eq!(s.matches("\"valid\": true").count(), 16, "{s}");
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
