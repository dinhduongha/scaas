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
        eprintln!("{} {}: proof {} B, input {} B, {:?}", if h.pqzl() { "PQZL" } else { "PQZH" }, h.name(), h.proof.len(), h.input().len(), r);
        assert_eq!(r, Ok(VALID), "{}", h.name());
        assert_eq!(precompile(&h.input()), Ok(VALID), "same input twice");
    }
    // 8 forms each; op 7: PQZL M in {1, 2, 4, 8}, PQZH {1, 2, 4}, auditor on and off (P6-ANON D3 / D20)
    assert_eq!(honest().iter().filter(|h| h.pqzl()).count(), 8 + 8);
    assert_eq!(honest().iter().filter(|h| !h.pqzl()).count(), if PQZH { 8 + 6 } else { 0 });
}

/// Op 7 (P6-ANON S3, D3): every built shape's input within `MAX_INPUT` with the id's worst-case proof (PQZL
/// `MAX_PROOF`, PQZH Ligero's exact bound for the shape); the PQZH (4, on) boundary (`MAX_INPUT` exactly ⇒ decoded and
/// rejected, one byte more ⇒ revert); the oversize shapes refused by the decoder; `recipientsHash` and the memo.
#[test]
fn multi_limits_and_memo() {
    let mut largest = 0;
    for h in honest().iter().filter(|h| h.multi.is_some()) {
        let (m, aud) = h.multi.unwrap();
        let bound = if h.pqzl() { stmt::MAX_PROOF_PQZL } else { pqzh::max_proof_len_multi(m, aud) };
        let worst = 5 + h.stmt.len() + bound;
        eprintln!(
            "op 7 {} {}: statement {} B, proof {} B (bound {bound}), input {} B, worst-case input {worst} B (MAX_INPUT {MAX_INPUT})",
            if h.pqzl() { "PQZL" } else { "PQZH" },
            h.name(),
            h.stmt.len(),
            h.proof.len(),
            h.input().len()
        );
        assert!(h.proof.len() <= bound && worst <= MAX_INPUT, "{}", h.name());
        largest = largest.max(worst);
    }
    eprintln!("op 7 largest worst-case input {largest} B of MAX_INPUT {MAX_INPUT}");
    // PQZH (4, on) padded to exactly MAX_INPUT (n2048-kmax1024: 5 + 149,376 + 374,907, G = 2 since the R0 review fix)
    // decodes or fails ProofLength, so invalid; one byte more reverts (the set's MAX_INPUT, plan 5h Task 8c part 2)
    if PQZH {
        let h = honest().iter().find(|h| !h.pqzl() && h.multi == Some((4, true))).unwrap();
        let pad = |n: usize| stmt::input(7, &h.stmt, &[&h.proof[..], &vec![0; n - h.proof.len()]].concat());
        let room = MAX_INPUT - 5 - h.stmt.len();
        assert!(stmt::SET != "n2048-kmax1024" || room == 374_907);
        assert_eq!(pad(room).len(), MAX_INPUT);
        assert_eq!(precompile(&pad(room)), Ok(INVALID));
        assert_eq!(precompile(&pad(room + 1)), Err(Error::Revert));
    }
    // oversize shapes (bench builds only) never decode here: PQZL M = 16, PQZH M = 8 (the decoder knows both ids in
    // every build of a set with PQZH; n2816-kmax65536 has none)
    for (id, m) in [(PQZL_ID, 16), (PQZH_ID, 8)].into_iter().filter(|&(id, _)| id == PQZL_ID || stmt::HAS_PQZH) {
        let mut st = vec![0u8; stmt::multi_len(m, true)];
        for (i, w) in stmt::Multi::header(&id, m, true).iter().enumerate() {
            st[32 * i..32 * i + 32].copy_from_slice(w);
        }
        // Legs; or Input where the oversize statement alone exceeds MAX_INPUT (PQZL M = 16 at k >= 36)
        let e = decode(&stmt::input(7, &st, &[1])).err();
        assert!(matches!(e, Some(Reject::Legs | Reject::Input)), "M = {m}: {e:?}");
    }
    // recipientsHash and the memo of the fixture
    for (m, aud) in [(1, false), (8, true)] {
        let c = fixture::multi_case(&PQZL_ID, m, aud).unwrap();
        let s = stmt::parse_multi(&c.stmt).unwrap();
        let uas: Vec<Word> = (0..m).map(fixture::leg_ua).collect();
        assert_eq!(s.header[stmt::H_RECIPIENTS_HASH], fixture::recipients_hash(&uas));
        assert_eq!(s.header[stmt::H_MEMO_HASH], selftest::keccak(&[&c.memo]));
        assert_eq!(c.memo.len(), memo::memo_len(m));
        let (a, legs) = memo::open(&fixture::MEMO_KEY_SEED, &s.header, &c.memo).unwrap();
        let want: Vec<(u64, Word)> = (0..m).map(|j| (if j == m - 1 { fixture::VALUE } else { 0 }, uas[j])).collect();
        assert_eq!((a, legs), (aud, want));
        assert_ne!(memo::open(&[0x4e; 32], &s.header, &c.memo).map(|x| x.1), Some((0..m).map(|j| (0, uas[j])).collect()));
        assert_eq!(memo::open(&fixture::MEMO_KEY_SEED, &s.header, &c.memo[..c.memo.len() - 1]), None);
    }
}

#[test]
fn every_rejection() {
    let mut n = 0;
    for h in honest() {
        for (name, input, why) in negatives(h) {
            if let Some(r) = why {
                assert_eq!(decode(&input).err(), Some(r), "{} {name}", h.name());
            }
            assert_eq!(precompile(&input), Ok(INVALID), "{} {name}", h.name());
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

/// Specialised vs generic PQZL verifier through the FFI on honest and mutated proofs of all six forms and every built op 7 shape (plan R5): they
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
                // a random byte, never the same one (set n2560-kmax16384: a draw equal to the byte left the proof
                // unchanged and accepted; every other draw is as before)
                3 => {
                    let b = next() as u8;
                    p[i] = if b == p[i] { !b } else { b };
                }
                4 => p.truncate(i.max(1)),
                _ => p[i..].iter_mut().for_each(|b| *b = 0),
            }
            proofs.push(p);
        }
        for p in proofs {
            let fast = verify_input(&stmt::input(op, &h.stmt, &p)).unwrap();
            let generic = pqzl::verify_generic(op, &h.stmt, &p).unwrap();
            assert_eq!(fast, generic, "{}", h.name());
            cases += 1;
            accepted += fast as usize;
        }
    }
    eprintln!("differential: {cases} cases, {accepted} accepted, 0 disagreements");
    assert_eq!(accepted, 16);
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

/// pqz_kat.py --check prints "A digest keccak256(A bytes) = f176b313…" (Python, independent of the C core); the v3 set
const A_DIGEST: &str = "f176b313331c898e11230c6addae3d44821413361e1416a6aedf9f26a7be3df0";

#[test]
fn selftest_report() {
    let r = selftest::report().unwrap();
    let hex = |w: &[u8]| w.iter().map(|b| format!("{b:02x}")).collect::<String>();
    eprintln!("selftest: {r:?}\nselftest hash {}", hex(&r.hash));
    if stmt::SET == "n2048-kmax1024" {
        assert_eq!(hex(&r.a_digest), A_DIGEST);
    }
    assert_eq!(r.fft_ok, PQZH);
    assert_eq!(r.m, selftest::digits(selftest::MSG_VALUE));
    assert_eq!(r.results, [true, false, PQZH, false]);
    assert_eq!(precompile(&[6, 0, 0, 0, 0]), Ok(r.hash));
    assert_eq!(selftest::report().unwrap(), r, "deterministic");
}

/// The compiled-in self-test proofs: regenerated (same RND, deterministic provers) they equal the embedded ones.
/// They are the REGISTER rows of smartcontracts/vectors/pqz/proof_*.json (build.rs); pqz-vectors rewrites them.
#[test]
fn selftest_vectors() {
    let key = pqzl::keygen(&selftest::SEED_KEY).unwrap();
    for (i, id) in ids().into_iter().enumerate() {
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
    let s = fixture::digest_lines(&PQZL_ID, true) + &fixture::digest_lines(&PQZH_ID, true) + &fixture::selftest_line();
    // 8 forms + the op 7 shapes with M <= 4, each id; PQZL without the shapes above WASM_PQZL_MAX_LEGS (the C backend's
    // wasm32 refusal, printed natively as `Statement(Legs)`: fixture::digest_lines)
    let shapes = |id: &Word| 2 * [1, 2, 4].iter().filter(|&&m| *id != PQZL_ID || m <= pqzl::WASM_PQZL_MAX_LEGS).count();
    let valid: usize = ids().iter().map(|id| 8 + shapes(id)).sum();
    assert_eq!(s.matches("\"valid\": true").count(), valid, "{s}");
    assert_eq!(s.matches("\"proof\": \"Statement(Legs)\"").count(), ids().len() * 14 - valid, "{s}");
    if let Ok(p) = std::env::var("PQZ_FFI_DIGESTS") {
        std::fs::write(p, s).unwrap();
    }
}

/// pqz_ffi.h's constants are the crate's; the input limit is the library's `pqz_max_input()` = the set's MAX_INPUT (plan
/// 5h Task 8d: the node reads it, the header has no literal)
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
    assert!(!h.contains("#define PQZ_FFI_MAX_INPUT"));
    assert!(h.contains("size_t pqz_max_input (void);"));
    assert_eq!(pqz_ffi::pqz_max_input(), MAX_INPUT);
    assert_eq!(MAX_INPUT, 524_288); // every set since the R0 review fix (owner 2026-10-25; n2048-kmax1024 was 393,216)
    assert_eq!(def("PQZ_FFI_OUT_BYTES"), 32);
    assert!(h.contains("int pqz_precompile (const uint8_t *input, size_t len, uint8_t *out, size_t out_len);"));
}
