//! The parameter set of this build (owner 2026-10-21: one per build, pqz-core/params/sets/<set>/; plan 5h Task 8c):
//! cargo feature `set-<set>`, at most one; none = the frozen set `n2048-kmax1024` (pqz-ffi forwards its set, plan 5h
//! Task 8c part 2). The lattice constants (q, n, k, Delta, bit widths, norm bounds, Barrett constants) are PQZL's
//! `rust/set.rs`, the PQZH ones (generator, F_q^4 non-residue, radices, preset) the set's `pqzh_set.rs` (both generated
//! by pqz-core/params/sets/gen_set.py); the proof limit MAX_PROOF_PQZH is pqz-stmt's (from the same `rust/set.rs`).

const _: () = assert!(
    cfg!(feature = "set-n2048-kmax1024") as u8
        + cfg!(feature = "set-n2304-kmax4096") as u8
        + cfg!(feature = "set-n2560-kmax16384") as u8
        <= 1,
    "enable at most one set-<set> feature"
);

#[cfg(feature = "set-n2304-kmax4096")]
#[path = "../../../params/sets/n2304-kmax4096/rust/set.rs"]
mod lattice;
// n2304-kmax4096: preset B (radices 7 / 17, n 45,752, k 952, t 120; owner 2026-10-22); feature `fallback-retry`: THE
// preset with the prover's retry under MAX_PROOF_PQZH (fallback A, docs/research/pqzh-set-a-proof-limit.md)
#[cfg(all(feature = "set-n2304-kmax4096", not(feature = "fallback-retry")))]
#[path = "../../../params/sets/n2304-kmax4096/pqzh_set.rs"]
mod pqzh;
#[cfg(all(feature = "set-n2304-kmax4096", feature = "fallback-retry"))]
#[path = "../../../params/sets/n2304-kmax4096/pqzh_set_fallback.rs"]
mod pqzh;
const _: () = assert!(
    !cfg!(feature = "fallback-retry") || cfg!(feature = "set-n2304-kmax4096"),
    "fallback-retry is n2304-kmax4096 only"
);

#[cfg(feature = "set-n2560-kmax16384")]
#[path = "../../../params/sets/n2560-kmax16384/rust/set.rs"]
mod lattice;
#[cfg(feature = "set-n2560-kmax16384")]
#[path = "../../../params/sets/n2560-kmax16384/pqzh_set.rs"]
mod pqzh;

#[cfg(not(any(feature = "set-n2304-kmax4096", feature = "set-n2560-kmax16384")))]
#[path = "../../../params/sets/n2048-kmax1024/rust/set.rs"]
mod lattice;
#[cfg(not(any(feature = "set-n2304-kmax4096", feature = "set-n2560-kmax16384")))]
#[path = "../../../params/sets/n2048-kmax1024/pqzh_set.rs"]
mod pqzh;

// the Ligero build's set is pqz-stmt's (a dependent enabling pqz-stmt/set-X without pqzh-ligero/set-X would otherwise
// build Ligero at n2048-kmax1024's constants against set X's codec; review 8c part 2 m6)
const fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
const _: () = assert!(same(lattice::SET_NAME, pqz_stmt::SET), "pqzh-ligero's set-<set> must be pqz-stmt's");

pub(crate) use lattice::*;
pub(crate) use pqzh::*;

/// the set's name (pqz-core/params/sets/<SET_NAME>/)
pub const NAME: &str = lattice::SET_NAME;
/// l2 bounds: CBD(1) vectors (s, r), CBD(20) vectors (e, e1), e2 (v3 36 / 164 / 64)
pub const BETA_S: usize = lattice::BETA_S;
pub const BETA_E: usize = lattice::BETA_E;
pub const BETA_2: usize = lattice::BETA_2;
/// bit widths: M_i < 2^MBITS, c_i + 64 < 2^CBITS, e_T + 2^(EBITS-1) < 2^EBITS (v3 14 / 11 / 25)
pub const MBITS: u32 = lattice::MBITS;
pub const CBITS: u32 = lattice::CBITS;
pub const EBITS: u32 = lattice::EBITS;
