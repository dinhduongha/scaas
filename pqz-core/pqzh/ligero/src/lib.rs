//! PQZH over Ligero (P6-PQZH, Ligero backend): R_REG, R_TX, R_TX0, R_BURN, R_DS, R_DR and R_TXM (op 7) of PQ Zether proved by
//! Ligero over F_q itself (q of the parameter set, `set`: v3 2^42 - 215), challenges in F_q^4, Keccak-256 Merkle tree and transcript, zero knowledge.
//! See docs/research/pqzh-ligero.md. Statements are decoded by `pqz-stmt` (plan R2, D15); witness bytes as pqz-core
//! (pqz.h). Depends on `sha3` and `pqz-stmt` only (D11). Feature `bench` (default): the reference presets, the float
//! parameter model and soundness accounting, and the test client (`client`: pqz_bench.c's setup, mutations); the
//! production build (`--no-default-features`) has none of them.
#![cfg_attr(not(feature = "bench"), deny(clippy::float_arithmetic))]
#![cfg_attr(not(feature = "ctgrind"), forbid(unsafe_code))]
// only the test-only memcheck client requests (ct.rs, feature ctgrind) allow it (review P-E, as pqzl/rust)
#![cfg_attr(feature = "ctgrind", deny(unsafe_code))]

#[cfg(feature = "bench")]
pub mod client;
pub mod cs;
#[cfg(feature = "ctgrind")]
#[doc(hidden)]
pub mod ct; // the ctgrind check's `secret` (src/bin/ct.rs): test entry point, not API
#[cfg(not(feature = "ctgrind"))]
mod ct;
pub mod fft;
pub mod fq;
pub mod ligero;
pub mod merkle;
pub mod ring;
pub mod set;
pub mod transcript;

/// Whether the research feature `fallback-retry` (n2304-kmax4096's THE preset with the prover's retry, fallback A) is on.
/// Such a build has no proofSystemId of its own (its preset is not the one PQZH_ID's label names: the test
/// `ids_are_the_labels_keccak` fails there by design), so pqz-ffi refuses to compile with it (review R3-1 / R4-C5)
pub const FALLBACK_RETRY: bool = cfg!(feature = "fallback-retry");

pub use cs::{RELS, Rel, form_of, multi_rels, rel_of};
pub use ligero::{Params, prove, try_verify, verify};
#[cfg(feature = "bench")]
pub use ligero::{breakdown, prove_unchecked, soundness};
pub use pqz_stmt::{self, Form, OP_BURN, OP_DISCLOSE_RECEIVER, OP_DISCLOSE_SENDER, OP_REGISTER, OP_TRANSFER, OP_TRANSFER_MULTI};

/// Out of memory: a fault of the machine, not a property of the input (review P-D). [`try_verify`] returns it when one
/// of the verifier's buffers could not be reserved; pqz-ffi maps it to `NodeFault`, as PQZL's `Error::Memory`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Oom;

/// an empty Vec with room for `n` elements (reserved fallibly: no allocation-failure abort)
pub(crate) fn try_vec<T>(n: usize) -> Result<Vec<T>, Oom> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Oom)?;
    Ok(v)
}

/// Clears the prover's secrets on drop (review P-C, as PQZL fix B: `pqzl/rust/src/lib.rs` `wipe` / `Wiped`): the
/// witness values, rows, row polynomials and their encodings, the masks, salts, the products and quotients of the
/// tests, the honest prover's decryptions; the SHAKE256 reader is replaced in place (`ligero::Rng`).
/// Platform boundary: best effort, not guaranteed. Plain stores plus `black_box` (a volatile write needs `unsafe`,
/// forbidden here, and `zeroize` would be a third dependency, D11), so the compiler is not bound to keep the stores,
/// and copies it or the allocator made (by-value arguments such as `rnd32`, moves, register spills, stack temporaries, a
/// Vec's old buffer after a reallocation, the sha3 hasher state before `finalize_xof`) are never cleared.
pub(crate) trait Wipe {
    fn wipe(&mut self);
}

macro_rules! wipe_leaf {
    ($($t:ty),*) => {$(
        impl Wipe for $t {
            fn wipe(&mut self) {
                *self = <$t>::default();
            }
        }
    )*};
}
wipe_leaf!(u8, i64, i128, u128, fq::Fq, fq::F4, fq::Acc4);

impl<T: Wipe> Wipe for Vec<T> {
    fn wipe(&mut self) {
        self.iter_mut().for_each(T::wipe);
        std::hint::black_box(&*self);
    }
}

impl<T: Wipe, const N: usize> Wipe for [T; N] {
    fn wipe(&mut self) {
        self.iter_mut().for_each(T::wipe);
        std::hint::black_box(&*self);
    }
}

/// A prover secret that [`Wipe`]s itself when dropped, so every exit, `?` included, clears it.
pub(crate) struct Wiped<T: Wipe>(pub(crate) T);

impl<T: Wipe> Drop for Wiped<T> {
    fn drop(&mut self) {
        self.0.wipe();
    }
}

impl<T: Wipe> std::ops::Deref for Wiped<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Wipe> std::ops::DerefMut for Wiped<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
