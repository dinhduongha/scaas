//! Hashing and sampling: SHAKE128 / SHAKE256 and the keys' CBD bit stream (`shake128.c`, `pqz_keys.c`), the library
//! PRNG (`rng.c`, `aes256ctr.c`), the uniform, binomial and discrete Gaussian samplers (`urandom.c`, `brandom.c`,
//! `grandom.c`) and the rejection tests (`rejection.c`) on the integer exp of `pqz_fixexp.h`.
pub(crate) mod aes_ctr;
pub(crate) mod brandom;
pub(crate) mod fixexp;
pub(crate) mod grandom;
pub(crate) mod rejection;
pub(crate) mod rng;
pub(crate) mod shake;
pub(crate) mod urandom;
