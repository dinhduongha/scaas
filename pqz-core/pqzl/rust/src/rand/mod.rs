//! The library PRNG and the samplers driven by it (`rng.c`, `aes256ctr.c`, `urandom.c`, `brandom.c`). Task 2 brings
//! the part the arithmetic KAT needs (the AES-256-CTR stream, the uniform and binomial samplers); Task 3 the rest.
pub(crate) mod aes_ctr;
pub(crate) mod brandom;
pub(crate) mod rng;
pub(crate) mod urandom;
