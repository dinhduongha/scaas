//! Test-only: pqz-ffi's C ABI plus `pqz_test_fail_worker` (pqzl::TEST_FAIL_WORKER) and `pqz_test_panic`
//! (pqzl::TEST_PANIC), so a .NET child process can drive the node-fault status (4, P6f D4) and the input-panic status (3,
//! review R4-C6) through `PqzPrecompile.Run`.
use std::sync::atomic::Ordering::Relaxed;

pub use pqz_ffi::{pqz_max_input, pqz_precompile};

#[no_mangle]
pub extern "C" fn pqz_test_fail_worker(on: bool) {
    pqz_ffi::pqzl::TEST_FAIL_WORKER.store(on, Relaxed);
}

/// Review R4-C6 (plan 5h Task 8d part 2b): every core call panics inside pqz-ffi's catch, as a panic in the decoder /
/// verifier would (status 3, `PQZ-INPUT-PANIC`, `…00`).
#[no_mangle]
pub extern "C" fn pqz_test_panic(on: bool) {
    pqz_ffi::pqzl::TEST_PANIC.store(on, Relaxed);
}
