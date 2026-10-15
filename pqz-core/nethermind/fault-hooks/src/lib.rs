//! Test-only: pqz-ffi's C ABI plus `pqz_test_fail_worker` (pqzl::TEST_FAIL_WORKER), so a .NET child process can drive
//! the node-fault status (4) through `PqzPrecompile.Run` (P6f D4).
use std::sync::atomic::Ordering::Relaxed;

pub use pqz_ffi::pqz_precompile;

#[no_mangle]
pub extern "C" fn pqz_test_fail_worker(on: bool) {
    pqz_ffi::pqzl::TEST_FAIL_WORKER.store(on, Relaxed);
}
