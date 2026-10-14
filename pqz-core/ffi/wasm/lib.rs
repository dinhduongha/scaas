//! pqz-ffi prove feature in wasm32: `run(sel)` writes the digest lines of `pqz_ffi::fixture::digest_lines` (sel bit 0
//! PQZL, bit 1 PQZH) and the self-test hash; `out_ptr` / return value = the UTF-8 text in linear memory.
use std::cell::RefCell;

use pqz_ffi::{fixture, PQZH_ID, PQZL_ID};

thread_local! {
    static OUT: RefCell<String> = const { RefCell::new(String::new()) };
}

#[no_mangle]
pub extern "C" fn run(sel: u32) -> u32 {
    let mut s = String::new();
    for (bit, id) in [(1, PQZL_ID), (2, PQZH_ID)] {
        if sel & bit != 0 {
            s += &fixture::digest_lines(&id);
        }
    }
    s += &fixture::selftest_line();
    OUT.with(|o| {
        *o.borrow_mut() = s;
        o.borrow().len() as u32
    })
}

#[no_mangle]
pub extern "C" fn out_ptr() -> *const u8 {
    OUT.with(|o| o.borrow().as_ptr())
}
