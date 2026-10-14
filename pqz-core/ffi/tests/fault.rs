//! Node faults (controller 2026-10-14): injected through the test hooks, in a process of their own (they disturb
//! every other libpqz call). Arena exhaustion and an unavailable worker give `Err(NodeFault)` / status 4 with `out`
//! untouched, never …00; after the fault is gone the same inputs verify again.
use std::sync::atomic::Ordering::Relaxed;

use pqz_ffi::*;

/// the graceful band 14–20 MiB of `runs/ffi1d-arena-probe.txt`
const ARENA_MIB: usize = 18;

#[test]
fn node_faults_are_status_4() {
    let c = fixture::cases(&PQZL_ID).unwrap().into_iter().find(|c| c.form == stmt::Form::Transfer).unwrap();
    let proof = prove(c.op(), &c.stmt, &c.wit, &[7; 32]).unwrap();
    let input = stmt::input(c.op(), &c.stmt, &proof);
    let r = fixture::cases(&PQZL_ID).unwrap().into_iter().find(|c| c.form == stmt::Form::Register).unwrap();
    let reg_input = stmt::input(r.op(), &r.stmt, &prove(r.op(), &r.stmt, &r.wit, &[7; 32]).unwrap());
    let h = fixture::cases(&PQZH_ID).unwrap().into_iter().find(|c| c.form == stmt::Form::Register).unwrap();
    let pqzh_input = stmt::input(h.op(), &h.stmt, &prove(h.op(), &h.stmt, &h.wit, &[7; 32]).unwrap());
    assert_eq!(precompile(&input), Ok(VALID));
    let c_abi = |inp: &[u8]| {
        let mut out = [0xEEu8; 32];
        let rc = unsafe { pqz_precompile(inp.as_ptr(), inp.len(), out.as_mut_ptr(), 32) };
        (rc, out)
    };

    // arena exhaustion: 18 MiB holds A, R_REG's whole verify, and R_TX's ABDLOP keys but not its whole verify (R_TX
    // alone needs 20–24 MiB);
    // the core then fails gracefully. Below 14 MiB it crashes (SIGSEGV, exhaustion inside the relation's key
    // generation: STATUS.md Open 2), so the probe ffi1d-arena-probe.txt picked the middle of the 14–20 MiB band.
    let mib: usize = std::env::var("PQZ_FAULT_ARENA_MIB").ok().and_then(|v| v.parse().ok()).unwrap_or(ARENA_MIB);
    eprintln!("fault arena {mib} MiB");
    pqzl::TEST_ARENA_BYTES.store(mib << 20, Relaxed);
    pqzl::reinit(mib << 20);
    assert_eq!(precompile(&input), Err(Error::NodeFault));
    assert_eq!(c_abi(&input), (PQZ_FFI_NODE_FAULT, [0xEE; 32]));
    assert_eq!(pqzl::verify_fast(c.op(), &c.stmt, &proof), Err(NodeFault));
    // the decoder's rejections need no core: still …00
    assert_eq!(precompile(&input[..input.len() - proof.len()]), Ok(INVALID));
    // each fault dropped the core (the three calls above each ran on a fresh core and faulted the same way); at the
    // SAME fixed size a fresh core verifies what fits (R_REG): never a stale, half-exhausted core
    assert_eq!(precompile(&reg_input), Ok(VALID), "fresh core at {mib} MiB");
    assert_eq!(precompile(&reg_input), Ok(VALID));
    pqzl::TEST_ARENA_BYTES.store(0, Relaxed);
    assert_eq!(precompile(&input), Ok(VALID), "re-initialised after the fault");

    // worker unavailable: verify and the (uncached) self-test
    pqzl::TEST_FAIL_WORKER.store(true, Relaxed);
    assert_eq!(precompile(&input), Err(Error::NodeFault));
    assert_eq!(c_abi(&input), (PQZ_FFI_NODE_FAULT, [0xEE; 32]));
    assert_eq!(precompile(&[6, 0, 0, 0, 0]), Err(Error::NodeFault));
    assert_eq!(c_abi(&[6, 0, 0, 0, 0]), (PQZ_FFI_NODE_FAULT, [0xEE; 32]));
    assert!(pqzl::keygen(&[1; 32]).is_none());
    assert_eq!(prove(c.op(), &c.stmt, &c.wit, &[7; 32]), Err(ProveError::Pqzl(-1)));
    // PQZH needs no core
    assert_eq!(precompile(&pqzh_input), Ok(VALID));
    pqzl::TEST_FAIL_WORKER.store(false, Relaxed);
    assert_eq!(precompile(&input), Ok(VALID));
    let st = precompile(&[6, 0, 0, 0, 0]).unwrap();
    assert_eq!(st, selftest::report().unwrap().hash);
    eprintln!("node faults: arena exhaustion and worker failure → status 4, out untouched; recovered");
}
