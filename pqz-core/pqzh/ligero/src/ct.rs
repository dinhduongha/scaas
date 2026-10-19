//! Constant-time marks of the prover (review P-B, 2026-10-19; the method of PQZL fix E, `pqzl/rust/src/ct.rs`).
//!
//! [`public`] marks secret-derived data that is public by design (the commitment root, a proof field, the opened
//! columns) for valgrind's memcheck (the ctgrind check, `src/bin/ct.rs`, `runs/ct.sh`); [`verdict`] does the same for
//! a scalar verdict (the witness-valid verdicts, the prover's self-checks, a rejection-sampling accept bit); [`secret`]
//! marks the witness and rnd32 secret there. All are memcheck client requests under the test-only feature `ctgrind`
//! (x86-64 only), and no-ops in every other build.

/// all ones if `c == 1`, 0 if `c == 0`, through `black_box`, so LLVM cannot turn a masked select on secret data back
/// into a branch (x86-64 cmov conversion did that to `ring::modq`'s centring; memcheck run `runs/ct-rev2-wip.txt`).
/// `black_box` is a best-effort barrier (core documents it so); the ctgrind check is the evidence.
#[inline(always)]
pub(crate) fn mask(c: u64) -> u64 {
    core::hint::black_box(c.wrapping_neg())
}

/// public by design from here on (memcheck: defined)
#[inline(always)]
pub fn public<T: ?Sized>(x: &T) {
    #[cfg(feature = "ctgrind")]
    vg::request(vg::MAKE_MEM_DEFINED, x);
    #[cfg(not(feature = "ctgrind"))]
    let _ = x;
}

/// a verdict that is public by design: `x`, marked defined. A separate function from [`public`]: through a shared
/// reference the compiler may keep branching on the register copy memcheck still sees as secret, so the value is
/// copied, marked through its address and read back.
#[inline(always)]
pub(crate) fn verdict(x: bool) -> bool {
    #[cfg(feature = "ctgrind")]
    {
        vg::defined_u8(x as u8) != 0
    }
    #[cfg(not(feature = "ctgrind"))]
    x
}

/// secret (memcheck: undefined); the ctgrind check marks its inputs with it
#[cfg(feature = "ctgrind")]
pub fn secret<T: ?Sized>(x: &T) {
    vg::request(vg::MAKE_MEM_UNDEFINED, x);
}

#[cfg(feature = "ctgrind")]
mod vg {
    /// memcheck.h: VG_USERREQ_TOOL_BASE ('M', 'C') + 1, + 2
    pub(super) const MAKE_MEM_UNDEFINED: u64 = 0x4d43_0001;
    pub(super) const MAKE_MEM_DEFINED: u64 = 0x4d43_0002;

    /// `x` through memory: marked defined by its address, then read back (volatile) from it
    #[allow(unsafe_code)]
    pub(super) fn defined_u8(x: u8) -> u8 {
        let mut y = x;
        let p: *mut u8 = &mut y;
        // SAFETY: p points to the live local y
        unsafe {
            request(MAKE_MEM_DEFINED, &*p);
            core::ptr::read_volatile(p)
        }
    }

    /// valgrind.h's amd64 client request (VALGRIND_DO_CLIENT_REQUEST_EXPR): a no-op sequence outside valgrind
    #[allow(unsafe_code)]
    pub(super) fn request<T: ?Sized>(req: u64, x: &T) {
        let args = [req, x as *const T as *const u8 as u64, core::mem::size_of_val(x) as u64, 0, 0, 0];
        core::hint::black_box(&args);
        let mut res = 0u64;
        // SAFETY: the magic sequence rotates rdi by 128 bits (unchanged) and exchanges rbx with itself; valgrind
        // reads `args` (rax) and writes rdx. Test-only feature.
        unsafe {
            core::arch::asm!(
                "rol rdi, 3", "rol rdi, 13", "rol rdi, 61", "rol rdi, 51", "xchg rbx, rbx",
                inout("rdx") res, in("rax") args.as_ptr(), out("rdi") _, options(nostack)
            );
        }
        let _ = res;
    }
}
