//! The arithmetic layer of the C core: limbs (`pqz_mpn.h`), LaZer's ints and int vectors (`int.c`, `intvec.c`, the
//! `pqz_glue.h` reductions), R_q and its NTT (`poly.c`, `pqz_ntt.c`), dense and sparse vectors and matrices of
//! polys (`polyvec.c`, `polymat.c`, `spolyvec.c`, `spolymat.c`). LaZer's `mont.h` (Montgomery helpers of the dropped
//! CRT representation) and `intmat.c` (no caller in the core) have no counterpart.
pub(crate) mod int;
pub(crate) mod mpn;
pub(crate) mod ntt;
pub(crate) mod poly;
pub(crate) mod polymat;
pub(crate) mod polyvec;
pub(crate) mod spoly;
