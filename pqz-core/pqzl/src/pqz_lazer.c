/*
 * pqz-core unity build of the kept LaZer protocol code over the rewritten layers.
 * lazer.h is assembled by build.sh from lazer/lazer-in1.h, lazer/config.h and lazer/lazer-in2.h,
 * as upstream's Makefile does.
 */
#include "abdlop.c"
#include "brandom.c"
#include "coder.c"
#include "dcompress.c"
#include "grandom.c"
#include "int.c"
#include "intmat.c"
#include "intvec.c"
/* lnp-quad-eval.c: not built since the R0 review fix (R1-1 / R1-C7: no caller, upstream lazer#28 transcript without h);
   kept in ../legacy/ */
#include "lnp-quad-many.c"
#include "lnp-quad.c"
#include "lnp-tbox.c"
#include "memory.c"
#include "poly.c"
#include "polymat.c"
#include "polyring.c"
#include "polyvec.c"
#include "rejection.c"
#include "rng.c"
#include "shake128.c"
#include "spolymat.c"
#include "spolyvec.c"
#include "urandom.c"
#include "aes256ctr.c"
