/* C smoke test of pqz_ffi.h against libpqz_ffi.so (run.sh): argument errors, revert, an invalid input, the
   self-test (printed: it must equal the Rust test's hash). Exit 0 = ok. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../pqz_ffi.h"

/* the build's set limit (run.sh passes set.json max_input; plan 5h Task 8c part 2): PQZ_FFI_MAX_INPUT is the node's
   limit, n2048-kmax1024's; the other sets' pqz-stmt accepts up to 524,288 until the node follows in Task 8d */
#ifndef PQZ_SET_MAX_INPUT
#define PQZ_SET_MAX_INPUT PQZ_FFI_MAX_INPUT
#endif

int
main (void)
{
  uint8_t out[PQZ_FFI_OUT_BYTES], st[5] = { 6, 0, 0, 0, 0 }, bad[5] = { 1, 0, 0, 0, 0 };
  int fails = 0;
  fails += pqz_precompile (NULL, 5, out, sizeof out) != PQZ_FFI_BAD_ARGS;
  fails += pqz_precompile (st, 5, out, 31) != PQZ_FFI_BAD_ARGS;
  uint8_t *big = calloc (PQZ_SET_MAX_INPUT + 1, 1);
  fails += big == NULL || pqz_precompile (big, PQZ_SET_MAX_INPUT + 1, out, sizeof out) != PQZ_FFI_REVERT;
  free (big);
  memset (out, 0xEE, sizeof out);
  fails += pqz_precompile (bad, 5, out, sizeof out) != PQZ_FFI_OK || out[31] != 0 || out[0] != 0;
  fails += pqz_precompile (st, 5, out, sizeof out) != PQZ_FFI_OK;
  printf ("c_abi: selftest ");
  for (int i = 0; i < 32; i++)
    printf ("%02x", out[i]);
  printf ("\nc_abi: %s (%d failures)\n", fails ? "FAIL" : "ok", fails);
  return fails != 0;
}
