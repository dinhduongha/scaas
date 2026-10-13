/* Review PoC hooks, prepended to a patched copy of lazer/lnp-quad.c by sv/review/review.sh (never in a production
   build). pqz_poc_mode selects the cheating prover: 0 honest, 1 z1 inflated (y1 << 3, z1 rejection skipped),
   2 z21 inflated (y21 << 7, z2 rejection and the prover's own ||y2|| check skipped), 3 w1 shifted by +2 mod m before
   the final hash, the hint shifted to match (so the verifier recovers the hashed w1 and ||w - gamma w1|| grows). */
int pqz_poc_mode;
int64_t pqz_poc_z21sq; /* mode 2: ||z21||^2 of the emitted proof */

static void
poc_shift (polyvec_t v, int_srcptr m, int64_t s) /* v in [0, m) -> v + s mod m */
{
  const int64_t mm = int_get_i64 (m);
  polyvec_fromcrt (v);
  for (unsigned i = 0; i < polyvec_get_nelems (v); i++)
    for (unsigned j = 0; j < 64; j++)
      {
        int_ptr c = poly_get_coeff (polyvec_get_elem (v, i), j);
        int64_t x = (int_get_i64 (c) + s) % mm;
        int_set_i64 (c, x < 0 ? x + mm : x);
      }
}
static void
poc_add (polyvec_t v, int64_t s)
{
  polyvec_fromcrt (v);
  for (unsigned i = 0; i < polyvec_get_nelems (v); i++)
    for (unsigned j = 0; j < 64; j++)
      {
        int_ptr c = poly_get_coeff (polyvec_get_elem (v, i), j);
        int_set_i64 (c, int_get_i64 (c) + s);
      }
}
