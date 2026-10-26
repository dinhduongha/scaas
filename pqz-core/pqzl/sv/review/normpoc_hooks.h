/* Review PoC hooks, prepended to a patched copy of lazer/lnp-quad.c by sv/review/review.sh (never in a production
   build). pqz_poc_mode selects the cheating prover: 0 honest, 1 z1 inflated (y1 << 3, z1 rejection skipped),
   2 z21 inflated (y21 << pqz_poc_shift, 7, or less while the proof exceeds PQZ_MAX_PROOF: 6 at n2816-kmax65536, as its tbox logs print; z2 rejection and the prover's own ||y2|| check skipped), 3 w1 shifted by +2 mod m before
   the final hash, the hint shifted to match (so the verifier recovers the hashed w1 and ||w - gamma w1|| grows);
   4 (P6-Z21 differential, sv/review/z21diff.c) ||z21||^2 grown as if the first polynomial p of y21 were times
   pqz_poc_k, but in one coefficient: p_0 += sign(p_0) (k - 1) ||p||_2, so ||z21||^2 ~ k^2 ||p||^2 + the rest (the
   same k crosses Bsq as with p times k) while the proof grows by ~ (k - 1) ||p||_2 / 2^log2o bits instead of
   ~ (k - 1) ||p||_1 / 2^log2o (coder_enc_grandom codes the high part in unary; ||p||_1 ~ 6.4 ||p||_2): with p times k
   the audited R_TXM M = 8 of n2304-kmax4096 (G = 3 since the R0 review fix, Bsq 3.9e16) reached PQZ_MAX_PROOF at
   ||z2||^2 / Bsq = 0.36 (k = 1578, 96,741 B) and never saw its reject (R0 fix gate, 2026-10-26); z2 rejection and
   ||y2|| check skipped as in 2. */
int pqz_poc_mode;
int64_t pqz_poc_k = 1;
int pqz_poc_shift = 7; /* mode 2 */
int64_t pqz_poc_z21sq; /* modes 2, 4: ||z21||^2 of the emitted proof */
int64_t pqz_poc_z2sq;  /* modes 2, 4: ||(z21, z22)||^2, the quantity the honest prover bounds by Bsqr */
#define POC_Z21 (pqz_poc_mode == 2 || pqz_poc_mode == 4)

static void
poc_mul0 (polyvec_t v, int64_t k) /* mode 4: p_0 += sign(p_0) (k - 1) ||p||_2, p the first polynomial of v */
{
  uint64_t s = 0, r = 0; /* y21 is Gaussian (sigma < 2^20 at every set): s < 2^47 */
  polyvec_fromcrt (v);
  for (unsigned j = 0; j < 64; j++)
    {
      const int64_t x = int_get_i64 (poly_get_coeff (polyvec_get_elem (v, 0), j));
      s += (uint64_t)(x * x);
    }
  for (uint64_t b = (uint64_t)1 << 31; b; b >>= 1) /* r = floor(sqrt(s)), no libm (normpoc links without it) */
    if ((r + b) * (r + b) <= s)
      r += b;
  int_ptr c = poly_get_coeff (polyvec_get_elem (v, 0), 0);
  const int64_t c0 = int_get_i64 (c), add = (k - 1) * (int64_t)r;
  int_set_i64 (c, c0 < 0 ? c0 - add : c0 + add);
}

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
