/*
 * l2dom PoC, R_TX (P6-L2, https://github.com/lazer-crypto/lazer/issues/25). A sender and a colluding recipient (the sender knows the recipient key
 * (s_t, e_t)) build a transfer whose (r, e1) is aligned with (e_t, -s_t) and uses the whole pooled l2 budget
 * sum_z B_z^2 = 2*36^2 + 2*164^2 + 3*64^2 = 68672 (‖r‖ <= 36 and ‖e1‖ <= 164 are not respected). The recipient's
 * decryption noise on coefficient 0 then exceeds the spec's B_FRESH = 11,872 (pq-zether.md §4.3).
 *
 *   l2dom_tx prove DIR    (built with -DPQZ_L2DOM_POC) prove, verify in-process, write DIR/tx_over.{stmt,proof}
 *   l2dom_tx verify DIR   (linked against the production libpqz.a)
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pqz.h"

#ifdef PQZ_L2DOM_POC
extern int pqz_l2dom_poc, pqz_err, pqz_err_line;
extern const char *pqz_err_file;
#endif

#define DELTA ((int64_t)((1 << 26) - 1))

static uint64_t xs = 0x243F6A8885A308D3ULL;
static int
cbd (int eta)
{
  xs ^= xs >> 12, xs ^= xs << 25, xs ^= xs >> 27;
  uint64_t r = xs * 2685821657736338717ULL;
  int a = 0, b = 0;
  for (int i = 0; i < eta; i++)
    a += (r >> i) & 1, b += (r >> (32 + i)) & 1;
  return a - b;
}

static void
le16 (uint8_t *p, int16_t v)
{
  p[0] = (uint8_t)v, p[1] = (uint8_t)((uint16_t)v >> 8);
}

static void
digits (uint8_t m[16], uint64_t x)
{
  for (int i = 0; i < 16; i++)
    m[i] = (uint8_t)((x >> (4 * i)) & 15);
}

/* b = c * a "reversed" so that coefficient 0 of a * b in Z[X]/(X^64 + 1) is c * ||a||^2 (per poly) */
static void
align (int64_t *b, const int64_t *a, double c)
{
  for (int k = 0; k < 32; k++)
    {
      const int64_t *ak = a + 64 * k;
      int64_t *bk = b + 64 * k;
      bk[0] = llround (c * ak[0]);
      for (int j = 1; j < 64; j++)
        bk[64 - j] = llround (-c * ak[j]);
    }
}

static long
n2 (const int64_t *a, int n)
{
  long s = 0;
  for (int i = 0; i < n; i++)
    s += a[i] * a[i];
  return s;
}

int
main (int argc, char **argv)
{
  static uint8_t stmt[PQZ_TX_STMT_BYTES], wit[PQZ_TX_WIT_BYTES], proof[PQZ_MAX_PROOF];
  static int8_t sf[2048], st[2048], sa[2048], r8[2048], r0[2048];
  static int16_t ef[2048], et[2048], ea[2048], e1[2048], e10[2048], e2[3][16], e20[1][16];
  static uint8_t pkf[PQZ_POLYVEC_BYTES], pkt[PQZ_POLYVEC_BYTES], pka[PQZ_POLYVEC_BYTES], uT[PQZ_POLYVEC_BYTES],
      vT[1][PQZ_V_BYTES], u[PQZ_POLYVEC_BYTES], vs[3][PQZ_V_BYTES];
  static int64_t x[4096], y[4096];
  size_t arena_len = (size_t)768 << 20;
  void *arena = malloc (arena_len);
  if (argc < 3 || !arena || pqz_init (arena, arena_len))
    return fprintf (stderr, "usage: %s prove|verify DIR\n", argv[0]), 2;
  char ps[512], pp[512];
  snprintf (ps, sizeof ps, "%s/tx_over.stmt", argv[2]);
  snprintf (pp, sizeof pp, "%s/tx_over.proof", argv[2]);
  size_t pl = sizeof proof;

  if (!strcmp (argv[1], "verify"))
    {
      FILE *f = fopen (ps, "rb"), *g = fopen (pp, "rb");
      if (!f || !g)
        return printf ("tx_over (no proof file)\n"), 0;
      fread (stmt, 1, sizeof stmt, f), pl = fread (proof, 1, sizeof proof, g), fclose (f), fclose (g);
      printf ("  production-lib pqz_verify(tx_over): %s\n",
              pqz_verify (PQZ_OP_TRANSFER, stmt, sizeof stmt, proof, pl) ? "ACCEPT" : "REJECT");
      return 0;
    }
#ifndef PQZ_L2DOM_POC
  return fprintf (stderr, "prove needs -DPQZ_L2DOM_POC\n"), 2;
#else
  /* keys: recipient t and auditor a honest-shaped (s CBD(1), e CBD(20)); sender f small (both CBD(1)), leaving the
     budget to (r, e1) */
  for (int j = 0; j < 2048; j++)
    {
      sf[j] = (int8_t)cbd (1), ef[j] = (int16_t)cbd (1);
      st[j] = (int8_t)cbd (1), et[j] = (int16_t)cbd (20);
      sa[j] = (int8_t)cbd (1), ea[j] = (int16_t)cbd (20);
      r0[j] = (int8_t)cbd (1), e10[j] = (int16_t)cbd (20);
    }
  pqz_keypair_from_secret (sf, ef, pkf), pqz_keypair_from_secret (st, et, pkt), pqz_keypair_from_secret (sa, ea, pka);

  /* balance 1,000,000 encrypted honestly to pk_f; transfer 123,456, fee 7 */
  const uint64_t B = 1000000, v = 123456, fee = 7, bp = B - v - fee;
  uint8_t mT[1][16], m[3][16];
  digits (mT[0], B);
  const uint8_t *pf1[1] = { pkf };
  pqz_encrypt (pf1, 1, (const uint8_t (*)[16])mT, r0, e10, (const int16_t (*)[16])e20, uT, vT);

  /* x = (e_t, -s_t); y = (r, e1) = c * aligned(x), ||y||^2 just under the pooled budget left by s_f, e_f */
  for (int j = 0; j < 2048; j++)
    x[j] = et[j], x[2048 + j] = -st[j];
  long nf = 0;
  for (int j = 0; j < 2048; j++)
    nf += sf[j] * sf[j] + ef[j] * ef[j];
  const long budget = 68672 - nf - 64; /* keep a little room for rounding */
  double c = sqrt ((double)budget / (double)n2 (x, 4096));
  do
    {
      align (y, x, c), align (y + 2048, x + 2048, c);
      c *= 0.999;
    }
  while (n2 (y, 4096) > budget);
  for (int j = 0; j < 2048; j++)
    r8[j] = (int8_t)y[j], e1[j] = (int16_t)y[2048 + j];
  memset (e2, 0, sizeof e2);
  digits (m[0], v), digits (m[1], bp), digits (m[2], v);
  const uint8_t *pks[3] = { pkt, pkf, pka };
  pqz_encrypt (pks, 3, (const uint8_t (*)[16])m, r8, e1, (const int16_t (*)[16])e2, u, vs);

  /* statement (§7.7 header, fee word at 256) and witness, as test/pqz_bench.c */
  uint8_t *p = stmt;
  memset (p, 0x5A, PQZ_HEADER_BYTES);
  for (int b = 7; b >= 0; b--)
    p[PQZ_HDR_FEE + 31 - b] = (uint8_t)(fee >> (8 * b));
  memset (p + PQZ_HDR_FEE, 0, 24), memset (p + PQZ_HDR_AMOUNT, 0, 32);
  memset (p + PQZ_HDR_AUDITOR_ON, 0, 32), p[PQZ_HDR_AUDITOR_ON + 31] = 1; /* P6e R6: auditorOn 1 on this form */
  memset (p + PQZ_HDR_SALT, 0, 16); /* canonical salt word (P6e D15) */
  p += PQZ_HEADER_BYTES;
  memcpy (p, pkf, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, pkt, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, pka, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, uT, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  memcpy (p, vT[0], PQZ_V_BYTES), p += PQZ_V_BYTES;
  memcpy (p, u, PQZ_POLYVEC_BYTES), p += PQZ_POLYVEC_BYTES;
  for (int k = 0; k < 3; k++)
    memcpy (p, vs[k], PQZ_V_BYTES), p += PQZ_V_BYTES;
  p = wit;
  for (int j = 0; j < 2048; j++)
    p[j] = (uint8_t)sf[j];
  p += 2048;
  for (int j = 0; j < 2048; j++)
    le16 (p + 2 * j, ef[j]);
  p += 4096;
  for (int j = 0; j < 2048; j++)
    p[j] = (uint8_t)r8[j];
  p += 2048;
  for (int j = 0; j < 2048; j++)
    le16 (p + 2 * j, e1[j]);
  p += 4096 + 96; /* e2 = 0 */
  for (int i = 0; i < 16; i++)
    p[i] = m[0][i], p[16 + i] = m[1][i];

  long nr = n2 (y, 2048), ne1 = n2 (y + 2048, 2048);
  int64_t w[16];
  pqz_decrypt_raw (st, u, vs[0], w);
  int64_t noise0 = w[0] - DELTA * m[0][0];
  printf ("tx_over  ||s_f||^2+||e_f||^2=%ld ||r||^2=%ld (bound 1296, ||r||=%.1f vs 36) ||e1||^2=%ld (bound 26896) "
          "sum=%ld (bound 68672)\n",
          nf, nr, sqrt ((double)nr), ne1, nf + nr + ne1);
  printf ("  recipient decryption noise, coefficient 0: %lld  (spec worst case B_FRESH = 11872; ratio %.2f)\n",
          (long long)noise0, (double)noise0 / 11872.0);
  printf ("  x 1023 credits = %.2f M  (2^24 = 16.78 M debit range; Delta/2 = 33.55 M; mint threshold Delta - 2^24 = "
          "50.33 M)\n",
          1023.0 * (double)noise0 / 1e6);
  uint8_t rnd32[32];
  for (int i = 0; i < 32; i++)
    rnd32[i] = (uint8_t)(17 + i);
  pqz_l2dom_poc = 0;
  int rc0 = pqz_prove (PQZ_OP_TRANSFER, stmt, sizeof stmt, wit, sizeof wit, rnd32, proof, &pl);
  printf ("  honest prover rc=%d (%s)\n", rc0, rc0 ? "refuses: witness above a block bound" : "proves");
  pqz_l2dom_poc = 1;
  pl = sizeof proof;
  int rc = pqz_prove (PQZ_OP_TRANSFER, stmt, sizeof stmt, wit, sizeof wit, rnd32, proof, &pl);
  printf ("  pooled-slack prover rc=%d proof %zu B; prover self-checks: %s%s:%d\n", rc, pl,
          pqz_err ? "FAIL (ignored), first at " : "pass", pqz_err ? pqz_err_file : "", pqz_err ? pqz_err_line : 0);
  if (rc && !(rc == pqz_err && pl < sizeof proof))
    return 0;
  FILE *f = fopen (ps, "wb"), *g = fopen (pp, "wb");
  fwrite (stmt, 1, sizeof stmt, f), fwrite (proof, 1, pl, g), fclose (f), fclose (g);
  printf ("  in-process pqz_verify(tx_over): %s\n",
          pqz_verify (PQZ_OP_TRANSFER, stmt, sizeof stmt, proof, pl) ? "ACCEPT" : "REJECT");
  return 0;
#endif
}
