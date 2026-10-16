/*
 * Arithmetic-layer KAT dump (pq-zero-knowledge.md CTR-PQZ-09: the cross-check against upstream LaZer).
 *
 * One source, two backends: built against upstream LaZer 3330e48 (build-lazer-dump.sh, static binary for any
 * AVX-512 machine or Intel SDE) it writes the golden file kat/lazer-3330e48.json; built against pqz-core
 * (build.sh native) it writes the same cases from the rewritten layers, and kat/check.py compares the two.
 *
 * Inputs are fixed: a xorshift64* stream with a fixed seed plus edge polynomials, no RNG of the library
 * except where the case is the library's PRNG (rng/urandom/brandom: AES-256-CTR, bit-exact by design).
 * Cases: ring products (R_q, q = 2^42 - 215, d = 64), matrix-vector and dot products, add/sub/neg/scale,
 * the automorphism X -> X^-1, l2^2 and l_inf norms, Dilithium-style decompose/power2round (tbox params),
 * the AES-256-CTR stream, uniform and binomial samplers. Output: JSON on stdout.
 */
#include "lazer.h"

#include "pqz_tx_params.h"

#include <stdio.h>
#include <string.h>

#ifdef PQZ_BACKEND
#include <stdlib.h>
static uint8_t *arena_mem;
#define BACKEND "pqz-core"
#else
#define BACKEND "lazer-3330e48"
#endif

#ifndef BUILD_FLAGS
#define BUILD_FLAGS "unknown"
#endif

static uint64_t xs = 0x9E3779B97F4A7C15ULL;
static uint64_t
rnd (void)
{
  xs ^= xs >> 12;
  xs ^= xs << 25;
  xs ^= xs >> 27;
  return xs * 2685821657736338717ULL;
}

#define Q 4398046510889LL
#define H ((Q - 1) / 2)

static int first;

static void
print_int (const int_t a)
{
  unsigned __int128 m = a->limbs[0];
  char buf[64];
  int n = 0;
  if (a->nlimbs > 1)
    m |= (unsigned __int128)a->limbs[1] << 64;
  for (unsigned i = 2; i < a->nlimbs; i++)
    if (a->limbs[i])
      {
        printf ("\"overflow\"");
        return;
      }
  if (m == 0)
    {
      printf ("0");
      return;
    }
  while (m)
    {
      buf[n++] = (char)('0' + (int)(m % 10));
      m /= 10;
    }
  if (a->neg)
    putchar ('-');
  while (n)
    putchar (buf[--n]);
}

static void
print_poly (poly_t p)
{
  polyvec_t v;
  (void)v;
  poly_redc (p, p); /* centred representative, forces coefficient domain */
  printf ("[");
  for (unsigned j = 0; j < 64; j++)
    {
      if (j)
        printf (",");
      print_int (poly_get_coeff (p, j));
    }
  printf ("]");
}

static void
fill (poly_t p, int kind)
{
  for (unsigned j = 0; j < 64; j++)
    {
      int64_t v;
      switch (kind)
        {
        case 0: v = (int64_t)(rnd () % (uint64_t)Q) - H; break;
        case 1: v = H; break;
        case 2: v = -H; break;
        case 3: v = (j & 1) ? H : -H; break;
        case 4: v = (int64_t)(rnd () % 3) - 1; break;           /* ternary */
        default: v = (int64_t)(rnd () % 1000001) - 500000; break; /* masked-response size */
        }
      int_set_i64 (poly_get_coeff (p, j), v);
    }
}

static void
begin_case (const char *name)
{
  printf ("%s\n  \"%s\": ", first ? "" : ",", name);
  first = 0;
}

int
main (void)
{
  polyring_srcptr R = pqz_tx_ring;
  const unsigned NP = 24;
  poly_t a[24], b[24];
  unsigned i, j;

#ifdef PQZ_BACKEND
  arena_mem = malloc ((size_t)64 << 20);
  pqz_arena_init (arena_mem, (size_t)64 << 20);
#else
  lazer_init ();
#endif

  for (i = 0; i < NP; i++)
    {
      poly_alloc (a[i], R);
      poly_alloc (b[i], R);
      fill (a[i], i < 4 ? (int)i + 1 : (i < 8 ? 4 : (i < 12 ? 5 : 0)));
      fill (b[i], i < 4 ? (int)((i + 1) % 4) + 1 : (i % 3 == 0 ? 4 : 0));
    }

  printf ("{\n  \"meta\": {\"backend\": \"%s\", \"lazer_commit\": \"3330e487228f633eceb322807b13a596b516770f\", "
          "\"build\": \"%s\", \"compiler\": \"%s\", \"cpu_avx512f\": %d, \"cpu_avx512ifma\": %d, "
          "\"ring\": \"Z_q[X]/(X^64+1), q = 2^42 - 215\"},\n  \"cases\": {",
          BACKEND, BUILD_FLAGS, __VERSION__, __builtin_cpu_supports ("avx512f") ? 1 : 0,
          __builtin_cpu_supports ("avx512ifma") ? 1 : 0);
  first = 1;

  begin_case ("inputs_a");
  printf ("[");
  for (i = 0; i < NP; i++)
    {
      printf (i ? "," : "");
      print_poly (a[i]);
    }
  printf ("]");
  begin_case ("inputs_b");
  printf ("[");
  for (i = 0; i < NP; i++)
    {
      printf (i ? "," : "");
      print_poly (b[i]);
    }
  printf ("]");

  POLY_T (r, R);
  POLY_T (s, R);
  INT_T (sc, R->q->nlimbs);
  INT_T (l2, 2 * R->q->nlimbs);
  INT_T (li, R->q->nlimbs);

#define PER_PAIR(name, stmt)                                                  \
  begin_case (name);                                                          \
  printf ("[");                                                               \
  for (i = 0; i < NP; i++)                                                    \
    {                                                                         \
      printf (i ? "," : "");                                                  \
      stmt;                                                                   \
      print_poly (r);                                                         \
    }                                                                         \
  printf ("]");

  PER_PAIR ("mul", poly_mul (r, a[i], b[i]));
  PER_PAIR ("add", poly_add (r, a[i], b[i], 0));
  PER_PAIR ("sub", poly_sub (r, a[i], b[i], 0));
  PER_PAIR ("neg", poly_neg (r, a[i]));
  PER_PAIR ("scale", (int_set_i64 (sc, (int64_t)(i * 1234567891ULL % (uint64_t)Q) - H), poly_scale (r, sc, b[i])));
  PER_PAIR ("auto", poly_auto (r, a[i]));
  /* products accumulated in the transform domain, then mapped back */
  PER_PAIR ("mul_add_crt", (poly_mul (r, a[i], b[i]), poly_mul (s, b[i], b[(i + 1) % NP]), poly_add (r, r, s, 1)));
  PER_PAIR ("mul_sub_crt", (poly_mul (r, a[i], b[i]), poly_mul (s, a[i], a[(i + 1) % NP]), poly_sub (r, r, s, 1)));

  begin_case ("l2sqr_linf");
  printf ("[");
  for (i = 0; i < NP; i++)
    {
      poly_l2sqr (l2, a[i]);
      poly_linf (li, a[i]);
      printf ("%s[", i ? "," : "");
      print_int (l2);
      printf (",");
      print_int (li);
      printf ("]");
    }
  printf ("]");

  /* polymat (4 x 8) times polyvec (8), and a dot product, over the first inputs */
  {
    polymat_t A;
    polyvec_t x, y;
    polymat_alloc (A, R, 4, 8);
    polyvec_alloc (x, R, 8);
    polyvec_alloc (y, R, 4);
    for (i = 0; i < 4; i++)
      for (j = 0; j < 8; j++)
        poly_set (polymat_get_elem (A, i, j), a[(8 * i + j) % NP]);
    for (j = 0; j < 8; j++)
      poly_set (polyvec_get_elem (x, j), b[(3 * j + 1) % NP]);
    polyvec_mul (y, A, x);
    polyvec_fromcrt (y);
    begin_case ("matvec");
    printf ("[");
    for (i = 0; i < 4; i++)
      {
        printf (i ? "," : "");
        print_poly (polyvec_get_elem (y, i));
      }
    printf ("]");
    polyvec_t row;
    polymat_get_row (row, A, 1);
    polyvec_dot (r, row, x);
    begin_case ("dot");
    print_poly (r);
    INT_T (vl2, 2 * R->q->nlimbs);
    polyvec_l2sqr (vl2, x);
    begin_case ("vec_l2sqr");
    print_int (vl2);
    polyvec_free (y);
    polyvec_free (x);
    polymat_free (A);
  }

  /* Dilithium-style decompose / power2round with the R_TX tbox parameters */
  {
    POLY_T (r1, R);
    POLY_T (r0, R);
    begin_case ("decompose");
    printf ("[");
    for (i = 0; i < NP; i++)
      {
        poly_dcompress_decompose (r1, r0, a[i], pqz_tx_dcomp);
        printf ("%s[", i ? "," : "");
        print_poly (r1);
        printf (",");
        print_poly (r0);
        printf ("]");
      }
    printf ("]");
    PER_PAIR ("power2round", poly_dcompress_power2round (r, a[i], pqz_tx_dcomp));
  }

  /* the library PRNG and the samplers driven by it */
  {
    uint8_t seed[32], out[1024];
    rng_state_t st;
    for (i = 0; i < 32; i++)
      seed[i] = (uint8_t)(i * 7 + 1);
    rng_init (st, seed, 5);
    rng_urandom (st, out, 1000); /* odd length: exercises the block cache */
    rng_urandom (st, out + 1000, 24);
    rng_clear (st);
    begin_case ("aes256ctr_stream_hex");
    printf ("\"");
    for (i = 0; i < 1024; i++)
      printf ("%02x", out[i]);
    printf ("\"");
    PER_PAIR ("urandom", poly_urandom (r, R->q, 42, seed, i));
    PER_PAIR ("brandom", poly_brandom (r, 2, seed, i));
  }

  printf ("\n  }\n}\n");
#ifdef PQZ_BACKEND
  if (pqz_err != PQZ_OK)
    {
      fprintf (stderr, "pqz_err = %d\n", pqz_err);
      return 1;
    }
#endif
  return 0;
}
