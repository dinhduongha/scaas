/*
 * PQZL verifier floor: the scalar kernels shared by kern.c (native) and wasm.c (wasm32): CRT over 3 NTT-friendly
 * 30-bit primes (complete negacyclic NTT of degree 64, 32-bit Montgomery) and the JL fold. Plain C, 64-bit
 * integer products only (no u128), so it compiles freestanding for wasm32.
 */
#include <stdint.h>
#include <string.h>

#define NP 3
typedef struct
{
  uint32_t p, pinv; /* pinv = -p^-1 mod 2^32 */
  uint32_t F;       /* R / 64 mod p, R = 2^32: the inverse NTT's 1/64 (operands are lifted with tomont) */
  uint32_t R2;      /* R^2 mod p */
  uint32_t zetas[64];
} prime_t;
static prime_t PR[NP];

static uint64_t
powm (uint64_t b, uint64_t e, uint64_t m)
{
  uint64_t r = 1;
  b %= m;
  while (e)
    {
      if (e & 1)
        r = r * b % m;
      b = b * b % m;
      e >>= 1;
    }
  return r;
}
static int
isprime (uint32_t n)
{
  for (uint32_t d = 2; d * d <= n; d++)
    if (n % d == 0)
      return 0;
  return n > 1;
}
static unsigned
brv6 (unsigned x)
{
  unsigned r = 0;
  for (int b = 0; b < 6; b++)
    r |= ((x >> b) & 1) << (5 - b);
  return r;
}

static void
primes_init (void)
{
  uint32_t p = (1u << 30) - 127; /* = 1 mod 128 */
  for (int n = 0; n < NP; p -= 128)
    {
      if (!isprime (p))
        continue;
      prime_t *P = &PR[n++];
      P->p = p;
      uint32_t x = p; /* Newton: x = p^-1 mod 2^32 */
      for (int i = 0; i < 5; i++)
        x *= 2 - p * x;
      P->pinv = -x;
      uint64_t R = ((uint64_t)1 << 32) % p, psi = 0;
      for (uint64_t g = 2;; g++)
        {
          psi = powm (g, (p - 1) / 128, p);
          if (powm (psi, 64, p) == p - 1)
            break;
        }
      for (unsigned k = 0; k < 64; k++)
        P->zetas[k] = (uint32_t)(powm (psi, brv6 (k), p) * R % p);
      P->R2 = (uint32_t)(R * R % p);
      P->F = (uint32_t)(R * powm (64, p - 2, p) % p);
    }
}

static inline uint32_t
mont (uint64_t a, uint64_t b, const prime_t *P) /* a, b < 2p -> a b R^-1 in [0, 2p) */
{
  uint64_t t = a * b;
  uint32_t m = (uint32_t)t * P->pinv;
  return (uint32_t)((t + (uint64_t)m * P->p) >> 32);
}
static inline uint32_t
csub (uint32_t x, uint32_t m) /* x < 2m, m < 2^31 */
{
  uint32_t t = x - m;
  return t + (m & -(t >> 31));
}

static void
ntt_fwd (uint32_t a[64], const prime_t *P)
{
  const uint32_t p2 = 2 * P->p;
  unsigned k = 1;
  for (unsigned len = 32; len >= 1; len >>= 1)
    for (unsigned s = 0; s < 64; s += 2 * len)
      {
        const uint32_t z = P->zetas[k++];
        for (unsigned j = s; j < s + len; j++)
          {
            uint32_t t = mont (z, a[j + len], P), x = a[j];
            a[j + len] = csub (x + p2 - t, p2);
            a[j] = csub (x + t, p2);
          }
      }
}
static void
ntt_inv (uint32_t a[64], const prime_t *P) /* output in [0, p) */
{
  const uint32_t p2 = 2 * P->p;
  unsigned k = 64;
  for (unsigned len = 1; len < 64; len <<= 1)
    for (unsigned s = 0; s < 64; s += 2 * len)
      {
        const uint32_t z = P->p - P->zetas[--k];
        for (unsigned j = s; j < s + len; j++)
          {
            uint32_t x = a[j], y = a[j + len];
            a[j] = csub (x + y, p2);
            a[j + len] = mont (z, x + p2 - y, P);
          }
      }
  for (unsigned j = 0; j < 64; j++)
    a[j] = csub (mont (a[j], P->F, P), P->p);
}
/* acc += a o b (Montgomery, each term < 2p < 2^31; acc < 2^63 for < 2^32 terms) */
static void
pw_acc (uint64_t acc[64], const uint32_t a[64], const uint32_t b[64], const prime_t *P)
{
  for (unsigned j = 0; j < 64; j++)
    acc[j] += mont (a[j], b[j], P);
}
/* Montgomery-domain lift: x -> x R mod p (x < 2p) so that one pw_acc yields the plain product */
static uint32_t
tomont (uint64_t x, const prime_t *P)
{
  return mont (x, P->R2, P);
}

/* vR[k][j] = sum_i V[k][i] R[i][j] mod q, R[i] expanded as LaZer's _brandom (k = 1): row bytes = 2 ncols / 8,
   bit j = +1 part, bit ncols + j = -1 part. lambda = 4 challenge rows, 256 JL rows. */
#define JLR 256
static void
jl_scalar (int64_t *acc /* ncols x 4 */, const uint8_t *R, const int64_t V[4][JLR], unsigned ncols)
{
  const unsigned rb = 2 * ncols / 8;
  memset (acc, 0, sizeof (int64_t) * ncols * 4);
  for (unsigned i = 0; i < JLR; i++)
    {
      const uint8_t *row = R + (size_t)i * rb;
      const int64_t v0 = V[0][i], v1 = V[1][i], v2 = V[2][i], v3 = V[3][i];
      for (unsigned j = 0; j < ncols; j++)
        {
          const int64_t m1 = -(int64_t)((row[j >> 3] >> (j & 7)) & 1);
          const int64_t m2 = -(int64_t)((row[(ncols + j) >> 3] >> ((ncols + j) & 7)) & 1);
          int64_t *a = acc + 4 * j;
          a[0] += (v0 & m1) - (v0 & m2);
          a[1] += (v1 & m1) - (v1 & m2);
          a[2] += (v2 & m1) - (v2 & m2);
          a[3] += (v3 & m1) - (v3 & m2);
        }
    }
}
