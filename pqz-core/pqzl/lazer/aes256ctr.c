/*
 * PQZ rewrite of LaZer's AES-256-CTR PRNG (upstream: AES-NI in aes256ctr-amd64.c, a slow bit-serial
 * reference in this file). Bitsliced software AES, bit-exact with the AES-NI stream (same key, same
 * 128-bit big-endian counter starting at the nonce), constant-time: no table lookups, no data-dependent
 * branches. 4 blocks per call: 64 bytes, bit plane p holds bit p of every byte (see gen_aes.py).
 * S-box: the Boyar-Peralta circuit (P6d-2; E-S1 computed the inversion x^254 by bitsliced multiplications).
 */
#include "aes256ctr.h"
#include "lazer.h"

#include "pqz_aes_gen.h"

#if RNG == RNG_AES256CTR
#if TARGET == TARGET_GENERIC

/* P6d-2: S-box as the Boyar-Peralta circuit (113 gates: 32 AND, 81 XOR/XNOR; the same circuit as BearSSL's
   constant-time AES), was the inversion chain x^254 (4 bitsliced GF(2^8) multiplications, ~4x the gates).
   Plane i = bit i (x7 = plane 0, the LSB, in the circuit's naming). */
static void
sbox (uint64_t q[8])
{
  uint64_t x0 = q[7], x1 = q[6], x2 = q[5], x3 = q[4], x4 = q[3], x5 = q[2], x6 = q[1], x7 = q[0];
  uint64_t y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14, y15, y16, y17, y18, y19, y20, y21;
  uint64_t z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15, z16, z17;
  uint64_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16, t17, t18, t19, t20;
  uint64_t t21, t22, t23, t24, t25, t26, t27, t28, t29, t30, t31, t32, t33, t34, t35, t36, t37, t38, t39;
  uint64_t t40, t41, t42, t43, t44, t45, t46, t47, t48, t49, t50, t51, t52, t53, t54, t55, t56, t57, t58;
  uint64_t t59, t60, t61, t62, t63, t64, t65, t66, t67;
  uint64_t s0, s1, s2, s3, s4, s5, s6, s7;

  /* top linear transformation */
  y14 = x3 ^ x5;
  y13 = x0 ^ x6;
  y9 = x0 ^ x3;
  y8 = x0 ^ x5;
  t0 = x1 ^ x2;
  y1 = t0 ^ x7;
  y4 = y1 ^ x3;
  y12 = y13 ^ y14;
  y2 = y1 ^ x0;
  y5 = y1 ^ x6;
  y3 = y5 ^ y8;
  t1 = x4 ^ y12;
  y15 = t1 ^ x5;
  y20 = t1 ^ x1;
  y6 = y15 ^ x7;
  y10 = y15 ^ t0;
  y11 = y20 ^ y9;
  y7 = x7 ^ y11;
  y17 = y10 ^ y11;
  y19 = y10 ^ y8;
  y16 = t0 ^ y11;
  y21 = y13 ^ y16;
  y18 = x0 ^ y16;

  /* non-linear section */
  t2 = y12 & y15;
  t3 = y3 & y6;
  t4 = t3 ^ t2;
  t5 = y4 & x7;
  t6 = t5 ^ t2;
  t7 = y13 & y16;
  t8 = y5 & y1;
  t9 = t8 ^ t7;
  t10 = y2 & y7;
  t11 = t10 ^ t7;
  t12 = y9 & y11;
  t13 = y14 & y17;
  t14 = t13 ^ t12;
  t15 = y8 & y10;
  t16 = t15 ^ t12;
  t17 = t4 ^ t14;
  t18 = t6 ^ t16;
  t19 = t9 ^ t14;
  t20 = t11 ^ t16;
  t21 = t17 ^ y20;
  t22 = t18 ^ y19;
  t23 = t19 ^ y21;
  t24 = t20 ^ y18;

  t25 = t21 ^ t22;
  t26 = t21 & t23;
  t27 = t24 ^ t26;
  t28 = t25 & t27;
  t29 = t28 ^ t22;
  t30 = t23 ^ t24;
  t31 = t22 ^ t26;
  t32 = t31 & t30;
  t33 = t32 ^ t24;
  t34 = t23 ^ t33;
  t35 = t27 ^ t33;
  t36 = t24 & t35;
  t37 = t36 ^ t34;
  t38 = t27 ^ t36;
  t39 = t29 & t38;
  t40 = t25 ^ t39;

  t41 = t40 ^ t37;
  t42 = t29 ^ t33;
  t43 = t29 ^ t40;
  t44 = t33 ^ t37;
  t45 = t42 ^ t41;
  z0 = t44 & y15;
  z1 = t37 & y6;
  z2 = t33 & x7;
  z3 = t43 & y16;
  z4 = t40 & y1;
  z5 = t29 & y7;
  z6 = t42 & y11;
  z7 = t45 & y17;
  z8 = t41 & y10;
  z9 = t44 & y12;
  z10 = t37 & y3;
  z11 = t33 & y4;
  z12 = t43 & y13;
  z13 = t40 & y5;
  z14 = t29 & y2;
  z15 = t42 & y9;
  z16 = t45 & y14;
  z17 = t41 & y8;

  /* bottom linear transformation (with the affine constant 0x63: the complemented outputs) */
  t46 = z15 ^ z16;
  t47 = z10 ^ z11;
  t48 = z5 ^ z13;
  t49 = z9 ^ z10;
  t50 = z2 ^ z12;
  t51 = z2 ^ z5;
  t52 = z7 ^ z8;
  t53 = z0 ^ z3;
  t54 = z6 ^ z7;
  t55 = z16 ^ z17;
  t56 = z12 ^ t48;
  t57 = t50 ^ t53;
  t58 = z4 ^ t46;
  t59 = z3 ^ t54;
  t60 = t46 ^ t57;
  t61 = z14 ^ t57;
  t62 = t52 ^ t58;
  t63 = t49 ^ t58;
  t64 = z4 ^ t59;
  t65 = t61 ^ t62;
  t66 = z1 ^ t63;
  s0 = t59 ^ t63;
  s6 = t56 ^ ~t62;
  s7 = t48 ^ ~t60;
  t67 = t64 ^ t65;
  s3 = t53 ^ t66;
  s4 = t51 ^ t66;
  s5 = t47 ^ t65;
  s1 = t64 ^ ~s3;
  s2 = t55 ^ ~t67;

  q[7] = s0;
  q[6] = s1;
  q[5] = s2;
  q[4] = s3;
  q[3] = s4;
  q[2] = s5;
  q[1] = s6;
  q[0] = s7;
}

/* 8 x 8 bit transpose of x (bit 8 r + c -> bit 8 c + r), three delta swaps */
static inline uint64_t
transpose8 (uint64_t x)
{
  uint64_t t;
  t = (x ^ (x >> 7)) & 0x00AA00AA00AA00AAULL;
  x ^= t ^ (t << 7);
  t = (x ^ (x >> 14)) & 0x0000CCCC0000CCCCULL;
  x ^= t ^ (t << 14);
  t = (x ^ (x >> 28)) & 0x00000000F0F0F0F0ULL;
  x ^= t ^ (t << 28);
  return x;
}

/* P6d-2: bytes <-> bit planes by 8 x 8 transposes (was a bit-by-bit loop, 512 steps each way) */
static inline void
to_planes (uint64_t q[8], const uint8_t in[64])
{
  int w, p, k;

  for (p = 0; p < 8; p++)
    q[p] = 0;
  for (w = 0; w < 8; w++)
    {
      uint64_t x = 0;
      for (k = 0; k < 8; k++)
        x |= (uint64_t)in[8 * w + k] << (8 * k);
      x = transpose8 (x); /* byte p = bit p of the 8 bytes */
      for (p = 0; p < 8; p++)
        q[p] |= ((x >> (8 * p)) & 0xff) << (8 * w);
    }
}

static inline void
from_planes (uint8_t out[64], const uint64_t q[8])
{
  int w, p, k;

  for (w = 0; w < 8; w++)
    {
      uint64_t x = 0;
      for (p = 0; p < 8; p++)
        x |= ((q[p] >> (8 * w)) & 0xff) << (8 * p);
      x = transpose8 (x);
      for (k = 0; k < 8; k++)
        out[8 * w + k] = (uint8_t)(x >> (8 * k));
    }
}

static inline void
mixcolumns (uint64_t q[8])
{
  uint64_t r1[8], t[8];
  int p;

  for (p = 0; p < 8; p++)
    {
      r1[p] = pqz_aes_rotrow1 (q[p]);
      t[p] = q[p] ^ r1[p];
    }
  /* out = xtime(a_r ^ a_{r+1}) ^ a_{r+1} ^ a_{r+2} ^ a_{r+3} */
  uint64_t hi = t[7];
  uint64_t xt[8] = { hi, t[0] ^ hi, t[1], t[2] ^ hi, t[3] ^ hi, t[4], t[5], t[6] };
  for (p = 0; p < 8; p++)
    q[p] = xt[p] ^ r1[p] ^ pqz_aes_rotrow2 (q[p]) ^ pqz_aes_rotrow3 (q[p]);
}

static void
aes256_4blocks (const aes256ctr_state_t state, uint8_t out[64], const uint8_t in[64])
{
  uint64_t q[8];
  int r, p;

  to_planes (q, in);
  for (p = 0; p < 8; p++)
    q[p] ^= state->rk[0][p];
  for (r = 1; r < 15; r++)
    {
      sbox (q);
      for (p = 0; p < 8; p++)
        q[p] = pqz_aes_shiftrows (q[p]);
      if (r < 14)
        mixcolumns (q);
      for (p = 0; p < 8; p++)
        q[p] ^= state->rk[r][p];
    }
  from_planes (out, q);
}

/* SubWord on 4 bytes through the bitsliced S-box (lanes 4..63 unused) */
static void
subword (uint8_t w[4])
{
  uint8_t buf[64] = { 0 };
  uint64_t q[8];
  int i;

  for (i = 0; i < 4; i++)
    buf[i] = w[i];
  to_planes (q, buf);
  sbox (q);
  from_planes (buf, q);
  for (i = 0; i < 4; i++)
    w[i] = buf[i];
}

static void
_aes256ctr_init (aes256ctr_state_t state, const uint8_t key[32], const uint8_t nonce[16])
{
  uint8_t w[240], t[4], rcon = 1, blk[64];
  int i, j;

  state->cache_ptr = NULL;
  state->nbytes = 0;
  memcpy (state->nonce, nonce, 16);

  memcpy (w, key, 32);
  for (i = 8; i < 60; i++)
    {
      for (j = 0; j < 4; j++)
        t[j] = w[4 * (i - 1) + j];
      if (i % 8 == 0)
        {
          uint8_t t0 = t[0];
          t[0] = t[1], t[1] = t[2], t[2] = t[3], t[3] = t0;
          subword (t);
          t[0] ^= rcon;
          rcon = (uint8_t)((rcon << 1) ^ (0x1b & -(rcon >> 7)));
        }
      else if (i % 8 == 4)
        subword (t);
      for (j = 0; j < 4; j++)
        w[4 * i + j] = w[4 * (i - 8) + j] ^ t[j];
    }
  for (i = 0; i < 15; i++)
    {
      for (j = 0; j < 4; j++)
        memcpy (blk + 16 * j, w + 16 * i, 16);
      to_planes (state->rk[i], blk);
    }
  pqz_zeroize (w, sizeof (w));
  pqz_zeroize (blk, sizeof (blk));
}

static inline void
incbe (uint8_t n[16])
{
  unsigned int c = 1;
  for (int i = 15; i >= 0; i--)
    {
      c += n[i];
      n[i] = c & 0xff;
      c >>= 8;
    }
}

static void
next64 (aes256ctr_state_t state, uint8_t out[64])
{
  uint8_t ctr[64];
  for (int j = 0; j < 4; j++)
    {
      memcpy (ctr + 16 * j, state->nonce, 16);
      incbe (state->nonce);
    }
  aes256_4blocks (state, out, ctr);
}

static void
_aes256ctr_stream (aes256ctr_state_t state, uint8_t *out, size_t outlen)
{
  size_t len = MIN (outlen, state->nbytes);

  if (len > 0)
    memcpy (out, state->cache_ptr, len);
  state->cache_ptr += len;
  state->nbytes -= len;
  out += len;
  outlen -= len;

  while (outlen >= 64)
    {
      next64 (state, out);
      out += 64;
      outlen -= 64;
    }
  if (outlen > 0)
    {
      next64 (state, state->cache);
      memcpy (out, state->cache, outlen);
      state->cache_ptr = state->cache + outlen;
      state->nbytes = 64 - outlen;
    }
}

#endif

static void
_aes256ctr_clear (aes256ctr_state_t state)
{
  explicit_bzero (state, sizeof (aes256ctr_state_struct));
}

#endif
