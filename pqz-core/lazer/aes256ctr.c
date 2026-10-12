/*
 * PQZ rewrite of LaZer's AES-256-CTR PRNG (upstream: AES-NI in aes256ctr-amd64.c, a slow bit-serial
 * reference in this file). Bitsliced software AES, bit-exact with the AES-NI stream (same key, same
 * 128-bit big-endian counter starting at the nonce), constant-time: no table lookups, no data-dependent
 * branches. 4 blocks per call: 64 bytes, bit plane p holds bit p of every byte (see gen_aes.py).
 * S-box: inversion x^254 in GF(2^8) (bitsliced multiply, linear squaring) and the FIPS-197 affine map.
 */
#include "aes256ctr.h"
#include "lazer.h"

#include "pqz_aes_gen.h"

#if RNG == RNG_AES256CTR
#if TARGET == TARGET_GENERIC

/* r = a * b in GF(2^8) = GF(2)[x]/(x^8 + x^4 + x^3 + x + 1), bitsliced */
static inline void
gfmul (uint64_t r[8], const uint64_t a[8], const uint64_t b[8])
{
  uint64_t p[15] = { 0 };
  int i, j;

  for (i = 0; i < 8; i++)
    for (j = 0; j < 8; j++)
      p[i + j] ^= a[i] & b[j];
  for (i = 14; i >= 8; i--)
    {
      p[i - 8] ^= p[i];
      p[i - 7] ^= p[i];
      p[i - 5] ^= p[i];
      p[i - 4] ^= p[i];
    }
  for (i = 0; i < 8; i++)
    r[i] = p[i];
}

static void
sbox (uint64_t x[8])
{
  uint64_t c3[8], c7[8], c63[8], c127[8], t[8];

  /* x^254 = x^-1 (0 -> 0), as upstream's generic bytesub chain */
  pqz_aes_gfsq (t, x);
  gfmul (c3, t, x);
  pqz_aes_gfsq (t, c3);
  gfmul (c7, t, x);
  pqz_aes_gfsq (t, c7);
  pqz_aes_gfsq (t, t);
  pqz_aes_gfsq (t, t);
  gfmul (c63, t, c7);
  pqz_aes_gfsq (t, c63);
  gfmul (c127, t, x);
  pqz_aes_gfsq (t, c127);
  /* affine: b_i = t_i ^ t_{i+4} ^ t_{i+5} ^ t_{i+6} ^ t_{i+7} ^ c_i, c = 0x63 */
  for (int i = 0; i < 8; i++)
    {
      uint64_t c = -(uint64_t)((0x63 >> i) & 1);
      x[i] = t[i] ^ t[(i + 4) & 7] ^ t[(i + 5) & 7] ^ t[(i + 6) & 7] ^ t[(i + 7) & 7] ^ c;
    }
}

static inline void
to_planes (uint64_t q[8], const uint8_t in[64])
{
  for (int p = 0; p < 8; p++)
    {
      uint64_t v = 0;
      for (int j = 0; j < 64; j++)
        v |= (uint64_t)((in[j] >> p) & 1) << j;
      q[p] = v;
    }
}

static inline void
from_planes (uint8_t out[64], const uint64_t q[8])
{
  for (int j = 0; j < 64; j++)
    {
      uint8_t b = 0;
      for (int p = 0; p < 8; p++)
        b |= (uint8_t)(((q[p] >> j) & 1) << p);
      out[j] = b;
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
