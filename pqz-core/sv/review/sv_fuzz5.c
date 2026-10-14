/*
 * Review libFuzzer target (docs/reviews/specs/2026-10-13-pqz-sv-review.md, checklist 6): the specialised verifier
 * alone, all five relations, ASan + UBSan; the generic verifier runs only when the fast one accepts, and must accept
 * too (the soundness direction). Faster than test/pqz_sv_fuzz.c (which runs both verifiers on every input and covers
 * R_REG / R_TX only), so it reaches more inputs per minute. Built and run by sv/review/review.sh fuzz SECS.
 *
 * Input: byte 0 % 5 = relation; byte 1 % 4 = mode: 0 proof byte XORs, 1 one decoded field changed and re-encoded
 * (pqz_test_mutate kind byte 2 % 14, r1 / r2 from bytes 3..18) then XORs, 2 statement XORs, 3 truncate / extend;
 * the rest: 4-byte edits [offset lo, mid, hi, value].
 */
#define main pqz_sv_diff_main
#include "../../test/pqz_sv_diff.c"
#undef main

static uint8_t hp[NREL][PQZ_MAX_PROOF], fb[PQZ_MAX_PROOF + 64], fs[PQZ_TX_STMT_BYTES];
static size_t hl[NREL];
static uint8_t hs[NREL][PQZ_TX_STMT_BYTES];

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void)argc, (void)argv;
  xs = 0x243F6A8885A308D3ULL;
  if (pqz_init (malloc (ARENA_BYTES), ARENA_BYTES) != 0)
    abort ();
  for (int rel = 0; rel < NREL; rel++)
    {
      uint8_t r32[32] = { (uint8_t)rel };
      if (rel == 0)
        make_reg ();
      else if (rel == 1)
        make_tx ();
      else if (rel == 2)
        make_burn ();
      else if (rel == 3)
        make_disc (); /* makes both disclosure statements */
      hl[rel] = PQZ_MAX_PROOF;
      if (pqz_prove (OPS[rel], STMT[rel], STLEN[rel], WIT[rel], WLEN[rel], r32, hp[rel], &hl[rel]) != 0)
        abort ();
      memcpy (hs[rel], STMT[rel], STLEN[rel]);
      if (pqz_verify_fast (OPS[rel], hs[rel], STLEN[rel], hp[rel], hl[rel]) != 1
          || pqz_verify (OPS[rel], hs[rel], STLEN[rel], hp[rel], hl[rel]) != 1)
        abort ();
    }
  return 0;
}

static uint64_t
le64 (const uint8_t *p, size_t n)
{
  uint64_t v = 0;
  for (size_t i = 0; i < n && i < 8; i++)
    v |= (uint64_t)p[i] << (8 * i);
  return v;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 3)
    return 0;
  const int rel = data[0] % NREL, mode = data[1] % 4;
  const uint8_t op = OPS[rel];
  const size_t stlen = STLEN[rel];
  size_t len = hl[rel], i = 2;
  memcpy (fb, hp[rel], len);
  memcpy (fs, hs[rel], stlen);
  if (mode == 1)
    {
      size_t n = sizeof fb;
      const uint64_t r1 = size > 3 ? le64 (data + 3, size - 3) : 0, r2 = size > 11 ? le64 (data + 11, size - 11) : 0;
      if (!pqz_test_mutate (MOP[rel], hp[rel], hl[rel], data[2] % 14, r1, r2, fb, &n))
        return 0;
      len = n;
      i = size < 19 ? size : 19;
    }
  if (mode == 3)
    {
      const size_t n = data[2];
      if (data[2] & 1)
        len = n < len ? len - n : 0;
      else
        memset (fb + len, data[2] & 2 ? 0xff : 0, n % 64), len += n % 64;
      i = 3;
    }
  for (; i + 4 <= size; i += 4)
    {
      const size_t off = data[i] | (data[i + 1] << 8) | ((size_t)data[i + 2] << 16);
      if (mode == 2)
        fs[off % stlen] ^= data[i + 3];
      else if (len > 0)
        fb[off % len] ^= data[i + 3];
    }
  if (pqz_verify_fast (op, fs, stlen, fb, len) == 1 && pqz_verify (op, fs, stlen, fb, len) != 1)
    abort (); /* the specialised verifier accepted what the reference rejects */
  return 0;
}
