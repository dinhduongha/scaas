/*
 * pqz-core freestanding runtime for wasm32 (no libc, no compiler-rt): the string functions the library
 * references and the 128-bit helpers clang emits for unsigned __int128 on a 32-bit target.
 * Build with -ffreestanding -fno-builtin so the loops are not turned back into calls to themselves.
 */
#include <stddef.h>
#include <stdint.h>

void *
memcpy (void *d, const void *s, size_t n)
{
  uint8_t *a = d;
  const uint8_t *b = s;
  while (n--)
    *a++ = *b++;
  return d;
}

void *
memmove (void *d, const void *s, size_t n)
{
  uint8_t *a = d;
  const uint8_t *b = s;
  if (a < b)
    while (n--)
      *a++ = *b++;
  else
    while (n--)
      a[n] = b[n];
  return d;
}

void *
memset (void *d, int c, size_t n)
{
  uint8_t *a = d;
  while (n--)
    *a++ = (uint8_t)c;
  return d;
}

int
memcmp (const void *x, const void *y, size_t n)
{
  const uint8_t *a = x, *b = y;
  for (; n; n--, a++, b++)
    if (*a != *b)
      return *a - *b;
  return 0;
}

typedef unsigned __int128 u128;

static u128
mk (uint64_t hi, uint64_t lo)
{
  return ((u128)hi << 64) | lo; /* constant shifts are lowered inline */
}

/* 128 x 128 -> 128 (low half), from 32-bit partial products */
u128
__multi3 (u128 a, u128 b)
{
  uint64_t al = (uint64_t)a, ah = (uint64_t)(a >> 64), bl = (uint64_t)b, bh = (uint64_t)(b >> 64);
  uint64_t a0 = al & 0xffffffffu, a1 = al >> 32, b0 = bl & 0xffffffffu, b1 = bl >> 32;
  uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
  uint64_t mid = (p00 >> 32) + (p01 & 0xffffffffu) + (p10 & 0xffffffffu);
  uint64_t lo = (mid << 32) | (p00 & 0xffffffffu);
  uint64_t hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32) + al * bh + ah * bl;
  return mk (hi, lo);
}

/* variable shifts (0 <= s < 128) without branches: the fixed-point rejection (rejection.c, pqz_fixexp.h)
   shifts by amounts derived from secret data */
u128
__ashlti3 (u128 a, int s)
{
  uint64_t lo = (uint64_t)a, hi = (uint64_t)(a >> 64);
  unsigned t = (unsigned)s & 63;
  uint64_t big = -(uint64_t)(((unsigned)s >> 6) & 1), nz = -(uint64_t)(t != 0);
  uint64_t lo_s = lo << t, hi_s = (hi << t) | ((lo >> ((64 - t) & 63)) & nz);
  return mk ((hi_s & ~big) | (lo_s & big), lo_s & ~big);
}

u128
__lshrti3 (u128 a, int s)
{
  uint64_t lo = (uint64_t)a, hi = (uint64_t)(a >> 64);
  unsigned t = (unsigned)s & 63;
  uint64_t big = -(uint64_t)(((unsigned)s >> 6) & 1), nz = -(uint64_t)(t != 0);
  uint64_t hi_s = hi >> t, lo_s = (lo >> t) | ((hi << ((64 - t) & 63)) & nz);
  return mk (hi_s & ~big, (lo_s & ~big) | (hi_s & big));
}
