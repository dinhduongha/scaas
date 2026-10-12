/*
 * pqz-core runtime: error returns instead of abort, a caller-provided arena instead of malloc,
 * and the few libc pieces the vendored LaZer code needs (string.h, endian) on a freestanding target.
 */
#ifndef PQZ_RT_H
#define PQZ_RT_H

#include <stddef.h>
#include <stdint.h>

/* ---- errors: LaZer's ERR()/ASSERT_ERR() set a sticky flag; every public entry point returns it. ---- */
#define PQZ_OK 0
#define PQZ_ERR_INTERNAL 1 /* an upstream ERR/ASSERT condition fired */
#define PQZ_ERR_ARENA 2    /* arena exhausted */
#define PQZ_ERR_INPUT 3    /* malformed input (decoder) */
#define PQZ_ERR_REJECT 4   /* rejection-sampling loop hit its cap */

extern int pqz_err;
static inline void
pqz_err_set (int e)
{
  if (pqz_err == PQZ_OK)
    pqz_err = e;
}

/* ---- arena ---- */
void pqz_arena_init (void *mem, size_t len);
void *pqz_arena_alloc (size_t len);
void *pqz_arena_realloc (void *p, size_t olen, size_t nlen);
void pqz_arena_free (void *p, size_t len);
size_t pqz_arena_peak (void);
size_t pqz_arena_used (void);

/* ---- freestanding libc subset ---- */
#ifdef PQZ_FREESTANDING
void *memcpy (void *d, const void *s, size_t n);
void *memmove (void *d, const void *s, size_t n);
void *memset (void *d, int c, size_t n);
int memcmp (const void *a, const void *b, size_t n);
#define htole64(x) ((uint64_t)(x))
#define le64toh(x) ((uint64_t)(x))
#define htole32(x) ((uint32_t)(x))
#define le32toh(x) ((uint32_t)(x))
#define htobe64(x) __builtin_bswap64 (x)
#define be64toh(x) __builtin_bswap64 (x)
#define htobe32(x) __builtin_bswap32 (x)
#define be32toh(x) __builtin_bswap32 (x)
#else
#include <endian.h>
#include <string.h>
#endif
#define explicit_bzero(p, n) pqz_zeroize ((p), (n))
static inline void
pqz_zeroize (void *p, size_t n)
{
  volatile uint8_t *v = (volatile uint8_t *)p;
  while (n--)
    *v++ = 0;
}

/* qsort replacement (insertion sort; sorts sparse-matrix index lists, public data) */
static inline void
pqz_qsort (void *base, size_t n, size_t sz, int (*cmp) (const void *, const void *))
{
  uint8_t *b = (uint8_t *)base, tmp[64];
  for (size_t i = 1; i < n; i++)
    for (size_t j = i; j > 0 && cmp (b + (j - 1) * sz, b + j * sz) > 0; j--)
      {
        memcpy (tmp, b + j * sz, sz);
        memcpy (b + j * sz, b + (j - 1) * sz, sz);
        memcpy (b + (j - 1) * sz, tmp, sz);
      }
}

#endif
