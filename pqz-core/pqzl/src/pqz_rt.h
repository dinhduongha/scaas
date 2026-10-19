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

extern unsigned pqz_rej_tries; /* rejection-loop iterations (z3/z4 and z1/z2 loops), diagnostics */
/* per rejection loop (z3/z4, z1/z2). Since Rej1 for z2 (P6-D2) the z1/z2 loop takes 2 M1 M2 tries on average, 12.3
   (R_REG) to 24.0 (R_TXM M=4), measured pqz_rej_tries ~14 (R_REG) / ~19 (R_TX) with both loops (relfix fs4); 1000 fail
   with prob <= (1 - 1/24.0)^1000 ~ e^-42.5 ~ 2^-61 (R_TXM M=4), e^-84 (R_REG) */
#define PQZ_REJ_MAX 1000

/* constant-time check (test/ct.sh, ctgrind): the prover's secret-derived data that is public by design (a rejection
   verdict, the witness-valid verdict, a proof component or transcript message) is marked defined for valgrind's
   memcheck where it becomes public; a no-op in every other build */
#ifdef PQZ_CTGRIND
#include <valgrind/memcheck.h>
#define PQZ_CT_PUBLIC(p, n) ((void)VALGRIND_MAKE_MEM_DEFINED ((p), (n)))
#else
#define PQZ_CT_PUBLIC(p, n) ((void)0)
#endif

/* value barrier for masks on secret data: the optimiser no longer knows a mask is 0 or all ones, so it cannot turn a
   masked select back into a branch or a cmov of pointers plus a load (clang 18 did that to limbs_cnd_select: a
   secret-dependent address; review E). Empty asm: no instruction on x86-64, aarch64 or wasm32. */
static inline uint64_t
pqz_ct_barrier (uint64_t x)
{
  __asm__ ("" : "+r" (x));
  return x;
}

extern int pqz_err;
extern const char *pqz_err_file; /* where the first error of the call was raised (diagnostics) */
extern int pqz_err_line;
#define pqz_err_set(e) pqz_err_set_at ((e), __FILE__, __LINE__)
static inline void
pqz_err_set_at (int e, const char *file, int line)
{
  if (pqz_err == PQZ_OK)
    {
      pqz_err = e;
      pqz_err_file = file;
      pqz_err_line = line;
    }
}

/* ---- arena ---- */
void pqz_arena_init (void *mem, size_t len);
void *pqz_arena_alloc (size_t len);
void *pqz_arena_realloc (void *p, size_t olen, size_t nlen);
void pqz_arena_free (void *p, size_t len);
size_t pqz_arena_peak (void);
size_t pqz_arena_used (void);
void pqz_arena_peak_reset (void);
typedef struct
{
  size_t top, last;
} pqz_arena_mark_t;
void pqz_arena_mark (pqz_arena_mark_t *m);
void pqz_arena_release (const pqz_arena_mark_t *m);

/* ---- freestanding libc subset ---- */
#ifdef PQZ_FREESTANDING
void *memcpy (void *d, const void *s, size_t n);
void *memmove (void *d, const void *s, size_t n);
void *memset (void *d, int c, size_t n);
int memcmp (const void *a, const void *b, size_t n);
#define htole16(x) ((uint16_t)(x))
#define le16toh(x) ((uint16_t)(x))
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

/* qsort replacement: heapsort, O(n log n), in place (sorts sparse-matrix index lists, public data; keys are
   unique, so the result is the same as any other sort's). P6d-2: was insertion sort, O(n^2) on LaZer's
   ~10^4-element Schwartz-Zippel matrices */
static inline void
pqz_qsort_swap (uint8_t *x, uint8_t *y, size_t sz)
{
  for (size_t i = 0; i < sz; i++)
    {
      uint8_t t = x[i];
      x[i] = y[i];
      y[i] = t;
    }
}

static inline void
pqz_qsort_sift (uint8_t *b, size_t root, size_t n, size_t sz, int (*cmp) (const void *, const void *))
{
  for (size_t c; (c = 2 * root + 1) < n; root = c)
    {
      if (c + 1 < n && cmp (b + c * sz, b + (c + 1) * sz) < 0)
        c++;
      if (cmp (b + root * sz, b + c * sz) >= 0)
        return;
      pqz_qsort_swap (b + root * sz, b + c * sz, sz);
    }
}

static inline void
pqz_qsort (void *base, size_t n, size_t sz, int (*cmp) (const void *, const void *))
{
  uint8_t *b = (uint8_t *)base;
  for (size_t i = n / 2; i-- > 0;)
    pqz_qsort_sift (b, i, n, sz, cmp);
  for (size_t i = n; i-- > 1;)
    {
      pqz_qsort_swap (b, b + i * sz, sz);
      pqz_qsort_sift (b, 0, i, sz, cmp);
    }
}

#endif
