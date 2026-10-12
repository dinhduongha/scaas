/*
 * Caller-provided arena replacing LaZer's malloc/realloc/free (memory.c).
 *
 * A stack allocator with lazy frees: every block carries a header; freeing the top block pops it and any
 * already-freed blocks below it, freeing an inner block only marks it. LaZer allocates and frees almost
 * strictly LIFO, so the peak stays close to the live set. Exhaustion sets PQZ_ERR_ARENA and hands out a
 * fixed sink block (writes stay in bounds up to PQZ_SINK bytes); the caller sees the error on return.
 */
#include "pqz_rt.h"

#define ALIGN 16
#define HDR 16
#ifndef PQZ_SINK
#define PQZ_SINK (1u << 20)
#endif

static uint8_t *base;
static size_t cap, top, peak, last = SIZE_MAX; /* last: offset of the top block, SIZE_MAX if none */
static _Alignas (16) uint8_t sink[PQZ_SINK];

int pqz_err;

void
pqz_arena_init (void *mem, size_t len)
{
  base = (uint8_t *)mem;
  cap = len;
  top = 0;
  peak = 0;
  last = SIZE_MAX;
}

size_t
pqz_arena_peak (void)
{
  return peak;
}

size_t
pqz_arena_used (void)
{
  return top;
}

/* header: [offset of the previous block, SIZE_MAX if none : 8][freed flag : 8] */
void *
pqz_arena_alloc (size_t len)
{
  size_t sz = HDR + ((len + ALIGN - 1) & ~(size_t)(ALIGN - 1));
  if (base == NULL || sz > cap - top || len > cap)
    {
      pqz_err_set (PQZ_ERR_ARENA);
      return sink;
    }
  uint8_t *h = base + top;
  ((uint64_t *)h)[0] = last;
  ((uint64_t *)h)[1] = 0;
  last = top;
  top += sz;
  if (top > peak)
    peak = top;
  return h + HDR;
}

static void
pop (void)
{
  while (last != SIZE_MAX && ((uint64_t *)(base + last))[1] != 0)
    {
      top = last;
      last = ((uint64_t *)(base + last))[0];
    }
}

void
pqz_arena_free (void *p, size_t len)
{
  (void)len;
  uint8_t *h = (uint8_t *)p - HDR;
  if ((uint8_t *)p == sink || h < base || h >= base + top)
    return;
  ((uint64_t *)h)[1] = 1;
  pop ();
}

void *
pqz_arena_realloc (void *p, size_t olen, size_t nlen)
{
  uint8_t *n = pqz_arena_alloc (nlen);
  if (n != sink)
    memcpy (n, p, olen < nlen ? olen : nlen);
  pqz_arena_free (p, olen);
  return n;
}
