/*
 * Caller-provided arena replacing LaZer's malloc/realloc/free (memory.c).
 *
 * A stack allocator with lazy frees and exact-size recycling: every block carries a header; freeing the top
 * block pops it and any already-freed blocks below it; freeing an inner block marks it and puts it on the
 * free list of its size, where the next allocation of that size takes it. LaZer is mostly LIFO, but it
 * allocates crtreps (poly.c, polyvec.c) and sparse-matrix elements lazily: a crtrep of a long-lived poly
 * created in the middle of a call would otherwise pin every block freed below it (the upstream tbox test ran
 * a 512 MiB arena out). The temporaries come in a handful of sizes, so the pinned blocks are reused.
 * Exhaustion (review round 2, Q-C; STATUS Open item 2): LaZer never checks an allocation, so a failed
 * pqz_arena_alloc stops the process (__builtin_trap: a trap on every target, wasm32's unreachable) before anything
 * can write; the former shared 1 MiB sink was smaller than single allocations (R_TXM8's Schwartz-Zippel
 * accumulators, a relation's ABDLOP keys, A) and aliased every later block. The specialised verifier's own
 * allocations (pqz_sv.c, which check) use pqz_arena_try_alloc: NULL and PQZ_ERR_ARENA, the call returns the error.
 * pqz_arena_wipe_release (Q-B) zeroes what a secret-holding call used before releasing it.
 */
#include "pqz_rt.h"

#define ALIGN 16
#define HDR 16
#define NONE SIZE_MAX
#define NCLS 32 /* distinct recycled block sizes (the tbox prover uses about 6); others are not recycled */

/* header: [offset of the previous block, NONE if none : 8][size | LISTED | FREED : 8]
   a freed, listed block keeps [next, prev] free-list offsets in its first 16 payload bytes */
#define FREED 1u
#define LISTED 2u
#define H(o) ((uint64_t *)(base + (o)))

static uint8_t *base;
static size_t cap, top, peak, last = NONE; /* last: offset of the top block */
static size_t hw; /* high-water mark since the last wipe (pqz_arena_wipe_release) */
static size_t cls_sz[NCLS], cls_head[NCLS];
static int ncls;

int pqz_err;
const char *pqz_err_file;
int pqz_err_line;
unsigned pqz_rej_tries;

void
pqz_arena_init (void *mem, size_t len)
{
  base = (uint8_t *)mem;
  cap = len;
  top = 0;
  peak = 0;
  hw = 0;
  last = NONE;
  ncls = 0;
}

size_t
pqz_arena_peak (void)
{
  return peak;
}

void
pqz_arena_peak_reset (void) /* diagnostics (P6-SV): measure the peak of the calls that follow */
{
  peak = top;
}

size_t
pqz_arena_used (void)
{
  return top;
}

static int
cls (size_t sz, int add)
{
  for (int c = 0; c < ncls; c++)
    if (cls_sz[c] == sz)
      return c;
  if (!add || ncls == NCLS)
    return -1;
  cls_sz[ncls] = sz;
  cls_head[ncls] = NONE;
  return ncls++;
}

static void
push (int c, size_t o)
{
  H (o)[1] |= LISTED;
  H (o)[2] = cls_head[c];
  H (o)[3] = NONE;
  if (cls_head[c] != NONE)
    H (cls_head[c])[3] = o;
  cls_head[c] = o;
}

static void
unlink_blk (size_t o)
{
  int c = cls (H (o)[1] & ~(uint64_t)(ALIGN - 1), 0);
  size_t next = H (o)[2], prev = H (o)[3];
  if (prev == NONE)
    cls_head[c] = next;
  else
    H (prev)[2] = next;
  if (next != NONE)
    H (next)[3] = prev;
  H (o)[1] &= ~(uint64_t)LISTED;
}

static void
pop (void)
{
  while (last != NONE && (H (last)[1] & FREED))
    {
      if (H (last)[1] & LISTED)
        unlink_blk (last);
      top = last;
      last = H (last)[0];
    }
}

void *
pqz_arena_try_alloc (size_t len)
{
  size_t sz = HDR + ((len + ALIGN - 1) & ~(size_t)(ALIGN - 1));
  if (sz < HDR + 16)
    sz = HDR + 16; /* room for the free-list links */
  if (base == NULL || len > cap)
    goto fail;
  int c = cls (sz, 0);
  if (c >= 0 && cls_head[c] != NONE)
    {
      size_t o = cls_head[c];
      unlink_blk (o);
      H (o)[1] = sz;
      return base + o + HDR;
    }
  if (sz > cap - top)
    goto fail;
  H (top)[0] = last;
  H (top)[1] = sz;
  last = top;
  top += sz;
  if (top > peak)
    peak = top;
  if (top > hw)
    hw = top;
  return base + last + HDR;
fail:
  pqz_err_set (PQZ_ERR_ARENA);
  return NULL;
}

void *
pqz_arena_alloc (size_t len)
{
  void *p = pqz_arena_try_alloc (len);
  if (p == NULL)
    __builtin_trap (); /* fail-stop (Q-C): LaZer would write through the result */
  return p;
}

void
pqz_arena_free (void *p, size_t len)
{
  (void)len; /* not trusted: upstream changes nelems_max after allocating */
  if (p == NULL)
    return;
  uint8_t *h = (uint8_t *)p - HDR;
  if (h < base || h >= base + top || (((uint64_t *)h)[1] & FREED))
    return;
  size_t o = (size_t)(h - base);
  H (o)[1] |= FREED;
  if (o == last)
    pop ();
  else
    {
      int c = cls (H (o)[1] & ~(uint64_t)(ALIGN - 1), 1);
      if (c >= 0)
        push (c, o);
    }
}

/* mark / release: everything allocated after the mark is dropped (long-lived caches sit below it; they must
   not allocate during a call, e.g. their crtreps are created before the mark) */
void
pqz_arena_mark (pqz_arena_mark_t *m)
{
  m->top = top;
  m->last = last;
}

void
pqz_arena_release (const pqz_arena_mark_t *m)
{
  top = m->top;
  last = m->last;
  /* rebuild the size classes and free lists from the blocks that remain (drops the listed blocks above the mark,
     and the classes only they used: the sizes of earlier calls of other relations would otherwise fill the
     NCLS classes, and the sizes of the next call would not be recycled) */
  ncls = 0;
  for (size_t o = last; o != NONE; o = H (o)[0])
    if (H (o)[1] & LISTED)
      {
        int c = cls (H (o)[1] & ~(uint64_t)(ALIGN - 1), 1);
        if (c >= 0)
          push (c, o);
        else
          H (o)[1] &= ~(uint64_t)LISTED; /* stays freed below the mark, not reused */
      }
  pop ();
}

/* Q-B (review round 2; STATUS Open item 8): release to m after zeroing what the call may have left secrets in: every
   byte above the mark up to the high-water mark since the last wipe (blocks there are dropped by the release), and
   the payload of every freed block below it (a block recycled from a free list below the mark may have held a
   secret; a listed block keeps its free-list links in its first 16 bytes). pqz_prove and the key / encryption
   helpers call it; the verifiers keep pqz_arena_release (no secrets). Volatile stores (pqz_zeroize). */
void
pqz_arena_wipe_release (const pqz_arena_mark_t *m)
{
  if (hw > m->top)
    pqz_zeroize (base + m->top, hw - m->top);
  hw = m->top;
  pqz_arena_release (m);
  for (size_t o = last; o != NONE; o = H (o)[0])
    if (H (o)[1] & FREED)
      {
        const size_t skip = H (o)[1] & LISTED ? 16 : 0, sz = H (o)[1] & ~(uint64_t)(ALIGN - 1);
        pqz_zeroize (base + o + HDR + skip, sz - HDR - skip);
      }
}
