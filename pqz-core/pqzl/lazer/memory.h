#ifndef MEMORY_H
#define MEMORY_H

#include <stddef.h>

#include "pqz_rt.h"

/* PQZ: LaZer's malloc/realloc/free hooks point at the caller-provided arena (pqz_arena.c). */
#ifdef PQZ_DEBUG_MALLOC /* debugging aid only (ASan builds): libc heap instead of the arena */
#include <stdlib.h>
#define _alloc(n) malloc (n)
#define _try_alloc(n) malloc (n)
#define _free(p, n) free (p)
#else
#define _alloc pqz_arena_alloc         /* traps on exhaustion (review round 2, Q-C) */
#define _try_alloc pqz_arena_try_alloc /* NULL on exhaustion: pqz_sv.c, which checks */
#define _free pqz_arena_free
#endif

#endif
