#ifndef MEMORY_H
#define MEMORY_H

#include <stddef.h>

#include "pqz_rt.h"

/* PQZ: LaZer's malloc/realloc/free hooks point at the caller-provided arena (pqz_arena.c). */
#define _alloc pqz_arena_alloc
#define _realloc pqz_arena_realloc
#define _free pqz_arena_free

#endif
