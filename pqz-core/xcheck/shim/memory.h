/* xcheck shim: lets the fork's src/pqz_rel.c (R_REG / R_TX statement builder, unchanged) compile against
   UPSTREAM LaZer 3330e48. libc heap instead of the fork's arena; arena calls are no-ops. */
#ifndef MEMORY_H
#define MEMORY_H
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define _alloc(n) malloc (n)
#define _free(p, n) free (p)
#define PQZ_Q 4398046510889ULL
#define PQZ_D 64
#define PQZ_OK 0
#define PQZ_ERR_INTERNAL 1
#define PQZ_ERR_INPUT 3
extern int pqz_err;
typedef struct { size_t top, last; } pqz_arena_mark_t;
void pqz_arena_init (void *mem, size_t len);
size_t pqz_arena_peak (void);
static inline void pqz_arena_mark (pqz_arena_mark_t *m) { (void)m; }
static inline void pqz_arena_release (const pqz_arena_mark_t *m) { (void)m; }
#endif
