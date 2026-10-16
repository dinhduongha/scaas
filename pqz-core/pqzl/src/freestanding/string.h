/* pqz-core freestanding builds (wasm32): the vendored LaZer files include <string.h>; the four functions
   come from src/pqz_wasm_rt.c. */
#ifndef PQZ_FREESTANDING_STRING_H
#define PQZ_FREESTANDING_STRING_H
#include <stddef.h>
void *memcpy (void *d, const void *s, size_t n);
void *memmove (void *d, const void *s, size_t n);
void *memset (void *d, int c, size_t n);
int memcmp (const void *a, const void *b, size_t n);
#endif
