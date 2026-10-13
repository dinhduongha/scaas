#include <stddef.h>
#include <sys/resource.h>
void lazer_init (void);
int pqz_err;
unsigned pqz_rej_tries;
const char *pqz_err_file;
int pqz_err_line;
void pqz_arena_init (void *mem, size_t len) { (void)mem; (void)len; lazer_init (); }
size_t pqz_arena_peak (void) { struct rusage u; getrusage (RUSAGE_SELF, &u); return (size_t)u.ru_maxrss << 10; } /* max RSS */
