/*
 * TARGET: GENERIC, AMD64
 * Architecture target.
 */
#define TARGET TARGET_GENERIC /* PQZ: portable, no intrinsics */

/*
 * RNG: SHAKE128, AES256CTR
 * Use Shake128 or AES-256-CTR for pseudorandom generation.
 */
#define RNG RNG_AES256CTR

/*
 * ASSERT: ENABLED, DISABLED
 * Enable or diasble assertions.
 */
#ifndef PQZ_ASSERT
#define PQZ_ASSERT 1
#endif
#if PQZ_ASSERT /* PQZ: invariant checks stay on in release (error returns), pq-zether.md §10 */
#define ASSERT ASSERT_ENABLED
#else
#define ASSERT ASSERT_DISABLED
#endif

/*
 * TIMERS: ENABLED, DISABLED
 * Run timers and print the results.
 */
#define TIMERS TIMERS_DISABLED

/*
 * DEBUGINFO: ENABLED, DISABLED
 * Print out debug information.
 */
#define DEBUGINFO DEBUGINFO_DISABLED

/*
 * VALGRIND: ENABLED, DISABLED
 * Build and run valgrind tests.
 * Requires valgrind installation.
 * Requires ASSERT_DISABLED
 */
#define VALGRIND VALGRIND_DISABLED
