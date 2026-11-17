// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// T0 Q1 harness (ua-rs-sign): PQClean Falcon crypto_sign_keypair with randombytes() fed the 48-byte seed xi given as hex
// on argv[1]. Prints "<pk hex> <sk hex>". Built per variant by q1.sh with -DKEYPAIR=<PQClean symbol> -DPKB=<pk> -DSKB=<sk>.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t seed[48];
static int calls;

// PQClean's randombytes.h maps randombytes to PQCLEAN_randombytes; keygen asks for exactly one 48-byte draw.
int PQCLEAN_randombytes(uint8_t *out, size_t n) {
    if (n != sizeof seed || calls++ != 0) { fprintf(stderr, "unexpected randombytes(%zu) call %d\n", n, calls); exit(2); }
    memcpy(out, seed, n);
    return 0;
}

int KEYPAIR(uint8_t *pk, uint8_t *sk);

int main(int argc, char **argv) {
    static uint8_t pk[PKB], sk[SKB];
    if (argc != 2 || strlen(argv[1]) != 96) { fprintf(stderr, "usage: %s <48-byte seed hex>\n", argv[0]); return 2; }
    for (int i = 0; i < 48; i++) { unsigned v; if (sscanf(argv[1] + 2 * i, "%2x", &v) != 1) return 2; seed[i] = (uint8_t)v; }
    if (KEYPAIR(pk, sk) != 0) return 3;
    for (int i = 0; i < PKB; i++) printf("%02x", pk[i]);
    printf(" ");
    for (int i = 0; i < SKB; i++) printf("%02x", sk[i]);
    printf("\n");
    return 0;
}
