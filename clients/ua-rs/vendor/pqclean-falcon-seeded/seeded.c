/*
 * SPDX-License-Identifier: MIT
 * PQClean's `pqclean.c` of falcon-padded-512 / -1024 (clean), MIT, Copyright (c) 2017-2019 Falcon Project (LICENSE), with
 * the randomness passed in instead of drawn through `randombytes` (ua-rs-sign T3b, MD-8). Built once per degree with
 * FNDSA_LOGN = 9 or 10 and that degree's directory on the include path (build.rs). The key pair of a 48-byte seed is
 * PQClean's `crypto_sign_keypair` when `randombytes` returns that seed, the generator noble 0.7.1 uses as well (T0 Q1:
 * 102 comparisons, equal). A signature takes 88 bytes: the 40-byte nonce, then the 48-byte seed of the sampler's SHAKE256
 * stream, in the order `do_sign` draws them. The caller (src/falcon.rs) checks every length; the local secrets of this
 * file are wiped before return (PQClean's own functions wipe none: a stated residual). UNAUDITED.
 */
#include <stddef.h>
#include <string.h>

#include "api.h"
#include "inner.h"

#if FNDSA_LOGN == 9
#define NS(x) SCAAS_UA_FNDSA512_##x
#define EX(x) scaas_ua_fndsa512_##x
#define KEYGEN_TEMP FALCON_KEYGEN_TEMP_9
#elif FNDSA_LOGN == 10
#define NS(x) SCAAS_UA_FNDSA1024_##x
#define EX(x) scaas_ua_fndsa1024_##x
#define KEYGEN_TEMP FALCON_KEYGEN_TEMP_10
#else
#error "FNDSA_LOGN must be 9 or 10"
#endif

#define LOGN FNDSA_LOGN
#define N (1 << LOGN)
#define NONCELEN 40
#define SEEDLEN 48

static void wipe(void *p, size_t n) {
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) {
        *v++ = 0;
    }
}

int EX(keypair)(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    union {
        uint8_t b[KEYGEN_TEMP];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    int8_t f[N], g[N], F[N];
    uint16_t h[N];
    inner_shake256_context rng;
    size_t u, v;
    int ret = -1;

    inner_shake256_init(&rng);
    inner_shake256_inject(&rng, seed, SEEDLEN);
    inner_shake256_flip(&rng);
    NS(keygen)(&rng, f, g, F, NULL, h, LOGN, tmp.b);
    inner_shake256_ctx_release(&rng);

    sk[0] = 0x50 + LOGN;
    u = 1;
    v = NS(trim_i8_encode)(sk + u, NS(CRYPTO_SECRETKEYBYTES) - u, f, LOGN, NS(max_fg_bits)[LOGN]);
    if (v == 0) {
        goto out;
    }
    u += v;
    v = NS(trim_i8_encode)(sk + u, NS(CRYPTO_SECRETKEYBYTES) - u, g, LOGN, NS(max_fg_bits)[LOGN]);
    if (v == 0) {
        goto out;
    }
    u += v;
    v = NS(trim_i8_encode)(sk + u, NS(CRYPTO_SECRETKEYBYTES) - u, F, LOGN, NS(max_FG_bits)[LOGN]);
    if (v == 0) {
        goto out;
    }
    u += v;
    if (u != NS(CRYPTO_SECRETKEYBYTES)) {
        goto out;
    }

    pk[0] = 0x00 + LOGN;
    v = NS(modq_encode)(pk + 1, NS(CRYPTO_PUBLICKEYBYTES) - 1, h, LOGN);
    if (v != NS(CRYPTO_PUBLICKEYBYTES) - 1) {
        goto out;
    }
    ret = 0;
out:
    wipe(&tmp, sizeof tmp);
    wipe(f, sizeof f);
    wipe(g, sizeof g);
    wipe(F, sizeof F);
    return ret;
}

/* PQClean's do_sign with `rnd` = nonce (40 B) || sampler seed (48 B). */
static int do_sign(uint8_t *nonce, uint8_t *sigbuf, size_t sigbuflen, const uint8_t *m, size_t mlen, const uint8_t *sk,
                   const uint8_t *rnd) {
    union {
        uint8_t b[72 * N];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    int8_t f[N], g[N], F[N], G[N];
    struct {
        int16_t sig[N];
        uint16_t hm[N];
    } r;
    inner_shake256_context sc;
    size_t u, v;
    int ret = -1;

    if (sk[0] != 0x50 + LOGN) {
        return -1;
    }
    u = 1;
    v = NS(trim_i8_decode)(f, LOGN, NS(max_fg_bits)[LOGN], sk + u, NS(CRYPTO_SECRETKEYBYTES) - u);
    if (v == 0) {
        goto out;
    }
    u += v;
    v = NS(trim_i8_decode)(g, LOGN, NS(max_fg_bits)[LOGN], sk + u, NS(CRYPTO_SECRETKEYBYTES) - u);
    if (v == 0) {
        goto out;
    }
    u += v;
    v = NS(trim_i8_decode)(F, LOGN, NS(max_FG_bits)[LOGN], sk + u, NS(CRYPTO_SECRETKEYBYTES) - u);
    if (v == 0) {
        goto out;
    }
    u += v;
    if (u != NS(CRYPTO_SECRETKEYBYTES)) {
        goto out;
    }
    if (!NS(complete_private)(G, f, g, F, LOGN, tmp.b)) {
        goto out;
    }

    memcpy(nonce, rnd, NONCELEN);

    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, nonce, NONCELEN);
    inner_shake256_inject(&sc, m, mlen);
    inner_shake256_flip(&sc);
    NS(hash_to_point_ct)(&sc, r.hm, LOGN, tmp.b);
    inner_shake256_ctx_release(&sc);

    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, rnd + NONCELEN, SEEDLEN);
    inner_shake256_flip(&sc);

    for (;;) {
        NS(sign_dyn)(r.sig, &sc, f, g, F, G, r.hm, LOGN, tmp.b);
        v = NS(comp_encode)(sigbuf, sigbuflen, r.sig, LOGN);
        if (v != 0) {
            inner_shake256_ctx_release(&sc);
            memset(sigbuf + v, 0, sigbuflen - v);
            ret = 0;
            break;
        }
    }
out:
    wipe(&tmp, sizeof tmp);
    wipe(f, sizeof f);
    wipe(g, sizeof g);
    wipe(F, sizeof F);
    wipe(G, sizeof G);
    wipe(&r, sizeof r);
    return ret;
}

/* `sig` holds CRYPTO_BYTES (666 / 1,280): the padded signature. */
int EX(sign)(uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd) {
    size_t vlen = NS(CRYPTO_BYTES) - NONCELEN - 1;
    if (do_sign(sig + 1, sig + 1 + NONCELEN, vlen, m, mlen, sk, rnd) < 0) {
        return -1;
    }
    sig[0] = 0x30 + LOGN;
    return 0;
}

/* PQClean's crypto_sign_verify and do_verify, unchanged. */
static int do_verify(const uint8_t *nonce, const uint8_t *sigbuf, size_t sigbuflen, const uint8_t *m, size_t mlen,
                     const uint8_t *pk) {
    union {
        uint8_t b[2 * N];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    uint16_t h[N], hm[N];
    int16_t sig[N];
    inner_shake256_context sc;
    size_t v;

    if (pk[0] != 0x00 + LOGN) {
        return -1;
    }
    if (NS(modq_decode)(h, LOGN, pk + 1, NS(CRYPTO_PUBLICKEYBYTES) - 1) != NS(CRYPTO_PUBLICKEYBYTES) - 1) {
        return -1;
    }
    NS(to_ntt_monty)(h, LOGN);

    if (sigbuflen == 0) {
        return -1;
    }
    v = NS(comp_decode)(sig, LOGN, sigbuf, sigbuflen);
    if (v == 0) {
        return -1;
    }
    if (v != sigbuflen) {
        if (sigbuflen == NS(CRYPTO_BYTES) - NONCELEN - 1) {
            while (v < sigbuflen) {
                if (sigbuf[v++] != 0) {
                    return -1;
                }
            }
        } else {
            return -1;
        }
    }

    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, nonce, NONCELEN);
    inner_shake256_inject(&sc, m, mlen);
    inner_shake256_flip(&sc);
    NS(hash_to_point_ct)(&sc, hm, LOGN, tmp.b);
    inner_shake256_ctx_release(&sc);

    if (!NS(verify_raw)(hm, sig, h, LOGN, tmp.b)) {
        return -1;
    }
    return 0;
}

int EX(verify)(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    if (siglen < 1 + NONCELEN) {
        return -1;
    }
    if (sig[0] != 0x30 + LOGN) {
        return -1;
    }
    return do_verify(sig + 1, sig + 1 + NONCELEN, siglen - 1 - NONCELEN, m, mlen, pk);
}
