// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// C99 smoke test of include/scaas_ua.h against the staticlib. The full vector suite is tests/test_vectors.py.
// ABI v6 (ua-rs-sign T12): one sign.json row per kind group through key handles, and a child handle after its wallet is freed
// (KEY_REVOKED; run under AddressSanitizer, tests/asan-smoke.sh: no use after free). T14: a Zether key's PoP and balance-cache box, and
// its handle after the wallet is freed. T15: a PQZ key's set, an R_REG proof, a key field refused, the cache box, the leaf export, and
// its handle after the wallet is freed.
#include <stdio.h>
#include <string.h>

#include "scaas_ua.h"

static int failures = 0;
#define CHECK(c)                                                       \
    do {                                                               \
        if (!(c)) {                                                    \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c);    \
            ++failures;                                                \
        }                                                              \
    } while (0)

static void hex(const char *h, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; ++i) sscanf(h + 2 + 2 * i, "%2hhx", &out[i]);
}

int main(void) {
    CHECK(scaas_ua_abi_version() == SCAAS_UA_ABI_VERSION);

    // kinds.json: ed25519
    ScaasUaKind k;
    CHECK(scaas_ua_kind_info(0x0102, &k) == SCAAS_UA_OK);
    CHECK(k.kind == 0x0102 && !k.native && k.lengths_len == 1 && k.lengths[0] == 32);
    CHECK(strcmp(k.name, "ed25519") == 0 && k.group && strcmp(k.group, "ed25519") == 0);

    // kinds.json valid: ed25519
    uint8_t key[32], want[32], ua[32];
    hex("0xc3a25e9d1581017c4533be88827b7d473c88750c58cdc56cdb26e84443f92d3b", key, 32);
    hex("0x62743c5211ce3ee6487bf754a8e8d89c988ced805bb072156fb72ca66a3ae53a", want, 32);
    CHECK(scaas_ua_derive_ua(0x0102, key, sizeof key, false, ua) == SCAAS_UA_OK);
    CHECK(memcmp(ua, want, 32) == 0);
    CHECK(strcmp(scaas_ua_last_error(), "") == 0);

    // an error status and its detail
    CHECK(scaas_ua_validate_key_data(0x0101, key, 3, false) == SCAAS_UA_ERR_KEY_DATA);
    CHECK(strcmp(scaas_ua_status_name(SCAAS_UA_ERR_KEY_DATA), "UAKeyData") == 0);
    CHECK(strncmp(scaas_ua_last_error(), "UAKeyData: ", 11) == 0);

    // the buffer-size query, then the call
    size_t len = 0;
    CHECK(scaas_ua_kind_tag_string(0x0102, NULL, &len) == SCAAS_UA_ERR_BUFFER);
    CHECK(len == sizeof "scaas.ua.ed25519.v1");
    char tag[64];
    len = sizeof tag;
    CHECK(scaas_ua_kind_tag_string(0x0102, tag, &len) == SCAAS_UA_OK);
    CHECK(len == sizeof "scaas.ua.ed25519.v1" && strcmp(tag, "scaas.ua.ed25519.v1") == 0);

    // ABI v6: a wallet and its key handles (sign.json rows of the mnemonic pq_kat)
    static const char *words =
        "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice "
        "deposit sauce coconut afford frown better";
    uint8_t purpose[32], digest[32], sig[8192], want_sig[128];
    hex("0x659f1188c729a1ac7e7f664f5bdf6be9f45677d902d8cc3cf2c018ac7449c18f", purpose, 32);  // metatx v1
    hex("0x5a66b3357e5f76dc43bd110885c382fc13e78b775e6a1f7eb042fa1f17ce205c", digest, 32);
    CHECK(scaas_ua_features() & SCAAS_UA_FEATURE_WALLET);
    ScaasUaWallet *w = NULL;
    CHECK(scaas_ua_wallet_from_mnemonic(words, NULL, &w) == SCAAS_UA_OK && w);

    // classic curves: p256 (RFC 6979, byte-equal)
    ScaasUaKey *p256 = NULL;
    CHECK(scaas_ua_wallet_ua_key(w, 0x0101, 0, 0, &p256) == SCAAS_UA_OK);
    hex("0x6989d4ad675592f86c32ae9b864d7b2c60ee7a7b4335f4820ddfd43428123418197fa57778a4c5fbee94239e1af8d76dffe9848eb1ec04c04f4fee2ec1a583e8",
        want_sig, 64);
    len = sizeof sig;
    CHECK(scaas_ua_sign_ua(p256, purpose, digest, sig, &len) == SCAAS_UA_OK && len == 64 && memcmp(sig, want_sig, 64) == 0);

    // pairing curves: bls12381-minsig (deterministic, byte-equal)
    ScaasUaKey *bls = NULL;
    CHECK(scaas_ua_wallet_ua_key(w, 0x0106, 0, 0, &bls) == SCAAS_UA_OK);
    hex("0x00000000000000000000000000000000036054e26d86603fbfa01b2a871534023fc6a27e6f9e3151efab81d1c215070835955a91b971d8513022c72afa3f5498"
        "00000000000000000000000000000000102e1284ba45694ddabe32996f7a99e3dc1092d7bee0bc8f540912da856ac6cba6d371ebd5a4303ee735f9fe79ed7040",
        want_sig, 128);
    len = sizeof sig;
    CHECK(scaas_ua_sign_ua(bls, purpose, digest, sig, &len) == SCAAS_UA_OK && len == 128 && memcmp(sig, want_sig, 128) == 0);

    // PQ: mldsa44 (hedged: its length)
    ScaasUaKey *mldsa = NULL;
    CHECK(scaas_ua_wallet_ua_key(w, 0x0130, 0, 0, &mldsa) == SCAAS_UA_OK);
    len = sizeof sig;
    CHECK(scaas_ua_sign_ua(mldsa, purpose, digest, sig, &len) == SCAAS_UA_OK && len == 2420);

    // native: the EVM key's raw digest (65 bytes), refused for a UA key
    ScaasUaKey *evm = NULL;
    CHECK(scaas_ua_wallet_native_key(w, SCAAS_UA_NETWORK_EVM, 0, SCAAS_UA_COIN_DEFAULT, &evm) == SCAAS_UA_OK);
    len = sizeof sig;
    CHECK(scaas_ua_sign_digest_raw(evm, digest, sig, &len) == SCAAS_UA_OK && len == 65);
    len = sizeof sig;
    CHECK(scaas_ua_sign_digest_raw(p256, digest, sig, &len) == SCAAS_UA_ERR_RAW_DIGEST_REFUSED);

    // KEM: the mldsa44 UA's key (no wallet argument), a seal to it and its open
    ScaasUaKemKey *kk = NULL;
    CHECK(scaas_ua_kem_key(mldsa, 0, &kk) == SCAAS_UA_OK);
    uint8_t pk[1601], mlkem_ct[1568], eph[32], ct[64], pt[64];
    CHECK(scaas_ua_kem_pk(kk, pk) == SCAAS_UA_OK);
    size_t ct_len = sizeof ct, mlkem_len = sizeof mlkem_ct, pt_len = sizeof pt;
    CHECK(scaas_ua_seal(pk, sizeof pk, "scaas/test/v1", NULL, 0, (const uint8_t *)"smoke", 5, mlkem_ct, &mlkem_len, eph, ct, &ct_len) == SCAAS_UA_OK);
    CHECK(scaas_ua_open(kk, "scaas/test/v1", NULL, 0, mlkem_ct, mlkem_len, eph, ct, ct_len, pt, &pt_len) == SCAAS_UA_OK && pt_len == 5 &&
          memcmp(pt, "smoke", 5) == 0);

    // Zether (T14, default build): the conf key's PoP and a balance-cache box round trip; a key field is refused
    CHECK(scaas_ua_features() & SCAAS_UA_FEATURE_ZETHER);
    ScaasUaZetherKey *zk = NULL;
    CHECK(scaas_ua_wallet_zether_key(w, 60, 0, SCAAS_UA_ZETHER_USE_CONF, &zk) == SCAAS_UA_OK && zk);
    uint8_t zy[SCAAS_UA_ZETHER_Y_LEN], zua[32];
    CHECK(scaas_ua_zether_public(zk, zy, zua) == SCAAS_UA_OK);
    char zout[4096];
    len = sizeof zout;
    CHECK(scaas_ua_zether_call(zk, "pop", "{\"curve\":\"bls12381\"}", zout, &len) == SCAAS_UA_OK && strstr(zout, "\"pop\""));
    len = sizeof zout;
    CHECK(scaas_ua_zether_call(zk, "pop", "{\"key\":{\"x\":\"0x01\"}}", zout, &len) == SCAAS_UA_ERR_ARGUMENT);
    len = sizeof zout;
    CHECK(scaas_ua_zether_seal_balance_cache(zk, (const uint8_t *)"{}", 2, zout, &len) == SCAAS_UA_OK);
    uint8_t zpt[16];
    size_t zpt_len = sizeof zpt;
    CHECK(scaas_ua_zether_open_balance_cache(zk, zout, zpt, &zpt_len) == SCAAS_UA_OK && zpt_len == 2 && memcmp(zpt, "{}", 2) == 0);

    // PQZ (T15, default build: n2304-kmax4096): the set, an R_REG proof, a key field refused, a cache box, the leaf export
    CHECK(scaas_ua_features() & SCAAS_UA_FEATURE_PQZ);
    CHECK(scaas_ua_features() & SCAAS_UA_FEATURE_PQZ_SET_N2304_KMAX4096);
    static char qout[SCAAS_UA_PQZ_OUT_MAX];
    len = sizeof qout;
    CHECK(scaas_ua_pqz_set(qout, &len) == SCAAS_UA_OK && strstr(qout, "\"n2304-kmax4096\""));
    CHECK(scaas_ua_pqz_check_set(qout) == SCAAS_UA_OK);
    CHECK(scaas_ua_pqz_check_set("{\"set\":\"n2048-kmax1024\",\"pkLen\":16384,\"pqzlId\":\"0x00\",\"pqzhId\":null}") ==
          SCAAS_UA_ERR_ARGUMENT);
    ScaasUaPqzKey *qk = NULL;
    CHECK(scaas_ua_wallet_pqz_key(w, 0, 0, &qk) == SCAAS_UA_OK && qk);
    static uint8_t qpk[32768];
    size_t qpk_len = sizeof qpk;
    CHECK(scaas_ua_pqz_public(qk, qpk, &qpk_len) == SCAAS_UA_OK && qpk_len == 18432);
    char qreq[256];
    snprintf(qreq, sizeof qreq, "{\"proofSystemId\":\"0x%s\",\"kind\":305,\"ua\":\"0x%064d\"}",
             "ef1ffbcbd05394f8276e50a6c254022edf53bbd08a56e22aadddac2b9b90336e", 1);
    len = sizeof qout;
    CHECK(scaas_ua_pqz_call(qk, "proveRegister", qreq, qout, &len) == SCAAS_UA_OK && strstr(qout, "\"proof\"") && strstr(qout, "\"message\""));
    len = sizeof qout;
    CHECK(scaas_ua_pqz_call(qk, "dec", "{\"key\":{\"seed32\":\"0x01\"}}", qout, &len) == SCAAS_UA_ERR_ARGUMENT);
    len = sizeof qout;
    CHECK(scaas_ua_pqz_seal_balance_cache(qk, (const uint8_t *)"{}", 2, qout, &len) == SCAAS_UA_OK);
    size_t qpt_len = sizeof zpt;
    CHECK(scaas_ua_pqz_open_balance_cache(qk, qout, zpt, &qpt_len) == SCAAS_UA_OK && qpt_len == 2 && memcmp(zpt, "{}", 2) == 0);
    uint8_t leaf[32];
    CHECK(scaas_ua_export_pqz_leaf_raw(w, 0, 0, leaf) == SCAAS_UA_OK);
    memset(leaf, 0, sizeof leaf); // the caller zeroizes the exported leaf

    // external keys (T16, MD-13): none in a release build; the callback is neither kept nor called, *out untouched
    CHECK(!(scaas_ua_features() & SCAAS_UA_FEATURE_EXTERNAL));
    ScaasUaExternalSigner ext = {NULL, NULL, NULL};
    ScaasUaKey *ek = p256;
    CHECK(scaas_ua_external_key_new("{\"kind\":257,\"keyData\":\"0x\"}", &ext, &ek) == SCAAS_UA_ERR_KIND_UNAVAILABLE && ek == p256);

    // the wallet freed before its children: each child stays valid memory and answers KEY_REVOKED (ASan: no use after free)
    scaas_ua_wallet_free(w);
    len = sizeof qout;
    CHECK(scaas_ua_pqz_call(qk, "dec", "{}", qout, &len) == SCAAS_UA_ERR_ARGUMENT); // decoded before the key: no ct
    len = sizeof qout;
    CHECK(scaas_ua_pqz_seal_balance_cache(qk, (const uint8_t *)"{}", 2, qout, &len) == SCAAS_UA_ERR_KEY_REVOKED);
    qpk_len = sizeof qpk;
    CHECK(scaas_ua_pqz_public(qk, qpk, &qpk_len) == SCAAS_UA_OK);
    scaas_ua_pqz_key_free(qk);
    len = sizeof zout;
    CHECK(scaas_ua_zether_call(zk, "pop", "{}", zout, &len) == SCAAS_UA_ERR_KEY_REVOKED);
    CHECK(scaas_ua_zether_public(zk, zy, zua) == SCAAS_UA_OK);
    scaas_ua_zether_key_free(zk);
    len = sizeof sig;
    CHECK(scaas_ua_sign_ua(p256, purpose, digest, sig, &len) == SCAAS_UA_ERR_KEY_REVOKED);
    len = sizeof sig;
    CHECK(scaas_ua_sign_digest_raw(evm, digest, sig, &len) == SCAAS_UA_ERR_KEY_REVOKED);
    pt_len = sizeof pt;
    CHECK(scaas_ua_open(kk, "scaas/test/v1", NULL, 0, mlkem_ct, mlkem_len, eph, ct, ct_len, pt, &pt_len) == SCAAS_UA_ERR_KEY_REVOKED);
    len = sizeof sig;
    CHECK(scaas_ua_key_data(mldsa, sig, &len) == SCAAS_UA_OK && len == 1312);
    scaas_ua_kem_free(kk);
    scaas_ua_key_free(p256);
    scaas_ua_key_free(bls);
    scaas_ua_key_free(mldsa);
    scaas_ua_key_free(evm);
    // _free(NULL) is a no-op
    scaas_ua_wallet_free(NULL);
    scaas_ua_key_free(NULL);
    scaas_ua_kem_free(NULL);
    scaas_ua_link_session_free(NULL);
    scaas_ua_seed_backup_free(NULL);
    scaas_ua_zether_key_free(NULL);
    scaas_ua_pqz_key_free(NULL);

    if (failures) return 1;
    puts("smoke ok");
    return 0;
}
