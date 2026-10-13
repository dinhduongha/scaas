// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// C99 smoke test of include/scaas_ua.h against the staticlib. The full vector suite is tests/test_vectors.py.
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

    if (failures) return 1;
    puts("smoke ok");
    return 0;
}
