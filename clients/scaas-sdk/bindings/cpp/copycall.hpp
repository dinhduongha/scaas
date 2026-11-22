// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-sdk spec §5, §16.1: the reference library's secret copy calls for C++ (plan T20b; review B12). A secret's bytes
// cross only here, never through the generated codec: `write` copies a buffer into the secret named by its id and zeroes
// the buffer, `read` copies a secret out (the caller zeroes what it read once done), `dispose` zeroes and frees a secret.
#pragma once
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

extern "C" {
int32_t scaas_sdk_secret_write(uint64_t id, const uint8_t *src, size_t len);
int64_t scaas_sdk_secret_read(uint64_t id, uint8_t *dst, size_t cap);
int32_t scaas_sdk_secret_dispose(uint64_t id);
}

namespace scaas_copycall {

// `buf` into secret `id` (its length exactly), then `buf` zeroed (also on a refusal); throws on a refusal.
inline void write(uint64_t id, std::vector<uint8_t> &buf) {
    int32_t r = scaas_sdk_secret_write(id, buf.data(), buf.size());
    for (auto &b : buf)
        *static_cast<volatile uint8_t *>(&b) = 0;
    if (r != 0)
        throw std::invalid_argument("scaas_sdk_secret_write");
}

// Secret `id` (at most `cap` bytes) out.
inline std::vector<uint8_t> read(uint64_t id, size_t cap) {
    std::vector<uint8_t> out(cap);
    int64_t n = scaas_sdk_secret_read(id, out.data(), cap);
    if (n < 0)
        throw std::invalid_argument("scaas_sdk_secret_read");
    out.resize(static_cast<size_t>(n));
    return out;
}

// Secret `id` zeroed and freed; false when unknown.
inline bool dispose(uint64_t id) { return scaas_sdk_secret_dispose(id) == 0; }

} // namespace scaas_copycall
