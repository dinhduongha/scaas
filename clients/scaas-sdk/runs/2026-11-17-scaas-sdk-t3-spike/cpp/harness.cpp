// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-sdk T3 spike: the sync control of the probe through uniffi-bindgen-cpp's output (the async shapes do not generate).
#include "sdk_spike_probe.hpp"
#include <cstdio>
#include <exception>

struct CppStore : sdk_spike_probe::SyncStore {
    bool fail;
    explicit CppStore(bool f) : fail(f) {}
    std::optional<std::vector<uint8_t>> get(const std::string &name) override {
        if (fail) throw std::runtime_error("a foreign exception");
        return std::vector<uint8_t>(name.size(), 7);
    }
};

int main() {
    int bad = 0;
    auto s = sdk_spike_probe::seeds();
    if (s.size() != 1 || s[0].label != "Main" || s[0].words != 24) { std::puts("FAIL seeds"); bad++; } else std::puts("ok seeds: a record list");
    try { sdk_spike_probe::panics(); std::puts("FAIL panics returned"); bad++; }
    catch (const std::exception &e) { std::printf("ok panics: caught as a C++ exception (%s)\n", e.what()); }
    auto good = std::make_shared<CppStore>(false);
    if (sdk_spike_probe::read_sync(good, "keystore") != 8) { std::puts("FAIL read_sync"); bad++; } else std::puts("ok read_sync: a C++ store called from Rust");
    try { sdk_spike_probe::read_sync(std::make_shared<CppStore>(true), "keystore"); std::puts("FAIL foreign exception passed"); bad++; }
    catch (const sdk_spike_probe::probe_error::Unexpected &) { std::puts("ok foreign exception: Unexpected, no Rust panic"); }
    catch (const std::exception &e) { std::printf("FAIL foreign exception as %s\n", e.what()); bad++; }
    return bad;
}
