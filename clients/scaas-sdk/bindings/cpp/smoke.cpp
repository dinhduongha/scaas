// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-sdk plan T20b: the sync C++ surface (spec §16.1 (a′)) through uniffi-bindgen-cpp's output, over the reference library
// built with `sync-api`. Rows: smartcontracts/vectors/keystore/keystore.json (as ../rows.py writes them, argv[1]); each
// container is the C++ store's `keystore`. Valid rows list their seeds and every seed opens with the rows' passphrase (its
// accounts listed); refused rows fail with their named error. Then: a C++ authenticator's PRF through the copy call (passkey
// unlock), a panic as Internal, a C++ exception in the store and in the authenticator (Unexpected on the Rust side: no panic,
// the SDK's error), a cancel token, `next_blocking`, the load check. Secrets go in and out only by the copy calls.
#include "scaas_sdk.hpp"
#include "scaas_sdk_ffi.hpp"

#include <cstdio>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>

extern "C" {
int32_t scaas_sdk_secret_write(uint64_t id, const uint8_t *src, size_t len);
}

namespace s = scaas_sdk;

static int bad = 0;
#define CHECK(c, ...)                                                                                                  \
    do {                                                                                                               \
        if (!(c)) {                                                                                                    \
            std::printf("FAIL " __VA_ARGS__);                                                                          \
            std::puts("");                                                                                             \
            bad++;                                                                                                     \
        }                                                                                                              \
    } while (0)

static std::string unhex(const std::string &h) {
    std::string out;
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(char(std::stoi(h.substr(i, 2), nullptr, 16)));
    return out;
}

static std::shared_ptr<s::SecretBytes> sec(const std::string &v) {
    auto x = s::secret_new(uint32_t(v.size()));
    if (scaas_sdk_secret_write(s::secret_id(x), reinterpret_cast<const uint8_t *>(v.data()), v.size()) != 0)
        throw std::runtime_error("copy call");
    return x;
}

struct MemStore : s::SyncStore {
    std::mutex m;
    std::map<std::string, std::vector<uint8_t>> items;
    bool throws = false;
    std::optional<s::StoredItem> get(const std::string &name, const std::string &) override {
        std::lock_guard g(m);
        if (throws)
            throw std::runtime_error("the app's store threw");
        auto it = items.find(name);
        if (it == items.end())
            return std::nullopt;
        return s::StoredItem{it->second, s::rev_of(it->second)};
    }
    void put_if(const std::string &name, std::optional<uint64_t> prev, const std::vector<uint8_t> &bytes,
                const s::StorePolicy &) override {
        std::lock_guard g(m);
        auto it = items.find(name);
        std::optional<uint64_t> have = it == items.end() ? std::nullopt : std::optional(s::rev_of(it->second));
        if (have != prev)
            throw s::store_error::Conflict();
        items[name] = bytes;
    }
    void remove(const std::string &name) override {
        std::lock_guard g(m);
        items.erase(name);
    }
    // one caller at a time here: no lock to hold
    uint64_t lock(const std::string &) override { return 1; }
    void unlock(uint64_t) override {}
};

// A PRF: 32 bytes from the salt (deterministic, a test stand-in), written by the copy call into the secret `prf_out` names.
struct FakeAuth : s::SyncAuthenticator {
    bool throws = false;
    s::PasskeyCreated create_passkey(const std::string &, const std::string &,
                                     const std::vector<std::vector<uint8_t>> &) override {
        throw s::auth_error::Unavailable();
    }
    s::Assertion get_assertion(const s::AssertionRequest &req, uint64_t prf_out) override {
        if (throws)
            throw std::runtime_error("the app's authenticator threw");
        if (!req.prf_salt)
            throw s::auth_error::Refused();
        uint8_t out[32];
        for (size_t i = 0; i < 32; i++)
            out[i] = uint8_t((*req.prf_salt)[i % req.prf_salt->size()] ^ 0x5a ^ i);
        if (scaas_sdk_secret_write(prf_out, out, 32) != 0)
            throw s::auth_error::Refused();
        return s::Assertion{{0xc1, 0xed}, std::vector<uint8_t>(37), {}, std::vector<uint8_t>(64), true};
    }
    void platform_secret(const std::string &, const std::vector<uint8_t> &, const std::string &,
                         std::optional<s::KeyPolicy>, uint64_t) override {
        throw s::auth_error::Unavailable();
    }
    s::SePublic p256_generate(const s::KeyPolicy &) override { throw s::auth_error::Unavailable(); }
    std::vector<uint8_t> p256_sign(const std::string &, const std::vector<uint8_t> &, const std::string &) override {
        throw s::auth_error::Unavailable();
    }
};

static s::BindingConfig config() { return s::BindingConfig{{}, "wallet.example", s::limits_default(), {}}; }

static std::shared_ptr<s::Sdk> open(std::shared_ptr<MemStore> st,
                                    std::shared_ptr<FakeAuth> auth = std::make_shared<FakeAuth>()) {
    return s::open_blocking(config(), st, auth);
}

static std::shared_ptr<s::Sdk> over(const std::string &text) {
    auto st = std::make_shared<MemStore>();
    st->items["keystore"] = std::vector<uint8_t>(text.begin(), text.end());
    return open(st);
}

template <typename F> static std::string failure(F f) {
    try {
        f();
        return "Ok";
    } catch (const s::SdkError &e) {
        return e.what();
    }
}

struct Seed {
    std::string id, label, backup;
    uint32_t words;
    std::vector<std::string> accounts;
};

static std::vector<std::string> split(const std::string &l, char c) {
    std::vector<std::string> v;
    std::stringstream ss(l);
    for (std::string f; std::getline(ss, f, c);)
        v.push_back(f);
    if (!l.empty() && l.back() == c)
        v.emplace_back();
    return v;
}

static void rows(const char *path) {
    std::ifstream in(path);
    std::string line, pass;
    struct Valid {
        std::string id, text;
        std::vector<Seed> seeds;
    };
    std::vector<Valid> valid;
    std::vector<std::array<std::string, 3>> refused;
    while (std::getline(in, line)) {
        auto f = split(line, '\t');
        if (f[0] == "pass")
            pass = unhex(f[1]);
        else if (f[0] == "valid")
            valid.push_back({unhex(f[1]), unhex(f[2]), {}});
        else if (f[0] == "seed") {
            std::vector<std::string> acc;
            if (!f[5].empty())
                acc = split(f[5], ',');
            valid.back().seeds.push_back({f[1], unhex(f[2]), f[4], uint32_t(std::stoul(f[3])), acc});
        } else if (f[0] == "refused")
            refused.push_back({unhex(f[1]), f[2], unhex(f[3])});
    }
    CHECK(valid.size() >= 5 && refused.size() >= 19, "control: rows read (%zu valid, %zu refused)", valid.size(),
          refused.size());
    int opened = 0;
    for (auto &r : valid) {
        auto sdk = over(r.text);
        auto got = sdk->vault()->seeds_blocking(nullptr);
        CHECK(got.size() == r.seeds.size(), "%s: %zu seeds", r.id.c_str(), got.size());
        for (size_t i = 0; i < got.size() && i < r.seeds.size(); i++) {
            auto &w = r.seeds[i];
            CHECK(got[i].id == w.id && got[i].label == w.label && got[i].words == w.words &&
                      got[i].backup == w.backup && !got[i].unlocked,
                  "%s: seed %zu", r.id.c_str(), i);
        }
        for (auto &w : r.seeds) {
            sdk->vault()->unlock_blocking(w.id, s::Unlock(s::Unlock::kPassphrase{sec(pass)}), nullptr);
            CHECK(sdk->vault()->seed_blocking(w.id, nullptr).unlocked, "%s %s unlocked", r.id.c_str(), w.id.c_str());
            std::vector<std::string> ids;
            for (auto &a : sdk->account()->accounts_blocking(w.id, nullptr))
                ids.push_back(a.id);
            CHECK(ids == w.accounts, "%s %s accounts", r.id.c_str(), w.id.c_str());
            opened++;
        }
        if (!r.seeds.empty()) {
            auto first = r.seeds[0].id;
            sdk->vault()->lock_blocking(first);
            auto e = failure([&] {
                sdk->vault()->unlock_blocking(first, s::Unlock(s::Unlock::kPassphrase{sec("not the one 9")}), nullptr);
            });
            CHECK(e == "VaultOpen", "%s: a wrong passphrase is %s", r.id.c_str(), e.c_str());
        }
    }
    CHECK(opened >= 5, "control: seeds were opened (%d)", opened);
    std::printf("ok rows: %zu valid (%d seeds opened)\n", valid.size(), opened);
    for (auto &r : refused) {
        auto e = failure([&] { over(r[2])->vault()->seeds_blocking(nullptr); });
        CHECK(e == r[1], "%s: %s, want %s", r[0].c_str(), e.c_str(), r[1].c_str());
    }
    std::printf("ok rows: %zu refused by name\n", refused.size());
}

static const char *REPO = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author "
                          "capable act festival slice deposit sauce coconut afford frown better";
static const char *PASS = "river-otter-7 \xc3\xbcn\xc3\xaf";

static std::string import(const std::shared_ptr<s::Sdk> &sdk) {
    return sdk->vault()->import_words_blocking(s::ImportWords{"Main", sec(REPO), sec(PASS)}, nullptr).id;
}

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    CHECK(s::api_version() == 1, "load check: api_version %u", s::api_version());
    rows(argv[1]);

    // the PRF return: a C++ authenticator writes it by the copy call; the passkey unlock opens the seed with it
    auto st = std::make_shared<MemStore>();
    auto auth = std::make_shared<FakeAuth>();
    auto sdk = open(st, auth);
    auto sub = sdk->subscribe();
    CHECK(!sub->next_blocking(50).has_value(), "next_blocking: nothing yet");
    auto id = import(sdk);
    bool changed = false;
    while (auto e = sub->next_blocking(200))
        if (std::holds_alternative<s::Event::kKeystoreChanged>(e->get_variant()))
            changed = true;
    CHECK(changed, "next_blocking: KeystoreChanged");
    sdk->vault()->enable_passkey_unlock_blocking(id, sec(PASS), nullptr);
    sdk->vault()->lock_blocking(id);
    sdk->vault()->unlock_blocking(id, s::Unlock(s::Unlock::kPasskey{}), nullptr);
    CHECK(sdk->vault()->seed_blocking(id, nullptr).unlocked, "passkey unlock by the PRF");
    std::puts("ok C++ store and authenticator: import, PRF by the copy call, passkey unlock, next_blocking");

    // a C++ exception in the authenticator: Unexpected on the Rust side, the SDK's refusal here, no panic
    sdk->vault()->lock_blocking(id);
    auth->throws = true;
    auto ea = failure([&] { sdk->vault()->unlock_blocking(id, s::Unlock(s::Unlock::kPasskey{}), nullptr); });
    CHECK(ea != "Ok" && ea != "Internal", "authenticator exception: %s", ea.c_str());
    auth->throws = false;
    // a C++ exception in the store: Unexpected, the store's failure (VaultIo)
    st->throws = true;
    auto es = failure([&] { sdk->vault()->seeds_blocking(nullptr); });
    CHECK(es == "VaultIo", "store exception: %s", es.c_str());
    st->throws = false;
    CHECK(sdk->vault()->seeds_blocking(nullptr).size() == 1, "control: the store again");
    std::printf("ok C++ exceptions: authenticator %s, store %s\n", ea.c_str(), es.c_str());

    // a panic inside a call (the reference library's hook): Internal, the SDK goes on
    auto ep = failure([&] { scaas_sdk_ffi::panic_in_call_blocking(sdk); });
    CHECK(ep == "Internal", "panic: %s", ep.c_str());
    // a cancelled token: Cancelled
    auto t = s::CancelToken::init();
    t->cancel();
    auto ec = failure([&] { sdk->vault()->seeds_blocking(t); });
    CHECK(ec == "Cancelled", "cancel: %s", ec.c_str());
    CHECK(sdk->vault()->seeds_blocking(nullptr).size() == 1, "control: after the panic and the cancel");
    std::printf("ok panic %s, cancel %s\n", ep.c_str(), ec.c_str());
    std::printf("%s (%d failures)\n", bad ? "FAIL" : "PASS", bad);
    return bad ? 1 : 0;
}
