// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// ua-cxx wallet surface (ua-rs-sign T13a) against smartcontracts/vectors/ua/{keys,sign,kem,seal,vault,rs_vault,rs_signatures,zether}.json
// and the PQZ / Zether facades: mirrors clients/ua-c/tests/test_vectors.py's wallet classes through the Rust API. `wallet_test <name>`.
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <map>
#include <nlohmann/json.hpp>
#include <set>

#include "scaas_ua.hpp"

using nlohmann::json;
using namespace scaas::ua;

static int failures = 0;
#define CHECK(c, ctx)                                                                                    \
    do {                                                                                                 \
        if (!(c)) {                                                                                      \
            std::fprintf(stderr, "%s:%d: %s [%s]\n", __FILE__, __LINE__, #c, std::string(ctx).c_str()); \
            ++failures;                                                                                  \
        }                                                                                                \
    } while (0)

static json load_json(const std::string& path) {
    std::ifstream f(path);
    if (!f) {
        std::fprintf(stderr, "cannot open %s\n", path.c_str());
        std::exit(2);
    }
    return json::parse(f);
}
static json vec(const char* name) { return load_json(std::string(SCAAS_UA_VECTORS_DIR) + "/" + name); }
static Bytes bytes(const json& v) {
    std::string h = v.get<std::string>();
    if (h.rfind("0x", 0) == 0) h = h.substr(2);
    Bytes out;
    for (size_t i = 0; i + 1 < h.size(); i += 2) out.push_back(uint8_t(std::stoi(h.substr(i, 2), nullptr, 16)));
    return out;
}
static std::string hx(const Bytes& b) {
    static const char* d = "0123456789abcdef";
    std::string s = "0x";
    for (auto c : b) {
        s += d[c >> 4];
        s += d[c & 15];
    }
    return s;
}
static Bytes str(const std::string& s) { return Bytes(s.begin(), s.end()); }
static std::string code_of(const std::function<void()>& f) {
    try {
        f();
    } catch (const Error& e) {
        return e.code();
    }
    return "";
}
static bool all_zero(const uint8_t* p, size_t n) { return std::all_of(p, p + n, [](uint8_t b) { return b == 0; }); }
static std::string dump(const json& v) { return v.is_null() ? std::string() : v.dump(); }

static json KEYS = vec("keys.json");
static std::map<std::string, json> mnemonics() {
    std::map<std::string, json> m;
    for (auto& r : KEYS["mnemonics"]) m[r["id"].get<std::string>()] = r;
    return m;
}
static std::map<std::string, json> MN = mnemonics();
static const std::set<uint16_t> DETERMINISTIC = {0x0101, 0x0102, 0x0106, 0x0107, 0x0108};
static bool falcon() { return features() & feature::kFalcon; }

static Wallet wallet_of(const std::string& id) {
    Secret w(MN.at(id)["words"].get<std::string>()), p(MN.at(id)["passphrase"].get<std::string>());
    return Wallet::fromMnemonic(w, p);
}
// one wallet per mnemonic, kept for the run
static const Wallet& W(const std::string& id) {
    static std::map<std::string, Wallet> cache;
    auto it = cache.find(id);
    if (it == cache.end()) it = cache.emplace(id, wallet_of(id)).first;
    return it->second;
}
// a number, or its decimal string (kem.json writes versions as strings: one row is 2^64)
static uint64_t u64(const json& v) { return v.is_string() ? std::stoull(v.get<std::string>()) : v.get<uint64_t>(); }
static KemKey kem_of(const json& r, const Wallet* w = nullptr) {
    std::string mid = r.contains("mnemonic") && !r["mnemonic"].is_null() ? r["mnemonic"].get<std::string>() : "pq_kat";
    const Wallet& ww = w ? *w : W(mid);
    return ww.uaKey(uint16_t(u64(r["kind"])), uint32_t(u64(r["account"])), uint32_t(u64(r["index"]))).kemKey(u64(r["version"]));
}

// --- load, secrets, handles ------------------------------------------------------------------------------------------------

static void load_refuses_wrong_abi_or_features() {
    load();  // positive control: the linked core is this header's
    CHECK((features() & kRequiredFeatures) == kRequiredFeatures, "required features");
    auto abi = detail::reportedAbiVersion;
    auto feat = detail::reportedFeatures;
    detail::reportedAbiVersion = [] { return 5u; };  // an older core
    CHECK(code_of([] { load(); }) == "UAAbiMismatch", "abi 5");
    CHECK(code_of([] { Secret w(MN.at("pq_kat")["words"].get<std::string>()), p; Wallet::fromMnemonic(w, p); }) == "UAAbiMismatch",
          "a factory refuses before it runs");
    CHECK(code_of([] { KemKey::ephemeral(); }) == "UAAbiMismatch", "kem ephemeral");
    CHECK(code_of([] { LinkSession::create(); }) == "UAAbiMismatch", "link session");
    CHECK(code_of([] { seal(Bytes(1601, 1), "scaas/backup/v1", {}, {}); }) == "UAAbiMismatch", "seal");
    detail::reportedAbiVersion = [] { return 7u; };
    CHECK(code_of([] { load(); }) == "UAAbiMismatch", "abi 7");
    detail::reportedAbiVersion = abi;
    detail::reportedFeatures = [] { return kRequiredFeatures & ~feature::kPqz; };
    CHECK(code_of([] { load(); }) == "UAAbiMismatch", "features without pqz");
    detail::reportedFeatures = [] { return kRequiredFeatures & ~feature::kPqzSetN2304Kmax4096; };
    CHECK(code_of([] { load(); }) == "UAAbiMismatch", "another pqz set");
    detail::reportedFeatures = [] { return kRequiredFeatures | feature::kVectors; };  // Codex C1: a test build
    CHECK(code_of([] { load(); }) == "UAAbiMismatch", "a vectors build");
    CHECK(code_of([] { KemKey::ephemeral(); }) == "UAAbiMismatch", "a vectors build: kem ephemeral");
    detail::reportedFeatures = feat;
    CHECK(!(features() & feature::kVectors), "the linked core is not a test build");
    load();
}

static void secret_buffer_wiped_after_call() {
    auto words = MN.at("pq_kat")["words"].get<std::string>();
    Secret w(words), p(MN.at("pq_kat")["passphrase"].get<std::string>());
    size_t n = w.size();
    Wallet wl = Wallet::fromMnemonic(w, p);
    CHECK(w.size() == n && all_zero(w.data(), n), "mnemonic wiped after the call");
    CHECK(all_zero(p.data(), p.size()), "BIP-39 passphrase wiped");
    Secret bad(words.substr(0, words.rfind(' ')) + " zzzz"), none;
    CHECK(code_of([&] { Wallet::fromMnemonic(bad, none); }) == "UAArgument", "a bad word");
    CHECK(all_zero(bad.data(), bad.size()), "wiped on the error path too");
    Secret pin("correct horse 9");
    std::string v = wl.sealVault(pin);
    CHECK(all_zero(pin.data(), pin.size()) && pin.size() == 15, "seal_vault passphrase wiped");
    Secret pin2("correct horse 9"), prf, b39;
    Wallet w2 = Wallet::openVault(v, pin2, prf, b39);
    CHECK(all_zero(pin2.data(), pin2.size()), "open_vault passphrase wiped");
    Bytes raw(32);
    for (size_t i = 0; i < 32; ++i) raw[i] = uint8_t(i + 1);
    Secret imp(raw);
    w2.importNativeKey("evm", imp);
    CHECK(all_zero(imp.data(), 32), "imported key wiped");
    Secret o1("correct horse 9"), o2("battery staple 7");
    vault::rewrapPin(v, o1, o2);
    CHECK(all_zero(o1.data(), o1.size()) && all_zero(o2.data(), o2.size()), "rewrap passphrases wiped");
    // an output secret: wipe() zeroizes it in place (the destructor runs the same wipe)
    auto [gw, sb] = Wallet::generate();
    Secret phrase = sb.reveal();
    CHECK(phrase.size() > 100, "24 words");
    const uint8_t* q = phrase.data();
    size_t m = phrase.size();
    phrase.wipe();
    CHECK(all_zero(q, m), "revealed phrase wiped");
    Secret leaf = W("pq_kat").exportPqzLeafRaw(0, 0);
    CHECK(leaf.size() == 32 && !all_zero(leaf.data(), 32), "leaf");
    q = leaf.data();
    leaf.wipe();
    CHECK(all_zero(q, 32), "leaf wiped");
}

static void handle_freed_once() {
    int64_t base = liveHandles();
    {
        Wallet w = wallet_of("twelve_words");
        Key k = w.uaKey(0x0102, 0, 0);
        Key k2 = std::move(k);
        CHECK(code_of([&] { k.keyData(); }) == "UAArgument", "a moved-from handle");
        std::vector<Key> v;
        v.push_back(std::move(k2));
        v.push_back(w.uaKey(0x0101, 0, 0));
        Key k3 = std::move(v[0]);
        k3 = std::move(v[1]);  // the old key of k3 is freed here, once
        KemKey kk = w.uaKey(0x0130, 0, 0).kemKey(0);
        KemKey kk2(std::move(kk));
        Wallet w2 = std::move(w);
        CHECK(liveHandles() == base + 3, "w2, k3, kk2, and no other");
    }
    CHECK(liveHandles() == base, "every handle freed exactly once");
}

// --- keys.json -------------------------------------------------------------------------------------------------------------

static void keys_json() {
    size_t n = 0;
    for (auto& r : KEYS["ua"]) {
        uint16_t kind = r["kind"].get<uint16_t>();
        if ((kind == 0x0132 || kind == 0x0135) && !falcon()) continue;
        Key k = W(r["mnemonic"].get<std::string>()).uaKey(kind, r["account"].get<uint32_t>(), r["index"].get<uint32_t>());
        CHECK(hx(k.keyData()) == r["keyData"].get<std::string>(), r["name"].get<std::string>());
        if (!r["ua"].is_null() && kind != 0x0110 && kind != 0x0112) CHECK(hx(k.ua()) == r["ua"].get<std::string>(), r["name"].get<std::string>());
        ++n;
    }
    CHECK(n >= 184, "ua rows");
    for (auto& r : KEYS["native"]) {
        uint32_t coin = r["coinType"].is_null() ? kCoinDefault : r["coinType"].get<uint32_t>();
        Key k = W(r["mnemonic"].get<std::string>()).nativeKey(r["network"].get<std::string>(), r["index"].get<uint32_t>(), coin);
        CHECK(hx(k.keyData()) == "0x" + r["publicKey"].get<std::string>(), r["network"].get<std::string>());
        if (r["address"].is_null())
            CHECK(code_of([&] { k.address(); }) == "UAArgument", r["network"].get<std::string>() + ": no address");
        else
            CHECK(k.address() == r["address"].get<std::string>(), r["network"].get<std::string>());
    }
    for (auto& r : KEYS["refusals"]) {
        std::string got = code_of([&] {
            const Wallet& w = W(r["mnemonic"].get<std::string>());
            if (r["what"] == "ua")
                w.uaKey(r["kind"].get<uint16_t>(), r["account"].get<uint32_t>(), r["index"].get<uint32_t>());
            else
                w.nativeKey(r["network"].get<std::string>(), r["index"].get<uint32_t>(),
                            r["coinType"].is_null() ? kCoinDefault : r["coinType"].get<uint32_t>());
        });
        CHECK(got == "UA" + r["error"].get<std::string>(), r["reason"].get<std::string>());
    }
    CHECK(code_of([] { W("pq_kat").nativeKey("bitcoin", 0); }) == "UAArgument", "unknown network");
}

// --- sign.json -------------------------------------------------------------------------------------------------------------

static void sign_json() {
    json S = vec("sign.json");
    size_t exact = 0;
    for (auto& r : S["ua"]) {
        uint16_t kind = r["kind"].get<uint16_t>();
        if ((kind == 0x0132 || kind == 0x0135) && !falcon()) continue;
        Key k = W(r["mnemonic"].get<std::string>()).uaKey(kind, r["account"].get<uint32_t>(), r["index"].get<uint32_t>());
        Bytes sig = k.signUa(bytes(r["purposeTag"]), bytes(r["digest"]));
        if (DETERMINISTIC.count(kind)) {
            CHECK(hx(sig) == r["signature"].get<std::string>(), r["name"].get<std::string>());
            ++exact;
        } else if (kind != 0x0132 && kind != 0x0135) {
            CHECK(sig.size() == bytes(r["signature"]).size(), r["name"].get<std::string>());
        }
    }
    CHECK(exact >= 10, "deterministic rows");
    for (auto& r : S["member"]) {
        uint16_t kind = r["kind"].get<uint16_t>();
        Key k = W(r["mnemonic"].get<std::string>()).uaKey(kind, r["account"].get<uint32_t>(), r["index"].get<uint32_t>());
        Bytes sig = k.signMember(bytes(r["structureUa"]), bytes(r["structureUaMsg"]));
        if (DETERMINISTIC.count(kind))
            CHECK(hx(sig) == r["signature"].get<std::string>(), r["name"].get<std::string>());
        else
            CHECK(sig.size() == bytes(r["signature"]).size(), r["name"].get<std::string>());
    }
    Key evm = W("pq_kat").nativeKey("evm", 0);
    int signed_ = 0, refused = 0;
    for (auto& r : S["policy"]) {
        if (r.contains("refused")) {
            CHECK(code_of([&] { evm.signTyped(r["td"].dump(), r["expect"].dump()); }) == "UAPolicyRefused", r["id"].get<std::string>());
            ++refused;
        } else {
            CHECK(evm.signTyped(r["td"].dump(), r["expect"].dump()) == evm.signDigestRaw(bytes(r["digest"])), r["id"].get<std::string>());
            ++signed_;
        }
    }
    CHECK(signed_ == 10 && refused == 14, "policy rows");
    for (auto& r : S["typed"]["generic"])
        CHECK(evm.signTypedAny(r["td"].dump()) == evm.signDigestRaw(bytes(r["digest"])), r["id"].get<std::string>());
    for (auto& r : S["typed"]["refusals"])
        CHECK(code_of([&] { evm.signTypedAny(r["td"].dump()); }) == "UAArgument", r["id"].get<std::string>());
    for (auto& r : S["tx"]["rows"]) {
        auto& s = r["signer"];
        Key k = W(s["mnemonic"].get<std::string>()).nativeKey(s["network"].get<std::string>(), s["index"].get<uint32_t>());
        CHECK(hx(k.signTransaction(r["tx"].dump())) == r["raw"].get<std::string>(), r["tx"]["type"].dump());
    }
    for (auto& r : S["tx"]["refusals"])
        CHECK(code_of([&] { evm.signTransaction(r["tx"].dump()); }) == "UAArgument", r["id"].get<std::string>());
    for (auto& r : S["webauthn"]["accepted"]) {
        CHECK(webauthnChallenge(bytes(r["purposeTag"]), bytes(r["digest"])) == bytes(r["expectedChallenge"]), "challenge");
        CHECK(webauthnAssertion(bytes(r["keyData"]), bytes(r["expectedChallenge"]), bytes(r["authData"]), bytes(r["clientDataJSON"]),
                                bytes(r["r"]), bytes(r["s"])) == bytes(r["assertion"]),
              "assertion");
    }
    for (auto& r : S["webauthn"]["refusals"])
        CHECK(code_of([&] {
                  webauthnAssertion(bytes(r["keyData"]), bytes(r["expectedChallenge"]), bytes(r["authData"]), bytes(r["clientDataJSON"]),
                                    bytes(r["r"]), bytes(r["s"]));
              }) == "UA" + r["error"].get<std::string>(),
              r["case"].get<std::string>());
    // msig through the UASig builder: keys by position
    int built = 0, mrefused = 0;
    for (auto& r : S["msig"]) {
        std::vector<Key> keys;
        auto pos = [&](const json& x) {
            auto& k = x["key"];
            keys.push_back(W(k["mnemonic"].get<std::string>()).uaKey(k["kind"].get<uint16_t>(), k["account"].get<uint32_t>(), k["index"].get<uint32_t>()));
            return keys.size() - 1;
        };
        json slots = json::array();
        for (auto& s : r["slots"]) {
            if (s.contains("members")) {
                json ms = json::array();
                for (auto& x : s["members"]) ms.push_back({{"index", x["index"]}, {"key", pos(x)}});
                slots.push_back({{"index", s["index"]}, {"members", ms}});
            } else {
                slots.push_back({{"index", s["index"]}, {"key", pos(s)}});
            }
        }
        json m = {{"keyData", r["keyData"]}, {"slots", slots}};
        if (r.contains("inner")) m["inner"] = r["inner"];
        json req = {{"purpose", r["purposeTag"]}, {"digest", r["digest"]}, {"msig", m}};
        std::vector<const Key*> ptrs;
        for (auto& k : keys) ptrs.push_back(&k);
        if (r.contains("refused")) {
            CHECK(code_of([&] { uaSig(req.dump(), ptrs); }) == r["refused"].get<std::string>(), r["case"].get<std::string>());
            ++mrefused;
        } else {
            json sig = json::parse(uaSig(req.dump(), ptrs));
            CHECK(sig["keyData"] == "0x" && sig["signature"] == "0x", r["case"].get<std::string>());
            CHECK(sig["members"].size() > 0, r["case"].get<std::string>());
            ++built;
        }
    }
    CHECK(built == 3 && mrefused == 4, "msig rows");
    // a single key through the builder is sign_ua; a position past the keys is UAArgument
    for (auto& r : S["ua"]) {
        if (r["kind"] != 0x0101) continue;
        Key k = W(r["mnemonic"].get<std::string>()).uaKey(0x0101, 0, 0);
        json got = json::parse(uaSig(json{{"purpose", r["purposeTag"]}, {"digest", r["digest"]}, {"key", 0}}.dump(), {&k}));
        CHECK(got == (json{{"keyData", r["keyData"]}, {"signature", r["signature"]}, {"members", json::array()}}), "uasig single");
        CHECK(code_of([&] { uaSig(json{{"purpose", r["purposeTag"]}, {"digest", r["digest"]}, {"key", 1}}.dump(), {&k}); }) == "UAArgument",
              "key position");
        break;
    }
    Key uak = W("pq_kat").uaKey(0x0108, 0, 0);
    CHECK(code_of([&] { uak.signDigestRaw(Bytes(32)); }) == "UARawDigestRefused", "raw digest on a UA key");
    CHECK(evm.signDigestRaw(Bytes(32)).size() == 65, "raw digest on a native key");
    CHECK(evm.signKeyProof(str("challenge")).size() == 65, "key proof");
    CHECK(code_of([&] { W("pq_kat").uaKey(0x0101, 0, 0).signKeyProof(str("challenge")); }) == "UAArgument", "key proof on a UA key");
    CHECK(code_of([&] { evm.signUa(Bytes(32), Bytes(32)); }) == "UAArgument", "sign_ua on a native key");
}

// rs_signatures.json: release signatures of ua-rs over the sign.json verify rows; the keys are the binding's own
static void rs_signatures_json() {
    json R = vec("rs_signatures.json");
    for (auto& r : R["rows"]) {
        uint16_t kind = r["kind"].get<uint16_t>();
        if ((kind == 0x0132 || kind == 0x0135) && !falcon()) continue;
        Key k = W(r["mnemonic"].get<std::string>()).uaKey(kind, r["account"].get<uint32_t>(), r["index"].get<uint32_t>());
        std::string ctx = r["name"].get<std::string>() + " " + r["role"].get<std::string>();
        CHECK(hx(k.keyData()) == r["keyData"].get<std::string>(), ctx);
        CHECK(hx(uaMessage(kind, bytes(r["purposeTag"]), bytes(r["digest"]))) == r["uaMsg"].get<std::string>(), ctx);
        Bytes sig = k.signUa(bytes(r["purposeTag"]), bytes(r["digest"]));
        if (kind != 0x0132 && kind != 0x0135) CHECK(sig.size() == bytes(r["signature"]).size(), ctx);
        CHECK(sig != bytes(r["signature"]) || DETERMINISTIC.count(kind), ctx + ": randomized");
    }
}

// --- kem.json --------------------------------------------------------------------------------------------------------------

static void kem_json() {
    json K = vec("kem.json");
    for (auto& r : K["keys"]) CHECK(hx(kem_of(r).kemPk()) == r["kemPk"].get<std::string>(), r["kind"].dump());
    int refusals = 0;
    for (auto& r : K["refusals"]) {  // decimal strings (a version may be 2^64)
        auto num = [&](const char* f) { return u64(r[f]); };
        if (!r.contains("mnemonic") || (r["version"].is_string() && r["version"].get<std::string>().size() > 19))
            continue;  // the msig row: no wallet handle; 2^64: no uint64_t
        Key k = W(r["mnemonic"].get<std::string>()).uaKey(uint16_t(num("kind")), uint32_t(num("account")), uint32_t(num("index")));
        CHECK(code_of([&] { k.kemKey(num("version")); }) == "UA" + r["error"].get<std::string>(), r["reason"].get<std::string>());
        ++refusals;
    }
    CHECK(refusals == 9, "kem refusal rows");
    for (auto& r : K["encapsRefusals"])
        CHECK(code_of([&] { kemEncaps(bytes(r["kemPk"])); }) == "UA" + r["error"].get<std::string>(), r["id"].get<std::string>());
    KemKey kk = kem_of(K["keys"][0]);
    Encapsulated e = kemEncaps(bytes(K["keys"][0]["kemPk"]));
    CHECK(e.mlkemCt.size() == 1568 && e.x25519Eph.size() == 32, "encaps lengths");
    Secret ss = kk.decaps(e.mlkemCt, e.x25519Eph);
    CHECK(ss.copy() == e.ss.copy(), "encaps / decaps round trip");
    for (auto& r : K["decaps"]) {
        Bytes eph = bytes(r["x25519Eph"]);
        std::string id = r["id"].get<std::string>();
        if (eph.size() != 32) continue;  // a 31-byte E: the binding's length check (UAArgument) runs first
        if (r.contains("error") && !r["error"].is_null()) {
            CHECK(code_of([&] { kem_of(r["key"]).decaps(bytes(r["mlkemCt"]), eph); }) == "UA" + r["error"].get<std::string>(), id);
        } else {
            CHECK(hx(kem_of(r["key"]).decaps(bytes(r["mlkemCt"]), eph).copy()) == r["ss"].get<std::string>(), id);
        }
    }
    KemKey eph = KemKey::ephemeral();
    CHECK(eph.kemPk().size() == 1601 && eph.kemPk()[0] == 1, "ephemeral");
}

// --- seal.json -------------------------------------------------------------------------------------------------------------

static void seal_json() {
    json S = vec("seal.json");
    for (auto& r : S["seal"]) {
        if (!r["recipient"].contains("kind")) continue;  // an ephemeral recipient from a fixed seed: under `vectors` only
        KemKey kk = kem_of(r["recipient"]);
        std::string id = r["id"].get<std::string>();
        Sealed s{bytes(r["mlkemCt"]), bytes(r["x25519Eph"]), bytes(r["ciphertext"])};
        CHECK(kk.open(r["purpose"], bytes(r["aad"]), s).copy() == bytes(r["pt"]), id);
        Sealed fresh = seal(bytes(r["kemPk"]), r["purpose"], bytes(r["aad"]), bytes(r["pt"]));
        CHECK(fresh.mlkemCt.size() == 1568 && fresh.ciphertext.size() == bytes(r["pt"]).size() + 16, id);
        CHECK(kk.open(r["purpose"], bytes(r["aad"]), fresh).copy() == bytes(r["pt"]), id + ": fresh seal");
    }
    json base;
    for (auto& r : S["seal"])
        if (r["id"] == S["refusals"]["base"]) base = r;
    for (auto& r : S["refusals"]["rows"]) {
        Bytes wire = bytes(r.value("wire", base["wire"]));
        if (wire[0] != 1 || wire[1] != 1) continue;  // version / scheme 2: the named fields carry neither
        KemKey kk = kem_of(r.value("key", S["refusals"]["key"]));
        Bytes aad = bytes(r.value("aad", base["aad"]));
        Sealed s{Bytes(wire.begin() + 2, wire.begin() + 2 + 1568), Bytes(wire.begin() + 1570, wire.begin() + 1602), Bytes(wire.begin() + 1602, wire.end())};
        CHECK(code_of([&] { kk.open(r.value("purpose", base["purpose"].get<std::string>()), aad, s); }) == "UA" + r["error"].get<std::string>(),
              r["id"].get<std::string>());
    }
    for (auto& r : S["argumentRefusals"])
        CHECK(code_of([&] { seal(bytes(S["seal"][0]["kemPk"]), r["purpose"], {}, Bytes(r["ptLength"].get<size_t>())); }) ==
                  "UA" + r["error"].get<std::string>(),
              r["id"].get<std::string>());
    int n = 0;
    for (auto& r : S["containers"]) {
        if (r["opener"].contains("session")) continue;
        KemKey kk = kem_of(r["opener"]["kem"]);
        CHECK(kk.openContainer(r["container"].dump(), r["expect"].dump(), dump(r.value("members", json())), dump(r.value("accepted", json()))).copy() ==
                  bytes(r["pt"]),
              r["id"].get<std::string>());
        if (r.contains("accepted"))
            CHECK(code_of([&] { kk.openContainer(r["container"].dump(), r["expect"].dump(), dump(r.value("members", json())), ""); }) ==
                      "UAContainerSender",
                  "msig without accepted");
        ++n;
    }
    CHECK(n == 3, "containers");
    n = 0;
    for (auto& r : S["acceptance"]) {
        if (r.contains("link")) continue;
        KemKey kk = kem_of(r["opener"]["kem"]);
        std::string members = dump(r.value("members", json())), accepted = dump(r.value("accepted", json()));
        std::string got = code_of([&] {
            if (r.value("restore", false)) {
                Secret b39;
                Wallet::restoreBackup(kk, r["container"].dump(), r["expect"].dump(), members, accepted, b39);
            } else {
                kk.openContainer(r["container"].dump(), r["expect"].dump(), members, accepted);
            }
        });
        std::string want = r.contains("error") && !r["error"].is_null() ? "UA" + r["error"].get<std::string>() : "";
        CHECK(got == want, r["id"].get<std::string>());
        ++n;
    }
    CHECK(n == 28, "acceptance rows");
}

static void backup_link_restore() {
    json K = vec("kem.json"), S = vec("seal.json");
    Wallet w = wallet_of("twelve_words");
    Key sender = w.uaKey(0x0102, 0, 0);
    w.uaKey(0x0101, 0, 1);
    Key rec = W("pq_kat").uaKey(0x0130, 0, 0);
    Bytes pk = bytes(K["keys"][0]["kemPk"]);
    std::vector<std::string> cs = w.backupSeal(sender, {Recipient{0x0130, rec.keyData(), 0, pk, false}, Recipient{0, {}, 0, pk, true}});
    CHECK(cs.size() == 2, "two containers");
    json expect = {{"purpose", "scaas/backup/v1"}, {"sender", {{"ua", hx(sender.ua())}}}, {"recipient", {{"ua", hx(rec.ua())}, {"version", 0}}}};
    Secret b39;
    auto r = Wallet::restoreBackup(kem_of(K["keys"][0]), cs[0], expect.dump(), "", "", b39);
    CHECK(r.has_value(), "installed");
    CHECK(r->uaKey(0x0102, 0, 0).keyData() == sender.keyData(), "restored key");
    json m = json::parse(r->manifestJson());
    CHECK(m["backupGeneration"] == 1 && m["entries"].size() == 2, "manifest");
    Secret b2;
    CHECK(!r->restoreBackupOver(kem_of(K["keys"][0]), cs[0], expect.dump(), "", "", b2).has_value(), "an equal generation installs nothing");
    w.backupSeal(sender, {Recipient{0x0130, rec.keyData(), 0, pk, false}});  // generation 2 on w
    Secret b3;
    CHECK(code_of([&] { w.restoreBackupOver(kem_of(K["keys"][0]), cs[0], expect.dump(), "", "", b3); }) == "UABackupRollback", "rollback");
    Secret b4;
    CHECK(w.restoreBackupRollback(kem_of(K["keys"][0]), cs[0], expect.dump(), "", "", b4).has_value(), "rollback by its own name");
    CHECK(code_of([&] { w.backupSeal(W("pq_kat").nativeKey("evm", 0), {Recipient{0, {}, 0, pk, true}}); }) == "UAArgument", "native sender");
    // link: the existing device seals, the new device installs once
    LinkSession s = LinkSession::create();
    CHECK(s.kemPk().size() == 1601 && s.shortCode().size() == 8, "session");
    std::string c = w.linkSeal(sender, s.kemPk(), s.shortCode());
    json lexp = {{"purpose", "scaas/link/v1"}, {"sender", {{"ua", hx(sender.ua())}}}, {"recipient", {{"kemPkHash", hx(keccak256(s.kemPk()))}}}};
    Secret b5;
    Wallet linked = Wallet::fromLink(s, c, lexp.dump(), "", "", b5);
    CHECK(linked.uaKey(0x0102, 0, 0).keyData() == sender.keyData(), "linked key");
    Secret b6;
    CHECK(code_of([&] { Wallet::fromLink(s, c, lexp.dump(), "", "", b6); }) == "UAKeyRevoked", "the session is consumed");
    CHECK(code_of([&] { s.kemPk(); }) == "UAKeyRevoked", "consumed session");
    LinkSession s2 = LinkSession::create();
    std::string wrong = s2.shortCode() == "00000000" ? "00000001" : "00000000";
    std::string c2 = w.linkSeal(sender, s2.kemPk(), wrong);
    json lexp2 = {{"purpose", "scaas/link/v1"}, {"sender", {{"ua", hx(sender.ua())}}}, {"recipient", {{"kemPkHash", hx(keccak256(s2.kemPk()))}}}};
    Secret b7;
    CHECK(code_of([&] { Wallet::fromLink(s2, c2, lexp2.dump(), "", "", b7); }) == "UASealOpen", "a wrong short code");
    for (auto& r : S["containers"]) {
        if (!r["opener"].contains("session")) continue;
        LinkSession s3 = LinkSession::create();
        json e3 = r["expect"];
        e3["recipient"] = {{"kemPkHash", hx(keccak256(s3.kemPk()))}};
        Secret b8;
        CHECK(code_of([&] { Wallet::fromLink(s3, r["container"].dump(), e3.dump(), "", "", b8); }) == "UAContainerReplay", "outside the window");
    }
}

// --- vault.json, rs_vault.json ---------------------------------------------------------------------------------------------

static Wallet open_row(const json& v, const json& u) {
    Secret pin(u.contains("pin") ? u["pin"].get<std::string>() : ""), prf(u.contains("prfOutput") ? bytes(u["prfOutput"]) : Bytes()), b39;
    return Wallet::openVault(v.dump(), pin, prf, b39);
}
static void vault_json() {
    json V = vec("vault.json");
    std::map<std::string, std::string> by_entropy;
    for (auto& m : KEYS["mnemonics"])
        if (m["passphrase"] == "") by_entropy[m["entropy"].get<std::string>()] = m["id"].get<std::string>();
    for (auto& r : V["vaults"]) {
        Wallet w = open_row(r["vault"], r["unlock"]);
        CHECK(w.uaKey(0x0102, 0, 0).keyData() == W(by_entropy.at(r["plaintext"].get<std::string>())).uaKey(0x0102, 0, 0).keyData(),
              r["id"].get<std::string>());
    }
    for (auto& r : V["refusals"])
        CHECK(code_of([&] { open_row(r["vault"], r["unlock"]); }) == "UA" + r["error"].get<std::string>(), r["id"].get<std::string>());
    json prfRow, pinRow = V["vaults"][0];
    for (auto& r : V["vaults"])
        if (r["unlock"].contains("prfOutput")) prfRow = r;
    Secret n1, n2, n3;
    CHECK(code_of([&] { Wallet::openVault(prfRow["vault"].dump(), n1, n2, n3); }) == "UAArgument", "neither");
    Secret p1("not the passphrase"), f1(bytes(prfRow["unlock"]["prfOutput"])), z1;
    Wallet::openVault(prfRow["vault"].dump(), p1, f1, z1);  // both: PRF first
    Secret p2(pinRow["unlock"]["pin"].get<std::string>()), f2(Bytes(32)), z2;
    CHECK(code_of([&] { Wallet::openVault(prfRow["vault"].dump(), p2, f2, z2); }) == "UAVaultOpen", "both: a wrong PRF");
    // seal, rewrap, enable PRF
    const Wallet& w = W("twelve_words");
    Secret s1("correct horse 9");
    std::string v = w.sealVault(s1);
    Secret weak("12345678");
    CHECK(code_of([&] { w.sealVault(weak); }) == "UAArgument", "new-passphrase policy");
    CHECK(!vault::needsRewrap(v), "fresh vault");
    Secret o("correct horse 9"), nw("battery staple 7");
    std::string v2 = vault::rewrapPin(v, o, nw);
    Bytes prf32(32);
    for (size_t i = 0; i < 32; ++i) prf32[i] = uint8_t(i);
    Secret pp("battery staple 7"), pf(prf32);
    std::string v3 = vault::enablePrf(v2, pp, pf, "cred-1", str("salt"));
    Bytes want = W("twelve_words").uaKey(0x0102, 0, 0).keyData();
    CHECK(open_row(json::parse(v), {{"pin", "correct horse 9"}}).uaKey(0x0102, 0, 0).keyData() == want, "sealed");
    CHECK(open_row(json::parse(v2), {{"pin", "battery staple 7"}}).uaKey(0x0102, 0, 0).keyData() == want, "rewrapped");
    CHECK(open_row(json::parse(v3), {{"prfOutput", hx(prf32)}}).uaKey(0x0102, 0, 0).keyData() == want, "PRF");
    CHECK(code_of([&] { open_row(json::parse(v2), {{"pin", "correct horse 9"}}); }) == "UAVaultOpen", "the old passphrase");
}

static void rs_vault_json() {
    json R = vec("rs_vault.json"), K = vec("kem.json");
    for (auto& r : R["vaults"]) {
        Wallet w = open_row(r["vault"], r["unlock"]);
        CHECK(w.uaKey(0x0102, 0, 0).keyData() == W(r["mnemonic"].get<std::string>()).uaKey(0x0102, 0, 0).keyData(), r["id"].get<std::string>());
    }
    for (auto& b : R["backups"]) {
        auto& s = b["sender"];
        Key sender = W(s["mnemonic"].get<std::string>()).uaKey(s["kind"].get<uint16_t>(), s["account"].get<uint32_t>(), s["index"].get<uint32_t>());
        CHECK(hx(sender.ua()) == b["senderUa"].get<std::string>(), "sender");
        KemKey kk = kem_of(b["opener"]["kem"]);
        Bytes rua = W(b["opener"]["kem"]["mnemonic"].get<std::string>()).uaKey(b["opener"]["kem"]["kind"].get<uint16_t>(), 0, 0).ua();
        json expect = {{"purpose", "scaas/backup/v1"}, {"sender", {{"ua", b["senderUa"]}}}, {"recipient", {{"ua", hx(rua)}, {"version", 0}}}};
        Secret b39;
        auto w = Wallet::restoreBackup(kk, b["container"].dump(), expect.dump(), "", "", b39);
        CHECK(w.has_value(), b["id"].get<std::string>());
        json m = json::parse(w->manifestJson());
        CHECK(m["backupGeneration"] == b["generation"], "generation");
        CHECK(m["imports"].size() == b["secrets"].size(), "imports");
        CHECK(w->uaKey(0x0102, 0, 0).keyData() == sender.keyData(), "restored");
        w->importedKey("evm", 0);
    }
}

// --- custody ---------------------------------------------------------------------------------------------------------------

static void custody() {
    Wallet w = wallet_of("twelve_words");
    Secret pin("correct horse 9");
    std::string v = w.sealVault(pin);
    Key k = w.uaKey(0x0101, 0, 0);
    Bytes metatx = purposeTag("metatx");
    Bytes before = k.signUa(metatx, Bytes(32));
    w.lock();
    CHECK(code_of([&] { k.signUa(metatx, Bytes(32)); }) == "UAKeyRevoked", "after lock");
    CHECK(code_of([&] { w.uaKey(0x0101, 0, 0); }) == "UAWalletLocked", "locked wallet");
    auto mp = w.memoryProtection();
    CHECK(mp.chunks == 0 && mp.locked == 0 && mp.noDump == 0, "locked: no chunks");
    Secret p2("correct horse 9"), f, b;
    w.unlock(v, p2, f, b);
    CHECK(code_of([&] { k.signUa(metatx, Bytes(32)); }) == "UAKeyRevoked", "unlock does not revive");
    CHECK(w.uaKey(0x0101, 0, 0).signUa(metatx, Bytes(32)) == before, "a new handle signs");
    Secret p3("correct horse 9"), f3, b3;
    CHECK(code_of([&] { w.unlock(v, p3, f3, b3); }) == "UAArgument", "already unlocked");
    // imported key: back after unlock through its label vault
    Bytes raw(32);
    for (size_t i = 0; i < 32; ++i) raw[i] = uint8_t(i + 1);
    Secret imp(raw);
    Key ik = w.importNativeKey("evm", imp);
    Bytes d(32, 7);
    Bytes sig = ik.signDigestRaw(d);
    Secret lp("correct horse 9");
    std::string label = w.sealLabelVault("native-import:evm:0", lp);
    w.lock();
    CHECK(code_of([&] { w.importedKey("evm", 0); }) == "UAWalletLocked", "imported while locked");
    Secret p4("correct horse 9"), f4, b4;
    w.unlock(v, p4, f4, b4);
    CHECK(code_of([&] { w.importedKey("evm", 0); }) == "UAArgument", "not held before its vault opens");
    Secret lp2("correct horse 9"), lf;
    w.openLabelVault(label, lp2, lf);
    CHECK(w.importedKey("evm", 0).signDigestRaw(d) == sig, "the same key");
    CHECK(code_of([&] { ik.signDigestRaw(d); }) == "UAKeyRevoked", "the old handle stays revoked");
    // children after the wallet's destruction
    Key k2 = W("pq_kat").uaKey(0x0102, 0, 0);
    std::optional<Key> child;
    std::optional<KemKey> kchild;
    {
        Wallet tmp = wallet_of("pq_kat");
        child.emplace(tmp.uaKey(0x0130, 0, 0));
        kchild.emplace(child->kemKey(0));
    }
    CHECK(code_of([&] { child->signUa(metatx, Bytes(32)); }) == "UAKeyRevoked", "child after wallet free");
    CHECK(code_of([&] { kchild->decaps(Bytes(1568), Bytes(32, 1)); }) == "UAKeyRevoked", "KEM child after wallet free");
    CHECK(child->keyData().size() == 1312, "public data stays readable");
    // another wallet's vault
    Wallet w5 = wallet_of("twelve_words");
    w5.uaKey(0x0102, 0, 0);
    Secret op("correct horse 9");
    std::string other = W("pq_kat").sealVault(op);
    w5.lock();
    Secret p5("correct horse 9"), f5, b5;
    CHECK(code_of([&] { w5.unlock(other, p5, f5, b5); }) == "UAWalletMismatch", "another wallet's vault");
    // memory protection, manifest, discover
    auto m2 = W("pq_kat").memoryProtection();
    CHECK(m2.chunks >= 1 && m2.locked <= m2.chunks && m2.noDump <= m2.chunks, "memory protection");
    if (features() & feature::kMlock) CHECK(m2.noDump == m2.chunks, "no-dump");
    json disc = json::parse(W("pq_kat").discoverCandidates(0x0102, 0, 3));
    CHECK(disc.size() == 3 && disc[0]["index"] == 0, "discover");
    for (auto& r : KEYS["ua"])
        if (r["mnemonic"] == "pq_kat" && r["kind"] == 0x0102 && r["account"] == 0 && r["index"] == 0) CHECK(disc[0]["ua"] == r["ua"], "discover ua");
}

static void seed_backup_sequence() {
    auto [w, sb] = Wallet::generate();
    Secret phrase = sb.reveal();
    std::vector<std::string> words;
    std::string s(phrase.view());
    for (size_t p = 0, q; p < s.size(); p = q + 1) {
        q = s.find(' ', p);
        if (q == std::string::npos) q = s.size();
        words.push_back(s.substr(p, q - p));
    }
    CHECK(words.size() == 24, "24 words");
    CHECK(code_of([&] { sb.reveal(); }) == "UAArgument", "shown once");
    CHECK(sb.take().empty(), "not before the words are confirmed");
    auto pos = sb.challenge();
    CHECK(pos.size() == 3 && 1 <= pos[0] && pos[0] < pos[1] && pos[1] < pos[2] && pos[2] <= 24, "positions");
    Secret x("x"), y("y"), z("z");
    CHECK(!sb.verify(x, y, z), "wrong answers");
    pos = sb.challenge();
    Secret a1(words[pos[0] - 1]), a2(words[pos[1] - 1]), a3(words[pos[2] - 1]);
    CHECK(sb.verify(a1, a2, a3), "right answers");
    CHECK(all_zero(a1.data(), a1.size()) && all_zero(a3.data(), a3.size()), "answers wiped");
    Secret e = sb.take();
    CHECK(e.size() == 32, "entropy once");
    CHECK(sb.take().empty(), "handed out once");
    Secret ws(s), none;
    Wallet w2 = Wallet::fromMnemonic(ws, none);
    CHECK(w2.uaKey(0x0102, 0, 0).keyData() == w.uaKey(0x0102, 0, 0).keyData(), "the phrase is the wallet's");
}

// --- errors never echo an input ---------------------------------------------------------------------------------------------

static void error_strings_never_contain_an_input() {
    const std::vector<std::string> secrets = {"zebrasecretword", "Pa55-word-Secret", "SECRETvalue0xdead", "deadbeefcafe1234"};
    const Wallet& w = W("pq_kat");
    Key evm = w.nativeKey("evm", 0);
    auto words = MN.at("pq_kat")["words"].get<std::string>();
    std::vector<std::function<void()>> calls = {
        [&] { Secret a(words.substr(0, words.rfind(' ')) + " zebrasecretword"), b("Pa55-word-Secret"); Wallet::fromMnemonic(a, b); },
        [&] { Secret a("Pa55-word-Secret"), b, c("zebrasecretword"); Wallet::openVault(R"({"v":1,"label":"Pa55-word-Secret"})", a, b, c); },
        [&] { evm.signTyped(R"({"types":{"EIP712Domain":[]},"primaryType":"SECRETvalue0xdead","domain":{},"message":{}})",
                            R"({"check":"Payment","account":"0xdeadbeefcafe1234"})"); },
        [&] { evm.signTransaction(R"({"type":2,"chainId":"SECRETvalue0xdead"})"); },
        [&] { w.zetherKey(60, 0, 7).call("zebrasecretword", "{}"); },
        [&] { w.pqzKey(0, 0).call("dec", R"({"ct":"0xdeadbeefcafe1234","window":"SECRETvalue0xdead"})"); },
        [&] { Secret s(str("deadbeefcafe1234")); w.importNativeKey("evm", s); },
        [&] { uaSig(R"({"purpose":"zebrasecretword"})", {}); },
    };
    for (size_t i = 0; i < calls.size(); ++i) {
        std::string what;
        try {
            calls[i]();
        } catch (const Error& e) {
            what = e.what();
        }
        CHECK(!what.empty(), "call " + std::to_string(i) + " fails");
        for (auto& s : secrets)
            for (size_t j = 0; j + 6 <= s.size(); ++j) CHECK(what.find(s.substr(j, 6)) == std::string::npos, what);
    }
}

// --- AEAD, HKDF, HMAC ------------------------------------------------------------------------------------------------------

static void aead_hkdf_hmac() {
    CHECK(hx(hmacSha256(Bytes(20, 0x0b), str("Hi There"))) == "0xb0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "RFC 4231");
    Bytes salt, info;
    for (int i = 0; i < 13; ++i) salt.push_back(uint8_t(i));
    for (int i = 0xf0; i < 0xfa; ++i) info.push_back(uint8_t(i));
    CHECK(hx(hkdfSha256(Bytes(22, 0x0b), salt, info, 42).copy()) ==
              "0x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
          "RFC 5869 A.1");
    CHECK(code_of([] { hkdfSha256(str("k"), {}, {}, 255 * 32 + 1); }) == "UAArgument", "hkdf length");
    Bytes key(32), nonce(12), data = str("plaintext");
    for (uint32_t alg : {kAeadAes256Gcm, kAeadAes256GcmSiv}) {
        Bytes ct = aeadSeal(alg, key, nonce, str("aad"), data);
        CHECK(ct.size() == data.size() + 16, "tag");
        CHECK(aeadOpen(alg, key, nonce, str("aad"), ct).copy() == data, "round trip");
        ct.back() ^= 1;
        CHECK(code_of([&] { aeadOpen(alg, key, nonce, str("aad"), ct); }) == "UAAead", "a flipped tag");
    }
    CHECK(code_of([&] { aeadSeal(3, key, nonce, {}, data); }) == "UAArgument", "alg");
}

// --- Zether facade ---------------------------------------------------------------------------------------------------------

static void zether_facade() {
    CHECK(features() & feature::kZether, "zether in the build");
    json Z = vec("zether.json");
    json R33 = load_json(std::string(SCAAS_UA_VECTORS_DIR) + "/../../../clients/zether-prover/vectors/r33_keys.json");
    Secret mw(R33["mnemonic"].get<std::string>()), mp;
    Wallet w = Wallet::fromMnemonic(mw, mp);
    for (auto& r : R33["bls12381"]["keys"]) {
        std::string path = r["path"];  // m/12381/coin/account/use
        std::vector<uint32_t> part;
        for (size_t p = 0, q; p <= path.size(); p = q + 1) {
            q = path.find('/', p);
            if (q == std::string::npos) q = path.size();
            std::string t = path.substr(p, q - p);
            if (!t.empty() && std::isdigit(uint8_t(t[0]))) part.push_back(uint32_t(std::stoul(t)));
        }
        CHECK(part.size() == 4, path);
        ZetherKey k = w.zetherKey(part[1], part[2], part[3]);
        CHECK(hx(k.y()) == r["Y"].get<std::string>() && hx(k.ua()) == r["UA"].get<std::string>(), path);
    }
    CHECK(code_of([&] { w.zetherKey(60, 0, 9); }) == "UAArgument", "use 9");
    ZetherKey k = w.zetherKey(60, 0, kZetherUseConf);
    json pop = json::parse(k.call("pop", R"({"curve":"bls12381"})"));
    for (auto f : {"popDigest", "registrationDigest", "uaMsg"}) CHECK(pop[f] == R33["bls12381"]["keys"][0]["pop"][f], f);
    CHECK(code_of([&] { k.call("pop", R"({"key":{"seed":"0x11","coin":60,"account":0}})"); }) == "UAArgument", "a key field");
    CHECK(code_of([&] { k.call("verifyTransfer", "{}"); }) == "UAArgument", "verifiers are not exposed");
    // ARCH-POS-13 (T15c2, Fable P2-5): a release build has no raw decrypt; a well-formed `decrypt` / `checkBalance` of a
    // ciphertext is an unknown command
    json ct = json::parse(k.call("encrypt", json{{"curve", "bls12381"}, {"Y", hx(k.y())}, {"amount", 5}}.dump()));
    CHECK(ct.contains("C") && ct.contains("D"), "encrypt (positive control)");
    CHECK(code_of([&] { k.call("decrypt", json{{"curve", "bls12381"}, {"ct", ct}}.dump()); }) == "UAArgument",
          "no decrypt in a release build");
    CHECK(code_of([&] { k.call("checkBalance", json{{"curve", "bls12381"}, {"acc", ct}, {"balance", 5}}.dump()); }) == "UAArgument",
          "no checkBalance in a release build");
    for (auto& r : Z["cacheBox"]) {
        Secret a(MN.at(r["mnemonic"])["words"].get<std::string>()), b(MN.at(r["mnemonic"])["passphrase"].get<std::string>());
        Wallet zw = Wallet::fromMnemonic(a, b);
        ZetherKey zk = zw.zetherKey(r["coin"], r["account"], r["use"]);
        CHECK(hx(zk.y()) == r["Y"].get<std::string>() && hx(zk.ua()) == r["UA"].get<std::string>(), r["id"].get<std::string>());
        Secret pt = zk.openBalanceCache(r["box"].dump());
        CHECK(hx(pt.copy()) == r["plaintext"].get<std::string>(), r["id"].get<std::string>());
        CHECK(zk.openBalanceCache(zk.sealBalanceCache(pt.copy())).copy() == pt.copy(), "round trip");
    }
    for (auto& r : Z["cacheRefusals"]) {
        Secret a(MN.at(r["mnemonic"])["words"].get<std::string>()), b(MN.at(r["mnemonic"])["passphrase"].get<std::string>());
        Wallet zw = Wallet::fromMnemonic(a, b);
        CHECK(code_of([&] { zw.zetherKey(r["coin"], r["account"], r["use"]).openBalanceCache(r["box"].dump()); }) == "UAAead", r["id"].get<std::string>());
    }
    Bytes y = k.y();
    w.lock();
    CHECK(code_of([&] { k.call("pop", "{}"); }) == "UAKeyRevoked", "after lock");
    CHECK(k.y() == y, "public data stays readable");
}

// --- PQZ facade ------------------------------------------------------------------------------------------------------------

static void pqz_facade() {
    CHECK(features() & feature::kPqz && features() & feature::kPqzSetN2304Kmax4096, "pqz n2304-kmax4096 in the build");
    json set = json::parse(pqzSet());
    CHECK(set["set"] == "n2304-kmax4096" && set["pkLen"] == 18432, "set");
    pqzCheckSet(set.dump());
    json other = set;
    other["set"] = "n2048-kmax1024";
    CHECK(code_of([&] { pqzCheckSet(other.dump()); }) == "UAPqzSetMismatch", "another set");
    Wallet w = wallet_of("pq_kat");
    PqzKey k = w.pqzKey(0, 0);
    CHECK(k.pk().size() == 18432, "pk");
    json req = {{"proofSystemId", set["pqzlId"]}, {"kind", 0x0131}, {"ua", hx(Bytes(32, 0x11))}};
    std::string proof = k.call("proveRegister", req.dump());
    CHECK(!proof.empty() && proof.size() <= kPqzOutMax, "a proof within kPqzOutMax");
    CHECK(json::parse(proof)["stmt"].get<std::string>().size() > 2, "statement");
    json bad = req;
    bad["proofSystemId"] = hx(Bytes(32, 0xde));
    CHECK(code_of([&] { k.call("proveRegister", bad.dump()); }) == "UAPqzSetMismatch", "set mismatch");
    bad = req;
    bad["key"] = {{"seed32", hx(Bytes(32, 0x11))}};
    CHECK(code_of([&] { k.call("proveRegister", bad.dump()); }) == "UAArgument", "a key field");
    json e = json::parse(k.call("enc", json{{"pks", json::array({hx(k.pk())})}, {"values", json::array({123456})}}.dump()));
    // ARCH-POS-13 (T15c): a release build has no raw decrypt; a well-formed `dec` is an unknown command
    std::string ct = e["u"].get<std::string>() + e["vs"][0].get<std::string>().substr(2);
    CHECK(code_of([&] { k.call("dec", json{{"ct", ct}}.dump()); }) == "UAArgument", "no dec in a release build");
    std::string box = k.sealBalanceCache(str(R"({"v":1})"));
    CHECK(k.openBalanceCache(box).copy() == str(R"({"v":1})"), "cache box");
    CHECK(code_of([&] { w.pqzKey(0, 1).openBalanceCache(box); }) == "UAAead", "another key's box");
    Bytes pk = k.pk();
    w.lock();
    CHECK(code_of([&] { k.call("proveRegister", req.dump()); }) == "UAKeyRevoked", "after lock");
    CHECK(code_of([&] { w.exportPqzLeafRaw(0, 0); }) == "UAWalletLocked", "export while locked");
    CHECK(k.pk() == pk, "public data stays readable");
}

int main(int argc, char** argv) {
    std::map<std::string, void (*)()> tests{
        {"load_refuses_wrong_abi_or_features", load_refuses_wrong_abi_or_features},
        {"secret_buffer_wiped_after_call", secret_buffer_wiped_after_call},
        {"handle_freed_once", handle_freed_once},
        {"keys_json", keys_json},
        {"sign_json", sign_json},
        {"rs_signatures_json", rs_signatures_json},
        {"kem_json", kem_json},
        {"seal_json", seal_json},
        {"backup_link_restore", backup_link_restore},
        {"vault_json", vault_json},
        {"rs_vault_json", rs_vault_json},
        {"custody", custody},
        {"seed_backup_sequence", seed_backup_sequence},
        {"error_strings_never_contain_an_input", error_strings_never_contain_an_input},
        {"aead_hkdf_hmac", aead_hkdf_hmac},
        {"zether_facade", zether_facade},
        {"pqz_facade", pqz_facade}};
    if (argc != 2 || !tests.count(argv[1])) {
        std::fprintf(stderr, "usage: wallet_test <name>\n");
        return 2;
    }
    try {
        tests[argv[1]]();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "exception: %s\n", e.what());
        return 1;
    }
    return failures ? 1 : 0;
}
