// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-ua (C++ / cxx) against smartcontracts/vectors/ua/: mirrors clients/ua-rs/tests/vectors.rs. `vectors_test <name>`.
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <map>
#include <nlohmann/json.hpp>

#include "scaas_ua.hpp"

using nlohmann::json;
using namespace scaas::ua;

static int failures = 0;
#define CHECK(c, ctx)                                                                      \
    do {                                                                                   \
        if (!(c)) {                                                                        \
            std::fprintf(stderr, "%s:%d: %s [%s]\n", __FILE__, __LINE__, #c, std::string(ctx).c_str()); \
            ++failures;                                                                    \
        }                                                                                  \
    } while (0)

static json load(const char* name) {
    std::ifstream f(std::string(SCAAS_UA_VECTORS_DIR) + "/" + name);
    if (!f) { std::fprintf(stderr, "cannot open %s\n", name); std::exit(2); }
    return json::parse(f);
}
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
    for (auto c : b) { s += d[c >> 4]; s += d[c & 15]; }
    return s;
}
static uint16_t kind(const json& v) { return v.get<uint16_t>(); }
// the error code thrown by f ("" if it does not throw)
static std::string code_of(const std::function<void()>& f) {
    try { f(); } catch (const Error& e) { return e.code(); }
    return "";
}

static void table_groups_purposes_constants() {
    json k = load("kinds.json");
    auto table = kinds();
    CHECK(k["kinds"].size() == table.size(), "table size");
    for (auto& r : k["kinds"]) {
        uint16_t n = kind(r["kind"]);
        auto info = kindInfo(n);
        std::string name = info.name;
        CHECK(info.name == r["name"].get<std::string>(), name);
        CHECK(info.native == r["native"].get<bool>(), name);
        CHECK(info.lengths == r["lengths"].get<std::vector<size_t>>(), name);
        CHECK(info.group.has_value() == !r["group"].is_null(), name);
        if (info.group) CHECK(*info.group == r["group"].get<std::string>(), name);
        CHECK(isSigning(n) == r["signing"].get<bool>(), name);
        CHECK(isZether(n) == r["zether"].get<bool>(), name);
        CHECK(isMember(n, false) == r["member"].get<bool>(), name);
        CHECK(isMember(n, true) == r["memberHedera"].get<bool>(), name);
        CHECK(isNative(n) == info.native, name);
        if (info.native) {
            CHECK(code_of([&] { tag(n); }) == "UAKindNotDerived", name);
        } else {
            CHECK(kindTagString(n) == r["tag"].get<std::string>(), name);
            CHECK(hx(tag(n)) == r["TAG"].get<std::string>(), name);
        }
    }
    for (auto& r : k["groups"]) {
        auto g = r["group"].get<std::string>();
        CHECK(groupTagString(g) == r["tag"].get<std::string>(), g);
        CHECK(hx(*groupTag(g)) == r["GROUP"].get<std::string>(), g);
    }
    CHECK(!groupTag("nope") && !groupTagString("nope"), "unknown group");
    CHECK(k["purposes"].size() == 12, "purposes size");
    for (auto& r : k["purposes"]) CHECK(hx(purposeTag(r["purpose"])) == r["purposeTag"].get<std::string>(), r["purpose"].get<std::string>());
    CHECK(code_of([] { purposeTag("nope"); }) == "UAPurposeUnknown", "purpose");
    auto& c = k["constants"];
    CHECK(hx(msgTag()) == c["MSG_TAG"].get<std::string>(), "MSG_TAG");
    CHECK(hx(purposeTag("pop")) == c["POP_TAG"].get<std::string>(), "POP_TAG");
    // DOMAIN_TYPEHASH / UAAUTH_TYPEHASH / NAME_HASH are not exposed by the C++ API (keccak256 is internal); they are
    // covered through uaAuthDomainSeparator / uaAuthDigest in structures.
}

static void valid_rows() {
    json k = load("kinds.json");
    for (auto& r : k["valid"]) {
        uint16_t n = kind(r["kind"]);
        Bytes d = bytes(r["keyData"]);
        bool hn = r["hederaNative"].get<bool>();
        std::string name = r["name"].get<std::string>();
        CHECK(hx(deriveUA(n, d, hn)) == r["ua"].get<std::string>(), name);
        auto kh = keyHashOf(n, d);
        if (r["keyHash"].is_null()) CHECK(!kh, name);
        else CHECK(kh && hx(*kh) == r["keyHash"].get<std::string>(), name);
    }
}

static void invalid_rows() {
    json k = load("kinds.json");
    for (auto& r : k["invalid"]) {
        uint16_t n = kind(r["kind"]);
        Bytes d = bytes(r["keyData"]);
        bool hn = r["hederaNative"].get<bool>();
        CHECK(code_of([&] { validateKeyData(n, d, hn); }) == r["error"].get<std::string>(), r["reason"].get<std::string>());
    }
    // the reason label travels with UAKeyData
    try { validateKeyData(0x0101, Bytes(3), false); CHECK(false, "must throw"); }
    catch (const Error& e) { CHECK(e.code() == "UAKeyData" && !e.reason().empty(), e.what()); }
}

static void natives_native_space_canonical_ids() {
    json k = load("kinds.json");
    for (auto& r : k["natives"]) {
        Bytes id = nativeId(kind(r["kind"]), bytes(r["raw"]));
        CHECK(hx(id) == r["id"].get<std::string>(), "native id");
        CHECK(canonicalId(hx(id)) == r["canonical"].get<std::string>(), "canonical");
    }
    for (auto& r : k["nativeInvalid"])
        CHECK(code_of([&] { nativeId(kind(r["kind"]), bytes(r["raw"])); }) == r["error"].get<std::string>(), "nativeInvalid");
    for (auto& r : k["nativeSpace"]) CHECK(inNativeSpace(bytes(r["id"])) == r["inNativeSpace"].get<bool>(), "nativeSpace");
    for (auto& r : k["canonicalIds"]) {
        auto in = r["input"].get<std::string>();
        if (r.contains("canonical")) CHECK(canonicalId(in) == r["canonical"].get<std::string>(), in);
        else CHECK(code_of([&] { canonicalId(in); }) == r["error"].get<std::string>(), in);
    }
}

static void messages() {
    json k = load("kinds.json");
    for (auto& r : k["messages"]) {
        Bytes p = purposeTag(r["purpose"]);
        CHECK(hx(p) == r["purposeTag"].get<std::string>(), "purposeTag");
        CHECK(hx(uaMessage(kind(r["kind"]), p, bytes(r["digest"]))) == r["uaMsg"].get<std::string>(), "uaMsg");
    }
}

static void structures() {
    json s = load("structures.json");
    for (auto& p : s["pop"]) {
        auto& c = s["contexts"][p["context"].get<std::string>()];
        uint64_t chain = c["chainId"].get<uint64_t>();  // context E is 2^40+7
        CHECK(hx(chainKeyHash(chain)) == p["chainKeyHash"].get<std::string>(), "chainKeyHash");
        CHECK(hx(popDigest(chain, bytes(c["chainUid"]), bytes(c["registry"]), bytes(p["ua"]), bytes(p["authRef"]))) ==
                  p["popDigest"].get<std::string>(), "popDigest");
    }
    for (auto& a : s["uaAuth"]) {
        auto& c = s["contexts"][a["context"].get<std::string>()];
        Domain d{a["generation"].get<uint32_t>(), c["chainId"].get<uint64_t>(), bytes(c["registry"]), bytes(c["chainUid"])};
        CHECK(hx(uaAuthDomainSeparator(d)) == a["domainSeparator"].get<std::string>(), "domainSeparator");
        CHECK(hx(uaAuthDigest(d, bytes(a["ua"]), bytes(a["purposeTag"]), bytes(a["digest"]))) == a["uaAuthDigest"].get<std::string>(), "uaAuthDigest");
    }
    for (auto& m : s["member"])
        CHECK(hx(memberDigest(bytes(m["structureUa"]), bytes(m["uaMsg"]))) == m["memberDigest"].get<std::string>(), "memberDigest");
    // malformed input is an error, not a crash
    CHECK(code_of([] { memberDigest(Bytes(3), Bytes(32)); }) == "UAKeyData", "short digest");
    // non-UTF-8 text stays inside the documented error contract
    const std::string bad("\xff\xfe");
    CHECK(code_of([&] { purposeTag(bad); }) == "UAPurposeUnknown", "non-UTF-8 purpose");
    CHECK(code_of([&] { canonicalId(bad); }) == "UAIdFormat", "non-UTF-8 id");
    CHECK(!groupTag(bad) && !groupTagString(bad), "non-UTF-8 group");
    CHECK(encodeMsig(2, {{0x0001, Bytes(32, 1), 1}}).size() == 4 + 36, "encodeMsig size");
}

int main(int argc, char** argv) {
    std::map<std::string, void (*)()> tests{
        {"table_groups_purposes_constants", table_groups_purposes_constants}, {"valid_rows", valid_rows},
        {"invalid_rows", invalid_rows}, {"natives_native_space_canonical_ids", natives_native_space_canonical_ids},
        {"messages", messages}, {"structures", structures}};
    if (argc != 2 || !tests.count(argv[1])) { std::fprintf(stderr, "usage: vectors_test <name>\n"); return 2; }
    try { tests[argv[1]](); } catch (const std::exception& e) { std::fprintf(stderr, "exception: %s\n", e.what()); return 1; }
    return failures ? 1 : 0;
}
