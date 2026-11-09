// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-ua (C++ / cxx) against smartcontracts/vectors/ua/: mirrors clients/ua-rs/tests/vectors.rs. `vectors_test <name>`.
#include <algorithm>
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
        CHECK(isPqzHolder(n) == r["pqzHolder"].get<bool>(), name);
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
    for (auto& r : k["schemes"]) {  // schemes are not kinds: tag and keyHash only
        uint16_t n = kind(r["kind"]);
        CHECK(kindTagString(n) == r["tag"].get<std::string>(), "scheme tag");
        CHECK(hx(tag(n)) == r["TAG"].get<std::string>(), "scheme TAG");
        CHECK(code_of([&] { kindInfo(n); }) == "UAKindUnknown", "scheme is no kind");
        CHECK(code_of([&] { uaOf(n, {}); }) == "UAKindNotDerived", "scheme uaOf");
        CHECK(code_of([&] { validateKeyData(n, {}, false); }) == "UAKindNotDerived", "scheme validate");
    }
    CHECK(hx(*keyHashOf(0x0142, bytes(k["pqzKey"]))) == k["pqzKeyHash"].get<std::string>(), "pqzKeyHash");
    for (auto& r : k["groups"]) {
        auto g = r["group"].get<std::string>();
        CHECK(groupTagString(g) == r["tag"].get<std::string>(), g);
        CHECK(hx(*groupTag(g)) == r["GROUP"].get<std::string>(), g);
    }
    CHECK(!groupTag("nope") && !groupTagString("nope"), "unknown group");
    CHECK(k["purposes"].size() == 15, "purposes size");  // 14 purposes, `pop` has v1 and v2
    for (auto& r : k["purposes"]) {
        CHECK(hx(purposeTag(r["purpose"], r["version"].get<uint32_t>())) == r["purposeTag"].get<std::string>(), r["purpose"].get<std::string>());
        if (r["version"] == 1) CHECK(hx(purposeTag(r["purpose"])) == r["purposeTag"].get<std::string>(), r["purpose"].get<std::string>());
    }
    CHECK(code_of([] { purposeTag("metatx", 2); }) == "UAPurposeUnknown", "metatx v2");
    CHECK(code_of([] { purposeTag("pop", 3); }) == "UAPurposeUnknown", "pop v3");
    CHECK(code_of([] { purposeTag("pop", 0); }) == "UAPurposeUnknown", "pop v0");
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

// ua-mtx-merge spec §6, MD-9: every row of id_display.json, and a row for every kind of the table.
static void id_display_rows() {
    json d = load("id_display.json");
    for (auto& r : d["rows"]) {
        auto id = r["id"].get<std::string>();
        auto name = r["name"].get<std::string>();
        uint16_t k = kind(r["kind"]);
        if (r.contains("display")) {
            auto& w = r["display"];
            CHECK(idDisplay(id, k) == (w.contains("address") ? w["address"] : w["urn"]).get<std::string>(), name);
        } else {
            CHECK(code_of([&] { idDisplay(id, k); }) == r["error"].get<std::string>(), name);
        }
    }
    for (auto& info : kinds()) {
        bool has = false;
        for (auto& r : d["rows"])
            has = has || (kind(r["kind"]) == info.kind && (info.native ? r.value("error", "") == "UAKindNotDerived"
                                                                        : r.contains("display") && r["display"].contains("urn")));
        CHECK(has, std::string("no row for ") + std::string(info.name));
    }
}

static void messages() {
    json k = load("kinds.json");
    for (auto& r : k["messages"]) {
        Bytes p = purposeTag(r["purpose"], r["version"].get<uint32_t>());  // each row carries its purpose `version` (A4-c1)
        CHECK(hx(p) == r["purposeTag"].get<std::string>(), "purposeTag");
        CHECK(hx(uaMessage(kind(r["kind"]), p, bytes(r["digest"]))) == r["uaMsg"].get<std::string>(), "uaMsg");
    }
}

static void structures() {
    json s = load("structures.json");
    Bytes pk = bytes(load("kinds.json")["pqzKey"]);
    Bytes proof(32, 7);
    for (auto& p : s["pop"]) {
        Bytes ua = bytes(p["ua"]), kh = bytes(p["pqzKeyHash"]), kr = bytes(p["kemRecordHash"]);
        CHECK(hx(portableRecordDigest(ua, kind(p["kind"]), kh, kr)) == p["portableRecordDigest"].get<std::string>(), "portableRecordDigest");
        CHECK(hx(registrationDigest(ua, kind(p["kind"]), kh, kr, bytes(p["pqzPopHash"]))) == p["registrationDigest"].get<std::string>(), "registrationDigest");
    }
    CHECK(hx(chainKeyHash(0x10000000007ULL)) == "0x6e45d591a544f53396f6e86d49f5809196c5725f9d99dbd2ca97f9925c7ce950", "chainKeyHash");  // keccak256("evm:1099511627783")
    for (auto& p : s["pqzReg"]) {
        Bytes ua = bytes(p["ua"]), kem = bytes(p["kemRecordHash"]), h = *keyHashOf(0x0142, pk);
        CHECK(hx(h) == p["pqzKeyHash"].get<std::string>(), "pqzReg keyHash");
        Bytes portable = portableRecordDigest(ua, kind(p["kind"]), h, kem);
        CHECK(hx(portable) == p["portableRecordDigest"].get<std::string>(), "pqzReg portable");
        CHECK(hx(uaMessage(0x0142, purposeTag("pop", 2), portable)) == p["pqzRegMessage"].get<std::string>(), "pqzReg message");
        if (kem != kemRecordHash(ua, 0, {})) continue;  // the row's KEM record hash is opaque; the real records are in portable.json
        CHECK(hx(pqzRegMessage(kind(p["kind"]), ua, pk)) == p["pqzRegMessage"].get<std::string>(), "pqzRegMessage");
        auto got = holderPopMessage(kind(p["kind"]), ua, {}, pk, std::nullopt, proof);
        CHECK(hx(got.pqzKeyHash) == p["pqzKeyHash"].get<std::string>(), "holder pqzKeyHash");
        CHECK(hx(got.portableRecordDigest) == p["portableRecordDigest"].get<std::string>(), "holder portable");
        CHECK(code_of([&] { holderPopMessage(0x0101, ua, {}, pk, std::nullopt, proof); }) == "UAPqzHolder", "classical holder");
        CHECK(code_of([&] { holderPopMessage(0x0133, ua, {}, pk, std::nullopt, proof); }) == "UAPqzHolder", "slhdsa holder");
    }
    Bytes eligibleHash = bytes(load("kinds.json")["pqzKeyHash"]);
    for (auto& p : s["pqzMsig"]) {
        Bytes d = bytes(p["keyData"]);
        CHECK(msigPqzEligible(d) == p["eligible"].get<bool>(), p["reason"].get<std::string>());
        CHECK(hx(deriveUA(0x0120, d, false)) == p["ua"].get<std::string>(), "pqzMsig ua");
        Bytes ua = bytes(p["ua"]);
        CHECK(hx(portableRecordDigest(ua, 0x0120, p["eligible"].get<bool>() ? eligibleHash : Bytes(32), kemRecordHash(ua, 0, {}))) ==
                  p["portableRecordDigest"].get<std::string>(), "pqzMsig portable");
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

static std::string opt_hex(const json& r, const char* k) { return r.contains(k) ? r[k].get<std::string>() : ""; }
static std::string mh(const std::optional<Bytes>& m) { return m ? hx(*m) : ""; }

// The holder call over a registration row's attrs (and the proof bytes, or only their hash).
static HolderPop registerRow(const json& row, bool hashOnly = false) {
    auto& a = row["attrs"];
    Bytes key = bytes(a["pqzKey"]), pop = bytes(row["pqzPop"]), hash = bytes(a["pqzPopHash"]), pk = bytes(a["kemPk"]);
    std::optional<Bytes> popArg = (hashOnly || pop.empty()) ? std::nullopt : std::optional<Bytes>(pop);
    std::optional<Bytes> hashArg = hash == Bytes(32) ? std::nullopt : std::optional<Bytes>(hash);
    return holderPopMessage(kind(row["kind"]), bytes(row["ua"]), bytes(row["keyData"]),
                            key.empty() ? std::nullopt : std::optional<Bytes>(key), popArg, hashArg, pk);
}
static const json& byName(const json& rows, const char* key, const std::string& v) {
    for (auto& r : rows) if (r[key].get<std::string>() == v) return r;
    std::fprintf(stderr, "no row with %s = %s\n", key, v.c_str());
    std::exit(2);
}

static void portable() {
    json p = load("portable.json");
    auto& t = p["tags"];
    CHECK(hx(purposeTag("pop", 2)) == t["PURPOSE_POP_V2"]["hash"].get<std::string>(), "POP_V2");
    CHECK(hx(purposeTag("kem")) == t["PURPOSE_KEM"]["hash"].get<std::string>(), "KEM");
    CHECK(hx(purposeTag("pqz-key")) == t["PURPOSE_PQZ_KEY"]["hash"].get<std::string>(), "PQZ_KEY");
    CHECK(!t.contains("KEM_RECORD_TAG"), "the raw record tags are legacy (TS-D3)");
    CHECK(hx(portableDomainSeparator()) == p["typed"]["domainSeparator"].get<std::string>(), "DS_P");
    int n = 0, withPqz = 0, msigs = 0;
    for (auto& r : p["registrations"]) {
        std::string name = r["name"].get<std::string>();
        Bytes ua = bytes(r["ua"]);
        CHECK(hx(uaOf(kind(r["kind"]), bytes(r["keyData"]))) == r["ua"].get<std::string>(), name);
        for (bool hashOnly : {false, true}) {
            auto h = registerRow(r, hashOnly);
            CHECK(hx(h.pqzKeyHash) == r["pqzKeyHash"].get<std::string>(), name);
            CHECK(hx(h.pqzPopHash) == r["attrs"]["pqzPopHash"].get<std::string>(), name);
            CHECK(hx(h.kemRecordHash) == r["kemRecordHash"].get<std::string>(), name);
            CHECK(hx(h.portableRecordDigest) == r["portableRecordDigest"].get<std::string>(), name);
            CHECK(hx(h.registrationDigest) == r["registrationDigest"].get<std::string>(), name);
            CHECK(hx(h.message) == r["popMessage"].get<std::string>(), name);
            CHECK(portableRecordDigest(ua, kind(r["kind"]), h.pqzKeyHash, h.kemRecordHash) == h.portableRecordDigest, name);
            CHECK(registrationDigest(ua, kind(r["kind"]), h.pqzKeyHash, h.kemRecordHash, h.pqzPopHash) == h.registrationDigest, name);
            CHECK(uaMessage(kind(r["kind"]), purposeTag("pop", 2), h.registrationDigest) == h.message, name);
            CHECK(mh(h.memberDigest) == opt_hex(r, "memberDigest"), name);
        }
        auto& a = r["attrs"];
        Bytes pk = bytes(a["pqzKey"]), kpk = bytes(a["kemPk"]);
        CHECK(hx(kemRecordHash(ua, 0, kpk)) == r["kemRecordHash"].get<std::string>(), name);  // the register key: version 0
        if (!pk.empty()) {
            ++withPqz;
            CHECK(hx(pqzRegMessage(kind(r["kind"]), ua, pk, kpk)) == r["pqzRegMessage"].get<std::string>(), name);
            // TS-D3: R_REG proves over the typed UAPortableRecord of the registering kind
            CHECK(hx(uaMessage(0x0142, purposeTag("pop", 2), bytes(r["portableRecordDigest"]))) == r["pqzRegMessage"].get<std::string>(), name);
        } else {
            CHECK(bytes(r["pqzRegMessage"]) == Bytes(32), name);
        }
        if (kind(r["kind"]) == 0x0120) ++msigs;
        ++n;
    }
    CHECK(n == int(p["registrations"].size()) && withPqz && msigs, "registration counts");
    // mldsa87 (CTR-UA-39), fndsa1024 (CTR-UA-40): holders, read here and in kem_record / pqz_key_record: a registration with its KEM
    // register key, KEM records v1-v3, PQZ key records at the four sets
    for (int k : {0x0134, 0x0135}) {
        std::vector<int> got;
        for (const char* s : {"registrations", "kemRecords", "pqzKeyRecords"})
            got.push_back(int(std::count_if(p[s].begin(), p[s].end(), [&](const json& r) { return kind(r["kind"]) == k; })));
        CHECK(got == std::vector<int>({1, 3, 4}), "level-V rows");
    }
}

static void kem_record() {
    json p = load("portable.json");
    for (auto& r : p["kemRecords"]) {
        std::string id = r["id"].get<std::string>();
        Bytes ua = bytes(r["ua"]), pk = bytes(r["kemPk"]);
        uint64_t v = r["version"].get<uint64_t>();
        Bytes d = kemRecordDigest(ua, v, pk), m = kemRecordMessage(kind(r["kind"]), ua, v, pk);
        CHECK(hx(d) == r["digest"].get<std::string>(), id);
        CHECK(hx(kemRecordHash(ua, v, pk)) == r["structHash"].get<std::string>(), id);
        CHECK(hx(m) == r["message"].get<std::string>(), id);
        CHECK(m == uaMessage(kind(r["kind"]), purposeTag("kem"), d), id);
        CHECK(kind(r["kind"]) != 0x0120, id + ": CTR-UA-32, an msig holds no KEM key");
    }
    CHECK(p["kemRecords"].size() == 12, "kemRecords");
    Bytes u(32, 1);
    auto kem = [](size_t n, uint8_t scheme = 1) { Bytes k(n); k[0] = scheme; return k; };  // scheme byte, zeros
    // CTR-UA-32 (T66a): a PQ-eligible msig holds a PQZ key but no KEM key; the same record under a single PQ kind builds
    Bytes mq = bytes(byName(p["registrations"], "name", "msig-pq/n2048-kmax1024")["ua"]);
    CHECK(code_of([&] { kemRecordMessage(0x0120, mq, 1, kem(kKemPkLength)); }) == "UAKemHolder", "msig KEM record");
    CHECK(kemRecordMessage(0x0131, mq, 1, kem(kKemPkLength)).size() == 32, "the control");
    CHECK(code_of([&] { kemRecordDigest(u, 0, kem(kKemPkLength)); }) == "UAKemVersion", "version 0");
    CHECK(code_of([&] { kemRecordDigest(u, 1, kem(kKemPkLength - 1)); }) == "UAKemKeyLength", "short key");
    CHECK(code_of([&] { kemRecordDigest(u, 1, kem(kKemPkLength + 1)); }) == "UAKemKeyLength", "long key");
    CHECK(code_of([&] { kemRecordDigest(u, 1, Bytes{}); }) == "UAKemKeyLength", "empty key");
    CHECK(code_of([&] { kemRecordHash(u, 1, Bytes{}); }) == "UAKemKeyLength", "empty key (hash)");
    // owner 2026-10-31: version 0 with a key is the register key's record (scheme != 0; its words against portable.json's
    // registrations above), never a setKemKey record
    CHECK(kemRecordHash(u, 0, kem(kKemPkLength)) != kemRecordHash(u, 0, Bytes{}), "version 0 with a key");
    CHECK(code_of([&] { kemRecordHash(u, 0, kem(kKemPkLength, 0)); }) == "UAKemScheme", "version 0, scheme 0");
    for (uint8_t scheme : {0, 2, 255}) CHECK(code_of([&] { kemRecordDigest(u, 1, kem(kKemPkLength, scheme)); }) == "UAKemScheme", "scheme not enabled");
    CHECK(hx(kemRecordDigest(u, UINT64_MAX, kem(kKemPkLength))) == "0xa0063a84b56d80c83688d8caf5aeb4be8fb4556928e8bc649686449573938f07", "max version");  // pins the 8-byte version word
}

static void pqz_key_record() {
    json p = load("portable.json");
    int n = 0, msigRows = 0;
    for (auto& r : p["pqzKeyRecords"]) {
        std::string name = r["name"].get<std::string>();
        Bytes ua = bytes(r["ua"]), key = bytes(r["pqzKey"]), hash = bytes(r["pqzPopHash"]);
        uint16_t k = kind(r["kind"]);
        Bytes kd = bytes(byName(p["registrations"], "ua", r["ua"].get<std::string>())["keyData"]);
        Bytes pop = bytes(byName(p["registrations"], "set", r["set"].get<std::string>())["pqzPop"]);
        for (bool hashOnly : {false, true}) {
            auto g = pqzKeyRecordMessage(k, ua, kd, key, hashOnly ? std::nullopt : std::optional<Bytes>(pop),
                                         hashOnly ? std::optional<Bytes>(hash) : std::nullopt);
            CHECK(hx(g.pqzKeyHash) == r["pqzKeyHash"].get<std::string>(), name);
            CHECK(hx(g.pqzPopHash) == r["pqzPopHash"].get<std::string>(), name);
            CHECK(hx(g.pqzKeyDigest) == r["pqzKeyDigest"].get<std::string>(), name);
            CHECK(hx(g.recordDigest) == r["recordDigest"].get<std::string>(), name);
            CHECK(hx(g.message) == r["message"].get<std::string>(), name);
            CHECK(hx(g.pqzRegMessage) == r["pqzRegMessage"].get<std::string>(), name);
            CHECK(pqzKeyDigest(ua, g.pqzKeyHash) == g.pqzKeyDigest, name);
            CHECK(pqzKeyRecordDigest(ua, g.pqzKeyHash, g.pqzPopHash) == g.recordDigest, name);
            CHECK(g.memberDigest.has_value() == (k == 0x0120), name);
            CHECK(mh(g.memberDigest) == opt_hex(r, "memberDigest"), name);
            if (k == 0x0120) { ++msigRows; CHECK(memberDigest(ua, g.message) == *g.memberDigest, name); }
        }
        // write-once: a key already set refuses
        CHECK(code_of([&] { pqzKeyRecordMessage(k, ua, kd, key, std::nullopt, hash, true); }) == "UAPqzKeySet", name);
        ++n;
    }
    CHECK(n == int(p["pqzKeyRecords"].size()) && msigRows, "pqzKeyRecords counts");
}

static void membership_rows() {
    json p = load("portable.json");
    CHECK(p["memberships"].size() == 6, "memberships");
    for (auto& r : p["memberships"]) {
        Bytes u = bytes(r["ua"]);
        Bytes d = membershipDigest(u, bytes(r["member"]));
        CHECK(d == bytes(r["digest"]), "membership digest");
        Bytes m = uaMessage(0x0120, purposeTag("membership"), d);
        CHECK(m == bytes(r["message"]), "membership message");
        CHECK(memberDigest(u, m) == bytes(r["memberDigest"]), "membership memberDigest");
    }
}

static void portable_purposes() {
    json p = load("portable.json");
    CHECK(isPortablePurpose(purposeTag("pop", 2)) && isPortablePurpose(purposeTag("kem")) && isPortablePurpose(purposeTag("pqz-key")), "portable");
    CHECK(!isPortablePurpose(purposeTag("metatx")) && !isPortablePurpose(purposeTag("pop")), "not portable");
    auto& n = byName(p["negatives"], "name", "native-personal-sign-under-metatx");
    CHECK(!isPortablePurpose(bytes(n["mutation"]["set"]["purposeTag"])), "metatx is UAAuth");
}

static void holder_refusals() {
    json p = load("portable.json");
    auto& regs = p["registrations"];
    int run = 0, sigLevel = 0;
    for (auto& n : p["negatives"]) {
        if (n.value("rule", "") == "msig-minimal") continue; // a registry rule over a full registration (msig minimal form)
        std::string entry = n["entry"].get<std::string>(), name = n["name"].get<std::string>(), err = n["error"].get<std::string>();
        auto& m = n["mutation"];
        json set = m.contains("set") ? m["set"] : json::object();
        bool plain = true;
        for (auto& [k, v] : set.items()) plain = plain && (k.rfind("attrs.", 0) == 0 || k == "pqzPop");
        if ((entry == "register" || entry == "storePqzPop") && plain) {
            const json& row = byName(regs, "name", m["row"].get<std::string>());
            json mut = row;
            json steps = json::array({m.contains("registerWith") ? m["registerWith"] : json::object(), set});  // registerWith first
            for (auto& o : steps)
                for (auto& [k, v] : o.items()) {
                    if (k.rfind("attrs.", 0) == 0) mut["attrs"][k.substr(6)] = v;
                    else mut[k] = v;
                }
            if (err == "UAPoP") {  // the digest layer accepts it; the PoP of the unmutated row does not cover it
                CHECK(hx(registerRow(mut).message) != row["popMessage"].get<std::string>(), name);
            } else {
                CHECK(code_of([&] { registerRow(mut); }) == err, name);
            }
            ++run;
        } else if (entry == "setPqzKey" && (err == "UAPqzKeySet" || err == "UAPqzHolder" || err == "UAPqzPopHash")) {
            const json& rec = byName(p["pqzKeyRecords"], "name", m["row"].get<std::string>());
            std::string uaHex = set.contains("ua") ? set["ua"].get<std::string>() : rec["ua"].get<std::string>();
            const json& holder = byName(regs, "ua", uaHex);
            Bytes hash = bytes(set.contains("pqzPopHash") ? set["pqzPopHash"] : rec["pqzPopHash"]);
            CHECK(code_of([&] {
                      pqzKeyRecordMessage(kind(holder["kind"]), bytes(json(uaHex)), bytes(holder["keyData"]), bytes(rec["pqzKey"]),
                                          std::nullopt, hash, holder["attrs"]["pqzKey"].get<std::string>() != "0x");
                  }) == err, name);
            ++run;
        } else if (entry == "setKemKey" && err == "UAKemHolder") {
            // CTR-UA-32 (msig-kem-record): an msig's KEM record is refused by its kind (the target's kind is the row's)
            const json& k = byName(p["kemRecords"], "id", m["row"].get<std::string>());
            const json& t = byName(regs, "ua", set["ua"].get<std::string>());
            CHECK(t["kind"] == m["kind"], name);
            CHECK(code_of([&] { kemRecordMessage(kind(t["kind"]), bytes(set["ua"]), k["version"].get<uint64_t>(), bytes(set["kemPk"])); }) == err, name);
            ++run;
        } else if (entry == "setKemKey" && name == "kem-record-of-other-ua") {
            // the record of one UA offered for another: the signed message differs, so the signature cannot verify
            const json& k = byName(p["kemRecords"], "id", m["row"].get<std::string>());
            const json& t = byName(regs, "ua", set["ua"].get<std::string>());
            Bytes msg = kemRecordMessage(kind(t["kind"]), bytes(set["ua"]), k["version"].get<uint64_t>(), bytes(k["kemPk"]));
            CHECK(hx(msg) != k["message"].get<std::string>(), name);
            ++run;
        } else if (name == "record-kind-mismatch") {
            // the typed record binds `kind`: the same UA and attributes under another kind is another message
            const json& row = byName(regs, "name", m["row"].get<std::string>());
            Bytes ua = bytes(row["ua"]);
            Bytes d = registrationDigest(ua, kind(m["otherKind"]), Bytes(32), kemRecordHash(ua, 0, {}), Bytes(32));
            CHECK(hx(uaMessage(kind(row["kind"]), purposeTag("pop", 2), d)) != row["popMessage"].get<std::string>(), name);
            ++run;
        } else if (name == "kem-record-as-registration") {
            // the row's own typed KEM record is not its registration (struct type)
            const json& row = byName(regs, "name", m["row"].get<std::string>());
            CHECK(byName(p["kemRecords"], "ua", row["ua"].get<std::string>())["digest"] != row["registrationDigest"], name);
            ++run;
        } else {
            ++sigLevel;  // signatures / native members: verified by the signature vectors
        }
    }
    CHECK(run + sigLevel + 1 == int(p["negatives"].size()) && run && sigLevel, "negatives counts"); // + the skipped msig-minimal row
    Bytes u(32, 1), key(16384), proof(32, 7);
    // malformed msig key data is UAKeyData, not "not a holder"; an msig without key data is not a holder
    for (Bytes kd : {Bytes{0, 2, 0}, Bytes{0, 2, 0, 2, 9, 9}})
        CHECK(code_of([&] { holderPopMessage(0x0120, u, kd, key, std::nullopt, proof); }) == "UAKeyData", "msig key data");
    CHECK(code_of([&] { holderPopMessage(0x0120, u, {}, key, std::nullopt, proof); }) == "UAPqzHolder", "msig without key data");
    CHECK(code_of([&] { holderPopMessage(0x0130, u, {}, key, std::nullopt, Bytes(31)); }) == "UAPqzPopHash", "31-byte hash");
    CHECK(code_of([&] { holderPopMessage(0x0130, u, {}, key, Bytes{}); }) == "UAPqzPopHash", "empty proof is no proof");
    CHECK(code_of([&] { holderPopMessage(0x0130, u, {}, Bytes(100), std::nullopt, proof); }) == "UAKeyData", "key length");
    CHECK(code_of([&] { holderPopMessage(0x0130, u, {}, std::nullopt, std::nullopt, std::nullopt, Bytes(kKemPkLength - 1, 1)); }) == "UAKemKeyLength", "kem key");
    CHECK(code_of([&] { holderPopMessage(0x0130, u, {}, std::nullopt, std::nullopt, std::nullopt, Bytes(kKemPkLength, 0)); }) == "UAKemScheme", "kem scheme 0");
    CHECK(code_of([&] { holderPopMessage(0x0101, u, {}, std::nullopt, std::nullopt, std::nullopt, Bytes(kKemPkLength, 1)); }) == "UAKemHolder", "kem holder");
    Bytes mq = bytes(byName(regs, "name", "msig-pq/n2048-kmax1024")["keyData"]);  // a PQ-eligible msig holds no KEM key (CTR-UA-32)
    CHECK(code_of([&] { holderPopMessage(0x0120, u, mq, std::nullopt, std::nullopt, std::nullopt, Bytes(kKemPkLength, 1)); }) == "UAKemHolder", "msig kem holder");
    CHECK(holderPopMessage(0x0130, u, {}).message == holderPopMessage(0x0130, u, {}, std::nullopt, std::nullopt, std::nullopt, Bytes{}).message, "empty KEM key is absent");
    // a zero-length proof hash is absent (same as no hash)
    CHECK(holderPopMessage(0x0130, u, {}).message == holderPopMessage(0x0130, u, {}, std::nullopt, std::nullopt, Bytes{}).message, "empty hash is absent");
}

// clientkeys registrationArgs' input of a registration row; an msig's pop is its typed member list.
static json regInput(const json& r) {
    auto& a = r["attrs"];
    return {{"kind", r["kind"]}, {"keyData", r["keyData"]}, {"pqzKey", a["pqzKey"]}, {"pqzPopHash", a["pqzPopHash"]},
            {"pqzPop", r["pqzPop"]}, {"kemPk", a["kemPk"]}, {"pop", r["args"]["pop"]}};
}
static json regArgs(const json& i) { return json::parse(registrationArgs(i.dump())); }
static std::string hexOf(const char* byte, size_t n) {
    std::string s = "0x";
    for (size_t i = 0; i < n; ++i) s += byte;
    return s;
}

// Nested msig (nested.json): the digest chain from the low-level calls, the JSON calls with `inner`. Key data alone refuses an msig member by
// name, so holderPopMessage and pqzKeyRecordMessage stop there on a record that needs its inner keys; their `With` forms take `inner`
// (nested_inner). This API verifies no signature.
static void nested_rows() {
    json n = load("nested.json"), inner = json::object();
    for (auto& r : n["registrations"]) {
        if (kind(r["kind"]) == 0x0120) inner[r["ua"].get<std::string>()] = r["keyData"];
    }
    auto str = [](const json& v) { return v.get<std::string>(); };
    Bytes popTag = purposeTag("pop", 2), memberTag = purposeTag("member"), noHash(32);
    int rows = 0;
    for (auto* list : {&n["registrations"], &n["afterAcceptance"]}) {
        for (auto& r : *list) {
            ++rows;
            std::string name = r["name"];
            uint16_t k = kind(r["kind"]);
            Bytes ua = bytes(r["ua"]), kemPk = bytes(r["attrs"]["kemPk"]);
            CHECK(hx(uaOf(k, bytes(r["keyData"]))) == str(r["ua"]), name);
            Bytes kem = kemRecordHash(ua, 0, kemPk), rd = registrationDigest(ua, k, noHash, kem, noHash), msg = uaMessage(k, popTag, rd);
            CHECK(hx(kem) == str(r["kemRecordHash"]), name);
            CHECK(hx(portableRecordDigest(ua, k, noHash, kem)) == str(r["portableRecordDigest"]), name);
            CHECK(hx(rd) == str(r["registrationDigest"]), name);
            CHECK(hx(msg) == str(r["popMessage"]), name);
            json i = regInput(r);
            i["kemCommit"] = false;
            i["inner"] = inner;
            CHECK(regArgs(i)["args"] == r["args"], name);
            if (r.contains("kemCommit")) {
                i["kemCommit"] = true;
                json c = regArgs(i);
                CHECK(c["args"] == r["kemCommit"]["register"] && c["kemFill"] == r["kemCommit"]["fill"], name);
                CHECK(code_of([&] { holderPopMessage(k, ua, bytes(r["keyData"]), std::nullopt, std::nullopt, std::nullopt, kemPk); }) == "UAMemberUnknown", name);
            }
            if (k != 0x0120) continue;
            Bytes md = memberDigest(ua, msg);
            CHECK(hx(md) == str(r["memberDigest"]), name);
            if (!r.contains("innerDigests")) continue;
            for (auto& x : r["innerDigests"]) CHECK(hx(memberDigest(bytes(x["inner"]), uaMessage(0x0120, memberTag, md))) == str(x["memberDigest"]), name);
        }
    }
    CHECK(rows == 17, "registration rows");
    CHECK(n["kemRecords"].empty() && n["pqzKeyRecords"].size() == 4, "record rows");  // CTR-UA-32: an msig has no KEM record
    {
        const json& pq = byName(n["registrations"], "name", "msig-nested-pq");
        Bytes kem(kKemPkLength);
        kem[0] = 1;
        CHECK(code_of([&] { kemRecordMessage(0x0120, bytes(pq["ua"]), 1, kem); }) == "UAKemHolder", "msig KEM record");
        json i = regInput(pq);
        i["inner"] = inner;
        i["kemPk"] = hx(kem);
        CHECK(code_of([&] { regArgs(i); }) == "UAKemHolder", "msig KEM key");
    }
    for (auto& r : n["kemRecords"]) {
        Bytes ua = bytes(r["ua"]), pk = bytes(r["kemPk"]);
        uint64_t v = r["version"];
        Bytes m = kemRecordMessage(kind(r["kind"]), ua, v, pk);
        CHECK(hx(kemRecordDigest(ua, v, pk)) == str(r["digest"]), "kem digest");
        CHECK(hx(m) == str(r["message"]) && hx(memberDigest(ua, m)) == str(r["memberDigest"]), "kem message");
        json i = {{"ua", r["ua"]}, {"version", v}, {"kemPk", r["kemPk"]}, {"sig", {{"members", r["args"]["sig"]["members"]}}}};
        CHECK(json::parse(setKemKeyArgs(i.dump())) == r["args"], "kem args");
    }
    for (auto& r : n["pqzKeyRecords"]) {
        std::string name = r["name"];
        Bytes ua = bytes(r["ua"]), h = bytes(r["pqzKeyHash"]), tag = purposeTag("pqz-key");
        Bytes kd = pqzKeyDigest(ua, h), rd = pqzKeyRecordDigest(ua, h, bytes(r["pqzPopHash"])), m = uaMessage(0x0120, tag, rd);
        CHECK(hx(kd) == str(r["pqzKeyDigest"]) && hx(rd) == str(r["recordDigest"]), name);
        CHECK(hx(m) == str(r["message"]) && hx(memberDigest(ua, m)) == str(r["memberDigest"]), name);
        CHECK(hx(uaMessage(0x0142, tag, kd)) == str(r["pqzRegMessage"]), name);
        json i = {{"ua", r["ua"]}, {"pqzKey", r["pqzKey"]}, {"pqzPopHash", r["pqzPopHash"]}, {"sig", {{"members", r["args"]["sig"]["members"]}}}};
        CHECK(json::parse(setPqzKeyArgs(i.dump())) == r["args"], name);
        CHECK(code_of([&] { pqzKeyRecordMessage(0x0120, ua, bytes(inner[r["ua"].get<std::string>()]), bytes(r["pqzKey"]), std::nullopt, bytes(r["pqzPopHash"])); }) == "UAMemberUnknown", name);
    }
    CHECK(n["memberships"].size() == 4, "membership rows");
    for (auto& m : n["memberships"]) {
        std::string name = m["name"];
        Bytes ua = bytes(m["ua"]), d = membershipDigest(ua, bytes(m["member"])), msg = uaMessage(0x0120, purposeTag("membership"), d);
        CHECK(hx(d) == str(m["digest"]) && hx(msg) == str(m["message"]), name);
        CHECK(hx(memberDigest(ua, msg)) == str(m["memberDigest"]), name);
    }
    CHECK(n["authorizations"].size() == 5, "authorization rows");
    for (auto& a : n["authorizations"]) {
        std::string name = a["name"];
        CHECK(hx(memberDigest(bytes(a["ua"]), uaMessage(0x0120, bytes(a["purposeTag"]), bytes(a["digest"])))) == str(a["memberDigest"]), name);
        auto& k = n["pqzKeyRecords"][0];  // (was kemRecords[0]: CTR-UA-32, an msig has no KEM record)
        json i = {{"ua", k["ua"]}, {"pqzKey", k["pqzKey"]}, {"pqzPopHash", k["pqzPopHash"]}, {"sig", a["uaSig"]}};
        CHECK(json::parse(setPqzKeyArgs(i.dump()))["sig"] == a["uaSig"], name);
    }
    // the builder's own refusal is the minimal rule at both levels; the others are the registry's, on the signatures
    const std::vector<std::string> minimal = {"inner-below-threshold", "inner-index-past-the-members", "inner-unsorted", "inner-not-minimal", "outer-not-minimal"};
    CHECK(n["negatives"].size() == 13, "negative rows");
    int found = 0;
    for (auto& x : n["negatives"]) {
        std::string name = x["name"];
        for (auto* list : {&n["registrations"], &n["afterAcceptance"]}) {
            for (auto& r : *list) {
                if (r["name"] != x["row"]) continue;
                ++found;
                json i = regInput(r);
                i["kemCommit"] = false;
                i["inner"] = inner;
                i["pop"] = x["popTyped"];
                if (std::find(minimal.begin(), minimal.end(), name) != minimal.end()) CHECK(code_of([&] { regArgs(i); }) == str(x["error"]), name);
                else CHECK(regArgs(i)["args"]["pop"] == x["popTyped"], name);
            }
        }
    }
    CHECK(found == 13, "every negative's row, afterAcceptance's included");
    CHECK(n["structures"].size() == 2, "structure rows");
    for (auto& s : n["structures"]) {
        Bytes d = bytes(s["keyData"]);
        CHECK(hx(uaOf(0x0120, d)) == str(s["ua"]), s["name"].get<std::string>());
        CHECK(code_of([&] { msigPqzEligible(d); }) == str(s["error"]), s["name"].get<std::string>());
    }
    for (auto& r : n["eligibility"]) {
        Bytes d = bytes(r["keyData"]);
        CHECK(code_of([&] { msigPqzEligible(d); }) == "UAMemberUnknown", r["reason"].get<std::string>());
    }
}

// The With forms with inner ({id: keyData}, the JSON calls' form): msig-nested-pq's eligibility and record (no KEM key, CTR-UA-32), every eligibility row and
// every nested PQZ key record reproduce; without inner they stay UAMemberUnknown, so does a third level. Every memberships row's stored
// bytes turn back into its slot through replayedMemberSig.
static void nested_inner() {
    json n = load("nested.json"), inner = json::object();
    for (auto& r : n["registrations"]) {
        if (kind(r["kind"]) == 0x0120) inner[r["ua"].get<std::string>()] = r["keyData"];
    }
    auto str = [](const json& v) { return v.get<std::string>(); };
    auto mh = [](const std::optional<Bytes>& m) { return m ? hx(*m) : std::string(); };
    const std::string all = inner.dump();
    int holders = 0;
    for (auto* list : {&n["registrations"], &n["afterAcceptance"]}) {
        for (auto& r : *list) {
            if (r["attrs"]["kemPk"] == "0x" && r["attrs"]["pqzKey"] == "0x") continue;
            ++holders;
        }
    }
    CHECK(holders == 0, "no nested holder row");  // CTR-UA-32 (T66a): msig-nested-pq registers without a KEM key (was the one row)
    {
        const json& r = byName(n["registrations"], "name", "msig-nested-pq");
        std::string name = r["name"];
        Bytes ua = bytes(r["ua"]), d = bytes(r["keyData"]), kem(kKemPkLength);
        kem[0] = 1;
        CHECK(msigPqzEligibleWith(d, all), name);
        CHECK(code_of([&] { msigPqzEligible(d); }) == "UAMemberUnknown", name);
        HolderPop h = holderPopMessageWith(0x0120, ua, d, all, std::nullopt, std::nullopt, std::nullopt, std::nullopt);
        CHECK(hx(h.kemRecordHash) == str(r["kemRecordHash"]) && hx(h.portableRecordDigest) == str(r["portableRecordDigest"]), name);
        CHECK(hx(h.registrationDigest) == str(r["registrationDigest"]) && hx(h.message) == str(r["popMessage"]), name);
        CHECK(mh(h.memberDigest) == str(r["memberDigest"]), name);
        // an msig holds no KEM key: refused by its kind, before its key data or inner is read
        for (const std::string& i : {all, std::string()})
            CHECK(code_of([&] { holderPopMessageWith(0x0120, ua, d, i, std::nullopt, std::nullopt, std::nullopt, kem); }) == "UAKemHolder", name);
    }
    for (auto& r : n["eligibility"]) {
        std::string why = r["reason"];
        Bytes d = bytes(r["keyData"]);
        CHECK(msigPqzEligibleWith(d, r["inner"].dump()) == r["eligible"].get<bool>(), why);
        for (const char* none : {"", "null", "{}"}) CHECK(code_of([&] { msigPqzEligibleWith(d, none); }) == "UAMemberUnknown", why);
    }
    auto& third = n["structures"][0];
    std::string pq;
    for (auto& r : n["registrations"]) if (r["name"] == "msig-nested-pq") pq = str(r["keyData"]);
    CHECK(code_of([&] { msigPqzEligibleWith(bytes(third["keyData"]), json{{str(third["member"]), pq}}.dump()); }) == "UAMemberUnknown", "a third level");
    for (const auto& bad : std::vector<std::string>{"not json", "[]", "{\"0x01\": \"0x\"}", std::string(65537, ' '), "\xff"})
        CHECK(code_of([&] { msigPqzEligibleWith(bytes(json(pq)), bad); }) == "UAArgument", bad.substr(0, 12));
    CHECK(n["pqzKeyRecords"].size() == 4, "record rows");
    for (auto& r : n["pqzKeyRecords"]) {
        std::string name = r["name"];
        Bytes ua = bytes(r["ua"]), d = bytes(inner[str(r["ua"])]), key = bytes(r["pqzKey"]), h = bytes(r["pqzPopHash"]);
        PqzKeyRecord g = pqzKeyRecordMessageWith(0x0120, ua, d, all, key, std::nullopt, h);
        CHECK(hx(g.pqzKeyHash) == str(r["pqzKeyHash"]) && hx(g.pqzPopHash) == str(r["pqzPopHash"]), name);
        CHECK(hx(g.pqzKeyDigest) == str(r["pqzKeyDigest"]) && hx(g.recordDigest) == str(r["recordDigest"]), name);
        CHECK(hx(g.message) == str(r["message"]) && hx(g.pqzRegMessage) == str(r["pqzRegMessage"]), name);
        CHECK(mh(g.memberDigest) == str(r["memberDigest"]), name);
        CHECK(code_of([&] { pqzKeyRecordMessageWith(0x0120, ua, d, "", key, std::nullopt, h); }) == "UAMemberUnknown", name);
    }
    CHECK(n["memberships"].size() == 4, "membership rows");
    for (auto& m : n["memberships"]) {
        std::string name = m["name"];
        Bytes d;
        for (auto& r : n["registrations"]) if (r["ua"] == m["ua"]) d = bytes(r["keyData"]);
        Bytes stored = bytes(m["stored"]);
        uint16_t index = m["index"];
        CHECK(json::parse(replayedMemberSig(d, index, stored)) == json({{"index", index}, {"members", m["members"]}, {"sig", m["sig"]}}), name);
        CHECK(code_of([&] { replayedMemberSig(d, 16, stored); }) == "UAUnauthorized", name);
        Bytes longer = stored;
        longer.push_back(0);
        if (!m["members"].empty()) CHECK(code_of([&] { replayedMemberSig(d, index, longer); }) == "UAUnauthorized", name + ": not canonical");
    }
}

// abi.encode(InnerSig[]) of a typed list [{index, sig}]: the bytes an msig member's UAMemberSig carries.
static Bytes encodeInnerSigs(const json& list) {
    auto word = [](Bytes& o, size_t v) { for (int i = 31; i >= 0; --i) o.push_back(i < 8 ? uint8_t(v >> (8 * i)) : 0); };
    Bytes head, tail;
    word(head, 0x20);
    word(head, list.size());
    for (auto& x : list) {
        Bytes s = bytes(x["sig"]);
        word(head, 32 * list.size() + tail.size());
        word(tail, x["index"].get<uint16_t>());
        word(tail, 0x40);
        word(tail, s.size());
        tail.insert(tail.end(), s.begin(), s.end());
        tail.resize(tail.size() + (32 - s.size() % 32) % 32, 0);
    }
    head.insert(head.end(), tail.begin(), tail.end());
    return head;
}

// owner 2026-11-03: memberSigHashOf(ua, index) is keccak256 of the bytes the slot's UAMemberSig carries: its sig, or an msig member's
// abi.encode(InnerSig[]). Every msig registration row's memberSigHashes (portable.json, its negative, nested.json), and every memberships
// row's storedHash = keccak256(stored), stored being that slot's bytes.
static void member_sig_hashes() {
    json p = load("portable.json"), n = load("nested.json");
    std::vector<const json*> rows;
    for (auto& r : p["registrations"]) rows.push_back(&r);
    for (auto& x : p["negatives"]) if (x.contains("registration")) rows.push_back(&x["registration"]);
    for (auto* list : {&n["registrations"], &n["afterAcceptance"]}) for (auto& r : *list) rows.push_back(&r);
    int msigs = 0, slots = 0, inner = 0;
    for (auto* r : rows) {
        if (kind((*r)["kind"]) != 0x0120) continue;
        ++msigs;
        std::string name = (*r)["name"];
        auto &pop = (*r)["args"]["pop"], &hs = (*r)["memberSigHashes"];
        CHECK(hs.size() == pop.size(), name);
        for (size_t i = 0; i < pop.size() && i < hs.size(); ++i, ++slots) {
            bool msig = !pop[i]["members"].empty();
            inner += msig;
            Bytes b = msig ? encodeInnerSigs(pop[i]["members"]) : bytes(pop[i]["sig"]);
            CHECK(hs[i]["index"] == pop[i]["index"] && hx(keccak256(b)) == hs[i]["hash"].get<std::string>(), name + " slot " + std::to_string(i));
        }
    }
    CHECK(msigs == 19 && slots == 30 && inner == 7, "msig rows, slots, msig-member slots");
    CHECK(n["memberships"].size() == 4, "membership rows");
    for (auto& m : n["memberships"]) {
        std::string name = m["name"];
        Bytes stored = bytes(m["stored"]);
        CHECK(hx(keccak256(stored)) == m["storedHash"].get<std::string>(), name);
        CHECK((m["members"].empty() ? bytes(m["sig"]) : encodeInnerSigs(m["members"])) == stored, name + ": the encoder's control");
    }
    CHECK(hx(keccak256({})) == "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "keccak256 of nothing");
}

static void registration_args() {
    json p = load("portable.json"), k = load("kinds.json");
    int commits = 0, withCommit = 0;
    for (auto& r : p["registrations"]) {
        std::string name = r["name"];
        json i = regInput(r), o = i;
        o["kemCommit"] = false;
        json a = regArgs(o);
        CHECK(a["args"] == r["args"], name);
        CHECK(a["kemFill"].is_null() && a["kemFillCalldataLength"].is_null(), name);
        CHECK(regArgs(i)["args"] == r["args"], name + ": under the limit, the full key");
        withCommit += r.contains("kemCommit");
        if (r["attrs"]["kemPk"] == "0x") { CHECK(!r.contains("kemCommit"), name); continue; }
        o["kemCommit"] = true;
        json c = regArgs(o);
        CHECK(c["args"] == r["kemCommit"]["register"], name);
        CHECK(c["kemFill"] == r["kemCommit"]["fill"], name);
        CHECK(c["kemFillCalldataLength"] == 2020, name);
        ++commits;
    }
    CHECK(commits == withCommit && commits == 7, "kemCommit rows");  // CTR-UA-32: msig-pq/<set> registers without a KEM key
    {  // CTR-UA-32 (T66a): a PQ-eligible msig holds no KEM key, in either form
        json i = regInput(byName(p["registrations"], "name", "msig-pq/n2048-kmax1024"));
        i["kemPk"] = p["kemRecords"][0]["kemPk"];
        for (const json& c : {json(true), json(false), json()}) {
            json o = i;
            if (!c.is_null()) o["kemCommit"] = c;
            CHECK(code_of([&] { regArgs(o); }) == "UAKemHolder", "msig KEM key " + c.dump());
        }
    }
    int typed = 0;
    for (auto& v : k["valid"]) {  // no attributes, a 32-byte pop (cast 1.8.5)
        uint16_t n = kind(v["kind"]);
        std::string entry = n == 0x0100 ? "registerWebAuthn" : n == 0x0110 || n == 0x0112 ? "registerMuSig2"
                          : n == 0x0111 || n == 0x0113 ? "registerFrost" : "";
        if (entry.empty()) continue;
        json a = regArgs({{"kind", n}, {"keyData", v["keyData"]}, {"pop", hexOf("00", 32)}});
        CHECK(a["args"]["entry"] == entry, entry);
        CHECK(a["calldataLength"] == (n == 0x0100 ? 580 : entry == "registerMuSig2" ? 1124 : 2308), entry);
        ++typed;
    }
    CHECK(typed == 6, "typed key rows");
    CHECK(regArgs({{"kind", 0x0101}, {"keyData", k["valid"][1]["keyData"]}})["args"]["entry"] == "register", "p256 stays register");
    // the hash commit only over 261,909 B (PQZH n2560-kmax16384's sizes; ua-rs registration_hash_commit_when_over_limit)
    json x = {{"kind", 0x0131}, {"keyData", hexOf("5a", 1952)}, {"pqzKey", hexOf("5a", 20480)}, {"pqzPop", hexOf("5a", 234238)},
              {"kemPk", "0x01" + hexOf("5a", 1600).substr(2)}, {"pop", hexOf("5a", 3309)}};
    json full = x;
    full["kemCommit"] = false;
    CHECK(regArgs(full)["calldataLength"] == 262116, "full");
    json aut = regArgs(x);
    CHECK(aut["calldataLength"] == 260548 && aut["kemFillCalldataLength"] == 2020 && aut["kemFill"]["version"] == 0, "auto");
    for (auto& bad : std::vector<std::pair<std::string, std::string>>{
             {"not json", "UAArgument"}, {R"({"kind": 65536})", "UAArgument"}, {R"({"kind": 257, "keyData": "0xzz"})", "UAArgument"},
             {R"({"kind": 288, "keyData": "0x00020000", "pop": "0x"})", "UAArgument"}, {R"({"kind": 288, "keyData": "0x000200"})", "UAKeyData"},
             {R"({"kind": 305, "kemPk": "0x0101"})", "UAKemKeyLength"},
             {R"({"kind": 305, "pqzKey": "0x01", "pqzPopHash": "0x01", "pqzPop": "0x01"})", "UAPqzPopHash"}})
        CHECK(code_of([&] { registrationArgs(bad.first); }) == bad.second, bad.first);
}

// a record row's UASig: its sig, an msig's as the typed member list; absent fields are empty
static json recordSig(const json& r) {
    if (r["kind"] == 0x0120) return {{"members", r["args"]["sig"]["members"]}};
    return {{"signature", r["sig"]}};
}

static void set_key_args() {
    json p = load("portable.json");
    CHECK(p["kemRecords"].size() == 12, "kemRecords"); // + v1-v3 of mldsa87, fndsa1024; no msig (CTR-UA-32)
    for (auto& k : p["kemRecords"]) {
        json i = {{"ua", k["ua"]}, {"version", k["version"]}, {"kemPk", k["kemPk"]}, {"sig", recordSig(k)}};
        CHECK(json::parse(setKemKeyArgs(i.dump())) == k["args"], k["id"].get<std::string>());
    }
    CHECK(p["pqzKeyRecords"].size() == 16, "pqzKeyRecords"); // + mldsa87, fndsa1024 at the four sets
    for (auto& r : p["pqzKeyRecords"]) {
        json i = {{"ua", r["ua"]}, {"pqzKey", r["pqzKey"]}, {"pqzPopHash", r["pqzPopHash"]}, {"sig", recordSig(r)}};
        CHECK(json::parse(setPqzKeyArgs(i.dump())) == r["args"], r["name"].get<std::string>());
    }
    std::string ua = "\"" + hexOf("11", 32) + "\"";
    for (auto& bad : std::vector<std::pair<std::string, std::string>>{
             {"not json", "UAArgument"}, {R"({"ua": "0x11", "version": 1})", "UAArgument"}, {"{\"ua\": " + ua + "}", "UAArgument"},
             {"{\"ua\": " + ua + R"(, "version": 1, "kemPk": "0x0101"})", "UAKemKeyLength"}})
        CHECK(code_of([&] { setKemKeyArgs(bad.first); }) == bad.second, bad.first);
    for (auto& bad : std::vector<std::pair<std::string, std::string>>{
             {"not json", "UAArgument"}, {"{\"ua\": " + ua + R"(, "pqzPopHash": "0x01"})", "UAPqzPopHash"},
             {"{\"ua\": " + ua + ", \"pqzPopHash\": " + ua + R"(, "sig": "0x01"})", "UAArgument"}})
        CHECK(code_of([&] { setPqzKeyArgs(bad.first); }) == bad.second, bad.first);
}

// governance T14: governanceBit against governance_bits.json on disk, every row; past bit 23 UAArgument
static void governance_bits_rows() {
    std::ifstream f(std::string(SCAAS_UA_VECTORS_DIR) + "/../governance/governance_bits.json");
    if (!f) { std::fprintf(stderr, "cannot open governance_bits.json\n"); std::exit(2); }
    json v = json::parse(f);
    CHECK(v["bits"].size() == 24, "rows 0-23");
    for (auto& r : v["bits"]) CHECK(json::parse(governanceBit(r["bit"].get<uint8_t>())) == r, std::to_string(r["bit"].get<int>()));
    for (int bit : {24, 127, 128, 255}) CHECK(code_of([&] { governanceBit(uint8_t(bit)); }) == "UAArgument", std::to_string(bit));
}

// pay-meta-tax T41: paymeta.json v2 rows (257 bytes refused) and paytax.json's UAPayWithTax digest row
static void pay_rows() {
    auto read = [](const std::string& n) {
        std::ifstream f(std::string(SCAAS_UA_VECTORS_DIR) + "/../metatx/" + n);
        if (!f) { std::fprintf(stderr, "cannot open %s\n", n.c_str()); std::exit(2); }
        return json::parse(f);
    };
    // plan T83: the v2 rows (`payNo` text) in legacy/ua-mtx-merge/t83/ until ua-rs takes PayMeta v3 (ua-rs-sign sync)
    for (auto& r : read("legacy/ua-mtx-merge/t83/paymeta.json")) {
        json i = {{"salt", r["salt"]}, {"payNo", r["payNo"]}, {"schema", r["schema"]}, {"body", r["body"]}};
        if (r["accepted"].get<bool>()) CHECK(json::parse(metaPayId(i.dump()))["payId"] == r["payId"], r["name"].get<std::string>());
        else CHECK(code_of([&] { metaPayId(i.dump()); }) == "UAArgument", r["name"].get<std::string>());
    }
    for (auto& r : read("paytax.json")) {
        if (r["name"] != "digest_unbound_relayer_fee_recipient") continue;
        json p;
        for (auto k : {"from", "to", "value", "entryRef", "batch", "nonce", "validUntil", "mode", "relayer", "fee", "feeRecipient"}) p[k] = r[k];
        json i = {{"struct", "UAPayWithTax"}, {"domain", r["domain"]}, {"message", {{"payment", p}, {"taxMode", r["taxMode"]}, {"tax", r["tax"]}}}};
        json got = json::parse(payDigest(i.dump()));
        CHECK(got["digest"] == r["digest"], "UAPayWithTax digest");
        CHECK(got["structHash"] == r["structHash"], "UAPayWithTax struct hash");
    }
}

int main(int argc, char** argv) {
    std::map<std::string, void (*)()> tests{
        {"table_groups_purposes_constants", table_groups_purposes_constants}, {"valid_rows", valid_rows},
        {"invalid_rows", invalid_rows}, {"natives_native_space_canonical_ids", natives_native_space_canonical_ids},
        {"messages", messages}, {"structures", structures}, {"portable", portable}, {"kem_record", kem_record},
        {"pqz_key_record", pqz_key_record}, {"membership_rows", membership_rows}, {"portable_purposes", portable_purposes},
        {"holder_refusals", holder_refusals}, {"registration_args", registration_args}, {"nested_rows", nested_rows}, {"nested_inner", nested_inner}, {"set_key_args", set_key_args}, {"pay_rows", pay_rows},
        {"member_sig_hashes", member_sig_hashes}, {"governance_bits_rows", governance_bits_rows}, {"id_display_rows", id_display_rows}};
    if (argc != 2 || !tests.count(argv[1])) { std::fprintf(stderr, "usage: vectors_test <name>\n"); return 2; }
    try { tests[argv[1]](); } catch (const std::exception& e) { std::fprintf(stderr, "exception: %s\n", e.what()); return 1; }
    return failures ? 1 : 0;
}
