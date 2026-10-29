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
    CHECK(k["purposes"].size() == 14, "purposes size");  // 13 purposes, `pop` has v1 and v2
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
        Bytes portable = portablePopDigest(bytes(p["ua"]), bytes(p["pqzKeyHash"]), bytes(p["kemRecordHash"]));
        CHECK(hx(portable) == p["portablePopDigest"].get<std::string>(), "portablePopDigest");
        CHECK(hx(registrationDigest(portable, bytes(p["pqzPopHash"]))) == p["registrationDigest"].get<std::string>(), "registrationDigest");
    }
    CHECK(hx(chainKeyHash(0x10000000007ULL)) == "0x6e45d591a544f53396f6e86d49f5809196c5725f9d99dbd2ca97f9925c7ce950", "chainKeyHash");  // keccak256("evm:1099511627783")
    for (auto& p : s["pqzReg"]) {
        Bytes ua = bytes(p["ua"]), kem = bytes(p["kemRecordHash"]), h = *keyHashOf(0x0142, pk);
        CHECK(hx(h) == p["pqzKeyHash"].get<std::string>(), "pqzReg keyHash");
        Bytes portable = portablePopDigest(ua, h, kem);
        CHECK(hx(portable) == p["portablePopDigest"].get<std::string>(), "pqzReg portable");
        CHECK(hx(uaMessage(0x0142, purposeTag("pop", 2), portable)) == p["pqzRegMessage"].get<std::string>(), "pqzReg message");
        if (kem != Bytes(32)) continue;  // the row's KEM record hash is opaque; the real records are in portable.json
        CHECK(hx(pqzRegMessage(ua, pk)) == p["pqzRegMessage"].get<std::string>(), "pqzRegMessage");
        auto got = holderPopMessage(kind(p["kind"]), ua, {}, pk, std::nullopt, proof);
        CHECK(hx(got.pqzKeyHash) == p["pqzKeyHash"].get<std::string>(), "holder pqzKeyHash");
        CHECK(hx(got.portablePopDigest) == p["portablePopDigest"].get<std::string>(), "holder portable");
        CHECK(code_of([&] { holderPopMessage(0x0101, ua, {}, pk, std::nullopt, proof); }) == "UAPqzHolder", "classical holder");
        CHECK(code_of([&] { holderPopMessage(0x0133, ua, {}, pk, std::nullopt, proof); }) == "UAPqzHolder", "slhdsa holder");
    }
    Bytes eligibleHash = bytes(load("kinds.json")["pqzKeyHash"]);
    for (auto& p : s["pqzMsig"]) {
        Bytes d = bytes(p["keyData"]);
        CHECK(msigPqzEligible(d) == p["eligible"].get<bool>(), p["reason"].get<std::string>());
        CHECK(hx(deriveUA(0x0120, d, false)) == p["ua"].get<std::string>(), "pqzMsig ua");
        CHECK(hx(portablePopDigest(bytes(p["ua"]), p["eligible"].get<bool>() ? eligibleHash : Bytes(32), Bytes(32))) ==
                  p["portablePopDigest"].get<std::string>(), "pqzMsig portable");
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
    uint64_t ver = a["kemVersion"].get<uint64_t>();
    std::optional<Bytes> popArg = (hashOnly || pop.empty()) ? std::nullopt : std::optional<Bytes>(pop);
    std::optional<Bytes> hashArg = hash == Bytes(32) ? std::nullopt : std::optional<Bytes>(hash);
    std::optional<Kem> kem = (ver == 0 && pk.empty()) ? std::nullopt : std::optional<Kem>(Kem{ver, pk});
    return holderPopMessage(kind(row["kind"]), bytes(row["ua"]), bytes(row["keyData"]),
                            key.empty() ? std::nullopt : std::optional<Bytes>(key), popArg, hashArg, kem);
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
    CHECK(hx(kemRecordTag()) == t["KEM_RECORD_TAG"]["hash"].get<std::string>(), "KEM_RECORD_TAG");
    CHECK(hx(pqzKeyRecordTag()) == t["PQZ_KEY_RECORD_TAG"]["hash"].get<std::string>(), "PQZ_KEY_RECORD_TAG");
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
            CHECK(hx(h.portablePopDigest) == r["portablePopDigest"].get<std::string>(), name);
            CHECK(hx(h.registrationDigest) == r["registrationDigest"].get<std::string>(), name);
            CHECK(hx(h.message) == r["popMessage"].get<std::string>(), name);
            CHECK(portablePopDigest(ua, h.pqzKeyHash, h.kemRecordHash) == h.portablePopDigest, name);
            CHECK(registrationDigest(h.portablePopDigest, h.pqzPopHash) == h.registrationDigest, name);
            CHECK(uaMessage(kind(r["kind"]), purposeTag("pop", 2), h.registrationDigest) == h.message, name);
            CHECK(mh(h.memberDigest) == opt_hex(r, "memberDigest"), name);
        }
        auto& a = r["attrs"];
        Bytes pk = bytes(a["pqzKey"]);
        if (!pk.empty()) {
            ++withPqz;
            uint64_t ver = a["kemVersion"].get<uint64_t>();
            std::optional<Kem> kem = ver ? std::optional<Kem>(Kem{ver, bytes(a["kemPk"])}) : std::nullopt;
            CHECK(hx(pqzRegMessage(ua, pk, kem)) == r["pqzRegMessage"].get<std::string>(), name);
        } else {
            CHECK(bytes(r["pqzRegMessage"]) == Bytes(32), name);
        }
        if (kind(r["kind"]) == 0x0120) ++msigs;
        ++n;
    }
    CHECK(n == 25 && withPqz == 8 && msigs == 6, "registration counts");
}

static void kem_record() {
    json p = load("portable.json");
    for (auto& r : p["kemRecords"]) {
        std::string id = r["id"].get<std::string>();
        Bytes ua = bytes(r["ua"]), pk = bytes(r["kemPk"]);
        uint64_t v = r["version"].get<uint64_t>();
        Bytes d = kemRecordDigest(ua, v, pk), m = kemRecordMessage(kind(r["kind"]), ua, v, pk);
        CHECK(hx(d) == r["digest"].get<std::string>(), id);
        CHECK(hx(m) == r["message"].get<std::string>(), id);
        CHECK(m == uaMessage(kind(r["kind"]), purposeTag("kem"), d), id);
        if (kind(r["kind"]) == 0x0120) CHECK(hx(memberDigest(ua, m)) == r["memberDigest"].get<std::string>(), id);
    }
    CHECK(p["kemRecords"].size() == 9, "kemRecords size");
    Bytes u(32, 1);
    CHECK(code_of([&] { kemRecordDigest(u, 0, Bytes(kKemPkLength)); }) == "UAKemVersion", "version 0");
    CHECK(code_of([&] { kemRecordDigest(u, 1, Bytes(kKemPkLength - 1)); }) == "UAKemKeyLength", "short key");
    CHECK(code_of([&] { kemRecordDigest(u, 1, Bytes(kKemPkLength + 1)); }) == "UAKemKeyLength", "long key");
    CHECK(hx(kemRecordDigest(u, UINT64_MAX, Bytes(kKemPkLength))) == "0xdea39530ca31145e34cb14a02a34952227ee39703d12cbeb2428539002c7dd31", "max version");  // pins the 8-byte version word
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
            CHECK(pqzKeyRecordDigest(g.pqzKeyDigest, g.pqzPopHash) == g.recordDigest, name);
            CHECK(g.memberDigest.has_value() == (k == 0x0120), name);
            CHECK(mh(g.memberDigest) == opt_hex(r, "memberDigest"), name);
            if (k == 0x0120) { ++msigRows; CHECK(memberDigest(ua, g.message) == *g.memberDigest, name); }
        }
        // write-once: a key already set refuses
        CHECK(code_of([&] { pqzKeyRecordMessage(k, ua, kd, key, std::nullopt, hash, true); }) == "UAPqzKeySet", name);
        ++n;
    }
    CHECK(n == 8 && msigRows == 8, "pqzKeyRecords counts");  // 4 msig rows, each with the proof bytes and hash-only
}

static void personal_sign_portable_purposes() {
    json p = load("portable.json");
    CHECK(isPortablePurpose(purposeTag("pop", 2)) && isPortablePurpose(purposeTag("kem")) && isPortablePurpose(purposeTag("pqz-key")), "portable");
    CHECK(!isPortablePurpose(purposeTag("metatx")) && !isPortablePurpose(purposeTag("pop")), "not portable");
    Bytes md = bytes(byName(p["registrations"], "name", "msig-pq-native")["memberDigest"]);
    // known answer from the JS reference (clientkeys ua.js); the prefix is 0x19 + "Ethereum Signed Message:\n32" (28 bytes);
    // personalSignDigest builds it in Rust, so no C++ "\x19E" escape (greedy hex) is involved
    CHECK(hx(md) == "0x606d9a70c70d39e5d8d079c3ae31eefa6db574219dab56d6c776cb6731e61a7c", "memberDigest");
    CHECK(hx(personalSignDigest(md)) == "0xe5d24987e9b4e710063a5432d6215eaead64d8dc073f7561726d21644d54c3d8", "personalSignDigest");
    auto& n = byName(p["negatives"], "name", "native-personal-sign-under-metatx");
    CHECK(!isPortablePurpose(bytes(n["mutation"]["set"]["purposeTag"])), "metatx is UAAuth");
}

static void holder_refusals() {
    json p = load("portable.json");
    auto& regs = p["registrations"];
    int run = 0, sigLevel = 0;
    for (auto& n : p["negatives"]) {
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
        } else if (entry == "setKemKey" && name == "kem-record-of-other-ua") {
            // the record of one UA offered for another: the signed message differs, so the signature cannot verify
            const json& k = byName(p["kemRecords"], "id", m["row"].get<std::string>());
            const json& t = byName(regs, "ua", set["ua"].get<std::string>());
            Bytes msg = kemRecordMessage(kind(t["kind"]), bytes(set["ua"]), k["version"].get<uint64_t>(), bytes(k["kemPk"]));
            CHECK(hx(msg) != k["message"].get<std::string>(), name);
            ++run;
        } else {
            ++sigLevel;  // signatures / native personal_sign: verified by the signature vectors
        }
    }
    CHECK(run == 56 && sigLevel == 7, "negatives counts");
    Bytes u(32, 1), key(16384), proof(32, 7);
    // malformed msig key data is UAKeyData, not "not a holder"; an msig without key data is not a holder
    for (Bytes kd : {Bytes{0, 2, 0}, Bytes{0, 2, 0, 2, 9, 9}})
        CHECK(code_of([&] { holderPopMessage(0x0120, u, kd, key, std::nullopt, proof); }) == "UAKeyData", "msig key data");
    CHECK(code_of([&] { holderPopMessage(0x0120, u, {}, key, std::nullopt, proof); }) == "UAPqzHolder", "msig without key data");
    CHECK(code_of([&] { holderPopMessage(0x0130, u, {}, key, std::nullopt, Bytes(31)); }) == "UAPqzPopHash", "31-byte hash");
    CHECK(code_of([&] { holderPopMessage(0x0130, u, {}, key, Bytes{}); }) == "UAPqzPopHash", "empty proof is no proof");
    CHECK(code_of([&] { holderPopMessage(0x0130, u, {}, Bytes(100), std::nullopt, proof); }) == "UAKeyData", "key length");
    CHECK(code_of([&] { holderPopMessage(0x0130, u, {}, std::nullopt, std::nullopt, std::nullopt, Kem{1, Bytes{}}); }) == "UAKemKeyLength", "kem key");
    CHECK(code_of([&] { holderPopMessage(0x0101, u, {}, std::nullopt, std::nullopt, std::nullopt, Kem{1, Bytes(kKemPkLength)}); }) == "UAKemHolder", "kem holder");
    // a zero-length proof hash is absent (same as no hash)
    CHECK(holderPopMessage(0x0130, u, {}).message == holderPopMessage(0x0130, u, {}, std::nullopt, std::nullopt, Bytes{}).message, "empty hash is absent");
}

int main(int argc, char** argv) {
    std::map<std::string, void (*)()> tests{
        {"table_groups_purposes_constants", table_groups_purposes_constants}, {"valid_rows", valid_rows},
        {"invalid_rows", invalid_rows}, {"natives_native_space_canonical_ids", natives_native_space_canonical_ids},
        {"messages", messages}, {"structures", structures}, {"portable", portable}, {"kem_record", kem_record},
        {"pqz_key_record", pqz_key_record}, {"personal_sign_portable_purposes", personal_sign_portable_purposes},
        {"holder_refusals", holder_refusals}};
    if (argc != 2 || !tests.count(argv[1])) { std::fprintf(stderr, "usage: vectors_test <name>\n"); return 2; }
    try { tests[argv[1]](); } catch (const std::exception& e) { std::fprintf(stderr, "exception: %s\n", e.what()); return 1; }
    return failures ? 1 : 0;
}
