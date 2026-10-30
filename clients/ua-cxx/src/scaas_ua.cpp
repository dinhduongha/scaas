// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Implements include/scaas_ua.hpp over the cxx-generated bridge; translates rust::Error into scaas::ua::Error.
#include "scaas_ua.hpp"

#include <stdexcept>

#include "rust/cxx.h"  // rust::Error
#include "scaas-ua-cxx/src/lib.rs.h"

namespace scaas::ua {
namespace {
Error translate(const rust::Error& e) {
    std::string m = e.what();
    auto p = m.find(": ");
    return p == std::string::npos ? Error(m, "") : Error(m.substr(0, p), m.substr(p + 2));
}
template <class F>
auto call(F&& f) -> decltype(f()) {
    try {
        return f();
    } catch (const rust::Error& e) {
        throw translate(e);
    }
}
Bytes bytes(const rust::Vec<uint8_t>& v) { return Bytes(v.begin(), v.end()); }
rust::Slice<const uint8_t> sl(const Bytes& b) { return {b.data(), b.size()}; }
std::optional<Bytes> opt(const rust::Vec<uint8_t>& v) {
    if (v.empty()) return std::nullopt;
    return bytes(v);
}
KindInfo conv(const ffi::KindInfo& k) {
    return {k.kind, std::string(k.name), k.native, std::vector<size_t>(k.lengths.begin(), k.lengths.end()),
            k.has_group ? std::optional<std::string>(std::string(k.group)) : std::nullopt};
}
ffi::Member conv(const Member& m) {
    rust::Vec<uint8_t> id;
    for (auto b : m.id) id.push_back(b);
    return {m.kind, std::move(id), m.weight};
}
}  // namespace

KindInfo kindInfo(uint16_t k) { return call([&] { return conv(ffi::kind_info(k)); }); }
std::vector<KindInfo> kinds() {
    std::vector<KindInfo> out;
    for (size_t i = 0, n = ffi::kind_count(); i < n; ++i) out.push_back(conv(ffi::kind_at(i)));
    return out;
}
Bytes tag(uint16_t k) { return call([&] { return bytes(ffi::tag(k)); }); }
std::string kindTagString(uint16_t k) { return call([&] { return std::string(ffi::kind_tag_string(k)); }); }
// Non-UTF-8 text is not a known group / purpose / id: std::invalid_argument from rust::Str becomes the matching code.
std::optional<Bytes> groupTag(const std::string& g) {
    try {
        return opt(ffi::group_tag(g));
    } catch (const std::invalid_argument&) {
        return std::nullopt;
    }
}
std::optional<std::string> groupTagString(const std::string& g) {
    try {
        std::string s(ffi::group_tag_string(g));
        if (s.empty()) return std::nullopt;
        return s;
    } catch (const std::invalid_argument&) {
        return std::nullopt;
    }
}
Bytes msgTag() { return bytes(ffi::msg_tag()); }
Bytes kemRecordTag() { return bytes(ffi::kem_record_tag()); }
Bytes pqzKeyRecordTag() { return bytes(ffi::pqz_key_record_tag()); }
Bytes purposeTag(const std::string& p, uint32_t version) {
    try {
        return call([&] { return bytes(ffi::purpose_tag_v(p, version)); });
    } catch (const std::invalid_argument&) {
        throw Error("UAPurposeUnknown", "");
    }
}
Bytes uaOf(uint16_t k, const Bytes& d) { return call([&] { return bytes(ffi::ua_of(k, sl(d))); }); }
Bytes deriveUA(uint16_t k, const Bytes& d, bool h) { return call([&] { return bytes(ffi::derive_ua(k, sl(d), h)); }); }
Bytes nativeId(uint16_t k, const Bytes& r) { return call([&] { return bytes(ffi::native_id(k, sl(r))); }); }
std::optional<Bytes> keyHashOf(uint16_t k, const Bytes& d) { return call([&] { return opt(ffi::key_hash_of(k, sl(d))); }); }
void validateKeyData(uint16_t k, const Bytes& d, bool h) { call([&] { ffi::validate_key_data(k, sl(d), h); }); }
bool inNativeSpace(const Bytes& id) { return call([&] { return ffi::in_native_space(sl(id)); }); }
bool isNative(uint16_t k) { return ffi::is_native(k); }
bool isZether(uint16_t k) { return ffi::is_zether(k); }
bool isPqzHolder(uint16_t k) { return ffi::is_pqz_holder(k); }
bool msigPqzEligible(const Bytes& d) { return call([&] { return ffi::msig_pqz_eligible(sl(d)); }); }
bool isSigning(uint16_t k) { return ffi::is_signing(k); }
bool isMember(uint16_t k, bool h) { return ffi::is_member(k, h); }
Bytes uaMessage(uint16_t k, const Bytes& p, const Bytes& d) { return call([&] { return bytes(ffi::ua_message(k, sl(p), sl(d))); }); }
Bytes chainKeyHash(uint64_t c) { return bytes(ffi::chain_key_hash(c)); }
Bytes portablePopDigest(const Bytes& ua, const Bytes& pqzKeyHash, const Bytes& kemRecordHash) {
    return call([&] { return bytes(ffi::portable_pop_digest(sl(ua), sl(pqzKeyHash), sl(kemRecordHash))); });
}
Bytes registrationDigest(const Bytes& portable, const Bytes& pqzPopHash) {
    return call([&] { return bytes(ffi::registration_digest(sl(portable), sl(pqzPopHash))); });
}
Bytes kemRecordDigest(const Bytes& ua, uint64_t version, const Bytes& kemPk) {
    return call([&] { return bytes(ffi::kem_record_digest(sl(ua), version, sl(kemPk))); });
}
Bytes kemRecordMessage(uint16_t kind, const Bytes& ua, uint64_t version, const Bytes& kemPk) {
    return call([&] { return bytes(ffi::kem_record_message(kind, sl(ua), version, sl(kemPk))); });
}
namespace {
const Bytes kNone;
const Bytes& orNone(const std::optional<Bytes>& b) { return b ? *b : kNone; }
std::optional<Bytes> memberOf(bool has, const rust::Vec<uint8_t>& v) { return has ? std::optional<Bytes>(bytes(v)) : std::nullopt; }
}  // namespace
HolderPop holderPopMessage(uint16_t kind, const Bytes& ua, const Bytes& keyData, const std::optional<Bytes>& pqzKey,
                           const std::optional<Bytes>& pqzPop, const std::optional<Bytes>& pqzPopHash, const std::optional<Kem>& kem) {
    return call([&] {
        auto r = ffi::holder_pop_message(kind, sl(ua), sl(keyData), sl(orNone(pqzKey)), sl(orNone(pqzPop)), sl(orNone(pqzPopHash)),
                                         kem ? kem->first : 0, sl(kem ? kem->second : kNone));
        return HolderPop{bytes(r.pqz_key_hash),   bytes(r.pqz_pop_hash), bytes(r.kem_record_hash),
                         bytes(r.portable_pop_digest), bytes(r.registration_digest), bytes(r.message),
                         memberOf(r.has_member_digest, r.member_digest)};
    });
}
Bytes pqzRegMessage(const Bytes& ua, const Bytes& key, const std::optional<Kem>& kem) {
    return call([&] { return bytes(ffi::pqz_reg_message(sl(ua), sl(key), kem ? kem->first : 0, sl(kem ? kem->second : kNone))); });
}
Bytes pqzKeyDigest(const Bytes& ua, const Bytes& pqzKeyHash) { return call([&] { return bytes(ffi::pqz_key_digest(sl(ua), sl(pqzKeyHash))); }); }
Bytes pqzKeyRecordDigest(const Bytes& keyDigest, const Bytes& pqzPopHash) {
    return call([&] { return bytes(ffi::pqz_key_record_digest(sl(keyDigest), sl(pqzPopHash))); });
}
PqzKeyRecord pqzKeyRecordMessage(uint16_t kind, const Bytes& ua, const Bytes& keyData, const Bytes& pqzKey,
                                 const std::optional<Bytes>& pqzPop, const std::optional<Bytes>& pqzPopHash, bool alreadySet) {
    return call([&] {
        auto r = ffi::pqz_key_record_message(kind, sl(ua), sl(keyData), sl(pqzKey), sl(orNone(pqzPop)), sl(orNone(pqzPopHash)), alreadySet);
        return PqzKeyRecord{bytes(r.pqz_key_hash), bytes(r.pqz_pop_hash), bytes(r.pqz_key_digest), bytes(r.record_digest),
                            bytes(r.message), bytes(r.pqz_reg_message), memberOf(r.has_member_digest, r.member_digest)};
    });
}
Bytes personalSignDigest(const Bytes& digest) { return call([&] { return bytes(ffi::personal_sign_digest(sl(digest))); }); }
bool isPortablePurpose(const Bytes& tag) { return call([&] { return ffi::is_portable_purpose(sl(tag)); }); }
Bytes uaAuthDomainSeparator(const Domain& d) {
    return call([&] { return bytes(ffi::ua_auth_domain_separator(d.generation, d.chainId, sl(d.registry), sl(d.chainUid))); });
}
Bytes uaAuthDigest(const Domain& d, const Bytes& ua, const Bytes& p, const Bytes& dg) {
    return call([&] {
        return bytes(ffi::ua_auth_digest(d.generation, d.chainId, sl(d.registry), sl(d.chainUid), sl(ua), sl(p), sl(dg)));
    });
}
Bytes memberDigest(const Bytes& s, const Bytes& m) { return call([&] { return bytes(ffi::member_digest(sl(s), sl(m))); }); }
std::string canonicalId(const std::string& t) {
    try {
        return call([&] { return std::string(ffi::canonical_id(t)); });
    } catch (const std::invalid_argument&) {
        throw Error("UAIdFormat", "");
    }
}
Bytes encodeMsig(uint16_t th, const std::vector<Member>& ms) {
    std::vector<ffi::Member> v;
    for (auto& m : ms) v.push_back(conv(m));
    return call([&] { return bytes(ffi::encode_msig(th, {v.data(), v.size()})); });
}

}  // namespace scaas::ua
