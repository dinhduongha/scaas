// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
// Plain C++17 API over the Rust crate scaas-ua (via cxx). No Qt. Errors are thrown as scaas::ua::Error.
#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace scaas::ua {

using Bytes = std::vector<uint8_t>;

// code(): UAKeyData, UAIdInNativeSpace, UAKindUnknown, UAKindNotDerived, UAKindNotNative, UAIdFormat, UAPurposeUnknown.
// reason(): the label after "UAKeyData: " (empty for every other code).
class Error : public std::runtime_error {
public:
    Error(std::string code, std::string reason)
        : std::runtime_error(reason.empty() ? code : code + ": " + reason), code_(std::move(code)), reason_(std::move(reason)) {}
    const std::string& code() const noexcept { return code_; }
    const std::string& reason() const noexcept { return reason_; }

private:
    std::string code_, reason_;
};

struct KindInfo {
    uint16_t kind;
    std::string name;
    bool native;
    std::vector<size_t> lengths;  // empty = variable length
    std::optional<std::string> group;
};
struct Member {
    uint16_t kind;
    Bytes id;  // 32 bytes
    uint16_t weight;
};
struct Domain {
    uint32_t generation;
    uint64_t chainId;
    Bytes registry;  // 20 bytes
    Bytes chainUid;  // 32 bytes
};

KindInfo kindInfo(uint16_t kind);
std::vector<KindInfo> kinds();  // the whole table, in order
Bytes tag(uint16_t kind);
std::string kindTagString(uint16_t kind);
std::optional<Bytes> groupTag(const std::string& group);
std::optional<std::string> groupTagString(const std::string& group);
Bytes msgTag();
Bytes purposeTag(const std::string& purpose);
Bytes uaOf(uint16_t kind, const Bytes& keyData);
Bytes deriveUA(uint16_t kind, const Bytes& keyData, bool hederaNative);
Bytes nativeId(uint16_t kind, const Bytes& raw);
std::optional<Bytes> keyHashOf(uint16_t kind, const Bytes& keyData);  // nullopt for structure kinds
void validateKeyData(uint16_t kind, const Bytes& keyData, bool hederaNative);
bool inNativeSpace(const Bytes& id);
bool isNative(uint16_t kind);
bool isZether(uint16_t kind);
bool isSigning(uint16_t kind);
bool isMember(uint16_t kind, bool hederaNative);
Bytes uaMessage(uint16_t kind, const Bytes& purposeTag, const Bytes& digest);
Bytes chainKeyHash(uint64_t chainId);
Bytes popDigest(uint64_t chainId, const Bytes& chainUid, const Bytes& registry, const Bytes& ua, const Bytes& authRef);
Bytes uaAuthDomainSeparator(const Domain& d);
Bytes uaAuthDigest(const Domain& d, const Bytes& ua, const Bytes& purposeTag, const Bytes& digest);
Bytes memberDigest(const Bytes& structureUa, const Bytes& uaMsg);
std::string canonicalId(const std::string& text);
Bytes encodeMsig(uint16_t threshold, const std::vector<Member>& members);

}  // namespace scaas::ua
