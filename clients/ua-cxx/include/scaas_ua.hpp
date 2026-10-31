// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
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

// code(): UAKeyData, UAIdInNativeSpace, UAKindUnknown, UAKindNotDerived, UAKindNotNative, UAIdFormat, UAPurposeUnknown, UAPqzHolder, UAKemHolder,
// UAKemVersion, UAKemKeyLength, UAKemScheme, UAPqzPopHash, UAPqzKeySet.
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
// A KEM record attribute: (version >= 1, 1,601-byte key, scheme byte first). nullopt, or (0, empty), = absent.
using Kem = std::pair<uint64_t, Bytes>;
// The portable PoP of a registration (UA-8 P1, P2); every hash is 32 bytes, 0 when absent.
struct HolderPop {
    Bytes pqzKeyHash, pqzPopHash, kemRecordHash, portableRecordDigest, registrationDigest;
    Bytes message;  // uaMessage(kind, POP_V2, registrationDigest): what the signer's pop signs (every kind)
    // msig only: memberDigest(ua, message), what each derived member signs under `member`. A native member signs
    // registrationDigest itself (eth_signTypedData_v4, typed-signing TS-D4).
    std::optional<Bytes> memberDigest;
};
// The PQZ key record of setPqzKey (ruling A1-I1).
struct PqzKeyRecord {
    Bytes pqzKeyHash, pqzPopHash, pqzKeyDigest, recordDigest;
    Bytes message;         // uaMessage(kind, PURPOSE_PQZ_KEY, recordDigest): what the UA signs
    Bytes pqzRegMessage;   // uaMessage(0x0142, PURPOSE_PQZ_KEY, pqzKeyDigest): what the key's R_REG proves over
    std::optional<Bytes> memberDigest;  // msig only, as in HolderPop
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
Bytes purposeTag(const std::string& purpose, uint32_t version = 1);  // every purpose is v1; pop is also v2 (UA-8)
constexpr uint8_t kKemSchemeMlkem1024X25519 = 1;  // kemPk[0] (CTR-UA-32); 2 = ML-KEM-1024 + HQC + X25519 is reserved (UAKemScheme)
constexpr size_t kKemPkLength = 1601;  // 0x01 ‖ ML-KEM-1024 ek ‖ X25519 pk (X-Wing order)
Bytes uaOf(uint16_t kind, const Bytes& keyData);
Bytes deriveUA(uint16_t kind, const Bytes& keyData, bool hederaNative);
Bytes nativeId(uint16_t kind, const Bytes& raw);
std::optional<Bytes> keyHashOf(uint16_t kind, const Bytes& keyData);  // nullopt for structure kinds
void validateKeyData(uint16_t kind, const Bytes& keyData, bool hederaNative);
bool inNativeSpace(const Bytes& id);
bool isNative(uint16_t kind);
bool isZether(uint16_t kind);
bool isPqzHolder(uint16_t kind);  // 0x0130-0x0132 may hold a PQZ key
bool msigPqzEligible(const Bytes& keyData);  // msig members outside 0x0130-0x0133 weigh less than the threshold
bool isSigning(uint16_t kind);
bool isMember(uint16_t kind, bool hederaNative);
Bytes uaMessage(uint16_t kind, const Bytes& purposeTag, const Bytes& digest);
Bytes chainKeyHash(uint64_t chainId);
// The portable records are typed EIP-712 structs (typed-signing TS-D1): typed(s) = keccak256(0x1901 ‖ DS_P ‖ hashStruct(s)), DS_P the
// domain EIP712Domain(string name,string version) = ("SCaaS UA Portable", "1"): no chain id, verifying contract or salt.
Bytes portableDomainSeparator();
// hashStruct(UAKemRecord{ua, version, scheme = kemPk[0], keccak256(kemPk)}), the kem word of a portable record; (0, empty) is the
// zero record UAKemRecord{ua, 0, 0, 0} (no KEM record), otherwise the rules of kemRecordDigest.
Bytes kemRecordHash(const Bytes& ua, uint64_t version, const Bytes& kemPk);
// typed(UAPortableRecord{ua, kind, pqzKeyHash, kem}): what R_REG proves over at register; pqzKeyHash 32 zero bytes without a key.
Bytes portableRecordDigest(const Bytes& ua, uint16_t kind, const Bytes& pqzKeyHash, const Bytes& kemRecordHash);
// typed(UARegistration{record, pqzPopHash}): what the signer's pop signs under uaMessage(kind, POP_V2, ·) (and a native msig member itself).
Bytes registrationDigest(const Bytes& ua, uint16_t kind, const Bytes& pqzKeyHash, const Bytes& kemRecordHash, const Bytes& pqzPopHash);
// typed(UAKemRecord{…}) that setKemKey signs: version 1 … 2^64 − 1 (UAKemVersion), a 1,601-byte key, scheme byte first (UAKemScheme for an id other than 1, UAKemKeyLength).
Bytes kemRecordDigest(const Bytes& ua, uint64_t version, const Bytes& kemPk);
Bytes kemRecordMessage(uint16_t kind, const Bytes& ua, uint64_t version, const Bytes& kemPk);  // uaMessage(kind, PURPOSE_KEM, digest)
// The portable PoP message of a registration. pqzKey with its proof pqzPop (or only its hash pqzPopHash; a relayer may hold only
// that; an empty hash is absent, another length than 32 is UAPqzPopHash) and the initial KEM record; nullopt = absent. Only
// holders carry them (UAPqzHolder, UAKemHolder; an msig needs keyData to show it is PQ-eligible); a PQZ key always comes with its
// proof hash and only with it (UAPqzPopHash).
HolderPop holderPopMessage(uint16_t kind, const Bytes& ua, const Bytes& keyData, const std::optional<Bytes>& pqzKey = std::nullopt,
                           const std::optional<Bytes>& pqzPop = std::nullopt, const std::optional<Bytes>& pqzPopHash = std::nullopt,
                           const std::optional<Kem>& kem = std::nullopt);
// The message R_REG proves over: uaMessage(0x0142, POP_V2, portableRecordDigest(ua, kind, keyHash(0x0142, pqzKey), kemRecordHash)),
// kind the registering kind.
Bytes pqzRegMessage(uint16_t kind, const Bytes& ua, const Bytes& pqzKey, const std::optional<Kem>& kem = std::nullopt);
Bytes pqzKeyDigest(const Bytes& ua, const Bytes& pqzKeyHash);  // typed(UAPqzKey{ua, pqzKeyHash})
// typed(UAPqzKeyRecord{UAPqzKey{ua, pqzKeyHash}, pqzPopHash}): what setPqzKey's signature signs under uaMessage(kind, PURPOSE_PQZ_KEY, ·)
Bytes pqzKeyRecordDigest(const Bytes& ua, const Bytes& pqzKeyHash, const Bytes& pqzPopHash);
// The signed, portable, write-once PQZ key record of setPqzKey: alreadySet = the registration has a key (UAPqzKeySet). The holder
// rules of holderPopMessage; the key and its proof (or hash) are both required.
PqzKeyRecord pqzKeyRecordMessage(uint16_t kind, const Bytes& ua, const Bytes& keyData, const Bytes& pqzKey,
                                 const std::optional<Bytes>& pqzPop = std::nullopt, const std::optional<Bytes>& pqzPopHash = std::nullopt,
                                 bool alreadySet = false);
// POP_V2, KEM, PQZ_KEY: the purposes where a native msig member signs the record's typed digest itself (TS-D4); every other
// purpose stays UAAuth.
bool isPortablePurpose(const Bytes& purposeTag);
Bytes uaAuthDomainSeparator(const Domain& d);
Bytes uaAuthDigest(const Domain& d, const Bytes& ua, const Bytes& purposeTag, const Bytes& digest);
Bytes memberDigest(const Bytes& structureUa, const Bytes& uaMsg);
std::string canonicalId(const std::string& text);
Bytes encodeMsig(uint16_t threshold, const std::vector<Member>& members);

}  // namespace scaas::ua
