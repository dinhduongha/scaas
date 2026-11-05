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
// UAKemVersion, UAKemKeyLength, UAKemScheme, UAPqzPopHash, UAPqzKeySet, UAArgument (the JSON calls only).
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
// governance_bits.json's row of `bit` as JSON {bit, name, type, sentences} (bits 0-21; any other throws UAArgument)
std::string governanceBit(uint8_t bit);
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
bool isPqzHolder(uint16_t kind);  // 0x0130-0x0132, 0x0134 and 0x0135 may hold a PQZ key
bool msigPqzEligible(const Bytes& keyData);  // msig members outside 0x0130-0x0135 weigh less than the threshold; an msig member: UAMemberUnknown
// The With forms take inner, the msig members' structures: {id: keyData} JSON as registrationArgs' inner ("" = none; over 65,536 bytes,
// more than 16 entries or key data over 580 bytes is UAArgument). An msig member counts as PQ iff it is PQ-eligible itself, read from its
// entry; a member without an entry, or an entry that holds an msig (two levels only), is UAMemberUnknown.
bool msigPqzEligibleWith(const Bytes& keyData, const std::string& inner);
bool isSigning(uint16_t kind);
bool isMember(uint16_t kind, bool hederaNative);
Bytes uaMessage(uint16_t kind, const Bytes& purposeTag, const Bytes& digest);
Bytes chainKeyHash(uint64_t chainId);
// keccak256(data): e.g. memberSigHashOf, the hash of a slot's sig, or of an msig member's abi.encode(InnerSig[]).
Bytes keccak256(const Bytes& data);
// The portable records are typed EIP-712 structs (typed-signing TS-D1): typed(s) = keccak256(0x1901 ‖ DS_P ‖ hashStruct(s)), DS_P the
// domain EIP712Domain(string name,string version) = ("SCaaS UA Portable", "1"): no chain id, verifying contract or salt.
Bytes portableDomainSeparator();
// hashStruct(UAKemRecord{ua, version, scheme = kemPk[0], keccak256(kemPk)}), the kem word of a portable record; (0, empty) is the
// zero record UAKemRecord{ua, 0, 0, 0} (no KEM record), (0, key) the register key's record (owner 2026-10-31), otherwise the rules
// of kemRecordDigest.
Bytes kemRecordHash(const Bytes& ua, uint64_t version, const Bytes& kemPk);
// typed(UAPortableRecord{ua, kind, pqzKeyHash, kem}): what R_REG proves over at register; pqzKeyHash 32 zero bytes without a key.
Bytes portableRecordDigest(const Bytes& ua, uint16_t kind, const Bytes& pqzKeyHash, const Bytes& kemRecordHash);
// typed(UARegistration{record, pqzPopHash}): what the signer's pop signs under uaMessage(kind, POP_V2, ·) (and a native msig member itself).
Bytes registrationDigest(const Bytes& ua, uint16_t kind, const Bytes& pqzKeyHash, const Bytes& kemRecordHash, const Bytes& pqzPopHash);
// typed(UAKemRecord{…}) that setKemKey signs: version 1 … 2^64 − 1 (UAKemVersion), a 1,601-byte key, scheme byte first (UAKemScheme for an id other than 1, UAKemKeyLength).
Bytes kemRecordDigest(const Bytes& ua, uint64_t version, const Bytes& kemPk);
Bytes kemRecordMessage(uint16_t kind, const Bytes& ua, uint64_t version, const Bytes& kemPk);  // uaMessage(kind, PURPOSE_KEM, digest)
// The portable PoP message of a registration. pqzKey with its proof pqzPop (or only its hash pqzPopHash; a relayer may hold only
// that; an empty hash is absent, another length than 32 is UAPqzPopHash) and the initial KEM key kemPk (1,601 bytes, scheme byte
// first; its record is always version 0, owner 2026-10-31); nullopt / empty = absent. Only
// holders carry them (UAPqzHolder, UAKemHolder; an msig needs keyData to show it is PQ-eligible); a PQZ key always comes with its
// proof hash and only with it (UAPqzPopHash).
HolderPop holderPopMessage(uint16_t kind, const Bytes& ua, const Bytes& keyData, const std::optional<Bytes>& pqzKey = std::nullopt,
                           const std::optional<Bytes>& pqzPop = std::nullopt, const std::optional<Bytes>& pqzPopHash = std::nullopt,
                           const std::optional<Bytes>& kemPk = std::nullopt);
HolderPop holderPopMessageWith(uint16_t kind, const Bytes& ua, const Bytes& keyData, const std::string& inner,
                               const std::optional<Bytes>& pqzKey = std::nullopt, const std::optional<Bytes>& pqzPop = std::nullopt,
                               const std::optional<Bytes>& pqzPopHash = std::nullopt, const std::optional<Bytes>& kemPk = std::nullopt);
// The message R_REG proves over: uaMessage(0x0142, POP_V2, portableRecordDigest(ua, kind, keyHash(0x0142, pqzKey), kemRecordHash)),
// kind the registering kind, kemPk the register KEM key (version 0).
Bytes pqzRegMessage(uint16_t kind, const Bytes& ua, const Bytes& pqzKey, const std::optional<Bytes>& kemPk = std::nullopt);
Bytes pqzKeyDigest(const Bytes& ua, const Bytes& pqzKeyHash);  // typed(UAPqzKey{ua, pqzKeyHash})
// typed(UAPqzKeyRecord{UAPqzKey{ua, pqzKeyHash}, pqzPopHash}): what setPqzKey's signature signs under uaMessage(kind, PURPOSE_PQZ_KEY, ·)
Bytes pqzKeyRecordDigest(const Bytes& ua, const Bytes& pqzKeyHash, const Bytes& pqzPopHash);
// typed(UAMembership{ua, member}): what member signs to accept its slot in the msig ua (CTR-UA-37): a native member this digest
// itself, a derived member memberDigest(ua, uaMessage(MSIG, PURPOSE_MEMBERSHIP, ·)) under member
Bytes membershipDigest(const Bytes& ua, const Bytes& member);
// The signed, portable, write-once PQZ key record of setPqzKey: alreadySet = the registration has a key (UAPqzKeySet). The holder
// rules of holderPopMessage; the key and its proof (or hash) are both required.
PqzKeyRecord pqzKeyRecordMessage(uint16_t kind, const Bytes& ua, const Bytes& keyData, const Bytes& pqzKey,
                                 const std::optional<Bytes>& pqzPop = std::nullopt, const std::optional<Bytes>& pqzPopHash = std::nullopt,
                                 bool alreadySet = false);
PqzKeyRecord pqzKeyRecordMessageWith(uint16_t kind, const Bytes& ua, const Bytes& keyData, const std::string& inner, const Bytes& pqzKey,
                                     const std::optional<Bytes>& pqzPop = std::nullopt,
                                     const std::optional<Bytes>& pqzPopHash = std::nullopt, bool alreadySet = false);
// The MemberSig a copy sends to acceptMembership from the bytes of its UAMemberSig alone, which hash to memberSigHashOf(ua, index) (CTR-UA-37), as the slot JSON {index, members:
// [{index, sig}], sig} of a registrationArgs pop entry: keyData the msig ua's, stored a signing slot's sig or an msig slot's
// abi.encode(InnerSig[]), canonical, at most 16 entries. Anything else, or an index past the members, is UAUnauthorized.
std::string replayedMemberSig(const Bytes& keyData, uint16_t index, const Bytes& stored);
// POP_V2, KEM, PQZ_KEY: the purposes where a native msig member signs the record's typed digest itself (TS-D4); every other
// purpose stays UAAuth.
bool isPortablePurpose(const Bytes& purposeTag);
Bytes uaAuthDomainSeparator(const Domain& d);
Bytes uaAuthDigest(const Domain& d, const Bytes& ua, const Bytes& purposeTag, const Bytes& digest);
Bytes memberDigest(const Bytes& structureUa, const Bytes& uaMsg);
std::string canonicalId(const std::string& text);
// How a client shows a bytes32 id before the user signs (ua-mtx-merge spec §6): the EIP-55 address of a native-space id, else the
// URN urn:scaas:ua:v1:<kind name>:<hex32> under kind, the id's registry kind (0 = none known: UAKindUnknown). id: "0x" + 64 hex.
std::string idDisplay(const std::string& id, uint16_t kind);
Bytes encodeMsig(uint16_t threshold, const std::vector<Member>& members);
// The registry's explicit arguments of a registration, JSON in and out. In: {kind, keyData, pqzKey, pqzPopHash, pqzPop, kemPk, pop,
// kemCommit, inner}: bytes as "0x…" hex, an absent field is empty, an msig's pop is [{index, members: [{index, sig}], sig}], inner
// {id: keyData} its msig members' structures, kemCommit true / false forces the
// KEM form (absent: the hash commit only when the full call is over 261,909 B). Out: {args, kemFill, calldataLength,
// kemFillCalldataLength}: args.entry names the registry entry, kemFill is the setKemKey(ua, 0, …) that stores a hash-committed key
// (null otherwise). UAArgument when the input is not this JSON.
std::string registrationArgs(const std::string& input);
// setKemKey's explicit arguments, JSON in and out. In: {ua, version, kemPk, sig}, sig the UASig {keyData, signature, members: [{index,
// members: [{index, sig}], sig}]} (absent: empty, the version-0 fill of a hash commit). Out: {ua, version, kem, sig}.
std::string setKemKeyArgs(const std::string& input);
// setPqzKey's explicit arguments, JSON in and out. In: {ua, pqzKey, pqzPopHash, sig}, sig as setKemKeyArgs. Out: the same fields, sig complete.
std::string setPqzKeyArgs(const std::string& input);

}  // namespace scaas::ua
