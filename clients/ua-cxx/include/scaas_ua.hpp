// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Plain C++17 API over the Rust crate scaas-ua (via cxx). No Qt. Errors are thrown as scaas::ua::Error.
#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
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


// ---------------------------------------------------------------------------------------------------------------------------
// The wallet (ua-rs-sign T13a, spec §9.1, §9.2, §10): the Rust API of scaas_ua::wallet and the Zether and PQZ facades, through
// cxx. Handles are move-only classes; each frees its Rust handle exactly once (a moved-from handle throws UAArgument on use). A
// key handle holds its wallet's store, a generation and a slot, never secret bytes: after Wallet::lock() or the wallet's
// destruction every earlier handle answers UAKeyRevoked (unlock does not revive it), public data stays readable.
//
// Secrets (spec §9.2 "caller memory"): every secret input (mnemonic, passphrases, PRF secret, an imported key, the seed-backup
// answers) is a Secret& that the call zeroizes before it returns, whatever the outcome; every secret output (an opened plaintext,
// a shared secret, a revealed phrase, the exported PQZ leaf, a balance-cache plaintext) is a Secret, wiped by wipe() and by its
// destructor. An empty Secret is an absent one (prf32, an empty BIP-39 passphrase). Errors: Error::code() "UA<Name>" as the wallet
// vector files ("UAKeyRevoked", "UASealOpen", ...); no error carries an input.
// ---------------------------------------------------------------------------------------------------------------------------

namespace ffi {
struct Wallet;
struct Key;
struct KemKey;
struct LinkSession;
struct SeedBackup;
struct ZetherKey;
struct PqzKey;
}  // namespace ffi

// The surface generation this header was written for (the C ABI's SCAAS_UA_ABI_VERSION, 6) and the build features it needs
// (the bits of scaas_ua_features()).
constexpr uint32_t kAbiVersion = 6;
namespace feature {
constexpr uint64_t kWallet = 1u << 0, kPq = 1u << 1, kFalcon = 1u << 2, kZether = 1u << 3, kPqz = 1u << 4,
                   kPqzSetN2048Kmax1024 = 1u << 5, kPqzSetN2304Kmax4096 = 1u << 6, kPqzSetN2560Kmax16384 = 1u << 7,
                   kPqzSetN2816Kmax65536 = 1u << 8, kExternal = 1u << 9, kMlock = 1u << 10;
}
constexpr uint64_t kRequiredFeatures =
    feature::kWallet | feature::kPq | feature::kZether | feature::kPqz | feature::kPqzSetN2304Kmax4096;
// The PQZ facade's largest output (SCAAS_UA_PQZ_OUT_MAX): a proof is returned whole, never sized by a query.
constexpr size_t kPqzOutMax = 1052672;
constexpr uint32_t kCoinDefault = 0xffffffffu;  // nativeKey: the network's own SLIP-44 coin type
constexpr uint32_t kAeadAes256Gcm = 1, kAeadAes256GcmSiv = 2;
constexpr uint32_t kZetherUseConf = 7, kZetherUseViewing = 8;

// Checks the linked core against this header: abi_version == kAbiVersion and every bit of kRequiredFeatures present, else
// Error("UAAbiMismatch", "abi_version" | "features"). Every entry point that takes no handle runs it first.
void load();
uint64_t features();     // what the linked core holds (feature::*)
int64_t liveHandles();   // handles alive now (a test of "freed exactly once")
namespace detail {
// Where load() reads the core's values; the linked core unless a test points them elsewhere.
extern uint32_t (*reportedAbiVersion)();
extern uint64_t (*reportedFeatures)();
void drop(ffi::Wallet*) noexcept;
void drop(ffi::Key*) noexcept;
void drop(ffi::KemKey*) noexcept;
void drop(ffi::LinkSession*) noexcept;
void drop(ffi::SeedBackup*) noexcept;
void drop(ffi::ZetherKey*) noexcept;
void drop(ffi::PqzKey*) noexcept;
}  // namespace detail

// Bytes the binding wipes: at destruction, on wipe(), and (as an input) inside the call it is passed to.
class Secret {
public:
    Secret() = default;
    explicit Secret(std::string_view s) : b_(s.begin(), s.end()) {}
    explicit Secret(Bytes b) : b_(std::move(b)) {}
    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;
    Secret(Secret&& o) noexcept : b_(std::move(o.b_)) { o.b_.clear(); }
    Secret& operator=(Secret&& o) noexcept {
        if (this != &o) {
            wipe();
            b_ = std::move(o.b_);
            o.b_.clear();
        }
        return *this;
    }
    ~Secret() { wipe(); }
    void wipe() noexcept;
    uint8_t* data() noexcept { return b_.data(); }
    const uint8_t* data() const noexcept { return b_.data(); }
    size_t size() const noexcept { return b_.size(); }
    bool empty() const noexcept { return b_.empty(); }
    std::string_view view() const noexcept { return {reinterpret_cast<const char*>(b_.data()), b_.size()}; }
    Bytes copy() const { return b_; }

private:
    Bytes b_;
};

template <class T>
class Handle {
public:
    Handle(Handle&& o) noexcept : p_(std::exchange(o.p_, nullptr)) {}
    Handle& operator=(Handle&& o) noexcept {
        if (this != &o) {
            reset();
            p_ = std::exchange(o.p_, nullptr);
        }
        return *this;
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    ~Handle() { reset(); }
    explicit operator bool() const noexcept { return p_ != nullptr; }
    const T& ffi() const {
        if (!p_) throw Error("UAArgument", "");
        return *p_;
    }
    explicit Handle(T* p) noexcept : p_(p) {}  // adopts a handle the bridge returned

protected:
    void reset() noexcept {
        if (p_) detail::drop(std::exchange(p_, nullptr));
    }
    T* p_ = nullptr;
};

class Key;
class KemKey;
class LinkSession;
class SeedBackup;
class ZetherKey;
class PqzKey;

struct MemoryProtection {
    size_t chunks, locked, noDump;
};
// A recipient of Wallet::backupSeal: the KEM key kemPk of record `version` of the UA of (kind, keyData), a single-key KEM holder;
// or, with `ephemeral`, an ephemeral key (kind, keyData and version unread).
struct Recipient {
    uint16_t kind = 0;
    Bytes keyData;
    uint64_t version = 0;
    Bytes kemPk;
    bool ephemeral = false;
};
// A seal's named fields (version and scheme 1).
struct Sealed {
    Bytes mlkemCt, x25519Eph, ciphertext;
};
struct Encapsulated {
    Bytes mlkemCt, x25519Eph;
    Secret ss;
};

class Wallet : public Handle<ffi::Wallet> {
public:
    using Handle::Handle;
    // A new wallet of 24 words (OS entropy) and its recovery phrase.
    static std::pair<Wallet, SeedBackup> generate();
    static Wallet fromMnemonic(Secret& words, Secret& bip39Passphrase);
    // Exactly one of vaultPassphrase / prf32 is meant (both given: the PRF secret, the passphrase not tried; neither: UAArgument).
    static Wallet openVault(const std::string& vaultJson, Secret& vaultPassphrase, Secret& prf32, Secret& bip39Passphrase);
    // The opener's JSON: expectJson required, membersJson "" = none, acceptedJson "" = no lookup. nullopt: an equal generation
    // installed nothing.
    static std::optional<Wallet> restoreBackup(const KemKey& kk, const std::string& containerJson, const std::string& expectJson,
                                               const std::string& membersJson, const std::string& acceptedJson, Secret& bip39Passphrase);
    std::optional<Wallet> restoreBackupOver(const KemKey& kk, const std::string& containerJson, const std::string& expectJson,
                                            const std::string& membersJson, const std::string& acceptedJson,
                                            Secret& bip39Passphrase) const;
    std::optional<Wallet> restoreBackupRollback(const KemKey& kk, const std::string& containerJson, const std::string& expectJson,
                                                const std::string& membersJson, const std::string& acceptedJson,
                                                Secret& bip39Passphrase) const;
    // Consumes the session (later calls on it: UAKeyRevoked), whatever the outcome once its inputs parse.
    static Wallet fromLink(const LinkSession& s, const std::string& containerJson, const std::string& expectJson,
                           const std::string& membersJson, const std::string& acceptedJson, Secret& bip39Passphrase);

    void unlock(const std::string& vaultJson, Secret& vaultPassphrase, Secret& prf32, Secret& bip39Passphrase) const;
    std::string sealVault(Secret& vaultPassphrase) const;
    void lock() const;
    MemoryProtection memoryProtection() const;
    Key uaKey(uint16_t kind, uint32_t account, uint32_t index) const;
    Key nativeKey(const std::string& network, uint32_t index, uint32_t coinType = kCoinDefault) const;
    Key importNativeKey(const std::string& network, Secret& secret) const;
    Key importedKey(const std::string& network, uint32_t n) const;
    std::string sealLabelVault(const std::string& label, Secret& vaultPassphrase) const;
    void openLabelVault(const std::string& vaultJson, Secret& vaultPassphrase, Secret& prf32) const;
    std::string manifestJson() const;
    std::string discoverCandidates(uint16_t kind, uint32_t account, uint32_t gap) const;  // JSON [{index, ua}]
    std::vector<std::string> backupSeal(const Key& sender, const std::vector<Recipient>& recipients) const;  // container JSONs
    std::string linkSeal(const Key& sender, const Bytes& sessionKemPk, const std::string& shortCode) const;
    ZetherKey zetherKey(uint32_t coin, uint32_t account, uint32_t keyUse) const;
    PqzKey pqzKey(uint32_t account, uint32_t index) const;
    Secret exportPqzLeafRaw(uint32_t account, uint32_t index) const;  // the explicit export (spec §8.4)
};

class SeedBackup : public Handle<ffi::SeedBackup> {
public:
    using Handle::Handle;
    Secret reveal() const;                       // the words, once
    std::vector<uint32_t> challenge() const;     // three 1-based positions
    bool verify(Secret& word1, Secret& word2, Secret& word3) const;
    Secret take() const;                         // the entropy once confirmed; empty before and after
};

class Key : public Handle<ffi::Key> {
public:
    using Handle::Handle;
    bool isUa() const;
    uint16_t kind() const;  // 0 for a native key
    Bytes keyData() const;  // a UA key's key data; a native key's public key
    Bytes ua() const;
    std::string network() const;  // "" for a UA key
    std::string address() const;
    Bytes signUa(const Bytes& purposeTag, const Bytes& digest) const;
    Bytes signMember(const Bytes& structureUa, const Bytes& structureUaMsg) const;
    Bytes signTyped(const std::string& typedDataJson, const std::string& expectJson) const;
    Bytes signTypedAny(const std::string& typedDataJson) const;
    Bytes signTransaction(const std::string& txJson) const;  // the raw transaction
    Bytes signKeyProof(const Bytes& challenge) const;
    Bytes signDigestRaw(const Bytes& digest) const;  // a native key only (UARawDigestRefused for a UA key)
    KemKey kemKey(uint64_t version) const;
};
// The UASig builder (the C ABI's scaas_ua_uasig): request JSON with keys by position in `keys`.
std::string uaSig(const std::string& requestJson, const std::vector<const Key*>& keys);

class KemKey : public Handle<ffi::KemKey> {
public:
    using Handle::Handle;
    static KemKey ephemeral();
    Bytes kemPk() const;
    Secret decaps(const Bytes& mlkemCt, const Bytes& x25519Eph) const;
    Secret open(const std::string& purpose, const Bytes& aad, const Sealed& s) const;
    Secret openContainer(const std::string& containerJson, const std::string& expectJson, const std::string& membersJson = "",
                         const std::string& acceptedJson = "") const;
};
Encapsulated kemEncaps(const Bytes& kemPk);
Sealed seal(const Bytes& kemPk, const std::string& purpose, const Bytes& aad, const Bytes& pt);  // authenticates no sender

class LinkSession : public Handle<ffi::LinkSession> {
public:
    using Handle::Handle;
    static LinkSession create();
    Bytes kemPk() const;
    std::string shortCode() const;
};

namespace vault {
bool needsRewrap(const std::string& vaultJson);
std::string rewrapPin(const std::string& vaultJson, Secret& oldPassphrase, Secret& newPassphrase);
std::string enablePrf(const std::string& vaultJson, Secret& vaultPassphrase, Secret& prf32, const std::string& credentialId,
                      const Bytes& salt);
}  // namespace vault

Bytes aeadSeal(uint32_t alg, const Bytes& key, const Bytes& nonce, const Bytes& aad, const Bytes& data);
Secret aeadOpen(uint32_t alg, const Bytes& key, const Bytes& nonce, const Bytes& aad, const Bytes& data);
Secret hkdfSha256(const Bytes& ikm, const Bytes& salt, const Bytes& info, size_t len);
Bytes hmacSha256(const Bytes& key, const Bytes& data);
Bytes webauthnChallenge(const Bytes& purposeTag, const Bytes& digest);
Bytes webauthnAssertion(const Bytes& keyData, const Bytes& expectedChallenge, const Bytes& authData, const Bytes& clientDataJson,
                        const Bytes& r, const Bytes& s);  // verified before return

// The Zether facade (spec §10.1): zether-prover's commands with the handle's key; no request field carries a key.
class ZetherKey : public Handle<ffi::ZetherKey> {
public:
    using Handle::Handle;
    Bytes y() const;   // 128 bytes
    Bytes ua() const;  // 32 bytes
    std::string call(const std::string& cmd, const std::string& requestJson) const;
    std::string sealBalanceCache(const Bytes& entriesJson) const;
    Secret openBalanceCache(const std::string& boxJson) const;
};
// The PQZ facade (spec §10.2), separate from Zether.
class PqzKey : public Handle<ffi::PqzKey> {
public:
    using Handle::Handle;
    Bytes pk() const;
    std::string call(const std::string& cmd, const std::string& requestJson) const;  // at most kPqzOutMax bytes
    std::string sealBalanceCache(const Bytes& entries) const;
    Secret openBalanceCache(const std::string& boxJson) const;
};
std::string pqzSet();                            // {set, pkLen, pqzlId, pqzhId} of this build
void pqzCheckSet(const std::string& deployedJson);  // UAPqzSetMismatch for another set

}  // namespace scaas::ua
