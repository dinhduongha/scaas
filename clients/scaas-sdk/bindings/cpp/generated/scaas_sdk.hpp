#pragma once

#include <algorithm>
#include <bit>
#include <chrono>
#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <streambuf>
#include <type_traits>
#include <variant>
#include <vector>

#include "scaas_sdk_scaffolding.hpp"

#ifndef UNIFFI_CPP_RUST_STREAM
#define UNIFFI_CPP_RUST_STREAM
namespace uniffi {
struct RustStreamBuffer: std::basic_streambuf<char> {
    RustStreamBuffer(RustBuffer *buf) {
        char* data = reinterpret_cast<char*>(buf->data);
        this->setg(data, data, data + buf->len);
        this->setp(data, data + buf->capacity);
    }
    ~RustStreamBuffer() = default;

private:
    RustStreamBuffer() = delete;
    RustStreamBuffer(const RustStreamBuffer &) = delete;
    RustStreamBuffer(RustStreamBuffer &&) = delete;

    RustStreamBuffer &operator=(const RustStreamBuffer &) = delete;
    RustStreamBuffer &operator=(RustStreamBuffer &&) = delete;
};

struct RustStream: std::basic_iostream<char> {
    RustStream(RustBuffer *buf):
        std::basic_iostream<char>(&streambuf), streambuf(RustStreamBuffer(buf)) { }

    template <typename T, typename = std::enable_if_t<std::is_arithmetic_v<T>>>
    RustStream &operator>>(T &val) {
        read(reinterpret_cast<char *>(&val), sizeof(T));

        if (std::endian::native != std::endian::big) {
            auto bytes = reinterpret_cast<char *>(&val);

            std::reverse(bytes, bytes + sizeof(T));
        }

        return *this;
    }

    template <typename T, typename = std::enable_if_t<std::is_arithmetic_v<T>>>
    RustStream &operator<<(T val) {
        if (std::endian::native != std::endian::big) {
            auto bytes = reinterpret_cast<char *>(&val);

            std::reverse(bytes, bytes + sizeof(T));
        }

        write(reinterpret_cast<char *>(&val), sizeof(T));

        return *this;
    }
private:
    RustStreamBuffer streambuf;
};

}
#endif

namespace scaas_sdk {
struct Account;
struct Admin;
struct CancelToken;
struct Confidential;
struct Dex;
struct Op;
struct Prepared;
struct PreparedOrder;
struct RegistryWrite;
struct Sdk;
struct SecretBytes;
struct SeedBackup;
struct Subscription;
struct SyncAuthenticator;
struct SyncStore;
struct Vault;
struct Wallet;
struct AcceptMembership;
struct AccountInfo;
struct AddNative;
struct AddReserve;
struct AddUa;
struct AddWatch;
struct Assertion;
struct AssertionRequest;
struct AttrsArgs;
struct AuditorConsent;
struct Balances;
struct BindingConfig;
struct BlsMultiPart;
struct Burn;
struct CancelAll;
struct CancelNonce;
struct CancelOrder;
struct CancelWrapOrder;
struct ChainProfile;
struct ConfirmRemove;
struct ConfirmRemoveUnbacked;
struct Create3Preview;
struct CreatePasskeyKey;
struct CreateSeKey;
struct Cursor;
struct DelegateRevoke;
struct DeriveChild;
struct DeriveFromKey;
struct DeriveFromSignature;
struct EndpointConfig;
struct Envelope;
struct Execute;
struct GasBase;
struct GasLine;
struct GasPerByte;
struct GasPerItem;
struct GasRows;
struct GasSources;
struct GasTable;
struct GasVerify;
struct Generate;
struct HistoryItem;
struct HistoryPage;
struct ImportExpect;
struct ImportKey;
struct ImportWords;
struct ImportedKey;
struct KemArgs;
struct KemRecord;
struct KeyPolicy;
struct Limits;
struct LiquidityOrder;
struct LiquidityToken;
struct ListedDex;
struct ListedToken;
struct MemoryProtection;
struct MsigLeafValue;
struct MsigMemberArgs;
struct MsigRegister;
struct MsigSlotState;
struct MsigState;
struct MsigStructureArgs;
struct MsigUpdatePlan;
struct NativeAddress;
struct NativeCap;
struct NativeKeyRef;
struct NativeQuote;
struct NativeSend;
struct NewSeed;
struct OpItem;
struct OrderTerms;
struct OwnerRelay;
struct PasskeyCreated;
struct Pay;
struct PayMeta;
struct PayUnderMandate;
struct PayWithTax;
struct PayeeFee;
struct PayerAuth;
struct Payment;
struct PositionReader;
struct PqzAccountOp;
struct PqzBalance;
struct PqzBalanceAll;
struct PqzBalanceRequest;
struct PqzLeg;
struct PqzShield;
struct PqzTransfer;
struct PqzTransferMulti;
struct PqzUnshield;
struct PqzUnshieldUnwrap;
struct PqzVerdictRequest;
struct PqzWrapShield;
struct Register;
struct RegisterArgs;
struct RegisterAttrs;
struct RegistrationBlob;
struct RegistrationGas;
struct RegistrationState;
struct RelayFee;
struct Remove;
struct RescueVault;
struct Restore;
struct ReviewField;
struct RevokeMandate;
struct SePublic;
struct SeedInfo;
struct SessionSet;
struct SetMandate;
struct SetPayee;
struct SignedOpBlob;
struct SignedOrder;
struct SignedRescue;
struct SmartOp;
struct StepGas;
struct StorePolicy;
struct StoredItem;
struct SubjectKeyArgs;
struct SubmitQuote;
struct TokenBalance;
struct TokenInfo;
struct TradeOrder;
struct Transfer;
struct UaAcceptAdmin;
struct UaApproveDexRelease;
struct UaApproveRelease;
struct UaApproveTokenRelease;
struct UaCancelGrant;
struct UaCancelNonce;
struct UaCancelRate;
struct UaCreateDex;
struct UaCreateInstance;
struct UaCreateToken;
struct UaDeprecateDex;
struct UaDeprecateRelease;
struct UaDeprecateToken;
struct UaDisableFeature;
struct UaDisableWrap;
struct UaEnableFeature;
struct UaExecuteRate;
struct UaForceTransfer;
struct UaFreeze;
struct UaGrantRole;
struct UaLine;
struct UaMint;
struct UaMintToUA;
struct UaOperatorTransfer;
struct UaPause;
struct UaPqzCancelVerifier;
struct UaPqzRevokeVerifier;
struct UaPqzSetVerifier;
struct UaProposeRate;
struct UaPublishClassEnv;
struct UaPublishDexEnv;
struct UaPublishTokenEnv;
struct UaRecordOrder;
struct UaRenounceAdmin;
struct UaRenounceRole;
struct UaRevokeApproval;
struct UaRevokeOrder;
struct UaRevokeRole;
struct UaSetAllowed;
struct UaSetAuditorKey;
struct UaSetAuditorUA;
struct UaSetChainEntries;
struct UaSetClassKindEnabled;
struct UaSetCompliance;
struct UaSetDenied;
struct UaSetExchangeTarget;
struct UaSetFeeSplit;
struct UaSetGrant;
struct UaSetKycProvider;
struct UaSetListedOnly;
struct UaSetMarket;
struct UaSetMaxSupply;
struct UaSetMaxWrapSupply;
struct UaSetProofStore;
struct UaSetTaxRate;
struct UaSetTaxRecipient;
struct UaSetTokenKindEnabled;
struct UaSetVerifierFee;
struct UaSetWrapLimits;
struct UaSetWrapMember;
struct UaTransferAdmin;
struct UaUnfreeze;
struct UaUnpause;
struct Unwrap;
struct UnwrapLeg;
struct UnwrapToUa;
struct UpdateMsig;
struct WebAuthnArgs;
struct Wrap;
struct WrapLeg;
struct WrapOrder;
struct WrapOrderTerms;
struct WrapToUa;
struct ZetherBalance;
struct ZetherBalanceRequest;
struct ZetherKeyInfo;
struct ZetherLeg;
struct ZetherOwnerRollOver;
struct ZetherOwnerSetMode;
struct ZetherRollOver;
struct ZetherRollOverBatch;
struct ZetherShield;
struct ZetherTransfer;
struct ZetherTransferMulti;
struct ZetherUnshield;
struct ZetherUnshieldUnwrap;
struct ZetherWrapShield;
struct AccountRow;
struct AuthError;
enum class Class;
struct DelaySentence;
struct EndpointAuth;
struct Event;
struct ExecuteCall;
enum class Family;
struct FamilyParams;
struct Finality;
struct GasFrom;
enum class HolderKind;
enum class InFlight;
struct KeyRef;
enum class L1Fee;
struct MsigSlotValue;
struct OpState;
struct PayBody;
enum class Policy;
enum class Presence;
struct RescueOp;
struct SdkError;
struct SlotKey;
struct SmartCall;
enum class Source;
struct StoreError;
struct SubmitPath;
struct Unlock;
typedef bool AllowOpaqueCall;
typedef MsigSlotValue MsigSlot;
typedef std::string Secret;
typedef std::string Value;


/**
 * One of the account's operations in `sdk.state` (spec §13.4).
 */
struct OpItem {
    std::string op;
    std::string entry;
    /**
     * `signed`, `sent`, `landed`, `reverted`, `consumed`, `expired`
     */
    std::string state;
    std::optional<uint64_t> landed_block;
};


/**
 * A token and an amount of a liquidity order's plan.
 */
struct LiquidityToken {
    std::string token;
    std::string amount;
};


/**
 * A decrypted PQZ balance, for the holder only.
 */
struct PqzBalance {
    /**
     * the smallest unit, decimal: what a debit at this block may spend (the account and the window `[rolled, p)`)
     */
    std::string amount;
    /**
     * the final block the words were read at
     */
    uint64_t block;
    /**
     * the window's end and the UA's `sendCounter` at that block
     */
    uint64_t p;
    uint64_t send_counter;
};

namespace uniffi {
struct FfiConverterFinality;
} // namespace uniffi

/**
 * The block of every decisive and decryption read (§9.4 requirement 3).
 */
struct Finality {
    friend uniffi::FfiConverterFinality;
    struct kFinalized {
    };
    struct kDepth {
        uint64_t v1;
    };
    Finality(kFinalized variant): variant(variant) {}
    Finality(kDepth variant): variant(variant) {}

    Finality(const Finality &other): variant(other.variant) {}
    Finality(Finality &&other): variant(std::move(other.variant)) {}

    Finality &operator=(const Finality &other) {
        variant = other.variant;
        return *this;
    }

    Finality &operator=(Finality &&other) {
        variant = std::move(other.variant);
        return *this;
    }

    /**
     * Returns the variant of this enum
     */
    const std::variant<kFinalized, kDepth> &get_variant() const {
        return variant;
    }

private:
    std::variant<kFinalized, kDepth> variant;

    Finality();
};


/**
 * A base row's per-byte part (owner 2026-11-19, ruling B): `gas` (whole gas, rounded up) for each byte of the operation's
 * variable-length `input`: `meta.body` (a pay entry's `PayMeta` body, as encoded) or `data` (`mtxExecute`'s call data).
 */
struct GasPerByte {
    std::string input;
    uint64_t gas;
};


/**
 * A `SubjectKey` by name: `kind` 1 a passkey (`x`, `y` P-256, `rpIdHash`, `originHash`), 2 a secp256k1 key (`x` its address
 * right-aligned, the rest 0); words as `0x` + 64 hex.
 */
struct SubjectKeyArgs {
    uint8_t kind;
    std::string x;
    std::string y;
    std::string rp_id_hash;
    std::string origin_hash;
};


/**
 * The envelope's terms the user chooses (the lane's nonce is read; a pay's lane is its `payLane(entryRef)`).
 */
struct Envelope {
    /**
     * unix seconds on the chain's clock
     */
    uint64_t valid_until;
    /**
     * the fee mode: bit 0 binds `relayer`, bit 1 binds `fee_recipient` (an unbound one is 0 in what is signed), the fee kind
     * above
     */
    uint32_t mode;
    std::optional<std::string> relayer;
    /**
     * the fee to the relayer in the token's smallest unit, decimal; 0 is a value
     */
    std::string fee;
    std::optional<std::string> fee_recipient;
};


/**
 * `KemKey`, named.
 */
struct KemArgs {
    uint8_t scheme;
    std::string mlkem_ek;
    std::string x25519;
};


/**
 * Whether the platform asks for the user before it gives the item.
 */
enum class Presence: int32_t {
    kNone = 1,
    kRequired = 2
};


namespace uniffi {
    struct FfiConverterSecretBytes;
} // namespace uniffi

struct SecretBytes {
    friend uniffi::FfiConverterSecretBytes;

    SecretBytes() = delete;

    SecretBytes(SecretBytes &&) = delete;

    SecretBytes &operator=(const SecretBytes &) = delete;
    SecretBytes &operator=(SecretBytes &&) = delete;

    ~SecretBytes();

    private:
    SecretBytes(const SecretBytes &);

    SecretBytes(uint64_t);

    uint64_t _uniffi_internal_clone_handle() const;

    uint64_t instance = 0;
};


/**
 * One chain's native cost cap (`Limits::max_native_cost`).
 */
struct NativeCap {
    /**
     * the profile's key
     */
    std::string chain;
    /**
     * decimal, the chain's smallest unit (stroops on Soroban)
     */
    std::string max;
};


/**
 * The first marker of `remove`.
 */
struct ConfirmRemove {
};


/**
 * One log naming the account in an indexed field.
 */
struct HistoryItem {
    uint64_t block;
    std::string tx_hash;
    uint64_t log_index;
    /**
     * the token that emitted it, `0x` + 40 hex lower case
     */
    std::string contract;
    /**
     * `UATransfer`, `Transfer`, `PaymentSettled`, `Wrapped`, `Unwrapped`, `UnwrappedToUA`, else `unknown`
     */
    std::string event;
    std::vector<std::string> topics;
    std::string data;
};

namespace uniffi {
struct FfiConverterSlotKey;
} // namespace uniffi

/**
 * A slot's key: `KeyRef` without the slots of an `msig` (a slot's key is never one, spec §7).
 */
struct SlotKey {
    friend uniffi::FfiConverterSlotKey;
    struct kUa {
        std::string seed;
        uint16_t kind;
        uint32_t account;
        uint32_t index;
    };
    struct kNative {
        std::string seed;
        std::string network;
        uint32_t index;
    };
    struct kImported {
        std::string seed;
        std::string network;
        uint32_t index;
    };
    struct kKey {
        std::string seed;
        std::string id;
    };
    /**
     * refused at signing (`Argument`)
     */
    struct kMsig {
        std::string ua;
    };
    /**
     * a `bls12381-multi` group's member key (as `KeyRef::BlsMulti`)
     */
    struct kBlsMulti {
        std::string seed;
        uint32_t account;
        uint32_t index;
        std::string key_data;
    };
    /**
     * another party's signer (as `KeyRef::Signed`, a hand-off): never a slot's key, refused at signing
     */
    struct kSigned {
        std::string signer;
    };
    SlotKey(kUa variant): variant(variant) {}
    SlotKey(kNative variant): variant(variant) {}
    SlotKey(kImported variant): variant(variant) {}
    SlotKey(kKey variant): variant(variant) {}
    SlotKey(kMsig variant): variant(variant) {}
    SlotKey(kBlsMulti variant): variant(variant) {}
    SlotKey(kSigned variant): variant(variant) {}

    SlotKey(const SlotKey &other): variant(other.variant) {}
    SlotKey(SlotKey &&other): variant(std::move(other.variant)) {}

    SlotKey &operator=(const SlotKey &other) {
        variant = other.variant;
        return *this;
    }

    SlotKey &operator=(SlotKey &&other) {
        variant = std::move(other.variant);
        return *this;
    }

    /**
     * Returns the variant of this enum
     */
    const std::variant<kUa, kNative, kImported, kKey, kMsig, kBlsMulti, kSigned> &get_variant() const {
        return variant;
    }

private:
    std::variant<kUa, kNative, kImported, kKey, kMsig, kBlsMulti, kSigned> variant;

    SlotKey();
};


/**
 * One real recipient of a multi-recipient transfer: a registered Zether UA and its amount.
 */
struct ZetherLeg {
    std::string to_ua;
    std::string amount;
};


/**
 * What is known of an operation in flight (spec §13.5): none of it ends the operation.
 */
enum class InFlight: int32_t {
    /**
     * signed and written, not sent yet
     */
    kSigned = 1,
    /**
     * a gateway queued it
     */
    kQueued = 2,
    /**
     * every gateway it went to refused it or could not be reached (one node's `dead` covers its own sends only)
     */
    kGivenUpByEveryNode = 3,
    /**
     * the self-relay transaction was accepted by an endpoint
     */
    kSent = 4,
    /**
     * no endpoint accepted the self-relay transaction (`BroadcastRejected`, an outcome, never final)
     */
    kBroadcastRejected = 5,
    /**
     * the self-relay transaction is in a block, not final, or final and successful while the event is not read yet
     */
    kTxIncluded = 6,
    /**
     * the self-relay transaction is final and failed: the signed operation may still land by another relayer
     */
    kTxFinalFailed = 7,
    /**
     * the self-relay transaction was replaced
     */
    kTxReplaced = 8,
    /**
     * the signed operation's simulation from the payer reverted, failed or needed more gas than the confirmed quote: not sent
     * by this SDK (owner 2026-11-19, ruling A). It is signed and may still land by another relayer until its nonce is spent or
     * `validUntil` passes; `resend` tries again, a cancel of the lane's nonce ends it.
     */
    kSimRefused = 9
};


/**
 * One token's balance.
 */
struct TokenBalance {
    std::string address;
    std::string display;
    uint8_t decimals;
    /**
     * the smallest unit, decimal
     */
    std::string amount;
};


/**
 * A reviewed position reader of a position manager (a liquidity order that receives a position names one).
 */
struct PositionReader {
    std::string manager;
    std::string reader;
};


/**
 * A seed as listed: public fields of the container entry, and whether it is unlocked (its MAC checked) in this session.
 */
struct SeedInfo {
    std::string id;
    std::string label;
    uint32_t words;
    std::string origin;
    std::string class_;
    std::vector<std::string> warnings;
    std::string backup;
    bool unlocked;
    /**
     * the index MAC of this entry was checked in this session (spec §6.2)
     */
    bool verified;
};


namespace uniffi {
    struct FfiConverterSeedBackup;
} // namespace uniffi

/**
 * The words of a seed made here: revealed once, a three-word check, then forgotten (`scaas-ua`'s `SeedBackup`, CLI-SGN-11).
 */
struct SeedBackup {
    friend uniffi::FfiConverterSeedBackup;

    SeedBackup() = delete;

    SeedBackup(SeedBackup &&) = delete;

    SeedBackup &operator=(const SeedBackup &) = delete;
    SeedBackup &operator=(SeedBackup &&) = delete;

    ~SeedBackup();
    /**
     * Three positions to ask (1-based).
     */
    std::vector<uint32_t> challenge();
    /**
     * The words, once (`Argument` after), as a secret read through the copy call.
     */
    std::shared_ptr<SecretBytes> reveal();
    /**
     * The user's three words (a secret) against the challenge.
     */
    bool verify(const std::shared_ptr<SecretBytes> &answers);

    private:
    SeedBackup(const SeedBackup &);

    SeedBackup(uint64_t);

    uint64_t _uniffi_internal_clone_handle() const;

    uint64_t instance = 0;
};

namespace uniffi {
struct FfiConverterRescueOp;
} // namespace uniffi

/**
 * A rescue vault's admin operation (CTR-GOV-25): `seq` the vault's shared order, from 1.
 */
struct RescueOp {
    friend uniffi::FfiConverterRescueOp;
    /**
     * `setRescuer(seq, newRescuer)`, `new_rescuer` an address (not 0)
     */
    struct kSetRescuer {
        uint64_t seq;
        std::string new_rescuer;
    };
    /**
     * `rotateAdmin(seq, newAdmin)`, `new_admin` a native UA (not 0)
     */
    struct kRotateAdmin {
        uint64_t seq;
        std::string new_admin;
    };
    RescueOp(kSetRescuer variant): variant(variant) {}
    RescueOp(kRotateAdmin variant): variant(variant) {}

    RescueOp(const RescueOp &other): variant(other.variant) {}
    RescueOp(RescueOp &&other): variant(std::move(other.variant)) {}

    RescueOp &operator=(const RescueOp &other) {
        variant = other.variant;
        return *this;
    }

    RescueOp &operator=(RescueOp &&other) {
        variant = std::move(other.variant);
        return *this;
    }

    /**
     * Returns the variant of this enum
     */
    const std::variant<kSetRescuer, kRotateAdmin> &get_variant() const {
        return variant;
    }

private:
    std::variant<kSetRescuer, kRotateAdmin> variant;

    RescueOp();
};


/**
 * A platform key's access policy (biometry of the current enrollment, invalidated by a new one: research decision 8).
 */
struct KeyPolicy {
    bool biometry_current_set;
    bool invalidated_by_enrollment;
};


enum class Policy: int32_t {
    kFailover = 1,
    kStrictMajority = 2
};


/**
 * One leg of an op 7: a registered PQZ holder and its amount (`"0"`: a decoy).
 */
struct PqzLeg {
    std::string to_ua;
    std::string amount;
};

namespace uniffi {
struct FfiConverterGasFrom;
} // namespace uniffi

/**
 * Where a part of a quote's gas figure came from (owner 2026-11-19), so the app and the operator see a figure not measured on
 * the chain.
 */
struct GasFrom {
    friend uniffi::FfiConverterGasFrom;
    /**
     * a row of the chain profile, measured on that chain
     */
    struct kChain {
    };
    /**
     * a row of the named module table, the profile having opted in
     */
    struct kModule {
        std::string v1;
    };
    /**
     * a row of the SCaaS reference table, the profile having opted in; not measured on this chain
     */
    struct kReference {
    };
    /**
     * the figure the app passed on the call
     */
    struct kApp {
    };
    /**
     * a native send's own estimate (or 21,000 for a plain transfer to an account without code)
     */
    struct kEstimate {
    };
    GasFrom(kChain variant): variant(variant) {}
    GasFrom(kModule variant): variant(variant) {}
    GasFrom(kReference variant): variant(variant) {}
    GasFrom(kApp variant): variant(variant) {}
    GasFrom(kEstimate variant): variant(variant) {}

    GasFrom(const GasFrom &other): variant(other.variant) {}
    GasFrom(GasFrom &&other): variant(std::move(other.variant)) {}

    GasFrom &operator=(const GasFrom &other) {
        variant = other.variant;
        return *this;
    }

    GasFrom &operator=(GasFrom &&other) {
        variant = std::move(other.variant);
        return *this;
    }

    /**
     * Returns the variant of this enum
     */
    const std::variant<kChain, kModule, kReference, kApp, kEstimate> &get_variant() const {
        return variant;
    }

private:
    std::variant<kChain, kModule, kReference, kApp, kEstimate> variant;

    GasFrom();
};


/**
 * The KEM key of version 0 a hash-commit registration carries beside its arguments.
 */
struct KemRecord {
    uint64_t version;
    /**
     * `0x` hex: `mlkemEk ‖ x25519` (`scaas-ua` `kem_pk`)
     */
    std::string kem_pk;
};


/**
 * One step of a registration carrying its PQZ key's proof as quoted at prepare (owner 2026-11-20).
 */
struct StepGas {
    /**
     * `register` (or `registerWebAuthn`, `registerMsig`), with or without the proof, or `storePqzPop`
     */
    std::string entry;
    /**
     * the step's gas limit: max(the node's estimate, the gas table's figure), the table's with the intrinsic cost, the
     * calldata and the margin; `None` where neither is known yet (a later step is not estimated before the one before it
     * landed)
     */
    std::optional<uint64_t> gas;
    /**
     * the bound of its regular part (EIP-8037): the table's; the estimate, whole, where the table has no row
     */
    std::optional<uint64_t> regular_gas;
};


/**
 * What a registration carries besides the key (spec §7): the PQZ key with its `R_REG` proof, the KEM key (version 0).
 */
struct RegisterAttrs {
    bool pqz_key;
    bool kem;
};


/**
 * A wrap order as it was signed (`UAWrapOrder`'s named fields).
 */
struct WrapOrderTerms {
    std::string from;
    std::string wrapped_token;
    std::string amount;
    std::string min_minted;
    std::string min_fill;
    std::string fee;
    std::string relayer;
    std::string destination;
    uint8_t flags;
    std::string batch;
    std::string nonce;
    std::string valid_until;
};


/**
 * An order as it was signed: a `TradeOrder`'s 13 named fields, `from` and `destination` 32-byte ids for a SCaaS sell token's
 * `UATradeOrder`, addresses for an outside token's.
 */
struct OrderTerms {
    std::string from;
    std::string receive_token;
    std::string amount;
    std::string receive_amount;
    std::string min_fill;
    std::string fee;
    std::string relayer;
    std::string dex;
    std::string destination;
    uint8_t flags;
    std::string batch;
    std::string nonce;
    std::string valid_until;
};


/**
 * The payer's `UASig` over the payment (no members).
 */
struct PayerAuth {
    /**
     * `0x` hex; `0x` for a native id
     */
    std::string key_data;
    std::string signature;
};


/**
 * One member of an `msig` structure (CTR-UA-09): its kind, its id (`0x` + 64 hex), its weight.
 */
struct MsigMemberArgs {
    uint16_t kind;
    std::string id;
    uint16_t weight;
};


namespace uniffi {
    struct FfiConverterRegistryWrite;
} // namespace uniffi

/**
 * A registry write as the user reviews it (spec §7, §13.1): opaque, kept in the SDK's table; it holds public data only
 * (the PoP binds no caller). `submit_registry_write` sends exactly its calldata to the profile's registry.
 */
struct RegistryWrite {
    friend uniffi::FfiConverterRegistryWrite;

    RegistryWrite() = delete;

    RegistryWrite(RegistryWrite &&) = delete;

    RegistryWrite &operator=(const RegistryWrite &) = delete;
    RegistryWrite &operator=(RegistryWrite &&) = delete;

    ~RegistryWrite();
    std::string calldata();
    std::string chain();
    std::string entry();
    std::string id();
    KeyRef payer();
    /**
     * A registration carrying its PQZ key's proof: one transaction or two, each step's gas (owner 2026-11-20).
     */
    std::optional<RegistrationGas> registration_gas();
    std::vector<ReviewField> review();
    std::string ua();

    private:
    RegistryWrite(const RegistryWrite &);

    RegistryWrite(uint64_t);

    uint64_t _uniffi_internal_clone_handle() const;

    uint64_t instance = 0;
};


/**
 * An L1 data fee model (plan T38).
 */
enum class L1Fee: int32_t {
    /**
     * OP Stack: `GasPriceOracle.getL1Fee(bytes)` (`0x4200…000F`) over the unsigned transaction, read at the quote's block
     */
    kOpStack = 1
};

namespace uniffi {
struct FfiConverterPayBody;
} // namespace uniffi

/**
 * The `PayMeta` body by schema (pay-meta-tax spec §7.1), named.
 */
struct PayBody {
    friend uniffi::FfiConverterPayBody;
    struct kNone {
    };
    struct kNote {
        std::string note;
    };
    struct kCreditorRef {
        std::string creditor_ref;
        uint64_t due_date;
    };
    struct kBoundCall {
        std::string chain_id;
        std::string target;
        std::string call_hash;
    };
    struct kCiphertext {
        std::string ciphertext;
    };
    PayBody(kNone variant): variant(variant) {}
    PayBody(kNote variant): variant(variant) {}
    PayBody(kCreditorRef variant): variant(variant) {}
    PayBody(kBoundCall variant): variant(variant) {}
    PayBody(kCiphertext variant): variant(variant) {}

    PayBody(const PayBody &other): variant(other.variant) {}
    PayBody(PayBody &&other): variant(std::move(other.variant)) {}

    PayBody &operator=(const PayBody &other) {
        variant = other.variant;
        return *this;
    }

    PayBody &operator=(PayBody &&other) {
        variant = std::move(other.variant);
        return *this;
    }

    /**
     * Returns the variant of this enum
     */
    const std::variant<kNone, kNote, kCreditorRef, kBoundCall, kCiphertext> &get_variant() const {
        return variant;
    }

private:
    std::variant<kNone, kNote, kCreditorRef, kBoundCall, kCiphertext> variant;

    PayBody();
};


/**
 * A row's per-item part (owner 2026-11-19, I1), on a base or a verify row: `gas` (whole gas, the measured slope rounded
 * up) for each counted `item` of the operation, one of `GAS_ITEMS` (`legs`, `accounts`, `entries`, `members`,
 * `env_items`, `orders`). The row's own `gas` is its figure at a count of 0 (the line's intercept; the file states
 * `"base_count": 0`), so the quote adds `gas × count` with no offset.
 */
struct GasPerItem {
    std::string item;
    uint64_t gas;
    /**
     * the regular part of `gas` (EIP-8037), on a base row with a `regular` figure only
     */
    std::optional<uint64_t> regular;
    /**
     * the largest count the row was measured at (`gas/generate.py`); a count above it is `GasCountUnknown`, never a line
     * extrapolated past its points (merged-tree review M18, 2026-11-20); `None`: a row that names none (the chain's own)
     */
    std::optional<uint64_t> measured_max;
};


/**
 * One slot of an `msig` as the registry holds it now.
 */
struct MsigSlotState {
    uint16_t kind;
    std::string id;
    uint16_t weight;
    bool enabled;
    /**
     * accepted (CTR-UA-37; never cleared, whether enabled or not)
     */
    bool accepted;
    /**
     * `memberSigHashOf(ua, i)` (`0x` + 64 hex; zero for a slot not accepted): what a copy to another registry checks
     */
    std::string sig_hash;
};


/**
 * A `registerWebAuthn` key, named.
 */
struct WebAuthnArgs {
    std::string x;
    std::string y;
    std::string rp_id_hash;
};


/**
 * The second marker of `remove`, for a seed whose backup is `pending`.
 */
struct ConfirmRemoveUnbacked {
};


/**
 * Where a reviewed value comes from (spec §13.1).
 */
enum class Source: int32_t {
    /**
     * a field of the signed struct (or committed to by it, as a pay's `PayMeta`), decoded
     */
    kSigned = 1,
    /**
     * what the request named and the signed struct holds only in encrypted form (a confidential amount, recipient)
     */
    kRequest = 2,
    /**
     * what the SDK chose or read: the contract, every token or market touched with its mark
     */
    kDerived = 3
};


/**
 * A chain family (the `scaas-rpc` readers'). Hedera is `Evm` with its chain id.
 */
enum class Family: int32_t {
    kEvm = 1,
    kSoroban = 2,
    kSolana = 3,
    kNear = 4,
    kAlgorand = 5,
    kAptos = 6,
    kSui = 7,
    kCosmos = 8,
    kTon = 9
};


/**
 * A token of a profile's reviewed list (spec §8.2).
 */
struct ListedToken {
    /**
     * EVM: `0x` + 40 hex; another family: its token id as text, checked by the family's form (spec §8.7; a NEAR account)
     */
    std::string address;
    std::string symbol;
    uint8_t decimals;
};


enum class Class: int32_t {
    kNamed = 1,
    kDefault = 2,
    kDiscovered = 3
};


/**
 * The payment a payee fee co-signs (the contract's shape: fee none, relayer bound).
 */
struct Payment {
    std::string from;
    std::string to;
    std::string value;
    uint64_t valid_until;
    std::string relayer;
};


/**
 * A position in a chain's logs: a page holds items strictly older than it.
 */
struct Cursor {
    uint64_t block;
    uint64_t log_index;
};


/**
 * A verify row's registry-line columns (spec 2026-11-19-registry-verify-only-kinds §12, CTR-UA-65; §13 Gas): the row is
 * keyed by chain (the table it is in), registry address and signer kind; the verify path, the depth and the write path are
 * columns. Within one table no two verify rows share signer, registry, path, depth and write.
 */
struct GasLine {
    /**
     * the registry the row was measured through (`0x` + 40 hex): a quote bound to it takes it first; `None`: a row of no one
     * registry
     */
    std::optional<std::string> registry;
    /**
     * `cache`, `precompile` or `fallback` (the holder's verdict after the verify-only verifier gave no answer, §5); `None`:
     * the holder's own check
     */
    std::optional<std::string> path;
    /**
     * the generations between the registry asked and the holder (0: the registry holds the record), at most 15
     */
    uint8_t depth;
    /**
     * the write path of W1 (a registry write whose signature the holder checks), never a consumer operation's quote
     */
    bool write;
};


/**
 * `UAZetherUnshield`: `amount` out of the holder's Zether account to `recipient` (a 32-byte id).
 */
struct ZetherUnshield {
    std::string seed;
    uint32_t account;
    std::string chain;
    std::string token;
    std::string batch;
    std::string recipient;
    std::string amount;
    uint64_t valid_until_block;
    Envelope envelope;
    std::optional<uint32_t> table_bits;
    std::optional<uint32_t> bound_bits;
};


/**
 * A slot of an inner `msig`: its index there and its key.
 */
struct MsigLeafValue {
    uint16_t index;
    SlotKey key;
};


/**
 * `UAAttrs`, named.
 */
struct AttrsArgs {
    std::string pqz_key;
    std::string pqz_pop_hash;
    KemArgs kem;
    std::string kem_pk_hash;
};


/**
 * `UAZetherUnshieldUnwrap` (`WRAPPED_ZETHER`): `amount` out of the holder's Zether account, unwrapped by leg `underlying` to
 * `recipient` (a 32-byte id: a native address zero-padded, or a derived UA in the leg's own ledger), at least `min_out` of
 * the leg. The burn proof binds `recipient` and `amount` (the contract's `unshieldWith(b, proof, x.amount, x.recipient, …)`);
 * the relayed form binds the envelope, never `unwrapBinding` (the direct call's).
 */
struct ZetherUnshieldUnwrap {
    std::string seed;
    uint32_t account;
    std::string chain;
    std::string token;
    std::string batch;
    std::string underlying;
    std::string recipient;
    std::string amount;
    std::string min_out;
    uint64_t valid_until_block;
    Envelope envelope;
    std::optional<uint32_t> table_bits;
    std::optional<uint32_t> bound_bits;
};


/**
 * A prepared update: its write and `scaas-ua`'s warnings (`plan_msig_update`, none a refusal), in their `Debug` form.
 */
struct MsigUpdatePlan {
    std::shared_ptr<RegistryWrite> write;
    std::vector<std::string> warnings;
};

namespace uniffi {
struct FfiConverterOpState;
} // namespace uniffi

/**
 * An operation's state (spec §13.5, CLI-SDK-18): terminal only on a chain fact from a decisive read at the profile's final
 * block.
 */
struct OpState {
    friend uniffi::FfiConverterOpState;
    /**
     * the executed event of the operation's digest at or below the final block
     */
    struct kLanded {
        uint64_t block;
        std::string hash;
    };
    /**
     * the lane's nonce spent at the final block without that event; a replaced native send
     */
    struct kConsumed {
    };
    /**
     * an EVM native send final at or below the final block and reverted (owner 2026-11-18, ruling 4; the node's `reverted`)
     */
    struct kReverted {
        uint64_t block;
        std::string hash;
    };
    /**
     * `validUntil` below the final block's timestamp while the nonce is unspent
     */
    struct kExpired {
    };
    /**
     * anything else, with what is known (never an end)
     */
    struct kInFlight {
        InFlight detail;
    };
    OpState(kLanded variant): variant(variant) {}
    OpState(kConsumed variant): variant(variant) {}
    OpState(kReverted variant): variant(variant) {}
    OpState(kExpired variant): variant(variant) {}
    OpState(kInFlight variant): variant(variant) {}

    OpState(const OpState &other): variant(other.variant) {}
    OpState(OpState &&other): variant(std::move(other.variant)) {}

    OpState &operator=(const OpState &other) {
        variant = other.variant;
        return *this;
    }

    OpState &operator=(OpState &&other) {
        variant = std::move(other.variant);
        return *this;
    }

    /**
     * Returns the variant of this enum
     */
    const std::variant<kLanded, kConsumed, kReverted, kExpired, kInFlight> &get_variant() const {
        return variant;
    }

private:
    std::variant<kLanded, kConsumed, kReverted, kExpired, kInFlight> variant;

    OpState();
};


/**
 * How an item is kept: on this device only, out of cloud backups, behind user presence.
 */
struct StorePolicy {
    bool device_only;
    bool no_cloud_backup;
    Presence user_presence;
};


/**
 * One reviewed value: its name (a path for a nested field, `payment.value`), the value as signed, its display form.
 */
struct ReviewField {
    std::string name;
    std::string value;
    std::string display;
    Source source;
};


/**
 * A new seed and its one reveal.
 */
struct NewSeed {
    SeedInfo info;
    std::shared_ptr<SeedBackup> backup;
};


/**
 * The envelope of an owner statement's relayed form (`UARollOverSigned`, `UASetRollOverMode`): the Zether UA's own lane.
 */
struct OwnerRelay {
    std::string batch;
    Envelope envelope;
};


/**
 * `vault.derive_child`'s request: a stored seed (never a hidden set), the child's label and vault passphrase.
 */
struct DeriveChild {
    std::string parent;
    std::string label;
    std::shared_ptr<SecretBytes> vault_passphrase;
};


/**
 * A DEX of the chain profile (NET-ALL-24): its address, its liquidity mark (a module of group 11 among its `modules()`,
 * CTR-DEX-30) and the position readers reviewed for it, each beside its position manager.
 */
struct ListedDex {
    /**
     * `0x` + 40 hex
     */
    std::string address;
    bool liquidity;
    std::vector<PositionReader> position_readers;
};


/**
 * An `msig` structure: the threshold and the members, in slot order.
 */
struct MsigStructureArgs {
    uint16_t threshold;
    std::vector<MsigMemberArgs> members;
};


/**
 * A signed operation handed off (spec §27.5 (c)): the operation's named fields as signed (canonical), its signature in the
 * entry's form, the signer's subject id and kind. It holds no secret; who holds it can land it, never redirect it.
 */
struct SignedOpBlob {
    /**
     * 1
     */
    uint32_t v;
    /**
     * the profile's `chain_uid` (`0x` + 64 hex)
     */
    std::string chain_uid;
    /**
     * `evm`, `soroban`
     */
    std::string family;
    /**
     * the domain's contract, the token (`0x` + 40 hex; a `C…` on Soroban)
     */
    std::string contract;
    /**
     * the contract function (`mtxPay`, `mtxCancelNonce`, …; `pay`, `transfer`, `burn` on Soroban)
     */
    std::string entry;
    /**
     * the signed struct
     */
    std::string name;
    /**
     * the domain kind (`token`)
     */
    std::string kind;
    /**
     * the struct's fields, canonical (an unbound `relayer` and `feeRecipient` 0)
     */
    Value message;
    /**
     * what the entry takes unsigned beside them (a pay's `meta`, …)
     */
    Value extra;
    /**
     * the signature in the entry's form (`bytes`, a `UASig`)
     */
    Value signature;
    /**
     * the signer's subject id (the lane's `from`)
     */
    std::string signer;
    /**
     * the signer's kind (a UA kind, 0 a native EVM key)
     */
    uint16_t signer_kind;
    /**
     * the transfer on ids (`mtxExecuteTransfer`)
     */
    bool ids;
};


/**
 * `vault.import_words`'s request: 12 to 24 English words as a secret.
 */
struct ImportWords {
    std::string label;
    std::shared_ptr<SecretBytes> words;
    std::shared_ptr<SecretBytes> vault_passphrase;
};


/**
 * A registration carrying its PQZ key's proof as the SDK quoted it at prepare (owner 2026-11-20): one transaction, or two
 * (`register` without the proof, then `storePqzPop`, F22's restart-safe flow) when the one transaction's gas is above half
 * the chain's block gas limit or its regular gas above the per-transaction cap; each step's gas and the total.
 */
struct RegistrationGas {
    /**
     * 1 or 2
     */
    uint32_t transactions;
    /**
     * the steps prepared, in the order they land (after a restart between the two, the second alone)
     */
    std::vector<StepGas> steps;
    /**
     * the steps' gas added; `None` when a step's is not known
     */
    std::optional<uint64_t> total_gas;
};


/**
 * `UAZetherTransferSingle`: `amount` from the holder's Zether account (`seed`, `account`) to `to_ua` (a registered Zether
 * UA), the proof valid until block `valid_until_block`.
 */
struct ZetherTransfer {
    std::string seed;
    uint32_t account;
    std::string chain;
    std::string token;
    std::string batch;
    std::string to_ua;
    std::string amount;
    uint64_t valid_until_block;
    Envelope envelope;
    /**
     * the BSGS bits of the balance the proof needs (`None`: the facade's defaults)
     */
    std::optional<uint32_t> table_bits;
    std::optional<uint32_t> bound_bits;
};


/**
 * `vault.derive_from_signature`'s request (root (c)): the external wallet's account and the seed-set number `set` it signed
 * for, its two signatures of [`Vault::key_derivation_typed_data`] (65 bytes each; a 64-byte EIP-2098 one goes through
 * [`Vault::signature_from_compact`] first), the derivation passphrase (≥ 10 code points), the new seed's label and vault
 * passphrase.
 */
struct DeriveFromSignature {
    std::string label;
    /**
     * `0x` and 40 hex digits, any case
     */
    std::string account;
    uint32_t set;
    std::shared_ptr<SecretBytes> signature1;
    std::shared_ptr<SecretBytes> signature2;
    std::shared_ptr<SecretBytes> derivation_passphrase;
    std::shared_ptr<SecretBytes> vault_passphrase;
};


/**
 * `UAZetherTransfer` / `UAZetherTransferCompact`: the real `recipients` and `decoys` legs of amount 0 drawn uniformly from
 * the registry's `0x0141` list (CTR-UA-29, the default), every leg's position shuffled. `decoy_fee`: the per-leg fee the
 * token pays (decimal, `"0"` none; the token's `minDecoyFee` is the contract's check). `ua_signer_gas`: the Zether UA's
 * verify gas the prover's gas-cap check adds for the relayed build (zether-prover `uaSignerGas`), the app's figure: a verify
 * row for `0x0141` in the gas tables (chain → module → reference) wins over it (owner 2026-11-19, P1).
 */
struct ZetherTransferMulti {
    std::string seed;
    uint32_t account;
    std::string chain;
    std::string token;
    std::string batch;
    std::vector<ZetherLeg> recipients;
    uint32_t decoys;
    std::string decoy_fee;
    uint64_t ua_signer_gas;
    uint64_t valid_until_block;
    Envelope envelope;
    std::optional<uint32_t> table_bits;
    std::optional<uint32_t> bound_bits;
};


/**
 * A base row (gas table v2, owner 2026-11-19): the execution gas of `entry` (`mtxCancelNonce`, `mtxExecuteTransfer`, …) on a
 * contract of domain kind `kind` (`token`, `zether`, `pqz`, `wallet`, `account`, `dex`, `gov_router`), on a lane whose nonce
 * is 0 (`fresh`) or above, signed by the reference signer, a native EVM key (its path makes no registry call).
 */
struct GasBase {
    std::string entry;
    std::string kind;
    bool fresh;
    uint64_t gas;
    /**
     * the part that grows with an input's length (owner 2026-11-19, ruling B)
     */
    std::optional<GasPerByte> per_byte;
    /**
     * the fixed gas added when the operation saves its `PayMeta` record (owner 2026-11-19, ruling 1)
     */
    std::optional<uint64_t> save;
    /**
     * the gas added when the operation's fee is > 0, measured paying a recipient holding nothing (owner 2026-11-19, ruling 3)
     */
    std::optional<uint64_t> fee_extra;
    /**
     * the regular gas a derived-UA signer adds on this entry over the native reference signer, beyond its verify row (owner
     * 2026-11-19, A1: a derived id's ledger debit); added when the signer is a derived UA. `None`: nothing added
     */
    std::optional<uint64_t> ua_extra;
    /**
     * the part that grows with a count the operation names (owner 2026-11-19, I1); `None`: no count, nothing added
     */
    std::optional<GasPerItem> per_item;
    /**
     * the row's regular gas, its figure's part EIP-7825's per-transaction cap holds under EIP-8037 (controller call, owner
     * auto-run 2026-11-19; at a count of 0 on a counted row, whose `per_item` then carries its slope); `None`: the whole
     * figure is held to the cap
     */
    std::optional<uint64_t> regular;
};


/**
 * `vault.derive_from_key`'s request (root (d)): a 32-byte key of `network` (`evm` only: `Argument` otherwise), the derivation
 * passphrase (empty, or ≥ 10 code points), the seed-set number `index`, the new seed's label and vault passphrase.
 */
struct DeriveFromKey {
    std::string label;
    std::string network;
    std::shared_ptr<SecretBytes> key;
    std::shared_ptr<SecretBytes> derivation_passphrase;
    uint32_t index;
    std::shared_ptr<SecretBytes> vault_passphrase;
};


/**
 * `vault.import_key`'s request (spec §6.7): a classical private key of `network` (32 bytes) as a leaf of a seed, sealed as the
 * new label vault `native-import:<network>:<n>` under the seed's vault passphrase.
 */
struct ImportKey {
    std::string seed;
    /**
     * `ua-rs`'s network name (`evm`, `cosmos`, `hedera_ecdsa`, `hedera_ed25519`, `sui`, `stellar`, `ton`, `aptos`, `solana`)
     */
    std::string network;
    std::shared_ptr<SecretBytes> secret;
    std::shared_ptr<SecretBytes> vault_passphrase;
};


/**
 * A verify row (gas table v2): what a signer of UA kind `signer` (`0`: a native EVM key, the reference) adds over the
 * reference signer's execution gas.
 */
struct GasVerify {
    uint16_t signer;
    uint64_t gas;
    /**
     * the signer kind's signature length in calldata, `UASig` key data and signature ABI-padded (owner 2026-11-19, ruling
     * 2; for an `msig`, per member); the quote adds 64 gas a byte of it. Required in every row (owner 2026-11-19, A4); a
     * variable-length kind's longest (A5)
     */
    uint64_t sig_bytes;
    /**
     * a safety margin added to the row's gas, where the kind's worst case cannot be determined and the row is the most
     * expensive of many measurements (owner 2026-11-19, the sampled check's ruling 2 (b)); 0 when absent
     */
    uint64_t margin;
    /**
     * the part that grows with a count of the signer's (owner 2026-11-19, I1: `members`, a `0x0121` UA's n); `None`: none
     */
    std::optional<GasPerItem> per_item;
    /**
     * the registry line's columns (spec 2026-11-19-registry-verify-only-kinds §12, CTR-UA-65); all absent: the holder's own
     * check on any registry (every row before the line)
     */
    GasLine line;
};


/**
 * Every key version's balance of `signer` on `token` and their sum (P-T16-5): versions `0..=latest`, `latest` the registry's
 * `pqzVersions` word read with version 0's words; each version a [`super::Confidential::pqz_balance`] read of its own fixed
 * word set (R1 to R7), decrypted by its own key.
 */
struct PqzBalanceAll {
    /**
     * the sum, decimal
     */
    std::string amount;
    /**
     * version `i`'s balance at index `i`
     */
    std::vector<PqzBalance> versions;
};

namespace uniffi {
struct FfiConverterUnlock;
} // namespace uniffi

/**
 * How a seed opens (spec §6.10). `Passkey` and `Platform` go through the seed's PRF envelope (plan T7).
 */
struct Unlock {
    friend uniffi::FfiConverterUnlock;
    struct kPassphrase {
        std::shared_ptr<SecretBytes> v1;
    };
    struct kPasskey {
    };
    struct kPlatform {
    };
    Unlock(kPassphrase variant): variant(variant) {}
    Unlock(kPasskey variant): variant(variant) {}
    Unlock(kPlatform variant): variant(variant) {}

    Unlock(const Unlock &other): variant(other.variant) {}
    Unlock(Unlock &&other): variant(std::move(other.variant)) {}

    Unlock &operator=(const Unlock &other) {
        variant = other.variant;
        return *this;
    }

    Unlock &operator=(Unlock &&other) {
        variant = std::move(other.variant);
        return *this;
    }

    /**
     * Returns the variant of this enum
     */
    const std::variant<kPassphrase, kPasskey, kPlatform> &get_variant() const {
        return variant;
    }

private:
    std::variant<kPassphrase, kPasskey, kPlatform> variant;

    Unlock();
};


/**
 * The sources of a quote's figure: its base row's and its verify row's (owner 2026-11-19, part 3b). An app's figure, one
 * total, is `App` for both; a native send's estimate `Estimate` for both.
 */
struct GasSources {
    GasFrom base;
    GasFrom verify;
};


/**
 * `vault.remove`'s request.
 */
struct Remove {
    std::string seed;
    ConfirmRemove confirm;
    std::optional<ConfirmRemoveUnbacked> unbacked;
};

namespace uniffi {
struct FfiConverterExecuteCall;
} // namespace uniffi

/**
 * A mandate wallet's call (spec §13.2): decoded, or opaque under the marker.
 */
struct ExecuteCall {
    friend uniffi::FfiConverterExecuteCall;
    /**
     * an ERC-20 `transfer(to, amount)` of `token` held by the wallet
     */
    struct kTransfer {
        std::string token;
        std::string to;
        std::string amount;
    };
    /**
     * any other call: `OpaqueCallRefused` without the marker
     */
    struct kOpaque {
        std::string target;
        std::string value;
        std::string data;
        std::optional<AllowOpaqueCall> allow;
    };
    ExecuteCall(kTransfer variant): variant(variant) {}
    ExecuteCall(kOpaque variant): variant(variant) {}

    ExecuteCall(const ExecuteCall &other): variant(other.variant) {}
    ExecuteCall(ExecuteCall &&other): variant(std::move(other.variant)) {}

    ExecuteCall &operator=(const ExecuteCall &other) {
        variant = other.variant;
        return *this;
    }

    ExecuteCall &operator=(ExecuteCall &&other) {
        variant = std::move(other.variant);
        return *this;
    }

    /**
     * Returns the variant of this enum
     */
    const std::variant<kTransfer, kOpaque> &get_variant() const {
        return variant;
    }

private:
    std::variant<kTransfer, kOpaque> variant;

    ExecuteCall();
};


/**
 * An account's balances at one block.
 */
struct Balances {
    uint64_t block;
    /**
     * the native balance of an address or a native id (`None` for a derived UA: it holds no native coin)
     */
    std::optional<std::string> native;
    std::vector<TokenBalance> tokens;
};


/**
 * The SDK's caps and queues (spec §4). The fee caps are the app's to set for its chains; the defaults below are a floor
 * against a runaway quote, never a value assumed of a chain.
 */
struct Limits {
    /**
     * decimal wei
     */
    std::string max_fee_per_gas;
    uint64_t max_gas;
    /**
     * decimal wei
     */
    std::string max_cost;
    uint64_t watch_poll_ms;
    /**
     * accounts × chains × tokens per poll
     */
    uint32_t max_watch;
    /**
     * scrypt, Argon2id, proofs, slow key generation at once
     */
    uint32_t max_concurrent_heavy;
    /**
     * the longest an operation's `validUntil` may lie ahead of the SDK's clock, in seconds (the signing check's window), where
     * a profile names none
     */
    uint64_t max_valid_secs;
    uint32_t event_queue;
    /**
     * how long a terminal operation row stays in `sdk.state` after it ended, in seconds (default 90 days); a non-terminal row
     * is never pruned (owner 2026-11-19, T13b ruling 2)
     */
    uint64_t state_retention_secs;
    /**
     * the most a family's native transaction may cost its payer, per chain profile, as a decimal string in the chain's
     * smallest unit (spec §27.5 (e): fee + storage + forward; plan T41): never from an endpoint. A chain without its row
     * spends nothing natively (`FeeAboveCap`: fail closed). EVM's self-relay keeps `max_cost`
     */
    std::vector<NativeCap> max_native_cost;
};


/**
 * A page of history.
 */
struct HistoryPage {
    std::vector<HistoryItem> items;
    /**
     * on the first page (`before` none) only
     */
    std::vector<OpItem> ops;
    /**
     * where the next page starts; `None` after block 0
     */
    std::optional<Cursor> next;
};


/**
 * A verdict request (spec §9.3): the verifier's named fields of the operation (`op`: `{entry, args, binding?, amount?,
 * recipient?, unwrap?}`, the proof-carrying entry and its argument struct, as `POST /v1/pqz-verdict` takes them), the
 * statement the token rebuilds and the proof, `0x` hex.
 */
struct PqzVerdictRequest {
    std::string chain;
    std::string token;
    Value op;
    std::string statement;
    std::string proof;
};


/**
 * `vault.generate`'s request: the seed's label and its new vault passphrase (vault v1's rule).
 */
struct Generate {
    std::string label;
    std::shared_ptr<SecretBytes> vault_passphrase;
};


/**
 * `create_se_key`: a new secure-element P-256 key under `policy`, named `name` beside seed `seed`.
 */
struct CreateSeKey {
    std::string seed;
    std::string name;
    KeyPolicy policy;
};

namespace uniffi {
struct FfiConverterSmartCall;
} // namespace uniffi

/**
 * The call of a `SmartKeyAccount`'s `Execute` (spec §13.2): decoded, or opaque under the marker.
 */
struct SmartCall {
    friend uniffi::FfiConverterSmartCall;
    /**
     * an ERC-20 `transfer(to, amount)` of `token` held by the account
     */
    struct kTransfer {
        std::string token;
        std::string to;
        std::string amount;
    };
    /**
     * `account.initiateRecovery(key)`: the signer's account is `account`'s guardian (CTR-ACC-03)
     */
    struct kInitiateRecovery {
        std::string account;
        SubjectKeyArgs key;
    };
    /**
     * any other call: `OpaqueCallRefused` without the marker
     */
    struct kOpaque {
        std::string target;
        std::string value;
        std::string data;
        std::optional<AllowOpaqueCall> allow;
    };
    SmartCall(kTransfer variant): variant(variant) {}
    SmartCall(kInitiateRecovery variant): variant(variant) {}
    SmartCall(kOpaque variant): variant(variant) {}

    SmartCall(const SmartCall &other): variant(other.variant) {}
    SmartCall(SmartCall &&other): variant(std::move(other.variant)) {}

    SmartCall &operator=(const SmartCall &other) {
        variant = other.variant;
        return *this;
    }

    SmartCall &operator=(SmartCall &&other) {
        variant = std::move(other.variant);
        return *this;
    }

    /**
     * Returns the variant of this enum
     */
    const std::variant<kTransfer, kInitiateRecovery, kOpaque> &get_variant() const {
        return variant;
    }

private:
    std::variant<kTransfer, kInitiateRecovery, kOpaque> variant;

    SmartCall();
};


/**
 * A pay's `PayMeta` v3 (CTR-MTX-26): committed to by the signed `entryRef` (`metaPayId`).
 */
struct PayMeta {
    /**
     * `0x` + 64 hex; `None`: 32 random bytes
     */
    std::optional<std::string> salt;
    /**
     * a UUIDv7 in its text form, or `0x` + 64 hex; `None`: no number
     */
    std::optional<std::string> pay_no;
    /**
     * store the payment's record under `pay_no` on chain
     */
    bool save;
    PayBody body;
};

namespace uniffi {
struct FfiConverterEndpointAuth;
} // namespace uniffi

struct EndpointAuth {
    friend uniffi::FfiConverterEndpointAuth;
    struct kBearer {
        Secret v1;
    };
    struct kHmac {
        Secret v1;
    };
    struct kHeader {
        std::string name;
        Secret value;
    };
    EndpointAuth(kBearer variant): variant(variant) {}
    EndpointAuth(kHmac variant): variant(variant) {}
    EndpointAuth(kHeader variant): variant(variant) {}

    EndpointAuth(const EndpointAuth &other): variant(other.variant) {}
    EndpointAuth(EndpointAuth &&other): variant(std::move(other.variant)) {}

    EndpointAuth &operator=(const EndpointAuth &other) {
        variant = other.variant;
        return *this;
    }

    EndpointAuth &operator=(EndpointAuth &&other) {
        variant = std::move(other.variant);
        return *this;
    }

    /**
     * Returns the variant of this enum
     */
    const std::variant<kBearer, kHmac, kHeader> &get_variant() const {
        return variant;
    }

private:
    std::variant<kBearer, kHmac, kHeader> variant;

    EndpointAuth();
};

namespace uniffi {
struct FfiConverterMsigSlotValue;
} // namespace uniffi

/**
 * One slot of an `msig` signature (`KeyRef::Msig`), as `MsigSlot`.
 */
struct MsigSlotValue {
    friend uniffi::FfiConverterMsigSlotValue;
    /**
     * the signing (or native) member at `index` signs with `key`
     */
    struct kMember {
        uint16_t index;
        SlotKey key;
    };
    /**
     * the `msig` member at `index` signs by its own slots, one level down
     */
    struct kMsig {
        uint16_t index;
        std::vector<MsigLeafValue> members;
    };
    /**
     * the slot at `index` already signed on another device: its `MemberSig` JSON as `Op::member_sign` returned it
     */
    struct kSigned {
        uint16_t index;
        std::string member;
    };
    MsigSlotValue(kMember variant): variant(variant) {}
    MsigSlotValue(kMsig variant): variant(variant) {}
    MsigSlotValue(kSigned variant): variant(variant) {}

    MsigSlotValue(const MsigSlotValue &other): variant(other.variant) {}
    MsigSlotValue(MsigSlotValue &&other): variant(std::move(other.variant)) {}

    MsigSlotValue &operator=(const MsigSlotValue &other) {
        variant = other.variant;
        return *this;
    }

    MsigSlotValue &operator=(MsigSlotValue &&other) {
        variant = std::move(other.variant);
        return *this;
    }

    /**
     * Returns the variant of this enum
     */
    const std::variant<kMember, kMsig, kSigned> &get_variant() const {
        return variant;
    }

private:
    std::variant<kMember, kMsig, kSigned> variant;

    MsigSlotValue();
};

namespace uniffi {
struct FfiConverterEvent;
} // namespace uniffi

/**
 * An SDK event (appended only).
 */
struct Event {
    friend uniffi::FfiConverterEvent;
    struct kSeedUnlocked {
        std::string seed;
    };
    struct kSeedLocked {
        std::string seed;
    };
    struct kKeystoreChanged {
        uint64_t rev;
    };
    struct kKeystoreMismatch {
        std::string seed;
    };
    struct kKeystoreRollback {
    };
    struct kHiddenOpsAbandoned {
        uint32_t count;
    };
    /**
     * The subscriber's queue overflowed: `missed` events were dropped for it
     */
    struct kLagged {
        uint64_t missed;
    };
    /**
     * An operation's state changed (spec §13.4, §13.5): every send result after `submit` arrives here, never as its error.
     */
    struct kOpState {
        std::string op;
        OpState state;
    };
    /**
     * A watched token's balance moved at the profile's final block (spec §14).
     */
    struct kBalanceChanged {
        std::string account;
        std::string chain;
        std::string token;
    };
    /**
     * A watched account's new history items (spec §8.4), newest first.
     */
    struct kHistoryAdded {
        std::string account;
        std::string chain;
        std::vector<HistoryItem> items;
    };
    /**
     * Another process changed `sdk.state` (R17): its `rev` now.
     */
    struct kStateChanged {
        uint64_t rev;
    };
    Event(kSeedUnlocked variant): variant(variant) {}
    Event(kSeedLocked variant): variant(variant) {}
    Event(kKeystoreChanged variant): variant(variant) {}
    Event(kKeystoreMismatch variant): variant(variant) {}
    Event(kKeystoreRollback variant): variant(variant) {}
    Event(kHiddenOpsAbandoned variant): variant(variant) {}
    Event(kLagged variant): variant(variant) {}
    Event(kOpState variant): variant(variant) {}
    Event(kBalanceChanged variant): variant(variant) {}
    Event(kHistoryAdded variant): variant(variant) {}
    Event(kStateChanged variant): variant(variant) {}

    Event(const Event &other): variant(other.variant) {}
    Event(Event &&other): variant(std::move(other.variant)) {}

    Event &operator=(const Event &other) {
        variant = other.variant;
        return *this;
    }

    Event &operator=(Event &&other) {
        variant = std::move(other.variant);
        return *this;
    }

    /**
     * Returns the variant of this enum
     */
    const std::variant<kSeedUnlocked, kSeedLocked, kKeystoreChanged, kKeystoreMismatch, kKeystoreRollback, kHiddenOpsAbandoned, kLagged, kOpState, kBalanceChanged, kHistoryAdded, kStateChanged> &get_variant() const {
        return variant;
    }

private:
    std::variant<kSeedUnlocked, kSeedLocked, kKeystoreChanged, kKeystoreMismatch, kKeystoreRollback, kHiddenOpsAbandoned, kLagged, kOpState, kBalanceChanged, kHistoryAdded, kStateChanged> variant;

    Event();
};


/**
 * One endpoint of a profile's RPC or gateway list (CLI-RPC-02): `{url, class, label, auth}`; `auth` belongs to this endpoint
 * only and is built by the app from its own secret source.
 */
struct EndpointConfig {
    std::string url;
    Class class_;
    std::optional<std::string> label;
    std::optional<EndpointAuth> auth;
};


/**
 * The rows of a gas table: base and verify, looked up independently (spec §13.3). The quote's figure is base + verify.
 */
struct GasRows {
    std::vector<GasBase> base;
    std::vector<GasVerify> verify;
};


/**
 * An `msig` on the profile's registry (`msig_state`).
 */
struct MsigState {
    std::string ua;
    /**
     * the structure the id derives from (`registrationOf`)
     */
    MsigStructureArgs first;
    /**
     * the current threshold (`msigOf`)
     */
    uint16_t threshold;
    /**
     * the current slots, disabled ones included
     */
    std::vector<MsigSlotState> slots;
    /**
     * `msigStateOf`'s update counter (0: never updated here)
     */
    uint64_t version;
    /**
     * the weight of the slots enabled and accepted
     */
    uint32_t active_weight;
    /**
     * that weight reaches the threshold: until then the `msig` authorizes nothing (CTR-UA-37)
     */
    bool active;
};


/**
 * A single-key registration's arguments by name, as `scaas-ua`'s `registration_args` gives them: `register` (`kind`,
 * `keyData`) or `registerWebAuthn` (`key`); bytes as `0x` hex.
 */
struct RegisterArgs {
    std::string entry;
    std::optional<uint16_t> kind;
    std::optional<std::string> key_data;
    std::optional<WebAuthnArgs> key;
    AttrsArgs attrs;
    std::string pqz_pop;
    std::string pop;
};


/**
 * A gas table file (spec §13.3, the gas table format): `{format: "scaas.gas-table", v: 2, name, family, assumptions, base,
 * verify}`, each base row `{entry, kind, fresh, gas, measured, source, calldata_gas?, per_byte?: {input, gas, source},
 * save?: {gas, measured, source}, fee_extra?: {gas, measured, source}, ua_extra?: {gas, measured, source}, item?,
 * per_item?: {gas, base_count, source, regular?}, stand_in?, regular?: {gas, measured, source}}`, each verify row
 * `{signer, gas, measured, source, sig_bytes, margin?, item?, per_item?, stand_in?, registry?, path?, depth?, write?}` (the
 * line's columns, [`GasLine`]), read by [`GasTable::parse`]. One format for the chain's measured rows, a module's table
 * and the SDK's reference table.
 */
struct GasTable {
    /**
     * a module's name, `reference`, or the chain key of a chain's measured rows
     */
    std::string name;
    /**
     * `evm` (the only family with a table today)
     */
    std::string family;
    GasRows rows;
};

namespace uniffi {
struct FfiConverterKeyRef;
} // namespace uniffi

/**
 * A key the SDK signs with, by reference (spec §5): the seed's open wallet holds it, or, for [`KeyRef::Key`], the platform's
 * authenticator (a passkey or a secure-element key, a row of the seed: owner 2026-11-19, S1).
 */
struct KeyRef {
    friend uniffi::FfiConverterKeyRef;
    struct kUa {
        std::string seed;
        uint16_t kind;
        uint32_t account;
        uint32_t index;
    };
    struct kNative {
        std::string seed;
        /**
         * a `scaas-ua` network name (`evm` for a payer)
         */
        std::string network;
        uint32_t index;
    };
    /**
     * an imported classical key (spec §6.7, `vault.import_key`): the seed's vault `native-import:<network>:<index>`
     */
    struct kImported {
        std::string seed;
        std::string network;
        uint32_t index;
    };
    /**
     * the stored key row `id` of seed `seed` (`AccountRow::Key`: a passkey `webauthn-p256` with its credential id, a
     * secure-element `p256` key with its handle), signing through the `Authenticator` (`external`)
     */
    struct kKey {
        std::string seed;
        std::string id;
    };
    /**
     * the `msig` UA `ua` (`0x` + 64 hex) of the profile's registry, signing by the member slots named (CTR-UA-09, CTR-UA-38),
     * each slot's key one this SDK holds; a minimal set of enabled and accepted slots of its current structure (CTR-UA-07,
     * CTR-UA-37, CTR-UA-44). A slot's key is never an `Msig` itself (`Argument`).
     */
    struct kMsig {
        std::string ua;
        std::vector<MsigSlot> slots;
    };
    /**
     * a `bls12381-multi` (`0x0121`) group (plan Task 17): the seed's member key `ua_key(0x0121, account, index)` (EIP-2333:
     * index 0) and the group's key data `d` (`0x` hex, spec 2026-11-19-bls12381-multi §2); the signer's id is the group's
     * UA, its signature the members' aggregate ([`Op::submit_bls_multi`])
     */
    struct kBlsMulti {
        std::string seed;
        uint32_t account;
        uint32_t index;
        std::string key_data;
    };
    /**
     * an operation another party signed and handed off (`Op::import_signed`, spec §27.5 (c)): its signer's subject id (`0x`
     * hex); nothing in this SDK signs for it
     */
    struct kSigned {
        std::string signer;
    };
    KeyRef(kUa variant): variant(variant) {}
    KeyRef(kNative variant): variant(variant) {}
    KeyRef(kImported variant): variant(variant) {}
    KeyRef(kKey variant): variant(variant) {}
    KeyRef(kMsig variant): variant(variant) {}
    KeyRef(kBlsMulti variant): variant(variant) {}
    KeyRef(kSigned variant): variant(variant) {}

    KeyRef(const KeyRef &other): variant(other.variant) {}
    KeyRef(KeyRef &&other): variant(std::move(other.variant)) {}

    KeyRef &operator=(const KeyRef &other) {
        variant = other.variant;
        return *this;
    }

    KeyRef &operator=(KeyRef &&other) {
        variant = std::move(other.variant);
        return *this;
    }

    /**
     * Returns the variant of this enum
     */
    const std::variant<kUa, kNative, kImported, kKey, kMsig, kBlsMulti, kSigned> &get_variant() const {
        return variant;
    }

private:
    std::variant<kUa, kNative, kImported, kKey, kMsig, kBlsMulti, kSigned> variant;

    KeyRef();
};


/**
 * The sponsored registration's blob (spec §7.1; owner 2026-11-19, R2): public data only, every field named. Its text form is
 * clientkeys' `registrationBlob` (`smartcontracts/vectors/ua/registration_blobs.json`).
 */
struct RegistrationBlob {
    uint32_t v;
    std::string ua;
    uint16_t kind;
    RegisterArgs args;
    std::optional<KemRecord> kem;
};

namespace uniffi {
struct FfiConverterFamilyParams;
} // namespace uniffi

/**
 * A family's own profile data (spec §8.7 rule 2; decisions CLI-SDK-15's Changes of 2026-11-21).
 */
struct FamilyParams {
    friend uniffi::FfiConverterFamilyParams;
    /**
     * Cosmos: the chain id the gateways' `node_info` must name (the identity a Cosmos node answers; `chain_uid` stays the
     * profile's 32-byte network id), the REST gateways with their policy (the profile's `rpc` are the CometBFT endpoints),
     * the native denom and the bech32 prefix of the chain's addresses
     */
    struct kCosmos {
        std::string chain_id;
        std::vector<EndpointConfig> rest;
        Policy rest_policy;
        std::string denom;
        std::string prefix;
    };
    /**
     * Aptos: the chain id ledger info must name (`aptos_framework::chain_id`, 1 to 255; the identity an Aptos node answers)
     * and the `scaas` package's address, whose view `meta::account_of(owner)` gives the Account an owner's tokens are in
     * (NET-APT-05), as `0x` + 64 lowercase hex (AIP-40's long form)
     */
    struct kAptos {
        uint8_t chain_id;
        std::string package;
    };
    /**
     * Solana: the `scaas` program's id (base58 of 32 bytes), under which an owner's SCaaS Account is the `["acct", owner]`
     * program address (`ua-rs` `families::solana`); the cluster's identity is its genesis hash, `chain_uid`'s 32 bytes
     */
    struct kSolana {
        std::string program;
    };
    /**
     * Soroban: the network passphrase its RPC endpoints name (`getNetwork`; its SHA-256 is `chain_uid`, checked at `Sdk::open`)
     * and the XLM SAC contract (`C…`), pinned, whose balance entry is a `C…` holder's native XLM (never derived here)
     */
    struct kSoroban {
        std::string passphrase;
        std::string xlm_sac;
    };
    /**
     * Sui: the GraphQL endpoints the reads go to, with their policy (public fullnodes refuse JSON-RPC, docs/networks/sui.md
     * §14; the profile's `rpc` are the JSON-RPC endpoints), each named by `chain_uid`, the genesis checkpoint's digest, whose
     * 32 bytes in base58 `chainIdentifier` must answer
     */
    struct kSui {
        std::vector<EndpointConfig> graphql;
        Policy graphql_policy;
    };
    /**
     * Polkadot Hub's Substrate side on its EVM profile (decisions CLI-SDK-32's Change of 2026-11-22, plan T32's read part): the
     * Substrate JSON-RPC endpoints with their policy, each named by `genesis` (`0x` + 64 hex, `chain_getBlockHash(0)`), and the
     * SS58 prefix of the chain's addresses (0 to 16,383, not 46 or 47); `balances` of an SS58 id reads its `System.Account`
     * there. The same params serve the relay chain's Substrate side
     */
    struct kSubstrate {
        std::vector<EndpointConfig> rpc;
        Policy rpc_policy;
        std::string genesis;
        uint16_t ss58_prefix;
    };
    FamilyParams(kCosmos variant): variant(variant) {}
    FamilyParams(kAptos variant): variant(variant) {}
    FamilyParams(kSolana variant): variant(variant) {}
    FamilyParams(kSoroban variant): variant(variant) {}
    FamilyParams(kSui variant): variant(variant) {}
    FamilyParams(kSubstrate variant): variant(variant) {}

    FamilyParams(const FamilyParams &other): variant(other.variant) {}
    FamilyParams(FamilyParams &&other): variant(std::move(other.variant)) {}

    FamilyParams &operator=(const FamilyParams &other) {
        variant = other.variant;
        return *this;
    }

    FamilyParams &operator=(FamilyParams &&other) {
        variant = std::move(other.variant);
        return *this;
    }

    /**
     * Returns the variant of this enum
     */
    const std::variant<kCosmos, kAptos, kSolana, kSoroban, kSui, kSubstrate> &get_variant() const {
        return variant;
    }

private:
    std::variant<kCosmos, kAptos, kSolana, kSoroban, kSui, kSubstrate> variant;

    FamilyParams();
};


struct SetMandate {
    KeyRef signer;
    std::string chain;
    /**
     * the contract (`0x` + 40 hex): a token, or a mandate wallet
     */
    std::string contract;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string token;
    std::string delegate;
    std::string max_per_payment;
    std::string max_per_period;
    std::string period_seconds;
    std::string expiry;
    Envelope envelope;
};


/**
 * What the payee expects of an imported operation: its chain, its own ids (`0x` + 64 hex: a pay or transfer must name one as
 * `to`), and the native key that will submit it (`SubmitPath::SelfRelay`).
 */
struct ImportExpect {
    std::string chain;
    std::vector<std::string> payee;
    KeyRef payer;
};


/**
 * A wrap order (`UAWrapOrder`, CTR-TOK wrap orders): `amount` of the SCaaS token `token` wrapped into `wrapped_token`, at least
 * `min_minted` minted; fills whole (`min_fill` = `amount`).
 */
struct WrapOrder {
    KeyRef signer;
    std::string chain;
    /**
     * the underlying: the order's domain
     */
    std::string token;
    /**
     * a wrapper of the profile's list
     */
    std::string wrapped_token;
    std::string amount;
    std::string min_minted;
    std::string min_fill;
    std::string fee;
    std::string relayer;
    std::optional<std::string> destination;
    uint8_t flags;
    std::string batch;
    /**
     * `None`: the lane's floor on the underlying
     */
    std::optional<std::string> nonce;
    uint64_t valid_until;
};


/**
 * `pqz_shield` (`UAShield` on a PQZ token): `amount` of the signer's public balance into `to_ua`'s pending window.
 */
struct PqzShield {
    KeyRef signer;
    std::string chain;
    std::string token;
    std::string batch;
    std::string to_ua;
    std::string amount;
    Envelope envelope;
};


/**
 * `prepare_msig_register`: the `msig` `structure` registered on `chain` (`registerMsig`), its `pop` signed by `slots` (a
 * minimal set, CTR-UA-07; none: an empty `pop`, a classical-dominant `msig`'s), sent by `payer`.
 */
struct MsigRegister {
    std::string chain;
    MsigStructureArgs structure;
    std::vector<MsigSlot> slots;
    KeyRef payer;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetAuditorUA
 */
struct UaSetAuditorUa {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string new_auditor;
    std::string epoch;
    std::string consent;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UATransferAdmin
 */
struct UaTransferAdmin {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string new_admin;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UACancelGrant
 */
struct UaCancelGrant {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string bit;
    std::string account;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * The ordered cancel of a lane's nonce on ids (a token kind or a mandate wallet).
 */
struct CancelNonce {
    KeyRef signer;
    std::string chain;
    /**
     * the contract (`0x` + 40 hex): a token, or a mandate wallet
     */
    std::string contract;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string lane;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAEnableFeature
 */
struct UaEnableFeature {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string bit;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


struct DelegateRevoke {
    KeyRef signer;
    std::string chain;
    /**
     * the contract (`0x` + 40 hex): a token, or a mandate wallet
     */
    std::string contract;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string token;
    std::string epoch;
    Envelope envelope;
};


/**
 * The cancel of one order (`CancelUAOrder` on its SCaaS sell token, `CancelDexOrder` on the DEX for an outside token's).
 */
struct CancelOrder {
    KeyRef signer;
    std::string chain;
    std::string sell_token;
    OrderTerms order;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetAllowed
 */
struct UaSetAllowed {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::vector<std::string> accounts;
    bool on;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetDenied
 */
struct UaSetDenied {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::vector<std::string> accounts;
    bool on;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAApproveRelease
 */
struct UaApproveRelease {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string contract_class;
    std::string kind;
    std::string version;
    std::string env_version;
    std::string init_selector;
    std::string interface_id;
    std::string initcode_hash;
    std::string impl_args_hash;
    std::string factory;
    std::string admin_generation;
    std::string until;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UARenounceRole
 */
struct UaRenounceRole {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string bit;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * `pqz_wrap_shield` (`WrapShield` on a PQZ token): wrap `amount_in` of `underlying` and shield it to `to_ua`.
 */
struct PqzWrapShield {
    KeyRef signer;
    std::string chain;
    std::string token;
    std::string batch;
    std::string underlying;
    std::string amount_in;
    std::string to_ua;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetCompliance
 */
struct UaSetCompliance {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::vector<std::string> accounts;
    std::vector<std::string> flags;
    std::vector<std::string> until;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UARevokeApproval
 */
struct UaRevokeApproval {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string key;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetListedOnly
 */
struct UaSetListedOnly {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    bool on;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * `prepare_native_send`'s request.
 */
struct NativeSend {
    /**
     * a native `evm` key
     */
    KeyRef key;
    std::string chain;
    /**
     * `0x` + 40 hex
     */
    std::string to;
    /**
     * wei, decimal
     */
    std::string value;
    /**
     * `0x` hex calldata, or none
     */
    std::optional<std::string> data;
    /**
     * the EIP-2718 type asked: 0, 1 or 2 (2 only where the chain has a base fee); `None`: 2 where it has one, else 0.
     * `TxTypeRefused` otherwise (3 and 4 never)
     */
    std::optional<uint8_t> tx_type;
};


/**
 * `UAPqzTransfer` / `UAPqzTransferCompact`: the `legs` (their count one the set builds, 1, 2, 4 or 8), `decoy_fee` the per-leg
 * fee (decimal; at least the token's `minDecoyFee`, the contract's check).
 */
struct PqzTransferMulti {
    KeyRef signer;
    std::string chain;
    std::string token;
    std::string batch;
    uint64_t key_version;
    std::vector<PqzLeg> legs;
    std::string decoy_fee;
    uint64_t valid_until_block;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAExecuteRate
 */
struct UaExecuteRate {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetFeeSplit
 */
struct UaSetFeeSplit {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string relayer_share_ppm;
    std::string treasury;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetWrapLimits
 */
struct UaSetWrapLimits {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string legs;
    bool net_unwrap;
    bool wrap_list;
    bool unwrap_list;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAProposeRate
 */
struct UaProposeRate {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string leg;
    std::string num;
    std::string den;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * The part every `SmartKeyAccount` entry shares: the account (`0x` + 40 hex), the key of it that signs, the lane, the envelope.
 * `key_index` (decimal) is the signer's index in the account; `None`: read from the account (S3).
 */
struct SmartOp {
    KeyRef signer;
    std::optional<std::string> key_index;
    std::string chain;
    std::string account;
    std::string batch;
    Envelope envelope;
};


/**
 * `accept_membership` (CTR-UA-37): slot `slot` of the `msig` `ua` accepts on `chain`, sent by `payer`.
 */
struct AcceptMembership {
    std::string chain;
    std::string ua;
    MsigSlot slot;
    KeyRef payer;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAForceTransfer
 */
struct UaForceTransfer {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string record_id;
    std::string amount;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UADisableWrap
 */
struct UaDisableWrap {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string leg;
    std::string reason;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetChainEntries
 */
struct UaSetChainEntries {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string entries;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetExchangeTarget
 */
struct UaSetExchangeTarget {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string exchange_target;
    bool listed;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * The rescue vault's signature request: the vault's admin key (a native EVM key) and the operation.
 */
struct RescueVault {
    KeyRef signer;
    std::string vault;
    RescueOp op;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAPublishTokenEnv
 */
struct UaPublishTokenEnv {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string kind;
    std::string env_version;
    std::string env;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * `UARollOverBatch`: roll each of `uas` over.
 */
struct ZetherRollOverBatch {
    KeyRef signer;
    std::string chain;
    std::string token;
    std::string batch;
    std::vector<std::string> uas;
    Envelope envelope;
};


/**
 * `prepare_register`: the UA key `key` (a seed's `KeyRef::Ua`) registered on `chain`, its writes self-relayed by `payer` (a
 * native `evm` key).
 */
struct Register {
    KeyRef key;
    std::string chain;
    RegisterAttrs attrs;
    KeyRef payer;
};


/**
 * `mtxPay`: a `UAMetaTransfer` whose `entryRef` is `metaPayId(meta)`, on its pay lane, signed under `Expect::PayMeta`.
 */
struct Pay {
    KeyRef signer;
    std::string chain;
    std::string token;
    std::string to;
    std::string value;
    PayMeta meta;
    Envelope envelope;
};

namespace uniffi {
struct FfiConverterSubmitPath;
} // namespace uniffi

/**
 * How an operation reaches the chain (spec §13.3).
 */
struct SubmitPath {
    friend uniffi::FfiConverterSubmitPath;
    /**
     * a gateway when the profile has one and the entry is one a gateway takes (door A), else a self-relay by `payer` when
     * given, else `SubmitPathNone`
     */
    struct kAuto {
        std::optional<KeyRef> payer;
    };
    /**
     * the profile's gateways, the same body to each
     */
    struct kGateway {
    };
    /**
     * an EIP-1559 transaction from the holder's own native EVM key, which pays the gas
     */
    struct kSelfRelay {
        KeyRef payer;
    };
    SubmitPath(kAuto variant): variant(variant) {}
    SubmitPath(kGateway variant): variant(variant) {}
    SubmitPath(kSelfRelay variant): variant(variant) {}

    SubmitPath(const SubmitPath &other): variant(other.variant) {}
    SubmitPath(SubmitPath &&other): variant(std::move(other.variant)) {}

    SubmitPath &operator=(const SubmitPath &other) {
        variant = other.variant;
        return *this;
    }

    SubmitPath &operator=(SubmitPath &&other) {
        variant = std::move(other.variant);
        return *this;
    }

    /**
     * Returns the variant of this enum
     */
    const std::variant<kAuto, kGateway, kSelfRelay> &get_variant() const {
        return variant;
    }

private:
    std::variant<kAuto, kGateway, kSelfRelay> variant;

    SubmitPath();
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UADeprecateDex
 */
struct UaDeprecateDex {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string version;
    std::string reason;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAPqzSetVerifier
 */
struct UaPqzSetVerifier {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string next;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * `UAPayeeFee` (CTR-MTX-86): the payee's co-signature of its fee over the payment it expects; signed by the payee.
 */
struct PayeeFee {
    KeyRef signer;
    std::string chain;
    std::string token;
    Payment payment;
    PayMeta meta;
    PayerAuth payer_auth;
    std::string fee;
    std::string fee_recipient;
    uint64_t valid_until;
};


/**
 * `UAExecute` on a mandate wallet: the owner's call, decoded only.
 */
struct Execute {
    KeyRef signer;
    std::string chain;
    std::string wallet;
    ExecuteCall call;
    std::string batch;
    Envelope envelope;
};


/**
 * `UARelayFee` (CTR-MTX-27): a fee to `payee` for relaying the operation `call`, bound by the hash of its signed calldata; the
 * gateway job carries that operation as its `call` (`scaas-ua` `relay_fee_op`; owner 2026-11-19, ruling F).
 */
struct RelayFee {
    KeyRef signer;
    std::string chain;
    std::string token;
    /**
     * the operation paid for: an operation id of this SDK (`Op::submit`'s), signed, on this chain, with a gateway job form;
     * its contract is the signed `target`
     */
    std::string call;
    std::string payee;
    std::string value;
    std::string batch;
    uint64_t valid_until;
    std::string relayer;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UARenounceAdmin
 */
struct UaRenounceAdmin {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetKycProvider
 */
struct UaSetKycProvider {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string provider;
    bool enabled;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * `UAPrepareAcc` (`half` 0 or 1 of the materialisation) and `UAPqzRollOver` (`n` pending entries) of `ua`'s account at key
 * version `key_version`.
 */
struct PqzAccountOp {
    KeyRef signer;
    std::string chain;
    std::string token;
    std::string batch;
    std::string ua;
    uint64_t key_version;
    /**
     * `half` for `UAPrepareAcc`, `n` for `UAPqzRollOver`
     */
    std::string value;
    Envelope envelope;
};


/**
 * A trade order (`TradeOrder`'s named fields, CTR-DEX-15): sold `amount` of `sell_token` for at least `receive_amount` of
 * `receive_token`, each settlement at least `min_fill` unless it closes the order.
 */
struct TradeOrder {
    KeyRef signer;
    std::string chain;
    std::string sell_token;
    /**
     * a DEX of the profile's list (CLI-SGN-35)
     */
    std::string dex;
    std::string receive_token;
    std::string amount;
    std::string receive_amount;
    std::string min_fill;
    /**
     * the DEX fee rate the order accepts on what it receives, in millionths (at most 10,000)
     */
    std::string fee;
    std::string relayer;
    /**
     * `None`: 0 (the signer receives)
     */
    std::optional<std::string> destination;
    /**
     * 1 IOC, 2 ESCROW (with IOC, SCaaS sell tokens only), 4 reserved by the venue
     */
    uint8_t flags;
    /**
     * the order lane, decimal (not an envelope's lane)
     */
    std::string batch;
    /**
     * `None`: the lane's floor (`minNonce(from, batch)` on the sell token, or on the DEX for an outside token) read now
     */
    std::optional<std::string> nonce;
    /**
     * unix seconds on the chain's clock
     */
    uint64_t valid_until;
};


/**
 * `UAPayUnderMandate`: the delegate's payment from the mandate wallet, its `entryRef` `metaPayId(meta)`.
 */
struct PayUnderMandate {
    KeyRef signer;
    std::string chain;
    std::string wallet;
    std::string token;
    std::string payee;
    std::string amount;
    std::string epoch;
    std::string batch;
    PayMeta meta;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UARevokeRole
 */
struct UaRevokeRole {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string bit;
    std::string account;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A PQZ balance read (spec §9.2, §9.4): the account of the UA key `signer` (a PQZ-capable kind, `KeyRef::Ua`) at key
 * version `key_version`, whose PQZ key is the wallet's `pqz_key_version(account, index, key_version)` of the same account and
 * index (spec §7).
 */
struct PqzBalanceRequest {
    KeyRef signer;
    std::string chain;
    /**
     * the token, `0x` + 40 hex
     */
    std::string token;
    uint64_t key_version;
};


/**
 * The cancel of every order of one lane below `min_nonce` (`POST /v1/dex/cancel-all`).
 */
struct CancelAll {
    KeyRef signer;
    std::string chain;
    std::string sell_token;
    /**
     * the DEX whose factory names the sell token's form; on the profile's list
     */
    std::string dex;
    std::string batch;
    /**
     * `None`: the lane's floor read now plus one (every order signed at the floor)
     */
    std::optional<std::string> min_nonce;
};


struct Burn {
    KeyRef signer;
    std::string chain;
    /**
     * the contract (`0x` + 40 hex): a token, or a mandate wallet
     */
    std::string contract;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string amount;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAMintToUA
 */
struct UaMintToUa {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string to;
    std::string amount;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAUnfreeze
 */
struct UaUnfreeze {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string account;
    std::string ref_id;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UACancelRate
 */
struct UaCancelRate {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetClassKindEnabled
 */
struct UaSetClassKindEnabled {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string contract_class;
    std::string kind;
    bool on;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetMaxSupply
 */
struct UaSetMaxSupply {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string max_supply;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * `UAPayWithTax` (regulated kinds): the payer's payment and its tax.
 */
struct PayWithTax {
    KeyRef signer;
    std::string chain;
    std::string token;
    std::string to;
    std::string value;
    PayMeta meta;
    uint8_t tax_mode;
    std::string tax;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAPause
 */
struct UaPause {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string ref_id;
    std::string until;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * The new auditor's consent to a set-auditor (spec 2026-11-18 set-auditor §5.2): `AuditorConsent(token, auditor, epoch,
 * chainUid)` in the confidential token's domain.
 */
struct AuditorConsent {
    /**
     * PQZ: the auditor's UA key; Zether: the auditor's Zether UA (`kind` 0x0141)
     */
    KeyRef signer;
    std::string chain;
    std::string token;
    uint32_t epoch;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAOperatorTransfer
 */
struct UaOperatorTransfer {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string account;
    std::string to;
    std::string amount;
    std::string ref_id;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetVerifierFee
 */
struct UaSetVerifierFee {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string next;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAPqzRevokeVerifier
 */
struct UaPqzRevokeVerifier {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


struct AddReserve {
    KeyRef signer;
    std::string chain;
    /**
     * the contract (`0x` + 40 hex): a token, or a mandate wallet
     */
    std::string contract;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string underlying;
    std::string amount;
    Envelope envelope;
};


struct UnwrapLeg {
    KeyRef signer;
    std::string chain;
    /**
     * the contract (`0x` + 40 hex): a token, or a mandate wallet
     */
    std::string contract;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string underlying;
    std::string wrapped;
    std::string recipient;
    std::string min_out;
    Envelope envelope;
};


struct UnwrapToUa {
    KeyRef signer;
    std::string chain;
    /**
     * the contract (`0x` + 40 hex): a token, or a mandate wallet
     */
    std::string contract;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string underlying;
    std::string wrapped;
    std::string to;
    std::string min_out;
    Envelope envelope;
};


/**
 * `zether_shield` (`UAShield` on a Zether token): `amount` of the signer's public balance into `to_ua`'s pending balance.
 */
struct ZetherShield {
    KeyRef signer;
    std::string chain;
    std::string token;
    std::string batch;
    std::string to_ua;
    std::string amount;
    Envelope envelope;
};


struct WrapToUa {
    KeyRef signer;
    std::string chain;
    /**
     * the contract (`0x` + 40 hex): a token, or a mandate wallet
     */
    std::string contract;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string underlying;
    std::string amount;
    std::string to;
    Envelope envelope;
};


struct Wrap {
    KeyRef signer;
    std::string chain;
    /**
     * the contract (`0x` + 40 hex): a token, or a mandate wallet
     */
    std::string contract;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string amount;
    Envelope envelope;
};


/**
 * The cancel of one wrap order (`CancelUAWrapOrder` on the underlying `token`).
 */
struct CancelWrapOrder {
    KeyRef signer;
    std::string chain;
    std::string token;
    WrapOrderTerms order;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetMaxWrapSupply
 */
struct UaSetMaxWrapSupply {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string max_wrap_supply;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UADisableFeature
 */
struct UaDisableFeature {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string bit;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A liquidity order (`LiquidityOrder`, CTR-DEX-30; dex-liquidity spec §4.2), signed in its DEX's domain.
 */
struct LiquidityOrder {
    KeyRef signer;
    std::string chain;
    /**
     * a DEX of the profile's list with its liquidity mark
     */
    std::string dex;
    std::vector<LiquidityToken> inputs;
    std::vector<LiquidityToken> outputs;
    std::optional<std::string> position_manager;
    std::optional<std::string> position_reader;
    std::string position_in;
    /**
     * `0x` + 64 hex; `None`: no position received
     */
    std::optional<std::string> position_pool;
    int32_t tick_lower;
    int32_t tick_upper;
    std::string min_liquidity;
    /**
     * a 32-byte id; `None`: the signer
     */
    std::optional<std::string> recipient;
    std::string fee;
    std::string relayer;
    uint8_t flags;
    std::string batch;
    /**
     * the order's nonce (the planner's; no lane is read)
     */
    std::string nonce;
    uint64_t valid_until;
    /**
     * tokens the plan counts beside its inputs and outputs (at most eight)
     */
    std::vector<std::string> extra_tokens;
    /**
     * a partial withdraw or fee collect (it must receive the position back)
     */
    bool partial;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAPqzCancelVerifier
 */
struct UaPqzCancelVerifier {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetProofStore
 */
struct UaSetProofStore {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string next;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetTaxRecipient
 */
struct UaSetTaxRecipient {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string tax_recipient;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UADeprecateToken
 */
struct UaDeprecateToken {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string kind;
    std::string version;
    std::string reason;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


struct Unwrap {
    KeyRef signer;
    std::string chain;
    /**
     * the contract (`0x` + 40 hex): a token, or a mandate wallet
     */
    std::string contract;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string wrapped;
    std::string recipient;
    std::string min_out;
    Envelope envelope;
};


struct WrapLeg {
    KeyRef signer;
    std::string chain;
    /**
     * the contract (`0x` + 40 hex): a token, or a mandate wallet
     */
    std::string contract;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string underlying;
    std::string amount;
    Envelope envelope;
};


/**
 * A chain as the app's release pins it (spec §4).
 */
struct ChainProfile {
    /**
     * `scaas-testnet`, `<chain>-mainnet`, `<chain>-testnet`
     */
    std::string key;
    Family family;
    /**
     * EVM and Hedera
     */
    std::optional<uint64_t> chain_id;
    /**
     * `0x` + 64 hex (NET-ALL-24): every SCaaS EIP-712 domain's salt, pinned on every connection
     */
    std::string chain_uid;
    std::vector<EndpointConfig> rpc;
    Policy rpc_policy;
    /**
     * scaas-node gateways; empty: no gateway path on this chain
     */
    std::vector<EndpointConfig> gateways;
    std::optional<std::string> registry;
    std::optional<std::string> factory;
    std::optional<std::string> router;
    Finality finality;
    /**
     * the chain's per-transaction cap of the **regular** gas (EIP-7825 on a chain applying EIP-8037) when it has one, from
     * the release data: a quote's regular bound is held to it, its gas limit (regular + state) to the block gas limit. A
     * chain capping the whole gas limit (EIP-7825 without EIP-8037) is not supported (merged-tree review M19, 2026-11-20)
     */
    std::optional<uint64_t> tx_gas_cap;
    /**
     * the reviewed token list (spec §8.2): a token not on it is `unlisted` wherever it is shown
     */
    std::vector<ListedToken> tokens;
    /**
     * gas figures measured on this chain, shipped with its release data (owner 2026-11-19, gas-table rulings; spec §13.3);
     * first in every lookup, base and verify each on its own
     */
    GasRows gas;
    /**
     * the further gas tables this chain uses, by name, only because it names them here (explicit opt-in): module tables of
     * [`SdkConfig::gas_tables`] in this order, and `"reference"` for the SDK's forge-generated reference table, read after
     * every module table; a name the SDK does not hold is `Argument` at `Sdk::open`
     */
    std::vector<std::string> gas_opt_in;
    /**
     * the longest an operation's `validUntil` may lie ahead of the SDK's clock on this chain, in seconds; `None`:
     * `Limits::max_valid_secs` (default 86 400, one day) (owner 2026-11-19, T13b ruling 1)
     */
    std::optional<uint64_t> max_valid_secs;
    /**
     * the PQZ verifiers a verifier-mode token's verdict is asked of (spec §9.3): a list of endpoints with its own policy,
     * `failover` (the default) or `strict_majority` (ARCH-POS-15; owner 2026-11-19, T16-a), each with its own credential;
     * empty: no verdict on this chain (`VerdictRefused`)
     */
    std::vector<EndpointConfig> verifiers;
    Policy verifier_policy;
    /**
     * the SCaaS DEXes of the chain (NET-ALL-24): an order or a cancel naming a DEX not here is refused before anything is
     * signed (CLI-SGN-35, `DexNotListed`)
     */
    std::vector<ListedDex> dexes;
    /**
     * the reviewed wrapped tokens a `UAWrapOrder` may mint (`Expect::WrapOrder`'s list; `DexNotListed` for another)
     */
    std::vector<std::string> wrappers;
    /**
     * the family data a non-EVM read needs beyond the fields above (spec §8.7 rule 2), release data as the rest; `None` on a
     * family that needs none. Params of another family than `family`, or a field out of its form, are `Argument` at
     * `Sdk::open`
     */
    std::optional<FamilyParams> family_params;
    /**
     * the chain's L1 data fee model, added to a self-relay quote's `max_cost` (plan T38, spec §27.3): `OpStack` on Base, Celo
     * and OP (the node's `params.l1_fee = "op-stack"`); `None`: no L1 fee and no L1 read. EVM profiles only (`Argument` at
     * `Sdk::open` on another family)
     */
    std::optional<L1Fee> l1_fee;
    /**
     * the kinds this chain cannot carry, disabled by the owner (2026-11-22, ARCH-POS-18 confirmed: OP, Arbitrum, Base mainnet
     * and Celo, the kinds whose largest transaction is above the chain's limit): a UA kind by its name (`mldsa65`), the PQZ token and key
     * attachment as `pqz`; an operation signed by such a kind, a registration of it, a PQZ operation or attachment is
     * `KindDisabled` before anything is signed. A name the SDK does not know is `Argument` at `Sdk::open`
     */
    std::vector<std::string> disabled_kinds;
};


struct RevokeMandate {
    KeyRef signer;
    std::string chain;
    /**
     * the contract (`0x` + 40 hex): a token, or a mandate wallet
     */
    std::string contract;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string token;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetAuditorKey
 */
struct UaSetAuditorKey {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string new_key;
    std::string epoch;
    std::string pop;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAApproveDexRelease
 */
struct UaApproveDexRelease {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string version;
    std::string env_version;
    std::string initcode_hash;
    std::string impl_args_hash;
    std::string factory;
    std::string admin_generation;
    std::string until;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UARevokeOrder
 */
struct UaRevokeOrder {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string record_id;
    std::string reason_ref;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAPublishDexEnv
 */
struct UaPublishDexEnv {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string env_version;
    std::string env;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetMarket
 */
struct UaSetMarket {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string base;
    std::string quote;
    bool listed;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * `UARollOver`: roll `ua`'s pending balance over (`n`: the entries to take).
 */
struct ZetherRollOver {
    KeyRef signer;
    std::string chain;
    std::string token;
    std::string batch;
    std::string ua;
    std::string n;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAGrantRole
 */
struct UaGrantRole {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string bit;
    std::string account;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * `UAPqzUnshieldUnwrap` (`WRAPPED_PQZ`): `amount` out, unwrapped by leg `underlying` to `recipient`, at least `min_out`.
 */
struct PqzUnshieldUnwrap {
    KeyRef signer;
    std::string chain;
    std::string token;
    std::string batch;
    uint64_t key_version;
    std::string underlying;
    std::string recipient;
    std::string amount;
    std::string min_out;
    uint64_t valid_until_block;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetTokenKindEnabled
 */
struct UaSetTokenKindEnabled {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string kind;
    bool on;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * `UAPqzTransferSingle` / `UAPqzTransferSingleCompact`: `amount` from the holder's account (the UA key `signer`, PQZ key
 * version `key_version`) to `to_ua`, a registered PQZ holder; the proof valid until block `valid_until_block`.
 */
struct PqzTransfer {
    KeyRef signer;
    std::string chain;
    std::string token;
    std::string batch;
    uint64_t key_version;
    std::string to_ua;
    std::string amount;
    uint64_t valid_until_block;
    Envelope envelope;
};


struct SetPayee {
    KeyRef signer;
    std::string chain;
    /**
     * the contract (`0x` + 40 hex): a token, or a mandate wallet
     */
    std::string contract;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string token;
    std::string payee;
    bool allowed;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAPublishClassEnv
 */
struct UaPublishClassEnv {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string contract_class;
    std::string kind;
    std::string env_version;
    std::string env;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetTaxRate
 */
struct UaSetTaxRate {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string rate_ppm;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * The transfer on ids (`UAMetaTransfer`, entry `mtxExecuteTransfer`, `POST /v1/ua-metatx`; owner 2026-11-18, ruling 6): a plain
 * transfer, `entryRef = 0` on the lane `batch` the caller names, its nonce read, signed under `Expect::Transfer` (owner
 * 2026-11-19, ruling D): not recorded on chain as a payment, and a retry of the same request reads the same lane nonce.
 */
struct Transfer {
    KeyRef signer;
    std::string chain;
    std::string token;
    /**
     * the receiver's 32-byte id (a native address zero-padded, or a UA)
     */
    std::string to;
    std::string value;
    /**
     * the lane, decimal
     */
    std::string batch;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAApproveTokenRelease
 */
struct UaApproveTokenRelease {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string kind;
    std::string version;
    std::string env_version;
    std::string initcode_hash;
    std::string impl_args_hash;
    std::string factory;
    std::string admin_generation;
    std::string until;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UACreateToken
 */
struct UaCreateToken {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string kind;
    std::string version;
    std::string salt;
    std::string config;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UACreateDex
 */
struct UaCreateDex {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string version;
    std::string salt;
    std::string config;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UADeprecateRelease
 */
struct UaDeprecateRelease {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string contract_class;
    std::string kind;
    std::string version;
    std::string reason;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetWrapMember
 */
struct UaSetWrapMember {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string account;
    bool can_wrap;
    bool can_unwrap;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAUnpause
 */
struct UaUnpause {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string ref_id;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UACreateInstance
 */
struct UaCreateInstance {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string contract_class;
    std::string kind;
    std::string version;
    std::string salt;
    std::string init_call;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * `UAPqzUnshield`: `amount` out of the holder's account to `recipient` (a 32-byte id: a padded address or a registered UA).
 */
struct PqzUnshield {
    KeyRef signer;
    std::string chain;
    std::string token;
    std::string batch;
    uint64_t key_version;
    std::string recipient;
    std::string amount;
    uint64_t valid_until_block;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAAcceptAdmin
 */
struct UaAcceptAdmin {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAFreeze
 */
struct UaFreeze {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string account;
    std::string ref_id;
    std::string record_id;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UAMint
 */
struct UaMint {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string to;
    std::string amount;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UARecordOrder
 */
struct UaRecordOrder {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string order_id;
    std::string document_hash;
    std::string subject;
    std::string beneficiary;
    std::string max_amount;
    std::string freeze_until;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * `update_msig` (CTR-UA-44): the `msig` `ua` on `chain`'s registry becomes `structure` (every slot, the stored ones unchanged,
 * new members appended), `enabled` the slots that count, valid to block `valid_until_block`; signed by `slots` of the
 * **stored** structure, sent by `payer`.
 */
struct UpdateMsig {
    std::string chain;
    std::string ua;
    MsigStructureArgs structure;
    std::vector<uint16_t> enabled;
    uint64_t valid_until_block;
    std::vector<MsigSlot> slots;
    KeyRef payer;
    /**
     * the caller's facts for `plan_msig_update` (M4, owner 2026-11-19): a token names this `msig` as its PQZ verifier; the UA is
     * in use on a family with no `msig` update yet. Whether it holds a PQZ key is read (`pqzKeyAt(ua, 0)`).
     */
    bool verifier;
    bool family_without_update;
};


/**
 * `zether_wrap_shield` (`WrapShield` on a Zether token): wrap `amount_in` of `underlying` and shield it to `to_ua`.
 */
struct ZetherWrapShield {
    KeyRef signer;
    std::string chain;
    std::string token;
    std::string batch;
    std::string underlying;
    std::string amount_in;
    std::string to_ua;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UACancelNonce
 */
struct UaCancelNonce {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string lane;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
 * UASetGrant
 */
struct UaSetGrant {
    KeyRef signer;
    std::string chain;
    /**
     * the lane, decimal
     */
    std::string batch;
    std::string target;
    std::string bit;
    std::string holder;
    std::string terms;
    /**
     * the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
     */
    std::optional<std::string> chain_uid;
    Envelope envelope;
};


/**
 * A quote the user confirms (spec §13.3); `submit` takes exactly it. Amounts are decimal strings of wei.
 */
struct SubmitQuote {
    /**
     * `Gateway` or `SelfRelay`, never `Auto`
     */
    SubmitPath path;
    /**
     * the payer's address (a self-relay): linked on chain to the subject
     */
    std::optional<std::string> payer;
    /**
     * the self-relay transaction's gas limit (`gas`); 0 on the gateway path, where the holder sends no transaction
     */
    uint64_t gas_limit;
    /**
     * the bound of `gas_limit`'s regular part, with the margin (EIP-8037; controller call, owner auto-run 2026-11-19): the part
     * held to the profile's `tx_gas_cap` (EIP-7825 caps the regular gas only), the whole `gas_limit` where the split is not
     * known (a native send's estimate, an app's figure); 0 on the gateway path
     */
    uint64_t regular_gas;
    /**
     * what the operation costs in gas, with the margin, on every path (owner 2026-11-19): on a relayed path for the user and
     * the app only, to choose the token fee; it is not sent to the gateway. `None`: unquoted (no figure anywhere)
     */
    std::optional<uint64_t> gas;
    /**
     * where `gas` came from, its base part and its verify part each (owner 2026-11-19, part 3b): the chain's measured rows,
     * a module table, the reference table; the app's figure or a native send's estimate for both
     */
    std::optional<GasSources> gas_from;
    std::string max_fee_per_gas;
    std::string max_priority_fee_per_gas;
    std::string max_cost;
    /**
     * the operation's own fee to its relayer, as signed
     */
    std::string fee_to_relayer;
    /**
     * the gateways the body goes to, by index in the profile's list
     */
    std::vector<uint32_t> gateways;
    /**
     * the payer's transaction nonce
     */
    uint64_t tx_nonce;
    /**
     * a self-relay's EIP-2718 type: 2 where the chain's head has a base fee, else 0 (owner 2026-11-18, ruling 3)
     */
    uint8_t tx_type;
};


/**
 * A binding's configuration (spec §4): the profiles, the passkey RP ID, the limits, the module gas tables; the runtime is the
 * SDK's own (`RuntimeChoice::Own`) and the clock the device's. `expect_api` and `need_features` are the binding's load check
 * (spec §16.3): the `api_version` it was generated against and the feature bits it needs; the opening refuses another
 * library with `AbiMismatch`.
 */
struct BindingConfig {
    uint32_t expect_api;
    uint64_t need_features;
    std::vector<ChainProfile> profiles;
    std::optional<std::string> rp_id;
    Limits limits;
    std::vector<GasTable> gas_tables;
};


/**
 * A native send as the user reviews it: the transaction's fields and the quote; `submit_native_send` signs exactly these.
 */
struct NativeQuote {
    KeyRef key;
    std::string chain;
    std::string from;
    std::string to;
    std::string value;
    std::string data;
    SubmitQuote quote;
    /**
     * the sender's code is an EIP-7702 designator (`0xef0100…`, the account's delegation mark, T9): the send is the EOA's own
     * transaction and stays allowed; the app can warn (owner 2026-11-18, ruling 5)
     */
    bool delegated;
};


namespace uniffi {
    struct FfiConverterAccount;
} // namespace uniffi

/**
 * Accounts (spec §7).
 */
struct Account {
    friend uniffi::FfiConverterAccount;

    Account() = delete;

    Account(Account &&) = delete;

    Account &operator=(const Account &) = delete;
    Account &operator=(Account &&) = delete;

    ~Account();
    std::vector<AccountInfo> accounts_blocking(const std::string &seed, std::shared_ptr<CancelToken> cancel);
    AccountInfo add_native_blocking(const AddNative &req, std::shared_ptr<CancelToken> cancel);
    AccountInfo add_ua_blocking(const AddUa &req, std::shared_ptr<CancelToken> cancel);
    AccountInfo add_watch_blocking(const AddWatch &req, std::shared_ptr<CancelToken> cancel);
    KeyRef create_passkey_key_blocking(const CreatePasskeyKey &req, std::shared_ptr<CancelToken> cancel);
    KeyRef create_se_key_blocking(const CreateSeKey &req, std::shared_ptr<CancelToken> cancel);
    std::vector<AccountInfo> marks_blocking(const std::string &seed, const std::string &chain, std::shared_ptr<CancelToken> cancel);
    MsigState msig_state_blocking(const std::string &chain, const std::string &ua, std::shared_ptr<CancelToken> cancel);
    uint32_t next_account_blocking(const std::string &seed, std::shared_ptr<CancelToken> cancel);
    std::vector<std::string> pqz_decoy_candidates_blocking(const std::string &chain, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<RegistryWrite> prepare_accept_membership_blocking(const AcceptMembership &req, std::shared_ptr<CancelToken> cancel);
    NativeQuote prepare_complete_recovery_blocking(KeyRef key, const std::string &chain, const std::string &account, const SubjectKeyArgs &new_key, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_initiate_recovery_blocking(const SmartOp &op, const std::string &account, const SubjectKeyArgs &new_key, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<RegistryWrite> prepare_kem_repair_blocking(KeyRef key, const std::string &chain, KeyRef payer, std::shared_ptr<CancelToken> cancel);
    std::vector<std::shared_ptr<RegistryWrite>> prepare_msig_register_blocking(const MsigRegister &req, std::shared_ptr<CancelToken> cancel);
    std::vector<std::shared_ptr<RegistryWrite>> prepare_register_blocking(const Register &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_smart_add_key_blocking(const SmartOp &op, const SubjectKeyArgs &key, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_smart_cancel_nonce_blocking(const SmartOp &op, const std::string &lane, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_smart_cancel_recovery_blocking(const SmartOp &op, std::shared_ptr<CancelToken> cancel);
    NativeQuote prepare_smart_deploy_blocking(KeyRef key, const std::string &chain, const std::string &factory, const SubjectKeyArgs &first_key, const std::string &guardian, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_smart_execute_blocking(const SmartOp &op, SmartCall call, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_smart_remove_key_blocking(const SmartOp &op, const std::string &index, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_smart_rotate_key_blocking(const SmartOp &op, const std::string &index, const SubjectKeyArgs &key, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_smart_set_guardian_blocking(const SmartOp &op, const std::string &guardian, std::shared_ptr<CancelToken> cancel);
    std::vector<std::shared_ptr<RegistryWrite>> prepare_submit_registration_blocking(const RegistrationBlob &blob, const std::string &chain, const std::string &expected_ua, KeyRef payer, std::shared_ptr<CancelToken> cancel);
    MsigUpdatePlan prepare_update_msig_blocking(const UpdateMsig &req, std::shared_ptr<CancelToken> cancel);
    SubmitQuote quote_registry_write_blocking(const std::shared_ptr<RegistryWrite> &write, std::shared_ptr<CancelToken> cancel);
    std::string register_target_blocking(const std::string &chain, uint16_t kind, std::shared_ptr<CancelToken> cancel);
    RegistrationBlob registration_blob_blocking(KeyRef key, const RegisterAttrs &attrs, std::shared_ptr<CancelToken> cancel);
    RegistrationState registration_of_blocking(const std::string &chain, const std::string &ua, std::shared_ptr<CancelToken> cancel);
    std::vector<AccountInfo> restore_blocking(const Restore &req, std::shared_ptr<CancelToken> cancel);
    bool signs_blocking(const std::string &seed, const std::string &id, std::shared_ptr<CancelToken> cancel);
    std::string submit_registry_write_blocking(const std::shared_ptr<RegistryWrite> &write, const SubmitQuote &quote, std::shared_ptr<CancelToken> cancel);
    UaLine ua_line_blocking(const std::string &chain, const std::string &ua, std::shared_ptr<CancelToken> cancel);

    private:
    Account(const Account &);

    Account(uint64_t);

    uint64_t _uniffi_internal_clone_handle() const;

    uint64_t instance = 0;
};


namespace uniffi {
    struct FfiConverterAdmin;
} // namespace uniffi

/**
 * Governance and admin rows (spec §11).
 */
struct Admin {
    friend uniffi::FfiConverterAdmin;

    Admin() = delete;

    Admin(Admin &&) = delete;

    Admin &operator=(const Admin &) = delete;
    Admin &operator=(Admin &&) = delete;

    ~Admin();
    std::shared_ptr<Prepared> admin_ua_accept_admin_blocking(const UaAcceptAdmin &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_approve_dex_release_blocking(const UaApproveDexRelease &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_approve_release_blocking(const UaApproveRelease &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_approve_token_release_blocking(const UaApproveTokenRelease &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_cancel_grant_blocking(const UaCancelGrant &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_cancel_nonce_blocking(const UaCancelNonce &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_cancel_rate_blocking(const UaCancelRate &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_create_dex_blocking(const UaCreateDex &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_create_instance_blocking(const UaCreateInstance &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_create_token_blocking(const UaCreateToken &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_deprecate_dex_blocking(const UaDeprecateDex &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_deprecate_release_blocking(const UaDeprecateRelease &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_deprecate_token_blocking(const UaDeprecateToken &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_disable_feature_blocking(const UaDisableFeature &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_disable_wrap_blocking(const UaDisableWrap &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_enable_feature_blocking(const UaEnableFeature &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_execute_rate_blocking(const UaExecuteRate &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_force_transfer_blocking(const UaForceTransfer &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_freeze_blocking(const UaFreeze &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_grant_role_blocking(const UaGrantRole &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_mint_blocking(const UaMint &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_mint_to_ua_blocking(const UaMintToUa &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_operator_transfer_blocking(const UaOperatorTransfer &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_pause_blocking(const UaPause &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_pqz_cancel_verifier_blocking(const UaPqzCancelVerifier &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_pqz_revoke_verifier_blocking(const UaPqzRevokeVerifier &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_pqz_set_verifier_blocking(const UaPqzSetVerifier &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_propose_rate_blocking(const UaProposeRate &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_publish_class_env_blocking(const UaPublishClassEnv &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_publish_dex_env_blocking(const UaPublishDexEnv &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_publish_token_env_blocking(const UaPublishTokenEnv &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_record_order_blocking(const UaRecordOrder &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_renounce_admin_blocking(const UaRenounceAdmin &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_renounce_role_blocking(const UaRenounceRole &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_revoke_approval_blocking(const UaRevokeApproval &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_revoke_order_blocking(const UaRevokeOrder &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_revoke_role_blocking(const UaRevokeRole &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_allowed_blocking(const UaSetAllowed &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_auditor_key_blocking(const UaSetAuditorKey &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_auditor_ua_blocking(const UaSetAuditorUa &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_chain_entries_blocking(const UaSetChainEntries &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_class_kind_enabled_blocking(const UaSetClassKindEnabled &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_compliance_blocking(const UaSetCompliance &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_denied_blocking(const UaSetDenied &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_exchange_target_blocking(const UaSetExchangeTarget &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_fee_split_blocking(const UaSetFeeSplit &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_grant_blocking(const UaSetGrant &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_kyc_provider_blocking(const UaSetKycProvider &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_listed_only_blocking(const UaSetListedOnly &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_market_blocking(const UaSetMarket &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_max_supply_blocking(const UaSetMaxSupply &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_max_wrap_supply_blocking(const UaSetMaxWrapSupply &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_proof_store_blocking(const UaSetProofStore &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_tax_rate_blocking(const UaSetTaxRate &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_tax_recipient_blocking(const UaSetTaxRecipient &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_token_kind_enabled_blocking(const UaSetTokenKindEnabled &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_verifier_fee_blocking(const UaSetVerifierFee &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_wrap_limits_blocking(const UaSetWrapLimits &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_set_wrap_member_blocking(const UaSetWrapMember &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_transfer_admin_blocking(const UaTransferAdmin &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_unfreeze_blocking(const UaUnfreeze &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> admin_ua_unpause_blocking(const UaUnpause &req, std::shared_ptr<CancelToken> cancel);
    /**
     * A creation's CREATE3 addresses (`scaas-ua` `create3_address`).
     */
    Create3Preview create3_address(const std::string &factory, const std::string &creator_id, uint16_t contract_class, uint16_t kind, const std::string &salt);
    std::vector<DelaySentence> governance_delay_blocking(const std::string &chain, const std::string &token, uint16_t bit, std::optional<HolderKind> holder, std::shared_ptr<CancelToken> cancel);
    std::string sign_pqz_auditor_consent_blocking(const AuditorConsent &req, std::shared_ptr<CancelToken> cancel);
    SignedRescue sign_rescue_vault_blocking(const RescueVault &req, std::shared_ptr<CancelToken> cancel);
    std::string sign_zether_auditor_consent_blocking(const AuditorConsent &req, std::shared_ptr<CancelToken> cancel);

    private:
    Admin(const Admin &);

    Admin(uint64_t);

    uint64_t _uniffi_internal_clone_handle() const;

    uint64_t instance = 0;
};


namespace uniffi {
    struct FfiConverterCancelToken;
} // namespace uniffi

/**
 * A cancel token (spec §16.1): cancelled from another thread, the call returns `Cancelled` at once and its work goes on on
 * the SDK's runtime, the effect of a dropped future (spec §13.4).
 */
struct CancelToken {
    friend uniffi::FfiConverterCancelToken;

    CancelToken() = delete;

    CancelToken(CancelToken &&) = delete;

    CancelToken &operator=(const CancelToken &) = delete;
    CancelToken &operator=(CancelToken &&) = delete;

    ~CancelToken();
    static std::shared_ptr<CancelToken> init();
    void cancel();
    bool is_cancelled();

    private:
    CancelToken(const CancelToken &);

    CancelToken(uint64_t);

    uint64_t _uniffi_internal_clone_handle() const;

    uint64_t instance = 0;
};


namespace uniffi {
    struct FfiConverterConfidential;
} // namespace uniffi

/**
 * Zether and PQZ (spec §9).
 */
struct Confidential {
    friend uniffi::FfiConverterConfidential;

    Confidential() = delete;

    Confidential(Confidential &&) = delete;

    Confidential &operator=(const Confidential &) = delete;
    Confidential &operator=(Confidential &&) = delete;

    ~Confidential();
    PqzBalanceAll pqz_balance_all_blocking(const PqzBalanceRequest &r, std::shared_ptr<CancelToken> cancel);
    PqzBalance pqz_balance_blocking(const PqzBalanceRequest &r, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_pqz_prepare_acc_blocking(const PqzAccountOp &r, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_pqz_roll_over_blocking(const PqzAccountOp &r, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_pqz_shield_blocking(const PqzShield &r, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_pqz_transfer_blocking(const PqzTransfer &r, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_pqz_transfer_compact_blocking(const PqzTransfer &r, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_pqz_transfer_multi_blocking(const PqzTransferMulti &r, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_pqz_transfer_multi_compact_blocking(const PqzTransferMulti &r, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_pqz_unshield_blocking(const PqzUnshield &r, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_pqz_unshield_unwrap_blocking(const PqzUnshieldUnwrap &r, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_pqz_wrap_shield_blocking(const PqzWrapShield &r, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_zether_owner_roll_over_blocking(const ZetherOwnerRollOver &r, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_zether_owner_set_mode_blocking(const ZetherOwnerSetMode &r, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_zether_roll_over_batch_blocking(const ZetherRollOverBatch &r, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_zether_roll_over_blocking(const ZetherRollOver &r, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_zether_roll_over_signed_blocking(const ZetherOwnerRollOver &r, const OwnerRelay &relay, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_zether_set_roll_over_mode_blocking(const ZetherOwnerSetMode &r, const OwnerRelay &relay, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_zether_shield_blocking(const ZetherShield &r, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_zether_transfer_blocking(const ZetherTransfer &r, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_zether_transfer_compact_blocking(const ZetherTransferMulti &r, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_zether_transfer_multi_blocking(const ZetherTransferMulti &r, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_zether_unshield_blocking(const ZetherUnshield &r, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_zether_unshield_unwrap_blocking(const ZetherUnshieldUnwrap &r, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_zether_wrap_shield_blocking(const ZetherWrapShield &r, std::shared_ptr<CancelToken> cancel);
    Value request_verdict_blocking(const PqzVerdictRequest &r, std::shared_ptr<CancelToken> cancel);
    ZetherBalance zether_balance_blocking(const ZetherBalanceRequest &req, std::shared_ptr<CancelToken> cancel);
    ZetherKeyInfo zether_key_blocking(const std::string &seed, uint32_t account, std::shared_ptr<CancelToken> cancel);

    private:
    Confidential(const Confidential &);

    Confidential(uint64_t);

    uint64_t _uniffi_internal_clone_handle() const;

    uint64_t instance = 0;
};


namespace uniffi {
    struct FfiConverterDex;
} // namespace uniffi

/**
 * The DEX (spec §10).
 */
struct Dex {
    friend uniffi::FfiConverterDex;

    Dex() = delete;

    Dex(Dex &&) = delete;

    Dex &operator=(const Dex &) = delete;
    Dex &operator=(Dex &&) = delete;

    ~Dex();
    std::string cancel_all_blocking(const CancelAll &req, std::shared_ptr<CancelToken> cancel);
    std::string depth_blocking(const std::string &chain, int64_t market, std::optional<uint32_t> levels, std::shared_ptr<CancelToken> cancel);
    std::string markets_blocking(const std::string &chain, std::shared_ptr<CancelToken> cancel);
    std::string orders_blocking(const std::string &chain, const std::string &maker, std::shared_ptr<CancelToken> cancel);
    std::string place_blocking(const std::shared_ptr<PreparedOrder> &order, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_cancel_order_blocking(const CancelOrder &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_cancel_wrap_order_blocking(const CancelWrapOrder &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<PreparedOrder> prepare_liquidity_order_blocking(const LiquidityOrder &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<PreparedOrder> prepare_trade_order_blocking(const TradeOrder &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_wrap_order_blocking(const WrapOrder &req, std::shared_ptr<CancelToken> cancel);
    SignedOrder sign_order_blocking(const std::shared_ptr<PreparedOrder> &order, std::shared_ptr<CancelToken> cancel);
    std::string ticker_blocking(const std::string &chain, int64_t market, std::shared_ptr<CancelToken> cancel);
    std::string trades_blocking(const std::string &chain, int64_t market, std::shared_ptr<CancelToken> cancel);

    private:
    Dex(const Dex &);

    Dex(uint64_t);

    uint64_t _uniffi_internal_clone_handle() const;

    uint64_t instance = 0;
};


namespace uniffi {
    struct FfiConverterOp;
} // namespace uniffi

/**
 * Operations: quote, submit, follow (spec §13).
 */
struct Op {
    friend uniffi::FfiConverterOp;

    Op() = delete;

    Op(Op &&) = delete;

    Op &operator=(const Op &) = delete;
    Op &operator=(Op &&) = delete;

    ~Op();
    BlsMultiPart bls_multi_part_blocking(const std::shared_ptr<Prepared> &prepared, KeyRef member, std::shared_ptr<CancelToken> cancel);
    /**
     * Whether `part` is a valid partial of `prepared`'s group on it (`bls12381-multi`, spec §5.4).
     */
    bool bls_multi_part_ok(const std::shared_ptr<Prepared> &prepared, const BlsMultiPart &part);
    /**
     * Member `member`'s PoP part for its group's registration.
     */
    BlsMultiPart bls_multi_pop_part(KeyRef member);
    /**
     * Whether `part` is a valid PoP part of the group `key_data` (`0x` hex).
     */
    bool bls_multi_pop_part_ok(const std::string &key_data, const BlsMultiPart &part);
    SignedOpBlob hand_off_blocking(const std::shared_ptr<Prepared> &prepared, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> import_signed_blocking(const SignedOpBlob &blob, const ImportExpect &expect, std::shared_ptr<CancelToken> cancel);
    std::string member_sign_blocking(const std::shared_ptr<Prepared> &prepared, std::shared_ptr<CancelToken> cancel);
    SubmitQuote quote_blocking(const std::shared_ptr<Prepared> &prepared, SubmitPath path, std::shared_ptr<CancelToken> cancel);
    SubmitQuote quote_register_bls_multi_blocking(const std::string &chain, const std::string &key_data, KeyRef payer, std::shared_ptr<CancelToken> cancel);
    SubmitQuote quote_with_gas_blocking(const std::shared_ptr<Prepared> &prepared, SubmitPath path, uint64_t gas, std::shared_ptr<CancelToken> cancel);
    std::string register_bls_multi_blocking(const std::string &chain, const std::string &key_data, const std::vector<BlsMultiPart> &parts, const SubmitQuote &quote, std::shared_ptr<CancelToken> cancel);
    void resend_blocking(const std::string &op, const SubmitQuote &quote, std::shared_ptr<CancelToken> cancel);
    uint32_t resume_blocking(std::shared_ptr<CancelToken> cancel);
    OpState state_blocking(const std::string &op, std::shared_ptr<CancelToken> cancel);
    std::string submit_blocking(const std::shared_ptr<Prepared> &prepared, const SubmitQuote &quote, std::shared_ptr<CancelToken> cancel);
    std::string submit_bls_multi_blocking(const std::shared_ptr<Prepared> &prepared, const SubmitQuote &quote, const std::vector<BlsMultiPart> &parts, bool surplus, std::shared_ptr<CancelToken> cancel);

    private:
    Op(const Op &);

    Op(uint64_t);

    uint64_t _uniffi_internal_clone_handle() const;

    uint64_t instance = 0;
};


namespace uniffi {
    struct FfiConverterPrepared;
} // namespace uniffi

/**
 * A prepared operation (spec §13.1): opaque, kept in the SDK's table; it holds no secret and nothing signed.
 */
struct Prepared {
    friend uniffi::FfiConverterPrepared;

    Prepared() = delete;

    Prepared(Prepared &&) = delete;

    Prepared &operator=(const Prepared &) = delete;
    Prepared &operator=(Prepared &&) = delete;

    ~Prepared();
    std::string chain();
    /**
     * The contract function: `mtxPay`, `mtxCancelNonce`, …
     */
    std::string entry();
    /**
     * The operation's `validUntil` (`u64::MAX`: none).
     */
    uint64_t expires_at();
    /**
     * The typed digest, the node's in-flight key too.
     */
    std::string id();
    /**
     * An undecoded call under `AllowOpaqueCall` (§13.2).
     */
    bool opaque();
    std::vector<ReviewField> review();
    KeyRef signer();

    private:
    Prepared(const Prepared &);

    Prepared(uint64_t);

    uint64_t _uniffi_internal_clone_handle() const;

    uint64_t instance = 0;
};


namespace uniffi {
    struct FfiConverterPreparedOrder;
} // namespace uniffi

/**
 * An order prepared (a trade order or a liquidity order): opaque, holding nothing signed.
 */
struct PreparedOrder {
    friend uniffi::FfiConverterPreparedOrder;

    PreparedOrder() = delete;

    PreparedOrder(PreparedOrder &&) = delete;

    PreparedOrder &operator=(const PreparedOrder &) = delete;
    PreparedOrder &operator=(PreparedOrder &&) = delete;

    ~PreparedOrder();
    std::string chain();
    /**
     * The order's hash (its typed digest).
     */
    std::string id();
    std::vector<ReviewField> review();
    KeyRef signer();

    private:
    PreparedOrder(const PreparedOrder &);

    PreparedOrder(uint64_t);

    uint64_t _uniffi_internal_clone_handle() const;

    uint64_t instance = 0;
};


namespace uniffi {
    struct FfiConverterSdk;
} // namespace uniffi

/**
 * The SDK (spec §4): the module accessors, events, watching.
 */
struct Sdk {
    friend uniffi::FfiConverterSdk;

    Sdk() = delete;

    Sdk(Sdk &&) = delete;

    Sdk &operator=(const Sdk &) = delete;
    Sdk &operator=(Sdk &&) = delete;

    ~Sdk();
    /**
     * The account module (spec §7).
     */
    std::shared_ptr<Account> account();
    /**
     * The admin module (spec §11).
     */
    std::shared_ptr<Admin> admin();
    /**
     * The confidential module (spec §9).
     */
    std::shared_ptr<Confidential> confidential();
    /**
     * The DEX module (spec §10).
     */
    std::shared_ptr<Dex> dex();
    /**
     * The limits in force.
     */
    Limits limits();
    /**
     * The operations module (spec §13).
     */
    std::shared_ptr<Op> op();
    uint64_t state_rev_blocking(std::shared_ptr<CancelToken> cancel);
    /**
     * A subscription to the SDK's events (spec §14).
     */
    std::shared_ptr<Subscription> subscribe();
    /**
     * The seed module (spec §6).
     */
    std::shared_ptr<Vault> vault();
    /**
     * The wallet module (spec §8).
     */
    std::shared_ptr<Wallet> wallet();
    void watch_blocking(const std::string &account, const std::vector<std::string> &chains, std::shared_ptr<CancelToken> cancel);

    private:
    Sdk(const Sdk &);

    Sdk(uint64_t);

    uint64_t _uniffi_internal_clone_handle() const;

    uint64_t instance = 0;
};


namespace uniffi {
    struct FfiConverterSubscription;
} // namespace uniffi

/**
 * A subscription to the SDK's events (spec §14): a bounded queue, `Lagged { missed }` for a slow reader.
 */
struct Subscription {
    friend uniffi::FfiConverterSubscription;

    Subscription() = delete;

    Subscription(Subscription &&) = delete;

    Subscription &operator=(const Subscription &) = delete;
    Subscription &operator=(Subscription &&) = delete;

    ~Subscription();
    /**
     * The next event, or `None` within `timeout_ms` (blocks the calling thread; never a UI thread).
     */
    std::optional<Event> next_blocking(uint64_t timeout_ms);

    private:
    Subscription(const Subscription &);

    Subscription(uint64_t);

    uint64_t _uniffi_internal_clone_handle() const;

    uint64_t instance = 0;
};




/**
 * The app's authenticator (spec §6.10) as a sync foreign interface, called on a blocking thread; secret outputs through the
 * copy calls into the secret whose id it is given.
 */
struct SyncAuthenticator {
    virtual ~SyncAuthenticator() {}
    virtual PasskeyCreated create_passkey(const std::string &rp_id, const std::string &user_name, const std::vector<std::vector<uint8_t>> &exclude) = 0;
    virtual Assertion get_assertion(const AssertionRequest &req, uint64_t prf_out) = 0;
    /**
     * `key_handle`: the platform key's handle (named as in the async `ForeignAuthenticator`)
     */
    virtual void platform_secret(const std::string &key_handle, const std::vector<uint8_t> &salt, const std::string &reason, std::optional<KeyPolicy> policy, uint64_t out) = 0;
    virtual SePublic p256_generate(const KeyPolicy &policy) = 0;
    virtual std::vector<uint8_t> p256_sign(const std::string &key_handle, const std::vector<uint8_t> &ua_msg, const std::string &reason) = 0;
};

namespace uniffi {
    struct UniffiCallbackInterfaceSyncAuthenticator {
        static void uniffi_free(uint64_t uniffi_handle);
        static uint64_t uniffi_clone(uint64_t uniffi_handle);
        static void init();
        static void create_passkey(uint64_t uniffi_handle,RustBuffer rp_id,RustBuffer user_name,RustBuffer exclude,RustBuffer & uniffi_out_return,RustCallStatus *out_status);
        static void get_assertion(uint64_t uniffi_handle,RustBuffer req,uint64_t prf_out,RustBuffer & uniffi_out_return,RustCallStatus *out_status);
        static void platform_secret(uint64_t uniffi_handle,RustBuffer key_handle,RustBuffer salt,RustBuffer reason,RustBuffer policy,uint64_t out,void * uniffi_out_return,RustCallStatus *out_status);
        static void p256_generate(uint64_t uniffi_handle,RustBuffer policy,RustBuffer & uniffi_out_return,RustCallStatus *out_status);
        static void p256_sign(uint64_t uniffi_handle,RustBuffer key_handle,RustBuffer ua_msg,RustBuffer reason,RustBuffer & uniffi_out_return,RustCallStatus *out_status);

    private:
        static inline UniffiVTableCallbackInterfaceSyncAuthenticator vtable = UniffiVTableCallbackInterfaceSyncAuthenticator {
            .uniffi_free = reinterpret_cast<void *>(&uniffi_free),
            .uniffi_clone = reinterpret_cast<void *>(&uniffi_clone),
            .create_passkey = reinterpret_cast<void *>(&create_passkey),
            .get_assertion = reinterpret_cast<void *>(&get_assertion),
            .platform_secret = reinterpret_cast<void *>(&platform_secret),
            .p256_generate = reinterpret_cast<void *>(&p256_generate),
            .p256_sign = reinterpret_cast<void *>(&p256_sign),
        };
    };
}

namespace uniffi {
    struct FfiConverterSyncAuthenticator;
} // namespace uniffi

/**
 * The app's authenticator (spec §6.10) as a sync foreign interface, called on a blocking thread; secret outputs through the
 * copy calls into the secret whose id it is given.
 */
struct SyncAuthenticatorImpl : public SyncAuthenticator {
    friend uniffi::FfiConverterSyncAuthenticator;

    SyncAuthenticatorImpl() = delete;

    SyncAuthenticatorImpl(SyncAuthenticatorImpl &&) = delete;

    SyncAuthenticatorImpl &operator=(const SyncAuthenticatorImpl &) = delete;
    SyncAuthenticatorImpl &operator=(SyncAuthenticatorImpl &&) = delete;

    ~SyncAuthenticatorImpl();
    PasskeyCreated create_passkey(const std::string &rp_id, const std::string &user_name, const std::vector<std::vector<uint8_t>> &exclude);
    Assertion get_assertion(const AssertionRequest &req, uint64_t prf_out);
    /**
     * `key_handle`: the platform key's handle (named as in the async `ForeignAuthenticator`)
     */
    void platform_secret(const std::string &key_handle, const std::vector<uint8_t> &salt, const std::string &reason, std::optional<KeyPolicy> policy, uint64_t out);
    SePublic p256_generate(const KeyPolicy &policy);
    std::vector<uint8_t> p256_sign(const std::string &key_handle, const std::vector<uint8_t> &ua_msg, const std::string &reason);

    private:
    SyncAuthenticatorImpl(const SyncAuthenticatorImpl &);

    SyncAuthenticatorImpl(uint64_t);

    uint64_t _uniffi_internal_clone_handle() const;

    uint64_t instance = 0;
};




/**
 * The app's store (spec §6.9) as a sync foreign interface, called by the SDK on a blocking thread. `remove` is the store's
 * `delete` (a C++ keyword).
 */
struct SyncStore {
    virtual ~SyncStore() {}
    virtual std::optional<StoredItem> get(const std::string &name, const std::string &reason) = 0;
    virtual void put_if(const std::string &name, std::optional<uint64_t> prev_rev, const std::vector<uint8_t> &bytes, const StorePolicy &policy) = 0;
    virtual void remove(const std::string &name) = 0;
    virtual uint64_t lock(const std::string &name) = 0;
    virtual void unlock(uint64_t token) = 0;
};

namespace uniffi {
    struct UniffiCallbackInterfaceSyncStore {
        static void uniffi_free(uint64_t uniffi_handle);
        static uint64_t uniffi_clone(uint64_t uniffi_handle);
        static void init();
        static void get(uint64_t uniffi_handle,RustBuffer name,RustBuffer reason,RustBuffer & uniffi_out_return,RustCallStatus *out_status);
        static void put_if(uint64_t uniffi_handle,RustBuffer name,RustBuffer prev_rev,RustBuffer bytes,RustBuffer policy,void * uniffi_out_return,RustCallStatus *out_status);
        static void remove(uint64_t uniffi_handle,RustBuffer name,void * uniffi_out_return,RustCallStatus *out_status);
        static void lock(uint64_t uniffi_handle,RustBuffer name,uint64_t & uniffi_out_return,RustCallStatus *out_status);
        static void unlock(uint64_t uniffi_handle,uint64_t token,void * uniffi_out_return,RustCallStatus *out_status);

    private:
        static inline UniffiVTableCallbackInterfaceSyncStore vtable = UniffiVTableCallbackInterfaceSyncStore {
            .uniffi_free = reinterpret_cast<void *>(&uniffi_free),
            .uniffi_clone = reinterpret_cast<void *>(&uniffi_clone),
            .get = reinterpret_cast<void *>(&get),
            .put_if = reinterpret_cast<void *>(&put_if),
            .remove = reinterpret_cast<void *>(&remove),
            .lock = reinterpret_cast<void *>(&lock),
            .unlock = reinterpret_cast<void *>(&unlock),
        };
    };
}

namespace uniffi {
    struct FfiConverterSyncStore;
} // namespace uniffi

/**
 * The app's store (spec §6.9) as a sync foreign interface, called by the SDK on a blocking thread. `remove` is the store's
 * `delete` (a C++ keyword).
 */
struct SyncStoreImpl : public SyncStore {
    friend uniffi::FfiConverterSyncStore;

    SyncStoreImpl() = delete;

    SyncStoreImpl(SyncStoreImpl &&) = delete;

    SyncStoreImpl &operator=(const SyncStoreImpl &) = delete;
    SyncStoreImpl &operator=(SyncStoreImpl &&) = delete;

    ~SyncStoreImpl();
    std::optional<StoredItem> get(const std::string &name, const std::string &reason);
    void put_if(const std::string &name, std::optional<uint64_t> prev_rev, const std::vector<uint8_t> &bytes, const StorePolicy &policy);
    void remove(const std::string &name);
    uint64_t lock(const std::string &name);
    void unlock(uint64_t token);

    private:
    SyncStoreImpl(const SyncStoreImpl &);

    SyncStoreImpl(uint64_t);

    uint64_t _uniffi_internal_clone_handle() const;

    uint64_t instance = 0;
};


namespace uniffi {
    struct FfiConverterVault;
} // namespace uniffi

/**
 * Seeds (spec §6).
 */
struct Vault {
    friend uniffi::FfiConverterVault;

    Vault() = delete;

    Vault(Vault &&) = delete;

    Vault &operator=(const Vault &) = delete;
    Vault &operator=(Vault &&) = delete;

    ~Vault();
    void change_passphrase_blocking(const std::string &seed, const std::shared_ptr<SecretBytes> &old, const std::shared_ptr<SecretBytes> &new_, std::shared_ptr<CancelToken> cancel);
    void confirm_backup_blocking(const std::string &seed, std::shared_ptr<CancelToken> cancel);
    NewSeed derive_child_blocking(const DeriveChild &req, std::shared_ptr<CancelToken> cancel);
    NewSeed derive_from_key_blocking(const DeriveFromKey &req, std::shared_ptr<CancelToken> cancel);
    NewSeed derive_from_signature_blocking(const DeriveFromSignature &req, std::shared_ptr<CancelToken> cancel);
    void disable_prf_unlock_blocking(const std::string &seed, std::shared_ptr<CancelToken> cancel);
    void enable_passkey_unlock_blocking(const std::string &seed, const std::shared_ptr<SecretBytes> &vault_passphrase, std::shared_ptr<CancelToken> cancel);
    void enable_platform_unlock_blocking(const std::string &seed, const std::shared_ptr<SecretBytes> &vault_passphrase, const KeyPolicy &policy, std::shared_ptr<CancelToken> cancel);
    NewSeed generate_blocking(const Generate &req, std::shared_ptr<CancelToken> cancel);
    ImportedKey import_key_blocking(const ImportKey &req, std::shared_ptr<CancelToken> cancel);
    SeedInfo import_words_blocking(const ImportWords &req, std::shared_ptr<CancelToken> cancel);
    /**
     * Root (c)'s typed data for the account `account_hex` and set `set` (spec §6.6).
     */
    std::string key_derivation_typed_data(const std::string &account_hex, uint32_t set);
    bool keystore_rollback_blocking(std::shared_ptr<CancelToken> cancel);
    /**
     * Locks every seed (blocking twin of `lock_all`).
     */
    std::vector<std::string> lock_all_blocking();
    /**
     * Locks `seed` (blocking twin of `lock`; a failed call, such as one from a runtime thread, is `Internal`).
     */
    std::vector<std::string> lock_blocking(const std::string &seed);
    /**
     * The memory protection of an unlocked seed's arena.
     */
    MemoryProtection memory_protection(const std::string &seed);
    SessionSet open_hidden_blocking(const std::string &seed, Unlock unlock, const std::shared_ptr<SecretBytes> &bip39_passphrase, std::shared_ptr<CancelToken> cancel);
    void remove_blocking(const Remove &req, std::shared_ptr<CancelToken> cancel);
    void rename_blocking(const std::string &seed, const std::string &label, std::shared_ptr<CancelToken> cancel);
    SeedInfo seed_blocking(const std::string &seed, std::shared_ptr<CancelToken> cancel);
    std::vector<SeedInfo> seeds_blocking(std::shared_ptr<CancelToken> cancel);
    /**
     * A 65-byte signature from its compact form (a secret in, a secret out).
     */
    std::shared_ptr<SecretBytes> signature_from_compact(const std::shared_ptr<SecretBytes> &sig);
    void unlock_blocking(const std::string &seed, Unlock unlock, std::shared_ptr<CancelToken> cancel);
    /**
     * Whether a word (a secret) is on the BIP-39 list.
     */
    bool word_in_list(const std::shared_ptr<SecretBytes> &word);

    private:
    Vault(const Vault &);

    Vault(uint64_t);

    uint64_t _uniffi_internal_clone_handle() const;

    uint64_t instance = 0;
};


namespace uniffi {
    struct FfiConverterWallet;
} // namespace uniffi

/**
 * Tokens, balances, payments (spec §8).
 */
struct Wallet {
    friend uniffi::FfiConverterWallet;

    Wallet() = delete;

    Wallet(Wallet &&) = delete;

    Wallet &operator=(const Wallet &) = delete;
    Wallet &operator=(Wallet &&) = delete;

    ~Wallet();
    Balances balances_blocking(const std::string &id, const std::string &chain, std::shared_ptr<CancelToken> cancel);
    HistoryPage history_blocking(const std::string &account, const std::string &chain, std::optional<Cursor> before, uint32_t limit, std::shared_ptr<CancelToken> cancel);
    NativeAddress native_address_blocking(const NativeKeyRef &key, std::optional<uint16_t> ss58_prefix, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_add_reserve_blocking(const AddReserve &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_burn_blocking(const Burn &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_cancel_nonce_blocking(const CancelNonce &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_delegate_revoke_blocking(const DelegateRevoke &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_execute_blocking(const Execute &req, std::shared_ptr<CancelToken> cancel);
    NativeQuote prepare_native_send_blocking(const NativeSend &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_pay_blocking(const Pay &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_pay_under_mandate_blocking(const PayUnderMandate &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_pay_with_tax_blocking(const PayWithTax &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_payee_fee_blocking(const PayeeFee &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_relay_fee_blocking(const RelayFee &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_revoke_mandate_blocking(const RevokeMandate &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_set_mandate_blocking(const SetMandate &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_set_payee_blocking(const SetPayee &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_transfer_blocking(const Transfer &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_unwrap_blocking(const Unwrap &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_unwrap_leg_blocking(const UnwrapLeg &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_unwrap_to_ua_blocking(const UnwrapToUa &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_wrap_blocking(const Wrap &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_wrap_leg_blocking(const WrapLeg &req, std::shared_ptr<CancelToken> cancel);
    std::shared_ptr<Prepared> prepare_wrap_to_ua_blocking(const WrapToUa &req, std::shared_ptr<CancelToken> cancel);
    std::string submit_native_send_blocking(const NativeQuote &q, std::shared_ptr<CancelToken> cancel);
    std::vector<TokenInfo> tokens_blocking(const std::string &chain, bool with_index, std::shared_ptr<CancelToken> cancel);

    private:
    Wallet(const Wallet &);

    Wallet(uint64_t);

    uint64_t _uniffi_internal_clone_handle() const;

    uint64_t instance = 0;
};


/**
 * One account row as the app shows it.
 */
struct AccountInfo {
    std::string id;
    /**
     * The seed the row belongs to (R2).
     */
    std::string seed;
    std::string name;
    /**
     * `ua`, `native`, `key` or `watch`.
     */
    std::string shape;
    std::optional<uint16_t> kind;
    std::optional<uint32_t> account;
    std::optional<uint32_t> index;
    std::optional<std::string> network;
    /**
     * A UA row's or a key row's UA, a native row's address, a watch row's id.
     */
    std::string id_text;
    /**
     * The seed is unlocked and its index MAC verified at unlock (spec §6.2); a locked seed's rows are unverified.
     */
    bool verified;
    /**
     * An EVM row whose code is an EIP-7702 designator (`0xef0100…`), from [`Account::marks`]; the SDK builds no type-4
     * transaction, so it cannot offer to clear it (CLI-SDK-31).
     */
    bool delegated;
};


/**
 * `add_native`: the native key of `network` (a `scaas-ua` network name) at `index`.
 */
struct AddNative {
    std::string seed;
    std::string network;
    uint32_t index;
    std::string name;
};


/**
 * `add_ua`: the UA key `kind` of wallet `account` at `index`.
 */
struct AddUa {
    std::string seed;
    uint16_t kind;
    uint32_t account;
    uint32_t index;
    std::string name;
};


/**
 * `add_watch`: an id to watch (a `0x` 32-byte UA or a `0x` 20-byte address); no key.
 */
struct AddWatch {
    std::string seed;
    std::string watch;
    std::string name;
};


/**
 * A WebAuthn assertion as the platform returns it; `prf` says whether a PRF output was written.
 */
struct Assertion {
    std::vector<uint8_t> credential_id;
    std::vector<uint8_t> authenticator_data;
    std::vector<uint8_t> client_data_json;
    std::vector<uint8_t> signature;
    bool prf;
};


/**
 * A WebAuthn get-assertion request: the RP ID (the deployment's), a 32-byte challenge, the allowed credentials, the PRF salt.
 */
struct AssertionRequest {
    std::string rp_id;
    std::vector<uint8_t> challenge;
    std::vector<std::vector<uint8_t>> allow;
    std::optional<std::vector<uint8_t>> prf_salt;
};


/**
 * A member's part (spec §5.4, §4): its index in the group's key data and its partial `σ_i` (or PoP part `π_i`), 128 bytes,
 * `0x` hex.
 */
struct BlsMultiPart {
    uint8_t index;
    std::string signature;
};


/**
 * A creation's CREATE3 addresses (`scaas-ua` `create3_address`): the salt `s`, the proxy, the instance.
 */
struct Create3Preview {
    std::string s;
    std::string proxy;
    std::string instance;
};


/**
 * `create_passkey_key`: a new passkey of the deployment's RP ID (`SdkConfig::rp_id`), named `name` beside seed `seed`.
 */
struct CreatePasskeyKey {
    std::string seed;
    std::string name;
};


/**
 * An imported key's place: its network and its number `n` (the vault `native-import:<network>:<n>`).
 */
struct ImportedKey {
    std::string network;
    uint32_t index;
};


/**
 * A seed's memory protection (`scaas-ua`'s, its counts as `u64`).
 */
struct MemoryProtection {
    /**
     * the arena's chunks (16 KiB each)
     */
    uint64_t chunks;
    /**
     * chunks locked in RAM (`mlock`)
     */
    uint64_t locked;
    /**
     * chunks excluded from core dumps
     */
    uint64_t no_dump;
};


/**
 * A native key's public parts.
 */
struct NativeAddress {
    std::string network;
    /**
     * hex, no `0x`
     */
    std::string public_key;
    /**
     * as the network prints it; `None` for `ton` and `hedera_ed25519`
     */
    std::optional<std::string> address;
    /**
     * a Polkadot key's SS58 address at the prefix asked
     */
    std::optional<std::string> ss58;
    /**
     * a Bitcoin key's witness program: its version and program (hex, no `0x`)
     */
    std::optional<uint8_t> witness_version;
    std::optional<std::string> witness_program;
};


/**
 * A seed's native key by its derivation: `network` a `scaas-ua` name; Bitcoin's `change` chain (0 receive, 1 change); a
 * `coin_type` in place of the network's (Bitcoin 0 / 1, Stellar's Pi Network); Polkadot's junction `path` (`//hard/soft`).
 *
 * Without the feature `raw-native` the raw entry does not exist (spec §8.6: no build without it can reach it):
 * ```compile_fail
 * let _ = scaas_sdk::wallet::AllowRawNative::new();
 * ```
 */
struct NativeKeyRef {
    std::string seed;
    std::string network;
    uint32_t index;
    std::optional<uint32_t> change;
    std::optional<uint32_t> coin_type;
    std::optional<std::string> path;
};


/**
 * A new passkey: its credential id and its key data (`webauthn-p256` 0x0100).
 */
struct PasskeyCreated {
    std::vector<uint8_t> credential_id;
    std::vector<uint8_t> key_data;
};


/**
 * A registration as the registry holds it (`registration_of`).
 */
struct RegistrationState {
    bool registered;
    /**
     * the hash commit of the KEM key (`attrs.kemPkHash`, `0x` + 64 hex; all zero: none)
     */
    std::string kem_pk_hash;
    /**
     * the KEM key of version 0 is stored (a commit filled, or the full key given at `register`)
     */
    bool kem_stored;
    /**
     * the PQZ key of version 0 has its proof stored (`pqzPopOf`; owner 2026-11-19, S2)
     */
    bool pqz_pop_stored;
    /**
     * and a PoP verifier checked it (`pqzKeyAt(…).proven`; false on a chain with none)
     */
    bool pqz_proven;
};


/**
 * `restore`: seed `seed` on chain `chain` (a profile key): the UA keys `kinds` of wallet `account`, `gap` (at most 1024, the
 * usual 20) past the last registered index.
 */
struct Restore {
    std::string seed;
    std::string chain;
    std::vector<uint16_t> kinds;
    uint32_t account;
    uint32_t gap;
};


/**
 * A secure-element key's handle and public key data (`p256` 0x0101).
 */
struct SePublic {
    std::string handle;
    std::vector<uint8_t> key_data;
};


/**
 * A hidden set: its own session id, used in every reference to it; never written.
 */
struct SessionSet {
    std::string id;
};


/**
 * A signed order: its hash, the order as signed (named-field JSON) and its signature (a `UASig` JSON for a 32-byte `from`,
 * else `0x` hex).
 */
struct SignedOrder {
    std::string order_hash;
    std::string order;
    std::string signature;
};


/**
 * A signed rescue-vault operation: its typed digest and the admin's 65-byte signature, both `0x` hex.
 */
struct SignedRescue {
    std::string digest;
    std::string signature;
};


/**
 * An item and its revision (its JSON `rev`; `u64::MAX` when the bytes hold none, so no `put_if` matches it).
 */
struct StoredItem {
    std::vector<uint8_t> bytes;
    uint64_t rev;
};


/**
 * A token as the wallet shows it.
 */
struct TokenInfo {
    /**
     * `0x` + 40 hex, lower case
     */
    std::string address;
    std::string name;
    std::string symbol;
    uint8_t decimals;
    /**
     * on the profile's reviewed list
     */
    bool listed;
    /**
     * what a screen shows: the symbol, with `[unlisted]` before an unlisted one's
     */
    std::string display;
};


/**
 * Where a UA's record and its PQZ attachment live, as the bound registry's one walk answers (`holderOf`, §11.1).
 */
struct UaLine {
    /**
     * the generation holding the record (`0x` + 40 hex): the target of a key write, where its record is read
     */
    std::string holder;
    uint16_t kind;
    /**
     * the record's PQZ home (§11.2): the target of a PQZ write, where its attachment is read; `None`: no home on the walk
     */
    std::optional<std::string> pqz_home;
};


/**
 * A decrypted balance, for the holder only.
 */
struct ZetherBalance {
    /**
     * the smallest unit, decimal
     */
    std::string amount;
    /**
     * the final block the words were read at
     */
    uint64_t block;
    /**
     * the account's `accSeq` at that block (what a balance cache stores)
     */
    uint64_t acc_seq;
};


/**
 * A balance read (spec §9.4).
 */
struct ZetherBalanceRequest {
    std::string seed;
    uint32_t account;
    std::string chain;
    /**
     * the token, `0x` + 40 hex
     */
    std::string token;
    /**
     * the pending balance (received, not rolled over) instead of the spendable one
     */
    bool pending;
    /**
     * the BSGS table and bound bits (`None`: the facade's defaults for this target)
     */
    std::optional<uint32_t> table_bits;
    std::optional<uint32_t> bound_bits;
};


/**
 * A Zether key's public parts.
 */
struct ZetherKeyInfo {
    /**
     * the UA of kind `zether-bls12381` (0x0141), `0x` + 64 hex
     */
    std::string ua;
    /**
     * `Y = [x]G`, 128 bytes, `0x` hex
     */
    std::string y;
};


/**
 * The owner's roll-over (`ZetherRollOver`, its direct call `mtxRollOverSigned`; or with `relayed`, `UARollOverSigned`): every
 * pending entry up to the account's `pendingSeq` at the final block, signed by the Zether UA under `zether-owner` (owner
 * 2026-11-19, C3).
 */
struct ZetherOwnerRollOver {
    std::string seed;
    uint32_t account;
    std::string chain;
    std::string token;
    uint64_t valid_until_block;
};


/**
 * The owner's roll-over mode (`ZetherSetRollOverMode`; or `UASetRollOverMode`): `mode` 0 PUBLIC, 1 OWNER_ONLY.
 */
struct ZetherOwnerSetMode {
    std::string seed;
    uint32_t account;
    std::string chain;
    std::string token;
    uint8_t mode;
    uint64_t valid_until_block;
};

namespace uniffi {
struct FfiConverterAccountRow;
} // namespace uniffi

/**
 * An account row, by shape (spec §6.1), each with its fields in the written order.
 */
struct AccountRow {
    friend uniffi::FfiConverterAccountRow;
    struct kUa {
        std::string id;
        std::string name;
        uint64_t kind;
        uint64_t account;
        uint64_t index;
        std::string ua;
    };
    struct kNative {
        std::string id;
        std::string name;
        std::string network;
        uint64_t index;
        std::optional<uint64_t> coin_type;
        std::optional<uint64_t> change;
        std::optional<std::string> path;
        std::optional<uint64_t> ss58_prefix;
        std::string address;
    };
    struct kKey {
        std::string id;
        std::string name;
        uint64_t kind;
        std::string key_data;
        std::optional<std::string> credential_id;
        std::optional<std::string> handle;
        std::string ua;
    };
    struct kWatch {
        std::string id;
        std::string name;
        std::string watch;
    };
    AccountRow(kUa variant): variant(variant) {}
    AccountRow(kNative variant): variant(variant) {}
    AccountRow(kKey variant): variant(variant) {}
    AccountRow(kWatch variant): variant(variant) {}

    AccountRow(const AccountRow &other): variant(other.variant) {}
    AccountRow(AccountRow &&other): variant(std::move(other.variant)) {}

    AccountRow &operator=(const AccountRow &other) {
        variant = other.variant;
        return *this;
    }

    AccountRow &operator=(AccountRow &&other) {
        variant = std::move(other.variant);
        return *this;
    }

    /**
     * Returns the variant of this enum
     */
    const std::variant<kUa, kNative, kKey, kWatch> &get_variant() const {
        return variant;
    }

private:
    std::variant<kUa, kNative, kKey, kWatch> variant;

    AccountRow();
};

namespace uniffi {
struct FfiConverterAuthError;
} // namespace uniffi

/**
 * An authenticator's failure; `Unexpected` is a foreign exception inside the app's implementation.
 */
struct AuthError: std::runtime_error {
    friend uniffi::FfiConverterAuthError;

    AuthError() : std::runtime_error("") {}
    AuthError(const std::string &what_arg) : std::runtime_error(what_arg) {}

    virtual ~AuthError() = default;

    virtual void throw_underlying() {
        throw *this;
    }

    

protected:
    virtual int32_t get_variant_idx() const {
        return 0;
    };
};
/**
 * Contains variants of AuthError
 */
namespace auth_error {

struct Refused: AuthError {

    Refused() : AuthError("") {}
    Refused(const std::string &what_arg) : AuthError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 1;
    }
};

struct Cancelled: AuthError {

    Cancelled() : AuthError("") {}
    Cancelled(const std::string &what_arg) : AuthError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 2;
    }
};

struct Unavailable: AuthError {

    Unavailable() : AuthError("") {}
    Unavailable(const std::string &what_arg) : AuthError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 3;
    }
};

struct Unexpected: AuthError {

    Unexpected() : AuthError("") {}
    Unexpected(const std::string &what_arg) : AuthError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 4;
    }
};
} // namespace auth_error

namespace uniffi {
struct FfiConverterDelaySentence;
} // namespace uniffi

/**
 * One delay sentence of a power bit, by name.
 */
struct DelaySentence {
    friend uniffi::FfiConverterDelaySentence;
    /**
     * `atOnce`: the delay is 0, a holder's change applies at once
     */
    struct kAtOnce {
    };
    /**
     * the change applies after `delay` seconds, the longer of the factory's notice period and the token's grant delay
     */
    struct kAfter {
        uint64_t delay;
    };
    /**
     * `singleKey`: the holder is a single key
     */
    struct kSingleKey {
    };
    /**
     * `locked`: the bit is locked and the admin is gone; nobody can revoke its holders
     */
    struct kLocked {
    };
    /**
     * a bit of the table without delay sentences
     */
    struct kNoDelay {
    };
    /**
     * a bit the table does not know
     */
    struct kUnknown {
    };
    DelaySentence(kAtOnce variant): variant(variant) {}
    DelaySentence(kAfter variant): variant(variant) {}
    DelaySentence(kSingleKey variant): variant(variant) {}
    DelaySentence(kLocked variant): variant(variant) {}
    DelaySentence(kNoDelay variant): variant(variant) {}
    DelaySentence(kUnknown variant): variant(variant) {}

    DelaySentence(const DelaySentence &other): variant(other.variant) {}
    DelaySentence(DelaySentence &&other): variant(std::move(other.variant)) {}

    DelaySentence &operator=(const DelaySentence &other) {
        variant = other.variant;
        return *this;
    }

    DelaySentence &operator=(DelaySentence &&other) {
        variant = std::move(other.variant);
        return *this;
    }

    /**
     * Returns the variant of this enum
     */
    const std::variant<kAtOnce, kAfter, kSingleKey, kLocked, kNoDelay, kUnknown> &get_variant() const {
        return variant;
    }

private:
    std::variant<kAtOnce, kAfter, kSingleKey, kLocked, kNoDelay, kUnknown> variant;

    DelaySentence();
};


/**
 * The holder's kind as the app read it from the registry (`singleKey` is per holder: spec set-auditor §4).
 */
enum class HolderKind: int32_t {
    /**
     * a single key (one signer)
     */
    kSingleKey = 1,
    /**
     * a threshold (`msig`) UA
     */
    kThreshold = 2,
    /**
     * a native id with code
     */
    kContract = 3
};

namespace uniffi {
struct FfiConverterSdkError;
} // namespace uniffi

/**
 * An SDK error. `Display` is the code; no variant carries an input, a URL, a body, a key or a ciphertext.
 */
struct SdkError: std::runtime_error {
    friend uniffi::FfiConverterSdkError;

    SdkError() : std::runtime_error("") {}
    SdkError(const std::string &what_arg) : std::runtime_error(what_arg) {}

    virtual ~SdkError() = default;

    virtual void throw_underlying() {
        throw *this;
    }

    

protected:
    virtual int32_t get_variant_idx() const {
        return 0;
    };
};
/**
 * Contains variants of SdkError
 */
namespace sdk_error {

/**
 * A malformed input or configuration (the meaning `scaas-ua` and `scaas-rpc` give the same name).
 */
struct Argument: SdkError {

    Argument() : SdkError("") {}
    Argument(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 1;
    }
};

/**
 * The keystore's `format` or `v` is not `scaas.keystore` / 1 (the meaning of `scaas-ua`'s vault `VaultVersion`).
 */
struct VaultVersion: SdkError {

    VaultVersion() : SdkError("") {}
    VaultVersion(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 2;
    }
};

struct VaultFormat: SdkError {

    VaultFormat() : SdkError("") {}
    VaultFormat(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 3;
    }
};

struct VaultIo: SdkError {

    VaultIo() : SdkError("") {}
    VaultIo(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 4;
    }
};

struct StoreConflict: SdkError {

    StoreConflict() : SdkError("") {}
    StoreConflict(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 5;
    }
};

struct KeystoreMismatch: SdkError {

    KeystoreMismatch() : SdkError("") {}
    KeystoreMismatch(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 6;
    }
};

struct KeystoreRollback: SdkError {

    KeystoreRollback() : SdkError("") {}
    KeystoreRollback(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 7;
    }
};

struct AccountUnverified: SdkError {

    AccountUnverified() : SdkError("") {}
    AccountUnverified(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 8;
    }
};

struct SeedUnknown: SdkError {

    SeedUnknown() : SdkError("") {}
    SeedUnknown(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 9;
    }
};

struct SeedExists: SdkError {

    SeedExists() : SdkError("") {}
    SeedExists(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 10;
    }
};

struct LabelTaken: SdkError {

    LabelTaken() : SdkError("") {}
    LabelTaken(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 11;
    }
};

struct ConfirmationMissing: SdkError {

    ConfirmationMissing() : SdkError("") {}
    ConfirmationMissing(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 12;
    }
};

struct MnemonicInvalid: SdkError {

    MnemonicInvalid() : SdkError("") {}
    MnemonicInvalid(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 13;
    }
};

struct VaultPassphraseWeak: SdkError {

    VaultPassphraseWeak() : SdkError("") {}
    VaultPassphraseWeak(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 14;
    }
};

struct DerivationPassphraseShort: SdkError {

    DerivationPassphraseShort() : SdkError("") {}
    DerivationPassphraseShort(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 15;
    }
};

struct OriginSignature: SdkError {

    OriginSignature() : SdkError("") {}
    OriginSignature(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 16;
    }
};

struct AuthenticatorRefused: SdkError {

    AuthenticatorRefused() : SdkError("") {}
    AuthenticatorRefused(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 17;
    }
};

struct ChainUnknown: SdkError {

    ChainUnknown() : SdkError("") {}
    ChainUnknown(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 18;
    }
};

struct ProfileMismatch: SdkError {

    ProfileMismatch() : SdkError("") {}
    ProfileMismatch(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 19;
    }
};

struct FeatureMissing: SdkError {

    FeatureMissing() : SdkError("") {}
    FeatureMissing(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 20;
    }
};

struct PreparedStale: SdkError {

    PreparedStale() : SdkError("") {}
    PreparedStale(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 21;
    }
};

struct PreparedUnknown: SdkError {

    PreparedUnknown() : SdkError("") {}
    PreparedUnknown(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 22;
    }
};

struct OpaqueCallRefused: SdkError {

    OpaqueCallRefused() : SdkError("") {}
    OpaqueCallRefused(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 23;
    }
};

struct FeeAboveCap: SdkError {

    FeeAboveCap() : SdkError("") {}
    FeeAboveCap(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 24;
    }
};

struct GasAboveTxCap: SdkError {

    GasAboveTxCap() : SdkError("") {}
    GasAboveTxCap(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 25;
    }
};

struct PayerDelegated: SdkError {

    PayerDelegated() : SdkError("") {}
    PayerDelegated(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 26;
    }
};

struct SubmitPathNone: SdkError {

    SubmitPathNone() : SdkError("") {}
    SubmitPathNone(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 27;
    }
};

struct VerdictRefused: SdkError {

    VerdictRefused() : SdkError("") {}
    VerdictRefused(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 28;
    }
};

struct TxTypeRefused: SdkError {

    TxTypeRefused() : SdkError("") {}
    TxTypeRefused(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 29;
    }
};

struct KindDisabled: SdkError {

    KindDisabled() : SdkError("") {}
    KindDisabled(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 30;
    }
};

struct RawDigestRefused: SdkError {

    RawDigestRefused() : SdkError("") {}
    RawDigestRefused(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 31;
    }
};

struct AppDomainRefused: SdkError {

    AppDomainRefused() : SdkError("") {}
    AppDomainRefused(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 32;
    }
};

struct AppPurposeRefused: SdkError {

    AppPurposeRefused() : SdkError("") {}
    AppPurposeRefused(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 33;
    }
};

struct AppSaltMismatch: SdkError {

    AppSaltMismatch() : SdkError("") {}
    AppSaltMismatch(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 34;
    }
};

struct AppHandleForeign: SdkError {

    AppHandleForeign() : SdkError("") {}
    AppHandleForeign(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 35;
    }
};

struct AppLabelRefused: SdkError {

    AppLabelRefused() : SdkError("") {}
    AppLabelRefused(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 36;
    }
};

struct AppKeyUsage: SdkError {

    AppKeyUsage() : SdkError("") {}
    AppKeyUsage(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 37;
    }
};

struct AppArenaFull: SdkError {

    AppArenaFull() : SdkError("") {}
    AppArenaFull(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 38;
    }
};

struct KemKeyGone: SdkError {

    KemKeyGone() : SdkError("") {}
    KemKeyGone(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 39;
    }
};

struct ReceiverUnregistered: SdkError {

    ReceiverUnregistered() : SdkError("") {}
    ReceiverUnregistered(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 40;
    }
};

struct RegistrationUaMismatch: SdkError {

    RegistrationUaMismatch() : SdkError("") {}
    RegistrationUaMismatch(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 41;
    }
};

struct RegistrationKindDisabled: SdkError {

    RegistrationKindDisabled() : SdkError("") {}
    RegistrationKindDisabled(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 42;
    }
};

struct RegistrationPopInvalid: SdkError {

    RegistrationPopInvalid() : SdkError("") {}
    RegistrationPopInvalid(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 43;
    }
};

struct RegistrationKemMissing: SdkError {

    RegistrationKemMissing() : SdkError("") {}
    RegistrationKemMissing(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 44;
    }
};

struct AbiMismatch: SdkError {

    AbiMismatch() : SdkError("") {}
    AbiMismatch(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 45;
    }
};

/**
 * No better name (a failed task included); carries nothing.
 */
struct Internal: SdkError {

    Internal() : SdkError("") {}
    Internal(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 46;
    }
};

/**
 * An account row whose key (the same UA, native key or watched id) the seed lists already (owner 2026-11-18, Q1).
 */
struct AccountExists: SdkError {

    AccountExists() : SdkError("") {}
    AccountExists(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 47;
    }
};

/**
 * A relayed operation's quote found no row of the gas table for its key (entry, domain kind, signer kind, fresh lane;
 * owner 2026-11-18, ruling 1; owner 2026-11-19, ruling B).
 */
struct GasUnquoted: SdkError {

    GasUnquoted() : SdkError("") {}
    GasUnquoted(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 48;
    }
};

/**
 * An operation's `validUntil` already past on the SDK's clock, or further ahead than the chain's window (owner 2026-11-19,
 * T13b ruling 1).
 */
struct ValidUntilRefused: SdkError {

    ValidUntilRefused() : SdkError("") {}
    ValidUntilRefused(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 49;
    }
};

/**
 * A confidential token the profile's factory does not catalogue as a token of the family, or whose code is not the
 * factory's clone (spec §9.4 R5; owner 2026-11-19, C4).
 */
struct TokenUncatalogued: SdkError {

    TokenUncatalogued() : SdkError("") {}
    TokenUncatalogued(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 50;
    }
};

/**
 * A UA whose registry record does not hold the key the read expects: the holder's leg not the handle's key, or a recipient's
 * record not its UA's key (spec §9.4 R6; owner 2026-11-19, C4).
 */
struct LegKeyMismatch: SdkError {

    LegKeyMismatch() : SdkError("") {}
    LegKeyMismatch(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 51;
    }
};

/**
 * A `SmartKeyAccount` entry's signer that is not a key of the account (owner 2026-11-19, P2).
 */
struct SignerNotAccountKey: SdkError {

    SignerNotAccountKey() : SdkError("") {}
    SignerNotAccountKey(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 52;
    }
};

/**
 * A PQZ token with the sealed opening (`proofSystemId` `PQZL_SPLIT_ID`, CTR-PQZ-38): its keys and debits are the `pqz3k`
 * handles', not built in the SDK yet (P-T16-4, controller call 2026-11-19).
 */
struct PqzOpeningUnsupported: SdkError {

    PqzOpeningUnsupported() : SdkError("") {}
    PqzOpeningUnsupported(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 53;
    }
};

/**
 * An `msig` slot (or an inner leaf) that is not both enabled and accepted: it cannot sign (spec §15; M2, owner 2026-11-19).
 */
struct MsigSlotInactive: SdkError {

    MsigSlotInactive() : SdkError("") {}
    MsigSlotInactive(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 54;
    }
};

/**
 * A gas table's verify row without `sig_bytes` (owner 2026-11-19, A4): every verify row states its signature's length.
 */
struct GasSigBytesMissing: SdkError {

    GasSigBytesMissing() : SdkError("") {}
    GasSigBytesMissing(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 55;
    }
};

/**
 * A self-relay whose gas, recomputed after signing from the signed calldata (the real signature's length; owner
 * 2026-11-19, G3), exceeds `Limits::max_gas`: nothing written or sent.
 */
struct SignedGasAboveCap: SdkError {

    SignedGasAboveCap() : SdkError("") {}
    SignedGasAboveCap(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 56;
    }
};

/**
 * A gas table's row with `per_item` but no `item`, or the reverse (owner 2026-11-19, I1).
 */
struct GasItemUnpaired: SdkError {

    GasItemUnpaired() : SdkError("") {}
    GasItemUnpaired(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 57;
    }
};

/**
 * A gas table's row whose `item` names no count the SDK reads (owner 2026-11-19, I1).
 */
struct GasItemUnknown: SdkError {

    GasItemUnknown() : SdkError("") {}
    GasItemUnknown(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 58;
    }
};

/**
 * An operation whose gas row grows with a count (`per_item`) that the SDK cannot read from the operation, or above
 * 65,536 (owner 2026-11-19, I1): refused, never quoted without it.
 */
struct GasCountUnknown: SdkError {

    GasCountUnknown() : SdkError("") {}
    GasCountUnknown(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 59;
    }
};

/**
 * bls12381-multi (plan Task 17): the valid partials' weight is below the group's threshold
 */
struct BlsMultiBelowThreshold: SdkError {

    BlsMultiBelowThreshold() : SdkError("") {}
    BlsMultiBelowThreshold(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 60;
    }
};

/**
 * A gas table with a key outside the format, at the top, on a row or inside a row's part (PR A review, finding 1): an
 * unknown part is refused, never dropped from a quote.
 */
struct GasFieldUnknown: SdkError {

    GasFieldUnknown() : SdkError("") {}
    GasFieldUnknown(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 61;
    }
};

/**
 * A registration of a kind whose home (`kindHome(kind)`) is another generation than the bound registry: that registry
 * carries it verify-only, or not at all (spec 2026-11-19-registry-verify-only-kinds §12, CTR-UA-65); nothing is sent.
 */
struct RegistrationVerifyOnly: SdkError {

    RegistrationVerifyOnly() : SdkError("") {}
    RegistrationVerifyOnly(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 62;
    }
};

/**
 * A UA no generation of the bound registry's line holds (`holderOf(ua)` answers no holder, §11.1).
 */
struct UaUnregistered: SdkError {

    UaUnregistered() : SdkError("") {}
    UaUnregistered(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 63;
    }
};

/**
 * A PQZ write or read of a UA whose record has no PQZ home on the bound registry's walk (`pqzHomeOf(ua)` 0, §11.2).
 */
struct PqzHomeNone: SdkError {

    PqzHomeNone() : SdkError("") {}
    PqzHomeNone(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 64;
    }
};

/**
 * An order, a cancel or a liquidity order naming a DEX that is not on the chain profile's list, or a wrap order whose
 * wrapped token is not on its wrapper list (CLI-SGN-35): refused before anything is signed (plan T17).
 */
struct DexNotListed: SdkError {

    DexNotListed() : SdkError("") {}
    DexNotListed(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 65;
    }
};

/**
 * A PQZ auditor consent whose auditor is a native (address) key (controller call, owner auto-run 2026-11-19): a native id
 * holds no PQZ key (CTR-UA-32), so the token refuses it on chain anyway; refused before anything is read or signed.
 */
struct PqzAuditorNative: SdkError {

    PqzAuditorNative() : SdkError("") {}
    PqzAuditorNative(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 66;
    }
};

/**
 * A registration step whose gas (regular + state) is above half the chain's block gas limit (owner 2026-11-20): a
 * registration carrying its PQZ key's proof above it goes in two steps, and a step above it alone is refused, nothing
 * sent.
 */
struct GasAboveBlockShare: SdkError {

    GasAboveBlockShare() : SdkError("") {}
    GasAboveBlockShare(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 67;
    }
};

/**
 * An imported operation (spec §27.5 (c), owner 2026-11-22, Q-R3) of a kind the importer's family cannot show and check
 * before sending, a confidential one (Zether, PQZ), or a struct or entry the family's rows do not hold.
 */
struct ImportKindRefused: SdkError {

    ImportKindRefused() : SdkError("") {}
    ImportKindRefused(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 68;
    }
};

/**
 * An imported pay or transfer whose `to` is none of the importer's ids.
 */
struct ImportNotPayee: SdkError {

    ImportNotPayee() : SdkError("") {}
    ImportNotPayee(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 69;
    }
};

/**
 * An imported operation whose signed `relayer` is bound to another address than the importer's payer (Soroban binds none).
 */
struct ImportRelayerBound: SdkError {

    ImportRelayerBound() : SdkError("") {}
    ImportRelayerBound(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 70;
    }
};

/**
 * An imported operation with a fee to anyone: a hand-off is fee 0 (spec §27.5 (b)).
 */
struct ImportFeeRefused: SdkError {

    ImportFeeRefused() : SdkError("") {}
    ImportFeeRefused(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 71;
    }
};

/**
 * An imported operation valid for less than the node's 120 s: its `validUntil` on the chain's clock (EVM, a Soroban
 * pay), or its auth entry's expiry ledger (Soroban, a ledger at most each second).
 */
struct ImportExpired: SdkError {

    ImportExpired() : SdkError("") {}
    ImportExpired(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 72;
    }
};

/**
 * An imported operation already spent at the final height: its lane nonce (EVM), its host nonce or `pay_ref` entry
 * (Soroban); it landed, or another operation took the nonce.
 */
struct ImportConsumed: SdkError {

    ImportConsumed() : SdkError("") {}
    ImportConsumed(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 73;
    }
};

/**
 * An imported operation the simulation from the payer refused: the chain's judgement of the signature and the effect.
 */
struct ImportedOpRefused: SdkError {

    ImportedOpRefused() : SdkError("") {}
    ImportedOpRefused(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 74;
    }
};

/**
 * An Arweave upload above the free tier, or refused there, with no payer: none configured, or the operator's node payer
 * off (NODE-SPN-05; CLI-SDK-21).
 */
struct PayerUnavailable: SdkError {

    PayerUnavailable() : SdkError("") {}
    PayerUnavailable(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 75;
    }
};

/**
 * An Arweave upload the bundler refused for payment (HTTP 402): the user's own credits, or a payer's approval, are missing.
 */
struct PaymentRequired: SdkError {

    PaymentRequired() : SdkError("") {}
    PaymentRequired(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 76;
    }
};

/**
 * An Arweave upload no bundler accepted, for a reason other than payment.
 */
struct UploadRejected: SdkError {

    UploadRejected() : SdkError("") {}
    UploadRejected(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 77;
    }
};

/**
 * A kept Arweave upload still unsettled after its last re-post (C20): shown; the bytes stay kept.
 */
struct UploadUnsettled: SdkError {

    UploadUnsettled() : SdkError("") {}
    UploadUnsettled(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 78;
    }
};

/**
 * A data item that is not one `scaas-ua` built: its verifying parser refused it, or it carries a target, an anchor or a
 * tag, or its object is no bucket's (CLI-UAL-64): `scaas-ua`'s code for an item it built.
 */
struct ArweaveItem: SdkError {

    ArweaveItem() : SdkError("") {}
    ArweaveItem(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 79;
    }
};

/**
 * A file or object above the platform's cap or the store's largest object (CLI-UAL-65): `scaas-ua`'s code.
 */
struct FileTooLarge: SdkError {

    FileTooLarge() : SdkError("") {}
    FileTooLarge(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 80;
    }
};

/**
 * A file object or plaintext whose SHA-256 is not the signed one (CLI-UAL-65): `scaas-ua`'s code.
 */
struct FileHashMismatch: SdkError {

    FileHashMismatch() : SdkError("") {}
    FileHashMismatch(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 81;
    }
};

/**
 * a `*_blocking` call whose cancel token fired (spec §16.1, feature `sync-api`); the work goes on as a dropped future
 */
struct Cancelled: SdkError {

    Cancelled() : SdkError("") {}
    Cancelled(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 82;
    }
};

/**
 * A `scaas-ua` wallet error, by its own code.
 */
struct Ua: SdkError {

    Ua() : SdkError("") {}
    Ua(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 83;
    }
};

/**
 * A `scaas-rpc` error, by its own code (its text redacted by `scaas-rpc`, CLI-RPC-11).
 */
struct Rpc: SdkError {

    Rpc() : SdkError("") {}
    Rpc(const std::string &what_arg) : SdkError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 84;
    }
};
} // namespace sdk_error

namespace uniffi {
struct FfiConverterStoreError;
} // namespace uniffi

/**
 * A store's failure; `Unexpected` is a foreign exception inside an app's implementation.
 */
struct StoreError: std::runtime_error {
    friend uniffi::FfiConverterStoreError;

    StoreError() : std::runtime_error("") {}
    StoreError(const std::string &what_arg) : std::runtime_error(what_arg) {}

    virtual ~StoreError() = default;

    virtual void throw_underlying() {
        throw *this;
    }

    

protected:
    virtual int32_t get_variant_idx() const {
        return 0;
    };
};
/**
 * Contains variants of StoreError
 */
namespace store_error {

/**
 * `put_if`: the stored revision is not the expected one
 */
struct Conflict: StoreError {

    Conflict() : StoreError("") {}
    Conflict(const std::string &what_arg) : StoreError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 1;
    }
};

struct Io: StoreError {

    Io() : StoreError("") {}
    Io(const std::string &what_arg) : StoreError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 2;
    }
};

struct Unavailable: StoreError {

    Unavailable() : StoreError("") {}
    Unavailable(const std::string &what_arg) : StoreError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 3;
    }
};

struct Unexpected: StoreError {

    Unexpected() : StoreError("") {}
    Unexpected(const std::string &what_arg) : StoreError(what_arg) {}

    void throw_underlying() override {
        throw *this;
    }

protected:
    int32_t get_variant_idx() const override {
        return 4;
    }
};
} // namespace store_error

namespace uniffi {
using ::uniffi::RustStream;
using ::uniffi::RustStreamBuffer;

RustBuffer rustbuffer_alloc(uint64_t);
RustBuffer rustbuffer_from_bytes(const ForeignBytes &);
void rustbuffer_free(RustBuffer);template <typename T> struct HandleMap {
    HandleMap() = default;

    std::shared_ptr<T> at(uint64_t handle) {
        std::lock_guard<std::mutex> guard(this->mutex);

        return this->map.at(handle);
    }

    uint64_t insert(std::shared_ptr<T> impl) {
        std::lock_guard<std::mutex> guard(this->mutex);

        return this->insert_locked(impl);
    }

    uint64_t clone(uint64_t handle) {
        std::lock_guard<std::mutex> guard(this->mutex);

        return this->insert_locked(this->map.at(handle));
    }

    void erase(uint64_t handle) {
        // We store the object here to avoid re-entrant locking
        std::shared_ptr<T> cleanup;
        {
            std::lock_guard<std::mutex> guard(this->mutex);
            auto it = this->map.find(handle);
            if (it != this->map.end()) {
                cleanup = it->second;
                this->map.erase(it);
            }
        }
    }

    private:
        HandleMap(const HandleMap<T> &) = delete;
        HandleMap(HandleMap<T> &&) = delete;

        HandleMap<T> &operator=(const HandleMap<T> &) = delete;
        HandleMap<T> &operator=(HandleMap<T> &&) = delete;

        std::mutex mutex;
        /// Rust handles are generated by leaking a raw pointer.
        /// Foreign handles are generated with a handle map that only generates odd values.
        /// * 0 is an invalid value.
        /// * The lowest bit will always be set for foreign handles and never set for Rust ones
        uint64_t cur_handle = 1;
        std::map<uint64_t, std::shared_ptr<T>> map;


        uint64_t insert_locked(std::shared_ptr<T> impl) {
            auto handle = this->cur_handle;

            this->map.insert({ handle, impl });
            this->cur_handle += 2;

            return handle;
        }
};
struct FfiConverterUInt8 {
    static uint8_t lift(uint8_t);
    static uint8_t lower(uint8_t);
    static uint8_t read(RustStream &);
    static void write(RustStream &, uint8_t);
    static uint64_t allocation_size(uint8_t);
};
struct FfiConverterUInt16 {
    static uint16_t lift(uint16_t);
    static uint16_t lower(uint16_t);
    static uint16_t read(RustStream &);
    static void write(RustStream &, uint16_t);
    static uint64_t allocation_size(uint16_t);
};
struct FfiConverterUInt32 {
    static uint32_t lift(uint32_t);
    static uint32_t lower(uint32_t);
    static uint32_t read(RustStream &);
    static void write(RustStream &, uint32_t);
    static uint64_t allocation_size(uint32_t);
};
struct FfiConverterInt32 {
    static int32_t lift(int32_t);
    static int32_t lower(int32_t);
    static int32_t read(RustStream &);
    static void write(RustStream &, int32_t);
    static uint64_t allocation_size(int32_t);
};
struct FfiConverterUInt64 {
    static uint64_t lift(uint64_t);
    static uint64_t lower(uint64_t);
    static uint64_t read(RustStream &);
    static void write(RustStream &, uint64_t);
    static uint64_t allocation_size(uint64_t);
};
struct FfiConverterInt64 {
    static int64_t lift(int64_t);
    static int64_t lower(int64_t);
    static int64_t read(RustStream &);
    static void write(RustStream &, int64_t);
    static uint64_t allocation_size(int64_t);
};
struct FfiConverterBool {
    static bool lift(uint8_t);
    static uint8_t lower(bool);
    static bool read(RustStream &);
    static void write(RustStream &, bool);
    static uint64_t allocation_size(bool);
};
struct FfiConverterString {
    static std::string lift(RustBuffer buf);
    static RustBuffer lower(const std::string &);
    static std::string read(RustStream &);
    static void write(RustStream &, const std::string &);
    static uint64_t allocation_size(const std::string &);
};

struct FfiConverterBytes {
    static std::vector<uint8_t> lift(RustBuffer);
    static RustBuffer lower(const std::vector<uint8_t> &);
    static std::vector<uint8_t> read(RustStream &);
    static void write(RustStream &, const std::vector<uint8_t> &);
    static uint64_t allocation_size(const std::vector<uint8_t> &);
};


struct FfiConverterAccount {
    static std::shared_ptr<Account> lift(uint64_t);
    static uint64_t lower(const std::shared_ptr<Account> &);
    static std::shared_ptr<Account> read(RustStream &);
    static void write(RustStream &, const std::shared_ptr<Account> &);
    static uint64_t allocation_size(const std::shared_ptr<Account> &);
private:
};


struct FfiConverterAdmin {
    static std::shared_ptr<Admin> lift(uint64_t);
    static uint64_t lower(const std::shared_ptr<Admin> &);
    static std::shared_ptr<Admin> read(RustStream &);
    static void write(RustStream &, const std::shared_ptr<Admin> &);
    static uint64_t allocation_size(const std::shared_ptr<Admin> &);
private:
};


struct FfiConverterCancelToken {
    static std::shared_ptr<CancelToken> lift(uint64_t);
    static uint64_t lower(const std::shared_ptr<CancelToken> &);
    static std::shared_ptr<CancelToken> read(RustStream &);
    static void write(RustStream &, const std::shared_ptr<CancelToken> &);
    static uint64_t allocation_size(const std::shared_ptr<CancelToken> &);
private:
};


struct FfiConverterConfidential {
    static std::shared_ptr<Confidential> lift(uint64_t);
    static uint64_t lower(const std::shared_ptr<Confidential> &);
    static std::shared_ptr<Confidential> read(RustStream &);
    static void write(RustStream &, const std::shared_ptr<Confidential> &);
    static uint64_t allocation_size(const std::shared_ptr<Confidential> &);
private:
};


struct FfiConverterDex {
    static std::shared_ptr<Dex> lift(uint64_t);
    static uint64_t lower(const std::shared_ptr<Dex> &);
    static std::shared_ptr<Dex> read(RustStream &);
    static void write(RustStream &, const std::shared_ptr<Dex> &);
    static uint64_t allocation_size(const std::shared_ptr<Dex> &);
private:
};


struct FfiConverterOp {
    static std::shared_ptr<Op> lift(uint64_t);
    static uint64_t lower(const std::shared_ptr<Op> &);
    static std::shared_ptr<Op> read(RustStream &);
    static void write(RustStream &, const std::shared_ptr<Op> &);
    static uint64_t allocation_size(const std::shared_ptr<Op> &);
private:
};


struct FfiConverterPrepared {
    static std::shared_ptr<Prepared> lift(uint64_t);
    static uint64_t lower(const std::shared_ptr<Prepared> &);
    static std::shared_ptr<Prepared> read(RustStream &);
    static void write(RustStream &, const std::shared_ptr<Prepared> &);
    static uint64_t allocation_size(const std::shared_ptr<Prepared> &);
private:
};


struct FfiConverterPreparedOrder {
    static std::shared_ptr<PreparedOrder> lift(uint64_t);
    static uint64_t lower(const std::shared_ptr<PreparedOrder> &);
    static std::shared_ptr<PreparedOrder> read(RustStream &);
    static void write(RustStream &, const std::shared_ptr<PreparedOrder> &);
    static uint64_t allocation_size(const std::shared_ptr<PreparedOrder> &);
private:
};


struct FfiConverterRegistryWrite {
    static std::shared_ptr<RegistryWrite> lift(uint64_t);
    static uint64_t lower(const std::shared_ptr<RegistryWrite> &);
    static std::shared_ptr<RegistryWrite> read(RustStream &);
    static void write(RustStream &, const std::shared_ptr<RegistryWrite> &);
    static uint64_t allocation_size(const std::shared_ptr<RegistryWrite> &);
private:
};


struct FfiConverterSdk {
    static std::shared_ptr<Sdk> lift(uint64_t);
    static uint64_t lower(const std::shared_ptr<Sdk> &);
    static std::shared_ptr<Sdk> read(RustStream &);
    static void write(RustStream &, const std::shared_ptr<Sdk> &);
    static uint64_t allocation_size(const std::shared_ptr<Sdk> &);
private:
};


struct FfiConverterSecretBytes {
    static std::shared_ptr<SecretBytes> lift(uint64_t);
    static uint64_t lower(const std::shared_ptr<SecretBytes> &);
    static std::shared_ptr<SecretBytes> read(RustStream &);
    static void write(RustStream &, const std::shared_ptr<SecretBytes> &);
    static uint64_t allocation_size(const std::shared_ptr<SecretBytes> &);
private:
};


struct FfiConverterSeedBackup {
    static std::shared_ptr<SeedBackup> lift(uint64_t);
    static uint64_t lower(const std::shared_ptr<SeedBackup> &);
    static std::shared_ptr<SeedBackup> read(RustStream &);
    static void write(RustStream &, const std::shared_ptr<SeedBackup> &);
    static uint64_t allocation_size(const std::shared_ptr<SeedBackup> &);
private:
};


struct FfiConverterSubscription {
    static std::shared_ptr<Subscription> lift(uint64_t);
    static uint64_t lower(const std::shared_ptr<Subscription> &);
    static std::shared_ptr<Subscription> read(RustStream &);
    static void write(RustStream &, const std::shared_ptr<Subscription> &);
    static uint64_t allocation_size(const std::shared_ptr<Subscription> &);
private:
};


struct FfiConverterSyncAuthenticator {
    static std::shared_ptr<SyncAuthenticator> lift(uint64_t);
    static uint64_t lower(const std::shared_ptr<SyncAuthenticator> &);
    static std::shared_ptr<SyncAuthenticator> read(RustStream &);
    static void write(RustStream &, const std::shared_ptr<SyncAuthenticator> &);
    static uint64_t allocation_size(const std::shared_ptr<SyncAuthenticator> &);
private:
    friend struct UniffiCallbackInterfaceSyncAuthenticator;
    inline static HandleMap<SyncAuthenticator> handle_map = {};
};


struct FfiConverterSyncStore {
    static std::shared_ptr<SyncStore> lift(uint64_t);
    static uint64_t lower(const std::shared_ptr<SyncStore> &);
    static std::shared_ptr<SyncStore> read(RustStream &);
    static void write(RustStream &, const std::shared_ptr<SyncStore> &);
    static uint64_t allocation_size(const std::shared_ptr<SyncStore> &);
private:
    friend struct UniffiCallbackInterfaceSyncStore;
    inline static HandleMap<SyncStore> handle_map = {};
};


struct FfiConverterVault {
    static std::shared_ptr<Vault> lift(uint64_t);
    static uint64_t lower(const std::shared_ptr<Vault> &);
    static std::shared_ptr<Vault> read(RustStream &);
    static void write(RustStream &, const std::shared_ptr<Vault> &);
    static uint64_t allocation_size(const std::shared_ptr<Vault> &);
private:
};


struct FfiConverterWallet {
    static std::shared_ptr<Wallet> lift(uint64_t);
    static uint64_t lower(const std::shared_ptr<Wallet> &);
    static std::shared_ptr<Wallet> read(RustStream &);
    static void write(RustStream &, const std::shared_ptr<Wallet> &);
    static uint64_t allocation_size(const std::shared_ptr<Wallet> &);
private:
};

struct FfiConverterTypeAcceptMembership {
    static AcceptMembership lift(RustBuffer);
    static RustBuffer lower(const AcceptMembership &);
    static AcceptMembership read(RustStream &);
    static void write(RustStream &, const AcceptMembership &);
    static uint64_t allocation_size(const AcceptMembership &);
};

struct FfiConverterTypeAccountInfo {
    static AccountInfo lift(RustBuffer);
    static RustBuffer lower(const AccountInfo &);
    static AccountInfo read(RustStream &);
    static void write(RustStream &, const AccountInfo &);
    static uint64_t allocation_size(const AccountInfo &);
};

struct FfiConverterTypeAddNative {
    static AddNative lift(RustBuffer);
    static RustBuffer lower(const AddNative &);
    static AddNative read(RustStream &);
    static void write(RustStream &, const AddNative &);
    static uint64_t allocation_size(const AddNative &);
};

struct FfiConverterTypeAddReserve {
    static AddReserve lift(RustBuffer);
    static RustBuffer lower(const AddReserve &);
    static AddReserve read(RustStream &);
    static void write(RustStream &, const AddReserve &);
    static uint64_t allocation_size(const AddReserve &);
};

struct FfiConverterTypeAddUa {
    static AddUa lift(RustBuffer);
    static RustBuffer lower(const AddUa &);
    static AddUa read(RustStream &);
    static void write(RustStream &, const AddUa &);
    static uint64_t allocation_size(const AddUa &);
};

struct FfiConverterTypeAddWatch {
    static AddWatch lift(RustBuffer);
    static RustBuffer lower(const AddWatch &);
    static AddWatch read(RustStream &);
    static void write(RustStream &, const AddWatch &);
    static uint64_t allocation_size(const AddWatch &);
};

struct FfiConverterTypeAssertion {
    static Assertion lift(RustBuffer);
    static RustBuffer lower(const Assertion &);
    static Assertion read(RustStream &);
    static void write(RustStream &, const Assertion &);
    static uint64_t allocation_size(const Assertion &);
};

struct FfiConverterTypeAssertionRequest {
    static AssertionRequest lift(RustBuffer);
    static RustBuffer lower(const AssertionRequest &);
    static AssertionRequest read(RustStream &);
    static void write(RustStream &, const AssertionRequest &);
    static uint64_t allocation_size(const AssertionRequest &);
};

struct FfiConverterTypeAttrsArgs {
    static AttrsArgs lift(RustBuffer);
    static RustBuffer lower(const AttrsArgs &);
    static AttrsArgs read(RustStream &);
    static void write(RustStream &, const AttrsArgs &);
    static uint64_t allocation_size(const AttrsArgs &);
};

struct FfiConverterTypeAuditorConsent {
    static AuditorConsent lift(RustBuffer);
    static RustBuffer lower(const AuditorConsent &);
    static AuditorConsent read(RustStream &);
    static void write(RustStream &, const AuditorConsent &);
    static uint64_t allocation_size(const AuditorConsent &);
};

struct FfiConverterTypeBalances {
    static Balances lift(RustBuffer);
    static RustBuffer lower(const Balances &);
    static Balances read(RustStream &);
    static void write(RustStream &, const Balances &);
    static uint64_t allocation_size(const Balances &);
};

struct FfiConverterTypeBindingConfig {
    static BindingConfig lift(RustBuffer);
    static RustBuffer lower(const BindingConfig &);
    static BindingConfig read(RustStream &);
    static void write(RustStream &, const BindingConfig &);
    static uint64_t allocation_size(const BindingConfig &);
};

struct FfiConverterTypeBlsMultiPart {
    static BlsMultiPart lift(RustBuffer);
    static RustBuffer lower(const BlsMultiPart &);
    static BlsMultiPart read(RustStream &);
    static void write(RustStream &, const BlsMultiPart &);
    static uint64_t allocation_size(const BlsMultiPart &);
};

struct FfiConverterTypeBurn {
    static Burn lift(RustBuffer);
    static RustBuffer lower(const Burn &);
    static Burn read(RustStream &);
    static void write(RustStream &, const Burn &);
    static uint64_t allocation_size(const Burn &);
};

struct FfiConverterTypeCancelAll {
    static CancelAll lift(RustBuffer);
    static RustBuffer lower(const CancelAll &);
    static CancelAll read(RustStream &);
    static void write(RustStream &, const CancelAll &);
    static uint64_t allocation_size(const CancelAll &);
};

struct FfiConverterTypeCancelNonce {
    static CancelNonce lift(RustBuffer);
    static RustBuffer lower(const CancelNonce &);
    static CancelNonce read(RustStream &);
    static void write(RustStream &, const CancelNonce &);
    static uint64_t allocation_size(const CancelNonce &);
};

struct FfiConverterTypeCancelOrder {
    static CancelOrder lift(RustBuffer);
    static RustBuffer lower(const CancelOrder &);
    static CancelOrder read(RustStream &);
    static void write(RustStream &, const CancelOrder &);
    static uint64_t allocation_size(const CancelOrder &);
};

struct FfiConverterTypeCancelWrapOrder {
    static CancelWrapOrder lift(RustBuffer);
    static RustBuffer lower(const CancelWrapOrder &);
    static CancelWrapOrder read(RustStream &);
    static void write(RustStream &, const CancelWrapOrder &);
    static uint64_t allocation_size(const CancelWrapOrder &);
};

struct FfiConverterTypeChainProfile {
    static ChainProfile lift(RustBuffer);
    static RustBuffer lower(const ChainProfile &);
    static ChainProfile read(RustStream &);
    static void write(RustStream &, const ChainProfile &);
    static uint64_t allocation_size(const ChainProfile &);
};

struct FfiConverterTypeConfirmRemove {
    static ConfirmRemove lift(RustBuffer);
    static RustBuffer lower(const ConfirmRemove &);
    static ConfirmRemove read(RustStream &);
    static void write(RustStream &, const ConfirmRemove &);
    static uint64_t allocation_size(const ConfirmRemove &);
};

struct FfiConverterTypeConfirmRemoveUnbacked {
    static ConfirmRemoveUnbacked lift(RustBuffer);
    static RustBuffer lower(const ConfirmRemoveUnbacked &);
    static ConfirmRemoveUnbacked read(RustStream &);
    static void write(RustStream &, const ConfirmRemoveUnbacked &);
    static uint64_t allocation_size(const ConfirmRemoveUnbacked &);
};

struct FfiConverterTypeCreate3Preview {
    static Create3Preview lift(RustBuffer);
    static RustBuffer lower(const Create3Preview &);
    static Create3Preview read(RustStream &);
    static void write(RustStream &, const Create3Preview &);
    static uint64_t allocation_size(const Create3Preview &);
};

struct FfiConverterTypeCreatePasskeyKey {
    static CreatePasskeyKey lift(RustBuffer);
    static RustBuffer lower(const CreatePasskeyKey &);
    static CreatePasskeyKey read(RustStream &);
    static void write(RustStream &, const CreatePasskeyKey &);
    static uint64_t allocation_size(const CreatePasskeyKey &);
};

struct FfiConverterTypeCreateSeKey {
    static CreateSeKey lift(RustBuffer);
    static RustBuffer lower(const CreateSeKey &);
    static CreateSeKey read(RustStream &);
    static void write(RustStream &, const CreateSeKey &);
    static uint64_t allocation_size(const CreateSeKey &);
};

struct FfiConverterTypeCursor {
    static Cursor lift(RustBuffer);
    static RustBuffer lower(const Cursor &);
    static Cursor read(RustStream &);
    static void write(RustStream &, const Cursor &);
    static uint64_t allocation_size(const Cursor &);
};

struct FfiConverterTypeDelegateRevoke {
    static DelegateRevoke lift(RustBuffer);
    static RustBuffer lower(const DelegateRevoke &);
    static DelegateRevoke read(RustStream &);
    static void write(RustStream &, const DelegateRevoke &);
    static uint64_t allocation_size(const DelegateRevoke &);
};

struct FfiConverterTypeDeriveChild {
    static DeriveChild lift(RustBuffer);
    static RustBuffer lower(const DeriveChild &);
    static DeriveChild read(RustStream &);
    static void write(RustStream &, const DeriveChild &);
    static uint64_t allocation_size(const DeriveChild &);
};

struct FfiConverterTypeDeriveFromKey {
    static DeriveFromKey lift(RustBuffer);
    static RustBuffer lower(const DeriveFromKey &);
    static DeriveFromKey read(RustStream &);
    static void write(RustStream &, const DeriveFromKey &);
    static uint64_t allocation_size(const DeriveFromKey &);
};

struct FfiConverterTypeDeriveFromSignature {
    static DeriveFromSignature lift(RustBuffer);
    static RustBuffer lower(const DeriveFromSignature &);
    static DeriveFromSignature read(RustStream &);
    static void write(RustStream &, const DeriveFromSignature &);
    static uint64_t allocation_size(const DeriveFromSignature &);
};

struct FfiConverterTypeEndpointConfig {
    static EndpointConfig lift(RustBuffer);
    static RustBuffer lower(const EndpointConfig &);
    static EndpointConfig read(RustStream &);
    static void write(RustStream &, const EndpointConfig &);
    static uint64_t allocation_size(const EndpointConfig &);
};

struct FfiConverterTypeEnvelope {
    static Envelope lift(RustBuffer);
    static RustBuffer lower(const Envelope &);
    static Envelope read(RustStream &);
    static void write(RustStream &, const Envelope &);
    static uint64_t allocation_size(const Envelope &);
};

struct FfiConverterTypeExecute {
    static Execute lift(RustBuffer);
    static RustBuffer lower(const Execute &);
    static Execute read(RustStream &);
    static void write(RustStream &, const Execute &);
    static uint64_t allocation_size(const Execute &);
};

struct FfiConverterTypeGasBase {
    static GasBase lift(RustBuffer);
    static RustBuffer lower(const GasBase &);
    static GasBase read(RustStream &);
    static void write(RustStream &, const GasBase &);
    static uint64_t allocation_size(const GasBase &);
};

struct FfiConverterTypeGasLine {
    static GasLine lift(RustBuffer);
    static RustBuffer lower(const GasLine &);
    static GasLine read(RustStream &);
    static void write(RustStream &, const GasLine &);
    static uint64_t allocation_size(const GasLine &);
};

struct FfiConverterTypeGasPerByte {
    static GasPerByte lift(RustBuffer);
    static RustBuffer lower(const GasPerByte &);
    static GasPerByte read(RustStream &);
    static void write(RustStream &, const GasPerByte &);
    static uint64_t allocation_size(const GasPerByte &);
};

struct FfiConverterTypeGasPerItem {
    static GasPerItem lift(RustBuffer);
    static RustBuffer lower(const GasPerItem &);
    static GasPerItem read(RustStream &);
    static void write(RustStream &, const GasPerItem &);
    static uint64_t allocation_size(const GasPerItem &);
};

struct FfiConverterTypeGasRows {
    static GasRows lift(RustBuffer);
    static RustBuffer lower(const GasRows &);
    static GasRows read(RustStream &);
    static void write(RustStream &, const GasRows &);
    static uint64_t allocation_size(const GasRows &);
};

struct FfiConverterTypeGasSources {
    static GasSources lift(RustBuffer);
    static RustBuffer lower(const GasSources &);
    static GasSources read(RustStream &);
    static void write(RustStream &, const GasSources &);
    static uint64_t allocation_size(const GasSources &);
};

struct FfiConverterTypeGasTable {
    static GasTable lift(RustBuffer);
    static RustBuffer lower(const GasTable &);
    static GasTable read(RustStream &);
    static void write(RustStream &, const GasTable &);
    static uint64_t allocation_size(const GasTable &);
};

struct FfiConverterTypeGasVerify {
    static GasVerify lift(RustBuffer);
    static RustBuffer lower(const GasVerify &);
    static GasVerify read(RustStream &);
    static void write(RustStream &, const GasVerify &);
    static uint64_t allocation_size(const GasVerify &);
};

struct FfiConverterTypeGenerate {
    static Generate lift(RustBuffer);
    static RustBuffer lower(const Generate &);
    static Generate read(RustStream &);
    static void write(RustStream &, const Generate &);
    static uint64_t allocation_size(const Generate &);
};

struct FfiConverterTypeHistoryItem {
    static HistoryItem lift(RustBuffer);
    static RustBuffer lower(const HistoryItem &);
    static HistoryItem read(RustStream &);
    static void write(RustStream &, const HistoryItem &);
    static uint64_t allocation_size(const HistoryItem &);
};

struct FfiConverterTypeHistoryPage {
    static HistoryPage lift(RustBuffer);
    static RustBuffer lower(const HistoryPage &);
    static HistoryPage read(RustStream &);
    static void write(RustStream &, const HistoryPage &);
    static uint64_t allocation_size(const HistoryPage &);
};

struct FfiConverterTypeImportExpect {
    static ImportExpect lift(RustBuffer);
    static RustBuffer lower(const ImportExpect &);
    static ImportExpect read(RustStream &);
    static void write(RustStream &, const ImportExpect &);
    static uint64_t allocation_size(const ImportExpect &);
};

struct FfiConverterTypeImportKey {
    static ImportKey lift(RustBuffer);
    static RustBuffer lower(const ImportKey &);
    static ImportKey read(RustStream &);
    static void write(RustStream &, const ImportKey &);
    static uint64_t allocation_size(const ImportKey &);
};

struct FfiConverterTypeImportWords {
    static ImportWords lift(RustBuffer);
    static RustBuffer lower(const ImportWords &);
    static ImportWords read(RustStream &);
    static void write(RustStream &, const ImportWords &);
    static uint64_t allocation_size(const ImportWords &);
};

struct FfiConverterTypeImportedKey {
    static ImportedKey lift(RustBuffer);
    static RustBuffer lower(const ImportedKey &);
    static ImportedKey read(RustStream &);
    static void write(RustStream &, const ImportedKey &);
    static uint64_t allocation_size(const ImportedKey &);
};

struct FfiConverterTypeKemArgs {
    static KemArgs lift(RustBuffer);
    static RustBuffer lower(const KemArgs &);
    static KemArgs read(RustStream &);
    static void write(RustStream &, const KemArgs &);
    static uint64_t allocation_size(const KemArgs &);
};

struct FfiConverterTypeKemRecord {
    static KemRecord lift(RustBuffer);
    static RustBuffer lower(const KemRecord &);
    static KemRecord read(RustStream &);
    static void write(RustStream &, const KemRecord &);
    static uint64_t allocation_size(const KemRecord &);
};

struct FfiConverterTypeKeyPolicy {
    static KeyPolicy lift(RustBuffer);
    static RustBuffer lower(const KeyPolicy &);
    static KeyPolicy read(RustStream &);
    static void write(RustStream &, const KeyPolicy &);
    static uint64_t allocation_size(const KeyPolicy &);
};

struct FfiConverterTypeLimits {
    static Limits lift(RustBuffer);
    static RustBuffer lower(const Limits &);
    static Limits read(RustStream &);
    static void write(RustStream &, const Limits &);
    static uint64_t allocation_size(const Limits &);
};

struct FfiConverterTypeLiquidityOrder {
    static LiquidityOrder lift(RustBuffer);
    static RustBuffer lower(const LiquidityOrder &);
    static LiquidityOrder read(RustStream &);
    static void write(RustStream &, const LiquidityOrder &);
    static uint64_t allocation_size(const LiquidityOrder &);
};

struct FfiConverterTypeLiquidityToken {
    static LiquidityToken lift(RustBuffer);
    static RustBuffer lower(const LiquidityToken &);
    static LiquidityToken read(RustStream &);
    static void write(RustStream &, const LiquidityToken &);
    static uint64_t allocation_size(const LiquidityToken &);
};

struct FfiConverterTypeListedDex {
    static ListedDex lift(RustBuffer);
    static RustBuffer lower(const ListedDex &);
    static ListedDex read(RustStream &);
    static void write(RustStream &, const ListedDex &);
    static uint64_t allocation_size(const ListedDex &);
};

struct FfiConverterTypeListedToken {
    static ListedToken lift(RustBuffer);
    static RustBuffer lower(const ListedToken &);
    static ListedToken read(RustStream &);
    static void write(RustStream &, const ListedToken &);
    static uint64_t allocation_size(const ListedToken &);
};

struct FfiConverterTypeMemoryProtection {
    static MemoryProtection lift(RustBuffer);
    static RustBuffer lower(const MemoryProtection &);
    static MemoryProtection read(RustStream &);
    static void write(RustStream &, const MemoryProtection &);
    static uint64_t allocation_size(const MemoryProtection &);
};

struct FfiConverterTypeMsigLeafValue {
    static MsigLeafValue lift(RustBuffer);
    static RustBuffer lower(const MsigLeafValue &);
    static MsigLeafValue read(RustStream &);
    static void write(RustStream &, const MsigLeafValue &);
    static uint64_t allocation_size(const MsigLeafValue &);
};

struct FfiConverterTypeMsigMemberArgs {
    static MsigMemberArgs lift(RustBuffer);
    static RustBuffer lower(const MsigMemberArgs &);
    static MsigMemberArgs read(RustStream &);
    static void write(RustStream &, const MsigMemberArgs &);
    static uint64_t allocation_size(const MsigMemberArgs &);
};

struct FfiConverterTypeMsigRegister {
    static MsigRegister lift(RustBuffer);
    static RustBuffer lower(const MsigRegister &);
    static MsigRegister read(RustStream &);
    static void write(RustStream &, const MsigRegister &);
    static uint64_t allocation_size(const MsigRegister &);
};

struct FfiConverterTypeMsigSlotState {
    static MsigSlotState lift(RustBuffer);
    static RustBuffer lower(const MsigSlotState &);
    static MsigSlotState read(RustStream &);
    static void write(RustStream &, const MsigSlotState &);
    static uint64_t allocation_size(const MsigSlotState &);
};

struct FfiConverterTypeMsigState {
    static MsigState lift(RustBuffer);
    static RustBuffer lower(const MsigState &);
    static MsigState read(RustStream &);
    static void write(RustStream &, const MsigState &);
    static uint64_t allocation_size(const MsigState &);
};

struct FfiConverterTypeMsigStructureArgs {
    static MsigStructureArgs lift(RustBuffer);
    static RustBuffer lower(const MsigStructureArgs &);
    static MsigStructureArgs read(RustStream &);
    static void write(RustStream &, const MsigStructureArgs &);
    static uint64_t allocation_size(const MsigStructureArgs &);
};

struct FfiConverterTypeMsigUpdatePlan {
    static MsigUpdatePlan lift(RustBuffer);
    static RustBuffer lower(const MsigUpdatePlan &);
    static MsigUpdatePlan read(RustStream &);
    static void write(RustStream &, const MsigUpdatePlan &);
    static uint64_t allocation_size(const MsigUpdatePlan &);
};

struct FfiConverterTypeNativeAddress {
    static NativeAddress lift(RustBuffer);
    static RustBuffer lower(const NativeAddress &);
    static NativeAddress read(RustStream &);
    static void write(RustStream &, const NativeAddress &);
    static uint64_t allocation_size(const NativeAddress &);
};

struct FfiConverterTypeNativeCap {
    static NativeCap lift(RustBuffer);
    static RustBuffer lower(const NativeCap &);
    static NativeCap read(RustStream &);
    static void write(RustStream &, const NativeCap &);
    static uint64_t allocation_size(const NativeCap &);
};

struct FfiConverterTypeNativeKeyRef {
    static NativeKeyRef lift(RustBuffer);
    static RustBuffer lower(const NativeKeyRef &);
    static NativeKeyRef read(RustStream &);
    static void write(RustStream &, const NativeKeyRef &);
    static uint64_t allocation_size(const NativeKeyRef &);
};

struct FfiConverterTypeNativeQuote {
    static NativeQuote lift(RustBuffer);
    static RustBuffer lower(const NativeQuote &);
    static NativeQuote read(RustStream &);
    static void write(RustStream &, const NativeQuote &);
    static uint64_t allocation_size(const NativeQuote &);
};

struct FfiConverterTypeNativeSend {
    static NativeSend lift(RustBuffer);
    static RustBuffer lower(const NativeSend &);
    static NativeSend read(RustStream &);
    static void write(RustStream &, const NativeSend &);
    static uint64_t allocation_size(const NativeSend &);
};

struct FfiConverterTypeNewSeed {
    static NewSeed lift(RustBuffer);
    static RustBuffer lower(const NewSeed &);
    static NewSeed read(RustStream &);
    static void write(RustStream &, const NewSeed &);
    static uint64_t allocation_size(const NewSeed &);
};

struct FfiConverterTypeOpItem {
    static OpItem lift(RustBuffer);
    static RustBuffer lower(const OpItem &);
    static OpItem read(RustStream &);
    static void write(RustStream &, const OpItem &);
    static uint64_t allocation_size(const OpItem &);
};

struct FfiConverterTypeOrderTerms {
    static OrderTerms lift(RustBuffer);
    static RustBuffer lower(const OrderTerms &);
    static OrderTerms read(RustStream &);
    static void write(RustStream &, const OrderTerms &);
    static uint64_t allocation_size(const OrderTerms &);
};

struct FfiConverterTypeOwnerRelay {
    static OwnerRelay lift(RustBuffer);
    static RustBuffer lower(const OwnerRelay &);
    static OwnerRelay read(RustStream &);
    static void write(RustStream &, const OwnerRelay &);
    static uint64_t allocation_size(const OwnerRelay &);
};

struct FfiConverterTypePasskeyCreated {
    static PasskeyCreated lift(RustBuffer);
    static RustBuffer lower(const PasskeyCreated &);
    static PasskeyCreated read(RustStream &);
    static void write(RustStream &, const PasskeyCreated &);
    static uint64_t allocation_size(const PasskeyCreated &);
};

struct FfiConverterTypePay {
    static Pay lift(RustBuffer);
    static RustBuffer lower(const Pay &);
    static Pay read(RustStream &);
    static void write(RustStream &, const Pay &);
    static uint64_t allocation_size(const Pay &);
};

struct FfiConverterTypePayMeta {
    static PayMeta lift(RustBuffer);
    static RustBuffer lower(const PayMeta &);
    static PayMeta read(RustStream &);
    static void write(RustStream &, const PayMeta &);
    static uint64_t allocation_size(const PayMeta &);
};

struct FfiConverterTypePayUnderMandate {
    static PayUnderMandate lift(RustBuffer);
    static RustBuffer lower(const PayUnderMandate &);
    static PayUnderMandate read(RustStream &);
    static void write(RustStream &, const PayUnderMandate &);
    static uint64_t allocation_size(const PayUnderMandate &);
};

struct FfiConverterTypePayWithTax {
    static PayWithTax lift(RustBuffer);
    static RustBuffer lower(const PayWithTax &);
    static PayWithTax read(RustStream &);
    static void write(RustStream &, const PayWithTax &);
    static uint64_t allocation_size(const PayWithTax &);
};

struct FfiConverterTypePayeeFee {
    static PayeeFee lift(RustBuffer);
    static RustBuffer lower(const PayeeFee &);
    static PayeeFee read(RustStream &);
    static void write(RustStream &, const PayeeFee &);
    static uint64_t allocation_size(const PayeeFee &);
};

struct FfiConverterTypePayerAuth {
    static PayerAuth lift(RustBuffer);
    static RustBuffer lower(const PayerAuth &);
    static PayerAuth read(RustStream &);
    static void write(RustStream &, const PayerAuth &);
    static uint64_t allocation_size(const PayerAuth &);
};

struct FfiConverterTypePayment {
    static Payment lift(RustBuffer);
    static RustBuffer lower(const Payment &);
    static Payment read(RustStream &);
    static void write(RustStream &, const Payment &);
    static uint64_t allocation_size(const Payment &);
};

struct FfiConverterTypePositionReader {
    static PositionReader lift(RustBuffer);
    static RustBuffer lower(const PositionReader &);
    static PositionReader read(RustStream &);
    static void write(RustStream &, const PositionReader &);
    static uint64_t allocation_size(const PositionReader &);
};

struct FfiConverterTypePqzAccountOp {
    static PqzAccountOp lift(RustBuffer);
    static RustBuffer lower(const PqzAccountOp &);
    static PqzAccountOp read(RustStream &);
    static void write(RustStream &, const PqzAccountOp &);
    static uint64_t allocation_size(const PqzAccountOp &);
};

struct FfiConverterTypePqzBalance {
    static PqzBalance lift(RustBuffer);
    static RustBuffer lower(const PqzBalance &);
    static PqzBalance read(RustStream &);
    static void write(RustStream &, const PqzBalance &);
    static uint64_t allocation_size(const PqzBalance &);
};

struct FfiConverterTypePqzBalanceAll {
    static PqzBalanceAll lift(RustBuffer);
    static RustBuffer lower(const PqzBalanceAll &);
    static PqzBalanceAll read(RustStream &);
    static void write(RustStream &, const PqzBalanceAll &);
    static uint64_t allocation_size(const PqzBalanceAll &);
};

struct FfiConverterTypePqzBalanceRequest {
    static PqzBalanceRequest lift(RustBuffer);
    static RustBuffer lower(const PqzBalanceRequest &);
    static PqzBalanceRequest read(RustStream &);
    static void write(RustStream &, const PqzBalanceRequest &);
    static uint64_t allocation_size(const PqzBalanceRequest &);
};

struct FfiConverterTypePqzLeg {
    static PqzLeg lift(RustBuffer);
    static RustBuffer lower(const PqzLeg &);
    static PqzLeg read(RustStream &);
    static void write(RustStream &, const PqzLeg &);
    static uint64_t allocation_size(const PqzLeg &);
};

struct FfiConverterTypePqzShield {
    static PqzShield lift(RustBuffer);
    static RustBuffer lower(const PqzShield &);
    static PqzShield read(RustStream &);
    static void write(RustStream &, const PqzShield &);
    static uint64_t allocation_size(const PqzShield &);
};

struct FfiConverterTypePqzTransfer {
    static PqzTransfer lift(RustBuffer);
    static RustBuffer lower(const PqzTransfer &);
    static PqzTransfer read(RustStream &);
    static void write(RustStream &, const PqzTransfer &);
    static uint64_t allocation_size(const PqzTransfer &);
};

struct FfiConverterTypePqzTransferMulti {
    static PqzTransferMulti lift(RustBuffer);
    static RustBuffer lower(const PqzTransferMulti &);
    static PqzTransferMulti read(RustStream &);
    static void write(RustStream &, const PqzTransferMulti &);
    static uint64_t allocation_size(const PqzTransferMulti &);
};

struct FfiConverterTypePqzUnshield {
    static PqzUnshield lift(RustBuffer);
    static RustBuffer lower(const PqzUnshield &);
    static PqzUnshield read(RustStream &);
    static void write(RustStream &, const PqzUnshield &);
    static uint64_t allocation_size(const PqzUnshield &);
};

struct FfiConverterTypePqzUnshieldUnwrap {
    static PqzUnshieldUnwrap lift(RustBuffer);
    static RustBuffer lower(const PqzUnshieldUnwrap &);
    static PqzUnshieldUnwrap read(RustStream &);
    static void write(RustStream &, const PqzUnshieldUnwrap &);
    static uint64_t allocation_size(const PqzUnshieldUnwrap &);
};

struct FfiConverterTypePqzVerdictRequest {
    static PqzVerdictRequest lift(RustBuffer);
    static RustBuffer lower(const PqzVerdictRequest &);
    static PqzVerdictRequest read(RustStream &);
    static void write(RustStream &, const PqzVerdictRequest &);
    static uint64_t allocation_size(const PqzVerdictRequest &);
};

struct FfiConverterTypePqzWrapShield {
    static PqzWrapShield lift(RustBuffer);
    static RustBuffer lower(const PqzWrapShield &);
    static PqzWrapShield read(RustStream &);
    static void write(RustStream &, const PqzWrapShield &);
    static uint64_t allocation_size(const PqzWrapShield &);
};

struct FfiConverterTypeRegister {
    static Register lift(RustBuffer);
    static RustBuffer lower(const Register &);
    static Register read(RustStream &);
    static void write(RustStream &, const Register &);
    static uint64_t allocation_size(const Register &);
};

struct FfiConverterTypeRegisterArgs {
    static RegisterArgs lift(RustBuffer);
    static RustBuffer lower(const RegisterArgs &);
    static RegisterArgs read(RustStream &);
    static void write(RustStream &, const RegisterArgs &);
    static uint64_t allocation_size(const RegisterArgs &);
};

struct FfiConverterTypeRegisterAttrs {
    static RegisterAttrs lift(RustBuffer);
    static RustBuffer lower(const RegisterAttrs &);
    static RegisterAttrs read(RustStream &);
    static void write(RustStream &, const RegisterAttrs &);
    static uint64_t allocation_size(const RegisterAttrs &);
};

struct FfiConverterTypeRegistrationBlob {
    static RegistrationBlob lift(RustBuffer);
    static RustBuffer lower(const RegistrationBlob &);
    static RegistrationBlob read(RustStream &);
    static void write(RustStream &, const RegistrationBlob &);
    static uint64_t allocation_size(const RegistrationBlob &);
};

struct FfiConverterTypeRegistrationGas {
    static RegistrationGas lift(RustBuffer);
    static RustBuffer lower(const RegistrationGas &);
    static RegistrationGas read(RustStream &);
    static void write(RustStream &, const RegistrationGas &);
    static uint64_t allocation_size(const RegistrationGas &);
};

struct FfiConverterTypeRegistrationState {
    static RegistrationState lift(RustBuffer);
    static RustBuffer lower(const RegistrationState &);
    static RegistrationState read(RustStream &);
    static void write(RustStream &, const RegistrationState &);
    static uint64_t allocation_size(const RegistrationState &);
};

struct FfiConverterTypeRelayFee {
    static RelayFee lift(RustBuffer);
    static RustBuffer lower(const RelayFee &);
    static RelayFee read(RustStream &);
    static void write(RustStream &, const RelayFee &);
    static uint64_t allocation_size(const RelayFee &);
};

struct FfiConverterTypeRemove {
    static Remove lift(RustBuffer);
    static RustBuffer lower(const Remove &);
    static Remove read(RustStream &);
    static void write(RustStream &, const Remove &);
    static uint64_t allocation_size(const Remove &);
};

struct FfiConverterTypeRescueVault {
    static RescueVault lift(RustBuffer);
    static RustBuffer lower(const RescueVault &);
    static RescueVault read(RustStream &);
    static void write(RustStream &, const RescueVault &);
    static uint64_t allocation_size(const RescueVault &);
};

struct FfiConverterTypeRestore {
    static Restore lift(RustBuffer);
    static RustBuffer lower(const Restore &);
    static Restore read(RustStream &);
    static void write(RustStream &, const Restore &);
    static uint64_t allocation_size(const Restore &);
};

struct FfiConverterTypeReviewField {
    static ReviewField lift(RustBuffer);
    static RustBuffer lower(const ReviewField &);
    static ReviewField read(RustStream &);
    static void write(RustStream &, const ReviewField &);
    static uint64_t allocation_size(const ReviewField &);
};

struct FfiConverterTypeRevokeMandate {
    static RevokeMandate lift(RustBuffer);
    static RustBuffer lower(const RevokeMandate &);
    static RevokeMandate read(RustStream &);
    static void write(RustStream &, const RevokeMandate &);
    static uint64_t allocation_size(const RevokeMandate &);
};

struct FfiConverterTypeSePublic {
    static SePublic lift(RustBuffer);
    static RustBuffer lower(const SePublic &);
    static SePublic read(RustStream &);
    static void write(RustStream &, const SePublic &);
    static uint64_t allocation_size(const SePublic &);
};

struct FfiConverterTypeSeedInfo {
    static SeedInfo lift(RustBuffer);
    static RustBuffer lower(const SeedInfo &);
    static SeedInfo read(RustStream &);
    static void write(RustStream &, const SeedInfo &);
    static uint64_t allocation_size(const SeedInfo &);
};

struct FfiConverterTypeSessionSet {
    static SessionSet lift(RustBuffer);
    static RustBuffer lower(const SessionSet &);
    static SessionSet read(RustStream &);
    static void write(RustStream &, const SessionSet &);
    static uint64_t allocation_size(const SessionSet &);
};

struct FfiConverterTypeSetMandate {
    static SetMandate lift(RustBuffer);
    static RustBuffer lower(const SetMandate &);
    static SetMandate read(RustStream &);
    static void write(RustStream &, const SetMandate &);
    static uint64_t allocation_size(const SetMandate &);
};

struct FfiConverterTypeSetPayee {
    static SetPayee lift(RustBuffer);
    static RustBuffer lower(const SetPayee &);
    static SetPayee read(RustStream &);
    static void write(RustStream &, const SetPayee &);
    static uint64_t allocation_size(const SetPayee &);
};

struct FfiConverterTypeSignedOpBlob {
    static SignedOpBlob lift(RustBuffer);
    static RustBuffer lower(const SignedOpBlob &);
    static SignedOpBlob read(RustStream &);
    static void write(RustStream &, const SignedOpBlob &);
    static uint64_t allocation_size(const SignedOpBlob &);
};

struct FfiConverterTypeSignedOrder {
    static SignedOrder lift(RustBuffer);
    static RustBuffer lower(const SignedOrder &);
    static SignedOrder read(RustStream &);
    static void write(RustStream &, const SignedOrder &);
    static uint64_t allocation_size(const SignedOrder &);
};

struct FfiConverterTypeSignedRescue {
    static SignedRescue lift(RustBuffer);
    static RustBuffer lower(const SignedRescue &);
    static SignedRescue read(RustStream &);
    static void write(RustStream &, const SignedRescue &);
    static uint64_t allocation_size(const SignedRescue &);
};

struct FfiConverterTypeSmartOp {
    static SmartOp lift(RustBuffer);
    static RustBuffer lower(const SmartOp &);
    static SmartOp read(RustStream &);
    static void write(RustStream &, const SmartOp &);
    static uint64_t allocation_size(const SmartOp &);
};

struct FfiConverterTypeStepGas {
    static StepGas lift(RustBuffer);
    static RustBuffer lower(const StepGas &);
    static StepGas read(RustStream &);
    static void write(RustStream &, const StepGas &);
    static uint64_t allocation_size(const StepGas &);
};

struct FfiConverterTypeStorePolicy {
    static StorePolicy lift(RustBuffer);
    static RustBuffer lower(const StorePolicy &);
    static StorePolicy read(RustStream &);
    static void write(RustStream &, const StorePolicy &);
    static uint64_t allocation_size(const StorePolicy &);
};

struct FfiConverterTypeStoredItem {
    static StoredItem lift(RustBuffer);
    static RustBuffer lower(const StoredItem &);
    static StoredItem read(RustStream &);
    static void write(RustStream &, const StoredItem &);
    static uint64_t allocation_size(const StoredItem &);
};

struct FfiConverterTypeSubjectKeyArgs {
    static SubjectKeyArgs lift(RustBuffer);
    static RustBuffer lower(const SubjectKeyArgs &);
    static SubjectKeyArgs read(RustStream &);
    static void write(RustStream &, const SubjectKeyArgs &);
    static uint64_t allocation_size(const SubjectKeyArgs &);
};

struct FfiConverterTypeSubmitQuote {
    static SubmitQuote lift(RustBuffer);
    static RustBuffer lower(const SubmitQuote &);
    static SubmitQuote read(RustStream &);
    static void write(RustStream &, const SubmitQuote &);
    static uint64_t allocation_size(const SubmitQuote &);
};

struct FfiConverterTypeTokenBalance {
    static TokenBalance lift(RustBuffer);
    static RustBuffer lower(const TokenBalance &);
    static TokenBalance read(RustStream &);
    static void write(RustStream &, const TokenBalance &);
    static uint64_t allocation_size(const TokenBalance &);
};

struct FfiConverterTypeTokenInfo {
    static TokenInfo lift(RustBuffer);
    static RustBuffer lower(const TokenInfo &);
    static TokenInfo read(RustStream &);
    static void write(RustStream &, const TokenInfo &);
    static uint64_t allocation_size(const TokenInfo &);
};

struct FfiConverterTypeTradeOrder {
    static TradeOrder lift(RustBuffer);
    static RustBuffer lower(const TradeOrder &);
    static TradeOrder read(RustStream &);
    static void write(RustStream &, const TradeOrder &);
    static uint64_t allocation_size(const TradeOrder &);
};

struct FfiConverterTypeTransfer {
    static Transfer lift(RustBuffer);
    static RustBuffer lower(const Transfer &);
    static Transfer read(RustStream &);
    static void write(RustStream &, const Transfer &);
    static uint64_t allocation_size(const Transfer &);
};

struct FfiConverterTypeUaAcceptAdmin {
    static UaAcceptAdmin lift(RustBuffer);
    static RustBuffer lower(const UaAcceptAdmin &);
    static UaAcceptAdmin read(RustStream &);
    static void write(RustStream &, const UaAcceptAdmin &);
    static uint64_t allocation_size(const UaAcceptAdmin &);
};

struct FfiConverterTypeUaApproveDexRelease {
    static UaApproveDexRelease lift(RustBuffer);
    static RustBuffer lower(const UaApproveDexRelease &);
    static UaApproveDexRelease read(RustStream &);
    static void write(RustStream &, const UaApproveDexRelease &);
    static uint64_t allocation_size(const UaApproveDexRelease &);
};

struct FfiConverterTypeUaApproveRelease {
    static UaApproveRelease lift(RustBuffer);
    static RustBuffer lower(const UaApproveRelease &);
    static UaApproveRelease read(RustStream &);
    static void write(RustStream &, const UaApproveRelease &);
    static uint64_t allocation_size(const UaApproveRelease &);
};

struct FfiConverterTypeUaApproveTokenRelease {
    static UaApproveTokenRelease lift(RustBuffer);
    static RustBuffer lower(const UaApproveTokenRelease &);
    static UaApproveTokenRelease read(RustStream &);
    static void write(RustStream &, const UaApproveTokenRelease &);
    static uint64_t allocation_size(const UaApproveTokenRelease &);
};

struct FfiConverterTypeUaCancelGrant {
    static UaCancelGrant lift(RustBuffer);
    static RustBuffer lower(const UaCancelGrant &);
    static UaCancelGrant read(RustStream &);
    static void write(RustStream &, const UaCancelGrant &);
    static uint64_t allocation_size(const UaCancelGrant &);
};

struct FfiConverterTypeUaCancelNonce {
    static UaCancelNonce lift(RustBuffer);
    static RustBuffer lower(const UaCancelNonce &);
    static UaCancelNonce read(RustStream &);
    static void write(RustStream &, const UaCancelNonce &);
    static uint64_t allocation_size(const UaCancelNonce &);
};

struct FfiConverterTypeUaCancelRate {
    static UaCancelRate lift(RustBuffer);
    static RustBuffer lower(const UaCancelRate &);
    static UaCancelRate read(RustStream &);
    static void write(RustStream &, const UaCancelRate &);
    static uint64_t allocation_size(const UaCancelRate &);
};

struct FfiConverterTypeUaCreateDex {
    static UaCreateDex lift(RustBuffer);
    static RustBuffer lower(const UaCreateDex &);
    static UaCreateDex read(RustStream &);
    static void write(RustStream &, const UaCreateDex &);
    static uint64_t allocation_size(const UaCreateDex &);
};

struct FfiConverterTypeUaCreateInstance {
    static UaCreateInstance lift(RustBuffer);
    static RustBuffer lower(const UaCreateInstance &);
    static UaCreateInstance read(RustStream &);
    static void write(RustStream &, const UaCreateInstance &);
    static uint64_t allocation_size(const UaCreateInstance &);
};

struct FfiConverterTypeUaCreateToken {
    static UaCreateToken lift(RustBuffer);
    static RustBuffer lower(const UaCreateToken &);
    static UaCreateToken read(RustStream &);
    static void write(RustStream &, const UaCreateToken &);
    static uint64_t allocation_size(const UaCreateToken &);
};

struct FfiConverterTypeUaDeprecateDex {
    static UaDeprecateDex lift(RustBuffer);
    static RustBuffer lower(const UaDeprecateDex &);
    static UaDeprecateDex read(RustStream &);
    static void write(RustStream &, const UaDeprecateDex &);
    static uint64_t allocation_size(const UaDeprecateDex &);
};

struct FfiConverterTypeUaDeprecateRelease {
    static UaDeprecateRelease lift(RustBuffer);
    static RustBuffer lower(const UaDeprecateRelease &);
    static UaDeprecateRelease read(RustStream &);
    static void write(RustStream &, const UaDeprecateRelease &);
    static uint64_t allocation_size(const UaDeprecateRelease &);
};

struct FfiConverterTypeUaDeprecateToken {
    static UaDeprecateToken lift(RustBuffer);
    static RustBuffer lower(const UaDeprecateToken &);
    static UaDeprecateToken read(RustStream &);
    static void write(RustStream &, const UaDeprecateToken &);
    static uint64_t allocation_size(const UaDeprecateToken &);
};

struct FfiConverterTypeUaDisableFeature {
    static UaDisableFeature lift(RustBuffer);
    static RustBuffer lower(const UaDisableFeature &);
    static UaDisableFeature read(RustStream &);
    static void write(RustStream &, const UaDisableFeature &);
    static uint64_t allocation_size(const UaDisableFeature &);
};

struct FfiConverterTypeUaDisableWrap {
    static UaDisableWrap lift(RustBuffer);
    static RustBuffer lower(const UaDisableWrap &);
    static UaDisableWrap read(RustStream &);
    static void write(RustStream &, const UaDisableWrap &);
    static uint64_t allocation_size(const UaDisableWrap &);
};

struct FfiConverterTypeUaEnableFeature {
    static UaEnableFeature lift(RustBuffer);
    static RustBuffer lower(const UaEnableFeature &);
    static UaEnableFeature read(RustStream &);
    static void write(RustStream &, const UaEnableFeature &);
    static uint64_t allocation_size(const UaEnableFeature &);
};

struct FfiConverterTypeUaExecuteRate {
    static UaExecuteRate lift(RustBuffer);
    static RustBuffer lower(const UaExecuteRate &);
    static UaExecuteRate read(RustStream &);
    static void write(RustStream &, const UaExecuteRate &);
    static uint64_t allocation_size(const UaExecuteRate &);
};

struct FfiConverterTypeUaForceTransfer {
    static UaForceTransfer lift(RustBuffer);
    static RustBuffer lower(const UaForceTransfer &);
    static UaForceTransfer read(RustStream &);
    static void write(RustStream &, const UaForceTransfer &);
    static uint64_t allocation_size(const UaForceTransfer &);
};

struct FfiConverterTypeUaFreeze {
    static UaFreeze lift(RustBuffer);
    static RustBuffer lower(const UaFreeze &);
    static UaFreeze read(RustStream &);
    static void write(RustStream &, const UaFreeze &);
    static uint64_t allocation_size(const UaFreeze &);
};

struct FfiConverterTypeUaGrantRole {
    static UaGrantRole lift(RustBuffer);
    static RustBuffer lower(const UaGrantRole &);
    static UaGrantRole read(RustStream &);
    static void write(RustStream &, const UaGrantRole &);
    static uint64_t allocation_size(const UaGrantRole &);
};

struct FfiConverterTypeUaLine {
    static UaLine lift(RustBuffer);
    static RustBuffer lower(const UaLine &);
    static UaLine read(RustStream &);
    static void write(RustStream &, const UaLine &);
    static uint64_t allocation_size(const UaLine &);
};

struct FfiConverterTypeUaMint {
    static UaMint lift(RustBuffer);
    static RustBuffer lower(const UaMint &);
    static UaMint read(RustStream &);
    static void write(RustStream &, const UaMint &);
    static uint64_t allocation_size(const UaMint &);
};

struct FfiConverterTypeUaMintToUA {
    static UaMintToUa lift(RustBuffer);
    static RustBuffer lower(const UaMintToUa &);
    static UaMintToUa read(RustStream &);
    static void write(RustStream &, const UaMintToUa &);
    static uint64_t allocation_size(const UaMintToUa &);
};

struct FfiConverterTypeUaOperatorTransfer {
    static UaOperatorTransfer lift(RustBuffer);
    static RustBuffer lower(const UaOperatorTransfer &);
    static UaOperatorTransfer read(RustStream &);
    static void write(RustStream &, const UaOperatorTransfer &);
    static uint64_t allocation_size(const UaOperatorTransfer &);
};

struct FfiConverterTypeUaPause {
    static UaPause lift(RustBuffer);
    static RustBuffer lower(const UaPause &);
    static UaPause read(RustStream &);
    static void write(RustStream &, const UaPause &);
    static uint64_t allocation_size(const UaPause &);
};

struct FfiConverterTypeUaPqzCancelVerifier {
    static UaPqzCancelVerifier lift(RustBuffer);
    static RustBuffer lower(const UaPqzCancelVerifier &);
    static UaPqzCancelVerifier read(RustStream &);
    static void write(RustStream &, const UaPqzCancelVerifier &);
    static uint64_t allocation_size(const UaPqzCancelVerifier &);
};

struct FfiConverterTypeUaPqzRevokeVerifier {
    static UaPqzRevokeVerifier lift(RustBuffer);
    static RustBuffer lower(const UaPqzRevokeVerifier &);
    static UaPqzRevokeVerifier read(RustStream &);
    static void write(RustStream &, const UaPqzRevokeVerifier &);
    static uint64_t allocation_size(const UaPqzRevokeVerifier &);
};

struct FfiConverterTypeUaPqzSetVerifier {
    static UaPqzSetVerifier lift(RustBuffer);
    static RustBuffer lower(const UaPqzSetVerifier &);
    static UaPqzSetVerifier read(RustStream &);
    static void write(RustStream &, const UaPqzSetVerifier &);
    static uint64_t allocation_size(const UaPqzSetVerifier &);
};

struct FfiConverterTypeUaProposeRate {
    static UaProposeRate lift(RustBuffer);
    static RustBuffer lower(const UaProposeRate &);
    static UaProposeRate read(RustStream &);
    static void write(RustStream &, const UaProposeRate &);
    static uint64_t allocation_size(const UaProposeRate &);
};

struct FfiConverterTypeUaPublishClassEnv {
    static UaPublishClassEnv lift(RustBuffer);
    static RustBuffer lower(const UaPublishClassEnv &);
    static UaPublishClassEnv read(RustStream &);
    static void write(RustStream &, const UaPublishClassEnv &);
    static uint64_t allocation_size(const UaPublishClassEnv &);
};

struct FfiConverterTypeUaPublishDexEnv {
    static UaPublishDexEnv lift(RustBuffer);
    static RustBuffer lower(const UaPublishDexEnv &);
    static UaPublishDexEnv read(RustStream &);
    static void write(RustStream &, const UaPublishDexEnv &);
    static uint64_t allocation_size(const UaPublishDexEnv &);
};

struct FfiConverterTypeUaPublishTokenEnv {
    static UaPublishTokenEnv lift(RustBuffer);
    static RustBuffer lower(const UaPublishTokenEnv &);
    static UaPublishTokenEnv read(RustStream &);
    static void write(RustStream &, const UaPublishTokenEnv &);
    static uint64_t allocation_size(const UaPublishTokenEnv &);
};

struct FfiConverterTypeUaRecordOrder {
    static UaRecordOrder lift(RustBuffer);
    static RustBuffer lower(const UaRecordOrder &);
    static UaRecordOrder read(RustStream &);
    static void write(RustStream &, const UaRecordOrder &);
    static uint64_t allocation_size(const UaRecordOrder &);
};

struct FfiConverterTypeUaRenounceAdmin {
    static UaRenounceAdmin lift(RustBuffer);
    static RustBuffer lower(const UaRenounceAdmin &);
    static UaRenounceAdmin read(RustStream &);
    static void write(RustStream &, const UaRenounceAdmin &);
    static uint64_t allocation_size(const UaRenounceAdmin &);
};

struct FfiConverterTypeUaRenounceRole {
    static UaRenounceRole lift(RustBuffer);
    static RustBuffer lower(const UaRenounceRole &);
    static UaRenounceRole read(RustStream &);
    static void write(RustStream &, const UaRenounceRole &);
    static uint64_t allocation_size(const UaRenounceRole &);
};

struct FfiConverterTypeUaRevokeApproval {
    static UaRevokeApproval lift(RustBuffer);
    static RustBuffer lower(const UaRevokeApproval &);
    static UaRevokeApproval read(RustStream &);
    static void write(RustStream &, const UaRevokeApproval &);
    static uint64_t allocation_size(const UaRevokeApproval &);
};

struct FfiConverterTypeUaRevokeOrder {
    static UaRevokeOrder lift(RustBuffer);
    static RustBuffer lower(const UaRevokeOrder &);
    static UaRevokeOrder read(RustStream &);
    static void write(RustStream &, const UaRevokeOrder &);
    static uint64_t allocation_size(const UaRevokeOrder &);
};

struct FfiConverterTypeUaRevokeRole {
    static UaRevokeRole lift(RustBuffer);
    static RustBuffer lower(const UaRevokeRole &);
    static UaRevokeRole read(RustStream &);
    static void write(RustStream &, const UaRevokeRole &);
    static uint64_t allocation_size(const UaRevokeRole &);
};

struct FfiConverterTypeUaSetAllowed {
    static UaSetAllowed lift(RustBuffer);
    static RustBuffer lower(const UaSetAllowed &);
    static UaSetAllowed read(RustStream &);
    static void write(RustStream &, const UaSetAllowed &);
    static uint64_t allocation_size(const UaSetAllowed &);
};

struct FfiConverterTypeUaSetAuditorKey {
    static UaSetAuditorKey lift(RustBuffer);
    static RustBuffer lower(const UaSetAuditorKey &);
    static UaSetAuditorKey read(RustStream &);
    static void write(RustStream &, const UaSetAuditorKey &);
    static uint64_t allocation_size(const UaSetAuditorKey &);
};

struct FfiConverterTypeUaSetAuditorUA {
    static UaSetAuditorUa lift(RustBuffer);
    static RustBuffer lower(const UaSetAuditorUa &);
    static UaSetAuditorUa read(RustStream &);
    static void write(RustStream &, const UaSetAuditorUa &);
    static uint64_t allocation_size(const UaSetAuditorUa &);
};

struct FfiConverterTypeUaSetChainEntries {
    static UaSetChainEntries lift(RustBuffer);
    static RustBuffer lower(const UaSetChainEntries &);
    static UaSetChainEntries read(RustStream &);
    static void write(RustStream &, const UaSetChainEntries &);
    static uint64_t allocation_size(const UaSetChainEntries &);
};

struct FfiConverterTypeUaSetClassKindEnabled {
    static UaSetClassKindEnabled lift(RustBuffer);
    static RustBuffer lower(const UaSetClassKindEnabled &);
    static UaSetClassKindEnabled read(RustStream &);
    static void write(RustStream &, const UaSetClassKindEnabled &);
    static uint64_t allocation_size(const UaSetClassKindEnabled &);
};

struct FfiConverterTypeUaSetCompliance {
    static UaSetCompliance lift(RustBuffer);
    static RustBuffer lower(const UaSetCompliance &);
    static UaSetCompliance read(RustStream &);
    static void write(RustStream &, const UaSetCompliance &);
    static uint64_t allocation_size(const UaSetCompliance &);
};

struct FfiConverterTypeUaSetDenied {
    static UaSetDenied lift(RustBuffer);
    static RustBuffer lower(const UaSetDenied &);
    static UaSetDenied read(RustStream &);
    static void write(RustStream &, const UaSetDenied &);
    static uint64_t allocation_size(const UaSetDenied &);
};

struct FfiConverterTypeUaSetExchangeTarget {
    static UaSetExchangeTarget lift(RustBuffer);
    static RustBuffer lower(const UaSetExchangeTarget &);
    static UaSetExchangeTarget read(RustStream &);
    static void write(RustStream &, const UaSetExchangeTarget &);
    static uint64_t allocation_size(const UaSetExchangeTarget &);
};

struct FfiConverterTypeUaSetFeeSplit {
    static UaSetFeeSplit lift(RustBuffer);
    static RustBuffer lower(const UaSetFeeSplit &);
    static UaSetFeeSplit read(RustStream &);
    static void write(RustStream &, const UaSetFeeSplit &);
    static uint64_t allocation_size(const UaSetFeeSplit &);
};

struct FfiConverterTypeUaSetGrant {
    static UaSetGrant lift(RustBuffer);
    static RustBuffer lower(const UaSetGrant &);
    static UaSetGrant read(RustStream &);
    static void write(RustStream &, const UaSetGrant &);
    static uint64_t allocation_size(const UaSetGrant &);
};

struct FfiConverterTypeUaSetKycProvider {
    static UaSetKycProvider lift(RustBuffer);
    static RustBuffer lower(const UaSetKycProvider &);
    static UaSetKycProvider read(RustStream &);
    static void write(RustStream &, const UaSetKycProvider &);
    static uint64_t allocation_size(const UaSetKycProvider &);
};

struct FfiConverterTypeUaSetListedOnly {
    static UaSetListedOnly lift(RustBuffer);
    static RustBuffer lower(const UaSetListedOnly &);
    static UaSetListedOnly read(RustStream &);
    static void write(RustStream &, const UaSetListedOnly &);
    static uint64_t allocation_size(const UaSetListedOnly &);
};

struct FfiConverterTypeUaSetMarket {
    static UaSetMarket lift(RustBuffer);
    static RustBuffer lower(const UaSetMarket &);
    static UaSetMarket read(RustStream &);
    static void write(RustStream &, const UaSetMarket &);
    static uint64_t allocation_size(const UaSetMarket &);
};

struct FfiConverterTypeUaSetMaxSupply {
    static UaSetMaxSupply lift(RustBuffer);
    static RustBuffer lower(const UaSetMaxSupply &);
    static UaSetMaxSupply read(RustStream &);
    static void write(RustStream &, const UaSetMaxSupply &);
    static uint64_t allocation_size(const UaSetMaxSupply &);
};

struct FfiConverterTypeUaSetMaxWrapSupply {
    static UaSetMaxWrapSupply lift(RustBuffer);
    static RustBuffer lower(const UaSetMaxWrapSupply &);
    static UaSetMaxWrapSupply read(RustStream &);
    static void write(RustStream &, const UaSetMaxWrapSupply &);
    static uint64_t allocation_size(const UaSetMaxWrapSupply &);
};

struct FfiConverterTypeUaSetProofStore {
    static UaSetProofStore lift(RustBuffer);
    static RustBuffer lower(const UaSetProofStore &);
    static UaSetProofStore read(RustStream &);
    static void write(RustStream &, const UaSetProofStore &);
    static uint64_t allocation_size(const UaSetProofStore &);
};

struct FfiConverterTypeUaSetTaxRate {
    static UaSetTaxRate lift(RustBuffer);
    static RustBuffer lower(const UaSetTaxRate &);
    static UaSetTaxRate read(RustStream &);
    static void write(RustStream &, const UaSetTaxRate &);
    static uint64_t allocation_size(const UaSetTaxRate &);
};

struct FfiConverterTypeUaSetTaxRecipient {
    static UaSetTaxRecipient lift(RustBuffer);
    static RustBuffer lower(const UaSetTaxRecipient &);
    static UaSetTaxRecipient read(RustStream &);
    static void write(RustStream &, const UaSetTaxRecipient &);
    static uint64_t allocation_size(const UaSetTaxRecipient &);
};

struct FfiConverterTypeUaSetTokenKindEnabled {
    static UaSetTokenKindEnabled lift(RustBuffer);
    static RustBuffer lower(const UaSetTokenKindEnabled &);
    static UaSetTokenKindEnabled read(RustStream &);
    static void write(RustStream &, const UaSetTokenKindEnabled &);
    static uint64_t allocation_size(const UaSetTokenKindEnabled &);
};

struct FfiConverterTypeUaSetVerifierFee {
    static UaSetVerifierFee lift(RustBuffer);
    static RustBuffer lower(const UaSetVerifierFee &);
    static UaSetVerifierFee read(RustStream &);
    static void write(RustStream &, const UaSetVerifierFee &);
    static uint64_t allocation_size(const UaSetVerifierFee &);
};

struct FfiConverterTypeUaSetWrapLimits {
    static UaSetWrapLimits lift(RustBuffer);
    static RustBuffer lower(const UaSetWrapLimits &);
    static UaSetWrapLimits read(RustStream &);
    static void write(RustStream &, const UaSetWrapLimits &);
    static uint64_t allocation_size(const UaSetWrapLimits &);
};

struct FfiConverterTypeUaSetWrapMember {
    static UaSetWrapMember lift(RustBuffer);
    static RustBuffer lower(const UaSetWrapMember &);
    static UaSetWrapMember read(RustStream &);
    static void write(RustStream &, const UaSetWrapMember &);
    static uint64_t allocation_size(const UaSetWrapMember &);
};

struct FfiConverterTypeUaTransferAdmin {
    static UaTransferAdmin lift(RustBuffer);
    static RustBuffer lower(const UaTransferAdmin &);
    static UaTransferAdmin read(RustStream &);
    static void write(RustStream &, const UaTransferAdmin &);
    static uint64_t allocation_size(const UaTransferAdmin &);
};

struct FfiConverterTypeUaUnfreeze {
    static UaUnfreeze lift(RustBuffer);
    static RustBuffer lower(const UaUnfreeze &);
    static UaUnfreeze read(RustStream &);
    static void write(RustStream &, const UaUnfreeze &);
    static uint64_t allocation_size(const UaUnfreeze &);
};

struct FfiConverterTypeUaUnpause {
    static UaUnpause lift(RustBuffer);
    static RustBuffer lower(const UaUnpause &);
    static UaUnpause read(RustStream &);
    static void write(RustStream &, const UaUnpause &);
    static uint64_t allocation_size(const UaUnpause &);
};

struct FfiConverterTypeUnwrap {
    static Unwrap lift(RustBuffer);
    static RustBuffer lower(const Unwrap &);
    static Unwrap read(RustStream &);
    static void write(RustStream &, const Unwrap &);
    static uint64_t allocation_size(const Unwrap &);
};

struct FfiConverterTypeUnwrapLeg {
    static UnwrapLeg lift(RustBuffer);
    static RustBuffer lower(const UnwrapLeg &);
    static UnwrapLeg read(RustStream &);
    static void write(RustStream &, const UnwrapLeg &);
    static uint64_t allocation_size(const UnwrapLeg &);
};

struct FfiConverterTypeUnwrapToUa {
    static UnwrapToUa lift(RustBuffer);
    static RustBuffer lower(const UnwrapToUa &);
    static UnwrapToUa read(RustStream &);
    static void write(RustStream &, const UnwrapToUa &);
    static uint64_t allocation_size(const UnwrapToUa &);
};

struct FfiConverterTypeUpdateMsig {
    static UpdateMsig lift(RustBuffer);
    static RustBuffer lower(const UpdateMsig &);
    static UpdateMsig read(RustStream &);
    static void write(RustStream &, const UpdateMsig &);
    static uint64_t allocation_size(const UpdateMsig &);
};

struct FfiConverterTypeWebAuthnArgs {
    static WebAuthnArgs lift(RustBuffer);
    static RustBuffer lower(const WebAuthnArgs &);
    static WebAuthnArgs read(RustStream &);
    static void write(RustStream &, const WebAuthnArgs &);
    static uint64_t allocation_size(const WebAuthnArgs &);
};

struct FfiConverterTypeWrap {
    static Wrap lift(RustBuffer);
    static RustBuffer lower(const Wrap &);
    static Wrap read(RustStream &);
    static void write(RustStream &, const Wrap &);
    static uint64_t allocation_size(const Wrap &);
};

struct FfiConverterTypeWrapLeg {
    static WrapLeg lift(RustBuffer);
    static RustBuffer lower(const WrapLeg &);
    static WrapLeg read(RustStream &);
    static void write(RustStream &, const WrapLeg &);
    static uint64_t allocation_size(const WrapLeg &);
};

struct FfiConverterTypeWrapOrder {
    static WrapOrder lift(RustBuffer);
    static RustBuffer lower(const WrapOrder &);
    static WrapOrder read(RustStream &);
    static void write(RustStream &, const WrapOrder &);
    static uint64_t allocation_size(const WrapOrder &);
};

struct FfiConverterTypeWrapOrderTerms {
    static WrapOrderTerms lift(RustBuffer);
    static RustBuffer lower(const WrapOrderTerms &);
    static WrapOrderTerms read(RustStream &);
    static void write(RustStream &, const WrapOrderTerms &);
    static uint64_t allocation_size(const WrapOrderTerms &);
};

struct FfiConverterTypeWrapToUa {
    static WrapToUa lift(RustBuffer);
    static RustBuffer lower(const WrapToUa &);
    static WrapToUa read(RustStream &);
    static void write(RustStream &, const WrapToUa &);
    static uint64_t allocation_size(const WrapToUa &);
};

struct FfiConverterTypeZetherBalance {
    static ZetherBalance lift(RustBuffer);
    static RustBuffer lower(const ZetherBalance &);
    static ZetherBalance read(RustStream &);
    static void write(RustStream &, const ZetherBalance &);
    static uint64_t allocation_size(const ZetherBalance &);
};

struct FfiConverterTypeZetherBalanceRequest {
    static ZetherBalanceRequest lift(RustBuffer);
    static RustBuffer lower(const ZetherBalanceRequest &);
    static ZetherBalanceRequest read(RustStream &);
    static void write(RustStream &, const ZetherBalanceRequest &);
    static uint64_t allocation_size(const ZetherBalanceRequest &);
};

struct FfiConverterTypeZetherKeyInfo {
    static ZetherKeyInfo lift(RustBuffer);
    static RustBuffer lower(const ZetherKeyInfo &);
    static ZetherKeyInfo read(RustStream &);
    static void write(RustStream &, const ZetherKeyInfo &);
    static uint64_t allocation_size(const ZetherKeyInfo &);
};

struct FfiConverterTypeZetherLeg {
    static ZetherLeg lift(RustBuffer);
    static RustBuffer lower(const ZetherLeg &);
    static ZetherLeg read(RustStream &);
    static void write(RustStream &, const ZetherLeg &);
    static uint64_t allocation_size(const ZetherLeg &);
};

struct FfiConverterTypeZetherOwnerRollOver {
    static ZetherOwnerRollOver lift(RustBuffer);
    static RustBuffer lower(const ZetherOwnerRollOver &);
    static ZetherOwnerRollOver read(RustStream &);
    static void write(RustStream &, const ZetherOwnerRollOver &);
    static uint64_t allocation_size(const ZetherOwnerRollOver &);
};

struct FfiConverterTypeZetherOwnerSetMode {
    static ZetherOwnerSetMode lift(RustBuffer);
    static RustBuffer lower(const ZetherOwnerSetMode &);
    static ZetherOwnerSetMode read(RustStream &);
    static void write(RustStream &, const ZetherOwnerSetMode &);
    static uint64_t allocation_size(const ZetherOwnerSetMode &);
};

struct FfiConverterTypeZetherRollOver {
    static ZetherRollOver lift(RustBuffer);
    static RustBuffer lower(const ZetherRollOver &);
    static ZetherRollOver read(RustStream &);
    static void write(RustStream &, const ZetherRollOver &);
    static uint64_t allocation_size(const ZetherRollOver &);
};

struct FfiConverterTypeZetherRollOverBatch {
    static ZetherRollOverBatch lift(RustBuffer);
    static RustBuffer lower(const ZetherRollOverBatch &);
    static ZetherRollOverBatch read(RustStream &);
    static void write(RustStream &, const ZetherRollOverBatch &);
    static uint64_t allocation_size(const ZetherRollOverBatch &);
};

struct FfiConverterTypeZetherShield {
    static ZetherShield lift(RustBuffer);
    static RustBuffer lower(const ZetherShield &);
    static ZetherShield read(RustStream &);
    static void write(RustStream &, const ZetherShield &);
    static uint64_t allocation_size(const ZetherShield &);
};

struct FfiConverterTypeZetherTransfer {
    static ZetherTransfer lift(RustBuffer);
    static RustBuffer lower(const ZetherTransfer &);
    static ZetherTransfer read(RustStream &);
    static void write(RustStream &, const ZetherTransfer &);
    static uint64_t allocation_size(const ZetherTransfer &);
};

struct FfiConverterTypeZetherTransferMulti {
    static ZetherTransferMulti lift(RustBuffer);
    static RustBuffer lower(const ZetherTransferMulti &);
    static ZetherTransferMulti read(RustStream &);
    static void write(RustStream &, const ZetherTransferMulti &);
    static uint64_t allocation_size(const ZetherTransferMulti &);
};

struct FfiConverterTypeZetherUnshield {
    static ZetherUnshield lift(RustBuffer);
    static RustBuffer lower(const ZetherUnshield &);
    static ZetherUnshield read(RustStream &);
    static void write(RustStream &, const ZetherUnshield &);
    static uint64_t allocation_size(const ZetherUnshield &);
};

struct FfiConverterTypeZetherUnshieldUnwrap {
    static ZetherUnshieldUnwrap lift(RustBuffer);
    static RustBuffer lower(const ZetherUnshieldUnwrap &);
    static ZetherUnshieldUnwrap read(RustStream &);
    static void write(RustStream &, const ZetherUnshieldUnwrap &);
    static uint64_t allocation_size(const ZetherUnshieldUnwrap &);
};

struct FfiConverterTypeZetherWrapShield {
    static ZetherWrapShield lift(RustBuffer);
    static RustBuffer lower(const ZetherWrapShield &);
    static ZetherWrapShield read(RustStream &);
    static void write(RustStream &, const ZetherWrapShield &);
    static uint64_t allocation_size(const ZetherWrapShield &);
};
struct FfiConverterAccountRow {
    static AccountRow lift(RustBuffer);
    static RustBuffer lower(const AccountRow &);
    static AccountRow read(RustStream &);
    static void write(RustStream &, const AccountRow &);
    static uint64_t allocation_size(const AccountRow &);
};

struct FfiConverterAuthError {
    static std::shared_ptr<AuthError> lift(RustBuffer buf);
    static RustBuffer lower(const AuthError &);
    static std::shared_ptr<AuthError> read(RustStream &stream);
    static void write(RustStream &stream, const AuthError &);
    static uint64_t allocation_size(const AuthError &);
};
struct FfiConverterClass {
    static Class lift(RustBuffer);
    static RustBuffer lower(const Class &);
    static Class read(RustStream &);
    static void write(RustStream &, const Class &);
    static uint64_t allocation_size(const Class &);
};
struct FfiConverterDelaySentence {
    static DelaySentence lift(RustBuffer);
    static RustBuffer lower(const DelaySentence &);
    static DelaySentence read(RustStream &);
    static void write(RustStream &, const DelaySentence &);
    static uint64_t allocation_size(const DelaySentence &);
};
struct FfiConverterEndpointAuth {
    static EndpointAuth lift(RustBuffer);
    static RustBuffer lower(const EndpointAuth &);
    static EndpointAuth read(RustStream &);
    static void write(RustStream &, const EndpointAuth &);
    static uint64_t allocation_size(const EndpointAuth &);
};
struct FfiConverterEvent {
    static Event lift(RustBuffer);
    static RustBuffer lower(const Event &);
    static Event read(RustStream &);
    static void write(RustStream &, const Event &);
    static uint64_t allocation_size(const Event &);
};
struct FfiConverterExecuteCall {
    static ExecuteCall lift(RustBuffer);
    static RustBuffer lower(const ExecuteCall &);
    static ExecuteCall read(RustStream &);
    static void write(RustStream &, const ExecuteCall &);
    static uint64_t allocation_size(const ExecuteCall &);
};
struct FfiConverterFamily {
    static Family lift(RustBuffer);
    static RustBuffer lower(const Family &);
    static Family read(RustStream &);
    static void write(RustStream &, const Family &);
    static uint64_t allocation_size(const Family &);
};
struct FfiConverterFamilyParams {
    static FamilyParams lift(RustBuffer);
    static RustBuffer lower(const FamilyParams &);
    static FamilyParams read(RustStream &);
    static void write(RustStream &, const FamilyParams &);
    static uint64_t allocation_size(const FamilyParams &);
};
struct FfiConverterFinality {
    static Finality lift(RustBuffer);
    static RustBuffer lower(const Finality &);
    static Finality read(RustStream &);
    static void write(RustStream &, const Finality &);
    static uint64_t allocation_size(const Finality &);
};
struct FfiConverterGasFrom {
    static GasFrom lift(RustBuffer);
    static RustBuffer lower(const GasFrom &);
    static GasFrom read(RustStream &);
    static void write(RustStream &, const GasFrom &);
    static uint64_t allocation_size(const GasFrom &);
};
struct FfiConverterHolderKind {
    static HolderKind lift(RustBuffer);
    static RustBuffer lower(const HolderKind &);
    static HolderKind read(RustStream &);
    static void write(RustStream &, const HolderKind &);
    static uint64_t allocation_size(const HolderKind &);
};
struct FfiConverterInFlight {
    static InFlight lift(RustBuffer);
    static RustBuffer lower(const InFlight &);
    static InFlight read(RustStream &);
    static void write(RustStream &, const InFlight &);
    static uint64_t allocation_size(const InFlight &);
};
struct FfiConverterKeyRef {
    static KeyRef lift(RustBuffer);
    static RustBuffer lower(const KeyRef &);
    static KeyRef read(RustStream &);
    static void write(RustStream &, const KeyRef &);
    static uint64_t allocation_size(const KeyRef &);
};
struct FfiConverterL1Fee {
    static L1Fee lift(RustBuffer);
    static RustBuffer lower(const L1Fee &);
    static L1Fee read(RustStream &);
    static void write(RustStream &, const L1Fee &);
    static uint64_t allocation_size(const L1Fee &);
};
struct FfiConverterMsigSlotValue {
    static MsigSlotValue lift(RustBuffer);
    static RustBuffer lower(const MsigSlotValue &);
    static MsigSlotValue read(RustStream &);
    static void write(RustStream &, const MsigSlotValue &);
    static uint64_t allocation_size(const MsigSlotValue &);
};
struct FfiConverterOpState {
    static OpState lift(RustBuffer);
    static RustBuffer lower(const OpState &);
    static OpState read(RustStream &);
    static void write(RustStream &, const OpState &);
    static uint64_t allocation_size(const OpState &);
};
struct FfiConverterPayBody {
    static PayBody lift(RustBuffer);
    static RustBuffer lower(const PayBody &);
    static PayBody read(RustStream &);
    static void write(RustStream &, const PayBody &);
    static uint64_t allocation_size(const PayBody &);
};
struct FfiConverterPolicy {
    static Policy lift(RustBuffer);
    static RustBuffer lower(const Policy &);
    static Policy read(RustStream &);
    static void write(RustStream &, const Policy &);
    static uint64_t allocation_size(const Policy &);
};
struct FfiConverterPresence {
    static Presence lift(RustBuffer);
    static RustBuffer lower(const Presence &);
    static Presence read(RustStream &);
    static void write(RustStream &, const Presence &);
    static uint64_t allocation_size(const Presence &);
};
struct FfiConverterRescueOp {
    static RescueOp lift(RustBuffer);
    static RustBuffer lower(const RescueOp &);
    static RescueOp read(RustStream &);
    static void write(RustStream &, const RescueOp &);
    static uint64_t allocation_size(const RescueOp &);
};

struct FfiConverterSdkError {
    static std::shared_ptr<SdkError> lift(RustBuffer buf);
    static RustBuffer lower(const SdkError &);
    static std::shared_ptr<SdkError> read(RustStream &stream);
    static void write(RustStream &stream, const SdkError &);
    static uint64_t allocation_size(const SdkError &);
};
struct FfiConverterSlotKey {
    static SlotKey lift(RustBuffer);
    static RustBuffer lower(const SlotKey &);
    static SlotKey read(RustStream &);
    static void write(RustStream &, const SlotKey &);
    static uint64_t allocation_size(const SlotKey &);
};
struct FfiConverterSmartCall {
    static SmartCall lift(RustBuffer);
    static RustBuffer lower(const SmartCall &);
    static SmartCall read(RustStream &);
    static void write(RustStream &, const SmartCall &);
    static uint64_t allocation_size(const SmartCall &);
};
struct FfiConverterSource {
    static Source lift(RustBuffer);
    static RustBuffer lower(const Source &);
    static Source read(RustStream &);
    static void write(RustStream &, const Source &);
    static uint64_t allocation_size(const Source &);
};

struct FfiConverterStoreError {
    static std::shared_ptr<StoreError> lift(RustBuffer buf);
    static RustBuffer lower(const StoreError &);
    static std::shared_ptr<StoreError> read(RustStream &stream);
    static void write(RustStream &stream, const StoreError &);
    static uint64_t allocation_size(const StoreError &);
};
struct FfiConverterSubmitPath {
    static SubmitPath lift(RustBuffer);
    static RustBuffer lower(const SubmitPath &);
    static SubmitPath read(RustStream &);
    static void write(RustStream &, const SubmitPath &);
    static uint64_t allocation_size(const SubmitPath &);
};
struct FfiConverterUnlock {
    static Unlock lift(RustBuffer);
    static RustBuffer lower(const Unlock &);
    static Unlock read(RustStream &);
    static void write(RustStream &, const Unlock &);
    static uint64_t allocation_size(const Unlock &);
};
struct FfiConverterOptionalUInt8 {
    static std::optional<uint8_t> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<uint8_t>& val);
    static std::optional<uint8_t> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<uint8_t>& value);
    static uint64_t allocation_size(const std::optional<uint8_t> &val);
};
struct FfiConverterOptionalUInt16 {
    static std::optional<uint16_t> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<uint16_t>& val);
    static std::optional<uint16_t> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<uint16_t>& value);
    static uint64_t allocation_size(const std::optional<uint16_t> &val);
};
struct FfiConverterOptionalUInt32 {
    static std::optional<uint32_t> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<uint32_t>& val);
    static std::optional<uint32_t> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<uint32_t>& value);
    static uint64_t allocation_size(const std::optional<uint32_t> &val);
};
struct FfiConverterOptionalUInt64 {
    static std::optional<uint64_t> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<uint64_t>& val);
    static std::optional<uint64_t> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<uint64_t>& value);
    static uint64_t allocation_size(const std::optional<uint64_t> &val);
};
struct FfiConverterOptionalString {
    static std::optional<std::string> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<std::string>& val);
    static std::optional<std::string> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<std::string>& value);
    static uint64_t allocation_size(const std::optional<std::string> &val);
};
struct FfiConverterOptionalBytes {
    static std::optional<std::vector<uint8_t>> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<std::vector<uint8_t>>& val);
    static std::optional<std::vector<uint8_t>> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<std::vector<uint8_t>>& value);
    static uint64_t allocation_size(const std::optional<std::vector<uint8_t>> &val);
};
struct FfiConverterOptionalCancelToken {
    static std::shared_ptr<CancelToken> lift(RustBuffer buf);
    static RustBuffer lower(const std::shared_ptr<CancelToken>& val);
    static std::shared_ptr<CancelToken> read(RustStream &stream);
    static void write(RustStream &stream, const std::shared_ptr<CancelToken>& value);
    static uint64_t allocation_size(const std::shared_ptr<CancelToken> &val);
};
struct FfiConverterOptionalRegistryWrite {
    static std::shared_ptr<RegistryWrite> lift(RustBuffer buf);
    static RustBuffer lower(const std::shared_ptr<RegistryWrite>& val);
    static std::shared_ptr<RegistryWrite> read(RustStream &stream);
    static void write(RustStream &stream, const std::shared_ptr<RegistryWrite>& value);
    static uint64_t allocation_size(const std::shared_ptr<RegistryWrite> &val);
};
struct FfiConverterOptionalSyncAuthenticator {
    static std::shared_ptr<SyncAuthenticator> lift(RustBuffer buf);
    static RustBuffer lower(const std::shared_ptr<SyncAuthenticator>& val);
    static std::shared_ptr<SyncAuthenticator> read(RustStream &stream);
    static void write(RustStream &stream, const std::shared_ptr<SyncAuthenticator>& value);
    static uint64_t allocation_size(const std::shared_ptr<SyncAuthenticator> &val);
};
struct FfiConverterOptionalTypeConfirmRemoveUnbacked {
    static std::optional<ConfirmRemoveUnbacked> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<ConfirmRemoveUnbacked>& val);
    static std::optional<ConfirmRemoveUnbacked> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<ConfirmRemoveUnbacked>& value);
    static uint64_t allocation_size(const std::optional<ConfirmRemoveUnbacked> &val);
};
struct FfiConverterOptionalTypeCursor {
    static std::optional<Cursor> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<Cursor>& val);
    static std::optional<Cursor> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<Cursor>& value);
    static uint64_t allocation_size(const std::optional<Cursor> &val);
};
struct FfiConverterOptionalTypeGasPerByte {
    static std::optional<GasPerByte> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<GasPerByte>& val);
    static std::optional<GasPerByte> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<GasPerByte>& value);
    static uint64_t allocation_size(const std::optional<GasPerByte> &val);
};
struct FfiConverterOptionalTypeGasPerItem {
    static std::optional<GasPerItem> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<GasPerItem>& val);
    static std::optional<GasPerItem> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<GasPerItem>& value);
    static uint64_t allocation_size(const std::optional<GasPerItem> &val);
};
struct FfiConverterOptionalTypeGasSources {
    static std::optional<GasSources> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<GasSources>& val);
    static std::optional<GasSources> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<GasSources>& value);
    static uint64_t allocation_size(const std::optional<GasSources> &val);
};
struct FfiConverterOptionalTypeKemRecord {
    static std::optional<KemRecord> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<KemRecord>& val);
    static std::optional<KemRecord> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<KemRecord>& value);
    static uint64_t allocation_size(const std::optional<KemRecord> &val);
};
struct FfiConverterOptionalTypeKeyPolicy {
    static std::optional<KeyPolicy> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<KeyPolicy>& val);
    static std::optional<KeyPolicy> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<KeyPolicy>& value);
    static uint64_t allocation_size(const std::optional<KeyPolicy> &val);
};
struct FfiConverterOptionalTypeRegistrationGas {
    static std::optional<RegistrationGas> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<RegistrationGas>& val);
    static std::optional<RegistrationGas> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<RegistrationGas>& value);
    static uint64_t allocation_size(const std::optional<RegistrationGas> &val);
};
struct FfiConverterOptionalTypeStoredItem {
    static std::optional<StoredItem> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<StoredItem>& val);
    static std::optional<StoredItem> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<StoredItem>& value);
    static uint64_t allocation_size(const std::optional<StoredItem> &val);
};
struct FfiConverterOptionalTypeWebAuthnArgs {
    static std::optional<WebAuthnArgs> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<WebAuthnArgs>& val);
    static std::optional<WebAuthnArgs> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<WebAuthnArgs>& value);
    static uint64_t allocation_size(const std::optional<WebAuthnArgs> &val);
};
struct FfiConverterOptionalEndpointAuth {
    static std::optional<EndpointAuth> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<EndpointAuth>& val);
    static std::optional<EndpointAuth> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<EndpointAuth>& value);
    static uint64_t allocation_size(const std::optional<EndpointAuth> &val);
};
struct FfiConverterOptionalEvent {
    static std::optional<Event> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<Event>& val);
    static std::optional<Event> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<Event>& value);
    static uint64_t allocation_size(const std::optional<Event> &val);
};
struct FfiConverterOptionalFamilyParams {
    static std::optional<FamilyParams> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<FamilyParams>& val);
    static std::optional<FamilyParams> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<FamilyParams>& value);
    static uint64_t allocation_size(const std::optional<FamilyParams> &val);
};
struct FfiConverterOptionalHolderKind {
    static std::optional<HolderKind> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<HolderKind>& val);
    static std::optional<HolderKind> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<HolderKind>& value);
    static uint64_t allocation_size(const std::optional<HolderKind> &val);
};
struct FfiConverterOptionalKeyRef {
    static std::optional<KeyRef> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<KeyRef>& val);
    static std::optional<KeyRef> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<KeyRef>& value);
    static uint64_t allocation_size(const std::optional<KeyRef> &val);
};
struct FfiConverterOptionalL1Fee {
    static std::optional<L1Fee> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<L1Fee>& val);
    static std::optional<L1Fee> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<L1Fee>& value);
    static uint64_t allocation_size(const std::optional<L1Fee> &val);
};
struct FfiConverterOptionalTypeAllowOpaqueCall {
    static std::optional<AllowOpaqueCall> lift(RustBuffer buf);
    static RustBuffer lower(const std::optional<AllowOpaqueCall>& val);
    static std::optional<AllowOpaqueCall> read(RustStream &stream);
    static void write(RustStream &stream, const std::optional<AllowOpaqueCall>& value);
    static uint64_t allocation_size(const std::optional<AllowOpaqueCall> &val);
};

struct FfiConverterSequenceUInt16 {
    static std::vector<uint16_t> lift(RustBuffer);
    static RustBuffer lower(const std::vector<uint16_t> &);
    static std::vector<uint16_t> read(RustStream &);
    static void write(RustStream &, const std::vector<uint16_t> &);
    static uint64_t allocation_size(const std::vector<uint16_t> &);
};

struct FfiConverterSequenceUInt32 {
    static std::vector<uint32_t> lift(RustBuffer);
    static RustBuffer lower(const std::vector<uint32_t> &);
    static std::vector<uint32_t> read(RustStream &);
    static void write(RustStream &, const std::vector<uint32_t> &);
    static uint64_t allocation_size(const std::vector<uint32_t> &);
};

struct FfiConverterSequenceString {
    static std::vector<std::string> lift(RustBuffer);
    static RustBuffer lower(const std::vector<std::string> &);
    static std::vector<std::string> read(RustStream &);
    static void write(RustStream &, const std::vector<std::string> &);
    static uint64_t allocation_size(const std::vector<std::string> &);
};

struct FfiConverterSequenceBytes {
    static std::vector<std::vector<uint8_t>> lift(RustBuffer);
    static RustBuffer lower(const std::vector<std::vector<uint8_t>> &);
    static std::vector<std::vector<uint8_t>> read(RustStream &);
    static void write(RustStream &, const std::vector<std::vector<uint8_t>> &);
    static uint64_t allocation_size(const std::vector<std::vector<uint8_t>> &);
};

struct FfiConverterSequenceRegistryWrite {
    static std::vector<std::shared_ptr<RegistryWrite>> lift(RustBuffer);
    static RustBuffer lower(const std::vector<std::shared_ptr<RegistryWrite>> &);
    static std::vector<std::shared_ptr<RegistryWrite>> read(RustStream &);
    static void write(RustStream &, const std::vector<std::shared_ptr<RegistryWrite>> &);
    static uint64_t allocation_size(const std::vector<std::shared_ptr<RegistryWrite>> &);
};

struct FfiConverterSequenceTypeAccountInfo {
    static std::vector<AccountInfo> lift(RustBuffer);
    static RustBuffer lower(const std::vector<AccountInfo> &);
    static std::vector<AccountInfo> read(RustStream &);
    static void write(RustStream &, const std::vector<AccountInfo> &);
    static uint64_t allocation_size(const std::vector<AccountInfo> &);
};

struct FfiConverterSequenceTypeBlsMultiPart {
    static std::vector<BlsMultiPart> lift(RustBuffer);
    static RustBuffer lower(const std::vector<BlsMultiPart> &);
    static std::vector<BlsMultiPart> read(RustStream &);
    static void write(RustStream &, const std::vector<BlsMultiPart> &);
    static uint64_t allocation_size(const std::vector<BlsMultiPart> &);
};

struct FfiConverterSequenceTypeChainProfile {
    static std::vector<ChainProfile> lift(RustBuffer);
    static RustBuffer lower(const std::vector<ChainProfile> &);
    static std::vector<ChainProfile> read(RustStream &);
    static void write(RustStream &, const std::vector<ChainProfile> &);
    static uint64_t allocation_size(const std::vector<ChainProfile> &);
};

struct FfiConverterSequenceTypeEndpointConfig {
    static std::vector<EndpointConfig> lift(RustBuffer);
    static RustBuffer lower(const std::vector<EndpointConfig> &);
    static std::vector<EndpointConfig> read(RustStream &);
    static void write(RustStream &, const std::vector<EndpointConfig> &);
    static uint64_t allocation_size(const std::vector<EndpointConfig> &);
};

struct FfiConverterSequenceTypeGasBase {
    static std::vector<GasBase> lift(RustBuffer);
    static RustBuffer lower(const std::vector<GasBase> &);
    static std::vector<GasBase> read(RustStream &);
    static void write(RustStream &, const std::vector<GasBase> &);
    static uint64_t allocation_size(const std::vector<GasBase> &);
};

struct FfiConverterSequenceTypeGasTable {
    static std::vector<GasTable> lift(RustBuffer);
    static RustBuffer lower(const std::vector<GasTable> &);
    static std::vector<GasTable> read(RustStream &);
    static void write(RustStream &, const std::vector<GasTable> &);
    static uint64_t allocation_size(const std::vector<GasTable> &);
};

struct FfiConverterSequenceTypeGasVerify {
    static std::vector<GasVerify> lift(RustBuffer);
    static RustBuffer lower(const std::vector<GasVerify> &);
    static std::vector<GasVerify> read(RustStream &);
    static void write(RustStream &, const std::vector<GasVerify> &);
    static uint64_t allocation_size(const std::vector<GasVerify> &);
};

struct FfiConverterSequenceTypeHistoryItem {
    static std::vector<HistoryItem> lift(RustBuffer);
    static RustBuffer lower(const std::vector<HistoryItem> &);
    static std::vector<HistoryItem> read(RustStream &);
    static void write(RustStream &, const std::vector<HistoryItem> &);
    static uint64_t allocation_size(const std::vector<HistoryItem> &);
};

struct FfiConverterSequenceTypeLiquidityToken {
    static std::vector<LiquidityToken> lift(RustBuffer);
    static RustBuffer lower(const std::vector<LiquidityToken> &);
    static std::vector<LiquidityToken> read(RustStream &);
    static void write(RustStream &, const std::vector<LiquidityToken> &);
    static uint64_t allocation_size(const std::vector<LiquidityToken> &);
};

struct FfiConverterSequenceTypeListedDex {
    static std::vector<ListedDex> lift(RustBuffer);
    static RustBuffer lower(const std::vector<ListedDex> &);
    static std::vector<ListedDex> read(RustStream &);
    static void write(RustStream &, const std::vector<ListedDex> &);
    static uint64_t allocation_size(const std::vector<ListedDex> &);
};

struct FfiConverterSequenceTypeListedToken {
    static std::vector<ListedToken> lift(RustBuffer);
    static RustBuffer lower(const std::vector<ListedToken> &);
    static std::vector<ListedToken> read(RustStream &);
    static void write(RustStream &, const std::vector<ListedToken> &);
    static uint64_t allocation_size(const std::vector<ListedToken> &);
};

struct FfiConverterSequenceTypeMsigLeafValue {
    static std::vector<MsigLeafValue> lift(RustBuffer);
    static RustBuffer lower(const std::vector<MsigLeafValue> &);
    static std::vector<MsigLeafValue> read(RustStream &);
    static void write(RustStream &, const std::vector<MsigLeafValue> &);
    static uint64_t allocation_size(const std::vector<MsigLeafValue> &);
};

struct FfiConverterSequenceTypeMsigMemberArgs {
    static std::vector<MsigMemberArgs> lift(RustBuffer);
    static RustBuffer lower(const std::vector<MsigMemberArgs> &);
    static std::vector<MsigMemberArgs> read(RustStream &);
    static void write(RustStream &, const std::vector<MsigMemberArgs> &);
    static uint64_t allocation_size(const std::vector<MsigMemberArgs> &);
};

struct FfiConverterSequenceTypeMsigSlotState {
    static std::vector<MsigSlotState> lift(RustBuffer);
    static RustBuffer lower(const std::vector<MsigSlotState> &);
    static std::vector<MsigSlotState> read(RustStream &);
    static void write(RustStream &, const std::vector<MsigSlotState> &);
    static uint64_t allocation_size(const std::vector<MsigSlotState> &);
};

struct FfiConverterSequenceTypeNativeCap {
    static std::vector<NativeCap> lift(RustBuffer);
    static RustBuffer lower(const std::vector<NativeCap> &);
    static std::vector<NativeCap> read(RustStream &);
    static void write(RustStream &, const std::vector<NativeCap> &);
    static uint64_t allocation_size(const std::vector<NativeCap> &);
};

struct FfiConverterSequenceTypeOpItem {
    static std::vector<OpItem> lift(RustBuffer);
    static RustBuffer lower(const std::vector<OpItem> &);
    static std::vector<OpItem> read(RustStream &);
    static void write(RustStream &, const std::vector<OpItem> &);
    static uint64_t allocation_size(const std::vector<OpItem> &);
};

struct FfiConverterSequenceTypePositionReader {
    static std::vector<PositionReader> lift(RustBuffer);
    static RustBuffer lower(const std::vector<PositionReader> &);
    static std::vector<PositionReader> read(RustStream &);
    static void write(RustStream &, const std::vector<PositionReader> &);
    static uint64_t allocation_size(const std::vector<PositionReader> &);
};

struct FfiConverterSequenceTypePqzBalance {
    static std::vector<PqzBalance> lift(RustBuffer);
    static RustBuffer lower(const std::vector<PqzBalance> &);
    static std::vector<PqzBalance> read(RustStream &);
    static void write(RustStream &, const std::vector<PqzBalance> &);
    static uint64_t allocation_size(const std::vector<PqzBalance> &);
};

struct FfiConverterSequenceTypePqzLeg {
    static std::vector<PqzLeg> lift(RustBuffer);
    static RustBuffer lower(const std::vector<PqzLeg> &);
    static std::vector<PqzLeg> read(RustStream &);
    static void write(RustStream &, const std::vector<PqzLeg> &);
    static uint64_t allocation_size(const std::vector<PqzLeg> &);
};

struct FfiConverterSequenceTypeReviewField {
    static std::vector<ReviewField> lift(RustBuffer);
    static RustBuffer lower(const std::vector<ReviewField> &);
    static std::vector<ReviewField> read(RustStream &);
    static void write(RustStream &, const std::vector<ReviewField> &);
    static uint64_t allocation_size(const std::vector<ReviewField> &);
};

struct FfiConverterSequenceTypeSeedInfo {
    static std::vector<SeedInfo> lift(RustBuffer);
    static RustBuffer lower(const std::vector<SeedInfo> &);
    static std::vector<SeedInfo> read(RustStream &);
    static void write(RustStream &, const std::vector<SeedInfo> &);
    static uint64_t allocation_size(const std::vector<SeedInfo> &);
};

struct FfiConverterSequenceTypeStepGas {
    static std::vector<StepGas> lift(RustBuffer);
    static RustBuffer lower(const std::vector<StepGas> &);
    static std::vector<StepGas> read(RustStream &);
    static void write(RustStream &, const std::vector<StepGas> &);
    static uint64_t allocation_size(const std::vector<StepGas> &);
};

struct FfiConverterSequenceTypeTokenBalance {
    static std::vector<TokenBalance> lift(RustBuffer);
    static RustBuffer lower(const std::vector<TokenBalance> &);
    static std::vector<TokenBalance> read(RustStream &);
    static void write(RustStream &, const std::vector<TokenBalance> &);
    static uint64_t allocation_size(const std::vector<TokenBalance> &);
};

struct FfiConverterSequenceTypeTokenInfo {
    static std::vector<TokenInfo> lift(RustBuffer);
    static RustBuffer lower(const std::vector<TokenInfo> &);
    static std::vector<TokenInfo> read(RustStream &);
    static void write(RustStream &, const std::vector<TokenInfo> &);
    static uint64_t allocation_size(const std::vector<TokenInfo> &);
};

struct FfiConverterSequenceTypeZetherLeg {
    static std::vector<ZetherLeg> lift(RustBuffer);
    static RustBuffer lower(const std::vector<ZetherLeg> &);
    static std::vector<ZetherLeg> read(RustStream &);
    static void write(RustStream &, const std::vector<ZetherLeg> &);
    static uint64_t allocation_size(const std::vector<ZetherLeg> &);
};

struct FfiConverterSequenceAccountRow {
    static std::vector<AccountRow> lift(RustBuffer);
    static RustBuffer lower(const std::vector<AccountRow> &);
    static std::vector<AccountRow> read(RustStream &);
    static void write(RustStream &, const std::vector<AccountRow> &);
    static uint64_t allocation_size(const std::vector<AccountRow> &);
};

struct FfiConverterSequenceDelaySentence {
    static std::vector<DelaySentence> lift(RustBuffer);
    static RustBuffer lower(const std::vector<DelaySentence> &);
    static std::vector<DelaySentence> read(RustStream &);
    static void write(RustStream &, const std::vector<DelaySentence> &);
    static uint64_t allocation_size(const std::vector<DelaySentence> &);
};

struct FfiConverterSequenceTypeMsigSlot {
    static std::vector<MsigSlot> lift(RustBuffer);
    static RustBuffer lower(const std::vector<MsigSlot> &);
    static std::vector<MsigSlot> read(RustStream &);
    static void write(RustStream &, const std::vector<MsigSlot> &);
    static uint64_t allocation_size(const std::vector<MsigSlot> &);
};
typedef struct FfiConverterBool FfiConverterTypeAllowOpaqueCall;
typedef struct FfiConverterMsigSlotValue FfiConverterTypeMsigSlot;
typedef struct FfiConverterString FfiConverterTypeSecret;
typedef struct FfiConverterString FfiConverterTypeValue;
} // namespace uniffi

/**
 * The account rows' JSON (the keystore's form).
 */
std::string accounts_json(const std::vector<AccountRow> &rows);
/**
 * The binding surface's version this library was built with (spec §16.3).
 */
uint32_t api_version();
/**
 * This library's feature bits (spec §3.3).
 */
uint64_t features();
/**
 * No gas rows.
 */
GasRows gas_rows_default();
/**
 * A gas table file (spec §13.3), parsed and checked.
 */
GasTable gas_table_parse(const std::string &text);
/**
 * Whether `s` is a UUID v4 (a seed's or an account's id).
 */
bool is_uuid4(const std::string &s);
/**
 * Whether `label` is a valid seed label (spec §6.1).
 */
bool label_ok(const std::string &label);
/**
 * The default limits (spec §4).
 */
Limits limits_default();
/**
 * An `msig` structure: members sorted by id, the threshold checked (spec §7).
 */
MsigStructureArgs msig_structure(const std::vector<MsigMemberArgs> &members, uint16_t threshold);
/**
 * An `msig` structure's UA.
 */
std::string msig_structure_ua(const MsigStructureArgs &args);
/**
 * Whether `label` is a valid new seed label (NFC, spec §6.1).
 */
bool new_label_ok(const std::string &label);
/**
 * Whether an operation's state is final.
 */
bool op_state_is_terminal(OpState state);
/**
 * No registration attributes (no PQZ key, no KEM key).
 */
RegisterAttrs register_attrs_default();
/**
 * A registration blob from its JSON (spec §7.1).
 */
RegistrationBlob registration_blob_from_json(const std::string &text);
/**
 * A registration blob's JSON (spec §7.1).
 */
std::string registration_blob_to_json(const RegistrationBlob &blob);
/**
 * The revision of an item's bytes: its top-level JSON `rev`, else `u64::MAX`.
 */
uint64_t rev_of(const std::vector<uint8_t> &bytes);
/**
 * A secret's id for the C copy calls.
 */
uint64_t secret_id(const std::shared_ptr<SecretBytes> &s);
/**
 * A secret's length in bytes.
 */
uint32_t secret_len(const std::shared_ptr<SecretBytes> &s);
/**
 * A new secret of `len` zero bytes (16 MiB at most); its bytes move only through the C copy calls by [`secret_id`].
 */
std::shared_ptr<SecretBytes> secret_new(uint32_t len);
/**
 * A signed operation's hand-off blob from its JSON (spec §27.5 (c)).
 */
SignedOpBlob signed_op_blob_from_json(const std::string &text);
/**
 * A hand-off blob's JSON (spec §27.5 (c)).
 */
std::string signed_op_blob_to_json(const SignedOpBlob &blob);
/**
 * A `SmartKeyAccount`'s address before its deployment (spec §7).
 */
std::string smart_account_address(const std::string &factory, const std::string &implementation, const SubjectKeyArgs &first_key, const std::string &guardian);
/**
 * The default store policy of an item (spec §6.9).
 */
StorePolicy store_policy_default();
/**
 * A secp256k1 subject key from its address.
 */
SubjectKeyArgs subject_key_args_secp256k1(const std::string &address);
/**
 * The target of a key write of the UA (`UaLine::key_target`, §12): its holder.
 */
std::string ua_line_key_target(const UaLine &line);
/**
 * The target of a PQZ write of the UA (`UaLine::pqz_target`, §12): its PQZ home; `PqzHomeNone` where the walk has none.
 */
std::string ua_line_pqz_target(const UaLine &line);
/**
 * Opens the SDK (spec §4) over the app's sync store and authenticator; blocks the calling thread (never a UI thread).
 */
std::shared_ptr<Sdk> open_blocking(const BindingConfig &config, const std::shared_ptr<SyncStore> &store, std::shared_ptr<SyncAuthenticator> authenticator);
} // namespace scaas_sdk