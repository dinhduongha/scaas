// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @title UA identity layer (accounts.md §1.3–§1.6): kind table, tags, ids, keyHash, purpose tags, `ua_msg`, the UA-8
///        portable records as typed EIP-712 structs (typed-signing TS-D1: `UARegistration`, `UAPortableRecord`,
///        `UAKemRecord`, `UAPqzKey`, `UAPqzKeyRecord` under the domain ("SCaaS UA Portable", "1")), the
///        registry's `UAAuth` digest, member digests and key-data validation.
/// @notice The same rules are implemented by clientkeys `ua.js`, `clients/ua-rs`, `clients/ua-py`, `clients/ua-go` and
///         `clients/ua-cs`; `smartcontracts/vectors/ua/kinds.json` and `structures.json` pin all six.
///         `GROUP(g) = keccak256("scaas.ua.group." ‖ g ‖ ".v1")`, `keyHash = keccak256(GROUP(g) ‖ canonical pubkey)`.
///         Validation uses EIP-2537 (BLS12-381 G1/G2 MSM with scalar 1: canonical, on curve, in the subgroup) and the
///         bn254 pairing precompile (G2 on the twist and in the subgroup). Each precompile call is capped at 2× its EIP
///         price (G1MSM 24 000, G2MSM 45 000, pairing 158 000), so a failing call cannot burn the caller's gas; a call
///         starting with less gas than the cap plus 1/64 reverts `UAVerifyGas`, never `UAKeyData`.
///         UNAUDITED.
library UAKinds {
    uint16 internal constant EVM_EOA = 0x0001;
    uint16 internal constant EVM_CONTRACT = 0x0002;
    uint16 internal constant HEDERA_NATIVE = 0x0003;
    uint16 internal constant WEBAUTHN_P256 = 0x0100;
    uint16 internal constant P256 = 0x0101;
    uint16 internal constant ED25519 = 0x0102;
    uint16 internal constant BIP340 = 0x0103;
    uint16 internal constant SCHNORR_BN254 = 0x0104;
    uint16 internal constant SCHNORR_BLS12381 = 0x0105;
    uint16 internal constant BLS12381_MINSIG = 0x0106;
    uint16 internal constant BLS_BN254_MINSIG = 0x0107;
    uint16 internal constant SECP256K1 = 0x0108;
    uint16 internal constant MUSIG2_SECP256K1 = 0x0110;
    uint16 internal constant FROST_SECP256K1 = 0x0111;
    uint16 internal constant MUSIG2_BN254 = 0x0112;
    uint16 internal constant FROST_BN254 = 0x0113;
    uint16 internal constant MSIG = 0x0120;
    uint16 internal constant MLDSA44 = 0x0130;
    uint16 internal constant MLDSA65 = 0x0131;
    uint16 internal constant FNDSA512 = 0x0132;
    uint16 internal constant SLHDSA128S = 0x0133;
    uint16 internal constant ZETHER_BLS12381 = 0x0141;
    /// @notice A scheme id since UA-6, not a kind: the PQZ key attribute of a PQ signing UA (its tag for `R_REG`'s
    ///         `uaMessage`, its keyHash group `pqz-mlwe`, the registry slot of its verifier and the `0x0142` list).
    uint16 internal constant PQZ_MLWE = 0x0142;

    bytes32 internal constant MSG_TAG = keccak256("scaas.ua.msg.v1");
    bytes32 internal constant PURPOSE_POP = keccak256("scaas.ua.purpose.pop.v1");
    bytes32 internal constant PURPOSE_METATX = keccak256("scaas.ua.purpose.metatx.v1");
    bytes32 internal constant PURPOSE_METATX_CANCEL = keccak256("scaas.ua.purpose.metatx-cancel.v1");
    bytes32 internal constant PURPOSE_MEMBER = keccak256("scaas.ua.purpose.member.v1");
    bytes32 internal constant PURPOSE_ZETHER_AUTH = keccak256("scaas.ua.purpose.zether-auth.v1");
    bytes32 internal constant PURPOSE_ZETHER_OWNER = keccak256("scaas.ua.purpose.zether-owner.v1");
    bytes32 internal constant PURPOSE_KEYOP = keccak256("scaas.ua.purpose.keyop.v1");
    bytes32 internal constant PURPOSE_RECEIVER_FEE = keccak256("scaas.ua.purpose.receiver-fee.v1");
    bytes32 internal constant PURPOSE_VP = keccak256("scaas.ua.purpose.vp.v1");
    bytes32 internal constant PURPOSE_VC_ANCHOR = keccak256("scaas.ua.purpose.vc-anchor.v1");
    /// @notice `UATradeOrder`, `CancelOrder` over a UA order hash, `UAInvalidateNonces` (dex.md CTR-DEX-25; UA-5b).
    bytes32 internal constant PURPOSE_TRADE = keccak256("scaas.ua.purpose.trade.v1");
    /// UA-8 portable registrations (P1, P7; UA8-D1): the PoP purpose v2 (no chain context), the KEM record's purpose, the
    /// later PQZ key record's (`setPqzKey`, ruling A1-I1) purpose. `PURPOSE_POP` (v1) was the chain-bound PoP's
    /// (`popDigest`, in `legacy/ua8/` since UA-8 Task A5); `register` refuses it. The record tags of the raw digests
    /// (`KEM_RECORD_TAG`, `PQZ_KEY_RECORD_TAG`) are in `legacy/typed-signing/` (TS-D3: the struct type names the record).
    bytes32 internal constant PURPOSE_POP_V2 = keccak256("scaas.ua.purpose.pop.v2");
    bytes32 internal constant PURPOSE_KEM = keccak256("scaas.ua.purpose.kem.v1");
    bytes32 internal constant PURPOSE_PQZ_KEY = keccak256("scaas.ua.purpose.pqz-key.v1");
    /// typed-signing TS-D1 (owner 2026-10-31 decisions 2 + 8): the portable domain `EIP712Domain(string name,string
    /// version)` = ("SCaaS UA Portable", "1"), no chain id, verifying contract or salt (a record registers a UA on every
    /// chain, CTR-UA-07); `kind` is `uint16` (its name: `name(kind)`, the registry's `kindName`).
    bytes32 internal constant PORTABLE_DOMAIN_SEPARATOR = 0x9a2c390d4dc940ccdb5fa6b21e673e87159bdd99aeef22ea791bcea9efc64ca1;
    bytes32 internal constant UA_KEM_RECORD_TYPEHASH =
        keccak256("UAKemRecord(bytes32 ua,uint64 version,uint8 scheme,bytes32 kemPkHash)");
    bytes32 internal constant UA_PORTABLE_RECORD_TYPEHASH = keccak256(
        "UAPortableRecord(bytes32 ua,uint16 kind,bytes32 pqzKeyHash,UAKemRecord kem)UAKemRecord(bytes32 ua,uint64 version,uint8 scheme,bytes32 kemPkHash)"
    );
    bytes32 internal constant UA_REGISTRATION_TYPEHASH = keccak256(
        "UARegistration(UAPortableRecord record,bytes32 pqzPopHash)UAKemRecord(bytes32 ua,uint64 version,uint8 scheme,bytes32 kemPkHash)UAPortableRecord(bytes32 ua,uint16 kind,bytes32 pqzKeyHash,UAKemRecord kem)"
    );
    bytes32 internal constant UA_PQZ_KEY_TYPEHASH = keccak256("UAPqzKey(bytes32 ua,bytes32 pqzKeyHash)");
    bytes32 internal constant UA_PQZ_KEY_RECORD_TYPEHASH =
        keccak256("UAPqzKeyRecord(UAPqzKey key,bytes32 pqzPopHash)UAPqzKey(bytes32 ua,bytes32 pqzKeyHash)");
    /// First byte of `kemPk` = the KEM scheme id (CTR-UA-32). Scheme 1 = ML-KEM-1024 + X25519; 2 (ML-KEM-1024 + HQC +
    /// X25519, after FIPS 207) is reserved and refused until enabled.
    uint8 internal constant KEM_SCHEME_MLKEM1024_X25519 = 1;
    /// `kemPk` of scheme 1: `0x01 ‖ ML-KEM-1024 ek (1,568 B) ‖ X25519 pk (32 B)` (X-Wing order): the only KEM key the registry stores.
    uint256 internal constant KEM_PK_LENGTH = 1601;
    /// Who checked a part of a record (UA-8 P11.3), the code points of every family; `RELAYER` comes with the relayer id.
    uint8 internal constant CHECKED_NONE = 0;
    uint8 internal constant CHECKED_CHAIN = 1;
    uint8 internal constant CHECKED_RELAYER = 2;
    bytes32 internal constant UAAUTH_TYPEHASH = keccak256("UAAuth(bytes32 ua,bytes32 purpose,bytes32 digest)");
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    bytes32 internal constant NAME_HASH = keccak256("SCaaS UARegistry");

    error UAKeyData(uint16 kind);
    error UAKindUnknown(uint16 kind);
    error UAKindNotDerived(uint16 kind);
    /// Gas left is below what a validation precompile needs. A statement about the gas, not about the key.
    error UAVerifyGas();

    // Gas caps for the precompile calls: 2× the EIP-2537 / EIP-1108 prices for one pair or one point.
    uint256 internal constant G1MSM_GAS = 24_000;
    uint256 internal constant G2MSM_GAS = 45_000;
    uint256 internal constant PAIRING_GAS = 158_000;

    uint256 private constant SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 private constant SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 private constant P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
    uint256 private constant P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;
    uint256 private constant ED_P = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED;
    uint256 private constant ED_D = 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3;
    uint256 private constant ED_SQRT_M1 = 0x2B8324804FC1DF0B2B4D00993DFBD7A72F431806AD2FE478C4EE1B274A0EA0B0;
    uint256 private constant BN_P = 0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47;
    uint256 private constant BN_R = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001;

    // ----- sets (accounts.md §1.6 "Closed kind sets"; slhdsa128s in SIGNING and MEMBER; UA-6 U8: zether-bls12381 in
    //       SIGNING, not MEMBER) -----

    function isNative(uint16 kind) internal pure returns (bool) {
        return (kind >= EVM_EOA && kind <= HEDERA_NATIVE) || (kind >= 0x0010 && kind <= 0x0018);
    }

    /// `zether-bls12381` only: `zether-bn254` (0x0140) is in `legacy/ua6/` since UA-6 (U10, CTR-ZTH-32).
    function isZether(uint16 kind) internal pure returns (bool) {
        return kind == ZETHER_BLS12381;
    }

    function _singleSigning(uint16 kind) private pure returns (bool) {
        return (kind >= WEBAUTHN_P256 && kind <= SECP256K1) || (kind >= MUSIG2_SECP256K1 && kind <= FROST_BN254)
            || (kind >= MLDSA44 && kind <= SLHDSA128S);
    }

    function isSigning(uint16 kind) internal pure returns (bool) {
        return kind == MSIG || kind == ZETHER_BLS12381 || _singleSigning(kind);
    }

    function isDerived(uint16 kind) internal pure returns (bool) {
        return isSigning(kind) || isZether(kind);
    }

    function isMember(uint16 kind, bool hederaNative) internal pure returns (bool) {
        return _singleSigning(kind) || kind == EVM_EOA || kind == EVM_CONTRACT || (hederaNative && kind == HEDERA_NATIVE);
    }

    // ----- names, tags, groups -----

    function name(uint16 kind) internal pure returns (string memory) {
        if (kind == 0x0001) return "evm-eoa";
        if (kind == 0x0002) return "evm-contract";
        if (kind == 0x0003) return "hedera-native";
        if (kind == 0x0010) return "solana-ed25519";
        if (kind == 0x0011) return "stellar-account";
        if (kind == 0x0012) return "soroban-contract";
        if (kind == 0x0013) return "aptos-account";
        if (kind == 0x0014) return "sui-address";
        if (kind == 0x0015) return "cosmos-account";
        if (kind == 0x0016) return "ton-wallet";
        if (kind == 0x0017) return "near-account";
        if (kind == 0x0018) return "algorand-address";
        if (kind == 0x0100) return "webauthn-p256";
        if (kind == 0x0101) return "p256";
        if (kind == 0x0102) return "ed25519";
        if (kind == 0x0103) return "bip340";
        if (kind == 0x0104) return "schnorr-bn254";
        if (kind == 0x0105) return "schnorr-bls12381";
        if (kind == 0x0106) return "bls12381-minsig";
        if (kind == 0x0107) return "bls-bn254-minsig";
        if (kind == 0x0108) return "secp256k1";
        if (kind == 0x0110) return "musig2-secp256k1";
        if (kind == 0x0111) return "frost-secp256k1";
        if (kind == 0x0112) return "musig2-bn254";
        if (kind == 0x0113) return "frost-bn254";
        if (kind == 0x0120) return "msig";
        if (kind == 0x0130) return "mldsa44";
        if (kind == 0x0131) return "mldsa65";
        if (kind == 0x0132) return "fndsa512";
        if (kind == 0x0133) return "slhdsa128s";
        if (kind == 0x0141) return "zether-bls12381";
        if (kind == 0x0142) return "pqz-mlwe";
        revert UAKindUnknown(kind);
    }

    function _requireDerived(uint16 kind) private pure {
        if (isDerived(kind)) return;
        if (isNative(kind) || kind == PQZ_MLWE) revert UAKindNotDerived(kind);
        revert UAKindUnknown(kind);
    }

    /// A derived kind or the scheme `pqz-mlwe` (UA-6: it keeps its tag and keyHash group).
    function _requireTagged(uint16 kind) private pure {
        if (kind != PQZ_MLWE) _requireDerived(kind);
    }

    /// `TAG(kind) = keccak256("scaas.ua." ‖ name ‖ ".v1")`.
    function tag(uint16 kind) internal pure returns (bytes32) {
        _requireTagged(kind);
        return keccak256(abi.encodePacked("scaas.ua.", name(kind), ".v1"));
    }

    /// The keyHash group of a derived kind or of the scheme `pqz-mlwe`; "" for `msig`.
    function groupName(uint16 kind) internal pure returns (string memory) {
        _requireTagged(kind);
        if (kind == WEBAUTHN_P256 || kind == P256) return "p256";
        if (kind == ED25519) return "ed25519";
        if (kind == BIP340 || kind == SECP256K1 || kind == MUSIG2_SECP256K1 || kind == FROST_SECP256K1) return "secp256k1";
        if (kind == SCHNORR_BN254 || kind == MUSIG2_BN254 || kind == FROST_BN254) return "bn254-g1";
        if (kind == SCHNORR_BLS12381 || kind == ZETHER_BLS12381) return "bls12381-g1";
        if (kind == BLS12381_MINSIG) return "bls12381-g2";
        if (kind == BLS_BN254_MINSIG) return "bn254-g2";
        if (kind == MSIG) return "";
        return name(kind); // mldsa44, mldsa65, fndsa512, slhdsa128s, the scheme pqz-mlwe: the group is the name
    }

    function groupTag(string memory group) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("scaas.ua.group.", group, ".v1"));
    }

    // ----- ids, keyHash, messages, digests -----

    /// `keccak256(TAG(kind) ‖ keyData)`; no validation.
    function uaOf(uint16 kind, bytes memory keyData) internal pure returns (bytes32) {
        _requireDerived(kind); // pqz-mlwe is a key attribute, not an id kind (CTR-PQZ-13)
        return keccak256(abi.encodePacked(tag(kind), keyData));
    }

    function inNativeSpace(bytes32 id) internal pure returns (bool) {
        return uint256(id) >> 160 == 0;
    }

    /// `keccak256(GROUP(g) ‖ canonical pubkey)`, 0 for `msig`. Call on validated key data.
    function keyHashOf(uint16 kind, bytes memory d) internal pure returns (bytes32) {
        string memory g = groupName(kind);
        if (bytes(g).length == 0) return bytes32(0);
        (uint256 lo, uint256 len) = (0, d.length);
        if (kind == WEBAUTHN_P256 || kind == P256 || kind == SECP256K1) len = 32;
        else if (kind == MUSIG2_SECP256K1 || kind == FROST_SECP256K1) (lo, len) = (1, 32);
        else if (kind == MUSIG2_BN254 || kind == FROST_BN254) len = 64;
        if (d.length < lo + len) revert UAKeyData(kind);
        if (lo == 0 && len == d.length) return keccak256(abi.encodePacked(groupTag(g), d));
        bytes memory pub = new bytes(len);
        for (uint256 i; i < len; ++i) pub[i] = d[lo + i];
        return keccak256(abi.encodePacked(groupTag(g), pub));
    }

    function uaMessage(uint16 kind, bytes32 purposeTag, bytes32 digest) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(MSG_TAG, tag(kind), purposeTag, digest));
    }

    /// `keccak256("evm:" ‖ decimal(chainId))` (the registry computes it in its constructor from `block.chainid`).
    function chainKeyHash(uint256 chainId) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("evm:", Strings.toString(chainId)));
    }

    // The portable records (UA-8 UA8-D1; typed-signing TS-D1 … TS-D3): EIP-712 structs under the portable domain, no
    // chain id, no chain uid, no registry. The registry checks the attributes (holder, version ≥ 1, 1,601-byte scheme-1
    // key) before it hashes them. `pqzKeyHash = keyHashOf(0x0142, pqzKey)`, `pqzPopHash = keccak256(pqzPop)`, each 0
    // when absent.

    /// `keccak256(0x1901 ‖ PORTABLE_DOMAIN_SEPARATOR ‖ structHash)`: what `eth_signTypedData_v4` returns for the record.
    function portableDigest(bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", PORTABLE_DOMAIN_SEPARATOR, structHash));
    }

    /// `hashStruct(UAKemRecord{ua, version, scheme = kemPk[0], kemPkHash = keccak256(kemPk)})` over the whole key; no
    /// record (version 0, no key) is the zero record `UAKemRecord{ua, 0, 0, 0}` (TS-D2: version 0 is never a record).
    function kemRecordHash(bytes32 ua, uint64 version, bytes memory kemPk) internal pure returns (bytes32) {
        if (version == 0 && kemPk.length == 0) return keccak256(abi.encode(UA_KEM_RECORD_TYPEHASH, ua, 0, 0, bytes32(0)));
        uint8 scheme = kemPk.length == 0 ? 0 : uint8(kemPk[0]); // an empty key never reaches a record (UAKemKeyLength)
        return keccak256(abi.encode(UA_KEM_RECORD_TYPEHASH, ua, version, scheme, keccak256(kemPk)));
    }

    /// `hashStruct(UAPortableRecord{ua, kind, pqzKeyHash, kem})`, `kemHash = kemRecordHash` of the initial KEM record.
    function portableRecordHash(bytes32 ua, uint16 kind, bytes32 pqzKeyHash, bytes32 kemHash)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(UA_PORTABLE_RECORD_TYPEHASH, ua, kind, pqzKeyHash, kemHash));
    }

    /// `hashStruct(UARegistration{record, pqzPopHash})`, `recordHash = portableRecordHash`.
    function registrationHash(bytes32 recordHash, bytes32 pqzPopHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(UA_REGISTRATION_TYPEHASH, recordHash, pqzPopHash));
    }

    /// `hashStruct(UAPqzKey{ua, pqzKeyHash})`.
    function pqzKeyHash_(bytes32 ua, bytes32 pqzKeyHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(UA_PQZ_KEY_TYPEHASH, ua, pqzKeyHash));
    }

    /// `hashStruct(UAPqzKeyRecord{key, pqzPopHash})`, `keyHash = pqzKeyHash_`.
    function pqzKeyRecordHash(bytes32 keyHash, bytes32 pqzPopHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(UA_PQZ_KEY_RECORD_TYPEHASH, keyHash, pqzPopHash));
    }

    /// typed(`UAPortableRecord`): R_REG proves over `uaMessage(0x0142, PURPOSE_POP_V2, ·)` of it (`register`, the first
    /// `storePqzPop`), `kind` the registering kind.
    function portableRecordDigest(bytes32 ua, uint16 kind, bytes32 pqzKeyHash, bytes32 kemHash)
        internal
        pure
        returns (bytes32)
    {
        return portableDigest(portableRecordHash(ua, kind, pqzKeyHash, kemHash));
    }

    /// typed(`UARegistration`): the `pop` signs `uaMessage(kind, PURPOSE_POP_V2, ·)` of it (an msig's derived members
    /// through `memberDigest`, a native member the digest itself, TS-D4).
    function registrationDigest(bytes32 ua, uint16 kind, bytes32 pqzKeyHash, bytes32 kemHash, bytes32 pqzPopHash)
        internal
        pure
        returns (bytes32)
    {
        return portableDigest(registrationHash(portableRecordHash(ua, kind, pqzKeyHash, kemHash), pqzPopHash));
    }

    /// typed(`UAKemRecord`), signed as `uaMessage(kind, PURPOSE_KEM, ·)` (`setKemKey`).
    function kemRecordDigest(bytes32 ua, uint64 version, bytes memory kemPk) internal pure returns (bytes32) {
        return portableDigest(kemRecordHash(ua, version, kemPk));
    }

    /// typed(`UAPqzKey`): a later PQZ key's R_REG proves over `uaMessage(0x0142, PURPOSE_PQZ_KEY, ·)` (no proof hash:
    /// no cycle).
    function pqzKeyDigest(bytes32 ua, bytes32 pqzKeyHash) internal pure returns (bytes32) {
        return portableDigest(pqzKeyHash_(ua, pqzKeyHash));
    }

    /// typed(`UAPqzKeyRecord`): `setPqzKey`'s signature signs `uaMessage(kind, PURPOSE_PQZ_KEY, ·)`.
    function pqzKeyRecordDigest(bytes32 ua, bytes32 pqzKeyHash, bytes32 pqzPopHash) internal pure returns (bytes32) {
        return portableDigest(pqzKeyRecordHash(pqzKeyHash_(ua, pqzKeyHash), pqzPopHash));
    }

    function uaAuthDomainSeparator(uint256 generation, uint256 chainId, address registry, bytes32 chainUid)
        internal pure returns (bytes32)
    {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, NAME_HASH, keccak256(bytes(Strings.toString(generation))), chainId, registry, chainUid)
        );
    }

    function uaAuthDigest(bytes32 domainSeparator, bytes32 ua, bytes32 purposeTag, bytes32 digest)
        internal pure returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(hex"1901", domainSeparator, keccak256(abi.encode(UAAUTH_TYPEHASH, ua, purposeTag, digest)))
        );
    }

    function memberDigest(bytes32 structureUa, bytes32 uaMsg) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(structureUa, uaMsg));
    }

    // ----- key-data validation (accounts.md §1.6 "Validation at registration") -----

    /// Reverts `UAKeyData(kind)` unless `d` is the unique canonical encoding of a valid key or structure of `kind`.
    function validateKeyData(uint16 kind, bytes memory d, bool hederaNative) internal view {
        _requireDerived(kind);
        uint256 len = _fixedLength(kind);
        if (len != 0 && d.length != len) revert UAKeyData(kind);
        bool ok;
        if (kind == WEBAUTHN_P256 || kind == P256) ok = _p256(d);
        else if (kind == ED25519) ok = _ed25519(d);
        else if (kind == BIP340) ok = _secpX(_word(d, 0));
        else if (kind == SECP256K1) ok = _secpXY(_word(d, 0), _word(d, 32));
        else if (kind == SCHNORR_BN254) ok = _bnG1(d, 0);
        else if (kind == SCHNORR_BLS12381 || kind == ZETHER_BLS12381) ok = _bls(d, address(0x0c), 128);
        else if (kind == BLS12381_MINSIG) ok = _bls(d, address(0x0e), 256);
        else if (kind == BLS_BN254_MINSIG) ok = _bnG2(d);
        else if (kind == MUSIG2_SECP256K1) ok = _musig2(d, 33);
        else if (kind == FROST_SECP256K1) ok = _frost(d, 33);
        else if (kind == MUSIG2_BN254) ok = _musig2(d, 64);
        else if (kind == FROST_BN254) ok = _frost(d, 64);
        else if (kind == MSIG) ok = _msig(d, hederaNative);
        else if (kind == FNDSA512) ok = _fndsa(d);
        else ok = true; // mldsa44/65, slhdsa128s: the length is the whole check
        if (!ok) revert UAKeyData(kind);
    }

    function _fixedLength(uint16 kind) private pure returns (uint256) {
        if (kind == WEBAUTHN_P256) return 96;
        if (kind == P256 || kind == SECP256K1 || kind == SCHNORR_BN254) return 64;
        if (kind == ED25519 || kind == BIP340 || kind == SLHDSA128S) return 32;
        if (kind == SCHNORR_BLS12381 || kind == ZETHER_BLS12381 || kind == BLS_BN254_MINSIG) return 128;
        if (kind == BLS12381_MINSIG) return 256;
        if (kind == MLDSA44) return 1312;
        if (kind == MLDSA65) return 1952;
        if (kind == FNDSA512) return 897;
        return 0; // MuSig2, FROST, msig: variable
    }

    function _word(bytes memory d, uint256 o) private pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := mload(add(add(d, 32), o))
        }
    }

    function _u16(bytes memory d, uint256 o) private pure returns (uint256) {
        return _word(d, o) >> 240;
    }

    function _isZero(bytes memory d) private pure returns (bool) {
        return keccak256(d) == keccak256(new bytes(d.length));
    }

    function _modexp(uint256 b, uint256 e, uint256 m) private view returns (uint256 r) {
        (bool ok, bytes memory out) = address(0x05).staticcall(abi.encode(32, 32, 32, b, e, m));
        if (!ok || out.length != 32) revert UAVerifyGas();
        r = abi.decode(out, (uint256));
    }

    function _secpXY(uint256 x, uint256 y) private pure returns (bool) {
        if (x >= SECP_P || y >= SECP_P) return false;
        return mulmod(y, y, SECP_P) == addmod(mulmod(mulmod(x, x, SECP_P), x, SECP_P), 7, SECP_P);
    }

    function _secpX(uint256 x) private view returns (bool) {
        if (x >= SECP_P) return false;
        uint256 rhs = addmod(mulmod(mulmod(x, x, SECP_P), x, SECP_P), 7, SECP_P);
        uint256 y = _modexp(rhs, (SECP_P + 1) / 4, SECP_P);
        return mulmod(y, y, SECP_P) == rhs;
    }

    function _secpCompressed(bytes memory d, uint256 o) private view returns (bool) {
        uint8 prefix = uint8(d[o]);
        return (prefix == 2 || prefix == 3) && _secpX(_word(d, o + 1));
    }

    function _p256(bytes memory d) private pure returns (bool) {
        (uint256 x, uint256 y) = (_word(d, 0), _word(d, 32));
        if (x >= P256_P || y >= P256_P) return false;
        uint256 rhs = addmod(
            addmod(mulmod(mulmod(x, x, P256_P), x, P256_P), P256_P - mulmod(3, x, P256_P), P256_P), P256_B, P256_P
        );
        return mulmod(y, y, P256_P) == rhs;
    }

    function _ed25519(bytes memory d) private view returns (bool) {
        uint256 raw = _word(d, 0);
        uint256 le = _reverse(raw);
        uint256 y = le & ((1 << 255) - 1);
        if (y >= ED_P) return false;
        uint256 yy = mulmod(y, y, ED_P);
        uint256 u = addmod(yy, ED_P - 1, ED_P);
        uint256 v = addmod(mulmod(ED_D, yy, ED_P), 1, ED_P);
        uint256 x2 = mulmod(u, _modexp(v, ED_P - 2, ED_P), ED_P);
        uint256 x = _modexp(x2, (ED_P + 3) / 8, ED_P);
        if (mulmod(x, x, ED_P) != x2) x = mulmod(x, ED_SQRT_M1, ED_P);
        if (mulmod(x, x, ED_P) != x2) return false; // not a point
        if (x == 0 && le >> 255 == 1) return false; // negative zero
        return !_edSmallOrder(raw);
    }

    /// The canonical encodings of the 8 small-order points (pinned against noble's ED25519_TORSION_SUBGROUP by the vectors).
    function _edSmallOrder(uint256 raw) private pure returns (bool) {
        return raw == 0x0100000000000000000000000000000000000000000000000000000000000000
            || raw == 0xecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
            || raw == 0x0000000000000000000000000000000000000000000000000000000000000000
            || raw == 0x0000000000000000000000000000000000000000000000000000000000000080
            || raw == 0x26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05
            || raw == 0x26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85
            || raw == 0xc7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a
            || raw == 0xc7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa;
    }

    function _reverse(uint256 v) private pure returns (uint256) {
        v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8)
            | ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);
        v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16)
            | ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);
        v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32)
            | ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);
        v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64)
            | ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);
        return (v >> 128) | (v << 128);
    }

    function _bnG1(bytes memory d, uint256 o) private pure returns (bool) {
        (uint256 x, uint256 y) = (_word(d, o), _word(d, o + 32));
        if (x >= BN_P || y >= BN_P || (x == 0 && y == 0)) return false;
        return mulmod(y, y, BN_P) == addmod(mulmod(mulmod(x, x, BN_P), x, BN_P), 3, BN_P);
    }

    /// EIP-197 pairing with the G1 generator: fails unless the G2 point is canonical, on the twist and in the subgroup.
    function _bnG2(bytes memory d) private view returns (bool) {
        if (_isZero(d)) return false;
        if (gasleft() < PAIRING_GAS + PAIRING_GAS / 63 + 5_000) revert UAVerifyGas();
        (bool ok, bytes memory out) = address(0x08).staticcall{gas: PAIRING_GAS}(
            abi.encodePacked(uint256(1), uint256(2), d)
        );
        return ok && out.length == 32;
    }

    /// EIP-2537 MSM with scalar 1 (G1MSM `0x0c` / G2MSM `0x0e`): fails unless padded, canonical, on curve, in the subgroup.
    function _bls(bytes memory d, address msm, uint256 size) private view returns (bool) {
        if (_isZero(d)) return false;
        uint256 cap = size == 128 ? G1MSM_GAS : G2MSM_GAS;
        if (gasleft() < cap + cap / 63 + 5_000) revert UAVerifyGas();
        (bool ok, bytes memory out) = msm.staticcall{gas: cap}(abi.encodePacked(d, uint256(1)));
        return ok && out.length == size;
    }

    function _point(bytes memory d, uint256 o, uint256 size) private view returns (bool) {
        return size == 33 ? _secpCompressed(d, o) : _bnG1(d, o);
    }

    /// `d[a .. a+len) < d[b .. b+len)` as big-endian byte strings.
    function _lt(bytes memory d, uint256 a, uint256 b, uint256 len) private pure returns (bool) {
        for (uint256 i; i < len; i += 32) {
            uint256 n = len - i < 32 ? len - i : 32;
            uint256 shift = 8 * (32 - n);
            (uint256 x, uint256 y) = (_word(d, a + i) >> shift, _word(d, b + i) >> shift);
            if (x != y) return x < y;
        }
        return false;
    }

    function _musig2(bytes memory d, uint256 size) private view returns (bool) {
        if (d.length < size + 2) return false;
        uint256 n = _u16(d, size);
        if (n < 2 || n > 16 || d.length != size + 2 + n * size || !_point(d, 0, size)) return false;
        for (uint256 i; i < n; ++i) {
            uint256 o = size + 2 + i * size;
            if (!_point(d, o, size) || (i > 0 && !_lt(d, o - size, o, size))) return false;
        }
        return true;
    }

    function _frost(bytes memory d, uint256 size) private view returns (bool) {
        if (d.length < size + 4) return false;
        (uint256 t, uint256 n) = (_u16(d, size), _u16(d, size + 2));
        if (t < 2 || t > n || n > 16) return false;
        uint256 per = (t + 1) * size + 32;
        if (d.length != size + 4 + n * per || !_point(d, 0, size)) return false;
        uint256 order = size == 33 ? SECP_N : BN_R;
        for (uint256 i; i < n; ++i) {
            uint256 o = size + 4 + i * per;
            for (uint256 j; j <= t; ++j) {
                if (!_point(d, o + j * size, size)) return false; // t commitments, then R_i
            }
            if (_word(d, o + (t + 1) * size) >= order) return false;
        }
        return true;
    }

    function _msig(bytes memory d, bool hederaNative) private pure returns (bool) {
        if (d.length < 4) return false;
        (uint256 threshold, uint256 count) = (_u16(d, 0), _u16(d, 2));
        if (count == 0 || count > 16 || d.length != 4 + 36 * count) return false;
        uint256 total;
        for (uint256 i; i < count; ++i) {
            uint256 o = 4 + 36 * i;
            uint16 kind = uint16(_u16(d, o));
            bytes32 id = bytes32(_word(d, o + 2));
            uint256 weight = _u16(d, o + 34);
            if (!isMember(kind, hederaNative) || weight == 0 || isNative(kind) != inNativeSpace(id)) return false;
            if (i > 0 && _word(d, o - 34) >= uint256(id)) return false;
            total += weight;
        }
        return threshold != 0 && threshold <= total;
    }

    /// `0x09 ‖ 512 × 14-bit h_i`, each `< 12289` (the decoding of `Falcon512._decodePk`, over memory).
    function _fndsa(bytes memory d) private pure returns (bool) {
        if (uint8(d[0]) != 0x09) return false;
        for (uint256 i; i < 512; ++i) {
            uint256 bit = i * 14;
            uint256 h = (_word(d, 1 + (bit >> 3)) >> (242 - (bit & 7))) & 0x3fff;
            if (h >= 12289) return false;
        }
        return true;
    }
}
