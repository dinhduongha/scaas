// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {SaltedEIP712} from "../common/SaltedEIP712.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {SSTORE2} from "../common/SSTORE2.sol";
import {IUARegistry} from "./IUARegistry.sol";
import {IUAKindVerifier, IUAPopVerifier} from "./IUAVerifier.sol";
import {UAKinds} from "./UAKinds.sol";

/// @title UA registry, UA-2a/2c scope (accounts.md §1.8): the single-key kinds 0x0100–0x0107, the group kinds
///        0x0110–0x0113 (MuSig2/FROST, stored), the structure `msig`, native EVM ids, generations.
/// @notice Monotonic and admin-free (CTR-UA-15): no owner, no setter, no `payable`, a record never changes. `register`
///         derives every record field from `keyData` (CTR-UA-07), so anyone may relay it. Every verifier `staticcall` (group PoP: see below) is
///         capped at the kind's `verifyCap` and counts only exactly 32 bytes equal to 1; a caller that leaves too little
///         gas for the cap gets `UAVerifyGas`, never a pass (T-AUTH-4).
///
///         Kind table: one `uint256` immutable per kind this code can verify, `verifier | cap << 160` (0 = disabled):
///         read with no SLOAD and no EXTCODECOPY. Kinds whose registry code is not written yet — PQ (P6c), Zether
///         (UA-3) — are refused by the constructor; each later sub-plan adds its slot and code and redeploys (all chains
///         are test chains). `ed25519` (0x0102) has its slot already: it is a plain single-key kind, so UA-2b only
///         deploys its verifier and passes it here.
///
///         Stored kinds (CTR-UA-17; UA-2c: MuSig2/FROST): `register` has the kind's verifier run the whole group check
///         in `verifyPop` (KeyAgg with hints / DKG PoKs, then one group signature; capped at `verifyBudget`, no hold:
///         a starved PoP is `UAPoP`, a revert like every PoP failure), then stores `vk` (`Q` / `Y`: 33 bytes on
///         secp256k1, 64 on bn254) with SSTORE2 as `keyPtr`. `requireAuthorized` takes `auth = abi.encode(bytes keyData,
///         bytes sig)` with `keyData` empty (non-empty ⇒ `UAUnauthorized`) and verifies `sig` against `vk` read from the
///         record's `keyPtr`; an `msig` member of a stored kind is checked the same way through the member's own record.
///
///         Gen 2 (`predecessor ≠ 0`) reads gen 1 for `UAAlreadyRegistered` / `UAKeyInUse` / `kindOf` / `keyOwner` /
///         `recordOf` and hands records it does not hold, and members whose kind it does not enable, to gen 1's
///         `requireAuthorized`. Its constructor refuses every single-key kind whose keyHash group gen 1 enables.
///
///         Open in UA-2a: HIP-632 (`hedera-native` members' 64-byte ed25519 signatures) needs a non-static CALL, which a
///         `view` `requireAuthorized` cannot make; such members verify as ECDSA/1271 only.
///         UNAUDITED — NOT FOR PRODUCTION FUNDS.
contract UARegistry is IUARegistry, SaltedEIP712 {
    struct KindConfig {
        uint16 kind;
        address verifier;
        uint64 cap;
    }

    struct MemberSig {
        uint16 index;
        bytes keyData;
        bytes sig;
    }

    /// @notice A constructor argument is refused (kind outside this code's table, duplicate, verifier without code, cap
    ///         0 or above the budget, a keyHash group the predecessor enables, a predecessor of another chain/profile).
    error UAConfig(uint16 kind);

    uint256 internal constant SMART_KEY_1271_GAS = 400_000;
    /// @notice Registration bound for `msig` (register step 4): gas per member beyond its cap — MemberSig decoding,
    ///         `uaOf`, `uaMessage`, the call or the gen-1 hand-off, cold accounts (measured worst, cold under
    ///         `--isolate`: 19,987 for a member handed to gen 1), plus what the caller must hold for the largest cap
    ///         (400 k / 63 + 5 k): 31,336, rounded up. A member handed to gen 1 adds gen 1's own hold
    ///         (`cap / 63 + GAS_MARGIN`) in `_checkMembers`. `UAGas.t.sol` `test_T_GAS_msigAtBudget` authorizes msigs
    ///         registered exactly at `verifyBudget` within `verifyBudget`.
    uint256 internal constant MSIG_MEMBER_GAS = 35_000;

    uint8 public immutable generation;
    address public immutable predecessor;
    bool public immutable hederaNative;
    uint64 public immutable verifyBudget;
    /// @notice `keccak256("evm:" ‖ decimal(block.chainid))`, computed at deploy (CTR-UA-07).
    bytes32 public immutable chainKeyHash;
    bytes32 private immutable _SMART_KEY_CLONE_CODEHASH;

    uint256 private immutable _CFG0; // 0x0100 webauthn-p256
    uint256 private immutable _CFG1; // 0x0101 p256
    uint256 private immutable _CFG2; // 0x0102 ed25519 (UA-2b)
    uint256 private immutable _CFG3; // 0x0103 bip340
    uint256 private immutable _CFG4; // 0x0104 schnorr-bn254
    uint256 private immutable _CFG5; // 0x0105 schnorr-bls12381
    uint256 private immutable _CFG6; // 0x0106 bls12381-minsig
    uint256 private immutable _CFG7; // 0x0107 bls-bn254-minsig
    uint256 private immutable _CFG8; // 0x0110 musig2-secp256k1 (UA-2c, stored)
    uint256 private immutable _CFG9; // 0x0111 frost-secp256k1 (UA-2c, stored)
    uint256 private immutable _CFG10; // 0x0112 musig2-bn254 (UA-2c, stored)
    uint256 private immutable _CFG11; // 0x0113 frost-bn254 (UA-2c, stored)
    uint256 private immutable _CFG_MSIG; // 0x0120: address(this) | verifyBudget << 160

    mapping(bytes32 ua => Record) private _records;
    mapping(bytes32 keyHash => bytes32) private _keyOwner;

    /// @param chainUid_ the chain's genesis hash (≠ 0, `SaltedEIP712.ChainUidZero`).
    /// @param predecessor_ 0 for generation 1, else the chain's gen-1 registry.
    /// @param smartKeyAccountImpl_ the chain's `SmartKeyAccount` implementation (0 = none): its EIP-1167 clones get the
    ///        400 k ERC-1271 cap.
    /// @param msig_ enables the structure kind `msig`.
    /// @param kinds_ the enabled single-key and group kinds with their verifier and measured verify cap.
    constructor(
        bytes32 chainUid_,
        address predecessor_,
        bool hederaNative_,
        uint64 verifyBudget_,
        address smartKeyAccountImpl_,
        bool msig_,
        KindConfig[] memory kinds_
    ) SaltedEIP712("SCaaS UARegistry", predecessor_ == address(0) ? "1" : "2", chainUid_) {
        if (verifyBudget_ == 0 || (smartKeyAccountImpl_ != address(0) && smartKeyAccountImpl_.code.length == 0)) {
            revert UAConfig(0);
        }
        if (predecessor_ != address(0)) {
            IUARegistry p = IUARegistry(predecessor_);
            if (p.generation() != 1 || p.chainUid() != chainUid_ || p.hederaNative() != hederaNative_) {
                revert UAConfig(0);
            }
        }
        uint256[12] memory k;
        for (uint256 i; i < kinds_.length; ++i) {
            KindConfig memory c = kinds_[i];
            uint256 slot = _slot(c.kind);
            if (
                slot > 11 || k[slot] != 0 || c.verifier.code.length == 0 || c.cap == 0 || c.cap > verifyBudget_
                    || (predecessor_ != address(0) && _groupInPredecessor(predecessor_, c.kind))
            ) revert UAConfig(c.kind);
            k[slot] = uint256(uint160(c.verifier)) | uint256(c.cap) << 160;
        }
        (_CFG0, _CFG1, _CFG2, _CFG3) = (k[0], k[1], k[2], k[3]);
        (_CFG4, _CFG5, _CFG6, _CFG7) = (k[4], k[5], k[6], k[7]);
        (_CFG8, _CFG9, _CFG10, _CFG11) = (k[8], k[9], k[10], k[11]);
        _CFG_MSIG = msig_ ? uint256(uint160(address(this))) | uint256(verifyBudget_) << 160 : 0;

        generation = predecessor_ == address(0) ? 1 : 2;
        predecessor = predecessor_;
        hederaNative = hederaNative_;
        verifyBudget = verifyBudget_;
        chainKeyHash = UAKinds.chainKeyHash(block.chainid);
        _SMART_KEY_CLONE_CODEHASH = smartKeyAccountImpl_ == address(0)
            ? bytes32(0)
            : keccak256(
                abi.encodePacked(hex"363d3d373d3d3d363d73", smartKeyAccountImpl_, hex"5af43d82803e903d91602b57fd5bf3")
            );
    }

    // ----- views -----

    function kindEnabled(uint16 kind) external view returns (bool) {
        return uint160(_cfg(kind)) != 0;
    }

    function verifyCap(uint16 kind) public view returns (uint64) {
        return uint64(_cfg(kind) >> 160);
    }

    function chainUid() external view returns (bytes32) {
        return CHAIN_UID;
    }

    function uaOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32) {
        return UAKinds.uaOf(kind, keyData);
    }

    function keyHashOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32) {
        return UAKinds.keyHashOf(kind, keyData);
    }

    function popDigest(bytes32 ua, bytes32 authRef) public view returns (bytes32) {
        return UAKinds.popDigest(chainKeyHash, CHAIN_UID, address(this), ua, authRef);
    }

    function uaMessage(uint16 kind, bytes32 purposeTag, bytes32 digest) external pure returns (bytes32) {
        return UAKinds.uaMessage(kind, purposeTag, digest);
    }

    function uaAuthDigest(bytes32 ua, bytes32 purposeTag, bytes32 digest) public view returns (bytes32) {
        return UAKinds.uaAuthDigest(_domainSeparatorV4(), ua, purposeTag, digest);
    }

    /// `authRef` is always 0 here: only Zether kinds (UA-3) store one. `r.keyPtr ≠ 0` only for stored kinds.
    function recordOf(bytes32 ua) external view returns (Record memory r, bytes32 authRef) {
        r = _records[ua];
        if (r.kind == 0 && predecessor != address(0)) return IUARegistry(predecessor).recordOf(ua);
    }

    function kindOf(bytes32 ua) public view returns (uint16 kind) {
        kind = _records[ua].kind;
        if (kind == 0 && predecessor != address(0)) kind = IUARegistry(predecessor).kindOf(ua);
    }

    function isRegistered(bytes32 ua) external view returns (bool) {
        return kindOf(ua) != 0;
    }

    function keyOwner(bytes32 keyHash) public view returns (bytes32 owner) {
        owner = _keyOwner[keyHash];
        if (owner == 0 && predecessor != address(0)) owner = IUARegistry(predecessor).keyOwner(keyHash);
    }

    // ----- register (accounts.md §1.8 steps 1–8; steps 5 and 7 reduce to "authRef == 0" until UA-3) -----

    function register(uint16 kind, bytes calldata keyData, bytes calldata pop, bytes32 authRef, bytes calldata authPop)
        external
        returns (bytes32 ua)
    {
        uint256 cfg = _cfg(kind); // 1
        if (uint160(cfg) == 0) revert UAKindDisabled(kind);
        bool structure = kind == UAKinds.MSIG;
        bytes memory d = keyData;
        // 2. msig: the layout with the widest member set; the profile's MEMBER set is step 4 (UAMemberUnknown).
        UAKinds.validateKeyData(kind, d, structure || hederaNative);
        ua = UAKinds.uaOf(kind, d); // 3
        if (UAKinds.inNativeSpace(ua)) revert UAIdInNativeSpace(ua);
        if (kindOf(ua) != 0) revert UAAlreadyRegistered(ua);
        bytes32 kh; // 4
        if (structure) {
            _checkMembers(d);
        } else {
            kh = UAKinds.keyHashOf(kind, d);
            bytes32 owner = keyOwner(kh);
            if (owner != 0) revert UAKeyInUse(kh, owner);
        }
        if (authRef != 0 || authPop.length != 0) revert UAAuthRef(authRef); // 5, 7
        // 6. Structures have no PoP of their own (members proved theirs): `pop` must be empty.
        if (structure ? pop.length != 0 : !_popOk(cfg, kind, d, ua, pop)) revert UAPoP();
        _records[ua] = Record(kind, uint40(block.timestamp), _keyPtr(kind, keyData)); // 8
        if (!structure) _keyOwner[kh] = ua;
        emit UARegistered(ua, kind, keyData, 0);
    }

    /// Stored kinds keep `vk` (`Q` / `Y`, the first bytes of the key data) as SSTORE2 code (CTR-UA-17); others: 0.
    function _keyPtr(uint16 kind, bytes calldata keyData) private returns (address) {
        uint256 len = _vkLength(kind);
        return len == 0 ? address(0) : SSTORE2.write(keyData[0:len]);
    }

    function _popOk(uint256 cfg, uint16 kind, bytes memory d, bytes32 ua, bytes calldata pop)
        private
        view
        returns (bool)
    {
        bytes32 message = UAKinds.uaMessage(kind, UAKinds.PURPOSE_POP, popDigest(ua, 0));
        bytes memory data = abi.encodeWithSelector(IUAPopVerifier.verifyPop.selector, d, message, pop);
        // group kinds: the whole group check runs here, bounded by verifyBudget (§1.8 step 6), without the hold
        if (_vkLength(kind) != 0) return _capped(address(uint160(cfg)), verifyBudget, data, 1, false);
        return _capped(address(uint160(cfg)), cfg >> 160, data, 1, true);
    }

    /// Step 4 for `msig`: every member ∈ MEMBER of this profile and native or registered under its stated kind; the
    /// worst case of a minimal authorizing set (the `c` largest caps + `c` × `MSIG_MEMBER_GAS`) fits `verifyBudget`.
    function _checkMembers(bytes memory d) private view {
        (uint256 threshold, uint256 count) = (_u16(d, 0), _u16(d, 2));
        uint256[] memory weights = new uint256[](count);
        uint256[] memory caps = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            uint256 o = 4 + 36 * i;
            uint16 kind = uint16(_u16(d, o));
            bytes32 id = bytes32(_word(d, o + 2));
            if (!UAKinds.isMember(kind, hederaNative)) revert UAMemberUnknown(id);
            if (UAKinds.isNative(kind)) {
                caps[i] = _nativeCap();
            } else {
                if (kindOf(id) != kind) revert UAMemberUnknown(id);
                uint256 cfg = _cfg(kind);
                if (uint160(cfg) != 0) {
                    caps[i] = cfg >> 160;
                } else {
                    // handed to gen 1, which holds cap / 63 + GAS_MARGIN again inside the 63/64 gen 2 gives it
                    uint256 cap = IUARegistry(predecessor).verifyCap(kind);
                    caps[i] = cap + cap / 63 + SigCheck.GAS_MARGIN;
                }
            }
            weights[i] = _u16(d, o + 34);
        }
        _sort(weights);
        _sort(caps);
        uint256 c;
        for (uint256 acc; acc < threshold; ++c) {
            acc += weights[c];
        }
        uint256 worst = c * MSIG_MEMBER_GAS;
        for (uint256 i; i < c; ++i) {
            worst += caps[count - 1 - i];
        }
        if (worst > verifyBudget) revert UAKeyData(UAKinds.MSIG);
    }

    /// A native member may be (or later become, counterfactually) a `SmartKeyAccount` clone: the bound takes its cap.
    function _nativeCap() private view returns (uint256) {
        return _SMART_KEY_CLONE_CODEHASH != 0 ? SMART_KEY_1271_GAS : SigCheck.ERC1271_GAS;
    }

    // ----- requireAuthorized -----

    function requireAuthorized(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes calldata auth) external view {
        if (!_authorized(ua, purposeTag, digest, auth)) revert UAUnauthorized(ua);
    }

    function _authorized(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes calldata auth)
        private
        view
        returns (bool)
    {
        if (UAKinds.inNativeSpace(ua)) return _native(ua, purposeTag, digest, auth);
        uint16 kind = _records[ua].kind; // every kind this code registers is SIGNING
        if (kind == 0) return _viaPredecessor(ua, purposeTag, digest, auth);
        (bytes memory keyData, bytes memory sig) = abi.decode(auth, (bytes, bytes));
        return _derived(ua, kind, purposeTag, digest, keyData, sig);
    }

    /// A derived id of `kind` (taken from the record, or from the structure for members): key data against the id
    /// (stored kinds: `keyData` empty, `vk` from the id's own record), then the kind's verifier, `msig`, or gen 1 for
    /// a kind this generation does not enable.
    function _derived(
        bytes32 id,
        uint16 kind,
        bytes32 purposeTag,
        bytes32 digest,
        bytes memory keyData,
        bytes memory sig
    ) private view returns (bool) {
        uint256 cfg = _cfg(kind);
        if (_vkLength(kind) != 0) {
            if (keyData.length != 0) return false; // CTR-UA-17: auth carries only the signature
            if (uint160(cfg) != 0) {
                Record memory r = _records[id];
                if (r.kind != kind) return false;
                keyData = SSTORE2.read(r.keyPtr);
            }
        } else if (UAKinds.uaOf(kind, keyData) != id) {
            return false;
        }
        if (kind == UAKinds.MSIG) return _msig(id, purposeTag, digest, keyData, sig);
        if (uint160(cfg) == 0) return _viaPredecessor(id, purposeTag, digest, abi.encode(keyData, sig));
        return _verifierCall(
            cfg, IUAKindVerifier.verify.selector, keyData, UAKinds.uaMessage(kind, purposeTag, digest), sig
        );
    }

    /// accounts.md §1.9 `msig` row: strictly increasing member indexes, stop at the threshold (a MemberSig after it
    /// fails, which keeps the registration bound sound), `member_digest = keccak256(ua ‖ ua_msg)`.
    function _msig(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes memory d, bytes memory blob)
        private
        view
        returns (bool)
    {
        MemberSig[] memory sigs = abi.decode(blob, (MemberSig[]));
        bytes32 md = UAKinds.memberDigest(ua, UAKinds.uaMessage(UAKinds.MSIG, purposeTag, digest));
        (uint256 threshold, uint256 count) = (_u16(d, 0), _u16(d, 2));
        uint256 acc;
        uint256 next; // lowest index the next MemberSig may use
        for (uint256 i; i < sigs.length; ++i) {
            MemberSig memory s = sigs[i];
            if (acc >= threshold || s.index < next || s.index >= count) return false;
            next = uint256(s.index) + 1;
            uint256 o = 4 + 36 * uint256(s.index);
            uint16 kind = uint16(_u16(d, o));
            bytes32 id = bytes32(_word(d, o + 2));
            bool ok = UAKinds.isNative(kind)
                ? s.keyData.length == 0 && _native(id, UAKinds.PURPOSE_MEMBER, md, s.sig) // native: no key data
                : _derived(id, kind, UAKinds.PURPOSE_MEMBER, md, s.keyData, s.sig);
            if (!ok) return false;
            acc += _u16(d, o + 34);
        }
        return acc >= threshold;
    }

    /// CTR-UA-24: by code at call time. Empty ⇒ ECDSA; the 23-byte EIP-7702 designator ⇒ ECDSA, else ERC-1271 through
    /// the delegate; other code ⇒ ERC-1271 only. Always over `uaAuthDigest`. OZ `tryRecover` refuses high s and a
    /// recovered `address(0)`, so neither id 0 nor a garbage signature ever matches.
    function _native(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes memory sig) private view returns (bool) {
        address a = address(uint160(uint256(ua)));
        bytes32 h = uaAuthDigest(ua, purposeTag, digest);
        uint256 len = a.code.length;
        bool designator = len == 23 && bytes3(a.code) == 0xef0100;
        if (len == 0 || designator) {
            (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(h, sig);
            if (err == ECDSA.RecoverError.NoError && rec == a) return true;
            if (len == 0) return false;
        }
        uint256 cap = _SMART_KEY_CLONE_CODEHASH != 0 && a.codehash == _SMART_KEY_CLONE_CODEHASH
            ? SMART_KEY_1271_GAS
            : SigCheck.ERC1271_GAS;
        return _capped(
            a,
            cap,
            abi.encodeCall(IERC1271.isValidSignature, (h, sig)),
            uint256(bytes32(IERC1271.isValidSignature.selector)),
            true
        );
    }

    function _verifierCall(uint256 cfg, bytes4 selector, bytes memory keyData, bytes32 message, bytes memory sig)
        private
        view
        returns (bool)
    {
        return
            _capped(address(uint160(cfg)), cfg >> 160, abi.encodeWithSelector(selector, keyData, message, sig), 1, true);
    }

    /// `staticcall` with exactly `cap` gas; true iff it succeeds with exactly one 32-byte word equal to `expect`.
    /// `hold`: too little gas left to hand over the full cap ⇒ `UAVerifyGas` (63/64 starvation never turns into a
    /// verdict). Without `hold` (the group PoP, whose failure reverts `register` anyway) the call gets at most `cap`.
    function _capped(address target, uint256 cap, bytes memory data, uint256 expect, bool hold)
        private
        view
        returns (bool ok)
    {
        if (hold && gasleft() < cap + cap / 63 + SigCheck.GAS_MARGIN) revert UAKinds.UAVerifyGas();
        assembly ("memory-safe") {
            mstore(0, 0)
            let s := staticcall(cap, target, add(data, 0x20), mload(data), 0, 0x20)
            ok := and(and(s, eq(returndatasize(), 0x20)), eq(mload(0), expect))
        }
    }

    /// Records and kinds of gen 1 are checked by gen 1 (its verifiers, its `UAAuth` domain for native members of its
    /// structures). Any revert there is a failed check, except `UAVerifyGas` (re-raised).
    function _viaPredecessor(bytes32 id, bytes32 purposeTag, bytes32 digest, bytes memory auth)
        private
        view
        returns (bool)
    {
        if (predecessor == address(0)) return false;
        try IUARegistry(predecessor).requireAuthorized(id, purposeTag, digest, auth) {
            return true;
        } catch (bytes memory err) {
            // a starved caller must see UAVerifyGas, never a verdict (T-AUTH-4)
            if (err.length == 4 && bytes4(err) == UAKinds.UAVerifyGas.selector) revert UAKinds.UAVerifyGas();
            return false;
        }
    }

    // ----- kind table -----

    function _cfg(uint16 kind) private view returns (uint256) {
        if (kind == UAKinds.MSIG) return _CFG_MSIG;
        uint256 s = _slot(kind);
        if (s > 11) return 0;
        if (s > 7) return s < 10 ? (s == 8 ? _CFG8 : _CFG9) : (s == 10 ? _CFG10 : _CFG11);
        if (s < 4) return s < 2 ? (s == 0 ? _CFG0 : _CFG1) : (s == 2 ? _CFG2 : _CFG3);
        return s < 6 ? (s == 4 ? _CFG4 : _CFG5) : (s == 6 ? _CFG6 : _CFG7);
    }

    /// Kind-table slot: 0x0100–0x0107 → 0–7, 0x0110–0x0113 → 8–11, anything else 12 (not in this code's table).
    function _slot(uint16 kind) private pure returns (uint256) {
        if (kind >= 0x0100 && kind <= 0x0107) return kind - 0x0100;
        if (kind >= UAKinds.MUSIG2_SECP256K1 && kind <= UAKinds.FROST_BN254) return kind - 0x0110 + 8;
        return 12;
    }

    /// Length of the stored `vk` of a stored kind (CTR-UA-17), 0 otherwise: `Q` / `Y` SEC1 compressed (secp256k1) or
    /// EIP-196 uncompressed (bn254), the first bytes of the key data.
    function _vkLength(uint16 kind) private pure returns (uint256) {
        if (kind == UAKinds.MUSIG2_SECP256K1 || kind == UAKinds.FROST_SECP256K1) return 33;
        if (kind == UAKinds.MUSIG2_BN254 || kind == UAKinds.FROST_BN254) return 64;
        return 0;
    }

    /// Gen-2 rule (§1.8 "Generations"): a single-key kind whose keyHash group any kind of gen 1 enables stays in gen 1.
    function _groupInPredecessor(address pred, uint16 kind) private view returns (bool) {
        bytes32 g = keccak256(bytes(UAKinds.groupName(kind)));
        for (uint16 j = 0x0100; j <= UAKinds.PQZ_MLWE; ++j) {
            if (
                j != UAKinds.MSIG && UAKinds.isDerived(j) && keccak256(bytes(UAKinds.groupName(j))) == g
                    && IUARegistry(pred).kindEnabled(j)
            ) return true;
        }
        return false;
    }

    // ----- bytes helpers -----

    function _word(bytes memory d, uint256 o) private pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := mload(add(add(d, 32), o))
        }
    }

    function _u16(bytes memory d, uint256 o) private pure returns (uint256) {
        return _word(d, o) >> 240;
    }

    /// Insertion sort, ascending (count ≤ 16).
    function _sort(uint256[] memory a) private pure {
        for (uint256 i = 1; i < a.length; ++i) {
            uint256 v = a[i];
            uint256 j = i;
            for (; j > 0 && a[j - 1] > v; --j) {
                a[j] = a[j - 1];
            }
            a[j] = v;
        }
    }
}
