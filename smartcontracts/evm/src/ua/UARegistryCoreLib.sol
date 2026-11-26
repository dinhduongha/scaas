// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "./IUARegistry.sol";
import {IUAKindVerifier, IUAPopVerifier, IUAMinimalVerifier} from "./IUAVerifier.sol";
import {SSTORE2} from "../common/SSTORE2.sol";
import {UAKinds} from "./UAKinds.sol";
import {UAStore} from "./UAStore.sol";
import {MldsaVerifier} from "./MlDsa.sol";

/// @title `UARegistry`'s core library (typed-signing R2, owner 2026-11-01; T66b 3.1b, owner 2026-11-09, spec
///        2026-11-09-t66b-library-organisation.md §11 (f); split by domain, owner 2026-11-19, candidate (2)): the
///        authorization and verify paths: the portable signature (`portableOk`, `msigOk`), `requirePortable`,
///        `requirePortableApp`, `acceptMembership`, the pure views `uaOf` and `keyHashOf`, the read `uaCount`. Every `register`
///        form and the registration-bound helpers are `UARegistryRegLib`'s, which checks the step-6 PoP here by a nested
///        DELEGATECALL (`portableOk`); the key writes after registration and the other reads off the hot path are
///        `UARegistryAuxLib`'s, which runs `portableOk` and `msigOk` here by a nested DELEGATECALL (T66b 3.1c). Both compile in
///        this library's small `internal` helpers (the appended words, the getters, `_msigBytes`, `_memberSig`, `_pqEligible`).
///        Run by DELEGATECALL from a thin entry per function, so `address(this)` is the registry and the storage is its
///        `UAStore.Layout`. Same check order, same stored bytes, same events and errors as when this code was in the registry
///        (`legacy/typed-signing/UARegistryPreSplit.sol`; `test/ua/UARegistrySplit.t.sol`).
/// @notice What a library cannot read, the registry's immutables, reaches it two ways (no new selector):
///         - 4 words the entry appends after the forwarded calldata: `_cfg(kind)` of the kind the entry knows (its
///           parameter, or the record's), `_cfg(0x0142)`, the clone codehash, `_cfg(0x0121)` (spec 2026-11-19-bls12381-multi
///           §5.3, N1). They are read from the end of the calldata,
///           so nothing a caller sends can stand in their place, however long its calldata; a nested ABI offset may point
///           into them, which only reads public values as that caller's own argument.
///         - everything with a getter is called back on `address(this)`: `predecessor`, `hederaNative`, `verifyBudget`,
///           `verifyCap` (an `msig` member's cap and whether its kind is enabled), `kindOf`, `keyOwner`.
///         A derived `msig` member's signature goes through `requireAuthorized` on `address(this)` under `member`: the
///         same `_derived`, its kind was checked against its record at registration (`UARegistryRegLib._membersWorst`); the
///         verifier call stays in the one place, and this library needs no member's verifier address, but one: a `0x0121`
///         member on a stored path is checked here, by `verifyMinimal` on the verifier of the fourth word (`_multi`, §5.3).
///         Called directly every writer reverts: solc's library call protection covers each one, none is `view`; the two
///         `pure` views answer a direct call with their pure result.
///         `acceptMembership` (CTR-UA-37) runs here too; its member check is `_memberOk`, as a stored record's.
///         UNAUDITED.
library UARegistryCoreLib {
    // ----- the registry's `pure` views (T66b R-1, spec 2026-11-09-t66b-library-organisation.md §5) -----

    /// One copy of their code in the registry pair: `UARegistry` runs these by DELEGATECALL (`_libPure`, nothing appended), the
    /// same ABI and answers as when they were compiled into the registry. `pure`, so solc's call protection does not cover them:
    /// a direct call answers the same pure result, and reads and writes nothing.
    function uaOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32) {
        return UAKinds.uaOf(kind, keyData);
    }

    function keyHashOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32) {
        return UAKinds.keyHashOf(kind, keyData);
    }

    // The five `*Digest` views run in `UARegistryAuxLib` (task 3.1d, spec §11 (f), owner 2026-11-09); their internal twins
    // (`UAKinds`) are compiled into `UARegistryRegLib` (`register`) and here (`requirePortable`).

    // ----- the appended words -----

    function _cfgKind() internal pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := calldataload(sub(calldatasize(), 128))
        }
    }

    function _cfgPqz() internal pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := calldataload(sub(calldatasize(), 96))
        }
    }

    function _cloneHash() internal pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := calldataload(sub(calldatasize(), 64))
        }
    }

    /// The fourth word (spec 2026-11-19-bls12381-multi §5.3, N1): `_cfg(0x0121)`, the verifier and cap of a `0x0121` `msig` member.
    function _cfgMulti() internal pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := calldataload(sub(calldatasize(), 32))
        }
    }

    // ----- the getters, on the registry -----

    function _pred() internal view returns (address) {
        return IUARegistry(address(this)).predecessor();
    }

    function _kindOf(bytes32 ua) internal view returns (uint16) {
        return IUARegistry(address(this)).kindOf(ua);
    }

    function _keyOwner(bytes32 h) internal view returns (bytes32) {
        return IUARegistry(address(this)).keyOwner(h);
    }

    /// A record gen 1 holds (this registry is gen 2 and has none of its own), as `UARegistry._elsewhere`.
    function _elsewhere(bytes32 ua) internal view returns (bool) {
        return UAStore.layout().records[ua].kind == 0 && _pred() != address(0);
    }

    /// N11 (spec 2026-11-19-registry-verify-only-kinds §11.1): the generation that holds a record this one does not, read there
    /// directly; 0 when held here or nowhere. The walk by a static self-call to the registry's `holderOf` (plan C8; its smallest form:
    /// the libraries' readers have the least room).
    function _holder(bytes32 ua) internal view returns (address h) {
        if (UAStore.layout().records[ua].kind == 0) (h,,) = IUARegistry(address(this)).holderOf(ua);
    }

    /// The clone codehash of the generation holding the structure `ua` (0: the registration's own, held here), its native members'.
    function _cloneHashOf(bytes32 ua) private view returns (bytes32) {
        address h = ua == 0 ? address(0) : _holder(ua);
        return h == address(0) ? _cloneHash() : IUARegistry(h).smartKeyCloneHash();
    }

    /// Spec 2026-11-19-registry-verify-only-kinds §11.2 (owner P7), `UARegistry._pqzWhere`'s rule: `t` the generation a PQZ read of
    /// `ua` forwards to (its home, or its holder where it has none; 0: this one), `h` the holder of a record held elsewhere whose PQZ
    /// home this generation is (0 otherwise).
    function _pqzWhere(bytes32 ua) internal view returns (address t, address h) {
        address p = _pred();
        if (p == address(0) || UAStore.layout().records[ua].kind != 0) return (t, h);
        address home;
        (h,, home) = IUARegistry(p).holderOf(ua);
        if (home == address(0) && h != address(0) && uint160(_cfgPqz()) != 0) return (t, h);
        (t, h) = (home != address(0) ? home : h, address(0));
    }

    /// `holderOf(ua)`'s holder for a check: this generation where it holds the record or where no generation does (its own answer
    /// then refuses), else the holder (W1, N2).
    function _at(bytes32 ua) internal view returns (address h) {
        h = _holder(ua);
        if (h == address(0)) h = address(this);
    }

    /// The one walk (§11.1, M4; owner Y1): this generation's record `(this, kind, this if it enables 0x0142)`; else the predecessor's
    /// answer (`(0, 0, 0)` at generation 1), its PQZ home filled with this generation where none is below and this one enables
    /// `0x0142` (`_cfgPqz()`) for a record some generation holds. One call per generation; three words, nothing re-encoded.
    function _holderOf(bytes32 ua) internal view returns (address h, uint16 k, address home) {
        bool pqz = uint160(_cfgPqz()) != 0;
        k = UAStore.layout().records[ua].kind;
        if (k != 0) return (address(this), k, pqz ? address(this) : address(0));
        address p = _pred();
        if (p == address(0)) return (address(0), 0, address(0));
        (h, k, home) = IUARegistry(p).holderOf(ua);
        if (h != address(0) && home == address(0) && pqz) home = address(this);
    }

    /// A kind this generation lists itself (`UARegistry._listedHere`): `_cfgKind()` is the kind's word the entry appended.
    function _listedHere() internal view returns (bool) {
        return _pred() == address(0) || UAStore._registrable(_cfgKind());
    }

    /// The **current** structure of the `msig` `id` (CTR-UA-44, the key bytes only, never its `pop`): its blob or registration bytes
    /// here (`UAStore.msig`), else gen 1's `msigOf` + `msigStateOf` in the blob form (`UAStore.blob`, one allocation), so its
    /// `enabled` word travels with it (`UAStore.enabledOf`).
    function _msigBytes(bytes32 id) internal view returns (bytes memory) {
        IUARegistry.Record memory r = UAStore.layout().records[id];
        if (r.kind != 0) return UAStore.msig(id, r.keyPtr);
        IUARegistry self = IUARegistry(address(this));
        (uint64 v, uint256 en,) = self.msigStateOf(id);
        return UAStore.blob(self.msigOf(id), en, v, address(0));
    }

    /// The signature object `b` of the `msig` `ua`'s slot `index` (owner 2026-11-03; an `msig` member's: `abi.encode(InnerSig[])` followed
    /// by its version tag, CTR-UA-74): its hash kept, written once with the slot's bit, its bytes in `UAMemberSig`, under `purpose` (`PURPOSE_POP_V2` or `PURPOSE_MEMBERSHIP`). `d`: the `msig`'s key data.
    function _memberSig(bytes32 ua, bytes memory d, uint16 index, bytes32 purpose, bytes memory b) internal {
        UAStore.layout().memberSigHash[ua][index] = keccak256(b);
        emit IUARegistry.UAMemberSig(ua, bytes32(UAStore.word(d, 4 + 36 * uint256(index) + 2)), index, purpose, b);
    }

    /// An `msig` whose enabled members of kinds outside 0x0130–0x0135 weigh less than its threshold (CTR-PQZ-12): it may hold
    /// a PQZ key and registers with an m-of-n PoP (U5). An `msig` member counts as PQ iff it is PQ-eligible itself: a forger of every
    /// classical key cannot reach its threshold. CTR-UA-44: a disabled slot signs nothing (MM-9); `inner` (MM-14): `d` is a member's
    /// own structure, whose `msig` slots are classical weight, never followed (no third level, no recursion).
    function _pqEligible(bytes memory d, bool inner) internal view returns (bool) {
        (uint256 threshold, uint256 count) = (UAStore.u16(d, 0), UAStore.u16(d, 2));
        uint256 en = UAStore.enabledOf(d);
        uint256 classical;
        for (uint256 i; i < count; ++i) {
            if (en >> i & 1 == 0) continue;
            uint256 o = 4 + 36 * i;
            uint16 kind = uint16(UAStore.u16(d, o));
            if (UAStore.isPq(kind)) continue;
            if (kind == UAKinds.MSIG && !inner && _pqEligible(_msigBytes(bytes32(UAStore.word(d, o + 2))), true)) {
                continue;
            }
            classical += UAStore.u16(d, o + 34);
        }
        return classical < threshold;
    }

    /// A portable record's `UASig` (`setPqzKey`, `setKemKey` ≥ 1): never `keyData`; `signature` or `members` (`_sigOk`).
    function _portableOk(
        uint16 kind,
        bytes memory d,
        bytes32 ua,
        bytes32 purpose,
        bytes32 digest,
        IUARegistry.UASig calldata sig
    ) internal view returns (bool) {
        return sig.keyData.length == 0
            && _sigOk(_cfgKind(), kind, d, ua, purpose, digest, sig.signature, sig.members, true);
    }

    // ----- the helpers the other two libraries call (T66b 3.1c, owner 2026-11-09, spec 2026-11-09-t66b-library-organisation.md §11 (f); owner 2026-11-19) -----

    /// One copy of the verify code in the registry's libraries: `UARegistryAuxLib` (both) and `UARegistryRegLib` (`portableOk`,
    /// the step-6 PoP) run these by a nested DELEGATECALL (their `_lib`), this call's arguments followed by the four words the
    /// registry appended to the caller's entry, so `address(this)`, the storage and `_cfgKind` / `_cfgPqz` / `_cloneHash` are the
    /// registry's, as when the caller compiled this code in. Each is its `internal` twin and nothing else. None is `view` or
    /// `pure`: solc's library call protection covers each, a direct call reverts.
    function portableOk(
        uint16 kind,
        bytes memory d,
        bytes32 ua,
        bytes32 purpose,
        bytes32 digest,
        IUARegistry.UASig calldata sig
    ) external returns (bool) {
        return _portableOk(kind, d, ua, purpose, digest, sig);
    }

    /// `updateMsig` row 9 (CTR-UA-44): `_msig` of `sigs` over the **stored** structure `d` of `ua`, held here, minimal.
    function msigOk(bytes32 ua, bytes32 md, bytes32 typed, bytes memory d, IUARegistry.MemberSig[] memory sigs)
        external
        returns (bool)
    {
        return _msig(ua, md, typed, false, d, sigs, true);
    }

    // ----- the portable check (UA-7 O1, owner 2026-11-04; plan T66a) -----

    /// `IUARegistry.requirePortable` on a record held here (the registry forwards a gen-1 record to gen 1 first): the closed list of
    /// portable purposes (`_portablePurpose`), then `_portable`. No write: the registry runs it inside its view.
    function requirePortable(bytes32 ua, bytes32 purposeTag, bytes32 typedDigest, IUARegistry.UASig calldata auth)
        external
    {
        _portablePurpose(ua, purposeTag);
        _portable(ua, purposeTag, typedDigest, auth, 0);
    }

    /// `IUARegistry.requirePortableApp` on a record held here (CTR-UA-46): `_portable` under `appPurpose(appId)`, a purpose the
    /// registry derives, so no caller names a SCaaS purpose through it; `appId` 0 refused. No write.
    function requirePortableApp(bytes32 ua, bytes32 appId, bytes32 typedDigest, IUARegistry.UASig calldata auth)
        external
    {
        if (appId == 0) revert IUARegistry.UAUnauthorized(ua);
        _portable(ua, UAKinds.appPurpose(appId), typedDigest, auth, appId);
    }

    /// The portable check of `requirePortable` and `requirePortableApp` (its purpose already checked by the caller): a single key by
    /// `_single` with `signature` only, the check `setKemKey` and `setPqzKey` make; an `msig` by `_msig` over its accepted slots,
    /// minimal, whatever its PQ weight (`_sigOk`'s empty `pop` of a classical-dominant `msig` is the registration's rule, never a
    /// signature: a classical-only `msig` with no members is refused here).
    function _portable(
        bytes32 ua,
        bytes32 purposeTag,
        bytes32 typedDigest,
        IUARegistry.UASig calldata auth,
        bytes32 appId
    ) internal view {
        IUARegistry.Record memory r = UAStore.layout().records[ua];
        // the registration's `pop` is `register`'s own check (its slots need no acceptance): never a view's, never a later generation's
        if (purposeTag == UAKinds.PURPOSE_POP_V2) revert IUARegistry.UAUnauthorized(ua);
        bool ok;
        if (r.kind == 0) {
            // spec 2026-11-19-registry-verify-only-kinds §4: held elsewhere, of a kind verify-only here (the registry hands every other
            // such record to its holder), or held nowhere (refused)
            ok = auth.keyData.length == 0 && auth.members.length == 0
                && _voPortable(ua, purposeTag, typedDigest, auth.signature, appId);
        } else if (r.kind != UAKinds.MSIG) {
            bytes memory d; // a surplus-form kind verifies its stored `p` (`_multi`), never `d`
            if (!UAKinds.hasSurplusForm(r.kind)) (d,) = UAStore.registration(ua, r);
            ok = auth.keyData.length == 0 && auth.members.length == 0
                && _single(_cfgKind(), r.kind, d, ua, purposeTag, typedDigest, auth.signature);
        } else {
            bytes32 md = UAKinds.memberDigest(ua, UAKinds.uaMessage(UAKinds.MSIG, purposeTag, typedDigest));
            // CTR-UA-44: the current structure (MM-9); CTR-UA-74: `signature` its version tag
            bytes memory d = UAStore.msig(ua, r.keyPtr);
            ok = auth.keyData.length == 0 && UAStore.verOk(auth.signature, d)
                && _msig(ua, md, typedDigest, false, d, auth.members, false);
        }
        // No UAKeyNotCached here (3zh, 2026-11-15): a record of this registry exists only after `register`, which needs the
        // complete ML-DSA cache without a precompile (`_consent`), and SSTORE2 parts are never removed; a gen-1 record has no
        // row here (r.kind == 0 above). A refusal of a stored ML-DSA record is a wrong signature, never a missing cache.
        if (!ok) revert IUARegistry.UAUnauthorized(ua);
    }

    /// `IUARegistry.requireAuthorized` of a record held elsewhere whose kind is verify-only here (spec 2026-11-19-registry-verify-only-kinds
    /// §4, CTR-UA-60): the registry walked, handed every other such record to its holder, and appended the word of the holder's kind
    /// (`_cfgKind()`); held nowhere, or a word not verify-only: `UAUnauthorized`. Its `UAKeyNotCached` (key form 1) and `UAVerifyGas`
    /// as they are. No write: the registry runs it inside its view.
    function requireAuthorized(bytes32 ua, bytes32 purposeTag, bytes32 digest, IUARegistry.UASig calldata auth)
        external
    {
        (address h, uint16 k,) = _holderOf(ua);
        if (
            h == address(0) || _cfgKind() >> 224 & 1 == 0 || auth.members.length != 0
                || !_voCheck(h, ua, k, purposeTag, digest, auth.keyData, auth.signature)
        ) revert IUARegistry.UAUnauthorized(ua);
    }

    /// §4 (CTR-UA-60): the record `id` of `kind`, held at `h`, checked by this generation's verify-only verifier (`_cfgKind()`) on the
    /// bytes the holder's code passes on that path ("Key bytes"): the stored key (`keyOf`), a classical member's registration key
    /// data, the holder's complete ML-DSA cache under key form 1 (else `UAKeyNotCached`), a classical signer's `keyData` against the
    /// id; the holder's entry (`verify`, `verifyCached`); under the cap with the hold. Every read of the holder fails only by gas:
    /// `UAVerifyGas` (F11).
    function _voCheck(
        address h,
        bytes32 id,
        uint16 kind,
        bytes32 purposeTag,
        bytes32 digest,
        bytes memory keyData,
        bytes memory sig
    ) private view returns (bool) {
        uint256 cfg = _cfgKind();
        bytes4 sel = IUAKindVerifier.verify.selector;
        uint256 vl = UAStore.vkLength(kind);
        // §5's fallback (N10): the holder's `requireAuthorized` with the caller's `auth` (a member's: `UASig("", sig, [])`)
        IUARegistry.UASig memory back = IUARegistry.UASig(keyData, sig, new IUARegistry.MemberSig[](0));
        if (vl != 0 || purposeTag == UAKinds.PURPOSE_MEMBER) {
            if (keyData.length != 0) return false;
            if (cfg >> 225 & 1 != 0) {
                (keyData, sel) = (UAStore.cacheAt(h, id, kind), MldsaVerifier.verifyCached.selector);
            } else if (vl != 0) {
                keyData = abi.decode(UAStore.read(h, abi.encodeCall(IUARegistry.keyOf, (id))), (bytes));
            } else {
                keyData = UAStore.regKey(h, id);
            }
        } else if (UAKinds.uaOf(kind, keyData) != id) {
            return false;
        }
        bytes memory data = abi.encodeWithSelector(sel, keyData, UAKinds.uaMessage(kind, purposeTag, digest), sig);
        // §5 (CTR-UA-68): 1 accepts, 0 refuses (no fallback), no answer falls back to the holder's verdict
        uint256 v = UAStore.voCall(address(uint160(cfg)), UAStore._capOf(cfg), data);
        return v == 2 ? UAStore.via(h, id, purposeTag, digest, back) : v == 1;
    }

    /// §4 / §5 (CTR-UA-60): the portable check of a record held elsewhere by this generation's verify-only verifier (`_cfgKind()`, the
    /// word of the holder's kind the registry passed): `verifyPop` on the holder's registration key data (`verifyCached` on its
    /// complete cache under key form 1), the path and DST the holder's `_single` takes; under the cap with the hold, the group kinds'
    /// cap `verifyBudget` held too (P10). False where no generation holds `ua` or the word is not verify-only.
    function _voPortable(bytes32 ua, bytes32 purpose, bytes32 digest, bytes memory sig, bytes32 appId)
        internal
        view
        returns (bool)
    {
        uint256 cfg = _cfgKind();
        (address h, uint16 k,) = _holderOf(ua);
        if (h == address(0) || cfg >> 224 & 1 == 0) return false;
        bytes32 message = UAKinds.uaMessage(k, purpose, digest);
        bytes memory data = cfg >> 225 & 1 != 0
            ? abi.encodeWithSelector(MldsaVerifier.verifyCached.selector, UAStore.cacheAt(h, ua, k), message, sig)
            : abi.encodeWithSelector(IUAPopVerifier.verifyPop.selector, UAStore.regKey(h, ua), message, sig);
        uint256 cap = k >= UAKinds.MUSIG2_SECP256K1 && k <= UAKinds.FROST_BN254
            ? IUARegistry(address(this)).verifyBudget()
            : UAStore._capOf(cfg);
        // §5: no answer falls back to the holder's entry for this path, `requirePortableApp` with its `appId` (N10), never on 0
        uint256 v = UAStore.voCall(address(uint160(cfg)), cap, data);
        if (v != 2) return v == 1;
        IUARegistry.UASig memory back = IUARegistry.UASig("", sig, new IUARegistry.MemberSig[](0));
        return UAStore.verdict(
            h,
            appId == 0
                ? abi.encodeCall(IUARegistry.requirePortable, (ua, purpose, digest, back))
                : abi.encodeCall(IUARegistry.requirePortableApp, (ua, appId, digest, back))
        );
    }

    // ----- acceptance (CTR-UA-37) -----

    /// Slot `memberSig.index` of the `msig` `ua` accepts its place (`IUARegistry.acceptMembership`): the check of a stored
    /// record's member (`_memberOk`) over typed(`UAMembership{ua, member}`), no threshold, no minimal form: one slot speaks
    /// for itself. A gen-1 record on gen 2 is refused here as in `setKemKey` (UA8-D11): the bits live with the record, gen 1.
    function acceptMembership(bytes32 ua, IUARegistry.MemberSig calldata memberSig) external {
        UAStore.Layout storage s = UAStore.layout();
        IUARegistry.Record memory r = s.records[ua];
        if (r.kind != UAKinds.MSIG) revert IUARegistry.UAUnauthorized(ua);
        // CTR-UA-44 MM-11: any slot of the current structure, enabled or not (an appended slot accepts here)
        bytes memory d = UAStore.msig(ua, r.keyPtr);
        uint16 index = memberSig.index;
        if (index >= UAStore.u16(d, 2)) revert IUARegistry.UAUnauthorized(ua);
        uint256 bits = s.accepted[ua];
        if (bits >> index & 1 != 0) return;
        bytes32 member = bytes32(UAStore.word(d, 4 + 36 * uint256(index) + 2));
        bytes32 typed = UAKinds.membershipDigest(ua, member);
        bytes32 md = UAKinds.memberDigest(ua, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_MEMBERSHIP, typed));
        if (!_memberOk(d, md, typed, memberSig, 0, true)) revert IUARegistry.UAUnauthorized(ua);
        s.accepted[ua] = bits | 1 << index;
        // owner 2026-11-03: the hash kept, written once as the bit it goes with, the bytes in `UAMemberSig`: a copy checks them against
        // `memberSigHashOf` and replays them
        _memberSig(
            ua,
            d,
            index,
            UAKinds.PURPOSE_MEMBERSHIP,
            // CTR-UA-74: an `msig` member's list, then its version tag (nothing at version 0)
            memberSig.members.length == 0 ? memberSig.sig : bytes.concat(abi.encode(memberSig.members), memberSig.sig)
        );
        emit IUARegistry.UAMembershipAccepted(ua, index, member);
    }

    // ----- the portable signature -----

    /// Step 6 (and `setKemKey`, `setPqzKey`): a portable record's signature over `uaMessage(kind, purpose, digest)`.
    /// `msig`: no signature unless PQ-eligible, then the m-of-n `members` (under `member`, U5; a native member over the
    /// typed `digest` itself, by ECDSA or ERC-1271), `sig` empty; single keys: `sig` by the kind's
    /// verifier (`verifyPop`), no `members`. Only the portable purposes reach this chain-free path (`_portablePurpose`).
    /// `cfg`: the registry's `_cfg(kind)`. `internal` for `SigOkHarness` (ruling A5-m3).
    function _sigOk(
        uint256 cfg,
        uint16 kind,
        bytes memory d,
        bytes32 ua,
        bytes32 purpose,
        bytes32 digest,
        bytes memory sig,
        IUARegistry.MemberSig[] memory members,
        bool write
    ) internal view returns (bool) {
        _portablePurpose(ua, purpose);
        if (kind == UAKinds.MSIG) {
            if (!UAStore.verOk(sig, d)) return false; // CTR-UA-74: `sig` the version tag of `d`
            if (!_pqEligible(d, false)) return members.length == 0;
            bytes32 md = UAKinds.memberDigest(ua, UAKinds.uaMessage(UAKinds.MSIG, purpose, digest));
            return members.length != 0 && _msig(ua, md, digest, purpose == UAKinds.PURPOSE_POP_V2, d, members, write);
        }
        if (members.length != 0) return false;
        return _single(cfg, kind, d, ua, purpose, digest, sig);
    }

    /// `_sigOk`'s single-key tail, shared with `_portable` (CTR-UA-46): `sig` by the kind's verifier over `uaMessage(kind, purpose,
    /// digest)`; the caller has checked the purpose and that no `members` came.
    function _single(
        uint256 cfg,
        uint16 kind,
        bytes memory d,
        bytes32 ua,
        bytes32 purpose,
        bytes32 digest,
        bytes memory sig
    ) internal view returns (bool) {
        // spec 2026-11-19-bls12381-multi §5.3 (N1): a surplus-form kind by its own dispatch, `cfg` 0 included (no hand-off)
        if (UAKinds.hasSurplusForm(kind)) return _multi(cfg, kind, ua, purpose, digest, d, sig);
        // A6-I1: a predecessor's holder's PQZ key record on its PQZ home (the PQ holder kinds are stored: no key data in `auth`); the
        // PQ verifiers' `verify` is their `verifyPop`. R2 / N2 / M1 (spec 2026-11-19-registry-verify-only-kinds §3): any record whose
        // kind is not registrable here (not carried, or carried verify-only) goes to the generation that holds it, directly, never
        // through `predecessor` (a middle generation would answer with its verify-only verifier)
        if (!UAStore._registrable(cfg)) {
            return UAStore.via(_at(ua), ua, purpose, digest, IUARegistry.UASig("", sig, new IUARegistry.MemberSig[](0)));
        }
        bytes32 message = UAKinds.uaMessage(kind, purpose, digest);
        bytes memory ek = UAStore.expanded(ua, kind); // ML-DSA: a complete cache is the key the PoP verifies on
        bytes memory data = ek.length != 0
            ? abi.encodeWithSelector(MldsaVerifier.verifyCached.selector, ek, message, sig)
            : abi.encodeWithSelector(IUAPopVerifier.verifyPop.selector, d, message, sig);
        // group kinds: the whole group check runs here, bounded by verifyBudget (§1.8 step 6), without the hold
        if (kind >= UAKinds.MUSIG2_SECP256K1 && kind <= UAKinds.FROST_BN254) {
            return UAStore.capped(address(uint160(cfg)), IUARegistry(address(this)).verifyBudget(), data, 1, false);
        }
        return UAStore.capped(address(uint160(cfg)), UAStore._capOf(cfg), data, 1, true);
    }

    /// A surplus-form kind (`0x0121`, spec 2026-11-19-bls12381-multi §5.3 dispatch, N1) on the library's paths, every one a stored path:
    /// the registration `pop` v2 → `verifyPop(d)` (all n, `DST_MULTI_POP`, the only use of that DST), under `verifyBudget` without the
    /// hold; any other purpose → `verifyMinimal(p)` (`DST_MULTI_SIG`, every signer necessary), `p` the stored `ua ‖ s` of the record
    /// held here with that kind (else `false`), under the kind's cap with the hold. `cfg` 0 (this generation has no verifier for the
    /// kind): `false`, never a hand-off to the predecessor, whose `requireAuthorized` would take `verify`.
    function _multi(
        uint256 cfg,
        uint16 kind,
        bytes32 ua,
        bytes32 purpose,
        bytes32 digest,
        bytes memory d,
        bytes memory sig
    ) private view returns (bool) {
        if (!UAStore._registrable(cfg)) return false;
        bytes32 message = UAKinds.uaMessage(kind, purpose, digest);
        if (purpose == UAKinds.PURPOSE_POP_V2) {
            bytes memory pop = abi.encodeWithSelector(IUAPopVerifier.verifyPop.selector, d, message, sig);
            return UAStore.capped(address(uint160(cfg)), IUARegistry(address(this)).verifyBudget(), pop, 1, false);
        }
        IUARegistry.Record memory r = UAStore.layout().records[ua];
        if (r.kind != kind) return false;
        bytes memory data =
            abi.encodeWithSelector(IUAMinimalVerifier.verifyMinimal.selector, SSTORE2.read(r.keyPtr), message, sig);
        return UAStore.capped(address(uint160(cfg)), UAStore._capOf(cfg), data, 1, true);
    }

    /// The portable purposes (POP_V2, KEM, PQZ_KEY; rulings A1-f1, A5-m3; PQCHAT, UA-7 O1; PQZ_SCOPED_KEY, the three-key model
    /// K3-3, its record names the chain): any other purpose reverts `UAUnauthorized` (writes stay on `requireAuthorized`, UAAuth
    /// for native members).
    function _portablePurpose(bytes32 ua, bytes32 purpose) internal pure {
        if (
            purpose != UAKinds.PURPOSE_POP_V2 && purpose != UAKinds.PURPOSE_KEM && purpose != UAKinds.PURPOSE_PQZ_KEY
                && purpose != UAKinds.PURPOSE_PQCHAT && purpose != UAKinds.PURPOSE_PQZ_SCOPED_KEY
        ) revert IUARegistry.UAUnauthorized(ua);
    }

    /// accounts.md §1.9 `msig` row, a portable record's signature (`_sigOk` and `requirePortable` only — never `requireAuthorized`; rulings C7 /
    /// A1-I2 / A1-f1, owner 2026-10-30): strictly increasing member indexes, stop at the threshold (a MemberSig after it
    /// fails, which keeps the registration bound sound), `member_digest = keccak256(ua ‖ ua_msg)`. A native member signs
    /// the record's typed digest `digest` itself (typed-signing TS-D4, owner decision 4: `eth_signTypedData_v4`; an EOA:
    /// code-less or an EIP-7702 designator, its own key only) or, a contract, answers ERC-1271 over `digest`. Derived members
    /// sign `member_digest` under `member`. (The members come typed, TS-D12: no encoding to canonicalise.) A stored signature
    /// is minimal too (owner 2026-10-31, U8S-D1): with T the slots' total weight and N the threshold, T >= N and
    /// T - weight(i) < N for every slot, i.e. T - min(weight) < N.
    /// Only an accepted slot counts (CTR-UA-37), except in the registration's own `pop` (`pop`), which is what accepts its signers.
    /// An `msig` member is this same check one level down: its members sign under `member`, its native members `typed` still, its
    /// slots are minimal too and count only if accepted in it, a `pop` above exempting no slot of it (spec 2026-11-02-msig-nested).
    /// `md`: this structure's `member_digest`; `typed`: the record's typed digest, the same at both levels.
    function _msig(
        bytes32 ua,
        bytes32 md,
        bytes32 typed,
        bool pop,
        bytes memory d,
        IUARegistry.MemberSig[] memory sigs,
        bool write
    ) private view returns (bool) {
        uint256 threshold = UAStore.u16(d, 0);
        uint256 acc;
        // the slots that may sign: the enabled ones (CTR-UA-44 MM-3; past the members is none of them, MM-9: no count mask, which
        // would panic at 256 slots)
        uint256 yes = (pop ? type(uint256).max : _accepted(ua, sigs)) & UAStore.enabledOf(d);
        uint256 wMin = type(uint256).max; // the smallest slot weight
        uint256 next; // lowest index the next MemberSig may use
        bytes32 at = pop ? bytes32(0) : ua; // the structure (0: the registration's own, held here; `_cloneHashOf`)
        for (uint256 i; i < sigs.length; ++i) {
            {
                uint256 x = sigs[i].index;
                if (acc >= threshold || x < next || yes >> x & 1 == 0) return false;
                next = x + 1;
            }
            if (!_memberOk(d, md, typed, sigs[i], at, write)) return false;
            uint256 w = UAStore.u16(d, 4 + 36 * uint256(sigs[i].index) + 34);
            acc += w;
            if (w < wMin) wMin = w;
        }
        return acc >= threshold && acc - wMin < threshold;
    }

    /// The accepted bits `sigs` are checked against: one read for a record held here. The bits live with the record, so a gen 2
    /// hosting a gen-1 record (`setPqzKey`) asks gen 1 slot by slot, that word having no getter; gen 1's view cannot revert but out of
    /// gas, and a starved caller sees `UAVerifyGas`, never a verdict.
    function _accepted(bytes32 ua, IUARegistry.MemberSig[] memory sigs) internal view returns (uint256 bits) {
        UAStore.Layout storage s = UAStore.layout();
        if (s.records[ua].kind != 0) return s.accepted[ua];
        IUARegistry g1 = IUARegistry(_holder(ua)); // N11: the bits live with the record, at its holder
        for (uint256 i; i < sigs.length; ++i) {
            uint256 index = sigs[i].index;
            try g1.memberAccepted(ua, index) returns (bool yes) {
                if (yes) bits |= 1 << index;
            } catch {
                revert UAKinds.UAVerifyGas();
            }
        }
    }

    /// The signature `s` of member `s.index` of the structure `d`: a registered member over `md` under `member`, without key
    /// data (the registry reads the member's record, CTR-UA-33); a native member over the typed digest `typed`; an `msig` member by
    /// `_msig`, under `member` over `md`. `ua`: the structure (0: the registration's own); held elsewhere, a clone is its holder's,
    /// with the 400 k cap `_slotCap` counted for it. `write` (W1, spec 2026-11-19-registry-verify-only-kinds §3): a write's derived
    /// member is checked by its holder, a consumer entry's by this generation (§4).
    function _memberOk(
        bytes memory d,
        bytes32 md,
        bytes32 typed,
        IUARegistry.MemberSig memory s,
        bytes32 ua,
        bool write
    ) internal view returns (bool) {
        uint256 o = 4 + 36 * uint256(s.index);
        (uint16 kind, bytes32 id) = (uint16(UAStore.u16(d, o)), bytes32(UAStore.word(d, o + 2)));
        if (kind == UAKinds.MSIG) {
            bytes32 inner = UAKinds.memberDigest(id, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_MEMBER, md));
            // R6 (spec 2026-11-19-registry-verify-only-kinds §4): an inner `msig` held elsewhere keeps its holding generation's
            // verifiers on every path: its members are checked by their holder, as on a write
            bytes memory di = _msigBytes(id);
            return UAStore.verOk(s.sig, di) // CTR-UA-74: `sig` its version tag
                && _msig(
                id, inner, typed, false, di, UAStore.lift(s.members), write || UAStore.layout().records[id].kind == 0
            );
        }
        if (s.members.length != 0) return false;
        // spec 2026-11-19-bls12381-multi §5.3 (N1): a surplus-form member is checked here by `verifyMinimal`, never by the hop below
        // (whose `requireAuthorized` takes `verify`, extra signers included)
        if (UAKinds.hasSurplusForm(kind)) return _multi(_cfgMulti(), kind, id, UAKinds.PURPOSE_MEMBER, md, "", s.sig);
        if (!UAKinds.isNative(kind)) {
            // W1 (spec 2026-11-19-registry-verify-only-kinds §3): on a write the member's own holder checks it under its verifier, never a
            // verify-only one; a consumer entry asks this generation (§4)
            return UAStore.via(
                write ? _at(id) : address(this),
                id,
                UAKinds.PURPOSE_MEMBER,
                md,
                IUARegistry.UASig("", s.sig, new IUARegistry.MemberSig[](0))
            );
        }
        return UAStore.byCode(address(uint160(uint256(id))), typed, s.sig, _cloneHashOf(ua));
    }

    // ----- the line (spec 2026-11-19-registry-verify-only-kinds §11.1, owner Y1): run by `_libView` -----

    /// `IUARegistry.kindHome`: this generation where `kind` is registrable here (`_cfgKind()`, its word), else the predecessor's
    /// answer, 0 at generation 1; for `0x0142` (enabled in several generations, §11.2) the newest on the walk.
    function kindHome(uint16 kind) external returns (address) {
        if (UAStore._registrable(_cfgKind())) return address(this);
        address p = _pred();
        return p == address(0) ? address(0) : IUARegistry(p).kindHome(kind);
    }

    /// `IUARegistry.lineReaches` (§10, CTR-UA-67): `root`'s clone hash is this registry's (`_cloneHash()`, owner P4), and the
    /// walk from here reaches `root` within `MAX_GENERATION - 1` (15) predecessor steps, each a contract.
    function lineReaches(address root) external returns (bool) {
        if (root.code.length == 0 || IUARegistry(root).smartKeyCloneHash() != _cloneHash()) return false;
        address r = address(this);
        for (uint256 i; i < 16; ++i) {
            if (r == root) return true;
            if (i == 15 || r.code.length == 0) return false;
            r = IUARegistry(r).predecessor();
        }
        return false;
    }

    /// `IUARegistry.holderOf` (the registry answers a native-space id itself, P5).
    function holderOf(bytes32 ua) external returns (address, uint16, address) {
        return _holderOf(ua);
    }

    /// `IUARegistry.pqzHomeOf`: the walk's third word, never a second walk (M4).
    function pqzHomeOf(bytes32 ua) external returns (address home) {
        (,, home) = _holderOf(ua);
    }

    // ----- the PQZ readers off the hot path, run by `_libView` (moved from `UARegistryAuxLib` for its size, spec
    // 2026-11-19-registry-verify-only-kinds §11.2, controller call (auto-run)) -----

    /// The scoped views forward a record whose PQZ home is elsewhere (§11.2): to its home, or its holder where it has none.
    function _away(bytes32 ua) private view returns (address t) {
        (t,) = _pqzWhere(ua);
    }

    function pqzScopedKeyLatest(bytes32 ua, address scope) external returns (uint64) {
        address t = _away(ua);
        if (t != address(0)) return IUARegistry(t).pqzScopedKeyLatest(ua, scope);
        return UAStore.layout().scopedVersions[ua][scope].latest;
    }

    function pqzScopedPopOf(bytes32 ua, address scope, uint64 version) external returns (bytes memory) {
        address t = _away(ua);
        if (t != address(0)) return IUARegistry(t).pqzScopedPopOf(ua, scope, version);
        return SSTORE2.readChunks(UAStore.layout().scopedPop[ua][scope][version]);
    }

    function pqzOpenKemAt(bytes32 ua, address scope, uint64 version) external returns (IUARegistry.KemKey memory k) {
        address t = _away(ua);
        if (t != address(0)) return IUARegistry(t).pqzOpenKemAt(ua, scope, version);
        address p = UAStore.layout().scopedOpenKem[ua][scope][version];
        if (p == address(0)) return k;
        bytes memory pk = SSTORE2.read(p); // scheme 1 (1 B) ‖ ek (1,568 B) ‖ x25519 (32 B)
        (k.scheme, k.mlkemEk, k.x25519) = (uint8(pk[0]), UAStore.cut(pk, 1, 1568), bytes32(UAStore.word(pk, 1569)));
    }

    /// Codex U4h-2 (owner 2026-11-15), §11.2 for N generations: a scope's holder list is the line's, the predecessor's list first
    /// (itself the lists below it), then this registry's own: every generation's scoped records, oldest first.
    function _scopedFrom() private view returns (address) {
        return _pred();
    }

    function pqzScopedCount(address scope) external returns (uint256 n) {
        address p = _scopedFrom();
        if (p != address(0)) n = IUARegistry(p).pqzScopedCount(scope);
        n += UAStore.layout().scopedCount[scope];
    }

    function pqzScopedAt(address scope, uint256 i) external returns (bytes32) {
        address p = _scopedFrom();
        uint256 j = i;
        if (p != address(0)) {
            uint256 m = IUARegistry(p).pqzScopedCount(scope);
            if (j < m) return IUARegistry(p).pqzScopedAt(scope, j);
            j -= m;
        }
        if (j >= UAStore.layout().scopedCount[scope]) revert IUARegistry.UAIndex(UAKinds.PQZ_MLWE, i);
        return UAStore.layout().scopedAt[scope][j];
    }

    /// A version this generation has no copy of: the home's, or the holder's (host rule 2); 0 for one of its own records.
    function _pqzFrom(bytes32 ua) private view returns (address) {
        (address t, address h) = _pqzWhere(ua);
        return t != address(0) ? t : h;
    }

    function pqzPopOf(bytes32 ua, uint64 version) external returns (bytes memory) {
        if (UAStore.layout().pqzKey[ua][version].ptr == address(0)) {
            address t = _pqzFrom(ua);
            if (t != address(0)) return IUARegistry(t).pqzPopOf(ua, version);
        }
        return SSTORE2.readChunks(UAStore.layout().pqzPop[ua][version]);
    }

    // ----- moved from `UARegistry` (T66b 3.1b): a read off the hot path, run by `_libView` -----

    function pqzKeySigOf(bytes32 ua, uint64 version) external returns (bytes memory) {
        // gen 2 proving gen 1's `setPqzKey` key keeps no copy of the signature: gen 1 has it
        if (UAStore.layout().pqzKeySig[ua][version].length == 0) {
            address t = _pqzFrom(ua);
            if (t != address(0)) return IUARegistry(t).pqzKeySigOf(ua, version);
        }
        return SSTORE2.readChunks(UAStore.layout().pqzKeySig[ua][version]);
    }

    // ----- moved from `UARegistry` (T66b 3.1b): a read off the hot path, run by `_libView` -----

    function uaCount(uint16 kind) external returns (uint256) {
        if (!_listedHere()) return IUARegistry(_pred()).uaCount(kind);
        return UAStore.layout().uaCount[kind];
    }
}
