// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {SSTORE2} from "../common/SSTORE2.sol";
import {IUARegistry} from "./IUARegistry.sol";
import {UAKinds} from "./UAKinds.sol";
import {UAStore} from "./UAStore.sol";
import {MldsaVerifier} from "./MlDsa.sol";
import {PqUA} from "./PqUA.sol";
import {UARegistryCoreLib} from "./UARegistryCoreLib.sol";
import {UARegistryRegLib} from "./UARegistryRegLib.sol";
import {IUAPopVerifier} from "./IUAVerifier.sol";
import {PqzSet} from "../pqz/PqzSet.sol";

/// @title `UARegistry`'s auxiliary library (T66b 3.1b, owner 2026-11-09, spec 2026-11-09-t66b-library-organisation.md §11 (f)):
///        the key writes after registration: the ML-DSA expanded-key cache, the PQZ key proof and versions (`storePqzPop`,
///        `setPqzKey`) and the KEM records (`setKemKey`); and reads off the registry's hot path (`popOf`, `popSlotsOf`,
///        `webAuthnKeyOf`, `pqzPopOf`, `pqzKeySigOf`, `uaAt`, `uaPage`, `uaIndex`, run inside the registry's view). Run by
///        DELEGATECALL from the registry's thin entry (`_lib`, the same four appended words as `UARegistryCoreLib`'s), so
///        `address(this)` is the registry and the storage is its `UAStore.Layout`; one DELEGATECALL per operation, as before.
///        Same check order, same stored bytes, same events and errors as when this code was in `UARegistryCoreLib`
///        (`legacy/ua-mtx-merge/t66b/src/ua/UARegistryLib.sol`, the reads `UARegistry.sol` there). The helpers it shares with registration (the appended words,
///        the getters, the portable signature check) are `UARegistryCoreLib`'s, the registration-bound ones (the PQZ proof, the
///        holder checks, the `msig` bound, `keyUa`) `UARegistryRegLib`'s (owner 2026-11-19): the large ones run there by one
///        nested DELEGATECALL each (`_core`, T66b 3.1c, owner 2026-11-09), the small `internal` ones are compiled in: one
///        source, one copy of the large code in the registry's libraries. Called directly every entry reverts (solc's library call protection; none
///        is `view` or `pure`). UNAUDITED.
library UARegistryAuxLib {
    /// `UARegistry.UAConfig(0)`: a library this one is linked to has no code (T66b 3.1c).
    error UAConfig(uint16 kind);

    // ----- the core's shared helpers (T66b 3.1c, owner 2026-11-09, spec §11 (f)) -----

    /// Runs a helper of `core` (`UARegistryCoreLib`, or since owner 2026-11-19 `UARegistryRegLib` for the registration-bound
    /// ones) by a nested DELEGATECALL: `call`, then the four words the registry appended to this entry's calldata (its last 128
    /// bytes), so the helper reads this frame's configuration; `address(this)` and the storage stay the registry's. One level
    /// only: neither calls back here (`UARegistryRegLib` reaches only the core's `portableOk`, not from these helpers). A
    /// library without code reverts `UAConfig(0)` (a DELEGATECALL to it would succeed with nothing checked); the helper's revert
    /// data passes verbatim.
    function _core(address core, bytes memory call) private returns (bytes memory ret) {
        if (core.code.length == 0) revert UAConfig(0);
        bool ok;
        (ok, ret) = core.delegatecall(bytes.concat(call, msg.data[msg.data.length - 128:]));
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    function _portableOk(
        uint16 kind,
        bytes memory d,
        bytes32 ua,
        bytes32 purpose,
        bytes32 digest,
        IUARegistry.UASig calldata sig
    ) private returns (bool) {
        return abi.decode(
            _core(
                address(UARegistryCoreLib),
                abi.encodeWithSelector(UARegistryCoreLib.portableOk.selector, kind, d, ua, purpose, digest, sig)
            ),
            (bool)
        );
    }

    // ----- ML-DSA expanded-key cache (P6c; owner 2026-10-12) -----

    // ----- the `*Digest` views (task 3.1d, spec 2026-11-09-t66b-library-organisation.md §11 (f), owner 2026-11-09) -----

    /// `pure` views the registry runs here by DELEGATECALL (`_libPure`, nothing appended): the same ABI and answers as in the
    /// core before 3.1d (their internal twins stay there for `register` and `requirePortable`). A direct call answers the same
    /// pure result, and reads and writes nothing.
    function portableRecordDigest(bytes32 ua, uint16 kind, bytes32 pqzKeyHash, bytes32 kemRecordHash_)
        external
        pure
        returns (bytes32)
    {
        return UAKinds.portableRecordDigest(ua, kind, pqzKeyHash, kemRecordHash_);
    }

    function registrationDigest(bytes32 ua, uint16 kind, bytes32 pqzKeyHash, bytes32 kemRecordHash_, bytes32 pqzPopHash)
        external
        pure
        returns (bytes32)
    {
        return UAKinds.registrationDigest(ua, kind, pqzKeyHash, kemRecordHash_, pqzPopHash);
    }

    function pqzKeyRecordDigest(bytes32 ua, bytes32 pqzKeyHash, bytes32 pqzPopHash) external pure returns (bytes32) {
        return UAKinds.pqzKeyRecordDigest(ua, pqzKeyHash, pqzPopHash);
    }

    function pqzKeyVersionDigest(bytes32 ua, uint64 version, bytes32 pqzKeyHash) external pure returns (bytes32) {
        return UAKinds.pqzKeyVersionDigest(ua, version, pqzKeyHash);
    }

    function pqzKeyVersionRecordDigest(bytes32 ua, uint64 version, bytes32 pqzKeyHash, bytes32 pqzPopHash)
        external
        pure
        returns (bytes32)
    {
        return UAKinds.pqzKeyVersionRecordDigest(ua, version, pqzKeyHash, pqzPopHash);
    }

    /// Stores part `part` of the expanded key of `pk` under `uaOf(kind, pk)`, computed by the kind's verifier
    /// (`expandedKeyPart`) from the authenticated `pk` — never accepted from a caller (a caller-supplied expanded key
    /// allows universal forgery). Anyone may call it, before or after `register`; a part already stored is left as it
    /// is (a front-runner stored the same bytes). Each part is one transaction under EIP-7825's 2^24 regular gas (ML-DSA-44
    /// one part, ML-DSA-65 two, ML-DSA-87 three: `PqUA.mldsaParts`; `UARegistryPq.t.sol` pins each). Without a precompile `register` needs every part
    /// first (`UAKeyNotCached`, CTR-UA-23).
    /// Reverts `UAKeyCache(kind)` for a kind other than ML-DSA, a disabled kind, a part past the last, or a verifier
    /// that uses a precompile; `UAKeyData` for a key of the wrong length.
    function cacheExpandedKey(uint16 kind, bytes calldata pk, uint256 part) external returns (bytes32 ua) {
        UAStore.Layout storage s = UAStore.layout();
        address v = address(uint160(UARegistryCoreLib._cfgKind()));
        if (part >= PqUA.mldsaParts(kind) || v == address(0) || MldsaVerifier(v).PRECOMPILE() != address(0)) {
            revert IUARegistry.UAKeyCache(kind);
        }
        ua = abi.decode(
            _core(address(UARegistryRegLib), abi.encodeWithSelector(UARegistryRegLib.keyUa.selector, kind, pk)),
            (bytes32)
        );
        if (s.ekPtr[ua][part] != address(0)) return ua;
        address ptr = SSTORE2.write(MldsaVerifier(v).expandedKeyPart(pk, part));
        s.ekPtr[ua][part] = ptr;
        emit IUARegistry.UAKeyCached(ua, kind, part, ptr);
    }

    // ----- the PQZ proof later (UA8-D8, P8) and the PQZ key versions later (ruling A1-I1; group 3g) -----

    function storePqzPop(bytes32 ua, uint64 version, bytes calldata pqzPop) external {
        bool host = _host(ua);
        if (pqzPop.length == 0) revert IUARegistry.UAPqzPopHash(ua); // an empty proof is no proof (ruling A6-m)
        UAStore.PqzKey memory k = _pqzRecord(ua, version, host, keccak256(pqzPop));
        if (UAStore.layout().pqzPop[ua][version].length != 0) return; // stored: proven, or never provable here (no verifier)
        bytes memory key = SSTORE2.read(k.ptr);
        bytes32 h = UAKinds.keyHashOf(UAKinds.PQZ_MLWE, key);
        bytes32 message = version != 0
            ? UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_PQZ_KEY, UAKinds.pqzKeyVersionDigest(ua, version, h))
            : k.added
                ? UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_PQZ_KEY, UAKinds.pqzKeyDigest(ua, h))
                : _registerKeyMessage(ua, h, host);
        _core(
            address(UARegistryRegLib),
            abi.encodeWithSelector(UARegistryRegLib.pqzProof.selector, ua, version, key, pqzPop, h, message)
        );
    }

    /// Version `version`'s record for `storePqzPop`, its proof hash `popHash` checked (`UAPqzPopHash`; no such version: the
    /// hash is 0). On a host without its own record, gen 1's (from its `register` or `setPqzKey`), proven in this generation
    /// (ruling A6-I1, host rule 3) and copied here: from then on the host answers this version from its own record,
    /// whatever gen 1 writes later (host rule 2).
    function _pqzRecord(bytes32 ua, uint64 version, bool host, bytes32 popHash)
        private
        returns (UAStore.PqzKey memory k)
    {
        UAStore.Layout storage s = UAStore.layout();
        k = s.pqzKey[ua][version];
        bytes32 ph = s.pqzPopHash[ua][version];
        bool copy = host && k.ptr == address(0);
        if (copy) {
            IUARegistry g1 = IUARegistry(UARegistryCoreLib._pred());
            (k.ptr, ph,) = g1.pqzKeyAt(ua, version);
            k.added = version != 0 || g1.pqzKeySigOf(ua, 0).length != 0;
        }
        if (popHash != ph) revert IUARegistry.UAPqzPopHash(ua);
        if (copy) {
            s.pqzKey[ua][version] = k;
            s.pqzPopHash[ua][version] = ph;
            UAStore.PqzVersions storage vs = s.pqzVersions[ua];
            if (version > vs.latest) vs.latest = version;
        }
    }

    /// The R_REG message of a `register` key: `uaMessage(0x0142, PURPOSE_POP_V2, typed(UAPortableRecord))` with the
    /// registering kind from either generation (a gen-1 record on its gen-2 host: `kindOf` reads gen 1).
    function _registerKeyMessage(bytes32 ua, bytes32 h, bool host) private view returns (bytes32) {
        bytes32 d = UAKinds.portableRecordDigest(ua, UARegistryCoreLib._kindOf(ua), h, _kemHash(ua, host));
        return UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP_V2, d);
    }

    /// The initial KEM record's struct hash (the zero record = none) that `register`'s PoP signed: version 0 — the key,
    /// or its committed hash, filled or not (owner 2026-10-31) —, of the `register` arguments here or gen 1's.
    function _kemHash(bytes32 ua, bool host) private view returns (bytes32) {
        UAStore.Layout storage s = UAStore.layout();
        IUARegistry.KemKey memory kem;
        bytes32 committed;
        if (host) {
            (,, IUARegistry.UAAttrs memory a,,) = IUARegistry(UARegistryCoreLib._pred()).registrationOf(ua);
            (kem, committed) = (a.kem, a.kemPkHash);
        } else {
            UAStore.KemCommit memory c = s.kemCommit[ua];
            if (c.kemPkHash != 0) return UAKinds.kemRecordHash(ua, 0, c.scheme, c.kemPkHash);
            (kem,) = UAStore.kemAt(ua, 0);
        }
        if (committed != 0) return UAKinds.kemRecordHash(ua, 0, kem.scheme, committed);
        return UAKinds.kemRecordHash(ua, 0, UAKinds.kemPk(kem));
    }

    /// Where `storePqzPop` / `setPqzKey` write (ruling A6-I1): false = the record is here; true = gen 1 holds it and this
    /// gen 2 enables 0x0142 (its constructor refuses 0x0142 when gen 1 enables it, so this is the oldest generation
    /// with the verifier); else `UAUnauthorized` (unregistered, or a gen-1 record on a gen 2 without 0x0142: UA8-D11).
    function _host(bytes32 ua) private view returns (bool) {
        UAStore.Layout storage s = UAStore.layout();
        if (s.records[ua].kind != 0) return false;
        if (
            UARegistryCoreLib._pred() != address(0) && uint160(UARegistryCoreLib._cfgPqz()) != 0
                && UARegistryCoreLib._kindOf(ua) != 0
        ) return true;
        revert IUARegistry.UAUnauthorized(ua);
    }

    function setPqzKey(
        bytes32 ua,
        uint64 version,
        bytes calldata pqzKey,
        bytes32 pqzPopHash,
        IUARegistry.UASig calldata sig
    ) external {
        UAStore.Layout storage s = UAStore.layout();
        (uint16 kind, bytes memory d, bool host) = _holderOf(ua);
        _core(address(UARegistryRegLib), abi.encodeWithSelector(UARegistryRegLib.pqzHolder.selector, kind, d, ua, host));
        _pqzNext(ua, version, host);
        bytes32 h = UARegistryRegLib._pqzKeyHash(pqzKey);
        // KV-1 (Codex #1): no two versions of one UA hold the same key, before any proof exists; a host reads gen 1's too
        if (s.pqzKeyUsed[ua][h] || (host && IUARegistry(UARegistryCoreLib._pred()).pqzKeyUsed(ua, h))) {
            revert IUARegistry.UAKeyInUse(h, ua);
        }
        if (pqzPopHash == 0 || pqzPopHash == UARegistryRegLib.EMPTY_PROOF_HASH) revert IUARegistry.UAPqzPopHash(ua);
        bytes32 rd = version == 0
            ? UAKinds.pqzKeyRecordDigest(ua, h, pqzPopHash)
            : UAKinds.pqzKeyVersionRecordDigest(ua, version, h, pqzPopHash);
        if (!_portableOk(kind, d, ua, UAKinds.PURPOSE_PQZ_KEY, rd, sig)) revert IUARegistry.UAUnauthorized(ua);
        bytes memory stored = _portableBytes(sig);
        s.pqzKey[ua][version] = UAStore.PqzKey(SSTORE2.write(pqzKey), false, true);
        s.pqzPopHash[ua][version] = pqzPopHash;
        s.pqzKeySig[ua][version] = SSTORE2.writeChunks(stored);
        s.pqzKeyUsed[ua][h] = true;
        s.pqzVersions[ua].latest = version;
        emit IUARegistry.UAPqzKeyAdded(ua, version, h, pqzPopHash, pqzKey, stored);
    }

    /// The record `setPqzKey` / `setPqzScopedKey` sign for (`_host`'s rule): its kind and key data, here or in gen 1 on a host. An
    /// `msig`: its **current** structure (CTR-UA-44), gen 1's `msigOf` + `msigStateOf` on a host, never `registrationOf` (a raised
    /// threshold would be read as the first one).
    function _holderOf(bytes32 ua) private view returns (uint16 kind, bytes memory d, bool host) {
        host = _host(ua);
        IUARegistry.Record memory r = UAStore.layout().records[ua];
        kind = host ? UARegistryCoreLib._kindOf(ua) : r.kind;
        if (kind == UAKinds.MSIG) d = UARegistryCoreLib._msigBytes(ua);
        else if (host) (, d,,,) = IUARegistry(UARegistryCoreLib._pred()).registrationOf(ua);
        else (d,) = UAStore.registration(ua, r);
    }

    // ----- `msig` member changes (CTR-UA-44, TODO 3ze, owner 2026-11-14) -----

    /// The calldata-free part of an `updateMsig` (stack): the id, the chain word, the stored structure, the target (typed and as
    /// its blob), the slots this update appends or re-enables.
    struct Update {
        bytes32 ua;
        bytes32 chainUid;
        bytes stored;
        IUARegistry.MsigStructure st;
        bytes t;
        uint256 fresh;
    }

    /// `IUARegistry.updateMsig` (CTR-UA-44), its check order (spec rows 1–13), then the blob (MM-6) behind the record's `keyPtr`
    /// (MM-7). Nothing reads an event; the id, `registrationOf`, `popOf`, `popSlotsOf` keep the first structure (MM-1).
    function updateMsig(
        bytes32 ua,
        uint64 version,
        IUARegistry.MsigStructure calldata structure,
        uint256 enabled,
        uint64 validUntilBlock,
        IUARegistry.MemberSig[] calldata sigs,
        bytes32 chainUid_
    ) external {
        Update memory u;
        (u.ua, u.chainUid) = (ua, _chainUid());
        if (chainUid_ != u.chainUid) revert IUARegistry.ChainUidMismatch(u.chainUid, chainUid_); // 1
        if (block.number > validUntilBlock) revert IUARegistry.UAMsigExpired(ua); // 2
        u.stored = _stored(ua, version); // 3, 4
        u.st = structure;
        _target(u, enabled); // 5–8
        u.t = UAStore.blob(u.st, enabled, version);
        _quorumSigned(
            u, UAKinds.msigUpdateDigest(ua, u.chainUid, address(this), version, u.st, enabled, validUntilBlock), sigs
        );
        _fresh(u); // 10
        _core(address(UARegistryRegLib), abi.encodeWithSelector(UARegistryRegLib.msigBound.selector, ua, u.t, u.stored)); // 11–13
        UAStore.layout().records[ua].keyPtr = SSTORE2.write(u.t);
        emit IUARegistry.UAMsigUpdated(ua, version, u.st.threshold, uint16(u.st.members.length), enabled);
    }

    /// Rows 3, 4: an `msig` held here (a gen-1 record on gen 2 too: `UAUnauthorized`, as `acceptMembership`), and `version` =
    /// the stored one + 1 (MM-13, owner 2026-11-14: no jump; `UAMsigVersion`). Returns the stored structure.
    function _stored(bytes32 ua, uint64 version) private view returns (bytes memory d) {
        IUARegistry.Record memory r = UAStore.layout().records[ua];
        if (r.kind != UAKinds.MSIG) revert IUARegistry.UAUnauthorized(ua);
        d = UAStore.msig(ua, r.keyPtr);
        uint64 stored = UAStore.versionOf(d);
        if (version != stored + 1) revert IUARegistry.UAMsigVersion(ua, stored);
    }

    /// Rows 5–8 on the target `u.st` / `enabled` against `u.stored`: the slot count, the enabled bits, at most 16 enabled
    /// (`UAMsigSlots`); every stored slot keeps `kind` and `id` (`UAMsigSlotChanged`); weights ≠ 0, an appended slot a member
    /// kind with a native kind iff a native-space id, one slot per `id` whatever its kind, no enabled self-slot
    /// (`UAKeyData(0x0120)`); the threshold ≠ 0 and at most the weight of the enabled and accepted slots (an appended slot has
    /// not accepted yet; `UAMsigThreshold`). Sets `u.fresh`: the slots appended, or enabled again, here (row 10).
    function _target(Update memory u, uint256 enabled) private view {
        IUARegistry.MsigMember[] memory m = u.st.members;
        uint256 n = m.length;
        uint256 sn = UAStore.u16(u.stored, 2);
        uint256 on;
        for (uint256 b = enabled; b != 0; b &= b - 1) {
            ++on;
        }
        if (n < sn || n > 256 || (n != 256 && enabled >> n != 0) || on > 16) revert IUARegistry.UAMsigSlots(n);
        for (uint256 i; i < sn; ++i) {
            uint256 o = 4 + 36 * i;
            if (m[i].kind != UAStore.u16(u.stored, o) || m[i].id != bytes32(UAStore.word(u.stored, o + 2))) {
                revert IUARegistry.UAMsigSlotChanged(uint16(i));
            }
        }
        uint256 se = UAStore.enabledOf(u.stored);
        uint256 accepted = UAStore.layout().accepted[u.ua];
        uint256 weight;
        for (uint256 i; i < n; ++i) {
            IUARegistry.MsigMember memory x = m[i];
            bool en = enabled >> i & 1 != 0;
            if (x.weight == 0 || (en && x.kind == UAKinds.MSIG && x.id == u.ua)) {
                revert IUARegistry.UAKeyData(UAKinds.MSIG);
            }
            if (i >= sn) {
                if (!UAKinds.isMember(x.kind, true) || UAKinds.isNative(x.kind) != UAKinds.inNativeSpace(x.id)) {
                    revert IUARegistry.UAKeyData(UAKinds.MSIG);
                }
                for (uint256 j; j < i; ++j) {
                    if (m[j].id == x.id) revert IUARegistry.UAKeyData(UAKinds.MSIG);
                }
            }
            if (i >= sn || (en && se >> i & 1 == 0)) u.fresh |= 1 << i;
            if (en && accepted >> i & 1 != 0) weight += x.weight;
        }
        if (u.st.threshold == 0 || u.st.threshold > weight) revert IUARegistry.UAMsigThreshold(u.ua);
    }

    /// Row 9: `sigs` reach the **stored** threshold over the stored enabled and accepted slots, minimal, over `typed` (the
    /// `requirePortable` `msig` arm under `PURPOSE_MSIG_UPDATE`; `UAUnauthorized`).
    function _quorumSigned(Update memory u, bytes32 typed, IUARegistry.MemberSig[] calldata sigs) private {
        bytes32 md = UAKinds.memberDigest(u.ua, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_MSIG_UPDATE, typed));
        bytes memory ok = _core(
            address(UARegistryCoreLib),
            abi.encodeWithSelector(UARegistryCoreLib.msigOk.selector, u.ua, md, typed, u.stored, sigs)
        );
        if (!abi.decode(ok, (bool))) revert IUARegistry.UAUnauthorized(u.ua);
    }

    /// Row 10: a slot appended or enabled again by this update is a member of this profile, native or registered under its kind,
    /// and an `msig` member holds no enabled `msig` slot now (a third level; `UAMemberUnknown`). A slot already enabled is never
    /// re-judged here: a member that grew a level since is left out of the bound instead (MM-14).
    function _fresh(Update memory u) private view {
        IUARegistry self = IUARegistry(address(this));
        bool hedera = self.hederaNative();
        IUARegistry.MsigMember[] memory m = u.st.members;
        for (uint256 i; u.fresh >> i != 0; ++i) {
            if (u.fresh >> i & 1 == 0) continue;
            (uint16 kind, bytes32 id) = (m[i].kind, m[i].id);
            if (
                !UAKinds.isMember(kind, hedera) || (!UAKinds.isNative(kind) && self.kindOf(id) != kind)
                    || (kind == UAKinds.MSIG && _nested(id))
            ) revert IUARegistry.UAMemberUnknown(id);
        }
    }

    /// Does the `msig` `id` hold an enabled `msig` slot (its current structure, here or gen 1's)?
    function _nested(bytes32 id) private view returns (bool) {
        bytes memory d = UARegistryCoreLib._msigBytes(id);
        uint256 en = UAStore.enabledOf(d);
        uint256 n = UAStore.u16(d, 2);
        for (uint256 i; i < n; ++i) {
            if (en >> i & 1 != 0 && UAStore.u16(d, 4 + 36 * i) == UAKinds.MSIG) return true;
        }
        return false;
    }

    /// `IUARegistry.msigStateOf` (CTR-UA-44): run by `_libView`.
    function msigStateOf(bytes32 ua) external returns (uint64 version, uint256 enabled, uint256 accepted) {
        if (UARegistryCoreLib._elsewhere(ua)) return IUARegistry(UARegistryCoreLib._pred()).msigStateOf(ua);
        IUARegistry.Record memory r = UAStore.layout().records[ua];
        if (r.kind != UAKinds.MSIG) return (0, 0, 0);
        accepted = UAStore.layout().accepted[ua];
        if (r.keyPtr != address(0)) (enabled, version) = UAStore.trailer(r.keyPtr);
        else enabled = UAStore.enabledOf(UAStore.keyRest(ua));
    }

    // ----- the PQZ three-key model: scoped PQZ key records (spec 2026-11-13-pqz-three-keys K3-3) -----

    /// `IPqzToken.pqzVerifyConfig()` and the word of its static `PqzVerifyConfig` tuple that holds `pqzOpening`: the
    /// thirteenth (index 12), after `pqzOwnKey` (index 11) appended behind `verifierFeeEta` (K3-1).
    bytes4 private constant PQZ_VERIFY_CONFIG = bytes4(keccak256("pqzVerifyConfig()"));
    uint256 private constant OPENING_WORD = 12 * 32;

    /// The calldata-free part of a `setPqzScopedKey` (stack): the record's kind and key data, host, key hash, opening KEM key.
    struct Scoped {
        uint16 kind;
        bytes d;
        bool host;
        bytes32 h;
        bytes kemPk;
    }

    /// `IUARegistry.setPqzScopedKey` (K3-3), its check order.
    function setPqzScopedKey(
        bytes32 ua,
        address scope,
        uint64 version,
        bytes calldata pqzKey,
        bytes32 pqzPopHash,
        IUARegistry.KemKey calldata openKem,
        uint64 validUntilBlock,
        IUARegistry.UASig calldata sig
    ) external {
        if (block.number > validUntilBlock) revert IUARegistry.UAPqzRecordExpired(ua);
        Scoped memory c;
        (c.kind, c.d, c.host) = _holderOf(ua);
        _core(
            address(UARegistryRegLib),
            abi.encodeWithSelector(UARegistryRegLib.pqzHolder.selector, c.kind, c.d, ua, c.host)
        );
        // ruling 9 (owner 2026-11-13): no `msig` holds the shared key at first
        if (scope == address(0) && c.kind == UAKinds.MSIG) revert IUARegistry.UAPqzHolder(ua);
        c.h = _scopedNext(ua, scope, version, pqzKey, c.host);
        if (pqzPopHash == 0 || pqzPopHash == UARegistryRegLib.EMPTY_PROOF_HASH) revert IUARegistry.UAPqzPopHash(ua);
        c.kemPk = UAKinds.kemPk(openKem);
        if ((c.kemPk.length != 0) != _opening(scope)) revert IUARegistry.UAPqzOpenKem(scope);
        if (c.kemPk.length != 0) UARegistryRegLib._checkKemPk(c.kemPk);
        bytes32 rd = UAKinds.pqzScopedKeyRecordDigest(
            ua,
            _class(scope),
            _chainUid(),
            scope,
            version,
            c.h,
            pqzPopHash,
            c.kemPk.length == 0 ? bytes32(0) : keccak256(c.kemPk),
            validUntilBlock
        );
        if (!_portableOk(c.kind, c.d, ua, UAKinds.PURPOSE_PQZ_SCOPED_KEY, rd, sig)) {
            revert IUARegistry.UAUnauthorized(ua);
        }
        UAStore.Layout storage s = UAStore.layout();
        s.scopedKey[ua][scope][version].ptr = SSTORE2.write(pqzKey);
        s.scopedPopHash[ua][scope][version] = pqzPopHash;
        if (c.kemPk.length != 0) s.scopedOpenKem[ua][scope][version] = SSTORE2.write(c.kemPk);
        s.pqzKeyUsed[ua][c.h] = true;
        s.scopedVersions[ua][scope].latest = version;
        emit IUARegistry.UAPqzScopedKeyAdded(
            ua, scope, version, c.h, pqzPopHash, pqzKey, openKem, validUntilBlock, _portableBytes(sig)
        );
    }

    /// K3-3's sequence and key checks: `version == latest + 1`, the first 0 (`UAPqzKeyVersion`); a set's length and version 0's
    /// length (`UAKeyData(0x0142)`, review S-5: a holder's set is fixed per scope); key bytes in no record space of the UA
    /// (`pqzKeyUsed`, a host's gen 1 too; `UAKeyInUse(h, ua)`). Returns the key hash.
    function _scopedNext(bytes32 ua, address scope, uint64 version, bytes calldata pqzKey, bool host)
        private
        view
        returns (bytes32 h)
    {
        UAStore.Layout storage s = UAStore.layout();
        address p0 = s.scopedKey[ua][scope][0].ptr;
        if (version != (p0 == address(0) ? 0 : s.scopedVersions[ua][scope].latest + 1)) {
            revert IUARegistry.UAPqzKeyVersion(ua, version);
        }
        h = UARegistryRegLib._pqzKeyHash(pqzKey);
        if (p0 != address(0) && pqzKey.length + 1 != p0.code.length) revert IUARegistry.UAKeyData(UAKinds.PQZ_MLWE);
        if (s.pqzKeyUsed[ua][h] || (host && IUARegistry(UARegistryCoreLib._pred()).pqzKeyUsed(ua, h))) {
            revert IUARegistry.UAKeyInUse(h, ua);
        }
    }

    /// Does `scope`'s record carry the opening KEM key? Scope 0 (class `offchain-shared`): always. A token: its `pqzOpening`,
    /// read by one static call of `pqzVerifyConfig()` whose answer is copied up to word 12 and no further (Fable P3-1: a
    /// hostile scope's long return costs the relayer nothing); no answer, a short one, `pqzOwnKey` (word 11) other than 1 (a
    /// class-3 record of a token that never reads one) or `pqzOpening` other than 0 / 1: `UAPqzOpenKem`.
    function _opening(address scope) private view returns (bool) {
        if (scope == address(0)) return true;
        bytes4 sel = PQZ_VERIFY_CONFIG;
        bool ok;
        uint256 own;
        uint256 w;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, sel)
            ok := staticcall(gas(), scope, m, 4, m, add(OPENING_WORD, 32))
            ok := and(ok, iszero(lt(returndatasize(), add(OPENING_WORD, 32)))) // after the call (Yul evaluates arguments right to left)
            own := mload(add(m, sub(OPENING_WORD, 32)))
            w := mload(add(m, OPENING_WORD))
        }
        if (!ok || own != 1 || w > 1) revert IUARegistry.UAPqzOpenKem(scope);
        return w == 1;
    }

    /// `keyClass` of a scope: 2 `offchain-shared` (scope 0), 3 `offchain-token`.
    function _class(address scope) private pure returns (uint8) {
        return scope == address(0) ? 2 : 3;
    }

    function _chainUid() private view returns (bytes32) {
        return IUARegistry(address(this)).chainUid();
    }

    /// `IUARegistry.storePqzScopedPop` (K3-3): `storePqzPop`'s rule on the scoped record space.
    function storePqzScopedPop(bytes32 ua, address scope, uint64 version, bytes calldata pqzPop) external {
        UAStore.Layout storage s = UAStore.layout();
        if (pqzPop.length == 0 || keccak256(pqzPop) != s.scopedPopHash[ua][scope][version]) {
            revert IUARegistry.UAPqzPopHash(ua);
        }
        if (s.scopedPop[ua][scope][version].length != 0) return;
        bytes memory key = SSTORE2.read(s.scopedKey[ua][scope][version].ptr);
        s.scopedPop[ua][scope][version] = SSTORE2.writeChunks(pqzPop);
        bool proven = _scopedProve(ua, scope, version, key, pqzPop);
        emit IUARegistry.UAPqzScopedPopStored(ua, scope, version, UAStore.checked(proven), pqzPop);
        // a token's scope (class 3): its versions share version 0's length, the token's set (K3-3 "Sets", Fable P3-2), so a key
        // of another set than this registry's build becomes current too; scope 0 keeps the class-1 rule
        if (proven || scope != address(0) || key.length == PqzSet.PK) _scopedCurrent(ua, scope, version);
    }

    /// Where slot 0x0142 has a verifier: `R_REG` over the scoped message (`UAPoP`), then one owner per proven key across every
    /// record space (K3-3 "never the registry key"; `UAKeyInUse`), `keyOwner`, `proven`. False without the verifier, and
    /// (owner 2026-11-15, Codex U4h-1, CTR-PQZ-30's Change) for a key of another set than this build's (`PqzSet.PK`): the
    /// verifier checks its own set only, so such a proof is stored unproven, `proven` false and `UAPqzScopedPopStored` with
    /// `CHECKED_NONE`, for the off-chain check of CTR-PQZ-30; no on-chain path takes it as checked.
    function _scopedProve(bytes32 ua, address scope, uint64 version, bytes memory key, bytes calldata pqzPop)
        private
        returns (bool)
    {
        uint256 cfg = UARegistryCoreLib._cfgPqz();
        if (uint160(cfg) == 0 || key.length != PqzSet.PK) return false;
        bytes32 h = UAKinds.keyHashOf(UAKinds.PQZ_MLWE, key);
        bytes32 m = UAKinds.uaMessage(
            UAKinds.PQZ_MLWE,
            UAKinds.PURPOSE_PQZ_SCOPED_KEY,
            UAKinds.pqzScopedKeyDigest(ua, _class(scope), _chainUid(), scope, version, h)
        );
        bytes memory data = abi.encodeWithSelector(IUAPopVerifier.verifyPop.selector, key, m, pqzPop);
        if (!UAStore.capped(address(uint160(cfg)), cfg >> 160, data, 1, true)) revert IUARegistry.UAPoP();
        bytes32 owner = UARegistryCoreLib._keyOwner(h);
        if (owner != 0) revert IUARegistry.UAKeyInUse(h, owner);
        UAStore.Layout storage s = UAStore.layout();
        s.keyOwner[h] = ua;
        s.scopedKey[ua][scope][version].proven = true;
        return true;
    }

    /// An eligible scoped version: the scope's holder list once per UA, then `current` when at or above it (never down).
    function _scopedCurrent(bytes32 ua, address scope, uint64 version) private {
        UAStore.Layout storage s = UAStore.layout();
        UAStore.PqzVersions storage vs = s.scopedVersions[ua][scope];
        if (!vs.listed) {
            uint256 n = s.scopedCount[scope];
            s.scopedAt[scope][n] = ua;
            s.scopedCount[scope] = n + 1;
            vs.listed = true;
        }
        if (version < vs.current) return;
        vs.current = version;
        emit IUARegistry.UAPqzScopedKeyCurrent(ua, scope, version);
    }

    /// A gen-1 record read on a gen 2 that is not the PQZ host: the scoped views forward it (as `pqzKeyOf`).
    function _away(bytes32 ua) private view returns (bool) {
        return UARegistryCoreLib._elsewhere(ua) && uint160(UARegistryCoreLib._cfgPqz()) == 0;
    }

    function pqzScopedKeyLatest(bytes32 ua, address scope) external returns (uint64) {
        if (_away(ua)) return IUARegistry(UARegistryCoreLib._pred()).pqzScopedKeyLatest(ua, scope);
        return UAStore.layout().scopedVersions[ua][scope].latest;
    }

    function pqzScopedPopOf(bytes32 ua, address scope, uint64 version) external returns (bytes memory) {
        if (_away(ua)) return IUARegistry(UARegistryCoreLib._pred()).pqzScopedPopOf(ua, scope, version);
        return SSTORE2.readChunks(UAStore.layout().scopedPop[ua][scope][version]);
    }

    function pqzOpenKemAt(bytes32 ua, address scope, uint64 version) external returns (IUARegistry.KemKey memory k) {
        if (_away(ua)) return IUARegistry(UARegistryCoreLib._pred()).pqzOpenKemAt(ua, scope, version);
        address p = UAStore.layout().scopedOpenKem[ua][scope][version];
        if (p == address(0)) return k;
        bytes memory pk = SSTORE2.read(p); // scheme 1 (1 B) ‖ ek (1,568 B) ‖ x25519 (32 B)
        (k.scheme, k.mlkemEk, k.x25519) = (uint8(pk[0]), UAStore.cut(pk, 1, 1568), bytes32(UAStore.word(pk, 1569)));
    }

    /// Codex U4h-2 (owner 2026-11-15): a scope's holder list follows the scoped key reads' forwarding (`_away`): on a registry that
    /// is not the PQZ host (slot 0x0142 empty) in front of a predecessor, the predecessor's list first, then this registry's own.
    function _scopedFrom() private view returns (address p) {
        if (uint160(UARegistryCoreLib._cfgPqz()) == 0) p = UARegistryCoreLib._pred();
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

    function pqzScopedKeyDigest(
        bytes32 ua,
        uint8 keyClass,
        bytes32 chainUid,
        address token,
        uint64 version,
        bytes32 pqzKeyHash
    ) external pure returns (bytes32) {
        return UAKinds.pqzScopedKeyDigest(ua, keyClass, chainUid, token, version, pqzKeyHash);
    }

    function pqzScopedKeyRecordDigest(
        bytes32 ua,
        uint8 keyClass,
        bytes32 chainUid,
        address token,
        uint64 version,
        bytes32 pqzKeyHash,
        bytes32 pqzPopHash,
        bytes32 openKemHash,
        uint64 validUntilBlock
    ) external pure returns (bytes32) {
        return UAKinds.pqzScopedKeyRecordDigest(
            ua, keyClass, chainUid, token, version, pqzKeyHash, pqzPopHash, openKemHash, validUntilBlock
        );
    }

    /// KV-1 (R2, O6): version 0 is write-once (`UAPqzKeySet` once the UA has one, here or, on a host, in gen 1); a version
    /// v ≥ 1 needs version 0 and `v == latest + 1` (`UAPqzKeyVersion`), `latest` the larger of both generations' on a host.
    function _pqzNext(bytes32 ua, uint64 version, bool host) private view {
        UAStore.Layout storage s = UAStore.layout();
        bool has0 = s.pqzKey[ua][0].ptr != address(0);
        uint64 latest = s.pqzVersions[ua].latest;
        if (host) {
            IUARegistry g1 = IUARegistry(UARegistryCoreLib._pred());
            (address p0,,) = g1.pqzKeyAt(ua, 0);
            has0 = has0 || p0 != address(0);
            uint64 l1 = g1.pqzKeyLatest(ua);
            if (l1 > latest) latest = l1;
        }
        if (version == 0) {
            if (has0) revert IUARegistry.UAPqzKeySet(ua);
        } else if (!has0 || version != latest + 1) {
            revert IUARegistry.UAPqzKeyVersion(ua, version);
        }
    }

    /// The stored bytes of a portable `UASig`: `signature`, or an msig's `abi.encode(members)` (the pre-R1 form).
    function _portableBytes(IUARegistry.UASig calldata sig) private pure returns (bytes memory) {
        return sig.members.length != 0 ? abi.encode(sig.members) : sig.signature;
    }

    // ----- KEM records (P4, P5, P7; UA8-D3–D5, D11, D12) -----

    function setKemKey(bytes32 ua, uint64 version, IUARegistry.KemKey calldata kem, IUARegistry.UASig calldata sig)
        external
    {
        UAStore.Layout storage s = UAStore.layout();
        IUARegistry.Record memory r = s.records[ua];
        // UA8-D11 before `_sigOk`: its gen-1 fallback would verify a gen-1 holder's record here (A6 re-review)
        if (r.kind == 0) revert IUARegistry.UAUnauthorized(ua);
        if (!UARegistryRegLib._kemHolder(r.kind)) revert IUARegistry.UAKemHolder(ua); // CTR-UA-32: an `msig` holds no KEM key
        (bytes memory d,) = UAStore.registration(ua, r);
        // owner 2026-10-31: never overwrite (every version write-once); version 0 only to fill the `register` commit
        if (s.kem[ua][version].length != 0) revert IUARegistry.UAKemVersion(ua, version);
        bytes32 committed = version == 0 ? s.kemCommit[ua].kemPkHash : bytes32(0);
        if (version == 0 && committed == 0) revert IUARegistry.UAKemVersion(ua, 0);
        bytes memory kemPk = UAKinds.kemPk(kem);
        UARegistryRegLib._checkKemPk(kemPk);
        bytes memory stored;
        if (version == 0) {
            // the PoP signed the committed record: no signature of its own, anyone may fill it (as `storePqzPop`)
            if (sig.keyData.length != 0 || sig.signature.length != 0 || sig.members.length != 0) {
                revert IUARegistry.UAUnauthorized(ua);
            }
            if (keccak256(kemPk) != committed) revert IUARegistry.UAKemKeyHash(ua);
        } else {
            bytes32 rd = UAKinds.kemRecordDigest(ua, version, kemPk);
            if (!_portableOk(r.kind, d, ua, UAKinds.PURPOSE_KEM, rd, sig)) revert IUARegistry.UAUnauthorized(ua);
            stored = _portableBytes(sig);
            if (version > s.kemMax[ua]) s.kemMax[ua] = version;
        }
        s.kem[ua][version] = SSTORE2.writeChunks(bytes.concat(kemPk, stored));
        emit IUARegistry.UAKemKeySet(ua, version, keccak256(kemPk), kem, stored);
    }

    // ----- moved from `UARegistry` (T66b 3.1b): a read off the hot path, run by `_libView` -----

    function popSlotsOf(bytes32 ua) external returns (uint16[] memory index, bytes32[] memory hash) {
        if (UARegistryCoreLib._elsewhere(ua)) return IUARegistry(UARegistryCoreLib._pred()).popSlotsOf(ua);
        uint256 bits = UAStore.layout().popSlots[ua];
        uint256 n;
        for (uint256 b = bits; b != 0; b &= b - 1) {
            ++n;
        }
        (index, hash) = (new uint16[](n), new bytes32[](n));
        n = 0;
        for (uint256 i; bits >> i != 0; ++i) {
            if (bits >> i & 1 == 0) continue;
            (index[n], hash[n]) = (uint16(i), UAStore.layout().memberSigHash[ua][i]);
            ++n;
        }
    }

    // ----- moved from `UARegistry` (T66b 3.1b): a read off the hot path, run by `_libView` -----

    /// TS-D13: the typed keys of `webauthn-p256` / MuSig2 / FROST records (empty for any other id).
    function webAuthnKeyOf(bytes32 ua) external returns (IUARegistry.WebAuthnKey memory k) {
        if (UARegistryCoreLib._elsewhere(ua)) return IUARegistry(UARegistryCoreLib._pred()).webAuthnKeyOf(ua);
        if (UAStore.layout().records[ua].kind != UAKinds.WEBAUTHN_P256) return k;
        bytes memory d = UAStore.keyRest(ua);
        (k.x, k.y, k.rpIdHash) =
        (bytes32(UAStore.word(d, 0)), bytes32(UAStore.word(d, 32)), bytes32(UAStore.word(d, 64)));
    }

    /// `bls12381-multi`'s typed key (spec 2026-11-19-bls12381-multi §2): `d` expanded from the stored `ua ‖ s` (the blob holds no key
    /// bytes), cut into `aggKey ‖ u16 threshold ‖ u16 n ‖ n × (key ‖ u16 weight)`.
    function blsMultiKeyOf(bytes32 ua) external returns (IUARegistry.BlsMultiKey memory k) {
        if (UARegistryCoreLib._elsewhere(ua)) return IUARegistry(UARegistryCoreLib._pred()).blsMultiKeyOf(ua);
        IUARegistry.Record memory r = UAStore.layout().records[ua];
        if (r.kind != UAKinds.BLS12381_MULTI) return k;
        (bytes memory d,) = UAStore.registration(ua, r);
        k.aggKey = UAStore.cut(d, 0, 256);
        k.threshold = uint16(UAStore.u16(d, 256));
        k.members = new IUARegistry.BlsMultiMember[](UAStore.u16(d, 258));
        for (uint256 i; i < k.members.length; ++i) {
            uint256 o = 260 + 258 * i;
            k.members[i] = IUARegistry.BlsMultiMember(UAStore.cut(d, o, 256), uint16(UAStore.u16(d, o + 256)));
        }
    }

    // ----- moved from `UARegistry` (T66b 3.1b): a read off the hot path, run by `_libView` -----

    function pqzPopOf(bytes32 ua, uint64 version) external returns (bytes memory) {
        if (UAStore.layout().pqzKey[ua][version].ptr == address(0) && UARegistryCoreLib._elsewhere(ua)) {
            return IUARegistry(UARegistryCoreLib._pred()).pqzPopOf(ua, version);
        }
        return SSTORE2.readChunks(UAStore.layout().pqzPop[ua][version]);
    }

    // ----- moved from `UARegistry` (T66b 3.1b): a read off the hot path, run by `_libView` -----

    function pqzKeySigOf(bytes32 ua, uint64 version) external returns (bytes memory) {
        // gen 2 proving gen 1's `setPqzKey` key keeps no copy of the signature: gen 1 has it
        if (UAStore.layout().pqzKeySig[ua][version].length == 0 && UARegistryCoreLib._elsewhere(ua)) {
            return IUARegistry(UARegistryCoreLib._pred()).pqzKeySigOf(ua, version);
        }
        return SSTORE2.readChunks(UAStore.layout().pqzKeySig[ua][version]);
    }

    // ----- moved from `UARegistry` (T66b 3.1b): a read off the hot path, run by `_libView` -----

    function uaPage(uint16 kind, uint256 start, uint256 n) external returns (bytes32[] memory page) {
        if (!UARegistryCoreLib._listedHere()) return IUARegistry(UARegistryCoreLib._pred()).uaPage(kind, start, n);
        uint256 count = UAStore.layout().uaCount[kind];
        if (start >= count) return page;
        if (n > count - start) n = count - start;
        page = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            page[i] = UAStore.layout().uaAt[kind][start + i];
        }
    }

    // ----- moved from `UARegistry` (T66b 3.1b): a read off the hot path, run by `_libView` -----

    function uaIndex(bytes32 ua) external returns (uint256) {
        IUARegistry.Record memory r = UAStore.layout().records[ua];
        if (r.kind == 0 && UARegistryCoreLib._pred() != address(0)) {
            return IUARegistry(UARegistryCoreLib._pred()).uaIndex(ua);
        }
        if (r.kind == 0) revert IUARegistry.UANotIndexed(ua);
        return r.index;
    }

    // ----- moved from `UARegistry` (T66b 3.1b): a read off the hot path, run by `_libView` -----

    function uaAt(uint16 kind, uint256 i) external returns (bytes32) {
        if (!UARegistryCoreLib._listedHere()) return IUARegistry(UARegistryCoreLib._pred()).uaAt(kind, i);
        if (i >= UAStore.layout().uaCount[kind]) revert IUARegistry.UAIndex(kind, i);
        return UAStore.layout().uaAt[kind][i];
    }

    // ----- moved from `UARegistry` (T66b 3.1b), then from `UARegistryCoreLib` (owner 2026-11-15, D1): a read off the hot path, run by
    // `_libView` -----

    function registrationOf(bytes32 ua)
        external
        returns (
            uint16 kind,
            bytes memory keyData,
            IUARegistry.UAAttrs memory attrs,
            bytes memory pop,
            bytes memory pqzPop
        )
    {
        if (UARegistryCoreLib._elsewhere(ua)) {
            (kind, keyData, attrs, pop, pqzPop) = IUARegistry(UARegistryCoreLib._pred()).registrationOf(ua);
            // A5-c2 / A6-I1: gen 1's `register` key (version 0) proven here, its proof stored here
            if (attrs.pqzKey.length != 0 && pqzPop.length == 0 && !UAStore.layout().pqzKey[ua][0].added) {
                pqzPop = SSTORE2.readChunks(UAStore.layout().pqzPop[ua][0]);
            }
            return (kind, keyData, attrs, pop, pqzPop);
        }
        IUARegistry.Record memory r = UAStore.layout().records[ua];
        kind = r.kind;
        if (kind == 0) return (kind, keyData, attrs, pop, pqzPop);
        (keyData, pop) = UAStore.registration(ua, r);
        UAStore.KemCommit memory c = UAStore.layout().kemCommit[ua];
        if (c.kemPkHash != 0) (attrs.kem.scheme, attrs.kemPkHash) = (c.scheme, c.kemPkHash); // the committed form
        else (attrs.kem,) = UAStore.kemAt(ua, 0); // the register KEM key is version 0
        UAStore.PqzKey memory k = UAStore.layout().pqzKey[ua][0];
        if (k.added) return (kind, keyData, attrs, pop, pqzPop); // A4-c3: an added key is no `register` argument
        (attrs.pqzKey, attrs.pqzPopHash) = (SSTORE2.read(k.ptr), UAStore.layout().pqzPopHash[ua][0]);
        pqzPop = SSTORE2.readChunks(UAStore.layout().pqzPop[ua][0]);
    }

    // ----- moved from `UARegistry` (T66b 3.1b): a read off the hot path, run by `_libView` -----

    function popOf(bytes32 ua) external returns (bytes memory pop) {
        if (UARegistryCoreLib._elsewhere(ua)) return IUARegistry(UARegistryCoreLib._pred()).popOf(ua);
        if (UAStore.layout().records[ua].kind == 0) return pop;
        (, pop) = abi.decode(SSTORE2.readChunks(UAStore.layout().reg[ua]), (bytes, bytes));
    }
}
