// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {SSTORE2} from "../common/SSTORE2.sol";
import {IUARegistry} from "./IUARegistry.sol";
import {UAKinds} from "./UAKinds.sol";
import {UAStore} from "./UAStore.sol";
import {UAMldsaVerifier} from "./MlDsa.sol";
import {UARegistryCoreLib} from "./UARegistryCoreLib.sol";

/// @title `UARegistry`'s auxiliary library (T66b 3.1b, owner 2026-11-09, spec 2026-11-09-t66b-library-organisation.md §11 (f)):
///        the key writes after registration: the ML-DSA expanded-key cache, the PQZ key proof and versions (`storePqzPop`,
///        `setPqzKey`) and the KEM records (`setKemKey`); and reads off the registry's hot path (`popOf`, `popSlotsOf`,
///        `webAuthnKeyOf`, `pqzPopOf`, `pqzKeySigOf`, `uaAt`, `uaPage`, `uaIndex`, run inside the registry's view). Run by
///        DELEGATECALL from the registry's thin entry (`_lib`, the same three appended words as `UARegistryCoreLib`'s), so
///        `address(this)` is the registry and the storage is its `UAStore.Layout`; one DELEGATECALL per operation, as before.
///        Same check order, same stored bytes, same events and errors as when this code was in `UARegistryCoreLib`
///        (`legacy/ua-mtx-merge/t66b/src/ua/UARegistryLib.sol`, the reads `UARegistry.sol` there). The helpers it shares with registration (the appended words,
///        the getters, the portable signature check, the PQZ proof, the holder checks) are `UARegistryCoreLib`'s: the large ones
///        run there by one nested DELEGATECALL each (`_core`, T66b 3.1c, owner 2026-11-09), the small `internal` ones are
///        compiled in: one source, one copy of the large code in the pair. Called directly every entry reverts (solc's library call protection; none
///        is `view` or `pure`). UNAUDITED.
library UARegistryAuxLib {
    /// `UARegistry.UAConfig(0)`: the core library this one is linked to has no code (T66b 3.1c).
    error UAConfig(uint16 kind);

    // ----- the core's shared helpers (T66b 3.1c, owner 2026-11-09, spec §11 (f)) -----

    /// Runs a `UARegistryCoreLib` helper by a nested DELEGATECALL: `call`, then the three words the registry appended to this
    /// entry's calldata (its last 96 bytes), so the helper reads this frame's configuration; `address(this)` and the storage
    /// stay the registry's. One level only: the core never calls back here. A core without code reverts `UAConfig(0)` (a
    /// DELEGATECALL to it would succeed with nothing checked); the helper's revert data passes verbatim.
    function _core(bytes memory call) private returns (bytes memory ret) {
        address core = address(UARegistryCoreLib);
        if (core.code.length == 0) revert UAConfig(0);
        bool ok;
        (ok, ret) = core.delegatecall(bytes.concat(call, msg.data[msg.data.length - 96:]));
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    function _portableOk(uint16 kind, bytes memory d, bytes32 ua, bytes32 purpose, bytes32 digest,
        IUARegistry.UASig calldata sig) private returns (bool)
    {
        return abi.decode(
            _core(abi.encodeWithSelector(UARegistryCoreLib.portableOk.selector, kind, d, ua, purpose, digest, sig)), (bool)
        );
    }

    // ----- ML-DSA expanded-key cache (P6c; owner 2026-10-12) -----

    /// Stores part `part` of the expanded key of `pk` under `uaOf(kind, pk)`, computed by the kind's verifier
    /// (`expandedKeyPart`) from the authenticated `pk` — never accepted from a caller (a caller-supplied expanded key
    /// allows universal forgery). Anyone may call it, before or after `register`; a part already stored is left as it
    /// is (a front-runner stored the same bytes). Each part is one transaction (ML-DSA-65 part 1: ≈ 13.4 M gas).
    /// Reverts `UAKeyCache(kind)` for a kind other than ML-DSA, a disabled kind, a part past the last, or a verifier
    /// that uses a precompile; `UAKeyData` for a key of the wrong length.
    function cacheExpandedKey(uint16 kind, bytes calldata pk, uint256 part) external returns (bytes32 ua) {
        UAStore.Layout storage s = UAStore.layout();
        address v = address(uint160(UARegistryCoreLib._cfgKind()));
        if (
            (kind != UAKinds.MLDSA44 && kind != UAKinds.MLDSA65) || v == address(0) || part >= _ekParts(kind)
                || UAMldsaVerifier(v).PRECOMPILE() != address(0)
        ) revert IUARegistry.UAKeyCache(kind);
        ua = abi.decode(_core(abi.encodeWithSelector(UARegistryCoreLib.keyUa.selector, kind, pk)), (bytes32));
        if (s.ekPtr[ua][part] != address(0)) return ua;
        address ptr = SSTORE2.write(UAMldsaVerifier(v).expandedKeyPart(pk, part));
        s.ekPtr[ua][part] = ptr;
        emit IUARegistry.UAKeyCached(ua, kind, part, ptr);
    }

    function _ekParts(uint16 kind) private pure returns (uint256) {
        return kind == UAKinds.MLDSA44 ? 1 : 2;
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
        _core(abi.encodeWithSelector(UARegistryCoreLib.pqzProof.selector, ua, version, key, pqzPop, h, message));
    }

    /// Version `version`'s record for `storePqzPop`, its proof hash `popHash` checked (`UAPqzPopHash`; no such version: the
    /// hash is 0). On a host without its own record, gen 1's (from its `register` or `setPqzKey`), proven in this generation
    /// (ruling A6-I1, host rule 3) and copied here: from then on the host answers this version from its own record,
    /// whatever gen 1 writes later (host rule 2).
    function _pqzRecord(bytes32 ua, uint64 version, bool host, bytes32 popHash) private returns (UAStore.PqzKey memory k) {
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
        if (UARegistryCoreLib._pred() != address(0) && uint160(UARegistryCoreLib._cfgPqz()) != 0 && UARegistryCoreLib._kindOf(ua) != 0) return true;
        revert IUARegistry.UAUnauthorized(ua);
    }

    function setPqzKey(bytes32 ua, uint64 version, bytes calldata pqzKey, bytes32 pqzPopHash,
        IUARegistry.UASig calldata sig) external
    {
        UAStore.Layout storage s = UAStore.layout();
        bool host = _host(ua);
        uint16 kind;
        bytes memory d;
        if (host) {
            (kind, d,,,) = IUARegistry(UARegistryCoreLib._pred()).registrationOf(ua);
        } else {
            IUARegistry.Record memory r = s.records[ua];
            kind = r.kind;
            (d,) = UAStore.registration(ua, r.keyPtr);
        }
        _core(abi.encodeWithSelector(UARegistryCoreLib.pqzHolder.selector, kind, d, ua, host));
        _pqzNext(ua, version, host);
        bytes32 h = UARegistryCoreLib._pqzKeyHash(pqzKey);
        // KV-1 (Codex #1): no two versions of one UA hold the same key, before any proof exists; a host reads gen 1's too
        if (s.pqzKeyUsed[ua][h] || (host && IUARegistry(UARegistryCoreLib._pred()).pqzKeyUsed(ua, h))) revert IUARegistry.UAKeyInUse(h, ua);
        if (pqzPopHash == 0 || pqzPopHash == UARegistryCoreLib.EMPTY_PROOF_HASH) revert IUARegistry.UAPqzPopHash(ua);
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

    function setKemKey(bytes32 ua, uint64 version, IUARegistry.KemKey calldata kem, IUARegistry.UASig calldata sig) external {
        UAStore.Layout storage s = UAStore.layout();
        IUARegistry.Record memory r = s.records[ua];
        // UA8-D11 before `_sigOk`: its gen-1 fallback would verify a gen-1 holder's record here (A6 re-review)
        if (r.kind == 0) revert IUARegistry.UAUnauthorized(ua);
        if (!UARegistryCoreLib._kemHolder(r.kind)) revert IUARegistry.UAKemHolder(ua); // CTR-UA-32: an `msig` holds no KEM key
        (bytes memory d,) = UAStore.registration(ua, r.keyPtr);
        // owner 2026-10-31: never overwrite (every version write-once); version 0 only to fill the `register` commit
        if (s.kem[ua][version].length != 0) revert IUARegistry.UAKemVersion(ua, version);
        bytes32 committed = version == 0 ? s.kemCommit[ua].kemPkHash : bytes32(0);
        if (version == 0 && committed == 0) revert IUARegistry.UAKemVersion(ua, 0);
        bytes memory kemPk = UAKinds.kemPk(kem);
        UARegistryCoreLib._checkKemPk(kemPk);
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
        for (uint256 b = bits; b != 0; b &= b - 1) ++n;
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
        (k.x, k.y, k.rpIdHash) = (bytes32(UAStore.word(d, 0)), bytes32(UAStore.word(d, 32)), bytes32(UAStore.word(d, 64)));
    }

    // ----- moved from `UARegistry` (T66b 3.1b): a read off the hot path, run by `_libView` -----

    function pqzPopOf(bytes32 ua, uint64 version) external returns (bytes memory) {
        if (UAStore.layout().pqzKey[ua][version].ptr == address(0) && UARegistryCoreLib._elsewhere(ua)) return IUARegistry(UARegistryCoreLib._pred()).pqzPopOf(ua, version);
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
        if (r.kind == 0 && UARegistryCoreLib._pred() != address(0)) return IUARegistry(UARegistryCoreLib._pred()).uaIndex(ua);
        if (r.kind == 0) revert IUARegistry.UANotIndexed(ua);
        return r.index;
    }

    // ----- moved from `UARegistry` (T66b 3.1b): a read off the hot path, run by `_libView` -----

    function uaAt(uint16 kind, uint256 i) external returns (bytes32) {
        if (!UARegistryCoreLib._listedHere()) return IUARegistry(UARegistryCoreLib._pred()).uaAt(kind, i);
        if (i >= UAStore.layout().uaCount[kind]) revert IUARegistry.UAIndex(kind, i);
        return UAStore.layout().uaAt[kind][i];
    }

    // ----- moved from `UARegistry` (T66b 3.1b): a read off the hot path, run by `_libView` -----

    function popOf(bytes32 ua) external returns (bytes memory pop) {
        if (UARegistryCoreLib._elsewhere(ua)) return IUARegistry(UARegistryCoreLib._pred()).popOf(ua);
        if (UAStore.layout().records[ua].kind == 0) return pop;
        (, pop) = abi.decode(SSTORE2.readChunks(UAStore.layout().reg[ua]), (bytes, bytes));
    }
}
