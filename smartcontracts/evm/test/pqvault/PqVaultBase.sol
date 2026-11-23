// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChatTypes} from "../../src/pqchat/PqChatTypes.sol";
import {IPqVault} from "../../src/pqvault/IPqVault.sol";
import {PqVault} from "../../src/pqvault/PqVault.sol";
import {PqVaultTypes} from "../../src/pqvault/PqVaultTypes.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {UACall} from "../ua/UACall.sol";
import {UARegistryBase} from "../ua/UARegistryBase.sol";

/// The struct hashes and typed digests of `PqVaultTypes` over calldata, as the contract computes them (the tests build records
/// in memory); `ds` is the vault's domain (`PqVaultTypes.DS_V` or `dsB(instance)`).
contract PqVaultHasher {
    function create(IPqVault.PqVaultCreate calldata v, bytes32 ds) external pure returns (bytes32) {
        return PqVaultTypes.typed(ds, PqVaultTypes.hashCreate(v));
    }

    function epoch(IPqVault.PqVaultEpoch calldata e, bytes32 ds) external pure returns (bytes32) {
        return PqVaultTypes.typed(ds, PqVaultTypes.hashEpoch(e));
    }

    function leave(IPqVault.PqVaultLeave calldata l, bytes32 ds) external pure returns (bytes32) {
        return PqVaultTypes.typed(ds, PqVaultTypes.hashLeave(l));
    }

    function remove(IPqVault.PqVaultRemove calldata r, bytes32 ds) external pure returns (bytes32) {
        return PqVaultTypes.typed(ds, PqVaultTypes.hashRemove(r));
    }

    function item(IPqVault.PqVaultItem calldata it, bytes32 ds) external pure returns (bytes32) {
        return PqVaultTypes.typed(ds, PqVaultTypes.hashItem(it));
    }

    function edit(IPqVault.PqVaultEdit calldata d, bytes32 ds) external pure returns (bytes32) {
        return PqVaultTypes.typed(ds, PqVaultTypes.hashEdit(d));
    }

    function batch(IPqVault.PqVaultBatch calldata b, bytes32 ds) external pure returns (bytes32) {
        return PqVaultTypes.typed(ds, PqVaultTypes.hashBatch(b));
    }

    function structHashes(IPqVault.PqVaultCreate calldata v, IPqVault.PqVaultBatch calldata b)
        external
        pure
        returns (bytes32, bytes32)
    {
        return (PqVaultTypes.hashCreate(v), PqVaultTypes.hashBatch(b));
    }

    function dsB(address c) external view returns (bytes32) {
        return PqVaultTypes.dsB(c);
    }
}

/// The fixture of the `PqVault` suites: a registry with the PQ holder kinds behind the stand-in verifier (`MockVerifier`: a
/// signature is the keccak of key and message), an `OpenFactory` with class 4 registered on the generic path (env v1: the
/// registry, the code-size limit `params[0]`), the release and two instances (A, the home of the vaults the tests create unless
/// they say otherwise; B). Members are `mldsa65` UAs with a KEM key (version 0). A record is signed as the registry checks it
/// in either mode: the key over `uaMessage(kind, P_V, typed)`, `typed` in the vault's domain. **UNAUDITED.**
abstract contract PqVaultBase is UARegistryBase {
    address internal constant REGISTRAR = address(0xF00D);
    address internal constant REG_P = 0x5cA0000000000000000000000000000000000009;
    address internal constant STRANGER = address(0x5757);
    bytes32 internal constant OWNER_UA = bytes32(uint256(0x0A11CE));
    uint256 internal constant LIMIT = 131_072;
    uint16 internal constant ML = UAKinds.MLDSA65;
    uint256 internal constant EOA_SK = 0xA11CE5EC;

    UARegistry internal p;
    OpenFactory internal f;
    PqVaultHasher internal h;
    address internal impl;
    PqVault internal vault; // instance A
    PqVault internal vaultB; // instance B

    /// The registered members, sorted by id.
    bytes32[] internal ids;
    mapping(bytes32 => bytes) internal keyOf_;

    function setUp() public virtual override {
        super.setUp();
        UARegistry.KindConfig[] memory base = _cfgs(address(mock));
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](base.length + 3);
        for (uint256 i; i < base.length; ++i) {
            c[i] = base[i];
        }
        c[base.length] = UARegistry.KindConfig(UAKinds.MLDSA65, address(mock), 50_000, false, 0);
        c[base.length + 1] = UARegistry.KindConfig(UAKinds.FNDSA512, address(mock), 50_000, false, 0);
        c[base.length + 2] = UARegistry.KindConfig(UAKinds.MLDSA44, address(mock), 50_000, false, 0);
        p = _deploy(REG_P, chainUidA, address(0), false, BUDGET, address(0), true, c);
        h = new PqVaultHasher();
        f = EnvKit.factory(REGISTRAR, chainUidA, 0);
        vm.prank(REGISTRAR);
        f.publishClassEnv(4, 0, 1, EnvKit.uidOf(address(f)), _classEnv(address(p), LIMIT));
        vm.prank(REGISTRAR);
        impl = f.deployImplementation(
            IOpenFactory.ReleaseId(4, 0, 1),
            1,
            IPqVault.initialize.selector,
            type(IPqVault).interfaceId,
            type(PqVault).creationCode,
            "",
            EnvKit.uidOf(address(f))
        );
        vm.prank(REGISTRAR);
        f.setClassKindEnabled(4, 0, true, EnvKit.uidOf(address(f)));
        vault = _instance("a", OWNER_UA);
        vaultB = _instance("b", bytes32(0));
        for (uint8 i = 1; i <= 5; ++i) {
            _member(i);
        }
    }

    /// The class env: the registry and the code-size limit `params[0]`; no body module.
    function _classEnv(address registry, uint256 limit) internal pure returns (IFactoryToken.Env memory e) {
        e.registry = registry;
        e.params = new bytes32[](1);
        e.params[0] = bytes32(limit);
    }

    function _instance(bytes32 salt, bytes32 ownerUA) internal returns (PqVault c) {
        bool derived = ownerUA >> 160 != 0;
        if (derived) vm.mockCall(address(f), abi.encodeCall(IOpenFactory.creating, ()), abi.encode(ownerUA));
        else if (ownerUA != 0) vm.prank(address(uint160(uint256(ownerUA))));
        c = PqVault(
            f.createInstance(IOpenFactory.ReleaseId(4, 0, 1), salt, abi.encodeCall(IPqVault.initialize, (ownerUA)))
        );
        if (derived) vm.clearMockedCalls();
    }

    // ----- members -----

    function _mlKey(uint8 seed) internal pure returns (bytes memory d) {
        d = new bytes(1952);
        for (uint256 i; i < d.length; ++i) {
            d[i] = bytes1(uint8(i) ^ seed);
        }
    }

    function _kem(uint8 seed) internal pure returns (IUARegistry.KemKey memory k) {
        k.scheme = 1;
        k.mlkemEk = new bytes(1568);
        for (uint256 i; i < 1568; ++i) {
            k.mlkemEk[i] = bytes1(uint8(i * 7) ^ seed);
        }
        k.x25519 = bytes32(uint256(seed) << 8 | 0x09);
    }

    /// An `mldsa65` UA with KEM key version 0, kept in `ids` (sorted).
    function _member(uint8 seed) internal returns (bytes32 ua) {
        bytes memory key = _mlKey(seed);
        IUARegistry.UAAttrs memory a;
        a.kem = _kem(seed);
        ua = _register(p, ML, key, a, _pop(p, ML, key, a), "");
        keyOf_[ua] = key;
        ids.push(ua);
        for (uint256 i = ids.length - 1; i > 0 && ids[i - 1] > ids[i]; --i) {
            (ids[i - 1], ids[i]) = (ids[i], ids[i - 1]);
        }
    }

    /// `ua`'s signature over the typed digest `digest` (either mode: `uaMessage(kind, P_V, digest)`).
    /// KEM key version `version` of `ua` set in the registry (a device key, owner (M) 2026-11-23, or a new seed version).
    function _setKem(bytes32 ua, uint64 version, IUARegistry.KemKey memory k) internal {
        p.setKemKey(ua, version, k, _kemSig(ua, version, k));
    }

    function _kemSig(bytes32 ua, uint64 version, IUARegistry.KemKey memory k)
        internal
        view
        returns (IUARegistry.UASig memory s)
    {
        s.signature = _sig(keyOf_[ua], UAKinds.uaMessage(ML, UAKinds.PURPOSE_KEM, p.kemRecordDigest(ua, version, k)));
    }

    /// `ua`'s KEM versions `1..n` set (stand-in keys), so it may sit in an epoch with keyIds `0..n`.
    function _devices(bytes32 ua, uint64 n) internal {
        for (uint64 v = 1; v <= n; ++v) {
            _setKem(ua, v, _kem(uint8(uint256(keccak256(abi.encode(ua, v))))));
        }
    }

    function _sig(bytes32 ua, bytes32 digest) internal view returns (IUARegistry.UASig memory s) {
        s.signature = _sig(keyOf_[ua], UAKinds.uaMessage(ML, PqVaultTypes.P_V, digest));
    }

    /// The domain of a vault of `mode` homed at instance `c`.
    function _ds(uint8 mode, address c) internal view returns (bytes32) {
        return mode == 0 ? PqVaultTypes.DS_V : h.dsB(c);
    }

    // ----- records -----

    function _list(bytes32 a) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](1);
        l[0] = a;
    }

    function _list(bytes32 a, bytes32 b) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](2);
        (l[0], l[1]) = a < b ? (a, b) : (b, a);
    }

    /// The first `n` registered members, sorted, KEM version 0, `via` 0.
    function _members(uint256 n) internal view returns (IPqChat.MemberKey[] memory m) {
        m = new IPqChat.MemberKey[](n);
        for (uint256 i; i < n; ++i) {
            m[i] = IPqChat.MemberKey(ids[i], 0, bytes32(0));
        }
    }

    /// The wrap of `m` in epoch `epochId` (stand-in bytes: the contract checks shape and hash only).
    function _wrap(IPqChat.MemberKey memory m, bytes32 epochId) internal pure returns (IPqChat.Wrap memory w) {
        w.member = m.ua;
        w.keyId = m.keyId;
        w.mlkemCt = new bytes(1568);
        for (uint256 i; i < 1568; i += 32) {
            bytes32 x = keccak256(abi.encode(epochId, m.ua, i));
            for (uint256 j; j < 32; ++j) {
                w.mlkemCt[i + j] = x[j];
            }
        }
        w.x25519Eph = keccak256(abi.encode("eph", epochId, m.ua));
        w.sealedKey = abi.encodePacked(keccak256(abi.encode("k", epochId, m.ua)), bytes16(keccak256(abi.encode(m.ua))));
    }

    function _wraps(IPqChat.MemberKey[] memory m, bytes32 epochId) internal pure returns (IPqChat.Wrap[] memory w) {
        w = new IPqChat.Wrap[](m.length);
        for (uint256 i; i < m.length; ++i) {
            w[i] = _wrap(m[i], epochId);
        }
    }

    function _hashes(IPqChat.Wrap[] memory w) internal pure returns (bytes32[] memory hs) {
        hs = new bytes32[](w.length);
        for (uint256 i; i < w.length; ++i) {
            hs[i] = keccak256(
                abi.encode(
                    PqChatTypes.WRAP_TYPEHASH,
                    w[i].member,
                    w[i].keyId,
                    keccak256(w[i].mlkemCt),
                    w[i].x25519Eph,
                    keccak256(w[i].sealedKey)
                )
            );
        }
    }

    function _slice(IPqChat.Wrap[] memory w, uint256 from, uint256 to) internal pure returns (IPqChat.Wrap[] memory r) {
        r = new IPqChat.Wrap[](to - from);
        for (uint256 i = from; i < to; ++i) {
            r[i - from] = w[i];
        }
    }

    /// A vault of the first `n` members in `mode`, created by `ids[0]` (member and only admin), homed at `home`; the
    /// passphrase on (set 1).
    function _vault(uint256 n, uint64 nonce, uint8 mode, address home)
        internal
        view
        returns (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w)
    {
        v.creator = ids[0];
        v.nonce = nonce;
        v.mode = mode;
        v.homeChain = chainUidA;
        v.homeVaultContract = home;
        v.admins = _list(ids[0]);
        v.members = _members(n);
        w = _wraps(v.members, PqVaultTypes.vaultId(v.creator, nonce, mode, chainUidA, home));
        v.wrapHashes = _hashes(w);
        v.passKdf = 1;
        v.passSalt = keccak256(abi.encode("salt", nonce));
        v.sealedInfo = _info(0x5e);
    }

    /// A stand-in `sealedInfo` of the size a client writes: nonce, the 1,024-B bucket, tag (1,052 B; F12, owner 2026-11-21).
    function _info(uint8 fill) internal pure returns (bytes memory b) {
        b = new bytes(1052);
        for (uint256 i; i < b.length; i += 32) {
            b[i] = bytes1(fill);
        }
    }

    function _createSig(IPqVault.PqVaultCreate memory v, address c) internal view returns (IUARegistry.UASig memory) {
        return _sig(v.creator, h.create(v, _ds(v.mode, c)));
    }

    function _create(PqVault c, IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) internal returns (bytes32) {
        return c.createVault(v, w, _createSig(v, address(c)));
    }

    /// A complete vault of the first `n` members on `vault` in `mode`.
    function _newVault(uint256 n, uint8 mode) internal returns (bytes32 vid, IPqVault.PqVaultCreate memory v) {
        IPqChat.Wrap[] memory w;
        (v, w) = _vault(n, 1, mode, address(vault));
        vid = _create(vault, v, w);
    }

    /// An epoch record over `members` and `admins`, its wraps.
    function _epoch(
        bytes32 vid,
        bytes32 author,
        uint64 nonce,
        uint64 number,
        bytes32 parent,
        bytes32[] memory admins,
        IPqChat.MemberKey[] memory members
    ) internal view returns (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) {
        (e.vaultId, e.author, e.nonce, e.epoch, e.parentEpochId) = (vid, author, nonce, number, parent);
        e.admins = admins;
        e.members = members;
        w = _wraps(members, PqVaultTypes.epochId(vid, author, nonce));
        e.wrapHashes = _hashes(w);
        e.passKdf = 1;
        e.passSalt = keccak256(abi.encode("salt e", nonce));
        e.sealedInfo = _info(0xe9);
    }

    function _rekey(PqVault c, IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w, uint8 mode)
        internal
        returns (bytes32)
    {
        return c.rekeyVault(e, w, _sig(e.author, h.epoch(e, _ds(mode, address(c)))));
    }

    function _without(IPqChat.MemberKey[] memory m, bytes32 ua) internal pure returns (IPqChat.MemberKey[] memory r) {
        r = new IPqChat.MemberKey[](m.length - 1);
        uint256 k;
        for (uint256 i; i < m.length; ++i) {
            if (m[i].ua != ua) r[k++] = m[i];
        }
    }

    /// A view's raw return data (a `UASig` in it cannot be decoded in memory by the legacy code generator: compare the bytes).
    function _raw(address c, bytes memory data) internal view returns (bytes memory ret) {
        bool ok;
        (ok, ret) = c.staticcall(data);
        require(ok, "view reverted");
    }

    function _rawRefused(bytes memory data, bytes memory err) internal view {
        (bool ok, bytes memory ret) = address(vault).staticcall(data);
        assertFalse(ok);
        assertEq(ret, err);
    }

    function _unauthorized(bytes32 ua) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua);
    }

    // ----- an msig admin with a native member (an EOA, 1-of-1) -----

    function _nativeMsig() internal returns (bytes32 ms) {
        Member[] memory m = new Member[](1);
        m[0] = Member(UAKinds.EVM_EOA, _pad(vm.addr(EOA_SK)), 1);
        bytes memory d = _msigKey(1, m);
        ms = UACall.register(p, UAKinds.MSIG, d, _none(), "", "");
        p.acceptMembership(ms, _acceptEoaSig(d, EOA_SK));
    }

    /// The msig's signature over `typed` in `mode`: mode 0 the EOA signs `typed` itself (the portable rule), mode 1 `UAAuth`
    /// over the member digest (the chain-bound rule).
    function _nativeMsigSig(bytes32 ms, bytes32 typed, uint8 mode) internal view returns (IUARegistry.UASig memory s) {
        s.members = new IUARegistry.MemberSig[](1);
        s.members[0] = IUARegistry.MemberSig(
            0,
            new IUARegistry.InnerSig[](0),
            mode == 0
                ? _ecdsa(EOA_SK, typed)
                : _nativeSig(p, EOA_SK, UAKinds.PURPOSE_MEMBER, _memberDigest(ms, PqVaultTypes.P_V, typed))
        );
    }
}
