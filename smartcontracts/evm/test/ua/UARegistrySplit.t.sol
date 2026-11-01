// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UARegistryLib} from "../../src/ua/UARegistryLib.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UARegistryPreSplit} from "../../legacy/typed-signing/UARegistryPreSplit.sol";
import {UARegistryBase, MockVerifier, MockWallet} from "./UARegistryBase.sol";
import {UACall} from "./UACall.sol";
import {SplitDiff} from "./SplitDiff.sol";
import {GasMeter} from "./GroupFixtures.sol";

contract Create2er {
    function create(bytes32 salt, bytes memory init) external returns (address a) {
        assembly ("memory-safe") {
            a := create2(0, add(init, 32), mload(init), salt)
        }
        require(a != address(0), "create2");
    }
}

/// A stand-in with the ML-DSA cache interface: `PRECOMPILE` as given, the parts derived from the key.
contract CacheVerifier is MockVerifier {
    address public immutable PRECOMPILE;

    constructor(address precompile) MockVerifier(0, 0) {
        PRECOMPILE = precompile;
    }

    function expandedKeyPart(bytes calldata pk, uint256 part) external pure returns (bytes memory) {
        return abi.encode(keccak256(pk), part);
    }

    function verifyCached(bytes calldata chunks, bytes32 message, bytes calldata sig) external pure returns (bool) {
        return sig.length == 32 && bytes32(sig) == keccak256(abi.encode(chunks, message));
    }
}

/// During a write the registry calls this verifier by STATICCALL. It tries a write back through the registry, and answers
/// by the outcome: a pass only if that write failed.
contract ReentrantVerifier {
    address public registry;
    bytes public attempt;

    function arm(address r, bytes calldata data) external {
        (registry, attempt) = (r, data);
    }

    function verifyPop(bytes calldata, bytes32, bytes calldata) external returns (bool) {
        (bool ok,) = registry.call(attempt);
        return !ok;
    }
}

/// ERC-1271 member that answers only the registry itself: a call from the library's address, or anyone else's, is refused.
contract SenderWallet {
    address public immutable registry;

    constructor(address r) {
        registry = r;
    }

    function isValidSignature(bytes32, bytes calldata) external view returns (bytes4) {
        return msg.sender == registry ? IERC1271.isValidSignature.selector : bytes4(0);
    }
}

/// Someone else's contract that delegates to the library: the getters the library calls back, and its own storage.
contract Foreign {
    function run(address lib, bytes calldata data) external returns (bool ok, bytes memory ret) {
        (ok, ret) = lib.delegatecall(data);
    }

    function predecessor() external pure returns (address) {}

    function hederaNative() external pure returns (bool) {}

    function kindOf(bytes32) external pure returns (uint16) {}

    function keyOwner(bytes32) external pure returns (bytes32) {}

    function verifyBudget() external pure returns (uint64) {}
}

/// typed-signing R2 (owner 2026-11-01): `UARegistry` + `UARegistryLib` against the pre-split source
/// (`legacy/typed-signing/UARegistryPreSplit.sol`). The same scenario runs on each, at the same addresses, in one state:
/// `SplitDiff` compares return and revert data, logs, every storage write, every created contract and every call out, row
/// by row. Stand-in verifiers here, one per kind, so a wrong immutable shows; the real signatures of portable.json are
/// `UARegistryUA8Test.test_split_portableRowsSame`.
contract UARegistrySplitTest is UARegistryBase {
    using SplitDiff for SplitDiff.Run;

    string internal constant OLD = "UARegistryPreSplit.sol:UARegistryPreSplit";
    string internal constant NEW = "UARegistry.sol:UARegistry";
    address internal constant R1 = 0x5cA00000000000000000000000000000000000a1;
    address internal constant R2 = 0x5ca00000000000000000000000000000000000A2;
    address internal constant R3 = 0x5ca00000000000000000000000000000000000a3;
    address internal constant R4 = 0x5ca00000000000000000000000000000000000A4;
    address internal constant R5 = 0x5CA00000000000000000000000000000000000A5;
    address internal constant R6 = 0x5ca00000000000000000000000000000000000A6;
    address internal constant R7 = 0x5CA00000000000000000000000000000000000a7;
    address internal constant R8 = 0x5ca00000000000000000000000000000000000a8;
    uint64 internal constant PQ = 1_000_000;
    uint256 internal constant ALICE = 0xA11CE;
    uint16 internal constant ML44 = 0x0130;
    uint16 internal constant ML65 = 0x0131;
    uint16 internal constant FN = 0x0132;
    uint16 internal constant SLH = 0x0133;
    bytes32 internal constant NONE_UA = keccak256("unregistered");

    bytes32[] internal ids;
    GasMeter internal gm;

    function setUp() public override {
        super.setUp();
        gm = new GasMeter();
    }

    function _err(bytes4 sel, bytes32 ua) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(sel, ua);
    }

    // ----- keys -----

    function _pk(uint16 kind, uint256 salt) internal pure returns (bytes memory pk) {
        uint256 len = kind == ML44 ? 1312 : kind == ML65 ? 1952 : kind == FN ? 897 : kind == SLH ? 32 : 18_432;
        pk = new bytes(len);
        for (uint256 i; i < len; i += 32) {
            bytes32 w = keccak256(abi.encode(kind, salt, i));
            for (uint256 j; j < 32 && i + j < len; ++j) pk[i + j] = w[j];
        }
        if (kind == FN) {
            pk[0] = 0x09;
            for (uint256 i = 1; i < len; ++i) pk[i] = 0;
            pk[1] = bytes1(uint8(salt)); // FN-DSA h: only its length is checked here, the salt keeps ids apart
        }
    }

    function _kemPk(uint256 salt) internal pure returns (bytes memory pk) {
        pk = new bytes(1601);
        for (uint256 i; i < 1601; i += 32) {
            bytes32 w = keccak256(abi.encode("kem", salt, i));
            for (uint256 j; j < 32 && i + j < 1601; ++j) pk[i + j] = w[j];
        }
        pk[0] = 0x01;
    }

    function _h(bytes memory pqzKey) internal pure returns (bytes32) {
        return UAKinds.keyHashOf(UAKinds.PQZ_MLWE, pqzKey);
    }

    /// One key data per kind of kinds.json `valid`, `msig` left out.
    function _rows() internal view returns (uint16[] memory k, bytes[] memory d) {
        string memory j = _kindsJson();
        uint256[] memory all = abi.decode(vm.parseJson(j, ".valid[*].kind"), (uint256[]));
        k = new uint16[](all.length);
        d = new bytes[](all.length);
        uint256 n;
        for (uint256 i; i < all.length; ++i) {
            bool seen = all[i] == UAKinds.MSIG;
            for (uint256 m; m < n; ++m) seen = seen || k[m] == all[i];
            if (seen) continue;
            k[n] = uint16(all[i]);
            d[n++] = vm.parseJsonBytes(j, string.concat(".valid[", vm.toString(i), "].keyData"));
        }
        assembly ("memory-safe") {
            mstore(k, n)
            mstore(d, n)
        }
    }

    function _keyOf(uint16 want) internal view returns (bytes memory) {
        (uint16[] memory k, bytes[] memory d) = _rows();
        for (uint256 i; i < k.length; ++i) if (k[i] == want) return d[i];
        revert("no row");
    }

    /// Every kind of `_rows`, each with its own verifier; 0x0142 too if `pqz`.
    function _all(bool pqz) internal returns (UARegistry.KindConfig[] memory c) {
        (uint16[] memory k,) = _rows();
        c = new UARegistry.KindConfig[](k.length + (pqz ? 1 : 0));
        for (uint256 i; i < k.length; ++i) {
            address v = k[i] == ML44 || k[i] == ML65 ? address(new CacheVerifier(address(0))) : address(new MockVerifier(0, 0));
            c[i] = UARegistry.KindConfig(k[i], v, k[i] >= 0x0110 ? PQ : _cap(k[i]));
        }
        if (pqz) c[k.length] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, address(new MockVerifier(0, 0)), PQ);
    }

    function _one(uint16 kind, address v, uint64 cap) internal pure returns (UARegistry.KindConfig[] memory c) {
        c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(kind, v, cap);
    }

    // ----- calldata of the writes -----

    function _regCall(uint16 kind, bytes memory d, IUARegistry.UAAttrs memory a, bytes memory pop, bytes memory pqzPop)
        internal
        pure
        returns (bytes memory)
    {
        return UACall.registerCall(kind, d, a, pop, pqzPop);
    }

    /// The plain registration of `d`.
    function _plain(uint16 kind, bytes memory d) internal pure returns (bytes memory) {
        return _regCall(kind, d, _none(), _pop(UARegistry(address(0)), kind, d), "");
    }

    function _reg(SplitDiff.Run memory r, string memory label, address at, bytes memory data) internal returns (bytes32 ua) {
        ua = abi.decode(r.write(label, at, data), (bytes32));
        ids.push(ua);
    }

    function _sigFor(bytes memory key, uint16 kind, bytes32 purpose, bytes32 digest)
        internal
        pure
        returns (IUARegistry.UASig memory s)
    {
        s.signature = _sig(key, UAKinds.uaMessage(kind, purpose, digest));
    }

    function _noSig() internal pure returns (IUARegistry.UASig memory) {}

    function _pqzKeyCall(bytes32 ua, uint16 kind, bytes memory key, bytes memory pqz, bytes32 hash)
        internal
        pure
        returns (bytes memory)
    {
        IUARegistry.UASig memory s = _sigFor(key, kind, UAKinds.PURPOSE_PQZ_KEY, UAKinds.pqzKeyRecordDigest(ua, _h(pqz), hash));
        return abi.encodeCall(IUARegistry.setPqzKey, (ua, pqz, hash, s));
    }

    function _kemCall(bytes32 ua, uint16 kind, bytes memory key, uint64 v, bytes memory kem) internal pure returns (bytes memory) {
        IUARegistry.UASig memory s = _sigFor(key, kind, UAKinds.PURPOSE_KEM, UAKinds.kemRecordDigest(ua, v, kem));
        return abi.encodeCall(IUARegistry.setKemKey, (ua, v, UACall.kem(kem), s));
    }

    /// The attributes of a holder with a PQZ key, unproven, and a KEM key, in full or by hash; the proof it could give.
    function _holderAttrs(uint16 kind, bytes32 ua, uint256 salt, bool commit)
        internal
        pure
        returns (IUARegistry.UAAttrs memory a, bytes memory pqzPop)
    {
        bytes memory pqzKey = _pk(UAKinds.PQZ_MLWE, salt);
        bytes memory kem = _kemPk(salt);
        bytes32 kh = commit ? UAKinds.kemRecordHash(ua, 0, 1, keccak256(kem)) : UAKinds.kemRecordHash(ua, 0, kem);
        bytes32 rec = UAKinds.portableRecordDigest(ua, kind, _h(pqzKey), kh);
        pqzPop = _sig(pqzKey, UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP_V2, rec));
        a = UACall.attrs(pqzKey, keccak256(pqzPop), kem);
        if (commit) a = UACall.commit(a);
    }

    function _holder(SplitDiff.Run memory r, string memory label, address at, uint16 kind, bytes memory pk, uint256 salt, bool commit)
        internal
        returns (bytes32 ua, bytes memory pqzPop)
    {
        bytes memory data;
        (ua, pqzPop, data) = _holderCall(kind, pk, salt, commit);
        _reg(r, label, at, data);
    }

    function _holderCall(uint16 kind, bytes memory pk, uint256 salt, bool commit)
        internal
        pure
        returns (bytes32 ua, bytes memory pqzPop, bytes memory data)
    {
        ua = UAKinds.uaOf(kind, pk);
        IUARegistry.UAAttrs memory a;
        (a, pqzPop) = _holderAttrs(kind, ua, salt, commit);
        data = _regCall(kind, pk, a, _pop(UARegistry(address(0)), kind, pk, a), "");
    }

    /// `threshold` of an EOA and the PQ keys `ml` (mldsa44), `fn` (fndsa512): PQ-eligible, native typed + derived members.
    function _msigStructure(bytes memory ml, bytes memory fn, uint16 threshold) internal pure returns (bytes memory) {
        Member[] memory m = new Member[](3);
        m[0] = Member(UAKinds.EVM_EOA, _pad(vm.addr(ALICE)), 1);
        m[1] = Member(ML44, UAKinds.uaOf(ML44, ml), 1);
        m[2] = Member(FN, UAKinds.uaOf(FN, fn), 1);
        return _msigKey(threshold, m);
    }

    function _member(bytes memory d, bytes32 id, bytes memory sig) internal pure returns (IUARegistry.MemberSig memory) {
        return IUARegistry.MemberSig(_indexOf(d, id), "", sig);
    }

    function _sorted(IUARegistry.MemberSig[] memory s) internal pure returns (IUARegistry.MemberSig[] memory) {
        for (uint256 i = 1; i < s.length; ++i) {
            for (uint256 j = i; j > 0 && s[j - 1].index > s[j].index; --j) (s[j - 1], s[j]) = (s[j], s[j - 1]);
        }
        return s;
    }

    /// The PoP of `msigStructure(ml, fn, 2)` over `rd`, by the EOA and `fn`.
    function _eoaFn(bytes memory d, bytes32 ua, bytes32 rd, bytes32 purpose, bytes memory fn)
        internal
        pure
        returns (IUARegistry.MemberSig[] memory s)
    {
        s = new IUARegistry.MemberSig[](2);
        bytes32 md = _memberDigest(ua, purpose, rd);
        s[0] = _member(d, _pad(vm.addr(ALICE)), _ecdsa(ALICE, rd));
        s[1] = _member(d, UAKinds.uaOf(FN, fn), _sig(fn, UAKinds.uaMessage(FN, UAKinds.PURPOSE_MEMBER, md)));
        _sorted(s);
    }

    // ----- the scenario -----

    function _gen1Registrations(SplitDiff.Run memory r, address at) internal {
        (uint16[] memory k, bytes[] memory d) = _rows();
        for (uint256 i; i < k.length; ++i) {
            _reg(r, string.concat("register kind ", vm.toString(k[i])), at, _plain(k[i], d[i]));
        }
    }

    function _attachments(SplitDiff.Run memory r, address at) internal returns (bytes32 h2, bytes memory proof2) {
        (bytes32 h1, bytes memory proof1) = _holder(r, "holder, full KEM key", at, ML65, _pk(ML65, 1), 1, false);
        (h2, proof2) = _holder(r, "holder, KEM by hash", at, ML44, _pk(ML44, 2), 2, true);
        r.write("storePqzPop", at, abi.encodeCall(IUARegistry.storePqzPop, (h1, proof1)));
        r.write("storePqzPop again: stored, no effect", at, abi.encodeCall(IUARegistry.storePqzPop, (h1, proof1)));
        bytes memory kem2 = _kemPk(2);
        r.write("setKemKey v0 fills the commit", at, abi.encodeCall(IUARegistry.setKemKey, (h2, 0, UACall.kem(kem2), _noSig())));
        r.write("setKemKey v3", at, _kemCall(h2, ML44, _pk(ML44, 2), 3, _kemPk(3)));
        r.write("setKemKey v1, below the max", at, _kemCall(h2, ML44, _pk(ML44, 2), 1, _kemPk(4)));
        // the key registered on chain: the PQZ key later, on a holder without one
        bytes memory ml = _pk(ML44, 11);
        bytes32 mlUa = _reg(r, "register mldsa44 without attributes", at, _plain(ML44, ml));
        r.write("setPqzKey", at, _pqzKeyCall(mlUa, ML44, ml, _pk(UAKinds.PQZ_MLWE, 9), keccak256("later proof")));
    }

    /// The msig PoP, its KEM record, its PQZ key.
    function _msigs(SplitDiff.Run memory r, address at) internal returns (bytes32 ms) {
        bytes memory ml = _pk(ML44, 11);
        bytes memory fn = _keyOf(FN);
        bytes memory d = _msigStructure(ml, fn, 2);
        ms = UAKinds.uaOf(UAKinds.MSIG, d);
        bytes memory good = abi.encode(_eoaFn(d, ms, _regDigest(ms, UAKinds.MSIG), UAKinds.PURPOSE_POP_V2, fn));
        // one change each from the call below, which passes
        r.refused("msig: no PoP", at, _regCall(UAKinds.MSIG, d, _none(), "", ""), abi.encodePacked(IUARegistry.UAPoP.selector));
        bytes memory wrong = abi.encode(_eoaFn(d, ms, keccak256("other"), UAKinds.PURPOSE_POP_V2, fn));
        r.refused("msig: PoP over another digest", at, _regCall(UAKinds.MSIG, d, _none(), wrong, ""),
            abi.encodePacked(IUARegistry.UAPoP.selector));
        IUARegistry.MemberSig[] memory s = abi.decode(good, (IUARegistry.MemberSig[]));
        (s[0], s[1]) = (s[1], s[0]);
        r.refused("msig: members out of order", at, _regCall(UAKinds.MSIG, d, _none(), abi.encode(s), ""),
            abi.encodePacked(IUARegistry.UAPoP.selector));
        s = abi.decode(good, (IUARegistry.MemberSig[]));
        s[0].keyData = hex"01";
        r.refused("msig: a member with key data", at, _regCall(UAKinds.MSIG, d, _none(), abi.encode(s), ""),
            abi.encodePacked(IUARegistry.UAPoP.selector));
        s = new IUARegistry.MemberSig[](1);
        s[0] = abi.decode(good, (IUARegistry.MemberSig[]))[0];
        r.refused("msig: below the threshold", at, _regCall(UAKinds.MSIG, d, _none(), abi.encode(s), ""),
            abi.encodePacked(IUARegistry.UAPoP.selector));
        _reg(r, "registerMsig PQ-eligible", at, _regCall(UAKinds.MSIG, d, _none(), good, ""));
        _msigRecords(r, at, ms, d, fn);
    }

    function _msigRecords(SplitDiff.Run memory r, address at, bytes32 ms, bytes memory d, bytes memory fn) internal {
        bytes memory kem = _kemPk(5);
        bytes32 kd = UAKinds.kemRecordDigest(ms, 1, kem);
        IUARegistry.UASig memory sig;
        sig.members = _eoaFn(d, ms, kd, UAKinds.PURPOSE_KEM, fn);
        r.write("setKemKey msig", at, abi.encodeCall(IUARegistry.setKemKey, (ms, 1, UACall.kem(kem), sig)));

        bytes memory pqz = _pk(UAKinds.PQZ_MLWE, 12);
        bytes32 hash = keccak256("msig proof");
        sig.members = _eoaFn(d, ms, UAKinds.pqzKeyRecordDigest(ms, _h(pqz), hash), UAKinds.PURPOSE_PQZ_KEY, fn);
        r.write("setPqzKey msig", at, abi.encodeCall(IUARegistry.setPqzKey, (ms, pqz, hash, sig)));
    }

    /// `register` with the key data of the typed kinds (the same bytes, the same record as the typed entry).
    function _packedEntries(SplitDiff.Run memory r, address at) internal {
        (uint16[] memory k, bytes[] memory d) = _rows();
        for (uint256 i; i < k.length; ++i) {
            if (k[i] != 0x0100 && (k[i] < 0x0110 || k[i] > 0x0113)) continue;
            bytes memory pop = _pop(UARegistry(address(0)), k[i], d[i]);
            r.write(string.concat("register packed ", vm.toString(k[i])), at, abi.encodeCall(IUARegistry.register, (k[i], d[i], _none(), pop, "")));
        }
    }

    /// The ML-DSA cache: a part stored, stored again, every refusal; and a PoP through the cached key.
    function _cache(SplitDiff.Run memory r, address at) internal {
        bytes memory pk = _pk(ML44, 40);
        bytes memory good = abi.encodeCall(IUARegistry.cacheExpandedKey, (ML44, pk, 0));
        bytes32 ua = UAKinds.uaOf(ML44, pk);
        r.refused("cache: another kind", at, abi.encodeCall(IUARegistry.cacheExpandedKey, (FN, pk, 0)),
            abi.encodeWithSelector(IUARegistry.UAKeyCache.selector, FN));
        r.refused("cache: part past the last", at, abi.encodeCall(IUARegistry.cacheExpandedKey, (ML44, pk, 1)),
            abi.encodeWithSelector(IUARegistry.UAKeyCache.selector, ML44));
        bytes memory shortKey = new bytes(1311);
        r.refused("cache: key length", at, abi.encodeCall(IUARegistry.cacheExpandedKey, (ML44, shortKey, 0)),
            abi.encodeWithSelector(IUARegistry.UAKeyData.selector, ML44));
        r.write("cache: part 0", at, good);
        r.write("cache: part 0 again", at, good);
        r.write("cache: mldsa65 part 1", at, abi.encodeCall(IUARegistry.cacheExpandedKey, (ML65, _pk(ML65, 40), 1)));
        bytes memory ek = abi.encodePacked(UARegistry(at).expandedKeyOf(ua)[0]);
        bytes32 m = UAKinds.uaMessage(ML44, UAKinds.PURPOSE_POP_V2, _regDigest(ua, ML44));
        bytes memory pop = abi.encodePacked(keccak256(abi.encode(ek, m)));
        r.refused("register: a key-signed PoP once the cache is complete", at, _plain(ML44, pk),
            abi.encodePacked(IUARegistry.UAPoP.selector));
        _reg(r, "register through the cached key", at, _regCall(ML44, pk, _none(), pop, ""));
    }

    /// Each one change from the fresh call that ends the list and passes.
    function _registerNegatives(SplitDiff.Run memory r, address at) internal {
        bytes memory key = _pk(ML44, 50);
        bytes memory pop = _pop(UARegistry(address(0)), ML44, key);
        bytes memory poP = abi.encodePacked(IUARegistry.UAPoP.selector);
        r.refused("bad PoP", at, _regCall(ML44, key, _none(), hex"01", ""), poP);
        r.refused("PoP of another key", at, _regCall(ML44, key, _none(), _pop(UARegistry(address(0)), ML44, _pk(ML44, 51)), ""), poP);
        r.refused("disabled kind", at, _regCall(0x0777, key, _none(), pop, ""),
            abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, uint16(0x0777)));
        r.refused("key length", at, _regCall(ML44, new bytes(1311), _none(), pop, ""),
            abi.encodeWithSelector(IUARegistry.UAKeyData.selector, ML44));
        r.refused("msig through register", at, abi.encodeCall(IUARegistry.register, (UAKinds.MSIG, key, _none(), pop, "")),
            abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        _pqzAttrNegatives(r, at, key, pop);
        _kemAttrNegatives(r, at, key, pop);
        _holderNegatives(r, at);
        r.write("the base call: passes", at, _regCall(ML44, key, _none(), pop, ""));
    }

    function _pqzAttrNegatives(SplitDiff.Run memory r, address at, bytes memory key, bytes memory pop) internal {
        bytes memory hashErr = _err(IUARegistry.UAPqzPopHash.selector, UAKinds.uaOf(ML44, key));
        bytes memory pqz = _pk(UAKinds.PQZ_MLWE, 50);
        IUARegistry.UAAttrs memory a = _none();
        a.pqzPopHash = keccak256("p");
        r.refused("proof hash without a key", at, _regCall(ML44, key, a, pop, ""), hashErr);
        r.refused("a key without a proof hash", at, _regCall(ML44, key, UACall.attrs(pqz, 0, ""), pop, ""), hashErr);
        r.refused("the empty proof's hash", at, _regCall(ML44, key, UACall.attrs(pqz, keccak256(""), ""), pop, ""), hashErr);
        a = UACall.attrs(pqz, keccak256("p"), "");
        r.refused("proof bytes that do not hash to it", at, _regCall(ML44, key, a, pop, hex"01"), hashErr);
        a = UACall.attrs(new bytes(16_385), keccak256("p"), "");
        r.refused("PQZ key length", at, _regCall(ML44, key, a, pop, ""),
            abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.PQZ_MLWE));
    }

    function _kemAttrNegatives(SplitDiff.Run memory r, address at, bytes memory key, bytes memory pop) internal {
        bytes memory kemShort = new bytes(1600);
        kemShort[0] = 0x01;
        r.refused("KEM key length", at, _regCall(ML44, key, UACall.attrs("", 0, kemShort), pop, ""),
            abi.encodeWithSelector(IUARegistry.UAKemKeyLength.selector, uint256(1600)));
        bytes memory kem2 = _kemPk(50);
        kem2[0] = 0x02;
        r.refused("KEM scheme", at, _regCall(ML44, key, UACall.attrs("", 0, kem2), pop, ""),
            abi.encodeWithSelector(IUARegistry.UAKemScheme.selector, uint8(2)));
        IUARegistry.UAAttrs memory a = UACall.commit(UACall.attrs("", 0, _kemPk(50)));
        a.kem.x25519 = keccak256("x");
        r.refused("hash commit with key bytes", at, _regCall(ML44, key, a, pop, ""),
            abi.encodeWithSelector(IUARegistry.UAKemKeyLength.selector, uint256(33)));
        a = UACall.commit(UACall.attrs("", 0, _kemPk(50)));
        a.kem.scheme = 2;
        r.refused("hash commit, scheme", at, _regCall(ML44, key, a, pop, ""),
            abi.encodeWithSelector(IUARegistry.UAKemScheme.selector, uint8(2)));
    }

    /// Kinds that may not hold (slhdsa128s), ids and keys in use.
    function _holderNegatives(SplitDiff.Run memory r, address at) internal {
        bytes memory slh = _pk(SLH, 50);
        bytes32 slhUa = UAKinds.uaOf(SLH, slh);
        r.refused("PQZ key on a non-holder", at,
            _regCall(SLH, slh, UACall.attrs(_pk(UAKinds.PQZ_MLWE, 50), keccak256("p"), ""), hex"01", ""),
            _err(IUARegistry.UAPqzHolder.selector, slhUa));
        r.refused("KEM key on a non-holder", at, _regCall(SLH, slh, UACall.attrs("", 0, _kemPk(50)), hex"01", ""),
            _err(IUARegistry.UAKemHolder.selector, slhUa));
        bytes memory p = _key(0x0101);
        bytes32 pUa = UAKinds.uaOf(0x0101, p);
        r.refused("already registered", at, _plain(0x0101, p), _err(IUARegistry.UAAlreadyRegistered.selector, pUa));
        bytes memory w = vm.parseJsonBytes(_kindsJson(), ".valid[20].keyData"); // the same point under webauthn-p256
        r.refused("key in use", at, _regCall(0x0100, w, _none(), _pop(UARegistry(address(0)), 0x0100, w), ""),
            abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, UAKinds.keyHashOf(0x0100, w), pUa));
    }

    function _groupNegatives(SplitDiff.Run memory r, address at) internal {
        IUARegistry.MuSig2Key memory mk;
        mk.aggKey = hex"01";
        bytes memory wrongPoint = abi.encodeWithSelector(IUARegistry.UAKeyData.selector, uint16(0x0110));
        r.refused("MuSig2: another kind", at, abi.encodeCall(IUARegistry.registerMuSig2, (uint16(0x0111), mk, _none(), "", "")),
            abi.encodeWithSelector(IUARegistry.UAKeyData.selector, uint16(0x0111)));
        r.refused("MuSig2: point size", at, abi.encodeCall(IUARegistry.registerMuSig2, (uint16(0x0110), mk, _none(), "", "")), wrongPoint);
        IUARegistry.FrostKey memory fk;
        fk.groupKey = hex"01";
        r.refused("FROST: another kind", at, abi.encodeCall(IUARegistry.registerFrost, (uint16(0x0110), fk, _none(), "", "")),
            wrongPoint);
        r.refused("FROST: point size", at, abi.encodeCall(IUARegistry.registerFrost, (uint16(0x0111), fk, _none(), "", "")),
            abi.encodeWithSelector(IUARegistry.UAKeyData.selector, uint16(0x0111)));
        fk.groupKey = new bytes(33);
        fk.threshold = 1;
        fk.members = new IUARegistry.FrostMember[](1);
        r.refused("FROST: commitments", at, abi.encodeCall(IUARegistry.registerFrost, (uint16(0x0111), fk, _none(), "", "")),
            abi.encodeWithSelector(IUARegistry.UAKeyData.selector, uint16(0x0111)));
    }

    function _attachmentNegatives(SplitDiff.Run memory r, address at, bytes32 h2) internal {
        bytes32 slh = UAKinds.uaOf(SLH, _keyOf(SLH));
        r.refused("storePqzPop: unregistered", at, abi.encodeCall(IUARegistry.storePqzPop, (NONE_UA, hex"01")),
            _err(IUARegistry.UAUnauthorized.selector, NONE_UA));
        r.refused("storePqzPop: empty", at, abi.encodeCall(IUARegistry.storePqzPop, (h2, "")),
            _err(IUARegistry.UAPqzPopHash.selector, h2));
        r.refused("storePqzPop: other bytes", at, abi.encodeCall(IUARegistry.storePqzPop, (h2, hex"01")),
            _err(IUARegistry.UAPqzPopHash.selector, h2));
        r.refused("storePqzPop: no key", at, abi.encodeCall(IUARegistry.storePqzPop, (slh, hex"01")),
            _err(IUARegistry.UAPqzPopHash.selector, slh));
        _pqzKeyNegatives(r, at, h2, slh);
        _kemKeyNegatives(r, at, h2, slh);
        _kemCommitNegatives(r, at);
    }

    function _pqzKeyNegatives(SplitDiff.Run memory r, address at, bytes32 h2, bytes32 slh) internal {
        bytes memory pqz = _pk(UAKinds.PQZ_MLWE, 30);
        bytes memory fn = _keyOf(FN);
        bytes32 u = UAKinds.uaOf(FN, fn);
        bytes32 hash = keccak256("p");
        r.refused("setPqzKey: unregistered", at, _pqzKeyCall(NONE_UA, FN, fn, pqz, hash), _err(IUARegistry.UAUnauthorized.selector, NONE_UA));
        r.refused("setPqzKey: not a holder", at, _pqzKeyCall(slh, SLH, _keyOf(SLH), pqz, hash), _err(IUARegistry.UAPqzHolder.selector, slh));
        r.refused("setPqzKey: key set", at, _pqzKeyCall(h2, ML44, _pk(ML44, 2), pqz, hash), _err(IUARegistry.UAPqzKeySet.selector, h2));
        r.refused("setPqzKey: key length", at, _pqzKeyCall(u, FN, fn, new bytes(16_385), hash),
            abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.PQZ_MLWE));
        r.refused("setPqzKey: hash 0", at, _pqzKeyCall(u, FN, fn, pqz, 0), _err(IUARegistry.UAPqzPopHash.selector, u));
        r.refused("setPqzKey: the empty proof's hash", at, _pqzKeyCall(u, FN, fn, pqz, keccak256("")), _err(IUARegistry.UAPqzPopHash.selector, u));
        IUARegistry.UASig memory bad = _sigFor(fn, FN, UAKinds.PURPOSE_PQZ_KEY, keccak256("other"));
        r.refused("setPqzKey: bad signature", at, abi.encodeCall(IUARegistry.setPqzKey, (u, pqz, hash, bad)), _err(IUARegistry.UAUnauthorized.selector, u));
        IUARegistry.UASig memory good = _sigFor(fn, FN, UAKinds.PURPOSE_PQZ_KEY, UAKinds.pqzKeyRecordDigest(u, _h(pqz), hash));
        good.keyData = hex"01";
        r.refused("setPqzKey: key data in the signature", at, abi.encodeCall(IUARegistry.setPqzKey, (u, pqz, hash, good)),
            _err(IUARegistry.UAUnauthorized.selector, u));
        good.keyData = "";
        r.write("setPqzKey: the base call passes", at, abi.encodeCall(IUARegistry.setPqzKey, (u, pqz, hash, good)));
    }

    function _kemKeyNegatives(SplitDiff.Run memory r, address at, bytes32 h2, bytes32 slh) internal {
        bytes memory fn = _keyOf(FN);
        bytes32 u = UAKinds.uaOf(FN, fn);
        bytes memory kem = _kemPk(31);
        r.refused("setKemKey: unregistered", at, _kemCall(NONE_UA, FN, fn, 1, kem), _err(IUARegistry.UAUnauthorized.selector, NONE_UA));
        r.refused("setKemKey: not a holder", at, _kemCall(slh, SLH, _keyOf(SLH), 1, kem), _err(IUARegistry.UAKemHolder.selector, slh));
        r.refused("setKemKey: version used", at, _kemCall(h2, ML44, _pk(ML44, 2), 3, kem),
            abi.encodeWithSelector(IUARegistry.UAKemVersion.selector, h2, uint64(3)));
        r.refused("setKemKey: version 0 without a commit", at, abi.encodeCall(IUARegistry.setKemKey, (u, 0, UACall.kem(kem), _noSig())),
            abi.encodeWithSelector(IUARegistry.UAKemVersion.selector, u, uint64(0)));
        bytes memory kem2 = _kemPk(31);
        kem2[0] = 0x02;
        r.refused("setKemKey: scheme", at, _kemCall(u, FN, fn, 1, kem2), abi.encodeWithSelector(IUARegistry.UAKemScheme.selector, uint8(2)));
        IUARegistry.UASig memory kbad = _sigFor(fn, FN, UAKinds.PURPOSE_KEM, keccak256("other"));
        r.refused("setKemKey: bad signature", at, abi.encodeCall(IUARegistry.setKemKey, (u, 1, UACall.kem(kem), kbad)),
            _err(IUARegistry.UAUnauthorized.selector, u));
        r.write("setKemKey: the base call passes", at, _kemCall(u, FN, fn, 1, kem));
    }

    /// Version 0 of a commit, on its own holder.
    function _kemCommitNegatives(SplitDiff.Run memory r, address at) internal {
        (bytes32 c,) = _holder(r, "holder 60, KEM by hash", at, ML65, _pk(ML65, 60), 60, true);
        r.refused("setKemKey v0: not the committed key", at, abi.encodeCall(IUARegistry.setKemKey, (c, 0, UACall.kem(_kemPk(31)), _noSig())),
            _err(IUARegistry.UAKemKeyHash.selector, c));
        r.refused("setKemKey v0: a signature", at, abi.encodeCall(IUARegistry.setKemKey, (c, 0, UACall.kem(_kemPk(60)), UACall.sig(hex"01"))),
            _err(IUARegistry.UAUnauthorized.selector, c));
        r.write("setKemKey v0: the base call passes", at, abi.encodeCall(IUARegistry.setKemKey, (c, 0, UACall.kem(_kemPk(60)), _noSig())));
    }

    /// kinds.json `invalid`: every row as `register`, whatever it answers (both sides must agree).
    function _invalidRows(SplitDiff.Run memory r, address at) internal {
        string memory j = _kindsJson();
        uint256[] memory all = abi.decode(vm.parseJson(j, ".invalid[*].kind"), (uint256[]));
        for (uint256 i; i < all.length; ++i) {
            bytes memory d = vm.parseJsonBytes(j, string.concat(".invalid[", vm.toString(i), "].keyData"));
            bytes memory pop = hex"01";
            r.attempt(string.concat("invalid row ", vm.toString(i)), at,
                abi.encodeCall(IUARegistry.register, (uint16(all[i]), d, _none(), pop, "")));
        }
    }

    /// `msig` member rules: unknown member, wrong kind, over the budget, a PQZ holder over the debit bound.
    function _msigNegatives(SplitDiff.Run memory r, address at) internal {
        bytes memory fn = _keyOf(FN);
        bytes32 fnUa = UAKinds.uaOf(FN, fn);
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.EVM_EOA, _pad(vm.addr(ALICE)), 1);
        m[1] = Member(FN, NONE_UA, 1);
        r.refused("msig: unregistered member", at, _regCall(UAKinds.MSIG, _msigKey(2, m), _none(), "", ""),
            _err(IUARegistry.UAMemberUnknown.selector, NONE_UA));
        m[0] = Member(UAKinds.EVM_EOA, _pad(vm.addr(ALICE)), 1);
        m[1] = Member(ML44, fnUa, 1);
        r.refused("msig: member of another kind", at, _regCall(UAKinds.MSIG, _msigKey(2, m), _none(), "", ""),
            _err(IUARegistry.UAMemberUnknown.selector, fnUa));
        m[0] = Member(UAKinds.EVM_EOA, _pad(vm.addr(ALICE)), 1);
        m[1] = Member(UAKinds.MSIG, fnUa, 1);
        r.refused("msig: an msig member", at, _regCall(UAKinds.MSIG, _msigKey(2, m), _none(), "", ""),
            abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        // classical: the PoP is no PoP
        m[0] = Member(UAKinds.EVM_EOA, _pad(vm.addr(ALICE)), 1);
        m[1] = Member(0x0101, UAKinds.uaOf(0x0101, _key(0x0101)), 1);
        bytes memory d = _msigKey(2, m);
        IUARegistry.MemberSig[] memory one = new IUARegistry.MemberSig[](1);
        r.refused("msig classical: a member signature", at, _regCall(UAKinds.MSIG, d, _none(), abi.encode(one), ""),
            abi.encodePacked(IUARegistry.UAPoP.selector));
        _reg(r, "msig classical, no PoP", at, _regCall(UAKinds.MSIG, d, _none(), "", ""));
    }

    /// A PQ-eligible `msig` of 10 members at the stand-in cap 1,000,000: inside the budget, over the PQZ holder's debit bound.
    function _debitBound(SplitDiff.Run memory r, address at) internal {
        Member[] memory m = new Member[](10);
        IUARegistry.MemberSig[] memory s = new IUARegistry.MemberSig[](10);
        for (uint256 i; i < 10; ++i) {
            bytes memory k = _pk(SLH, 100 + i);
            m[i] = Member(SLH, _reg(r, "member", at, _plain(SLH, k)), 1);
        }
        bytes memory d = _msigKey(10, m);
        bytes32 ua = UAKinds.uaOf(UAKinds.MSIG, d);
        IUARegistry.UAAttrs memory a = UACall.attrs(_pk(UAKinds.PQZ_MLWE, 70), keccak256("p"), "");
        r.refused("msig PQZ holder over the debit bound", at, _regCall(UAKinds.MSIG, d, a, abi.encode(s), ""),
            _err(IUARegistry.UAPqzHolder.selector, ua));
    }

    /// Verifiers that fail in every way (`MockVerifier` modes), with a registry of their own.
    function _verifierFailures(SplitDiff.Run memory r) internal {
        uint16[5] memory k = [ML44, ML65, FN, SLH, uint16(0x0101)];
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](5);
        for (uint256 i; i < 5; ++i) c[i] = UARegistry.KindConfig(k[i], address(new MockVerifier(uint8(i + 1), 0)), 400_000);
        _deploy(R5, chainUidA, address(0), false, BUDGET, address(0), true, c);
        for (uint256 i; i < 4; ++i) {
            r.refused(string.concat("verifier mode ", vm.toString(i + 1)), R5, _plain(k[i], _pk(k[i], 80)),
                abi.encodePacked(IUARegistry.UAPoP.selector));
        }
        r.refused("verifier mode 5, out of gas", R5, _plain(0x0101, _key(0x0101)), abi.encodePacked(IUARegistry.UAPoP.selector));
    }

    /// Calldata the ABI decoder refuses, and trailing bytes it ignores.
    function _malformed(SplitDiff.Run memory r, address at) internal {
        bytes memory good = _plain(SLH, _pk(SLH, 90));
        bytes memory cut = new bytes(good.length - 40);
        for (uint256 i; i < cut.length; ++i) cut[i] = good[i];
        r.attempt("calldata cut short", at, cut);
        bytes memory dirty = bytes.concat(good);
        dirty[4 + 29] = 0x01; // the kind word's bytes above the uint16
        r.attempt("dirty kind word", at, dirty);
        bytes memory head = new bytes(3);
        r.attempt("short selector", at, head);
        r.attempt("unknown selector", at, hex"deadbeef");
        r.write("trailing bytes are ignored", at, bytes.concat(good, bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3))));
    }

    function _authRows(SplitDiff.Run memory r, address at) internal {
        (uint16[] memory k, bytes[] memory d) = _rows();
        for (uint256 i; i < k.length; ++i) {
            bytes32 ua = UAKinds.uaOf(k[i], d[i]);
            string memory n = vm.toString(uint256(k[i]));
            IUARegistry.UASig memory s;
            bytes memory key = UARegistry(at).keyOf(ua);
            if (key.length == 0) {
                s.keyData = d[i];
                key = d[i];
            }
            s.signature = _sig(key, UAKinds.uaMessage(k[i], UAKinds.PURPOSE_METATX, DIGEST));
            r.read(string.concat("requireAuthorized ", n), at, abi.encodeCall(IUARegistry.requireAuthorized, (ua, UAKinds.PURPOSE_METATX, DIGEST, s)));
            s.signature = hex"01";
            r.read(string.concat("requireAuthorized bad ", n), at, abi.encodeCall(IUARegistry.requireAuthorized, (ua, UAKinds.PURPOSE_METATX, DIGEST, s)));
        }
        IUARegistry.UASig memory e;
        bytes32 alice = _pad(vm.addr(ALICE));
        e.signature = _ecdsa(ALICE, UARegistry(at).uaAuthDigest(alice, UAKinds.PURPOSE_METATX, DIGEST));
        r.read("requireAuthorized native", at, abi.encodeCall(IUARegistry.requireAuthorized, (alice, UAKinds.PURPOSE_METATX, DIGEST, e)));
        e.signature = hex"01";
        r.read("requireAuthorized native, bad", at, abi.encodeCall(IUARegistry.requireAuthorized, (alice, UAKinds.PURPOSE_METATX, DIGEST, e)));
    }

    function _dumpUa(SplitDiff.Run memory r, address at, uint256 i) internal view {
        bytes32 u = ids[i];
        string memory n = vm.toString(i);
        r.read(string.concat(n, " recordOf"), at, abi.encodeCall(IUARegistry.recordOf, (u)));
        r.read(string.concat(n, " registrationOf"), at, abi.encodeCall(IUARegistry.registrationOf, (u)));
        r.read(string.concat(n, " popOf"), at, abi.encodeCall(IUARegistry.popOf, (u)));
        r.read(string.concat(n, " msigOf"), at, abi.encodeCall(IUARegistry.msigOf, (u)));
        r.read(string.concat(n, " webAuthnKeyOf"), at, abi.encodeCall(IUARegistry.webAuthnKeyOf, (u)));
        r.read(string.concat(n, " muSig2KeyOf"), at, abi.encodeCall(IUARegistry.muSig2KeyOf, (u)));
        r.read(string.concat(n, " frostKeyOf"), at, abi.encodeCall(IUARegistry.frostKeyOf, (u)));
        r.read(string.concat(n, " pqzPopOf"), at, abi.encodeCall(IUARegistry.pqzPopOf, (u)));
        r.read(string.concat(n, " pqzKeySigOf"), at, abi.encodeCall(IUARegistry.pqzKeySigOf, (u)));
        r.read(string.concat(n, " pqzKeyOf"), at, abi.encodeCall(IUARegistry.pqzKeyOf, (u)));
        r.read(string.concat(n, " checkedOf"), at, abi.encodeCall(IUARegistry.checkedOf, (u)));
        r.read(string.concat(n, " kemKeyOf"), at, abi.encodeCall(IUARegistry.kemKeyOf, (u)));
        r.read(string.concat(n, " kemKeyAt0"), at, abi.encodeCall(IUARegistry.kemKeyAt, (u, 0)));
        r.read(string.concat(n, " kemKeyAt1"), at, abi.encodeCall(IUARegistry.kemKeyAt, (u, 1)));
        r.read(string.concat(n, " keyOf"), at, abi.encodeCall(IUARegistry.keyOf, (u)));
        r.read(string.concat(n, " uaIndex"), at, abi.encodeCall(IUARegistry.uaIndex, (u)));
        r.read(string.concat(n, " expandedKeyOf"), at, abi.encodeCall(IUARegistry.expandedKeyOf, (u)));
        r.read(string.concat(n, " kindOf"), at, abi.encodeCall(IUARegistry.kindOf, (u)));
        r.read(string.concat(n, " isRegistered"), at, abi.encodeCall(IUARegistry.isRegistered, (u)));
    }

    function _dump(SplitDiff.Run memory r, address at) internal view {
        for (uint256 i; i < ids.length; ++i) _dumpUa(r, at, i);
        r.read("unknown recordOf", at, abi.encodeCall(IUARegistry.recordOf, (NONE_UA)));
        r.read("unknown registrationOf", at, abi.encodeCall(IUARegistry.registrationOf, (NONE_UA)));
        r.read("unknown uaIndex", at, abi.encodeCall(IUARegistry.uaIndex, (NONE_UA)));
        (uint16[] memory k,) = _rows();
        for (uint256 i; i < k.length + 3; ++i) {
            uint16 c = i < k.length ? k[i] : [UAKinds.MSIG, UAKinds.PQZ_MLWE, uint16(0x0777)][i - k.length];
            string memory n = vm.toString(uint256(c));
            r.read(string.concat(n, " uaCount"), at, abi.encodeCall(IUARegistry.uaCount, (c)));
            r.read(string.concat(n, " uaAt0"), at, abi.encodeCall(IUARegistry.uaAt, (c, 0)));
            r.read(string.concat(n, " uaAt9"), at, abi.encodeCall(IUARegistry.uaAt, (c, 9)));
            r.read(string.concat(n, " uaPage"), at, abi.encodeCall(IUARegistry.uaPage, (c, 0, 5)));
            r.read(string.concat(n, " kindName"), at, abi.encodeCall(IUARegistry.kindName, (c)));
            r.read(string.concat(n, " kindEnabled"), at, abi.encodeCall(IUARegistry.kindEnabled, (c)));
            r.read(string.concat(n, " verifyCap"), at, abi.encodeCall(IUARegistry.verifyCap, (c)));
        }
        (bytes32 a, bytes32 b, bytes32 c2) = (keccak256("a"), keccak256("b"), keccak256("c"));
        IUARegistry.KemKey memory kk = UACall.kem(_kemPk(7));
        r.read("uaOf", at, abi.encodeCall(IUARegistry.uaOf, (0x0101, _key(0x0101))));
        r.read("uaOf bad", at, abi.encodeCall(IUARegistry.uaOf, (0x0777, hex"00")));
        r.read("keyHashOf", at, abi.encodeCall(IUARegistry.keyHashOf, (0x0101, _key(0x0101))));
        r.read("uaMessage", at, abi.encodeCall(IUARegistry.uaMessage, (0x0101, a, b)));
        r.read("uaAuthDigest", at, abi.encodeCall(IUARegistry.uaAuthDigest, (a, b, c2)));
        r.read("portableDomainSeparator", at, abi.encodeCall(IUARegistry.portableDomainSeparator, ()));
        r.read("portableRecordDigest", at, abi.encodeCall(IUARegistry.portableRecordDigest, (a, ML44, b, c2)));
        r.read("registrationDigest", at, abi.encodeCall(IUARegistry.registrationDigest, (a, ML44, b, c2, a)));
        r.read("pqzKeyDigest", at, abi.encodeCall(IUARegistry.pqzKeyDigest, (a, b)));
        r.read("pqzKeyRecordDigest", at, abi.encodeCall(IUARegistry.pqzKeyRecordDigest, (a, b, c2)));
        r.read("kemRecordHash", at, abi.encodeCall(IUARegistry.kemRecordHash, (a, 3, kk)));
        r.read("kemRecordDigest", at, abi.encodeCall(IUARegistry.kemRecordDigest, (a, 3, kk)));
        r.read("eip712Domain", at, abi.encodeWithSignature("eip712Domain()"));
    }

    /// Gen 2 in front of gen 1, 0x0142 enabled here only: the attachment of a gen-1 record, forwarded reads and checks.
    function _gen2(SplitDiff.Run memory r, bytes32 h2, bytes memory proof2) internal {
        UARegistry.KindConfig[] memory c = _one(UAKinds.PQZ_MLWE, address(new MockVerifier(0, 0)), PQ);
        _deploy(R2, chainUidA, R1, false, BUDGET, address(0), true, c);
        r.write("gen 2: storePqzPop of a gen-1 key", R2, abi.encodeCall(IUARegistry.storePqzPop, (h2, proof2)));
        // a gen-1 record without a PQZ key takes one here, signed through gen 1
        bytes memory pk = _pk(ML65, 70);
        bytes32 ua = _reg(r, "gen 1: a holder for gen 2", R1, _plain(ML65, pk));
        bytes memory pqz = _pk(UAKinds.PQZ_MLWE, 71);
        r.refused("gen 2: setPqzKey, bad signature", R2, _pqzKeyCall(ua, ML65, pk, pqz, 0x0), _err(IUARegistry.UAPqzPopHash.selector, ua));
        r.write("gen 2: setPqzKey on a gen-1 record", R2, _pqzKeyCall(ua, ML65, pk, pqz, keccak256("g2")));
        r.refused("gen 2: setKemKey of a gen-1 record", R2, _kemCall(ua, ML65, pk, 1, _kemPk(70)), _err(IUARegistry.UAUnauthorized.selector, ua));
        _gen2Msigs(r);
        // a kind gen 2 does not enable; an id neither generation holds
        r.refused("gen 2: disabled kind", R2, _plain(ML44, _pk(ML44, 72)), abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, ML44));
        r.refused("gen 2: unregistered", R2, abi.encodeCall(IUARegistry.storePqzPop, (NONE_UA, hex"01")), _err(IUARegistry.UAUnauthorized.selector, NONE_UA));
    }

    /// Msigs of gen-1 members on gen 2: classical, and PQ-eligible with its PoP checked through gen 1.
    function _gen2Msigs(SplitDiff.Run memory r) internal {
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.EVM_EOA, _pad(vm.addr(ALICE)), 1);
        m[1] = Member(0x0102, UAKinds.uaOf(0x0102, _key(0x0102)), 1);
        _reg(r, "gen 2: classical msig of gen-1 members", R2, _regCall(UAKinds.MSIG, _msigKey(2, m), _none(), "", ""));
        bytes memory fn = _keyOf(FN);
        bytes memory ml = _pk(ML44, 11);
        bytes memory d = _msigStructure(ml, fn, 3);
        bytes32 ms = UAKinds.uaOf(UAKinds.MSIG, d);
        bytes32 rd = _regDigest(ms, UAKinds.MSIG);
        bytes32 md = _memberDigest(ms, UAKinds.PURPOSE_POP_V2, rd);
        IUARegistry.MemberSig[] memory s = new IUARegistry.MemberSig[](3);
        s[0] = _member(d, _pad(vm.addr(ALICE)), _ecdsa(ALICE, rd));
        s[1] = _member(d, UAKinds.uaOf(FN, fn), _sig(fn, UAKinds.uaMessage(FN, UAKinds.PURPOSE_MEMBER, md)));
        s[2] = _member(d, UAKinds.uaOf(ML44, ml), _sig(ml, UAKinds.uaMessage(ML44, UAKinds.PURPOSE_MEMBER, md)));
        _reg(r, "gen 2: PQ-eligible msig, PoP through gen 1", R2, _regCall(UAKinds.MSIG, d, _none(), abi.encode(_sorted(s)), ""));
    }

    /// Gen 2 without 0x0142 in front of a gen 1 with it: no PQZ key here.
    function _gen2NoPqz(SplitDiff.Run memory r) internal {
        _deploy(R6, chainUidA, address(0), false, BUDGET, address(0), true, _one(UAKinds.PQZ_MLWE, address(new MockVerifier(0, 0)), PQ));
        _deploy(R7, chainUidA, R6, false, BUDGET, address(0), true, _one(ML65, address(new MockVerifier(0, 0)), PQ));
        bytes memory pk = _pk(ML65, 75);
        IUARegistry.UAAttrs memory a = UACall.attrs(_pk(UAKinds.PQZ_MLWE, 75), keccak256("p"), "");
        r.refused("gen 2: a PQZ key where gen 1 enables 0x0142", R7, _regCall(ML65, pk, a, hex"01", ""),
            abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, UAKinds.PQZ_MLWE));
        bytes memory p = _pk(ML65, 76);
        bytes32 ua = _reg(r, "gen 2: holder, no attributes", R7, _plain(ML65, p));
        r.refused("gen 2: setPqzKey where gen 1 enables 0x0142", R7, _pqzKeyCall(ua, ML65, p, _pk(UAKinds.PQZ_MLWE, 75), keccak256("p")),
            abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, UAKinds.PQZ_MLWE));
    }

    /// `_cloneHash()`'s word: a `SmartKeyAccount` clone member gets 400 k, the same code outside the clone hash 50 k.
    function _cloneMember(SplitDiff.Run memory r) internal {
        MockWallet impl = new MockWallet(vm.addr(ALICE), 0, 300_000, R8);
        _deploy(R8, chainUidA, address(0), false, BUDGET, address(impl), true, _one(FN, address(new MockVerifier(0, 0)), PQ));
        bytes memory fn = _pk(FN, 81);
        _reg(r, "clone: the PQ member", R8, _plain(FN, fn));
        address clone = address(0xC10E);
        vm.etch(clone, abi.encodePacked(hex"363d3d373d3d3d363d73", address(impl), hex"5af43d82803e903d91602b57fd5bf3"));
        r.refused("clone: the same wallet outside the clone hash", R8, _walletMsig(address(new MockWallet(vm.addr(ALICE), 0, 300_000, R8)), fn),
            abi.encodePacked(IUARegistry.UAPoP.selector));
        _reg(r, "clone: a member at 400 k", R8, _walletMsig(clone, fn));
    }

    /// `registerMsig` of the wallet `w` and the PQ member `fn`, 2 of 2, signed.
    function _walletMsig(address w, bytes memory fn) internal pure returns (bytes memory) {
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.EVM_EOA, _pad(w), 1);
        m[1] = Member(FN, UAKinds.uaOf(FN, fn), 1);
        bytes memory d = _msigKey(2, m);
        bytes32 ua = UAKinds.uaOf(UAKinds.MSIG, d);
        bytes32 rd = _regDigest(ua, UAKinds.MSIG);
        IUARegistry.MemberSig[] memory s = new IUARegistry.MemberSig[](2);
        s[0] = _member(d, _pad(w), _ecdsa(ALICE, rd));
        s[1] = _member(d, m[0].id == _pad(w) ? m[1].id : m[0].id,
            _sig(fn, UAKinds.uaMessage(FN, UAKinds.PURPOSE_MEMBER, _memberDigest(ua, UAKinds.PURPOSE_POP_V2, rd))));
        return _regCall(UAKinds.MSIG, d, _none(), abi.encode(_sorted(s)), "");
    }

    function _scenario(string memory art) internal returns (SplitDiff.Run memory r) {
        registryArtifact = art;
        delete ids;
        vm.setNonceUnsafe(address(this), 1_000); // the verifiers' addresses: the same in both runs (a state revert keeps it)
        r = SplitDiff.start(12_000, address(UARegistryLib));
        _deploy(R1, chainUidA, address(0), false, BUDGET, address(0), true, _all(false));
        _gen1Registrations(r, R1);
        _authRows(r, R1);
        (bytes32 h2, bytes memory proof2) = _attachments(r, R1);
        _msigs(r, R1);
        _packedRegistry(r);
        _cache(r, R1);
        _registerNegatives(r, R1);
        _groupNegatives(r, R1);
        _attachmentNegatives(r, R1, h2);
        _msigNegatives(r, R1);
        _debitBound(r, R1);
        _invalidRows(r, R1);
        _malformed(r, R1);
        _verifierFailures(r);
        _gen2(r, h2, proof2);
        _dump(r, R1);
        _dump(r, R2);
        _gen2NoPqz(r);
        _cloneMember(r);
    }

    /// `register`'s packed entry for the typed kinds, on a registry of its own (the same ids).
    function _packedRegistry(SplitDiff.Run memory r) internal {
        _deploy(R4, chainUidA, address(0), false, BUDGET, address(0), true, _all(false));
        _packedEntries(r, R4);
    }

    /// The whole scenario on both sides. The negatives check their exact revert data on both; a positive reverts the test.
    function test_diff() public {
        uint256 snap = vm.snapshotState();
        SplitDiff.Run memory a = _scenario(OLD);
        vm.revertToState(snap);
        SplitDiff.Run memory b = _scenario(NEW);
        assertEq(SplitDiff.firstDiff(a, b), "", "first row that differs");
        emit log_named_uint("rows", a.n);
        emit log_named_uint("writes that went through", a.writes);
        emit log_named_uint("expected reverts", a.reverts);
        assertGe(a.n, 2_000, "the views of the spike's 1,210 and the writes");
        assertEq(a.reverts, b.reverts);
        assertEq(a.writes, b.writes);
    }

    // ----- the ABI and the storage layout -----

    function _art(string memory n) internal view returns (string memory) {
        return vm.readFile(string.concat("out/", n, ".sol/", n, ".json"));
    }

    /// The 53 selectors, every function, event and error name of the pre-split ABI, `SSTORE2WriteFailed` among them.
    function test_abiUnchanged() public view {
        (string memory a, string memory b) = (_art("UARegistryPreSplit"), _art("UARegistry"));
        string[] memory fa = vm.parseJsonKeys(a, ".methodIdentifiers");
        string[] memory fb = vm.parseJsonKeys(b, ".methodIdentifiers");
        assertEq(fa.length, fb.length);
        assertEq(fb.length, 53, "selectors");
        for (uint256 i; i < fa.length; ++i) {
            assertEq(fa[i], fb[i]);
            string memory k = string.concat(".methodIdentifiers['", fa[i], "']");
            assertEq(vm.parseJsonString(a, k), vm.parseJsonString(b, k), fa[i]);
        }
        string[3] memory t = ["function", "event", "error"];
        for (uint256 i; i < 3; ++i) {
            string memory q = string.concat("$.abi[?(@.type=='", t[i], "')].name");
            assertEq(keccak256(vm.parseJson(a, q)), keccak256(vm.parseJson(b, q)), t[i]);
        }
        bool found;
        string[] memory errs = abi.decode(vm.parseJson(b, "$.abi[?(@.type=='error')].name"), (string[]));
        for (uint256 i; i < errs.length; ++i) found = found || keccak256(bytes(errs[i])) == keccak256("SSTORE2WriteFailed");
        assertTrue(found, "SSTORE2WriteFailed on the registry's ABI");
    }

    /// Every `UAStore.Layout` field in the slot its mapping had. (`test_diff` compares the slots written, library included.)
    function test_storageLayoutUnchanged() public view {
        (string memory a, string memory b) = (_art("UARegistryPreSplit"), _art("UARegistry"));
        assertEq(vm.parseJsonString(b, ".storageLayout.storage[0].label"), "_s");
        assertEq(vm.parseJsonString(b, ".storageLayout.storage[0].slot"), "0");
        assertFalse(vm.keyExistsJson(b, ".storageLayout.storage[1]"), "no second variable");
        string memory m = string.concat(".storageLayout.types['", vm.parseJsonString(b, ".storageLayout.storage[0].type"), "'].members[");
        string[15] memory names = ["records", "keyOwner", "pqzKey", "ekPtr", "uaCount", "uaAt", "reg", "pqzPopHash", "pqzPop", "pqzKeySig",
            "kem", "kemMax", "kemCommit", "regPqzKey", "regPqzPopHash"];
        for (uint256 i; i < 15; ++i) {
            string memory n = string.concat(m, vm.toString(i), "]");
            string memory o = string.concat(".storageLayout.storage[", vm.toString(i), "]");
            assertEq(vm.parseJsonString(b, string.concat(n, ".label")), names[i]);
            assertEq(vm.parseJsonString(a, string.concat(o, ".label")), string.concat("_", names[i]));
            assertEq(vm.parseJsonString(b, string.concat(n, ".slot")), vm.toString(i));
            assertEq(vm.parseJsonString(a, string.concat(o, ".slot")), vm.toString(i));
        }
    }

    /// No CALL, CALLCODE, DELEGATECALL or SELFDESTRUCT in the library: everything it calls runs under the static flag, so
    /// nothing can come back into a write, and it can hand its context to nobody.
    function test_libraryOpcodes() public view {
        bytes memory c = address(UARegistryLib).code;
        uint256 end = c.length - 2 - ((uint256(uint8(c[c.length - 2])) << 8) | uint8(c[c.length - 1]));
        while (end > 0 && c[end - 1] != 0xfe) --end;
        uint256 statics;
        for (uint256 i; i < end; ++i) {
            uint8 op = uint8(c[i]);
            if (op >= 0x60 && op <= 0x7f) i += op - 0x5f;
            else if (op == 0xfa) ++statics;
            else {
                assertTrue(op != 0xf1, "CALL");
                assertTrue(op != 0xf2, "CALLCODE");
                assertTrue(op != 0xf4, "DELEGATECALL");
                assertTrue(op != 0xff, "SELFDESTRUCT");
            }
        }
        assertGt(statics, 0, "the walk reached the calls");
    }

    // ----- the words, a direct call -----

    function _words(address v) internal pure returns (bytes memory) {
        uint256 w = uint256(uint160(v)) | uint256(PQ) << 160;
        return abi.encode(w, w, bytes32(0));
    }

    /// Each library entry with `v` in the words a registry would append.
    function _entries(address v) internal pure returns (bytes[] memory c) {
        bytes memory pk = _pk(ML44, 1);
        bytes32 ua = UAKinds.uaOf(ML44, pk);
        IUARegistry.WebAuthnKey memory w;
        IUARegistry.MuSig2Key memory m;
        IUARegistry.FrostKey memory f;
        IUARegistry.MsigStructure memory st;
        c = new bytes[](9);
        c[0] = abi.encodeWithSelector(UARegistryLib.cacheExpandedKey.selector, ML44, pk, uint256(0));
        c[1] = abi.encodeWithSelector(UARegistryLib.register.selector, ML44, pk, _none(), _pop(UARegistry(address(0)), ML44, pk), bytes(""));
        c[2] = abi.encodeWithSelector(UARegistryLib.registerWebAuthn.selector, w, _none(), bytes(""), bytes(""));
        c[3] = abi.encodeWithSelector(UARegistryLib.registerMuSig2.selector, uint16(0x0110), m, _none(), bytes(""), bytes(""));
        c[4] = abi.encodeWithSelector(UARegistryLib.registerFrost.selector, uint16(0x0111), f, _none(), bytes(""), bytes(""));
        c[5] = abi.encodeWithSelector(UARegistryLib.registerMsig.selector, st, _none(), new IUARegistry.MemberSig[](0), bytes(""));
        c[6] = abi.encodeWithSelector(UARegistryLib.storePqzPop.selector, ua, hex"01");
        c[7] = abi.encodeWithSelector(UARegistryLib.setPqzKey.selector, ua, _pk(UAKinds.PQZ_MLWE, 1), keccak256("p"), _noSig());
        c[8] = abi.encodeWithSelector(UARegistryLib.setKemKey.selector, ua, uint64(1), UACall.kem(_kemPk(1)), _noSig());
        for (uint256 i; i < 9; ++i) c[i] = bytes.concat(c[i], _words(v));
    }

    /// Called directly, every entry reverts with nothing (solc's library call protection), with no write and no log, even
    /// with an accepting verifier in the words. The same bytes through a DELEGATECALL reach the code (control), on the
    /// caller's own storage: a typed answer, or a pass, never the registry's state.
    function test_libraryDirectCallRefused() public {
        bytes[] memory c = _entries(address(new CacheVerifier(address(0))));
        Foreign foreign = new Foreign();
        address lib = address(UARegistryLib);
        for (uint256 i; i < c.length; ++i) {
            vm.record();
            vm.recordLogs();
            (bool ok, bytes memory ret) = lib.call(c[i]);
            (, bytes32[] memory writes) = vm.accesses(lib);
            assertFalse(ok, vm.toString(i));
            assertEq(ret.length, 0, vm.toString(i));
            assertEq(writes.length, 0, vm.toString(i));
            assertEq(vm.getRecordedLogs().length, 0, vm.toString(i));
            (bool ok2, bytes memory ret2) = foreign.run(lib, c[i]);
            assertTrue(ok2 || ret2.length >= 4, string.concat("the control reached the code ", vm.toString(i)));
        }
        bytes32 ua = UAKinds.uaOf(ML44, _pk(ML44, 1));
        assertEq(reg.kindOf(ua), 0, "a foreign run writes nowhere near a registry");
    }

    /// Three words a caller appends stay its own trailing bytes: the library reads the ones the registry appends after them.
    /// One change each from a passing call, on both sides.
    function test_callerCannotSupplyTheWords() public {
        string[2] memory arts = [OLD, NEW];
        address yes = address(new MockVerifier(0, 0));
        for (uint256 i; i < 2; ++i) {
            registryArtifact = arts[i];
            address at = i == 0 ? R1 : R2;
            UARegistry r = _deploy(at, chainUidA, address(0), false, BUDGET, address(0), true, _one(SLH, address(mock), PQ));
            bytes memory words = _words(yes);
            bytes memory key = _pk(SLH, 1);
            // a disabled kind stays disabled, whatever word follows
            bytes memory off = _regCall(ML44, _pk(ML44, 1), _none(), _pop(r, ML44, _pk(ML44, 1)), "");
            (bool ok, bytes memory ret) = at.call(bytes.concat(off, words));
            assertFalse(ok);
            assertEq(ret, abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, ML44));
            // a bad PoP stays bad under the kind's own verifier
            (ok, ret) = at.call(bytes.concat(_regCall(SLH, key, _none(), hex"01", ""), words));
            assertFalse(ok);
            assertEq(ret, abi.encodePacked(IUARegistry.UAPoP.selector));
            // control: the same trailing bytes after a good call
            (ok,) = at.call(bytes.concat(_plain(SLH, key), words));
            assertTrue(ok);
            assertEq(r.kindOf(UAKinds.uaOf(SLH, key)), SLH);
        }
    }

    /// The one known difference, malformed calldata only: an offset inside a struct is checked where it is read, and in
    /// the library the calldata is 96 B longer. A `pqzKey` offset aimed at the appended clone word (0 here) reverted before;
    /// now it reads as the empty key, which is what the well-formed call has: same record, nothing the caller could not send.
    function test_nestedOffsetReadsAWordAsItsOwnArgument() public {
        bytes memory good = _plain(SLH, _pk(SLH, 1));
        uint256 attrs = 4 + uint256(_word(good, 4 + 2 * 32));
        uint256 aim = good.length + 64;
        bytes memory bad = bytes.concat(good);
        bytes32 rel = bytes32(aim - attrs);
        assembly ("memory-safe") {
            mstore(add(add(bad, 32), attrs), rel)
        }
        registryArtifact = OLD;
        _deploy(R1, chainUidA, address(0), false, BUDGET, address(0), true, _one(SLH, address(mock), PQ));
        (bool ok, bytes memory ret) = R1.call(bad);
        assertFalse(ok, "before: past the calldata");
        assertEq(ret.length, 0);
        registryArtifact = NEW;
        _deploy(R2, chainUidA, address(0), false, BUDGET, address(0), true, _one(SLH, address(mock), PQ));
        (ok,) = R2.call(bad);
        assertTrue(ok, "now: the word, 0, as the length");
        bytes32 ua = UAKinds.uaOf(SLH, _pk(SLH, 1));
        (bool g,) = R1.call(good);
        assertTrue(g);
        (, bytes memory a) = R1.staticcall(abi.encodeCall(IUARegistry.registrationOf, (ua)));
        (, bytes memory b) = R2.staticcall(abi.encodeCall(IUARegistry.registrationOf, (ua)));
        assertEq(a, b, "the record of the well-formed call");
        assertEq(UARegistry(R2).verifyCap(SLH), PQ, "the immutables did not move");
    }

    function _word(bytes memory d, uint256 o) internal pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(d, 32), o))
        }
    }

    // ----- DELEGATECALL safety -----

    /// A verifier called during `register` (in the library, on the registry's storage) tries to write back through the
    /// registry. The STATICCALL frame refuses it, on both sides: the verifier's pass is that refusal. Control: the same
    /// write, with the same gas, outside the static frame goes through.
    function test_reentryFromAVerifierRefused() public {
        string[2] memory arts = [OLD, NEW];
        for (uint256 i; i < 2; ++i) {
            registryArtifact = arts[i];
            ReentrantVerifier v = new ReentrantVerifier();
            address at = i == 0 ? R1 : R2;
            UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](2);
            (c[0], c[1]) = (UARegistry.KindConfig(ML44, address(v), 6_000_000), UARegistry.KindConfig(SLH, address(mock), PQ));
            _deploy(at, chainUidA, address(0), false, BUDGET, address(0), true, c);
            bytes memory inner = _plain(SLH, _pk(SLH, 2));
            v.arm(at, inner);
            bytes memory pk = _pk(ML44, 2);
            UARegistry(at).register(ML44, pk, _none(), hex"01", "");
            bytes32 ua = UAKinds.uaOf(SLH, _pk(SLH, 2));
            assertEq(UARegistry(at).kindOf(ua), 0, "the inner write did not land");
            (bool ok,) = at.call{gas: 5_900_000}(inner);
            assertTrue(ok, "the write fits that gas outside the static frame");
            assertEq(UARegistry(at).kindOf(ua), SLH);
        }
    }

    /// An ERC-1271 member asked during a write sees the registry as `msg.sender`, not the library. One change: a wallet
    /// that wants another registry refuses.
    function test_1271MemberSeesTheRegistry() public {
        string[2] memory arts = [OLD, NEW];
        for (uint256 i; i < 2; ++i) {
            registryArtifact = arts[i];
            address at = i == 0 ? R1 : R2;
            UARegistry r = _deploy(at, chainUidA, address(0), false, BUDGET, address(0), true, _one(FN, address(mock), PQ));
            bytes memory fn = _pk(FN, 3);
            _register(r, FN, fn);
            (bool ok, bytes memory ret) = at.call(_walletMsig(address(new SenderWallet(address(UARegistryLib))), fn));
            assertFalse(ok);
            assertEq(ret, abi.encodePacked(IUARegistry.UAPoP.selector));
            (ok,) = at.call(_walletMsig(address(new SenderWallet(at)), fn));
            assertTrue(ok);
        }
    }

    /// A DELEGATECALL to an empty account succeeds: without the library every write would be a silent no-op, so the
    /// constructor refuses. Control: with the library the same arguments deploy.
    function test_constructorRefusesAMissingLibrary() public {
        address lib = address(UARegistryLib);
        bytes memory code = lib.code;
        vm.etch(lib, "");
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0)));
        new UARegistry(chainUidA, address(0), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0));
        vm.etch(lib, code);
        new UARegistry(chainUidA, address(0), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0));
    }

    /// Two registries on one library: it has no state of its own.
    function test_gen2SharesTheLibrary() public {
        UARegistry g1 = _deploy(R1, chainUidA, address(0), false, BUDGET, address(0), true, _one(0x0101, address(mock), 400_000));
        UARegistry g2 = _deploy(R2, chainUidA, R1, false, BUDGET, address(0), true, _one(UAKinds.PQZ_MLWE, address(mock), PQ));
        bytes32 ua = _register(g1, 0x0101, _key(0x0101));
        assertEq(g2.kindOf(ua), 0x0101, "gen 2 reads gen 1");
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.EVM_EOA, _pad(vm.addr(ALICE)), 1);
        m[1] = Member(0x0101, ua, 1);
        bytes32 ms = g2.registerMsig(UACall.structure(_msigKey(2, m)), _none(), new IUARegistry.MemberSig[](0), "");
        assertEq(g2.kindOf(ms), UAKinds.MSIG);
        assertEq(g1.kindOf(ms), 0, "gen 2's write stayed in gen 2");
    }

    // ----- gas and deployment -----

    struct Gas {
        string[] labels;
        uint256[] used;
        uint256 n;
    }

    function _put(Gas memory g, string memory label, uint256 used) internal pure {
        g.labels[g.n] = label;
        g.used[g.n++] = used;
    }

    function _meter(Gas memory g, address at, bytes32 ua, IUARegistry.UASig memory s, string memory label) internal {
        (bool ok,, uint256 used) = gm.measure(at, abi.encodeCall(IUARegistry.requireAuthorized, (ua, UAKinds.PURPOSE_METATX, DIGEST, s)));
        assertTrue(ok, label);
        _put(g, string.concat("requireAuthorized ", label), used);
    }

    function _gasRun(string memory art) internal returns (Gas memory g) {
        g.labels = new string[](100);
        g.used = new uint256[](100);
        registryArtifact = art;
        vm.setNonceUnsafe(address(this), 2_000);
        address at = R8;
        _deploy(at, chainUidA, address(0), false, BUDGET, address(0), true, _all(false));
        (uint16[] memory k, bytes[] memory d) = _rows();
        for (uint256 i; i < k.length; ++i) {
            string memory n = vm.toString(uint256(k[i]));
            (bool ok, bytes memory ret) = at.call(_plain(k[i], d[i]));
            Vm.Gas memory lg = vm.lastCallGas();
            assertTrue(ok, n);
            _put(g, string.concat("register regular ", n), lg.gasTotalUsed);
            _put(g, string.concat("register state ", n), uint256(int256(lg.gasStateUsed)));
            bytes32 ua = abi.decode(ret, (bytes32));
            IUARegistry.UASig memory s;
            bytes memory key = UARegistry(at).keyOf(ua);
            if (key.length == 0) (s.keyData, key) = (d[i], d[i]);
            s.signature = _sig(key, UAKinds.uaMessage(k[i], UAKinds.PURPOSE_METATX, DIGEST));
            _meter(g, at, ua, s, n);
        }
        IUARegistry.UASig memory e;
        bytes32 alice = _pad(vm.addr(ALICE));
        e.signature = _ecdsa(ALICE, UARegistry(at).uaAuthDigest(alice, UAKinds.PURPOSE_METATX, DIGEST));
        _meter(g, at, alice, e, "native eoa");
        MockWallet w = new MockWallet(vm.addr(ALICE), 0, 0, at);
        e.signature = _ecdsa(ALICE, UARegistry(at).uaAuthDigest(_pad(address(w)), UAKinds.PURPOSE_METATX, DIGEST));
        _meter(g, at, _pad(address(w)), e, "native 1271");
        bytes32 p = UAKinds.uaOf(0x0101, _key(0x0101));
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.EVM_EOA, alice, 1);
        m[1] = Member(0x0101, p, 1);
        bytes memory ds = _msigKey(2, m);
        bytes32 mu = UARegistry(at).registerMsig(UACall.structure(ds), _none(), new IUARegistry.MemberSig[](0), "");
        _put(g, "registerMsig regular", vm.lastCallGas().gasTotalUsed);
        bytes32 md = _memberDigest(mu, UAKinds.PURPOSE_METATX, DIGEST);
        IUARegistry.MemberSig[] memory s2 = new IUARegistry.MemberSig[](2);
        s2[_indexOf(ds, alice)] = IUARegistry.MemberSig(_indexOf(ds, alice), "", _ecdsa(ALICE, UARegistry(at).uaAuthDigest(alice, UAKinds.PURPOSE_MEMBER, md)));
        s2[_indexOf(ds, p)] = IUARegistry.MemberSig(_indexOf(ds, p), "", _sig(_key(0x0101), UAKinds.uaMessage(0x0101, UAKinds.PURPOSE_MEMBER, md)));
        IUARegistry.UASig memory sm;
        sm.members = s2;
        _meter(g, at, mu, sm, "msig 2-of-2");
    }

    /// `requireAuthorized`, every kind, native and `msig`, stays within the spike's +37 gas (bound here: +64, to take a code
    /// layout's change of JUMPDEST order); `register` state gas does not move. Rows `GAS|label|before|after|delta`.
    function test_gasHotPath() public {
        uint256 snap = vm.snapshotState();
        Gas memory a = _gasRun(OLD);
        vm.revertToState(snap);
        Gas memory b = _gasRun(NEW);
        assertEq(a.n, b.n);
        for (uint256 i; i < a.n; ++i) {
            int256 delta = int256(b.used[i]) - int256(a.used[i]);
            emit log_string(string.concat("GAS|", a.labels[i], "|", vm.toString(a.used[i]), "|", vm.toString(b.used[i]), "|", vm.toString(delta)));
            if (_starts(a.labels[i], "requireAuthorized")) assertLe(delta, 64, a.labels[i]);
            if (_starts(a.labels[i], "register state")) assertEq(delta, 0, a.labels[i]);
        }
    }

    function _starts(string memory s, string memory prefix) internal pure returns (bool) {
        bytes memory a = bytes(s);
        bytes memory p = bytes(prefix);
        for (uint256 i; i < p.length; ++i) if (i >= a.length || a[i] != p[i]) return false;
        return true;
    }

    function _msigAtBudget(string memory art, address at) internal returns (uint256 regular) {
        registryArtifact = art;
        MockVerifier burn = new MockVerifier(0, 1_390_000);
        _deploy(at, chainUidA, address(0), false, BUDGET, address(0), true, _one(SLH, address(burn), 1_400_000));
        Member[] memory m = new Member[](8);
        for (uint256 i; i < 8; ++i) {
            bytes memory k = _pk(SLH, 200 + i);
            bytes memory pop = _pop(UARegistry(at), SLH, k);
            m[i] = Member(SLH, UACall.register(IUARegistry(at), SLH, k, _none(), pop, ""), 1);
        }
        bytes memory d = _msigKey(8, m);
        bytes32 ua = UAKinds.uaOf(UAKinds.MSIG, d);
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_POP_V2, _regDigest(ua, UAKinds.MSIG));
        IUARegistry.MemberSig[] memory s = new IUARegistry.MemberSig[](8);
        for (uint16 i; i < 8; ++i) {
            bytes memory k = _pk(SLH, 200 + i);
            s[_indexOf(d, UAKinds.uaOf(SLH, k))] = IUARegistry.MemberSig(_indexOf(d, UAKinds.uaOf(SLH, k)), "",
                _sig(k, UAKinds.uaMessage(SLH, UAKinds.PURPOSE_MEMBER, md)));
        }
        (bool ok, bytes memory ret) = at.call(_regCall(UAKinds.MSIG, d, _none(), abi.encode(s), ""));
        regular = vm.lastCallGas().gasTotalUsed;
        assertTrue(ok, vm.toString(ret));
    }

    /// The spike left this open: the PoP of an `msig` at its bound (8 members near 1.4 M each, 11.6 M of the 12 M budget), each
    /// derived member now a `requireAuthorized` frame on the registry. It still fits a 2^24 transaction.
    function test_msigPopAtTheBudget() public {
        uint256 before = _msigAtBudget(OLD, R1);
        uint256 now_ = _msigAtBudget(NEW, R2);
        emit log_string(string.concat("GAS|registerMsig 8 members at the budget|", vm.toString(before), "|", vm.toString(now_), "|", vm.toString(int256(now_) - int256(before))));
        assertLt(now_, 1 << 24);
    }

    function _create2(Create2er c, bytes memory init) internal returns (uint256 regular, uint256 state) {
        c.create(keccak256("scaas.deploy.v1"), init);
        Vm.Gas memory g = vm.lastCallGas();
        return (g.gasTotalUsed, uint256(int256(g.gasStateUsed)));
    }

    /// Each deployment its own transaction, CREATE2 with a salt, as `DeployBase`: `UARegistryLib`, `UARegistry` of all kinds,
    /// and the pre-split contract. Every one fits a 60 M block by simulated gas; the regular gas fits 2^24.
    function test_deployGas() public {
        Create2er c = new Create2er();
        bytes memory args = abi.encode(chainUidA, address(0), false, BUDGET, address(0), true, _all(true));
        (uint256 r0, uint256 s0) = _create2(c, bytes.concat(type(UARegistryPreSplit).creationCode, args));
        emit log_string(string.concat("DEPLOY|pre-split UARegistry|", vm.toString(r0), "|", vm.toString(s0), "|", vm.toString(r0 + s0)));
        (uint256 r1, uint256 s1) = _create2(c, bytes.concat(type(UARegistry).creationCode, args));
        emit log_string(string.concat("DEPLOY|UARegistry|", vm.toString(r1), "|", vm.toString(s1), "|", vm.toString(r1 + s1)));
        (uint256 r2, uint256 s2) = _create2(c, vm.getCode("UARegistryLib.sol:UARegistryLib"));
        emit log_string(string.concat("DEPLOY|UARegistryLib|", vm.toString(r2), "|", vm.toString(s2), "|", vm.toString(r2 + s2)));
        assertLt(r1 + s1, 60_000_000);
        assertLt(r2 + s2, 60_000_000);
        assertLt(r1, 1 << 24);
        assertLt(r2, 1 << 24);
        assertGt(r0 + s0, 60_000_000, "the split's reason");
    }
}
