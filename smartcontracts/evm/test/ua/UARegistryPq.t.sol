// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UAMldsaVerifier} from "../../src/ua/MlDsa.sol";
import {UAFndsaVerifier} from "../../src/ua/FnDsa.sol";
import {UASlhdsaVerifier} from "../../src/ua/SlhDsa.sol";
import {P256Verifier} from "../../src/ua/verifiers/P256Verifier.sol";
import {console2} from "forge-std/Test.sol";
import {MockVerifier, UARegistryBase} from "./UARegistryBase.sol";
import {BurnAll, GasProbe} from "./UAGas.t.sol";

/// P6c: the PQ kinds in registry generation 1 (accounts.md CTR-UA-17, CTR-UA-23, §1.8, §1.9; pq-zero-knowledge.md CTR-PQZ-12,
/// CTR-PQZ-13). Mock verifiers for the slots, the stored keys, the cache refusals and the `pqz-mlwe` `authRef` rule; the
/// real verifiers on smartcontracts/vectors/ua/pq_signatures.json (context A) for T-REG-1/2, T-AUTH-1, the expanded-key
/// cache and T-GAS. Gas is logged (`-vv`).
contract UARegistryPqTest is UARegistryBase {
    uint64 internal constant CAP_MLDSA44 = 4_250_000;
    uint64 internal constant CAP_MLDSA65 = 5_950_000;
    uint64 internal constant CAP_FNDSA = 2_500_000;
    uint64 internal constant CAP_SLHDSA = 1_400_000;
    uint256 internal constant TX_CAP = 16_777_216; // EIP-7825

    /// Read per test into memory (a storage copy of the 0.5 MB file would cost millions of gas per access).
    function _pj() internal view returns (string memory) {
        return vm.readFile("../vectors/ua/pq_signatures.json");
    }

    // ----- configuration -----

    function _realPq() internal returns (UARegistry.KindConfig[] memory c) {
        c = new UARegistry.KindConfig[](5);
        c[0] = UARegistry.KindConfig(0x0101, address(new P256Verifier()), 400_000);
        c[1] = UARegistry.KindConfig(0x0130, address(new UAMldsaVerifier(0x0130, address(0), "", "")), CAP_MLDSA44);
        c[2] = UARegistry.KindConfig(0x0131, address(new UAMldsaVerifier(0x0131, address(0), "", "")), CAP_MLDSA65);
        c[3] = UARegistry.KindConfig(0x0132, address(new UAFndsaVerifier()), CAP_FNDSA);
        c[4] = UARegistry.KindConfig(0x0133, address(new UASlhdsaVerifier()), CAP_SLHDSA);
    }

    /// Mock verifiers for 0x0101, the four PQ kinds and `pqz-mlwe`, PQ caps `pqCap`.
    function _mockPq(address v, uint64 pqCap) internal pure returns (UARegistry.KindConfig[] memory c) {
        uint16[6] memory ks = [uint16(0x0101), 0x0130, 0x0131, 0x0132, 0x0133, 0x0142];
        c = new UARegistry.KindConfig[](6);
        for (uint256 i; i < 6; ++i) c[i] = UARegistry.KindConfig(ks[i], v, i == 0 ? 400_000 : pqCap);
    }

    function _pk(uint16 kind, uint256 salt) internal pure returns (bytes memory pk) {
        uint256 len = kind == 0x0130 ? 1312 : kind == 0x0131 ? 1952 : kind == 0x0132 ? 897 : kind == 0x0133 ? 32 : 16384;
        pk = new bytes(len);
        for (uint256 i; i < len; i += 32) {
            bytes32 w = keccak256(abi.encode(kind, salt, i));
            for (uint256 j; j < 32 && i + j < len; ++j) pk[i + j] = w[j];
        }
        if (kind == 0x0132) {
            pk[0] = 0x09;
            for (uint256 i = 1; i < len; ++i) pk[i] = 0; // every h_i = 0 < q
        }
    }

    /// Slots: every PQ kind and `pqz-mlwe` configurable, with its cap; the neighbours are not in the table.
    function test_pqSlots() public {
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _mockPq(address(mock), 1_000_000));
        uint16[5] memory on = [uint16(0x0130), 0x0131, 0x0132, 0x0133, 0x0142];
        for (uint256 i; i < 5; ++i) {
            assertTrue(r.kindEnabled(on[i]));
            assertEq(r.verifyCap(on[i]), 1_000_000);
        }
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        uint16[4] memory refused = [uint16(0x012f), 0x0134, 0x0143, 0x0150];
        for (uint256 i; i < 4; ++i) {
            c[0] = UARegistry.KindConfig(refused[i], address(mock), 50_000);
            vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, refused[i]));
            new UARegistry(chainUidA, address(0), false, BUDGET, address(0), true, c);
        }
    }

    /// CTR-UA-17: PQ keys are stored (`keyPtr` = SSTORE2(pk), `keyOf`); `auth` carries the signature only.
    function test_pqStored() public {
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _mockPq(address(mock), 1_000_000));
        uint16[4] memory ks = [uint16(0x0130), 0x0131, 0x0132, 0x0133];
        for (uint256 i; i < 4; ++i) {
            bytes memory pk = _pk(ks[i], 1);
            bytes32 ua = _register(r, ks[i], pk);
            (IUARegistry.Record memory rec,) = r.recordOf(ua);
            assertEq(rec.kind, ks[i]);
            assertEq(rec.keyPtr.code, bytes.concat(hex"00", pk), "SSTORE2(pk)");
            assertEq(r.keyOf(ua), pk);
            bytes memory sig = _sig(pk, r.uaMessage(ks[i], UAKinds.PURPOSE_METATX, DIGEST));
            r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, abi.encode(bytes(""), sig));
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
            r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, abi.encode(pk, sig)); // key data in auth: refused
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, ks[i]));
            r.register(ks[i], bytes.concat(pk, hex"00"), "", 0, "");
        }
    }

    /// The cache's refusals: other kinds, a disabled kind, a part past the last, a verifier with a precompile; a wrong
    /// key length.
    function test_cacheRefusals() public {
        UARegistry.KindConfig[] memory c = _realPq();
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, c);
        bytes memory pk44 = _pk(0x0130, 1);
        uint16[3] memory others = [uint16(0x0132), 0x0133, 0x0101];
        for (uint256 i; i < 3; ++i) {
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyCache.selector, others[i]));
            r.cacheExpandedKey(others[i], pk44, 0);
        }
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyCache.selector, uint16(0x0130)));
        r.cacheExpandedKey(0x0130, pk44, 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyCache.selector, uint16(0x0131)));
        r.cacheExpandedKey(0x0131, _pk(0x0131, 1), 2);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, uint16(0x0130)));
        r.cacheExpandedKey(0x0130, _pk(0x0131, 1), 0);
        // a registry without ML-DSA
        UARegistry none = _deploy(address(0x5ca3), chainUidA, address(0), false, BUDGET, address(0), true, _cfgs(address(mock)));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyCache.selector, uint16(0x0130)));
        none.cacheExpandedKey(0x0130, pk44, 0);
    }

    /// Where the ML-DSA verifier answers through a probed precompile the cache is refused: a cached Solidity path
    /// would exceed the precompile's cap and lock the UA.
    function test_cacheRefusedWithPrecompile() public {
        UARegistry.KindConfig[] memory c = _realPq();
        PrecompileStub stub = new PrecompileStub();
        string memory kat = vm.readFile("../vectors/ua/pq_kat.json");
        bytes memory valid = vm.parseJsonBytes(kat, ".kinds.mldsa44.eip8355_probe_valid");
        stub.set(keccak256(valid));
        c[1].verifier = address(
            new UAMldsaVerifier(0x0130, address(stub), valid, vm.parseJsonBytes(kat, ".kinds.mldsa44.eip8355_probe_invalid"))
        );
        assertEq(UAMldsaVerifier(c[1].verifier).PRECOMPILE(), address(stub));
        c[1].cap = 50_000;
        UARegistry pre = _deploy(address(0x5ca4), chainUidA, address(0), false, BUDGET, address(0), true, c);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyCache.selector, uint16(0x0130)));
        pre.cacheExpandedKey(0x0130, _pk(0x0130, 1), 0);
    }

    // ----- the vectors (real verifiers, context A) -----

    function _row(uint256 i, string memory f) internal pure returns (string memory) {
        return string.concat(".kinds[", vm.toString(i), "].", f);
    }

    /// Stores every part of an ML-DSA key's expanded key, one call each (logged); every part fits one EIP-7825
    /// transaction with its calldata at the EIP-7623 floor.
    function _cache(UARegistry r, uint16 kind, bytes memory pk, string memory name) internal {
        bytes32 ua = r.uaOf(kind, pk);
        for (uint256 p; p < (kind == 0x0130 ? 1 : 2); ++p) {
            uint256 g = gasleft();
            vm.expectEmit(true, true, false, false, address(r));
            emit IUARegistry.UAKeyCached(ua, kind, p, address(0));
            assertEq(r.cacheExpandedKey(kind, pk, p), ua);
            g -= gasleft();
            emit log_named_uint(string.concat("cacheExpandedKey ", name, " part ", vm.toString(p)), g);
            assertLt(g + 21_000 + 40 * (pk.length + 100), TX_CAP, "one Osaka transaction");
            assertTrue(r.expandedKeyOf(ua)[p] != address(0));
        }
        // a second call stores nothing new (front-running gives the same bytes)
        address first = r.expandedKeyOf(ua)[0];
        r.cacheExpandedKey(kind, pk, 0);
        assertEq(r.expandedKeyOf(ua)[0], first);
    }

    /// T-REG-1/2, T-AUTH-1 on pq_signatures.json: PoPs for another chain uid / registry refused; ML-DSA refused
    /// before its cache is complete (the FIPS 204 key exceeds the cap), registered after; every signature passes with
    /// an empty `keyData`; every verify-side negative is `UAUnauthorized`.
    function test_vectors_pq() public {
        string memory pj = _pj();
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _realPq());
        uint256 rows;
        uint256 sigs;
        uint256 negs;
        for (uint256 i; vm.keyExistsJson(pj, string.concat(".kinds[", vm.toString(i), "]")); ++i) {
            bytes32 ua = _pqRegister(r, pj, i);
            sigs += _pqSigs(r, pj, i, ua);
            negs += _pqNegatives(r, pj, i, ua);
            ++rows;
        }
        assertEq(rows, 4, "PQ kinds");
        assertEq(sigs, 8, "PQ sigs");
        assertEq(negs, 27, "PQ negatives");
    }

    /// PoP-side refusals, the ML-DSA cache (refused before it is complete), then `register` (logged).
    function _pqRegister(UARegistry r, string memory pj, uint256 i) internal returns (bytes32 ua) {
        uint16 kind = uint16(vm.parseJsonUint(pj, _row(i, "kind")));
        string memory name = vm.parseJsonString(pj, _row(i, "name"));
        bytes memory pk = vm.parseJsonBytes(pj, _row(i, "keyData"));
        ua = vm.parseJsonBytes32(pj, _row(i, "ua"));
        assertEq(r.popDigest(ua, 0), vm.parseJsonBytes32(pj, _row(i, "pop.popDigest")));
        bytes memory pop = vm.parseJsonBytes(pj, _row(i, "pop.sig"));
        if (kind == 0x0130 || kind == 0x0131) {
            _popRefused(r, kind, pk, pop); // no cache yet: the FIPS 204 key exceeds the cap
            _cache(r, kind, pk, name);
        }
        _popRefused(r, kind, pk, vm.parseJsonBytes(pj, _row(i, "popOther.sig")));
        for (uint256 n; vm.keyExistsJson(pj, _row(i, string.concat("negatives[", vm.toString(n), "]"))); ++n) {
            string memory ng = _row(i, string.concat("negatives[", vm.toString(n), "]."));
            if (vm.parseJsonBool(pj, string.concat(ng, "verifyPop"))) {
                _popRefused(r, kind, pk, vm.parseJsonBytes(pj, string.concat(ng, "sig")));
            }
        }
        uint256 g = gasleft();
        assertEq(r.register(kind, pk, pop, 0, ""), ua);
        g -= gasleft();
        emit log_named_uint(string.concat("register ", name), g);
        assertEq(r.keyOf(ua), pk);
    }

    /// The `metatx` and `member` signatures pass with an empty `keyData` (logged).
    function _pqSigs(UARegistry r, string memory pj, uint256 i, bytes32 ua) internal view returns (uint256 n) {
        bytes32 digest = vm.parseJsonBytes32(pj, ".digest");
        for (; n < 2; ++n) {
            string memory sr = _row(i, string.concat("sigs[", vm.toString(n), "]."));
            bytes32 p = keccak256(bytes(string.concat("scaas.ua.purpose.", vm.parseJsonString(pj, string.concat(sr, "purpose")), ".v1")));
            bytes memory auth = abi.encode(bytes(""), vm.parseJsonBytes(pj, string.concat(sr, "sig")));
            uint256 g = gasleft();
            r.requireAuthorized(ua, p, digest, auth);
            g -= gasleft();
            if (n == 0) console2.log(string.concat("requireAuthorized ", vm.parseJsonString(pj, _row(i, "name"))), g);
        }
    }

    /// Every verify-side negative: `UAUnauthorized` for exactly the message the row names.
    function _pqNegatives(UARegistry r, string memory pj, uint256 i, bytes32 ua) internal returns (uint256 n) {
        bytes32 digest = vm.parseJsonBytes32(pj, ".digest");
        uint16 kind = uint16(vm.parseJsonUint(pj, _row(i, "kind")));
        for (; vm.keyExistsJson(pj, _row(i, string.concat("negatives[", vm.toString(n), "]"))); ++n) {
            string memory ng = _row(i, string.concat("negatives[", vm.toString(n), "]."));
            if (vm.parseJsonBool(pj, string.concat(ng, "verifyPop"))) continue;
            bytes32 m = vm.parseJsonBytes32(pj, string.concat(ng, "message"));
            bytes32 p = m == UAKinds.uaMessage(kind, UAKinds.PURPOSE_MEMBER, digest)
                ? UAKinds.PURPOSE_MEMBER
                : UAKinds.PURPOSE_METATX;
            assertEq(m, UAKinds.uaMessage(kind, p, digest), "a message the registry asks");
            bytes memory auth = abi.encode(bytes(""), vm.parseJsonBytes(pj, string.concat(ng, "sig")));
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
            r.requireAuthorized(ua, p, digest, auth);
        }
    }

    function _popRefused(UARegistry r, uint16 kind, bytes memory pk, bytes memory sig) internal {
        vm.expectRevert(IUARegistry.UAPoP.selector);
        r.register(kind, pk, sig, 0, "");
    }

    /// Registers the three `mldsa65` keys (cache + PoP) and signatures.json's `p256` key on `r`.
    function _members(UARegistry r, string memory pj) internal {
        bytes memory pk = vm.parseJsonBytes(pj, _row(1, "keyData"));
        _cache(r, 0x0131, pk, "mldsa65 #0");
        r.register(0x0131, pk, vm.parseJsonBytes(pj, _row(1, "pop.sig")), 0, "");
        for (uint256 i; i < 2; ++i) {
            string memory x = string.concat(".extraKeys[", vm.toString(i), "].");
            bytes memory k = vm.parseJsonBytes(pj, string.concat(x, "keyData"));
            _cache(r, 0x0131, k, string.concat("mldsa65 #", vm.toString(i + 1)));
            r.register(0x0131, k, vm.parseJsonBytes(pj, string.concat(x, "pop.sig")), 0, "");
        }
        string memory sj = vm.readFile("../vectors/ua/signatures.json");
        assertEq(vm.parseJsonString(sj, ".derived[1].name"), "p256");
        r.register(0x0101, vm.parseJsonBytes(sj, ".derived[1].keyData"), vm.parseJsonBytes(sj, ".derived[1].pop.sig"), 0, "");
    }

    /// T-GAS (accounts.md §1.16): on a precompile-less registry the hybrid {mldsa65, p256} t=2 registers and
    /// authorizes within `verifyBudget`; the treasury {mldsa65 ×3} t=2 is refused (2 × 5.95 M + the hold > 12 M).
    function test_T_GAS_pqHybrid() public {
        string memory pj = _pj();
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _realPq());
        _members(r, pj);
        bytes32 hua = r.register(UAKinds.MSIG, vm.parseJsonBytes(pj, ".msig.hybrid.keyData"), "", 0, "");
        assertEq(hua, vm.parseJsonBytes32(pj, ".msig.hybrid.ua"));
        _sets(r, pj, ".msig.hybrid", hua, 1);
        bytes memory tk = vm.parseJsonBytes(pj, ".msig.treasury.keyData");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        r.register(UAKinds.MSIG, tk, "", 0, "");
    }

    /// T-GAS: at the largest `mldsa65` cap the bound admits for the treasury (5,921,000), it registers, and both of
    /// its signing sets authorize within `verifyBudget` with the real verifiers on the cached keys.
    function test_T_GAS_pqTreasury() public {
        string memory pj = _pj();
        UARegistry.KindConfig[] memory c = _realPq();
        c[2].cap = 5_921_000;
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, c);
        _members(r, pj);
        bytes32 tua = r.register(UAKinds.MSIG, vm.parseJsonBytes(pj, ".msig.treasury.keyData"), "", 0, "");
        assertEq(tua, vm.parseJsonBytes32(pj, ".msig.treasury.ua"));
        _sets(r, pj, ".msig.treasury", tua, 2);
    }

    /// Each valid set authorizes with exactly `verifyBudget` gas; the below-threshold set fails.
    function _sets(UARegistry r, string memory pj, string memory m, bytes32 ua, uint256 valid) internal {
        bytes32 digest = vm.parseJsonBytes32(pj, ".digest");
        uint256 n;
        for (uint256 s; vm.keyExistsJson(pj, string.concat(m, ".sets[", vm.toString(s), "]")); ++s) {
            string memory sr = string.concat(m, ".sets[", vm.toString(s), "].");
            bytes memory auth = vm.parseJsonBytes(pj, string.concat(sr, "auth"));
            if (vm.parseJsonBool(pj, string.concat(sr, "valid"))) {
                uint256 g = gasleft();
                r.requireAuthorized{gas: BUDGET}(ua, UAKinds.PURPOSE_METATX, digest, auth);
                g -= gasleft();
                emit log_named_uint(string.concat("requireAuthorized ", m, " ", vm.parseJsonString(pj, string.concat(sr, "name"))), g);
                ++n;
            } else {
                vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
                r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, digest, auth);
            }
        }
        assertEq(n, valid);
    }

    /// The msig bound with PQ caps (register step 4, P6c): members burning their whole cap authorize within
    /// `verifyBudget` at the largest cap the bound admits; one more thousand gas of cap and the structure is refused.
    function test_T_GAS_msigPqHold() public {
        MockVerifier burner = new MockVerifier(0, 5_911_000);
        (UARegistry r, bytes memory d) = _burnMembers(REG_A, address(burner), 5_921_000);
        bytes32 ua = r.register(UAKinds.MSIG, d, "", 0, "");
        r.requireAuthorized{gas: BUDGET}(ua, UAKinds.PURPOSE_METATX, DIGEST, _burnAuth(r, d, ua));
        (UARegistry r2,) = _burnMembers(address(0x5ca6), address(burner), 5_922_000);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        r2.register(UAKinds.MSIG, d, "", 0, "");
    }

    /// Three `mldsa65` UAs on mock verifiers with cap `cap` at `where`, and the treasury {×3, w1} t=2 over them.
    function _burnMembers(address where, address burner, uint64 cap) internal returns (UARegistry r, bytes memory d) {
        r = _deploy(where, chainUidA, address(0), false, BUDGET, address(0), true, _mockPq(burner, cap));
        Member[] memory m = new Member[](3);
        for (uint256 i; i < 3; ++i) m[i] = Member(0x0131, _register(r, 0x0131, _pk(0x0131, i)), 1);
        d = _msigKey(2, m);
    }

    /// Members 0 and 1 sign (mock signatures, stored kind: no key data).
    function _burnAuth(UARegistry r, bytes memory d, bytes32 ua) internal pure returns (bytes memory) {
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        UARegistry.MemberSig[] memory sigs = new UARegistry.MemberSig[](2);
        for (uint256 i; i < 2; ++i) {
            bytes memory pk = _pk(0x0131, _saltOf(r, d, i));
            sigs[i] = UARegistry.MemberSig(uint16(i), "", _sig(pk, r.uaMessage(0x0131, UAKinds.PURPOSE_MEMBER, md)));
        }
        return abi.encode(d, abi.encode(sigs));
    }

    /// The salt of the `_pk(0x0131, salt)` key that sits at member index `i` of `d` (members are sorted by id).
    function _saltOf(UARegistry r, bytes memory d, uint256 i) internal pure returns (uint256) {
        for (uint256 s; s < 3; ++s) if (_indexOf(d, r.uaOf(0x0131, _pk(0x0131, s))) == i) return s;
        revert("member");
    }

    // ----- fix round 1: gen 2 hand-off (C6-8, CTR-UA-23) -----

    /// A gen-2 `msig` {native SmartKeyAccount clone, `mldsa65` handed to gen 1} t=2, every capped call burning its whole
    /// cap, a real-size (3,309 B) signature: registered at exactly its bound (one gas less is refused), it authorizes
    /// with exactly the bound as the `requireAuthorized` frame's gas (gen 2 holds for the handed member too).
    function test_T_GAS_pqHandedAtBudget() public {
        (UARegistry home, address impl, bytes32 mlId) = _handedHome();
        address a = address(0x5d10);
        vm.etch(a, abi.encodePacked(hex"363d3d373d3d3d363d73", impl, hex"5af43d82803e903d91602b57fd5bf3"));
        Member[] memory m = new Member[](2);
        m[0] = Member(0x0131, mlId, 1);
        m[1] = Member(UAKinds.EVM_EOA, _pad(a), 1);
        bytes memory d = _msigKey(2, m);
        uint256 held = CAP_MLDSA65 + CAP_MLDSA65 / 63 + 5_000; // gen 1's hold inside gen 2's 63/64
        uint256 bound = 435_000 + 35_000 + held + (held - 400_000) / 63;
        UARegistry.KindConfig[] memory none = new UARegistry.KindConfig[](0);
        UARegistry tight = _deploy(address(0x5d20), chainUidA, address(home), false, uint64(bound - 1), impl, true, none);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        tight.register(UAKinds.MSIG, d, "", 0, "");
        UARegistry r = _deploy(address(0x5d21), chainUidA, address(home), false, uint64(bound), impl, true, none);
        bytes32 ua = r.register(UAKinds.MSIG, d, "", 0, "");
        uint256 least = _handedLeast(r, d, ua, mlId, bound);
        emit log_named_uint("gen-2 handed mldsa65 bound", bound);
        emit log_named_uint("  least requireAuthorized frame gas", least);
    }

    function _handedHome() internal returns (UARegistry home, address impl, bytes32 mlId) {
        impl = address(new BurnAll());
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(0x0131, address(new BurnAll()), CAP_MLDSA65);
        home = _deploy(address(0x5d00), chainUidA, address(0), false, BUDGET, impl, true, c);
        mlId = home.register(0x0131, _pk(0x0131, 1), "", 0, "");
    }

    /// Asserts `requireAuthorized` succeeds with `bound` gas (3,309 B ML-DSA-65 signature); returns the least frame gas.
    function _handedLeast(UARegistry r, bytes memory d, bytes32 ua, bytes32 mlId, uint256 bound)
        internal
        returns (uint256 hi)
    {
        UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](2);
        for (uint16 i; i < 2; ++i) s[i] = UARegistry.MemberSig(i, "", new bytes(i == _indexOf(d, mlId) ? 3309 : 65));
        bytes memory call = abi.encodeCall(r.requireAuthorized, (ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s)));
        GasProbe p = new GasProbe();
        assertTrue(p.probe(address(r), call, bound), "authorizes with its bound");
        uint256 lo;
        for (hi = bound; hi - lo > 1;) {
            uint256 mid = (lo + hi) / 2;
            if (p.probe(address(r), call, mid)) hi = mid;
            else lo = mid;
        }
    }

    /// Half of an `mldsa65` expanded key (part 0 of 2) does not satisfy the registry: the PoP is refused.
    function test_halfCacheRefusesPop() public {
        string memory pj = _pj();
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _realPq());
        bytes memory pk = vm.parseJsonBytes(pj, _row(1, "keyData"));
        r.cacheExpandedKey(0x0131, pk, 0);
        _popRefused(r, 0x0131, pk, vm.parseJsonBytes(pj, _row(1, "pop.sig")));
    }

    /// Gen 2 hands PQ records to gen 1: it authorizes with gen 1's cache; it has no cache of its own.
    function test_gen2PqHandoff() public {
        string memory pj = _pj();
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _realPq());
        UARegistry.KindConfig[] memory none = new UARegistry.KindConfig[](0);
        UARegistry g2 = _deploy(address(0x5d30), chainUidA, address(r), false, BUDGET, address(0), true, none);
        bytes memory pk = vm.parseJsonBytes(pj, _row(0, "keyData"));
        assertEq(uint16(vm.parseJsonUint(pj, _row(0, "kind"))), 0x0130);
        _cache(r, 0x0130, pk, "mldsa44");
        bytes32 ua = r.register(0x0130, pk, vm.parseJsonBytes(pj, _row(0, "pop.sig")), 0, "");
        _pqSigs(g2, pj, 0, ua);
        address[2] memory z = g2.expandedKeyOf(ua);
        assertEq(z[0], address(0));
        assertEq(z[1], address(0));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyCache.selector, uint16(0x0130)));
        g2.cacheExpandedKey(0x0130, pk, 0);
    }

    // ----- pqz-mlwe (CTR-PQZ-12/13; its verifier is P6g's: mocks here) -----

    function _pqzPop(UARegistry r, bytes memory pk, bytes32 authRef) internal view returns (bytes memory) {
        bytes32 ua = r.uaOf(0x0142, pk);
        return _sig(pk, r.uaMessage(0x0142, UAKinds.PURPOSE_POP, r.popDigest(ua, authRef)));
    }

    UARegistry internal zr;
    bytes internal zpk;
    bytes32 internal zua;
    bytes internal p256Key;
    bytes32 internal p256Ua;
    bytes internal mlKey;
    bytes32 internal mlUa;

    /// A registry with mock verifiers, a `pqz-mlwe` key and its id, a registered `p256` and `mldsa65` UA.
    function _pqzSetup() internal {
        zr = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _mockPq(address(mock), 1_000_000));
        zpk = _pk(0x0142, 1);
        zua = zr.uaOf(0x0142, zpk);
        p256Key = _key(0x0101);
        p256Ua = _register(zr, 0x0101, p256Key);
        mlKey = _pk(0x0131, 1);
        mlUa = _register(zr, 0x0131, mlKey);
    }

    /// An `msig` over the `mldsa65` (weight `wm`) and `p256` (weight `wp`) UAs with `threshold`, registered.
    function _pqzMsig(uint16 threshold, uint16 wm, uint16 wp) internal returns (bytes memory d, bytes32 ua) {
        Member[] memory m = new Member[](2);
        m[0] = Member(0x0131, mlUa, wm);
        m[1] = Member(0x0101, p256Ua, wp);
        d = _msigKey(threshold, m);
        ua = zr.register(UAKinds.MSIG, d, "", 0, "");
    }

    /// CTR-PQZ-12 refusals (`UAAuthRef`, before any signature is checked): self, a native id, a classical UA, an
    /// unregistered id, an `msig` whose classical members alone reach the threshold, an `msig` named with another
    /// structure's key data.
    function test_pqzAuthRef_refused() public {
        _pqzSetup();
        bytes32[4] memory bad = [bytes32(0), _pad(address(0xbeef)), p256Ua, keccak256("unregistered")];
        for (uint256 i; i < 4; ++i) {
            bytes memory pop = _pqzPop(zr, zpk, bad[i]);
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAAuthRef.selector, bad[i]));
            zr.register(0x0142, zpk, pop, bad[i], i == 0 ? bytes("") : bytes(hex"00"));
        }
        (bytes memory weak, bytes32 weakUa) = _pqzMsig(1, 1, 1); // p256 alone reaches t = 1
        (bytes memory heavy, bytes32 heavyUa) = _pqzMsig(2, 1, 2); // p256 alone reaches t = 2
        (, bytes32 hybridUa) = _pqzMsig(2, 1, 1);
        _pqzRefused(weakUa, abi.encode(weak, bytes("")));
        _pqzRefused(heavyUa, abi.encode(heavy, bytes("")));
        _pqzRefused(hybridUa, abi.encode(weak, bytes(""))); // the hybrid's id with the weak structure's key data
    }

    function _pqzRefused(bytes32 authRef, bytes memory authPop) internal {
        bytes memory pop = _pqzPop(zr, zpk, authRef);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAAuthRef.selector, authRef));
        zr.register(0x0142, zpk, pop, authRef, authPop);
    }

    /// The hybrid {mldsa65 w1, p256 w1} t=2 is accepted: both members co-sign the PoP digest (purpose `authref`).
    function test_pqzAuthRef_hybrid() public {
        _pqzSetup();
        (bytes memory hybrid, bytes32 hybridUa) = _pqzMsig(2, 1, 1);
        bytes32 md = UAKinds.memberDigest(
            hybridUa, zr.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_AUTHREF, zr.popDigest(zua, hybridUa))
        );
        UARegistry.MemberSig[] memory sigs = new UARegistry.MemberSig[](2);
        uint16 mi = _indexOf(hybrid, mlUa);
        uint16 pi = _indexOf(hybrid, p256Ua);
        sigs[mi < pi ? 0 : 1] = UARegistry.MemberSig(mi, "", _sig(mlKey, zr.uaMessage(0x0131, UAKinds.PURPOSE_MEMBER, md)));
        sigs[mi < pi ? 1 : 0] =
            UARegistry.MemberSig(pi, p256Key, _sig(p256Key, zr.uaMessage(0x0101, UAKinds.PURPOSE_MEMBER, md)));
        bytes memory pop = _pqzPop(zr, zpk, hybridUa);
        assertEq(zr.register(0x0142, zpk, pop, hybridUa, abi.encode(hybrid, abi.encode(sigs))), zua);
        (, bytes32 ar) = zr.recordOf(zua);
        assertEq(ar, hybridUa);
    }

    /// A single PQ signing UA (`slhdsa128s` too) is accepted; the key is stored (16,384 B); the authority spends
    /// (`zkCovered`, purpose `zether-auth`); an owner op needs `zether-owner`; the PQZ key itself never signs.
    function test_pqzAuthRef_pq() public {
        _pqzSetup();
        bytes memory slhKey = _pk(0x0133, 1);
        bytes32 slhUa = _register(zr, 0x0133, slhKey);
        uint256 snap = vm.snapshotState();
        bytes memory authPop =
            abi.encode(bytes(""), _sig(slhKey, zr.uaMessage(0x0133, UAKinds.PURPOSE_AUTHREF, zr.popDigest(zua, slhUa))));
        assertEq(zr.register(0x0142, zpk, _pqzPop(zr, zpk, slhUa), slhUa, authPop), zua);
        vm.revertToState(snap);
        authPop = abi.encode(bytes(""), _sig(mlKey, zr.uaMessage(0x0131, UAKinds.PURPOSE_AUTHREF, zr.popDigest(zua, mlUa))));
        bytes memory pop = _pqzPop(zr, zpk, mlUa);
        uint256 g = gasleft();
        zr.register(0x0142, zpk, pop, mlUa, authPop);
        emit log_named_uint("register pqz-mlwe (16 KB key, mock R_REG, mock co-sign)", g - gasleft());
        (IUARegistry.Record memory rec, bytes32 ar) = zr.recordOf(zua);
        assertEq(ar, mlUa);
        assertEq(rec.kind, UAKinds.PQZ_MLWE);
        assertEq(zr.keyOf(zua), zpk);
        bytes memory auth = abi.encode(bytes(""), _sig(mlKey, zr.uaMessage(0x0131, UAKinds.PURPOSE_ZETHER_AUTH, DIGEST)));
        zr.requireZetherAuthorized(zua, DIGEST, auth, true);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, zua));
        zr.requireZetherAuthorized(zua, DIGEST, auth, false);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, zua));
        zr.requireAuthorized(zua, UAKinds.PURPOSE_METATX, DIGEST, abi.encode(bytes(""), _sig(zpk, DIGEST)));
    }
}

/// A precompile stand-in for the probe: the word 1 for the one input whose hash is set, else the word 0.
contract PrecompileStub {
    bytes32 public good;

    function set(bytes32 h) external {
        good = h;
    }

    fallback(bytes calldata input) external returns (bytes memory) {
        return abi.encode(keccak256(input) == good ? uint256(1) : uint256(0));
    }
}
