// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {SSTORE2} from "../../src/common/SSTORE2.sol";
import {BlsMultiBls12381Verifier} from "../../src/ua/verifiers/BlsMultiBls12381Verifier.sol";
import {BlsMultiKit} from "./BlsMultiKit.sol";

/// `bls12381-multi` (0x0121) in the registry (spec 2026-11-19-bls12381-multi §2, §4, §6, §7; plan Task 7): `registerBlsMulti` and the
/// packed `register`, the stored `ua ‖ s`, `registrationOf` / `blsMultiKeyOf` returning `d`, `keyOf` returning `apk`, no keyHash,
/// the holder rules, the hot path. Rows: smartcontracts/vectors/ua/portable.json `blsMultiRegistrations` and groups.json `blsMulti`
/// (ua-rs and clientkeys); signatures over messages the test chooses from `BlsMultiKit`. UNAUDITED.
contract UARegistryBlsMultiTest is Test {
    uint16 internal constant K = 0x0121;
    bytes32 internal constant UID = keccak256("scaas.bls-multi.registry");
    bytes32 internal constant UID2 = keccak256("scaas.bls-multi.registry.second");
    uint64 internal constant BUDGET = 12_000_000;
    uint64 internal constant CAP = 330_000;

    BlsMultiBls12381Verifier internal verifier;
    UARegistry internal reg;

    function setUp() public {
        verifier = new BlsMultiBls12381Verifier();
        reg = _registry(UID, address(verifier));
    }

    function _registry(bytes32 uid, address v) internal returns (UARegistry) {
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](v == address(0) ? 0 : 1);
        if (v != address(0)) k[0] = UARegistry.KindConfig(K, v, CAP);
        return new UARegistry(uid, address(0), false, BUDGET, address(0), true, k);
    }

    function _groupsJson() internal view returns (string memory) {
        return vm.readFile("../vectors/ua/groups.json");
    }

    function _none() internal pure returns (IUARegistry.UAAttrs memory) {}

    function _typed(bytes memory d) internal pure returns (IUARegistry.BlsMultiKey memory key) {
        uint256 n = uint16(bytes2(BlsMultiKit._cut(d, 258, 2)));
        key.aggKey = BlsMultiKit._cut(d, 0, 256);
        key.threshold = uint16(bytes2(BlsMultiKit._cut(d, 256, 2)));
        key.members = new IUARegistry.BlsMultiMember[](n);
        for (uint256 i; i < n; ++i) {
            key.members[i] = IUARegistry.BlsMultiMember(
                BlsMultiKit._cut(d, 260 + 258 * i, 256), uint16(bytes2(BlsMultiKit._cut(d, 516 + 258 * i, 2)))
            );
        }
    }

    function _group(uint256 i) internal view returns (bytes memory d, bytes32 ua, bytes memory pop) {
        string memory groups = _groupsJson();
        string memory p = string.concat(".blsMulti.groups[", vm.toString(i), "]");
        d = vm.parseJsonBytes(groups, string.concat(p, ".keyData"));
        ua = vm.parseJsonBytes32(groups, string.concat(p, ".ua"));
        pop = vm.parseJsonBytes(groups, string.concat(p, ".pop"));
    }

    function _kit(uint256 n, uint16 t, uint256 seed) internal view returns (BlsMultiKit.Group memory) {
        uint256[] memory sks = new uint256[](n);
        uint16[] memory w = new uint16[](n);
        for (uint256 i; i < n; ++i) {
            sks[i] = uint256(keccak256(abi.encode(seed, i)))
                % 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
            w[i] = 1;
        }
        return BlsMultiKit.group(sks, w, t);
    }

    function _sig(bytes memory s) internal pure returns (IUARegistry.UASig memory a) {
        a.signature = s;
    }

    // ----- registration -----

    /// portable.json `blsMultiRegistrations`: `registerBlsMulti` (typed) and `register(0x0121, d)` (packed) on two registries give
    /// the row's id and record; the row's PoP message is the kit's (the registry's own digest).
    function test_register_typedEqualsPacked() public {
        UARegistry other = _registry(UID, address(verifier));
        string memory portable = vm.readFile("../vectors/ua/portable.json");
        for (uint256 i; i < 2; ++i) {
            string memory p = string.concat(".blsMultiRegistrations[", vm.toString(i), "]");
            bytes memory d = vm.parseJsonBytes(portable, string.concat(p, ".keyData"));
            bytes32 ua = vm.parseJsonBytes32(portable, string.concat(p, ".ua"));
            bytes memory pop = vm.parseJsonBytes(portable, string.concat(p, ".pop"));
            assertEq(BlsMultiKit.popMsg(ua), vm.parseJsonBytes32(portable, string.concat(p, ".popMessage")));
            assertEq(reg.registerBlsMulti(_typed(d), _none(), pop, ""), ua);
            assertEq(other.register(K, d, _none(), pop, ""), ua);
            (IUARegistry.Record memory a,) = reg.recordOf(ua);
            (IUARegistry.Record memory b,) = other.recordOf(ua);
            assertEq(a.kind, K);
            assertEq(keccak256(SSTORE2.read(a.keyPtr)), keccak256(SSTORE2.read(b.keyPtr)));
            assertEq(SSTORE2.read(a.keyPtr), vm.parseJsonBytes(portable, string.concat(p, ".stored")));
        }
    }

    /// `registrationOf` and `blsMultiKeyOf` return `d` byte-identical from the stored `ua ‖ s`; `keyOf` returns `apk` (N2).
    function test_registrationOf_returnsD() public {
        (bytes memory d, bytes32 ua, bytes memory pop) = _group(0);
        reg.register(K, d, _none(), pop, "");
        (uint16 kind, bytes memory got,, bytes memory gotPop,) = reg.registrationOf(ua);
        assertEq(kind, K);
        assertEq(got, d);
        assertEq(gotPop, pop);
        IUARegistry.BlsMultiKey memory key = reg.blsMultiKeyOf(ua);
        assertEq(abi.encode(key), abi.encode(_typed(d)));
        assertEq(reg.blsMultiKeyOf(bytes32(uint256(1))).members.length, 0);
    }

    function test_keyOf_returnsApk() public {
        (bytes memory d, bytes32 ua, bytes memory pop) = _group(1);
        reg.register(K, d, _none(), pop, "");
        assertEq(reg.keyOf(ua), BlsMultiKit._cut(d, 0, 256));
        string memory k = vm.readFile("../vectors/ua/kinds.json");
        // kinds.json's pinned `keyOf` of the same key data, where a row has it
        for (uint256 i; vm.keyExistsJson(k, string.concat(".valid[", vm.toString(i), "]")); ++i) {
            string memory p = string.concat(".valid[", vm.toString(i), "]");
            if (vm.parseJsonUint(k, string.concat(p, ".kind")) != K) continue;
            if (keccak256(vm.parseJsonBytes(k, string.concat(p, ".keyData"))) != keccak256(d)) continue;
            assertEq(reg.keyOf(ua), vm.parseJsonBytes(k, string.concat(p, ".keyOf")));
        }
    }

    /// R2-Q1: the first 32 bytes of the stored pointer are the registered id, the rest is `s`.
    function test_storedUaIsId() public {
        (bytes memory d, bytes32 ua, bytes memory pop) = _group(2);
        reg.register(K, d, _none(), pop, "");
        (IUARegistry.Record memory r,) = reg.recordOf(ua);
        bytes memory p = SSTORE2.read(r.keyPtr);
        assertEq(bytes32(BlsMultiKit._cut(p, 0, 32)), ua);
        assertEq(p.length, 228 + 194 * 16);
    }

    /// F8: the state a registration adds per member is the 194 bytes of `s`, not the 258 of `d` (n = 2 against n = 16, EIP-8037 state gas).
    function test_storedBytesPerMember() public {
        (bytes memory d2,, bytes memory pop2) = _group(0); // n2t2
        (bytes memory d16,, bytes memory pop16) = _group(2); // n16t8
        (bytes memory d5,, bytes memory pop5) = _group(1); // n5t3 first: the kind list's count slot is new only once
        reg.register(K, d5, _none(), pop5, "");
        reg.register(K, d2, _none(), pop2, "");
        uint256 s2 = uint256(int256(vm.lastCallGas().gasStateUsed));
        reg.register(K, d16, _none(), pop16, "");
        uint256 s16 = uint256(int256(vm.lastCallGas().gasStateUsed));
        uint256 perMember = (s16 - s2) / 14;
        emit log_named_uint("state gas per member", perMember);
        assertLe(perMember, 194 * 1530 + 1530); // ε: one byte's state gas of rounding
        assertGe(perMember, 194 * 1530);
    }

    /// Classical and never PQ-eligible: a KEM key reverts `UAKemHolder`, a PQZ key `UAPqzHolder` (spec §6).
    function test_kemOrPqzAttrs_revert() public {
        (bytes memory d, bytes32 ua, bytes memory pop) = _group(0);
        IUARegistry.UAAttrs memory a;
        a.kemPkHash = keccak256("kem");
        a.kem.scheme = 1;
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemHolder.selector, ua));
        reg.register(K, d, a, pop, "");
        a = _none();
        a.pqzKey = new bytes(18_432);
        a.pqzPopHash = keccak256("proof");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, ua));
        reg.register(K, d, a, pop, "");
        reg.register(K, d, _none(), pop, ""); // positive control
    }

    /// CTR-UA-31: the same call on a registry of another chain gives the same record.
    function test_copyToSecondRegistry() public {
        UARegistry second = _registry(UID2, address(verifier));
        (bytes memory d, bytes32 ua, bytes memory pop) = _group(1);
        reg.register(K, d, _none(), pop, "");
        assertEq(second.registerBlsMulti(_typed(d), _none(), pop, ""), ua);
        (IUARegistry.Record memory a,) = reg.recordOf(ua);
        (IUARegistry.Record memory b,) = second.recordOf(ua);
        assertEq(SSTORE2.read(a.keyPtr), SSTORE2.read(b.keyPtr));
        assertEq(a.kind, b.kind);
    }

    /// F5 / Q5: no keyHash on `apk`: the same member set at two thresholds registers twice (it reverts `UAKeyInUse` if a keyHash on
    /// `apk` is put back).
    function test_twoThresholdsSameSet_bothRegister() public {
        BlsMultiKit.Group memory g3 = _kit(3, 3, 7);
        BlsMultiKit.Group memory g2 = _kit(3, 2, 7);
        assertEq(keccak256(BlsMultiKit._cut(g3.d, 0, 256)), keccak256(BlsMultiKit._cut(g2.d, 0, 256))); // same apk
        reg.register(K, g3.d, _none(), BlsMultiKit.pop(g3, BlsMultiKit.popMsg(g3.ua)), "");
        reg.register(K, g2.d, _none(), BlsMultiKit.pop(g2, BlsMultiKit.popMsg(g2.ua)), "");
        assertEq(reg.kindOf(g3.ua), K);
        assertEq(reg.kindOf(g2.ua), K);
    }

    /// CTR-UA-07: the PoP is unique (all n members, deterministic BLS), so a second submission of the same record reverts
    /// `UAAlreadyRegistered`; a PoP of another threshold over the same keys is `UAPoP`.
    function test_frontRun_identicalRecordOrRevert() public {
        BlsMultiKit.Group memory g = _kit(3, 2, 11);
        bytes memory pop = BlsMultiKit.pop(g, BlsMultiKit.popMsg(g.ua));
        reg.register(K, g.d, _none(), pop, "");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAAlreadyRegistered.selector, g.ua));
        reg.register(K, g.d, _none(), pop, "");
        BlsMultiKit.Group memory g3 = _kit(3, 3, 11);
        vm.expectRevert(IUARegistry.UAPoP.selector); // `_kit` before it: its precompile calls would take the expectation
        reg.register(K, g3.d, _none(), pop, "");
    }

    // ----- the hot path -----

    /// `requireAuthorized`: 3-of-3 (all n: the stored apk), 2-of-3, a surplus set (verify path: `W(S) ≥ t`), and a wrong digest.
    function test_authorize_threeOfThree_onHotPath() public {
        BlsMultiKit.Group memory g = _kit(3, 2, 13);
        reg.register(K, g.d, _none(), BlsMultiKit.pop(g, BlsMultiKit.popMsg(g.ua)), "");
        bytes32 digest = keccak256("op");
        bytes32 m = UAKinds.uaMessage(K, UAKinds.PURPOSE_METATX, digest);
        (bytes memory all, bytes memory two, bytes memory one) =
            (BlsMultiKit.sign(g, 7, m), BlsMultiKit.sign(g, 5, m), BlsMultiKit.sign(g, 1, m)); // before `expectRevert`
        reg.requireAuthorized(g.ua, UAKinds.PURPOSE_METATX, digest, _sig(all));
        reg.requireAuthorized(g.ua, UAKinds.PURPOSE_METATX, digest, _sig(two));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, g.ua));
        reg.requireAuthorized(g.ua, UAKinds.PURPOSE_METATX, keccak256("other"), _sig(all));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, g.ua));
        reg.requireAuthorized(g.ua, UAKinds.PURPOSE_METATX, digest, _sig(one)); // weight 1 < 2
    }

    /// R2-Q1's first condition: `vkLength(0x0121) ≠ 0`, so `auth.keyData` must be empty: `d` and `p` there are both refused (with
    /// `vkLength` 0 the registry would take `d` from `auth` and verify it).
    function test_requireAuthorized_keyDataDOrP_refused() public {
        BlsMultiKit.Group memory g = _kit(3, 2, 17);
        reg.register(K, g.d, _none(), BlsMultiKit.pop(g, BlsMultiKit.popMsg(g.ua)), "");
        (IUARegistry.Record memory r,) = reg.recordOf(g.ua);
        bytes32 digest = keccak256("op");
        bytes memory s = BlsMultiKit.sign(g, 3, UAKinds.uaMessage(K, UAKinds.PURPOSE_METATX, digest));
        reg.requireAuthorized(g.ua, UAKinds.PURPOSE_METATX, digest, _sig(s)); // positive control
        bytes[2] memory forms = [g.d, SSTORE2.read(r.keyPtr)];
        for (uint256 i; i < 2; ++i) {
            IUARegistry.UASig memory a = _sig(s);
            a.keyData = forms[i];
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, g.ua));
            reg.requireAuthorized(g.ua, UAKinds.PURPOSE_METATX, digest, a);
        }
    }

    /// A registry that does not enable 0x0121 refuses both entries `UAKindDisabled` (Hedera's profile, a chain without EIP-2537).
    function test_disabledKind_refused() public {
        UARegistry off = _registry(UID, address(0));
        (bytes memory d,, bytes memory pop) = _group(0);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, K));
        off.register(K, d, _none(), pop, "");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, K));
        off.registerBlsMulti(_typed(d), _none(), pop, "");
        assertFalse(off.kindEnabled(K));
    }
}
