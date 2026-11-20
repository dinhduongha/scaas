// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {SSTORE2} from "../../src/common/SSTORE2.sol";
import {BlsMultiBls12381Verifier} from "../../src/ua/verifiers/BlsMultiBls12381Verifier.sol";
import {BlsMultiKit} from "./BlsMultiKit.sol";
import {UARegistryRegLib} from "../../src/ua/UARegistryRegLib.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";

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
        return _registry(uid, v, CAP);
    }

    function _registry(bytes32 uid, address v, uint64 cap) internal returns (UARegistry) {
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](v == address(0) ? 0 : 1);
        if (v != address(0)) k[0] = UARegistry.KindConfig(K, v, cap);
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

    // ----- the stored paths take the minimal form (spec §5.3 dispatch, N1; plan Task 8) -----

    /// `requirePortable` / `requirePortableApp`, signer `0x0121` (n = 3, unit weights, t = 2): a minimal set (2 signers) passes, a
    /// surplus set (all 3, which the hot path accepts) is refused; the purposes do not cross (a KEM signature is not an app one).
    function test_portable_minimalOnly() public {
        BlsMultiKit.Group memory g = _kit(3, 2, 19);
        reg.register(K, g.d, _none(), BlsMultiKit.pop(g, BlsMultiKit.popMsg(g.ua)), "");
        bytes32 app = UAKinds.appPurpose(bytes32("app"));
        _portable(g, UAKinds.PURPOSE_KEM, 3, true);
        _portable(g, app, 6, true);
        bytes32 op = keccak256("op");
        reg.requireAuthorized( // the hot path: a surplus set is accepted there
            g.ua,
            UAKinds.PURPOSE_METATX,
            op,
            _sig(BlsMultiKit.sign(g, 7, UAKinds.uaMessage(K, UAKinds.PURPOSE_METATX, op)))
        );
        _portable(g, UAKinds.PURPOSE_KEM, 7, false);
        _portable(g, app, 7, false);
        // test_appPurposes_doNotCross: a KEM signature is no app signature, nor one app's another's
        bytes memory kem2 = BlsMultiKit.sign(g, 3, UAKinds.uaMessage(K, UAKinds.PURPOSE_KEM, DIGEST));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, g.ua));
        reg.requirePortableApp(g.ua, bytes32("app"), DIGEST, _sig(kem2));
        bytes memory app2 = BlsMultiKit.sign(g, 3, UAKinds.uaMessage(K, app, DIGEST));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, g.ua));
        reg.requirePortableApp(g.ua, bytes32("other"), DIGEST, _sig(app2));
    }

    bytes32 internal constant DIGEST = keccak256("kem record");

    /// `requirePortable` (KEM) or `requirePortableApp` ("app") of `g` signed by `signers` over `DIGEST`: passes iff `ok`.
    function _portable(BlsMultiKit.Group memory g, bytes32 purpose, uint256 signers, bool ok) internal {
        bytes memory s = BlsMultiKit.sign(g, signers, UAKinds.uaMessage(K, purpose, DIGEST));
        if (!ok) vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, g.ua));
        if (purpose == UAKinds.PURPOSE_KEM) reg.requirePortable(g.ua, purpose, DIGEST, _sig(s));
        else reg.requirePortableApp(g.ua, bytes32("app"), DIGEST, _sig(s));
    }

    /// Review Focus 1 and spec §5.3's weighted rows: weights {3, 1, 1}, t = 3 (after sorting by key, found by weight): the
    /// weight-3 member alone is minimal; with one more it is a surplus (W − min = 3 ≥ t); the two weight-1 members do not reach t.
    function test_weighted_311_rows() public {
        uint256[] memory sks = new uint256[](3);
        uint16[] memory w = new uint16[](3);
        (sks[0], sks[1], sks[2]) = (101, 102, 103);
        (w[0], w[1], w[2]) = (3, 1, 1);
        BlsMultiKit.Group memory g = BlsMultiKit.group(sks, w, 3);
        reg.register(K, g.d, _none(), BlsMultiKit.pop(g, BlsMultiKit.popMsg(g.ua)), "");
        uint256 heavy = g.sk[0] == 101 ? 0 : g.sk[1] == 101 ? 1 : 2;
        uint256 light = 7 ^ (1 << heavy); // the two weight-1 members
        _portable(g, UAKinds.PURPOSE_KEM, 1 << heavy, true);
        _portable(g, UAKinds.PURPOSE_KEM, (1 << heavy) | (light & (light - 1)), false);
        _portable(g, UAKinds.PURPOSE_KEM, light, false);
    }

    /// N1: a valid t-of-n signature over `popMsg` under `DST_MULTI_SIG` is no registration PoP (`UAPoP`): `pop` v2 goes to
    /// `verifyPop` (all n, `DST_MULTI_POP`) only.
    function test_register_popUnderMultiSig_UAPoP() public {
        BlsMultiKit.Group memory g = _kit(3, 2, 23);
        bytes32 pm = BlsMultiKit.popMsg(g.ua);
        (bytes memory sigAll, bytes memory pop) = (BlsMultiKit.sign(g, 7, pm), BlsMultiKit.pop(g, pm));
        vm.expectRevert(IUARegistry.UAPoP.selector);
        reg.register(K, g.d, _none(), sigAll, "");
        reg.register(K, g.d, _none(), pop, ""); // positive control
    }

    /// N1: every member's distinct-message aggregate under `DST_MULTI_POP` over an app or KEM message (a "PoP" of that message) is
    /// refused on a stored path (`verifyMinimal`, never `verifyPop`), on a registry whose 0x0121 cap admits `verifyPop` (a deployer may
    /// set any cap up to the budget; 330,000 would refuse it by gas).
    function test_portableApp_popAggregateUnderMultiPop_UAUnauthorized() public {
        reg = _registry(UID, address(verifier), 11_000_000);
        BlsMultiKit.Group memory g = _kit(3, 2, 29);
        reg.register(K, g.d, _none(), BlsMultiKit.pop(g, BlsMultiKit.popMsg(g.ua)), "");
        bytes32 digest = keccak256("kem record");
        bytes memory popLikeApp = BlsMultiKit.pop(g, UAKinds.uaMessage(K, UAKinds.appPurpose(bytes32("app")), digest));
        bytes memory popLikeKem = BlsMultiKit.pop(g, UAKinds.uaMessage(K, UAKinds.PURPOSE_KEM, digest));
        bytes memory ok = BlsMultiKit.sign(g, 3, UAKinds.uaMessage(K, UAKinds.appPurpose(bytes32("app")), digest));
        reg.requirePortableApp(g.ua, bytes32("app"), digest, _sig(ok)); // positive control
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, g.ua));
        reg.requirePortableApp(g.ua, bytes32("app"), digest, _sig(popLikeApp));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, g.ua));
        reg.requirePortable(g.ua, UAKinds.PURPOSE_KEM, digest, _sig(popLikeKem));
    }

    // ----- `0x0121` as an `msig` member on a stored path (`_memberOk`, a direct `verifyMinimal`) -----

    uint256 internal constant ALICE = 0xA11CE;

    /// A classical `msig` {0x0121 group `g` (weight 1), the EOA of ALICE (weight 1)}, threshold `t`, on `r`.
    function _msig(UARegistry r, BlsMultiKit.Group memory g, uint16 t) internal returns (bytes32 mu, uint16 gi) {
        IUARegistry.MsigStructure memory st;
        st.threshold = t;
        st.members = new IUARegistry.MsigMember[](2);
        bytes32 alice = bytes32(uint256(uint160(vm.addr(ALICE))));
        // the members in ascending id order
        (IUARegistry.MsigMember memory a, IUARegistry.MsigMember memory b) =
            (IUARegistry.MsigMember(K, g.ua, 1), IUARegistry.MsigMember(UAKinds.EVM_EOA, alice, 1));
        if (uint256(g.ua) < uint256(alice)) (st.members[0], st.members[1], gi) = (a, b, 0);
        else (st.members[0], st.members[1], gi) = (b, a, 1);
        mu = r.registerMsig(st, _none(), new IUARegistry.MemberSig[](0), "");
    }

    /// The member `g`'s slot signature over `md` (`uaMessage(0x0121, member, md)`) by `signers`.
    function _memberSig(BlsMultiKit.Group memory g, uint16 gi, bytes32 md, uint256 signers)
        internal
        view
        returns (IUARegistry.MemberSig memory s)
    {
        s.index = gi;
        s.sig = BlsMultiKit.sign(g, signers, UAKinds.uaMessage(K, UAKinds.PURPOSE_MEMBER, md));
    }

    function _one(IUARegistry.MemberSig memory m) internal pure returns (IUARegistry.UASig memory a) {
        a.members = new IUARegistry.MemberSig[](1);
        a.members[0] = m;
    }

    function _membershipMd(bytes32 mu, bytes32 member) internal pure returns (bytes32) {
        return UAKinds.memberDigest(
            mu, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_MEMBERSHIP, UAKinds.membershipDigest(mu, member))
        );
    }

    /// `acceptMembership` of a `0x0121` slot (n = 3, t = 2): a surplus set (3 signers) is refused, a minimal one accepts.
    function test_acceptMembership_minimalOnly() public {
        BlsMultiKit.Group memory g = _kit(3, 2, 31);
        reg.register(K, g.d, _none(), BlsMultiKit.pop(g, BlsMultiKit.popMsg(g.ua)), "");
        (bytes32 mu, uint16 gi) = _msig(reg, g, 1);
        bytes32 md = _membershipMd(mu, g.ua);
        (IUARegistry.MemberSig memory three, IUARegistry.MemberSig memory two) =
            (_memberSig(g, gi, md, 7), _memberSig(g, gi, md, 5));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, mu));
        reg.acceptMembership(mu, three);
        reg.acceptMembership(mu, two);
        emit log_named_uint("GAS acceptMembership 0x0121 member n3 k2", vm.lastCallGas().gasTotalUsed);
        assertTrue(reg.memberAccepted(mu, gi));
    }

    /// `requirePortableApp` of an `msig` with an accepted `0x0121` slot (threshold 1): the slot's minimal signature passes, a
    /// surplus one is refused; and without the outer member digest (signed over the app message itself) it fails.
    function test_msigPortableApp_minimalOnly() public {
        BlsMultiKit.Group memory g = _kit(3, 2, 37);
        reg.register(K, g.d, _none(), BlsMultiKit.pop(g, BlsMultiKit.popMsg(g.ua)), "");
        (bytes32 mu, uint16 gi) = _msig(reg, g, 1);
        reg.acceptMembership(mu, _memberSig(g, gi, _membershipMd(mu, g.ua), 3));
        bytes32 digest = keccak256("app record");
        bytes32 md =
            UAKinds.memberDigest(mu, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.appPurpose(bytes32("app")), digest));
        reg.requirePortableApp(mu, bytes32("app"), digest, _one(_memberSig(g, gi, md, 6)));
        IUARegistry.UASig memory surplus = _one(_memberSig(g, gi, md, 7));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, mu));
        reg.requirePortableApp(mu, bytes32("app"), digest, surplus);
        // test_missingOuterMemberDigest_fails: the slot signed over the app message itself, not under `member` over `md`
        IUARegistry.MemberSig memory bare;
        bare.index = gi;
        bare.sig = BlsMultiKit.sign(g, 6, UAKinds.uaMessage(K, UAKinds.appPurpose(bytes32("app")), digest));
        IUARegistry.UASig memory b = _one(bare);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, mu));
        reg.requirePortableApp(mu, bytes32("app"), digest, b);
    }

    /// N1 and the Fable build review B1: a generation without a `0x0121` verifier (`_cfg(0x0121)` = 0) cannot verify a stored path
    /// of a `0x0121` member (`_multi` is `false` there, never a hand-off to the predecessor's `verify`), so it refuses to list a
    /// gen-1 group in an `msig` at all (`UAMemberUnknown`, `UARegistryRegLib._slotCap`): such a slot could never sign. Since B1
    /// no `msig` on such a generation reaches that `false`. The control: the same structure and signature on gen 1 accept.
    function test_storedPath_noMultiVerifier_false() public {
        BlsMultiKit.Group memory g = _kit(3, 2, 41);
        reg.register(K, g.d, _none(), BlsMultiKit.pop(g, BlsMultiKit.popMsg(g.ua)), "");
        UARegistry gen2 =
            new UARegistry(UID, address(reg), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0));
        // Fable build review B1: a gen-2 `msig` cannot list the gen-1 group at all (its slot could never sign there)
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAMemberUnknown.selector, g.ua));
        this.msigOn(gen2, g);
        (bytes32 mu1, uint16 gi1) = _msig(reg, g, 1); // the control on gen 1
        reg.acceptMembership(mu1, _memberSig(g, gi1, _membershipMd(mu1, g.ua), 3));
        assertTrue(reg.memberAccepted(mu1, gi1));
    }

    /// The registration `pop` of a PQ-eligible `msig` {0x0121 group (weight 1), an `slhdsa128s` key (weight 1, an accept-all
    /// stand-in verifier)}, threshold 2: the `0x0121` slot's signature is the minimal form (`_memberOk`, `verifyMinimal`): a surplus
    /// set (3 of a 2-of-3) is `UAPoP`, a minimal one registers.
    function test_msigPop_blsMultiMember_minimalOnly() public {
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](2);
        k[0] = UARegistry.KindConfig(K, address(verifier), CAP);
        k[1] = UARegistry.KindConfig(0x0133, address(new AcceptAllPq()), 1_400_000);
        reg = new UARegistry(UID, address(0), false, BUDGET, address(0), true, k);
        BlsMultiKit.Group memory g = _kit(3, 2, 47);
        reg.register(K, g.d, _none(), BlsMultiKit.pop(g, BlsMultiKit.popMsg(g.ua)), "");
        bytes32 slh = reg.register(0x0133, abi.encodePacked(keccak256("slh")), _none(), hex"01", "");
        IUARegistry.MsigStructure memory st;
        st.threshold = 2;
        st.members = new IUARegistry.MsigMember[](2);
        uint16 gi = uint256(g.ua) < uint256(slh) ? 0 : 1;
        st.members[gi] = IUARegistry.MsigMember(K, g.ua, 1);
        st.members[1 - gi] = IUARegistry.MsigMember(0x0133, slh, 1);
        bytes32 md = _msigPopMd(st);
        IUARegistry.MemberSig[] memory pop = new IUARegistry.MemberSig[](2);
        pop[1 - gi].index = 1 - gi;
        pop[1 - gi].sig = hex"01";
        pop[gi] = _memberSig(g, gi, md, 7); // surplus
        vm.expectRevert(IUARegistry.UAPoP.selector);
        reg.registerMsig(st, _none(), pop, "");
        pop[gi] = _memberSig(g, gi, md, 5); // minimal
        reg.registerMsig(st, _none(), pop, "");
    }

    /// Fable build review B3: `updateMsig` of an `msig` with a `0x0121` member, the route through `UARegistryAuxLib._core` (the fourth
    /// word forwarded) to `_memberOk`: the group's slot signature is the minimal form (`verifyMinimal`): a surplus set (3 of a
    /// 2-of-3) is `UAUnauthorized`, a minimal one updates (the version moves).
    function test_updateMsig_blsMultiMember_minimalOnly() public {
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](2);
        k[0] = UARegistry.KindConfig(K, address(verifier), CAP);
        k[1] = UARegistry.KindConfig(0x0133, address(new AcceptAllPq()), 1_400_000);
        reg = new UARegistry(UID, address(0), false, BUDGET, address(0), true, k);
        BlsMultiKit.Group memory g = _kit(3, 2, 53);
        reg.register(K, g.d, _none(), BlsMultiKit.pop(g, BlsMultiKit.popMsg(g.ua)), "");
        bytes32 slh = reg.register(0x0133, abi.encodePacked(keccak256("slh-up")), _none(), hex"01", "");
        IUARegistry.MsigStructure memory st;
        st.threshold = 2;
        st.members = new IUARegistry.MsigMember[](2);
        uint16 gi = uint256(g.ua) < uint256(slh) ? 0 : 1;
        st.members[gi] = IUARegistry.MsigMember(K, g.ua, 1);
        st.members[1 - gi] = IUARegistry.MsigMember(0x0133, slh, 1);
        IUARegistry.MemberSig[] memory pop = new IUARegistry.MemberSig[](2);
        pop[1 - gi].index = 1 - gi;
        pop[1 - gi].sig = hex"01";
        pop[gi] = _memberSig(g, gi, _msigPopMd(st), 5);
        bytes32 mu = reg.registerMsig(st, _none(), pop, "");
        (uint64 v, uint256 en,) = reg.msigStateOf(mu);
        uint64 until = uint64(block.number + 100);
        bytes32 typed = UAKinds.msigUpdateDigest(mu, reg.chainUid(), address(reg), v + 1, st, en, until);
        bytes32 md = UAKinds.memberDigest(mu, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_MSIG_UPDATE, typed));
        pop[gi] = _memberSig(g, gi, md, 7); // surplus
        bytes32 cu = reg.chainUid();
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, mu));
        reg.updateMsig(mu, v + 1, st, en, until, pop, cu);
        pop[gi] = _memberSig(g, gi, md, 5); // minimal
        reg.updateMsig(mu, v + 1, st, en, until, pop, cu);
        (uint64 v2,,) = reg.msigStateOf(mu);
        assertEq(v2, v + 1);
    }

    /// Fable build review B3: `setPqzKey` (version 0, the `msig` registered without one) of a PQ-eligible `msig` with a `0x0121`
    /// member, the other route through `UARegistryAuxLib._core` (the fourth word forwarded) to `_memberOk`: the group's slot
    /// signature is the minimal form (`verifyMinimal`): a surplus set (3 of a 2-of-3) is `UAUnauthorized`, a minimal one stores the
    /// key (version 0 latest, its signature stored as `abi.encode(members)`).
    function test_setPqzKey_blsMultiMember_minimalOnly() public {
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](2);
        k[0] = UARegistry.KindConfig(K, address(verifier), CAP);
        k[1] = UARegistry.KindConfig(0x0133, address(new AcceptAllPq()), 1_400_000);
        reg = new UARegistry(UID, address(0), false, BUDGET, address(0), true, k);
        BlsMultiKit.Group memory g = _kit(3, 2, 59);
        reg.register(K, g.d, _none(), BlsMultiKit.pop(g, BlsMultiKit.popMsg(g.ua)), "");
        bytes32 slh = reg.register(0x0133, abi.encodePacked(keccak256("slh-pqz")), _none(), hex"01", "");
        IUARegistry.MsigStructure memory st;
        st.threshold = 2;
        st.members = new IUARegistry.MsigMember[](2);
        uint16 gi = uint256(g.ua) < uint256(slh) ? 0 : 1;
        st.members[gi] = IUARegistry.MsigMember(K, g.ua, 1);
        st.members[1 - gi] = IUARegistry.MsigMember(0x0133, slh, 1);
        IUARegistry.UASig memory s;
        s.members = new IUARegistry.MemberSig[](2);
        s.members[1 - gi].index = 1 - gi;
        s.members[1 - gi].sig = hex"01";
        s.members[gi] = _memberSig(g, gi, _msigPopMd(st), 5);
        bytes32 mu = reg.registerMsig(st, _none(), s.members, "");
        bytes memory pqzKey = new bytes(PqzSet.PK);
        pqzKey[0] = 0x42;
        bytes32 ph = keccak256("pqz pop");
        bytes32 rd = UAKinds.pqzKeyRecordDigest(mu, UAKinds.keyHashOf(UAKinds.PQZ_MLWE, pqzKey), ph);
        bytes32 md = UAKinds.memberDigest(mu, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_PQZ_KEY, rd));
        s.members[gi] = _memberSig(g, gi, md, 7); // surplus
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, mu));
        reg.setPqzKey(mu, 0, pqzKey, ph, s);
        s.members[gi] = _memberSig(g, gi, md, 5); // minimal
        reg.setPqzKey(mu, 0, pqzKey, ph, s);
        assertEq(reg.pqzKeyLatest(mu), 0);
        assertEq(reg.pqzKeySigOf(mu, 0), abi.encode(s.members));
    }

    /// The `member` digest of an `msig`'s registration `pop` (no attributes): `memberDigest(mu, uaMessage(msig, pop v2, rd))`.
    function _msigPopMd(IUARegistry.MsigStructure memory st) internal pure returns (bytes32) {
        bytes memory d = abi.encodePacked(st.threshold, uint16(st.members.length));
        for (uint256 i; i < st.members.length; ++i) {
            d = bytes.concat(d, abi.encodePacked(st.members[i].kind, st.members[i].id, st.members[i].weight));
        }
        bytes32 mu = UAKinds.uaOf(UAKinds.MSIG, d);
        bytes32 rec = UAKinds.portableRecordHash(mu, UAKinds.MSIG, 0, UAKinds.kemRecordHash(mu, 0, bytes("")));
        bytes32 rd = UAKinds.portableDigest(UAKinds.registrationHash(rec, 0));
        return UAKinds.memberDigest(mu, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_POP_V2, rd));
    }

    /// `acceptMembership` of `g`'s slot by a minimal set, on the gen 2 `r`: `UAUnauthorized`.
    /// `_msig` as an external call, so `vm.expectRevert` meets the registration's revert.
    function msigOn(UARegistry r, BlsMultiKit.Group memory g) external returns (bytes32 mu) {
        (mu,) = _msig(r, g, 1);
    }

    /// The fourth appended word (N1): `_lib` appends `_cfg(kind)`, `_cfg(0x0142)`, the clone codehash, then `_cfg(0x0121)`, after the
    /// caller's calldata, unchanged (the library reads each at its offset from the end): a stand-in at the library's address
    /// answers the calldata it was given as its revert data, which the registry passes verbatim.
    function test_libWords_fourth_isMultiCfg() public {
        bytes memory call = abi.encodeCall(UARegistry.register, (K, hex"01", _none(), hex"02", bytes("")));
        vm.etch(address(UARegistryRegLib), address(new CalldataEcho()).code);
        (bool ok, bytes memory seen) = address(reg).call(call);
        assertFalse(ok);
        uint256 cfg = uint256(uint160(address(verifier))) | uint256(CAP) << 160;
        bytes memory args = BlsMultiKit._cut(call, 4, call.length - 4); // under the library's selector (its ABI names the structs)
        bytes memory want = bytes.concat(UARegistryRegLib.register.selector, args);
        assertEq(seen, bytes.concat(want, bytes32(cfg), bytes32(0), bytes32(0), bytes32(cfg)));
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

/// Reverts with the calldata it was given (`test_libWords_fourth_isMultiCfg`).
contract CalldataEcho {
    fallback() external {
        bytes memory d = msg.data;
        assembly ("memory-safe") {
            revert(add(d, 32), mload(d))
        }
    }
}

/// An accept-all stand-in for a PQ kind's verifier (`test_msigPop_blsMultiMember_minimalOnly`).
contract AcceptAllPq {
    function verify(bytes calldata, bytes32, bytes calldata) external pure returns (bool) {
        return true;
    }

    function verifyPop(bytes calldata, bytes32, bytes calldata) external pure returns (bool) {
        return true;
    }
}
