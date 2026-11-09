// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UARegistryCoreLib} from "../../src/ua/UARegistryCoreLib.sol";
import {UARegistryAuxLib} from "../../src/ua/UARegistryAuxLib.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UARegistryBase} from "./UARegistryBase.sol";

/// The seven `pure` views as they were in the registry (T66b spec §5, R-1): the same ABI, `UAKinds` compiled in.
contract KindsDirect {
    function uaOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32) {
        return UAKinds.uaOf(kind, keyData);
    }

    function keyHashOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32) {
        return UAKinds.keyHashOf(kind, keyData);
    }

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
}

/// T66b task 3.1 (spec 2026-11-09-t66b-library-organisation.md §5): the registry pair rebalanced. R-1: the seven `pure` views whose
/// code `UARegistryCoreLib` holds run there (`_libPure`, nothing appended); their answers and refusals are byte-equal to the code they
/// replace (`KindsDirect`). Task 3.1b (§11 (f), owner 2026-11-09): two write libraries by domain, `UARegistryCoreLib` (registration,
/// the portable check) and `UARegistryAuxLib` (the key writes after registration, reads off the hot path), one DELEGATECALL per operation. UNAUDITED.
contract UARegistryPairTest is UARegistryBase {
    KindsDirect internal direct;

    function setUp() public override {
        super.setUp();
        direct = new KindsDirect();
    }

    // ----- R-1: each view forwards to the library entry of its own name, its calldata unchanged -----

    function _forwarded(bytes memory data) internal {
        vm.expectCall(address(UARegistryCoreLib), data, 1);
        (bool ok,) = address(reg).staticcall(data);
        ok; // a refusal is forwarded as well
    }

    function test_r1_viewsRunInTheLibrary() public {
        bytes memory key = _key(0x0103);
        _forwarded(abi.encodeCall(KindsDirect.uaOf, (0x0103, key)));
        _forwarded(abi.encodeCall(KindsDirect.keyHashOf, (0x0103, key)));
        _forwarded(abi.encodeCall(KindsDirect.portableRecordDigest, (bytes32(uint256(1)), 0x0130, bytes32(uint256(2)), 0)));
        _forwarded(abi.encodeCall(KindsDirect.registrationDigest, (bytes32(uint256(1)), 0x0130, bytes32(uint256(2)), 0, 0)));
        _forwarded(abi.encodeCall(KindsDirect.pqzKeyRecordDigest, (bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)))));
        _forwarded(abi.encodeCall(KindsDirect.pqzKeyVersionDigest, (bytes32(uint256(1)), 2, bytes32(uint256(3)))));
        _forwarded(abi.encodeCall(KindsDirect.pqzKeyVersionRecordDigest, (bytes32(uint256(1)), 2, bytes32(uint256(3)), 0)));
    }

    /// Positive control of the `expectCall` above: a writer runs in the library today.
    function test_r1_control_writerRunsInTheLibrary() public {
        vm.expectCall(address(UARegistryCoreLib), abi.encodeWithSelector(UARegistryCoreLib.register.selector), 1);
        try reg.register(0x0103, _key(0x0103), _none(), "", "") {} catch {}
    }

    /// The six `pure` views smaller than their stub stay in the registry (§5): no library call.
    function test_r1_smallViewsStay() public {
        vm.expectCall(address(UARegistryCoreLib), "", 0);
        reg.kindName(0x0103);
        reg.uaMessage(0x0103, bytes32(0), bytes32(0));
        reg.pqzKeyDigest(bytes32(0), bytes32(0));
        reg.portableDomainSeparator();
    }

    // ----- R-1 differential: the registry against the replaced code, return and revert data byte for byte -----

    function _same(bytes memory data) internal view {
        (bool okR, bytes memory r) = address(reg).staticcall(data);
        (bool okD, bytes memory d) = address(direct).staticcall(data);
        assertEq(okR, okD, "same outcome");
        assertEq(r, d, "same return or revert data");
    }

    function test_r1_diff_vectors() public view {
        for (uint256 i; i < 8; ++i) {
            uint16 kind = uint16(0x0100 + i);
            _same(abi.encodeCall(KindsDirect.uaOf, (kind, keys[i])));
            _same(abi.encodeCall(KindsDirect.keyHashOf, (kind, keys[i])));
            // a refusal: the key data of another kind (a length the kind refuses), and an unknown kind
            _same(abi.encodeCall(KindsDirect.keyHashOf, (kind, keys[(i + 1) % 8])));
            _same(abi.encodeCall(KindsDirect.uaOf, (kind, keys[(i + 3) % 8])));
        }
        _same(abi.encodeCall(KindsDirect.keyHashOf, (0x0999, keys[0])));
        _same(abi.encodeCall(KindsDirect.uaOf, (0x0120, keys[0])));
        _same(abi.encodeCall(KindsDirect.keyHashOf, (UAKinds.PQZ_MLWE, new bytes(18_432))));
    }

    function testFuzz_r1_diff_keys(uint16 kind, bytes calldata keyData) public view {
        _same(abi.encodeCall(KindsDirect.uaOf, (kind, keyData)));
        _same(abi.encodeCall(KindsDirect.keyHashOf, (kind, keyData)));
        _same(abi.encodeCall(KindsDirect.uaOf, (uint16(0x0100 + kind % 0x50), keyData)));
        _same(abi.encodeCall(KindsDirect.keyHashOf, (uint16(0x0100 + kind % 0x50), keyData)));
    }

    function testFuzz_r1_diff_digests(bytes32 ua, uint16 kind, uint64 version, bytes32 a, bytes32 b, bytes32 c) public view {
        _same(abi.encodeCall(KindsDirect.portableRecordDigest, (ua, kind, a, b)));
        _same(abi.encodeCall(KindsDirect.registrationDigest, (ua, kind, a, b, c)));
        _same(abi.encodeCall(KindsDirect.pqzKeyRecordDigest, (ua, a, b)));
        _same(abi.encodeCall(KindsDirect.pqzKeyVersionDigest, (ua, version, a)));
        _same(abi.encodeCall(KindsDirect.pqzKeyVersionRecordDigest, (ua, version, a, b)));
    }

    /// Malformed calldata (a short or truncated argument area) is refused the same way.
    function testFuzz_r1_diff_raw(uint8 which, bytes calldata tail) public view {
        bytes4[7] memory s = [
            KindsDirect.uaOf.selector, KindsDirect.keyHashOf.selector, KindsDirect.portableRecordDigest.selector,
            KindsDirect.registrationDigest.selector, KindsDirect.pqzKeyRecordDigest.selector,
            KindsDirect.pqzKeyVersionDigest.selector, KindsDirect.pqzKeyVersionRecordDigest.selector
        ];
        _same(bytes.concat(s[which % 7], tail));
    }

    // ----- 3.1b: each writer runs in its domain's library, once, and never in the other -----

    function _routed(address lib, address other, bytes4 libSel) internal {
        vm.expectCall(lib, abi.encodeWithSelector(libSel), 1);
        vm.expectCall(other, abi.encodeWithSelector(libSel), 0);
    }

    function _try(bytes memory data) internal {
        (bool ok,) = address(reg).call(data);
        ok; // a refusal inside the library is still its call
    }

    function test_b_keyWritersRunInTheAuxLibrary() public {
        (address k, address r, bytes32 ua) = (address(UARegistryAuxLib), address(UARegistryCoreLib), bytes32(uint256(7)));
        IUARegistry.UASig memory none;
        IUARegistry.KemKey memory kem;
        IUARegistry.MemberSig memory m;
        _routed(k, r, UARegistryAuxLib.cacheExpandedKey.selector);
        _try(abi.encodeCall(UARegistry.cacheExpandedKey, (0x0130, "", 0)));
        _routed(k, r, UARegistryAuxLib.storePqzPop.selector);
        _try(abi.encodeCall(UARegistry.storePqzPop, (ua, 0, hex"01")));
        _routed(k, r, UARegistryAuxLib.setPqzKey.selector);
        _try(abi.encodeCall(UARegistry.setPqzKey, (ua, 0, "", bytes32(0), none)));
        _routed(k, r, UARegistryAuxLib.setKemKey.selector);
        _try(abi.encodeCall(UARegistry.setKemKey, (ua, 0, kem, none)));
        _routed(r, k, UARegistryCoreLib.acceptMembership.selector); // the core library's (§11 (f))
        _try(abi.encodeCall(UARegistry.acceptMembership, (ua, m)));
    }

    /// The reads off the hot path run in their library inside the view; the hot views run in no library.
    function test_b_readsRunInTheirLibrary() public {
        (address k, address r, bytes32 ua) = (address(UARegistryAuxLib), address(UARegistryCoreLib), bytes32(uint256(7)));
        _routed(r, k, UARegistryCoreLib.registrationOf.selector);
        reg.registrationOf(ua);
        _routed(r, k, UARegistryCoreLib.uaCount.selector);
        reg.uaCount(0x0103);
        bytes4[8] memory aux = [UARegistryAuxLib.popOf.selector, UARegistryAuxLib.popSlotsOf.selector,
            UARegistryAuxLib.webAuthnKeyOf.selector, UARegistryAuxLib.pqzPopOf.selector, UARegistryAuxLib.pqzKeySigOf.selector,
            UARegistryAuxLib.uaAt.selector, UARegistryAuxLib.uaPage.selector, UARegistryAuxLib.uaIndex.selector];
        for (uint256 i; i < aux.length; ++i) _routed(k, r, aux[i]);
        reg.popOf(ua);
        reg.popSlotsOf(ua);
        reg.webAuthnKeyOf(ua);
        reg.pqzPopOf(ua, 0);
        reg.pqzKeySigOf(ua, 0);
        _try(abi.encodeCall(UARegistry.uaAt, (0x0103, 0)));
        reg.uaPage(0x0103, 0, 4);
        _try(abi.encodeCall(UARegistry.uaIndex, (ua)));
    }

    function test_b_hotViewsRunInNoLibrary() public {
        bytes32 ua = bytes32(uint256(7));
        IUARegistry.UASig memory none;
        vm.expectCall(address(UARegistryCoreLib), "", 0);
        vm.expectCall(address(UARegistryAuxLib), "", 0);
        _try(abi.encodeCall(UARegistry.requireAuthorized, (ua, bytes32(0), bytes32(0), none)));
        reg.kindOf(ua);
        reg.recordOf(ua);
        reg.checkedOf(ua);
        reg.keyOf(ua);
        reg.keyOwner(ua);
        reg.pqzKeyOf(ua);
        reg.kemKeyOf(ua);
        reg.msigOf(ua);
        reg.memberAccepted(ua, 0);
        reg.memberSigHashOf(ua, 0);
        reg.uaAuthDigest(ua, bytes32(0), bytes32(0));
        reg.muSig2KeyOf(ua);
        reg.frostKeyOf(ua);
    }

    function test_b_registrationRunsInTheFirstLibrary() public {
        (address k, address r) = (address(UARegistryAuxLib), address(UARegistryCoreLib));
        _routed(r, k, UARegistryCoreLib.register.selector);
        _try(abi.encodeCall(UARegistry.register, (0x0103, _key(0x0103), _none(), "", "")));
        IUARegistry.MsigStructure memory st;
        _routed(r, k, UARegistryCoreLib.registerMsig.selector);
        _try(abi.encodeCall(UARegistry.registerMsig, (st, _none(), new IUARegistry.MemberSig[](0), "")));
        IUARegistry.UASig memory none;
        vm.expectCall(r, abi.encodeWithSelector(UARegistryCoreLib.requirePortable.selector), 1);
        vm.expectCall(k, "", 0);
        _try(abi.encodeCall(UARegistry.requirePortable, (bytes32(uint256(7)), bytes32(0), bytes32(0), none)));
    }

    /// The constructor refuses a registry whose auxiliary library has no code (`_lib` would "succeed" on it, every write a no-op).
    function test_b_constructorNeedsTheAuxLibrary() public {
        new UARegistry(chainUidA, address(0), false, BUDGET, address(0), true, _cfgs(address(mock))); // the control
        vm.etch(address(UARegistryAuxLib), "");
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0)));
        new UARegistry(chainUidA, address(0), false, BUDGET, address(0), true, _cfgs(address(mock)));
    }
}
