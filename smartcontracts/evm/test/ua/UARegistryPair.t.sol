// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {UARegistryLib} from "../../src/ua/UARegistryLib.sol";
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
/// code `UARegistryLib` holds run there (`_libPure`, nothing appended); their answers and refusals are byte-equal to the code they
/// replace (`KindsDirect`). UNAUDITED.
contract UARegistryPairTest is UARegistryBase {
    KindsDirect internal direct;

    function setUp() public override {
        super.setUp();
        direct = new KindsDirect();
    }

    // ----- R-1: each view forwards to the library entry of its own name, its calldata unchanged -----

    function _forwarded(bytes memory data) internal {
        vm.expectCall(address(UARegistryLib), data, 1);
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
        vm.expectCall(address(UARegistryLib), abi.encodeWithSelector(UARegistryLib.storePqzPop.selector), 1);
        try reg.storePqzPop(bytes32(uint256(7)), 0, hex"01") {} catch {}
    }

    /// The six `pure` views smaller than their stub stay in the registry (§5): no library call.
    function test_r1_smallViewsStay() public {
        vm.expectCall(address(UARegistryLib), "", 0);
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
}
