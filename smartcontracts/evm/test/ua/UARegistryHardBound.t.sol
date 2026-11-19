// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UARegistryRegLib} from "../../src/ua/UARegistryRegLib.sol";
import {UARegistryBase} from "./UARegistryBase.sol";
import {VerifyOnlyStandIn} from "./UARegistryLine.t.sol";
import {UACall} from "./UACall.sol";

/// The bounds of a line (spec 2026-11-19-registry-verify-only-kinds §4 P3, P9; plan Task 7): what a member held elsewhere costs
/// the consumer bound (`UARegistryRegLib._slotCap`: the walk, a verify-only member's reads, the holder's cap). UNAUDITED.
contract UARegistryHardBoundTest is UARegistryBase {
    uint16 internal constant ML87 = UAKinds.MLDSA87;
    uint64 internal constant CAP_VO = 250_000;

    UARegistry internal g1;
    bytes internal pk;
    bytes32 internal id;

    function setUp() public override {
        super.setUp();
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](1);
        // a verifier without a precompile and the mock rule (`PRECOMPILE() == 0`)
        k[0] = UARegistry.KindConfig(ML87, address(new VerifyOnlyStandIn(address(0), 0, 0)), 400_000, false, 0);
        g1 = _deploy(address(0x7f01), chainUidA, address(0), false, BUDGET, address(0), true, k);
        pk = new bytes(2592);
        pk[0] = 0x87;
        id = _register(g1, ML87, pk);
    }

    /// A gen-2 `msig` of the gen-1 `mldsa87` member (2,592 B key, the largest `keyOf` of a stored kind), the kind verify-only in gen
    /// 2: the consumer check's gas beyond the verifier's own work is within one hop, `VO_READ_GAS`, `MSIG_MEMBER_GAS` and
    /// `MSIG_ACCEPTED_GAS`, the terms `_slotCap` / `_worst` count beside the cap.
    function test_voMember_readsWithinConstant() public {
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](1);
        k[0] = UARegistry.KindConfig(ML87, address(new VerifyOnlyStandIn(address(0x5caa0014), 0, 0)), CAP_VO, true, 0);
        UARegistry g2 = _deploy(address(0x7f02), chainUidA, address(g1), false, BUDGET, address(0), true, k);
        Member[] memory m = new Member[](1);
        m[0] = Member(ML87, id, 1);
        bytes memory d = _msigKey(1, m);
        bytes32 ua = UAKinds.uaOf(UAKinds.MSIG, d);
        bytes32 pmd = _memberDigest(ua, UAKinds.PURPOSE_POP_V2, _regDigest(ua, UAKinds.MSIG));
        IUARegistry.MemberSig[] memory p = new IUARegistry.MemberSig[](1);
        p[0] = IUARegistry.MemberSig(
            0, new IUARegistry.InnerSig[](0), _sig(pk, UAKinds.uaMessage(ML87, UAKinds.PURPOSE_MEMBER, pmd))
        );
        UACall.register(g2, UAKinds.MSIG, d, _none(), abi.encode(p), "");
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        IUARegistry.UASig memory a;
        a.members = new IUARegistry.MemberSig[](1);
        a.members[0] = IUARegistry.MemberSig(
            0, new IUARegistry.InnerSig[](0), _sig(pk, UAKinds.uaMessage(ML87, UAKinds.PURPOSE_MEMBER, md))
        );
        bytes memory call = abi.encodeCall(IUARegistry.requireAuthorized, (ua, UAKinds.PURPOSE_METATX, DIGEST, a));
        uint256 g = gasleft();
        (bool ok,) = address(g2).staticcall(call);
        g -= gasleft();
        assertTrue(ok, "the member by gen 2's verifier");
        emit log_named_uint("gen-2 msig, one verify-only mldsa87 member at gen 1 (cold, frame)", g);
        // the stand-in's own work (a keccak over the key and message) is below 10,000
        assertLe(
            g,
            UARegistryRegLib.LINE_HOP_GAS + UARegistryRegLib.VO_READ_GAS + UARegistryRegLib.MSIG_MEMBER_GAS
                + UARegistryRegLib.MSIG_ACCEPTED_GAS + 10_000,
            "within the terms the bound counts"
        );
    }

    /// One `mldsa87` member's `msig` registered on `r` (no PoP check needed beyond the member's, a write its holder checks).
    function _msigOn(UARegistry r) internal returns (bytes32 ua) {
        Member[] memory m = new Member[](1);
        m[0] = Member(ML87, id, 1);
        bytes memory d = _msigKey(1, m);
        ua = UAKinds.uaOf(UAKinds.MSIG, d);
        bytes32 pmd = _memberDigest(ua, UAKinds.PURPOSE_POP_V2, _regDigest(ua, UAKinds.MSIG));
        IUARegistry.MemberSig[] memory p = new IUARegistry.MemberSig[](1);
        p[0] = IUARegistry.MemberSig(
            0, new IUARegistry.InnerSig[](0), _sig(pk, UAKinds.uaMessage(ML87, UAKinds.PURPOSE_MEMBER, pmd))
        );
        UACall.register(r, UAKinds.MSIG, d, _none(), abi.encode(p), "");
    }

    function _registerReverts(UARegistry r) internal {
        Member[] memory m = new Member[](1);
        m[0] = Member(ML87, id, 1);
        bytes memory d = _msigKey(1, m);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        UACall.register(r, UAKinds.MSIG, d, _none(), "", "");
    }

    /// P3: a verify-only member counts this generation's cap, its walk and `VO_READ_GAS`: one gas below that sum, refused at
    /// registration (`UAKeyData(msig)`); at it, registered.
    function test_voMember_boundCountsReads() public {
        uint64 b = uint64(
            CAP_VO + UARegistryRegLib.LINE_HOP_GAS + UARegistryRegLib.VO_READ_GAS + UARegistryRegLib.MSIG_MEMBER_GAS
                + UARegistryRegLib.MSIG_ACCEPTED_GAS
        );
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](1);
        k[0] = UARegistry.KindConfig(ML87, address(new VerifyOnlyStandIn(address(0x5caa0014), 0, 0)), CAP_VO, true, 0);
        _registerReverts(_deploy(address(0x7f03), chainUidA, address(g1), false, b - 1, address(0), true, k));
        _msigOn(_deploy(address(0x7f04), chainUidA, address(g1), false, b, address(0), true, k));
    }

    /// N3: a member of a kind this generation does not carry counts its holder's cap (gen 1's 400,000), one hand-off and its
    /// walk (two generations), never the predecessor's cap (gen 2 does not carry it: 0).
    function test_notCarriedMember_boundUsesHoldersCap() public {
        UARegistry.KindConfig[] memory none = new UARegistry.KindConfig[](0);
        UARegistry g2 = _deploy(address(0x7f05), chainUidA, address(g1), false, BUDGET, address(0), true, none);
        uint256 c = 400_000;
        uint256 e = c + c / 63 + 5_000 + 2 * UARegistryRegLib.LINE_HOP_GAS; // the slot, also its largest held cap
        // `_membersWorst`: the caller's hold for a held cap above the 400 k `MSIG_MEMBER_GAS` covers
        uint64 b =
            uint64(e + UARegistryRegLib.MSIG_MEMBER_GAS + UARegistryRegLib.MSIG_ACCEPTED_GAS + (e - 400_000) / 63);
        _registerReverts(_deploy(address(0x7f06), chainUidA, address(g2), false, b - 1, address(0), true, none));
        _msigOn(_deploy(address(0x7f07), chainUidA, address(g2), false, b, address(0), true, none));
    }
}
