// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";
import {AdminHarness} from "./helpers/AdminHarness.sol";
import {Puller} from "../helpers/WalletMocks.sol";

/// CTR-TOK-22: creation-time flag validation, owner, roles, `disableFeature`.
contract AdminLibTest is Test {
    AdminHarness internal h;
    address internal ownerA = address(0x0A);
    address internal ownerB = address(0x0B);
    address internal minter = address(0x111);
    AdminLib.Roles internal none;

    uint256 internal constant PAYABLE = 1 << 0;
    uint256 internal constant MINTABLE = 1 << 1;
    uint256 internal constant BURNABLE = 1 << 2;
    uint256 internal constant RATE = 1 << 3;
    uint256 internal constant WRAPDIS = 1 << 4;

    function setUp() public {
        h = new AdminHarness();
    }

    function _roles(address m) internal pure returns (AdminLib.Roles memory r) {
        r.minter = m;
    }

    // ------------------------------------------------------------------ validation

    function test_storageSlotIsTheErc7201Namespace() public {
        bytes32 slot = keccak256(abi.encode(uint256(keccak256("scaas.token")) - 1)) & ~bytes32(uint256(0xff));
        assertEq(slot, 0x83083067f3d1caf66741d4eeefa9d3f4f0e5b0793677731d6fee7e67b774ac00);
        h.init(AdminLib.KIND_NONE, MINTABLE, 0, ownerA, none);
        assertEq(vm.load(address(h), slot), bytes32(uint256(MINTABLE))); // features at slot+0
        assertEq(vm.load(address(h), bytes32(uint256(slot) + 2)), bytes32(uint256(uint160(ownerA)))); // owner at slot+2
    }

    function test_validFlagsPerKind() public {
        uint256[4] memory valid = [
            PAYABLE | MINTABLE | BURNABLE, PAYABLE | RATE | WRAPDIS, PAYABLE | MINTABLE | BURNABLE, PAYABLE | RATE | WRAPDIS
        ];
        for (uint8 k; k < 4; ++k) {
            for (uint8 b; b < 9; ++b) {
                if (b >= 5) continue; // regulated: separate test
                AdminHarness x = new AdminHarness();
                if (valid[k] & (1 << b) != 0) {
                    x.init(k, 1 << b, 0, address(0), none);
                    assertEq(x.features(), 1 << b);
                } else {
                    vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, b));
                    x.init(k, 1 << b, 0, address(0), none);
                }
            }
        }
    }

    function test_regulatedFlags_notBuiltOnPublicKinds_invalidOnConfidential() public {
        for (uint8 b = 5; b < 9; ++b) {
            vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureNotBuilt.selector, b));
            h.init(AdminLib.KIND_NONE, 1 << b, 0, address(0), none);
            vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureNotBuilt.selector, b));
            h.init(AdminLib.KIND_UNDERLYING, 1 << b, 0, address(0), none);
            vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, b));
            h.init(AdminLib.KIND_NONE_ZETHER, 1 << b, 0, address(0), none);
            vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, b));
            h.init(AdminLib.KIND_UNDERLYING_ZETHER, 1 << b, 0, address(0), none);
        }
    }

    function test_unknownBitsAndKinds_refused() public {
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, uint8(9)));
        h.init(AdminLib.KIND_NONE, 1 << 9, 0, address(0), none);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, uint8(0)));
        h.init(4, PAYABLE, 0, address(0), none); // reserved PQZ kinds: nothing valid
    }

    function test_lockedMustBeSubset_payableBurnableAlwaysLocked() public {
        vm.expectRevert(ITokenAdmin.LockedNotSubset.selector);
        h.init(AdminLib.KIND_NONE, MINTABLE, BURNABLE, address(0), none);
        h.init(AdminLib.KIND_NONE, PAYABLE | MINTABLE | BURNABLE, 0, address(0), none);
        assertEq(h.lockedFeatures(), PAYABLE | BURNABLE);
    }

    function test_initialRoles_onlyForSetFlags() public {
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.RoleWithoutFeature.selector, uint8(1)));
        h.init(AdminLib.KIND_NONE, BURNABLE, 0, address(0), _roles(minter));
        AdminLib.Roles memory r;
        r.issuer = address(1);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.RoleWithoutFeature.selector, uint8(5)));
        h.init(AdminLib.KIND_NONE, 0, 0, address(0), r);
        r.issuer = address(0);
        r.compliance = address(1);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.RoleWithoutFeature.selector, uint8(8)));
        h.init(AdminLib.KIND_NONE, 0, 0, address(0), r);
    }

    function test_rateAdminMustBeAContract() public {
        AdminLib.Roles memory r;
        r.rateAdmin = address(0xEE);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.RoleNotContract.selector, uint8(3), address(0xEE)));
        h.init(AdminLib.KIND_UNDERLYING, RATE, 0, address(0), r);
        r.rateAdmin = address(new Puller());
        h.init(AdminLib.KIND_UNDERLYING, RATE, 0, address(0), r);
        assertTrue(h.hasRole(3, r.rateAdmin));
    }

    function test_initEmitsRolesAndOwner() public {
        vm.expectEmit(address(h));
        emit ITokenAdmin.RoleGranted(1, minter, address(0));
        vm.expectEmit(address(h));
        emit ITokenAdmin.OwnershipTransferred(address(0), ownerA);
        h.init(AdminLib.KIND_NONE, MINTABLE, 0, ownerA, _roles(minter));
        assertEq(h.owner(), ownerA);
        assertTrue(h.hasRole(1, minter));
    }

    // ------------------------------------------------------------------ owner powers

    function test_grantRevokeRenounce() public {
        h.init(AdminLib.KIND_NONE, MINTABLE, 0, ownerA, none);
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.NotOwner.selector, minter));
        h.grantRole(1, minter);
        vm.prank(ownerA);
        vm.expectEmit(address(h));
        emit ITokenAdmin.RoleGranted(1, minter, ownerA);
        h.grantRole(1, minter);
        vm.prank(ownerA);
        h.grantRole(1, address(0x222)); // several holders
        assertTrue(h.hasRole(1, address(0x222)));
        vm.prank(ownerA);
        vm.expectEmit(address(h));
        emit ITokenAdmin.RoleRevoked(1, address(0x222), ownerA);
        h.revokeRole(1, address(0x222));
        assertFalse(h.hasRole(1, address(0x222)));
        vm.prank(minter);
        h.renounceRole(1);
        assertFalse(h.hasRole(1, minter));
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.MissingRole.selector, uint8(1), minter));
        h.renounceRole(1);
    }

    function test_grant_onlyARoleOfASetFlag() public {
        h.init(AdminLib.KIND_NONE, PAYABLE | BURNABLE, 0, ownerA, none);
        vm.startPrank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.NoSuchRole.selector, uint8(0)));
        h.grantRole(0, minter);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.NoSuchRole.selector, uint8(2)));
        h.grantRole(2, minter);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.RoleWithoutFeature.selector, uint8(1)));
        h.grantRole(1, minter);
        vm.stopPrank();
    }

    function test_disableFeature_alwaysLockedEvenWhenNeverSet() public {
        h.init(AdminLib.KIND_NONE, 0, 0, ownerA, _roles(address(0)));
        vm.startPrank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureLocked.selector, uint8(0)));
        h.disableFeature(0);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureLocked.selector, uint8(2)));
        h.disableFeature(2);
        vm.stopPrank();
    }

    function test_disableFeature_oneWay_lockedRefused() public {
        h.init(AdminLib.KIND_NONE, PAYABLE | MINTABLE | BURNABLE, 0, ownerA, _roles(minter));
        vm.startPrank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureLocked.selector, uint8(0)));
        h.disableFeature(0);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureLocked.selector, uint8(2)));
        h.disableFeature(2);
        vm.expectEmit(address(h));
        emit ITokenAdmin.FeatureDisabled(1, ownerA);
        h.disableFeature(1);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureNotSet.selector, uint8(1)));
        h.disableFeature(1);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.RoleWithoutFeature.selector, uint8(1)));
        h.grantRole(1, address(0x333)); // never set again, no new holder
        vm.stopPrank();
        assertTrue(h.hasRole(1, minter)); // the role stays, but the flag gate refuses it
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureNotSet.selector, uint8(1)));
        h.requireRole(1, minter);
    }

    function test_lockedFlagCannotBeDisabled() public {
        h.init(AdminLib.KIND_NONE, MINTABLE, MINTABLE, ownerA, none);
        vm.prank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureLocked.selector, uint8(1)));
        h.disableFeature(1);
    }

    function test_twoStepTransferAndRenounce_rolesSurvive() public {
        h.init(AdminLib.KIND_NONE, MINTABLE, 0, ownerA, _roles(minter));
        vm.prank(ownerA);
        vm.expectEmit(address(h));
        emit ITokenAdmin.OwnershipTransferStarted(ownerA, ownerB);
        h.transferOwnership(ownerB);
        assertEq(h.owner(), ownerA);
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.NotPendingOwner.selector, minter));
        h.acceptOwnership();
        vm.prank(ownerB);
        vm.expectEmit(address(h));
        emit ITokenAdmin.OwnershipTransferred(ownerA, ownerB);
        h.acceptOwnership();
        assertEq(h.owner(), ownerB);
        assertEq(h.pendingOwner(), address(0));
        vm.prank(ownerB);
        h.renounceOwnership();
        assertEq(h.owner(), address(0));
        assertTrue(h.hasRole(1, minter));
        vm.prank(ownerB);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.NotOwner.selector, ownerB));
        h.grantRole(1, ownerB);
    }

    function test_noOwnerMeansNoAdministration() public {
        h.init(AdminLib.KIND_NONE, MINTABLE, 0, address(0), _roles(minter));
        vm.prank(address(0));
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.NotOwner.selector, address(0)));
        h.disableFeature(1);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.NotPendingOwner.selector, address(0)));
        vm.prank(address(0));
        h.acceptOwnership();
    }

    // ------------------------------------------------------------------ negative paths

    function test_zeroAccountRoleRefused() public {
        // init skips a zero role holder (0 = none), so only `grantRole` can reach the check
        h.init(AdminLib.KIND_NONE, MINTABLE, 0, ownerA, none);
        vm.prank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.RoleAccountZero.selector, uint8(1)));
        h.grantRole(1, address(0));
        vm.prank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.RoleAccountZero.selector, uint8(0)));
        h.grantRole(0, address(0)); // checked before NoSuchRole
    }

    function test_nonOwnerCannotAdminister() public {
        h.init(AdminLib.KIND_NONE, MINTABLE, 0, ownerA, _roles(minter));
        address eve = address(0xE5);
        vm.startPrank(eve);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.NotOwner.selector, eve));
        h.transferOwnership(eve);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.NotOwner.selector, eve));
        h.revokeRole(1, minter);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.NotOwner.selector, eve));
        h.renounceOwnership();
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.NotOwner.selector, eve));
        h.disableFeature(1);
        vm.stopPrank();
    }

    function test_renounceClearsPendingOwner() public {
        h.init(AdminLib.KIND_NONE, MINTABLE, 0, ownerA, none);
        vm.startPrank(ownerA);
        h.transferOwnership(ownerB);
        h.renounceOwnership();
        vm.stopPrank();
        vm.prank(ownerB);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.NotPendingOwner.selector, ownerB));
        h.acceptOwnership();
    }

    function test_oldOwnerLosesPowerAfterTransfer() public {
        h.init(AdminLib.KIND_NONE, MINTABLE, 0, ownerA, none);
        vm.prank(ownerA);
        h.transferOwnership(ownerB);
        vm.prank(ownerB);
        h.acceptOwnership();
        vm.prank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.NotOwner.selector, ownerA));
        h.grantRole(1, minter);
    }

    function test_transferToZeroCannotBeAccepted() public {
        h.init(AdminLib.KIND_NONE, MINTABLE, 0, ownerA, none);
        vm.prank(ownerA);
        h.transferOwnership(address(0));
        vm.prank(address(0));
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.NotPendingOwner.selector, address(0)));
        h.acceptOwnership();
    }

    function test_ownerGrantRateAdminToEoaRefused() public {
        h.init(AdminLib.KIND_UNDERLYING, RATE, 0, ownerA, none);
        address eoa = address(0xEE);
        vm.prank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.RoleNotContract.selector, uint8(3), eoa));
        h.grantRole(3, eoa);
    }
}
