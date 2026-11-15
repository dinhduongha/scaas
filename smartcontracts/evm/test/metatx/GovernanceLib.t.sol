// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {TokenStore} from "../../src/metatx/TokenStore.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {GovernanceLibHarness} from "./helpers/GovernanceLibHarness.sol";
import {Puller} from "../helpers/WalletMocks.sol";
import {nid} from "../helpers/Ids.sol";

/// CTR-TOK-22: creation-time flag validation, owner, roles, `disableFeature`.
contract GovernanceLibTest is Test {
    GovernanceLibHarness internal h;
    address internal ownerA = address(0x0A);
    address internal ownerB = address(0x0B);
    address internal minter = address(0x111);
    GovernanceLib.Roles internal none;

    uint256 internal constant PAYABLE = 1 << 0;
    uint256 internal constant MINTABLE = 1 << 1;
    uint256 internal constant BURNABLE = 1 << 2;
    uint256 internal constant RATE = 1 << 3;
    uint256 internal constant WRAPDIS = 1 << 4;

    function setUp() public {
        h = new GovernanceLibHarness();
    }

    function _roles(address m) internal pure returns (GovernanceLib.Roles memory r) {
        r.minter = nid(m);
    }

    // ------------------------------------------------------------------ validation

    function test_storageSlotIsTheErc7201Namespace() public {
        bytes32 slot = keccak256(abi.encode(uint256(keccak256("scaas.governance")) - 1)) & ~bytes32(uint256(0xff));
        assertEq(slot, 0x0a3a361961b35589cdb03530b6f9e23a4db6ca9a0dad5ddf5d7761c7fabc8700);
        h.init(TokenStore.KIND_NORMAL, MINTABLE, 0, nid(ownerA), none);
        assertEq(vm.load(address(h), slot), bytes32(uint256(MINTABLE))); // features at slot+0
        assertEq(vm.load(address(h), bytes32(uint256(slot) + 2)), bytes32(uint256(uint160(ownerA)))); // owner at slot+2
    }

    function test_validFlagsPerKind() public {
        uint256[4] memory valid = [
            PAYABLE | MINTABLE | BURNABLE, PAYABLE | MINTABLE | RATE | WRAPDIS, PAYABLE | MINTABLE | BURNABLE,
            PAYABLE | MINTABLE | RATE | WRAPDIS // governance T9: MINTABLE on the wrapped kinds, the hybrid (spec §5.2)
        ];
        for (uint8 k; k < 4; ++k) {
            for (uint8 b; b < 9; ++b) {
                if (b >= 5) continue; // regulated: separate test
                GovernanceLibHarness x = new GovernanceLibHarness();
                if (valid[k] & (1 << b) != 0) {
                    x.init(k, 1 << b, 0, bytes32(0), none);
                    assertEq(x.features(), 1 << b);
                } else {
                    vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, b));
                    x.init(k, 1 << b, 0, bytes32(0), none);
                }
            }
        }
    }

    /// ua-mtx-merge T24 (regulated-kinds spec Q3): every plain kind refuses 5-9 as invalid for the kind; before, `NORMAL`
    /// and `WRAPPED` passed `| REGULATED` and reached `FeatureNotBuilt` (`test_regulatedFlags_notBuiltOnPublicKinds_invalidOnConfidential`).
    function test_regulatedFlags_invalidOnEveryPlainKind() public {
        for (uint8 b = 5; b <= 9; ++b) {
            vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, b));
            h.init(TokenStore.KIND_NORMAL, 1 << b, 0, bytes32(0), none);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, b));
            h.init(TokenStore.KIND_WRAPPED, 1 << b, 0, bytes32(0), none);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, b));
            h.init(TokenStore.KIND_NORMAL_ZETHER, 1 << b, 0, bytes32(0), none);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, b));
            h.init(TokenStore.KIND_WRAPPED_ZETHER, 1 << b, 0, bytes32(0), none);
        }
    }

    function test_unknownBitsAndKinds_refused() public {
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, uint8(13)));
        h.init(TokenStore.KIND_NORMAL, 1 << 13, 0, bytes32(0), none); // bit 13 is never allocated (CTR-GOV-14)
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, uint8(9)));
        h.init(TokenStore.KIND_NORMAL, 1 << 9, 0, bytes32(0), none); // DENYLIST: a regulated kind's bit (CTR-GOV-18, T24)
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, uint8(0)));
        h.init(6, PAYABLE, 0, bytes32(0), none); // reserved *_ZETHER_PQZ kinds: nothing valid (P6g built 4, 5)
    }

    function test_lockedMustBeSubset_payableBurnableAlwaysLocked() public {
        vm.expectRevert(IGovernance.LockedNotSubset.selector);
        h.init(TokenStore.KIND_NORMAL, MINTABLE, BURNABLE, bytes32(0), none);
        h.init(TokenStore.KIND_NORMAL, PAYABLE | MINTABLE | BURNABLE, 0, bytes32(0), none);
        assertEq(h.lockedFeatures(), PAYABLE | BURNABLE);
    }

    function test_initialRoles_onlyForSetFlags() public {
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleWithoutFeature.selector, uint8(1)));
        h.init(TokenStore.KIND_NORMAL, BURNABLE, 0, bytes32(0), _roles(minter));
        GovernanceLib.Roles memory r;
        r.issuer = nid(address(1));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleWithoutFeature.selector, uint8(5)));
        h.init(TokenStore.KIND_NORMAL, 0, 0, bytes32(0), r);
        r.issuer = 0;
        r.compliance = nid(address(1));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleWithoutFeature.selector, uint8(10))); // `compliance` is bit 10 RECORD (spec §1.2)
        h.init(TokenStore.KIND_NORMAL, 0, 0, bytes32(0), r);
    }

    function test_rateAdminMustBeAContract() public {
        GovernanceLib.Roles memory r;
        r.rateAdmin = nid(address(0xEE));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleNotContract.selector, uint8(3), address(0xEE)));
        h.init(TokenStore.KIND_WRAPPED, RATE, RATE, bytes32(0), r); // no owner: locked, so the holder survives (B-06)
        r.rateAdmin = nid(address(new Puller()));
        h.init(TokenStore.KIND_WRAPPED, RATE, RATE, bytes32(0), r); // no owner: locked, so the holder survives (B-06)
        assertTrue(h.hasRole(3, r.rateAdmin));
    }

    function test_initEmitsRolesAndOwner() public {
        vm.expectEmit(address(h));
        emit IGovernance.RoleGranted(1, nid(minter), bytes32(0));
        vm.expectEmit(address(h));
        emit IAdmin.AdminTransferred(bytes32(0), nid(ownerA));
        h.init(TokenStore.KIND_NORMAL, MINTABLE, 0, nid(ownerA), _roles(minter));
        assertEq(h.admin(), nid(ownerA));
        assertTrue(h.hasRole(1, nid(minter)));
    }

    // ------------------------------------------------------------------ owner powers

    function test_grantRevokeRenounce() public {
        h.init(TokenStore.KIND_NORMAL, MINTABLE, 0, nid(ownerA), none);
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, minter));
        h.grantRole(1, nid(minter));
        vm.prank(ownerA);
        vm.expectEmit(address(h));
        emit IGovernance.RoleGranted(1, nid(minter), nid(ownerA));
        h.grantRole(1, nid(minter));
        vm.prank(ownerA);
        h.grantRole(1, nid(address(0x222))); // several holders
        assertTrue(h.hasRole(1, nid(address(0x222))));
        vm.prank(ownerA);
        vm.expectEmit(address(h));
        emit IGovernance.RoleRevoked(1, nid(address(0x222)), nid(ownerA));
        h.revokeRole(1, nid(address(0x222)));
        assertFalse(h.hasRole(1, nid(address(0x222))));
        vm.prank(minter);
        h.renounceRole(1);
        assertFalse(h.hasRole(1, nid(minter)));
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, uint8(1), minter));
        h.renounceRole(1);
    }

    function test_grant_onlyARoleOfASetFlag() public {
        h.init(TokenStore.KIND_NORMAL, PAYABLE | BURNABLE, 0, nid(ownerA), none);
        vm.startPrank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NoSuchRole.selector, uint8(0)));
        h.grantRole(0, nid(minter));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NoSuchRole.selector, uint8(2)));
        h.grantRole(2, nid(minter));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleWithoutFeature.selector, uint8(1)));
        h.grantRole(1, nid(minter));
        vm.stopPrank();
    }

    function test_disableFeature_alwaysLockedEvenWhenNeverSet() public {
        h.init(TokenStore.KIND_NORMAL, 0, 0, nid(ownerA), _roles(address(0)));
        vm.startPrank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureLocked.selector, uint8(0)));
        h.disableFeature(0);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureLocked.selector, uint8(2)));
        h.disableFeature(2);
        vm.stopPrank();
    }

    function test_disableFeature_oneWay_lockedRefused() public {
        h.init(TokenStore.KIND_NORMAL, PAYABLE | MINTABLE | BURNABLE, 0, nid(ownerA), _roles(minter));
        vm.startPrank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureLocked.selector, uint8(0)));
        h.disableFeature(0);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureLocked.selector, uint8(2)));
        h.disableFeature(2);
        vm.expectEmit(address(h));
        emit IGovernance.FeatureDisabled(1, nid(ownerA));
        h.disableFeature(1);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, uint8(1)));
        h.disableFeature(1);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleWithoutFeature.selector, uint8(1)));
        h.grantRole(1, nid(address(0x333))); // never set again, no new holder
        vm.stopPrank();
        assertTrue(h.hasRole(1, nid(minter))); // the role stays, but the flag gate refuses it
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, uint8(1)));
        h.use(1, nid(minter));
    }

    function test_lockedFlagCannotBeDisabled() public {
        h.init(TokenStore.KIND_NORMAL, MINTABLE, MINTABLE, nid(ownerA), none);
        vm.prank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureLocked.selector, uint8(1)));
        h.disableFeature(1);
    }

    /// CTR-GOV-02: the flag is locked, so its holder survives the renounce (an unlocked one refuses it, `GovGrant.t.sol`).
    function test_twoStepTransferAndRenounce_rolesSurvive() public {
        h.init(TokenStore.KIND_NORMAL, MINTABLE, MINTABLE, nid(ownerA), _roles(minter));
        vm.prank(ownerA);
        vm.expectEmit(address(h));
        emit IAdmin.AdminTransferStarted(nid(ownerA), nid(ownerB));
        h.transferAdmin(nid(ownerB));
        assertEq(h.admin(), nid(ownerA));
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotPendingAdmin.selector, minter));
        h.acceptAdmin();
        vm.prank(ownerB);
        vm.expectEmit(address(h));
        emit IAdmin.AdminTransferred(nid(ownerA), nid(ownerB));
        h.acceptAdmin();
        assertEq(h.admin(), nid(ownerB));
        assertEq(h.pendingAdmin(), bytes32(0));
        vm.prank(ownerB);
        h.renounceAdmin();
        assertEq(h.admin(), bytes32(0));
        assertTrue(h.hasRole(1, nid(minter)));
        vm.prank(ownerB);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, ownerB));
        h.grantRole(1, nid(ownerB));
    }

    function test_noOwnerMeansNoAdministration() public {
        h.init(TokenStore.KIND_NORMAL, MINTABLE, MINTABLE, bytes32(0), _roles(minter)); // locked: B-06
        vm.prank(address(0));
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, address(0)));
        h.disableFeature(1);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotPendingAdmin.selector, address(0)));
        vm.prank(address(0));
        h.acceptAdmin();
    }

    // ------------------------------------------------------------------ negative paths

    function test_zeroAccountRoleRefused() public {
        // init skips a zero role holder (0 = none), so only `grantRole` can reach the check
        h.init(TokenStore.KIND_NORMAL, MINTABLE, 0, nid(ownerA), none);
        vm.prank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleAccountZero.selector, uint8(1)));
        h.grantRole(1, bytes32(0));
        vm.prank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleAccountZero.selector, uint8(0)));
        h.grantRole(0, bytes32(0)); // checked before NoSuchRole
    }

    function test_nonOwnerCannotAdminister() public {
        h.init(TokenStore.KIND_NORMAL, MINTABLE, 0, nid(ownerA), _roles(minter));
        address eve = address(0xE5);
        vm.startPrank(eve);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, eve));
        h.transferAdmin(nid(eve));
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, eve));
        h.revokeRole(1, nid(minter));
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, eve));
        h.renounceAdmin();
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, eve));
        h.disableFeature(1);
        vm.stopPrank();
    }

    function test_renounceClearsPendingOwner() public {
        h.init(TokenStore.KIND_NORMAL, MINTABLE, 0, nid(ownerA), none);
        vm.startPrank(ownerA);
        h.transferAdmin(nid(ownerB));
        h.renounceAdmin();
        vm.stopPrank();
        vm.prank(ownerB);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotPendingAdmin.selector, ownerB));
        h.acceptAdmin();
    }

    function test_oldOwnerLosesPowerAfterTransfer() public {
        h.init(TokenStore.KIND_NORMAL, MINTABLE, 0, nid(ownerA), none);
        vm.prank(ownerA);
        h.transferAdmin(nid(ownerB));
        vm.prank(ownerB);
        h.acceptAdmin();
        vm.prank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, ownerA));
        h.grantRole(1, nid(minter));
    }

    function test_transferToZeroCannotBeAccepted() public {
        h.init(TokenStore.KIND_NORMAL, MINTABLE, 0, nid(ownerA), none);
        vm.prank(ownerA);
        h.transferAdmin(bytes32(0));
        vm.prank(address(0));
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotPendingAdmin.selector, address(0)));
        h.acceptAdmin();
    }

    function test_ownerGrantRateAdminToEoaRefused() public {
        h.init(TokenStore.KIND_WRAPPED, RATE, 0, nid(ownerA), none);
        address eoa = address(0xEE);
        vm.prank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleNotContract.selector, uint8(3), eoa));
        h.grantRole(3, nid(eoa));
    }
}
