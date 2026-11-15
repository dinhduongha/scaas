// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IRescuable} from "../../src/governance/IRescuable.sol";
import {RescueLib} from "../../src/governance/RescueLib.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {RelayFeeRouter} from "../../src/metatx/RelayFeeRouter.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {PqChatBase} from "../pqchat/PqChatBase.sol";
import {HookLeg} from "../zether/ZetherWrapped.t.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

/// CTR-GOV-26 (owner 2026-11-12): `rescue(asset)` on the chain singletons `UARegistry`, `OpenFactory`, `GovernanceRouter`,
/// `RelayFeeRouter` and `PqChat`, each holding nothing by design. Anyone; the whole balance of an ERC-20 or (`address(0)`)
/// the native coin to `RescueLib.SCAAS_DEV_RESCUE`, `IRescuable.Rescued`; the native coin refused to a designator there.
contract SingletonRescueTest is PqChatBase {
    address constant ANYONE = address(0xA11);
    address constant DEV = RescueLib.SCAAS_DEV_RESCUE;
    MockERC20 internal foo = new MockERC20("FOO", "FOO", 18);

    function _five() internal returns (address[5] memory s) {
        s = [address(p), address(f), address(new GovernanceRouter(chainUidA, REG_P, address(0), false)),
            address(new RelayFeeRouter()), address(chat)];
    }

    function test_eachSingletonRescuesToTheDevAddress() public {
        address[5] memory s = _five();
        uint256 sent;
        for (uint256 i; i < 5; ++i) {
            foo.mint(s[i], 10 + i);
            vm.expectEmit(s[i]);
            emit IRescuable.Rescued(address(foo), DEV, 10 + i);
            vm.prank(ANYONE); // anyone: no role, no signature
            IRescuable(s[i]).rescue(address(foo));
            sent += 10 + i;
            assertEq(foo.balanceOf(s[i]), 0);
            assertEq(foo.balanceOf(DEV), sent);
            vm.deal(s[i], 1 ether); // a forced send (a coinbase, a SELFDESTRUCT): none of them is payable
            vm.prank(ANYONE);
            IRescuable(s[i]).rescue(address(0));
            assertEq(s[i].balance, 0);
            assertEq(DEV.balance, (i + 1) * 1 ether);
        }
    }

    /// The tokens' guard (`RescueLib.send`): the native coin is refused to an EIP-7702 designator; an ERC-20 still goes.
    function test_singletonNativeRefusedToADesignator() public {
        address[5] memory s = _five();
        vm.etch(DEV, abi.encodePacked(hex"ef0100", address(0xC0DE)));
        for (uint256 i; i < 5; ++i) {
            vm.deal(s[i], 1 ether);
            vm.expectRevert(abi.encodeWithSelector(IRescuable.RescueAssetInvalid.selector, address(0)));
            IRescuable(s[i]).rescue(address(0));
            foo.mint(s[i], 1); // control
            IRescuable(s[i]).rescue(address(foo));
        }
        assertEq(foo.balanceOf(DEV), 5);
    }

    /// `RelayFeeRouter` holds a payment for an instant inside `relay` (open mode), so its rescue runs under its entry
    /// guard: an asset whose transfer re-enters `rescue` fails whole; the control without the re-entry moves both.
    function test_relayFeeRouterRescueNotReentrant() public {
        RelayFeeRouter r = new RelayFeeRouter();
        HookLeg hook = new HookLeg();
        hook.mint(address(r), 10);
        foo.mint(address(r), 5);
        hook.arm(address(r), abi.encodeCall(RelayFeeRouter.rescue, (address(foo))));
        vm.expectRevert(ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector);
        r.rescue(address(hook));
        assertEq(foo.balanceOf(address(r)), 5, "the inner rescue did not run");
        hook.arm(address(0), ""); // positive control: no re-entry
        r.rescue(address(hook));
        r.rescue(address(foo));
        assertEq(hook.balanceOf(DEV) + foo.balanceOf(DEV), 15);
    }
}
