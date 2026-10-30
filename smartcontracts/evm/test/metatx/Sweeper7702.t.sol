// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MandateFixture} from "../wallet/MandateWallet.t.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {SigCheck} from "../../src/common/SigCheck.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {FeeMode} from "../../src/common/FeePolicy.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20Payment} from "../../src/metatx/IERC20Payment.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {MandateWallet} from "../../src/wallet/MandateWallet.sol";

/// The delegate of the 2026-10-29 hot-wallet drain: says yes to every ERC-1271 question and, called on the victim's
/// address, makes any call as the victim.
contract Sweeper {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }

    function sweep(address target, bytes calldata data) external returns (bytes memory r) {
        bool ok;
        (ok, r) = target.call(data);
        if (!ok) assembly ("memory-safe") { revert(add(r, 0x20), mload(r)) }
    }

    receive() external payable {}
}

/// Owner ruling 2026-10-30 after the EIP-7702 sweeper drain: "an EOA must really sign — no delegation at all; an EOA
/// must not run code." The victim (`owner`: holder, token owner and minter, `MandateWallet` owner) signed a 7702
/// authorization to a sweeper. Every path the sweeper tries — its code calling as the victim (D2) and its ERC-1271
/// answering for the victim (D1) — is refused; the victim's own key still works through a relayed meta-transaction.
contract Sweeper7702Test is MandateFixture {
    address internal attacker = address(0xA77AC);
    Sweeper internal sweeper;
    NormalToken internal v;
    WrappedToken internal wt;
    MockERC20 internal u;

    function setUp() public override {
        super.setUp();
        sweeper = new Sweeper();
        v = _normal(owner, 1_000, owner);
        u = new MockERC20("U", "U", 6);
        wt = _single(address(u), 6, 1, 1, _fixedRate());
        u.mint(owner, 100);
        vm.startPrank(owner);
        u.approve(address(wt), 100);
        wt.wrap(100);
        vm.stopPrank();
        t.mint(owner, 500);
        vm.etch(owner, abi.encodePacked(hex"ef0100", address(sweeper))); // the phished authorization
    }

    function _swept(address target, bytes memory data) internal {
        vm.expectRevert(abi.encodeWithSelector(SigCheck.CallerDelegated.selector, owner));
        vm.prank(attacker);
        Sweeper(payable(owner)).sweep(target, data);
    }

    function test_sweeper_directCallsRefused() public {
        address tokenOwner = v.owner();
        _swept(address(v), abi.encodeCall(IERC20.transfer, (attacker, 1_000)));
        _swept(address(v), abi.encodeCall(IERC20Payment.payWithFee, (attacker, 1_000, FeeMode.NONE, 0, address(0), 0)));
        _swept(address(v), abi.encodeCall(IERC20.approve, (address(sweeper), 1_000)));
        _swept(address(v), abi.encodeCall(NormalToken.mint, (attacker, 1e9)));
        _swept(address(v), abi.encodeCall(ITokenAdmin.transferOwnership, (attacker)));
        _swept(address(v), abi.encodeCall(IMetaTx.cancelNonce, (0)));
        _swept(address(wt), abi.encodeWithSignature("unwrap(uint256,address)", 100, attacker));
        _swept(address(w), abi.encodeCall(MandateWallet.execute, (address(t), 0, abi.encodeCall(IERC20.transfer, (attacker, 10_000)))));
        _swept(address(w), abi.encodeCall(MandateWallet.setMandate, (address(t), attacker, 10_000, 10_000, 1 days, uint64(block.timestamp + 1 days))));
        _swept(address(w), abi.encodeCall(MandateWallet.setPayee, (address(t), attacker, true)));
        assertEq(v.balanceOf(owner), 1_000);
        assertEq(v.owner(), tokenOwner);
        assertEq(wt.balanceOf(owner), 100);
        assertEq(t.balanceOf(address(w)), 10_000);
        assertEq(v.balanceOf(attacker) + wt.balanceOf(attacker) + u.balanceOf(attacker) + t.balanceOf(attacker), 0);
    }

    /// D1: the sweeper's ERC-1271 "yes" is never asked for a designator; the attacker's signature is just wrong.
    function test_sweeper_signaturesRefused() public {
        MetaTxLib.MetaTransfer memory x = _tr(owner, attacker, 1_000, 0, 0, RR);
        bytes memory s = _signTr(0xA77AC, address(v), x);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        vm.prank(relayer);
        v.mtxExecuteTransfer(x, s);
        bytes memory data = abi.encodeCall(MandateWallet.setPayee, (address(t), attacker, true));
        MetaTxLib.MetaTransaction memory m;
        (m.from, m.data, m.validUntil) = (owner, data, block.timestamp + 300);
        bytes memory sig = _sig(0xA77AC, w.mtxDigest(m));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        vm.prank(relayer);
        w.mtxExecuteAsOwner(data, 0, m.validUntil, sig);
        // the victim's own key still moves its tokens, relayed (fee 0), while the delegation stands
        x.to = stranger;
        _xfer(OWNER_PK, address(v), x);
        assertEq(v.balanceOf(stranger), 1_000);
    }

    /// A code-less EOA and a contract still call directly; only the designator is refused.
    function test_plainEoaAndContractCallersUnchanged() public {
        vm.etch(owner, "");
        vm.prank(owner);
        v.transfer(stranger, 400);
        vm.prank(stranger);
        v.transfer(address(this), 100);
        v.transfer(attacker, 100); // this test contract: real code
        assertEq(v.balanceOf(stranger), 300);
        assertEq(v.balanceOf(attacker), 100);
    }

    /// D3: a bound relayer with a designator is refused at the binding; the same intent left open (no relayer bound)
    /// may be submitted by anyone, a designator too (open roles unchanged).
    function test_boundRelayerDelegatedRefused() public {
        vm.etch(owner, "");
        vm.etch(relayer, abi.encodePacked(hex"ef0100", address(sweeper)));
        MetaTxLib.MetaTransfer memory x = _tr(owner, stranger, 10, 0, 0, RR);
        bytes memory s = _signTr(OWNER_PK, address(v), x);
        vm.expectRevert(abi.encodeWithSelector(SigCheck.CallerDelegated.selector, relayer));
        vm.prank(relayer);
        v.mtxExecuteTransfer(x, s);
        x = _tr(owner, stranger, 10, 0, 0, 0);
        s = _signTr(OWNER_PK, address(v), x);
        vm.prank(relayer);
        v.mtxExecuteTransfer(x, s);
        assertEq(v.balanceOf(stranger), 10);
    }
}
