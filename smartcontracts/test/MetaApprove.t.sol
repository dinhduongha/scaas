// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Fixtures} from "./helpers/Fixtures.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";
import {MetaTxLib} from "../src/common/MetaTxLib.sol";
import {IERC20MetaTx} from "../src/metatx/IERC20MetaTx.sol";

/// Op meta-tx `approve(address,uint256)` (R26 + R35): người dùng cấp allowance cho DEX không cần gas.
contract MetaApproveTest is Fixtures {
    uint256 constant PK = 0xA11CE;
    address alice;
    MetaToken t;
    address spender;
    uint32 constant R = MetaTxLib.MODE_RESTRICT_RELAYER;

    function setUp() public {
        vm.warp(1_800_000_000);
        alice = vm.addr(PK);
        _deployFactory();
        t = _standalone(address(this), "AAA", 18, 1_000 ether, address(0));
        t.transfer(alice, 100 ether);
        spender = address(new Dummy());
    }

    function _approveData(address s, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(bytes4(keccak256("approve(address,uint256)")), s, amount);
    }

    function _approveTx(address s, uint256 amount) internal view returns (MetaTxLib.MetaTransaction memory m) {
        m = _mt(alice, s, 0, _approveData(s, amount), 7, R);
    }

    function test_approveOpSetsAllowanceGasless() public {
        MetaTxLib.MetaTransaction memory m = _approveTx(spender, 50 ether);
        bytes memory sig = _sign(PK, t, m);
        vm.prank(relayer);
        t.executeMetaTransaction(m, sig);
        assertEq(t.allowance(alice, spender), 50 ether);
        assertEq(t.balanceOf(alice), 100 ether);
        assertEq(t.metaNonce(alice, 7), 1);
    }

    /// Phí relayer của chính approve bị trần 1 % của `value = 0` chặn về 0: relayer tài trợ
    /// approve (một lần cho mỗi token), thu phí ở lệnh DEX.
    function test_approveOpRelayerFeeIsCappedToZero() public {
        MetaTxLib.MetaTransaction memory m = _approveTx(spender, 50 ether);
        m.mode = R | MetaTxLib.MODE_FEE_FIXED;
        m.fee = 1;
        m.feeRecipient = relayer;
        bytes memory sig = _sign(PK, t, m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("FeeExceedsCap(uint256,uint256)")), 1, 0));
        t.executeMetaTransaction(m, sig);
    }

    function test_approveOpToAnEoaIsRefused() public {
        MetaTxLib.MetaTransaction memory m = _approveTx(address(0xE0A), 50 ether);
        bytes memory sig = _sign(PK, t, m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.SpenderNotContract.selector, address(0xE0A)));
        t.executeMetaTransaction(m, sig);
    }

    function test_approveOpToA7702DelegatedEoaIsRefused() public {
        address eoa = address(0x7702);
        vm.etch(eoa, abi.encodePacked(hex"ef0100", spender));
        MetaTxLib.MetaTransaction memory m = _approveTx(eoa, 1);
        bytes memory sig = _sign(PK, t, m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.SpenderNotContract.selector, eoa));
        t.executeMetaTransaction(m, sig);
    }

    function test_approveOpWithValueIsRefused() public {
        MetaTxLib.MetaTransaction memory m = _approveTx(spender, 50 ether);
        m.value = 1;
        bytes memory sig = _sign(PK, t, m);
        vm.prank(relayer);
        vm.expectRevert(MetaToken.ApproveCarriesValue.selector);
        t.executeMetaTransaction(m, sig);
    }

    function test_approveOpToMustNameTheSpender() public {
        MetaTxLib.MetaTransaction memory m = _approveTx(spender, 50 ether);
        m.to = address(0xCAFE);
        bytes memory sig = _sign(PK, t, m);
        vm.prank(relayer);
        vm.expectRevert(MetaToken.ApproveSpenderMismatch.selector);
        t.executeMetaTransaction(m, sig);
    }

    function test_approveOpWrongLengthIsUnknown() public {
        MetaTxLib.MetaTransaction memory m = _approveTx(spender, 50 ether);
        m.data = abi.encodePacked(_approveData(spender, 1), uint8(0));
        bytes memory sig = _sign(PK, t, m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(MetaToken.MetaTxUnknownOp.selector, bytes4(0x095ea7b3)));
        t.executeMetaTransaction(m, sig);
    }

    function test_approveOpCanRevokeToZero() public {
        MetaTxLib.MetaTransaction memory m = _approveTx(spender, 50 ether);
        bytes memory sig = _sign(PK, t, m);
        vm.prank(relayer);
        t.executeMetaTransaction(m, sig);
        m = _approveTx(spender, 0);
        m.batch = 8;
        sig = _sign(PK, t, m);
        vm.prank(relayer);
        t.executeMetaTransaction(m, sig);
        assertEq(t.allowance(alice, spender), 0);
    }
}

contract Dummy {}
