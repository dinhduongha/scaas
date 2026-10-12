// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Fixtures} from "./helpers/Fixtures.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";
import {SCaaSDexV1} from "../src/dex/SCaaSDexV1.sol";

/// Chuỗi khớp một phần + huỷ ngẫu nhiên trên MỘT lệnh bán: `filled` không bao giờ vượt
/// `sellAmount`, DEX không bao giờ giữ tiền, tổng cung bảo toàn.
contract DexHandler is Test {
    SCaaSDexV1 public dex;
    MetaToken public tA;
    MetaToken public tB;
    SCaaSDexV1.Order internal ask;
    uint256 constant ALICE_PK = 0xA11CE;
    uint256 constant BOB_PK = 0xB0B;
    uint256 n;

    constructor(SCaaSDexV1 d, MetaToken a, MetaToken b) {
        dex = d;
        tA = a;
        tB = b;
        ask = SCaaSDexV1.Order({
            maker: vm.addr(ALICE_PK), taker: address(0), sellToken: address(a), buyToken: address(b),
            sellAmount: 100 ether, buyAmount: 300 ether, nonce: 1, expiry: type(uint64).max, maxFeePpm: 10_000,
            flags: 0, relayer: address(0), feeMode: 0, fee: 0, feeToken: address(0), feeRecipient: address(0)
        });
    }

    function _sig(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    function fill(uint96 x, uint16 priceBump) external {
        x = uint96(bound(x, 1, 120 ether));               // may exceed what is left
        uint256 y = uint256(x) * 3 + priceBump;           // at or above the ask's price
        SCaaSDexV1.Order memory a = ask;
        SCaaSDexV1.Order memory bid = SCaaSDexV1.Order({
            maker: vm.addr(BOB_PK), taker: address(0), sellToken: address(tB), buyToken: address(tA),
            sellAmount: y, buyAmount: x, nonce: ++n, expiry: type(uint64).max, maxFeePpm: 10_000,
            flags: 0, relayer: address(0), feeMode: 0, fee: 0, feeToken: address(0), feeRecipient: address(0)
        });
        SCaaSDexV1.Match[] memory ms = new SCaaSDexV1.Match[](1);
        ms[0] = SCaaSDexV1.Match(bytes32(n), a, _sig(ALICE_PK, dex.orderHash(a)), bid,
            _sig(BOB_PK, dex.orderHash(bid)), x, y);
        try dex.settle(ms) {} catch {}
    }

    function askHash() external view returns (bytes32) {
        return dex.orderHash(ask);
    }

    function cancel() external {
        SCaaSDexV1.Order memory a = ask;
        SCaaSDexV1.CancelReq[] memory r = new SCaaSDexV1.CancelReq[](1);
        r[0] = SCaaSDexV1.CancelReq(a, _sig(ALICE_PK, dex.cancelDigest(dex.orderHash(a))));
        dex.cancel(r);
    }
}

contract SCaaSDexInvariantTest is Fixtures {
    SCaaSDexV1 dex;
    MetaToken tA;
    MetaToken tB;
    DexHandler h;

    function setUp() public {
        _deployFactory();
        dex = new SCaaSDexV1(address(this));
        tA = _standalone(address(this), "AAA", 18, 1_000 ether, address(0));
        tB = _standalone(address(this), "BBB", 18, 1_000_000 ether, address(0));
        dex.setMarket(address(tA), address(tB), SCaaSDexV1.Market(true, true, 1_000, 3_000, address(0xFEE)));
        h = new DexHandler(dex, tA, tB);
        address alice = vm.addr(0xA11CE);
        address bob = vm.addr(0xB0B);
        tA.transfer(alice, 1_000 ether);
        tB.transfer(bob, 1_000_000 ether);
        vm.prank(alice);
        tA.approve(address(dex), type(uint256).max);
        vm.prank(bob);
        tB.approve(address(dex), type(uint256).max);
        targetContract(address(h));
    }

    function invariant_neverOverfilled() public view {
        uint256 f = dex.filled(h.askHash());
        assertLe(f, 100 ether);
        // alice only ever loses what was filled
        assertGe(tA.balanceOf(vm.addr(0xA11CE)) + f, 1_000 ether);
    }

    function invariant_dexHoldsNothingAndSupplyIsConserved() public view {
        assertEq(tA.balanceOf(address(dex)), 0);
        assertEq(tB.balanceOf(address(dex)), 0);
        assertEq(tA.totalSupply(), 1_000 ether);
        assertEq(tB.totalSupply(), 1_000_000 ether);
    }
}
