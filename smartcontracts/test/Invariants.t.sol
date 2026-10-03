// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Fixtures} from "./helpers/Fixtures.sol";
import {MockERC20} from "./helpers/Mocks.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";
import {MetaTxDex} from "../src/dex/MetaTxDex.sol";
import {MetaTxLib} from "../src/common/MetaTxLib.sol";
import {IERC20MetaTx} from "../src/metatx/IERC20MetaTx.sol";

/// Handler: thao tác ngẫu nhiên trên một wrapper, hai token standalone và DEX.
contract Handler is Test {
    MetaToken public tA;
    MetaToken public tB;
    MetaToken public wrapped;
    MockERC20 public usdc;
    MetaTxDex public dex;
    uint256[3] public pks = [uint256(0xA1), 0xB2, 0xC3];
    uint256 public batchSeq;
    uint256 public settled;

    constructor(MetaToken a, MetaToken b, MetaToken w, MockERC20 u, MetaTxDex d) {
        tA = a; tB = b; wrapped = w; usdc = u; dex = d;
    }

    function actor(uint256 i) public view returns (address) { return vm.addr(pks[i % 3]); }

    function transfer(uint256 from, uint256 to, uint256 v) external {
        address f = actor(from);
        v = bound(v, 0, tA.balanceOf(f));
        vm.prank(f);
        tA.transfer(actor(to), v);
    }

    function wrap(uint256 who, uint256 v) external {
        address w = actor(who);
        v = bound(v, 0, 1_000e6);
        usdc.mint(w, v);
        vm.startPrank(w);
        usdc.approve(address(wrapped), v);
        wrapped.wrap(v);
        vm.stopPrank();
    }

    function unwrap(uint256 who, uint256 v) external {
        address w = actor(who);
        v = bound(v, 0, wrapped.balanceOf(w));
        vm.prank(w);
        wrapped.unwrap(v, w);
    }

    function trade(uint256 sellerA, uint256 sellerB, uint256 va, uint256 vb) external {
        uint256 ia = sellerA % 3;
        uint256 pa = pks[ia];
        uint256 pb = pks[(ia + 1 + sellerB % 2) % 3];
        uint256 balA = tA.balanceOf(vm.addr(pa));
        uint256 balB = tB.balanceOf(vm.addr(pb));
        if (balA == 0 || balB == 0) return;
        va = bound(va, 1, balA);
        vb = bound(vb, 1, balB);
        MetaTxDex.Leg memory a = _leg(pa, tA, va, tB, vb);
        MetaTxDex.Leg memory b = _leg(pb, tB, vb, tA, va);
        dex.settle(a, b);
        ++settled;
    }

    function _leg(uint256 pk, MetaToken sell, uint256 v, MetaToken buy, uint256 minBuy)
        internal returns (MetaTxDex.Leg memory l)
    {
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({
            from: vm.addr(pk), to: address(dex), value: v,
            data: abi.encodeWithSelector(bytes4(keccak256("trade(address,uint256,address)")), address(buy), minBuy, address(0)),
            batch: ++batchSeq, nonce: 0, validUntil: block.timestamp + 300,
            mode: MetaTxLib.MODE_RESTRICT_RELAYER, relayer: address(dex), fee: 0, feeRecipient: address(0)
        });
        (uint8 vv, bytes32 r, bytes32 s) = vm.sign(pk, sell.metaTxDigest(m));
        l = MetaTxDex.Leg({token: IERC20MetaTx(address(sell)), m: m, sig: abi.encodePacked(r, s, vv)});
    }
}

contract InvariantsTest is StdInvariant, Fixtures {
    Handler h;
    MetaToken tA;
    MetaToken tB;
    MetaToken w;
    MockERC20 usdc;
    MetaTxDex dex;

    function setUp() public {
        vm.warp(1_800_000_000);
        _deployFactory();
        dex = new MetaTxDex();
        usdc = new MockERC20("USD Coin", "USDC", 6);
        tA = _standalone(address(this), "AAA", 18, 3_000 ether, address(0));
        tB = _standalone(address(this), "BBB", 18, 3_000 ether, address(0));
        w = _wrapper(address(this), address(usdc), "wUSDC");
        h = new Handler(tA, tB, w, usdc, dex);
        for (uint256 i; i < 3; ++i) {
            tA.transfer(h.actor(i), 1_000 ether);
            tB.transfer(h.actor(i), 1_000 ether);
        }
        targetContract(address(h));
    }

    function invariant_supplyEqualsBalances() public view {
        uint256 sum = tA.balanceOf(address(dex));
        for (uint256 i; i < 3; ++i) sum += tA.balanceOf(h.actor(i));
        assertEq(sum, tA.totalSupply());
    }

    function invariant_wrapperIsFullyReserved() public view {
        assertGe(usdc.balanceOf(address(w)), w.totalSupply());
    }

    function invariant_dexHoldsNothing() public view {
        assertEq(tA.balanceOf(address(dex)), 0);
        assertEq(tB.balanceOf(address(dex)), 0);
    }
}
