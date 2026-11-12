// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IRig, KindRig, PlainRig, PqzRig, ZetherRig, Tk} from "../metatx/helpers/KindRigs.sol";
import {RegRig, ZetherRegRig, PqzRegRig} from "../metatx/helpers/RegKindRigs.sol";

/// The order's `dex`: pulls and refunds in one call (a refund is bounded by this transaction's pull).
contract ExactDex {
    function pullAndRestore(address t, ITradeToken.UATradeOrder calldata o, IUARegistry.UASig calldata auth,
        ITradeToken.TradeFill calldata f, uint256 back) external
    {
        ITradeToken(t).mtxTrade(o, auth, f);
        if (back != 0) ITradeToken(t).restorePulled(o, back);
    }
}

/// fix2-dex (owner 2026-11-12, "đồng ý bỏ đo token SCaaS"): the DEX measures no SCaaS token, so every SCaaS kind must move
/// exactly what it is asked on each path the DEX uses: the pull (`mtxTrade`, Path A the fill, Path B the whole amount),
/// a payout (`transfer`), a credit to a derived UA (`transferToUA`, where the kind's rig has one) and a refund
/// (`restorePulled`). Every kind: `NORMAL`, `WRAPPED`, `NORMAL` with the ledger off, `NORMAL_PQZ`, `WRAPPED_PQZ`,
/// `NORMAL_ZETHER`, `WRAPPED_ZETHER` (public side) and the regulated kinds 8-13. A kind that ever moves another amount
/// (a fee, a burn, a hook, a rebase) turns this red, and the DEX must measure it again. UNAUDITED.
contract ScaasExactMovesTest is Test {
    address internal constant PAYEE = address(0xBEE5);
    Tk[] internal ks;

    function setUp() public {
        IRig[6] memory rigs;
        RegRig rr = new RegRig();
        rr.init();
        rigs[0] = IRig(address(rr));
        PlainRig plain = new PlainRig();
        plain.init();
        rigs[1] = IRig(address(plain));
        PqzRig pqz = new PqzRig();
        pqz.init();
        rigs[2] = IRig(address(pqz));
        ZetherRig zeth = new ZetherRig();
        zeth.init();
        rigs[3] = IRig(address(zeth));
        ZetherRegRig zr = new ZetherRegRig();
        zr.init();
        rigs[4] = IRig(address(zr));
        PqzRegRig pr = new PqzRegRig();
        pr.init();
        rigs[5] = IRig(address(pr));
        for (uint256 r; r < 6; ++r) {
            (, address[] memory t,) = rigs[r].setup();
            for (uint256 i; i < t.length; ++i) ks.push(KindRig(address(rigs[r])).tkAt(i));
        }
        assertEq(ks.length, 13, "the twelve kinds 0-5, 8-13 and NORMAL with the ledger off");
    }

    function _order(Tk memory k, address dex, uint256 nonce, uint8 flags)
        internal view returns (ITradeToken.UATradeOrder memory o, IUARegistry.UASig memory auth)
    {
        o.from = bytes32(uint256(uint160(k.signer)));
        o.receiveToken = address(0x0B7);
        (o.amount, o.receiveAmount, o.dex, o.flags, o.batch, o.nonce) = (1000, 1000, dex, flags, 77, nonce);
        o.validUntil = block.timestamp + 300;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(k.pk, ITradeToken(k.t).tradeOrderDigest(o));
        auth.signature = abi.encodePacked(r, s, v);
    }

    function test_everyKind_movesExactly() public {
        for (uint256 i; i < ks.length; ++i) {
            Tk memory k = ks[i];
            IERC20 t = IERC20(k.t);
            ExactDex x = new ExactDex();
            address dex = address(x);
            // the pull, Path A: exactly the fill; the refund in the same call: exactly what is restored
            (ITradeToken.UATradeOrder memory o, IUARegistry.UASig memory auth) = _order(k, dex, 1, 0);
            uint256 s0 = t.balanceOf(k.signer);
            x.pullAndRestore(k.t, o, auth, ITradeToken.TradeFill(600, 600, 0, address(this)), 100);
            assertEq(t.balanceOf(k.signer), s0 - 500, string.concat(k.kind, ": pull and refund, seller"));
            assertEq(t.balanceOf(dex), 500, string.concat(k.kind, ": pull and refund, dex"));
            // a payout
            vm.prank(dex);
            t.transfer(PAYEE, 200);
            assertEq(t.balanceOf(PAYEE), 200, string.concat(k.kind, ": payout"));
            assertEq(t.balanceOf(dex), 300, string.concat(k.kind, ": payout, dex"));
            // a derived UA credit through the ledger
            if (k.uaD != 0) {
                uint256 u0 = IUALedger(k.t).balanceOfUA(k.uaD);
                vm.prank(dex);
                IUALedger(k.t).transferToUA(k.uaD, 100);
                assertEq(IUALedger(k.t).balanceOfUA(k.uaD), u0 + 100, string.concat(k.kind, ": ledger credit"));
                assertEq(t.balanceOf(dex), 200, string.concat(k.kind, ": ledger credit, dex"));
            }
            // the pull, Path B: exactly the whole amount
            (o, auth) = _order(k, dex, 2, 3); // ESCROW implies IOC
            x.pullAndRestore(k.t, o, auth, ITradeToken.TradeFill(1000, 0, 0, address(this)), 0);
            assertEq(t.balanceOf(k.signer), s0 - 1500, string.concat(k.kind, ": Path B pull"));
        }
    }
}
