// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {IRig, KindRig, PlainRig, PqzRig, ZetherRig, Tk} from "../metatx/helpers/KindRigs.sol";
import {RegRig, ZetherRegRig, PqzRegRig} from "../metatx/helpers/RegKindRigs.sol";
import {nid} from "../helpers/Ids.sol";

/// Fable fix2 F-1: the regulated rigs with a funded derived UA (`uaD`), and kind 8 with `TAX` on at 1 %.
contract ExactRegRig is RegRig {
    function extra() external {
        IFactoryToken.TokenConfig memory c = _cfg8();
        c.features |= 1 << GovernanceBits.TAX;
        c.reg.taxRecipient = nid(address(0x7A0));
        address tt = f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(c), "tax8");
        vm.prank(issuer);
        IRegulatedToken(tt).setTaxRate(10_000);
        require(IRegulatedToken(tt).taxConfig().effectivePpm == 10_000, "the rate");
        tks.push(Tk("NORMAL_REGULATED_TAX", tt, ALICE_PK, alice, BOB_PK, bob, address(0xFEE), relayer, 0, 0, address(0), address(0), 0, 0));
        for (uint256 i; i < tks.length; ++i) {
            vm.prank(alice);
            IUALedger(tks[i].t).transferToUA(UA_X, 100_000);
            tks[i].uaD = UA_X;
        }
    }
}

contract ExactZetherRegRig is ZetherRegRig {
    function extra() external {
        bytes32 u = ZetherTypes.UA.unwrap(bob.ua);
        for (uint256 i; i < tks.length; ++i) {
            vm.prank(tks[i].signer);
            IUALedger(tks[i].t).transferToUA(u, 100_000);
            tks[i].uaD = u;
        }
    }
}

/// The ML-DSA precompile is mocked to accept (`PqzRegistryBase`): `uaD` signs trade orders with a filler signature.
contract ExactPqzRegRig is PqzRegRig {
    function extra() external {
        bytes32 u = _mldsaUA(9);
        for (uint256 i; i < tks.length; ++i) {
            vm.prank(tks[i].signer);
            IUALedger(tks[i].t).transferToUA(u, 100_000);
            tks[i].uaD = u;
        }
    }
}

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
/// exactly what it is asked on each path the DEX uses: the pull (`mtxTrade`, Path A the fill, Path B the whole amount, both
/// measured at the seller and at the DEX), a payout (`transfer`), a credit to a derived UA (`transferToUA`), a derived
/// seller's pull and refund (`restorePulled` to a derived `from`, the ledger move). Every kind: `NORMAL`, `WRAPPED`, `NORMAL`
/// with the ledger off, `NORMAL_PQZ`, `WRAPPED_PQZ`, `NORMAL_ZETHER`, `WRAPPED_ZETHER` (public side), the regulated kinds
/// 8-13 and kind 8 with `TAX` on at 1 % (the tax is only on the pay entries). A kind that ever moves another amount (a fee,
/// a tax, a burn, a hook, a rebase) turns this red, and the DEX must measure it again. Fable fix2 F-1: every kind but the
/// ledger-off one runs the ledger credit (counted); the derived seller runs on the four PQZ kinds (4, 5, 12, 13), whose
/// ML-DSA UA signs under the mocked precompile (the ledger move is one body for every kind). UNAUDITED.
contract ScaasExactMovesTest is Test {
    address internal constant PAYEE = address(0xBEE5);
    uint256 internal constant ML65_SIG = 3309;
    Tk[] internal ks;
    bool[] internal mlUA; // `uaD` is an ML-DSA UA (the derived seller runs)

    function setUp() public {
        IRig[6] memory rigs;
        ExactRegRig rr = new ExactRegRig();
        rr.init();
        rr.extra();
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
        ExactZetherRegRig zr = new ExactZetherRegRig();
        zr.init();
        zr.extra();
        rigs[4] = IRig(address(zr));
        ExactPqzRegRig pr = new ExactPqzRegRig();
        pr.init();
        pr.extra();
        rigs[5] = IRig(address(pr));
        for (uint256 r; r < 6; ++r) {
            (, address[] memory t,) = rigs[r].setup();
            for (uint256 i; i < t.length; ++i) {
                ks.push(KindRig(address(rigs[r])).tkAt(i));
                mlUA.push(r == 2 || r == 5);
            }
        }
        assertEq(ks.length, 14, "the twelve kinds 0-5, 8-13, NORMAL with the ledger off and kind 8 with TAX");
    }

    function _order(Tk memory k, bytes32 from, address dex, uint256 nonce, uint8 flags)
        internal view returns (ITradeToken.UATradeOrder memory o, IUARegistry.UASig memory auth)
    {
        o.from = from;
        o.receiveToken = address(0x0B7);
        (o.amount, o.receiveAmount, o.dex, o.flags, o.batch, o.nonce) = (1000, 1000, dex, flags, 77, nonce);
        o.validUntil = block.timestamp + 300;
        if (from == bytes32(uint256(uint160(k.signer)))) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(k.pk, ITradeToken(k.t).tradeOrderDigest(o));
            auth.signature = abi.encodePacked(r, s, v);
        } else {
            auth.signature = new bytes(ML65_SIG); // the mocked ML-DSA precompile accepts it
        }
    }

    function test_everyKind_movesExactly() public {
        (uint256 ledger, uint256 derived) = (0, 0);
        for (uint256 i; i < ks.length; ++i) {
            Tk memory k = ks[i];
            IERC20 t = IERC20(k.t);
            ExactDex x = new ExactDex();
            address dex = address(x);
            bytes32 native = bytes32(uint256(uint160(k.signer)));
            // the pull, Path A: exactly the fill; the refund in the same call: exactly what is restored
            (ITradeToken.UATradeOrder memory o, IUARegistry.UASig memory auth) = _order(k, native, dex, 1, 0);
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
                ++ledger;
                uint256 u0 = IUALedger(k.t).balanceOfUA(k.uaD);
                vm.prank(dex);
                IUALedger(k.t).transferToUA(k.uaD, 100);
                assertEq(IUALedger(k.t).balanceOfUA(k.uaD), u0 + 100, string.concat(k.kind, ": ledger credit"));
                assertEq(t.balanceOf(dex), 200, string.concat(k.kind, ": ledger credit, dex"));
            }
            // the pull, Path B: exactly the whole amount, at the seller and at the DEX
            uint256 d0 = t.balanceOf(dex);
            (o, auth) = _order(k, native, dex, 2, 3); // ESCROW implies IOC
            x.pullAndRestore(k.t, o, auth, ITradeToken.TradeFill(1000, 0, 0, address(this)), 0);
            assertEq(t.balanceOf(k.signer), s0 - 1500, string.concat(k.kind, ": Path B pull"));
            assertEq(t.balanceOf(dex), d0 + 1000, string.concat(k.kind, ": Path B pull, dex"));
            // a derived seller: the pull from its ledger balance and the refund back to it
            if (mlUA[i]) {
                ++derived;
                uint256 u0 = IUALedger(k.t).balanceOfUA(k.uaD);
                d0 = t.balanceOf(dex);
                (o, auth) = _order(k, k.uaD, dex, 3, 0);
                x.pullAndRestore(k.t, o, auth, ITradeToken.TradeFill(600, 600, 0, address(this)), 100);
                assertEq(IUALedger(k.t).balanceOfUA(k.uaD), u0 - 500, string.concat(k.kind, ": derived pull and refund"));
                assertEq(t.balanceOf(dex), d0 + 500, string.concat(k.kind, ": derived pull and refund, dex"));
            }
        }
        assertEq(ledger, 13, "every kind but the ledger-off one ran the ledger credit");
        assertEq(derived, 4, "the four PQZ kinds ran the derived seller");
    }
}
