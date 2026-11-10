// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {ITradeToken, ILiquidityPullToken} from "../../src/trade/ITradeToken.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IRig, PlainRig, PqzRig, ZetherRig} from "../metatx/helpers/KindRigs.sol";
import {RegRig, ZetherRegRig, PqzRegRig} from "../metatx/helpers/RegKindRigs.sol";
import {MockWrongDex} from "./LiquidityMocks.sol";

/// `mtxLiquidityPull` on every EVM kind (spec 2026-11-10-dex-liquidity.md §5, §14; review P2-6): `NORMAL`, `WRAPPED`, `NORMAL`
/// with the UA ledger off, the public side of `NORMAL_PQZ`, `WRAPPED_PQZ`, `NORMAL_ZETHER`, `WRAPPED_ZETHER`, and the regulated
/// kinds 8-13 (lists off, as the service-pull rigs). A contract that answers the capability check T7 with the token's own `h`
/// pulls exactly `AMT` once; one that answers another word is refused; every kind answers `ILiquidityPullToken`. The PQZ
/// kinds are the committed set here; the gate runs this file at the four sets (`script/pqz/at-set.sh`). UNAUDITED.
contract DexLiquidityKindsTest is Test {
    uint256 internal constant PK = 0xA11CE;
    address internal constant REL = address(0x7E1A);
    uint256 internal constant AMT = 1_000;

    address internal signer = vm.addr(PK);
    string[] internal kinds;
    address[] internal toks;

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
            (string[] memory k, address[] memory t,) = rigs[r].setup();
            for (uint256 i; i < t.length; ++i) {
                kinds.push(k[i]);
                toks.push(t[i]);
            }
        }
        assertEq(toks.length, 13, "the twelve kinds 0-5, 8-13 and NORMAL with the ledger off");
    }

    function _order(address t) internal view returns (ITradeToken.LiquidityOrder memory o) {
        o.from = bytes32(uint256(uint160(signer)));
        o.inputs = new ITradeToken.LiquidityToken[](1);
        o.inputs[0] = ITradeToken.LiquidityToken(t, AMT);
        o.outputs = new ITradeToken.LiquidityToken[](1);
        o.outputs[0] = ITradeToken.LiquidityToken(address(0x0B7), 1);
        o.recipient = bytes32(uint256(0xC0FFEE));
        o.relayer = REL;
        o.batch = 9;
        o.validUntil = block.timestamp + 300;
    }

    function _hashOrder(ITradeToken.LiquidityOrder memory o) internal pure returns (bytes32) {
        bytes32 th = keccak256("LiquidityToken(address token,uint256 amount)");
        bytes32 hi = keccak256(abi.encodePacked(keccak256(abi.encode(th, o.inputs[0].token, o.inputs[0].amount))));
        bytes32 ho = keccak256(abi.encodePacked(keccak256(abi.encode(th, o.outputs[0].token, o.outputs[0].amount))));
        bytes32 ot = keccak256(bytes.concat("LiquidityOrder(bytes32 from,LiquidityToken[] inputs,LiquidityToken[] outputs,",
            "address positionManager,address positionReader,uint256 positionIn,bytes32 positionPool,int24 tickLower,",
            "int24 tickUpper,uint128 minLiquidity,bytes32 recipient,uint256 fee,address relayer,uint8 flags,uint256 batch,",
            "uint256 nonce,uint256 validUntil)LiquidityToken(address token,uint256 amount)"));
        return keccak256(bytes.concat(abi.encode(ot, o.from, hi, ho, o.positionManager, o.positionReader, o.positionIn,
            o.positionPool, o.tickLower), abi.encode(o.tickUpper, o.minLiquidity, o.recipient, o.fee, o.relayer, o.flags,
            o.batch, o.nonce, o.validUntil)));
    }

    function _digest(ITradeToken.LiquidityOrder memory o, address dex, address t) internal view returns (bytes32) {
        bytes32 sep = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS Dex"), keccak256("1"), block.chainid, dex, NormalToken(t).chainUid()));
        return keccak256(abi.encodePacked(hex"1901", sep, _hashOrder(o)));
    }

    function test_everyKind_pullsOnceThroughT7() public {
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            assertTrue(NormalToken(t).supportsInterface(type(ILiquidityPullToken).interfaceId), kinds[i]);
            MockWrongDex wd = new MockWrongDex();
            ITradeToken.LiquidityOrder memory o = _order(t);
            bytes32 h = _digest(o, address(wd), t);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, h);
            IUARegistry.UASig memory auth;
            auth.signature = abi.encodePacked(r, s, v);
            wd.set(1, 0); // another word: refused (T7)
            vm.expectRevert(abi.encodeWithSelector(ITradeToken.NotLiquidityDex.selector, address(wd)));
            vm.prank(REL);
            wd.pull(t, o, auth, AMT);
            wd.set(3, h);
            uint256 before = IERC20(t).balanceOf(signer);
            vm.prank(REL);
            wd.pull(t, o, auth, AMT);
            assertEq(IERC20(t).balanceOf(address(wd)), AMT, kinds[i]);
            assertEq(IERC20(t).balanceOf(signer), before - AMT, kinds[i]);
            assertEq(ITradeToken(t).pulled(h), AMT, kinds[i]);
            vm.expectRevert(abi.encodeWithSelector(ITradeToken.OrderClosed.selector, h));
            vm.prank(REL);
            wd.pull(t, o, auth, AMT);
        }
    }
}
