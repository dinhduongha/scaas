// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {PqUA} from "../../src/ua/PqUA.sol";
import {MldsaVerifier} from "../../src/ua/MlDsa.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";
import {Catalogue} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";
import {UACall} from "../ua/UACall.sol";
import {UARegistryBase} from "../ua/UARegistryBase.sol";
import {MockV2Factory, MockV2LiquidityPair} from "./LiquidityMocks.sol";

/// An `mldsa65` UA gives two SCaaS inputs (spec 2026-11-10-dex-liquidity.md §14's positive controls, §13 "the PQ fit"): each
/// input token verifies the same ML-DSA-65 signature over `h` through the registry (the real `MldsaVerifier`, cached key,
/// 5.95 M cap), both pull, and the plan fits one transaction of 2^24 gas. The key, its PoP and the signature over the `h` of
/// this run come from script/pqz/mldsa.mjs (noble post-quantum, FIPS 204) through `vm.ffi`: skipped without
/// `MLDSA_CLIENTKEYS` (the dir whose node_modules holds the noble post-quantum package), run as
/// `MLDSA_CLIENTKEYS=../../clients/clientkeys forge test --ffi --match-path test/liquidity/DexLiquidityMldsa.t.sol` (CI: the
/// clientkeys job).
contract DexLiquidityMldsaTest is UARegistryBase {
    address internal constant REG_M = 0x5Ca0000000000000000000000000000000000065;
    uint16 internal constant ML65 = 0x0131;
    uint256 internal constant TX_GAS_CAP = 16_777_216;
    address internal constant RELAYER = address(0xBEEF);
    address internal constant RECV = address(0xC0FFEE);
    /// A test key's seed (logged by nothing, worth nothing).
    bytes32 internal constant SEED = keccak256("ua-mtx-liquidity L1d mldsa65");
    string internal clientkeys;
    UARegistry internal mreg;
    SCaaSDex internal dex;
    NormalToken internal A;
    NormalToken internal B;
    MockV2LiquidityPair internal pair;
    bytes32 internal ua;

    function setUp() public override {
        clientkeys = vm.envOr("MLDSA_CLIENTKEYS", string(""));
        vm.skip(bytes(clientkeys).length == 0);
        super.setUp();
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(ML65, address(new MldsaVerifier(ML65, address(0), "", "")), 5_950_000);
        mreg = _deploy(REG_M, chainUidA, address(0), false, BUDGET, address(0), true, c);
        bytes memory pk = _ml(string.concat("keygen 65 ", _bare(SEED)));
        assertEq(pk.length, 1952, "an ML-DSA-65 key");
        ua = UAKinds.uaOf(ML65, pk);
        bytes32 rd = UAKinds.registrationDigest(ua, ML65, 0, UAKinds.kemRecordHash(ua, 0, bytes("")), 0);
        for (uint256 p; p < 2; ++p) mreg.cacheExpandedKey(ML65, pk, p);
        UACall.register(mreg, ML65, pk, _none(), _sign(mreg.uaMessage(ML65, UAKinds.PURPOSE_POP_V2, rd)), "");
        assertEq(mreg.kindOf(ua), ML65);

        OpenFactory f = EnvKit.factory(address(this), chainUidA, 0);
        Catalogue.plain(f, IOpenFactory.TokenKind.NORMAL, 1, type(NormalToken).creationCode, REG_M, address(0), false);
        Catalogue.dex(f, 1, type(SCaaSDex).creationCode, address(0));
        A = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1,
            abi.encode(normalInit("A", "A", 0, 1e6, address(this), address(0))), "A"));
        B = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1,
            abi.encode(normalInit("B", "B", 0, 1e6, address(this), address(0))), "B"));
        dex = SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(nid(address(this)), 200_000, address(0x7EA5), false, 0,
            address(0))), "dex"));
        dex.setMarket(address(A), address(B), true);
        pair = MockV2LiquidityPair(new MockV2Factory().createPair(address(A), address(B)));
        A.transferToUA(ua, 100_000);
        B.transferToUA(ua, 100_000);
    }

    // ----- the signer: script/pqz/mldsa.mjs through ffi (as script/onchain/Tokens.s.sol `_ml`) -----

    function _ml(string memory job) internal returns (bytes memory) {
        string[] memory c = new string[](3);
        (c[0], c[1]) = ("sh", "-c");
        c[2] = string.concat("printf '%s\\n' '", job, "' | node script/pqz/mldsa.mjs ", clientkeys, " | sed 's/^/0x/'");
        return vm.ffi(c);
    }

    function _bare(bytes32 x) internal pure returns (string memory) {
        bytes memory h = bytes(vm.toString(x));
        bytes memory o = new bytes(64);
        for (uint256 i; i < 64; ++i) o[i] = h[i + 2];
        return string(o);
    }

    /// The ML-DSA-65 signature of `uaMsg` (the registry's `uaMessage`) over `pq_msg = keccak256(TAG ‖ uaMsg)` (CTR-UA-23).
    function _sign(bytes32 uaMsg) internal returns (bytes memory) {
        return _ml(string.concat("sign 65 ", _bare(SEED), " ", _bare(PqUA.pqMessage(PqUA.tag(ML65), uaMsg))));
    }

    // ----- the plan -----

    function _order() internal view returns (ITradeToken.LiquidityOrder memory o) {
        o.from = ua;
        o.inputs = new ITradeToken.LiquidityToken[](2);
        o.inputs[0] = ITradeToken.LiquidityToken(address(A), 50_000);
        o.inputs[1] = ITradeToken.LiquidityToken(address(B), 50_000);
        o.outputs = new ITradeToken.LiquidityToken[](1);
        o.outputs[0] = ITradeToken.LiquidityToken(address(pair), 48_000);
        o.recipient = bytes32(uint256(uint160(RECV)));
        o.relayer = RELAYER;
        o.batch = 3;
        o.validUntil = block.timestamp + 300;
    }

    /// The plan of `o`, its `auth` the ML-DSA-65 signature over `signed` under the purpose `trade`.
    function _plan(ITradeToken.LiquidityOrder memory o, bytes32 signed) internal returns (ISCaaSDex.LiquidityPlan memory p) {
        p.ref = "mldsa65";
        p.order = o;
        p.auth.signature = _sign(mreg.uaMessage(ML65, UAKinds.PURPOSE_TRADE, signed));
        p.pull = new uint256[](2);
        (p.pull[0], p.pull[1]) = (50_000, 50_000);
    }

    function _xs() internal view returns (ISCaaSDex.Interaction[] memory xs) {
        xs = new ISCaaSDex.Interaction[](3);
        xs[0] = ISCaaSDex.Interaction(address(A), abi.encodeCall(IERC20.transfer, (address(pair), 50_000)));
        xs[1] = ISCaaSDex.Interaction(address(B), abi.encodeCall(IERC20.transfer, (address(pair), 50_000)));
        xs[2] = ISCaaSDex.Interaction(address(pair), abi.encodeCall(MockV2LiquidityPair.mint, (address(dex))));
    }

    /// EIP-2028 calldata gas (as test/ua/UATradeVectors.t.sol).
    function _calldataGas(bytes memory cd) internal pure returns (uint256 std) {
        uint256 zeros;
        for (uint256 i; i < cd.length; ++i) if (cd[i] == 0) ++zeros;
        std = 4 * zeros + 16 * (cd.length - zeros);
    }

    /// Both inputs pull from the `mldsa65` UA's ledger, the LP reaches the recipient, inside a transaction of 2^24 gas.
    function test_mldsa65_twoScaasInputs_fitOneTransaction() public {
        ITradeToken.LiquidityOrder memory o = _order();
        bytes32 h = dex.liquidityOrderDigest(o);
        bytes memory cd = abi.encodeCall(ISCaaSDex.mtxLiquidity, (_plan(o, h), _xs()));
        (uint256 a0, uint256 b0) = (A.balanceOfUA(ua), B.balanceOfUA(ua));
        vm.prank(RELAYER);
        (bool ok, bytes memory ret) = address(dex).call{gas: TX_GAS_CAP - 21_000 - _calldataGas(cd)}(cd);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        Vm.Gas memory g = vm.lastCallGas();
        emit log_named_uint("calldata bytes", cd.length);
        emit log_named_uint("GAS mtxLiquidity, two mldsa65-verified SCaaS inputs (regular)", g.gasTotalUsed);
        emit log_named_uint("GAS mtxLiquidity, two mldsa65-verified SCaaS inputs (state)", uint256(int256(g.gasStateUsed)));
        assertLe(g.gasTotalUsed, TX_GAS_CAP);
        assertEq(a0 - A.balanceOfUA(ua), 50_000, "A pulled");
        assertEq(b0 - B.balanceOfUA(ua), 50_000, "B pulled");
        assertEq(A.pulled(h), 50_000);
        assertEq(B.pulled(h), 50_000);
        assertEq(dex.pulled(h), 1);
        assertGe(pair.balanceOf(RECV), 48_000);
    }

    /// The positive's one change: the signature over another order's `h` (nonce + 1); the first input's verify refuses the UA
    /// (`UAUnauthorized`) and nothing moves.
    function test_mldsa65_signatureOverAnotherOrder_refused() public {
        ITradeToken.LiquidityOrder memory o = _order();
        ITradeToken.LiquidityOrder memory other = _order();
        other.nonce = 1;
        ISCaaSDex.LiquidityPlan memory p = _plan(o, dex.liquidityOrderDigest(other));
        ISCaaSDex.Interaction[] memory xs = _xs();
        vm.prank(RELAYER);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        dex.mtxLiquidity(p, xs);
        assertEq(A.balanceOfUA(ua), 100_000);
        assertEq(B.balanceOfUA(ua), 100_000);
    }
}
