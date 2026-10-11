// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ZetherFixture} from "./helpers/ZetherFixture.sol";
import {OpenFactoryV1} from "../../src/factory/OpenFactoryV1.sol";
import {IOpenFactoryV1} from "../../src/common/IOpenFactoryV1.sol";
import {ZetherToken} from "../../src/zether/ZetherToken.sol";
import {ZetherSafety} from "../../src/zether/ZetherSafety.sol";
import {ZetherVerifierBn254, ZetherVerifierBls12381} from "../../src/zether/ZetherVerifier.sol";

/// @notice Cổng của owner (R34, RS2-1): Zether TẮT mặc định và không bật được ngoài chain dev.
contract ZetherGateTest is ZetherFixture {
    function setUp() public {
        _deploy(false, false);
    }

    function test_zetherOffByDefault() public {
        OpenFactoryV1 f = new OpenFactoryV1(registrar);
        assertFalse(f.zetherEnabled());
        ZetherToken z = new ZetherToken(address(f), dis);
        vm.prank(registrar);
        f.registerImplementation(IOpenFactoryV1.TokenKind.ZETHER, 1, address(z));
        vm.expectRevert(OpenFactoryV1.ZetherDisabled.selector);
        f.createZetherToken(1, address(usd), address(ver), "", "s");
        vm.expectRevert(OpenFactoryV1.ZetherDisabled.selector);
        f.createUnregistered(IOpenFactoryV1.TokenKind.ZETHER, address(z), address(usd), address(ver), "", "s");
    }

    function test_cannotEnableOnNonDevChain() public {
        uint256[4] memory prod = [uint256(1), 100, 42220, 7622];
        for (uint256 i; i < prod.length; ++i) {
            vm.chainId(prod[i]);
            OpenFactoryV1 f = new OpenFactoryV1(registrar);
            vm.prank(registrar);
            vm.expectRevert(abi.encodeWithSelector(ZetherSafety.ZetherNotDevChain.selector, prod[i]));
            f.setZetherEnabled(true);
            vm.prank(registrar);
            f.setZetherEnabled(false); // tắt luôn được
        }
    }

    function test_onlyRegistrarToggles() public {
        vm.expectRevert(OpenFactoryV1.NotRegistrar.selector);
        factory.setZetherEnabled(false);
    }

    /// Bật trên chain dev rồi chain đổi id (fork/replay deploy): tạo token vẫn bị chặn.
    function test_flagDoesNotSurviveChainIdChange() public {
        vm.chainId(100);
        vm.expectRevert(abi.encodeWithSelector(ZetherSafety.ZetherNotDevChain.selector, 100));
        factory.createZetherToken(1, address(usd), address(ver), "", "s2");
    }

    function test_verifiersOnlyDeployOnDevChain() public {
        vm.chainId(1);
        vm.expectRevert(abi.encodeWithSelector(ZetherSafety.ZetherNotDevChain.selector, 1));
        new ZetherVerifierBn254();
        vm.expectRevert(abi.encodeWithSelector(ZetherSafety.ZetherNotDevChain.selector, 1));
        new ZetherVerifierBls12381();
    }

    function test_devChain1337Allowed() public {
        vm.chainId(1337);
        OpenFactoryV1 f = new OpenFactoryV1(registrar);
        vm.prank(registrar);
        f.setZetherEnabled(true);
        assertTrue(f.zetherEnabled());
    }

    function test_provenanceRecorded() public view {
        assertEq(address(tok.verifier()), address(ver));
        assertEq(tok.registry(), address(reg));
        assertEq(tok.factory(), address(factory));
        assertEq(tok.implementation(), address(impl));
        assertEq(tok.version(), 1);
        assertEq(tok.creator(), address(this));
        assertEq(tok.underlying(), address(usd));
        assertEq(tok.decimals(), 6);
        assertEq(tok.shieldScale(), SCALE);
        assertEq(tok.confidentialFee(), FEE);
        assertEq(tok.maxDecryptableShielded(), uint256(1) << 40);
        assertEq(tok.auditorKey().length, 0);
        assertEq(tok.name(), "Zether USD");
        assertEq(tok.symbol(), "zUSD");
        (IOpenFactoryV1.TokenKind k, uint64 v) = factory.versionOf(address(tok));
        assertEq(uint8(k), uint8(IOpenFactoryV1.TokenKind.ZETHER));
        assertEq(v, 1);
    }
}
