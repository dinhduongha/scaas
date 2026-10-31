// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ZetherFixture} from "./helpers/ZetherFixture.sol";
import {ZetherKeys} from "./helpers/ZetherKeys.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {ZetherInnerProductVerifierBls12381} from "../../src/zether/ZetherVerifier.sol";
import {ZetherSchnorrBls12381Verifier} from "../../src/ua/verifiers/PairingVerifiers.sol";

/// CTR-ZTH-52 (owner ruling 2026-10-31): with no chain-id gate, EIP-2537 is classical Zether's only chain requirement.
/// At the mainnet id 22776, an absent precompile (0x0b–0x11 answer "success, empty") must fail closed on every path.
contract ZetherNoEip2537Test is ZetherFixture {
    function setUp() public {
        vm.chainId(22776);
        _deploy(false);
    }

    function _noEip2537() internal {
        for (uint160 a = 0x0b; a <= 0x11; ++a) vm.mockCall(address(a), bytes(""), bytes(""));
    }

    function test_innerProductVerifierConstructorReverts() public {
        _noEip2537();
        vm.expectRevert();
        new ZetherInnerProductVerifierBls12381();
    }

    function test_verifierUnsupported_createTokenReverts() public {
        assertTrue(ver.isSupportedOnThisChain());
        _noEip2537();
        assertFalse(ver.isSupportedOnThisChain());
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.VerifierUnsupportedOnThisChain.selector, address(ver), "bls12-381"));
        factory.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(_cfg(false, 1 << 40)), "no-eip2537");
    }

    function test_validTransferReverts() public {
        _fund(tok, alice, 500);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, _none(), 0);
        _noEip2537();
        vm.expectRevert();
        _direct(tok, t, _none());
        vm.clearMockedCalls();
        _direct(tok, t, _none()); // the same proof passes with the precompiles
    }

    function test_schnorrVerifierAnswersFalse() public {
        ZetherSchnorrBls12381Verifier z = new ZetherSchnorrBls12381Verifier();
        bytes memory y = ZetherKeys.pub(0xA11CE, true);
        bytes32 m = keccak256("m");
        bytes memory sig = ZetherKeys.schnorr(0xA11CE, m, true);
        assertTrue(z.verify(y, m, sig));
        _noEip2537();
        assertFalse(z.verify(y, m, sig));
        assertFalse(z.verifyPop(y, m, sig));
    }
}
