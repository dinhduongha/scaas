// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Fixtures} from "./helpers/Fixtures.sol";
import {SupportedVerifier, UnsupportedVerifier, MockZetherImpl, MockERC20} from "./helpers/Mocks.sol";
import {IOpenFactoryV1} from "../src/common/IOpenFactoryV1.sol";
import {OpenFactoryV1} from "../src/factory/OpenFactoryV1.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";

contract OpenFactoryTest is Fixtures {
    IOpenFactoryV1.TokenKind constant META = IOpenFactoryV1.TokenKind.META;
    IOpenFactoryV1.TokenKind constant ZETHER = IOpenFactoryV1.TokenKind.ZETHER;
    bytes init = abi.encode("Points", "PTS", uint8(0), uint256(100), address(0));

    function setUp() public { _deployFactory(); }

    function test_onlyRegistrarRegisters() public {
        vm.expectRevert(OpenFactoryV1.NotRegistrar.selector);
        factory.registerImplementation(META, 2, address(impl));
    }

    function test_catalogueIsAppendOnly() public {
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactoryV1.VersionAlreadyRegistered.selector, META, 1, address(impl)));
        factory.registerImplementation(META, 1, address(0x1234));
    }

    function test_versionZeroIsReservedForUnregistered() public {
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactoryV1.VersionUnknown.selector, META, 0));
        factory.registerImplementation(META, 0, address(impl));
    }

    function test_implementationMustHaveCode() public {
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactoryV1.ImplementationNotAContract.selector, address(0x1234)));
        factory.registerImplementation(META, 2, address(0x1234));
    }

    function test_deprecateMarksButDoesNotBlock() public {
        vm.prank(registrar);
        factory.deprecate(META, 1, "bug #1");
        assertTrue(factory.isDeprecated(META, 1));
        address t = factory.createMetaToken(1, address(0), init, bytes32("s"));
        assertTrue(factory.isDeployedHere(t));
    }

    function test_deprecateUnknownVersionReverts() public {
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactoryV1.VersionUnknown.selector, META, 7));
        factory.deprecate(META, 7, "x");
    }

    function test_unknownVersionReverts() public {
        vm.expectRevert(abi.encodeWithSelector(IOpenFactoryV1.VersionUnknown.selector, META, 9));
        factory.createMetaToken(9, address(0), init, bytes32("s"));
    }

    function test_predictMatchesDeployedAndProvenanceIsRecorded() public {
        address predicted = factory.predictAddress(address(impl), address(this), bytes32("s"));
        address t = factory.createMetaToken(1, address(0), init, bytes32("s"));
        assertEq(t, predicted);
        assertEq(factory.creatorOf(t), address(this));
        (IOpenFactoryV1.TokenKind k, uint64 v) = factory.versionOf(t);
        assertEq(uint8(k), uint8(META));
        assertEq(v, 1);
        assertEq(factory.latestVersion(META), 1);
        assertEq(factory.implementationOf(META, 1), address(impl));
    }

    function test_saltIsScopedByCreator() public {
        address a = factory.createMetaToken(1, address(0), init, bytes32("s"));
        vm.prank(address(0xB0B));
        address b = factory.createMetaToken(1, address(0), init, bytes32("s"));
        assertTrue(a != b);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactoryV1.SaltAlreadyUsed.selector, a));
        factory.createMetaToken(1, address(0), init, bytes32("s"));
    }

    function test_wrapperLookupIsPerCreator() public {
        MockERC20 dai = new MockERC20("Dai", "DAI", 18);
        bytes memory w = abi.encode("zDAI", "zDAI", uint8(0), uint256(0), address(0));
        address a1 = factory.createMetaToken(1, address(dai), w, bytes32("1"));
        address a2 = factory.createMetaToken(1, address(dai), w, bytes32("2"));
        vm.prank(address(0xB0B));
        address b1 = factory.createMetaToken(1, address(dai), w, bytes32("1"));
        assertEq(factory.getWrapper(address(this), address(dai)), a1);
        assertEq(factory.getWrapperCount(address(this), address(dai)), 2);
        assertEq(factory.getWrapperAt(address(this), address(dai), 1), a2);
        assertEq(factory.getWrapper(address(0xB0B), address(dai)), b1);
        assertEq(factory.getWrapper(address(0xC0C), address(dai)), address(0));
        assertEq(factory.deployCountFor(address(dai)), 3);
        assertEq(factory.deployedFor(address(dai), 2), b1);
    }

    function test_standaloneTokensAreNotWrappers() public {
        factory.createMetaToken(1, address(0), init, bytes32("s"));
        assertEq(factory.getWrapper(address(this), address(0)), address(0));
        assertEq(factory.deployCountFor(address(0)), 0);
    }

    function test_createUnregisteredIsVersionZero() public {
        address t = factory.createUnregistered(META, address(impl), address(0), address(0), init, bytes32("u"));
        (, uint64 v) = factory.versionOf(t);
        assertEq(v, 0);
        assertEq(MetaToken(t).version(), 0);
    }

    function test_createUnregisteredNeedsCode() public {
        vm.expectRevert(abi.encodeWithSelector(IOpenFactoryV1.ImplementationNotAContract.selector, address(0x77)));
        factory.createUnregistered(META, address(0x77), address(0), address(0), init, bytes32("u"));
    }

    function test_metaTokenRefusesAVerifier() public {
        vm.expectRevert(MetaToken.VerifierNotAllowed.selector);
        factory.createUnregistered(META, address(impl), address(0), address(0x5), init, bytes32("u"));
    }

    function test_zetherNeedsAVerifier() public {
        MockZetherImpl z = new MockZetherImpl(address(factory));
        _enableZether();
        vm.prank(registrar);
        factory.registerImplementation(ZETHER, 1, address(z));
        vm.expectRevert(IOpenFactoryV1.VerifierRequiredForZether.selector);
        factory.createZetherToken(1, address(0), address(0), "", bytes32("z"));
    }

    function test_zetherRefusesAVerifierThisChainCannotRun() public {
        MockZetherImpl z = new MockZetherImpl(address(factory));
        UnsupportedVerifier bad = new UnsupportedVerifier();
        _enableZether();
        vm.prank(registrar);
        factory.registerImplementation(ZETHER, 1, address(z));
        vm.expectRevert(abi.encodeWithSelector(
            IOpenFactoryV1.VerifierUnsupportedOnThisChain.selector, address(bad), "bls12-381"));
        factory.createZetherToken(1, address(0), address(bad), "", bytes32("z"));
    }

    function test_zetherVerifierWithNoCodeIsRefused() public {
        MockZetherImpl z = new MockZetherImpl(address(factory));
        _enableZether();
        vm.prank(registrar);
        factory.registerImplementation(ZETHER, 1, address(z));
        vm.expectRevert(abi.encodeWithSelector(
            IOpenFactoryV1.VerifierUnsupportedOnThisChain.selector, address(0x99), ""));
        factory.createZetherToken(1, address(0), address(0x99), "", bytes32("z"));
    }

    function test_zetherWithSupportedVerifier() public {
        MockZetherImpl z = new MockZetherImpl(address(factory));
        SupportedVerifier ok = new SupportedVerifier();
        _enableZether();
        vm.prank(registrar);
        factory.registerImplementation(ZETHER, 1, address(z));
        address t = factory.createZetherToken(1, address(0), address(ok), "", bytes32("z"));
        assertEq(MockZetherImpl(t).verifier(), address(ok));
    }

    function _enableZether() internal {
        vm.prank(registrar);
        factory.setZetherEnabled(true);
    }
}
