// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Fixtures} from "./helpers/Fixtures.sol";
import {MockERC20, FeeOnTransferERC20} from "./helpers/Mocks.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";
import {MetaTxLib} from "../src/common/MetaTxLib.sol";
import {IERC20MetaTx} from "../src/metatx/IERC20MetaTx.sol";
import {IERC20Payment} from "../src/metatx/IERC20Payment.sol";
import {FeeMode} from "../src/common/FeePolicy.sol";

contract MetaTokenTest is Fixtures {
    uint256 constant ALICE_PK = 0xA11CE;
    address alice;
    address shop = address(0x5409);
    address minterAddr = address(0x313);
    MetaToken tok;

    function setUp() public {
        vm.warp(1_800_000_000);
        alice = vm.addr(ALICE_PK);
        _deployFactory();
        tok = _standalone(address(this), "BUSD", 6, 1_000_000e6, minterAddr);
        tok.transfer(alice, 1_000e6);
    }

    // ---- Task 1: init, metadata, provenance, mint ----

    function test_implementationIsLockedAtConstruction() public {
        vm.prank(address(factory));
        vm.expectRevert(MetaToken.AlreadyInitialized.selector);
        impl.initialize(address(1), address(0), address(0), 1, "");
    }

    function test_onlyFactoryInitializes() public {
        vm.expectRevert(MetaToken.NotFactory.selector);
        tok.initialize(address(1), address(0), address(0), 1, "");
    }

    function test_cloneInitializesOnce() public {
        vm.prank(address(factory));
        vm.expectRevert(MetaToken.AlreadyInitialized.selector);
        tok.initialize(address(1), address(0), address(0), 1, "");
    }

    function test_metadataIsPerClone() public {
        MetaToken other = _standalone(address(this), "PTS", 0, 5, address(0));
        assertEq(tok.name(), "Token BUSD");
        assertEq(tok.symbol(), "BUSD");
        assertEq(tok.decimals(), 6);
        assertEq(other.symbol(), "PTS");
        assertEq(other.decimals(), 0);
    }

    function test_provenance() public view {
        assertEq(tok.factory(), address(factory));
        assertEq(tok.creator(), address(this));
        assertEq(tok.implementation(), address(impl));
        assertEq(tok.version(), 1);
        assertEq(tok.underlying(), address(0));
        assertEq(tok.verifier(), address(0));
        assertEq(tok.minter(), minterAddr);
    }

    function test_domainIsImplementationNameAndCloneAddress() public view {
        (, string memory n, string memory v, uint256 cid, address vc,,) = tok.eip712Domain();
        assertEq(n, "Bamboo MetaToken");
        assertEq(v, "1");
        assertEq(cid, block.chainid);
        assertEq(vc, address(tok));
    }

    function test_initialSupplyGoesToCreatorAndMinterMints() public {
        assertEq(tok.totalSupply(), 1_000_000e6);
        vm.prank(minterAddr);
        tok.mint(shop, 7);
        assertEq(tok.balanceOf(shop), 7);
    }

    function test_nonMinterCannotMint() public {
        vm.expectRevert(MetaToken.NotMinter.selector);
        tok.mint(shop, 7);
    }

    function test_zeroMinterMeansFixedSupply() public {
        MetaToken fixedTok = _standalone(address(this), "FIX", 0, 10, address(0));
        vm.prank(address(0));
        vm.expectRevert(MetaToken.NotMinter.selector);
        fixedTok.mint(shop, 1);
    }
}
