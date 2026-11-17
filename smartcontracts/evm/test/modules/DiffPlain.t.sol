// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {V2Fixture} from "../v2/helpers/V2Fixture.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {LegacyDiff} from "./LegacyDiff.sol";

/// T66b §10: the differential per entry on kinds 0 (NORMAL) and 1 (WRAPPED), clones of the v2 fixture (the test plays
/// the factory): a holder with balance and allowance, the minter, the wrapper's owner, a stranger.
contract DiffPlainTest is V2Fixture, LegacyDiff {
    address internal constant HOLDER = address(0xA11CE);
    address internal constant MINTER = address(0x1111);
    address internal constant STRANGER = address(0x5757);
    NormalToken internal n;
    WrappedToken internal w;
    MockERC20 internal u;

    function setUp() public {
        n = _normal(HOLDER, 1e24, MINTER);
        vm.etch(HOLDER, hex"00"); // a contract holder and spender: the allowance rule (CTR-TOK-01)
        vm.etch(address(0xB0B), hex"00");
        vm.prank(HOLDER);
        n.approve(address(0xB0B), 1e20); // the rows' sample address
        u = new MockERC20("U", "U", 18);
        w = _single(address(u), 18, 1, 1, _fixedRate());
        u.mint(HOLDER, 1e24);
        vm.startPrank(HOLDER);
        u.approve(address(w), type(uint256).max);
        w.wrap(1e21);
        vm.stopPrank();
    }

    function _callers() internal pure returns (address[] memory c) {
        c = new address[](4);
        (c[0], c[1], c[2], c[3]) = (HOLDER, MINTER, address(0x0A11), STRANGER);
    }

    /// Positive control: the comparison fails when the other implementation differs (the normal clone against the
    /// pre-split WRAPPED release: `kind()` answers 1, `wrap` exists), and passes against its own pre-split release.
    function test_diff_control() public {
        address other = _legacyFor(address(w), 1);
        address own = _legacyFor(address(n), 0);
        this.diffWith(address(n), own, HOLDER, abi.encodeWithSignature("kind()"));
        vm.expectRevert();
        this.diffWith(address(n), other, HOLDER, abi.encodeWithSignature("kind()"));
    }

    function test_diff_normal() public {
        _diffRows(address(n), _callers());
    }

    function test_diff_wrapped() public {
        _diffRows(address(w), _callers());
    }

    function testFuzz_diff_normal(uint256 which, bytes calldata tail) public {
        _diffFuzz(address(n), HOLDER, which, tail);
    }

    function testFuzz_diff_wrapped(uint256 which, bytes calldata tail) public {
        _diffFuzz(address(w), HOLDER, which, tail);
    }
}
