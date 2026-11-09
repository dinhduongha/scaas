// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {nid} from "../helpers/Ids.sol";
import {LegacyDiff} from "./LegacyDiff.sol";
import {Catalogue} from "../helpers/Catalogue.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";

/// T66b §10: the differential per entry on the Zether kinds 2 and 3 (the Zether fixture's stack, auditor on).
contract DiffZetherTest is ZetherFixture, LegacyDiff {
    address internal n;
    address internal w;

    function setUp() public {
        _deploy(true);
        n = address(_newToken(true, "dn"));
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, _zenv(), type(WrappedZetherToken).creationCode);
        MockERC20 u = new MockERC20("USD", "USD", 6);
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals) = ("Z", "Z", 6);
        c.features = (1 << GovernanceBits.PAYABLE) | (1 << GovernanceBits.RATE_ADJUSTABLE);
        c.roles.rateAdmin = nid(address(this));
        c.lockedFeatures = 1 << GovernanceBits.RATE_ADJUSTABLE;
        c.rate = IFactoryToken.RateConfig(2 days, 1000);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(u), 1, 1);
        c.conf = IFactoryToken.ConfidentialConfig("", SCALE, 1 << 30, FEE, 0, 0, 1, 0, bytes32(0), false, 0);
        w = factory.createToken(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, abi.encode(c), "dw");
        vm.etch(address(0xB0B), hex"00");
    }

    function _callers() internal view returns (address[] memory c) {
        c = new address[](4);
        (c[0], c[1], c[2], c[3]) = (address(this), registrar, relayer, address(0x5757));
    }

    function test_diff_normalZether() public {
        _diffRows(n, _callers());
    }

    function test_diff_wrappedZether() public {
        _diffRows(w, _callers());
    }

    function testFuzz_diff_zether(bool wrapped, uint256 which, bytes calldata tail) public {
        _diffFuzz(wrapped ? w : n, address(this), which, tail);
    }
}
