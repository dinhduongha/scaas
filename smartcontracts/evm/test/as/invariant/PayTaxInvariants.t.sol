// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {RegFixture} from "../helpers/RegFixture.sol";
import {PayTaxHandler} from "./PayTaxHandler.t.sol";
import {OpenFactory} from "../../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {NormalRegulatedToken} from "../../../src/regulated/NormalRegulatedToken.sol";
import {GovernanceBits} from "../../../src/governance/GovernanceBits.sol";
import {Catalogue, plainEnv, regArgs} from "../../helpers/Catalogue.sol";
import {nid} from "../../helpers/Ids.sol";
import {EnvKit} from "../../helpers/EnvKit.sol";

/// @notice Pay-meta-tax spec §13 (plan T43) over `PayTaxHandler` on kind 8 with `TAX` and a 3-day notice: J1 every landed
///         pay entry carries one `PaymentMeta` for its `entryRef`, before its settled event; J2 a pay signature never
///         lands twice (`mtxPay`, `mtxPayWithTax`, and a pay signature replayed as `mtxExecuteTransfer`); J3 the books of
///         both tax entries; J4 a PERCENT tax is the floor at the effective rate (any other value reverts, and the suite
///         fails on a revert) and the effective rate never rises before `eta`; J5 the tax leg goes to the configured
///         recipient, never 0, a pool, the token or the payee, at most the value; `Σ balances == totalSupply`. Not here:
///         J6 is `PlusZero.t.sol`; J7 is `TaxConfidential.t.sol` (`vm.accesses` on a shield, a shielded transfer and an
///         unshield of 10-13 with `TAX` set; the handlers of 10-13 have no tax entry to drive); J8 is `RelayFeeRouter.t.sol`.
///         **UNAUDITED.**
contract PayTaxInvariants is RegFixture {
    uint64 internal constant NOTICE = 3 days;
    PayTaxHandler internal h;
    address internal tok;

    function setUp() public override {
        super.setUp();
        OpenFactory fN = EnvKit.factory(address(this), UID, NOTICE);
        Catalogue.release(fN, IOpenFactory.TokenKind.NORMAL_REGULATED, 1, plainEnv(address(fN), address(0), UID,
            address(ureg), false), type(NormalRegulatedToken).creationCode, regArgs());
        fN.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_REGULATED, true);
        vm.warp(block.timestamp + NOTICE);
        IFactoryToken.TokenConfig memory c = _cfg8();
        c.features |= 1 << GovernanceBits.TAX;
        c.reg.taxRecipient = nid(address(0x7A0));
        tok = fN.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(c), "inv");
        h = new PayTaxHandler(tok, issuer, address(0x7A0), address(0x7A1));
        for (uint256 i; i < 3; ++i) {
            address e = h.eoas(i); // read first: a prank is spent by the next external call
            vm.prank(alice);
            IERC20(tok).transfer(e, 100_000);
        }
        targetContract(address(h));
    }

    function _ok(uint256 j) internal view {
        assertEq(h.vio(j), 0, h.why());
    }

    function invariant_J1_payMetaBeforeSettled() public view { _ok(1); }
    function invariant_J2_oneLanding() public view { _ok(2); }
    function invariant_J3_books() public view { _ok(3); }
    function invariant_J4_rate() public view { _ok(4); }
    function invariant_J5_taxLeg() public view { _ok(5); }

    function invariant_supply() public view {
        uint256 s = IERC20(tok).balanceOf(alice) + IERC20(tok).balanceOf(h.recipient(0)) + IERC20(tok).balanceOf(h.recipient(1));
        for (uint256 i; i < 3; ++i) s += IERC20(tok).balanceOf(h.eoas(i));
        assertEq(s, IERC20(tok).totalSupply(), "supply");
    }

    function afterInvariant() public view {
        for (uint256 j = 1; j <= 6; ++j) console.log("J", j, "checks", h.hits(j));
    }
}
