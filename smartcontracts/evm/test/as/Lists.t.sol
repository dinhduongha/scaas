// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ListFixture, IListOps} from "./helpers/ListFixture.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {UAMetaTxBase} from "../../src/metatx/UAMetaTxBase.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {nid} from "../helpers/Ids.sol";

/// A contract party: it holds the token and pays several recipients in one call (spec A21, Fable R-5: a `Distribution`-like
/// payout reverts as a whole when one recipient is blocked by a list).
contract Payout {
    function pay(address t, address[] calldata to, uint256 v) external {
        for (uint256 i; i < to.length; ++i) IERC20(t).transfer(to[i], v);
    }
}

/// Round 3s, spec 2026-11-10-token-lists.md §4.2, §4.3, §13 (1): on kinds 8 and 9, under `ALLOWLIST` and under `DENYLIST`, each
/// party of each public path in turn blocked (unlisted / denied), each refusal with its positive control (the same call once
/// the party is open). `L` is two-sided: senders, payers and fee recipients as well as receivers; never a forced transfer's
/// subject nor the unwrap recipient.
contract ListsTest is ListFixture {
    bytes32 a;
    bytes32 b;
    Payout payout;

    function setUp() public override {
        super.setUp();
        (a, b) = (nid(alice), nid(bob));
        payout = new Payout();
    }

    /// Each kind (8, 9) under each list (8, 9): the token, `bob` open on it.
    function _each(uint256 k) internal returns (address t, uint8 bit) {
        uint256 i = k / 2;
        bit = k % 2 == 0 ? ALLOW : DENY;
        t = _lt(i, uint256(1) << bit, 0, bytes32(k + 1));
        if (bit == ALLOW) _open(t, bit, b);
    }

    function _transfer(address t, address from, address to, uint256 v, bytes memory err) internal {
        vm.prank(from);
        if (err.length != 0) vm.expectRevert(err);
        IERC20(t).transfer(to, v);
    }

    /// `transfer`: `L(from)` and `L(to)` (`_regMove`).
    function test_transfer_bothParties() public {
        for (uint256 k; k < 4; ++k) {
            (address t, uint8 bit) = _each(k);
            _transfer(t, alice, bob, 1, ""); // control
            _block(t, bit, b);
            _transfer(t, alice, bob, 1, _err(bit, b));
            _open(t, bit, b);
            _block(t, bit, a);
            _transfer(t, alice, bob, 1, _err(bit, a));
            _open(t, bit, a);
            _transfer(t, alice, bob, 1, "");
            assertEq(IERC20(t).balanceOf(bob), 2);
        }
    }

    /// A contract is listed like anyone else (§4.4): a contract sender and a contract receiver.
    function test_contractParties() public {
        for (uint256 k; k < 4; ++k) {
            (address t, uint8 bit) = _each(k);
            bytes32 p = nid(address(payout));
            _open(t, bit, p);
            _transfer(t, alice, address(payout), 10, "");
            _block(t, bit, p);
            _transfer(t, alice, address(payout), 1, _err(bit, p));
            address[] memory to = new address[](1);
            to[0] = bob;
            vm.expectRevert(_err(bit, p));
            payout.pay(t, to, 1);
            _open(t, bit, p);
            payout.pay(t, to, 1);
        }
    }

    /// A21, Fable R-5: a payout to several recipients in one call reverts as a whole when one is blocked; it passes once the
    /// recipient is open, or left out.
    function test_multiRecipientPayout_revertsAsAWhole() public {
        for (uint256 k; k < 4; ++k) {
            (address t, uint8 bit) = _each(k);
            _open(t, bit, nid(address(payout)));
            _transfer(t, alice, address(payout), 10, "");
            address carol = address(0xCA201);
            _open(t, bit, nid(carol));
            address[] memory to = new address[](2);
            (to[0], to[1]) = (carol, bob);
            _block(t, bit, b);
            vm.expectRevert(_err(bit, b));
            payout.pay(t, to, 1);
            assertEq(IERC20(t).balanceOf(carol), 0, "nothing paid");
            address[] memory one = new address[](1);
            one[0] = carol;
            payout.pay(t, one, 1); // bob left out
            _open(t, bit, b);
            payout.pay(t, to, 1);
            assertEq(IERC20(t).balanceOf(carol), 2);
            assertEq(IERC20(t).balanceOf(bob), 1);
        }
    }

    /// The mint (kind 8, this test the minter): `L(to)`.
    function test_mint_receiver() public {
        for (uint256 k; k < 2; ++k) {
            (address t, uint8 bit) = _each(k);
            _block(t, bit, b);
            vm.expectRevert(_err(bit, b));
            NormalToken(t).mint(bob, 1);
            _open(t, bit, b);
            NormalToken(t).mint(bob, 1);
        }
    }

    /// A holder's exit (A19): the burn (kind 8) and the burn inside unwrap (kind 9) check `L(from)`; the unwrap recipient is
    /// never checked (M27).
    function test_exit_holderChecked_unwrapRecipientNot() public {
        for (uint256 k; k < 4; ++k) {
            (address t, uint8 bit) = _each(k);
            _block(t, bit, a);
            vm.prank(alice);
            vm.expectRevert(_err(bit, a));
            if (k < 2) NormalToken(t).burn(1);
            else WrappedToken(payable(t)).unwrap(1, alice);
            _open(t, bit, a);
            _block(t, bit, b); // the recipient blocked: not checked
            uint256 before = usd.balanceOf(bob);
            vm.prank(alice);
            if (k < 2) {
                NormalToken(t).burn(1);
            } else {
                WrappedToken(payable(t)).unwrap(1, bob);
                assertEq(usd.balanceOf(bob), before + 1, "the unwrap recipient is not checked");
            }
        }
    }

    /// `_regPre` (CTR-AS-27, M3): a relayed op of a blocked `from` with a garbage signature stops before the signature is
    /// read; the control, `from` open, fails in the pipeline with another error.
    function test_pre_blockedFromBeforeSignature() public {
        for (uint256 k; k < 4; ++k) {
            (address t, uint8 bit) = _each(k);
            MetaTxLib.UAMetaTransfer memory x;
            (x.from, x.to, x.value, x.batch, x.validUntil) = (b, a, 1, 1, block.timestamp + 60);
            bytes memory c0 = abi.encodeCall(NormalToken.mtxExecuteTransfer, (x, _bad()));
            MetaTxLib.UAEnvelope memory e = MetaTxLib.UAEnvelope(b, 3, 0, block.timestamp + 60, 0, address(0), 0, address(0));
            bytes memory c1 = abi.encodeCall(UAMetaTxBase.mtxCancelNonce, (e, 9, _bad()));
            bytes4 sel = bit == ALLOW ? NOT_ALLOWED : DENIED_ERR;
            assertTrue(_try(t, c0) != sel && _try(t, c1) != sel, "control: open");
            _block(t, bit, b);
            assertEq(_try(t, c0), sel, "transfer: before the signature");
            assertEq(_try(t, c1), sel, "cancelNonce: before the signature");
        }
    }

    /// The envelope's fee leg (`_regFeeTo` → `_feeRecipient`, CTR-AS-25): `L(feeTo)` before effects.
    function test_feeLeg_relayerChecked() public {
        for (uint256 k; k < 4; ++k) {
            (address t, uint8 bit) = _each(k);
            MetaTxLib.UAMetaTransfer memory x;
            (x.from, x.to, x.value, x.batch, x.validUntil, x.mode, x.fee) =
                (a, b, 100, 1, block.timestamp + 60, MetaTxLib.MODE_FEE_FIXED, 1);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, NormalToken(t).mtxTransferDigest(x));
            IUARegistry.UASig memory sig;
            sig.signature = abi.encodePacked(r, s, v);
            if (bit == DENY) _block(t, bit, nid(relayer)); // under ALLOWLIST the relayer starts unlisted
            vm.prank(relayer);
            vm.expectRevert(_err(bit, nid(relayer)));
            NormalToken(t).mtxExecuteTransfer(x, sig);
            _open(t, bit, nid(relayer));
            vm.prank(relayer);
            NormalToken(t).mtxExecuteTransfer(x, sig);
            assertEq(IERC20(t).balanceOf(relayer), 1);
        }
    }

    /// `forceTransfer` (M7, M8): never `L(subject)` (the remedy reaches a blocked account), always `L(beneficiary)`.
    function test_forceTransfer_subjectNever_beneficiaryChecked() public {
        for (uint256 k; k < 4; ++k) {
            (address t, uint8 bit) = _each(k);
            bytes32 r = _order(t, "o1", a, b, 100, _now() + 90 days);
            _freeze(t, a);
            _block(t, bit, a);
            vm.prank(issuer);
            _r(t).forceTransfer(r, 10); // the blocked subject: not checked
            assertEq(IERC20(t).balanceOf(bob), 10);
            _block(t, bit, b);
            vm.prank(issuer);
            vm.expectRevert(_err(bit, b));
            _r(t).forceTransfer(r, 10);
        }
    }

    /// `canReceive` (§4.3): `L` first, 5 not on the allow list, 6 on the deny list; (true, 0) once open.
    function test_canReceive_reasons() public {
        for (uint256 k; k < 4; ++k) {
            (address t, uint8 bit) = _each(k);
            (bool ok, uint8 why) = _r(t).canReceive(b);
            assertTrue(ok);
            assertEq(why, 0);
            _block(t, bit, b);
            (ok, why) = _r(t).canReceive(b);
            assertFalse(ok);
            assertEq(why, bit == ALLOW ? 5 : 6);
        }
    }

    /// `listFlagsOf`: one byte, `ALLOWED` 1 and `DENIED` 2; the lists read no registry (no `KYC`: no call).
    function test_listFlagsOf_noRegistryCall() public {
        for (uint256 k; k < 4; ++k) {
            (address t, uint8 bit) = _each(k);
            _setList(t, ALLOW, b, true);
            _setList(t, DENY, b, true);
            assertEq(_flags(t, b), ALLOWED | DENIED);
            _setList(t, DENY, b, false);
            assertEq(_flags(t, b), ALLOWED);
            if (bit == DENY) _setList(t, ALLOW, b, false);
            _countStart();
            _transfer(t, alice, bob, 1, "");
            assertEq(_countEnd(0), 0, "no registry call");
        }
    }
}
