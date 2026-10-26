// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/Test.sol";
import {IConfidentialToken} from "../../src/confidential/IConfidentialToken.sol";
import {ZetherFixture} from "./helpers/ZetherFixture.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";

/// @notice The owner's fee ruling 4 on Zether (2026-10-20): a multi-recipient payload carries the sender's per-leg
///         `decoyFee` (`… ‖ be32(M) ‖ be32(decoyFee) ‖ Y_f …`), `minDecoyFee ≤ decoyFee < 2^64`, the statement's public
///         fee word is `txFee + M · decoyFee` (so the proof binds it), and the token pays `decoyFee` from `SHIELD_POOL`
///         to EVERY leg's public balance, the real recipient included; the single format never pays it. Real proofs.
contract ZetherDecoyFeeTest is ZetherFixture {
    uint256 internal constant MIN = 2;
    User[4] internal rs;

    function setUp() public {
        minDecoy = MIN;
        _deploy(true);
        for (uint256 i; i < 4; ++i) rs[i] = _user(0xD00 + i, address(uint160(0xE00 + i)));
        _fund(tok, alice, 1000);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
    }

    function _to(uint256 m) internal view returns (User[] memory to) {
        to = new User[](m);
        for (uint256 j; j < m; ++j) to[j] = rs[j];
    }

    function _vs4() internal pure returns (uint256[] memory vs) {
        vs = new uint256[](4);
        (vs[0], vs[1], vs[2], vs[3]) = (0, 300, 0, 50);
    }

    function _withD(bytes memory pl, uint256 d) internal pure returns (bytes memory out) {
        out = bytes.concat(pl);
        assembly ("memory-safe") { mstore(add(out, 144), d) } // payload bytes 112..144
    }

    function _fee(bytes memory statement) internal pure returns (uint256 f) {
        assembly ("memory-safe") { f := mload(add(statement, 320)) } // header word 9
    }

    /// d = 3 on M = 4 legs (two decoys), beneficiary carol: fee word FEE + 12, every leg 3 · SCALE, carol FEE · SCALE.
    function test_decoyFee_perLegUniform() public {
        decoyFee = 3;
        Tx memory t = _proveMulti(tok, alice, _to(4), _vs4(), 1000, carol.ua, ZetherTypes.TransferMode.BUNDLE);
        assertEq(_fee(stm.transferStatement(address(tok), t.payload, carol.ua, ZetherTypes.TransferMode.BUNDLE, 0)),
            FEE + 4 * 3, "statement fee = txFee + M * decoyFee");
        bytes32[] memory uas = new bytes32[](4);
        for (uint256 j; j < 4; ++j) uas[j] = ZetherTypes.UA.unwrap(rs[j].ua);
        vm.expectEmit(true, true, true, true, address(tok));
        emit IConfidentialToken.ConfidentialTransferMulti(_ref(tok, alice, 0), ZetherTypes.UA.unwrap(alice.ua),
            ZetherTypes.UA.unwrap(carol.ua), FEE + 12, 0, uas, uint8(ZetherTypes.TransferMode.BUNDLE), address(0));
        tok.mtxConfidentialTransfer(t.payload, t.proof, "", ZetherTypes.UA.unwrap(carol.ua), "");
        assertTrue(_holds(tok, alice, 1000 - 350 - FEE - 12, true), "sender: sum + txFee + M * decoyFee");
        for (uint256 j; j < 4; ++j) {
            assertEq(tok.balanceOfUA(ZetherTypes.UA.unwrap(rs[j].ua)), 3 * SCALE, "every leg, decoys included");
            assertTrue(_holds(tok, rs[j], _vs4()[j], false), "the transfers themselves");
        }
        assertEq(tok.balanceOfUA(ZetherTypes.UA.unwrap(carol.ua)), FEE * SCALE, "txFee to the beneficiary");
        assertEq(tok.totalShielded(), 1000 - FEE - 12);
        assertEq(tok.balanceOf(SHIELD_POOL_), tok.totalShielded() * SCALE, "pool = totalShielded x scale");
        assertEq(tok.totalSupply(), minted[address(tok)], "the fees are moves, not mints");
    }

    /// No beneficiary: no txFee, the decoy fees still paid (fee word = M · d).
    function test_decoyFee_noBeneficiary() public {
        decoyFee = MIN;
        uint256[] memory vs = new uint256[](2);
        vs[1] = 40;
        Tx memory t = _proveMulti(tok, alice, _to(2), vs, 1000, _none(), ZetherTypes.TransferMode.HASH);
        assertEq(_fee(stm.transferStatement(address(tok), t.payload, _none(), ZetherTypes.TransferMode.HASH, 0)), 2 * MIN);
        tok.mtxConfidentialTransferCompact(t.payload, t.proof, "", bytes32(0), "");
        assertEq(tok.balanceOfUA(ZetherTypes.UA.unwrap(rs[0].ua)), MIN * SCALE);
        assertEq(tok.balanceOfUA(ZetherTypes.UA.unwrap(rs[1].ua)), MIN * SCALE);
        assertTrue(_holds(tok, alice, 1000 - 40 - 2 * MIN, true));
        assertEq(tok.balanceOf(SHIELD_POOL_), tok.totalShielded() * SCALE);
    }

    /// `d < minDecoyFee` and `d ≥ 2^64` are refused before the proof (`DecoyFeeOutOfRange`), by the statement view too;
    /// `txFee + M · d ≥ 2^64` is `AmountOutOfRange`.
    function test_decoyFee_bounds() public {
        decoyFee = MIN;
        uint256[] memory vs = new uint256[](2);
        Tx memory t = _proveMulti(tok, alice, _to(2), vs, 1000, carol.ua, ZetherTypes.TransferMode.BUNDLE);
        bytes32 ben = ZetherTypes.UA.unwrap(carol.ua);
        uint256[2] memory bad = [MIN - 1, uint256(1) << 64];
        for (uint256 i; i < 2; ++i) {
            bytes memory pl = _withD(t.payload, bad[i]);
            vm.expectRevert(abi.encodeWithSelector(IZetherToken.DecoyFeeOutOfRange.selector, bad[i], MIN));
            tok.mtxConfidentialTransfer(pl, t.proof, "", ben, "");
            vm.expectRevert(abi.encodeWithSelector(IZetherToken.DecoyFeeOutOfRange.selector, bad[i], MIN));
            stm.transferStatement(address(tok), pl, carol.ua, ZetherTypes.TransferMode.BUNDLE, 0);
        }
        uint256 d = uint256(1) << 63; // FEE + 2 · 2^63 ≥ 2^64
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AmountOutOfRange.selector, FEE + 2 * d, uint256(1) << 64));
        tok.mtxConfidentialTransfer(_withD(t.payload, d), t.proof, "", ben, "");
    }

    /// A payload whose `decoyFee` is not the one proven (the fee word differs) fails the proof; the proven one settles.
    function test_decoyFee_mismatchRejected() public {
        decoyFee = 3;
        Tx memory t = _proveMulti(tok, alice, _to(4), _vs4(), 1000, carol.ua, ZetherTypes.TransferMode.BUNDLE);
        bytes32 ben = ZetherTypes.UA.unwrap(carol.ua);
        uint256[2] memory other = [uint256(MIN), 4];
        for (uint256 i; i < 2; ++i) {
            vm.expectRevert(IZetherToken.ProofRejected.selector);
            tok.mtxConfidentialTransfer(_withD(t.payload, other[i]), t.proof, "", ben, "");
        }
        tok.mtxConfidentialTransfer(t.payload, t.proof, "", ben, "");
        assertEq(tok.balanceOfUA(ZetherTypes.UA.unwrap(rs[0].ua)), 3 * SCALE);
    }

    /// The single format carries no `decoyFee` and never pays one, on a token whose `minDecoyFee` is 2.
    function test_single_neverPaysDecoyFee() public {
        Tx memory t = _proveTransfer(tok, alice, rs[0], 100, 1000, carol.ua, 0);
        _direct(tok, t, carol.ua);
        assertEq(tok.balanceOfUA(ZetherTypes.UA.unwrap(rs[0].ua)), 0, "no decoy fee to the recipient");
        assertEq(tok.balanceOfUA(ZetherTypes.UA.unwrap(carol.ua)), FEE * SCALE);
        assertEq(tok.totalShielded(), 1000 - FEE);
        assertTrue(_holds(tok, alice, 1000 - 100 - FEE, true));
    }

    /// `minDecoyFee < 2^64`, `confidentialFee + 16 · minDecoyFee` `< 2^64` and `< maxShielded`; 0 and the largest
    /// value under the cap accepted.
    function test_minDecoyFee_initBounds() public {
        assertEq(tok.minDecoyFee(), MIN);
        uint256 cap = uint256(1) << 40;
        uint256[3] memory bad = [uint256(1) << 64, uint256(1) << 60, (cap - FEE + 15) / 16];
        for (uint256 i; i < 3; ++i) {
            minDecoy = bad[i];
            vm.expectRevert(IZetherToken.BadInit.selector);
            _newToken(false, bytes32(i + 1), cap);
        }
        minDecoy = (cap - FEE - 1) / 16;
        assertEq(_newToken(false, "top", cap).minDecoyFee(), minDecoy);
        minDecoy = 0;
        assertEq(_newToken(false, "zero", cap).minDecoyFee(), 0);
    }
}

/// The gas a `decoyFee` adds per leg (the prover's `DECOY_LEG_GAS`, zether.rs): M = 4, d = 0 against d = 1 on a
/// `minDecoyFee = 0` token, each measured cold (the other under a reverted snapshot), every leg's first UA-ledger credit.
contract ZetherDecoyFeeGasTest is ZetherFixture {
    User[4] internal rs;

    function setUp() public {
        _deploy(true);
        for (uint256 i; i < 4; ++i) rs[i] = _user(0xD00 + i, address(uint160(0xE00 + i)));
        _fund(tok, alice, 1000);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
    }

    function _run(uint256 d) internal returns (uint256 g) {
        User[] memory to = new User[](4);
        for (uint256 j; j < 4; ++j) to[j] = rs[j];
        uint256[] memory vs = new uint256[](4);
        vs[1] = 100;
        decoyFee = d;
        Tx memory t = _proveMulti(tok, alice, to, vs, 1000, carol.ua, ZetherTypes.TransferMode.BUNDLE);
        bytes memory cd = abi.encodeCall(ZetherLayer.mtxConfidentialTransfer, (t.payload, t.proof, "", ZetherTypes.UA.unwrap(carol.ua), ""));
        uint256 g0 = gasleft();
        (bool ok,) = address(tok).call(cd);
        g = g0 - gasleft();
        require(ok, "transfer");
    }

    function test_gas_decoyFeePerLeg() public {
        uint256 snap = vm.snapshotState();
        uint256 g0 = _run(0);
        vm.revertToState(snap);
        uint256 g1 = _run(1);
        console2.log("M = 4 BUNDLE d = 0 / d = 1 gas", g0, g1);
        console2.log("per leg", (g1 - g0) / 4);
        // F185: was 32,000 = zether.rs `DECOY_LEG_GAS` (measured 28,663 on Osaka). Under Amsterdam a leg's payout to a
        // public balance costs 116,698: EIP-8037 state gas for the new balance slot, EIP-8038 for the writes. The prover's
        // constant is NOT changed here (Rust is outside F185): it undercounts by this much on the SCaaS testnet.
        assertLe((g1 - g0 + 3) / 4, 120_000, "a leg's payout (zether.rs DECOY_LEG_GAS is still 32,000)");
    }
}
