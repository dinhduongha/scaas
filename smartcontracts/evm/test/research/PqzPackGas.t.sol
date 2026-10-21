// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/Test.sol";
import {PqzStatePinGasTest} from "../pqz/PqzStateGas.t.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";

/// Spike PACK (plan 5h part B, research): the relayed full transactions at parameter set (a) (n = 2304, `K_MAX` 4,096),
/// run in the size-swapped work tree of `pqz-core/pqzl/params/pa-pack/gasa.sh` (64-bit lanes, or `PACK=46` / `PACK=51`
/// for the packed layouts). Measurement only; at the repository's sizes it compiles and measures today's n = 2048.
/// Every number is the parent's `_fullTx` convention: `mtxExecute` from a fresh relayer, ABSOLUTE outer fee 7, cold
/// implementation, regular gas before refunds (intrinsic, calldata or the EIP-7976 floor, execution, the precompile
/// stand-ins) and EIP-8037 state gas apart. Precompile prices [estimate]: today's PQZL v3 rows (auditor on) × 2304 / 2048.
contract PqzPackGasTest is PqzStatePinGasTest {
    /// `mtxRollOver(alice, n)` for n = 16, 32, …, `ROLL_MAX` of the build, each from the same state (snapshot / revert;
    /// every call is its own transaction, so cold access is per call): the `ROLL_MAX` scan in one run.
    function test_pack_scanRoll() public {
        for (uint256 n = 16; n <= PqzCore.ROLL_MAX; n += 16) {
            uint256 snap = vm.snapshotState();
            console2.log("scan: relayed mtxRollOver, full transaction, fee 7, entries", n);
            (uint256 reg, uint256 st) = _fullTx(abi.encodeCall(tok.mtxRollOver, (alice, n)), 7);
            console2.log("scan row: entries / regular / state", n, reg, st);
            console2.log(reg <= CAP ? "  fits 0.75 * 2^24" : "  OVER 0.75 * 2^24");
            vm.revertToState(snap);
        }
    }

    /// op 1 BUNDLE, auditor, fee 7: R_TX proof 48,724 B (set (a) codegen), precompile 5,409,000 × 1.125.
    function test_pack_op1_relayedFullTx_freshRef() public {
        _precompiles(vm.envOr("PQZ_GAS_TX", uint256(6_085_125)));
        uint256 plen = vm.envOr("PQZ_PROOF_TX", uint256(48_724));
        console2.log("relayed op 1 BUNDLE, auditor, fresh ref, full transaction, fee 7, proof bytes", plen);
        _fullTx(_op1p(carol, 0, true, "", _proof(plen)), 7);
    }

    function test_pack_op1_relayedFullTx_materialisedNoHint() public {
        _precompiles(vm.envOr("PQZ_GAS_TX", uint256(6_085_125)));
        uint256 plen = vm.envOr("PQZ_PROOF_TX", uint256(48_724));
        console2.log("relayed op 1 BUNDLE, auditor, materialised acc, no hint, full transaction, fee 7, proof bytes", plen);
        _fullTx(_op1p(alice, PRE, true, "", _proof(plen)), 7);
    }

    /// op 7 M = 4 (G = 1): txm4 proof 52,950 B (set (a) codegen), precompile 4,121,000 × 1.125.
    function test_pack_op7_relayedFullTx_M4() public {
        _precompiles(vm.envOr("PQZ_GAS_M4", uint256(4_636_125)));
        uint256 plen = vm.envOr("PQZ_PROOF_M4", uint256(52_950));
        console2.log("relayed op 7 M = 4 BUNDLE, auditor, fresh ref, full transaction, fee 7, proof bytes", plen);
        _fullTx(_op7p(4, _proof(plen)), 7);
    }

    /// op 7 M = 8, G = 2 (today's lane format, two groups of four legs): proof 70,353 B = txm4 52,950 × 76,002 / 57,202
    /// (the 16k txm8 / txm4 codegen ratio) [estimate]; precompile today's op 7 M = 8 row 6,177,000 × 1.125 [estimate].
    function test_pack_op7_relayedFullTx_M8() public {
        _precompiles(vm.envOr("PQZ_GAS_M8", uint256(6_949_125)));
        uint256 plen = vm.envOr("PQZ_PROOF_M8", uint256(70_353));
        console2.log("relayed op 7 M = 8 (G = 2) BUNDLE, auditor, fresh ref, full transaction, fee 7, proof bytes", plen);
        _fullTx(_op7p(8, _proof(plen)), 7);
    }
}
