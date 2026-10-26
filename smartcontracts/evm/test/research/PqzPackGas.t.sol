// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/Test.sol";
import {PqzStatePinGasTest} from "../pqz/PqzStateGas.t.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";

/// Research (measurement only, not a pin): the relayed full transactions through the real token at the build's set (the
/// stored form is the production P46 layout since plan 5h Task 8d part 2a; `script/pqz/at-set.sh <set>` picks the set).
/// Spike PACK first ran it in the size-swapped work tree of `pqz-core/pqzl/params/pa-pack/gasa.sh`; its op 1 / op 7
/// rows keep that spike's `n2304-kmax4096` proof sizes and precompile estimates (the production table with each set's real proof
/// sizes and provisional rows is `PqzStatePinGasTest.test_gasTable_*` in `test/pqz/PqzStateGas.t.sol`). `test_pack_scanRoll` is the `ROLL_MAX` scan of plan 5h
/// Task 8d part 2b: build with a larger `ROLL_MAX` (the set's `PqzSet.sol`, uncommitted) and read the rows.
/// Every number is the parent's `_fullTx` convention: `mtxExecute` from a fresh relayer, ABSOLUTE outer fee 7, cold
/// implementation, regular gas before refunds (intrinsic, calldata or the EIP-7976 floor, execution, the precompile
/// stand-ins) and EIP-8037 state gas apart.
contract PqzPackGasTest is PqzStatePinGasTest {
    /// `mtxRollOver(alice, n)` for n = 16, 32, …, `ROLL_MAX` of the build, each from the same state (snapshot / revert;
    /// every call is its own transaction, so cold access is per call): the `ROLL_MAX` scan in one run, on both relay paths
    /// (`mtxExecute`, and `uaExecute` with the ML-DSA-65 fee UA: 8d2b fix round, review I1). It stops after the first n
    /// over `0.75 · 2^24` on both paths (the next would approach 2^24, where the transaction runs out of regular gas).
    function test_pack_scanRoll() public {
        for (uint256 n = 16; n <= PqzCore.ROLL_MAX; n += 16) {
            uint256 snap = vm.snapshotState();
            console2.log("scan: relayed mtxRollOver, full transaction, fee 7, entries", n);
            (uint256 reg, uint256 st) = _fullTx(abi.encodeCall(tok.mtxRollOver, (alice, n)), 7);
            console2.log("scan row: entries / regular / state", n, reg, st);
            console2.log(reg <= CAP ? "  fits 0.75 * 2^24" : "  OVER 0.75 * 2^24");
            vm.revertToState(snap);
            (uint256 ru, uint256 su) = _fullTxVia(true, abi.encodeCall(tok.mtxRollOver, (alice, n)), 7);
            console2.log("scan row uaExecute: entries / regular / state", n, ru, su);
            console2.log(ru <= CAP ? "  fits 0.75 * 2^24" : "  OVER 0.75 * 2^24");
            vm.revertToState(snap);
            if (reg > CAP && ru > CAP) break;
        }
    }

    /// op 1 BUNDLE, auditor, fee 7: R_TX proof 48,724 B (`n2304-kmax4096` codegen at the time), precompile 5,409,000 × 1.125.
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

    /// op 7 M = 4 (G = 1): txm4 proof 52,950 B (`n2304-kmax4096` codegen at the time), precompile 4,121,000 × 1.125.
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
