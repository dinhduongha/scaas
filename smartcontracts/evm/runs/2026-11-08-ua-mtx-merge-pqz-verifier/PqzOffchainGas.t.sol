// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/console2.sol";
import {PqzOffchainBase} from "./helpers/PqzOffchainBase.sol";
import {noVerdict} from "./helpers/PqzVerdicts.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";

/// Group 3f, T50 figures (log only, not a gate): the execution gas of the same direct debit on a PRECOMPILE token (the
/// precompile MOCKED, so its row price is left out: add the set's row from `PqzStateGas.t.sol`) and on an OFFCHAIN token with
/// an EOA verifier (the statement and proof hashes, the verdict's fields, the EIP-712 digest, one `requireAuthorized` of
/// kind native EOA), and the verdict parameter's calldata in each mode. Another verifier kind adds its `requireAuthorized`
/// cost instead of the EOA's. Copied into `test/pqz/` by `gas.sh` for the run, then removed. UNAUDITED.
contract PqzOffchainGasProbe is PqzOffchainBase {
    PqzLayer internal off;

    function setUp() public {
        _offStack();
        tok = _newToken("pqz-precompile");
        off = _offToken("pqz-offchain", vA, false);
        _shieldOn(off, alice, 100);
        _shieldOn(tok, alice, 100);
    }

    function _log(string memory what, uint256 pre, uint256 offG) internal pure {
        console2.log(string.concat("GAS3F ", PqzSet.NAME, " | ", what, " | PRECOMPILE (mocked) ", vm.toString(pre),
            " | OFFCHAIN EOA ", vm.toString(offG), " | OFFCHAIN - PRECOMPILE ", vm.toString(int256(offG) - int256(pre))));
    }

    function test_gas_op1() public {
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op1Of(off, alice, bob, 5, true);
        (IPqzToken.PqzTransferArgs memory a2,) = _op1Of(tok, alice, bob, 5, true);
        IPqzToken.PqzSignedVerdict memory sv = _sv(off, st);
        console2.log(string.concat("VERDICT calldata | empty ", vm.toString(abi.encode(noVerdict()).length), " B | EOA-signed ",
            vm.toString(abi.encode(sv).length), " B"));
        // each from the same state (a shared first write is paid by both)
        uint256 snap = vm.snapshotState();
        uint256 g = gasleft();
        tok.mtxConfidentialTransferSingle(a2, VPROOF, _pqAuth(), "", noVerdict());
        uint256 pre = g - gasleft();
        vm.revertToState(snap);
        g = gasleft();
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
        _log("op 1, auditor", pre, g - gasleft());
    }

    function test_gas_burn() public {
        (IPqzToken.PqzBurnArgs memory b, bytes memory bst) = _burnOf(off, alice, 3, bytes32(uint256(0xD00D)), 9);
        (IPqzToken.PqzBurnArgs memory b2,) = _burnOf(tok, alice, 3, bytes32(uint256(0xD00D)), 9);
        IPqzToken.PqzSignedVerdict memory sv = _sv(off, bst);
        uint256 snap = vm.snapshotState();
        uint256 g = gasleft();
        tok.mtxUnshield(b2, 3, bytes32(uint256(0xD00D)), VPROOF, _pqAuth(), "", noVerdict());
        uint256 pre = g - gasleft();
        vm.revertToState(snap);
        g = gasleft();
        off.mtxUnshield(b, 3, bytes32(uint256(0xD00D)), VPROOF, _pqAuth(), "", sv);
        _log("unshield", pre, g - gasleft());
    }
}
