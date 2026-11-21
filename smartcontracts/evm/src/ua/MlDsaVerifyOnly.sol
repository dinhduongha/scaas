// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUAPopVerifier, IUAVerifyOnlyVerifier} from "./IUAVerifier.sol";
import {MlDsa} from "./MlDsa.sol";
import {PqUA} from "./PqUA.sol";
import {SSTORE2} from "../common/SSTORE2.sol";

/// @title ML-DSA verify-only verifiers (spec 2026-11-19-registry-verify-only-kinds §2, §5, §9; CTR-UA-58, CTR-UA-68).
/// @notice A later registry generation carries an ML-DSA kind its predecessor enables **verify-only** with one of these: the
///         consumer checks of a predecessor's record through a precompile that did not exist when the holder was deployed
///         (owner (b), R3, R4, P2, P11, P20, M7; plan Task 9, owner C4: one file, a shared base, one contract per kind).
///         - **Probe** (constructor, §9): the first candidate that answers exactly one word `1` to the valid row and exactly
///           one word `0` to every negative row (the flipped row and one row per §7 ML-DSA edge class) is `PRECOMPILE`; any
///           miss on every candidate: `PRECOMPILE = 0` (the registry constructor and the deploy refuse such a verifier, P11).
///         - **Three states** (§5, N5, P2): lengths first (the holder's split, `MldsaVerifier.verify`: a malformed input answers
///           `false`, never no-answer); the precompile with the explicit limit `CALL_GAS` (owner P20: its worst cost for the
///           kind's largest input, measured on the chain's client, part of this init code); exactly one word `1` accepts,
///           exactly one word `0` refuses; anything else re-runs the valid row under the same limit (the alive-check): answered
///           `1`, the input was invalid (`false`); else `PqNoAnswer()`, and the registry falls back to the holder's verdict.
///         - **Encodings**: the hint, `z` and `c~` encodings are FIPS 204's verify, inside an EIP-8355 precompile; the probe's
///           edge rows check that this precompile refuses each class. Nothing else is decoded here.
///         `KEY_FORM` 0 sends the FIPS key `ρ ‖ t1` (EIP-8355 layout `pk ‖ sig ‖ pq_msg`); 1 sends the holder's cached
///         EIP-8051 expanded key (`verifyCached`: the parts read as `MldsaVerifier.verifyCached` reads them, P1). **UNAUDITED.**
abstract contract MldsaVerifyOnly is IUAPopVerifier, IUAVerifyOnlyVerifier {
    error PqNoAnswer();
    error UAMldsaKind(uint16 kind);

    uint16 public immutable KIND;
    bytes32 public immutable KIND_TAG;
    address public immutable PRECOMPILE;
    uint8 public immutable KEY_FORM;
    uint256 public immutable CALL_GAS;
    address[] private _valid; // the valid row, kept in code (SSTORE2 chunks, written once here): the alive-check's input

    /// @param candidates precompile addresses in order (Final EIP addresses and the chain profile's own; a Draft address only
    ///        under the profile's flag, R9).
    /// @param valid the valid row in the precompile's layout; `invalid` the flipped row and the edge-class rows.
    constructor(
        uint16 kind,
        address[] memory candidates,
        bytes memory valid,
        bytes[] memory invalid,
        uint8 keyForm,
        uint256 callGas
    ) {
        if (kind != PqUA.MLDSA44 && kind != PqUA.MLDSA65 && kind != PqUA.MLDSA87) {
            revert UAMldsaKind(kind);
        }
        (KIND, KIND_TAG, KEY_FORM, CALL_GAS) = (kind, PqUA.tag(kind), keyForm, callGas);
        _valid = SSTORE2.writeChunks(valid);
        for (uint256 i; i < candidates.length; ++i) {
            if (_probe(candidates[i], valid, invalid, callGas)) {
                PRECOMPILE = candidates[i];
                break;
            }
        }
    }

    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) public view returns (bool) {
        MlDsa.Params memory P = _params();
        if (keyData.length != P.pkLen || sig.length != P.sigLen) return false; // the holder's split
        return _call(abi.encodePacked(keyData, sig, PqUA.pqMessage(KIND_TAG, message)));
    }

    /// The PoP is an ordinary signature over the PoP `ua_msg` (the holder's `verifyPop`).
    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        return verify(keyData, message, sig);
    }

    /// Key form 1: the holder's cached parts (`chunks`, the pointers its registry wrote from an authenticated key, CTR-UA-23 MD-10;
    /// the registry passes only pointers read from the holder on the line of the deploy book, F13).
    function verifyCached(bytes calldata chunks, bytes32 message, bytes calldata sig) external view returns (bool) {
        MlDsa.Params memory P = _params();
        if (KEY_FORM != 1 || sig.length != P.sigLen) return false;
        (bytes memory ek, bool ok) = MlDsa.readParts(P, chunks, PqUA.mldsaParts(KIND));
        if (!ok) return false;
        return _call(abi.encodePacked(ek, sig, PqUA.pqMessage(KIND_TAG, message)));
    }

    /// §5's three states on `input` (owner P2, M7).
    function _call(bytes memory input) private view returns (bool) {
        address pc = PRECOMPILE;
        uint256 g = CALL_GAS;
        uint256 w = _answer(pc, input, g);
        if (w <= 1) return w == 1;
        if (_answer(pc, SSTORE2.readChunks(_valid), g) == 1) return false; // alive: the input was invalid
        revert PqNoAnswer();
    }

    /// Exactly one word `0` or `1` from `pc` under the limit `g`; 2 for anything else (a failed call, other return data, no code).
    function _answer(address at, bytes memory input, uint256 g) private view returns (uint256 w) {
        if (at == address(0)) return 2;
        assembly ("memory-safe") {
            mstore(0, 2)
            let ok := staticcall(g, at, add(input, 0x20), mload(input), 0, 0x20)
            w := mload(0)
            if iszero(and(ok, eq(returndatasize(), 0x20))) { w := 2 }
            if gt(w, 1) { w := 2 }
        }
    }

    function _probe(address pc, bytes memory valid, bytes[] memory invalid, uint256 g) private view returns (bool) {
        if (_answer(pc, valid, g) != 1) return false;
        for (uint256 i; i < invalid.length; ++i) {
            if (_answer(pc, invalid[i], g) != 0) return false;
        }
        return invalid.length != 0;
    }

    function _params() private view returns (MlDsa.Params memory) {
        uint16 k = KIND;
        return k == PqUA.MLDSA44 ? MlDsa.params44() : k == PqUA.MLDSA65 ? MlDsa.params65() : MlDsa.params87();
    }
}

contract MldsaVerifyOnly44 is MldsaVerifyOnly {
    constructor(address[] memory c, bytes memory valid, bytes[] memory invalid, uint8 keyForm, uint256 callGas)
        MldsaVerifyOnly(PqUA.MLDSA44, c, valid, invalid, keyForm, callGas)
    {}
}

contract MldsaVerifyOnly65 is MldsaVerifyOnly {
    constructor(address[] memory c, bytes memory valid, bytes[] memory invalid, uint8 keyForm, uint256 callGas)
        MldsaVerifyOnly(PqUA.MLDSA65, c, valid, invalid, keyForm, callGas)
    {}
}

contract MldsaVerifyOnly87 is MldsaVerifyOnly {
    constructor(address[] memory c, bytes memory valid, bytes[] memory invalid, uint8 keyForm, uint256 callGas)
        MldsaVerifyOnly(PqUA.MLDSA87, c, valid, invalid, keyForm, callGas)
    {}
}
