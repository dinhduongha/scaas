// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MldsaVerifyOnly, MldsaVerifyOnly44, MldsaVerifyOnly65, MldsaVerifyOnly87} from "../../src/ua/MlDsaVerifyOnly.sol";
import {PqUA} from "../../src/ua/PqUA.sol";

/// A precompile stand-in (forge has no ML-DSA precompile): one word `1` for the valid row, one word `0` for each probe row (but
/// the row `acceptRow`, answered `1`: a precompile lax on that edge class), and for any other input by `mode`: 0 one word `0`
/// (correct), 1 empty (EIP-7951 / `ecrecover` style), 2 revert (malformed), 3 burn every forwarded gas (EIP-2537 style), 4 two
/// words.
contract PcStandIn {
    bytes32 public valid;
    mapping(bytes32 => bool) public probeRow;
    bytes32 public acceptRow;
    uint8 public mode;

    function set(bytes32 v, bytes[] memory rows, uint8 m, uint256 accept) external {
        (valid, mode) = (v, m);
        for (uint256 i; i < rows.length; ++i) {
            probeRow[keccak256(rows[i])] = true;
            if (i + 1 == accept) acceptRow = keccak256(rows[i]);
        }
    }

    fallback(bytes calldata input) external returns (bytes memory) {
        bytes32 h = keccak256(input);
        if (h == valid || h == acceptRow) return abi.encode(uint256(1));
        if (probeRow[h]) return abi.encode(uint256(0));
        uint8 m = mode;
        if (m == 1) return "";
        if (m == 2) revert("malformed");
        if (m == 3) {
            assembly {
                for {} 1 {} {}
            }
        }
        if (m == 4) return abi.encode(uint256(1), uint256(0));
        return abi.encode(uint256(0));
    }
}

/// `MldsaVerifyOnly` (spec 2026-11-19-registry-verify-only-kinds §2, §5, §9, M7; plan Task 9) against the stand-in. The edge rows
/// are synthetic here (one per §7 ML-DSA class, distinct bytes of the valid row's length); the verdicts on real rows need a client
/// with the precompile (a local chain, §7 (b)). UNAUDITED.
contract MlDsaVerifyOnlyTest is Test {
    uint256 internal constant CALL_GAS = 100_000;
    /// The verifier's own work beside its two limited calls (lengths, the message hash, the row read back, the encoding): pinned.
    uint256 internal constant OVERHEAD = 40_000;
    uint256 internal constant PK65 = 1952;
    uint256 internal constant SIG65 = 3309;
    /// §7's ML-DSA edge classes, one probe row each (and the flipped row first).
    uint256 internal constant EDGE = 10;

    bytes internal key;
    bytes internal sig;
    bytes32 internal constant MSG = keccak256("a ua_msg");

    function setUp() public {
        key = new bytes(PK65);
        sig = new bytes(SIG65);
        (key[0], sig[0]) = (0x11, 0x22);
    }

    function _row(bytes memory k, bytes memory s, bytes32 m) internal pure returns (bytes memory) {
        return abi.encodePacked(k, s, PqUA.pqMessage(PqUA.tag(PqUA.MLDSA65), m));
    }

    /// The flipped row, then one row per edge class: hint indices not increasing, non-zero hint padding, a hint count down, a hint
    /// count over ω, `‖z‖∞` at `γ1 − β`, at `γ1 − β − 1` (here a negative stand-in row), `c~` flipped, a non-empty context, HashML-DSA.
    function _rows() internal view returns (bytes[] memory r) {
        r = new bytes[](EDGE);
        for (uint256 i; i < EDGE; ++i) {
            bytes memory s = bytes.concat(sig);
            s[SIG65 - 1 - i] = bytes1(uint8(0xa0 + i));
            r[i] = _row(key, s, MSG);
        }
    }

    function _standIn(uint8 mode, uint256 accept) internal returns (PcStandIn p) {
        p = new PcStandIn();
        p.set(keccak256(_row(key, sig, MSG)), _rows(), mode, accept);
    }

    function _verifier(address pc) internal returns (MldsaVerifyOnly65 v) {
        address[] memory c = new address[](2);
        (c[0], c[1]) = (address(0x5caa0013), pc); // the first has no code: skipped
        v = new MldsaVerifyOnly65(c, _row(key, sig, MSG), _rows(), 0, CALL_GAS);
    }

    function test_probe_allRows_setsPrecompile() public {
        PcStandIn p = _standIn(0, 0);
        MldsaVerifyOnly65 v = _verifier(address(p));
        assertEq(v.PRECOMPILE(), address(p));
        assertEq(v.KEY_FORM(), 0);
        assertEq(v.KIND(), PqUA.MLDSA65);
        assertTrue(v.verify(key, MSG, sig));
        assertTrue(v.verifyPop(key, MSG, sig));
        assertFalse(v.verify(key, keccak256("another"), sig));
    }

    /// One stand-in lax on each edge class in turn (that row answered `1`): no precompile, `PRECOMPILE = 0`.
    function test_probe_edgeRowWrong_precompileZero() public {
        for (uint256 i = 1; i <= EDGE; ++i) {
            assertEq(_verifier(address(_standIn(0, i))).PRECOMPILE(), address(0), vm.toString(i));
        }
    }

    /// N5, M7: no caller-chosen signature, key or message gives `PqNoAnswer` or a revert on a working precompile, whatever it
    /// answers a malformed input (word 0, empty, revert, burn-all, two words).
    function testFuzz_noPqNoAnswer_onWorkingStandIn(uint8 mode, uint256 at, bytes32 m, bool keyFlip) public {
        mode %= 5;
        MldsaVerifyOnly65 v = _verifier(address(_standIn(mode, 0)));
        bytes memory k = bytes.concat(key);
        bytes memory s = bytes.concat(sig);
        if (keyFlip) k[at % PK65] ^= 0x01;
        else s[at % SIG65] ^= 0x01;
        try v.verify{gas: 2 * CALL_GAS + OVERHEAD}(k, m, s) returns (bool ok) {
            assertFalse(ok, "a changed row never verifies");
        } catch {
            fail();
        }
    }

    /// M7: a precompile that burns every forwarded gas on a malformed input leaves the alive-check its limit: the answer is 0.
    function test_burnAll_aliveCheckKeepsGas() public {
        MldsaVerifyOnly65 v = _verifier(address(_standIn(3, 0)));
        bytes memory s = bytes.concat(sig);
        s[7] = 0x01;
        assertFalse(v.verify{gas: 2 * CALL_GAS + OVERHEAD}(key, MSG, s));
    }

    /// No precompile at deploy, or its code gone after: `PqNoAnswer` (the registry falls back to the holder).
    function test_absentPrecompile_PqNoAnswer() public {
        address[] memory c = new address[](1);
        c[0] = address(0x5caa0013);
        MldsaVerifyOnly65 none = new MldsaVerifyOnly65(c, _row(key, sig, MSG), _rows(), 0, CALL_GAS);
        assertEq(none.PRECOMPILE(), address(0));
        vm.expectRevert(MldsaVerifyOnly.PqNoAnswer.selector);
        none.verify(key, MSG, sig);
        PcStandIn p = _standIn(0, 0);
        MldsaVerifyOnly65 v = _verifier(address(p));
        vm.etch(address(p), "");
        vm.expectRevert(MldsaVerifyOnly.PqNoAnswer.selector);
        v.verify(key, MSG, sig);
    }

    /// Lengths first: a key or signature one byte off answers 0 without a call (never no-answer).
    function test_malformed_answersZero() public {
        PcStandIn p = _standIn(2, 0);
        MldsaVerifyOnly65 v = _verifier(address(p));
        vm.expectCall(address(p), "", 0);
        assertFalse(v.verify(new bytes(PK65 - 1), MSG, sig));
        assertFalse(v.verify(key, MSG, new bytes(SIG65 + 1)));
        assertFalse(v.verifyCached(new bytes(20), MSG, sig), "key form 0: no cached path");
    }

    /// The cap covers the worst input: a failed call at its limit plus the alive-check (burn-all), within `2 × CALL_GAS + OVERHEAD`.
    function test_cap_coversWorstInput() public {
        MldsaVerifyOnly65 v = _verifier(address(_standIn(3, 0)));
        bytes memory s = bytes.concat(sig);
        s[9] = 0x01;
        uint256 g = gasleft();
        v.verify(key, MSG, s);
        g -= gasleft();
        emit log_named_uint("worst input (burn-all, then the alive-check), frame", g);
        assertLe(g, 2 * CALL_GAS + OVERHEAD);
    }

    /// Each level checks its own lengths and names its kind.
    function test_levels() public {
        address[] memory c = new address[](0);
        bytes[] memory r = new bytes[](0);
        assertEq(new MldsaVerifyOnly44(c, hex"01", r, 0, CALL_GAS).KIND(), PqUA.MLDSA44);
        assertEq(new MldsaVerifyOnly87(c, hex"01", r, 0, CALL_GAS).KIND(), PqUA.MLDSA87);
    }
}
