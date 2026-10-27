// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2, Vm} from "forge-std/Test.sol";
import {ZetherFixture} from "./helpers/ZetherFixture.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";

/// @notice EIP-7825 (zether.md §19, CTR-ZTH-38, CTR-ZTH-34): under Amsterdam a transaction's REGULAR gas (intrinsic, the
///         calldata floor, execution) is capped at 2^24; EIP-8037 state gas (new slots, SSTORE2 code) comes on top out of the
///         limit above the cap. Every call below runs isolated (inline `isolate`): forge executes it as its own transaction,
///         accounts and slots cold; `vm.lastCallGas()` reports its regular gas (`gasTotalUsed`, with the 21,000 and the
///         calldata floor) and state gas (`gasStateUsed`) apart. Forge gas is deterministic.
///         - `test_edge_*`: the largest `M` the prover admits per (form, auditor), direct and through `mtxExecute` (clone
///           -> implementation -> `ZetherLib` -> verifier, 63/64 per frame), settles at `CAP + STATE_RESERVOIR` and its
///           regular gas (`lastCallGas`) is within `CAP - MARGIN`. Forge does not enforce the regular cap on a transaction above
///           it, so the bound is asserted from the reported gas, not from an out-of-gas.
///         - `test_measure_*`: regular and state gas per `M`, the prover's table (zether.rs `gas_limits` = the regular
///           column). Opt-in, past forge's 2^30 test gas:
///           `ZETHER_GAS_PROBE=1 forge test --gas-limit 9000000000000000000 --match-test test_measure -vv`.
abstract contract ZetherGasLimitSuite is ZetherFixture {
    uint256 internal constant CAP = 1 << 24;
    uint256 internal constant MARGIN = CAP / 100;
    /// @dev The limit above the regular cap that pays EIP-8037 state gas (every recipient's first credit, the SSTORE2 record):
    ///      40 M covers the dearest cell (commit-reveal, M = 8: 18.5 M, measured). The regular gas stays within `CAP`.
    uint256 internal constant STATE_RESERVOIR = 40_000_000;
    uint256 internal constant EDGE_LIMIT = CAP + STATE_RESERVOIR;
    uint256 internal constant PAYER_PK = 0x9A7E5;
    User[12] internal rs;

    function setUp() public {
        _deploy(true);
        for (uint256 i; i < rs.length; ++i) rs[i] = _user(0xD00 + i, address(uint160(0xE00 + i)));
        _public(tok, vm.addr(PAYER_PK), 1000);
        _fund(tok, alice, 1_000_000);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
    }

    function _sel(ZetherTypes.TransferMode mode) internal pure returns (bytes4) {
        if (mode == ZetherTypes.TransferMode.HASH) return ZetherLayer.mtxConfidentialTransferCompact.selector;
        if (mode == ZetherTypes.TransferMode.BUNDLE) return ZetherLayer.mtxConfidentialTransfer.selector;
        revert("no such form");
    }

    /// @dev `alice → rs[0..m)`, one leg of 1000 (decoys 0), inner fee to carol (every account's first credit: the dear
    ///      case); relayed: a fixed-fee envelope signed by a fresh payer.
    function _build(uint256 m, ZetherTypes.TransferMode mode, bool relayed) internal view returns (bytes memory) {
        User[] memory to = new User[](m);
        for (uint256 j; j < m; ++j) to[j] = rs[j];
        uint256[] memory vs = new uint256[](m);
        vs[m / 2] = 1000;
        if (!relayed) {
            Tx memory t = _proveMulti(tok, alice, to, vs, 1_000_000, carol.ua, mode);
            return abi.encodeWithSelector(_sel(mode), t.payload, t.proof, bytes(""), ZetherTypes.UA.unwrap(carol.ua), bytes(""));
        }
        MetaTxLib.MetaTransaction memory mt = MetaTxLib.MetaTransaction({
            from: vm.addr(PAYER_PK), data: "", batch: 1, nonce: tok.mtxNonce(vm.addr(PAYER_PK), 1),
            validUntil: block.timestamp + 300, mode: MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_FEE_FIXED,
            relayer: relayer, fee: 3, feeRecipient: address(0)
        });
        Tx memory u = _proveMulti(tok, alice, to, vs, 1_000_000, carol.ua, mode, tok.envelopeBinding(mt));
        mt.data = abi.encodeWithSelector(_sel(mode), u.payload, u.proof, bytes(""), ZetherTypes.UA.unwrap(carol.ua), bytes(""));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PAYER_PK, tok.mtxDigest(mt));
        return abi.encodeCall(IMetaTx.mtxExecute, (mt, abi.encodePacked(r, s, v)));
    }

    /// @dev One isolated transaction with gas limit `limit`: does it settle, and its regular / state gas
    ///      (`vm.lastCallGas`). State restored.
    function _run(bytes memory cd, uint256 limit, bool relayed) internal returns (bool ok, uint256 reg, uint256 st) {
        uint256 snap = vm.snapshotState();
        if (relayed) vm.prank(relayer);
        (ok,) = address(tok).call{gas: limit - 21_000}(cd);
        Vm.Gas memory g = vm.lastCallGas();
        (reg, st) = (g.gasTotalUsed, uint256(int256(g.gasStateUsed)));
        vm.revertToState(snap);
    }

    function _ok(bytes memory cd, uint256 limit, bool relayed) internal returns (bool ok) {
        (ok,,) = _run(cd, limit, relayed);
    }

    /// @dev The prover's largest `M` (zether.rs `gas_limits`), direct then relayed, per cell: compact, bundle, each
    ///      auditor on then out.
    function _edges() internal pure virtual returns (uint8[8] memory);

    function _edge(uint256 cell) internal {
        ZetherTypes.TransferMode mode = [ZetherTypes.TransferMode.HASH, ZetherTypes.TransferMode.BUNDLE][cell / 2];
        audOut = cell % 2 == 1;
        uint8[8] memory e = _edges();
        for (uint256 r; r < 2; ++r) {
            (bool ok, uint256 reg, uint256 st) = _run(_build(e[2 * cell + r], mode, r == 1), EDGE_LIMIT, r == 1);
            console2.log(string.concat("EDGE cell ", vm.toString(cell), r == 1 ? " relayed" : " direct", " M=", vm.toString(e[2 * cell + r]),
                " regular=", vm.toString(reg), " state=", vm.toString(st)));
            assertTrue(ok, "edge settles");
            assertLe(reg, CAP - MARGIN, "regular within the cap less the margin");
        }
    }

    function test_edge_compactOn() public { _edge(0); }
    function test_edge_compactOut() public { _edge(1); }
    function test_edge_bundleOn() public { _edge(2); }
    function test_edge_bundleOut() public { _edge(3); }

    /// @dev Regular and state gas per `M` (one isolated transaction each, limit `CAP + STATE_RESERVOIR`); stops at the first
    ///      `M` whose REGULAR gas passes `CAP - MARGIN` (state gas is not under the cap).
    function _measure(ZetherTypes.TransferMode mode) internal {
        vm.skip(!vm.envOr("ZETHER_GAS_PROBE", false));
        for (uint256 k; k < 4; ++k) {
            audOut = k & 1 == 1;
            bool relayed = k >= 2;
            string memory head = string.concat(
                "GAS ", bls ? "bls12381 " : "bn254 ", relayed ? "relayed " : "direct ",
                mode == ZetherTypes.TransferMode.HASH ? "compact" : "bundle",
                audOut ? " out" : " on"
            );
            for (uint256 m = 1; m <= rs.length; ++m) {
                (bool ok, uint256 reg, uint256 st) = _run(_build(m, mode, relayed), CAP + STATE_RESERVOIR, relayed);
                console2.log(string.concat(head, " M=", vm.toString(m), " regular=", vm.toString(reg), " state=", vm.toString(st), ok ? " ok" : " FAIL"));
                if (reg + MARGIN > CAP) break;
                require(ok, "settles under the cap");
                require(m < rs.length, "more recipients needed");
            }
        }
    }

    /// @dev The calls run isolated: 100,000 zero calldata bytes alone need a limit over 1 M (EIP-7623's floor, 10 per
    ///      zero byte) and over 6.4 M under Amsterdam (F185: EIP-7976's floor, 15,000 + 64 per byte).
    function test_isolated() public {
        bytes memory cd = bytes.concat(abi.encodeWithSignature("decimals()"), new bytes(100_000));
        assertFalse(_ok(cd, 500_000, false), "isolated");
        assertTrue(_ok(cd, 6_500_000, false), "fits");
    }

    /// @dev `mtxConfidentialTransferSingle` alice → rs[0], auditor on and out, direct and relayed (§19 node cap).
    function test_measure_single() public {
        vm.skip(!vm.envOr("ZETHER_GAS_PROBE", false));
        for (uint256 k; k < 4; ++k) {
            audOut = k & 1 == 1;
            bool relayed = k >= 2;
            bytes memory cd;
            if (!relayed) {
                Tx memory t = _proveTransfer(tok, alice, rs[0], 1000, 1_000_000, carol.ua, 0);
                cd = abi.encodeCall(ZetherLayer.mtxConfidentialTransferSingle, (t.payload, t.proof, bytes(""), ZetherTypes.UA.unwrap(carol.ua), bytes("")));
            } else {
                MetaTxLib.MetaTransaction memory mt = MetaTxLib.MetaTransaction({
                    from: vm.addr(PAYER_PK), data: "", batch: 1, nonce: tok.mtxNonce(vm.addr(PAYER_PK), 1),
                    validUntil: block.timestamp + 300, mode: MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_FEE_FIXED,
                    relayer: relayer, fee: 3, feeRecipient: address(0)
                });
                Tx memory u = _proveTransfer(tok, alice, rs[0], 1000, 1_000_000, carol.ua, tok.envelopeBinding(mt));
                mt.data = abi.encodeCall(ZetherLayer.mtxConfidentialTransferSingle, (u.payload, u.proof, bytes(""), ZetherTypes.UA.unwrap(carol.ua), bytes("")));
                (uint8 v, bytes32 r, bytes32 s) = vm.sign(PAYER_PK, tok.mtxDigest(mt));
                cd = abi.encodeCall(IMetaTx.mtxExecute, (mt, abi.encodePacked(r, s, v)));
            }
            (bool ok, uint256 reg, uint256 st) = _run(cd, CAP + STATE_RESERVOIR, relayed);
            console2.log(string.concat("GAS ", bls ? "bls12381 " : "bn254 ", relayed ? "relayed " : "direct ", "single",
                audOut ? " out" : " on", " M=1 regular=", vm.toString(reg), " state=", vm.toString(st), ok ? " ok" : " FAIL"));
        }
    }

    function test_measure_compact() public { _measure(ZetherTypes.TransferMode.HASH); }
    function test_measure_bundle() public { _measure(ZetherTypes.TransferMode.BUNDLE); }
}

/// forge-config: default.isolate = true
contract ZetherGasLimitBls12381Test is ZetherGasLimitSuite {
    function _edges() internal pure override returns (uint8[8] memory) {
        return [8, 8, 8, 8, 7, 7, 8, 8];
    }
}
