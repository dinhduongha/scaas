// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/Test.sol";
import {isAmsterdam} from "../helpers/EvmVersion.sol";
import {ZetherFixture} from "./helpers/ZetherFixture.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";

/// @notice EIP-7825 (zether.md §19, CTR-ZTH-38): a transaction's gas LIMIT is capped at 2^24. Every call below runs
///         isolated (inline `isolate`): forge executes it as its own transaction, accounts and slots cold, charging the
///         calldata and applying the calldata floor (EIP-7623; EIP-7976 under Amsterdam); the call's gas is the limit less
///         the 21,000 base.
///         - `test_edge_*`: the most recipients the prover admits per (form, auditor) settles at a limit of 2^25 (`EDGE_LIMIT`; exactly
///           2^24 before Amsterdam), direct and through `mtxExecute` (clone → implementation → `ZetherLib` → verifier, 63/64 per frame).
///         - `test_measure_*`: the smallest limit per `M` by binary search, the prover's table. Opt-in, past forge's
///           2^30 test gas: `ZETHER_GAS_PROBE=1 forge test --gas-limit 9000000000000000000 --match-test test_measure -vv`.
abstract contract ZetherGasLimitSuite is ZetherFixture {
    uint256 internal constant CAP = 1 << 24;
    uint256 internal constant MARGIN = CAP / 100;
    /// @dev F185: under Amsterdam EIP-7825's 2^24 caps a transaction's REGULAR gas and EIP-8037 state gas (the new
    ///      accounts' slots: every recipient's first credit) comes on top. The edge cells need 21.4 M to 31.2 M in total
    ///      (BLS12-381, measured), so the edge limit is 2^25 there. On Osaka (the `zether` profile and the public chains)
    ///      EIP-7825 caps the whole transaction: a cell must settle at exactly 2^24.
    function _edgeLimit() internal returns (uint256) {
        return isAmsterdam() ? 2 * CAP : CAP;
    }
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
        return ZetherLayer.mtxConfidentialTransferNoBundle.selector;
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

    /// @dev Does a transaction with gas limit `limit` settle? State restored.
    function _ok(bytes memory cd, uint256 limit, bool relayed) internal returns (bool ok) {
        uint256 snap = vm.snapshotState();
        if (relayed) vm.prank(relayer);
        (ok,) = address(tok).call{gas: limit - 21_000}(cd);
        vm.revertToState(snap);
    }

    function _minLimit(bytes memory cd, bool relayed) internal returns (uint256 hi) {
        uint256 lo = 1_000_000;
        hi = 24_000_000;
        require(_ok(cd, hi, relayed), "fails at 24 M");
        while (hi - lo > 1) {
            uint256 mid = (lo + hi) / 2;
            if (_ok(cd, mid, relayed)) hi = mid;
            else lo = mid;
        }
    }

    /// @dev The prover's largest `M` (zether.rs `gas_limits`), direct then relayed, per cell: compact, bundle, none, each
    ///      auditor on then out.
    function _edges() internal pure virtual returns (uint8[12] memory);

    function _edge(uint256 cell) internal {
        ZetherTypes.TransferMode mode = [ZetherTypes.TransferMode.HASH, ZetherTypes.TransferMode.BUNDLE,
            ZetherTypes.TransferMode.NONE][cell / 2];
        audOut = cell % 2 == 1;
        uint8[12] memory e = _edges();
        assertTrue(_ok(_build(e[2 * cell], mode, false), _edgeLimit(), false), "direct edge at the limit");
        assertTrue(_ok(_build(e[2 * cell + 1], mode, true), _edgeLimit(), true), "relayed edge at the limit");
    }

    function test_edge_compactOn() public { _edge(0); }
    function test_edge_compactOut() public { _edge(1); }
    function test_edge_bundleOn() public { _edge(2); }
    function test_edge_bundleOut() public { _edge(3); }
    function test_edge_noneOn() public { _edge(4); }
    function test_edge_noneOut() public { _edge(5); }

    function _measure(ZetherTypes.TransferMode mode) internal {
        vm.skip(!vm.envOr("ZETHER_GAS_PROBE", false));
        for (uint256 k; k < 4; ++k) {
            audOut = k & 1 == 1;
            bool relayed = k >= 2;
            string memory head = string.concat(
                "GASLIMIT ", bls ? "bls12381 " : "bn254 ", relayed ? "relayed " : "direct ",
                mode == ZetherTypes.TransferMode.HASH ? "compact" : mode == ZetherTypes.TransferMode.BUNDLE ? "bundle" : "none",
                audOut ? " out" : " on"
            );
            for (uint256 m = 1; m <= rs.length; ++m) {
                uint256 lim = _minLimit(_build(m, mode, relayed), relayed);
                console2.log(string.concat(head, " M=", vm.toString(m), " limit=", vm.toString(lim)));
                if (lim + MARGIN > CAP) break;
                require(m < rs.length, "more recipients needed");
            }
        }
    }

    /// @dev The calls run isolated: 100,000 zero calldata bytes alone need a limit over 1 M (EIP-7623's floor, 10 per
    ///      zero byte) and over 6.4 M under Amsterdam (F185: EIP-7976's floor, 15,000 + 64 per byte).
    function test_isolated() public {
        bytes memory cd = bytes.concat(abi.encodeWithSignature("decimals()"), new bytes(100_000));
        assertFalse(_ok(cd, 500_000, false), "isolated");
        assertTrue(_ok(cd, isAmsterdam() ? 6_500_000 : 1_100_000, false), "fits");
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
            console2.log(string.concat("GASLIMIT ", bls ? "bls12381 " : "bn254 ", relayed ? "relayed " : "direct ", "single",
                audOut ? " out" : " on", " M=1 limit=", vm.toString(_minLimit(cd, relayed))));
        }
    }

    function test_measure_compact() public { _measure(ZetherTypes.TransferMode.HASH); }
    function test_measure_bundle() public { _measure(ZetherTypes.TransferMode.BUNDLE); }
    function test_measure_none() public { _measure(ZetherTypes.TransferMode.NONE); }
}

/// forge-config: default.isolate = true
contract ZetherGasLimitBls12381Test is ZetherGasLimitSuite {
    function _edges() internal pure override returns (uint8[12] memory) {
        return [7, 7, 7, 7, 6, 6, 6, 6, 7, 7, 7, 7];
    }
}
