// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {PqzStatePinGasTest, GasBurner, RowBurner} from "../pqz/PqzStateGas.t.sol";
import {noVerdict} from "../pqz/helpers/PqzVerdicts.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {IPqzToken, IPqzWrappedToken} from "../../src/pqz/IPqzToken.sol";
import {IConfidentialWrappedToken} from "../../src/confidential/IConfidentialToken.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {UACall} from "../ua/UACall.sol";
import {PqzRegFixture} from "../as/confidential/PqzRegFixture.sol";

bytes32 constant PROOF_EV = keccak256("PqzDebitProof(address,bytes32,uint64,bytes,bytes)");

/// The `PqzDebitProof` events `t` emitted in the last recorded call: one under `LOG`, none under `NONE` (the matrix measures
/// what it claims).
function _proofEvents(Vm vm_, address t) returns (uint256 n) {
    Vm.Log[] memory ls = vm_.getRecordedLogs();
    for (uint256 i; i < ls.length; ++i) if (ls[i].emitter == t && ls[i].topics[0] == PROOF_EV) ++n;
}

/// Group 3h, T60 (spec 2026-11-06-pqz-proof-path §7, Codex C4; O11, O13): the measurement matrix of `proofStore` `NONE` / `LOG`,
/// on `PqzStatePinGasTest`'s state and its gas-table method (the precompile at its schedule row, `RowBurner`; ML-DSA-65 at 68,006
/// [estimate]; each row its own transaction under a snapshot; the proofs pseudo-random bytes of the set's largest length,
/// `test/vectors/pqz-gas/<set>.json`): every debit form, direct and relayed (`mtxExecute`, `uaExecute`), PQZL and PQZH, the record
/// narrow and wide, under both modes (slot 0 byte 23 written between them, as the bit-24 setter will), with `regular`, EIP-8037
/// `state`, the EIP-7976 calldata floor, and the verdicts against 2^24 (EIP-7825, regular), a 60 M block, the SCaaS testnet's 200 M
/// block and its node's 64 M `max_gas_per_tx` (regular + state, the gas limit a transaction needs; `gas_used = max(..)` is
/// accounting, not inclusion). Forge gas is deterministic; nothing is timed. `MATRIX` lines are the published table's source;
/// `test_debitMinGas_isTheCheapestLogDebit` pins `PqzSet.PQZ_DEBIT_MIN_GAS` (O11). It inherits `PqzStatePinGasTest`'s tests:
/// select this contract. UNAUDITED.
/// Run: `scripts/capped smartcontracts/evm/script/pqz/at-set.sh <set> test --match-contract PqzProofStoreGasTest -vv`.
contract PqzProofStoreGasTest is PqzStatePinGasTest {
    uint256 internal constant BLOCK_60M = 60_000_000;
    uint256 internal constant BLOCK_200M = 200_000_000; // the SCaaS testnet's block gas limit
    uint256 internal constant NODE_64M = 64_000_000; // the SCaaS testnet node's max_gas_per_tx

    string internal path; // "direct", "mtxExecute", "uaExecute"

    function _setMode(address t, uint8 m) internal {
        uint256 w = uint256(vm.load(t, PqzCore._STORAGE));
        vm.store(t, PqzCore._STORAGE, bytes32((w & ~(uint256(0xff) << 184)) | (uint256(m) << 184)));
    }

    /// `_row`'s measurement returning both gases: the call (relayed by `viaUA`'s path when `relay`) as its own transaction.
    function _meas2(string memory sys, string memory key, address to, bytes memory data, bool relay, uint8 mode)
        internal returns (uint256 reg, uint256 st, uint256 n)
    {
        string memory k = string.concat(".", sys, "['", key, "']");
        uint256 row = vm.parseJsonUint(gj, string.concat(k, ".row"));
        vm.clearMockedCalls();
        vm.etch(PQZ, address(new RowBurner(row)).code);
        vm.etch(ML65, address(new GasBurner(68_006 - 2_900)).code);
        if (relay) data = _envelopeVia(viaUA, data, 7);
        n = data.length;
        uint256 snap = vm.snapshotState();
        vm.recordLogs();
        vm.prank(RELAYER);
        reg = _gasTo(to, data);
        st = lastState;
        assertEq(_proofEvents(vm, to), mode, "one PqzDebitProof under LOG, none under NONE");
        vm.revertToState(snap);
    }

    function _v(bool ok) internal pure returns (string memory) {
        return ok ? "yes" : "NO";
    }

    /// One form under `NONE` then `LOG` on the same state; a `MATRIX` line each, the `LOG` cost above `NONE`.
    function _pair(string memory sys, string memory key, string memory what, address to, bytes memory data, bool relay)
        internal returns (uint256 regLog)
    {
        uint256[2] memory regs;
        for (uint8 m; m < 2; ++m) {
            uint256 snap = vm.snapshotState();
            _setMode(to, m);
            (uint256 reg, uint256 st, uint256 n) = _meas2(sys, key, to, data, relay, m);
            vm.revertToState(snap);
            regs[m] = reg;
            console2.log(string.concat("MATRIX ", PqzSet.NAME, " | ", sys, " | ", relay ? path : "direct", " | ", what, " | ",
                m == 0 ? "NONE" : "LOG", " | regular ", vm.toString(reg), " | state ", vm.toString(st), " | floor ",
                vm.toString(15_000 + 64 * n)));
            console2.log(string.concat("  | 2^24 ", _v(reg <= 1 << 24), " | 60M ", _v(reg + st <= BLOCK_60M), " | 200M ",
                _v(reg + st <= BLOCK_200M), " | 64M tx ", _v(reg + st <= NODE_64M)));
        }
        console2.log(string.concat("  | LOG - NONE regular ", vm.toString(regs[1] > regs[0] ? regs[1] - regs[0] : 0)));
        regLog = regs[1];
    }

    /// The forms of the gas table, each relayed on the current path and direct.
    function _matrix(string memory sys) internal {
        gj = vm.readFile(string.concat(vm.projectRoot(), "/test/vectors/pqz-gas/", PqzSet.NAME, ".json"));
        for (uint256 rl; rl < 2; ++rl) {
            _matrix1(sys, rl == 0);
            _matrix7(sys, rl == 0);
        }
    }

    function _matrix1(string memory sys, bool relay) internal {
        _row1(sys, "TRANSFER", "op 1, auditor", carol, 0, true, relay);
        _row1(sys, "TRANSFER0", "op 1, no auditor", carol, 0, false, relay);
        _row1(sys, "TRANSFER", "op 1, auditor, materialised acc, no hint", alice, PRE, true, relay);
        _rowB(sys, "BURN", "burn (unshield) 1 to an address", 1, address(0xD00D), relay);
        _rowB(sys, "REFRESH", "refresh", 0, address(0), relay);
    }

    /// One row per frame, its memory back after it (`freed`: PQZH rows of 0.3 MB each run out of memory gas in one frame).
    function _row1(string memory sys, string memory key, string memory what, bytes32 from, uint256 p, bool aud, bool relay)
        internal freed
    {
        bytes memory data = _op1p(from, p, aud, "", _pf(sys, key));
        _pair(sys, key, what, address(tok), data, relay);
    }

    function _rowB(string memory sys, string memory key, string memory what, uint256 amount, address to, bool relay)
        internal freed
    {
        bytes memory data = _burnP(amount, to, _pf(sys, key));
        _pair(sys, key, what, address(tok), data, relay);
    }

    function _matrix7(string memory sys, bool relay) internal {
        uint256 top = keccak256(bytes(sys)) == keccak256("pqzh") ? 4 : 8;
        for (uint256 m = 1; m <= top; m *= 2) {
            _matrix7a(sys, m, true, relay);
            _matrix7a(sys, m, false, relay);
        }
    }

    function _matrix7a(string memory sys, uint256 m, bool aud, bool relay) internal freed {
        string memory key = string.concat("M", vm.toString(m), aud ? "-on" : "-off");
        _pair(sys, key, string.concat("op 7 M = ", vm.toString(m), aud ? ", auditor" : ", no auditor"), address(tok),
            _op7a(m, aud, _pf(sys, key)), relay);
    }

    function test_proofStoreMatrix_pqzl() public {
        path = "mtxExecute";
        _matrix("pqzl");
    }

    function test_proofStoreMatrix_pqzh() public {
        vm.skip(!PqzSet.HAS_PQZH);
        path = "mtxExecute";
        _matrix("pqzh");
    }

    function test_proofStoreMatrix_pqzl_ua() public {
        (viaUA, path) = (true, "uaExecute");
        _matrix("pqzl");
    }

    function test_proofStoreMatrix_pqzh_ua() public {
        vm.skip(!PqzSet.HAS_PQZH);
        (viaUA, path) = (true, "uaExecute");
        _matrix("pqzh");
    }

    /// The forms the gas table has not: the record wide (`shieldIn ≠ 0`, `w1` written; relayed on `mtxExecute`, the envelope's
    /// signer pays it), the 3g migration (op 1 from the stale version 0 to the holder itself: a narrow record), the unwrap of kind 5
    /// (direct; relayed adds the envelope the burn rows show).
    function test_proofStoreMatrix_extraForms() public {
        gj = vm.readFile(string.concat(vm.projectRoot(), "/test/vectors/pqz-gas/", PqzSet.NAME, ".json"));
        address t = address(tok);
        path = "mtxExecute";
        // kind 5's token first, while the precompile's self-test answers (a row below etches its stand-in): a TRIVIAL entry
        // of carol's, burnt to the leg at the end
        _releaseWrapped();
        WrappedPqzToken w = _newWrapped("matrix-w");
        MockERC20 usd = MockERC20(w.underlying());
        usd.mint(address(this), 10 * SCALE);
        usd.approve(address(w), 10 * SCALE);
        w.mtxWrapShield(address(usd), 10 * SCALE, carol);
        _public(tok, vm.addr(RKEY), 100 * SCALE);
        bytes memory wide = abi.encodeCall(IPqzToken.mtxConfidentialTransferSingle, (_ts(_payload(0, 5, carol, bob, alice,
            _out(77, true), "")), _pf("pqzl", "TRANSFER"), _pqAuth(), "", noVerdict()));
        _pair("pqzl", "TRANSFER", "op 1, auditor, wide record (shieldIn 5)", t, wide, true);
        // kind 5's unwrap
        IPqzToken.PqzBurnArgs memory b = _bs(bytes.concat(abi.encode(uint256(1), block.number + 5, uint256(0), carol, alice),
            _blob(5, PqzCt.CT)));
        IConfidentialWrappedToken.Unwrap memory x = IConfidentialWrappedToken.Unwrap(address(usd), MetaTxLib.pad(address(0xD00D)), 1, 0);
        bytes memory uw = abi.encodeCall(IPqzWrappedToken.mtxUnshieldUnwrap, (b, x, _pf("pqzl", "BURN"), _pqAuth(), "", noVerdict()));
        _pair("pqzl", "BURN", "kind 5 unwrap 1 to the leg", address(w), uw, false);
        // the migration: carol's version 0 stale after a rotation, op 1 to herself, the credit in (carol, 1); the rotation's
        // consent by the ML-DSA-65 stand-in, its R_REG by the precompile's (both answer 1)
        vm.etch(ML65, address(new GasBurner(68_006 - 2_900)).code);
        vm.mockCall(PQZ, abi.encodePacked(uint8(3)), abi.encode(uint256(1)));
        reg.setPqzKey(carol, 1, _pk(60), keccak256("pqzver carol 1"), UACall.sig(new bytes(ML65_SIG)));
        reg.storePqzPop(carol, 1, "pqzver carol 1");
        bytes memory mig = abi.encodeCall(IPqzToken.mtxConfidentialTransferSingle, (_ts(_payload(0, 0, carol, carol, alice,
            _out(78, true), "")), _pf("pqzl", "TRANSFER"), _pqAuth(), "", noVerdict()));
        _pair("pqzl", "TRANSFER", "the 3g migration (op 1 to itself from version 0), auditor", t, mig, true);
        _pair("pqzl", "TRANSFER", "the 3g migration (op 1 to itself from version 0), auditor", t, mig, false);
    }

    /// O11 (owner 2026-11-07): `PQZ_DEBIT_MIN_GAS` is the cheapest PQZL debit form, the burn of 1 to an address, as a full
    /// relayed transaction on the costlier path (`uaExecute`, the ML-DSA-65 fee UA) under `LOG`.
    function test_debitMinGas_isTheCheapestLogDebit() public {
        gj = vm.readFile(string.concat(vm.projectRoot(), "/test/vectors/pqz-gas/", PqzSet.NAME, ".json"));
        (viaUA, path) = (true, "uaExecute");
        uint256 g = _pair("pqzl", "BURN", "burn 1 to an address (the PQZ_DEBIT_MIN_GAS form)", address(tok),
            _burnP(1, address(0xD00D), _pf("pqzl", "BURN")), true);
        console2.log(string.concat("PQZ_DEBIT_MIN_GAS ", PqzSet.NAME, " pinned / measured under LOG"), PqzSet.PQZ_DEBIT_MIN_GAS, g);
        assertEq(PqzSet.PQZ_DEBIT_MIN_GAS, g, "set.toml debit_min_gas: the LOG burn's full relayed regular gas");
    }
}

/// Kind 13's unwrap (the regulated wrapped kind; T60 Step 5), direct, under `NONE` and `LOG`, PQZL and PQZH at the set's largest
/// `BURN` proof, the precompile at its schedule row; the relayed form adds the envelope the kind 5 and burn rows show (the same
/// for both modes). Same `MATRIX` line shape. UNAUDITED.
contract PqzProofStoreGas13Test is PqzRegFixture {
    function _isWrapped() internal pure override returns (bool) { return true; }

    function _setMode(uint8 m) internal {
        uint256 w = uint256(vm.load(address(tok), PqzCore._STORAGE));
        vm.store(address(tok), PqzCore._STORAGE, bytes32((w & ~(uint256(0xff) << 184)) | (uint256(m) << 184)));
    }

    function _proof(uint256 n) internal pure returns (bytes memory proof) {
        proof = new bytes(n);
        for (uint256 i; i < n; i += 32) {
            bytes32 x = keccak256(abi.encode("proof", i));
            assembly ("memory-safe") { mstore(add(add(proof, 32), i), x) }
        }
    }

    function _unwrap13(string memory sys) internal {
        string memory gj = vm.readFile(string.concat(vm.projectRoot(), "/test/vectors/pqz-gas/", PqzSet.NAME, ".json"));
        string memory k = string.concat(".", sys, "['BURN']");
        bytes memory proof = _proof(vm.parseJsonUint(gj, string.concat(k, ".proof")));
        _shieldTo(alice, BAL);
        IConfidentialWrappedToken.Unwrap memory x =
            IConfidentialWrappedToken.Unwrap(address(usd), MetaTxLib.pad(address(0xD00D)), 1, SCALE);
        bytes memory data = abi.encodeCall(IPqzWrappedToken.mtxUnshieldUnwrap, (_burnArgs(bytes32(0), 0, 81), x, proof, _pqAuth(), "",
            noVerdict()));
        vm.clearMockedCalls();
        vm.etch(PQZ, address(new RowBurner(vm.parseJsonUint(gj, string.concat(k, ".row")))).code);
        vm.etch(ML65, address(new GasBurner(68_006 - 2_900)).code); // the subject's ML-DSA-65 authorization, as the gas table
        for (uint8 m; m < 2; ++m) {
            uint256 snap = vm.snapshotState();
            _setMode(m);
            vm.recordLogs();
            (bool ok, bytes memory ret) = address(tok).call(data);
            if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
            Vm.Gas memory g = vm.lastCallGas();
            assertEq(_proofEvents(vm, address(tok)), m, "one PqzDebitProof under LOG, none under NONE");
            vm.revertToState(snap);
            uint256 reg = g.gasTotalUsed;
            uint256 st = uint256(int256(g.gasStateUsed));
            console2.log(string.concat("MATRIX ", PqzSet.NAME, " | ", sys, " | direct | kind 13 unwrap 1 to the leg | ",
                m == 0 ? "NONE" : "LOG", " | regular ", vm.toString(reg), " | state ", vm.toString(st), " | floor ",
                vm.toString(15_000 + 64 * data.length)));
            console2.log(string.concat("  | 2^24 ", reg <= 1 << 24 ? "yes" : "NO", " | 60M ", reg + st <= 60_000_000 ? "yes" : "NO",
                " | 200M ", reg + st <= 200_000_000 ? "yes" : "NO", " | 64M tx ", reg + st <= 64_000_000 ? "yes" : "NO"));
        }
    }

    function test_proofStoreMatrix_kind13_pqzl() public {
        _unwrap13("pqzl");
    }

    function test_proofStoreMatrix_kind13_pqzh() public {
        vm.skip(!PqzSet.HAS_PQZH);
        _unwrap13("pqzh");
    }
}
