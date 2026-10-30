// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/Test.sol";
import {PqzStatePinGasTest, GasBurner, RowBurner} from "./PqzStateGas.t.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";

/// metatx-split T5 (spec §3.6, §10 R9; owner variant A 2026-10-21): the split's relayed overhead must not grow with the
/// envelope's `data` size. For each accepted fee-UA kind (ECDSA address path, `mldsa65` and `fndsa512` on `uaExecute`) the
/// relayed transaction's regular gas is measured for the smallest envelope (`mtxRollOver(alice, 1)`, 68 B of data) and the
/// largest built one (PQZL op 7 M = 8 with the auditor; at a PQZH set also the largest PQZH debit, op 7 M = 4), exactly as
/// `PqzStateGas.t.sol`'s gas table does (the precompile at the set's row price, ML-DSA-65 68,006, `fndsa512` 2.3 M
/// stand-ins). The pre-split figures are the same test run on 2ceda92d (`test/vectors/metatx-overhead-presplit.json`).
/// Asserted: (largest − pre-split) − (smallest − pre-split) <= 8,000 per kind. `MTX_OV_PRESPLIT=1`: log only.
/// Run: `scripts/capped smartcontracts/evm/script/pqz/at-set.sh <set> test --match-contract MtxSplitOverheadTest -vv`
/// (log: runs/2026-10-27-metatx-split-overhead.txt). It inherits `PqzStatePinGasTest`'s tests; select this contract.
contract MtxSplitOverheadTest is PqzStatePinGasTest {
    uint256 internal constant BOUND = 8_000;
    string internal pre;
    bytes32 internal fnFee2;

    bool internal logOnly;
    uint256 internal sMeas; // the smallest envelope's relayed gas (this kind)
    string internal kind;

    function test_splitOverhead_dataSizeBound() public {
        gj = vm.readFile(string.concat(vm.projectRoot(), "/test/vectors/pqz-gas/", PqzSet.NAME, ".json"));
        logOnly = vm.envOr("MTX_OV_PRESPLIT", uint256(0)) == 1;
        if (!logOnly) pre = vm.readFile(string.concat(vm.projectRoot(), "/test/vectors/metatx-overhead-presplit.json"));
        // the pre-split figures exist for n2304-kmax4096 and n2048-kmax1024 only (T5 measured those two)
        if (!logOnly) vm.skip(!vm.keyExistsJson(pre, string.concat(".", PqzSet.NAME)));
        bytes memory fpk = new bytes(897); // fndsa512: 0x09 then every h_i = 0 < q
        fpk[0] = 0x09;
        fnFee2 = reg.register(UAKinds.FNDSA512, fpk, IUARegistry.UAAttrs("", 0, 0, ""), new bytes(666), "");
        NormalPqzToken(address(tok)).mintToUA(fnFee2, 1000);
        minted += 1000;
        bytes32 mlFee = feeUA;
        for (uint256 k; k < 3; ++k) {
            viaUA = k != 0;
            feeUA = k == 2 ? fnFee2 : mlFee;
            feeSigLen = k == 2 ? 666 : ML65_SIG;
            kind = k == 0 ? "ecdsa" : k == 1 ? "mldsa65" : "fndsa512";
            sMeas = _meas(abi.encodeCall(tok.mtxRollOver, (alice, 1)), 0);
            console2.log(string.concat("MEAS ", PqzSet.NAME, " ", kind, " S"), sMeas);
            _large("pqzl", "M8-on", 8);
            if (PqzSet.HAS_PQZH) _large("pqzh", "M4-on", 4);
        }
    }

    function _large(string memory sys, string memory key, uint256 m) internal {
        uint256 row = vm.parseJsonUint(gj, string.concat(".", sys, "['", key, "'].row"));
        uint256 l = _meas(_op7a(m, true, _pf(sys, key)), row);
        string memory id = string.concat(sys, "-", key);
        console2.log(string.concat("MEAS ", PqzSet.NAME, " ", kind, " ", id), l);
        if (logOnly) return;
        uint256 ovL = l - _pre(id, false) ;
        uint256 ovS = sMeas - _pre("", true);
        uint256 d = ovL > ovS ? ovL - ovS : 0;
        console2.log(string.concat("OVERHEAD ", PqzSet.NAME, " ", kind, " ", id, " smallest / largest / difference"), ovS, ovL, d);
        assertLe(d, BOUND, string.concat(kind, " ", id, ": overhead grows with data"));
    }

    function _pre(string memory id, bool small) internal view returns (uint256) {
        return vm.parseJsonUint(pre, string.concat(".", PqzSet.NAME, "['", kind, "|", small ? "S" : id, "']"));
    }

    /// the relayed call's EXECUTION gas (`GasMeter`: the callee warm as a transaction's `to`, cold state under a snapshot,
    /// the precompile stand-ins included, the EIP-8037 state gas subtracted as `_row` does). Not the transaction's regular
    /// gas: the EIP-7976 floor (64 per calldata byte) binds on the large envelopes (PQZH) and hides any overhead.
    function _meas(bytes memory data, uint256 row) internal returns (uint256 inner) {
        vm.clearMockedCalls();
        vm.etch(PQZ, address(new RowBurner(row)).code);
        vm.etch(ML65, address(new GasBurner(68_006 - 2_900)).code);
        bytes memory call = _envelopeVia(viaUA, data, 7);
        uint256 snap = vm.snapshotState();
        vm.prank(RELAYER);
        uint256 reg = _gasTo(address(tok), call);
        uint256 st = lastState;
        vm.revertToState(snap);
        inner = meter.measure(address(tok), call) - st;
        vm.revertToState(snap);
        console2.log("  tx regular / state / execution", reg, st, inner);
    }
}
