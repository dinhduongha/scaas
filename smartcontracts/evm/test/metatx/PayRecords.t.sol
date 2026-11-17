// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalToken} from "../../src/metatx/NormalToken.sol";

import {Vm} from "forge-std/Test.sol";
import {UACall} from "../ua/UACall.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {IMetaTokenV2} from "../../src/metatx/IMetaTokenV2.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {MtxPipelineLib} from "../../src/metatx/MtxPipelineLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {FeeMode} from "../../src/common/FeePolicy.sol";
import {PayRigBase} from "./PayMeta.t.sol";
import {PayMetaKit} from "../helpers/PayMetaKit.sol";

/// @notice Plan T83 (owner 2026-11-09, option 2 and `PayMeta.save`, option A): every public pay entry whose `PayMeta.save` is
///         set appends `PayRecord(to, amount, blockNumber)` to its `payNo` in the token's ERC-7201 namespace
///         `scaas.pay.records`, after the transfer; `amount` what the payee received; `save` off writes nothing;
///         `amount >= 2^192` reverts; `paymentCount` / `paymentsOf` paged, a page past the end empty. Every kind of the
///         parity rigs (the regulated forms in `test/as/Tax.t.sol`, `payWithFeeToUA` in `test/ua/UAReceivers.t.sol`, the
///         confidential ops in `test/as/confidential/TaxConfidential.t.sol`). `test_payRecordsVectors` writes
///         (`PAYMETA_WRITE=1`) or checks `../vectors/metatx/payrecords.json`.
contract PayRecordsTest is PayRigBase {
    uint256 internal constant PAYEE_PK = 0xB0B0B;
    address internal constant RF_TO = address(0xFEE6);
    address internal constant PAYEE2 = address(0xB0B6);
    /// keccak256(abi.encode(uint256(keccak256("scaas.pay.records")) - 1)) & ~bytes32(uint256(0xff)), computed in the test
    bytes32 internal ROOT = keccak256(abi.encode(uint256(keccak256("scaas.pay.records")) - 1)) & ~bytes32(uint256(0xff));
    /// A right-aligned UUIDv7, the recommended `payNo`.
    bytes32 internal constant NO = bytes32(uint256(0x019a6e3c5f007a3b8c4d5e6f708192a3));
    string internal constant FILE = "../vectors/metatx/payrecords.json";

    function _saved(uint256 i, bytes32 payNo) internal pure returns (MetaTxLib.PayMeta memory m) {
        m = PayMetaKit.saved(keccak256(abi.encode("payrecords.test", i)), payNo);
    }

    function _utTo(bytes32 ref, uint256 nonce, address to, uint256 amount) internal view
        returns (MetaTxLib.UAMetaTransfer memory x)
    {
        x = _ut(ref, 7, nonce);
        (x.to, x.value) = (MetaTxLib.pad(to), amount);
    }

    function _eq(MetaTxLib.PayRecord memory r, address to, uint256 amount, uint256 blockNumber, string memory what)
        internal pure
    {
        assertEq(r.to, MetaTxLib.pad(to), what);
        assertEq(r.amount, amount, what);
        assertEq(r.blockNumber, blockNumber, what);
    }

    function _lengthSlot(bytes32 payNo) internal view returns (bytes32) {
        return keccak256(abi.encode(payNo, ROOT));
    }

    /// `mtxPay` with `save`: one record, `to` the payee, `amount` the value (the FIXED fee is on top), this block.
    function test_records_mtxPay() public {
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            vm.roll(100 + i);
            MetaTxLib.PayMeta memory m = _saved(i, NO);
            _pay(t, _ut(PayMetaKit.id(m), 7, 0), m);
            assertEq(NormalToken(t).balanceOf(FEE_TO), FEE, kinds[i]);
            assertEq(NormalToken(t).paymentCount(NO), 1, kinds[i]);
            MetaTxLib.PayRecord[] memory r = NormalToken(t).paymentsOf(NO, 0, 10);
            assertEq(r.length, 1, kinds[i]);
            _eq(r[0], PAYEE, AMOUNT, 100 + i, kinds[i]);
        }
    }

    /// T66b rule 4 (spec §4.1): module P runs the pay code of `MtxPipelineLib` compiled in (`metaPayId`, `payMeta`, the
    /// typed transfer, `payRecord`, the payee-fee digest and authorisation), module A the two payment views: no
    /// DELEGATECALL to the library on any kind of the rigs; positive control: the library's own entry answers.
    function test_rule4_payCallsNoMtxPipelineLib() public {
        MtxPipelineLib.paymentCount(NO); // control: linked here, it answers
        vm.expectCall(address(MtxPipelineLib), "", 0);
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            MetaTxLib.PayMeta memory m = _saved(80 + i, NO);
            assertEq(NormalToken(t).metaPayId(m), PayMetaKit.id(m), kinds[i]);
            _pay(t, _ut(PayMetaKit.id(m), 7, 0), m);
            MetaTxLib.PayMeta memory m2 = _saved(90 + i, NO);
            MetaTxLib.UAMetaTransfer memory x = MetaTxLib.UAMetaTransfer(MetaTxLib.pad(signer),
                MetaTxLib.pad(vm.addr(PAYEE_PK)), AMOUNT, PayMetaKit.id(m2), 7, 1, block.timestamp + 300,
                MetaTxLib.MODE_RESTRICT_RELAYER, REL, 0, address(0));
            IUARegistry.UASig memory pa = _sigOf(t, x);
            IUARegistry.UASig memory qa = UACall.auth(x.to,
                _ecdsa(PAYEE_PK, NormalToken(t).payeeFeeDigest(x, 10, RF_TO, block.timestamp + 300)));
            uint256 vu = block.timestamp + 300;
            vm.prank(REL);
            NormalToken(t).mtxPayWithPayeeFee(x, pa, 10, RF_TO, vu, qa, m2);
            assertEq(NormalToken(t).paymentCount(NO), 2, kinds[i]);
            assertEq(NormalToken(t).paymentsOf(NO, 1, 1)[0].amount, AMOUNT - 10, kinds[i]);
        }
    }

    /// `save` off: the pay lands, `payNo` in the event, and nothing is written under `payNo` (count 0, the length slot 0).
    function test_records_saveFalseWritesNothing() public {
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            MetaTxLib.PayMeta memory m = _saved(i, NO);
            m.save = false;
            _pay(t, _ut(PayMetaKit.id(m), 7, 0), m);
            assertEq(NormalToken(t).balanceOf(PAYEE), AMOUNT, kinds[i]);
            assertEq(NormalToken(t).paymentCount(NO), 0, kinds[i]);
            assertEq(NormalToken(t).paymentsOf(NO, 0, 10).length, 0, kinds[i]);
            assertEq(vm.load(t, _lengthSlot(NO)), bytes32(0), kinds[i]);
        }
    }

    /// Two payments of one `payNo` (an ERP's rolled receiving addresses) to two payees, in order, each with its block.
    function test_records_twoPayeesOnePayNo() public {
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            vm.roll(200);
            MetaTxLib.PayMeta memory a = _saved(10 + i, NO);
            _pay(t, _utTo(PayMetaKit.id(a), 0, PAYEE, AMOUNT), a);
            vm.roll(201);
            MetaTxLib.PayMeta memory b = _saved(20 + i, NO);
            _pay(t, _utTo(PayMetaKit.id(b), 1, PAYEE2, 777), b);
            assertEq(NormalToken(t).paymentCount(NO), 2, kinds[i]);
            MetaTxLib.PayRecord[] memory r = NormalToken(t).paymentsOf(NO, 0, 2);
            _eq(r[0], PAYEE, AMOUNT, 200, kinds[i]);
            _eq(r[1], PAYEE2, 777, 201, kinds[i]);
            assertEq(NormalToken(t).paymentCount(bytes32(uint256(NO) + 1)), 0, kinds[i]);
        }
    }

    /// Paging: three records; pages cut at the end; `limit` 0 and a page at or past the end are empty; a huge `limit` does
    /// not overflow.
    function test_records_paging() public {
        address t = toks[0];
        for (uint256 k; k < 3; ++k) {
            MetaTxLib.PayMeta memory m = _saved(30 + k, NO);
            _pay(t, _utTo(PayMetaKit.id(m), k, PAYEE, AMOUNT + k), m);
        }
        NormalToken tok = NormalToken(t);
        assertEq(tok.paymentCount(NO), 3);
        MetaTxLib.PayRecord[] memory r = tok.paymentsOf(NO, 0, 2);
        assertEq(r.length, 2);
        assertEq(r[0].amount, AMOUNT);
        assertEq(r[1].amount, AMOUNT + 1);
        r = tok.paymentsOf(NO, 2, 2);
        assertEq(r.length, 1);
        assertEq(r[0].amount, AMOUNT + 2);
        r = tok.paymentsOf(NO, 1, type(uint256).max);
        assertEq(r.length, 2);
        assertEq(r[0].amount, AMOUNT + 1);
        assertEq(r[1].amount, AMOUNT + 2);
        assertEq(tok.paymentsOf(NO, 0, type(uint256).max).length, 3);
        assertEq(tok.paymentsOf(NO, 1, 0).length, 0, "limit 0");
        assertEq(tok.paymentsOf(NO, 3, 1).length, 0, "at the end");
        assertEq(tok.paymentsOf(NO, 4, 5).length, 0, "past the end");
        assertEq(tok.paymentsOf(NO, type(uint256).max, type(uint256).max).length, 0, "far past the end");
    }

    /// The direct `payWithFee` with `save`: `amount` (the fee on top); `amount >= 2^192` reverts `PayRecordAmount`, `2^192 - 1`
    /// lands, and the same `2^192` without `save` lands (the bound is the record's only).
    function test_records_payWithFee_amountBound() public {
        uint256 big = uint256(1) << 192;
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            deal(t, signer, 3 * big);
            MetaTxLib.PayMeta memory m = _saved(40 + i, NO);
            vm.prank(signer);
            vm.expectRevert(abi.encodeWithSelector(IMetaTokenV2.PayRecordAmount.selector, big));
            NormalToken(t).payWithFee(PAYEE, big, FeeMode.NONE, 0, address(0), PayMetaKit.id(m), m);
            vm.prank(signer);
            NormalToken(t).payWithFee(PAYEE, big - 1, FeeMode.FIXED, 3, FEE_TO, PayMetaKit.id(m), m);
            _eq(NormalToken(t).paymentsOf(NO, 0, 1)[0], PAYEE, big - 1, block.number, kinds[i]);
            m.save = false;
            vm.prank(signer);
            NormalToken(t).payWithFee(PAYEE, big, FeeMode.NONE, 0, address(0), PayMetaKit.id(m), m);
            assertEq(NormalToken(t).paymentCount(NO), 1, kinds[i]);
            assertEq(NormalToken(t).balanceOf(PAYEE), 2 * big - 1, kinds[i]);
        }
    }

    /// Payee fee: the payee received `value` and paid `fee` out of it; the record is the net `value - fee`.
    function test_records_payeeFeeNet() public {
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            MetaTxLib.PayMeta memory m = _saved(50 + i, NO);
            MetaTxLib.UAMetaTransfer memory x = MetaTxLib.UAMetaTransfer(MetaTxLib.pad(signer),
                MetaTxLib.pad(vm.addr(PAYEE_PK)), AMOUNT, PayMetaKit.id(m), 7, 0, block.timestamp + 300,
                MetaTxLib.MODE_RESTRICT_RELAYER, REL, 0, address(0));
            IUARegistry.UASig memory pa = _sigOf(t, x);
            IUARegistry.UASig memory qa = UACall.auth(x.to,
                _ecdsa(PAYEE_PK, NormalToken(t).payeeFeeDigest(x, 10, RF_TO, block.timestamp + 300)));
            uint256 vu = block.timestamp + 300;
            vm.prank(REL);
            NormalToken(t).mtxPayWithPayeeFee(x, pa, 10, RF_TO, vu, qa, m);
            assertEq(NormalToken(t).balanceOf(vm.addr(PAYEE_PK)), AMOUNT - 10, kinds[i]);
            _eq(NormalToken(t).paymentsOf(NO, 0, 1)[0], vm.addr(PAYEE_PK), AMOUNT - 10, block.number, kinds[i]);
        }
    }

    /// The record comes after the transfer: in the token's ordered storage writes, the payee's balance is written before
    /// `payNo`'s length.
    function test_records_writtenAfterTheTransfer() public {
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            vm.record();
            NormalToken(t).balanceOf(PAYEE);
            (bytes32[] memory reads,) = vm.accesses(t);
            bytes32 bal = reads[reads.length - 1];
            MetaTxLib.PayMeta memory m = _saved(60 + i, NO);
            MetaTxLib.UAMetaTransfer memory x = _ut(PayMetaKit.id(m), 7, 0);
            IUARegistry.UASig memory a = _sigOf(t, x);
            vm.startStateDiffRecording();
            vm.prank(REL);
            NormalToken(t).mtxPay(x, a, m);
            Vm.AccountAccess[] memory acc = vm.stopAndReturnStateDiff();
            (uint256 n, uint256 atBal, uint256 atLen) = (0, type(uint256).max, type(uint256).max);
            for (uint256 k; k < acc.length; ++k) {
                for (uint256 j; j < acc[k].storageAccesses.length; ++j) {
                    Vm.StorageAccess memory s = acc[k].storageAccesses[j];
                    if (s.account != t || !s.isWrite || s.reverted) continue;
                    if (s.slot == bal) atBal = n;
                    if (s.slot == _lengthSlot(NO) && atLen == type(uint256).max) atLen = n;
                    ++n;
                }
            }
            assertTrue(atBal != type(uint256).max && atLen != type(uint256).max, kinds[i]);
            assertLt(atBal, atLen, string.concat(kinds[i], ": the record after the transfer"));
        }
    }

    // ------------------------------------------------------------------ the shared vectors

    function _recJson(MetaTxLib.PayRecord memory r, bytes32 at) internal pure returns (string memory) {
        return string.concat('{"to":"', vm.toString(r.to), '","amount":"', vm.toString(uint256(r.amount)),
            '","blockNumber":', vm.toString(uint256(r.blockNumber)), ',"slots":["', vm.toString(at), '","',
            vm.toString(bytes32(uint256(at) + 1)), '"]}');
    }

    function _call(string memory key, bytes memory cd, bytes memory ret) internal pure returns (string memory) {
        return string.concat('"', key, '":{"calldata":"', vm.toString(cd), '","returndata":"', vm.toString(ret), '"}');
    }

    /// The row an ERP or indexer reads (plan T83): `payNo` (a UUIDv7, right-aligned) with two records, the namespace root,
    /// the length and record slots (`keccak256(payNo ‖ root)`, records from `keccak256(lengthSlot)`, two words each: `to`,
    /// then `amount` in the low 24 bytes and `blockNumber` above it), and the calldata / return data of `paymentCount` and
    /// three `paymentsOf` pages (all, the second record, past the end).
    function test_payRecordsVectors() public {
        address t = toks[0];
        vm.roll(1_000);
        MetaTxLib.PayMeta memory a = _saved(70, NO);
        _pay(t, _utTo(PayMetaKit.id(a), 0, PAYEE, AMOUNT), a);
        vm.roll(1_001);
        MetaTxLib.PayMeta memory b = _saved(71, NO);
        _pay(t, _utTo(PayMetaKit.id(b), 1, PAYEE2, 777), b);
        bytes32 len = _lengthSlot(NO);
        bytes32 data = keccak256(abi.encode(len));
        MetaTxLib.PayRecord[] memory r = NormalToken(t).paymentsOf(NO, 0, 2);
        bytes[4] memory cd = [abi.encodeCall(NormalToken.paymentCount, (NO)), abi.encodeCall(NormalToken.paymentsOf,
            (NO, 0, 10)), abi.encodeCall(NormalToken.paymentsOf, (NO, 1, 1)), abi.encodeCall(NormalToken.paymentsOf,
            (NO, 2, 1))];
        bytes[4] memory ret;
        for (uint256 k; k < 4; ++k) {
            (bool ok, bytes memory out) = t.staticcall(cd[k]);
            assertTrue(ok);
            ret[k] = out;
        }
        string memory j = string.concat('{\n  "_comment":"plan T83 (owner 2026-11-09): the pay records of one payNo on a ',
            'token, written by test/metatx/PayRecords.t.sol test_payRecordsVectors (PAYMETA_WRITE=1). UNAUDITED.",\n',
            '  "namespace":"scaas.pay.records","root":"', vm.toString(ROOT), '","payNo":"', vm.toString(NO),
            '","payNoUuid":"019a6e3c-5f00-7a3b-8c4d-5e6f708192a3",\n  "lengthSlot":"', vm.toString(len), '","length":2,\n');
        j = string.concat(j, '  "records":[', _recJson(r[0], data), ',', _recJson(r[1], bytes32(uint256(data) + 2)),
            '],\n  ', _call("paymentCount", cd[0], ret[0]), ',\n  ', _call("paymentsOfAll", cd[1], ret[1]), ',\n  ');
        j = string.concat(j, _call("paymentsOfSecond", cd[2], ret[2]), ',\n  ', _call("paymentsOfPastEnd", cd[3], ret[3]),
            '\n}\n');
        if (vm.envOr("PAYMETA_WRITE", false)) vm.writeFile(FILE, j);
        assertEq(vm.readFile(FILE), j, "payrecords.json is stale: PAYMETA_WRITE=1");
        // the slots as the row states them, read raw
        assertEq(uint256(vm.load(t, len)), 2, "length");
        assertEq(vm.load(t, data), MetaTxLib.pad(PAYEE), "record 0 to");
        assertEq(uint256(vm.load(t, bytes32(uint256(data) + 1))), AMOUNT | (uint256(1_000) << 192), "record 0 word 1");
        assertEq(vm.load(t, bytes32(uint256(data) + 2)), MetaTxLib.pad(PAYEE2), "record 1 to");
        assertEq(uint256(vm.load(t, bytes32(uint256(data) + 3))), 777 | (uint256(1_001) << 192), "record 1 word 1");
        assertEq(ret[0], abi.encode(uint256(2)));
        assertEq(ret[3], abi.encode(new MetaTxLib.PayRecord[](0)), "past the end: empty");
    }
}
