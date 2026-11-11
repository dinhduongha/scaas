// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {stdJson} from "forge-std/StdJson.sol";
import {PqzOffchainBase} from "./helpers/PqzOffchainBase.sol";
import {noVerdict} from "./helpers/PqzVerdicts.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {IPqzToken, IPqzWrappedToken} from "../../src/pqz/IPqzToken.sol";
import {IConfidentialWrappedToken} from "../../src/confidential/IConfidentialToken.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {nid} from "../helpers/Ids.sol";

/// Round 3t (verifier fee spec §12): the writer and the check of `smartcontracts/vectors/pqz/verifier_fee.json`, read by
/// clientkeys, ua-rs, the node and the verifier service. Rows from real token ops (proofs mocked; the verifier's real ECDSA
/// verdict): per form (op 1 BUNDLE and HASH, op 7 M ∈ {1, 2, 4, 8}, burn, refresh, unwrap) × beneficiary (0, set) × `vf`
/// (0, 1, the cap) × `shieldScale` (1, 10^12): the fee word (header word 256 of the statement view), each payout in
/// public units, Δ`totalShielded`, Δ pool; then the direct binding word 544 of op 1 and op 7 per mode and `vf` on `OFFCHAIN`
/// (`TAG_DIRECT_MODE_VF`) and on `PRECOMPILE` (today's `TAG_DIRECT_MODE`). `WRITE_VERIFIER_FEE=1` writes the file; without
/// it every row is rebuilt and compared. The file is the default build's set's. UNAUDITED.
contract PqzVerifierFeeVectorsTest is PqzOffchainBase {
    using stdJson for string;

    string internal constant OUT = "../vectors/pqz/verifier_fee.json";
    uint64 internal constant CAP = 10;
    bytes32 internal constant TO = bytes32(uint256(0xD00D));
    bytes32 internal ben;
    bytes32[8] internal lg;
    uint256 internal scale;
    string[] internal rows;

    function _cfg(uint256 m) internal view override returns (IFactoryToken.TokenConfig memory c) {
        c = super._cfg(m);
        c.conf.shieldScale = scale;
        c.admin = nid(address(this));
    }

    function setUp() public {
        _offStack();
        _releaseWrapped();
        aMode = 0;
        decoy = 2;
        ben = _mldsaUA(9);
        lg[0] = bob;
        lg[1] = carol;
        for (uint256 j = 2; j < 8; ++j) lg[j] = _pqzUA(_pk(uint8(40 + j)), uint8(40 + j));
    }

    function _tokens(uint64 vf) internal returns (NormalPqzToken n, NormalPqzToken w) {
        (vMode, vUA, vFee, vFeeMax) = (PqzCore.OFFCHAIN, vA, vf, CAP);
        n = _newToken(keccak256(abi.encode("vf-n", scale, vf)));
        w = NormalPqzToken(address(_newWrapped(keccak256(abi.encode("vf-w", scale, vf)))));
        (vMode, vUA, vFee, vFeeMax) = (0, bytes32(0), 0, 0);
        n.mint(address(this), 1000 * scale);
        n.mtxShield(alice, 1000);
        MockERC20 u = MockERC20(WrappedPqzToken(payable(address(w))).underlyings()[0]);
        u.mint(address(this), 1000 * scale);
        u.approve(address(w), 1000 * scale);
        WrappedPqzToken(payable(address(w))).mtxWrapShield(address(u), 1000 * scale, alice);
    }

    // form codes: 0 op 1 BUNDLE, 1 op 1 HASH, 2..5 op 7 M = 1, 2, 4, 8 (BUNDLE), 6 burn, 7 refresh, 8 unwrap
    string[9] internal NAMES = ["op1-bundle", "op1-hash", "op7-m1", "op7-m2", "op7-m4", "op7-m8", "burn", "refresh", "unwrap"];

    function _m(uint256 f) internal pure returns (uint256) {
        return f >= 2 && f <= 5 ? 1 << (f - 2) : 0;
    }

    function _amount(uint256 f) internal pure returns (uint256) {
        return f == 6 ? 5 : f == 8 ? 10 : 0;
    }

    function _p(NormalPqzToken t) internal view returns (uint256) {
        return t.pqzAccount(alice, 0).pendingCount;
    }

    function _burnA(NormalPqzToken t, bytes32 b) internal view returns (IPqzToken.PqzBurnArgs memory) {
        return _bs(bytes.concat(abi.encode(_p(t), block.number + 50, uint256(0), alice, b), _blob(14, PqzCt.CT)));
    }

    function _multiA(NormalPqzToken t, bytes32 b, uint256 m) internal view returns (IPqzToken.PqzMultiArgs memory) {
        bytes32[] memory legs = new bytes32[](m);
        for (uint256 j; j < m; ++j) legs[j] = lg[j];
        return _ms(_mpayload(_p(t), 0, alice, b, legs, _blob(13, _outLen(m, false)), ""));
    }

    function _unwrapX(NormalPqzToken t) internal view returns (IConfidentialWrappedToken.Unwrap memory) {
        return IConfidentialWrappedToken.Unwrap(WrappedPqzToken(payable(address(t))).underlyings()[0], TO, 10, 10 * scale);
    }

    /// Form `f` on `t` (direct, with the verifier's verdict): its statement and call data.
    function _op(uint256 f, NormalPqzToken t, bytes32 b) internal view returns (bytes memory st, bytes memory cd) {
        IUARegistry.UASig memory pa = _pqAuth();
        if (f <= 1) {
            IPqzToken.PqzTransferArgs memory a = _ts(_payload(_p(t), 0, alice, bob, b, _out(11, false), f == 1 ? _memo() : bytes("")));
            st = t.transferSingleStatement(a, 0);
            cd = f == 0 ? abi.encodeCall(IPqzToken.mtxConfidentialTransferSingle, (a, VPROOF, pa, "", _sv(t, st)))
                : abi.encodeCall(IPqzToken.mtxConfidentialTransferSingleCompact, (a, VPROOF, pa, "", _sv(t, st)));
        } else if (f <= 5) {
            IPqzToken.PqzMultiArgs memory m = _multiA(t, b, _m(f));
            st = t.transferStatement(m, 0);
            cd = abi.encodeCall(IPqzToken.mtxConfidentialTransfer, (m, VPROOF, pa, "", _sv(t, st)));
        } else if (f <= 7) {
            (uint256 amt, bytes32 r) = f == 6 ? (uint256(5), TO) : (uint256(0), bytes32(0));
            st = t.burnStatement(_burnA(t, b), amt, r, 0);
            cd = abi.encodeCall(IPqzToken.mtxUnshield, (_burnA(t, b), amt, r, VPROOF, pa, "", _sv(t, st)));
        } else {
            st = WrappedPqzToken(payable(address(t))).unshieldUnwrapStatement(_burnA(t, b), _unwrapX(t), 0);
            cd = abi.encodeCall(IPqzWrappedToken.mtxUnshieldUnwrap, (_burnA(t, b), _unwrapX(t), VPROOF, pa, "", _sv(t, st)));
        }
    }

    function _wd(bytes memory st, uint256 o) internal pure returns (uint256) {
        return uint256(bytes32(_slice(st, o, 32)));
    }

    struct R {
        uint256 feeWord;
        uint256 ben;
        uint256 verifier;
        uint256 leg;
        uint256 recipient;
        uint256 dShielded;
        uint256 dPool;
    }

    /// The balances a debit can pay into (as an `R`: verifier, beneficiary, leg 0, recipient, totalShielded, pool).
    function _snap(NormalPqzToken t, bytes32 b) internal view returns (R memory s) {
        IUALedger l = IUALedger(address(t));
        (s.verifier, s.ben, s.leg) = (t.balanceOf(vm.addr(VKEY)), b == 0 ? 0 : l.balanceOfUA(b), l.balanceOfUA(bob));
        (s.recipient, s.dShielded, s.dPool) = (t.balanceOf(address(0xD00D)), t.totalShielded(), t.balanceOf(MetaTxLib.SHIELD_POOL));
    }

    function _row(uint256 f, NormalPqzToken t, bytes32 b) internal returns (R memory r) {
        (bytes memory st, bytes memory cd) = _op(f, t, b);
        R memory x = _snap(t, b);
        (bool ok, bytes memory ret) = address(t).call(cd);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        R memory y = _snap(t, b);
        r.feeWord = _wd(st, 256);
        (r.verifier, r.ben, r.leg, r.recipient) = (y.verifier - x.verifier, y.ben - x.ben, f <= 1 ? 0 : y.leg - x.leg,
            y.recipient - x.recipient); // op 1's receiver gets a hidden credit, no public one
        (r.dShielded, r.dPool) = (x.dShielded - y.dShielded, x.dPool - y.dPool);
    }

    function _json(uint256 f, bool withBen, uint64 vf, R memory r) internal view returns (string memory) {
        return string.concat(_jsonHead(f, withBen, vf), _jsonPay(r));
    }

    function _jsonHead(uint256 f, bool withBen, uint64 vf) internal view returns (string memory) {
        return string.concat("{\"form\": \"", NAMES[f], "\", \"legs\": ", vm.toString(_m(f)), ", \"beneficiary\": ",
            withBen ? "true" : "false", ", \"shieldScale\": ", vm.toString(scale), ", \"confidentialFee\": ", vm.toString(FEE),
            ", \"verifierFee\": ", vm.toString(vf), ", \"decoyFee\": ", vm.toString(_m(f) == 0 ? 0 : decoy), ", \"amount\": ",
            vm.toString(_amount(f)));
    }

    function _jsonPay(R memory r) internal pure returns (string memory) {
        string memory a = string.concat(", \"feeWord\": ", vm.toString(r.feeWord), ", \"payBeneficiary\": ", vm.toString(r.ben),
            ", \"payVerifier\": ", vm.toString(r.verifier), ", \"payPerLeg\": ", vm.toString(r.leg));
        return string.concat(a, ", \"payRecipient\": ", vm.toString(r.recipient), ", \"dTotalShielded\": ",
            vm.toString(r.dShielded), ", \"dPool\": ", vm.toString(r.dPool), "}");
    }

    function _bindingRows() internal returns (string memory s) {
        scale = SCALE;
        tok = _newToken("vf-pre");
        uint64[3] memory fees = [uint64(0), 1, CAP];
        for (uint256 i; i < 4; ++i) {
            bool pre = i == 3;
            NormalPqzToken t = tok;
            uint64 vf = pre ? 0 : fees[i];
            if (!pre) (t,) = _tokens(vf);
            for (uint256 mode; mode < 2; ++mode) {
                IPqzToken.PqzTransferArgs memory a = _ts(_payload(_p(t), 0, alice, bob, 0, _out(11, false), mode == 0 ? _memo() : bytes("")));
                bytes32 w1 = bytes32(_wd(t.transferSingleStatement(a, 0), 544));
                bytes32 w7 = bytes32(_wd(t.transferStatement(_multiA(t, 0, 2), 0), 544));
                if (mode == 0) w7 = bytes32(_wd(t.transferStatement(_hashMulti(t), 0), 544));
                bytes32 want = pre ? keccak256(abi.encode(PqzCore.TAG_DIRECT_MODE, uint8(mode)))
                    : keccak256(abi.encode(PqzCore.TAG_DIRECT_MODE_VF, uint8(mode), uint256(vf)));
                assertEq(w1, want, "op 1 word 544");
                assertEq(w7, want, "op 7 word 544");
                s = string.concat(s, bytes(s).length == 0 ? "" : ", ", "{\"pqzVerifyMode\": \"", pre ? "PRECOMPILE" : "OFFCHAIN",
                    "\", \"mode\": \"", mode == 0 ? "HASH" : "BUNDLE", "\", \"modeByte\": ", vm.toString(mode), ", \"verifierFee\": ",
                    vm.toString(vf), ", \"op1Word544\": \"", vm.toString(w1), "\", \"op7Word544\": \"", vm.toString(w7), "\"}");
            }
        }
    }

    function _hashMulti(NormalPqzToken t) internal view returns (IPqzToken.PqzMultiArgs memory) {
        bytes32[] memory legs = new bytes32[](2);
        (legs[0], legs[1]) = (lg[0], lg[1]);
        return _ms(_mpayload(_p(t), 0, alice, 0, legs, _blob(13, _outLen(2, false)),
            bytes.concat(salt, _slice(_blob(0x3e31, 352), 0, 2 + 40 * 2))));
    }

    /// One block of rows, `scale` × `vf` (an external self-call: its memory starts afresh), checked against `pin` unless
    /// writing; rows `[first, first + 18)`.
    function rowBlock(uint256 si, uint256 fi, uint256 first, string calldata pin, bool write)
        external returns (string memory all)
    {
        scale = si == 0 ? 1 : 1e12;
        uint64 vf = [uint64(0), 1, CAP][fi];
        (NormalPqzToken nt, NormalPqzToken wt) = _tokens(vf);
        uint256 n = first;
        for (uint256 f; f < 9; ++f) {
            for (uint256 b; b < 2; ++b) {
                R memory r = _row(f, f == 8 ? wt : nt, b == 0 ? bytes32(0) : ben);
                all = string.concat(all, n == 0 ? "" : ",\n  ", _json(f, b == 1, vf, r));
                if (!write) _check(pin, n, f, b == 1, vf, r);
                ++n;
            }
        }
    }

    function test_verifierFeeVectors() public {
        bool write = vm.envOr("WRITE_VERIFIER_FEE", false);
        string memory pin = write ? "" : vm.readFile(OUT);
        if (!write && keccak256(bytes(pin.readString(".set"))) != keccak256(bytes(PqzSet.NAME))) vm.skip(true);
        string memory all;
        uint256 n;
        for (uint256 si; si < 2; ++si) {
            for (uint256 fi; fi < 3; ++fi) {
                all = string.concat(all, this.rowBlock(si, fi, n, pin, write));
                n += 18;
            }
        }
        string memory bind = _bindingRows();
        if (!write) {
            assertEq(pin.readUint(".rowCount"), n, "row count");
            assertEq(keccak256(bytes(pin.readString(".binding[0].op1Word544"))),
                keccak256(bytes(vm.toString(keccak256(abi.encode(PqzCore.TAG_DIRECT_MODE_VF, uint8(0), uint256(0)))))), "binding 0");
            return;
        }
        vm.writeFile(OUT, string.concat("{\n \"_comment\": \"GENERATED by smartcontracts/evm/test/pqz/PqzVerifierFeeVectors.t.sol ",
            "(WRITE_VERIFIER_FEE=1): round 3t, CTR-PQZ-36. Fee word (header word 256) = txFee + verifierFee + M*decoyFee, txFee = ",
            "confidentialFee with a beneficiary else 0; payouts in public units (units * shieldScale); dTotalShielded = feeWord + ",
            "amount; dPool = dTotalShielded * shieldScale. binding: the direct op 1 / op 7 word 544. Proofs mocked; UNAUDITED.\",\n",
            string.concat(" \"file\": \"pqz/verifier_fee.json\", \"set\": \"", PqzSet.NAME, "\", \"tagDirectMode\": \"",
            vm.toString(PqzCore.TAG_DIRECT_MODE), "\", \"tagDirectModeVf\": \"", vm.toString(PqzCore.TAG_DIRECT_MODE_VF),
            "\", \"verifierFeeMax\": ", vm.toString(CAP), ", \"rowCount\": ", vm.toString(n), ",\n \"rows\": [\n  ", all,
            "\n ],\n \"binding\": [", bind, "]\n}\n")));
    }

    function _check(string memory pin, uint256 i, uint256 f, bool withBen, uint64 vf, R memory r) internal view {
        string memory k = string.concat(".rows[", vm.toString(i), "]");
        assertEq(pin.readString(string.concat(k, ".form")), NAMES[f], k);
        assertEq(pin.readBool(string.concat(k, ".beneficiary")), withBen, k);
        assertEq(pin.readUint(string.concat(k, ".verifierFee")), vf, k);
        assertEq(pin.readUint(string.concat(k, ".shieldScale")), scale, k);
        assertEq(pin.readUint(string.concat(k, ".feeWord")), r.feeWord, string.concat(k, " feeWord"));
        assertEq(pin.readUint(string.concat(k, ".payVerifier")), r.verifier, string.concat(k, " payVerifier"));
        assertEq(pin.readUint(string.concat(k, ".payBeneficiary")), r.ben, string.concat(k, " payBeneficiary"));
        assertEq(pin.readUint(string.concat(k, ".payPerLeg")), r.leg, string.concat(k, " payPerLeg"));
        assertEq(pin.readUint(string.concat(k, ".payRecipient")), r.recipient, string.concat(k, " payRecipient"));
        assertEq(pin.readUint(string.concat(k, ".dTotalShielded")), r.dShielded, string.concat(k, " dTotalShielded"));
        assertEq(pin.readUint(string.concat(k, ".dPool")), r.dPool, string.concat(k, " dPool"));
        // the formula every reader implements, against the token
        assertEq(r.feeWord, (withBen ? FEE : 0) + vf + _m(f) * decoy, "the fee word formula");
        assertEq(r.verifier, vf * scale, "the verifier's payout");
        assertEq(r.dPool, r.dShielded * scale, "the pool");
    }
}
