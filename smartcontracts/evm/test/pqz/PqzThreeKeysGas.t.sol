// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2, Vm} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {PqzOffchainBase} from "./helpers/PqzOffchainBase.sol";
import {GasBurner} from "./PqzStateGas.t.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UACall} from "../ua/UACall.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";

/// Step 8 of the three-key round (spec 2026-11-13-pqz-three-keys §12; owner 2026-11-14): the cost table per set,
/// measured. Each row is its own transaction (`isolate`) measured cold (a snapshot reverted around it): REGULAR gas (intrinsic,
/// calldata or the EIP-7976 floor, execution) and EIP-8037 STATE gas apart, as `PqzStatePinGasTest`. Op 1 and the refresh are
/// relayed full transactions with a FIXED outer fee of 7 on both paths (`mtxExecute`, ECDSA; `uaExecute`, an `mldsa65` fee UA);
/// the holder's and the fee UA's ML-DSA-65 at 100,006 [estimate] (`GasBurner`), the verdict a real ECDSA `PqzVerdict` of the
/// token's verifier, the proof pseudo-random bytes of the set's vector length (env `PQZ_PROOF_<FORM>`, set by the runner from
/// `smartcontracts/vectors/pqz/<set>/proof_pqzl*.json`; defaults n2304-kmax4096's). A scoped key record and its stored `R_REG`
/// proof are direct registry transactions, the `PQZ` op 3 at the set's provisional `REGISTER` row (`test/vectors/pqz-gas`).
/// Logged as `GAS3K <set> | row | regular | state | total`; reported, not pinned. UNAUDITED.
contract PqzThreeKeysGasTest is PqzOffchainBase {
    using stdJson for string;

    uint256 internal constant RKEY = 0xA11CE;
    address internal constant RELAYER = address(0x7E1A7E);

    NormalPqzToken internal c2;
    NormalPqzToken internal c3o;
    NormalPqzToken internal c3;
    bytes32 internal feeUA;
    uint256 internal lastState;

    function setUp() public {
        vm.pauseGasMetering();
        _offStack();
        c2 = _mk(false, true, "g3k-c2");
        c3o = _mk(true, true, "g3k-c3o");
        c3 = _mk(true, false, "g3k-c3");
        feeUA = _mldsaUA(50);
        NormalPqzToken[3] memory ts = [c2, c3o, c3];
        for (uint256 i; i < 3; ++i) {
            _shieldOn(ts[i], bob, 100);
            _public(ts[i], vm.addr(RKEY), 1000);
            ts[i].mintToUA(feeUA, 1000, EnvKit.codeUidOf(address(ts[i]))); // round 3zb: the chain word (CTR-GOV-28 Change)
            minted += 1000;
        }
        vm.roll(block.number + 1);
        vm.resumeGasMetering();
    }

    function _mk(bool own, bool open, bytes32 s) internal returns (NormalPqzToken t) {
        (vMode, vUA, vOwnKey, vOpening) = (PqzCore.OFFCHAIN, vA, own, open);
        t = _newToken(s);
        (vMode, vUA, vOwnKey, vOpening) = (0, bytes32(0), false, false);
    }

    function _proofLen(string memory form, uint256 dflt) internal view returns (uint256) {
        return vm.envOr(string.concat("PQZ_PROOF_", form), dflt);
    }

    function _proof(uint256 n) internal pure returns (bytes memory p) {
        p = new bytes(n);
        for (uint256 i; i < n; i += 32) {
            bytes32 w = keccak256(abi.encode("proof", i));
            assembly ("memory-safe") { mstore(add(add(p, 32), i), w) }
        }
    }

    function _opening(uint256 seed) internal pure returns (IPqzToken.PqzOpening memory o) {
        (o.mlkemCt, o.x25519Eph, o.sealedSeed) =
        (_blob(seed, PqzCore.MLKEM_CT), keccak256(abi.encode("eph", seed)), _blob(seed + 1, PqzCore.SEALED_SEED));
    }

    function _gasTo(address t, bytes memory data) internal returns (uint256 used) {
        (bool ok, bytes memory ret) = t.call(data);
        if (!ok) {
            assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        }
        Vm.Gas memory g = vm.lastCallGas();
        used = g.gasTotalUsed;
        lastState = uint256(int256(g.gasStateUsed));
    }

    function _log(string memory row, uint256 reg) internal view {
        console2.log(
            string.concat(
                "GAS3K ",
                PqzSet.NAME,
                " | ",
                row,
                " | regular ",
                vm.toString(reg),
                " | state ",
                vm.toString(lastState),
                " | total ",
                vm.toString(reg + lastState)
            )
        );
    }

    /// `data` on token `t` relayed as a full transaction (fee 7) on one path, measured cold, logged.
    function _envU() internal view returns (MetaTxLib.UAMetaTransaction memory u) {
        (u.from, u.validUntil, u.mode, u.fee) = (feeUA, block.timestamp + 1 hours, MetaTxLib.MODE_FEE_FIXED, 7);
    }

    function _envM() internal view returns (MetaTxLib.MetaTransaction memory m) {
        (m.from, m.validUntil, m.mode, m.fee) = (vm.addr(RKEY), block.timestamp + 1 hours, MetaTxLib.MODE_FEE_FIXED, 7);
    }

    /// The envelope's binding the statement carries (its fields, not its `data`): the token's view for `uaExecute`, the address
    /// form a client computes for `mtxExecute` (`_addrBinding`).
    function _binding(NormalPqzToken t, bool ua) internal view returns (bytes32) {
        return ua ? t.envelopeBinding(_envU()) : _addrBinding(t, _envM());
    }

    function _relayed(NormalPqzToken t, bool ua, bytes memory data, string memory row) internal {
        bytes memory call;
        if (ua) {
            MetaTxLib.UAMetaTransaction memory u = _envU();
            u.data = data;
            call = abi.encodeCall(t.mtxExecute, (u, UACall.auth(feeUA, abi.encode(bytes(""), _proof(ML65_SIG)))));
        } else {
            MetaTxLib.MetaTransaction memory m = _envM();
            m.data = data;
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(RKEY, MtxDigest.metaTx(address(t), m));
            call = abi.encodeWithSignature(
                "executeMetaTransaction((address,bytes,uint256,uint256,uint256,uint32,address,uint256,address),bytes)",
                m,
                abi.encodePacked(r, s, v)
            );
        }
        uint256 snap = vm.snapshotState();
        vm.clearMockedCalls();
        vm.etch(ML65, address(new GasBurner(100_006 - 2_900)).code);
        vm.prank(RELAYER);
        uint256 g = _gasTo(address(t), call);
        _log(string.concat(row, ua ? " | uaExecute" : " | mtxExecute"), g);
        vm.revertToState(snap);
    }

    /// Op 1 BUNDLE of bob to alice, fresh ref, with or without the auditor; the opening's split proof on an opening token.
    function _op1(NormalPqzToken t, bool aud, string memory row) internal {
        bool open = t.pqzVerifyConfig().pqzOpening;
        IPqzToken.PqzTransferArgs memory a = _ts(_payload(1, 0, bob, alice, bytes32(0), _out(61, aud), ""));
        if (open) {
            a.uFrom = _blob(68, PqzCt.PK);
            a.openingTo = _opening(61);
            if (aud) a.openingAuditor = _opening(64);
        }
        uint256 plen = open
            ? (aud ? _proofLen("TXS", 61_276) : _proofLen("TXS0", 60_957))
            : (aud ? _proofLen("TX", 46_660) : _proofLen("TX0", 46_312));
        string memory r =
            string.concat(row, aud ? ", auditor on" : ", auditor off", ", proof ", vm.toString(plen), " B");
        for (uint256 k; k < 2; ++k) {
            _op1Via(t, k == 1, a, _proof(plen), r);
        }
    }

    function _op1Via(NormalPqzToken t, bool ua, IPqzToken.PqzTransferArgs memory a, bytes memory proof, string memory r)
        internal
    {
        IPqzToken.PqzSignedVerdict memory sv =
            _sign(t, VKEY, _verdict(t, t.transferSingleStatement(a, _binding(t, ua)), proof));
        _relayed(t, ua, abi.encodeCall(IPqzToken.mtxConfidentialTransferSingle, (a, proof, _pqAuth(), "", sv)), r);
    }

    function test_gas3k_op1_class2() public {
        _op1(c2, false, "op 1, class 2 (opening)");
        _op1(c2, true, "op 1, class 2 (opening)");
    }

    function test_gas3k_op1_class3Opening() public {
        _op1(c3o, false, "op 1, class 3 with the opening");
        _op1(c3o, true, "op 1, class 3 with the opening");
    }

    function test_gas3k_op1_class3NoOpening() public {
        _op1(c3, false, "op 1, class 3 without the opening");
        _op1(c3, true, "op 1, class 3 without the opening");
    }

    /// A refresh (burn of 0) of bob on the class-2 token.
    function test_gas3k_refresh_class2() public {
        IPqzToken.PqzBurnArgs memory b = _bs(
            bytes.concat(abi.encode(uint256(1), block.number + 50, uint256(0), bob, bytes32(0)), _blob(71, PqzCt.CT))
        );
        uint256 plen = _proofLen("REFRESH", 45_833);
        bytes memory proof = _proof(plen);
        string memory r = string.concat("refresh, class 2, proof ", vm.toString(plen), " B");
        for (uint256 k; k < 2; ++k) {
            bool ua = k == 1;
            IPqzToken.PqzSignedVerdict memory sv =
                _sign(c2, VKEY, _verdict(c2, c2.burnStatement(b, 0, bytes32(0), _binding(c2, ua)), proof));
            _relayed(c2, ua, abi.encodeCall(IPqzToken.mtxUnshield, (b, 0, bytes32(0), proof, _pqAuth(), "", sv)), r);
        }
    }

    /// A scoped key record of a fresh `mldsa65` UA (`setPqzScopedKey`) and its stored `R_REG` proof (`storePqzScopedPop`), each
    /// a direct transaction; the `PQZ` op 3 at the set's provisional `REGISTER` row.
    function _record(address scope, bool kem, string memory row) internal {
        bytes32 ua = _mldsaUA(90);
        bytes memory pop = _proof(_proofLen("REG", 30_379));
        (uint256 g1, uint256 s1) = _setRecord(ua, scope, kem, keccak256(pop));
        (uint256 g2, uint256 price) = _storePop(ua, scope, pop);
        string memory head = string.concat("GAS3K ", PqzSet.NAME, " | ", row);
        console2.log(
            string.concat(
                head, " | setPqzScopedKey regular with ML-DSA 100,006 ", vm.toString(g1), " state ", vm.toString(s1)
            )
        );
        console2.log(
            string.concat(
                head,
                " | storePqzScopedPop (proof ",
                vm.toString(pop.length),
                " B, op 3 ",
                vm.toString(price),
                ") regular with the op 3 row ",
                vm.toString(g2),
                " state ",
                vm.toString(lastState)
            )
        );
        console2.log(string.concat(head, " | sum total ", vm.toString(g1 + s1 + g2 + lastState)));
    }

    address internal rScope; // the record under measurement (state: the call below is deep enough)
    IUARegistry.KemKey internal rKem;
    bytes32 internal rPopHash;

    /// The record's own transaction (`isolate`: a top-level call), read back from `lastCallGas`.
    function _setRecord(bytes32 ua, address scope, bool kem, bytes32 popHash) internal returns (uint256, uint256) {
        IUARegistry.KemKey memory k;
        if (kem) (k.scheme, k.mlkemEk, k.x25519) = (1, _blob(91, 1568), keccak256("x"));
        (rScope, rKem, rPopHash) = (scope, k, popHash);
        _setCall(ua);
        Vm.Gas memory g = vm.lastCallGas();
        // the holder's ML-DSA-65 signature is the fixture's mock here: its price, 100,006 [estimate], added
        return (g.gasTotalUsed + 100_006, uint256(int256(g.gasStateUsed)));
    }

    function _setCall(bytes32 ua) internal {
        reg.setPqzScopedKey(
            ua, rScope, 0, _spk(++keySeed), rPopHash, rKem, type(uint64).max, UACall.auth(ua, _mlAuth())
        );
    }

    function _storePop(bytes32 ua, address scope, bytes memory pop) internal returns (uint256 g, uint256 price) {
        string memory gj = vm.readFile(string.concat(vm.projectRoot(), "/test/vectors/pqz-gas/", PqzSet.NAME, ".json"));
        price = gj.readUint(".pqzl['REGISTER'].row") + 3 * ((5 + PqzSet.STMT_REGISTER + pop.length + 31) / 32);
        // the fixture's mocks stay (the key verifier's self-test answer is a mock): op 3 itself is mocked here and its row price is
        // added to the reported sum (one precompile call, no other cost depends on it)
        g = _gasTo(address(reg), abi.encodeCall(reg.storePqzScopedPop, (ua, scope, 0, pop))) + price;
    }

    function test_gas3k_record_class2() public {
        _record(address(0), true, "key record + R_REG proof, class 2 (scope 0, openKem)");
    }

    function test_gas3k_record_class3Opening() public {
        _record(address(c3o), true, "key record + R_REG proof, class 3 with the opening (openKem)");
    }

    function test_gas3k_record_class3NoOpening() public {
        _record(address(c3), false, "key record + R_REG proof, class 3 without the opening");
    }
}
