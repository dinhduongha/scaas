// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/console2.sol";
import {Vm} from "forge-std/Vm.sol";
import {PqzOffchainBase} from "./helpers/PqzOffchainBase.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {Catalogue, pqzEnv} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";
import {PQZ_UID} from "./helpers/PqzRegistryBase.sol";

/// Round 3t, T9 figures (log only, not a gate; verifier fee spec §16): the T50 probe's method (`gasleft()` around one direct
/// call, each from the same state), `n2304-kmax4096`, the precompile not called (`OFFCHAIN`, EOA verifier). Per debit: the
/// `OFFCHAIN` token at `vf = 0`, at `vf = 2` with the verifier's ERC-20 balance already there, and at `vf = 2` as the
/// verifier's first payout (a new balance slot). The setter on a token of a factory with a 3-day notice: a decrease, a
/// proposal, its confirm after `eta`, a cancel by the current value. Copied into `test/pqz/` by `gas.sh` for the run, then
/// removed. UNAUDITED.
contract PqzVerifierFeeGasProbe is PqzOffchainBase {
    uint64 internal constant NOTICE = 3 days;
    NormalPqzToken internal z; // OFFCHAIN, vf 0
    NormalPqzToken internal f; // OFFCHAIN, vf 2, cap 10
    NormalPqzToken internal n; // OFFCHAIN, vf 2, cap 10, on a factory with a 3-day notice

    function _cfg(uint256 m) internal view override returns (IFactoryToken.TokenConfig memory c) {
        c = super._cfg(m);
        c.admin = nid(address(this));
    }

    function setUp() public {
        _offStack();
        z = _offToken("g-vf0", vA, false);
        (vMode, vUA, vFixed, vFee, vFeeMax) = (PqzCore.OFFCHAIN, vA, false, 2, 10);
        f = _newToken("g-vf2");
        OpenFactory fN = new OpenFactory(nid(registrar));
        EnvKit.configure(fN, PQZ_UID, NOTICE, address(0));
        Catalogue.release(fN, IOpenFactory.TokenKind.NORMAL_PQZ, 1, pqzEnv(address(fN), PQZ_UID, address(reg), address(pqv)),
            type(NormalPqzToken).creationCode);
        vm.prank(registrar);
        fN.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ, true);
        vm.warp(block.timestamp + NOTICE);
        n = NormalPqzToken(fN.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(_cfg(uint256(1) << 40)), "g-vfn"));
        (vMode, vUA, vFixed, vFee, vFeeMax) = (0, bytes32(0), false, 0, 0);
        _shieldOn(z, alice, 100);
        _shieldOn(f, alice, 100);
    }

    function _log(string memory what, uint256 g) internal pure {
        console2.log(string.concat("GAS3T ", PqzSet.NAME, " | ", what, " | ", vm.toString(g)));
    }

    function _op1(NormalPqzToken t) internal returns (uint256 g) {
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op1Of(t, alice, bob, 5, true);
        IPqzToken.PqzSignedVerdict memory sv = _sv(t, st);
        g = gasleft();
        t.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
        g -= gasleft();
    }

    function _unshield(NormalPqzToken t) internal returns (uint256 g) {
        (IPqzToken.PqzBurnArgs memory b, bytes memory bst) = _burnOf(t, alice, 3, bytes32(uint256(0xD00D)), 9);
        IPqzToken.PqzSignedVerdict memory sv = _sv(t, bst);
        g = gasleft();
        t.mtxUnshield(b, 3, bytes32(uint256(0xD00D)), VPROOF, _pqAuth(), "", sv);
        g -= gasleft();
    }

    /// `f` at `vf = 2` with the verifier's ERC-20 balance already non-zero (one public unit sent to it first).
    function _funded() internal {
        _public(f, vm.addr(VKEY), 1);
    }

    function test_gas_op1() public {
        uint256 snap = vm.snapshotState();
        _log("op 1, auditor, vf 0 (another token, created at 0)", _op1(z));
        vm.revertToState(snap);
        f.setVerifierFee(0);
        _log("op 1, auditor, vf 0 (the same token, lowered to 0)", _op1(f));
        vm.revertToState(snap);
        _log("op 1, auditor, vf 2, the verifier's first payout", _op1(f));
        vm.revertToState(snap);
        _funded();
        _log("op 1, auditor, vf 2, the verifier's balance exists", _op1(f));
    }

    function test_gas_unshield() public {
        uint256 snap = vm.snapshotState();
        _log("unshield, vf 0 (another token, created at 0)", _unshield(z));
        vm.revertToState(snap);
        f.setVerifierFee(0);
        _log("unshield, vf 0 (the same token, lowered to 0)", _unshield(f));
        vm.revertToState(snap);
        _log("unshield, vf 2, the verifier's first payout", _unshield(f));
        vm.revertToState(snap);
        _funded();
        _log("unshield, vf 2, the verifier's balance exists", _unshield(f));
    }

    /// Diagnostic: the storage writes and the state diff of the op on `z` and on `f` (balance exists): which slots the fee adds.
    function test_diag_op1Writes() public {
        uint256 snap = vm.snapshotState();
        _diag(z, "vf 0, another token");
        vm.revertToState(snap);
        f.setVerifierFee(0);
        _diag(f, "vf 0, the same token lowered");
        vm.revertToState(snap);
        _funded();
        _diag(f, "vf 2, the verifier's balance exists");
    }

    function _diag(NormalPqzToken t, string memory what) internal {
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op1Of(t, alice, bob, 5, true);
        IPqzToken.PqzSignedVerdict memory sv = _sv(t, st);
        vm.startStateDiffRecording();
        t.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
        Vm.AccountAccess[] memory acc = vm.stopAndReturnStateDiff();
        uint256 writes;
        uint256 fresh;
        uint256 calls;
        for (uint256 i; i < acc.length; ++i) {
            ++calls;
            for (uint256 j; j < acc[i].storageAccesses.length; ++j) {
                Vm.StorageAccess memory x = acc[i].storageAccesses[j];
                if (x.isWrite && !x.reverted) {
                    ++writes;
                    if (x.previousValue == bytes32(0) && x.newValue != bytes32(0)) ++fresh;
                }
            }
        }
        console2.log(string.concat("DIAG3T ", what, " | frames ", vm.toString(calls), " | writes ", vm.toString(writes),
            " | zero->nonzero ", vm.toString(fresh)));
    }

    function test_gas_setter() public {
        uint256 g = gasleft();
        n.setVerifierFee(1);
        _log("setVerifierFee, a decrease 2 -> 1 (direct)", g - gasleft());
        g = gasleft();
        n.setVerifierFee(5);
        _log("setVerifierFee, a proposal 1 -> 5 (direct, notice 3 days)", g - gasleft());
        vm.warp(block.timestamp + NOTICE);
        g = gasleft();
        n.setVerifierFee(5);
        _log("setVerifierFee, the confirm after eta (direct)", g - gasleft());
        n.setVerifierFee(7);
        g = gasleft();
        n.setVerifierFee(5);
        _log("setVerifierFee, a cancel by the current value (direct)", g - gasleft());
        require(n.pqzVerifyConfig().verifierFee == 5 && n.pqzVerifyConfig().verifierFeePending == 0, "the setter path");
    }
}
