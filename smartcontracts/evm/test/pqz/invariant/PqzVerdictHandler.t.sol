// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalPqzToken} from "../../../src/pqz/NormalPqzToken.sol";

import {noVerdict} from "../helpers/PqzVerdicts.sol";
import {PqzOffchainBase} from "../helpers/PqzOffchainBase.sol";
import {PqzLayer} from "../../../src/pqz/PqzLayer.sol";
import {PqzCore} from "../../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../../src/pqz/PqzCt.sol";
import {IPqzToken} from "../../../src/pqz/IPqzToken.sol";
import {IUARegistry} from "../../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../../src/ua/UAKinds.sol";
import {UARegistry} from "../../../src/ua/UARegistry.sol";
import {EnvKit} from "../../helpers/EnvKit.sol";

/// Group 3f, T49 (PQZ verifier mode spec §14): the handler of invariants I1-I6. Two tokens from the same state: `pre`
/// (PRECOMPILE, the precompile mocked to accept) and `off` (OFFCHAIN, this handler its owner; the factory's notice period 0, so a
/// transfer applies at once). Actions: the same debit (op 1, op 7 with two legs, a burn, a refresh) on both, `off` with its
/// verifier's verdict and `pre` with a garbage one (the registry's verdict purpose made to revert: never asked); a replay of a
/// verdict of an older epoch; transfers A -> B -> A; revocations and re-assignment; a native verifier gaining and losing code.
/// While `off` cannot serve (revoked, or its verifier's shape changed) the debit runs on `off` alone and must refuse, so the two
/// tokens' states stay comparable (I4). While it serves, the same verdict with another proof is tried first (it binds the exact
/// proof). Every transfer and revocation must raise the epoch (I3). During every `off` call the precompile is made to revert
/// (I5). Ghosts count what a rule forbids and happened anyway; no action reverts. UNAUDITED.
contract PqzVerdictHandler is PqzOffchainBase {
    NormalPqzToken public pre;
    NormalPqzToken public off;
    uint256 public refusedValid; // I2: a valid current verdict refused (or `off` reached the precompile, I5)
    uint256 public acceptedBad; // I2 / I3: a debit accepted with a stale, revoked or changed-shape verifier
    uint256 public wrongRefusal; // I2: refused, but not by the revocation / the changed shape it is
    uint256 public epochStuck; // I3: a verifier move that did not raise the epoch
    uint256 public preRefused; // I5: `pre` refused (it never reads the verdict)
    uint256 public debitsBoth; // debits landed on both tokens
    uint256 public moves; // verifier transfers and revocations
    bytes internal staleCd; // a debit with a verdict of an older epoch, withheld
    bool internal haveStale;
    uint256 internal movesAtWithhold; // verifier moves before the withheld verdict was signed
    uint256 internal keyNow = VKEY; // the current verifier's key (0 when revoked)
    bool internal coded; // the current native verifier holds code

    constructor(NormalPqzToken pre_, UARegistry r, bytes32 a_, bytes32 b_, bytes32 c_) {
        (pre, reg, alice, bob, carol) = (pre_, r, a_, b_, c_);
        vA = bytes32(uint256(uint160(vm.addr(VKEY))));
        vB = bytes32(uint256(uint160(vm.addr(VKEY2))));
    }

    function setOff(NormalPqzToken o) external {
        if (address(off) == address(0)) off = o; // once, by the suite's setUp (and no action: `targetSelector`)
    }

    /// `off` can serve now: a live verifier whose frozen shape still holds.
    function serving() public view returns (bool) {
        return keyNow != 0 && !coded;
    }

    function _mockPre() internal {
        vm.clearMockedCalls();
        _mockMlDsa();
        for (uint8 op = 1; op <= 7; ++op) if (op != 3 && op != 6) _mockOp(op, 1);
        vm.mockCallRevert(address(reg), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector, vA,
            UAKinds.PURPOSE_PQZ_VERDICT), "pre read the verdict");
        vm.mockCallRevert(address(reg), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector, vB,
            UAKinds.PURPOSE_PQZ_VERDICT), "pre read the verdict");
    }

    /// Only the ML-DSA consent mocked: the precompile reverts every call (I5).
    function _mockOff() internal {
        vm.clearMockedCalls();
        _mockMlDsa();
        vm.mockCallRevert(PQZ, bytes(""), "off called the precompile");
    }

    /// The statement of debit `kind` (0 op 1 alice -> bob, 1 op 7 alice -> [bob, carol], 2 a burn of 1, 3 a refresh) on `t`
    /// and its calldata with verdict `sv`.
    function _debit(NormalPqzToken t, uint8 kind, uint256 seed, IPqzToken.PqzSignedVerdict memory sv, bool withVerdict)
        internal view returns (bytes memory st, bytes memory cd)
    {
        uint256 p = t.pqzAccount(alice, 0).pendingCount;
        if (kind == 0) {
            IPqzToken.PqzTransferArgs memory a = _ts(_payload(p, 0, alice, bob, bytes32(0), _out(seed, false), ""));
            st = t.transferSingleStatement(a, 0);
            if (withVerdict) sv = _sign(t, keyNow, _verdict(t, st, VPROOF));
            cd = abi.encodeCall(IPqzToken.mtxConfidentialTransferSingle, (a, VPROOF, _pqAuth(), "", sv));
        } else if (kind == 1) {
            bytes32[] memory legs = new bytes32[](2);
            (legs[0], legs[1]) = (bob, carol);
            IPqzToken.PqzMultiArgs memory m = _ms(_mpayload(p, 0, alice, bytes32(0), legs, _blob(seed, _outLen(2, false)), ""));
            st = t.transferStatement(m, 0);
            if (withVerdict) sv = _sign(t, keyNow, _verdict(t, st, VPROOF));
            cd = abi.encodeCall(IPqzToken.mtxConfidentialTransfer, (m, VPROOF, _pqAuth(), "", sv));
        } else {
            (uint256 amt, bytes32 rcp) = kind == 2 ? (uint256(1), bytes32(uint256(0xD00D))) : (uint256(0), bytes32(0));
            IPqzToken.PqzBurnArgs memory b = _bs(bytes.concat(abi.encode(p, block.number + 50, uint256(0), alice, bytes32(0)),
                _blob(seed, PqzCt.CT)));
            st = t.burnStatement(b, amt, rcp, 0);
            if (withVerdict) sv = _sign(t, keyNow, _verdict(t, st, VPROOF));
            cd = abi.encodeCall(IPqzToken.mtxUnshield, (b, amt, rcp, VPROOF, _pqAuth(), "", sv));
        }
    }

    /// Debit `kind`'s calldata on `off` with the current verifier's verdict over `st` and `VPROOF`, but carrying another proof.
    function _withProof(bytes memory st, uint8 kind, uint256 seed) internal view returns (bytes memory cd) {
        IPqzToken.PqzSignedVerdict memory sv = _sign(off, keyNow, _verdict(off, st, VPROOF));
        uint256 p = off.pqzAccount(alice, 0).pendingCount;
        bytes memory other = hex"c0df";
        if (kind == 0) {
            IPqzToken.PqzTransferArgs memory a = _ts(_payload(p, 0, alice, bob, bytes32(0), _out(seed, false), ""));
            cd = abi.encodeCall(IPqzToken.mtxConfidentialTransferSingle, (a, other, _pqAuth(), "", sv));
        } else if (kind == 1) {
            bytes32[] memory legs = new bytes32[](2);
            (legs[0], legs[1]) = (bob, carol);
            IPqzToken.PqzMultiArgs memory m = _ms(_mpayload(p, 0, alice, bytes32(0), legs, _blob(seed, _outLen(2, false)), ""));
            cd = abi.encodeCall(IPqzToken.mtxConfidentialTransfer, (m, other, _pqAuth(), "", sv));
        } else {
            (uint256 amt, bytes32 rcp) = kind == 2 ? (uint256(1), bytes32(uint256(0xD00D))) : (uint256(0), bytes32(0));
            IPqzToken.PqzBurnArgs memory b = _bs(bytes.concat(abi.encode(p, block.number + 50, uint256(0), alice, bytes32(0)),
                _blob(seed, PqzCt.CT)));
            cd = abi.encodeCall(IPqzToken.mtxUnshield, (b, amt, rcp, other, _pqAuth(), "", sv));
        }
    }

    /// The same debit on both tokens (or on `off` alone while it cannot serve).
    function debit(uint8 kind, uint256 seed) external {
        kind %= 4;
        if (kind == 2 && off.totalShielded() < 2) kind = 3;
        bool live = serving();
        _mockOff();
        (bytes memory st, bytes memory cdOff) = _debit(off, kind, seed, noVerdict(), live);
        if (live) {
            // the same verdict with another proof (I2: the verdict binds the exact proof)
            (bool okSwap,) = address(off).call(_withProof(st, kind, seed));
            if (okSwap) ++acceptedBad;
        }
        (bool okOff, bytes memory ret) = address(off).call(cdOff);
        if (live && !okOff) ++refusedValid;
        if (!live && okOff) ++acceptedBad;
        if (!live && !okOff) {
            bytes4 want = keyNow == 0 ? IPqzToken.PqzVerifierRevoked.selector : IPqzToken.PqzVerifierChanged.selector;
            if (ret.length < 4 || bytes4(ret) != want) ++wrongRefusal;
        }
        if (!live || !okOff) return _mockPre();
        _mockPre();
        IPqzToken.PqzSignedVerdict memory garbage;
        garbage.pqzVerdict.token = address(0xBAD);
        garbage.sig.signature = hex"deadbeef";
        (, bytes memory cdPre) = _debit(pre, kind, seed, garbage, false);
        (bool okPre,) = address(pre).call(cdPre);
        if (!okPre) ++preRefused;
        else ++debitsBoth;
    }

    /// A debit with the current verdict, withheld: replayed after the epoch moved it must be refused (I3: A -> B -> A
    /// included; with no debit between, its statement is still the token's).
    function withhold(uint8 kind, uint256 seed) external {
        if (!serving()) return;
        (, staleCd) = _debit(off, kind % 4 == 2 ? 3 : kind % 4, seed, noVerdict(), true);
        (haveStale, movesAtWithhold) = (true, moves);
    }

    function replay() external {
        // after any transfer or revocation since it was signed (whatever the epoch now reads: I3 holds by the epoch)
        if (!haveStale || moves == movesAtWithhold) return;
        _mockOff();
        (bool ok,) = address(off).call(staleCd);
        if (ok) ++acceptedBad;
        _mockPre();
    }

    /// The owner moves the verifier to the other EOA (notice 0: at once), or back after a revocation.
    function transfer() external {
        bytes32 cur = off.pqzVerifyConfig().verifier;
        (bytes32 next, uint256 k) = cur == vA ? (vB, VKEY2) : (vA, VKEY);
        uint32 e = off.pqzVerifyConfig().pqzVerifierEpoch;
        try off.pqzSetVerifier(next, EnvKit.codeUidOf(address(off))) {
            (keyNow, coded) = (k, false); // a native verifier with code is refused at the proposal
            ++moves;
            if (off.pqzVerifyConfig().pqzVerifierEpoch <= e) ++epochStuck;
        } catch {}
    }

    function revoke() external {
        uint32 e = off.pqzVerifyConfig().pqzVerifierEpoch;
        try off.pqzRevokeVerifier(EnvKit.codeUidOf(address(off))) {
            keyNow = 0;
            coded = false;
            ++moves;
            if (off.pqzVerifyConfig().pqzVerifierEpoch <= e) ++epochStuck;
        } catch {}
    }

    /// The current native verifier gains code (its frozen shape no longer holds), or loses it again.
    function toggleCode() external {
        if (keyNow == 0) return;
        address a = vm.addr(keyNow);
        vm.etch(a, coded ? bytes("") : bytes(hex"00"));
        coded = !coded;
    }
}
