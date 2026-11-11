// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {noVerdict} from "../../pqz/helpers/PqzVerdicts.sol";
import {PqzRegFixture} from "./PqzRegFixture.sol";
import {WrappedPqzTokenLike} from "./PqzVerdictKinds.t.sol";
import {NormalPqzToken} from "../../../src/pqz/NormalPqzToken.sol";
import {WrappedPqzToken} from "../../../src/pqz/WrappedPqzToken.sol";
import {PqzCore} from "../../../src/pqz/PqzCore.sol";
import {IPqzToken, IPqzWrappedToken} from "../../../src/pqz/IPqzToken.sol";
import {IConfidentialWrappedToken} from "../../../src/confidential/IConfidentialToken.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {IRegulatedToken} from "../../../src/regulated/IRegulatedToken.sol";
import {IGovernance} from "../../../src/governance/IGovernance.sol";
import {GovernanceBits} from "../../../src/governance/GovernanceBits.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {UAKinds} from "../../../src/ua/UAKinds.sol";
import {nid} from "../../helpers/Ids.sol";

/// Round 3t (CTR-PQZ-36, verifier fee spec §6.4, §15 (7); Fable P2-1, owner 2026-11-11 "Giữ cách hiện tại"): on the regulated
/// PQZ kinds 12 (op 1) and 13 (the unshield-unwrap) the verifier fee is a fee leg (CTR-AS-25): `_regName(verifierPayee())`
/// refuses a frozen verifier `FeeRecipientFrozen` and a denied one `NotEligible` (the `DENYLIST` `R` check), only while
/// `vf ≠ 0` (positive control: the same token at fee 0 passes), before `_pullShieldIn` and before the library (M17, M22);
/// the relief: the admin sets the fee to 0 at once. 3s's list check (`Denied`) runs on this hook too (the deny-list test).
/// UNAUDITED.
abstract contract PqzVerifierFeeKinds is PqzRegFixture {
    uint256 internal constant VKEY = 0xA77E57;
    uint64 internal constant F = 2;

    function _denylist() internal pure override returns (bool) { return true; }

    function setUp() public override {
        super.setUp();
        (vMode, vUA, vFixed, vFee, vFeeMax) = (PqzCore.OFFCHAIN, _v(), false, F, 10);
        IFactoryToken.TokenConfig memory c = _regCfg();
        (vMode, vUA, vFixed, vFee, vFeeMax) = (0, bytes32(0), false, 0, 0);
        tok = NormalPqzToken(factory.createToken(_kind(), 1, abi.encode(c), "pr-fee"));
        w = WrappedPqzToken(payable(address(tok)));
        _shieldTo(alice, BAL);
    }

    function _v() internal pure returns (bytes32) {
        return nid(vm.addr(VKEY));
    }

    function _sepOf(address t) internal view returns (bytes32) {
        (, string memory n_, string memory ver, uint256 cid, address vc, bytes32 salt_,) = NormalPqzToken(t).eip712Domain();
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256(bytes(n_)), keccak256(bytes(ver)), cid, vc, salt_));
    }

    function _sv(bytes memory st) internal view returns (IPqzToken.PqzSignedVerdict memory sv) {
        sv.pqzVerdict = IPqzToken.PqzVerdict(address(tok), block.chainid, tok.proofSystemId(), keccak256(st), keccak256(PROOF),
            tok.pqzVerifyConfig().pqzVerifierEpoch, uint64(block.timestamp + 600));
        bytes32 d = MessageHashUtils.toTypedDataHash(_sepOf(address(tok)),
            keccak256(abi.encode(PqzCore.VERDICT_TYPEHASH, sv.pqzVerdict)));
        (uint8 w_, bytes32 r, bytes32 s_) = vm.sign(VKEY, reg.uaAuthDigest(_v(), UAKinds.PURPOSE_PQZ_VERDICT, d));
        sv.sig.signature = abi.encodePacked(r, s_, w_);
    }

    /// The kind's debit at the current fee (12: op 1 to `bob`; 13: the unshield-unwrap of 5 to `0xD00D`), `shieldIn` from this
    /// test, with the verifier's verdict (or the empty one; empty too with a `shieldIn`, whose statement view refuses the
    /// order test's amount above the cap's room).
    function _debit(uint256 shieldIn, bool verdict) internal view returns (bytes memory) {
        if (!_isWrapped()) {
            IPqzToken.PqzTransferArgs memory t = _single(false, bob, bytes32(0), shieldIn, 80);
            IPqzToken.PqzSignedVerdict memory sv = verdict && shieldIn == 0 ? _sv(tok.transferSingleStatement(t, 0)) : noVerdict();
            return abi.encodeCall(IPqzToken.mtxConfidentialTransferSingle, (t, PROOF, _pqAuth(), "", sv));
        }
        IConfidentialWrappedToken.Unwrap memory x =
            IConfidentialWrappedToken.Unwrap(address(usd), MetaTxLib.pad(address(0xD00D)), 5, 5 * SCALE);
        IPqzToken.PqzBurnArgs memory b = _burnArgs(bytes32(0), shieldIn, 81);
        IPqzToken.PqzSignedVerdict memory sv2 =
            verdict && shieldIn == 0 ? _sv(WrappedPqzTokenLike(address(tok)).unshieldUnwrapStatement(b, x, 0)) : noVerdict();
        return abi.encodeCall(IPqzWrappedToken.mtxUnshieldUnwrap, (b, x, PROOF, _pqAuth(), "", sv2));
    }

    function _do(bytes memory cd) internal returns (bool ok, bytes memory ret) {
        (ok, ret) = address(tok).call(cd);
    }

    function _setFee(uint64 next) internal {
        vm.prank(ownerA);
        IPqzToken(address(tok)).setVerifierFee(next);
    }

    /// A frozen verifier halts the debit while `vf ≠ 0`; the admin's fee 0 is the relief (at once), then the fee restored
    /// halts it again.
    function test_frozenVerifier_haltsDebitsWhileFeeSet() public {
        uint256 snap = vm.snapshotState();
        (bool ok,) = _do(_debit(0, true));
        assertTrue(ok, "control: an unfrozen verifier");
        assertEq(tok.balanceOf(vm.addr(VKEY)), F * SCALE, "the verifier paid");
        vm.revertToState(snap);
        _freeze(_v());
        (bool ok2, bytes memory ret) = _do(_debit(0, true));
        assertFalse(ok2);
        assertEq(ret, abi.encodeWithSelector(IRegulatedToken.FeeRecipientFrozen.selector, _v()));
        _setFee(0);
        (bool ok3,) = _do(_debit(0, true));
        assertTrue(ok3, "relief: fee 0, the frozen verifier is checked no more");
        _setFee(F);
        (bool ok4, bytes memory ret4) = _do(_debit(0, true));
        assertFalse(ok4, "the fee restored: halted again");
        assertEq(ret4, abi.encodeWithSelector(IRegulatedToken.FeeRecipientFrozen.selector, _v()));
    }

    /// A denied verifier (`DENYLIST`, its `R` fails) halts the debit while `vf ≠ 0`; at fee 0 it lands.
    function test_deniedVerifier_notEligibleWhileFeeSet() public {
        _attestDenied(_v());
        (bool ok, bytes memory ret) = _do(_debit(0, true));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IRegulatedToken.NotEligible.selector, _v(), uint8(0)));
        _setFee(0);
        (bool ok2,) = _do(_debit(0, true));
        assertTrue(ok2, "control: fee 0");
    }

    /// M22: the verifier's check runs before `_pullShieldIn` (a `shieldIn` above the cap's room is refused there) and before
    /// the library (an empty verdict is refused there).
    function test_verifierCheckedFirst() public {
        _freeze(_v());
        bytes memory frozen = abi.encodeWithSelector(IRegulatedToken.FeeRecipientFrozen.selector, _v());
        (, bytes memory r1) = _do(_debit(uint256(1) << 41, true));
        assertEq(r1, frozen, "before _pullShieldIn");
        (, bytes memory r2) = _do(_debit(0, false));
        assertEq(r2, frozen, "before the library");
        _setFee(0);
        (, bytes memory r3) = _do(_debit(uint256(1) << 41, true));
        assertEq(bytes4(r3), IPqzToken.AmountOutOfRange.selector, "control: fee 0, the pull's own refusal");
    }

    /// Round 3s x 3t (spec §6.4, T31; CTR-AS-25 on 3s's lists): the token's own deny list, enabled after creation by the admin
    /// (`enableFeature(9)`, at once), halts every debit once the verifier is on it (`Denied(v)`, the fee leg's `L`) while
    /// `vf != 0`; shields still land; `setVerifierFee(0)` restores the debit at once (no notice for a decrease). `ALLOWLIST` (8)
    /// is outside the confidential kinds' mask (CTR-GOV-17): `enableFeature(8)` refuses `FeatureInvalidForKind(8)`, so no allow
    /// list can leave the verifier unlisted on 12 or 13.
    function test_deniedListVerifier_haltsDebits_shieldsLand_feeZeroRestores() public {
        vm.prank(ownerA);
        (bool okA, bytes memory rA) = address(tok).call(abi.encodeCall(IRegulatedToken.enableFeature, (GovernanceBits.ALLOWLIST)));
        assertFalse(okA);
        assertEq(rA, abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, GovernanceBits.ALLOWLIST), "no allow list here");
        vm.prank(ownerA);
        _r().enableFeature(GovernanceBits.DENYLIST);
        bytes32[] memory v = new bytes32[](1);
        v[0] = _v();
        vm.prank(issuer);
        _r().setDenied(v, true);
        (bool ok, bytes memory ret) = _do(_debit(0, true));
        assertFalse(ok, "the listed verifier halts the debit");
        assertEq(ret, abi.encodeWithSelector(IRegulatedToken.Denied.selector, _v()));
        uint256 before = tok.totalShielded();
        _shieldTo(alice, 7);
        assertEq(tok.totalShielded(), before + 7, "a shield still lands");
        _setFee(0);
        (bool ok2,) = _do(_debit(0, true));
        assertTrue(ok2, "relief: fee 0 at once, the listed verifier is checked no more");
        assertEq(tok.balanceOf(vm.addr(VKEY)), 0, "nothing paid to it");
    }
}

contract PqzVerifierFeeKind12Test is PqzVerifierFeeKinds {
    function _isWrapped() internal pure override returns (bool) { return false; }
}

contract PqzVerifierFeeKind13Test is PqzVerifierFeeKinds {
    function _isWrapped() internal pure override returns (bool) { return true; }
}
