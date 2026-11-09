// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzOffchainBase} from "./helpers/PqzOffchainBase.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {IPqzToken, PqzVerifierRevoked} from "../../src/pqz/IPqzToken.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UACall} from "../ua/UACall.sol";
import {Catalogue, pqzEnv} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";
import {PQZ_UID} from "./helpers/PqzRegistryBase.sol";

/// Group 3f, T44 (PQZ verifier mode spec §4; CTR-PQZ-28 draft): the verifier UA's kinds (registered, spec §4.1's table),
/// its frozen shape, the owner's transfer with the factory's notice period (proposer, owner generation, `[eta, eta +
/// notice]`), the cancel and the immediate revocation; fixed means none of them. UNAUDITED.
contract PqzVerifierTest is PqzOffchainBase {
    uint64 internal constant NOTICE = 3 days;
    OpenFactory internal fN; // a factory whose notice period is 3 days
    bytes32 internal me;

    function setUp() public {
        _offStack();
        me = nid(address(this));
        fN = new OpenFactory(registrar);
        EnvKit.configure(fN, PQZ_UID, NOTICE, address(0));
        Catalogue.release(fN, IOpenFactory.TokenKind.NORMAL_PQZ, 1, pqzEnv(address(fN), PQZ_UID, address(reg), address(pqv)),
            type(NormalPqzToken).creationCode);
        vm.prank(registrar);
        fN.setKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ, true);
        vm.warp(block.timestamp + NOTICE); // the release usable
    }

    function _cfgOf(bytes32 v, bool fixed_, bytes32 owner_) internal returns (IFactoryToken.TokenConfig memory c) {
        (vMode, vUA, vFixed) = (PqzCore.OFFCHAIN, v, fixed_);
        c = _cfg(uint256(1) << 40);
        (vMode, vUA, vFixed) = (0, bytes32(0), false);
        c.owner = owner_;
    }

    /// An OFFCHAIN token with verifier `v` on the factory `f` (owner: this test).
    function _tok(OpenFactory f, bytes32 v, bool fixed_) internal returns (NormalPqzToken) {
        return NormalPqzToken(f.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(_cfgOf(v, fixed_, me)),
            keccak256(abi.encode(v, fixed_, gasleft()))));
    }

    function _tryCreate(bytes32 v) internal returns (bool ok, bytes memory err) {
        try factory.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(_cfgOf(v, false, me)),
            keccak256(abi.encode(v, gasleft()))) returns (address) {
            ok = true;
        } catch (bytes memory e) {
            err = e;
        }
    }

    function _kindErr(uint16 k) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IPqzToken.PqzVerifierKind.selector, k);
    }

    /// A derived id the registry reports as `kind` (mocked: the registry's own kind rules are not under test here).
    function _asKind(bytes32 id, uint16 kind) internal {
        vm.mockCall(address(reg), abi.encodeCall(IUARegistry.kindOf, (id)), abi.encode(kind));
    }

    /// An `msig` of `members` (kind, id), each weight 1, threshold `k`, the given slots accepted (mocked).
    function _asMsig(bytes32 id, uint16 k, uint16[] memory kinds, bytes32[] memory ids, bool[] memory accepted) internal {
        _asKind(id, UAKinds.MSIG);
        IUARegistry.MsigStructure memory m;
        m.threshold = k;
        m.members = new IUARegistry.MsigMember[](kinds.length);
        for (uint256 i; i < kinds.length; ++i) {
            m.members[i] = IUARegistry.MsigMember(kinds[i], ids[i], 1);
            vm.mockCall(address(reg), abi.encodeCall(IUARegistry.memberAccepted, (id, i)), abi.encode(accepted[i]));
        }
        vm.mockCall(address(reg), abi.encodeCall(IUARegistry.msigOf, (id)), abi.encode(m));
    }

    function _three(uint16 a, uint16 b, uint16 c) internal pure returns (uint16[] memory k) {
        k = new uint16[](3);
        (k[0], k[1], k[2]) = (a, b, c);
    }

    function _ids(bytes32 a, bytes32 b, bytes32 c) internal pure returns (bytes32[] memory k) {
        k = new bytes32[](3);
        (k[0], k[1], k[2]) = (a, b, c);
    }

    function _acc(bool a, bool b, bool c) internal pure returns (bool[] memory k) {
        k = new bool[](3);
        (k[0], k[1], k[2]) = (a, b, c);
    }

    // ------------------------------------------------------------------ kinds (spec §4.1, AV-3)

    /// Controls: a native EOA, `secp256k1`, `p256`, `webauthn-p256`, `mldsa65` (a real registration), a 2-of-3 `msig`.
    function test_verifierKind_controls() public {
        (bool ok,) = _tryCreate(vA);
        assertTrue(ok, "EOA");
        uint16[4] memory k = [UAKinds.SECP256K1, UAKinds.P256, UAKinds.WEBAUTHN_P256, UAKinds.MLDSA44];
        for (uint256 i; i < 4; ++i) {
            bytes32 id = keccak256(abi.encode("derived", i));
            _asKind(id, k[i]);
            (ok,) = _tryCreate(id);
            assertTrue(ok, "derived kind");
        }
        (ok,) = _tryCreate(_mldsaUA(61));
        assertTrue(ok, "mldsa65");
        bytes32 ms = keccak256("msig 2-of-3");
        _asMsig(ms, 2, _three(UAKinds.EVM_EOA, UAKinds.SECP256K1, UAKinds.MLDSA65), _ids(vB, keccak256("s"), keccak256("m")),
            _acc(true, true, false));
        (ok,) = _tryCreate(ms);
        assertTrue(ok, "2-of-3 msig");
    }

    function test_verifierKind_refused() public {
        uint16[4] memory k = [UAKinds.MLDSA87, UAKinds.ZETHER_BLS12381, UAKinds.BLS12381_MINSIG, UAKinds.SCHNORR_BN254];
        for (uint256 i; i < 4; ++i) {
            bytes32 id = keccak256(abi.encode("refused", i));
            _asKind(id, k[i]);
            vm.expectRevert(_kindErr(k[i]));
            _tryCreateStrict(id);
        }
        vm.etch(address(0xC0DE), hex"00"); // a native id with code (ERC-1271)
        vm.expectRevert(_kindErr(UAKinds.EVM_CONTRACT));
        _tryCreateStrict(nid(address(0xC0DE)));
        bytes32 ms = keccak256("msig with mldsa87");
        _asMsig(ms, 2, _three(UAKinds.MLDSA65, UAKinds.MLDSA87, UAKinds.SECP256K1), _ids(keccak256("a"), keccak256("b"),
            keccak256("c")), _acc(true, true, true));
        vm.expectRevert(_kindErr(UAKinds.MLDSA87));
        _tryCreateStrict(ms);
        bytes32 nested = keccak256("nested msig");
        _asMsig(nested, 1, _three(UAKinds.MLDSA65, UAKinds.MSIG, UAKinds.SECP256K1), _ids(keccak256("a"), ms,
            keccak256("c")), _acc(true, true, true));
        vm.expectRevert(_kindErr(UAKinds.MSIG));
        _tryCreateStrict(nested);
        bytes32 withContract = keccak256("msig with a contract member");
        _asMsig(withContract, 1, _three(UAKinds.MLDSA65, UAKinds.EVM_CONTRACT, UAKinds.SECP256K1), _ids(keccak256("a"),
            nid(address(0xC0DE)), keccak256("c")), _acc(true, true, true));
        vm.expectRevert(_kindErr(UAKinds.EVM_CONTRACT));
        _tryCreateStrict(withContract);
        bytes32 eoaWithCode = keccak256("msig with an EOA member that has code");
        _asMsig(eoaWithCode, 1, _three(UAKinds.MLDSA65, UAKinds.EVM_EOA, UAKinds.SECP256K1), _ids(keccak256("a"),
            nid(address(0xC0DE)), keccak256("c")), _acc(true, true, true));
        vm.expectRevert(_kindErr(UAKinds.EVM_CONTRACT));
        _tryCreateStrict(eoaWithCode);
    }

    function _tryCreateStrict(bytes32 v) internal {
        factory.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(_cfgOf(v, false, me)), keccak256(abi.encode(v)));
    }

    /// An unregistered derived id: `PqzVerifierUnregistered`, at init and at a proposal.
    function test_verifierKind_unregistered() public {
        bytes32 id = keccak256("never registered");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.PqzVerifierUnregistered.selector, id));
        _tryCreateStrict(id);
        NormalPqzToken t = _tok(fN, vA, false);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.PqzVerifierUnregistered.selector, id));
        t.pqzSetVerifier(id);
        _asKind(id, UAKinds.MLDSA87);
        vm.expectRevert(_kindErr(UAKinds.MLDSA87));
        t.pqzSetVerifier(id); // the kind check at the proposal
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.PqzVerifierUnregistered.selector, bytes32(0)));
        t.pqzSetVerifier(0); // the zero id: no transfer to "revoked"
    }

    // ------------------------------------------------------------------ the frozen shape (spec §4.1, C3)

    /// A shape from mocks: a 2-of-3 with an EOA member (`vB`), `secp256k1`, `mldsa65`; the third slot not yet accepted.
    function _msigVerifier() internal returns (bytes32 ms, NormalPqzToken t) {
        ms = keccak256("verifier msig");
        _asMsig(ms, 2, _three(UAKinds.EVM_EOA, UAKinds.SECP256K1, UAKinds.MLDSA65), _ids(vB, keccak256("s"), keccak256("m")),
            _acc(true, true, false));
        t = _tok(factory, ms, false);
        _shieldOn(t, alice, 10);
        // its signature: the registry's msig path is not under test here
        vm.mockCall(address(reg), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector, ms), "");
    }

    function _msigOp(NormalPqzToken t) internal view returns (IPqzToken.PqzTransferArgs memory a, IPqzToken.PqzSignedVerdict memory sv) {
        bytes memory st;
        (a, st) = _op1Of(t, alice, bob, 5, true);
        sv.pqzVerdict = _verdict(t, st, VPROOF);
    }

    function test_pqzVerdict_shapeChanged_msigMemberCode() public {
        (, NormalPqzToken t) = _msigVerifier();
        (IPqzToken.PqzTransferArgs memory a, IPqzToken.PqzSignedVerdict memory sv) = _msigOp(t);
        uint256 snap = vm.snapshotState();
        t.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv); // control
        vm.revertToState(snap);
        vm.etch(address(uint160(uint256(vB))), hex"00");
        vm.expectRevert(IPqzToken.PqzVerifierChanged.selector);
        t.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
    }

    function test_pqzVerdict_shapeChanged_slotAccepted() public {
        (bytes32 ms, NormalPqzToken t) = _msigVerifier();
        (IPqzToken.PqzTransferArgs memory a, IPqzToken.PqzSignedVerdict memory sv) = _msigOp(t);
        vm.mockCall(address(reg), abi.encodeCall(IUARegistry.memberAccepted, (ms, uint256(2))), abi.encode(true));
        vm.expectRevert(IPqzToken.PqzVerifierChanged.selector);
        t.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
    }

    /// A re-assignment through the notice accepts the new shape.
    function test_shape_reassignAccepts() public {
        NormalPqzToken t = _tok(factory, vA, false); // notice 0
        _shieldOn(t, alice, 10);
        vm.etch(address(uint160(uint256(vA))), hex"ef0100000000000000000000000000000000000000c0de"); // a 7702 designator
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op1Of(t, alice, bob, 5, true);
        IPqzToken.PqzSignedVerdict memory sv = _sv(t, st);
        vm.expectRevert(IPqzToken.PqzVerifierChanged.selector);
        t.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
        t.pqzSetVerifier(vB);
        t.pqzSetVerifier(vA); // a designator is an EOA: accepted, its new shape frozen
        t.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", _sv(t, st));
    }

    // ------------------------------------------------------------------ the transfer (spec §4.2, AV-4)

    function test_transfer_notReady() public {
        NormalPqzToken t = _tok(fN, vA, false);
        uint64 eta = uint64(block.timestamp) + NOTICE;
        vm.expectEmit(address(t));
        emit IPqzToken.PqzVerifierProposed(vA, vB, eta);
        t.pqzSetVerifier(vB);
        IPqzToken.PqzVerifyConfig memory c = t.pqzVerifyConfig();
        assertEq(c.pending, vB);
        assertEq(c.eta, eta);
        assertEq(c.noticePeriod, NOTICE);
        vm.warp(eta - 1);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.PqzVerifierNotReady.selector, eta));
        t.pqzSetVerifier(vB);
        assertEq(t.pqzVerifyConfig().verifier, vA, "still A");
    }

    function test_transfer_atEta() public {
        NormalPqzToken t = _tok(fN, vA, false);
        t.pqzSetVerifier(vB);
        vm.warp(block.timestamp + NOTICE);
        vm.expectEmit(address(t));
        emit IPqzToken.PqzVerifierSet(vA, vB, 1);
        t.pqzSetVerifier(vB);
        IPqzToken.PqzVerifyConfig memory c = t.pqzVerifyConfig();
        assertEq(c.verifier, vB);

        assertEq(c.pqzVerifierEpoch, 1);

        assertEq(c.pending, 0);
        // the window closes at eta + notice: a late confirm is a new proposal
        t.pqzSetVerifier(vA);
        vm.warp(block.timestamp + 2 * NOTICE + 1);
        t.pqzSetVerifier(vA);
        assertEq(t.pqzVerifyConfig().verifier, vB, "the dead pending did not apply");
        assertEq(t.pqzVerifyConfig().pending, vA, "a new proposal");
    }

    /// A confirm by anyone but the proposer: `NotProposer`; a proposal by a non-owner: `NotOwner`.
    function test_transfer_notProposer() public {
        NormalPqzToken t = _tok(fN, vA, false);
        vm.prank(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotOwner.selector, nid(address(0xBEEF))));
        t.pqzSetVerifier(vB);
        t.pqzSetVerifier(vB);
        vm.warp(block.timestamp + NOTICE);
        vm.prank(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotProposer.selector, uint8(0), vB, me));
        t.pqzSetVerifier(vB);
        vm.prank(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotOwner.selector, nid(address(0xBEEF))));
        t.pqzCancelVerifier();
        vm.prank(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotOwner.selector, nid(address(0xBEEF))));
        t.pqzRevokeVerifier();
    }

    /// An owner change between proposal and confirm kills the pending (`ownerGeneration`).
    function test_transfer_ownerChanged() public {
        NormalPqzToken t = _tok(fN, vA, false);
        t.pqzSetVerifier(vB);
        address o2 = address(0x0A2);
        IGovernance(address(t)).transferOwnership(nid(o2));
        vm.prank(o2);
        IGovernance(address(t)).acceptOwnership();
        vm.warp(block.timestamp + NOTICE);
        assertEq(t.pqzVerifyConfig().pending, 0, "dead");
        vm.prank(o2);
        t.pqzSetVerifier(vB); // a new proposal, not a confirm
        assertEq(t.pqzVerifyConfig().verifier, vA);
        assertEq(t.pqzVerifyConfig().pending, vB);
    }

    function test_transfer_fixed() public {
        NormalPqzToken t = _tok(fN, vA, true);
        vm.expectRevert(IPqzToken.PqzVerifierFixed.selector);
        t.pqzSetVerifier(vB);
        vm.expectRevert(IPqzToken.PqzVerifierFixed.selector);
        t.pqzCancelVerifier();
    }

    function test_transfer_same() public {
        NormalPqzToken t = _tok(fN, vA, false);
        vm.expectRevert(IPqzToken.PqzVerifierSame.selector);
        t.pqzSetVerifier(vA);
        t.pqzSetVerifier(vB);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.PqzVerifierPending.selector, vB));
        t.pqzSetVerifier(keccak256("another")); // another value while one is live
        vm.expectEmit(address(t));
        emit IPqzToken.PqzVerifierCancelled(vB);
        t.pqzCancelVerifier();
        assertEq(t.pqzVerifyConfig().pending, 0);
        t.pqzCancelVerifier(); // none live: nothing
    }

    /// A factory notice period 0: the first call applies at once.
    function test_transfer_zeroNotice() public {
        NormalPqzToken t = _tok(factory, vA, false);
        assertEq(t.pqzVerifyConfig().noticePeriod, 0);
        t.pqzSetVerifier(vB);
        assertEq(t.pqzVerifyConfig().verifier, vB);
        assertEq(t.pqzVerifyConfig().pqzVerifierEpoch, 1);
        assertEq(t.pqzVerifyConfig().pqzVerifyMode, PqzCore.OFFCHAIN, "I1: a transfer never writes the mode");
        t.pqzRevokeVerifier();
        assertEq(t.pqzVerifyConfig().pqzVerifyMode, PqzCore.OFFCHAIN, "I1: nor a revocation");
    }

    /// A PRECOMPILE token has no verifier: every op refuses `PqzVerifyConfigInvalid`.
    function test_transfer_precompileRefused() public {
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.owner = me;
        NormalPqzToken t = NormalPqzToken(factory.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), "precompile-owned"));
        vm.expectRevert(IPqzToken.PqzVerifyConfigInvalid.selector);
        t.pqzSetVerifier(vB);
        vm.expectRevert(IPqzToken.PqzVerifyConfigInvalid.selector);
        t.pqzCancelVerifier();
        vm.expectRevert(IPqzToken.PqzVerifyConfigInvalid.selector);
        t.pqzRevokeVerifier();
    }

    // ------------------------------------------------------------------ revocation (spec §4.3, R4)

    function test_revoke_immediate() public {
        NormalPqzToken t = _tok(fN, vA, false);
        vm.expectEmit(address(t));
        emit PqzVerifierRevoked(vA, 1);
        t.pqzRevokeVerifier();
        IPqzToken.PqzVerifyConfig memory c = t.pqzVerifyConfig();
        assertEq(c.verifier, 0);

        assertEq(c.pqzVerifierEpoch, 1);
        // a new verifier only after a full notice
        t.pqzSetVerifier(vB);
        vm.warp(block.timestamp + NOTICE - 1);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.PqzVerifierNotReady.selector, uint64(block.timestamp + 1)));
        t.pqzSetVerifier(vB);
        vm.warp(block.timestamp + 1);
        t.pqzSetVerifier(vB);
        assertEq(t.pqzVerifyConfig().verifier, vB);
        assertEq(t.pqzVerifyConfig().pqzVerifierEpoch, 2);
    }

    function test_revoke_deletesPending() public {
        NormalPqzToken t = _tok(fN, vA, false);
        t.pqzSetVerifier(vB);
        t.pqzRevokeVerifier();
        assertEq(t.pqzVerifyConfig().pending, 0);
        vm.warp(block.timestamp + NOTICE);
        t.pqzSetVerifier(vB); // a new proposal
        assertEq(t.pqzVerifyConfig().verifier, 0);
    }

    function test_revoke_fixedRefused() public {
        NormalPqzToken t = _tok(fN, vA, true);
        vm.expectRevert(IPqzToken.PqzVerifierFixed.selector);
        t.pqzRevokeVerifier();
    }
}
