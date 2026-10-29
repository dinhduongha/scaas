// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzFixture} from "./helpers/PqzFixture.sol";
import {PQZ_UID, PQZH_ID} from "./helpers/PqzRegistryBase.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {NoUnderlyingPqzToken} from "../../src/pqz/NoUnderlyingPqzToken.sol";
import {Catalogue, pqzEnv} from "../helpers/Catalogue.sol";

/// The token guards of the contracts review fix round (review2 T1, 2026-10-27): PQZH value tokens only at sets that
/// have them and only for single-key holders (C2-1, C0-2), the auditor (C2-3), `_keyPtr` on the value-in paths (C2-4),
/// `shieldIn` pulled first (C2-5), a failed precompile call is no verdict (C2-6), the interface views (C2-7), the fee
/// beneficiary needs no PQZ key (C0-7).
contract PqzGuardsTest is PqzFixture {
    bytes32 internal dave; // a second ordinary holder (registered before a PQZH verifier replaces the PoP mock)

    function setUp() public {
        _stack();
        dave = _pqzUA(_pk(20), 10);
        tok = _newToken("pqz");
    }

    /// A release (and one token) of the PQZH verifier at this set.
    function _pqzh(bytes32 salt_) internal returns (PqzLayer) {
        pqv = _newPqzVerifier(PQZH_ID);
        factory = new OpenFactory(registrar, PQZ_UID, 0);
        Catalogue.release(factory, IOpenFactory.TokenKind.NONE_PQZ, 1,
            pqzEnv(address(factory), PQZ_UID, address(reg), address(pqv)), type(NoUnderlyingPqzToken).creationCode);
        vm.prank(registrar);
        factory.setKindEnabled(IOpenFactory.TokenKind.NONE_PQZ, true);
        return _newToken(salt_);
    }

    function _kind(bytes32 ua, uint16 k) internal {
        vm.mockCall(address(reg), abi.encodeWithSelector(IUARegistry.kindOf.selector, ua), abi.encode(k));
    }

    // ------------------------------------------------------------------ C2-1: no PQZH value token without PQZH_VALUE

    function test_init_pqzhRefusedWithoutValueSets() public {
        vm.skip(!PqzSet.HAS_PQZH || PqzSet.PQZH_VALUE);
        pqv = _newPqzVerifier(PQZH_ID);
        factory = new OpenFactory(registrar, PQZ_UID, 0);
        Catalogue.release(factory, IOpenFactory.TokenKind.NONE_PQZ, 1,
            pqzEnv(address(factory), PQZ_UID, address(reg), address(pqv)), type(NoUnderlyingPqzToken).creationCode);
        vm.prank(registrar);
        factory.setKindEnabled(IOpenFactory.TokenKind.NONE_PQZ, true);
        vm.expectRevert(IPqzToken.PqzhValueUnsupported.selector);
        factory.createToken(IOpenFactory.TokenKind.NONE_PQZ, 1, abi.encode(_cfg(uint256(1) << 40)), "pqzh");
    }

    function test_pqzhValue_flagMatchesTheSet() public pure {
        assertEq(PqzSet.PQZH_VALUE, keccak256(bytes(PqzSet.NAME)) == keccak256("n2048-kmax1024"));
    }

    // ------------------------------------------------------------------ C0-2: holder kinds on a PQZH value token

    function test_pqzhValue_msigHolderRefused() public {
        vm.skip(!PqzSet.PQZH_VALUE);
        PqzLayer h = _pqzh("pqzh");
        _fund(h, alice, 1000);
        _kind(bob, UAKinds.MSIG);
        bytes memory err = abi.encodeWithSelector(IPqzToken.PqzhHolderKind.selector, bob, UAKinds.MSIG);
        _public(h, address(this), 10 * SCALE);
        vm.expectRevert(err); // shield
        h.mtxShield(bob, 1);
        bytes memory pl = _payloadFor(h, alice, bob, bytes32(0), _out(1, true));
        vm.expectRevert(err); // op 1 credit leg
        h.mtxConfidentialTransferSingle(pl, hex"c0de", _mlAuth(), _benT(pl), "");
        bytes32[] memory rec = new bytes32[](1);
        rec[0] = bob;
        _mockOp(7, 1);
        pl = _mpayload(h.pqzAccount(alice).pendingCount, 0, alice, 0, rec, _blob(2, _outLen(1, true)), "");
        vm.expectRevert(err); // op 7 leg
        h.mtxConfidentialTransfer(pl, hex"c0de", _mlAuth(), _benM(pl), "");
        // the fee beneficiary is exempt: a public credit, no pending entry
        _kind(carol, UAKinds.MSIG);
        _transfer(h, alice, dave, carol, 3, true);
        assertEq(h.balanceOfUA(carol), FEE * SCALE, "an msig beneficiary is paid");
    }

    function test_pqzhValue_singleKeyHolders() public {
        vm.skip(!PqzSet.PQZH_VALUE);
        PqzLayer h = _pqzh("pqzh");
        _fund(h, alice, 1000);
        uint16[3] memory ks = [UAKinds.MLDSA44, UAKinds.MLDSA65, UAKinds.FNDSA512];
        for (uint256 i; i < 3; ++i) {
            _kind(bob, ks[i]);
            _public(h, address(this), SCALE);
            h.mtxShield(bob, 1);
            _mirrorTrivial(h, bob, 1);
            _transfer(h, alice, bob, bytes32(0), 10 + i, true);
        }
        assertEq(h.pqzAccount(bob).pendingCount, 6, "three shields and three credits");
    }

    // ------------------------------------------------------------------ C2-3: a zero auditor

    function test_init_zeroAuditorRefused() public {
        uint8[2] memory modes = [uint8(ZetherTypes.AuditorMode.FULL), uint8(ZetherTypes.AuditorMode.OPTIONAL)];
        for (uint256 i; i < 2; ++i) {
            IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
            c.conf.auditorMode = modes[i];
            c.conf.auditorKey = abi.encode(bytes32(0));
            vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, bytes32(0)));
            factory.createToken(IOpenFactory.TokenKind.NONE_PQZ, 1, abi.encode(c), bytes32(i + 1));
        }
    }

    // ------------------------------------------------------------------ C2-4: value-in checks use _keyPtr

    function test_valueIn_keyOfAnotherLengthRefused() public {
        (, bytes32 ph, bool proven) = reg.pqzKeyOf(bob);
        vm.mockCall(address(reg), abi.encodeWithSelector(IUARegistry.pqzKeyOf.selector, bob), abi.encode(address(ct), ph, proven));
        bytes memory err = abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, bob);
        _public(tok, address(this), SCALE);
        vm.expectRevert(err);
        tok.mtxShield(bob, 1);
        vm.expectRevert(err);
        tok.mtxPrepareAcc(bob, 0);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.conf.auditorKey = abi.encode(bob);
        vm.expectRevert(err);
        factory.createToken(IOpenFactory.TokenKind.NONE_PQZ, 1, abi.encode(c), "badaud");
    }

    // ------------------------------------------------------------------ C2-5: shieldIn is pulled before the library

    function test_relay_shieldInPulledBeforeTheLibrary() public {
        _fund(tok, alice, 10);
        bytes memory pl = _payload(tok.pqzAccount(alice).pendingCount, 1000, alice, bob, bytes32(0), _out(1, true), "");
        vm.expectCall(PQZ, abi.encodePacked(uint8(1)), 0);
        vm.expectCall(address(reg), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector), 0);
        vm.expectRevert(); // ERC20InsufficientBalance of the signer: nothing to move
        tok.mtxConfidentialTransferSingle(pl, hex"c0de", _mlAuth(), _benT(pl), "");
    }

    function test_relay_shieldInAboveTheCapIsStillAmountOutOfRange() public {
        _fund(tok, alice, 10);
        uint256 room = tok.maxShielded() - tok.totalShielded();
        bytes memory pl = _payload(tok.pqzAccount(alice).pendingCount, type(uint256).max, alice, bob, bytes32(0),
            _out(1, true), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AmountOutOfRange.selector, type(uint256).max, room));
        tok.mtxConfidentialTransferSingle(pl, hex"c0de", _mlAuth(), _benT(pl), "");
    }

    // ------------------------------------------------------------------ C2-6: a failed precompile call is no verdict

    function test_verdict_failedCallRevertsNotRejects() public {
        _fund(tok, alice, 10);
        vm.mockCallRevert(PQZ, abi.encodePacked(uint8(1)), "");
        bytes memory pl = _payloadFor(tok, alice, bob, bytes32(0), _out(1, true));
        vm.expectRevert(UAKinds.UAVerifyGas.selector);
        tok.mtxConfidentialTransferSingle(pl, hex"c0de", _mlAuth(), _benT(pl), "");
    }

    function test_verifyTransferAmount_failedCallRevertsShapeErrorsAreFalse() public {
        _fund(tok, alice, 10);
        (bytes32 ref,) = _transfer(tok, alice, bob, bytes32(0), 5, true);
        assertTrue(tok.verifyTransferAmount(ref, 0, 123, 0, hex"0a0b"));
        assertFalse(tok.verifyTransferAmount(ref, 1, 123, 0, hex"0a0b"), "no leg 1");
        assertFalse(tok.verifyTransferAmount(keccak256("x"), 0, 123, 0, hex"0a0b"), "unknown entry");
        vm.mockCallRevert(PQZ, abi.encodePacked(uint8(4)), "");
        vm.expectRevert(UAKinds.UAVerifyGas.selector);
        tok.verifyTransferAmount(ref, 0, 123, 0, hex"0a0b");
    }

    // ------------------------------------------------------------------ C2-7: the views are in IPqzToken

    function test_interface_declaresTheViews() public {
        _fund(tok, alice, 10);
        IPqzToken t = IPqzToken(address(tok));
        assertEq(t.pqzAccount(alice).pendingCount, 1);
        assertEq(t.pqzAcc(alice).length, tok.pqzAcc(alice).length);
        assertEq(t.pqzPending(alice, 0), tok.pqzPending(alice, 0));
        assertEq(t.pqzPendingCt(alice, 0).length, tok.pqzPendingCt(alice, 0).length);
        (bytes32 ref,) = _transfer(tok, alice, bob, bytes32(0), 5, true);
        assertEq(t.pqzEntryBlob(ref), tok.pqzEntryBlob(ref));
    }

    // ------------------------------------------------------------------ C0-7: the beneficiary needs no PQZ key

    function test_beneficiary_anyRegisteredUA() public {
        bytes32 k = _mldsaUA(20); // registered, no PQZ key
        _fund(tok, alice, 10);
        _transfer(tok, alice, bob, k, 1, true);
        assertEq(tok.balanceOfUA(k), FEE * SCALE, "the keyless UA is paid");
        bytes32 none = bytes32(uint256(1));
        bytes memory pl = _payloadFor(tok, alice, bob, none, _out(2, true));
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, none));
        tok.mtxConfidentialTransferSingle(pl, hex"c0de", _mlAuth(), _benT(pl), "");
    }

    // ------------------------------------------------------------------ C0-13: a short op 1 payload is BadPayload

    function test_C0_13_shortSinglePayloadIsBadPayload() public {
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadPayload.selector, uint256(100)));
        tok.transferSingleStatement(new bytes(100), bytes32(0));
    }
}
