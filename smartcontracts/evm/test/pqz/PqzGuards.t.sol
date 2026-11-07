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
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {Catalogue, pqzEnv} from "../helpers/Catalogue.sol";

/// A registry frame that runs out of gas: `INVALID` spends all the gas it was given and reverts with no data.
contract OutOfGas {
    fallback() external {
        assembly ("memory-safe") { invalid() }
    }
}

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
        Catalogue.release(factory, IOpenFactory.TokenKind.NORMAL_PQZ, 1,
            pqzEnv(address(factory), PQZ_UID, address(reg), address(pqv)), type(NormalPqzToken).creationCode);
        vm.prank(registrar);
        factory.setKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ, true);
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
        Catalogue.release(factory, IOpenFactory.TokenKind.NORMAL_PQZ, 1,
            pqzEnv(address(factory), PQZ_UID, address(reg), address(pqv)), type(NormalPqzToken).creationCode);
        vm.prank(registrar);
        factory.setKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ, true);
        vm.expectRevert(IPqzToken.PqzhValueUnsupported.selector);
        factory.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(_cfg(uint256(1) << 40)), "pqzh");
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
        h.mtxConfidentialTransferSingle(_ts(pl), hex"c0de", _pqAuth(), "");
        bytes32[] memory rec = new bytes32[](1);
        rec[0] = bob;
        _mockOp(7, 1);
        pl = _mpayload(h.pqzAccount(alice, 0).pendingCount, 0, alice, 0, rec, _blob(2, _outLen(1, true)), "");
        vm.expectRevert(err); // op 7 leg
        h.mtxConfidentialTransfer(_ms(pl), hex"c0de", _pqAuth(), "");
        // the fee beneficiary is exempt: a public credit, no pending entry
        _kind(carol, UAKinds.MSIG);
        _transfer(h, alice, dave, carol, 3, true);
        assertEq(h.balanceOfUA(carol), FEE * SCALE, "an msig beneficiary is paid");
    }

    function test_pqzhValue_singleKeyHolders() public {
        vm.skip(!PqzSet.PQZH_VALUE);
        PqzLayer h = _pqzh("pqzh");
        _fund(h, alice, 1000);
        uint16[5] memory ks = [UAKinds.MLDSA44, UAKinds.MLDSA65, UAKinds.FNDSA512, UAKinds.MLDSA87, UAKinds.FNDSA1024]; // CTR-UA-39 / -40 Q2
        for (uint256 i; i < 5; ++i) {
            _kind(bob, ks[i]);
            _public(h, address(this), SCALE);
            h.mtxShield(bob, 1);
            _mirrorTrivial(h, bob, 1);
            _transfer(h, alice, bob, bytes32(0), 10 + i, true);
        }
        assertEq(h.pqzAccount(bob, 0).pendingCount, 10, "five shields and five credits");
    }

    // ------------------------------------------------------------------ C2-3: a zero auditor

    function test_init_zeroAuditorRefused() public {
        uint8[2] memory modes = [uint8(ZetherTypes.AuditorMode.FULL), uint8(ZetherTypes.AuditorMode.OPTIONAL)];
        for (uint256 i; i < 2; ++i) {
            IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
            c.conf.auditorMode = modes[i];
            c.conf.auditorKey = abi.encode(bytes32(0));
            vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, bytes32(0)));
            factory.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), bytes32(i + 1));
        }
    }

    // ------------------------------------------------------------------ C2-4: value-in checks use _keyPtr

    function test_valueIn_keyOfAnotherLengthRefused() public {
        (uint64 v,, bytes32 ph, bool proven) = reg.pqzKeyOf(bob);
        vm.mockCall(address(reg), abi.encodeWithSelector(IUARegistry.pqzKeyOf.selector, bob), abi.encode(v, address(ct), ph, proven));
        // group 3g T52 (KV-10): the prepare reads the version it names, `pqzKeyAt(bob, 0)`
        vm.mockCall(address(reg), abi.encodeCall(IUARegistry.pqzKeyAt, (bob, uint64(0))), abi.encode(address(ct), ph, proven));
        bytes memory err = abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, bob);
        _public(tok, address(this), SCALE);
        vm.expectRevert(err);
        tok.mtxShield(bob, 1);
        vm.expectRevert(err);
        tok.mtxPrepareAcc(bob, 0, 0);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.conf.auditorKey = abi.encode(bob);
        vm.expectRevert(err);
        factory.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), "badaud");
    }

    // ------------------------------------------------------------------ C2-5: shieldIn is pulled before the library

    function test_relay_shieldInPulledBeforeTheLibrary() public {
        _fund(tok, alice, 10);
        bytes memory pl = _payload(tok.pqzAccount(alice, 0).pendingCount, 1000, alice, bob, bytes32(0), _out(1, true), "");
        vm.expectCall(PQZ, abi.encodePacked(uint8(1)), 0);
        vm.expectCall(address(reg), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector), 0);
        vm.expectRevert(); // ERC20InsufficientBalance of the signer: nothing to move
        tok.mtxConfidentialTransferSingle(_ts(pl), hex"c0de", _pqAuth(), "");
    }

    function test_relay_shieldInAboveTheCapIsStillAmountOutOfRange() public {
        _fund(tok, alice, 10);
        uint256 room = tok.maxShielded() - tok.totalShielded();
        bytes memory pl = _payload(tok.pqzAccount(alice, 0).pendingCount, type(uint256).max, alice, bob, bytes32(0),
            _out(1, true), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AmountOutOfRange.selector, type(uint256).max, room));
        tok.mtxConfidentialTransferSingle(_ts(pl), hex"c0de", _pqAuth(), "");
    }

    // ------------------------------------------------------------------ C2-6: a failed precompile call is no verdict

    function test_verdict_failedCallRevertsNotRejects() public {
        _fund(tok, alice, 10);
        vm.mockCallRevert(PQZ, abi.encodePacked(uint8(1)), "");
        bytes memory pl = _payloadFor(tok, alice, bob, bytes32(0), _out(1, true));
        vm.expectRevert(UAKinds.UAVerifyGas.selector);
        tok.mtxConfidentialTransferSingle(_ts(pl), hex"c0de", _pqAuth(), "");
    }

    /// Review M5 (nested-msig reviews, 2026-11-04): the authority's registry frame out of gas (no revert data, at most the 1/64
    /// `_check` kept) is a starvation, `UAVerifyGas`, as `UAStore.via` reads it, never `AuthRejected`.
    function test_check_registryOutOfGasIsVerifyGas() public {
        _fund(tok, alice, 10);
        bytes memory pl = _payloadFor(tok, alice, bob, bytes32(0), _out(1, true));
        vm.mockFunction(address(reg), address(new OutOfGas()), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector));
        vm.expectRevert(UAKinds.UAVerifyGas.selector);
        tok.mtxConfidentialTransferSingle(_ts(pl), hex"c0de", _pqAuth(), "");
    }

    /// The control: an empty revert that returns its gas is a rejection, `AuthRejected`.
    function test_check_registryEmptyRevertWithGasIsAuthRejected() public {
        _fund(tok, alice, 10);
        bytes memory pl = _payloadFor(tok, alice, bob, bytes32(0), _out(1, true));
        vm.mockCallRevert(address(reg), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector), "");
        vm.expectRevert(IPqzToken.AuthRejected.selector);
        tok.mtxConfidentialTransferSingle(_ts(pl), hex"c0de", _pqAuth(), "");
    }

    function test_verifyTransferAmount_failedCallRevertsShapeErrorsAreFalse() public {
        _fund(tok, alice, 10);
        (bytes32 ref,) = _transfer(tok, alice, bob, bytes32(0), 5, true);
        assertTrue(tok.verifyTransferAmount(ref, 0, 123, 0, 0, hex"0a0b"));
        assertFalse(tok.verifyTransferAmount(ref, 1, 123, 0, 0, hex"0a0b"), "no leg 1");
        assertFalse(tok.verifyTransferAmount(keccak256("x"), 0, 123, 0, 0, hex"0a0b"), "unknown entry");
        vm.mockCallRevert(PQZ, abi.encodePacked(uint8(4)), "");
        vm.expectRevert(UAKinds.UAVerifyGas.selector);
        tok.verifyTransferAmount(ref, 0, 123, 0, 0, hex"0a0b");
    }

    // ------------------------------------------------------------------ C2-7: the views are in IPqzToken

    function test_interface_declaresTheViews() public {
        _fund(tok, alice, 10);
        IPqzToken t = IPqzToken(address(tok));
        assertEq(t.pqzAccount(alice, 0).pendingCount, 1);
        assertEq(t.pqzAcc(alice, 0).length, tok.pqzAcc(alice, 0).length);
        assertEq(t.pqzPending(alice, 0, 0), tok.pqzPending(alice, 0, 0));
        assertEq(t.pqzPendingCt(alice, 0, 0).length, tok.pqzPendingCt(alice, 0, 0).length);
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
        tok.mtxConfidentialTransferSingle(_ts(pl), hex"c0de", _pqAuth(), "");
    }

    // ------------------------------------------------------------------ C0-13: an op 1 of empty parts is BadPayload

    function test_C0_13_emptySinglePartsAreBadPayload() public {
        IPqzToken.PqzTransferArgs memory t;
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadPayload.selector, uint256(0)));
        tok.transferSingleStatement(t, bytes32(0));
    }
}
