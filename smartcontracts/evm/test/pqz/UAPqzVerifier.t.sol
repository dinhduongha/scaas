// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzRegistryBase, PQZL_ID, PQZH_ID} from "./helpers/PqzRegistryBase.sol";
import {UAPqzVerifier} from "../../src/pqz/UAPqzVerifier.sol";
import {PqzSafety} from "../../src/pqz/PqzSafety.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";

/// `UAPqzVerifier` (P6g plan Task 3, D3) and the `pqz-mlwe` kind in a gen-1 registry.
contract UAPqzVerifierTest is PqzRegistryBase {
    function test_constructorProbes() public {
        UAPqzVerifier v = _newPqzVerifier(PQZL_ID);
        assertEq(v.PRECOMPILE(), PQZ);
        assertEq(v.PROOF_SYSTEM_ID(), PQZL_ID);
        assertTrue(v.isSupportedOnThisChain());
        bytes memory pk = _slice(regStmt, 96, 16_384);
        bytes32 m = bytes32(_slice(regStmt, 64, 32));
        // the precompile accepting the flipped proof too: refused
        vm.mockCall(PQZ, abi.encodePacked(uint8(3)), abi.encode(uint256(1)));
        vm.expectRevert(UAPqzVerifier.UAPqzProbe.selector);
        new UAPqzVerifier(PQZ, PQZL_ID, pk, m, regProof);
        // accepting nothing: refused
        vm.mockCall(PQZ, abi.encodePacked(uint8(3)), abi.encode(uint256(0)));
        vm.clearMockedCalls();
        _mockSelfTest();
        vm.expectRevert(UAPqzVerifier.UAPqzProbe.selector);
        new UAPqzVerifier(PQZ, PQZL_ID, pk, m, regProof);
        vm.expectRevert(UAPqzVerifier.UAPqzProbe.selector);
        new UAPqzVerifier(PQZ, PQZL_ID, pk, m, "");
        // no self-test, other chain
        vm.clearMockedCalls();
        vm.expectRevert(abi.encodeWithSelector(PqzSafety.SelfTestFailed.selector, PQZ));
        new UAPqzVerifier(PQZ, PQZL_ID, pk, m, regProof);
        vm.chainId(22776);
        vm.expectRevert(abi.encodeWithSelector(PqzSafety.NotAllowedChain.selector, 22776));
        new UAPqzVerifier(PQZ, PQZL_ID, pk, m, regProof);
    }

    /// Review W-B: only the `PQZ` precompile, only PQZL / PQZH, only the pinned vector of that id.
    function test_constructorPins() public {
        UAPqzVerifier v = _newPqzVerifier(PQZL_ID);
        bytes memory pk = _slice(regStmt, 96, 16_384);
        bytes32 m = bytes32(_slice(regStmt, 64, 32));
        address fake = address(0xFA4E);
        vm.mockCall(fake, hex"0600000000", abi.encode(PqzSafety.SELFTEST));
        vm.mockCall(fake, abi.encodePacked(uint8(3)), abi.encode(uint256(0)));
        vm.expectRevert(abi.encodeWithSelector(PqzSafety.NotPqz.selector, fake, PQZL_ID));
        new UAPqzVerifier(fake, PQZL_ID, pk, m, regProof);
        bytes32 other = keccak256("another proof system");
        vm.expectRevert(abi.encodeWithSelector(PqzSafety.NotPqz.selector, PQZ, other));
        new UAPqzVerifier(PQZ, other, pk, m, regProof);
        // the PQZL vector under the PQZH id: the precompile (mocked) would accept it, the pin does not
        bytes memory st = bytes.concat(_slice(regStmt, 0, 32), PQZH_ID, _slice(regStmt, 64, 16_416));
        vm.mockCall(PQZ, abi.encodePacked(uint8(3), uint32(16_480), st, regProof), abi.encode(uint256(1)));
        vm.expectRevert(UAPqzVerifier.UAPqzProbe.selector);
        new UAPqzVerifier(PQZ, PQZH_ID, pk, m, regProof);
        // another message or key with the right proof: refused before the precompile
        vm.expectRevert(UAPqzVerifier.UAPqzProbe.selector);
        new UAPqzVerifier(PQZ, PQZL_ID, pk, keccak256("m"), regProof);
        assertEq(v.PRECOMPILE(), PQZ);
    }

    /// The input is exactly `u8(3) ‖ be32(16,480) ‖ opTag ‖ psid ‖ message ‖ pk ‖ proof`; the verdict only the word 1.
    function test_verifyInputAndVerdict() public {
        UAPqzVerifier v = _newPqzVerifier(PQZH_ID);
        bytes memory pk = _slice(regStmt, 96, 16_384);
        bytes32 m = keccak256("message");
        bytes memory input = abi.encodePacked(uint8(3), uint32(16_480), _slice(regStmt, 0, 32), PQZH_ID, m, pk, hex"0102");
        vm.mockCall(PQZ, input, abi.encode(uint256(1)));
        vm.expectCall(PQZ, input);
        assertTrue(v.verifyPop(pk, m, hex"0102"));
        assertTrue(v.verify(pk, m, hex"0102"));
        vm.mockCall(PQZ, input, abi.encode(uint256(2)));
        assertFalse(v.verifyPop(pk, m, hex"0102"), "only the word 1");
        vm.mockCall(PQZ, input, abi.encodePacked(uint256(1), uint8(0)));
        assertFalse(v.verifyPop(pk, m, hex"0102"), "only 32 bytes");
        vm.mockCall(PQZ, input, abi.encode(uint256(1)));
        // a coefficient = q, or a short key: false without asking the precompile
        bytes memory bad = bytes.concat(pk);
        bad[2] = 0x04; // coefficient 0 ≥ 2^42 > q
        assertFalse(v.verifyPop(bad, m, hex"0102"));
        assertFalse(v.verifyPop(_slice(pk, 0, 16_352), m, hex"0102"));
    }

    /// UA-6: an `mldsa65` holder registers with its PQZ key in one call; `R_REG` reaches the precompile over
    /// `uaMessage(0x0142, POP, popDigest(signerUA, h))`; the signer signs for its PQZ account (purpose `zether-auth`).
    function test_registerPqzKey() public {
        _registryStack();
        assertTrue(reg.kindEnabled(UAKinds.PQZ_MLWE));
        assertEq(reg.verifyCap(UAKinds.PQZ_MLWE), CAP_PQZ);
        bytes memory pk = _slice(regStmt, 96, 16_384);
        bytes32 ua = reg.uaOf(UAKinds.MLDSA65, _mlPk(1));
        bytes32 h = reg.keyHashOf(UAKinds.PQZ_MLWE, pk);
        bytes32 msg_ = reg.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP, reg.popDigest(ua, h));
        bytes memory input = abi.encodePacked(uint8(3), uint32(16_480), _slice(regStmt, 0, 32), PQZL_ID, msg_, pk, hex"aa");
        vm.mockCall(PQZ, input, abi.encode(uint256(1)));
        vm.expectCall(PQZ, input);
        uint256 g = gasleft();
        assertEq(_pqzUA(pk, 1), ua);
        emit log_named_uint("register mldsa65 + PQZ key (mocked R_REG, filler ML-DSA PoP) gas", g - gasleft());
        assertEq(reg.kindOf(ua), UAKinds.MLDSA65);
        (, address ptr) = reg.recordOf(ua);
        assertEq(ptr.code, bytes.concat(hex"00", pk));
        assertEq(reg.keyOwner(h), ua);
        reg.requireAuthorized(ua, UAKinds.PURPOSE_ZETHER_AUTH, keccak256("d"), _mlAuth());
    }

    function test_registerRefused() public {
        _registryStack();
        bytes memory pk = _slice(regStmt, 96, 16_384);
        // R_REG refused by the precompile (the default op-3 answer is 0)
        vm.expectRevert(IUARegistry.UAPoP.selector);
        _pqzUA(pk, 1);
        vm.mockCall(PQZ, abi.encodePacked(uint8(3)), abi.encode(uint256(1)));
        // 0x0142 is not a kind (UA-6)
        vm.expectRevert(abi.encodeWithSelector(UAKinds.UAKindNotDerived.selector, UAKinds.PQZ_MLWE));
        reg.register(UAKinds.PQZ_MLWE, pk, hex"aa", "", "");
        // non-canonical key or wrong length: the verifier refuses before the precompile ⇒ UAPoP
        bytes memory bad = bytes.concat(pk);
        bad[0] = 0xff;
        vm.expectRevert(IUARegistry.UAPoP.selector);
        _pqzUA(bad, 1);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        _pqzUA(_slice(pk, 0, 100), 1);
        bytes32 ua = _pqzUA(pk, 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAAlreadyRegistered.selector, ua));
        _pqzUA(pk, 1);
        bytes32 h = reg.keyHashOf(UAKinds.PQZ_MLWE, pk);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, h, ua));
        _pqzUA(pk, 2);
    }
}
