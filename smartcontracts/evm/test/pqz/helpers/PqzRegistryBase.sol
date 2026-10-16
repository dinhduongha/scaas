// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzMock} from "./PqzMock.sol";
import {UARegistry} from "../../../src/ua/UARegistry.sol";
import {UAKinds} from "../../../src/ua/UAKinds.sol";
import {UAMldsaVerifier} from "../../../src/ua/MlDsa.sol";
import {UAPqzVerifier} from "../../../src/pqz/UAPqzVerifier.sol";

bytes32 constant PQZ_UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464; // chain 7622's genesis
bytes32 constant PQZL_ID = 0x2e07e6ed1fd303a08c89b3eab6e8423fdfb8f31202958dd682a0619313798c2f;
bytes32 constant PQZH_ID = 0x0a47a7689250ba178a52ad5972cdd9153358c022cb694c08d2389e82de2fead4;

/// @notice A gen-1 `UARegistry` as on chain 7622 (P6g plan D15): `mldsa65` on its precompile candidate (mocked: every
///         input ⇒ 1 except the probe's invalid one) and `pqz-mlwe` on `UAPqzVerifier` (the `PQZ` precompile mocked,
///         `PqzMock`). ML-DSA signatures are filler bytes of the right length; what is real is every registry and
///         verifier path between them.
abstract contract PqzRegistryBase is PqzMock {
    address internal constant ML65 = 0x5CAA500000000000000000000000000000000013;
    uint256 internal constant ML65_PK = 1952;
    uint256 internal constant ML65_SIG = 3309;
    uint64 internal constant CAP_PQZ = 3_500_000;

    UARegistry internal reg;
    UAMldsaVerifier internal mlv;
    UAPqzVerifier internal pqv;
    bytes internal regStmt; // statement_register.json: opTag ‖ PQZL id ‖ message ‖ pk (the self-test's)
    bytes internal regProof; // proof_pqzl.json REGISTER

    function _mockMlDsa() internal returns (bytes memory valid, bytes memory invalid) {
        valid = new bytes(ML65_PK + ML65_SIG + 32);
        valid[0] = 0x01;
        invalid = new bytes(ML65_PK + ML65_SIG + 32);
        vm.mockCall(ML65, bytes(""), abi.encode(uint256(1)));
        vm.mockCall(ML65, invalid, abi.encode(uint256(0)));
    }

    /// The self-test's `R_REG` vector as the probe; the mocked precompile accepts exactly that input.
    function _newPqzVerifier(bytes32 psid) internal returns (UAPqzVerifier v) {
        regStmt = _vecHex("statement_register.json", ".rows[0].stmt");
        regProof = _vecHex("proof_pqzl.json", ".rows[4].proof");
        _mockSelfTest();
        vm.mockCall(PQZ, abi.encodePacked(uint8(3)), abi.encode(uint256(0)));
        bytes memory st = bytes.concat(_slice(regStmt, 0, 32), psid, _slice(regStmt, 64, 16_416));
        vm.mockCall(PQZ, abi.encodePacked(uint8(3), uint32(16_480), st, regProof), abi.encode(uint256(1)));
        v = new UAPqzVerifier(PQZ, psid, _slice(regStmt, 96, 16_384), bytes32(_slice(regStmt, 64, 32)), regProof);
    }

    function _registryStack() internal {
        (bytes memory valid, bytes memory invalid) = _mockMlDsa();
        mlv = new UAMldsaVerifier(UAKinds.MLDSA65, ML65, valid, invalid);
        pqv = _newPqzVerifier(PQZL_ID);
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](2);
        k[0] = UARegistry.KindConfig(UAKinds.MLDSA65, address(mlv), 100_000);
        k[1] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, address(pqv), CAP_PQZ);
        reg = new UARegistry(PQZ_UID, address(0), false, 12_000_000, address(0), true, k);
    }

    /// An `mldsa65` UA with the filler key `seed ‖ 0…` (PoP accepted by the mocked precompile).
    function _mldsaUA(uint8 seed) internal returns (bytes32 ua) {
        bytes memory pk = new bytes(ML65_PK);
        pk[0] = bytes1(seed);
        ua = reg.register(UAKinds.MLDSA65, pk, new bytes(ML65_SIG), 0, "");
    }

    /// The `UA` auth format with a filler ML-DSA signature (`abi.encode(bytes(""), sig)`).
    function _mlAuth() internal pure returns (bytes memory) {
        return abi.encode(bytes(""), new bytes(ML65_SIG));
    }

    /// A `pqz-mlwe` UA for `pk` with the `authRef` `auth` (PoP: any proof bytes, op 3 mocked to 1 by the caller).
    function _pqzUA(bytes memory pk, bytes32 auth) internal returns (bytes32) {
        return reg.register(UAKinds.PQZ_MLWE, pk, hex"aa", auth, _mlAuth());
    }
}
