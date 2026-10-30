// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzMock} from "./PqzMock.sol";
import {UARegistry} from "../../../src/ua/UARegistry.sol";
import {UAKinds} from "../../../src/ua/UAKinds.sol";
import {UAMldsaVerifier} from "../../../src/ua/MlDsa.sol";
import {UAPqzVerifier} from "../../../src/pqz/UAPqzVerifier.sol";
import {PqzSet} from "../../../src/pqz/PqzSet.sol";

/// @notice `slhdsa128s` (0x0133, 0.79 M) / `fndsa512` (0x0132, 2.3 M) stand-in: burns what a valid pure-Solidity verify
///         costs (accounts.md CTR-UA-23, measured P6a) and accepts: a fee UA of that kind in the relay gas rows (review2 T2).
contract SlhStandIn {
    uint256 internal immutable B;

    constructor(uint256 b) { B = b; }

    function verify(bytes calldata, bytes32, bytes calldata) external view returns (bool) {
        _burn();
        return true;
    }

    function verifyPop(bytes calldata, bytes32, bytes calldata) external view returns (bool) {
        _burn();
        return true;
    }

    function _burn() private view {
        uint256 g0 = gasleft();
        while (g0 - gasleft() < B) {}
    }
}

bytes32 constant PQZ_UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464; // chain 7622's genesis
// the build's set's ids (plan 5h Task 8d; PQZH_ID is the zero word at a set without PQZH)
bytes32 constant PQZL_ID = PqzSet.PQZL_ID;
bytes32 constant PQZH_ID = PqzSet.PQZH_ID;

/// @notice A gen-1 `UARegistry` as on chain 7622 (P6g plan D15): `mldsa65` on its precompile candidate (mocked: every
///         input ⇒ 1 except the probe's invalid one) and the PQZ key verifier `UAPqzVerifier` (slot 0x0142; the `PQZ`
///         precompile mocked, `PqzMock`). ML-DSA signatures are filler bytes of the right length; what is real is every
///         registry and verifier path between them.
abstract contract PqzRegistryBase is PqzMock {
    address internal constant ML65 = 0x000000000000000000000000000000005CAa0013; // 32-bit form (plan 5h Task 8d)
    uint256 internal constant ML65_PK = 1952;
    uint256 internal constant ML65_SIG = 3309;
    uint64 internal constant CAP_PQZ = 3_500_000;

    UARegistry internal reg;
    UAMldsaVerifier internal mlv;
    UAPqzVerifier internal pqv;
    bytes internal regStmt; // statement_register.json: opTag ‖ PQZL id ‖ message ‖ pk (the self-test's), the set's
    bytes internal regProof; // proof_pqzl.json REGISTER, the set's

    function _mockMlDsa() internal returns (bytes memory valid, bytes memory invalid) {
        valid = new bytes(ML65_PK + ML65_SIG + 32);
        valid[0] = 0x01;
        invalid = new bytes(ML65_PK + ML65_SIG + 32);
        vm.mockCall(ML65, bytes(""), abi.encode(uint256(1)));
        vm.mockCall(ML65, invalid, abi.encode(uint256(0)));
    }

    /// The self-test's `R_REG` vector of `psid` as the probe (the pinned one, W-B); the mocked precompile accepts
    /// exactly that input.
    function _newPqzVerifier(bytes32 psid) internal returns (UAPqzVerifier v) {
        regStmt = _vecHex("statement_register.json", ".rows[0].stmt");
        // PQZH: the set's `proof_pqzh.json` row 4 (REGISTER) extracted to `test/vectors/pqzh/<set>/register_proof.hex`
        // (its keccak = the set's selftest.json `register.pqzh.proof_keccak`; the probe pin `PqzSet.PROBE_PQZH` checks it):
        // the 7 MB JSON exceeds forge's per-test gas in memory expansion
        regProof = psid == PQZH_ID && PqzSet.HAS_PQZH
            ? vm.parseBytes(string.concat("0x", vm.readFile(string.concat(vm.projectRoot(), "/test/vectors/pqzh/",
                PqzSet.NAME, "/register_proof.hex"))))
            : _vecHex("proof_pqzl.json", ".rows[4].proof");
        _mockSelfTest();
        vm.mockCall(PQZ, abi.encodePacked(uint8(3)), abi.encode(uint256(0)));
        bytes memory st = bytes.concat(_slice(regStmt, 0, 32), psid, _slice(regStmt, 64, PqzSet.STMT_REGISTER - 64));
        vm.mockCall(PQZ, abi.encodePacked(uint8(3), uint32(PqzSet.STMT_REGISTER), st, regProof), abi.encode(uint256(1)));
        v = new UAPqzVerifier(PQZ, psid, _slice(regStmt, 96, PqzSet.PK), bytes32(_slice(regStmt, 64, 32)), regProof);
    }

    function _registryStack() internal {
        (bytes memory valid, bytes memory invalid) = _mockMlDsa();
        mlv = new UAMldsaVerifier(UAKinds.MLDSA65, ML65, valid, invalid);
        pqv = _newPqzVerifier(PQZL_ID);
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](4);
        k[0] = UARegistry.KindConfig(UAKinds.MLDSA65, address(mlv), 100_000);
        k[1] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, address(pqv), CAP_PQZ);
        k[2] = UARegistry.KindConfig(UAKinds.SLHDSA128S, address(new SlhStandIn(790_000)), 1_400_000); // DeployBase's cap
        k[3] = UARegistry.KindConfig(UAKinds.FNDSA512, address(new SlhStandIn(2_300_000)), 2_500_000);
        reg = new UARegistry(PQZ_UID, address(0), false, 12_000_000, address(0), true, k);
    }

    /// The filler `mldsa65` key `seed ‖ 0…`.
    function _mlPk(uint8 seed) internal pure returns (bytes memory pk) {
        pk = new bytes(ML65_PK);
        pk[0] = bytes1(seed);
    }

    /// An `mldsa65` UA with the filler key `seed ‖ 0…` (PoP accepted by the mocked precompile), no PQZ key.
    function _mldsaUA(uint8 seed) internal returns (bytes32 ua) {
        ua = reg.register(UAKinds.MLDSA65, _mlPk(seed), new bytes(ML65_SIG), "", "");
    }

    /// The `UA` auth format with a filler ML-DSA signature (`abi.encode(bytes(""), sig)`).
    function _mlAuth() internal pure returns (bytes memory) {
        return abi.encode(bytes(""), new bytes(ML65_SIG));
    }

    /// A PQZ account (UA-6): the `mldsa65` UA of the filler key `seed ‖ 0…` registered with the PQZ key `pk` in one
    /// call (`R_REG`: any proof bytes, op 3 mocked to 1 by the caller).
    function _pqzUA(bytes memory pk, uint8 seed) internal returns (bytes32) {
        return reg.register(UAKinds.MLDSA65, _mlPk(seed), new bytes(ML65_SIG), pk, hex"aa");
    }
}
