// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {IZetherVerifier, IZetherBurnVerifier} from "../../src/zether/IZetherVerifier.sol";
import {ZetherProver} from "./helpers/ZetherProver.sol";
import {ZetherVerifiers} from "./helpers/ZetherVerifiers.sol";

/// @notice Verify gas of the canonical verifiers (plan 5g-Z, CTR-ZTH-20 split): one single transfer, one M = 8
///         multi-recipient transfer and one burn per curve, each a cold external call from this contract (the token's
///         view of it). Honest proofs from `ZetherProver` on hand-built statements (zether.md §7); each must verify.
///         `forge test --match-contract ZetherVerifierGas -vv` prints the table (runs/2026-10-19-5gz.txt).
contract ZetherVerifierGasTest is Test {
    bytes32 constant OP_T = keccak256("SCAAS-ZETHER-OP-TRANSFER-V1");
    bytes32 constant OP_B = keccak256("SCAAS-ZETHER-OP-BURN-V1");
    bytes32 constant OP_M = keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/BUNDLE");
    uint256 constant XF = 0xA11CE;
    uint256 constant XA = 0xA0D17;
    uint256 constant RHO = 0x5EED;
    uint256 constant S = 0x5;
    uint256 constant T0 = 0x7A0;
    uint256 constant B = 1_000_000;
    uint256 constant FEE = 5;

    ZetherProver prover;
    IZetherVerifier v;
    IZetherBurnVerifier vb;

    function setUp() public {
        prover = new ZetherProver();
    }

    function _header(bytes32 op, bytes32 psid, uint256 amount, address recipient) internal view returns (bytes memory) {
        return bytes.concat(
            abi.encode(op, psid, block.chainid, keccak256("gas chain"), address(0x70CE), keccak256("ZTX_V1_DIRECT")),
            abi.encode(bytes32(0), uint256(7), uint256(3), FEE, bytes32(uint256(0xBE))),
            abi.encode(amount, recipient, op == OP_B ? bytes32(0) : bytes32(uint256(0x5A17)), bytes32(0), uint256(1000))
        ); // word 15: validUntilBlock (review C0-9)
    }

    function _acc() internal view returns (bytes memory c, bytes memory d) {
        uint256[] memory sc = new uint256[](2);
        (sc[0], sc[1]) = (B, RHO);
        c = v.g1Msm(bytes.concat(v.g1MulBase(1), v.g1MulBase(XF)), sc);
        d = v.g1MulBase(RHO);
    }

    function _single() internal view returns (bytes memory st, bytes memory pr) {
        st = _singleSt(300);
        ZetherProver.TransferWitness memory w = ZetherProver.TransferWitness(XF, 300, S, B - 300 - FEE, 0x77, 0x88, keccak256("t"));
        pr = prover.proveTransfer(v, st, w);
    }

    function _singleSt(uint256 amt) internal view returns (bytes memory) {
        (bytes memory cAcc, bytes memory dAcc) = _acc();
        bytes memory keys = bytes.concat(v.g1MulBase(XF), v.g1MulBase(0xB0B), v.g1MulBase(XA));
        return bytes.concat(_header(OP_T, v.proofSystemId(), 0, address(0)), keys, cAcc, dAcc, _cts(amt));
    }

    function _cts(uint256 amt) internal view returns (bytes memory) {
        (bytes memory cOut, bytes memory dOut, bytes memory cDeb, bytes memory cAud) =
            prover.ciphertexts(v, v.g1MulBase(XF), v.g1MulBase(0xB0B), v.g1MulBase(XA), amt, S);
        return bytes.concat(cOut, dOut, cDeb, cAud);
    }

    /// @dev Legs `(Y_tj, C_out_j, C_aud_j, D_aud_j)` of values `100 + j`, and `Σv`.
    function _legs(uint256 m, uint256[] memory vs) internal view returns (bytes memory legs, uint256 total) {
        for (uint256 j; j < m; ++j) {
            vs[j] = 100 + j;
            total += vs[j];
            legs = bytes.concat(legs, _leg(j, vs[j]));
        }
    }

    /// @dev `Y_tj ‖ C_out_j ‖ C_aud_j ‖ D_aud_j`, the auditor copy under `t_j = T0 + j` (review C0-1).
    function _leg(uint256 j, uint256 amt) internal view returns (bytes memory) {
        bytes memory yt = v.g1MulBase(0xD00 + j);
        (bytes memory cOut,,,) = prover.ciphertexts(v, v.g1MulBase(XF), yt, v.g1MulBase(XA), amt, S);
        (bytes memory cAud, bytes memory dAud) = prover.audCopy(v, v.g1MulBase(XA), amt, T0 + j);
        return bytes.concat(yt, cOut, cAud, dAud);
    }

    /// @dev `Y_f Y_a C_acc D_acc D_out C_deb` of a multi-recipient statement debiting `total`.
    function _multiPts(uint256 total) internal view returns (bytes memory) {
        bytes memory yf = v.g1MulBase(XF);
        bytes memory ya = v.g1MulBase(XA);
        (, bytes memory dOut, bytes memory cDeb,) = prover.ciphertexts(v, yf, yf, ya, total, S);
        (bytes memory cAcc, bytes memory dAcc) = _acc();
        return bytes.concat(yf, ya, cAcc, dAcc, dOut, cDeb);
    }

    function _witness(uint256[] memory vs, uint256 total) internal pure returns (ZetherProver.MultiWitness memory w) {
        uint256[] memory gv = new uint256[](vs.length);
        uint256[] memory t = new uint256[](vs.length);
        for (uint256 j; j < vs.length; ++j) (gv[j], t[j]) = (0x1234 + 7 * j, T0 + j);
        w = ZetherProver.MultiWitness(XF, S, vs, t, B - FEE - total, gv, 0x5678, keccak256("m"));
    }

    function _multi(uint256 m) internal view returns (bytes memory st, bytes memory pr) {
        uint256[] memory vs = new uint256[](m);
        (bytes memory legs, uint256 total) = _legs(m, vs);
        st = bytes.concat(_header(OP_M, v.proofSystemIdMulti(), 0, address(0)), _multiPts(total), abi.encode(m), legs);
        pr = prover.proveTransferMulti(v, st, _witness(vs, total));
    }

    function _burn() internal view returns (bytes memory st, bytes memory pr) {
        uint256 amt = 400;
        (bytes memory cAcc, bytes memory dAcc) = _acc();
        st = bytes.concat(_header(OP_B, v.proofSystemId(), amt, address(0xCAFE)), v.g1MulBase(XF), cAcc, dAcc);
        pr = prover.proveBurn(v, st, ZetherProver.BurnWitness(XF, B - amt - FEE, 0x99, keccak256("b")));
    }

    /// BLS12-381 only since UA-6 (CTR-ZTH-32); the bn254 rows are in `legacy/ua6/`.
    function _run(uint8 op) internal {
        (v, vb) = ZetherVerifiers.deploy();
        (bytes memory st, bytes memory pr) = op == 0 ? _single() : op == 1 ? _multi(8) : _burn();
        (bool ok, uint256 g) = _verify(op, st, pr);
        assertTrue(ok, "honest proof");
        string[3] memory names = ["transfer", "multi M=8", "burn"];
        console2.log("bls12-381", names[op], "verify gas (cold call)", g);
    }

    function _verify(uint8 op, bytes memory st, bytes memory pr) internal returns (bool ok, uint256 g) {
        vm.cool(address(v));
        vm.cool(address(vb));
        g = gasleft();
        if (op == 0) ok = v.verifyTransfer(st, pr);
        else if (op == 1) ok = v.verifyTransferMulti(st, pr);
        else ok = vb.verifyBurn(st, pr);
        g -= gasleft();
    }

    function test_gasTransferBls12381() public { _run(0); }
    function test_gasMulti8Bls12381() public { _run(1); }
    function test_gasBurnBls12381() public { _run(2); }
}
