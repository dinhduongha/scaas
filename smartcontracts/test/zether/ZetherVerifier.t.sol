// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {ZetherVerifierBn254, ZetherVerifierBls12381} from "../../src/zether/ZetherVerifier.sol";
import {IZetherVerifier} from "../../src/zether/IZetherVerifier.sol";
import {ZetherProver} from "./helpers/ZetherProver.sol";

/// @notice Verifier đứng một mình: proof đúng qua, mọi thay đổi một bit / một trường / một witness sai
///         đều bị từ chối. Statement dựng tay theo §6 (token dựng y hệt — xem ZetherToken.t.sol).
contract ZetherVerifierTest is Test {
    bytes32 constant OP_T = keccak256("BAMBOO-ZETHER-OP-TRANSFER-V1");
    bytes32 constant OP_B = keccak256("BAMBOO-ZETHER-OP-BURN-V1");
    bytes32 constant DIRECT = keccak256("ZTX_V1_DIRECT");

    ZetherVerifierBn254 bn;
    ZetherVerifierBls12381 bls;
    ZetherProver prover;

    uint256 constant XF = 0xA11CE;
    uint256 constant XT = 0xB0B;
    uint256 constant XA = 0xA0D17;
    uint256 constant RHO = 0x5EED;
    uint256 constant S = 0x5;

    function setUp() public {
        bn = new ZetherVerifierBn254();
        bls = new ZetherVerifierBls12381();
        prover = new ZetherProver();
    }

    struct Case {
        IZetherVerifier v;
        uint256 b;      // số dư acc
        uint256 amount; // v
        uint256 fee;
        bool auditor;
    }

    function _header(IZetherVerifier v, bytes32 op, uint256 fee, uint256 amount, address recipient)
        internal view returns (bytes memory)
    {
        return abi.encode(
            op, v.proofSystemId(), block.chainid, address(0x70CE), DIRECT, bytes32(0),
            uint256(7), uint256(3), fee, fee == 0 ? bytes32(0) : bytes32(uint256(0xBE)), amount, recipient
        );
    }

    function _acc(IZetherVerifier v, uint256 b) internal view returns (bytes memory c, bytes memory d) {
        uint256[] memory sc = new uint256[](2);
        (sc[0], sc[1]) = (b, RHO);
        c = v.g1Msm(bytes.concat(v.g1MulBase(1), v.g1MulBase(XF)), sc);
        d = v.g1MulBase(RHO);
    }

    function _transferStatement(Case memory k, uint256 ctAmount) internal view returns (bytes memory st) {
        IZetherVerifier v = k.v;
        bytes memory keys = bytes.concat(v.g1MulBase(XF), v.g1MulBase(XT), k.auditor ? v.g1MulBase(XA) : v.identity());
        (bytes memory cAcc, bytes memory dAcc) = _acc(v, k.b);
        st = bytes.concat(_header(v, OP_T, k.fee, 0, address(0)), keys, cAcc, dAcc, _cts(k, ctAmount));
    }

    function _cts(Case memory k, uint256 ctAmount) internal view returns (bytes memory) {
        IZetherVerifier v = k.v;
        (bytes memory cOut, bytes memory dOut, bytes memory cDeb, bytes memory cAud) = prover.ciphertexts(
            v, v.g1MulBase(XF), v.g1MulBase(XT), k.auditor ? v.g1MulBase(XA) : v.identity(), ctAmount, S);
        return bytes.concat(cOut, dOut, cDeb, cAud);
    }

    function _proveTransfer(Case memory k, bytes memory st, uint256 witnessV) internal view returns (bytes memory) {
        uint256 r = k.v.groupOrder();
        uint256 bPrime = addmod(k.b, r - addmod(witnessV, k.fee, r), r);
        return prover.proveTransfer(k.v, st, ZetherProver.TransferWitness({
            x: XF, v: witnessV, s: S, bPrime: bPrime, gammaV: 0x77, gammaB: 0x88, seed: keccak256("t")
        }));
    }

    function _ok(IZetherVerifier v, bytes memory st, bytes memory pr, bool transfer) internal view returns (bool) {
        try this.callVerify{gas: 20_000_000}(v, st, pr, transfer) returns (bool ok) { return ok; } catch { return false; }
    }

    function callVerify(IZetherVerifier v, bytes memory st, bytes memory pr, bool transfer) external view returns (bool) {
        return transfer ? v.verifyTransfer(st, pr) : v.verifyBurn(st, pr);
    }

    // ------------------------------------------------------------------ transfer

    function _honestTransfer(Case memory k) internal {
        bytes memory st = _transferStatement(k, k.amount);
        bytes memory pr = _proveTransfer(k, st, k.amount);
        assertEq(pr.length, 40 * k.v.g1EncodedBytes() + 512, "wire size");
        uint256 g0 = gasleft();
        assertTrue(k.v.verifyTransfer(st, pr), "honest proof");
        console2.log(k.v.curveName(), k.auditor ? "transfer+auditor verify gas" : "transfer verify gas", g0 - gasleft());
    }

    function test_transferBn254() public { _honestTransfer(Case(bn, 1000, 300, 5, false)); }
    function test_transferBn254Auditor() public { _honestTransfer(Case(bn, 1000, 300, 5, true)); }
    function test_transferBls() public { _honestTransfer(Case(bls, 1000, 300, 5, false)); }
    function test_transferBlsAuditor() public { _honestTransfer(Case(bls, 1000, 300, 5, true)); }
    function test_transferWholeBalanceNoFee() public { _honestTransfer(Case(bn, 1000, 1000, 0, true)); }
    function test_transferMaxValue() public { _honestTransfer(Case(bn, 2 ** 40, 2 ** 32 - 1, 7, false)); }

    function test_transferOverspendRejected() public {
        Case memory k = Case(bn, 1000, 1001, 0, false); // b' = −1 mod r: BP n=64 không chứng minh được
        bytes memory st = _transferStatement(k, k.amount);
        assertFalse(_ok(bn, st, _proveTransfer(k, st, k.amount), true));
    }

    function test_transferFeeOverspendRejected() public {
        Case memory k = Case(bls, 1000, 998, 5, false);
        bytes memory st = _transferStatement(k, k.amount);
        assertFalse(_ok(bls, st, _proveTransfer(k, st, k.amount), true));
    }

    function test_transferValueOutOfRangeRejected() public {
        Case memory k = Case(bn, 2 ** 40, 2 ** 32, 0, false); // v = 2^32 ∉ [0, 2^32)
        bytes memory st = _transferStatement(k, k.amount);
        assertFalse(_ok(bn, st, _proveTransfer(k, st, k.amount), true));
    }

    /// Σ-Bullets: ciphertext mang 900 nhưng witness (V_v, z_v) nói 100 — phải fail ở E3/E4.
    function test_sigmaBulletsLinkageRejected() public {
        Case memory k = Case(bn, 1000, 100, 0, false);
        bytes memory st = _transferStatement(k, 900);
        assertFalse(_ok(bn, st, _proveTransfer(k, st, 100), true));
    }

    function test_transferTamperedProofBitsRejected() public {
        Case memory k = Case(bn, 1000, 300, 5, true);
        bytes memory st = _transferStatement(k, k.amount);
        bytes memory pr = _proveTransfer(k, st, k.amount);
        uint256 p = 64;
        // một bit ở: V_v, A_bal, z_x, z_gb, BP32 A, BP32 L1, BP32 τ_x, BP64 R6, BP64 b
        uint256[9] memory offs = [uint256(5), 6 * p + 9, 10 * p + 31, 10 * p + 191, 10 * p + 192 + 40,
            10 * p + 192 + 4 * p + 3, 10 * p + 192 + 14 * p + 20, 10 * p + 192 + 14 * p + 160 + 15 * p + 1,
            pr.length - 1];
        for (uint256 i; i < offs.length; ++i) {
            bytes memory t = bytes.concat(pr);
            t[offs[i]] = bytes1(uint8(t[offs[i]]) ^ 0x01);
            assertFalse(_ok(bn, st, t, true), "tampered proof accepted");
        }
    }

    function test_transferTamperedStatementFieldsRejected() public {
        Case memory k = Case(bls, 1000, 300, 5, true);
        bytes memory st = _transferStatement(k, k.amount);
        bytes memory pr = _proveTransfer(k, st, k.amount);
        assertTrue(bls.verifyTransfer(st, pr));
        // chainId, token, bindingTag, binding, sendCounter, accSeq, fee, beneficiary, rồi một bit trong C_acc
        uint256[9] memory offs = [uint256(95), 127, 159, 191, 223, 255, 287, 319, 384 + 3 * 128 + 100];
        for (uint256 i; i < offs.length; ++i) {
            bytes memory t = bytes.concat(st);
            t[offs[i]] = bytes1(uint8(t[offs[i]]) ^ 0x01);
            assertFalse(_ok(bls, t, pr, true), "tampered statement accepted");
        }
    }

    function test_transferWrongOpTagOrSystemRejected() public view {
        Case memory k = Case(bn, 1000, 300, 5, false);
        bytes memory st = _transferStatement(k, k.amount);
        bytes memory pr = _proveTransfer(k, st, k.amount);
        bytes memory t = bytes.concat(st);
        t[0] = 0x00;
        assertFalse(bn.verifyTransfer(t, pr));
        t = bytes.concat(st);
        t[40] = 0x00;
        assertFalse(bn.verifyTransfer(t, pr));
        assertFalse(bn.verifyTransfer(st, bytes.concat(pr, hex"00")), "length");
        assertFalse(bls.verifyTransfer(st, pr), "cross-curve");
    }

    /// Auditor bật nhưng C_aud mã hoá số khác C_out: E6 (cùng z_v, z_s) phải bắt — auditor không bị lừa.
    function test_auditorCiphertextMustMatchValue() public {
        Case memory k = Case(bls, 1000, 300, 5, true);
        bytes memory st = _transferStatement(k, k.amount);
        bytes memory lie = _cts(Case(bls, 1000, 1, 5, true), 1); // C_aud của v = 1
        uint256 p = 128;
        for (uint256 i; i < p; ++i) st[384 + 8 * p + i] = lie[3 * p + i];
        assertFalse(_ok(bls, st, _proveTransfer(k, st, k.amount), true));
    }

    /// Witness b' sai (E1 đúng khoá, E5 sai số dư) — burn chỉ qua khi `b' = b − amount − fee`.
    function test_burnWrongBalanceWitnessRejected() public view {
        bytes memory st = _burnStatement(bn, 1000, 400, 5);
        bytes memory pr = prover.proveBurn(bn, st, ZetherProver.BurnWitness(XF, 596, 0x99, keccak256("b")));
        assertFalse(bn.verifyBurn(st, pr));
    }

    function test_auditorOffRequiresIdentityCaud() public {
        Case memory k = Case(bn, 1000, 300, 5, false);
        bytes memory st = _transferStatement(k, k.amount);
        bytes memory pr = _proveTransfer(k, st, k.amount);
        // nhét một C_aud khác O khi auditor tắt
        bytes memory t = bytes.concat(st);
        bytes memory junk = bn.g1MulBase(42);
        for (uint256 i; i < 64; ++i) t[384 + 8 * 64 + i] = junk[i];
        assertFalse(_ok(bn, t, pr, true));
    }

    function test_nonCanonicalScalarRejected() public view {
        Case memory k = Case(bn, 1000, 300, 5, false);
        bytes memory st = _transferStatement(k, k.amount);
        bytes memory pr = _proveTransfer(k, st, k.amount);
        // z_x + r: cùng điểm, khác byte — phải bị từ chối (chống malleability)
        uint256 zx;
        assembly { zx := mload(add(add(pr, 32), 640)) }
        uint256 alias_ = zx + bn.groupOrder();
        if (alias_ > zx) {
            assembly { mstore(add(add(pr, 32), 640), alias_) }
            assertFalse(bn.verifyTransfer(st, pr));
        }
    }

    // ------------------------------------------------------------------ burn

    function _burnStatement(IZetherVerifier v, uint256 b, uint256 amount, uint256 fee) internal view returns (bytes memory) {
        (bytes memory cAcc, bytes memory dAcc) = _acc(v, b);
        return bytes.concat(_header(v, OP_B, fee, amount, address(0xCAFE)), v.g1MulBase(XF), cAcc, dAcc);
    }

    function _burn(IZetherVerifier v, uint256 b, uint256 amount, uint256 fee) internal view returns (bool, uint256) {
        bytes memory st = _burnStatement(v, b, amount, fee);
        uint256 r = v.groupOrder();
        bytes memory pr = prover.proveBurn(v, st, ZetherProver.BurnWitness(XF, addmod(b, r - addmod(amount, fee, r), r), 0x99, keccak256("b")));
        uint256 g0 = gasleft();
        bool ok = _ok(v, st, pr, false);
        return (ok, g0 - gasleft());
    }

    function test_burnBn254() public {
        (bool ok, uint256 gas) = _burn(bn, 1000, 400, 5);
        assertTrue(ok);
        console2.log("bn254 burn verify gas", gas);
    }

    function test_burnBls() public {
        (bool ok, uint256 gas) = _burn(bls, 1000, 400, 5);
        assertTrue(ok);
        console2.log("bls12-381 burn verify gas", gas);
    }

    function test_burnOverspendRejected() public view {
        (bool ok,) = _burn(bn, 1000, 996, 5);
        assertFalse(ok);
    }

    function test_burnProofNotATransferProof() public view {
        bytes memory st = _burnStatement(bn, 1000, 400, 5);
        bytes memory pr = prover.proveBurn(bn, st, ZetherProver.BurnWitness(XF, 595, 0x99, keccak256("b")));
        assertTrue(bn.verifyBurn(st, pr));
        assertFalse(bn.verifyTransfer(st, pr));
        bytes memory t = bytes.concat(st);
        t[351] = bytes1(uint8(t[351]) ^ 1); // recipient bị relayer đổi
        assertFalse(bn.verifyBurn(t, pr));
    }

    function test_burnWrongKeyRejected() public view {
        bytes memory st = _burnStatement(bn, 1000, 400, 5);
        bytes memory pr = prover.proveBurn(bn, st, ZetherProver.BurnWitness(XT, 595, 0x99, keccak256("b")));
        assertFalse(bn.verifyBurn(st, pr));
    }
}
