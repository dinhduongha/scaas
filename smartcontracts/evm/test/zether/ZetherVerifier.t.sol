// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {IZetherVerifier, IZetherBurnVerifier} from "../../src/zether/IZetherVerifier.sol";
import {ZetherVerifiers} from "./helpers/ZetherVerifiers.sol";
import {G1Bls12381} from "../../src/zether/ZetherCurves.sol";
import {ZetherCurve, ZetherBls12381Curve} from "../../src/zether/ZetherVerifier.sol";
import {ZetherProver} from "./helpers/ZetherProver.sol";

contract InvHarness is ZetherBls12381Curve {
    function _store() internal pure override returns (address) { return address(0); }
    function inv(uint256 a, uint256 r) external view returns (uint256) { return _inv(a, r); }
}

/// @notice Verifier đứng một mình: proof đúng qua, mọi thay đổi một bit / một trường / một witness sai
///         đều bị từ chối. Statement dựng tay theo zether.md §7 (header 512 byte, `chainUid` là word 3; token và
///         `ZetherStatements` dựng y hệt — xem ZetherNormal.t.sol `test_statementHeaderCarriesChainUid`).
contract ZetherVerifierTest is Test {
    bytes32 constant OP_T = keccak256("SCAAS-ZETHER-OP-TRANSFER-V1");
    bytes32 constant OP_B = keccak256("SCAAS-ZETHER-OP-BURN-V1");
    bytes32 constant DIRECT = keccak256("ZTX_V1_DIRECT");

    IZetherVerifier bls;
    IZetherBurnVerifier blsB;
    ZetherProver prover;

    uint256 constant XF = 0xA11CE;
    uint256 constant XT = 0xB0B;
    uint256 constant XA = 0xA0D17;
    uint256 constant RHO = 0x5EED;
    uint256 constant S = 0x5;

    function setUp() public {
        (bls, blsB) = ZetherVerifiers.deploy(); // BLS12-381 only since UA-6 (CTR-ZTH-32)
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
        return bytes.concat(
            abi.encode(op, v.proofSystemId(), block.chainid, keccak256("verifier test chain"), address(0x70CE), DIRECT),
            abi.encode(bytes32(0), uint256(7), uint256(3), fee, fee == 0 ? bytes32(0) : bytes32(uint256(0xBE))),
            abi.encode(amount, recipient, op == OP_B ? bytes32(0) : bytes32(uint256(0x5A17)), bytes32(0), uint256(1000))
        ); // word 15: validUntilBlock (review C0-9), bound only
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
        return transfer ? v.verifyTransfer(st, pr) : _burnOf(v).verifyBurn(st, pr);
    }

    /// The burn verifier of `v`'s curve (CTR-ZTH-20: a transfer and a burn verifier per curve).
    function _burnOf(IZetherVerifier) internal view returns (IZetherBurnVerifier) {
        return blsB;
    }

    // ------------------------------------------------------------------ transfer

    function _honestTransfer(Case memory k) internal {
        bytes memory st = _transferStatement(k, k.amount);
        bytes memory pr = _proveTransfer(k, st, k.amount);
        assertEq(pr.length, 42 * k.v.g1EncodedBytes() + 512, "wire size (n_v = n_b = 64)");
        uint256 g0 = gasleft();
        assertTrue(k.v.verifyTransfer(st, pr), "honest proof");
        console2.log(k.v.curveName(), k.auditor ? "transfer+auditor verify gas" : "transfer verify gas", g0 - gasleft());
    }

    function test_transferBls() public { _honestTransfer(Case(bls, 1000, 300, 5, false)); }
    function test_transferBlsAuditor() public { _honestTransfer(Case(bls, 1000, 300, 5, true)); }
    function test_transferWholeBalanceNoFee() public { _honestTransfer(Case(bls, 1000, 1000, 0, true)); }
    /// n_v = 64 (limits D1): v = 2^64 − 1 và b' = 0 cùng qua — verifier chỉ biết dải đã chứng minh.
    function test_transferMaxValue() public { _honestTransfer(Case(bls, 2 ** 64 + 6, 2 ** 64 - 1, 7, false)); }
    function test_transferAbove2pow32Bls() public { _honestTransfer(Case(bls, 2 ** 54, 2 ** 44 + 3, 7, false)); }
    function test_transferMaxFee() public { _honestTransfer(Case(bls, 2 ** 64, 1, 2 ** 64 - 1, false)); }

    function test_transferOverspendRejected() public {
        Case memory k = Case(bls, 1000, 1001, 0, false); // b' = −1 mod r: BP n=64 không chứng minh được
        bytes memory st = _transferStatement(k, k.amount);
        assertFalse(_ok(bls, st, _proveTransfer(k, st, k.amount), true));
    }

    function test_transferFeeOverspendRejected() public {
        Case memory k = Case(bls, 1000, 998, 5, false);
        bytes memory st = _transferStatement(k, k.amount);
        assertFalse(_ok(bls, st, _proveTransfer(k, st, k.amount), true));
    }

    function test_transferValueOutOfRangeRejected() public {
        Case memory k = Case(bls, 2 ** 64 + 10, 2 ** 64, 0, false); // v = 2^64 ∉ [0, 2^64), b' = 10 hợp lệ
        bytes memory st = _transferStatement(k, k.amount);
        assertFalse(_ok(bls, st, _proveTransfer(k, st, k.amount), true));
    }

    /// Σ-Bullets: ciphertext mang 900 nhưng witness (V_v, z_v) nói 100 — phải fail ở E3/E4.
    function test_sigmaBulletsLinkageRejected() public {
        Case memory k = Case(bls, 1000, 100, 0, false);
        bytes memory st = _transferStatement(k, 900);
        assertFalse(_ok(bls, st, _proveTransfer(k, st, 100), true));
    }

    function test_transferTamperedProofBitsRejected() public {
        Case memory k = Case(bls, 1000, 300, 5, true);
        bytes memory st = _transferStatement(k, k.amount);
        bytes memory pr = _proveTransfer(k, st, k.amount);
        uint256 p = 64;
        // một bit ở: V_v, A_bal, z_x, z_gb, BP#1 A, BP#1 L1, BP#1 R6, BP#1 τ_x, BP#2 R6, BP#2 b
        // (n_v = 64: BP#1 = 16P + 160, cùng khuôn BP#2)
        uint256[10] memory offs = [uint256(5), 6 * p + 9, 10 * p + 31, 10 * p + 191, 10 * p + 192 + 40,
            10 * p + 192 + 4 * p + 3, 10 * p + 192 + 15 * p + 7, 10 * p + 192 + 16 * p + 20,
            10 * p + 192 + 16 * p + 160 + 15 * p + 1, pr.length - 1];
        for (uint256 i; i < offs.length; ++i) {
            bytes memory t = bytes.concat(pr);
            t[offs[i]] = bytes1(uint8(t[offs[i]]) ^ 0x01);
            assertFalse(_ok(bls, st, t, true), "tampered proof accepted");
        }
    }

    function test_transferTamperedStatementFieldsRejected() public {
        Case memory k = Case(bls, 1000, 300, 5, true);
        bytes memory st = _transferStatement(k, k.amount);
        bytes memory pr = _proveTransfer(k, st, k.amount);
        assertTrue(bls.verifyTransfer(st, pr));
        // chainId, chainUid, token, bindingTag, binding, sendCounter, accSeq, fee, beneficiary, salt, memoHash,
        // validUntilBlock (review C0-9), rồi một bit trong C_acc
        uint256[13] memory offs = [uint256(95), 127, 159, 191, 223, 255, 287, 319, 351, 447, 479, 511, 512 + 3 * 128 + 100];
        for (uint256 i; i < offs.length; ++i) {
            bytes memory t = bytes.concat(st);
            t[offs[i]] = bytes1(uint8(t[offs[i]]) ^ 0x01);
            assertFalse(_ok(bls, t, pr, true), "tampered statement accepted");
        }
    }

    function test_transferWrongOpTagOrSystemRejected() public view {
        Case memory k = Case(bls, 1000, 300, 5, false);
        bytes memory st = _transferStatement(k, k.amount);
        bytes memory pr = _proveTransfer(k, st, k.amount);
        bytes memory t = bytes.concat(st);
        t[0] = 0x00;
        assertFalse(bls.verifyTransfer(t, pr));
        t = bytes.concat(st);
        t[40] = 0x00;
        assertFalse(bls.verifyTransfer(t, pr));
        assertFalse(bls.verifyTransfer(st, bytes.concat(pr, hex"00")), "length");
    }

    /// Auditor bật nhưng C_aud mã hoá số khác C_out: E6 (cùng z_v, z_s) phải bắt — auditor không bị lừa.
    function test_auditorCiphertextMustMatchValue() public {
        Case memory k = Case(bls, 1000, 300, 5, true);
        bytes memory st = _transferStatement(k, k.amount);
        bytes memory lie = _cts(Case(bls, 1000, 1, 5, true), 1); // C_aud của v = 1
        uint256 p = 128;
        for (uint256 i; i < p; ++i) st[512 + 8 * p + i] = lie[3 * p + i];
        assertFalse(_ok(bls, st, _proveTransfer(k, st, k.amount), true));
    }

    /// Witness b' sai (E1 đúng khoá, E5 sai số dư) — burn chỉ qua khi `b' = b − amount − fee`.
    function test_burnWrongBalanceWitnessRejected() public view {
        bytes memory st = _burnStatement(bls, 1000, 400, 5);
        bytes memory pr = prover.proveBurn(bls, st, ZetherProver.BurnWitness(XF, 596, 0x99, keccak256("b")));
        assertFalse(blsB.verifyBurn(st, pr));
    }

    function test_auditorOffRequiresIdentityCaud() public {
        Case memory k = Case(bls, 1000, 300, 5, false);
        bytes memory st = _transferStatement(k, k.amount);
        bytes memory pr = _proveTransfer(k, st, k.amount);
        // nhét một C_aud khác O khi auditor tắt
        bytes memory t = bytes.concat(st);
        bytes memory junk = bls.g1MulBase(42);
        for (uint256 i; i < 128; ++i) t[512 + 8 * 128 + i] = junk[i]; // C_aud
        assertFalse(_ok(bls, t, pr, true));
    }

    /// CTR-ZTH-22 (c): `s = 0` gives `D_out = O` and `C_out = [v]G` (the amount in the clear); refused even with an
    /// otherwise honest proof.
    function test_dOutIdentityRejected() public view {
        bytes memory st = _zeroSStatement(bls, 1000, 300, 5);
        bytes memory pr = prover.proveTransfer(bls, st, ZetherProver.TransferWitness({
            x: XF, v: 300, s: 0, bPrime: 1000 - 300 - 5, gammaV: 0x77, gammaB: 0x88, seed: keccak256("t")
        }));
        assertFalse(_ok(bls, st, pr, true));
    }

    function _zeroSStatement(IZetherVerifier v, uint256 b, uint256 amount, uint256 fee) internal view returns (bytes memory) {
        (bytes memory cAcc, bytes memory dAcc) = _acc(v, b);
        bytes memory head = bytes.concat(
            _header(v, OP_T, fee, 0, address(0)), v.g1MulBase(XF), v.g1MulBase(XT), v.identity(), cAcc, dAcc
        );
        return bytes.concat(head, _zeroSCts(v, amount));
    }

    function _zeroSCts(IZetherVerifier v, uint256 amount) internal view returns (bytes memory) {
        (bytes memory cOut, bytes memory dOut, bytes memory cDeb, bytes memory cAud) =
            prover.ciphertexts(v, v.g1MulBase(XF), v.g1MulBase(XT), v.identity(), amount, 0);
        require(keccak256(dOut) == keccak256(v.identity()), "D_out = O");
        return bytes.concat(cOut, dOut, cDeb, cAud);
    }

    /// CTR-ZTH-22 (b): a BLS12-381 point on the curve but outside the subgroup is refused by the subgroup check of
    /// G1MSM (0x0c), not by the statement binding: as `Y_f` it reaches E1's MSM, which reverts `BadPoint`, while any
    /// subgroup point there only makes the proof fail (`false`). Without the check the verifier would return false.
    function test_blsNonSubgroupPointRejected() public {
        Case memory k = Case(bls, 1000, 300, 5, true);
        bytes memory st = _transferStatement(k, k.amount);
        bytes memory pr = _proveTransfer(k, st, k.amount);
        assertTrue(_ok(bls, st, pr, true));
        bytes memory good = bls.g1MulBase(7);
        for (uint256 i; i < 128; ++i) st[512 + i] = good[i]; // Y_f
        assertFalse(bls.verifyTransfer(st, pr));
        bytes memory bad = vm.parseJsonBytes(vm.readFile("test/vectors/zether/curve_misc.json"), ".blsNonSubgroup");
        for (uint256 i; i < 128; ++i) st[512 + i] = bad[i];
        vm.expectRevert(G1Bls12381.BadPoint.selector);
        bls.verifyTransfer(st, pr);
        uint256[] memory one = new uint256[](1);
        one[0] = 1;
        vm.expectRevert(G1Bls12381.BadPoint.selector);
        bls.g1Msm(bad, one);
    }

    function test_nonCanonicalScalarRejected() public view {
        Case memory k = Case(bls, 1000, 300, 5, false);
        bytes memory st = _transferStatement(k, k.amount);
        bytes memory pr = _proveTransfer(k, st, k.amount);
        // z_x + r: cùng điểm, khác byte — phải bị từ chối (chống malleability)
        uint256 zx;
        assembly { zx := mload(add(add(pr, 32), 640)) }
        uint256 alias_ = zx + bls.groupOrder();
        if (alias_ > zx) {
            assembly { mstore(add(add(pr, 32), 640), alias_) }
            assertFalse(bls.verifyTransfer(st, pr));
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

    function test_burnBls() public {
        (bool ok, uint256 gas) = _burn(bls, 1000, 400, 5);
        assertTrue(ok);
        console2.log("bls12-381 burn verify gas", gas);
    }

    function test_burnOverspendRejected() public view {
        (bool ok,) = _burn(bls, 1000, 996, 5);
        assertFalse(ok);
    }

    function test_burnProofNotATransferProof() public view {
        bytes memory st = _burnStatement(bls, 1000, 400, 5);
        bytes memory pr = prover.proveBurn(bls, st, ZetherProver.BurnWitness(XF, 595, 0x99, keccak256("b")));
        assertTrue(blsB.verifyBurn(st, pr));
        assertFalse(bls.verifyTransfer(st, pr));
        bytes memory t = bytes.concat(st);
        t[351] = bytes1(uint8(t[351]) ^ 1); // recipient bị relayer đổi
        assertFalse(blsB.verifyBurn(t, pr));
    }

    function test_burnWrongKeyRejected() public view {
        bytes memory st = _burnStatement(bls, 1000, 400, 5);
        bytes memory pr = prover.proveBurn(bls, st, ZetherProver.BurnWitness(XT, 595, 0x99, keccak256("b")));
        assertFalse(blsB.verifyBurn(st, pr));
    }

    /// C0-19: a failing MODEXP precompile reverts with `PrecompileFailed(5)`, not with empty data.
    function test_C0_19_invPrecompileFailureNamed() public {
        InvHarness h = new InvHarness();
        assertEq(h.inv(3, 7), 5, "3 * 5 = 15 = 1 mod 7");
        vm.mockCallRevert(address(5), bytes(""), bytes(""));
        vm.expectRevert(abi.encodeWithSelector(ZetherCurve.PrecompileFailed.selector, uint256(5)));
        h.inv(3, 7);
    }
}
