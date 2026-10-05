// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ZetherVerifierBn254, ZetherVerifierBls12381} from "../../src/zether/ZetherVerifier.sol";
import {IZetherVerifier} from "../../src/zether/IZetherVerifier.sol";
import {ZetherTranscript as T} from "../../src/zether/ZetherTranscript.sol";
import {ZetherToken} from "../../src/zether/ZetherToken.sol";

/// @notice Proof do prover Rust của luồng S3 (`r3-zether-prover`, chép vào `test/vectors/zether/s3/`) —
///         một hiện thực ĐỘC LẬP của đặc tả. Đúng thì qua verifier Solidity; lật bất kỳ bit nào thì không.
contract ZetherS3VectorsTest is Test {
    using stdJson for string;

    string constant DIR = "test/vectors/zether/s3/";
    ZetherVerifierBn254 bn;
    ZetherVerifierBls12381 bls;

    function setUp() public {
        bn = new ZetherVerifierBn254();
        bls = new ZetherVerifierBls12381();
    }

    function _v(string memory curve) internal view returns (IZetherVerifier) {
        return keccak256(bytes(curve)) == keccak256("bn254") ? IZetherVerifier(address(bn)) : IZetherVerifier(address(bls));
    }

    function _ok(IZetherVerifier v, bytes memory st, bytes memory pr, bool transfer) internal view returns (bool) {
        try this.verify{gas: 20_000_000}(v, st, pr, transfer) returns (bool ok) { return ok; } catch { return false; }
    }

    function verify(IZetherVerifier v, bytes memory st, bytes memory pr, bool transfer) external view returns (bool) {
        return transfer ? v.verifyTransfer(st, pr) : v.verifyBurn(st, pr);
    }

    function _flip(bytes memory a, uint256 i) internal pure returns (bytes memory b) {
        b = bytes.concat(a);
        b[i] = bytes1(uint8(b[i]) ^ 0x01);
    }

    /// Proof đúng qua; một bit lật ở 7 vị trí trải đều proof và 5 trường statement thì không.
    function _checkProof(string memory file, bool transfer) internal view {
        string memory j = vm.readFile(string.concat(DIR, file));
        IZetherVerifier v = _v(j.readString(".curve"));
        bytes memory st = j.readBytes(".statement");
        bytes memory pr = j.readBytes(".proof");
        assertTrue(j.readBool(".expect"));
        assertTrue(transfer ? v.verifyTransfer(st, pr) : v.verifyBurn(st, pr), "S3 proof rejected");
        for (uint256 k = 1; k <= 7; ++k) {
            assertFalse(_ok(v, st, _flip(pr, (pr.length * k) / 8 - 1), transfer), "tampered proof accepted");
        }
        uint256[5] memory fields = [uint256(95), 191, 223, 255, 287]; // chainId, binding, sendCounter, accSeq, fee
        for (uint256 k; k < 5; ++k) {
            assertFalse(_ok(v, _flip(st, fields[k]), pr, transfer), "tampered statement accepted");
        }
        // authDigest §11 khớp đặc tả
        assertEq(keccak256(abi.encodePacked("BAMBOO-ZETHER-AUTH-V1", keccak256(st))), j.readBytes32(".authDigest"));
    }

    function test_s3TransferBn254() public view { _checkProof("transfer_bn254.json", true); }
    function test_s3TransferBls12381() public view { _checkProof("transfer_bls12381.json", true); }
    function test_s3TransferNoAuditorBn254() public view { _checkProof("transfer_noaud_bn254.json", true); }
    function test_s3TransferNoAuditorBls12381() public view { _checkProof("transfer_noaud_bls12381.json", true); }
    function test_s3BurnBn254() public view { _checkProof("burn_bn254.json", false); }
    function test_s3BurnBls12381() public view { _checkProof("burn_bls12381.json", false); }

    /// Header statement của S3 đúng bố cục §6 với các trường của `request`.
    function test_s3StatementHeaderMatchesRequest() public view {
        string memory j = vm.readFile(string.concat(DIR, "transfer_bn254.json"));
        bytes memory st = j.readBytes(".statement");
        (bytes32 op, bytes32 psid, uint256 chainId, address token, bytes32 tag, bytes32 binding) =
            abi.decode(_head(st, 0), (bytes32, bytes32, uint256, address, bytes32, bytes32));
        assertEq(op, keccak256("BAMBOO-ZETHER-OP-TRANSFER-V1"));
        assertEq(psid, bn.proofSystemId());
        assertEq(chainId, j.readUint(".request.chainId"));
        assertEq(token, j.readAddress(".request.token"));
        assertEq(tag, keccak256("ZTX_V1_RELAYED"));
        assertEq(binding, j.readBytes32(".request.envelopeBinding"));
    }

    function test_s3StatementCountersAndEntryRef() public view {
        string memory j = vm.readFile(string.concat(DIR, "transfer_bn254.json"));
        bytes memory st = j.readBytes(".statement");
        (uint256 sc, uint256 accSeq, uint256 fee, bytes32 ben,,) =
            abi.decode(_head(st, 192), (uint256, uint256, uint256, bytes32, uint256, address));
        assertEq(sc, j.readUint(".request.sendCounter"));
        assertEq(accSeq, j.readUint(".request.accSeq"));
        assertEq(fee, j.readUint(".request.fee"));
        assertEq(ben, j.readBytes32(".request.beneficiary"));
        // entryRef §10 = keccak(tag, chainId, token, keccak(Y_f), sendCounter)
        bytes memory yf = new bytes(64);
        for (uint256 i; i < 64; ++i) yf[i] = st[384 + i];
        assertEq(
            keccak256(abi.encode(keccak256("BAMBOO-ZETHER-ENTRY-V1"), j.readUint(".request.chainId"),
                j.readAddress(".request.token"), keccak256(yf), sc)),
            j.readBytes32(".entryRef")
        );
    }

    function _head(bytes memory st, uint256 off) internal pure returns (bytes memory out) {
        out = new bytes(192);
        for (uint256 i; i < 192; ++i) out[i] = st[off + i];
    }

    /// `opData` của S3 = `OP_ZTRANSFER ‖ abi.encode(payload, proof, authSig, beneficiary)` (§10).
    function test_s3OpDataMatchesEnvelopeOp() public {
        string memory j = vm.readFile(string.concat(DIR, "transfer_bn254.json"));
        bytes memory op = j.readBytes(".opData");
        ZetherToken impl = new ZetherToken(address(this));
        assertEq(bytes4(op), impl.OP_ZTRANSFER());
        bytes memory args = new bytes(op.length - 4);
        for (uint256 i; i < args.length; ++i) args[i] = op[4 + i];
        (bytes memory pl, bytes memory pr,, bytes32 ben) = abi.decode(args, (bytes, bytes, bytes, bytes32));
        assertEq(pl, j.readBytes(".payload"));
        assertEq(pr, j.readBytes(".proof"));
        assertEq(ben, j.readBytes32(".request.beneficiary"));
    }

    /// Mở tiết lộ của S3 kiểm theo đúng phương trình §12 (chainId/token của vector).
    function _checkDisclosure(string memory file) internal view {
        string memory j = vm.readFile(string.concat(DIR, file));
        IZetherVerifier v = _v(j.readString(".curve"));
        uint256 n = 3;
        for (uint256 i; i < n; ++i) {
            string memory c = string.concat(".cases[", vm.toString(i), "]");
            assertTrue(j.readBool(string.concat(c, ".expect")));
            assertTrue(_disclose(v, j, c), "S3 opening rejected");
        }
    }

    function _disclose(IZetherVerifier v, string memory j, string memory c) internal view returns (bool) {
        uint256 kind = j.readUint(string.concat(c, ".kind"));
        if (kind == 0) return _senderS(v, j, c);
        bytes memory mMinus = v.g1Sub(
            j.readBytes(string.concat(c, kind == 2 ? ".Caud" : ".Cout")),
            v.g1MulBase(j.readUint(string.concat(c, ".amount")))
        );
        return _cp(v, j, c, j.readBytes(string.concat(c, kind == 2 ? ".Ya" : ".Yt")), mMinus, j.readBytes(string.concat(c, ".Dout")));
    }

    function _senderS(IZetherVerifier v, string memory j, string memory c) internal view returns (bool) {
        uint256 s = abi.decode(j.readBytes(string.concat(c, ".opening")), (uint256));
        bytes memory cOut = v.g1Add(v.g1MulBase(j.readUint(string.concat(c, ".amount"))), v.g1Mul(j.readBytes(string.concat(c, ".Yt")), s));
        return keccak256(v.g1MulBase(s)) == keccak256(j.readBytes(string.concat(c, ".Dout")))
            && keccak256(cOut) == keccak256(j.readBytes(string.concat(c, ".Cout")));
    }

    /// `[z]G == A1 + [e]K` và `[z]D_out == A2 + [e](M − [amount]G)`.
    function _cp(IZetherVerifier v, string memory j, string memory c, bytes memory k, bytes memory mMinus, bytes memory dOut)
        internal view returns (bool)
    {
        (bytes memory a1, bytes memory a2, uint256 z) = abi.decode(j.readBytes(string.concat(c, ".opening")), (bytes, bytes, uint256));
        uint256 e = _e(v, j, c, bytes.concat(a1, a2));
        if (keccak256(v.g1MulBase(z)) != keccak256(v.g1Add(a1, v.g1Mul(k, e)))) return false;
        return keccak256(v.g1Mul(dOut, z)) == keccak256(v.g1Add(a2, v.g1Mul(mMinus, e)));
    }

    function _e(IZetherVerifier v, string memory j, string memory c, bytes memory a1a2) internal view returns (uint256) {
        return T.hashToScalar(keccak256(bytes.concat(
            abi.encodePacked("BAMBOO-ZETHER-DISCLOSE-V1", j.readUint(string.concat(c, ".chainId")),
                j.readAddress(string.concat(c, ".token"))),
            abi.encodePacked(j.readBytes32(string.concat(c, ".entryRef")), j.readUint(string.concat(c, ".amount")),
                uint8(j.readUint(string.concat(c, ".kind"))), a1a2)
        )), v.groupOrder());
    }

    function test_s3DisclosureBn254() public view { _checkDisclosure("disclosure_bn254.json"); }
    function test_s3DisclosureBls12381() public view { _checkDisclosure("disclosure_bls12381.json"); }

    function test_s3SchnorrMatches() public view {
        string[2] memory files = ["schnorr_bn254.json", "schnorr_bls12381.json"];
        IZetherVerifier[2] memory vs = [IZetherVerifier(address(bn)), IZetherVerifier(address(bls))];
        for (uint256 i; i < 2; ++i) {
            string memory j = vm.readFile(string.concat(DIR, files[i]));
            bytes memory y = j.readBytes(".Y");
            bytes memory r = j.readBytes(".R");
            uint256 e = T.hashToScalar(keccak256(abi.encodePacked("BAMBOO-ZETHER-SCHNORR-V1", r, y, j.readBytes32(".msg"))), vs[i].groupOrder());
            assertEq(e, j.readUint(".e"));
            assertEq(vs[i].g1MulBase(j.readUint(".z")), vs[i].g1Add(r, vs[i].g1Mul(y, e)));
        }
    }
}
