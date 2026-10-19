// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {IZetherVerifier, IZetherBurnVerifier} from "../../src/zether/IZetherVerifier.sol";
import {ZetherVerifiers} from "./helpers/ZetherVerifiers.sol";
import {ZetherTranscript as T} from "../../src/zether/ZetherTranscript.sol";
import {ITransferDisclosure} from "../../src/zether/ITransferDisclosure.sol";
import {ZetherDisclosure} from "../../src/zether/ZetherDisclosure.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {ZetherSchnorrBn254Verifier, ZetherSchnorrBls12381Verifier} from "../../src/ua/verifiers/PairingVerifiers.sol";

/// Token views `ZetherDisclosure` reads, etched at a vector's token address.
contract S3Token {
    IZetherVerifier public verifier;
    bytes32 public chainUid;
    bytes public auditorKey;
    bytes entry;

    function set(IZetherVerifier v, bytes32 uid, bytes memory ya, bytes memory e) external {
        (verifier, chainUid, auditorKey, entry) = (v, uid, ya, e);
    }

    function transferEntry(bytes32) external view returns (bytes memory) { return entry; }
}

/// @notice Proof do prover Rust của luồng S3 (`r3-zether-prover`, chép vào `test/vectors/zether/s3/`) —
///         một hiện thực ĐỘC LẬP của đặc tả. Đúng thì qua verifier Solidity; lật bất kỳ bit nào thì không.
contract ZetherS3VectorsTest is Test {
    using stdJson for string;

    string constant DIR = "test/vectors/zether/s3/";
    IZetherVerifier bn;
    IZetherVerifier bls;
    IZetherBurnVerifier bnB;
    IZetherBurnVerifier blsB;
    ZetherDisclosure disc;

    function setUp() public {
        (bn, bnB) = ZetherVerifiers.deploy(false);
        (bls, blsB) = ZetherVerifiers.deploy(true);
        disc = new ZetherDisclosure();
    }

    function _v(string memory curve) internal view returns (IZetherVerifier) {
        return keccak256(bytes(curve)) == keccak256("bn254") ? bn : bls;
    }

    enum Op { TRANSFER, BURN, MULTI }

    function _ok(IZetherVerifier v, bytes memory st, bytes memory pr, Op op) internal view returns (bool) {
        try this.verify{gas: 60_000_000}(v, st, pr, op) returns (bool ok) { return ok; } catch { return false; }
    }

    function verify(IZetherVerifier v, bytes memory st, bytes memory pr, Op op) external view returns (bool) {
        if (op == Op.TRANSFER) return v.verifyTransfer(st, pr);
        if (op == Op.MULTI) return v.verifyTransferMulti(st, pr);
        return (address(v) == address(bn) ? bnB : blsB).verifyBurn(st, pr);
    }

    function _flip(bytes memory a, uint256 i) internal pure returns (bytes memory b) {
        b = bytes.concat(a);
        b[i] = bytes1(uint8(b[i]) ^ 0x01);
    }

    /// Proof đúng qua; một bit lật ở 7 vị trí trải đều proof và 5 trường statement thì không.
    function _checkProof(string memory file, Op op) internal view {
        string memory j = vm.readFile(string.concat(DIR, file));
        IZetherVerifier v = _v(j.readString(".curve"));
        bytes memory st = j.readBytes(".statement");
        bytes memory pr = j.readBytes(".proof");
        assertTrue(j.readBool(".expect"));
        assertTrue(this.verify(v, st, pr, op), "S3 proof rejected");
        for (uint256 k = 1; k <= 7; ++k) {
            assertFalse(_ok(v, st, _flip(pr, (pr.length * k) / 8 - 1), op), "tampered proof accepted");
        }
        // chainId, chainUid, binding, sendCounter, accSeq, fee
        uint256[6] memory fields = [uint256(95), 127, 223, 255, 287, 319];
        for (uint256 k; k < 6; ++k) {
            assertFalse(_ok(v, _flip(st, fields[k]), pr, op), "tampered statement accepted");
        }
        if (op == Op.MULTI) {
            // every leg point of the statement is bound; so is the mode (opTag)
            for (uint256 k = 1; k <= 5; ++k) {
                assertFalse(_ok(v, _flip(st, st.length - (st.length - 448) * k / 6), pr, op), "tampered leg accepted");
            }
            assertFalse(_ok(v, _flip(st, 31), pr, op), "mode switch accepted");
        }
        // authDigest §11 khớp đặc tả
        assertEq(keccak256(abi.encodePacked("SCAAS-ZETHER-AUTH-V1", keccak256(st))), j.readBytes32(".authDigest"));
    }

    function test_s3TransferBn254() public view { _checkProof("transfer_bn254.json", Op.TRANSFER); }
    function test_s3TransferBls12381() public view { _checkProof("transfer_bls12381.json", Op.TRANSFER); }
    function test_s3TransferNoAuditorBn254() public view { _checkProof("transfer_noaud_bn254.json", Op.TRANSFER); }
    function test_s3TransferNoAuditorBls12381() public view { _checkProof("transfer_noaud_bls12381.json", Op.TRANSFER); }
    function test_s3BurnBn254() public view { _checkProof("burn_bn254.json", Op.BURN); }
    function test_s3BurnBls12381() public view { _checkProof("burn_bls12381.json", Op.BURN); }
    function test_s3MultiBn254() public view { _checkProof("transfer_multi_bn254.json", Op.MULTI); }
    function test_s3MultiBls12381() public view { _checkProof("transfer_multi_bls12381.json", Op.MULTI); }
    function test_s3MultiNoAuditorBn254() public view { _checkProof("transfer_multi_noaud_bn254.json", Op.MULTI); }
    function test_s3MultiNoAuditorBls12381() public view { _checkProof("transfer_multi_noaud_bls12381.json", Op.MULTI); }

    /// Header của statement nhiều người nhận: opTag theo mode, proof system id "/multi".
    function test_s3MultiStatementHeader() public view {
        string memory j = vm.readFile(string.concat(DIR, "transfer_multi_bn254.json"));
        (bytes32 op, bytes32 psid) = abi.decode(_head(j.readBytes(".statement"), 0), (bytes32, bytes32));
        assertEq(op, keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/HASH"));
        assertEq(psid, bn.proofSystemIdMulti());
        assertEq(bn.proofSystemIdMulti(), keccak256("scaas/zether/sigma-bullets/bn254/n64-n64/v2/multi"));
        string memory k = vm.readFile(string.concat(DIR, "transfer_multi_noaud_bls12381.json"));
        (op,) = abi.decode(_head(k.readBytes(".statement"), 0), (bytes32, bytes32));
        assertEq(op, keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/NONE"));
    }

    /// Header statement của S3 đúng bố cục zether.md §7 (448 byte, `chainUid` là word 3) với các trường của `request`.
    function test_s3StatementHeaderMatchesRequest() public view {
        string memory j = vm.readFile(string.concat(DIR, "transfer_bn254.json"));
        bytes memory st = j.readBytes(".statement");
        (bytes32 op, bytes32 psid, uint256 chainId, bytes32 uid, address token, bytes32 tag) =
            abi.decode(_head(st, 0), (bytes32, bytes32, uint256, bytes32, address, bytes32));
        assertEq(op, keccak256("SCAAS-ZETHER-OP-TRANSFER-V1"));
        assertEq(psid, bn.proofSystemId());
        assertEq(chainId, j.readUint(".request.chainId"));
        assertEq(uid, j.readBytes32(".request.chainUid"));
        assertEq(token, j.readAddress(".request.token"));
        assertEq(tag, keccak256("ZTX_V1_RELAYED"));
        assertEq(bytes32(_head(st, 192)), j.readBytes32(".request.envelopeBinding"));
    }

    function test_s3StatementCountersAndEntryRef() public view {
        string memory j = vm.readFile(string.concat(DIR, "transfer_bn254.json"));
        bytes memory st = j.readBytes(".statement");
        (uint256 sc, uint256 accSeq, uint256 fee, bytes32 ben,,) =
            abi.decode(_head(st, 224), (uint256, uint256, uint256, bytes32, uint256, address));
        assertEq(sc, j.readUint(".request.sendCounter"));
        assertEq(accSeq, j.readUint(".request.accSeq"));
        assertEq(fee, j.readUint(".request.fee"));
        assertEq(ben, j.readBytes32(".request.beneficiary"));
        _checkMemo(j, st);
        _checkMemo(vm.readFile(string.concat(DIR, "transfer_multi_bls12381.json")), "");
        // entryRef (CTR-ZTH-36) = keccak(tag, chainId, chainUid, token, fromUA, sendCounter), fromUA tagged (CTR-UA-16)
        bytes memory yf = new bytes(64);
        for (uint256 i; i < 64; ++i) yf[i] = st[480 + i];
        bytes32 fromUA = keccak256(abi.encodePacked(keccak256("scaas.ua.zether-bn254.v1"), yf));
        assertEq(
            keccak256(abi.encode(keccak256("SCAAS-ZETHER-ENTRY-V1"), j.readUint(".request.chainId"),
                j.readBytes32(".request.chainUid"), j.readAddress(".request.token"), fromUA, sc)),
            j.readBytes32(".entryRef")
        );
    }

    /// Header word 13 is the salt (16 zero bytes ‖ salt), the payload's bytes 64..80 too (CTR-ZTH-30); word 14 is
    /// `keccak256(memo)` on commit-reveal, the payload then ending with the memo of `17 + 40·M` bytes, else 0
    /// (CTR-ZTH-50).
    function _checkMemo(string memory j, bytes memory st) internal view {
        if (st.length == 0) st = j.readBytes(".statement");
        bytes memory pl = j.readBytes(".payload");
        bytes16 salt = bytes16(j.readBytes(".salt"));
        assertEq(bytes32(_head(st, 416)), bytes32(uint256(uint128(salt))), "salt, word 13");
        assertEq(bytes16(_head(pl, 64)), salt, "salt after sendCounter");
        bytes memory memo = vm.keyExistsJson(j, ".memo") ? j.readBytes(".memo") : bytes("");
        assertEq(bytes32(_head(st, 448)), memo.length == 0 ? bytes32(0) : keccak256(memo), "memoHash, word 14");
        if (memo.length == 0) return;
        bytes memory tail = new bytes(memo.length);
        for (uint256 i; i < memo.length; ++i) tail[i] = pl[pl.length - memo.length + i];
        assertEq(tail, memo, "the payload ends with the memo");
        assertEq((memo.length - 17) % 40, 0);
    }

    function _head(bytes memory st, uint256 off) internal pure returns (bytes memory out) {
        out = new bytes(192);
        for (uint256 i; i < 192; ++i) out[i] = st[off + i];
    }

    /// `directCalldata` = `zetherTransferSingle(payload, proof, authSig, beneficiary)`: the direct call, and unchanged the
    /// envelope's `data` (CTR-ZTH-34).
    function test_s3DirectCalldataIsTheEntryPointCall() public view {
        string memory j = vm.readFile(string.concat(DIR, "transfer_bn254.json"));
        bytes memory op = j.readBytes(".directCalldata");
        assertEq(bytes4(op), bytes4(keccak256("zetherTransferSingle(bytes,bytes,bytes,bytes32)")));
        bytes memory args = new bytes(op.length - 4);
        for (uint256 i; i < args.length; ++i) args[i] = op[4 + i];
        (bytes memory pl, bytes memory pr,, bytes32 ben) = abi.decode(args, (bytes, bytes, bytes, bytes32));
        assertEq(pl, j.readBytes(".payload"));
        assertEq(pr, j.readBytes(".proof"));
        assertEq(ben, j.readBytes32(".request.beneficiary"));
    }

    /// Mở tiết lộ của S3 qua contract `ZetherDisclosure` thật (token giả etch tại địa chỉ token của vector): bốn kind
    ///      trên transfer một người nhận (leg 0) và bốn kind trên leg 1 của transfer nhiều người nhận. Leg chép sang
    ///      index kế tiếp thì không mở (index nằm trong challenge). `uid != 0`: chain B (cùng chainid, khác chainUid).
    function _checkDisclosure(string memory file, bytes32 uid) internal returns (uint256 ok) {
        string memory j = vm.readFile(string.concat(DIR, file));
        IZetherVerifier v = _v(j.readString(".curve"));
        address impl = address(new S3Token());
        uint256 n;
        for (; vm.keyExistsJson(j, string.concat(".cases[", vm.toString(n), "]")); ++n) {
            string memory c = string.concat(".cases[", vm.toString(n), "]");
            assertTrue(j.readBool(string.concat(c, ".expect")));
            uint256 idx = j.readUint(string.concat(c, ".index"));
            address tok = j.readAddress(string.concat(c, ".token"));
            vm.etch(tok, impl.code);
            bytes memory leg = bytes.concat(j.readBytes(string.concat(c, ".Yt")), j.readBytes(string.concat(c, ".Cout")),
                j.readBytes(string.concat(c, ".Dout")), j.readBytes(string.concat(c, ".Caud")));
            S3Token(tok).set(v, uid == 0 ? j.readBytes32(string.concat(c, ".chainUid")) : uid,
                j.readBytes(string.concat(c, ".Ya")), bytes.concat(new bytes(16 + idx * leg.length), leg, leg)); // R = salt ‖ …
            vm.chainId(j.readUint(string.concat(c, ".chainId")));
            if (!_disclose(j, c, tok, idx)) continue;
            ++ok;
            if (j.readUint(string.concat(c, ".kind")) != 0) assertFalse(_disclose(j, c, tok, idx + 1), "opening moved leg");
        }
        assertEq(n, 8);
    }

    function _disclose(string memory j, string memory c, address tok, uint256 idx) internal view returns (bool) {
        return disc.verifyTransferAmount(tok, j.readBytes32(string.concat(c, ".entryRef")), idx,
            j.readUint(string.concat(c, ".amount")), ITransferDisclosure.OpeningKind(j.readUint(string.concat(c, ".kind"))),
            j.readBytes(string.concat(c, ".opening")), "");
    }

    function test_s3DisclosureBn254() public { assertEq(_checkDisclosure("disclosure_bn254.json", 0), 8); }
    function test_s3DisclosureBls12381() public { assertEq(_checkDisclosure("disclosure_bls12381.json", 0), 8); }

    /// Chain B (same chainid, another chainUid, a re-created chain): every Chaum-Pedersen opening (kinds 1-3) fails.
    /// The two SENDER_S openings still pass by design: no challenge, bound through `entryRef` and the chain-specific `s`.
    function test_s3DisclosureRefusedOnAnotherChainUid() public {
        assertEq(_checkDisclosure("disclosure_bn254.json", keccak256("chain B")), 2);
        assertEq(_checkDisclosure("disclosure_bls12381.json", keccak256("chain B")), 2);
    }

    /// Review T2 m4: a foreign token's entry shorter than the salt is not a record: `BundlesMismatch`, not a panic.
    function test_shortEntryIsNotARecord() public {
        S3Token t = new S3Token();
        t.set(bn, bytes32(0), "", hex"0102");
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.BundlesMismatch.selector, bytes32("ref")));
        disc.verifyTransferAmount(address(t), "ref", 0, 1, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(1), "");
    }

    function test_s3SchnorrMatches() public view {
        string[2] memory files = ["schnorr_bn254.json", "schnorr_bls12381.json"];
        IZetherVerifier[2] memory vs = [bn, bls];
        for (uint256 i; i < 2; ++i) {
            string memory j = vm.readFile(string.concat(DIR, files[i]));
            bytes memory y = j.readBytes(".Y");
            bytes memory r = j.readBytes(".R");
            uint256 e = T.hashToScalar(keccak256(abi.encodePacked("SCAAS-ZETHER-SCHNORR-V1", r, y, j.readBytes32(".msg"))), vs[i].groupOrder());
            assertEq(e, j.readUint(".e"));
            assertEq(vs[i].g1MulBase(j.readUint(".z")), vs[i].g1Add(r, vs[i].g1Mul(y, e)));
        }
    }

    /// The prover's registration PoP (`r33_keys.json`, CTR-UA-07: chain 31337, the vectors' `chainUid`, registry
    /// `0xaa…aa`, `authRef` 0) registers on a real UA registry at that address: one PoP for the prover, clientkeys
    /// (`test/zether.test.js` reads the same file) and the registry. A flipped bit is `UAPoP`.
    function test_s3PopRegisters() public {
        string memory j = vm.readFile(string.concat(DIR, "r33_keys.json"));
        address at = j.readAddress(".bn254.keys[0].pop.registry");
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](2);
        k[0] = UARegistry.KindConfig(0x0140, address(new ZetherSchnorrBn254Verifier()), 50_000);
        k[1] = UARegistry.KindConfig(0x0141, address(new ZetherSchnorrBls12381Verifier()), 70_000);
        bytes32 uid = j.readBytes32(".bn254.keys[0].pop.chainUid");
        deployCodeTo("UARegistry.sol:UARegistry", abi.encode(uid, address(0), false, uint64(12_000_000), address(0), false, k), at);
        IUARegistry reg = IUARegistry(at);
        string[2] memory curves = [".bn254", ".bls12381"];
        for (uint256 i; i < 2; ++i) {
            string memory key = string.concat(curves[i], ".keys[0]");
            uint16 kind = uint16(j.readUint(string.concat(key, ".pop.kind")));
            bytes memory y = j.readBytes(string.concat(key, ".Y"));
            bytes32 ua = j.readBytes32(string.concat(key, ".UA"));
            assertEq(j.readUint(string.concat(key, ".pop.chainId")), block.chainid);
            assertEq(reg.uaOf(kind, y), ua);
            assertEq(reg.popDigest(ua, 0), j.readBytes32(string.concat(key, ".pop.popDigest")));
            bytes memory pop = j.readBytes(string.concat(key, ".pop.pop"));
            vm.expectRevert(IUARegistry.UAPoP.selector);
            reg.register(kind, y, _flip(pop, pop.length - 1), 0, "");
            assertEq(reg.register(kind, y, pop, 0, ""), ua);
            assertEq(reg.keyOf(ua), y);
        }
    }
}
