// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IZetherVerifier, IZetherBurnVerifier} from "../../../src/zether/IZetherVerifier.sol";
import {G1Bls12381} from "../../../src/zether/ZetherCurves.sol";
import {ZetherProver} from "./ZetherProver.sol";
import {ZetherVerifiers} from "./ZetherVerifiers.sol";

/// @notice Statements and proofs of every form on hand-built statements (zether.md §7) and the byte helpers the merged-check
///         suites share. `Case.wit` is the prover's value, `Case.amt` the ciphertexts': different, a cheating witness.
abstract contract ZetherMsmCorpus is Test {
    bytes32 constant OP_T = keccak256("SCAAS-ZETHER-OP-TRANSFER-V1");
    bytes32 constant OP_B = keccak256("SCAAS-ZETHER-OP-BURN-V1");
    bytes32 constant OP_M = keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/BUNDLE");
    uint256 constant XF = 0xA11CE;
    uint256 constant XT = 0xB0B;
    uint256 constant XA = 0xA0D17;
    uint256 constant RHO = 0x5EED;
    uint256 constant S = 0x5;
    uint256 constant T0 = 0x7A0;
    uint256 constant B = 1_000_000;
    uint256 constant FEE = 5;
    uint256 constant P = 128;
    uint256 constant HEADER = 512;
    uint256 constant BP_LEN = 16 * P + 160;
    uint256 constant R = G1Bls12381.R;

    IZetherVerifier v;
    IZetherBurnVerifier vb;
    ZetherProver prover;

    struct Case {
        uint256 bal;
        uint256 amt;
        uint256 wit;
        uint256 fee;
        bool aud;
    }

    function _corpus() internal {
        (v, vb) = ZetherVerifiers.deploy();
        prover = new ZetherProver();
    }

    function _header(bytes32 op, bytes32 psid, uint256 fee, uint256 amount, address to) internal view returns (bytes memory) {
        return bytes.concat(
            abi.encode(op, psid, block.chainid, keccak256("msm chain"), address(0x70CE), keccak256("ZTX_V1_DIRECT")),
            abi.encode(bytes32(0), uint256(7), uint256(3), fee, bytes32(uint256(0xBE))),
            abi.encode(amount, to, op == OP_B ? bytes32(0) : bytes32(uint256(0x5A17)), bytes32(0), uint256(1000))
        );
    }

    function _acc(uint256 bal) internal view returns (bytes memory c, bytes memory d) {
        uint256[] memory sc = new uint256[](2);
        (sc[0], sc[1]) = (bal, RHO);
        c = v.g1Msm(bytes.concat(v.g1MulBase(1), v.g1MulBase(XF)), sc);
        d = v.g1MulBase(RHO);
    }

    function _transferSt(Case memory k) internal view returns (bytes memory) {
        (bytes memory cAcc, bytes memory dAcc) = _acc(k.bal);
        bytes memory ya = k.aud ? v.g1MulBase(XA) : v.identity();
        bytes memory head = bytes.concat(_header(OP_T, v.proofSystemId(), k.fee, 0, address(0)), v.g1MulBase(XF), v.g1MulBase(XT));
        return bytes.concat(head, ya, cAcc, dAcc, _cts(ya, k.amt));
    }

    function _cts(bytes memory ya, uint256 amt) internal view returns (bytes memory) {
        (bytes memory cOut, bytes memory dOut, bytes memory cDeb, bytes memory cAud) =
            prover.ciphertexts(v, v.g1MulBase(XF), v.g1MulBase(XT), ya, amt, S);
        return bytes.concat(cOut, dOut, cDeb, cAud);
    }

    function _transfer(Case memory k) internal view returns (bytes memory st, bytes memory pr) {
        st = _transferSt(k);
        pr = _proveTransfer(k, st);
    }

    function _proveTransfer(Case memory k, bytes memory st) internal view returns (bytes memory) {
        uint256 bPrime = addmod(k.bal, R - addmod(k.wit, k.fee, R), R);
        return prover.proveTransfer(v, st, ZetherProver.TransferWitness(XF, k.wit, S, bPrime, 0x77, 0x88, keccak256("t")));
    }

    function _transfer(bool aud) internal view returns (bytes memory, bytes memory) {
        return _transfer(Case(B, 300, 300, FEE, aud));
    }

    function _burnSt(uint256 bal, uint256 amt, uint256 fee) internal view returns (bytes memory) {
        (bytes memory cAcc, bytes memory dAcc) = _acc(bal);
        return bytes.concat(_header(OP_B, v.proofSystemId(), fee, amt, address(0xCAFE)), v.g1MulBase(XF), cAcc, dAcc);
    }

    function _proveBurn(bytes memory st, uint256 x, uint256 bPrime) internal view returns (bytes memory) {
        return prover.proveBurn(v, st, ZetherProver.BurnWitness(x, bPrime, 0x99, keccak256("b")));
    }

    function _burn() internal view returns (bytes memory st, bytes memory pr) {
        st = _burnSt(B, 400, FEE);
        pr = _proveBurn(st, XF, B - 400 - FEE);
    }

    function _multiSt(uint256 m, uint256[] memory vs, bool aud) internal view returns (bytes memory st, uint256 total) {
        bytes memory ya = aud ? v.g1MulBase(XA) : v.identity();
        bytes memory legs;
        for (uint256 j; j < m; ++j) {
            vs[j] = 100 + j;
            total += vs[j];
            legs = bytes.concat(legs, _leg(j, vs[j], ya));
        }
        st = bytes.concat(_multiHead(total, ya), abi.encode(m), legs);
    }

    function _leg(uint256 j, uint256 amt, bytes memory ya) internal view returns (bytes memory) {
        bytes memory yt = v.g1MulBase(0xD00 + j);
        (bytes memory cOut,,,) = prover.ciphertexts(v, v.g1MulBase(XF), yt, ya, amt, S);
        (bytes memory cAud, bytes memory dAud) = prover.audCopy(v, ya, amt, T0 + j);
        return bytes.concat(yt, cOut, cAud, dAud);
    }

    function _multiHead(uint256 total, bytes memory ya) internal view returns (bytes memory) {
        bytes memory yf = v.g1MulBase(XF);
        (, bytes memory dOut, bytes memory cDeb,) = prover.ciphertexts(v, yf, yf, ya, total, S);
        (bytes memory cAcc, bytes memory dAcc) = _acc(B);
        return bytes.concat(_header(OP_M, v.proofSystemIdMulti(), FEE, 0, address(0)), yf, ya, bytes.concat(cAcc, dAcc, dOut, cDeb));
    }

    function _multi(uint256 m, bool aud) internal view returns (bytes memory st, bytes memory pr) {
        return _multi(m, aud, 0);
    }

    /// @dev `over`: the witness claims `b'` that much above the balance left, a cheating balance.
    function _multi(uint256 m, bool aud, uint256 over) internal view returns (bytes memory st, bytes memory pr) {
        uint256[] memory vs = new uint256[](m);
        uint256 total;
        (st, total) = _multiSt(m, vs, aud);
        uint256[] memory gv = new uint256[](m);
        uint256[] memory ts = new uint256[](m);
        for (uint256 j; j < m; ++j) (gv[j], ts[j]) = (0x1234 + 7 * j, T0 + j);
        pr = prover.proveTransferMulti(v, st,
            ZetherProver.MultiWitness(XF, S, vs, ts, B - FEE - total + over, gv, 0x5678, keccak256("m")));
    }

    function _word(bytes memory a, uint256 off) internal pure returns (uint256 w) {
        assembly ("memory-safe") { w := mload(add(add(a, 32), off)) }
    }

    function _setWord(bytes memory a, uint256 off, uint256 w) internal pure {
        assembly ("memory-safe") { mstore(add(add(a, 32), off), w) }
    }

    function _setPoint(bytes memory a, uint256 off, bytes memory pt) internal pure {
        for (uint256 i; i < P; i += 32) _setWord(a, off + i, _word(pt, i));
    }

    function _point(bytes memory a, uint256 off) internal pure returns (bytes memory pt) {
        return _at(a, off, P);
    }

    function _head(bytes memory a, uint256 n) internal pure returns (bytes memory) {
        return _at(a, 0, n);
    }

    function _at(bytes memory a, uint256 off, uint256 n) internal pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 i; i < n; i += 32) _setWord(out, i, _word(a, off + i));
    }

    /// @dev `(0, 2)`: on the curve, order 3 (`y² = x³ + 4`, and `x = 0` is an inflection), outside the `r`-subgroup.
    function _lowOrder() internal pure returns (bytes memory) {
        return abi.encodePacked(uint256(0), uint256(0), uint256(0), uint256(2));
    }
}
