// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {UniversalAccountRegistry} from "../../src/registry/UniversalAccountRegistry.sol";
import {IUniversalAccountRegistry as IR} from "../../src/registry/IUniversalAccountRegistry.sol";
import {AuthScheme} from "../../src/common/AuthScheme.sol";
import {MultiSig} from "../../src/common/MultiSig.sol";
import {Bls12381} from "../../src/common/Bls12381.sol";
import {HashToCurve} from "../../src/common/HashToCurve.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {ZetherSafety} from "../../src/zether/ZetherSafety.sol";
import {G1Bn254, G1Bls12381} from "../../src/zether/ZetherCurves.sol";
import {ZetherKeys} from "./helpers/ZetherKeys.sol";
import {Mock1271Wallet} from "../helpers/WalletMocks.sol";

/// @notice PoP chống rogue key, trùng lặp, 8 scheme (đăng ký + uỷ quyền), link hai chiều (SRS §7.5).
contract UniversalAccountRegistryTest is Test {
    using stdJson for string;

    UniversalAccountRegistry reg;
    uint256 constant X = 0xC0FFEE;
    bytes32 constant M = keccak256("digest");

    function setUp() public {
        reg = new UniversalAccountRegistry();
    }

    function _pop(uint256 x, bool bls, bytes memory authPop) internal view returns (bytes memory) {
        bytes memory y = ZetherKeys.pub(x, bls);
        return abi.encode(ZetherKeys.schnorr(x, reg.popChallenge(y, address(this)), bls), authPop);
    }

    function _reg(uint256 x, bool bls, AuthScheme s, bytes memory d, bytes memory authPop, bool link)
        internal returns (ZetherTypes.UA)
    {
        return reg.register(ZetherKeys.pub(x, bls), s, d, _pop(x, bls, authPop), link);
    }

    // ------------------------------------------------------------------ PoP, trùng, khoá

    function test_registerSelfSchnorrBothCurves() public {
        ZetherTypes.UA a = _reg(X, false, AuthScheme.SELF_SCHNORR, "", "", true);
        ZetherTypes.UA b = _reg(X, true, AuthScheme.SELF_SCHNORR, "", "", false);
        assertTrue(ZetherTypes.UA.unwrap(a) != ZetherTypes.UA.unwrap(b), "UA curve-dependent");
        assertTrue(reg.isRegistered(a) && reg.isRegistered(b));
        assertEq(reg.keyLengthOf(a), 64);
        assertEq(reg.keyLengthOf(b), 128);
        assertEq(ZetherTypes.UA.unwrap(reg.links(address(this))), ZetherTypes.UA.unwrap(a));
        assertEq(reg.link_eth(a), address(this));
        assertEq(reg.link_eth(b), address(0));
        (bool r, AuthScheme s, address l,) = reg.accounts(a);
        assertTrue(r);
        assertEq(uint8(s), uint8(AuthScheme.SELF_SCHNORR));
        assertEq(l, address(this));
    }

    function test_duplicateRejected() public {
        ZetherTypes.UA a = _reg(X, false, AuthScheme.SELF_SCHNORR, "", "", false);
        bytes memory y = ZetherKeys.pub(X, false);
        bytes memory pop = _pop(X, false, "");
        vm.expectRevert(abi.encodeWithSelector(IR.AccountAlreadyRegistered.selector, a));
        reg.register(y, AuthScheme.SELF_SCHNORR, "", pop, false);
    }

    /// Rogue key: kẻ gian đăng ký khoá của nạn nhân, ký PoP bằng khoá của chính mình.
    function test_rogueKeyRejected() public {
        bytes memory victimY = ZetherKeys.pub(X, false);
        bytes memory pop = abi.encode(ZetherKeys.schnorr(0xBAD, reg.popChallenge(victimY, address(this)), false), bytes(""));
        vm.expectRevert(IR.InvalidProofOfPossession.selector);
        reg.register(victimY, AuthScheme.SELF_SCHNORR, "", pop, false);
    }

    /// PoP trói `msg.sender`: không nhấc PoP của người khác từ mempool được.
    function test_popBoundToSender() public {
        bytes memory y = ZetherKeys.pub(X, true);
        bytes memory pop = _pop(X, true, "");
        vm.prank(address(0xE11E));
        vm.expectRevert(IR.InvalidProofOfPossession.selector);
        reg.register(y, AuthScheme.SELF_SCHNORR, "", pop, false);
    }

    /// Rogue key trong tổng hợp: groupKey = [a]G − Y_victim, kẻ gian không biết dlog ⇒ authPop chết.
    function test_rogueAggregateKeyRejected() public {
        bytes memory rogue = G1Bn254.sub(G1Bn254.mulBase(777), ZetherKeys.pub(X, false));
        bytes memory d = abi.encode(rogue, uint256(2));
        bytes memory y = ZetherKeys.pub(0xAB, false);
        bytes32 c = reg.popChallenge(y, address(this));
        bytes memory forged = ZetherKeys.schnorr(777, c, false); // ký bằng a, không phải dlog của rogue
        bytes memory pop = abi.encode(ZetherKeys.schnorr(0xAB, c, false), forged);
        vm.expectRevert(IR.InvalidProofOfPossession.selector);
        reg.register(y, AuthScheme.MUSIG2_BN254, d, pop, false);
    }

    function test_invalidKeysRejected() public {
        bytes memory pop = abi.encode(bytes(""), bytes(""));
        vm.expectRevert(IR.InvalidPublicKey.selector);
        reg.register(new bytes(64), AuthScheme.SELF_SCHNORR, "", pop, false); // vô cực
        vm.expectRevert(IR.InvalidPublicKey.selector);
        reg.register(abi.encodePacked(uint256(1), uint256(3)), AuthScheme.SELF_SCHNORR, "", pop, false);
        vm.expectRevert(IR.InvalidPublicKey.selector);
        reg.register(new bytes(96), AuthScheme.SELF_SCHNORR, "", pop, false);
        bytes memory ns = vm.readFile("test/vectors/zether/curve_misc.json").readBytes(".blsNonSubgroup");
        vm.expectRevert(IR.InvalidPublicKey.selector);
        reg.register(ns, AuthScheme.SELF_SCHNORR, "", pop, false);
    }

    function test_malformedSchnorrPopRejected() public {
        bytes memory y = ZetherKeys.pub(X, false);
        bytes memory sig = ZetherKeys.schnorr(X, reg.popChallenge(y, address(this)), false);
        bytes memory zero = bytes.concat(new bytes(64), new bytes(32)); // R = O
        vm.expectRevert(IR.InvalidProofOfPossession.selector);
        reg.register(y, AuthScheme.SELF_SCHNORR, "", abi.encode(zero, bytes("")), false);
        bytes memory big = bytes.concat(sig); // z ≥ r
        uint256 zr;
        assembly { zr := add(mload(add(big, 96)), 0) }
        zr += G1Bn254.R;
        assembly { mstore(add(big, 96), zr) }
        vm.expectRevert(IR.InvalidProofOfPossession.selector);
        reg.register(y, AuthScheme.SELF_SCHNORR, "", abi.encode(big, bytes("")), false);
        vm.expectRevert(IR.InvalidProofOfPossession.selector);
        reg.register(y, AuthScheme.SELF_SCHNORR, "", abi.encode(bytes.concat(sig, hex"00"), bytes("")), false);
        vm.expectRevert(IR.InvalidProofOfPossession.selector); // SELF không có authPop
        reg.register(y, AuthScheme.SELF_SCHNORR, "", abi.encode(sig, hex"01"), false);
    }

    function test_blsOnSameCurveProhibited() public {
        bytes memory pop = abi.encode(bytes(""), bytes(""));
        bytes memory y = ZetherKeys.pub(X, false);
        vm.expectRevert(abi.encodeWithSelector(IR.UnauthorizedScheme.selector, AuthScheme.BLS_BN254));
        reg.register(y, AuthScheme.BLS_BN254, "", pop, false);
        y = ZetherKeys.pub(X, true);
        vm.expectRevert(abi.encodeWithSelector(IR.UnauthorizedScheme.selector, AuthScheme.BLS_12381));
        reg.register(y, AuthScheme.BLS_12381, "", pop, false);
    }

    function test_evmLinkOncePerAddress() public {
        _reg(X, false, AuthScheme.SELF_SCHNORR, "", "", true);
        bytes memory y = ZetherKeys.pub(X + 1, false);
        bytes memory pop = _pop(X + 1, false, "");
        vm.expectRevert(abi.encodeWithSelector(IR.EVMAlreadyLinked.selector, address(this)));
        reg.register(y, AuthScheme.SELF_SCHNORR, "", pop, true);
    }

    function test_onlyDevChain() public {
        vm.chainId(100);
        vm.expectRevert(abi.encodeWithSelector(ZetherSafety.ZetherNotDevChain.selector, 100));
        new UniversalAccountRegistry();
    }

    // ------------------------------------------------------------------ uỷ quyền theo scheme

    function test_selfSchnorrAuth() public {
        ZetherTypes.UA a = _reg(X, false, AuthScheme.SELF_SCHNORR, "", "", false);
        reg.requireAuthorized(a, M, "", true); // proof đi kèm: không chữ ký
        vm.expectRevert(abi.encodeWithSelector(IR.Unauthorized.selector, a));
        reg.requireAuthorized(a, M, hex"00", true);
        bytes memory y = ZetherKeys.pub(X, false);
        reg.requireAuthorized(a, M, abi.encode(y, ZetherKeys.schnorr(X, M, false)), false);
        bytes memory wrongMsg = abi.encode(y, ZetherKeys.schnorr(X, keccak256("other"), false));
        vm.expectRevert(abi.encodeWithSelector(IR.Unauthorized.selector, a));
        reg.requireAuthorized(a, M, wrongMsg, false);
        bytes memory y2 = ZetherKeys.pub(X + 5, false);
        bytes memory otherKey = abi.encode(y2, ZetherKeys.schnorr(X + 5, M, false));
        vm.expectRevert(abi.encodeWithSelector(IR.Unauthorized.selector, a)); // Y không khớp UA
        reg.requireAuthorized(a, M, otherKey, false);
    }

    /// Chữ ký Schnorr do kat.py (Python, độc lập) sinh ra phải qua registry.
    function test_selfSchnorrAcceptsReferenceSignature() public {
        string memory j = vm.readFile("test/vectors/zether/schnorr_bls12381.json");
        uint256 x = uint256(j.readBytes32(".x"));
        ZetherTypes.UA a = _reg(x, true, AuthScheme.SELF_SCHNORR, "", "", false);
        reg.requireAuthorized(a, j.readBytes32(".msg"), abi.encode(j.readBytes(".Y"), j.readBytes(".sig")), false);
    }

    function test_unregisteredUnauthorized() public {
        ZetherTypes.UA u = ZetherTypes.UA.wrap(keccak256("nobody"));
        vm.expectRevert(abi.encodeWithSelector(IR.Unauthorized.selector, u));
        reg.requireAuthorized(u, M, "", true);
    }

    function _ecdsa(uint256 pk, bytes32 h) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, h);
        return abi.encodePacked(r, s, v);
    }

    function test_multisigAuth() public {
        uint256[3] memory pks = [uint256(0xA1), 0xA2, 0xA3];
        address[] memory owners = new address[](3);
        for (uint256 i; i < 3; ++i) owners[i] = vm.addr(pks[i]);
        // sắp tăng dần
        for (uint256 i; i < 3; ++i) for (uint256 k = i + 1; k < 3; ++k) if (owners[k] < owners[i]) {
            (owners[i], owners[k]) = (owners[k], owners[i]);
            (pks[i], pks[k]) = (pks[k], pks[i]);
        }
        bytes memory d = abi.encode(owners, uint256(2));
        bytes memory y = ZetherKeys.pub(X, false);
        bytes32 c = reg.popChallenge(y, address(this));
        bytes[] memory popSigs = new bytes[](2);
        popSigs[0] = _ecdsa(pks[0], c);
        popSigs[1] = _ecdsa(pks[1], c);
        ZetherTypes.UA a = reg.register(y, AuthScheme.ECDSA_MULTISIG, d,
            abi.encode(ZetherKeys.schnorr(X, c, false), abi.encode(popSigs)), false);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _ecdsa(pks[1], M);
        sigs[1] = _ecdsa(pks[2], M);
        reg.requireAuthorized(a, M, abi.encode(sigs), true); // vẫn cần chữ ký dù có proof
        bytes[] memory one = new bytes[](1);
        one[0] = sigs[0];
        vm.expectRevert(abi.encodeWithSelector(MultiSig.ThresholdNotMet.selector, 1, 2));
        reg.requireAuthorized(a, M, abi.encode(one), true);
    }

    function test_multisigBadAuthDataRejected() public {
        address[] memory owners = new address[](2);
        owners[0] = address(2);
        owners[1] = address(1); // không tăng
        bytes memory pop = abi.encode(bytes(""), bytes(""));
        bytes memory y = ZetherKeys.pub(X, false);
        vm.expectRevert(IR.InvalidAuthData.selector);
        reg.register(y, AuthScheme.ECDSA_MULTISIG, abi.encode(owners, uint256(1)), pop, false);
        owners[0] = address(1);
        owners[1] = address(2);
        vm.expectRevert(IR.InvalidAuthData.selector);
        reg.register(y, AuthScheme.ECDSA_MULTISIG, abi.encode(owners, uint256(0)), pop, false);
        vm.expectRevert(IR.InvalidAuthData.selector);
        reg.register(y, AuthScheme.ECDSA_MULTISIG, abi.encode(owners, uint256(3)), pop, false);
        vm.expectRevert(IR.InvalidAuthData.selector);
        reg.register(y, AuthScheme.SELF_SCHNORR, hex"01", pop, false);
        vm.expectRevert(IR.InvalidAuthData.selector);
        reg.register(y, AuthScheme.PQ_COMMITMENT, abi.encode(bytes32(0)), pop, false);
        vm.expectRevert(IR.InvalidAuthData.selector);
        reg.register(y, AuthScheme.SMART_ACCOUNT_1271, abi.encode(address(0x1234)), pop, false);
        vm.expectRevert(IR.InvalidAuthData.selector);
        reg.register(y, AuthScheme.FROST_BN254, abi.encode(new bytes(64), uint256(1), uint256(1)), pop, false);
        bytes memory key3 = G1Bn254.mulBase(3);
        vm.expectRevert(IR.InvalidAuthData.selector);
        reg.register(y, AuthScheme.MUSIG2_BN254, abi.encode(key3, uint256(0)), pop, false);
        bytes memory yb = ZetherKeys.pub(X, true);
        vm.expectRevert(IR.InvalidAuthData.selector);
        reg.register(yb, AuthScheme.BLS_BN254, abi.encode(new bytes(127)), pop, false);
    }

    function _schnorrGroup(AuthScheme s, bytes memory d, uint256 groupSk) internal {
        bytes memory y = ZetherKeys.pub(X, true);
        bytes32 c = reg.popChallenge(y, address(this));
        ZetherTypes.UA a = reg.register(y, s, d,
            abi.encode(ZetherKeys.schnorr(X, c, true), ZetherKeys.schnorr(groupSk, c, false)), false);
        reg.requireAuthorized(a, M, ZetherKeys.schnorr(groupSk, M, false), true);
        bytes memory wrong = ZetherKeys.schnorr(groupSk + 1, M, false);
        vm.expectRevert(abi.encodeWithSelector(IR.Unauthorized.selector, a));
        reg.requireAuthorized(a, M, wrong, true);
    }

    function test_frostAuth() public {
        _schnorrGroup(AuthScheme.FROST_BN254, abi.encode(G1Bn254.mulBase(0xF0057), uint256(3), uint256(5)), 0xF0057);
    }

    function test_musig2Auth() public {
        _schnorrGroup(AuthScheme.MUSIG2_BN254, abi.encode(G1Bn254.mulBase(0x3516), uint256(4)), 0x3516);
    }

    function test_blsBn254Auth() public {
        string memory j = vm.readFile("test/vectors/zether/curve_misc.json");
        uint256 sk = uint256(j.readBytes32(".bn254G2Sk"));
        bytes memory d = abi.encode(j.readBytes(".bn254G2Pk"));
        bytes memory y = ZetherKeys.pub(X, true); // khoá ElGamal ở BLS12-381: khác curve ⇒ được phép
        bytes32 c = reg.popChallenge(y, address(this));
        bytes memory popSig = G1Bn254.mul(G1Bn254.mapToG1(abi.encodePacked("BAMBOO-BLS-BN254-POP-V1", c)), sk);
        ZetherTypes.UA a = reg.register(y, AuthScheme.BLS_BN254, d, abi.encode(ZetherKeys.schnorr(X, c, true), popSig), false);
        bytes memory sig = G1Bn254.mul(G1Bn254.mapToG1(abi.encodePacked("BAMBOO-BLS-BN254-SIG-V1", M)), sk);
        reg.requireAuthorized(a, M, sig, true);
        vm.expectRevert(abi.encodeWithSelector(IR.Unauthorized.selector, a)); // PoP không dùng làm chữ ký được
        reg.requireAuthorized(a, c, popSig, true);
    }

    function test_bls12381Auth() public {
        uint256 sk = 0xB1512381;
        // pk = [sk]G2 = [r − sk](−G2)
        (bool ok, bytes memory pk) = address(0x0e).staticcall(abi.encodePacked(Bls12381.NEG_G2_GENERATOR, G1Bls12381.R - sk));
        assertTrue(ok);
        bytes memory d = abi.encode(pk);
        bytes memory y = ZetherKeys.pub(X, false); // khoá ElGamal bn254: khác curve
        bytes32 c = reg.popChallenge(y, address(this));
        bytes memory popSig = G1Bls12381.mul(HashToCurve.hashToG1(abi.encodePacked(c), "BAMBOO-AUTH-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"), sk);
        ZetherTypes.UA a = reg.register(y, AuthScheme.BLS_12381, d, abi.encode(ZetherKeys.schnorr(X, c, false), popSig), false);
        bytes memory sig = G1Bls12381.mul(HashToCurve.hashToG1(abi.encodePacked(M), "BAMBOO-AUTH-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_"), sk);
        reg.requireAuthorized(a, M, sig, true);
        vm.expectRevert(abi.encodeWithSelector(IR.Unauthorized.selector, a));
        reg.requireAuthorized(a, M, popSig, true);
        vm.expectRevert(abi.encodeWithSelector(IR.Unauthorized.selector, a));
        reg.requireAuthorized(a, M, hex"00", true);
    }

    function test_pqCommitmentAuth() public {
        ZetherTypes.UA a = _reg(X, false, AuthScheme.PQ_COMMITMENT, abi.encode(keccak256("slh-dsa pk")), "", false);
        reg.requireAuthorized(a, M, "", true);
        bytes memory y = ZetherKeys.pub(X, false);
        reg.requireAuthorized(a, M, abi.encode(y, ZetherKeys.schnorr(X, M, false)), false);
    }

    function test_smartAccount1271Auth() public {
        uint256 ownerPk = 0x5AFE;
        Mock1271Wallet w = new Mock1271Wallet(vm.addr(ownerPk));
        bytes memory y = ZetherKeys.pub(X, false);
        bytes32 c = reg.popChallenge(y, address(this));
        ZetherTypes.UA a = reg.register(y, AuthScheme.SMART_ACCOUNT_1271, abi.encode(address(w)),
            abi.encode(ZetherKeys.schnorr(X, c, false), _ecdsa(ownerPk, c)), false);
        reg.requireAuthorized(a, M, _ecdsa(ownerPk, M), true);
        w.setMode(Mock1271Wallet.Mode.WrongMagic);
        vm.expectRevert(abi.encodeWithSelector(IR.Unauthorized.selector, a));
        reg.requireAuthorized(a, M, _ecdsa(ownerPk, M), true);
    }

    /// Đăng ký thuần tuý về khoá: cùng PoP, cùng trạng thái, gas đo cho bảng §15.
    function test_registerGas() public {
        bytes memory y = ZetherKeys.pub(X, false);
        bytes memory pop = _pop(X, false, "");
        uint256 g0 = gasleft();
        reg.register(y, AuthScheme.SELF_SCHNORR, "", pop, true);
        emit log_named_uint("register bn254 SELF_SCHNORR gas", g0 - gasleft());
        y = ZetherKeys.pub(X, true);
        pop = _pop(X, true, "");
        g0 = gasleft();
        reg.register(y, AuthScheme.SELF_SCHNORR, "", pop, false);
        emit log_named_uint("register bls12-381 SELF_SCHNORR gas", g0 - gasleft());
    }
}
