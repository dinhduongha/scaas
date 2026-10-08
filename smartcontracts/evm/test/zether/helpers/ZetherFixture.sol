// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {OpenFactory} from "../../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../../src/common/IOpenFactory.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {AuthScheme} from "../../../src/common/AuthScheme.sol";
import {UniversalAccountRegistry} from "../../../src/registry/UniversalAccountRegistry.sol";
import {ZetherToken} from "../../../src/zether/ZetherToken.sol";
import {IZetherToken} from "../../../src/zether/IZetherToken.sol";
import {IZetherVerifier} from "../../../src/zether/IZetherVerifier.sol";
import {ZetherVerifierBn254, ZetherVerifierBls12381} from "../../../src/zether/ZetherVerifier.sol";
import {ZetherTypes} from "../../../src/zether/ZetherTypes.sol";
import {ZetherProver} from "./ZetherProver.sol";
import {ZetherKeys} from "./ZetherKeys.sol";
import {MockERC20} from "../../helpers/Mocks.sol";

/// @notice Dựng factory + registry + verifier + token thật; ví phía test giữ `x` và số dư rõ để dựng
///         witness và giải mã kiểm chứng. Prover là `ZetherProver` (chỉ test).
abstract contract ZetherFixture is Test {
    struct User {
        uint256 x;
        bytes y;
        ZetherTypes.UA ua;
        address evm;
    }

    OpenFactory internal factory;
    ZetherToken internal impl;
    UniversalAccountRegistry internal reg;
    MockERC20 internal usd;
    IZetherVerifier internal ver;
    ZetherToken internal tok;
    ZetherProver internal prover;
    bool internal bls;

    address internal registrar = address(0xF00D);
    address internal relayer = address(0xBEEF);
    uint256 internal constant SCALE = 10_000; // USD 6 decimals, giữ 2 chữ số (RS2-3)
    uint256 internal constant FEE = 2;
    uint256 internal constant X_AUD = 0xA0D17;

    User internal alice;
    User internal bob;
    User internal carol; // nhận phí tầng trong (relayer)

    function _deploy(bool useBls, bool auditor) internal {
        bls = useBls;
        factory = new OpenFactory(registrar);
        impl = new ZetherToken(address(factory));
        reg = new UniversalAccountRegistry();
        usd = new MockERC20("USD", "USD", 6);
        prover = new ZetherProver();
        ver = useBls ? IZetherVerifier(address(new ZetherVerifierBls12381())) : IZetherVerifier(address(new ZetherVerifierBn254()));
        vm.startPrank(registrar);
        factory.registerImplementation(IOpenFactory.TokenKind.ZETHER, 1, address(impl));
        factory.setZetherEnabled(true);
        vm.stopPrank();
        tok = _newToken(auditor, "zusd");
        alice = _user(0xA11CE, address(0xA1));
        bob = _user(0xB0B, address(0xB2));
        carol = _user(0xCA201, address(0xC3));
    }

    function _newToken(bool auditor, bytes32 salt) internal returns (ZetherToken) {
        return _newToken(auditor, salt, uint256(1) << 40);
    }

    function _newToken(bool auditor, bytes32 salt, uint256 maxShielded) internal returns (ZetherToken) {
        bytes memory aud = auditor ? ZetherKeys.pub(X_AUD, bls) : bytes("");
        bytes memory init = abi.encode("Zether USD", "zUSD", address(reg), SCALE, maxShielded, FEE, aud);
        return ZetherToken(factory.createZetherToken(1, address(usd), address(ver), init, salt));
    }

    function _user(uint256 x, address evm) internal returns (User memory u) {
        u.x = x;
        u.y = ZetherKeys.pub(x, bls);
        u.evm = evm;
        bytes memory pop = abi.encode(ZetherKeys.schnorr(x, reg.popChallenge(u.y, evm), bls), bytes(""));
        vm.prank(evm);
        u.ua = reg.register(u.y, AuthScheme.SELF_SCHNORR, "", pop, true);
    }

    // ------------------------------------------------------------------ thao tác

    function _fund(ZetherToken t, User memory u, uint256 amount) internal {
        usd.mint(address(this), amount * SCALE);
        usd.approve(address(t), amount * SCALE); // spender = token contract (R26 ở tầng token của ta)
        t.fund(u.y, amount);
    }

    struct Tx {
        bytes payload;
        bytes proof;
        uint256 s;
    }

    /// @dev Dựng payload + proof cho transfer `from → to` giá trị `v`, số dư acc hiện tại `b`.
    function _proveTransfer(ZetherToken t, User memory from, User memory to, uint256 v, uint256 b, ZetherTypes.UA ben, bytes32 binding)
        internal view returns (Tx memory r)
    {
        IZetherToken.AccountState memory st = t.accountState(from.ua);
        r.s = uint256(keccak256(abi.encode(from.x, st.sendCounter, v, address(t)))) % ver.groupOrder();
        r.payload = _payload(t, from, to, v, r.s, st);
        ZetherProver.TransferWitness memory w = _witness(from.x, v, r.s, b - v - (ZetherTypes.UA.unwrap(ben) == 0 ? 0 : t.confidentialFee()));
        r.proof = _proveT(t.transferStatementSingle(r.payload, ben, binding), w);
    }

    function _witness(uint256 x, uint256 v, uint256 s, uint256 bPrime) internal pure returns (ZetherProver.TransferWitness memory) {
        return ZetherProver.TransferWitness(x, v, s, bPrime, 0x1234 + v, 0x5678 + bPrime, keccak256(abi.encode(s)));
    }

    function _proveT(bytes memory statement, ZetherProver.TransferWitness memory w) internal view returns (bytes memory) {
        return prover.proveTransfer(ver, statement, w);
    }

    function _payload(ZetherToken t, User memory from, User memory to, uint256 v, uint256 s, IZetherToken.AccountState memory st)
        internal view returns (bytes memory)
    {
        return bytes.concat(abi.encode(uint256(st.accSeq), uint256(st.sendCounter)), from.y, to.y, _cts(t, from.y, to.y, v, s));
    }

    function _cts(ZetherToken t, bytes memory yf, bytes memory yt, uint256 v, uint256 s) internal view returns (bytes memory) {
        bytes memory aud = t.auditorKey();
        if (aud.length == 0) aud = ver.identity();
        (bytes memory cOut, bytes memory dOut, bytes memory cDeb, bytes memory cAud) = prover.ciphertexts(ver, yf, yt, aud, v, s);
        return bytes.concat(cOut, dOut, cDeb, cAud);
    }

    /// @dev Transfer `from → to[j]` giá trị `vs[j]` (mồi: 0), một `s` chung, số dư acc hiện tại `b`.
    function _proveMulti(
        ZetherToken t,
        User memory from,
        User[] memory to,
        uint256[] memory vs,
        uint256 b,
        ZetherTypes.UA ben,
        ZetherTypes.TransferMode mode
    ) internal view returns (Tx memory r) {
        IZetherToken.AccountState memory st = t.accountState(from.ua);
        r.s = uint256(keccak256(abi.encode(from.x, st.sendCounter, vs, address(t), "multi"))) % ver.groupOrder();
        r.payload = _multiPayload(t, from, to, vs, r.s, st);
        uint256 fee = ZetherTypes.UA.unwrap(ben) == 0 ? 0 : t.confidentialFee();
        bytes memory statement = t.transferStatement(r.payload, ben, mode);
        r.proof = prover.proveTransferMulti(ver, statement, _multiWitness(from.x, r.s, vs, b - fee));
    }

    /// @dev `bAfterFee` = số dư trừ phí tầng trong; `b' = bAfterFee − Σv`.
    function _multiWitness(uint256 x, uint256 s, uint256[] memory vs, uint256 bAfterFee)
        internal pure returns (ZetherProver.MultiWitness memory w)
    {
        uint256[] memory gv = new uint256[](vs.length);
        uint256 bPrime = bAfterFee;
        for (uint256 j; j < vs.length; ++j) {
            gv[j] = 0x1234 + 7 * j + vs[j];
            bPrime -= vs[j];
        }
        w = ZetherProver.MultiWitness(x, s, vs, bPrime, gv, 0x5678 + bPrime, keccak256(abi.encode(s)));
    }

    /// @dev `be32(accSeq) ‖ be32(sendCounter) ‖ be32(M) ‖ Y_f ‖ D_out ‖ C_deb ‖ (Y_tj ‖ C_out_j ‖ C_aud_j)_j`.
    function _multiPayload(
        ZetherToken t,
        User memory from,
        User[] memory to,
        uint256[] memory vs,
        uint256 s,
        IZetherToken.AccountState memory st
    ) internal view returns (bytes memory payload) {
        bytes memory aud = t.auditorKey();
        if (aud.length == 0) aud = ver.identity();
        bytes memory legs;
        uint256 total;
        for (uint256 j; j < to.length; ++j) {
            (bytes memory cOut,,, bytes memory cAud) = prover.ciphertexts(ver, from.y, to[j].y, aud, vs[j], s);
            legs = bytes.concat(legs, to[j].y, cOut, cAud);
            total += vs[j];
        }
        (,bytes memory dOut, bytes memory cDeb,) = prover.ciphertexts(ver, from.y, from.y, aud, total, s);
        payload = bytes.concat(
            abi.encode(uint256(st.accSeq), uint256(st.sendCounter), to.length), from.y, dOut, cDeb, legs
        );
    }

    function _proveBurn(ZetherToken t, User memory from, uint256 amount, uint256 b, address recipient, ZetherTypes.UA ben, bytes32 binding)
        internal view returns (bytes memory payload, bytes memory proof)
    {
        payload = _burnPayload(t, from);
        bytes memory statement = t.burnStatement(payload, amount, recipient, ben, binding);
        b = b - amount - (ZetherTypes.UA.unwrap(ben) == 0 ? 0 : t.confidentialFee()); // từ đây: b'
        proof = prover.proveBurn(ver, statement, ZetherProver.BurnWitness(from.x, b, 0x9abc + b, keccak256(abi.encode(b, amount))));
    }

    function _burnPayload(ZetherToken t, User memory from) internal view returns (bytes memory) {
        IZetherToken.AccountState memory st = t.accountState(from.ua);
        return bytes.concat(abi.encode(uint256(st.accSeq), uint256(st.sendCounter)), from.y);
    }

    function _direct(ZetherToken t, Tx memory r, ZetherTypes.UA ben) internal returns (bytes32) {
        return t.transferConfidentialSingle(r.payload, r.proof, "", ben);
    }

    function _none() internal pure returns (ZetherTypes.UA) {
        return ZetherTypes.UA.wrap(bytes32(0));
    }

    // ------------------------------------------------------------------ giải mã phía test

    /// @dev `[b]G = C − [x]D`, tìm `b` trong `[0, max]` bằng quét tuyến tính (số nhỏ trong test).
    function _decrypt(bytes memory c, bytes memory d, uint256 x, uint256 max) internal view returns (uint256) {
        bytes memory m = ver.g1Sub(c, ver.g1Mul(d, x));
        bytes memory g = ver.g1MulBase(1);
        bytes memory acc = ver.identity();
        for (uint256 b; b <= max; ++b) {
            if (keccak256(acc) == keccak256(m)) return b;
            acc = ver.g1Add(acc, g);
        }
        revert("decrypt: out of range");
    }

    /// @dev check_balance (limits §5): `[b]G == C − [x]D` — một phép so điểm, chạy với số dư bất kỳ
    ///      (quét tuyến tính `_decrypt` chỉ dùng được cho số nhỏ).
    function _holds(ZetherToken t, User memory u, uint256 b, bool acc) internal view returns (bool) {
        IZetherToken.AccountState memory s = t.accountState(u.ua);
        (bytes memory c, bytes memory d) = acc ? (s.accC, s.accD) : (s.pendingC, s.pendingD);
        return keccak256(ver.g1Sub(c, ver.g1Mul(d, u.x))) == keccak256(ver.g1MulBase(b));
    }

    function _balances(ZetherToken t, User memory u, uint256 max) internal view returns (uint256 acc, uint256 pend) {
        IZetherToken.AccountState memory s = t.accountState(u.ua);
        acc = _decrypt(s.accC, s.accD, u.x, max);
        pend = _decrypt(s.pendingC, s.pendingD, u.x, max);
    }

    /// @dev Bảo toàn: tổng số dư rõ (acc + pending, giải mã bằng khoá từng người) == totalShielded, và
    ///      underlying khoá trong token == totalShielded·scale + cung công khai.
    function _assertConservation(ZetherToken t, uint256 max) internal view {
        User[3] memory us = [alice, bob, carol];
        uint256 sum;
        for (uint256 i; i < 3; ++i) {
            (uint256 a, uint256 p) = _balances(t, us[i], max);
            sum += a + p;
        }
        assertEq(sum, t.totalShielded(), "sum of plaintext balances == totalShielded");
        assertEq(usd.balanceOf(address(t)), t.totalShielded() * SCALE + t.totalSupply(), "escrow == owed");
    }

    // ------------------------------------------------------------------ meta-tx

    function _mt(address from, bytes memory data, uint256 batch, uint32 mode, uint256 fee)
        internal view returns (MetaTxLib.MetaTransaction memory m)
    {
        m = MetaTxLib.MetaTransaction({
            from: from, to: address(0), value: 0, data: data, batch: batch, nonce: 0,
            validUntil: block.timestamp + 300, mode: mode, relayer: relayer, fee: fee, feeRecipient: address(0)
        });
    }

    function _sign(uint256 pk, ZetherToken t, MetaTxLib.MetaTransaction memory m) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, t.metaTxDigest(m));
        return abi.encodePacked(r, s, v);
    }
}
