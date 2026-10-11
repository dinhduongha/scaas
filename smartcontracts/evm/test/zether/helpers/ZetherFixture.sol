// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {OpenFactory} from "../../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {AdminLib} from "../../../src/metatx/AdminLib.sol";
import {AuthScheme} from "../../../src/common/AuthScheme.sol";
import {UniversalAccountRegistry} from "../../../src/registry/UniversalAccountRegistry.sol";
import {NoUnderlyingZetherToken} from "../../../src/zether/NoUnderlyingZetherToken.sol";
import {ZetherLayer} from "../../../src/zether/ZetherLayer.sol";
import {ZetherDisclosure} from "../../../src/zether/ZetherDisclosure.sol";
import {ZetherStatements} from "../../../src/zether/ZetherStatements.sol";
import {ITransferDisclosure} from "../../../src/zether/ITransferDisclosure.sol";
import {ZetherTranscript} from "../../../src/zether/ZetherTranscript.sol";
import {IZetherToken} from "../../../src/zether/IZetherToken.sol";
import {IZetherVerifier} from "../../../src/zether/IZetherVerifier.sol";
import {ZetherVerifierBn254, ZetherVerifierBls12381} from "../../../src/zether/ZetherVerifier.sol";
import {ZetherTypes} from "../../../src/zether/ZetherTypes.sol";
import {ZetherProver} from "./ZetherProver.sol";
import {ZetherKeys} from "./ZetherKeys.sol";

bytes32 constant ZUID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;

/// @notice The real stack: `OpenFactory` with the Zether gate on, the registry, a verifier, `ZetherDisclosure`,
///         `ZetherStatements` and `NoUnderlyingZetherToken` clones. The test wallet keeps `x` and the plaintext balances
///         to build witnesses and decrypt; the prover is the test-only `ZetherProver`. Public units come from `mint`
///         (the fixture is the minter); `_public` is overridden where they come from a wrap.
abstract contract ZetherFixture is Test {
    struct User {
        uint256 x;
        bytes y;
        ZetherTypes.UA ua;
        address evm;
    }

    OpenFactory internal factory;
    NoUnderlyingZetherToken internal noneImpl;
    UniversalAccountRegistry internal reg;
    IZetherVerifier internal ver;
    ZetherLayer internal tok;
    ZetherDisclosure internal dis;
    ZetherStatements internal stm;
    ZetherProver internal prover;
    bool internal bls;
    /// @dev CTR-ZTH-42: the sender leaves the auditor out (every `C_aud = O`) on a token with an auditor.
    bool internal audOut;
    /// @dev The sender puts the auditor key in (every `C_aud ≠ O`) even on a token without one.
    bool internal audForce;
    /// @dev The modes of the next token (`ZetherTypes`): disclosure `BUNDLE` (the default); with a key, auditor
    ///      `OPTIONAL` (the opt-out tests), set to `FULL` where a test needs it.
    uint8 internal dMode;
    /// @dev The sender's salt (CTR-ZTH-30) of every transfer the fixture builds; the memo of a commit-reveal transfer
    ///      starts with it, the rest is filler here (the token never reads it, CTR-ZTH-50).
    bytes16 internal salt = bytes16(uint128(0x5A17));
    uint8 internal aMode = uint8(ZetherTypes.AuditorMode.OPTIONAL);
    /// @dev Public units the fixture created per token (`mint` or wrap): `totalSupply + totalShielded·SCALE` stays equal.
    mapping(address => uint256) internal minted;

    address internal registrar = address(0xF00D);
    address internal relayer = address(0xBEEF);
    uint256 internal constant SCALE = 10_000; // a 6-decimal unit kept to 2 decimals (CTR-ZTH-04)
    uint256 internal constant FEE = 2;
    uint256 internal constant X_AUD = 0xA0D17;

    User internal alice;
    User internal bob;
    User internal carol; // receives the inner fee (a relayer)

    function _deploy(bool useBls, bool auditor) internal virtual {
        _stack(useBls);
        tok = _newToken(auditor, "zusd");
        _users();
    }

    function _stack(bool useBls) internal {
        bls = useBls;
        factory = new OpenFactory(registrar, ZUID);
        dis = new ZetherDisclosure();
        stm = new ZetherStatements();
        reg = new UniversalAccountRegistry();
        prover = new ZetherProver();
        ver = useBls ? IZetherVerifier(address(new ZetherVerifierBls12381())) : IZetherVerifier(address(new ZetherVerifierBn254()));
        noneImpl = new NoUnderlyingZetherToken(address(factory), address(0), ZUID, address(reg), dis);
        vm.startPrank(registrar);
        factory.registerImplementation(IOpenFactory.TokenKind.NONE_ZETHER, 1, address(noneImpl));
        factory.setZetherEnabled(true);
        vm.stopPrank();
    }

    function _users() internal {
        alice = _user(0xA11CE, address(0xA1));
        bob = _user(0xB0B, address(0xB2));
        carol = _user(0xCA201, address(0xC3));
    }

    /// @dev `PAYABLE | MINTABLE | BURNABLE`, the fixture is the minter, scale `SCALE`, inner fee `FEE`.
    function _cfg(bool auditor, uint256 maxShielded) internal view returns (IFactoryToken.TokenConfig memory c) {
        c.name = "Zether USD";
        c.symbol = "zUSD";
        c.decimals = 6;
        c.features = (1 << AdminLib.PAYABLE) | (1 << AdminLib.MINTABLE) | (1 << AdminLib.BURNABLE);
        c.roles.minter = address(this);
        c.conf = IFactoryToken.ConfidentialConfig(
            address(ver), auditor ? ZetherKeys.pub(X_AUD, bls) : bytes(""), SCALE, maxShielded, FEE, dMode,
            auditor ? aMode : 0
        );
    }

    function _newToken(bool auditor, bytes32 salt) internal virtual returns (ZetherLayer) {
        return _newToken(auditor, salt, uint256(1) << 40);
    }

    function _newToken(bool auditor, bytes32 salt, uint256 maxShielded) internal virtual returns (ZetherLayer) {
        return ZetherLayer(factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, _cfg(auditor, maxShielded), salt));
    }

    function _user(uint256 x, address evm) internal returns (User memory u) {
        u.x = x;
        u.y = ZetherKeys.pub(x, bls);
        u.evm = evm;
        bytes memory pop = abi.encode(ZetherKeys.schnorr(x, reg.popChallenge(u.y, evm), bls), bytes(""));
        vm.prank(evm);
        u.ua = reg.register(u.y, AuthScheme.SELF_SCHNORR, "", pop, true);
    }

    // ------------------------------------------------------------------ operations

    /// @dev `units` public units to `to`.
    function _public(ZetherLayer t, address to, uint256 units) internal virtual {
        NoUnderlyingZetherToken(address(t)).mint(to, units);
        minted[address(t)] += units;
    }

    /// @dev `amount` shielded units into `u`'s pending, paid from the fixture's public balance (CTR-ZTH-35).
    function _fund(ZetherLayer t, User memory u, uint256 amount) internal {
        _public(t, address(this), amount * SCALE);
        t.zetherShield(u.y, amount);
    }

    struct Tx {
        bytes payload;
        bytes proof;
        uint256 s;
    }

    /// @dev Payload and proof of `from → to`, value `v`, from the acc balance `b`; `binding` 0 = a direct call.
    function _proveTransfer(ZetherLayer t, User memory from, User memory to, uint256 v, uint256 b, ZetherTypes.UA ben, bytes32 binding)
        internal view returns (Tx memory r)
    {
        IZetherToken.AccountState memory st = t.accountState(from.ua);
        r.s = uint256(keccak256(abi.encode(from.x, st.sendCounter, v, address(t)))) % ver.groupOrder();
        r.payload = _payload(t, from, to, v, r.s, st);
        ZetherProver.TransferWitness memory w = _witness(from.x, v, r.s, b - v - (ZetherTypes.UA.unwrap(ben) == 0 ? 0 : t.confidentialFee()));
        r.proof = _proveT(stm.transferStatementSingle(address(t), r.payload, ben, binding), w);
    }

    function _witness(uint256 x, uint256 v, uint256 s, uint256 bPrime) internal pure returns (ZetherProver.TransferWitness memory) {
        return ZetherProver.TransferWitness(x, v, s, bPrime, 0x1234 + v, 0x5678 + bPrime, keccak256(abi.encode(s)));
    }

    function _proveT(bytes memory statement, ZetherProver.TransferWitness memory w) internal view returns (bytes memory) {
        return prover.proveTransfer(ver, statement, w);
    }

    function _payload(ZetherLayer t, User memory from, User memory to, uint256 v, uint256 s, IZetherToken.AccountState memory st)
        internal view returns (bytes memory)
    {
        return bytes.concat(
            abi.encode(uint256(st.accSeq), uint256(st.sendCounter)), salt, from.y, to.y, _cts(t, from.y, to.y, v, s)
        );
    }

    function _cts(ZetherLayer t, bytes memory yf, bytes memory yt, uint256 v, uint256 s) internal view returns (bytes memory) {
        bytes memory aud = _aud(t);
        (bytes memory cOut, bytes memory dOut, bytes memory cDeb, bytes memory cAud) = prover.ciphertexts(ver, yf, yt, aud, v, s);
        return bytes.concat(cOut, dOut, cDeb, cAud);
    }

    /// @dev A memo of `m` legs (CTR-ZTH-50): the salt, then `1 + 40·m` filler bytes.
    function _memo(uint256 m) internal view returns (bytes memory memo) {
        memo = bytes.concat(salt, new bytes(1 + 40 * m));
        for (uint256 i = 16; i < memo.length; ++i) memo[i] = bytes1(uint8(i));
    }

    /// @dev The `Y_a` the sender encrypts to: the token's key, `O` without one or when left out, the test key if forced.
    function _aud(ZetherLayer t) internal view returns (bytes memory aud) {
        aud = audForce ? ZetherKeys.pub(X_AUD, bls) : t.auditorKey();
        if (aud.length == 0 || audOut) aud = ver.identity();
    }

    /// @dev `from → to[j]`, value `vs[j]` (decoys 0), one shared `s`, from the acc balance `b`.
    function _proveMulti(
        ZetherLayer t,
        User memory from,
        User[] memory to,
        uint256[] memory vs,
        uint256 b,
        ZetherTypes.UA ben,
        ZetherTypes.TransferMode mode
    ) internal view returns (Tx memory r) {
        return _proveMulti(t, from, to, vs, b, ben, mode, bytes32(0));
    }

    function _proveMulti(
        ZetherLayer t,
        User memory from,
        User[] memory to,
        uint256[] memory vs,
        uint256 b,
        ZetherTypes.UA ben,
        ZetherTypes.TransferMode mode,
        bytes32 binding
    ) internal view returns (Tx memory r) {
        IZetherToken.AccountState memory st = t.accountState(from.ua);
        r.s = uint256(keccak256(abi.encode(from.x, st.sendCounter, vs, address(t), "multi"))) % ver.groupOrder();
        r.payload = _multiPayload(t, from, to, vs, r.s, st);
        if (mode == ZetherTypes.TransferMode.HASH) r.payload = bytes.concat(r.payload, _memo(to.length));
        if (ZetherTypes.UA.unwrap(ben) != 0) b -= t.confidentialFee();
        r.proof = prover.proveTransferMulti(
            ver, stm.transferStatement(address(t), r.payload, ben, mode, binding), _multiWitness(from.x, r.s, vs, b)
        );
    }

    /// @dev `bAfterFee` = the balance less the inner fee; `b' = bAfterFee − Σv`.
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

    /// @dev `be32(accSeq) ‖ be32(sendCounter) ‖ be32(M) ‖ Y_f ‖ D_out ‖ C_deb ‖ (Y_tj ‖ C_out_j ‖ C_aud_j)_j` (`salt(16)` after `sendCounter`); `_proveMulti` appends the memo on commit-reveal.
    function _multiPayload(
        ZetherLayer t,
        User memory from,
        User[] memory to,
        uint256[] memory vs,
        uint256 s,
        IZetherToken.AccountState memory st
    ) internal view returns (bytes memory payload) {
        bytes memory aud = _aud(t);
        bytes memory legs;
        uint256 total;
        for (uint256 j; j < to.length; ++j) {
            (bytes memory cOut,,, bytes memory cAud) = prover.ciphertexts(ver, from.y, to[j].y, aud, vs[j], s);
            legs = bytes.concat(legs, to[j].y, cOut, cAud);
            total += vs[j];
        }
        (,bytes memory dOut, bytes memory cDeb,) = prover.ciphertexts(ver, from.y, from.y, aud, total, s);
        payload = bytes.concat(
            abi.encode(uint256(st.accSeq), uint256(st.sendCounter)), salt, abi.encode(to.length), from.y, dOut, cDeb, legs
        );
    }

    /// @dev Payload and proof of an unshield of `amount` to `recipient` from the acc balance `b`.
    function _proveUnshield(ZetherLayer t, User memory from, uint256 amount, uint256 b, address recipient, ZetherTypes.UA ben, bytes32 binding)
        internal view returns (bytes memory payload, bytes memory proof)
    {
        payload = _unshieldPayload(t, from);
        bytes memory statement = stm.unshieldStatement(address(t), payload, amount, recipient, ben, binding);
        proof = _proveU(from, statement, amount, b, ben, t);
    }

    function _proveU(User memory from, bytes memory statement, uint256 amount, uint256 b, ZetherTypes.UA ben, ZetherLayer t)
        internal view returns (bytes memory)
    {
        b = b - amount - (ZetherTypes.UA.unwrap(ben) == 0 ? 0 : t.confidentialFee()); // from here: b'
        return prover.proveBurn(ver, statement, ZetherProver.BurnWitness(from.x, b, 0x9abc + b, keccak256(abi.encode(b, amount))));
    }

    function _unshieldPayload(ZetherLayer t, User memory from) internal view returns (bytes memory) {
        IZetherToken.AccountState memory st = t.accountState(from.ua);
        return bytes.concat(abi.encode(uint256(st.accSeq), uint256(st.sendCounter)), from.y);
    }

    /// @dev The calldata of the Zether-layer op `sel` on `tok` for an envelope with binding `b`: shield 3 to bob, else
    ///      10 from alice's acc balance `bal` (to bob, or unshielded to 0xB0C). Used to relay every listed selector once.
    function _zetherOpCall(bytes4 sel, uint256 bal, bytes32 b) internal view returns (bytes memory) {
        if (sel == ZetherLayer.zetherShield.selector) return abi.encodeCall(ZetherLayer.zetherShield, (bob.y, 3));
        if (sel == ZetherLayer.zetherUnshield.selector) {
            (bytes memory pl, bytes memory pr) = _proveUnshield(tok, alice, 10, bal, address(0xB0C), _none(), b);
            return abi.encodeCall(ZetherLayer.zetherUnshield, (pl, pr, bytes(""), _none(), address(0xB0C), 10));
        }
        if (sel == ZetherLayer.zetherTransferSingle.selector) {
            Tx memory t = _proveTransfer(tok, alice, bob, 10, bal, _none(), b);
            return abi.encodeCall(ZetherLayer.zetherTransferSingle, (t.payload, t.proof, bytes(""), _none()));
        }
        ZetherTypes.TransferMode mode = sel == ZetherLayer.zetherTransferCompact.selector ? ZetherTypes.TransferMode.HASH
            : sel == ZetherLayer.zetherTransfer.selector ? _defaultForm(tok) : ZetherTypes.TransferMode.NONE;
        require(mode != ZetherTypes.TransferMode.NONE || sel == ZetherLayer.zetherTransferNoBundle.selector, "not a Zether op");
        return _multiCall(sel, mode, bal, b);
    }

    /// @dev The stored form of `zetherTransfer` on `t` (CTR-ZTH-38): BUNDLE, or HASH on a `COMMIT` token.
    function _defaultForm(ZetherLayer t) internal view returns (ZetherTypes.TransferMode) {
        return t.disclosureMode() == ZetherTypes.DisclosureMode.COMPACT ? ZetherTypes.TransferMode.HASH
            : ZetherTypes.TransferMode.BUNDLE;
    }

    function _multiCall(bytes4 sel, ZetherTypes.TransferMode mode, uint256 bal, bytes32 b) internal view returns (bytes memory) {
        User[] memory to = new User[](1);
        to[0] = bob;
        uint256[] memory vs = new uint256[](1);
        vs[0] = 10;
        Tx memory u = _proveMulti(tok, alice, to, vs, bal, _none(), mode, b);
        return abi.encodeWithSelector(sel, u.payload, u.proof, bytes(""), _none());
    }

    function _direct(ZetherLayer t, Tx memory r, ZetherTypes.UA ben) internal returns (bytes32) {
        return t.zetherTransferSingle(r.payload, r.proof, "", ben);
    }

    // ------------------------------------------------------------------ disclosure (ZetherDisclosure)

    /// @dev `verifyTransferAmount` through `ZetherDisclosure`: one outside call, so `vm.expectRevert` catches it.
    function _vta(
        ZetherLayer t,
        bytes32 ref,
        uint256 j,
        uint256 amount,
        ITransferDisclosure.OpeningKind kind,
        bytes memory opening,
        bytes memory bundles
    ) internal view returns (bool) {
        return dis.verifyTransferAmount(address(t), ref, j, amount, kind, opening, bundles);
    }

    /// @dev Chaum-Pedersen `log_G(K) == log_B(M − [amount]G)` with key `x` on base `base` (`D_out` for
    ///      RECEIVER_X/AUDITOR, `Y_tj` for SENDER_CP), leg `j` of `ref`; the challenge carries `chainUid` (CTR-ZTH-36).
    function _cpOpening(
        ZetherLayer t,
        uint256 x,
        bytes32 ref,
        uint256 j,
        uint256 amount,
        ITransferDisclosure.OpeningKind kind,
        bytes memory base
    ) internal view returns (bytes memory) {
        uint256 r = ver.groupOrder();
        uint256 k = uint256(keccak256(abi.encode("cp", x, ref, j, amount, kind))) % r;
        bytes memory a1 = ver.g1MulBase(k);
        bytes memory a2 = ver.g1Mul(base, k);
        uint256 e = ZetherTranscript.hashToScalar(keccak256(bytes.concat(
            abi.encodePacked("SCAAS-ZETHER-DISCLOSE-V1", block.chainid, t.chainUid(), address(t)),
            abi.encodePacked(ref, j, amount, uint8(kind), a1, a2)
        )), r);
        return abi.encode(a1, a2, addmod(k, mulmod(e, x, r), r));
    }

    function _none() internal pure returns (ZetherTypes.UA) {
        return ZetherTypes.UA.wrap(bytes32(0));
    }

    /// @dev `entryRef` (CTR-ZTH-36) of `from`'s debit number `counter`.
    function _ref(ZetherLayer t, User memory from, uint256 counter) internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("SCAAS-ZETHER-ENTRY-V1"), block.chainid, t.chainUid(), address(t), from.ua, counter
        ));
    }

    // ------------------------------------------------------------------ test-side decryption

    /// @dev `[b]G = C − [x]D`, `b` found in `[0, max]` by a linear scan (small test numbers).
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

    /// @dev check_balance: `[b]G == C − [x]D`, one point comparison, any balance.
    function _holds(ZetherLayer t, User memory u, uint256 b, bool acc) internal view returns (bool) {
        IZetherToken.AccountState memory s = t.accountState(u.ua);
        (bytes memory c, bytes memory d) = acc ? (s.accC, s.accD) : (s.pendingC, s.pendingD);
        return keccak256(ver.g1Sub(c, ver.g1Mul(d, u.x))) == keccak256(ver.g1MulBase(b));
    }

    function _balances(ZetherLayer t, User memory u, uint256 max) internal view returns (uint256 acc, uint256 pend) {
        IZetherToken.AccountState memory s = t.accountState(u.ua);
        acc = _decrypt(s.accC, s.accD, u.x, max);
        pend = _decrypt(s.pendingC, s.pendingD, u.x, max);
    }

    /// @dev Conservation: Σ plaintext balances (acc + pending, each decrypted with its owner's key) == totalShielded,
    ///      and the public units the fixture created == `totalSupply + totalShielded·SCALE` (shield burns them, unshield
    ///      mints them back).
    function _assertConservation(ZetherLayer t, uint256 max) internal view virtual {
        User[3] memory us = [alice, bob, carol];
        uint256 sum;
        for (uint256 i; i < 3; ++i) {
            (uint256 a, uint256 p) = _balances(t, us[i], max);
            sum += a + p;
        }
        assertEq(sum, t.totalShielded(), "sum of plaintext balances == totalShielded");
        assertEq(t.totalSupply() + t.totalShielded() * SCALE, minted[address(t)], "public + shielded x scale == created");
    }
}
