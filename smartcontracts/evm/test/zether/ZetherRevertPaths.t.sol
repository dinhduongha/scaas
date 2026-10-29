// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {ZetherFixture, ZUID} from "./helpers/ZetherFixture.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {NoUnderlyingZetherToken} from "../../src/zether/NoUnderlyingZetherToken.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {ITransferDisclosure} from "../../src/zether/ITransferDisclosure.sol";
import {ZetherSafety} from "../../src/zether/ZetherSafety.sol";
import {G1Bls12381} from "../../src/zether/ZetherCurves.sol";
import {
    ZetherVerifierBase,
    ZetherInnerProductVerifierBls12381,
    ZetherTransferVerifierBls12381,
    ZetherBurnVerifierBls12381
} from "../../src/zether/ZetherVerifier.sol";
import {IZetherVerifier, IZetherBurnVerifier, IZetherInnerProductVerifier} from "../../src/zether/IZetherVerifier.sol";
import {UnderlyingZetherToken} from "../../src/zether/UnderlyingZetherToken.sol";
import {Catalogue, pinned} from "../helpers/Catalogue.sol";
import {ZetherDisclosure} from "../../src/zether/ZetherDisclosure.sol";
import {ZetherVerifiers} from "./helpers/ZetherVerifiers.sol";
import {Puller} from "../helpers/WalletMocks.sol";
import {ZetherKeys} from "./helpers/ZetherKeys.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";

/// `NONE_ZETHER` with one guarded call-out to the caller (`reenter`): a frame that holds the guard.
contract GuardHarness is NoUnderlyingZetherToken {
    constructor(Env memory env) NoUnderlyingZetherToken(1, env, "") {}

    function holdGuard(bytes calldata data) external nonReentrant {
        ZetherRevertPathsTest(msg.sender).reenter(data);
    }
}

/// A fake verifier (review W-B): every proof accepted, the group operations forwarded to an honest verifier, so a token
/// on it would work until the first forged unshield. It must never be attachable (CTR-ZTH-20).
contract AcceptAllVerifier {
    address internal immutable REAL;

    constructor(address real) { REAL = real; }

    function verifyTransfer(bytes calldata, bytes calldata) external pure returns (bool) { return true; }
    function verifyTransferMulti(bytes calldata, bytes calldata) external pure returns (bool) { return true; }
    function verifyBurn(bytes calldata, bytes calldata) external pure returns (bool) { return true; }

    fallback(bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = REAL.staticcall(data);
        require(ok);
        return ret;
    }
}

/// An honest verifier that says it does not run on this chain (its precompiles absent): `isSupportedOnThisChain()` false,
/// everything else forwarded.
contract UnsupportedHereVerifier {
    address internal immutable REAL;

    constructor(address real) { REAL = real; }

    function isSupportedOnThisChain() external pure returns (bool) { return false; }

    fallback(bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = REAL.staticcall(data);
        require(ok);
        return ret;
    }
}

/// A burn verifier of another proof system on the same inner-product verifier (the bn254 one before UA-6, CTR-ZTH-32).
contract OtherSystemBurnVerifier {
    address public immutable innerProduct;

    constructor(address ip) { innerProduct = ip; }

    function proofSystemId() external pure returns (bytes32) { return keccak256("another proof system"); }
}

/// The same, with a `curveName()` that reverts: the typed error survives with an empty name (review 5g-Z2 M-1).
contract UnsupportedNamelessVerifier is UnsupportedHereVerifier {
    constructor(address real) UnsupportedHereVerifier(real) {}

    function curveName() external pure returns (string memory) { revert(); }
}

/// @notice The revert paths of the confidential layer on `NONE_ZETHER` (the relaying ones are in `ZetherRelay.t`, the
///         underlying ones in `ZetherUnderlying.t`): shield, transfer and unshield shapes, the confidential config at
///         creation, the approve rule on the public side (CTR-TOK-01), the spending authority beside the proof.
contract ZetherRevertPathsTest is ZetherFixture {
    function setUp() public {
        _deploy(false);
    }

    function test_shieldRevertPaths() public {
        bytes memory stranger = ZetherKeys.pub(0x5757, true);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AccountNotRegistered.selector, ZetherTypes.toUA(stranger)));
        tok.mtxShield(ZetherTypes.UA.unwrap(ZetherTypes.toUA(stranger)), 1);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AmountOutOfRange.selector, 0, uint256(1) << 40));
        tok.mtxShield(ZetherTypes.UA.unwrap(alice.ua), 0);
        uint256 over = (uint256(1) << 40) + 1;
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AmountOutOfRange.selector, over, uint256(1) << 40));
        tok.mtxShield(ZetherTypes.UA.unwrap(alice.ua), over);
        // a bn254 key (the legacy curve, UA-6 U10): no registry holds it, so it is never registered here
        bytes memory bnKey = ZetherKeys.pub(0x7777, false);
        ZetherTypes.UA bnUa = ZetherTypes.toUA(bnKey);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, uint16(0x0140)));
        reg.register(0x0140, bnKey, IUARegistry.UAAttrs("", 0, 0, ""), "", "");
        assertFalse(tok.registered(bnUa));
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AccountNotRegistered.selector, bnUa));
        tok.mtxShield(ZetherTypes.UA.unwrap(ZetherTypes.toUA(bnKey)), 1);
    }

    function _aliceTx() internal returns (Tx memory) {
        _fund(tok, alice, 100);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        return _proveTransfer(tok, alice, bob, 10, 100, _none(), 0);
    }

    function _call(bytes memory payload, bytes memory proof, ZetherTypes.UA ben, bytes memory err) internal {
        vm.expectRevert(err);
        tok.mtxConfidentialTransferSingle(payload, proof, "", ZetherTypes.UA.unwrap(ben), "");
    }

    function test_transferBadPayloadLength() public {
        Tx memory t = _aliceTx();
        bytes memory longPl = bytes.concat(t.payload, hex"00");
        _call(longPl, t.proof, _none(), abi.encodeWithSelector(IZetherToken.BadPayload.selector, longPl.length));
    }

    function test_transferToSelfRejected() public {
        Tx memory t = _aliceTx();
        for (uint256 i; i < 128; ++i) t.payload[240 + i] = t.payload[112 + i]; // Y_to := Y_from
        _call(t.payload, t.proof, _none(), abi.encodeWithSelector(IZetherToken.SelfTransfer.selector));
    }

    function test_transferToUnregisteredRejected() public {
        Tx memory t = _aliceTx();
        bytes memory gy = ZetherKeys.pub(0x6057, true);
        for (uint256 i; i < 128; ++i) t.payload[240 + i] = gy[i];
        _call(t.payload, t.proof, _none(),
            abi.encodeWithSelector(IZetherToken.AccountNotRegistered.selector, ZetherTypes.toUA(gy)));
    }

    /// The fee is no back door to register an account: the beneficiary must be registered.
    function test_unregisteredBeneficiaryRejected() public {
        Tx memory t = _aliceTx();
        ZetherTypes.UA ghost = ZetherTypes.toUA(ZetherKeys.pub(0x6057, true));
        _call(t.payload, t.proof, ghost, abi.encodeWithSelector(IZetherToken.AccountNotRegistered.selector, ghost));
    }

    /// The beneficiary is in the statement: a valid fee-bearing proof made for carol is refused with another registered
    /// beneficiary, and passes with carol (review T3 m2).
    function test_otherBeneficiaryRejected() public {
        _fund(tok, alice, 100);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        Tx memory t = _proveTransfer(tok, alice, bob, 10, 100, carol.ua, 0);
        _call(t.payload, t.proof, bob.ua, abi.encodeWithSelector(IZetherToken.ProofRejected.selector));
        _direct(tok, t, carol.ua);
        assertEq(tok.balanceOfUA(ZetherTypes.UA.unwrap(carol.ua)), FEE * SCALE, "beneficiary public balance");
        assertEq(tok.accountState(carol.ua).pendingSeq, 0, "no pend_ben credit (D19)");
    }

    /// Every confidential entry point is `nonReentrant` (review T3 m1). The NONE kind makes no outside call inside a
    /// guarded frame, so a harness (this implementation plus one guarded call-out) is etched over the implementation:
    /// a call back into any entry point from that frame hits the guard before its body.
    function test_everyEntryPointNonReentrant() public {
        vm.etch(address(noneImpl), address(new GuardHarness(_zenv())).code);
        ZetherTypes.UA n = _none();
        bytes[9] memory calls = [
            abi.encodeCall(ZetherLayer.mtxShield, (ZetherTypes.UA.unwrap(alice.ua), 1)),
            abi.encodeCall(ZetherLayer.mtxConfidentialTransfer, ("", "", bytes(""), ZetherTypes.UA.unwrap(n), bytes(""))),
            abi.encodeCall(ZetherLayer.mtxConfidentialTransferCompact, ("", "", bytes(""), ZetherTypes.UA.unwrap(n), bytes(""))),
            abi.encodeCall(ZetherLayer.mtxConfidentialTransferSingle, ("", "", bytes(""), ZetherTypes.UA.unwrap(n), bytes(""))),
            abi.encodeCall(ZetherLayer.mtxUnshield, ("", "", bytes(""), ZetherTypes.UA.unwrap(n), bytes(""), 1, bytes32(uint256(uint160(address(0xD)))))),
            abi.encodeCall(ZetherLayer.mtxRollOver, (ZetherTypes.UA.unwrap(alice.ua), 1)),
            abi.encodeCall(ZetherLayer.mtxRollOverBatch, (new ZetherTypes.UA[](0))),
            abi.encodeCall(ZetherLayer.mtxRollOverSigned, (alice.ua, 1, 1, "")),
            abi.encodeCall(ZetherLayer.mtxSetRollOverMode, (alice.ua, ZetherTypes.RollOverMode.PUBLIC, 1, ""))
        ];
        for (uint256 i; i < calls.length; ++i) {
            vm.expectRevert(IMetaTx.Reentrancy.selector);
            GuardHarness(address(tok)).holdGuard(calls[i]);
        }
    }

    /// The harness's call-out: back into the token.
    function reenter(bytes calldata data) external {
        (bool ok, bytes memory ret) = address(tok).call(data);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
    }

    /// Amount and recipient are in the statement; checks before any precompile.
    function test_unshieldRevertPaths() public {
        _fund(tok, alice, 100);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        (bytes memory pl, bytes memory pr) = _proveUnshield(tok, alice, 10, 100, address(0xD), _none(), 0);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AmountOutOfRange.selector, 0, uint256(1) << 40));
        tok.mtxUnshield(pl, pr, "", bytes32(0), "", 0, bytes32(uint256(uint160(address(0xD)))));
        uint256 over = (uint256(1) << 40) + 1;
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AmountOutOfRange.selector, over, uint256(1) << 40));
        tok.mtxUnshield(pl, pr, "", bytes32(0), "", over, bytes32(uint256(uint160(address(0xD)))));
        vm.expectRevert(IZetherToken.ZeroRecipient.selector);
        tok.mtxUnshield(pl, pr, "", bytes32(0), "", 10, bytes32(0));
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadPayload.selector, pl.length - 1));
        tok.mtxUnshield(_trim(pl), pr, "", bytes32(0), "", 10, bytes32(uint256(uint160(address(0xD)))));
        vm.expectRevert(IZetherToken.ProofRejected.selector); // another recipient than the proven one
        tok.mtxUnshield(pl, pr, "", bytes32(0), "", 10, bytes32(uint256(uint160(address(0xE)))));
        vm.expectRevert(IZetherToken.ProofRejected.selector); // another amount
        tok.mtxUnshield(pl, pr, "", bytes32(0), "", 11, bytes32(uint256(uint160(address(0xD)))));
        // to the token itself: the proof passes, the mint is refused (CTR-MTX-18)
        (bytes memory pl2, bytes memory pr2) = _proveUnshield(tok, alice, 10, 100, address(tok), _none(), 0);
        vm.expectRevert(IERC20MetaTx.TransferToSelf.selector);
        tok.mtxUnshield(pl2, pr2, "", bytes32(0), "", 10, bytes32(uint256(uint160(address(tok)))));
        tok.mtxUnshield(pl, pr, "", bytes32(0), "", 10, bytes32(uint256(uint160(address(0xD)))));
        assertEq(tok.balanceOf(address(0xD)), 10 * SCALE);
        assertEq(tok.totalShielded(), 90);
    }

    function _trim(bytes memory a) internal pure returns (bytes memory out) {
        out = new bytes(a.length - 1);
        for (uint256 i; i < out.length; ++i) out[i] = a[i];
    }

    /// The inner fee `< 2^n_v` (n_v = 64) and `< maxShielded` (a fee at the cap would make every transfer with a
    /// beneficiary unprovable): 2^32 and cap − 1 create, the cap and 2^64 − 1 do not.
    function test_confidentialFeeBound() public {
        uint256 max = uint256(1) << 40;
        uint256[2] memory ok = [uint256(1) << 32, max - 1];
        for (uint256 i; i < ok.length; ++i) {
            IFactoryToken.TokenConfig memory c = _cfg(false, max);
            c.conf.confidentialFee = ok[i];
            ZetherLayer z = ZetherLayer(factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, abi.encode(c), bytes32(i + 900)));
            assertEq(z.confidentialFee(), ok[i]);
        }
        uint256[2] memory bad = [max, (uint256(1) << 64) - 1];
        for (uint256 i; i < bad.length; ++i) {
            IFactoryToken.TokenConfig memory c = _cfg(false, max);
            c.conf.confidentialFee = bad[i];
            vm.expectRevert(IZetherToken.BadInit.selector);
            factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, abi.encode(c), bytes32(i + 910));
        }
    }

    /// The confidential config at creation (CTR-ZTH-04, -09, -26); the kind's flags (CTR-ZTH-47); the dev-chain gate in
    /// `initialize` (a clone made by hand, around the factory).
    function test_initializeRevertPaths() public {
        IFactoryToken.TokenConfig memory c = _cfg(false, uint256(1) << 40);
        vm.expectRevert(MetaTokenBase.NotFactory.selector);
        noneImpl.initialize(address(this), 1, abi.encode(c));
        vm.prank(address(factory));
        vm.expectRevert(MetaTokenBase.AlreadyInitialized.selector);
        NoUnderlyingZetherToken(address(tok)).initialize(address(this), 1, abi.encode(c));
        IFactoryToken.TokenConfig[6] memory bad;
        for (uint256 i; i < 6; ++i) bad[i] = _cfg(false, uint256(1) << 40);
        bad[0].conf.shieldScale = 0;
        bad[1].conf.maxShielded = (uint256(1) << 54) + 1;               // > 2^54
        bad[2].conf.maxShielded = 0;
        bad[3].conf.auditorKey = new bytes(128);                        // auditor = O
        bytes memory off = ZetherKeys.pub(X_AUD, true);
        off[127] = off[127] ^ 0x01;
        bad[4].conf.auditorKey = off;                                   // not on the curve
        bad[5].conf.auditorKey = ZetherKeys.pub(X_AUD, false);          // a bn254 key (legacy) on the BLS12-381 token
        for (uint256 i; i < bad.length; ++i) {
            vm.expectRevert(IZetherToken.BadInit.selector);
            factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, abi.encode(bad[i]), bytes32(i + 100));
        }
        // cap · scale must not overflow
        IFactoryToken.TokenConfig memory big = _cfg(false, uint256(1) << 40);
        big.conf.shieldScale = type(uint256).max / (uint256(1) << 40) + 1;
        vm.expectRevert(IZetherToken.BadInit.selector);
        factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, abi.encode(big), "overflow");
        // the kind's fields: legs and rate belong to other kinds; the regulated flags are refused
        IFactoryToken.TokenConfig memory r = _cfg(false, uint256(1) << 40);
        r.rate.rateDelay = 2 days;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 3));
        factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, abi.encode(r), "rate");
        r = _cfg(false, uint256(1) << 40);
        r.features |= 1 << AdminLib.PAUSE;
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, AdminLib.PAUSE));
        factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, abi.encode(r), "pause");
        r = _cfg(false, uint256(1) << 40);
        r.features |= 1 << AdminLib.WRAP_DISABLEABLE;
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, AdminLib.WRAP_DISABLEABLE));
        factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, abi.encode(r), "wrap");
        // initialize outside a dev chain (a hand-made clone, around the factory gate)
        address cl = Clones.clone(address(noneImpl));
        vm.chainId(1);
        vm.prank(address(factory));
        vm.expectRevert(abi.encodeWithSelector(ZetherSafety.ZetherNotDevChain.selector, 1));
        NoUnderlyingZetherToken(cl).initialize(address(this), 1, abi.encode(c));
    }

    /// The release's `Env.deps` (plan 5g-Z2, CTR-ZTH-20): four entries with code, a registry, the two verifiers of one
    /// proof system, both fixed to the env's inner-product verifier, each in its role; never on Hedera.
    function test_constructorNeedsTheEnvDependencies() public {
        bytes memory code = type(NoUnderlyingZetherToken).creationCode;
        address ip = address(ZetherVerifierBase(address(ver)).innerProduct());
        address other = address(new OtherSystemBurnVerifier(ip));
        IZetherVerifier copy = IZetherVerifier(address(new ZetherTransferVerifierBls12381(
            ZetherVerifierBase(address(ver)).innerProduct())));
        IFactoryToken.Env[10] memory bad;
        for (uint256 i; i < bad.length; ++i) bad[i] = _zenv();
        bad[0].registry = address(0x1234);                               // a registry without code
        bad[1].deps[3] = address(0x1234);                                // a disclosure without code
        bad[2].deps[0] = address(0x1234);                                // a transfer verifier without code
        bad[3].deps[1] = other;                                          // a burn verifier of another proof system
        bad[4].deps[2] = address(0x99);                                  // not the verifiers' inner-product verifier
        bad[5].deps = new address[](3);                                  // too few
        bad[6].hedera = true;                                            // never on Hedera
        // each verifier in its role (review 5g-Z2 P2-2): a swapped or duplicated pair would lock every shield
        (bad[7].deps[0], bad[7].deps[1]) = (address(burnVer), address(ver)); // swapped
        bad[8].deps[1] = address(ver);                                   // the transfer verifier twice
        bad[9].deps[1] = address(copy);                                  // two transfer verifiers
        for (uint256 i; i < bad.length; ++i) {
            vm.expectRevert(IZetherToken.BadInit.selector);
            new NoUnderlyingZetherToken(1, bad[i], "");
        }
        // an honest copy of the transfer verifier on the same inner-product verifier is a different (valid) release
        IFactoryToken.Env memory e = _zenv();
        e.deps[0] = address(copy);
        assertEq(address(NoUnderlyingZetherToken(Catalogue.release(factory, IOpenFactory.TokenKind.NONE_ZETHER, 2, e, code))
            .verifier()), address(copy));
    }

    /// Plan 5g-Z2: the chain / verifier gate moved from the factory into the implementation's `initialize`
    /// (`ZetherLib.init`): a release whose transfer verifier does not run on this chain deploys, but every `createToken`
    /// of it reverts `VerifierUnsupportedOnThisChain`.
    function test_createToken_refusesAVerifierUnsupportedOnThisChain() public {
        UnsupportedHereVerifier w = new UnsupportedHereVerifier(address(ver));
        IFactoryToken.Env memory e = _zenv();
        e.deps[0] = address(w);
        Catalogue.release(factory, IOpenFactory.TokenKind.NONE_ZETHER, 2, e, type(NoUnderlyingZetherToken).creationCode);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.VerifierUnsupportedOnThisChain.selector, address(w), "bls12-381"));
        factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 2, abi.encode(_cfg(false, 1 << 40)), "unsupported");
        UnsupportedNamelessVerifier n = new UnsupportedNamelessVerifier(address(ver));
        e.deps[0] = address(n);
        Catalogue.release(factory, IOpenFactory.TokenKind.NONE_ZETHER, 3, e, type(NoUnderlyingZetherToken).creationCode);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.VerifierUnsupportedOnThisChain.selector, address(n), ""));
        factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 3, abi.encode(_cfg(false, 1 << 40)), "nameless");
        // the same config on the honest release of the same env shape is accepted
        assertTrue(factory.isRegisteredToken(
            factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, abi.encode(_cfg(false, 1 << 40)), "supported")));
    }

    /// Review 5g-Z2 P2-3 (controller proposal 2): the registrar may enable a Zether kind anywhere, but on a non-dev
    /// chain every `createToken` reverts with the implementation's gate.
    function test_createToken_enabledKindOnANonDevChain_reverts() public {
        assertTrue(factory.kindEnabled(IOpenFactory.TokenKind.NONE_ZETHER));
        vm.chainId(1);
        vm.expectRevert(abi.encodeWithSelector(ZetherSafety.ZetherNotDevChain.selector, 1));
        factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, abi.encode(_cfg(false, 1 << 40)), "mainnet");
    }

    /// CTR-ZTH-20 / plan 5g-Z2: the creator never names a verifier — the config has no field for it; the factory deploys
    /// every release with its own env appended, so the verifiers are the code's immutables by construction, and an
    /// unregistered confidential implementation cannot be cloned. A release on another env (a fake verifier that accepts
    /// every proof) can only come from the registrar, the trust root, and is a new version: tokens of version 1 keep
    /// theirs.
    function test_verifiersComeFromTheFactoryEnvOnly() public {
        AcceptAllVerifier fake = new AcceptAllVerifier(address(ver));
        // a hand-made clone around the factory is no factory token (and the implementation refuses a non-factory caller)
        address cl = Clones.clone(address(noneImpl));
        vm.expectRevert(MetaTokenBase.NotFactory.selector);
        NoUnderlyingZetherToken(cl).initialize(address(this), 1, abi.encode(_cfg(false, 1 << 40)));
        assertFalse(factory.isToken(cl));
        // unregistered confidential: refused before any check
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.UnregisteredConfidentialKind.selector,
            IOpenFactory.TokenKind.NONE_ZETHER));
        factory.createTokenUnregistered(IOpenFactory.TokenKind.NONE_ZETHER, address(noneImpl), abi.encode(_cfg(false, 1 << 40)), "x");
        // only the registrar publishes envs and deploys releases
        IFactoryToken.Env memory e = _zenv();
        e.deps[0] = address(fake);
        vm.expectRevert(IOpenFactory.NotRegistrar.selector);
        factory.publishEnv(IOpenFactory.TokenKind.NONE_ZETHER, 2, e);
        vm.expectRevert(IOpenFactory.NotRegistrar.selector);
        factory.deployImplementation(IOpenFactory.TokenKind.NONE_ZETHER, 2, 1, type(NoUnderlyingZetherToken).creationCode, "");
        // the factory-made token carries the env's verifiers
        assertEq(address(tok.verifier()), address(ver));
        assertEq(address(tok.burnVerifier()), address(burnVer));
        assertEq(address(tok.disclosure()), address(dis));
        assertEq(tok.curve(), "bls12-381");
        bytes32 ns = 0xd1eef6cbeb7b383e0a92b3cb723053d5c39c76707d89da6b14ff91b83198ce00;
        assertEq(address(uint160(uint256(vm.load(address(tok), ns)))), address(ver), "the library's copy");
        assertTrue(factory.isRegisteredToken(address(tok)));
        IOpenFactory.Release memory rel = factory.releaseOf(IOpenFactory.TokenKind.NONE_ZETHER, 1);
        assertEq(rel.implementation, address(noneImpl));
        assertEq(rel.envVersion, 1);
        assertEq(rel.envHash, keccak256(abi.encode(pinned(_zenv(), IOpenFactory.TokenKind.NONE_ZETHER))));
    }

    /// Every proof path goes through the release's verifiers (CTR-ZTH-20): a single and a multi-recipient transfer
    /// through the transfer verifier, an unshield through the burn verifier, each exactly once, and every range proof
    /// through the inner-product verifier the two fix.
    function test_everyProofPathUsesThePinnedVerifiers() public {
        _fund(tok, alice, 100);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        bytes4[3] memory ops = [ZetherLayer.mtxConfidentialTransferSingle.selector, ZetherLayer.mtxConfidentialTransfer.selector,
            ZetherLayer.mtxUnshield.selector];
        bytes4[3] memory checks = [IZetherVerifier.verifyTransfer.selector, IZetherVerifier.verifyTransferMulti.selector,
            IZetherBurnVerifier.verifyBurn.selector];
        address ip = address(ZetherVerifierBase(address(ver)).innerProduct());
        assertEq(ip, address(ZetherVerifierBase(address(burnVer)).innerProduct()), "one inner-product verifier");
        for (uint256 i; i < 3; ++i) vm.expectCall(i == 2 ? address(burnVer) : address(ver), abi.encodePacked(checks[i]), 1);
        // BP(v), BP(b'); BP(v_1), BP(b'); BP(b')
        vm.expectCall(ip, abi.encodePacked(IZetherInnerProductVerifier.verifyRange.selector), 5);
        for (uint256 i; i < 3; ++i) {
            (bool ok,) = address(tok).call(_zetherOpCall(ops[i], 100 - 10 * i, 0));
            assertTrue(ok, "honest op");
        }
    }

    /// The minter never mints shielded value (CTR-ZTH-44): `mint` and the initial supply only add public units.
    function test_minterMintsPublicUnitsOnly() public {
        IFactoryToken.TokenConfig memory c = _cfg(false, uint256(1) << 40);
        (c.initialSupply, c.initialHolder) = (7 * SCALE, address(0xA77));
        ZetherLayer z = ZetherLayer(factory.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, abi.encode(c), "supply"));
        assertEq(z.balanceOf(address(0xA77)), 7 * SCALE);
        assertEq(z.totalShielded(), 0);
        _public(tok, address(0xA77), 5 * SCALE);
        assertEq(tok.balanceOf(address(0xA77)), 5 * SCALE);
        assertEq(tok.totalShielded(), 0);
        vm.prank(address(0xBAD));
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.MissingRole.selector, AdminLib.MINTABLE, address(0xBAD)));
        NoUnderlyingZetherToken(address(tok)).mint(address(0xBAD), 1);
    }

    /// CTR-TOK-01 (MT-3) on the public side of a Zether token: only contracts grant and spend allowances.
    function test_contractOnlyAllowance() public {
        vm.prank(address(0xE0A));
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.CallerNotContract.selector, address(0xE0A)));
        tok.approve(address(this), 1);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.SpenderNotContract.selector, address(0xE0A)));
        tok.approve(address(0xE0A), 1);
        vm.prank(address(0xE0A));
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.CallerNotContract.selector, address(0xE0A)));
        tok.transferFrom(address(1), address(2), 0);
        Puller pl = new Puller();
        _public(tok, address(this), 10);
        tok.approve(address(pl), 10);
        pl.pull(address(tok), address(this), address(0xF1), 10);
        assertEq(tok.balanceOf(address(0xF1)), 10);
        // an EIP-7702 delegated EOA (code = 0xef0100 ‖ addr) is still an EOA: it holds no allowance
        address eoa = address(0x7702);
        vm.etch(eoa, abi.encodePacked(hex"ef0100", address(0x1234)));
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.SpenderNotContract.selector, eoa));
        tok.approve(eoa, 1);
    }

    function test_unknownEntryReverts() public {
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.UnknownEntry.selector, bytes32("nope")));
        _vta(tok, bytes32("nope"), 0, 1, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(uint256(1)));
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.UnknownEntry.selector, bytes32("nope")));
        dis.transferCiphertext(address(tok), bytes32("nope"), 0);
    }

    function test_curveLibBadLength() public {
        vm.expectRevert(abi.encodeWithSelector(G1Bls12381.BadLength.selector, 127));
        ver.g1Add(new bytes(127), new bytes(128));
        bytes memory g = ver.g1MulBase(1);
        vm.expectRevert(abi.encodeWithSelector(G1Bls12381.BadLength.selector, 127));
        ver.g1Sub(g, new bytes(127)); // neg
        vm.expectRevert(abi.encodeWithSelector(G1Bls12381.BadLength.selector, 256));
        ver.g1Msm(bytes.concat(g, g), new uint256[](1)); // msm: pts ≠ k·128
    }

    /// ERC-7201 `scaas.zether` (CTR-TOK-24): where an indexer reads the verifier, the scale, `totalShielded`.
    function test_zetherNamespaceSlot() public {
        _fund(tok, alice, 30);
        bytes32 ns = 0xd1eef6cbeb7b383e0a92b3cb723053d5c39c76707d89da6b14ff91b83198ce00;
        assertEq(ns, keccak256(abi.encode(uint256(keccak256("scaas.zether")) - 1)) & ~bytes32(uint256(0xff)));
        uint256 w0 = uint256(vm.load(address(tok), ns));
        assertEq(address(uint160(w0)), address(ver));
        // review T2 m5: disclosureMode at byte 20, auditorMode at byte 21 (this token: BUNDLE, NONE), nothing above
        assertEq(w0 >> 160, 0, "modes BUNDLE / NONE, packed after the verifier");
        assertEq(uint256(vm.load(address(tok), bytes32(uint256(ns) + 1))), SCALE);
        assertEq(uint256(vm.load(address(tok), bytes32(uint256(ns) + 4))), 30);
        // review T3 m4: maxShielded, confidentialFee, auditorKey (none here), psid, p, then acct[alice].pendingSeq
        assertEq(uint256(vm.load(address(tok), bytes32(uint256(ns) + 2))), uint256(1) << 40);
        assertEq(uint256(vm.load(address(tok), bytes32(uint256(ns) + 3))), FEE);
        assertEq(uint256(vm.load(address(tok), bytes32(uint256(ns) + 5))), 0);
        assertEq(vm.load(address(tok), bytes32(uint256(ns) + 6)), ver.proofSystemId());
        assertEq(uint256(vm.load(address(tok), bytes32(uint256(ns) + 7))), 128);
        bytes32 a = keccak256(abi.encode(alice.ua, uint256(ns) + 8)); // accC, accD, pendC, pendD, then the seqs
        assertEq(uint64(uint256(vm.load(address(tok), bytes32(uint256(a) + 4))) >> 64), 1, "pendingSeq");
    }

    /// CTR-ZTH-02: the verifiers refuse to deploy outside the dev chains (as the registry and `initialize`).
    function test_verifiersOnlyDeployOnDevChain() public {
        vm.chainId(1);
        vm.expectRevert(abi.encodeWithSelector(ZetherSafety.ZetherNotDevChain.selector, 1));
        new ZetherInnerProductVerifierBls12381();
        vm.expectRevert(abi.encodeWithSelector(ZetherSafety.ZetherNotDevChain.selector, 1));
        new ZetherTransferVerifierBls12381(IZetherInnerProductVerifier(address(0)));
        vm.expectRevert(abi.encodeWithSelector(ZetherSafety.ZetherNotDevChain.selector, 1));
        new ZetherBurnVerifierBls12381(IZetherInnerProductVerifier(address(0)));
    }

    /// Provenance (CTR-TOK-17): the kind, the factory's record, the immutables, the curve, the parameters.
    function test_provenanceRecorded() public view {
        assertEq(address(tok.verifier()), address(ver));
        assertEq(tok.registry(), address(reg));
        NoUnderlyingZetherToken z = NoUnderlyingZetherToken(address(tok));
        assertEq(z.factory(), address(factory));
        assertEq(z.implementation(), address(noneImpl));
        assertEq(z.version(), 1);
        assertEq(z.creator(), address(this));
        assertEq(z.kind(), AdminLib.KIND_NONE_ZETHER);
        assertEq(z.decimals(), 6);
        assertEq(tok.shieldScale(), SCALE);
        assertEq(tok.confidentialFee(), FEE);
        assertEq(tok.maxDecryptableShielded(), uint256(1) << 40);
        assertEq(tok.auditorKey().length, 0);
        assertEq(z.name(), "Zether USD");
        assertEq(z.symbol(), "zUSD");
        (, string memory n,,, address vc, bytes32 salt,) = z.eip712Domain();
        assertEq(n, "SCaaS ZetherToken");
        assertEq(vc, address(tok));
        assertEq(salt, ZUID);
        (IOpenFactory.TokenKind k, uint64 v) = factory.versionOf(address(tok));
        assertEq(uint8(k), uint8(IOpenFactory.TokenKind.NONE_ZETHER));
        assertEq(v, 1);
    }
}
