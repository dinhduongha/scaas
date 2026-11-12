// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {OnchainBase} from "./OnchainBase.sol";
import {Vm} from "forge-std/Vm.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {FeeMode} from "../../src/common/FeePolicy.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {PqUA} from "../../src/ua/PqUA.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {RelayFeeRouter} from "../../src/metatx/RelayFeeRouter.sol";
import {NormalRegulatedToken} from "../../src/regulated/NormalRegulatedToken.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {MockERC20} from "../../test/helpers/Mocks.sol";
import {OnchainForwarder} from "./OnchainForwarder.sol";

/// @notice T66b Step 5b, group `tokens`: the token kinds of the Step 5 factory (0-3, 8-11), each created by
///         `OpenFactory.createToken` (release 1), then its public entries direct and relayed (signed by test key 1's native
///         id, sent by test key 2), fee 0 and with a fee. A wrapped kind gets two tokens: W1, one MockERC20 leg (the sole-leg
///         entries, the common entries, the hybrid mint), W2, two legs (a MockERC20 and the kind-0 token, a SCaaS ledger leg:
///         the per-leg and `…ToUA` entries, the rate and the guardian). The regulated kinds 8-11 carry `KYC` on the Step 5
///         ComplianceRegistry and `TAX`. A secp256k1 UA registered on the Step 5 registry receives the `…ToUA` entries; an
///         ML-DSA-65 UA (keys by script/pqz/mldsa.mjs through `vm.ffi`: run with `--ffi`) signs a relayed `mtxTransfer` and
///         an `mtxTransferWithFee` on every kind.
///         Not here (other streams): the confidential layers (Zether, PQZ), the regulated controls, the trade entries.
///         UNAUDITED.
contract Tokens is OnchainBase {
    string internal constant UA_CANCEL_NONCE =
        "UACancelNonce(bytes32 from,uint256 lane,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string internal constant UA_BURN =
        "UABurn(bytes32 from,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string internal constant WRAP =
        "Wrap(address from,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string internal constant WRAP_LEG =
        "WrapLeg(address from,address underlying,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string internal constant WRAP_TO_UA =
        "WrapToUA(address from,address underlying,uint256 amount,bytes32 to,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string internal constant ADD_RESERVE =
        "AddReserve(address from,address underlying,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string internal constant UA_UNWRAP =
        "UAUnwrap(bytes32 from,uint256 wrapped,address recipient,uint256 minOut,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string internal constant UA_UNWRAP_LEG =
        "UAUnwrapLeg(bytes32 from,address underlying,uint256 wrapped,address recipient,uint256 minOut,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string internal constant UA_UNWRAP_TO_UA =
        "UAUnwrapToUA(bytes32 from,address underlying,uint256 wrapped,bytes32 to,uint256 minOut,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    bytes32 internal constant UA_RELAY_FEE = keccak256(
        "UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 batch,uint256 nonce,uint256 validUntil,address relayer)");
    bytes32 internal constant UA_PAY_WITH_TAX = keccak256(
        "UAPayWithTax(UAMetaTransfer payment,uint8 taxMode,uint256 tax)UAMetaTransfer(bytes32 from,bytes32 to,uint256 value,"
        "bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,"
        "address feeRecipient)");
    uint32 internal constant FIXED_FEE = MetaTxLib.MODE_FEE_FIXED | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT;
    uint32 internal constant PERCENT_FEE = MetaTxLib.MODE_FEE_PERCENT | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT;
    uint256 internal constant LANE_FEE = 2; // the relay-fee lane (Smoke.s.sol)
    uint16 internal constant ML65 = UAKinds.MLDSA65; // the PQ signer's kind (0x0131)

    OpenFactory f;
    address router;
    address registry;
    address compliance;
    bytes32 uaD; // a secp256k1 UA on the Step 5 registry (a receiver only)
    bytes32 uaM; // an ML-DSA-65 UA on the Step 5 registry: the PQ signer of a relayed transfer on every kind
    bytes32 mlSeed;
    MockERC20 m1; // W1's leg
    MockERC20 m2; // W2's first leg
    MockERC20 stray; // what `rescue` sends back
    OnchainForwarder fA;
    OnchainForwarder fB;
    OnchainForwarder fR; // the rate admin
    address base; // the kind-0 token: W2's SCaaS ledger leg and the negatives' token
    address t8; // the kind-8 token: the MissingRole negative
    address t; // the token under test
    uint8 k; // its kind
    uint256 seq; // pay salts

    function run() external {
        _init("tokens");
        f = OpenFactory(_dep("token_factory"));
        router = _dep("relay_fee_router");
        registry = _dep("ua_registry");
        compliance = _dep("compliance_registry");
        _book(address(f), "OpenFactory");
        _book(router, "RelayFeeRouter");
        _book(_dep("relay_fee_executor"), "RelayFeeExecutor");
        _book(registry, "UARegistry");
        _fixtures();
        _registerDerived();
        _registerMl();
        // the plain normal kinds and the regulated normal kinds
        uint8[4] memory ns = [uint8(0), 2, 8, 10];
        for (uint256 i; i < 4; ++i) _normalKind(ns[i]);
        _throwaway();
        uint8[4] memory ws = [uint8(1), 3, 9, 11];
        for (uint256 i; i < 4; ++i) _wrappedKind(ws[i]);
        _negatives();
        _writeBook();
    }

    // ------------------------------------------------------------------ fixtures

    function _fixtures() internal {
        vm.startBroadcast(k1);
        m1 = new MockERC20("Onchain leg 1", "oL1", 6);
        m2 = new MockERC20("Onchain leg 2", "oL2", 6);
        stray = new MockERC20("Onchain stray", "oST", 6);
        fA = new OnchainForwarder();
        fB = new OnchainForwarder();
        fR = new OnchainForwarder();
        m1.mint(a1, 1e15);
        m2.mint(a1, 1e15);
        vm.stopBroadcast();
        _book(address(m1), "MockERC20");
        _book(address(m2), "MockERC20");
        _book(address(stray), "MockERC20");
        _book(address(fA), "OnchainForwarder");
        _book(address(fB), "OnchainForwarder");
        _book(address(fR), "OnchainForwarder");
    }

    /// @dev A secp256k1 UA (0x0108) of a fresh key, registered on the Step 5 registry with its portable PoP (UA-8, no
    ///      attributes): `pop` over `uaMessage(kind, pop.v2, registrationDigest(ua, kind, 0, kemRecordHash(ua, 0, ""), 0))`.
    function _registerDerived() internal {
        uint256 kd = uint256(keccak256(abi.encode(runSalt, "derived"))) % (type(uint128).max) + 1;
        Vm.Wallet memory w = vm.createWallet(kd);
        bytes memory keyData = abi.encodePacked(w.publicKeyX, w.publicKeyY);
        uint16 kind = UAKinds.SECP256K1;
        bytes32 ua = UAKinds.uaOf(kind, keyData);
        bytes32 rd = UAKinds.registrationDigest(ua, kind, 0, UAKinds.kemRecordHash(ua, 0, bytes("")), 0);
        bytes memory pop = _ecdsa(kd, UAKinds.uaMessage(kind, UAKinds.PURPOSE_POP_V2, rd));
        IUARegistry.UAAttrs memory none;
        vm.broadcast(k1);
        uaD = IUARegistry(registry).register(kind, keyData, none, pop, "");
        require(uaD == ua && IUARegistry(registry).isRegistered(ua), "derived UA");
    }

    /// @dev The ML-DSA-65 key and signatures from script/pqz/mldsa.mjs (@noble/post-quantum, FIPS 204, empty context)
    ///      through `vm.ffi` (the script needs `--ffi`); the seed is the run's, never a secret worth keeping.
    function _ml(string memory job) internal returns (bytes memory) {
        string[] memory c = new string[](3);
        (c[0], c[1]) = ("sh", "-c");
        c[2] = string.concat("printf '%s\\n' '", job,
            "' | node script/pqz/mldsa.mjs ../../clients/clientkeys | sed 's/^/0x/'");
        return vm.ffi(c);
    }

    function _bare(bytes32 x) internal pure returns (string memory) {
        bytes memory h = bytes(vm.toString(x));
        bytes memory o = new bytes(64);
        for (uint256 i; i < 64; ++i) o[i] = h[i + 2];
        return string(o);
    }

    /// @dev The ML-DSA signature of `uaMsg` (the registry's `uaMessage`): over `pq_msg = keccak256(TAG ‖ uaMsg)`, as
    ///      MldsaVerifier checks it (PqUA.pqMessage).
    function _mlSign(bytes32 uaMsg) internal returns (bytes memory) {
        return _ml(string.concat("sign 65 ", _bare(mlSeed), " ", _bare(PqUA.pqMessage(PqUA.tag(ML65), uaMsg))));
    }

    /// @dev Registered as `_registerDerived` (no attributes), the PoP an ML-DSA-65 signature; the Step 5 verifiers are pure
    ///      Solidity (PRECOMPILE() = 0), so this runs on the fork and on the SCaaS testnet alike, after `cacheExpandedKey`.
    function _registerMl() internal {
        mlSeed = keccak256(abi.encode(runSalt, "mldsa65"));
        bytes memory pk = _ml(string.concat("keygen 65 ", _bare(mlSeed)));
        require(pk.length == 1952, "ML-DSA-65 key");
        bytes32 ua = UAKinds.uaOf(ML65, pk);
        bytes32 rd = UAKinds.registrationDigest(ua, ML65, 0, UAKinds.kemRecordHash(ua, 0, bytes("")), 0);
        bytes memory pop = _mlSign(IUARegistry(registry).uaMessage(ML65, UAKinds.PURPOSE_POP_V2, rd));
        IUARegistry.UAAttrs memory none;
        // no precompile: the registry verifies an ML-DSA key through its cached expanded key (two SSTORE2 parts for
        // ML-DSA-65, CTR-UA-39's verifyCached); a FIPS-key verify does not fit the kind's verify cap
        // each asks a fixed 56 M (under 60 M): the fork's estimate undershoots regular + state gas (EIP-8037)
        vm.startBroadcast(k1);
        IUARegistry(registry).cacheExpandedKey{gas: 56_000_000}(ML65, pk, 0);
        IUARegistry(registry).cacheExpandedKey{gas: 56_000_000}(ML65, pk, 1);
        uaM = IUARegistry(registry).register{gas: 56_000_000}(ML65, pk, none, pop, "");
        vm.stopBroadcast();
        require(uaM == ua && IUARegistry(registry).kindOf(ua) == ML65, "ML-DSA UA");
    }

    // ------------------------------------------------------------------ token configs

    function _label(uint8 kind) internal pure returns (string memory) {
        if (kind == 0) return "NormalToken";
        if (kind == 1) return "WrappedToken";
        if (kind == 2) return "NormalZetherToken";
        if (kind == 3) return "WrappedZetherToken";
        if (kind == 8) return "NormalRegulatedToken";
        if (kind == 9) return "WrappedRegulatedToken";
        if (kind == 10) return "NormalZetherRegulatedToken";
        return "WrappedZetherRegulatedToken";
    }

    function _zether(uint8 kind) internal pure returns (bool) {
        return kind == 2 || kind == 3 || kind == 10 || kind == 11;
    }

    function _regulated(uint8 kind) internal pure returns (bool) {
        return kind >= 8;
    }

    function _base(uint8 kind, string memory sym) internal view returns (IFactoryToken.TokenConfig memory c) {
        (c.name, c.symbol, c.decimals) = (string.concat("Onchain ", _label(kind)), sym, 6);
        c.admin = _pad(a1);
        if (_zether(kind)) c.conf = IFactoryToken.ConfidentialConfig("", 10_000, uint256(1) << 40, 2, 0, 0, 0, 0, 0, false, 0, 0, 0);
    }

    /// @dev `KYC` (round 3s, bit 28: the Step 5 ComplianceRegistry, flag 1 denied: nobody attested, so everyone passes) and `TAX` (the
    ///      issuer test key 1, the recipient test key 3).
    function _reg(IFactoryToken.TokenConfig memory c) internal view {
        c.features |= 1 << GovernanceBits.KYC | 1 << GovernanceBits.TAX;
        c.reg = IFactoryToken.RegulatedParams(compliance, 0, 1, keccak256("scaas.onchain.terms"), _pad(a3));
        c.roles.issuer = _pad(a1);
    }

    function _create(uint8 kind, IFactoryToken.TokenConfig memory c, string memory what) internal returns (address x) {
        vm.broadcast(k1);
        x = f.createToken(IOpenFactory.TokenKind(kind), 1, abi.encode(c), _salt(what));
        _book(x, _label(kind));
        require(NormalToken(x).kind() == kind, "kind");
    }

    // ------------------------------------------------------------------ the normal kinds 0, 2, 8, 10

    function _normalKind(uint8 kind) internal {
        IFactoryToken.TokenConfig memory c = _base(kind, "oN");
        c.features = 1 << GovernanceBits.PAYABLE | 1 << GovernanceBits.MINTABLE | 1 << GovernanceBits.BURNABLE
            | 1 << GovernanceBits.RESCUABLE;
        c.roles.minter = _pad(a1);
        (c.initialSupply, c.initialHolder, c.rescueTo) = (1e15, a1, a3);
        if (_regulated(kind)) _reg(c);
        (t, k) = (_create(kind, c, string.concat("normal", vm.toString(kind))), kind);
        if (kind == 0) base = t;
        if (kind == 8) t8 = t;
        _common();
        _normalOnly();
        if (_regulated(kind)) _tax();
        _gov();
    }

    function _normalOnly() internal {
        vm.startBroadcast(k1);
        NormalToken(t).mint(a1, 1_000);
        NormalToken(t).mintToUA(uaD, 100);
        NormalToken(t).burn(10);
        vm.stopBroadcast();
        MetaTxLib.UAEnvelope memory e = _env(a1, 8, _nonce(8));
        IUARegistry.UASig memory s = _sig(k1, _named(t, UA_BURN, abi.encode(uint256(10)), e));
        vm.broadcast(k2);
        NormalToken(t).mtxBurn(e, 10, s);
    }

    /// @dev Kind 0, `grantDelay` 1 hour: `grantRole` leaves a pending grant, `cancelGrant` drops it, then the owner
    ///      renounces (no live holder).
    function _throwaway() internal {
        IFactoryToken.TokenConfig memory c = _base(0, "oN0x");
        c.features = 1 << GovernanceBits.PAYABLE | 1 << GovernanceBits.MINTABLE;
        c.grantDelay = 1 hours;
        (c.initialSupply, c.initialHolder) = (1e6, a1);
        address x = _create(0, c, "throwaway");
        vm.startBroadcast(k1);
        NormalToken(x).grantRole(GovernanceBits.MINTABLE, _pad(a2), IMetaTx(x).chainUid());
        (uint64 eta,,,) = NormalToken(x).pendingGrant(GovernanceBits.MINTABLE, _pad(a2));
        require(eta != 0, "pending grant");
        NormalToken(x).cancelGrant(GovernanceBits.MINTABLE, _pad(a2), IMetaTx(x).chainUid());
        NormalToken(x).renounceAdmin(NormalToken(x).chainUid());
        vm.stopBroadcast();
        require(NormalToken(x).admin() == 0, "renounced");
    }

    // ------------------------------------------------------------------ the wrapped kinds 1, 3, 9, 11

    function _wrappedKind(uint8 kind) internal {
        // W1: one MockERC20 leg 1:1, a hybrid (MINTABLE, maxSupply), rescuable
        IFactoryToken.TokenConfig memory c = _base(kind, "oW1");
        c.features = 1 << GovernanceBits.PAYABLE | 1 << GovernanceBits.MINTABLE | 1 << GovernanceBits.RESCUABLE;
        c.roles.minter = _pad(a1);
        (c.maxSupply, c.rescueTo) = (1e30, a3);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(m1), 1, 1);
        if (_regulated(kind)) _reg(c);
        (t, k) = (_create(kind, c, string.concat("w1-", vm.toString(kind))), kind);
        _w1();
        _common();
        vm.startBroadcast(k1);
        WrappedToken(payable(t)).mint(a1, 1_000);
        WrappedToken(payable(t)).mintToUA(uaD, 100);
        vm.stopBroadcast();
        if (_regulated(kind)) _tax();
        _gov();
        // W2: two legs (a MockERC20 and the kind-0 SCaaS ledger token), rate admin `fR`, guardian test key 1
        c = _base(kind, "oW2");
        c.features = 1 << GovernanceBits.PAYABLE | 1 << GovernanceBits.RATE_ADJUSTABLE | 1 << GovernanceBits.WRAP_DISABLEABLE;
        (c.roles.rateAdmin, c.roles.guardian) = (_pad(address(fR)), _pad(a1));
        c.rate = IFactoryToken.RateConfig(2 days, 100);
        c.legs = new IFactoryToken.Leg[](2);
        c.legs[0] = IFactoryToken.Leg(address(m2), 1, 1);
        c.legs[1] = IFactoryToken.Leg(base, 1, 1);
        // round 3s (token-lists spec §5.5): the list bits stay enableable on a regulated W2, so its terms are required
        if (_regulated(kind)) c.reg.termsHash = keccak256("scaas.onchain.terms");
        t = _create(kind, c, string.concat("w2-", vm.toString(kind)));
        _w2();
        _w2Relayed();
        _w2Rate();
    }

    function _w1() internal {
        WrappedToken w = WrappedToken(payable(t));
        vm.startBroadcast(k1);
        m1.approve(t, type(uint256).max);
        w.wrap(uint256(1e9));
        w.wrap(address(m1), 1e6);
        w.unwrap(uint256(100), a1);
        w.unwrap(uint256(100), a1, uint256(0));
        vm.stopBroadcast();
        MetaTxLib.Envelope memory ea = _aenv(a1, 9, _nonce(9));
        bytes memory sa = _ecdsa(k1, _namedA(t, WRAP, abi.encode(uint256(100)), ea));
        vm.broadcast(k2);
        w.mtxWrap(ea, 100, sa);
        MetaTxLib.UAEnvelope memory e = _env(a1, 10, _nonce(10));
        IUARegistry.UASig memory s = _sig(k1, _named(t, UA_UNWRAP, abi.encode(uint256(100), a1, uint256(0)), e));
        vm.broadcast(k2);
        w.mtxUnwrap(e, 100, a1, 0, s);
    }

    function _w2() internal {
        WrappedToken w = WrappedToken(payable(t));
        vm.startBroadcast(k1);
        m2.approve(t, type(uint256).max);
        w.wrap(address(m2), 1e6);
        w.wrapToUA(address(m2), 100, uaD);
        w.unwrap(address(m2), 100, a1, 0);
        w.addReserve(address(m2), 100);
        // the SCaaS leg: a contract holder wraps it (an EOA cannot approve, CTR-TOK-01), then hands units to test key 1
        IERC20(base).transfer(address(fA), 10_000);
        fA.forwardCall(base, abi.encodeCall(IERC20.approve, (t, 10_000)));
        fA.forwardCall(t, abi.encodeWithSignature("wrap(address,uint256)", base, uint256(10_000)));
        fA.forwardCall(t, abi.encodeCall(IERC20.transfer, (a1, 5_000)));
        w.unwrapToUA(base, 100, uaD, 0);
        vm.stopBroadcast();
    }

    function _w2Relayed() internal {
        WrappedToken w = WrappedToken(payable(t));
        MetaTxLib.Envelope memory ea = _aenv(a1, 11, _nonce(11));
        bytes memory sa = _ecdsa(k1, _namedA(t, WRAP_LEG, abi.encode(address(m2), uint256(100)), ea));
        vm.broadcast(k2);
        w.mtxWrapLeg(ea, address(m2), 100, sa);
        ea = _aenv(a1, 11, _nonce(11));
        sa = _ecdsa(k1, _namedA(t, WRAP_TO_UA, abi.encode(address(m2), uint256(100), uaD), ea));
        vm.broadcast(k2);
        w.mtxWrapToUA(ea, address(m2), 100, uaD, sa);
        ea = _aenv(a1, 11, _nonce(11));
        sa = _ecdsa(k1, _namedA(t, ADD_RESERVE, abi.encode(address(m2), uint256(100)), ea));
        vm.broadcast(k2);
        w.mtxAddReserve(ea, address(m2), 100, sa);
        MetaTxLib.UAEnvelope memory e = _env(a1, 12, _nonce(12));
        IUARegistry.UASig memory s =
            _sig(k1, _named(t, UA_UNWRAP_LEG, abi.encode(address(m2), uint256(100), a1, uint256(0)), e));
        vm.broadcast(k2);
        w.mtxUnwrapLeg(e, address(m2), 100, a1, 0, s);
        e = _env(a1, 12, _nonce(12));
        s = _sig(k1, _named(t, UA_UNWRAP_TO_UA, abi.encode(base, uint256(100), uaD, uint256(0)), e));
        vm.broadcast(k2);
        w.mtxUnwrapToUA(e, base, 100, uaD, 0, s);
    }

    /// @dev Propose and cancel, propose again (left pending: `executeRate` waits the 2-day delay, a negative below), then
    ///      the guardian disables the MockERC20 leg's wrap (one-way).
    function _w2Rate() internal {
        bytes memory prop = abi.encodeCall(WrappedToken.proposeRate, (address(m2), uint96(1001), uint96(1000)));
        vm.startBroadcast(k1);
        fR.forwardCall(t, prop);
        fR.forwardCall(t, abi.encodeCall(WrappedToken.cancelRate, ()));
        fR.forwardCall(t, prop);
        WrappedToken(payable(t)).disableWrap(address(m2), keccak256("scaas.onchain.disable"));
        vm.stopBroadcast();
        if (k == 1) {
            (,,, uint64 eta) = WrappedToken(payable(t)).pendingRate();
            _neg(a1, address(fR), abi.encodeCall(OnchainForwarder.forwardCall, (t, abi.encodeCall(WrappedToken.executeRate, ()))),
                IWrappedToken.RateChangeNotReady.selector, string.concat("executeRate before the 2-day delay (eta ",
                vm.toString(eta), ")"));
        }
    }

    // ------------------------------------------------------------------ the common entries (every kind)

    function _nonce(uint256 lane) internal view returns (uint256) {
        return NormalToken(t).mtxNonce(_pad(a1), lane);
    }

    function _tr(bytes32 to, uint256 value, uint256 lane) internal view returns (MetaTxLib.UAMetaTransfer memory x) {
        (x.from, x.to, x.value, x.batch, x.nonce, x.validUntil) = (_pad(a1), to, value, lane, _nonce(lane), vu);
    }

    function _common() internal {
        _direct();
        _pq();
        _executeMeta();
        _transfers();
        _generic();
        _pays();
        _payeeFee();
        _relay();
        _cancels();
    }

    function _direct() internal {
        vm.startBroadcast(k1);
        IERC20(t).transfer(a2, 100);
        IERC20(t).transfer(address(fA), 100);
        fA.forwardCall(t, abi.encodeCall(IERC20.approve, (address(fB), 50)));
        fB.forwardCall(t, abi.encodeCall(IERC20.transferFrom, (address(fA), a2, 50)));
        NormalToken(t).transferToUA(uaD, 10);
        vm.stopBroadcast();
        require(IERC20(t).allowance(address(fA), address(fB)) == 0, "allowance spent");
    }

    /// @dev The PQ signer: test key 1 funds the ML-DSA-65 UA (`transferToUA`), which signs one relayed `mtxTransfer` (fee 0)
    ///      and one `mtxTransferWithFee` (FIXED 5 to test key 3), sent by test key 2; the registry verifies each by
    ///      `requireAuthorized` under `metatx`.
    function _pq() internal {
        NormalToken n = NormalToken(t);
        vm.broadcast(k1);
        n.transferToUA(uaM, 10_000);
        MetaTxLib.UAMetaTransfer memory x = _tr(_pad(a3), 100, 0);
        (x.from, x.nonce) = (uaM, n.mtxNonce(uaM, 0));
        IUARegistry.UASig memory s;
        s.signature = _mlSign(IUARegistry(registry).uaMessage(ML65, UAKinds.PURPOSE_METATX, n.mtxTransferDigest(x)));
        vm.broadcast(k2);
        n.mtxTransfer(uaM, x.to, 100, 0, x.nonce, vu, 0, address(0), s);
        x = _tr(_pad(a2), 1_000, 0);
        (x.from, x.nonce, x.mode, x.fee, x.feeRecipient) = (uaM, n.mtxNonce(uaM, 0), FIXED_FEE, 5, a3);
        s.signature = _mlSign(IUARegistry(registry).uaMessage(ML65, UAKinds.PURPOSE_METATX, n.mtxTransferDigest(x)));
        vm.broadcast(k2);
        n.mtxTransferWithFee(uaM, x.to, 1_000, 0, x.nonce, vu, FIXED_FEE, address(0), 5, a3, s);
        require(n.balanceOfUA(uaM) == 10_000 - 100 - 1_000 - 5, "PQ signer balance");
    }

    /// @dev The address `MetaTransaction` (v3) of `cancelNonce(77)`, signed by test key 1, relayed.
    function _executeMeta() internal {
        MetaTxLib.MetaTransaction memory m;
        (m.from, m.data, m.batch, m.nonce, m.validUntil) =
            (a1, abi.encodeCall(IMetaTx.cancelNonce, (uint256(77))), 5, _nonce(5), vu);
        bytes32 h = keccak256(abi.encode(MetaTxLib.METATX_TYPEHASH, m.from, keccak256(m.data), m.batch, m.nonce,
            m.validUntil, m.mode, address(0), m.fee, address(0)));
        bytes memory sg = _ecdsa(k1, _digest(t, h));
        vm.broadcast(k2);
        NormalToken(t).executeMetaTransaction(m, sg);
    }

    function _transfers() internal {
        NormalToken n = NormalToken(t);
        MetaTxLib.UAMetaTransfer memory x = _tr(_pad(a3), 1_000, 0);
        IUARegistry.UASig memory s = _sig(k1, n.mtxTransferDigest(x));
        vm.broadcast(k2);
        n.mtxTransfer(x.from, x.to, x.value, 0, x.nonce, vu, 0, address(0), s);
        // a FIXED fee of 5, then a PERCENT fee of 0.5 % (5,000 ppm), each to test key 3's bound recipient
        x = _tr(_pad(a2), 1_000, 0);
        (x.mode, x.fee, x.feeRecipient) = (FIXED_FEE, 5, a3);
        s = _sig(k1, n.mtxTransferDigest(x));
        vm.broadcast(k2);
        n.mtxTransferWithFee(x.from, x.to, x.value, 0, x.nonce, vu, x.mode, address(0), 5, a3, s);
        x = _tr(_pad(a2), 1_000, 0);
        (x.mode, x.fee, x.feeRecipient) = (PERCENT_FEE, 5_000, a3);
        s = _sig(k1, n.mtxTransferDigest(x));
        vm.broadcast(k2);
        n.mtxTransferWithFee(x.from, x.to, x.value, 0, x.nonce, vu, x.mode, address(0), 5_000, a3, s);
        x = _tr(_pad(a2), 1_000, 0);
        s = _sig(k1, n.mtxTransferDigest(x));
        vm.broadcast(k2);
        n.mtxExecuteTransfer(x, s);
        MetaTxLib.UAMetaTransfer[] memory xs = new MetaTxLib.UAMetaTransfer[](2);
        IUARegistry.UASig[] memory ss = new IUARegistry.UASig[](2);
        xs[0] = _tr(_pad(a2), 10, 0);
        xs[1] = _tr(_pad(a3), 20, 0);
        xs[1].nonce = xs[0].nonce + 1;
        (ss[0], ss[1]) = (_sig(k1, n.mtxTransferDigest(xs[0])), _sig(k1, n.mtxTransferDigest(xs[1])));
        vm.broadcast(k2);
        n.mtxBatchTransfer(xs, ss);
    }

    /// @dev `mtxExecute` and `mtxBatch` of `UAMetaTransaction`s running `cancelNonce` (allowlisted on every kind).
    function _generic() internal {
        NormalToken n = NormalToken(t);
        MetaTxLib.UAMetaTransaction memory m = _uam(78, 6, _nonce(6));
        IUARegistry.UASig memory s = _sig(k1, n.mtxDigest(m));
        vm.broadcast(k2);
        n.mtxExecute(m, s);
        MetaTxLib.UAMetaTransaction[] memory ms = new MetaTxLib.UAMetaTransaction[](2);
        IUARegistry.UASig[] memory ss = new IUARegistry.UASig[](2);
        uint256 nn = _nonce(6);
        (ms[0], ms[1]) = (_uam(79, 6, nn), _uam(80, 6, nn + 1));
        (ss[0], ss[1]) = (_sig(k1, n.mtxDigest(ms[0])), _sig(k1, n.mtxDigest(ms[1])));
        vm.broadcast(k2);
        n.mtxBatch(ms, ss);
    }

    function _uam(uint256 cancelLane, uint256 lane, uint256 nonce) internal view returns (MetaTxLib.UAMetaTransaction memory m) {
        (m.from, m.data, m.batch, m.nonce, m.validUntil) =
            (_pad(a1), abi.encodeCall(IMetaTx.cancelNonce, (cancelLane)), lane, nonce, vu);
    }

    function _payNo() internal view returns (bytes32) {
        return keccak256(abi.encode(runSalt, "payNo", t));
    }

    function _nextMeta(bool save) internal returns (MetaTxLib.PayMeta memory m) {
        m = _meta(bytes32(++seq), save ? _payNo() : bytes32(0), save);
    }

    /// @dev `mtxPay` with `save` true, then false; the record of `payNo` checked by `paymentCount` / `paymentsOf`; the
    ///      direct `payWithFee` (FIXED) and `payWithFeeToUA` (PERCENT, into the derived UA).
    function _pays() internal {
        NormalToken n = NormalToken(t);
        for (uint256 i; i < 2; ++i) {
            MetaTxLib.PayMeta memory m = _nextMeta(i == 0);
            MetaTxLib.UAMetaTransfer memory x = _tr(_pad(a2), 700, 0);
            x.entryRef = n.metaPayId(m);
            require(x.entryRef == _metaId(m), "metaPayId");
            IUARegistry.UASig memory s = _sig(k1, n.mtxTransferDigest(x));
            vm.broadcast(k2);
            n.mtxPay(x, s, m);
        }
        require(n.paymentCount(_payNo()) == 1, "paymentCount");
        MetaTxLib.PayRecord[] memory r = n.paymentsOf(_payNo(), 0, 10);
        require(r.length == 1 && r[0].to == _pad(a2) && r[0].amount == 700, "paymentsOf");
        MetaTxLib.PayMeta memory m3 = _nextMeta(false);
        MetaTxLib.PayMeta memory m4 = _nextMeta(false);
        vm.startBroadcast(k1);
        n.payWithFee(a2, 1_000, FeeMode.FIXED, 5, a3, _metaId(m3), m3);
        n.payWithFeeToUA(uaD, 1_000, FeeMode.PERCENT, 5_000, a3, _metaId(m4), m4);
        vm.stopBroadcast();
    }

    /// @dev The payee (test key 2, a native id) pays 5 of 1,000 to test key 3, co-signing under `payee-fee`; the payer's
    ///      transfer is bound to the relayer (the payee itself sends).
    function _payeeFee() internal {
        NormalToken n = NormalToken(t);
        MetaTxLib.PayMeta memory m = _nextMeta(false);
        MetaTxLib.UAMetaTransfer memory x = _tr(_pad(a2), 1_000, 0);
        (x.entryRef, x.mode, x.relayer) = (_metaId(m), MetaTxLib.MODE_RESTRICT_RELAYER, a2);
        IUARegistry.UASig memory ps = _sig(k1, n.mtxTransferDigest(x));
        IUARegistry.UASig memory qs = _sig(k2, n.payeeFeeDigest(x, 5, a3, vu));
        vm.broadcast(k2);
        n.mtxPayWithPayeeFee(x, ps, 5, a3, vu, qs, m);
    }

    /// @dev `RelayFeeRouter.relay`: its executor runs a relayed `mtxTransfer`, then the payer's `UARelayFee` of 1 to the
    ///      router, which forwards it to the caller (Smoke.s.sol's open mode).
    function _relay() internal {
        NormalToken n = NormalToken(t);
        MetaTxLib.UAMetaTransfer memory x = _tr(_pad(a3), 1, 0);
        bytes memory cd = abi.encodeCall(NormalToken.mtxTransfer,
            (x.from, x.to, 1, 0, x.nonce, vu, uint32(0), address(0), _sig(k1, n.mtxTransferDigest(x))));
        uint256 fn = _nonce(LANE_FEE);
        bytes32 payee = _pad(router);
        bytes32 d = _digest(t, keccak256(abi.encode(UA_RELAY_FEE, _pad(a1), t, keccak256(cd), payee, uint256(1), LANE_FEE,
            fn, vu, router)));
        IUARegistry.UASig memory s = _sig(k1, d);
        vm.broadcast(k2);
        RelayFeeRouter(router).relay(t, cd, t, _pad(a1), payee, 1, LANE_FEE, fn, vu, s);
        require(_nonce(LANE_FEE) == fn + 1, "relay fee lane");
    }

    function _cancels() internal {
        NormalToken n = NormalToken(t);
        vm.broadcast(k1);
        n.cancelNonce(81);
        MetaTxLib.UAEnvelope memory e = _env(a1, 7, _nonce(7));
        IUARegistry.UASig memory s = _sig(k1, _named(t, UA_CANCEL_NONCE, abi.encode(uint256(82)), e));
        vm.broadcast(k2);
        n.mtxCancelNonce(e, 82, s);
        require(_nonce(82) == 1, "lane 82 cancelled");
        uint256 newMin = n.minNonce(_pad(a1), 3) + 3;
        s = _sig(k1, n.invalidateNoncesDigest(_pad(a1), 3, newMin));
        vm.broadcast(k2);
        n.mtxInvalidateNonces(_pad(a1), 3, newMin, s);
        require(n.minNonce(_pad(a1), 3) == newMin, "minNonce");
    }

    // ------------------------------------------------------------------ TAX (kinds 8-11, pay-meta-tax spec §6)

    function _tax() internal {
        NormalRegulatedToken r = NormalRegulatedToken(t);
        vm.startBroadcast(k1);
        r.setTaxRate(10_000); // 1 %; a rise waits noticePeriod(), 0 on this factory
        // a fixed limit: RegulatedBase refuses the registry check below COMPLIANCE_REGISTRY_GAS x 64/63 + margin left
        // (ComplianceRegistryGasStarved(50000, 54362) at forge's simulated 51,440 x 2.00 on a fresh anvil): gasUsed is not that floor
        r.setTaxRecipient{gas: 500_000}(_pad(a3));
        vm.stopBroadcast();
        IRegulatedToken.TaxConfig memory tc = r.taxConfig();
        require(tc.effectivePpm == 10_000, "tax rate");
        MetaTxLib.PayMeta memory m = _nextMeta(false);
        vm.broadcast(k1);
        r.payWithTax(_pad(a2), 1_000, 1, 10, _metaId(m), m); // PERCENT: 1,000 x 1 %
        m = _nextMeta(false);
        MetaTxLib.UAMetaTransfer memory x = _tr(_pad(a2), 1_000, 0);
        x.entryRef = _metaId(m);
        bytes32 sh = keccak256(abi.encode(MetaTxLib.UAMETATRANSFER_TYPEHASH, x.from, x.to, x.value, x.entryRef, x.batch,
            x.nonce, x.validUntil, x.mode, address(0), x.fee, address(0)));
        IUARegistry.UASig memory s =
            _sig(k1, _digest(t, keccak256(abi.encode(UA_PAY_WITH_TAX, sh, uint8(2), uint256(7)))));
        vm.broadcast(k2);
        r.mtxPayWithTax(x, 2, 7, s, m); // FIXED: 7
    }

    // ------------------------------------------------------------------ owner governance, direct (every kind, last)

    /// @dev Roles (grant, renounce, grant, revoke, a limited grant used once, cancel with nothing pending), ownership there
    ///      and back, `rescue`, `disableFeature`, then the holders revoked and the owner renounces.
    function _gov() internal {
        NormalToken n = NormalToken(t);
        uint8 mb = GovernanceBits.MINTABLE;
        IGovernance.GrantTerms memory g;
        (g.max, g.total) = (100, 1_000);
        vm.startBroadcast(k1);
        n.grantRole(mb, _pad(a2), IMetaTx(address(n)).chainUid());
        vm.stopBroadcast();
        vm.broadcast(k2);
        n.renounceRole(mb);
        vm.startBroadcast(k1);
        n.grantRole(mb, _pad(a2), IMetaTx(address(n)).chainUid());
        n.revokeRole(mb, _pad(a2), IMetaTx(address(n)).chainUid());
        n.setGrant(mb, _pad(a3), g, IMetaTx(address(n)).chainUid());
        n.cancelGrant(mb, _pad(a2), IMetaTx(address(n)).chainUid());
        vm.stopBroadcast();
        vm.broadcast(k3);
        n.mint(a3, 10); // the limited holder: `useLimited`
        bytes32 nu = n.chainUid(); // the token's chain word (CTR-GOV-27)
        vm.broadcast(k1);
        n.transferAdmin(_pad(a2), nu);
        vm.startBroadcast(k2);
        n.acceptAdmin();
        n.transferAdmin(_pad(a1), nu);
        vm.stopBroadcast();
        vm.startBroadcast(k1);
        n.acceptAdmin();
        stray.mint(t, 5);
        n.rescue(address(stray));
        vm.stopBroadcast();
        require(stray.balanceOf(a3) >= 5 && n.admin() == _pad(a1), "rescue, ownership");
        _govEnd(n);
    }

    function _govEnd(NormalToken n) internal {
        vm.startBroadcast(k1);
        if (_regulated(k)) {
            // MINTABLE stays (the MissingRole negative on kind 8); KYC off (`_regDisabled`; grantDelay 0: at once), the holders
            // revoked
            n.disableFeature(GovernanceBits.KYC, IMetaTx(address(n)).chainUid());
            n.revokeRole(GovernanceBits.MINTABLE, _pad(a1), IMetaTx(address(n)).chainUid());
            n.revokeRole(GovernanceBits.MINTABLE, _pad(a3), IMetaTx(address(n)).chainUid());
            n.revokeRole(GovernanceBits.TAX, _pad(a1), IMetaTx(address(n)).chainUid());
        } else {
            n.disableFeature(GovernanceBits.MINTABLE, IMetaTx(address(n)).chainUid());
        }
        n.renounceAdmin(n.chainUid());
        vm.stopBroadcast();
        require(n.admin() == 0, "renounced");
    }

    // ------------------------------------------------------------------ negatives (eth_call on the final state)

    function _negatives() internal {
        t = base;
        MetaTxLib.UAMetaTransfer memory x = _tr(_pad(a3), 1, 0);
        IUARegistry.UASig memory bad = _sig(k2, NormalToken(t).mtxTransferDigest(x)); // signed by another key
        _neg(a2, t, abi.encodeCall(NormalToken.mtxTransfer, (x.from, x.to, 1, 0, x.nonce, vu, uint32(0), address(0), bad)),
            IMetaTx.MetaTxBadSignature.selector, "mtxTransfer signed by another key");
        _neg(a2, t, abi.encodeCall(IERC20.transferFrom, (a1, a2, 1)), IERC20MetaTx.CallerNotContract.selector,
            "transferFrom by an EOA (CTR-TOK-01)");
        _neg(a2, t8, abi.encodeCall(NormalToken.mint, (a2, 1)), IGovernance.MissingRole.selector,
            "mint by a non-minter (kind 8, MINTABLE set)");
        // a wrapped-only selector on a NORMAL clone: no stub, no fallback, so the empty revert (the dispatcher refuses it)
        vm.writeLine(_negFile(), string.concat(vm.toString(a2), " ", vm.toString(t), " ",
            vm.toString(abi.encodeWithSignature("wrap(uint256)", uint256(1))), " 0x wrap(uint256) on a NORMAL token: empty revert"));
    }
}
