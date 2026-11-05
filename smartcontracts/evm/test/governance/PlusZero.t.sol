// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IMetaTokenV2} from "../../src/metatx/IMetaTokenV2.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {NormalZetherToken} from "../../src/zether/NormalZetherToken.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {Catalogue} from "../helpers/Catalogue.sol";
import {UACall} from "../ua/UACall.sol";
import {UALedgerBase} from "../ua/UALedgerBase.sol";
import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";
import {ZetherKeys} from "../zether/helpers/ZetherKeys.sol";
import {PqzFixture} from "../pqz/helpers/PqzFixture.sol";
import {PQZ_UID} from "../pqz/helpers/PqzRegistryBase.sol";
import {GovRouterFixture} from "./GovRouter.t.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {IConfidentialToken, IConfidentialWrappedToken} from "../../src/confidential/IConfidentialToken.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {FeeMode} from "../../src/common/FeePolicy.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {DexLegs} from "../helpers/DexLegs.sol";
import {plainEnv, pqzEnv} from "../helpers/Catalogue.sol";
import {normalInit, wrappedInit, Rate} from "../v2/helpers/V2Fixture.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

/// @notice "+0" (CTR-GOV-11, spec §10.2, B-33): on every kind, `transfer`, `mtxTransfer`, `transferToUA`
///         (native → UA) and `mtxExecuteTransfer` (UA → UA, the `_uaMove` branch that skips `ERC20._update`) read and
///         write exactly the token slots pinned in `test/vectors/plus_zero_slots.json`, recorded at `2a864638`, before
///         any governance code. Not a range around a root: a mapping read lands at a hash. ua-mtx-merge T2: the rows
///         re-target the merged entries (an EOA's `mtxTransfer` is today's `uaTransfer` body, through `_uaMove`; the
///         `uaExecuteTransfer_*` rows run `mtxExecuteTransfer`); the pin file and its row names do not move (slots, not ABI).
///         Written against fixtures present on both sides.
///         `PLUS_ZERO_WRITE=true` records the pin; run it with `-j1`, each row merges into the one file.
abstract contract PlusZeroRows is Test {
    uint256 internal constant PZ_PK = 0xA11CE;
    address internal constant PZ_TO = address(0xCAFE);
    address internal constant PZ_RELAYER = address(0xBEEF);
    uint256 internal constant PZ_LANE = 1;
    string internal constant PZ_PIN = "test/vectors/plus_zero_slots.json";
    /// ua-mtx-merge T26 (regulated-kinds spec §8 I0, F-35): the gas of each row, pinned beside its slots; it moves only
    /// with old → new in the commit.
    string internal constant PZ_GAS = "test/vectors/plus_zero_gas.json";

    function _pzSigner() internal pure returns (address) { return vm.addr(PZ_PK); }

    /// The `auth` bytes of the derived UA `from` over `digest` (`UACall.auth` form), per fixture.
    function _pzAuth(bytes32 from, bytes32 digest) internal view virtual returns (bytes memory);

    /// Both sides of every row hold a balance and both lanes are past nonce 0, so no row pays a first write. The signer
    /// must hold units of `t`.
    function _pzPrime(address t, bytes32 a, bytes32 b) internal {
        address s = _pzSigner();
        _pzCall(t, s, abi.encodeWithSignature("transfer(address,uint256)", PZ_TO, 1), "prime transfer");
        _pzCall(t, PZ_RELAYER, _pzMtx(t, 0), "prime mtxTransfer");
        _pzCall(t, s, abi.encodeWithSignature("transferToUA(bytes32,uint256)", a, 10), "prime transferToUA a");
        _pzCall(t, s, abi.encodeWithSignature("transferToUA(bytes32,uint256)", b, 1), "prime transferToUA b");
        _pzCall(t, PZ_RELAYER, _pzUa(t, a, b), "prime mtxExecuteTransfer");
    }

    function _pzCall(address t, address sender, bytes memory cd, string memory label) internal {
        vm.prank(sender);
        (bool ok, bytes memory ret) = t.call(cd);
        if (!ok) {
            assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        }
        assertTrue(ok, label);
    }

    function _pzMtx(address t, uint256 nonce) internal view returns (bytes memory) {
        MetaTxLib.UAMetaTransfer memory x = MetaTxLib.UAMetaTransfer({from: MetaTxLib.pad(_pzSigner()),
            to: MetaTxLib.pad(PZ_TO), value: 1, entryRef: 0, batch: PZ_LANE, nonce: nonce,
            validUntil: block.timestamp + 600, mode: 0, relayer: address(0), fee: 0, feeRecipient: address(0)});
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PZ_PK, IERC20MetaTx(t).mtxTransferDigest(x));
        IUARegistry.UASig memory a;
        a.signature = abi.encodePacked(r, s, v);
        return abi.encodeCall(IMetaTokenV2.mtxTransfer,
            (x.from, x.to, x.value, x.batch, x.nonce, x.validUntil, x.mode, x.relayer, a));
    }

    function _pzUa(address t, bytes32 from, bytes32 to) internal view returns (bytes memory) {
        MetaTxLib.UAMetaTransfer memory x = MetaTxLib.UAMetaTransfer({from: from, to: to, value: 1, entryRef: 0,
            batch: PZ_LANE, nonce: NormalToken(t).mtxNonce(from, PZ_LANE), validUntil: block.timestamp + 600, mode: 0,
            relayer: address(0), fee: 0, feeRecipient: address(0)});
        IUARegistry.UASig memory sig = UACall.auth(from, _pzAuth(from, NormalToken(t).mtxTransferDigest(x)));
        return abi.encodeCall(IERC20MetaTx.mtxExecuteTransfer, (x, sig));
    }

    // ------------------------------------------------------------------ the four rows

    function _pzTransfer(string memory row, address t) internal {
        _pzRow(row, t, _pzSigner(), abi.encodeWithSignature("transfer(address,uint256)", PZ_TO, 1));
    }

    function _pzMtxTransfer(string memory row, address t) internal {
        _pzRow(row, t, PZ_RELAYER, _pzMtx(t, 1));
    }

    function _pzToUA(string memory row, address t, bytes32 a) internal {
        _pzRow(row, t, _pzSigner(), abi.encodeWithSignature("transferToUA(bytes32,uint256)", a, 1));
    }

    function _pzUaToUa(string memory row, address t, bytes32 a, bytes32 b) internal {
        _pzRow(row, t, PZ_RELAYER, _pzUa(t, a, b));
    }

    /// The call under `vm.record()`, then the sorted set of `t`'s read slots and of its written slots against the pin,
    /// and the call's gas (`vm.lastCallGas`, the isolated transaction) against its pin.
    function _pzRow(string memory row, address t, address sender, bytes memory cd) internal {
        vm.record();
        _pzCall(t, sender, cd, row);
        uint256 g = vm.lastCallGas().gasTotalUsed;
        (bytes32[] memory r, bytes32[] memory w) = vm.accesses(t);
        r = _pzSet(r);
        w = _pzSet(w);
        if (vm.envOr("PLUS_ZERO_WRITE", false)) {
            _pzWrite(row, r, w);
            _pzWriteGas(row, g);
            return;
        }
        string memory pin = vm.readFile(PZ_PIN);
        assertEq(r, vm.parseJsonBytes32Array(pin, string.concat(".", row, ".reads")), string.concat(row, ": reads"));
        assertEq(w, vm.parseJsonBytes32Array(pin, string.concat(".", row, ".writes")), string.concat(row, ": writes"));
        assertEq(g, vm.parseJsonUint(vm.readFile(PZ_GAS), string.concat(".", row)), string.concat(row, ": gas"));
    }

    function _pzWriteGas(string memory row, uint256 g) internal {
        if (vm.exists(PZ_GAS)) vm.serializeJson("pzg", vm.readFile(PZ_GAS));
        vm.writeJson(vm.serializeUint("pzg", row, g), PZ_GAS);
    }

    function _pzWrite(string memory row, bytes32[] memory r, bytes32[] memory w) internal {
        string memory o = string.concat("pz.", row);
        vm.serializeBytes32(o, "reads", r);
        string memory rowJson = vm.serializeBytes32(o, "writes", w);
        if (vm.exists(PZ_PIN)) vm.serializeJson("pz", vm.readFile(PZ_PIN));
        vm.writeJson(vm.serializeString("pz", row, rowJson), PZ_PIN);
    }

    /// Ascending, without repeats.
    function _pzSet(bytes32[] memory a) internal pure returns (bytes32[] memory s) {
        s = new bytes32[](a.length);
        uint256 n;
        for (uint256 i; i < a.length; ++i) {
            uint256 j = n;
            bool dup;
            for (uint256 k; k < n; ++k) if (s[k] == a[i]) dup = true;
            if (dup) continue;
            while (j != 0 && uint256(s[j - 1]) > uint256(a[i])) {
                s[j] = s[j - 1];
                --j;
            }
            s[j] = a[i];
            ++n;
        }
        assembly ("memory-safe") { mstore(s, n) }
    }
}

/// `NORMAL` and `WRAPPED`: the UA ledger fixture (two registered SIGNING UAs on the stand-in verifier).
contract PlusZeroPlainTest is PlusZeroRows, UALedgerBase {
    function setUp() public override {
        super.setUp();
        assertEq(alice, _pzSigner());
        _wrapFor(alice, 1_000);
        _pzPrime(address(tok), uaP, uaB);
        _pzPrime(address(wrp), uaP, uaB);
    }

    function _pzAuth(bytes32 from, bytes32 digest) internal view override returns (bytes memory) {
        return _authFor(from, digest);
    }

    function test_plusZero_transfer_normal() public { _pzTransfer("transfer_normal", address(tok)); }
    function test_plusZero_transfer_wrapped() public { _pzTransfer("transfer_wrapped", address(wrp)); }
    function test_plusZero_mtxTransfer_normal() public { _pzMtxTransfer("mtxTransfer_normal", address(tok)); }
    function test_plusZero_mtxTransfer_wrapped() public { _pzMtxTransfer("mtxTransfer_wrapped", address(wrp)); }
    function test_plusZero_transferToUA_normal() public { _pzToUA("transferToUA_normal", address(tok), uaP); }
    function test_plusZero_transferToUA_wrapped() public { _pzToUA("transferToUA_wrapped", address(wrp), uaP); }
    function test_plusZero_uaExecuteTransfer_normal() public {
        _pzUaToUa("uaExecuteTransfer_normal", address(tok), uaP, uaB);
    }
    function test_plusZero_uaExecuteTransfer_wrapped() public {
        _pzUaToUa("uaExecuteTransfer_wrapped", address(wrp), uaP, uaB);
    }
}

/// `NORMAL_ZETHER` and `WRAPPED_ZETHER`: two Zether UAs (SIGNING since UA-6) sign by Schnorr.
contract PlusZeroZetherTest is PlusZeroRows, ZetherFixture {
    address internal nz;
    address internal wz;

    function setUp() public {
        _stack();
        _users();
        nz = address(_newToken(false, "pz"));
        NormalZetherToken(nz).mint(_pzSigner(), 1_000_000);
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, _zenv(), type(WrappedZetherToken).creationCode);
        MockERC20 usd = new MockERC20("USD", "USD", 6);
        IFactoryToken.TokenConfig memory c = _cfg(false, uint256(1) << 40);
        c.features = 1; // PAYABLE
        c.lockedFeatures = 0; // the fixture locks MINTABLE for its minter (B-06); this token has neither
        c.roles.minter = 0;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        wz = factory.createToken(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, abi.encode(c), "pzw");
        usd.mint(_pzSigner(), 1_000e6);
        vm.startPrank(_pzSigner());
        usd.approve(wz, type(uint256).max);
        WrappedToken(payable(wz)).wrap(500e6);
        vm.stopPrank();
        _pzPrime(nz, _a(), _b());
        _pzPrime(wz, _a(), _b());
    }

    function _a() internal view returns (bytes32) { return ZetherTypes.UA.unwrap(alice.ua); }
    function _b() internal view returns (bytes32) { return ZetherTypes.UA.unwrap(bob.ua); }

    function _pzAuth(bytes32 from, bytes32 digest) internal view override returns (bytes memory) {
        uint256 x = from == _a() ? alice.x : bob.x;
        return abi.encode(bytes(""), ZetherKeys.schnorr(x, reg.uaMessage(_zkind(), UAKinds.PURPOSE_METATX, digest), bls));
    }

    function test_plusZero_transfer_normalZether() public { _pzTransfer("transfer_normalZether", nz); }
    function test_plusZero_transfer_wrappedZether() public { _pzTransfer("transfer_wrappedZether", wz); }
    function test_plusZero_mtxTransfer_normalZether() public { _pzMtxTransfer("mtxTransfer_normalZether", nz); }
    function test_plusZero_mtxTransfer_wrappedZether() public { _pzMtxTransfer("mtxTransfer_wrappedZether", wz); }
    function test_plusZero_transferToUA_normalZether() public { _pzToUA("transferToUA_normalZether", nz, _a()); }
    function test_plusZero_transferToUA_wrappedZether() public { _pzToUA("transferToUA_wrappedZether", wz, _a()); }
    function test_plusZero_uaExecuteTransfer_normalZether() public {
        _pzUaToUa("uaExecuteTransfer_normalZether", nz, _a(), _b());
    }
    function test_plusZero_uaExecuteTransfer_wrappedZether() public {
        _pzUaToUa("uaExecuteTransfer_wrappedZether", wz, _a(), _b());
    }
}

/// `NORMAL_PQZ` and `WRAPPED_PQZ`: two `mldsa65` UAs, the precompile candidate mocked.
contract PlusZeroPqzTest is PlusZeroRows, PqzFixture {
    address internal np;
    address internal wp;

    function setUp() public {
        _stack();
        np = address(_newToken("pz"));
        NormalPqzToken(np).mint(_pzSigner(), 1_000_000);
        _releaseWrapped();
        MockERC20 usd = new MockERC20("USD", "USD", 6);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.features = 1; // PAYABLE
        c.lockedFeatures = 0; // the fixture locks MINTABLE for its minter (B-06); this token has neither
        c.roles.minter = 0;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        wp = factory.createToken(IOpenFactory.TokenKind.WRAPPED_PQZ, 1, abi.encode(c), "pzw");
        usd.mint(_pzSigner(), 1_000e6);
        vm.startPrank(_pzSigner());
        usd.approve(wp, type(uint256).max);
        WrappedToken(payable(wp)).wrap(500e6);
        vm.stopPrank();
        _pzPrime(np, alice, bob);
        _pzPrime(wp, alice, bob);
    }

    function _pzAuth(bytes32, bytes32) internal pure override returns (bytes memory) {
        return _mlAuth();
    }

    function test_plusZero_transfer_normalPqz() public { _pzTransfer("transfer_normalPqz", np); }
    function test_plusZero_transfer_wrappedPqz() public { _pzTransfer("transfer_wrappedPqz", wp); }
    function test_plusZero_mtxTransfer_normalPqz() public { _pzMtxTransfer("mtxTransfer_normalPqz", np); }
    function test_plusZero_mtxTransfer_wrappedPqz() public { _pzMtxTransfer("mtxTransfer_wrappedPqz", wp); }
    function test_plusZero_transferToUA_normalPqz() public { _pzToUA("transferToUA_normalPqz", np, alice); }
    function test_plusZero_transferToUA_wrappedPqz() public { _pzToUA("transferToUA_wrappedPqz", wp, alice); }
    function test_plusZero_uaExecuteTransfer_normalPqz() public {
        _pzUaToUa("uaExecuteTransfer_normalPqz", np, alice, bob);
    }
    function test_plusZero_uaExecuteTransfer_wrappedPqz() public {
        _pzUaToUa("uaExecuteTransfer_wrappedPqz", wp, alice, bob);
    }
}

/// The router (regulated-kinds spec §8 I0): it inherits `UAMetaTxBase`'s two hooks empty and never overrides them; its
/// own typed flow (`_uaCall`) is no seat, `mtxCancelNonce` is. Two rows, slots of the router and gas: a typed op
/// (`mtxMint` on a `NormalToken`) and the inherited `mtxCancelNonce`, each primed once so no row pays a first write.
contract PlusZeroRouterTest is PlusZeroRows, GovRouterFixture {
    uint256 internal constant PZ_CANCEL_LANE = 7;

    function _pzAuth(bytes32, bytes32) internal pure override returns (bytes memory) {
        return "";
    }

    function _rtMint(address t) internal view returns (bytes memory) {
        bytes memory w = abi.encode(PZ_TO, uint256(1));
        return _signed(router, OP_MINT, eoa, PZ_LANE, t, w, w);
    }

    function _rtCancel() internal view returns (bytes memory) {
        MetaTxLib.UAEnvelope memory e = _envelope(router, eoa, PZ_LANE);
        bytes32 h = keccak256(abi.encode(MetaTxLib.UA_CANCEL_NONCE_TYPEHASH, e.from, PZ_CANCEL_LANE, e.batch, e.nonce,
            e.validUntil, e.mode, address(0), e.fee, address(0)));
        IUARegistry.UASig memory a;
        a.signature = _ecdsa(eoa, keccak256(abi.encodePacked("\x19\x01", _domain(router), h)));
        return abi.encodeCall(router.mtxCancelNonce, (e, PZ_CANCEL_LANE, a));
    }

    function test_plusZero_mtxMint_router() public {
        address t = address(_normal(next, eoa, 0));
        _pzCall(address(router), PZ_RELAYER, _rtMint(t), "prime mtxMint");
        _pzRow("mtxMint_router", address(router), PZ_RELAYER, _rtMint(t));
    }

    function test_plusZero_mtxCancelNonce_router() public {
        _pzCall(address(router), PZ_RELAYER, _rtCancel(), "prime mtxCancelNonce");
        _pzRow("mtxCancelNonce_router", address(router), PZ_RELAYER, _rtCancel());
    }
}

// ---------------------------------------------------------------------------------------------- hook seats (T26)

/// `Seat(hook, a, b, c)`: the probe's override of `hook` reached while armed, with its raw arguments (spec §2.2).
error Seat(uint8 hook, bytes32 a, bytes32 b, uint256 c);

uint8 constant H_PRE = 0;      // (from, sel, mode)
uint8 constant H_FEE = 1;      // (feeTo, 0, fee)
uint8 constant H_MOVE = 2;     // (from, to, value)
uint8 constant H_PAYER = 3;    // (the payer as `_subject()` reads it, 0, 0)
uint8 constant H_SENDER = 4;   // (a, 0, 0)
uint8 constant H_NAME = 5;     // (beneficiary, 0, 0)
uint8 constant H_RECEIVER = 6; // (recipient, 0, 0)
uint8 constant H_ZSENDER = 7;  // (yFrom.x0, yFrom.y1, 0)
// keccak256("scaas.test.hookprobe.arm"): the probe's arm mask, in the clone's storage.
uint256 constant PROBE_ARM = 0x23070c0bf924c575ed5098b27678cd5707273ab3de0359eff8a77a21570ada71;

function _seat(uint8 h, bytes32 a, bytes32 b, uint256 c) view {
    uint256 armed;
    assembly ("memory-safe") { armed := sload(PROBE_ARM) }
    if ((armed >> h) & 1 != 0) revert Seat(h, a, b, c);
}

/// Test only: `arm(1 << hook)` makes that hook's override revert `Seat` (0 disarms).
abstract contract Armed {
    function arm(uint256 mask) external {
        assembly ("memory-safe") { sstore(PROBE_ARM, mask) }
    }
}

contract NormalProbe is NormalToken, Armed {
    constructor(uint16 v, Env memory env, bytes memory a) NormalToken(v, env, a) {}
    function _regPre(bytes32 f, bytes4 s, uint32 m) internal view override { _seat(H_PRE, f, bytes32(s), m); }
    function _regFeeTo(bytes32 t, uint256 f) internal view override { _seat(H_FEE, t, 0, f); }
    function _regMove(bytes32 f, bytes32 t, uint256 v) internal view override { _seat(H_MOVE, f, t, v); }
    function _regPayer() internal view override { _seat(H_PAYER, _subject(), 0, 0); }
    function _regSender(bytes32 a) internal view override { _seat(H_SENDER, a, 0, 0); }
    function _regName(bytes32 a) internal view override { _seat(H_NAME, a, 0, 0); }
    function _regReceiver(bytes32 a) internal view override { _seat(H_RECEIVER, a, 0, 0); }
}

contract WrappedProbe is WrappedToken, Armed {
    constructor(uint16 v, Env memory env, bytes memory a) WrappedToken(v, env, a) {}
    function _regPre(bytes32 f, bytes4 s, uint32 m) internal view override { _seat(H_PRE, f, bytes32(s), m); }
    function _regFeeTo(bytes32 t, uint256 f) internal view override { _seat(H_FEE, t, 0, f); }
    function _regMove(bytes32 f, bytes32 t, uint256 v) internal view override { _seat(H_MOVE, f, t, v); }
    function _regPayer() internal view override { _seat(H_PAYER, _subject(), 0, 0); }
    function _regSender(bytes32 a) internal view override { _seat(H_SENDER, a, 0, 0); }
    function _regName(bytes32 a) internal view override { _seat(H_NAME, a, 0, 0); }
    function _regReceiver(bytes32 a) internal view override { _seat(H_RECEIVER, a, 0, 0); }
}

contract NormalZetherProbe is NormalZetherToken, Armed {
    constructor(uint16 v, Env memory env, bytes memory a) NormalZetherToken(v, env, a) {}
    function _regPre(bytes32 f, bytes4 s, uint32 m) internal view override { _seat(H_PRE, f, bytes32(s), m); }
    function _regFeeTo(bytes32 t, uint256 f) internal view override { _seat(H_FEE, t, 0, f); }
    function _regMove(bytes32 f, bytes32 t, uint256 v) internal view override { _seat(H_MOVE, f, t, v); }
    function _regPayer() internal view override { _seat(H_PAYER, _subject(), 0, 0); }
    function _regSender(bytes32 a) internal view override { _seat(H_SENDER, a, 0, 0); }
    function _regName(bytes32 a) internal view override { _seat(H_NAME, a, 0, 0); }
    function _regReceiver(bytes32 a) internal view override { _seat(H_RECEIVER, a, 0, 0); }
    function _regZetherSender(G1 calldata y) internal view override { _seat(H_ZSENDER, y.x0, y.y1, 0); }
}

contract WrappedZetherProbe is WrappedZetherToken, Armed {
    constructor(uint16 v, Env memory env, bytes memory a) WrappedZetherToken(v, env, a) {}
    function _regPre(bytes32 f, bytes4 s, uint32 m) internal view override { _seat(H_PRE, f, bytes32(s), m); }
    function _regFeeTo(bytes32 t, uint256 f) internal view override { _seat(H_FEE, t, 0, f); }
    function _regMove(bytes32 f, bytes32 t, uint256 v) internal view override { _seat(H_MOVE, f, t, v); }
    function _regPayer() internal view override { _seat(H_PAYER, _subject(), 0, 0); }
    function _regSender(bytes32 a) internal view override { _seat(H_SENDER, a, 0, 0); }
    function _regName(bytes32 a) internal view override { _seat(H_NAME, a, 0, 0); }
    function _regReceiver(bytes32 a) internal view override { _seat(H_RECEIVER, a, 0, 0); }
    function _regZetherSender(G1 calldata y) internal view override { _seat(H_ZSENDER, y.x0, y.y1, 0); }
}

contract NormalPqzProbe is NormalPqzToken, Armed {
    constructor(uint16 v, Env memory env, bytes memory a) NormalPqzToken(v, env, a) {}
    function _regPre(bytes32 f, bytes4 s, uint32 m) internal view override { _seat(H_PRE, f, bytes32(s), m); }
    function _regFeeTo(bytes32 t, uint256 f) internal view override { _seat(H_FEE, t, 0, f); }
    function _regMove(bytes32 f, bytes32 t, uint256 v) internal view override { _seat(H_MOVE, f, t, v); }
    function _regPayer() internal view override { _seat(H_PAYER, _subject(), 0, 0); }
    function _regSender(bytes32 a) internal view override { _seat(H_SENDER, a, 0, 0); }
    function _regName(bytes32 a) internal view override { _seat(H_NAME, a, 0, 0); }
    function _regReceiver(bytes32 a) internal view override { _seat(H_RECEIVER, a, 0, 0); }
}

contract WrappedPqzProbe is WrappedPqzToken, Armed {
    constructor(uint16 v, Env memory env, bytes memory a) WrappedPqzToken(v, env, a) {}
    function _regPre(bytes32 f, bytes4 s, uint32 m) internal view override { _seat(H_PRE, f, bytes32(s), m); }
    function _regFeeTo(bytes32 t, uint256 f) internal view override { _seat(H_FEE, t, 0, f); }
    function _regMove(bytes32 f, bytes32 t, uint256 v) internal view override { _seat(H_MOVE, f, t, v); }
    function _regPayer() internal view override { _seat(H_PAYER, _subject(), 0, 0); }
    function _regSender(bytes32 a) internal view override { _seat(H_SENDER, a, 0, 0); }
    function _regName(bytes32 a) internal view override { _seat(H_NAME, a, 0, 0); }
    function _regReceiver(bytes32 a) internal view override { _seat(H_RECEIVER, a, 0, 0); }
}

/// Arms one hook of `t` and expects the next call to revert `Seat` with those arguments.
abstract contract SeatExpect is Test {
    function _arm(address t, uint8 h) internal {
        Armed(t).arm(uint256(1) << h);
    }

    function _expect(address t, uint8 h, bytes32 a, bytes32 b, uint256 c) internal {
        _arm(t, h);
        vm.expectRevert(abi.encodeWithSelector(Seat.selector, h, a, b, c));
    }

    /// Armed on `h`, the call reverts but not at that seat (the seat is not on this path).
    function _notSeat(address t, uint8 h, address sender, bytes memory cd) internal {
        _arm(t, h);
        vm.prank(sender);
        (bool ok, bytes memory ret) = t.call(cd);
        assertTrue(ok || bytes4(ret) != Seat.selector, "seat reached");
    }
}

/// `test_hookSeatsCalled` (regulated-kinds spec §2.2, §3.2; plan T26): a probe of each plain kind overrides every hook to
/// revert `Seat` when armed, so each seat of the spec's tables is shown reached, with the raw arguments of the table,
/// direct and relayed. A probe holds no other change: the bases are the built kinds.
contract HookSeatsPlainTest is UALedgerBase, SeatExpect {
    NormalProbe internal np;
    WrappedProbe internal wp; // one leg: `tok` (a SCaaS ledger token, so a `UAWrapOrder` runs)

    function setUp() public override {
        super.setUp();
        np = NormalProbe(Clones.clone(address(new NormalProbe(1, plainEnv(address(this), address(0), chainUidA, REG_L, false), ""))));
        np.initialize(address(this), 1, abi.encode(normalInit("Probe", "PRB", 6, 1_000_000, alice, address(this))));
        wp = WrappedProbe(payable(Clones.clone(address(new WrappedProbe(1, plainEnv(address(this), address(0), chainUidA, REG_L, false), "")))));
        address[] memory us = new address[](1);
        uint256[] memory one = new uint256[](1);
        (us[0], one[0]) = (address(tok), 1);
        Rate memory fixedRate;
        wp.initialize(address(this), 1, abi.encode(wrappedInit(us, one, one, 6, fixedRate, address(0), address(0))));
        vm.prank(alice);
        np.transferToUA(uaP, 100);
    }

    function _env(bytes32 from, uint256 nonce, uint32 mode) internal view returns (MetaTxLib.UAEnvelope memory e) {
        (e.from, e.batch, e.nonce, e.validUntil, e.mode) = (from, 1, nonce, block.timestamp + 300, mode);
    }

    function _noSig() internal pure returns (IUARegistry.UASig memory) {}

    function _sigAlice(address t, bytes32 structHash) internal view returns (IUARegistry.UASig memory a) {
        a.signature = _ecdsa(ALICE_PK, MtxDigest.typed(t, structHash));
    }

    function _order(bytes32 destination, uint256 feePpm) internal view returns (ITradeToken.UAWrapOrder memory o) {
        (o.from, o.wrappedToken, o.amount, o.minMinted, o.minFill, o.fee) = (_pad(alice), address(wp), 1000, 1, 1000, feePpm);
        (o.relayer, o.destination, o.batch, o.nonce, o.validUntil) = (RELAYER, destination, 1, 1, block.timestamp + 300);
    }

    /// Direct entries: the ledger, the allowance, the pay entries, the wrap payer, the wrap order.
    function test_hookSeatsCalled() public {
        // _update
        _expect(address(np), H_MOVE, _pad(alice), _pad(bob), 1);
        vm.prank(alice);
        np.transfer(bob, 1);
        // _uaMove (native -> derived)
        _expect(address(np), H_MOVE, _pad(alice), uaP, 1);
        vm.prank(alice);
        np.transferToUA(uaP, 1);
        // approve, a contract caller
        _expect(address(np), H_PAYER, _pad(address(this)), 0, 0);
        np.approve(address(wp), 1);
        // payWithFee, payWithFeeToUA: the fee leg before the moves
        _expect(address(np), H_FEE, _pad(FEE_TO), 0, 5);
        vm.prank(alice);
        np.payWithFee(bob, 1000, FeeMode.FIXED, 5, FEE_TO, bytes32(0));
        _expect(address(np), H_FEE, _pad(FEE_TO), 0, 5);
        vm.prank(alice);
        np.payWithFeeToUA(uaP, 1000, FeeMode.FIXED, 5, FEE_TO, bytes32(0));
        // mtxPayReceiverFee: the fee recipient, before the payer's transfer
        MetaTxLib.UAMetaTransfer memory t = _t(_pad(alice), _pad(bob), 100);
        (t.entryRef, t.nonce) = (bytes32(uint256(9)), 0);
        t.batch = np.payLane(t.entryRef);
        _expect(address(np), H_FEE, _pad(FEE_TO), 0, 3);
        np.mtxPayReceiverFee(t, _noSig(), 3, FEE_TO, block.timestamp + 60, _noSig());
        // mtxRelayFee: the relay's payee and value
        _expect(address(np), H_FEE, uaB, 0, 7);
        np.mtxRelayFee(_pad(alice), address(0x1234), bytes32(0), uaB, 7, block.timestamp + 60, _noSig());
        // a wrap into another id: the payer; into the caller (positive control): no payer seat
        _expect(address(wp), H_PAYER, _pad(address(this)), 0, 0);
        wp.wrapToUA(address(tok), 1, uaP);
        _arm(address(wp), H_PAYER);
        tok.mint(address(this), 10);
        tok.approve(address(wp), 10);
        wp.wrap(address(tok), 10);
        // mtxWrapOrder: o.from when the destination is another id, before the pull; the submitter's fee after it
        _expect(address(wp), H_SENDER, _pad(alice), 0, 0);
        wp.mtxWrapOrder(address(tok), _order(uaB, 0), _noSig());
        ITradeToken.UAWrapOrder memory o = _order(bytes32(0), 3_000);
        IUARegistry.UASig memory oa;
        oa.signature = _ecdsa(ALICE_PK, tok.tradeOrderDigest(DexLegs.asTrade(o)));
        _arm(address(wp), H_SENDER); // destination 0: no sender seat; the fee seat stops it
        _expect(address(wp), H_FEE, _pad(RELAYER), 0, 3);
        vm.prank(RELAYER);
        wp.mtxWrapOrder(address(tok), o, oa);
        _arm(address(wp), H_SENDER);
        vm.prank(RELAYER);
        assertEq(wp.mtxWrapOrder(address(tok), o, oa), 1000);
    }

    /// Relayed entries: `_regPre` (no signature needed: it runs first) with the inner selector and the envelope's mode,
    /// then `_regFeeTo` after the pipeline, then the op's own seat inside the self-call.
    function test_hookSeatsCalledRelayed() public {
        _relayedGeneric(_pad(alice));
        _relayedCancelTyped(_pad(alice));
        _relayedAddress(_pad(alice));
    }

    function _relayedGeneric(bytes32 a) internal {
        // _uaExecute (mtxExecute): pre, fee, the burn's ledger seat; a derived signer's burn names the UA (the `ua` local)
        MetaTxLib.UAMetaTransaction memory m = _m(address(np), a, abi.encodeCall(NormalToken.burn, (1)));
        _expect(address(np), H_PRE, a, bytes32(NormalToken.burn.selector), RR);
        np.mtxExecute(m, _noSig());
        IUARegistry.UASig memory s = UACall.auth(a, _authM(address(np), m));
        _expect(address(np), H_FEE, _pad(RELAYER), 0, 0);
        vm.prank(RELAYER);
        np.mtxExecute(m, s);
        _expect(address(np), H_MOVE, a, 0, 1);
        vm.prank(RELAYER);
        np.mtxExecute(m, s);
        m = _m(address(np), uaP, abi.encodeCall(NormalToken.burn, (1)));
        s = UACall.auth(uaP, _authM(address(np), m));
        _expect(address(np), H_MOVE, uaP, 0, 1);
        vm.prank(RELAYER);
        np.mtxExecute(m, s);
        // mtxBatch: each item through _uaExecute
        MetaTxLib.UAMetaTransaction[] memory ms = new MetaTxLib.UAMetaTransaction[](1);
        IUARegistry.UASig[] memory ss = new IUARegistry.UASig[](1);
        ms[0] = _m(address(np), a, abi.encodeCall(NormalToken.burn, (1)));
        _expect(address(np), H_PRE, a, bytes32(NormalToken.burn.selector), RR);
        np.mtxBatch(ms, ss);
        // _namedCallUA (mtxBurn): the named op's selector
        _expect(address(np), H_PRE, a, bytes32(NormalToken.burn.selector), 0);
        np.mtxBurn(_env(a, 0, 0), 1, _noSig());
    }

    function _relayedCancelTyped(bytes32 a) internal {
        // mtxCancelNonce: pre (selector cancelNonce), then the fee seat after the pipeline
        MetaTxLib.UAEnvelope memory e = _env(a, np.mtxNonce(a, 1), 0);
        _expect(address(np), H_PRE, a, bytes32(IMetaTx.cancelNonce.selector), 0);
        np.mtxCancelNonce(e, 9, _noSig());
        IUARegistry.UASig memory cs = _sigAlice(address(np), keccak256(abi.encode(MetaTxLib.UA_CANCEL_NONCE_TYPEHASH, a,
            uint256(9), e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))));
        _expect(address(np), H_FEE, _pad(RELAYER), 0, 0);
        vm.prank(RELAYER);
        np.mtxCancelNonce(e, 9, cs);
        // _uaExecuteTransfer (mtxExecuteTransfer, mtxTransfer): pre with selector 0, fee, then the move
        MetaTxLib.UAMetaTransfer memory t = _t(a, _pad(bob), 2);
        t.nonce = np.mtxNonce(a, 1);
        _expect(address(np), H_PRE, a, 0, RR);
        np.mtxExecuteTransfer(t, _noSig());
        IUARegistry.UASig memory ts = UACall.auth(a, _authFor(a, np.mtxTransferDigest(t)));
        _expect(address(np), H_FEE, _pad(RELAYER), 0, 0);
        vm.prank(RELAYER);
        np.mtxExecuteTransfer(t, ts);
        _expect(address(np), H_MOVE, a, _pad(bob), 2);
        vm.prank(RELAYER);
        np.mtxExecuteTransfer(t, ts);
        _expect(address(np), H_PRE, a, 0, RR);
        np.mtxTransfer(a, _pad(bob), 2, 1, t.nonce, t.validUntil, RR, RELAYER, _noSig());
    }

    function _relayedAddress(bytes32 a) internal {
        // the address path: _execute (executeMetaTransaction), _namedCall (mtxWrap)
        MetaTxLib.MetaTransaction memory am = MetaTxLib.MetaTransaction(alice, abi.encodeCall(IMetaTx.cancelNonce, (9)),
            2, np.mtxNonce(a, 2), block.timestamp + 300, 0, address(0), 0, address(0));
        _expect(address(np), H_PRE, a, bytes32(IMetaTx.cancelNonce.selector), 0);
        np.executeMetaTransaction(am, "");
        bytes memory asig = _ecdsa(ALICE_PK, MtxDigest.metaTx(address(np), am));
        _expect(address(np), H_FEE, _pad(RELAYER), 0, 0);
        vm.prank(RELAYER);
        np.executeMetaTransaction(am, asig);
        MetaTxLib.Envelope memory we = MetaTxLib.Envelope(alice, 1, wp.mtxNonce(a, 1), block.timestamp + 300, 0,
            address(0), 0, address(0));
        bytes4 selWrap = bytes4(keccak256("wrap(uint256)"));
        _expect(address(wp), H_PRE, a, bytes32(selWrap), 0);
        wp.mtxWrap(we, 1, "");
        bytes32 wh = keccak256(abi.encode(keccak256("Wrap(address from,uint256 amount,uint256 batch,uint256 nonce,"
            "uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"), alice, uint256(1), we.batch,
            we.nonce, we.validUntil, we.mode, address(0), we.fee, address(0)));
        bytes memory wsig = _ecdsa(ALICE_PK, MtxDigest.typed(address(wp), wh));
        _expect(address(wp), H_FEE, _pad(RELAYER), 0, 0);
        vm.prank(RELAYER);
        wp.mtxWrap(we, 1, wsig);
        // _namedCallUA on the wrapper (mtxUnwrap): the inner unwrap selector
        _expect(address(wp), H_PRE, a, bytes32(bytes4(keccak256("unwrap(uint256,address,uint256)"))), 0);
        wp.mtxUnwrap(_env(a, 0, 0), 1, bob, 0, _noSig());
    }
}

/// The Zether seats (spec §4.1): before the proof, so a probe call with no valid proof reaches them.
contract HookSeatsZetherTest is ZetherFixture, SeatExpect {
    NormalZetherProbe internal nz;
    WrappedZetherProbe internal wz;
    MockERC20 internal usd;

    function setUp() public {
        _stack();
        _users();
        Catalogue.release(factory, IOpenFactory.TokenKind.NORMAL_ZETHER, 2, _zenv(), type(NormalZetherProbe).creationCode);
        nz = NormalZetherProbe(factory.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 2,
            abi.encode(_cfg(false, uint256(1) << 40)), "pz"));
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, _zenv(), type(WrappedZetherProbe).creationCode);
        usd = new MockERC20("USD", "USD", 6);
        IFactoryToken.TokenConfig memory c = _cfg(false, uint256(1) << 40);
        (c.features, c.lockedFeatures, c.roles.minter) = (1, 0, 0);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        wz = WrappedZetherProbe(payable(factory.createToken(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, abi.encode(c), "pzw")));
    }

    function _y(uint256 i) internal pure returns (IZetherToken.G1 memory y) {
        (y.x0, y.y1) = (bytes32(i), bytes32(i + 1));
    }

    function test_hookSeatsCalled() public {
        bytes32 ben = bytes32(uint256(0xBE));
        bytes32 me = MetaTxLib.pad(alice.evm);
        // shield: the payer
        _expect(address(nz), H_PAYER, me, 0, 0);
        vm.prank(alice.evm);
        nz.mtxShield(ZetherTypes.UA.unwrap(alice.ua), 1);
        // the three direct transfers: the sender from the raw G1, then the beneficiary, before the library
        IZetherToken.ZetherMulti memory t;
        (t.yFrom, t.beneficiaryUA) = (_y(11), ben);
        IZetherToken.ZetherSingle memory u;
        (u.yFrom, u.beneficiaryUA) = (_y(21), ben);
        _expect(address(nz), H_ZSENDER, bytes32(uint256(11)), bytes32(uint256(12)), 0);
        nz.mtxConfidentialTransfer(t, "");
        _expect(address(nz), H_NAME, ben, 0, 0);
        nz.mtxConfidentialTransfer(t, "");
        _expect(address(nz), H_ZSENDER, bytes32(uint256(11)), bytes32(uint256(12)), 0);
        nz.mtxConfidentialTransferCompact(t, "");
        _expect(address(nz), H_NAME, ben, 0, 0);
        nz.mtxConfidentialTransferCompact(t, "");
        _expect(address(nz), H_ZSENDER, bytes32(uint256(21)), bytes32(uint256(22)), 0);
        nz.mtxConfidentialTransferSingle(u, "");
        _expect(address(nz), H_NAME, ben, 0, 0);
        nz.mtxConfidentialTransferSingle(u, "");
        // unshield: sender, beneficiary, the recipient when the amount is not 0
        IZetherToken.ZetherBurn memory b;
        (b.yFrom, b.beneficiaryUA) = (_y(31), ben);
        bytes32 rcp = MetaTxLib.pad(bob.evm);
        _expect(address(nz), H_ZSENDER, bytes32(uint256(31)), bytes32(uint256(32)), 0);
        nz.mtxUnshield(b, 1, rcp, "");
        _expect(address(nz), H_NAME, ben, 0, 0);
        nz.mtxUnshield(b, 1, rcp, "");
        _expect(address(nz), H_RECEIVER, rcp, 0, 0);
        nz.mtxUnshield(b, 1, rcp, "");
        _notSeat(address(nz), H_RECEIVER, alice.evm, abi.encodeCall(IZetherToken.mtxUnshield, (b, 0, rcp, "")));
        // kind 11: wrap-shield's payer; unshield-unwrap's sender and beneficiary at the top
        _expect(address(wz), H_PAYER, me, 0, 0);
        vm.prank(alice.evm);
        wz.mtxWrapShield(address(usd), 1, ZetherTypes.UA.unwrap(alice.ua));
        IConfidentialWrappedToken.Unwrap memory x = IConfidentialWrappedToken.Unwrap(address(usd), rcp, 1, 0);
        _expect(address(wz), H_ZSENDER, bytes32(uint256(31)), bytes32(uint256(32)), 0);
        wz.mtxUnshieldUnwrap(b, x, "");
        _expect(address(wz), H_NAME, ben, 0, 0);
        wz.mtxUnshieldUnwrap(b, x, "");
    }

    /// The signed form reaches `_regPre` first with the inner op's selector.
    function test_hookSeatsCalledRelayed() public {
        bytes32 from = ZetherTypes.UA.unwrap(alice.ua);
        MetaTxLib.UAEnvelope memory e;
        (e.from, e.batch, e.validUntil) = (from, 1, block.timestamp + 300);
        IUARegistry.UASig memory none;
        _expect(address(nz), H_PRE, from, bytes32(IConfidentialToken.mtxShield.selector), 0);
        nz.mtxShield(e, from, 1, none);
    }
}

/// The PQZ seats (spec §4.2): first in `_single` / `_multi` / `_burn`, before `_pullShieldIn` and the proof.
contract HookSeatsPqzTest is PqzFixture, SeatExpect {
    NormalPqzProbe internal np;
    WrappedPqzProbe internal wp;
    MockERC20 internal usd;

    function setUp() public {
        _stack();
        Catalogue.release(factory, IOpenFactory.TokenKind.NORMAL_PQZ, 2,
            pqzEnv(address(factory), PQZ_UID, address(reg), address(pqv)), type(NormalPqzProbe).creationCode);
        np = NormalPqzProbe(factory.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 2, abi.encode(_cfg(uint256(1) << 40)), "pz"));
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_PQZ, 1,
            pqzEnv(address(factory), PQZ_UID, address(reg), address(pqv)), type(WrappedPqzProbe).creationCode);
        usd = new MockERC20("USD", "USD", 6);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        (c.features, c.lockedFeatures, c.roles.minter) = (1, 0, 0);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        wp = WrappedPqzProbe(payable(factory.createToken(IOpenFactory.TokenKind.WRAPPED_PQZ, 1, abi.encode(c), "pzw")));
        usd.mint(address(this), 1_000e6); // a reserve, so the unshield-unwrap's quote passes
        usd.approve(address(wp), type(uint256).max);
        wp.wrap(1_000e6);
    }

    function test_hookSeatsCalled() public {
        bytes32 ben = bytes32(uint256(0xBE));
        bytes32 me = MetaTxLib.pad(address(this));
        _expect(address(np), H_PAYER, me, 0, 0);
        np.mtxShield(alice, 1);
        IUARegistry.UASig memory none;
        // the four transfers: sender, beneficiary; the shieldIn payer only when shieldIn != 0
        IPqzToken.PqzMultiArgs memory t;
        (t.fromUA, t.beneficiaryUA) = (alice, ben);
        IPqzToken.PqzTransferArgs memory u;
        (u.fromUA, u.beneficiaryUA) = (alice, ben);
        _expect(address(np), H_SENDER, alice, 0, 0);
        np.mtxConfidentialTransfer(t, "", none, "");
        _expect(address(np), H_NAME, ben, 0, 0);
        np.mtxConfidentialTransferCompact(t, "", none, "");
        _expect(address(np), H_SENDER, alice, 0, 0);
        np.mtxConfidentialTransferSingle(u, "", none, "");
        _expect(address(np), H_NAME, ben, 0, 0);
        np.mtxConfidentialTransferSingleCompact(u, "", none, "");
        _notSeat(address(np), H_PAYER, address(this), abi.encodeCall(IPqzToken.mtxConfidentialTransferSingle, (u, "", none, "")));
        (t.shieldIn, u.shieldIn) = (1, 1);
        _expect(address(np), H_PAYER, me, 0, 0);
        np.mtxConfidentialTransfer(t, "", none, "");
        _expect(address(np), H_PAYER, me, 0, 0);
        np.mtxConfidentialTransferSingleCompact(u, "", none, "");
        // unshield: the recipient in the entry, sender, payer, beneficiary in `_burn`; a refresh names no sender
        IPqzToken.PqzBurnArgs memory b;
        (b.fromUA, b.beneficiaryUA, b.shieldIn) = (alice, ben, 1);
        bytes32 rcp = MetaTxLib.pad(address(0xB2));
        _expect(address(np), H_RECEIVER, rcp, 0, 0);
        np.mtxUnshield(b, 1, rcp, "", none, "");
        _expect(address(np), H_SENDER, alice, 0, 0);
        np.mtxUnshield(b, 1, rcp, "", none, "");
        _expect(address(np), H_PAYER, me, 0, 0);
        np.mtxUnshield(b, 1, rcp, "", none, "");
        _expect(address(np), H_NAME, ben, 0, 0);
        np.mtxUnshield(b, 0, 0, "", none, "");
        bytes memory refresh = abi.encodeCall(IPqzToken.mtxUnshield, (b, 0, bytes32(0), "", none, ""));
        _notSeat(address(np), H_SENDER, address(this), refresh);
        _notSeat(address(np), H_RECEIVER, address(this), refresh);
        // kind 13: wrap-shield's payer; unshield-unwrap's sender and beneficiary in `_burn`
        _expect(address(wp), H_PAYER, me, 0, 0);
        wp.mtxWrapShield(address(usd), 1, alice);
        IConfidentialWrappedToken.Unwrap memory x = IConfidentialWrappedToken.Unwrap(address(usd), rcp, 1, 0);
        _expect(address(wp), H_SENDER, alice, 0, 0);
        wp.mtxUnshieldUnwrap(b, x, "", none, "");
        _expect(address(wp), H_NAME, ben, 0, 0);
        wp.mtxUnshieldUnwrap(b, x, "", none, "");
    }

    function test_hookSeatsCalledRelayed() public {
        MetaTxLib.UAEnvelope memory e;
        (e.from, e.batch, e.validUntil) = (alice, 1, block.timestamp + 300);
        IUARegistry.UASig memory none;
        _expect(address(np), H_PRE, alice, bytes32(IConfidentialToken.mtxShield.selector), 0);
        np.mtxShield(e, alice, 1, none);
    }
}
