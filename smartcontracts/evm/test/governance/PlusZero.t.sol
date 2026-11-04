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

    /// The call under `vm.record()`, then the sorted set of `t`'s read slots and of its written slots against the pin.
    function _pzRow(string memory row, address t, address sender, bytes memory cd) internal {
        vm.record();
        _pzCall(t, sender, cd, row);
        (bytes32[] memory r, bytes32[] memory w) = vm.accesses(t);
        r = _pzSet(r);
        w = _pzSet(w);
        if (vm.envOr("PLUS_ZERO_WRITE", false)) {
            _pzWrite(row, r, w);
            return;
        }
        string memory pin = vm.readFile(PZ_PIN);
        assertEq(r, vm.parseJsonBytes32Array(pin, string.concat(".", row, ".reads")), string.concat(row, ": reads"));
        assertEq(w, vm.parseJsonBytes32Array(pin, string.concat(".", row, ".writes")), string.concat(row, ": writes"));
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
