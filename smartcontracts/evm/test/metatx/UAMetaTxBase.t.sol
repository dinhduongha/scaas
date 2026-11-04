// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MtxDigest} from "../helpers/MtxDigest.sol";
import {UACall} from "../ua/UACall.sol";
import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {UAMetaTxBase} from "../../src/metatx/UAMetaTxBase.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {GasBurner1271} from "../v2/helpers/V2Fixture.sol";

/// A contract that is no token, on the UA path (owner ruling 2026-11-01): one allowlisted op that records its subject.
contract UAOnly is UAMetaTxBase {
    bytes32 public subject;
    address public sender;

    constructor(bytes32 uid, address reg, address ska) UAMetaTxBase("SCaaS UAOnly", uid, reg, ska, false) {}

    function poke() external nonReentrant {
        subject = _subject();
        sender = _msgSender();
    }

    /// `AMOUNT(0)`: a small amount rounds a PERCENT fee to 0.
    function pokeAmount(uint256) external nonReentrant {}

    function _mtxRule(bytes4 sel) internal view override returns (MtxRule memory) {
        if (sel == this.poke.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 4);
        if (sel == this.pokeAmount.selector) return MtxRule(FEE_CLASS_AMOUNT, 0, 36);
        return super._mtxRule(sel);
    }

    function _uaAllowed(bytes4 sel) internal view virtual override returns (bool) {
        return sel == this.poke.selector || sel == this.pokeAmount.selector;
    }
}

/// `cancelNonce` on the UA allowlist too: a contract may list it, it must not act on `UA_POOL`'s lane.
contract UACancelListed is UAOnly {
    constructor(bytes32 uid, address reg) UAOnly(uid, reg, address(0)) {}

    function _uaAllowed(bytes4 sel) internal view override returns (bool) {
        return sel == IMetaTx.cancelNonce.selector || super._uaAllowed(sel);
    }
}

/// A non-token that claims every fee mode but has no ledger: the default `_uaChargeFee` still refuses.
contract UAFeeModes is UAOnly {
    constructor(bytes32 uid, address reg) UAOnly(uid, reg, address(0)) {}

    function supportedModes() public pure override returns (uint32) {
        return MetaTxLib.MODE_KNOWN_MASK;
    }
}

contract UAMetaTxBaseTest is Test {
    uint256 constant PK = 0xA11CE;
    address constant REG = address(0x5CA);
    bytes32 constant UA = keccak256("a derived UA");
    uint32 constant FIX = MetaTxLib.MODE_FEE_FIXED;
    address signer = vm.addr(PK);
    UAOnly c;

    function setUp() public {
        vm.etch(REG, hex"00");
        vm.mockCall(REG, abi.encodeWithSelector(IUARegistry.requireAuthorized.selector), "");
        c = new UAOnly(keccak256("chain"), REG, address(0));
    }

    function _m(bytes32 from, uint256 nonce, uint32 mode, uint256 fee)
        internal view returns (MetaTxLib.UAMetaTransaction memory)
    {
        return MetaTxLib.UAMetaTransaction(from, abi.encodeCall(UAOnly.poke, ()), 0, nonce, block.timestamp + 300, mode,
            address(0), fee, address(0));
    }

    function _auth(MetaTxLib.UAMetaTransaction memory m) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, c.mtxDigest(m));
        return abi.encodePacked(r, s, v);
    }

    function test_uaBaseRefusesFee() public {
        // a native id at fee 0: the id as the subject, its address as the sender
        MetaTxLib.UAMetaTransaction memory m = _m(MetaTxLib.pad(signer), 0, 0, 0);
        c.mtxExecute(m, UACall.auth(m.from, _auth(m)));
        assertEq(c.subject(), MetaTxLib.pad(signer));
        assertEq(c.sender(), signer);
        assertEq(c.mtxNonce(m.from, 0), 1);

        // a derived UA: `_msgSender()` is the pool, only `_ticketSubject()` names it
        m = _m(UA, 0, 0, 0);
        c.mtxExecute(m, UACall.auth(m.from, abi.encode(bytes(""), bytes(hex"01"))));
        assertEq(c.subject(), UA);
        assertEq(c.sender(), MetaTxLib.UA_POOL);

        // a direct call: no ticket, the caller as an id
        vm.prank(address(0xCA11));
        c.poke();
        assertEq(c.subject(), MetaTxLib.pad(address(0xCA11)));

        // the default hook, on a contract that claims the mode: fee ≠ 0 has no ledger, the whole call reverts
        UAFeeModes f = new UAFeeModes(keccak256("chain"), REG);
        m = _m(MetaTxLib.pad(signer), 0, FIX, 1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, f.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, FIX));
        f.mtxExecute(m, UACall.auth(m.from, abi.encodePacked(r, s, v)));
        assertEq(f.mtxNonce(m.from, 0), 0);
    }

    /// `supportedModes()` rules both paths alike (0x03 here): a PERCENT fee that rounds to 0 runs on neither.
    function test_uaBaseModesAsAddressPath() public {
        uint32 mode = MetaTxLib.MODE_FEE_PERCENT;
        bytes memory data = abi.encodeCall(UAOnly.pokeAmount, (1));
        MetaTxLib.UAMetaTransaction memory u = _m(MetaTxLib.pad(signer), 0, mode, 1);
        u.data = data;
        bytes memory auth = _auth(u);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, mode));
        c.mtxExecute(u, UACall.auth(u.from, auth));

        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction(signer, data, 0, 0, block.timestamp + 300, mode,
            address(0), 1, address(0));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, MtxDigest.metaTx(address(c), m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, mode));
        c.executeMetaTransaction(m, abi.encodePacked(r, s, v));
    }

    /// A derived subject has no lane through `cancelNonce` (it would be `UA_POOL`'s); `mtxCancelNonce` is its cancel.
    /// (ua-mtx-merge T1, meaning: the unordered `uaCancelNonce`, refused twice by `UACancelUsed`, is now the ordered
    /// `mtxCancelNonce(UAEnvelope, lane, UASig)` on its own lane 3, refused twice by `MetaTxBadNonce`, Q2.)
    function test_uaBaseCancelNonce() public {
        UACancelListed l = new UACancelListed(keccak256("chain"), REG);
        MetaTxLib.UAMetaTransaction memory m = _m(UA, 0, 0, 0);
        m.data = abi.encodeCall(IMetaTx.cancelNonce, (9));
        bytes memory auth = abi.encode(bytes(""), bytes(hex"01"));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, IMetaTx.cancelNonce.selector));
        l.mtxExecute(m, UACall.auth(m.from, auth));
        assertEq(l.mtxNonce(MetaTxLib.pad(MetaTxLib.UA_POOL), 9), 0);

        MetaTxLib.UAEnvelope memory e = MetaTxLib.UAEnvelope(UA, 3, 0, block.timestamp + 300, 0, address(0), 0, address(0));
        vm.expectEmit(address(l));
        emit IUALedger.UANonceCancelled(UA, 9, 1);
        l.mtxCancelNonce(e, 9, UACall.auth(UA, auth));
        assertEq(l.mtxNonce(UA, 9), 1);
        assertEq(l.mtxNonce(UA, 3), 1);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        l.mtxCancelNonce(e, 9, UACall.auth(UA, auth));
    }

    /// The address path of a non-token takes the same `Ctx`: 400k for a `SmartKeyAccount` clone, 50k for any other wallet.
    /// (ua-mtx-merge T1: the address path is `executeMetaTransaction` here, MD-1.)
    function test_uaBaseAddressPathUsesCtx() public {
        GasBurner1271 impl = new GasBurner1271();
        UAOnly a = new UAOnly(keccak256("chain"), REG, address(impl));
        address[2] memory wallets = [Clones.clone(address(impl)), address(impl)];
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction(wallets[0], abi.encodeCall(UAOnly.poke, ()), 0, 0,
            block.timestamp + 300, 0, address(0), 0, address(0));
        a.executeMetaTransaction(m, bytes(hex"01"));
        assertEq(a.subject(), MetaTxLib.pad(wallets[0]));

        m.from = wallets[1];
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        a.executeMetaTransaction(m, bytes(hex"01"));
    }

    /// ua-mtx-merge T1 (C, R9), meaning: without a registry a native id runs (it was `UALedgerOff`); a derived one is
    /// `UALedgerOff` by name.
    function test_uaBaseOffWithoutRegistry() public {
        UAOnly off = new UAOnly(keccak256("chain"), address(0), address(0));
        MetaTxLib.UAMetaTransaction memory m = _m(MetaTxLib.pad(signer), 0, 0, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, off.mtxDigest(m));
        off.mtxExecute(m, UACall.auth(m.from, abi.encodePacked(r, s, v)));
        assertEq(off.sender(), signer);
        m = _m(UA, 0, 0, 0);
        vm.expectRevert(IUALedger.UALedgerOff.selector);
        off.mtxExecute(m, UACall.auth(m.from, abi.encode(bytes(""), bytes(hex"01"))));
    }

    /// A derived id runs only the `_uaAllowed` selectors; `cancelNonce` is on the address allowlist, not this one.
    /// (ua-mtx-merge T1, B, meaning: a native id reads `_mtxRule`, so its `cancelNonce` runs; it was `MetaTxUnknownOp`.)
    function test_uaBaseAllowlist() public {
        MetaTxLib.UAMetaTransaction memory m = _m(UA, 0, 0, 0);
        m.data = abi.encodeCall(IMetaTx.cancelNonce, (1));
        vm.expectRevert(abi.encodeWithSelector(IUALedger.MetaTxUnknownOp.selector, IMetaTx.cancelNonce.selector));
        c.mtxExecute(m, UACall.auth(m.from, abi.encode(bytes(""), bytes(hex"01"))));
        m = _m(MetaTxLib.pad(signer), 0, 0, 0);
        m.data = abi.encodeCall(IMetaTx.cancelNonce, (1));
        c.mtxExecute(m, UACall.auth(m.from, _auth(m)));
        assertEq(c.mtxNonce(MetaTxLib.pad(signer), 1), 1);
    }

    function test_uaBaseBatch() public {
        MetaTxLib.UAMetaTransaction[] memory ms = new MetaTxLib.UAMetaTransaction[](2);
        bytes[] memory auths = new bytes[](2);
        ms[0] = _m(MetaTxLib.pad(signer), 0, 0, 0);
        ms[1] = _m(UA, 0, 0, 0);
        auths[0] = _auth(ms[0]);
        auths[1] = abi.encode(bytes(""), bytes(hex"01"));
        assertTrue(c.mtxBatch(ms, UACall.auths(ms, auths)));
        assertEq(c.subject(), UA);
    }
}
