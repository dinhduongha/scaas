// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {MtxPipelineLib} from "../../src/metatx/MtxPipelineLib.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {FeePolicy} from "../../src/common/FeePolicy.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";

/// A token stand-in: every external function of the library, run by DELEGATECALL in this contract's context.
contract PipeHarness {
    function preCall(MtxPipelineLib.Ctx calldata c, MtxPipelineLib.Envelope calldata e,
        MtxPipelineLib.CallFacts calldata f, bool ua, bytes calldata auth) external returns (MtxPipelineLib.Out memory)
    {
        return MtxPipelineLib.preCall(c, e, f, ua, auth);
    }

    function preTransfer(MtxPipelineLib.Ctx calldata c, MetaTxLib.UAMetaTransfer calldata t, bool ua, uint256 have,
        bytes calldata auth) external returns (MtxPipelineLib.Out memory)
    {
        return MtxPipelineLib.preTransfer(c, t, ua, have, auth);
    }

    function callDigest(bytes32 ds, bytes32 typehash, MtxPipelineLib.Envelope calldata e)
        external pure returns (bytes32)
    {
        return MtxPipelineLib.callDigest(ds, typehash, e);
    }

    function transferDigest(bytes32 ds, bool ua, MetaTxLib.UAMetaTransfer calldata t) external pure returns (bytes32) {
        return MtxPipelineLib.transferDigest(ds, ua, t);
    }

    function nonce(bytes32 from, uint256 batch) external view returns (uint256) {
        return MtxPipelineLib._mtxStorage().nonce[from][batch];
    }
}

/// The UA registry as the library sees it: `kindOf` as set; `requireAuthorized` accepts exactly
/// `auth == abi.encode(purpose, digest)`, so a pass proves the purpose and the digest the library sent.
contract PipeRegistryMock {
    mapping(bytes32 => uint16) public kindOf;

    function setKind(bytes32 ua, uint16 k) external { kindOf[ua] = k; }

    function requireAuthorized(bytes32 ua, bytes32 purpose, bytes32 digest, bytes calldata auth) external pure {
        if (keccak256(auth) != keccak256(abi.encode(purpose, digest))) revert IUARegistry.UAUnauthorized(ua);
    }
}

/// MtxPipelineLib (metatx split, spec §3.2): the order of every check, the one written slot, the library guard and the
/// digests against `MetaTxLib`.
contract MtxPipelineLibTest is Test {
    uint256 internal constant ALICE_PK = 0xA11CE;
    address internal alice = vm.addr(ALICE_PK);
    address internal bob = address(0xB0B);
    bytes32 internal constant DS = keccak256("test domain separator");
    bytes32 internal constant UA = keccak256("a derived ua");   // top 96 bits non-zero
    bytes4 internal constant SEL = 0x12345678;

    PipeHarness internal h;
    PipeRegistryMock internal reg;

    function setUp() public {
        vm.warp(1_800_000_000);
        h = new PipeHarness();
        reg = new PipeRegistryMock();
        reg.setKind(UA, UAKinds.P256);
    }

    // ---------------------------------------------------------------- helpers

    function _ctx() internal view returns (MtxPipelineLib.Ctx memory) {
        return MtxPipelineLib.Ctx(DS, address(reg), bytes32(0), false);
    }

    function _env(bytes32 from) internal view returns (MtxPipelineLib.Envelope memory) {
        return MtxPipelineLib.Envelope(from, keccak256("data"), 7, 0, block.timestamp + 300,
            MetaTxLib.MODE_FEE_FIXED, address(0), 1, address(0));
    }

    /// AMOUNT(0) on a 36-byte static selector, basis 100 (fee cap 1).
    function _facts() internal pure returns (MtxPipelineLib.CallFacts memory) {
        return MtxPipelineLib.CallFacts(SEL, 36, 2, 0, 36, 100, true);
    }

    function _sig(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    function _signCall(MtxPipelineLib.Envelope memory e) internal view returns (bytes memory) {
        return _sig(ALICE_PK, h.callDigest(DS, MetaTxLib.METATX_TYPEHASH, e));
    }

    function _uaAuth(MtxPipelineLib.Envelope memory e) internal view returns (bytes memory) {
        return abi.encode(UAKinds.PURPOSE_METATX, h.callDigest(DS, MetaTxLib.UAMETATX_TYPEHASH, e));
    }

    function _tauth(MetaTxLib.UAMetaTransfer memory t) internal view returns (bytes memory) {
        return abi.encode(UAKinds.PURPOSE_METATX, h.transferDigest(DS, true, t));
    }

    function _xfer(bytes32 from, bytes32 to) internal view returns (MetaTxLib.UAMetaTransfer memory) {
        return MetaTxLib.UAMetaTransfer(from, to, 100, bytes32(0), 3, 0, block.timestamp + 300,
            MetaTxLib.MODE_FEE_FIXED, address(0), 1, address(0));
    }

    function _nonceSlot(bytes32 from, uint256 batch) internal pure returns (bytes32) {
        return keccak256(abi.encode(batch, keccak256(abi.encode(from, MtxPipelineLib.STORAGE_SLOT))));
    }

    // ---------------------------------------------------------------- preCall

    /// Address path: envelope > signature > call shape > fee; `SelfSender` for `from == address(this)`.
    function test_preCall_orderAddressPath() public {
        MtxPipelineLib.Ctx memory c = _ctx();
        MtxPipelineLib.Envelope memory e = _env(MetaTxLib.pad(alice));
        MtxPipelineLib.CallFacts memory f = _facts();
        e.validUntil = block.timestamp - 1;  // envelope
        e.fee = 1000;                        // fee (cap 1)
        f.len = 40;                          // shape (static 36)
        bytes memory bad = _sig(0xBAD, keccak256("x"));

        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxExpired.selector, e.validUntil, block.timestamp));
        h.preCall(c, e, f, false, bad);

        e.validUntil = block.timestamp + 300;
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        h.preCall(c, e, f, false, bad);

        bytes memory sig = _signCall(e);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, SEL));
        h.preCall(c, e, f, false, sig);

        f.len = 36;
        vm.expectRevert(abi.encodeWithSelector(FeePolicy.FeeExceedsCap.selector, 1000, 1));
        h.preCall(c, e, f, false, sig);

        e.fee = 1;
        sig = _signCall(e);
        MtxPipelineLib.Out memory o = h.preCall(c, e, f, false, sig);
        assertEq(o.digest, h.callDigest(DS, MetaTxLib.METATX_TYPEHASH, e));
        assertEq(o.fee, 1);
        assertEq(o.feeTo, address(this)); // feeRecipient 0 = msg.sender (the relayer)
        assertEq(h.nonce(e.from, e.batch), 1);

        // from == the token: SelfSender, before the signature
        MtxPipelineLib.Envelope memory s = _env(MetaTxLib.pad(address(h)));
        vm.expectRevert(IMetaTx.SelfSender.selector);
        h.preCall(c, s, f, false, bad);
    }

    /// UA path: ledger on > envelope > authorize(PURPOSE_METATX) > MetaTxUnknownOp > call shape > fee (UA_POOL).
    function test_preCall_orderUaPath() public {
        MtxPipelineLib.Ctx memory c = _ctx();
        MtxPipelineLib.Envelope memory e = _env(UA);
        MtxPipelineLib.CallFacts memory f = _facts();
        e.nonce = 5;                       // envelope
        e.feeRecipient = MetaTxLib.UA_POOL; // fee
        f.uaAllowed = false;               // unknown op
        f.len = 40;                        // shape
        bytes memory bad = hex"00";

        c.registry = address(0);
        vm.expectRevert(IUALedger.UALedgerOff.selector);
        h.preCall(c, e, f, true, bad);
        c.registry = address(reg);

        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 0, 5));
        h.preCall(c, e, f, true, bad);

        e.nonce = 0;
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, UA));
        h.preCall(c, e, f, true, bad);

        bytes memory auth = _uaAuth(e);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.MetaTxUnknownOp.selector, SEL));
        h.preCall(c, e, f, true, auth);

        f.uaAllowed = true;
        f.len = 3;
        f.sel = 0x12345600;
        vm.expectRevert(abi.encodeWithSelector(IUALedger.MetaTxUnknownOp.selector, bytes4(0x12345600)));
        h.preCall(c, e, f, true, auth);

        f.sel = SEL;
        f.len = 40;
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, SEL));
        h.preCall(c, e, f, true, auth);

        f.len = 36;
        vm.expectRevert(IUALedger.UAPoolNotPayable.selector);
        h.preCall(c, e, f, true, auth);

        e.feeRecipient = bob;
        auth = _uaAuth(e);
        MtxPipelineLib.Out memory o = h.preCall(c, e, f, true, auth);
        assertEq(o.digest, h.callDigest(DS, MetaTxLib.UAMETATX_TYPEHASH, e));
        assertEq(o.fee, 1);
        assertEq(o.feeTo, bob);
        assertEq(h.nonce(UA, e.batch), 1);

        // a native id on the UA path: its own signature (CTR-UA-24), id 0 refused (C5-2)
        MtxPipelineLib.Envelope memory n = _env(MetaTxLib.pad(alice));
        h.preCall(c, n, f, true, _sig(ALICE_PK, h.callDigest(DS, MetaTxLib.UAMETATX_TYPEHASH, n)));
        assertEq(h.nonce(n.from, n.batch), 1);
        MtxPipelineLib.Envelope memory z = _env(bytes32(0));
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, bytes32(0)));
        h.preCall(c, z, f, true, bad);
    }

    /// R7: a passing `preCall` / `preTransfer` writes one slot, the lane's nonce, and nothing in the library's account.
    function test_preCall_writesOnlyTheNonceSlot() public {
        MtxPipelineLib.Ctx memory c = _ctx();
        MtxPipelineLib.CallFacts memory f = _facts();
        MtxPipelineLib.Envelope memory e = _env(MetaTxLib.pad(alice));
        bytes memory sig = _signCall(e);
        MtxPipelineLib.Envelope memory u = _env(UA);
        bytes memory auth = _uaAuth(u);
        MetaTxLib.UAMetaTransfer memory t = _xfer(UA, MetaTxLib.pad(bob));
        bytes memory tauth = _tauth(t);

        _expectOneWrite(abi.encodeCall(PipeHarness.preCall, (c, e, f, false, sig)), _nonceSlot(e.from, e.batch));
        _expectOneWrite(abi.encodeCall(PipeHarness.preCall, (c, u, f, true, auth)), _nonceSlot(UA, u.batch));
        _expectOneWrite(abi.encodeCall(PipeHarness.preTransfer, (c, t, true, 101, tauth)), _nonceSlot(UA, t.batch));
    }

    function _expectOneWrite(bytes memory call, bytes32 slot) internal {
        vm.record();
        (bool ok,) = address(h).call(call);
        assertTrue(ok);
        (, bytes32[] memory writes) = vm.accesses(address(h));
        assertEq(writes.length, 1);
        assertEq(writes[0], slot);
        (, writes) = vm.accesses(address(MtxPipelineLib));
        assertEq(writes.length, 0);
    }

    // ---------------------------------------------------------------- preTransfer

    /// Today's `_executeTransfer` / `_uaExecuteTransfer` steps 1–4, with `have` for the balance read.
    function test_preTransfer_matchesTodayOrder() public {
        MtxPipelineLib.Ctx memory c = _ctx();

        // address path (padded ids)
        MetaTxLib.UAMetaTransfer memory t = _xfer(MetaTxLib.pad(alice), bytes32(0));
        t.mode |= MetaTxLib.MODE_RESTRICT_RELAYER;
        t.relayer = bob; // envelope
        t.fee = 1000;    // fee (cap 1)
        bytes memory bad = _sig(0xBAD, keccak256("x"));

        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnauthorizedRelayer.selector, bob, address(this)));
        h.preTransfer(c, t, false, 0, bad);

        t.relayer = address(this);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        h.preTransfer(c, t, false, 0, bad);

        bytes memory sig = _sig(ALICE_PK, h.transferDigest(DS, false, t));
        vm.expectRevert(IERC20MetaTx.PayToZero.selector);
        h.preTransfer(c, t, false, 0, sig);

        t.to = MetaTxLib.pad(bob);
        sig = _sig(ALICE_PK, h.transferDigest(DS, false, t));
        vm.expectRevert(abi.encodeWithSelector(FeePolicy.FeeExceedsCap.selector, 1000, 1));
        h.preTransfer(c, t, false, 0, sig);

        t.fee = 1;
        t.feeRecipient = bob;
        sig = _sig(ALICE_PK, h.transferDigest(DS, false, t));
        vm.expectRevert(IERC20MetaTx.FeeRecipientIsPayee.selector);
        h.preTransfer(c, t, false, 0, sig);

        t.feeRecipient = address(0);
        sig = _sig(ALICE_PK, h.transferDigest(DS, false, t));
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.MetaTxInsufficientForFee.selector, 101, 100));
        h.preTransfer(c, t, false, 100, sig);

        MtxPipelineLib.Out memory o = h.preTransfer(c, t, false, 101, sig);
        assertEq(o.digest, h.transferDigest(DS, false, t));
        assertEq(o.fee, 1);
        assertEq(o.feeTo, address(this));
        assertEq(h.nonce(t.from, t.batch), 1);

        vm.expectRevert(IMetaTx.SelfSender.selector);
        h.preTransfer(c, _xfer(MetaTxLib.pad(address(h)), MetaTxLib.pad(bob)), false, 101, bad);

        // UA path: ledger on > envelope > authorize > receiver (registry) > fee > balance
        MetaTxLib.UAMetaTransfer memory u = _xfer(UA, keccak256("unregistered"));
        u.validUntil = block.timestamp - 1;
        c.registry = address(0);
        vm.expectRevert(IUALedger.UALedgerOff.selector);
        h.preTransfer(c, u, true, 0, bad);
        c.registry = address(reg);

        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxExpired.selector, u.validUntil, block.timestamp));
        h.preTransfer(c, u, true, 0, bad);

        u.validUntil = block.timestamp + 300;
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, UA));
        h.preTransfer(c, u, true, 0, bad);

        bytes memory auth = _tauth(u);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, u.to));
        h.preTransfer(c, u, true, 0, auth);

        u.to = keccak256("non-signing");
        reg.setKind(u.to, UAKinds.EVM_EOA);
        auth = _tauth(u);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UAKindNotAccepted.selector, u.to, UAKinds.EVM_EOA));
        h.preTransfer(c, u, true, 0, auth);

        u.to = MetaTxLib.pad(bob);
        u.feeRecipient = MetaTxLib.SHIELD_POOL;
        auth = _tauth(u);
        vm.expectRevert(IUALedger.ShieldPoolNotPayable.selector);
        h.preTransfer(c, u, true, 0, auth);

        u.feeRecipient = address(0);
        auth = _tauth(u);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.MetaTxInsufficientForFee.selector, 101, 0));
        h.preTransfer(c, u, true, 0, auth);

        o = h.preTransfer(c, u, true, 101, auth);
        assertEq(o.digest, h.transferDigest(DS, true, u));
        assertEq(o.fee, 1);
        assertEq(h.nonce(UA, u.batch), 1);
    }

    // ---------------------------------------------------------------- the library guard and the digests

    /// R6: a plain CALL of a state-changing entry reverts (solc's library call guard); a view entry answers.
    function test_directCallReverts() public {
        address lib = address(MtxPipelineLib);
        assertGt(lib.code.length, 0);
        MtxPipelineLib.Ctx memory c = _ctx();
        MtxPipelineLib.CallFacts memory f = _facts();
        MtxPipelineLib.Envelope memory e = _env(MetaTxLib.pad(alice));
        bytes memory sig = _signCall(e);
        MetaTxLib.UAMetaTransfer memory t = _xfer(UA, MetaTxLib.pad(bob));
        bytes memory tauth = _tauth(t);

        (bool ok,) = lib.call(abi.encodeWithSelector(MtxPipelineLib.preCall.selector, c, e, f, false, sig));
        assertFalse(ok);
        (ok,) = lib.call(abi.encodeWithSelector(MtxPipelineLib.preTransfer.selector, c, t, true, 101, tauth));
        assertFalse(ok);

        // the same arguments pass by DELEGATECALL, so the guard is what refused them
        h.preCall(c, e, f, false, sig);
        h.preTransfer(c, t, true, 101, tauth);

        bytes memory ret;
        (ok, ret) = lib.call(abi.encodeWithSelector(MtxPipelineLib.callDigest.selector, DS, MetaTxLib.METATX_TYPEHASH, e));
        assertTrue(ok);
        assertEq(abi.decode(ret, (bytes32)), h.callDigest(DS, MetaTxLib.METATX_TYPEHASH, e));
    }

    /// R2: `callDigest` / `transferDigest` equal `MetaTxLib` hashing of the same struct, for both typehashes each.
    function test_digestsEqualMetaTxLib(MetaTxLib.MetaTransaction memory m, MetaTxLib.MetaTransfer memory t, bytes32 ua)
        public view
    {
        MtxPipelineLib.Envelope memory e = MtxPipelineLib.Envelope(MetaTxLib.pad(m.from), keccak256(m.data), m.batch,
            m.nonce, m.validUntil, m.mode, m.relayer, m.fee, m.feeRecipient);
        assertEq(h.callDigest(DS, MetaTxLib.METATX_TYPEHASH, e),
            MessageHashUtils.toTypedDataHash(DS, MetaTxLib.hashStruct(m)));

        e.from = ua;
        MetaTxLib.UAMetaTransaction memory um = MetaTxLib.UAMetaTransaction(ua, m.data, m.batch, m.nonce, m.validUntil,
            m.mode, m.relayer, m.fee, m.feeRecipient);
        assertEq(h.callDigest(DS, MetaTxLib.UAMETATX_TYPEHASH, e),
            MessageHashUtils.toTypedDataHash(DS, MetaTxLib.hashStruct(um)));

        MetaTxLib.UAMetaTransfer memory ut = MetaTxLib.UAMetaTransfer(MetaTxLib.pad(t.from), MetaTxLib.pad(t.to),
            t.value, t.entryRef, t.batch, t.nonce, t.validUntil, t.mode, t.relayer, t.fee, t.feeRecipient);
        assertEq(h.transferDigest(DS, false, ut), MessageHashUtils.toTypedDataHash(DS, MetaTxLib.hashStruct(t)));

        ut.from = ua;
        assertEq(h.transferDigest(DS, true, ut), MessageHashUtils.toTypedDataHash(DS, MetaTxLib.hashStruct(ut)));
    }
}
