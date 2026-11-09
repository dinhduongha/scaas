// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {UAMetaTxBase, UAMetaTxBaseCore} from "../../src/metatx/UAMetaTxBase.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {SmartKeyAccount} from "../../src/account/SmartKeyAccount.sol";
import {MergeBase, IMergedT1} from "./MergedEntry.t.sol";

/// A contract on the UA path that is no token: one allowlisted op that records who it sees inside the self-call.
contract SubjectProbe is UAMetaTxBase {
    bytes32 public subject;
    address public sender;

    constructor(bytes32 uid, address reg) UAMetaTxBaseCore("SCaaS SubjectProbe", uid, reg, address(0), false) {}

    function poke() external nonReentrant {
        subject = _subject();
        sender = _msgSender();
    }

    function _mtxRule(bytes4 sel) internal view override returns (MtxRule memory) {
        if (sel == this.poke.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 4);
        return super._mtxRule(sel);
    }

    function _uaAllowed(bytes4 sel) internal view override returns (bool) {
        return sel == this.poke.selector;
    }
}

/// ua-mtx-merge T1, spec §8 invariants 1-4 and 6 on the generic entry and the cancel (plan T1 step 2).
contract MergeInvariantsTest is MergeBase {
    uint32 internal constant MODE_FIX = MetaTxLib.MODE_FEE_FIXED;

    function _burn(bytes32 from, uint256 nonce) internal view returns (MetaTxLib.UAMetaTransaction memory) {
        return _call(from, abi.encodeCall(NormalToken.burn, (1000)), 1, nonce);
    }

    function _members() internal pure returns (IUARegistry.MemberSig[] memory ms) {
        ms = new IUARegistry.MemberSig[](1);
        ms[0].sig = hex"01";
    }

    // ----- R17: a native id's `UASig` is `signature` only, on the generic and the named entries -----

    function test_nativeUASigWithKeyDataRefused() public {
        _r17(true);
    }

    function test_nativeUASigWithMembersRefused() public {
        _r17(false);
    }

    function _r17(bool keyData) internal {
        // generic
        MetaTxLib.UAMetaTransaction memory m = _burn(_pad(alice), 0);
        IUARegistry.UASig memory a = _sig(ALICE_PK, _callDigest(address(tok), m));
        (bool ok,) = _relay(address(tok), _execCd(m, a));
        assertTrue(ok, "positive control: generic");
        m.nonce = 1;
        a = _sig(ALICE_PK, _callDigest(address(tok), m));
        if (keyData) a.keyData = hex"01";
        else a.members = _members();
        bytes memory ret;
        (ok, ret) = _relay(address(tok), _execCd(m, a));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector), "generic");

        // named: the cancel
        MetaTxLib.UAEnvelope memory e = _env(_pad(alice), 2, 0);
        a = _sig(ALICE_PK, _cancelDigest(address(tok), e, 9));
        if (keyData) a.keyData = hex"01";
        else a.members = _members();
        (ok, ret) = _relay(address(tok), _cancelCd(e, 9, a));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector), "named");
        a.keyData = "";
        delete a.members;
        (ok,) = _relay(address(tok), _cancelCd(e, 9, a));
        assertTrue(ok, "positive control: named");
    }

    // ----- invariant 2: the canonical signed intent -----

    /// A signature over the canonical message (unbound `relayer` / `feeRecipient` as 0) verifies with non-zero values
    /// in calldata, and the fee goes where calldata says.
    function test_unboundRelayerAndFeeRecipientNotSigned() public {
        MetaTxLib.UAMetaTransaction memory m = _burn(_pad(alice), 0);
        (m.mode, m.fee) = (MODE_FIX, 10);
        m.feeRecipient = FEE_TO;
        bytes32 d = _callDigest(address(tok), m); // `MetaTxLib.hashStruct` zeroes both unbound fields
        MetaTxLib.UAMetaTransaction memory canonical = _copy(m);
        (canonical.relayer, canonical.feeRecipient) = (address(0), address(0));
        assertEq(d, _callDigest(address(tok), canonical), "both unbound");
        m.relayer = address(0x7777);
        uint256 before = tok.balanceOf(alice);
        (bool ok,) = _relay(address(tok), _execCd(m, _sig(ALICE_PK, d)));
        assertTrue(ok);
        assertEq(tok.balanceOf(FEE_TO), 10, "fee where calldata says");
        assertEq(tok.balanceOf(alice), before - 1010);
    }

    /// A client that signs a non-zero unbound value gets a refusal: the contract hashes it as 0.
    function test_clientSigningNonZeroUnboundIsRefused() public {
        MetaTxLib.UAMetaTransaction memory m = _burn(_pad(alice), 0);
        (m.mode, m.fee, m.feeRecipient, m.relayer) = (MODE_FIX, 10, FEE_TO, RELAYER);
        bytes32 raw = _dig(address(tok), keccak256(abi.encode(MetaTxLib.UAMETATX_TYPEHASH, m.from, keccak256(m.data),
            m.batch, m.nonce, m.validUntil, m.mode, m.relayer, m.fee, m.feeRecipient)));
        (bool ok, bytes memory ret) = _relay(address(tok), _execCd(m, _sig(ALICE_PK, raw)));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector));
        (ok,) = _relay(address(tok), _execCd(m, _sig(ALICE_PK, _callDigest(address(tok), m))));
        assertTrue(ok, "positive control: the canonical message");
    }

    /// Every bound field of the envelope and the operation: a change after signing is refused.
    function test_boundFieldChangedRefused() public {
        MetaTxLib.UAMetaTransaction memory m = _burn(_pad(alice), 0);
        uint32 bound = MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT | MODE_FIX;
        (m.mode, m.fee, m.feeRecipient, m.relayer) = (bound, 10, FEE_TO, RELAYER);
        IUARegistry.UASig memory a = _sig(ALICE_PK, _callDigest(address(tok), m));
        for (uint256 f; f < 8; ++f) {
            MetaTxLib.UAMetaTransaction memory x = _copy(m);
            address submitter = RELAYER;
            if (f == 0) x.from = _pad(bob);
            if (f == 1) x.data = abi.encodeCall(NormalToken.burn, (1001));
            if (f == 2) x.batch = 2;
            if (f == 3) x.validUntil += 1;
            if (f == 4) x.mode = MetaTxLib.MODE_RESTRICT_RELAYER | MODE_FIX;
            if (f == 5) (x.relayer, submitter) = (address(0x7777), address(0x7777));
            if (f == 6) x.fee = 9;
            if (f == 7) x.feeRecipient = address(0xFEE2);
            vm.prank(submitter);
            (bool ok, bytes memory ret) = address(tok).call(_execCd(x, a));
            assertFalse(ok, vm.toString(f));
            assertEq(ret, abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector), vm.toString(f));
        }
        vm.prank(RELAYER);
        (bool ok2,) = address(tok).call(_execCd(m, a));
        assertTrue(ok2, "positive control");
    }

    function _copy(MetaTxLib.UAMetaTransaction memory m) internal pure returns (MetaTxLib.UAMetaTransaction memory) {
        return MetaTxLib.UAMetaTransaction(m.from, m.data, m.batch, m.nonce, m.validUntil, m.mode, m.relayer, m.fee,
            m.feeRecipient);
    }

    // ----- invariant 3: retired and retained forms -----

    /// R3: a `MetaTransaction` signed for the old address `mtxExecute` runs through `executeMetaTransaction` (same struct,
    /// same domain); the address `mtxExecute` has no entry on a token.
    function test_oldMtxExecuteSignatureRunsThroughExecuteMetaTransaction() public {
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({from: alice,
            data: abi.encodeCall(IMetaTx.cancelNonce, (5)), batch: 1, nonce: 0, validUntil: block.timestamp + 600, mode: 0,
            relayer: address(0), fee: 0, feeRecipient: address(0)});
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, _dig(address(tok), MetaTxLib.hashStruct(m)));
        bytes memory sig = abi.encodePacked(r, s, v);
        uint256 snap = vm.snapshotState();
        vm.prank(RELAYER);
        assertTrue(tok.executeMetaTransaction(m, sig), "positive control");
        assertEq(_m(address(tok)).mtxNonce(_pad(alice), 5), 1);
        vm.revertToState(snap);
        bytes memory old = abi.encodeWithSignature(
            "mtxExecute((address,bytes,uint256,uint256,uint256,uint32,address,uint256,address),bytes)", m, sig);
        (bool ok,) = _relay(address(tok), old);
        assertFalse(ok, "no address mtxExecute on a token");
        assertEq(_m(address(tok)).mtxNonce(_pad(alice), 5), 0);
    }

    /// Q2: the unordered `uaCancelNonce` and its struct `UACancelNonce(bytes32 ua,uint256 batch,uint256 validUntil)` have
    /// no entry: the old selector reverts and an old-type signature does not verify on the new cancel.
    function test_oldUACancelNonceSignatureHasNoEntry() public {
        uint256 until = block.timestamp + 600;
        bytes32 oldD = _dig(address(tok), keccak256(abi.encode(
            keccak256("UACancelNonce(bytes32 ua,uint256 batch,uint256 validUntil)"), uaP, 9, until)));
        IUARegistry.UASig memory oldA = _authOf(uaP, oldD);
        (bool ok,) = _relay(address(tok), abi.encodeWithSignature(
            "uaCancelNonce(bytes32,uint256,uint256,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))", uaP, 9, until, oldA));
        assertFalse(ok, "old selector");
        MetaTxLib.UAEnvelope memory e = _env(uaP, 3, 0);
        (ok,) = _relay(address(tok), _cancelCd(e, 9, oldA));
        assertFalse(ok, "old struct on the new entry");
        assertEq(_m(address(tok)).mtxNonce(uaP, 9), 0);
        (ok,) = _relay(address(tok), _cancelCd(e, 9, _authOf(uaP, _cancelDigest(address(tok), e, 9))));
        assertTrue(ok, "positive control");
    }

    // ----- Q2 / R19: the cancel is nonce-ordered on its own lane -----

    function test_cancelIsNonceOrdered_native() public {
        _ordered(_pad(alice));
    }

    function test_cancelIsNonceOrdered_derived() public {
        _ordered(uaP);
    }

    /// A cancel signed at nonce n of lane 3, withheld; a newer op consumes n; the cancel then cannot land.
    function _ordered(bytes32 who) internal {
        MetaTxLib.UAEnvelope memory e = _env(who, 3, 0);
        bytes memory withheld = _cancelCd(e, 9, _authOf(who, _cancelDigest(address(tok), e, 9)));
        bytes memory op = who == uaP ? abi.encodeCall(NormalToken.burn, (0)) : abi.encodeCall(IMetaTx.cancelNonce, (4));
        MetaTxLib.UAMetaTransaction memory m = _call(who, op, 3, 0);
        (bool ok, bytes memory ret) = _relay(address(tok), _execCd(m, _authOf(who, _callDigest(address(tok), m))));
        assertTrue(ok, "the newer op");
        (ok, ret) = _relay(address(tok), withheld);
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        assertEq(_m(address(tok)).mtxNonce(who, 9), 0, "lane 9 untouched");
    }

    /// The lane is bumped for the signer itself (no self-call: a derived subject would be `UA_POOL` there).
    function test_cancelBumpsLaneForTheSubject() public {
        bytes32[2] memory who = [_pad(alice), uaP];
        for (uint256 i; i < 2; ++i) {
            MetaTxLib.UAEnvelope memory e = _env(who[i], 3, 0);
            bytes32 d = _cancelDigest(address(tok), e, 9);
            vm.expectEmit(address(tok));
            emit IUALedger.UANonceCancelled(who[i], 9, 1);
            vm.expectEmit(address(tok));
            emit IUALedger.UAMetaTransactionExecuted(who[i], RELAYER, 3, 0, d, RELAYER, 0);
            (bool ok,) = _relay(address(tok), _cancelCd(e, 9, _authOf(who[i], d)));
            assertTrue(ok);
            assertEq(_m(address(tok)).mtxNonce(who[i], 9), 1);
            assertEq(_m(address(tok)).mtxNonce(MetaTxLib.pad(POOL), 9), 0, "not the pool's lane");
            MetaTxLib.UAMetaTransaction memory late = _call(who[i], abi.encodeCall(IMetaTx.cancelNonce, (1)), 9, 0);
            bytes memory ret;
            (ok, ret) = _relay(address(tok), _execCd(late, _authOf(who[i], _callDigest(address(tok), late))));
            assertFalse(ok);
            assertEq(ret, abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0), "an op signed for the old nonce");
        }
    }

    /// Invariant 4: fee mode `NONE`, any submitter; a native with and without a registry, a derived one with.
    function test_cancelFeeZeroRelayable() public {
        address anyone = address(0x1234);
        MetaTxLib.UAEnvelope memory e = _env(_pad(alice), 3, 0);
        vm.prank(anyone);
        (bool ok,) = address(tok0).call(_cancelCd(e, 9, _sig(ALICE_PK, _cancelDigest(address(tok0), e, 9))));
        assertTrue(ok, "native, registry 0");
        vm.prank(anyone);
        (ok,) = address(tok).call(_cancelCd(e, 9, _sig(ALICE_PK, _cancelDigest(address(tok), e, 9))));
        assertTrue(ok, "native, registry");
        e.from = uaP;
        vm.prank(anyone);
        (ok,) = address(tok).call(_cancelCd(e, 9, _authOf(uaP, _cancelDigest(address(tok), e, 9))));
        assertTrue(ok, "derived, registry");
        e.from = uaB;
        vm.prank(anyone);
        bytes memory ret;
        (ok, ret) = address(tok0).call(_cancelCd(e, 9, _authOf(uaB, _cancelDigest(address(tok0), e, 9))));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IUALedger.UALedgerOff.selector), "derived, registry 0");
    }

    // ----- invariant 6: who the body sees -----

    function test_derivedSubjectIsPoolInSelfCall() public {
        SubjectProbe p = new SubjectProbe(chainUidA, REG_L);
        MetaTxLib.UAMetaTransaction memory m = _call(uaP, abi.encodeCall(SubjectProbe.poke, ()), 1, 0);
        (bool ok,) = _relay(address(p), _execCd(m, _authOf(uaP, _callDigest(address(p), m))));
        assertTrue(ok);
        assertEq(p.subject(), uaP);
        assertEq(p.sender(), POOL);
    }

    function test_nativeSubjectIsItselfInSelfCall() public {
        SubjectProbe p = new SubjectProbe(chainUidA, REG_L);
        MetaTxLib.UAMetaTransaction memory m = _call(_pad(alice), abi.encodeCall(SubjectProbe.poke, ()), 1, 0);
        (bool ok,) = _relay(address(p), _execCd(m, _sig(ALICE_PK, _callDigest(address(p), m))));
        assertTrue(ok);
        assertEq(p.subject(), _pad(alice));
        assertEq(p.sender(), alice);
    }

    // ----- C on the generic entry -----

    function test_noRegistryNativeGenericRuns() public {
        MetaTxLib.UAMetaTransaction memory m = _burn(_pad(alice), 0);
        uint256 before = tok0.balanceOf(alice);
        (bool ok,) = _relay(address(tok0), _execCd(m, _sig(ALICE_PK, _callDigest(address(tok0), m))));
        assertTrue(ok);
        assertEq(tok0.balanceOf(alice), before - 1000);
        SubjectProbe p = new SubjectProbe(chainUidA, address(0));
        m = _call(_pad(alice), abi.encodeCall(SubjectProbe.poke, ()), 1, 0);
        (ok,) = _relay(address(p), _execCd(m, _sig(ALICE_PK, _callDigest(address(p), m))));
        assertTrue(ok, "not a token");
        assertEq(p.sender(), alice);
    }

    function test_noRegistryDerivedIsLedgerOffByName() public {
        MetaTxLib.UAMetaTransaction memory m = _burn(uaP, 0);
        (bool ok, bytes memory ret) = _relay(address(tok0), _execCd(m, _authOf(uaP, _callDigest(address(tok0), m))));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IUALedger.UALedgerOff.selector));
    }

    // ----- `SmartKeyAccount` keeps its address surface, byte for byte (MD-1; Q6: the mandate wallets merged in T3b) -----

    /// keccak256 of the deployed code without its CBOR metadata tail, deployed at a fixed address (the immutables hold
    /// `address(this)`), recorded at `ref/pre-ua-mtx-merge` (9a4b8c5a). ua-mtx-merge T3b: the `MandateWallet` and
    /// `HederaMandateWallet` rows left (Q6 builds them in the merged form; `MandateWalletMerged.t.sol`).
    function test_walletsByteIdentical() public {
        bytes32 uid = keccak256("wallet-uid");
        address b = address(0xA002);
        deployCodeTo("SmartKeyAccount.sol:SmartKeyAccount", abi.encode(uid), b);
        assertEq(_codeHash(b), 0xd201866a71d652a5d6bb0a15bc64efa1cdedec3cf92ffe02e2441c67f48a5876, "SmartKeyAccount");
        // the artifact `deployCodeTo` reads is this contract's (compiled into this test)
        assertGt(type(SmartKeyAccount).creationCode.length, 0);
    }

    function _codeHash(address a) internal view returns (bytes32) {
        bytes memory c = a.code;
        uint256 meta = (uint256(uint8(c[c.length - 2])) << 8 | uint8(c[c.length - 1])) + 2;
        assembly ("memory-safe") { mstore(c, sub(mload(c), meta)) }
        return keccak256(c);
    }
}
