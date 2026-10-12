// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MtxFixture} from "../helpers/MtxFixture.sol";
import {MtxRegistryMock, ReenterHook} from "../helpers/MtxRegistryMock.sol";
import {Mock1271Wallet} from "../helpers/WalletMocks.sol";
import {MetaTxBase} from "../../src/metatx/MetaTxBase.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

contract Recorder {
    uint256 public hits;
    function ping() external { ++hits; }
}

/// CTR-MTX-16…19, CTR-MTX-22: the generic pipeline of `MetaTxBase` on a registry-like contract.
contract MetaTxBaseTest is MtxFixture {
    using MetaTxLib for MetaTxLib.MetaTransaction;

    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function _run(MetaTxLib.MetaTransaction memory m, bytes memory sig) internal returns (bytes memory) {
        vm.prank(relayer);
        return reg.mtxExecute(m, sig);
    }

    // ---------------------------------------------------------------- domain and digest

    function test_digestIsSaltedEip712() public view {
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("alice"), 1, 0);
        bytes32 sep = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS TestRegistry"), keccak256("1"), uint256(7622), address(reg), UID));
        assertEq(reg.mtxDigest(m), keccak256(abi.encodePacked(hex"1901", sep, m.hashStruct())));
        assertEq(reg.chainUid(), UID);
        (bytes1 fields,, string memory version,,, bytes32 salt,) = reg.eip712Domain();
        assertEq(fields, bytes1(0x1f));
        assertEq(version, "1");
        assertEq(salt, UID);
    }

    // ---------------------------------------------------------------- happy path

    function test_execute_runsTheCallAsTheSigner() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("alice"), 1, 0);
        bytes memory sig = _sign(ALICE_PK, m);
        vm.expectEmit(true, true, true, true, address(reg));
        emit IMetaTx.MetaTransactionExecuted(alice, relayer, 1, 0, reg.mtxDigest(m), relayer, 0);
        _run(m, sig);
        assertEq(reg.nameOf(alice), "alice");
        assertEq(reg.nameOf(relayer), "");
        assertEq(reg.mtxNonce(alice, 1), 1);
    }

    function test_execute_returnsTheInnerReturnData() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, abi.encodeCall(MtxRegistryMock.bump, (5)), 1, 0);
        assertEq(abi.decode(_run(m, _sign(ALICE_PK, m)), (uint256)), 5);
    }

    function test_alias_returnsTrue() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
        bytes memory sig = _sign(ALICE_PK, m);
        vm.prank(relayer);
        assertTrue(reg.executeMetaTransaction(m, sig));
        assertEq(reg.nameOf(alice), "a");
    }

    // ---------------------------------------------------------------- signature (step 2)

    function test_wrongSigner_refused() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
        bytes memory sig = _sign(BOB_PK, m);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _run(m, sig);
    }

    function test_highS_refused() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, reg.mtxDigest(m));
        bytes memory high = abi.encodePacked(r, bytes32(N - uint256(s)), v == 27 ? uint8(28) : uint8(27));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _run(m, high);
    }

    function test_erc1271_wallet() public {
        Mock1271Wallet w = new Mock1271Wallet(alice);
        MetaTxLib.MetaTransaction memory m = _m(address(w), _setName("wallet"), 1, 0);
        bytes memory sig = _sign(ALICE_PK, m);
        _run(m, sig);
        assertEq(reg.nameOf(address(w)), "wallet");

        w.setMode(Mock1271Wallet.Mode.WrongMagic);
        MetaTxLib.MetaTransaction memory m2 = _m(address(w), _setName("x"), 1, 1);
        bytes memory sig2 = _sign(ALICE_PK, m2);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _run(m2, sig2);
    }

    // ---------------------------------------------------------------- step 1: lanes, replay, expiry, relayer, mode

    function test_replay_refused() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
        bytes memory sig = _sign(ALICE_PK, m);
        _run(m, sig);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        _run(m, sig);
    }

    /// Anti-lock (networks/README.md#head-of-line): a stuck lane never blocks another lane.
    function test_lanesAreIndependent() public {
        MetaTxLib.MetaTransaction memory stuck = _m(alice, _setName("a"), 1, 3);
        bytes memory s1 = _sign(ALICE_PK, stuck);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 0, 3));
        _run(stuck, s1);
        MetaTxLib.MetaTransaction memory other = _m(alice, _setName("b"), 2, 0);
        _run(other, _sign(ALICE_PK, other));
        assertEq(reg.mtxNonce(alice, 1), 0);
        assertEq(reg.mtxNonce(alice, 2), 1);
        assertEq(reg.mtxNonce(bob, 2), 0);
    }

    function test_expired_refused() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
        m.validUntil = block.timestamp - 1;
        bytes memory sig = _sign(ALICE_PK, m);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxExpired.selector, block.timestamp - 1, block.timestamp));
        _run(m, sig);
        m.validUntil = block.timestamp;                          // inclusive
        _run(m, _sign(ALICE_PK, m));
    }

    function test_relayerBinding() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
        m.mode = MetaTxLib.MODE_RESTRICT_RELAYER;
        m.relayer = relayer;
        bytes memory sig = _sign(ALICE_PK, m);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnauthorizedRelayer.selector, relayer, bob));
        reg.mtxExecute(m, sig);
        _run(m, sig);
        assertEq(reg.nameOf(alice), "a");
    }

    /// Flags off ⇒ `relayer`/`feeRecipient` are hashed as 0: a submitter may rewrite them (NODE-LANE-10).
    function test_unboundFieldsAreNotSigned() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
        bytes memory sig = _sign(ALICE_PK, m);
        m.relayer = bob;
        m.feeRecipient = address(0xFEE);
        vm.expectEmit(true, true, true, true, address(reg));
        emit IMetaTx.MetaTransactionExecuted(alice, relayer, 1, 0, reg.mtxDigest(m), address(0xFEE), 0);
        _run(m, sig);
    }

    function test_unknownMode_refused() public {
        uint32[3] memory bad = [uint32(0x04), 0x30, 0x100];
        for (uint256 i; i < 3; ++i) {
            MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
            m.mode = bad[i];
            bytes memory sig = _sign(ALICE_PK, m);
            vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, bad[i]));
            _run(m, sig);
        }
    }

    function test_selfSender_refused() public {
        MetaTxLib.MetaTransaction memory m = _m(address(reg), _setName("a"), 1, 0);
        vm.expectRevert(IMetaTx.SelfSender.selector);
        _run(m, hex"");
    }

    // ---------------------------------------------------------------- step 3: allowlist and shape

    function test_notAllowlisted_refused() public {
        bytes[3] memory datas = [
            abi.encodeCall(MtxRegistryMock.whoAmI, ()),
            abi.encodeCall(IMetaTx.mtxExecute, (_m(alice, _setName("a"), 1, 0), hex"")),   // no nesting
            abi.encodeCall(IMetaTx.executeMetaTransaction, (_m(alice, _setName("a"), 1, 0), hex""))
        ];
        for (uint256 i; i < 3; ++i) {
            MetaTxLib.MetaTransaction memory m = _m(alice, datas[i], 1, 0);
            bytes memory sig = _sign(ALICE_PK, m);
            vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, bytes4(datas[i])));
            _run(m, sig);
        }
    }

    function test_dataShape_refused() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, hex"cfdd7a", 1, 0);   // 3 bytes
        bytes memory sig = _sign(ALICE_PK, m);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, bytes4(0xcfdd7a00)));
        _run(m, sig);

        bytes memory longBump = abi.encodePacked(abi.encodeCall(MtxRegistryMock.bump, (1)), uint8(0));
        m = _m(alice, longBump, 1, 0);
        sig = _sign(ALICE_PK, m);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, MtxRegistryMock.bump.selector));
        _run(m, sig);
    }

    function test_mtxSelectors_isPinnedAndMatchesTheRules() public view {
        (bytes4[] memory s, uint8[] memory c, uint8[] memory a) = reg.mtxSelectors();
        assertEq(s.length, 4);
        assertEq(s[0], IMetaTx.cancelNonce.selector);
        assertEq(s[1], MtxRegistryMock.setName.selector);
        assertEq(s[2], MtxRegistryMock.bump.selector);
        assertEq(s[3], MtxRegistryMock.poke.selector);
        for (uint256 i; i < s.length; ++i) {
            MetaTxBase.MtxRule memory r = reg.exposedRule(s[i]);
            assertEq(r.feeClass, c[i]);
            assertEq(r.amountArg, a[i]);
        }
        assertEq(reg.exposedRule(MtxRegistryMock.whoAmI.selector).feeClass, 0);
    }

    // ---------------------------------------------------------------- all or nothing

    function test_innerRevert_bubblesAndLeavesTheNonce() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, abi.encodeCall(MtxRegistryMock.bump, (0)), 1, 0);
        bytes memory sig = _sign(ALICE_PK, m);
        vm.expectRevert(MtxRegistryMock.ZeroBump.selector);
        _run(m, sig);
        assertEq(reg.mtxNonce(alice, 1), 0);
    }

    // ---------------------------------------------------------------- ticket and _msgSender (CTR-MTX-18)

    function test_msgSender_outsideTheSelfCall_isTheCaller() public {
        vm.prank(bob);
        reg.setName("bob");
        assertEq(reg.nameOf(bob), "bob");
        // after a self-call in the same transaction the ticket is cleared: `this` is just `msg.sender`
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
        _run(m, _sign(ALICE_PK, m));
        vm.prank(address(reg));
        assertEq(reg.whoAmI(), address(reg));
    }

    function test_directSelfCallWithoutTicket_isNotTheSigner() public {
        vm.prank(address(reg));
        reg.setName("self");
        assertEq(reg.nameOf(address(reg)), "self");
    }

    function test_ticketAdmitsOneSelfCall() public {
        bytes memory inner = _setName("twice");
        MetaTxLib.MetaTransaction memory m =
            _m(alice, abi.encodeCall(MtxRegistryMock.poke, (address(reg), inner)), 1, 0);
        bytes memory sig = _sign(ALICE_PK, m);
        vm.expectRevert(IMetaTx.Reentrancy.selector);
        _run(m, sig);
    }

    function test_reentryFromOutsideDuringTheSelfCall_refused() public {
        ReenterHook hook = new ReenterHook();
        MetaTxLib.MetaTransaction memory m = _m(
            alice, abi.encodeCall(MtxRegistryMock.poke, (address(hook), abi.encodeCall(ReenterHook.hit, (reg)))), 1, 0);
        bytes memory sig = _sign(ALICE_PK, m);
        vm.expectRevert(IMetaTx.Reentrancy.selector);
        _run(m, sig);
    }

    /// Every allowlisted function is `nonReentrant` (CTR-MTX-18): re-entered with the ticket spent, each reverts.
    function test_everyAllowlistedSelectorIsNonReentrant() public {
        (bytes4[] memory s,,) = reg.mtxSelectors();
        for (uint256 i; i < s.length; ++i) {
            MetaTxLib.MetaTransaction memory m =
                _m(alice, abi.encodeCall(MtxRegistryMock.poke, (address(reg), _sample(s[i]))), 1, 0);
            bytes memory sig = _sign(ALICE_PK, m);
            vm.expectRevert(IMetaTx.Reentrancy.selector);
            _run(m, sig);
        }
    }

    function _sample(bytes4 sel) internal view returns (bytes memory) {
        if (sel == IMetaTx.cancelNonce.selector) return abi.encodeCall(IMetaTx.cancelNonce, (9));
        if (sel == MtxRegistryMock.setName.selector) return _setName("x");
        if (sel == MtxRegistryMock.bump.selector) return abi.encodeCall(MtxRegistryMock.bump, (1));
        if (sel == MtxRegistryMock.poke.selector) return abi.encodeCall(MtxRegistryMock.poke, (address(reg), ""));
        revert("no sample for an allowlisted selector");
    }

    // ---------------------------------------------------------------- cancelNonce

    function test_cancelNonce_direct() public {
        MetaTxLib.MetaTransaction memory pending = _m(alice, _setName("a"), 7, 0);
        bytes memory sig = _sign(ALICE_PK, pending);
        vm.expectEmit(true, true, true, true, address(reg));
        emit IMetaTx.MetaNonceCancelled(alice, 7, 1);
        vm.prank(alice);
        reg.cancelNonce(7);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        _run(pending, sig);
    }

    /// A subject without gas cancels lane 7 by a signed self-call on lane 8.
    function test_cancelNonce_signedOnAnotherLane() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, abi.encodeCall(IMetaTx.cancelNonce, (7)), 8, 0);
        bytes memory sig = _sign(ALICE_PK, m);
        vm.expectEmit(true, true, true, true, address(reg));
        emit IMetaTx.MetaNonceCancelled(alice, 7, 1);
        _run(m, sig);
        assertEq(reg.mtxNonce(alice, 7), 1);
        assertEq(reg.mtxNonce(alice, 8), 1);
        assertEq(reg.mtxNonce(relayer, 7), 0);
    }

    // ---------------------------------------------------------------- fix round 1: binding end to end, alias conformance

    function test_feeRecipientBound_eventCarriesIt() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
        m.mode = MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT;
        m.feeRecipient = address(0xFEE);
        bytes memory sig = _sign(ALICE_PK, m);
        vm.expectEmit(true, true, true, true, address(reg));
        emit IMetaTx.MetaTransactionExecuted(alice, relayer, 1, 0, reg.mtxDigest(m), address(0xFEE), 0);
        _run(m, sig);
    }

    function test_feeRecipientBound_rewriteRefused() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
        m.mode = MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT;
        m.feeRecipient = address(0xFEE);
        bytes memory sig = _sign(ALICE_PK, m);
        m.feeRecipient = bob;
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _run(m, sig);
    }

    function test_relayerBound_otherSubmitterRefused_rewriteRefused() public {
        MetaTxLib.MetaTransaction memory m = _m(alice, _setName("a"), 1, 0);
        m.mode = MetaTxLib.MODE_RESTRICT_RELAYER;
        m.relayer = relayer;
        bytes memory sig = _sign(ALICE_PK, m);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnauthorizedRelayer.selector, relayer, bob));
        reg.mtxExecute(m, sig);
        m.relayer = bob;
        vm.prank(bob);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        reg.mtxExecute(m, sig);
    }

    function _alias(bytes memory data, uint256 nonce) internal {
        MetaTxLib.MetaTransaction memory m = _m(alice, data, 1, nonce);
        bytes memory sig = _sign(ALICE_PK, m);
        vm.prank(relayer);
        assertTrue(reg.executeMetaTransaction(m, sig));
    }

    /// metatx.md Conformance: every allowlisted selector also runs through the alias, each with an observable effect.
    function test_alias_everyAllowlistedSelector() public {
        Recorder rec = new Recorder();
        _alias(abi.encodeCall(IMetaTx.cancelNonce, (9)), 0);
        assertEq(reg.mtxNonce(alice, 9), 1);
        _alias(_setName("viaAlias"), 1);
        assertEq(reg.nameOf(alice), "viaAlias");
        _alias(abi.encodeCall(MtxRegistryMock.bump, (4)), 2);
        assertEq(reg.count(alice), 4);
        _alias(abi.encodeCall(MtxRegistryMock.poke, (address(rec), abi.encodeCall(Recorder.ping, ()))), 3);
        assertEq(rec.hits(), 1);
        assertEq(reg.mtxNonce(alice, 1), 4);
    }
}
