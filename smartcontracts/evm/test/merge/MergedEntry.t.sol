// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs} from "../../script/KindModules.sol";

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UALedgerBase} from "../ua/UALedgerBase.sol";
import {UACall} from "../ua/UACall.sol";
import {Mock1271Wallet} from "../helpers/WalletMocks.sol";
import {plainEnv} from "../helpers/Catalogue.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";

/// The merged entries of ua-mtx-merge T1, called by selector: these tests compile on the tree before T1 too, so each
/// one is red there on its own (plan T1 step 3).
interface IMergedT1 {
    function mtxNonce(bytes32 from, uint256 batch) external view returns (uint256);
    function mtxExecute(MetaTxLib.UAMetaTransaction calldata m, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function mtxBatch(MetaTxLib.UAMetaTransaction[] calldata ms, IUARegistry.UASig[] calldata auths)
        external returns (bool);
    function mtxCancelNonce(MetaTxLib.UAEnvelope calldata e, uint256 lane, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
}

interface SaltedDomain {
    function eip712Domain() external view returns (bytes1, string memory, string memory, uint256, address, bytes32,
        uint256[] memory);
}

/// The UA ledger fixture plus `tok0`, a `NORMAL` clone with no registry (`registry() == 0`), and the digests computed
/// here from the type strings and `eip712Domain()` (ERC-5267), not read from the token.
abstract contract MergeBase is UALedgerBase {
    bytes32 internal constant UA_CANCEL_NONCE_TYPEHASH = keccak256(
        "UACancelNonce(bytes32 from,uint256 lane,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");

    NormalToken internal tok0;

    function setUp() public virtual override {
        super.setUp();
        tok0 = NormalToken(EnvKit.clone(address(new NormalToken(address(this), kindArgs(0, address(this), ""))), EnvKit.env(chainUidA, address(0), address(0), false)));
        tok0.initialize(nid(address(this)), 1, abi.encode(normalInit("Zero", "ZRO", 6, 1_000_000, alice, address(this))));
        assertEq(tok0.registry(), address(0));
    }

    function _m(address t) internal pure returns (IMergedT1) {
        return IMergedT1(t);
    }

    /// The EIP-712 digest of `structHash` in `t`'s salted domain.
    function _dig(address t, bytes32 structHash) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt,) =
            SaltedDomain(t).eip712Domain();
        bytes32 ds = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256(bytes(name)), keccak256(bytes(version)), chainId, vc, salt));
        return keccak256(abi.encodePacked(hex"1901", ds, structHash));
    }

    /// ECDSA by `pk` over `d`, as a native id's `UASig` (signature only).
    function _sig(uint256 pk, bytes32 d) internal pure returns (IUARegistry.UASig memory a) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        a.signature = abi.encodePacked(r, s, v);
    }

    /// The `UASig` of `from` over `d` under `metatx`: a native id by its key, a derived one through the fixture.
    function _authOf(bytes32 from, bytes32 d) internal view returns (IUARegistry.UASig memory) {
        return UACall.auth(from, _authFor(from, d));
    }

    function _call(bytes32 from, bytes memory data, uint256 batch, uint256 nonce)
        internal view returns (MetaTxLib.UAMetaTransaction memory)
    {
        return MetaTxLib.UAMetaTransaction({from: from, data: data, batch: batch, nonce: nonce,
            validUntil: block.timestamp + 600, mode: 0, relayer: address(0), fee: 0, feeRecipient: address(0)});
    }

    function _callDigest(address t, MetaTxLib.UAMetaTransaction memory m) internal view returns (bytes32) {
        return _dig(t, MetaTxLib.hashStruct(m));
    }

    function _xfer(bytes32 from, bytes32 to, uint256 value, uint256 nonce)
        internal view returns (MetaTxLib.UAMetaTransfer memory)
    {
        return MetaTxLib.UAMetaTransfer({from: from, to: to, value: value, entryRef: 0, batch: 1, nonce: nonce,
            validUntil: block.timestamp + 600, mode: 0, relayer: address(0), fee: 0, feeRecipient: address(0)});
    }

    function _xferDigest(address t, MetaTxLib.UAMetaTransfer memory x) internal view returns (bytes32) {
        return _dig(t, MetaTxLib.hashStruct(x));
    }

    function _env(bytes32 from, uint256 batch, uint256 nonce) internal view returns (MetaTxLib.UAEnvelope memory e) {
        e.from = from;
        e.batch = batch;
        e.nonce = nonce;
        e.validUntil = block.timestamp + 600;
    }

    function _cancelDigest(address t, MetaTxLib.UAEnvelope memory e, uint256 lane) internal view returns (bytes32) {
        return _dig(t, keccak256(abi.encode(UA_CANCEL_NONCE_TYPEHASH, e.from, lane, e.batch, e.nonce, e.validUntil, e.mode,
            e.mode & MetaTxLib.MODE_RESTRICT_RELAYER != 0 ? e.relayer : address(0), e.fee,
            e.mode & MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT != 0 ? e.feeRecipient : address(0))));
    }

    /// A relayer that is no party (any submitter may relay at mode 0).
    function _relay(address t, bytes memory cd) internal returns (bool ok, bytes memory ret) {
        vm.prank(RELAYER);
        (ok, ret) = t.call(cd);
    }

    function _execCd(MetaTxLib.UAMetaTransaction memory m, IUARegistry.UASig memory a) internal pure returns (bytes memory) {
        return abi.encodeCall(IMergedT1.mtxExecute, (m, a));
    }

    function _cancelCd(MetaTxLib.UAEnvelope memory e, uint256 lane, IUARegistry.UASig memory a)
        internal pure returns (bytes memory)
    {
        return abi.encodeCall(IMergedT1.mtxCancelNonce, (e, lane, a));
    }

    function _xferCd(MetaTxLib.UAMetaTransfer memory x, IUARegistry.UASig memory a) internal pure returns (bytes memory) {
        return abi.encodeCall(IERC20MetaTx.mtxExecuteTransfer, (x, a));
    }
}

/// The merge spike's suite (docs/research/governance/prototype/merge-entries.md §4, T0's `test/merge`), ported to T1:
/// the generic entry and the cancel are the merged `mtxExecute` / `mtxCancelNonce`; a typed transfer runs the merged
/// body under its merged name `mtxExecuteTransfer` (T2). B: a native id signs with its own key and reads
/// `_mtxRule`; C: a registry only for a derived side.
contract MergedEntryTest is MergeBase {
    function test_eoaToEoa() public {
        MetaTxLib.UAMetaTransfer memory x = _xfer(_pad(alice), _pad(bob), 1, 0);
        bytes memory cd = _xferCd(x, _sig(ALICE_PK, _xferDigest(address(tok), x)));
        uint256 before = tok.balanceOf(alice);
        vm.expectCall(REG_L, bytes(""), 0); // no registry call at all
        vm.expectEmit(true, true, false, true, address(tok));
        emit IERC20.Transfer(alice, bob, 1);
        (bool ok,) = _relay(address(tok), cd);
        assertTrue(ok);
        assertEq(tok.balanceOf(alice), before - 1);
        assertEq(_m(address(tok)).mtxNonce(_pad(alice), 1), 1);
    }

    function test_eoaToUA() public {
        MetaTxLib.UAMetaTransfer memory x = _xfer(_pad(alice), uaP, 1, 0);
        bytes memory cd = _xferCd(x, _sig(ALICE_PK, _xferDigest(address(tok), x)));
        uint256 pool = tok.balanceOf(POOL);
        vm.expectCall(REG_L, bytes(""), 1); // one registry call: the receiver's `kindOf`
        vm.expectEmit(true, true, false, true, address(tok));
        emit IERC20.Transfer(alice, POOL, 1);
        vm.expectEmit(true, true, false, true, address(tok));
        emit IUALedger.UATransfer(_pad(alice), uaP, 1);
        (bool ok,) = _relay(address(tok), cd);
        assertTrue(ok);
        assertEq(tok.balanceOfUA(uaP), 1);
        assertEq(tok.balanceOf(POOL), pool + 1);
    }

    function test_badSignatureRefused() public {
        MetaTxLib.UAMetaTransfer memory x = _xfer(_pad(alice), _pad(bob), 1, 0);
        (bool ok, bytes memory ret) = _relay(address(tok), _xferCd(x, _sig(BOB_PK, _xferDigest(address(tok), x))));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector));
    }

    function test_replayRefused() public {
        MetaTxLib.UAMetaTransfer memory x = _xfer(_pad(alice), _pad(bob), 1, 0);
        bytes memory cd = _xferCd(x, _sig(ALICE_PK, _xferDigest(address(tok), x)));
        (bool ok,) = _relay(address(tok), cd);
        assertTrue(ok);
        (bool ok2, bytes memory ret) = _relay(address(tok), cd);
        assertFalse(ok2);
        assertEq(ret, abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
    }

    function test_unregisteredReceiverRefused() public {
        bytes32 id = keccak256("nobody");
        MetaTxLib.UAMetaTransfer memory x = _xfer(_pad(alice), id, 1, 0);
        (bool ok, bytes memory ret) = _relay(address(tok), _xferCd(x, _sig(ALICE_PK, _xferDigest(address(tok), x))));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IUALedger.UANotRegistered.selector, id));
    }

    /// One dispatch, `UAKinds.inNativeSpace`: any of the upper 96 bits set makes a derived id, which the EOA's key does
    /// not authorize (bit 160 included, so `from >> 160 < 2` is no native test).
    /// The refusal is the registry's own (the derived branch was taken), not a later check's.
    function test_derivedHighBitsAreNotTheEoa() public {
        uint8[3] memory bits = [160, 200, 255];
        for (uint256 i; i < bits.length; ++i) {
            bytes32 dirty = _pad(alice) | bytes32(uint256(1) << bits[i]);
            MetaTxLib.UAMetaTransfer memory x = _xfer(dirty, _pad(bob), 1, 0);
            bytes32 d = _xferDigest(address(tok), x);
            (bool ok, bytes memory ret) = _relay(address(tok), _xferCd(x, _sig(ALICE_PK, d)));
            assertFalse(ok, "derived");
            assertEq(ret, _registrySays(dirty, d), "the registry refused it");
            MetaTxLib.UAMetaTransaction memory m = _call(dirty, abi.encodeCall(IMetaTx.cancelNonce, (7)), 1, 0);
            d = _callDigest(address(tok), m);
            (ok, ret) = _relay(address(tok), _execCd(m, _sig(ALICE_PK, d)));
            assertFalse(ok, "derived, generic");
            assertEq(ret, _registrySays(dirty, d), "the registry refused it, generic");
        }
        assertEq(tok.balanceOf(bob), 0);
    }

    /// What the registry answers for `id`'s ECDSA-by-alice `UASig` over `d` under `metatx`: a revert, by its own error.
    function _registrySays(bytes32 id, bytes32 d) internal view returns (bytes memory ret) {
        bool ok;
        (ok, ret) = REG_L.staticcall(abi.encodeCall(IUARegistry.requireAuthorized,
            (id, UAKinds.PURPOSE_METATX, d, _sig(ALICE_PK, d))));
        assertFalse(ok, "the registry does not authorize it");
        assertGt(ret.length, 3);
    }

    function test_erc1271Holder() public {
        Mock1271Wallet w = new Mock1271Wallet(alice);
        vm.prank(alice);
        tok.transfer(address(w), 2);
        MetaTxLib.UAMetaTransfer memory x = _xfer(_pad(address(w)), _pad(bob), 1, 0);
        (bool ok,) = _relay(address(tok), _xferCd(x, _sig(ALICE_PK, _xferDigest(address(tok), x))));
        assertTrue(ok, "valid wallet");
        assertEq(tok.balanceOf(address(w)), 1);
        w.setMode(Mock1271Wallet.Mode.WrongMagic);
        x.nonce = 1;
        bytes memory ret;
        (ok, ret) = _relay(address(tok), _xferCd(x, _sig(ALICE_PK, _xferDigest(address(tok), x))));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector));
    }

    /// CTR-UA-24: a designator is an EOA: its own key signs, the delegate is never asked.
    function test_designatorSignsWithItsOwnKey() public {
        Mock1271Wallet delegate = new Mock1271Wallet(alice);
        vm.etch(alice, abi.encodePacked(hex"ef0100", address(delegate)));
        MetaTxLib.UAMetaTransfer memory x = _xfer(_pad(alice), _pad(bob), 1, 0);
        (bool ok,) = _relay(address(tok), _xferCd(x, _sig(ALICE_PK, _xferDigest(address(tok), x))));
        assertTrue(ok, "own key");
        x.nonce = 1;
        bytes memory ret;
        (ok, ret) = _relay(address(tok), _xferCd(x, _sig(BOB_PK, _xferDigest(address(tok), x))));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector));
    }

    /// B: the generic entry; a native id keeps the address allowlist (`cancelNonce` is not on the UA list).
    function test_nativeRunsAddressAllowlist() public {
        MetaTxLib.UAMetaTransaction memory m = _call(_pad(alice), abi.encodeCall(IMetaTx.cancelNonce, (7)), 1, 0);
        vm.expectEmit(address(tok));
        emit IMetaTx.MetaNonceCancelled(alice, 7, 1);
        (bool ok,) = _relay(address(tok), _execCd(m, _sig(ALICE_PK, _callDigest(address(tok), m))));
        assertTrue(ok);
        assertEq(_m(address(tok)).mtxNonce(_pad(alice), 7), 1);
    }

    /// B: the UA list stays closed for a derived id (inside the self-call it would be `UA_POOL`).
    function test_derivedStaysOnUAAllowlist() public {
        MetaTxLib.UAMetaTransaction memory m = _call(uaP, abi.encodeCall(IMetaTx.cancelNonce, (7)), 1, 0);
        (bool ok, bytes memory ret) = _relay(address(tok), _execCd(m, _authOf(uaP, _callDigest(address(tok), m))));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IUALedger.MetaTxUnknownOp.selector, IMetaTx.cancelNonce.selector));
    }

    /// Q2: the ordered cancel, `UACancelNonce(bytes32 from,uint256 lane,E)`, a native id by its own key.
    function test_nativeSignedCancel() public {
        bytes32 me = _pad(alice);
        MetaTxLib.UAEnvelope memory e = _env(me, 3, 0);
        (bool ok,) = _relay(address(tok), _cancelCd(e, 9, _sig(ALICE_PK, _cancelDigest(address(tok), e, 9))));
        assertTrue(ok);
        assertEq(_m(address(tok)).mtxNonce(me, 9), 1, "lane bumped");
        assertEq(_m(address(tok)).mtxNonce(me, 3), 1, "the cancel's own lane used");
    }

    /// Q2: ordered: the same signature twice is a bad nonce, not a second cancel.
    function test_signedCancelIsOrdered() public {
        MetaTxLib.UAEnvelope memory e = _env(_pad(alice), 3, 0);
        bytes memory cd = _cancelCd(e, 9, _sig(ALICE_PK, _cancelDigest(address(tok), e, 9)));
        (bool ok,) = _relay(address(tok), cd);
        assertTrue(ok);
        (bool ok2, bytes memory ret) = _relay(address(tok), cd);
        assertFalse(ok2);
        assertEq(ret, abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        assertEq(_m(address(tok)).mtxNonce(_pad(alice), 9), 1);
    }

    /// Q2: a derived id cancels through the registry under the named op's purpose (MD-5).
    function test_derivedSignedCancel() public {
        MetaTxLib.UAEnvelope memory e = _env(uaP, 3, 0);
        (bool ok,) = _relay(address(tok), _cancelCd(e, 9, _authOf(uaP, _cancelDigest(address(tok), e, 9))));
        assertTrue(ok);
        assertEq(_m(address(tok)).mtxNonce(uaP, 9), 1);
        assertEq(_m(address(tok)).mtxNonce(uaP, 3), 1);
    }

    /// R17: a native id's `UASig` carries `signature` only.
    function test_nativeKeyDataRefused() public {
        MetaTxLib.UAMetaTransfer memory x = _xfer(_pad(alice), _pad(bob), 1, 0);
        IUARegistry.UASig memory a = _sig(ALICE_PK, _xferDigest(address(tok), x));
        a.keyData = hex"01";
        (bool ok, bytes memory ret) = _relay(address(tok), _xferCd(x, a));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector));
    }

    // ----- registry() == 0 (C): a native side runs, a derived side is `UALedgerOff` by name -----

    function test_noRegistry_eoaToEoa() public {
        MetaTxLib.UAMetaTransfer memory x = _xfer(_pad(alice), _pad(bob), 1, 0);
        (bool ok,) = _relay(address(tok0), _xferCd(x, _sig(ALICE_PK, _xferDigest(address(tok0), x))));
        assertTrue(ok);
        assertEq(tok0.balanceOf(bob), 1);
    }

    function test_noRegistry_badSignatureRefused() public {
        MetaTxLib.UAMetaTransfer memory x = _xfer(_pad(alice), _pad(bob), 1, 0);
        (bool ok, bytes memory ret) = _relay(address(tok0), _xferCd(x, _sig(BOB_PK, _xferDigest(address(tok0), x))));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector));
    }

    function test_noRegistry_derivedReceiverIsLedgerOff() public {
        MetaTxLib.UAMetaTransfer memory x = _xfer(_pad(alice), keccak256("ua"), 1, 0);
        (bool ok, bytes memory ret) = _relay(address(tok0), _xferCd(x, _sig(ALICE_PK, _xferDigest(address(tok0), x))));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IUALedger.UALedgerOff.selector));
    }

    function test_noRegistry_derivedSenderIsLedgerOff() public {
        MetaTxLib.UAMetaTransfer memory x = _xfer(keccak256("ua"), _pad(bob), 1, 0);
        (bool ok, bytes memory ret) = _relay(address(tok0), _xferCd(x, _sig(ALICE_PK, _xferDigest(address(tok0), x))));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IUALedger.UALedgerOff.selector));
    }

    /// CTR-GOV-11 (no new read): the merged typed transfer of a native id touches exactly the slots of the address
    /// path's `mtxExecuteTransfer` for the same transfer (one nonce map, natives padded). ua-mtx-merge T2, meaning: the
    /// address path left the token; its slots for this transfer (alice's and bob's balance, the nonce of lane
    /// `(pad(alice), 1)`), recorded on it at the base (`6cdf0758`), are the pin.
    function test_slotsOfMergedTransferEqualAddressPath() public {
        MetaTxLib.UAMetaTransfer memory x = _xfer(_pad(alice), _pad(bob), 1, 0);
        bytes memory cd = _xferCd(x, _sig(ALICE_PK, _xferDigest(address(tok), x)));
        vm.record();
        (bool ok,) = _relay(address(tok), cd);
        assertTrue(ok, "merged");
        (bytes32[] memory r1, bytes32[] memory w1) = vm.accesses(address(tok));
        bytes32[] memory addressPath = new bytes32[](3);
        addressPath[0] = 0x3e51255cb1bb00175ac5829aeae2de3038ee9661d1f2e130f759cb14952986b4;
        addressPath[1] = 0x950250a79e3b9137c3c756dfa8d78e0f7e6d9001071d50ef0991bfb17dbda752;
        addressPath[2] = 0xc5751e02acbc50610d5b3010ffb7baf66e6d701d3dd4d0f94758ac96870d70ad;
        assertEq(_sorted(r1), addressPath, "reads");
        assertEq(_sorted(w1), addressPath, "writes");
    }

    /// The distinct slots of `a`, ascending.
    function _sorted(bytes32[] memory a) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](a.length);
        uint256 n;
        for (uint256 i; i < a.length; ++i) {
            bool seen;
            for (uint256 j; j < n; ++j) if (out[j] == a[i]) seen = true;
            if (!seen) out[n++] = a[i];
        }
        assembly ("memory-safe") { mstore(out, n) }
        for (uint256 i = 1; i < n; ++i) {
            for (uint256 j = i; j > 0 && out[j - 1] > out[j]; --j) (out[j - 1], out[j]) = (out[j], out[j - 1]);
        }
    }
}
