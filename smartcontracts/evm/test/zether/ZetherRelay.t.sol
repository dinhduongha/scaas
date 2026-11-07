// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {console2} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ZetherFixture, ZUID} from "./helpers/ZetherFixture.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {Mock1271Wallet} from "../helpers/WalletMocks.sol";
import {IConfidentialToken} from "../../src/confidential/IConfidentialToken.sol";

/// @notice Zether through the one meta-transaction base (CTR-ZTH-34): every confidential op is an allowlisted self-call
///         of `mtxExecute` whose statement carries the envelope binding (`ZTX_V1_RELAYED`); a direct call proves with
///         `ZTX_V1_DIRECT` and binding 0. The outer fee is the base's step 6, `ABSOLUTE`, from the signer's public
///         balance; the inner fee stays `confidentialFee` to a beneficiary UA.
contract ZetherRelayTest is ZetherFixture {
    using stdJson for string;

    uint256 constant PAYER_PK = 0x9A7E5;
    address payer = vm.addr(PAYER_PK);
    uint32 constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;
    uint32 constant RF = MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT;
    uint32 constant FIX = MetaTxLib.MODE_FEE_FIXED;
    uint32 constant PCT = MetaTxLib.MODE_FEE_PERCENT;

    function setUp() public {
        _deploy(true);
        _public(tok, payer, 1000); // public units for the outer fee
        _fund(tok, alice, 500);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
    }

    function _mt(bytes memory data, uint256 batch, uint32 mode, uint256 fee)
        internal view returns (MetaTxLib.MetaTransaction memory m)
    {
        m = MetaTxLib.MetaTransaction({
            from: payer, data: data, batch: batch, nonce: tok.mtxNonce(MetaTxLib.pad(payer), batch),
            validUntil: block.timestamp + 300, mode: mode, relayer: relayer, fee: fee, feeRecipient: address(0)
        });
    }

    function _ua(MetaTxLib.MetaTransaction memory m) internal pure returns (MetaTxLib.UAMetaTransaction memory) {
        return MetaTxLib.UAMetaTransaction(MetaTxLib.pad(m.from), m.data, m.batch, m.nonce, m.validUntil, m.mode, m.relayer,
            m.fee, m.feeRecipient);
    }

    function _uaSign(uint256 pk, MetaTxLib.UAMetaTransaction memory m) internal view returns (IUARegistry.UASig memory a) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, tok.mtxDigest(m));
        a.signature = abi.encodePacked(r, s, v);
    }

    function _sign(uint256 pk, MetaTxLib.MetaTransaction memory m) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, MtxDigest.metaTx(address(tok), m));
        return abi.encodePacked(r, s, v);
    }

    function _exec(MetaTxLib.MetaTransaction memory m, bytes memory sig) internal returns (bool) {
        vm.prank(relayer);
        return tok.executeMetaTransaction(m, sig);
    }

    /// The proof binds the envelope: build the statement with the address binding of `m` first (`_addrBinding`, what
    /// `executeMetaTransaction` binds), then sign `m` with the proof.
    function _relayedSingle(uint256 batch, uint256 fee) internal view returns (MetaTxLib.MetaTransaction memory m, Tx memory t) {
        m = _mt("", batch, RR | FIX, fee);
        t = _proveTransfer(tok, alice, bob, 100, 500, carol.ua, _addrBinding(tok, m));
        m.data = abi.encodeCall(IZetherToken.mtxConfidentialTransferSingle, (_zSingle(t.payload, carol.ua), t.proof));
    }

    function test_relayedTransferSingle_outerFeeFromPublicBalance_innerFeeToBeneficiary() public {
        (MetaTxLib.MetaTransaction memory m, Tx memory t) = _relayedSingle(uint256(keccak256("lane-1")), 25);
        // the statement of a relayed proof: tag ZTX_V1_RELAYED (word 5), the envelope binding (word 6)
        bytes memory st = stm.transferStatementSingle(address(tok), _zSingle(t.payload, carol.ua), _addrBinding(tok, m));
        (bytes32 tag, bytes32 binding) = abi.decode(_slice(st, 160, 64), (bytes32, bytes32));
        assertEq(tag, keccak256("ZTX_V1_RELAYED"));
        assertEq(binding, _addrBinding(tok, m));
        bytes memory sig = _sign(PAYER_PK, m);
        uint256 g0 = gasleft();
        assertTrue(_exec(m, sig));
        console2.log("bn254 relayed mtxConfidentialTransferSingle gas", g0 - gasleft());
        // ua-mtx-merge T1, meaning: the address `mtxExecute` returned the self-call's entryRef; its alias
        // `executeMetaTransaction` returns `true` (R3), so the entry is read at the expected ref instead
        assertGt(tok.transferEntry(_ref(tok, alice, 0)).length, 0, "the entry at the entryRef");
        assertEq(tok.balanceOf(relayer), 25, "outer fee: public units to the relayer");
        assertEq(tok.balanceOf(payer), 975);
        assertEq(tok.balanceOfUA(ZetherTypes.UA.unwrap(carol.ua)), FEE * SCALE, "inner fee: public units to the beneficiary");
        assertEq(tok.accountState(carol.ua).pendingSeq, 0, "no pend_ben credit (D19)");
        assertTrue(_holds(tok, alice, 500 - 100 - FEE, true));
        assertTrue(_holds(tok, bob, 100, false));
        assertEq(tok.mtxNonce(MetaTxLib.pad(payer), m.batch), 1);
        _assertConservation(tok, 1100);
    }

    function test_relayedMultiTransfer_unshield_shield() public {
        // mtxConfidentialTransferCompact (HASH), relayed
        MetaTxLib.MetaTransaction memory m = _mt("", 1, RR | FIX, 3);
        User[] memory to = new User[](2);
        (to[0], to[1]) = (bob, carol);
        uint256[] memory vs = new uint256[](2);
        (vs[0], vs[1]) = (40, 0);
        Tx memory t = _proveMulti(tok, alice, to, vs, 500, _none(), ZetherTypes.TransferMode.HASH, _addrBinding(tok, m));
        m.data = abi.encodeCall(IZetherToken.mtxConfidentialTransferCompact, (_zMulti(t.payload, _none()), t.proof));
        _exec(m, _sign(PAYER_PK, m));
        assertTrue(_holds(tok, bob, 40, false));
        assertTrue(_holds(tok, alice, 460, true));
        // mtxUnshield, relayed: public units minted to the statement's recipient
        m = _mt("", 2, RR | FIX, 3);
        (bytes memory pl, bytes memory pr) = _proveUnshield(tok, alice, 60, 460, address(0xB0C), carol.ua, _addrBinding(tok, m));
        m.data = abi.encodeCall(IZetherToken.mtxUnshield, (_zBurn(pl, carol.ua), 60, bytes32(uint256(uint160(address(0xB0C)))), pr));
        // lifted out and called directly: DIRECT statement ⇒ refused
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.mtxUnshield(_zBurn(pl, carol.ua), 60, bytes32(uint256(uint160(address(0xB0C)))), pr);
        _exec(m, _sign(PAYER_PK, m));
        assertEq(tok.balanceOf(address(0xB0C)), 60 * SCALE);
        assertTrue(_holds(tok, alice, 460 - 60 - FEE, true));
        // mtxShield, relayed: the SIGNER's public units, not the relayer's
        _public(tok, payer, 7 * SCALE);
        m = _mt(abi.encodeCall(IConfidentialToken.mtxShield, (ZetherTypes.UA.unwrap(bob.ua), 7)), 3, RR | FIX, 4);
        uint256 before = tok.balanceOf(payer);
        _exec(m, _sign(PAYER_PK, m));
        assertEq(tok.balanceOf(payer), before - 7 * SCALE - 4, "shield and outer fee, both from the signer");
        assertEq(tok.balanceOf(relayer), 3 + 3 + 4);
        assertEq(tok.accountState(bob.ua).pendingSeq, 2);
        // a direct call in the same transaction proves DIRECT: the binding is read only under a live ticket
        _direct(tok, _proveTransfer(tok, alice, carol, 5, 400 - FEE, _none(), 0), _none());
        assertTrue(_holds(tok, alice, 400 - FEE - 5, true));
        _assertConservation(tok, 1100);
    }

    /// The modes hold relayed: on a `COMPACT` / `FULL` token `mtxConfidentialTransfer` relays as commit-reveal, the no-bundle entry
    /// reverts `TransferEntryDisabled`, an opt-out reverts `AuditorRequired` (the refusal reverts the envelope: nonce
    /// unused).
    function test_relayedUnderTheModes() public {
        (dMode, aMode) = (1, 1);
        tok = _newToken(true, "commit-full");
        _public(tok, payer, 1000);
        _fund(tok, alice, 500);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        User[] memory to = new User[](2);
        (to[0], to[1]) = (bob, carol);
        uint256[] memory vs = new uint256[](2);
        vs[0] = 40;
        MetaTxLib.MetaTransaction memory m = _mt("", 1, RR | FIX, 3);
        Tx memory t = _proveMulti(tok, alice, to, vs, 500, _none(), ZetherTypes.TransferMode.HASH, _addrBinding(tok, m));
        m.data = abi.encodeCall(IZetherToken.mtxConfidentialTransfer, (_zMulti(t.payload, _none()), t.proof));
        _exec(m, _sign(PAYER_PK, m));
        assertTrue(_holds(tok, bob, 40, false));
        bytes memory entry = tok.transferEntry(_ref(tok, alice, 0));
        assertEq(entry.length, 16 + 5 * 128 * 2, "R itself, from state (review C0-3)");
        assertEq(tok.transferMemo(_ref(tok, alice, 0)).length, 17 + 40 * 2, "the sender memo");
        audOut = true;
        bytes memory pl = bytes.concat(_multiPayload(tok, alice, to, vs, 7, tok.accountState(alice.ua)), _memo(2));
        audOut = false;
        m = _mt(abi.encodeCall(IZetherToken.mtxConfidentialTransfer, (_zMulti(pl, _none()), bytes(""))), 2, RR, 0);
        bytes memory sig = _sign(PAYER_PK, m);
        vm.prank(relayer);
        vm.expectRevert(IZetherToken.AuditorRequired.selector);
        tok.executeMetaTransaction(m, sig);
        assertEq(tok.mtxNonce(MetaTxLib.pad(payer), 2), 0, "nonce not consumed");
    }

    function test_proofLiftedOutOfEnvelopeRejected() public {
        (, Tx memory t) = _relayedSingle(7, 25);
        vm.expectRevert(IZetherToken.ProofRejected.selector); // statement DIRECT ≠ RELAYED
        tok.mtxConfidentialTransferSingle(_zSingle(t.payload, carol.ua), t.proof);
    }

    function test_proofMovedToAnotherEnvelopeRejected() public {
        (MetaTxLib.MetaTransaction memory m,) = _relayedSingle(7, 25);
        m.batch = 8; // another envelope (another lane), same data ⇒ another binding
        bytes memory sig = _sign(PAYER_PK, m);
        vm.prank(relayer);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.executeMetaTransaction(m, sig);
        (m,) = _relayedSingle(7, 25);
        m.fee = 26; // the fee is in the binding
        sig = _sign(PAYER_PK, m);
        vm.prank(relayer);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.executeMetaTransaction(m, sig);
        // the same lane, its next nonce: the nonce is in the binding
        (m,) = _relayedSingle(7, 25);
        MetaTxLib.MetaTransaction memory c = _mt(abi.encodeCall(IMetaTx.cancelNonce, (99)), 7, RR, 0);
        _exec(c, _sign(PAYER_PK, c));
        m.nonce = 1;
        sig = _sign(PAYER_PK, m);
        vm.prank(relayer);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.executeMetaTransaction(m, sig);
    }

    /// Every selector `mtxSelectors()` publishes runs relayed once: the enforced `_mtxRule` agrees with the published
    /// list (review T4 I1).
    function test_everyListedSelectorRuns() public {
        _public(tok, payer, 3 * SCALE);
        (bytes4[] memory s,,) = tok.mtxSelectors();
        assertEq(s.length, 11);
        uint256 bal = 500;
        for (uint256 i; i < s.length; ++i) {
            // the owner-signed pair has its own relayed tests (ZetherUA5c)
            if (s[i] == IZetherToken.mtxRollOverSigned.selector || s[i] == IZetherToken.mtxSetRollOverMode.selector) continue;
            MetaTxLib.MetaTransaction memory m = _mt("", 200 + i, RR, 0);
            if (s[i] == IMetaTx.cancelNonce.selector) m.data = abi.encodeCall(IMetaTx.cancelNonce, (55));
            else if (s[i] == NormalToken.burn.selector) m.data = abi.encodeCall(NormalToken.burn, (7));
            else {
                m.data = _zetherOpCall(s[i], bal, _addrBinding(tok, m));
                if (s[i] != IConfidentialToken.mtxShield.selector && s[i] != IZetherToken.mtxRollOver.selector
                    && s[i] != IZetherToken.mtxRollOverBatch.selector) bal -= 10;
            }
            _exec(m, _sign(PAYER_PK, m));
        }
        assertEq(tok.mtxNonce(MetaTxLib.pad(payer), 55), 1, "cancelNonce");
        assertEq(tok.balanceOf(payer), 1000 - 7, "burn; shield");
        assertTrue(_holds(tok, bob, 3 + 3 * 10, false), "shield; three transfers");
        assertTrue(_holds(tok, alice, bal, true));
        assertEq(bal, 460);
        assertEq(tok.balanceOf(address(0xB0C)), 10 * SCALE, "unshield");
    }

    /// A direct proof (binding 0) put into an envelope: the statement is RELAYED there ⇒ refused.
    function test_directProofInsideAnEnvelopeRejected() public {
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, carol.ua, 0);
        MetaTxLib.MetaTransaction memory m =
            _mt(abi.encodeCall(IZetherToken.mtxConfidentialTransferSingle, (_zSingle(t.payload, carol.ua), t.proof)), 9, RR, 0);
        bytes memory sig = _sign(PAYER_PK, m);
        vm.prank(relayer);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.executeMetaTransaction(m, sig);
        _direct(tok, t, carol.ua); // the same proof as a direct call passes
    }

    /// CTR-ZTH-07: `PERCENT` is refused on every confidential op (`ABSOLUTE` class), before the call.
    function test_percentFeeRefused() public {
        (MetaTxLib.MetaTransaction memory m,) = _relayedSingle(7, 25);
        m.mode = RR | PCT;
        bytes memory sig = _sign(PAYER_PK, m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxFeeClass.selector, IZetherToken.mtxConfidentialTransferSingle.selector, m.mode));
        tok.executeMetaTransaction(m, sig);
    }

    /// The outer fee comes only from the signer's public balance; short ⇒ everything reverts (proof effects, nonce).
    function test_outerFeeOnlyFromThePublicBalance() public {
        (MetaTxLib.MetaTransaction memory m,) = _relayedSingle(7, 1001);
        bytes memory sig = _sign(PAYER_PK, m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSignature("ERC20InsufficientBalance(address,uint256,uint256)", payer, 1000, 1001));
        tok.executeMetaTransaction(m, sig);
        assertEq(tok.mtxNonce(MetaTxLib.pad(payer), 7), 0, "nonce not consumed");
        assertEq(tok.sendCounter(alice.ua), 0, "no confidential effect");
        assertTrue(_holds(tok, alice, 500, true));
    }

    /// CTR-ZTH-23: a fee to the token itself would be stuck; the base refuses every transfer to the token.
    function test_feeToTheTokenRefused() public {
        (MetaTxLib.MetaTransaction memory m,) = _relayedSingle(7, 25);
        m.mode = RR | RF | FIX;
        m.feeRecipient = address(tok);
        // the binding covers the bound fee recipient: re-prove for this envelope
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, carol.ua, _addrBinding(tok, m));
        m.data = abi.encodeCall(IZetherToken.mtxConfidentialTransferSingle, (_zSingle(t.payload, carol.ua), t.proof));
        bytes memory sig = _sign(PAYER_PK, m);
        vm.prank(relayer);
        vm.expectRevert(IERC20MetaTx.TransferToSelf.selector);
        tok.executeMetaTransaction(m, sig);
    }

    /// CTR-MTX-19: the published allowlist; the roll-over functions, `mint` and the trade entries are refused.
    function test_allowlistPinned() public {
        (bytes4[] memory s, uint8[] memory c, uint8[] memory a) = tok.mtxSelectors();
        bytes4[11] memory want = [
            IMetaTx.cancelNonce.selector, NormalToken.burn.selector, IConfidentialToken.mtxShield.selector,
            IZetherToken.mtxConfidentialTransfer.selector, IZetherToken.mtxConfidentialTransferCompact.selector,
            IZetherToken.mtxConfidentialTransferSingle.selector,
            IZetherToken.mtxUnshield.selector, IZetherToken.mtxRollOver.selector, IZetherToken.mtxRollOverBatch.selector,
            IZetherToken.mtxRollOverSigned.selector, IZetherToken.mtxSetRollOverMode.selector
        ];
        assertEq(s.length, 11);
        for (uint256 i; i < 11; ++i) {
            assertEq(s[i], want[i]);
            assertEq(c[i], i == 1 ? 2 : 1, "burn AMOUNT, the rest ABSOLUTE");
            assertEq(a[i], 0);
        }
        assertEq(bytes4(keccak256("mtxShield(bytes32,uint256)")), IConfidentialToken.mtxShield.selector);
        string memory p = "(bytes32,bytes32,bytes32,bytes32)";
        string memory multi = string.concat("(uint64,uint64,uint256,bytes16,bytes32,uint256,", p, ",", p, ",", p, ",(", p, ",", p, ",", p, ",", p, ")[],bytes)");
        assertEq(bytes4(keccak256(bytes(string.concat("mtxConfidentialTransfer(", multi, ",bytes)")))), IZetherToken.mtxConfidentialTransfer.selector);
        assertEq(bytes4(keccak256(bytes(string.concat("mtxConfidentialTransferCompact(", multi, ",bytes)")))), IZetherToken.mtxConfidentialTransferCompact.selector);
        assertEq(bytes4(keccak256(bytes(string.concat("mtxUnshield((uint64,uint64,uint256,bytes32,", p, "),uint256,bytes32,bytes)")))),
            IZetherToken.mtxUnshield.selector);
        bytes[1] memory refused = [
            abi.encodeCall(NormalToken.mint, (payer, 1))
        ];
        for (uint256 i; i < refused.length; ++i) {
            MetaTxLib.MetaTransaction memory m = _mt(refused[i], 100 + i, RR, 0);
            bytes memory sig = _sign(PAYER_PK, m);
            vm.prank(relayer);
            vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, bytes4(refused[i])));
            tok.executeMetaTransaction(m, sig);
        }
    }

    /// `mtxBatch`: each item has its own ticket and binding (a shield, then a relayed transfer on the next nonce).
    /// (ua-mtx-merge T1: the merged `mtxBatch` on the payer's id; its items bind the UA envelope, R35.)
    function test_batch_eachItemItsOwnBinding() public {
        _public(tok, payer, 5 * SCALE);
        MetaTxLib.UAMetaTransaction[] memory ms = new MetaTxLib.UAMetaTransaction[](2);
        ms[0] = _ua(_mt(abi.encodeCall(IConfidentialToken.mtxShield, (ZetherTypes.UA.unwrap(carol.ua), 5)), 4, RR, 0));
        ms[1] = _ua(_mt("", 4, RR | FIX, 2));
        ms[1].nonce = 1;
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, _none(), tok.envelopeBinding(ms[1]));
        ms[1].data = abi.encodeCall(IZetherToken.mtxConfidentialTransferSingle, (_zSingle(t.payload, _none()), t.proof));
        IUARegistry.UASig[] memory sigs = new IUARegistry.UASig[](2);
        (sigs[0], sigs[1]) = (_uaSign(PAYER_PK, ms[0]), _uaSign(PAYER_PK, ms[1]));
        vm.prank(relayer);
        tok.mtxBatch(ms, sigs);
        assertTrue(_holds(tok, carol, 5, false));
        assertTrue(_holds(tok, bob, 100, false));
        assertEq(tok.mtxNonce(MetaTxLib.pad(payer), 4), 2);
    }

    /// An ERC-1271 signer (CTR-ZTH-21, the base's cap) relays its own shield.
    function test_contractSignerRelaysItsShield() public {
        uint256 ownerPk = 0x0DD;
        Mock1271Wallet w = new Mock1271Wallet(vm.addr(ownerPk));
        _public(tok, address(w), 3 * SCALE);
        MetaTxLib.MetaTransaction memory m = _mt(abi.encodeCall(IConfidentialToken.mtxShield, (ZetherTypes.UA.unwrap(bob.ua), 3)), 1, RR, 0);
        m.from = address(w);
        bytes memory sig = _sign(ownerPk, m);
        vm.prank(relayer);
        tok.executeMetaTransaction(m, sig);
        assertEq(tok.balanceOf(address(w)), 0);
        assertTrue(_holds(tok, bob, 3, false));
    }

    /// The envelope binding and digest equal the Rust prover's (`envelope.json`, CTR-ZTH-06/36) through the spec
    /// formulas, and the fixture's client-side `_addrBinding` (what `executeMetaTransaction` binds) is that formula.
    /// ua-mtx-merge T4, meaning: the token no longer answers the address binding (its `envelopeBinding` view is the UA
    /// one, R35); the relayed tests below settle proofs bound to `_addrBinding` through `executeMetaTransaction`.
    function test_envelopeBindingAndDigestKat() public view {
        string memory j = vm.readFile("test/vectors/zether/s3/envelope.json");
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({
            from: j.readAddress(".meta.from"), data: j.readBytes(".meta.data"), batch: uint256(j.readBytes32(".meta.batch")),
            nonce: j.readUint(".meta.nonce"), validUntil: j.readUint(".meta.validUntil"), mode: uint32(j.readUint(".meta.mode")),
            relayer: j.readAddress(".meta.relayer"), fee: j.readUint(".meta.fee"), feeRecipient: j.readAddress(".meta.feeRecipient")
        });
        uint256 chainId = j.readUint(".chainId");
        bytes32 uid = j.readBytes32(".chainUid");
        address token = j.readAddress(".token");
        assertEq(_binding(m, chainId, uid, token), j.readBytes32(".binding"));
        assertEq(_digest(m, chainId, uid, token), j.readBytes32(".digest"));
        assertEq(_addrBinding(tok, m), _binding(m, block.chainid, ZUID, address(tok)));
        assertEq(MtxDigest.metaTx(address(tok), m), _digest(m, block.chainid, ZUID, address(tok)));
    }

    function _slice(bytes memory a, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i; i < len; ++i) out[i] = a[off + i];
    }

    function _binding(MetaTxLib.MetaTransaction memory m, uint256 chainId, bytes32 uid, address token)
        internal pure returns (bytes32)
    {
        (address r, address f) = MetaTxLib.canon(m);
        return keccak256(bytes.concat(
            abi.encode(keccak256("SCAAS-ZETHER-ENVELOPE-V1"), chainId, uid, token, m.from, m.batch),
            abi.encode(m.nonce, m.validUntil, m.mode, r, m.fee, f)
        ));
    }

    function _digest(MetaTxLib.MetaTransaction memory m, uint256 chainId, bytes32 uid, address token)
        internal pure returns (bytes32)
    {
        bytes32 ds = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS ZetherToken"), keccak256("1"), chainId, token, uid
        ));
        return keccak256(abi.encodePacked(hex"1901", ds, MetaTxLib.hashStruct(m)));
    }
}
