// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzFixture} from "./helpers/PqzFixture.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {NoUnderlyingPqzToken} from "../../src/pqz/NoUnderlyingPqzToken.sol";
import {UnderlyingPqzToken} from "../../src/pqz/UnderlyingPqzToken.sol";
import {IConfidentialToken, IConfidentialUnderlyingToken} from "../../src/confidential/IConfidentialToken.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {MockERC20} from "../helpers/Mocks.sol";

/// Plan 5h Task 3b on the PQZ kinds (the precompile mocked): the shared `IConfidentialToken` signature (`beneficiary`
/// = the payload's, D20), the unshield to a `bytes32` UA recipient (UA-5c (b)), the unshield-unwrap to a UA through a
/// SCaaS ledger leg, and the allow-lists (the rollover and `mtxPrepareAcc` off both paths, CTR-ZTH-34).
contract PqzSharedTest is PqzFixture {
    uint256 internal constant KEY = 0xA11CE;
    address internal relayer = address(0xBEEF);
    bytes32 internal fan; // a derived signing UA without a PQZ key

    function setUp() public {
        _stack();
        tok = _newToken("pqz");
        fan = _mldsaUA(9);
    }

    function _pad(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function _burnPl(uint256 seed, bytes32 ben) internal view returns (bytes memory) {
        return bytes.concat(abi.encode(uint256(1), block.number + 5, uint256(0), alice, ben), _blob(seed, PqzCt.CT));
    }

    // ------------------------------------------------------------------ UA-5c (b)

    /// The recipient word (header word 10) carries the UA id; the units move from the pool to its UA-ledger balance.
    function test_unshieldToDerivedUA() public {
        _fund(tok, alice, 100);
        bytes memory pl = _burnPl(3, bytes32(0));
        bytes memory st = tok.burnStatement(pl, 40, fan, 0);
        assertEq(bytes32(_cut(st, 320, 32)), fan, "header word 10: the recipient id");
        assertEq(bytes32(_cut(tok.burnStatement(pl, 40, _pad(address(0xD00D)), 0), 320, 32)), bytes32(abi.encode(address(0xD00D))),
            "a native recipient: the padded address, as before");
        vm.expectEmit(true, true, false, false, address(tok));
        emit IConfidentialToken.Unshielded(alice, 40, fan, address(0));
        tok.mtxUnshield(pl, hex"c0de", _mlAuth(), bytes32(0), "", 40, fan);
        assertEq(tok.balanceOfUA(fan), 40 * SCALE);
        assertEq(tok.balanceOf(MetaTxLib.SHIELD_POOL), 60 * SCALE);
        assertEq(tok.totalShielded(), 60);
        _assertConservation(tok);
    }

    /// A derived id must be a registered SIGNING UA (before the proof); the refresh keeps `recipient = 0`.
    function test_unshieldRecipient_refused() public {
        _fund(tok, alice, 100);
        bytes memory pl = _burnPl(3, bytes32(0));
        bytes32 ghost = bytes32(uint256(1) << 200);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UANotRegistered.selector, ghost));
        tok.mtxUnshield(pl, hex"c0de", _mlAuth(), bytes32(0), "", 40, ghost);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RefreshRecipient.selector, fan));
        tok.mtxUnshield(pl, hex"c0de", _mlAuth(), bytes32(0), "", 0, fan);
        vm.expectRevert(IPqzToken.ZeroRecipient.selector);
        tok.mtxUnshield(pl, hex"c0de", _mlAuth(), bytes32(0), "", 40, bytes32(0));
    }

    /// The unshield-unwrap to a UA pays it in a SCaaS ledger leg (`transferToUA`); an outside ERC-20 leg reverts
    /// `UALegNotLedger`.
    function test_unshieldUnwrap_toUA() public {
        PqzLayer legTok = _newToken("leg");
        MockERC20 usd = new MockERC20("USD", "USD", 6);
        _releaseUnderlying();
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.features = (1 << AdminLib.PAYABLE);
        c.roles.minter = address(0);
        c.legs = new IFactoryToken.Leg[](2);
        c.legs[0] = IFactoryToken.Leg(address(legTok), 1, 1);
        c.legs[1] = IFactoryToken.Leg(address(usd), 1, 1);
        UnderlyingPqzToken w = UnderlyingPqzToken(payable(factory.createToken(IOpenFactory.TokenKind.UNDERLYING_PQZ, 1, abi.encode(c), "w")));
        _public(legTok, address(this), 100 * SCALE);
        legTok.approve(address(w), type(uint256).max);
        w.mtxWrapShield(address(legTok), 100 * SCALE, alice);
        usd.mint(address(this), 100 * SCALE);
        usd.approve(address(w), type(uint256).max);
        w.mtxWrapShield(address(usd), 100 * SCALE, alice);
        bytes memory pl = _burnPl(3, bytes32(0));
        w.mtxUnshieldUnwrap(pl, hex"c0de", _mlAuth(), bytes32(0), "",
            IConfidentialUnderlyingToken.Unwrap(address(legTok), fan, 40, 0));
        assertEq(legTok.balanceOfUA(fan), 40 * SCALE, "the leg's own UA ledger");
        assertEq(w.totalSupply(), 160 * SCALE, "burnt from the pool");
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UALegNotLedger.selector, address(usd)));
        w.mtxUnshieldUnwrap(pl, hex"c0de", _mlAuth(), bytes32(0), "", IConfidentialUnderlyingToken.Unwrap(address(usd), fan, 10, 0));
        // the UA allowlist of the kind: not `mtxWrapShield` (a UA wrap-shields in two steps)
        _uaRefused(PqzLayer(address(w)), abi.encodeCall(UnderlyingPqzToken.mtxWrapShield, (address(usd), SCALE, alice)));
        (bytes4[] memory s, uint8[] memory cl,) = w.mtxSelectors();
        bytes4[16] memory want = [
            IMetaTx.cancelNonce.selector, bytes4(keccak256("wrap(uint256)")), bytes4(keccak256("unwrap(uint256,address,uint256)")),
            bytes4(keccak256("wrap(address,uint256)")), bytes4(keccak256("unwrap(address,uint256,address,uint256)")),
            UnderlyingToken.addReserve.selector, UnderlyingToken.wrapToUA.selector, UnderlyingToken.unwrapToUA.selector,
            PqzLayer.mtxShield.selector, PqzLayer.mtxConfidentialTransfer.selector, PqzLayer.mtxConfidentialTransferCompact.selector,
            PqzLayer.mtxUnshield.selector, UnderlyingPqzToken.mtxWrapShield.selector, UnderlyingPqzToken.mtxUnshieldUnwrap.selector,
            PqzLayer.mtxConfidentialTransferSingle.selector, PqzLayer.mtxConfidentialTransferSingleCompact.selector
        ];
        assertEq(s.length, 16);
        for (uint256 i; i < 16; ++i) {
            assertEq(s[i], want[i]);
            if (i >= 8) assertEq(cl[i], 1, "the PQZ ops ABSOLUTE");
        }
    }

    // ------------------------------------------------------------------ D20: the shared signature on PQZ

    /// `beneficiary` must be the payload's beneficiary word (op 1 at 160, op 7 and the burn at 128).
    function test_beneficiaryMismatch() public {
        _fund(tok, alice, 100);
        bytes memory p1 = _payload(1, 0, alice, bob, carol, _out(1, false), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BeneficiaryMismatch.selector, carol, bytes32(0)));
        tok.mtxConfidentialTransferSingle(p1, hex"c0de", _mlAuth(), bytes32(0), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BeneficiaryMismatch.selector, carol, bob));
        tok.mtxConfidentialTransferSingleCompact(p1, hex"c0de", _mlAuth(), bob, "");
        bytes32[] memory rec = new bytes32[](1);
        rec[0] = bob;
        bytes memory p7 = _mpayload(1, 0, alice, carol, rec, _blob(2, _outLen(1, false)), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BeneficiaryMismatch.selector, carol, bytes32(0)));
        tok.mtxConfidentialTransfer(p7, hex"c0de", _mlAuth(), bytes32(0), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BeneficiaryMismatch.selector, carol, bytes32(0)));
        tok.mtxConfidentialTransferCompact(p7, hex"c0de", _mlAuth(), bytes32(0), "");
        bytes memory pb = _burnPl(3, carol);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BeneficiaryMismatch.selector, carol, bytes32(0)));
        tok.mtxUnshield(pb, hex"c0de", _mlAuth(), bytes32(0), "", 0, bytes32(0));
        // too short for the word: the library's `BadPayload`
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadPayload.selector, 100));
        tok.mtxConfidentialTransfer(new bytes(100), hex"c0de", _mlAuth(), carol, "");
        tok.mtxConfidentialTransferSingle(p1, hex"c0de", _mlAuth(), carol, ""); // the matching word passes
    }

    // ------------------------------------------------------------------ allow-lists

    function _uaRefused(PqzLayer t, bytes memory data) internal {
        MetaTxLib.UAMetaTransaction memory m;
        m.from = fan;
        m.data = data;
        m.nonce = t.uaNonce(fan, 0);
        m.validUntil = block.timestamp + 1 hours;
        vm.expectRevert(abi.encodeWithSelector(IUALedger.MetaTxUnknownOp.selector, bytes4(data)));
        t.uaExecute(m, _mlAuth());
    }

    /// `NONE_PQZ`: exactly `cancelNonce`, `burn` and the six shared PQZ ops; the rollover and `mtxPrepareAcc` are on
    /// neither relaying path (CTR-ZTH-34: anyone calls them directly).
    function test_allowlists_noneKind() public {
        (bytes4[] memory s, uint8[] memory c,) = NoUnderlyingPqzToken(address(tok)).mtxSelectors();
        bytes4[8] memory want = [
            IMetaTx.cancelNonce.selector, NoUnderlyingToken.burn.selector, PqzLayer.mtxShield.selector,
            PqzLayer.mtxConfidentialTransfer.selector, PqzLayer.mtxConfidentialTransferCompact.selector,
            PqzLayer.mtxUnshield.selector, PqzLayer.mtxConfidentialTransferSingle.selector,
            PqzLayer.mtxConfidentialTransferSingleCompact.selector
        ];
        assertEq(s.length, 8);
        for (uint256 i; i < 8; ++i) {
            assertEq(s[i], want[i]);
            assertEq(c[i], i == 1 ? 2 : 1);
        }
        bytes[2] memory off = [abi.encodeCall(PqzLayer.mtxRollOver, (alice, 1)), abi.encodeCall(PqzLayer.mtxPrepareAcc, (alice, 0))];
        for (uint256 i; i < 2; ++i) {
            _uaRefused(tok, off[i]);
            MetaTxLib.MetaTransaction memory m;
            m.from = vm.addr(KEY);
            m.data = off[i];
            m.validUntil = block.timestamp + 1 hours;
            (uint8 v, bytes32 r, bytes32 sg) = vm.sign(KEY, tok.mtxDigest(m));
            vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, bytes4(off[i])));
            tok.mtxExecute(m, abi.encodePacked(r, sg, v));
        }
    }
}
