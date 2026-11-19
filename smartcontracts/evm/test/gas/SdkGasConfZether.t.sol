// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalZetherToken} from "../../src/zether/NormalZetherToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {IConfidentialWrappedToken} from "../../src/confidential/IConfidentialToken.sol";
import {typedDigest, burnJson, hexJson, T_G1, T_BURN, T_UNWRAP} from "../zether/ZetherTyped.t.sol";
import {n, a, h} from "../metatx/NamedEntry.t.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {nid} from "../helpers/Ids.sol";
import {SdkGasZetherBase} from "./SdkGasConfidential.t.sol";

/// The enveloped (relayed) forms of the `zether` kind's confidential entries the SDK prepares (`entries/zether.rs`).
interface ISdkGasZether {
    function mtxShield(MetaTxLib.UAEnvelope calldata e, bytes32 toUA, uint256 amount, IUARegistry.UASig calldata auth)
        external
        returns (bytes memory);
    function mtxWrapShield(
        MetaTxLib.Envelope calldata e,
        address underlying,
        uint256 amountIn,
        bytes32 toUA,
        bytes calldata sig
    ) external returns (bytes memory);
    function mtxRollOver(MetaTxLib.UAEnvelope calldata e, bytes32 ua, uint256 n, IUARegistry.UASig calldata auth)
        external
        returns (bytes memory);
    function mtxRollOverBatch(
        MetaTxLib.UAEnvelope calldata e,
        ZetherTypes.UA[] calldata uas,
        IUARegistry.UASig calldata auth
    ) external returns (bytes memory);
    function mtxRollOverSigned(
        MetaTxLib.UAEnvelope calldata e,
        ZetherTypes.UA ua,
        uint64 expectedPendingSeq,
        uint64 validUntilBlock,
        IUARegistry.UASig calldata ownerSig,
        IUARegistry.UASig calldata auth
    ) external returns (bytes memory);
    function mtxSetRollOverMode(
        MetaTxLib.UAEnvelope calldata e,
        ZetherTypes.UA ua,
        ZetherTypes.RollOverMode mode,
        uint64 validUntilBlock,
        IUARegistry.UASig calldata ownerSig,
        IUARegistry.UASig calldata auth
    ) external returns (bytes memory);
    function mtxUnshield(
        MetaTxLib.UAEnvelope calldata e,
        IZetherToken.ZetherBurn calldata b,
        uint256 amount,
        bytes32 recipient,
        bytes calldata proof,
        IUARegistry.UASig calldata auth
    ) external returns (bytes memory);
    function mtxUnshieldUnwrap(
        MetaTxLib.UAEnvelope calldata e,
        IZetherToken.ZetherBurn calldata b,
        IConfidentialWrappedToken.Unwrap calldata x,
        bytes calldata proof,
        IUARegistry.UASig calldata auth
    ) external returns (bytes memory);
}

/// The `zether` kind's confidential base rows (scaas-sdk spec §13.3; Zether only, Zether ≠ PQZ): each entry's enveloped
/// form on the kind's Normal and Wrapped tokens, plain and regulated (`SdkGasKindBase`'s config: `KYC` with the deny mask,
/// every party attested, `TAX` at 10 %), relayed and signed by the reference signer (`payer`'s native key). The proofs are
/// real: the fixture's Solidity prover over the real BLS12-381 verifier, each bound to the envelope it is measured with.
/// Each token's state before a row: `payer` holds public units (and, on a Wrapped, the leg `usd` approved); `alice` holds
/// `Z_BAL` units in `acc` (shielded, rolled over), the sender of the transfers and unshields; `dave` holds one pending entry
/// and an empty `acc`, the account of the roll-overs and the mode change (the first roll-over: `acc` written the first
/// time); `bob`, the receiver of the transfers and shields, holds nothing (a first write), as does `SG_PAYEE`, the unshield's
/// recipient. G2: the derived reference signer (`SdkGasZetherBase`) holds `payer`'s public units
/// and signs the envelope (the transfer's builder too, `_auth`) in its run. `mtxRollOverSigned` and `mtxSetRollOverMode` are
/// measured in their enveloped form (`UARollOverSigned`, `UASetRollOverMode`: the owner's Schnorr signature and the
/// envelope's), a superset of the owner-only form (`ZetherRollOver`) the SDK also prepares; `mtxRollOver` rolls the
/// account's one pending ciphertext (Zether's `n` changes nothing). Not here, their cost growing with a count the SDK has no
/// row part for (reported): `mtxConfidentialTransfer` and `…Compact` (the legs), `mtxRollOverBatch` (the accounts).
contract SdkGasConfZetherTest is SdkGasZetherBase {
    uint256 internal constant Z_BAL = 500;

    function setUp() public override {
        super.setUp();
        sgPk = PAYER_PK; // the fixture's transfer builders sign by `payer`
    }

    // ------------------------------------------------------------------ fixture

    /// `units` public units of `t` to `to`: a mint, or a 1:1 wrap of `usd` on a Wrapped.
    function _zPub(address t, bool wrapped, address to, uint256 units) internal {
        if (!wrapped) return _public(NormalZetherToken(t), to, units);
        usd.mint(address(this), units);
        usd.approve(t, units);
        WrappedToken(payable(t)).wrap(address(usd), units);
        if (to != address(this)) WrappedToken(payable(t)).transfer(to, units);
    }

    function _zPrep(address t, bool wrapped) internal {
        tok = NormalZetherToken(t); // the fixture's builders read `tok`
        _zPub(t, wrapped, payer, 1e10);
        if (wrapped) {
            usd.mint(payer, 1e10);
            vm.prank(payer);
            usd.approve(t, type(uint256).max);
            sgLeg = address(usd); // A6: `_sgHold` wraps it
        }
        _zPub(t, wrapped, address(this), (Z_BAL + 20) * SCALE);
        tok.mtxShield(aId, Z_BAL);
        tok.mtxRollOver(aId, 1);
        tok.mtxShield(dId, 20);
    }

    function _zRows(bool reg) internal {
        if (reg) {
            address[6] memory ps = [payer, SG_PAYEE, SG_TAX_TO, SG_RELAYER, SG_FEE_TO, address(this)];
            for (uint256 i; i < ps.length; ++i) {
                _sgAttest(nid(ps[i]));
            }
            _sgAttest(aId);
            _sgAttest(bId);
            _sgAttest(dId);
            _sgAttest(UAKinds.uaOf(sgUaKind, sgUaKey)); // G2: the derived reference signer
        }
        for (uint256 w; w < 2; ++w) {
            bool wrapped = w == 1;
            string memory v = wrapped ? (reg ? "wrapped_reg" : "wrapped") : (reg ? "normal_reg" : "normal");
            address t =
                _sgCreate(wrapped, reg, wrapped ? address(usd) : address(0), keccak256(abi.encode("sgz", w, reg)));
            _zPrep(t, wrapped);
            bytes32 from = _sgFrom();
            _both("zether", "mtxShield", v, t, from, _zShield);
            _both("zether", "mtxConfidentialTransferSingle", v, t, from, _zTransferSingle);
            _both("zether", "mtxUnshield", v, t, from, _zUnshield);
            _both("zether", "mtxRollOver", v, t, from, _zRoll);
            _both("zether", "mtxRollOverSigned", v, t, from, _zRollSigned);
            _both("zether", "mtxSetRollOverMode", v, t, from, _zSetMode);
            if (wrapped) {
                _both("zether", "mtxWrapShield", v, t, from, _zWrapShield);
                _both("zether", "mtxUnshieldUnwrap", v, t, from, _zUnwrap);
            }
        }
    }

    /// G2: the fixture's envelope signature (the transfer's builder) by the derived reference signer in its run.
    function _auth(MetaTxLib.UAEnvelope memory e, bytes32 d, bool bad)
        internal
        view
        override
        returns (IUARegistry.UASig memory)
    {
        return sgKind != 0 && !bad ? _sgUaSig(d) : super._auth(e, d, bad);
    }

    function test_sdkGas_zetherConf() public {
        _zRows(false);
    }

    function test_sdkGas_zetherConfRegulated() public {
        _zRows(true);
    }

    // ------------------------------------------------------------------ the entries' calldata

    function _zShield(address c, uint256 nonce) internal view returns (bytes memory) {
        uint256 amt = _amt(10);
        bytes32 d = _sgNamed(c, "UAShield(bytes32 from,bytes32 toUA,uint256 amount,", abi.encode(bId, amt), nonce);
        return abi.encodeCall(ISdkGasZether.mtxShield, (_sgE(nonce), bId, amt, _sgUaSig(d)));
    }

    function _zWrapShield(address c, uint256 nonce) internal view returns (bytes memory) {
        uint256 amt = 10 * SCALE;
        bytes32 d = _sgNamed(
            c,
            "WrapShield(address from,address underlying,uint256 amountIn,bytes32 toUA,",
            abi.encode(address(usd), amt, bId),
            nonce
        );
        return abi.encodeCall(ISdkGasZether.mtxWrapShield, (_sgAddrE(nonce), address(usd), amt, bId, _sgSign(sgPk, d)));
    }

    function _zTransferSingle(address, uint256 nonce) internal view returns (bytes memory) {
        return _signedCall(2, _sgE(nonce), Z_BAL, false);
    }

    function _zUnshield(address c, uint256 nonce) internal view returns (bytes memory) {
        MetaTxLib.UAEnvelope memory e = _sgE(nonce);
        (uint256 amt, bytes32 rcpt) = (_amt(10), MetaTxLib.pad(SG_PAYEE));
        (bytes memory pl, bytes memory pr) =
            _proveUnshieldTo(tok, alice, amt, Z_BAL, rcpt, _none(), _uaBindingOf(tok, e));
        IZetherToken.ZetherBurn memory b = _zBurn(pl, _none());
        bytes32 d = _zUnshieldDigest(c, e, b, amt, rcpt, pr);
        return abi.encodeCall(ISdkGasZether.mtxUnshield, (e, b, amt, rcpt, pr, _sgUaSig(d)));
    }

    function _zUnshieldDigest(
        address c,
        MetaTxLib.UAEnvelope memory e,
        IZetherToken.ZetherBurn memory b,
        uint256 amt,
        bytes32 rcpt,
        bytes memory pr
    ) internal view returns (bytes32) {
        string memory op = string.concat(
            '"args":', burnJson(b), ',"amount":', n(amt), ',"recipient":', h(rcpt), ',"proof":', hexJson(pr)
        );
        return typedDigest(
            c,
            "UAZetherUnshield",
            string.concat(
                F_UA,
                ',{"name":"args","type":"ZetherBurn"},{"name":"amount","type":"uint256"},{"name":"recipient","type":"bytes32"},{"name":"proof","type":"bytes"}'
            ),
            string.concat(",", T_G1, ",", T_BURN),
            _msg(e.from, op, e)
        );
    }

    /// `minOut` 0: the regulated variant's tax lowers the payout; the leg pays `amount · SCALE` less it.
    function _zUnwrap(address c, uint256 nonce) internal view returns (bytes memory) {
        MetaTxLib.UAEnvelope memory e = _sgE(nonce);
        IConfidentialWrappedToken.Unwrap memory x =
            IConfidentialWrappedToken.Unwrap(address(usd), MetaTxLib.pad(SG_PAYEE), _amt(10), 0);
        IZetherToken.ZetherBurn memory b = _zBurn(_unshieldPayload(tok, alice), _none());
        bytes memory pr = _proveU(
            alice,
            stm.unshieldUnwrapStatement(c, b, x.amount, x.recipient, x.underlying, x.minOut, _uaBindingOf(tok, e)),
            x.amount,
            Z_BAL,
            _none(),
            tok
        );
        return abi.encodeCall(ISdkGasZether.mtxUnshieldUnwrap, (e, b, x, pr, _sgUaSig(_zUnwrapDigest(c, e, b, x, pr))));
    }

    function _zUnwrapDigest(
        address c,
        MetaTxLib.UAEnvelope memory e,
        IZetherToken.ZetherBurn memory b,
        IConfidentialWrappedToken.Unwrap memory x,
        bytes memory pr
    ) internal view returns (bytes32) {
        string memory uw = string.concat(
            '{"underlying":',
            a(x.underlying),
            ',"recipient":',
            h(x.recipient),
            ',"amount":',
            n(x.amount),
            ',"minOut":',
            n(x.minOut),
            "}"
        );
        return typedDigest(
            c,
            "UAZetherUnshieldUnwrap",
            string.concat(
                F_UA,
                ',{"name":"args","type":"ZetherBurn"},{"name":"unwrap","type":"Unwrap"},{"name":"proof","type":"bytes"}'
            ),
            string.concat(",", T_G1, ",", T_UNWRAP, ",", T_BURN),
            _msg(e.from, string.concat('"args":', burnJson(b), ',"unwrap":', uw, ',"proof":', hexJson(pr)), e)
        );
    }

    function _zRoll(address c, uint256 nonce) internal view returns (bytes memory) {
        bytes32 d = _sgNamed(c, "UARollOver(bytes32 from,bytes32 ua,uint256 n,", abi.encode(dId, uint256(1)), nonce);
        return abi.encodeCall(ISdkGasZether.mtxRollOver, (_sgE(nonce), dId, 1, _sgUaSig(d)));
    }

    function _zRollSigned(address c, uint256 nonce) internal view returns (bytes memory) {
        IZetherToken.AccountState memory st = tok.accountState(dave.ua);
        uint64 until = uint64(block.number + 10);
        IUARegistry.UASig memory o = _ownerAuth(dave, _rollOverDigest(tok, dave.ua, st.accSeq, st.pendingSeq, until));
        bytes32 d = _sgNamed(
            c,
            "UARollOverSigned(bytes32 from,bytes32 ua,uint64 expectedPendingSeq,uint64 validUntilBlock,",
            abi.encode(dId, st.pendingSeq, until),
            nonce
        );
        return
            abi.encodeCall(
                ISdkGasZether.mtxRollOverSigned, (_sgE(nonce), dave.ua, st.pendingSeq, until, o, _sgUaSig(d))
            );
    }

    function _zSetMode(address c, uint256 nonce) internal view returns (bytes memory) {
        uint64 until = uint64(block.number + 10);
        IUARegistry.UASig memory o =
            _ownerAuth(dave, _setModeDigest(tok, dave.ua, 1, tok.accountState(dave.ua).modeNonce, until));
        bytes32 d = _sgNamed(
            c,
            "UASetRollOverMode(bytes32 from,bytes32 ua,uint8 rollOverMode,uint64 validUntilBlock,",
            abi.encode(dId, uint8(1), until),
            nonce
        );
        return abi.encodeCall(
            ISdkGasZether.mtxSetRollOverMode,
            (_sgE(nonce), dave.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, o, _sgUaSig(d))
        );
    }
}
