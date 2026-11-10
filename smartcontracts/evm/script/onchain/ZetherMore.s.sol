// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ZetherE2E} from "../ZetherE2E.s.sol";
import {console} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {NormalZetherToken} from "../../src/zether/NormalZetherToken.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {IConfidentialWrappedToken} from "../../src/confidential/IConfidentialToken.sol";

/// @notice T66b Step 5b, group `zether`: the Zether entries `ZetherE2E.run()` does not reach, on a NORMAL_ZETHER and a
///         WRAPPED_ZETHER token of its own (the e2e's `_normal` / `_wrapped`: alice shielded and rolled over first), each
///         step checked by decryption (alice, bob): the direct single / Compact / BUNDLE transfers and unshield, the direct
///         unshield-unwrap (wrapped; its proof bound to `unwrapBinding`), `mtxRollOverBatch`, the named UA-envelope forms
///         through `zether-cli namedCall` (single, Compact, BUNDLE, unshield, unshield-unwrap), the named UA-envelope
///         shield / roll-over / roll-over batch / signed roll-over / roll-over mode (signed here by the payer EOA over the
///         entry's own struct in the token's domain), the account-owner ops `mtxRollOverSigned` / `mtxSetRollOverMode`
///         (Schnorr by the Zether key, `zether-cli ownerAuth`), the direct shield of the wrapped kind and its named
///         `mtxWrapShield` (address `WrapShield` envelope). The regulated twin (kinds 10, 11) is generated from this file by
///         zether_reg.py. Writes `deployments/<key>-zether-more.json` (its header first, NET-EVM-13). Needs --ffi, `PRIVATE_KEY` (the sender).
///         UNAUDITED contracts.
contract ZetherMore is ZetherE2E {
    using stdJson for string;

    bytes32 internal constant SALTED =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    string internal constant ENV_TAIL =
        "uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    bytes32 internal constant TH_ROLL_OVER =
        keccak256("ZetherRollOver(bytes32 ua,uint64 accSeq,uint64 expectedPendingSeq,uint64 validUntilBlock)");
    bytes32 internal constant TH_SET_MODE =
        keccak256("ZetherSetRollOverMode(bytes32 ua,uint8 mode,uint64 modeNonce,uint64 validUntilBlock)");

    // alice (user 0) and bob (user 1) on the token under test: acc, pending
    uint256 internal aAcc;
    uint256 internal aPend;
    uint256 internal bAcc;
    uint256 internal bPend;

    function more() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        me = vm.addr(pk);
        _load();
        salt = keccak256(abi.encode("scaas.onchain.zether.more", block.number));
        address payer = vm.addr(PAYER_PK);
        vm.startBroadcast(pk);
        _register();
        _normal();
        address tn = t;
        IERC20(t).transfer(payer, 200);
        _all(false);
        _wrapped();
        t = wt;
        IERC20(und).approve(wt, 1000);
        WrappedZetherToken(payable(wt)).wrap(1000);
        IERC20(wt).transfer(payer, 300);
        IERC20(und).transfer(payer, 100);
        (bool ok,) = payable(payer).call{value: 0.01 ether}(""); // gas for the payer's own approve below
        require(ok, "fund the payer");
        _all(true);
        vm.stopBroadcast();
        _wrapShieldNamed(pk, payer);

        string memory k = "more";
        vm.serializeAddress(k, "normal_zether_token", tn);
        vm.serializeAddress(k, "wrapped_zether_token", wt);
        string memory j = vm.serializeAddress(k, "underlying_erc20", und);
        vm.writeFile(_bookPath(bookUid, "", "-zether-more.json"), _bookHeader(bookUid, j));
    }

    // ------------------------------------------------------------------ the sequence on `t`

    function _all(bool wrapped) internal {
        string memory w = wrapped ? " (wrapped)" : "";
        (aAcc, aPend) = _balances(t, 0);
        (bAcc, bPend) = _balances(t, 1);
        // direct: single, Compact M = 2, BUNDLE M = 2, unshield; unshield-unwrap (wrapped)
        _send(t, _cli("proveTransfer", _req(t, aAcc, string.concat(",", _q("yTo", vm.toString(ys[1])), ',"amount":10'))),
            string.concat("direct single transfer alice -> bob 10", w));
        _moved(10, 10, "direct single");
        _send(t, _cli("proveTransferMulti", _req(t, aAcc, string.concat(',"mode":"compact"', _two(5)))),
            string.concat("direct Compact M = 2 (bob 5 + 1 decoy)", w));
        _moved(5, 5, "direct Compact");
        _send(t, _cli("proveTransferMulti", _req(t, aAcc, string.concat(',"mode":"bundle"', _two(5)))),
            string.concat("direct BUNDLE M = 2 (bob 5 + 1 decoy)", w));
        _moved(5, 5, "direct BUNDLE");
        (bool ok,) = t.call(_cli("proveBurn", _req(t, aAcc, string.concat(',"amount":7,', _q("recipient", vm.toString(me)))))
            .readBytes(".directCalldata"));
        require(ok, "direct unshield reverted");
        _moved(7, 0, "direct unshield 7");
        if (wrapped) _unwrapDirect();
        // the public roll-over of a batch: bob's credits to his acc
        ZetherTypes.UA[] memory b = new ZetherTypes.UA[](2);
        (b[0], b[1]) = (ZetherTypes.UA.wrap(uas[1]), ZetherTypes.UA.wrap(uas[2]));
        NormalZetherToken(t).mtxRollOverBatch(b);
        (bAcc, bPend) = (bAcc + bPend, 0);
        _check(string.concat("mtxRollOverBatch([bob, carol])", w));
        // named transfers and unshields (zether-cli namedCall), the payer's UASig
        _namedTransfers(wrapped);
        // named roll-over of bob, then a credit and the named batch roll-over
        _namedRollOver(w);
        // shields: direct (from the sender's public units), named (the payer's); the owner's signed roll-over
        NormalZetherToken(t).mtxShield(uas[0], 20);
        aPend += 20;
        _check(string.concat("direct mtxShield(alice, 20)", w));
        _namedShield(9, w);
        _rollOverSigned(w);
        _namedShield(4, w);
        _rollOverSignedNamed(w);
        _modes(w);
    }

    function _two(uint256 v) internal view returns (string memory) {
        uint256[] memory who = new uint256[](2);
        uint256[] memory amt = new uint256[](2);
        (who[0], who[1], amt[0]) = (1, 3, v);
        return _recipients(who, amt);
    }

    /// alice's acc down `a`, bob's pending up `b`, then both checked by decryption.
    function _moved(uint256 a, uint256 b, string memory what) internal {
        (aAcc, bPend) = (aAcc - a, bPend + b);
        _check(what);
    }

    function _check(string memory what) internal {
        _expect(t, 0, aAcc, aPend, string.concat(what, ": alice"));
        _expect(t, 1, bAcc, bPend, string.concat(what, ": bob"));
    }

    /// A direct `mtxUnshieldUnwrap` of 6 to the sender in the underlying: the proof bound to `unwrapBinding(leg, minOut)`,
    /// the `ZetherBurn` decoded from the build's payload (`be32 accSeq ‖ be32 sendCounter ‖ be32 validUntilBlock ‖ Y_f`).
    function _unwrapDirect() internal {
        bytes32 ub = IZetherStatementsUnwrap(dep.readAddress(".zether_statements")).unwrapBinding(und, 0);
        string memory out = _cli("proveBurn", _req(t, aAcc, string.concat(',"amount":6,', _q("recipient", vm.toString(me)), ",",
            _q("unwrapBinding", vm.toString(ub)))));
        uint256 before = IERC20(und).balanceOf(me);
        WrappedZetherToken(payable(t)).mtxUnshieldUnwrap(_burnOf(out.readBytes(".payload")),
            IConfidentialWrappedToken.Unwrap(und, MetaTxLib.pad(me), 6, 0), out.readBytes(".proof"));
        require(IERC20(und).balanceOf(me) == before + 6, "direct unshield-unwrap: underlying");
        _moved(6, 0, "direct mtxUnshieldUnwrap 6 (wrapped)");
    }

    function _burnOf(bytes memory p) internal pure returns (IZetherToken.ZetherBurn memory b) {
        (uint256 acc, uint256 sc, uint256 vub, bytes32 x0, bytes32 x1, bytes32 y0, bytes32 y1) =
            abi.decode(p, (uint256, uint256, uint256, bytes32, bytes32, bytes32, bytes32));
        (b.accSeq, b.sendCounter, b.validUntilBlock) = (uint64(acc), uint64(sc), vub);
        b.yFrom = IZetherToken.G1(x0, x1, y0, y1);
    }

    function _namedTransfers(bool wrapped) internal {
        string memory w = wrapped ? " (wrapped)" : "";
        MetaTxLib.UAMetaTransaction memory m = _envelope();
        string memory out = _cli("proveTransfer", _req(t, aAcc, string.concat(_bindingOf(m), ',"uaSigner":"ecdsa",',
            _q("yTo", vm.toString(ys[1])), ',"amount":4')));
        _named("UAZetherTransferSingle", m, out, "", string.concat("named single alice -> bob 4", w));
        _moved(4, 4, "named single");
        m = _envelope();
        out = _cli("proveTransferMulti", _req(t, aAcc, string.concat(',"mode":"compact"', _bindingOf(m), ',"uaSigner":"ecdsa"', _two(3))));
        _named("UAZetherTransferCompact", m, out, "", string.concat("named Compact M = 2 (bob 3)", w));
        _moved(3, 3, "named Compact");
        m = _envelope();
        out = _cli("proveTransferMulti", _req(t, aAcc, string.concat(',"mode":"bundle"', _bindingOf(m), ',"uaSigner":"ecdsa"', _two(3))));
        _named("UAZetherTransfer", m, out, "", string.concat("named BUNDLE M = 2 (bob 3)", w));
        _moved(3, 3, "named BUNDLE");
        m = _envelope();
        out = _cli("proveBurn", _req(t, aAcc, string.concat(_bindingOf(m), ',"amount":2,', _q("recipient", vm.toString(me)))));
        _named("UAZetherUnshield", m, out, string.concat(',"amount":2,', _q("recipient", vm.toString(MetaTxLib.pad(me)))),
            string.concat("named unshield 2", w));
        _moved(2, 0, "named unshield");
        if (!wrapped) return;
        m = _envelope();
        out = _cli("proveBurn", _req(t, aAcc, string.concat(_bindingOf(m), ',"amount":2,', _q("recipient", vm.toString(me)))));
        uint256 before = IERC20(und).balanceOf(me);
        _named("UAZetherUnshieldUnwrap", m, out, string.concat(',"unwrap":{', _q("underlying", vm.toString(und)), ",",
            _q("recipient", vm.toString(MetaTxLib.pad(me))), ',"amount":"2","minOut":"0"}'), "named unshield-unwrap 2 (wrapped)");
        require(IERC20(und).balanceOf(me) == before + 2, "named unshield-unwrap: underlying");
        _moved(2, 0, "named unshield-unwrap");
    }

    function _namedRollOver(string memory w) internal {
        MetaTxLib.UAMetaTransaction memory m = _envelope();
        NormalZetherToken(t).mtxRollOver(_ue(m), uas[1], 1,
            _uaSig(string.concat("UARollOver(bytes32 from,bytes32 ua,uint256 n,", ENV_TAIL), abi.encode(uas[1], uint256(1)), m));
        (bAcc, bPend) = (bAcc + bPend, 0);
        _check(string.concat("named mtxRollOver(bob, 1)", w));
        _send(t, _cli("proveTransfer", _req(t, aAcc, string.concat(",", _q("yTo", vm.toString(ys[1])), ',"amount":1'))),
            string.concat("direct single transfer alice -> bob 1", w));
        _moved(1, 1, "direct single 1");
        ZetherTypes.UA[] memory b = new ZetherTypes.UA[](1);
        b[0] = ZetherTypes.UA.wrap(uas[1]);
        m = _envelope();
        NormalZetherToken(t).mtxRollOverBatch(_ue(m), b, _uaSig(string.concat("UARollOverBatch(bytes32 from,bytes32[] uas,", ENV_TAIL),
            abi.encode(keccak256(abi.encodePacked(uas[1]))), m));
        (bAcc, bPend) = (bAcc + bPend, 0);
        _check(string.concat("named mtxRollOverBatch([bob])", w));
    }

    function _namedShield(uint256 v, string memory w) internal {
        MetaTxLib.UAMetaTransaction memory m = _envelope();
        NormalZetherToken(t).mtxShield(_ue(m), uas[0], v, _uaSig(string.concat("UAShield(bytes32 from,bytes32 toUA,uint256 amount,",
            ENV_TAIL), abi.encode(uas[0], v), m));
        aPend += v;
        _check(string.concat("named mtxShield(alice, ", vm.toString(v), "), the payer's UASig", w));
    }

    /// alice's own roll-over (`mtxRollOverSigned`, direct): her Schnorr over typed `ZetherRollOver` in the token's domain.
    function _rollOverSigned(string memory w) internal {
        (uint64 seq, IUARegistry.UASig memory o, uint64 vub) = _ownerRoll();
        NormalZetherToken(t).mtxRollOverSigned(ZetherTypes.UA.wrap(uas[0]), seq, vub, o);
        (aAcc, aPend) = (aAcc + aPend, 0);
        _check(string.concat("mtxRollOverSigned(alice), the owner's Schnorr", w));
    }

    function _rollOverSignedNamed(string memory w) internal {
        (uint64 seq, IUARegistry.UASig memory o, uint64 vub) = _ownerRoll();
        MetaTxLib.UAMetaTransaction memory m = _envelope();
        NormalZetherToken(t).mtxRollOverSigned(_ue(m), ZetherTypes.UA.wrap(uas[0]), seq, vub, o, _uaSig(string.concat(
            "UARollOverSigned(bytes32 from,bytes32 ua,uint64 expectedPendingSeq,uint64 validUntilBlock,", ENV_TAIL),
            abi.encode(uas[0], seq, vub), m));
        (aAcc, aPend) = (aAcc + aPend, 0);
        _check(string.concat("named mtxRollOverSigned(alice): the owner's Schnorr inside, the payer's UASig", w));
    }

    function _ownerRoll() internal returns (uint64 seq, IUARegistry.UASig memory o, uint64 vub) {
        IZetherToken.AccountState memory s = IZetherToken(t).accountState(ZetherTypes.UA.wrap(uas[0]));
        (seq, vub) = (s.pendingSeq, uint64(block.number + 100_000));
        o = _owner(keccak256(abi.encode(TH_ROLL_OVER, uas[0], s.accSeq, seq, vub)));
    }

    /// The roll-over mode: OWNER_ONLY by the owner directly, back to PUBLIC by the named entry (its `modeNonce` moved).
    function _modes(string memory w) internal {
        ZetherTypes.UA a = ZetherTypes.UA.wrap(uas[0]);
        uint64 vub = uint64(block.number + 100_000);
        IZetherToken.AccountState memory s = IZetherToken(t).accountState(a);
        NormalZetherToken(t).mtxSetRollOverMode(a, ZetherTypes.RollOverMode.OWNER_ONLY, vub,
            _owner(keccak256(abi.encode(TH_SET_MODE, uas[0], uint8(ZetherTypes.RollOverMode.OWNER_ONLY), s.modeNonce, vub))));
        s = IZetherToken(t).accountState(a);
        require(s.mode == ZetherTypes.RollOverMode.OWNER_ONLY, "mode OWNER_ONLY");
        console.log(string.concat("ok    mtxSetRollOverMode(alice, OWNER_ONLY), the owner's Schnorr", w));
        MetaTxLib.UAMetaTransaction memory m = _envelope();
        NormalZetherToken(t).mtxSetRollOverMode(_ue(m), a, ZetherTypes.RollOverMode.PUBLIC, vub,
            _owner(keccak256(abi.encode(TH_SET_MODE, uas[0], uint8(ZetherTypes.RollOverMode.PUBLIC), s.modeNonce, vub))),
            _uaSig(string.concat("UASetRollOverMode(bytes32 from,bytes32 ua,uint8 rollOverMode,uint64 validUntilBlock,", ENV_TAIL),
                abi.encode(uas[0], uint8(ZetherTypes.RollOverMode.PUBLIC), vub), m));
        require(IZetherToken(t).accountState(a).mode == ZetherTypes.RollOverMode.PUBLIC, "mode PUBLIC");
        console.log(string.concat("ok    named mtxSetRollOverMode(alice, PUBLIC), the payer's UASig", w));
    }

    /// The named `mtxWrapShield` (an address `Envelope`, the payer's own key, no fee): its underlying pulled from the payer.
    function _wrapShieldNamed(uint256 pk, address payer) internal {
        vm.broadcast(PAYER_PK);
        IERC20(und).approve(wt, 10);
        MetaTxLib.Envelope memory e;
        (e.from, e.batch, e.nonce, e.validUntil) = (payer, 8, NormalZetherToken(wt).mtxNonce(MetaTxLib.pad(payer), 8), block.timestamp + 1 days);
        bytes32 d = keccak256(abi.encodePacked(hex"1901", _dom(wt), keccak256(abi.encode(keccak256(
            "WrapShield(address from,address underlying,uint256 amountIn,bytes32 toUA,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
            payer, und, uint256(10), uas[0], e.batch, e.nonce, e.validUntil, uint32(0), address(0), uint256(0), address(0)))));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PAYER_PK, d);
        vm.broadcast(pk);
        WrappedZetherToken(payable(wt)).mtxWrapShield(e, und, 10, uas[0], abi.encodePacked(r, s, v));
        aPend += 10;
        _check("named mtxWrapShield(payer's 10 -> alice) (wrapped)");
    }

    // ------------------------------------------------------------------ signing

    function _dom(address c) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address vc, bytes32 s,) = IERC5267(c).eip712Domain();
        return keccak256(abi.encode(SALTED, keccak256(bytes(name)), keccak256(bytes(version)), chainId, vc, s));
    }

    function _ue(MetaTxLib.UAMetaTransaction memory m) internal pure returns (MetaTxLib.UAEnvelope memory) {
        return MetaTxLib.UAEnvelope(m.from, m.batch, m.nonce, m.validUntil, m.mode, m.relayer, m.fee, m.feeRecipient);
    }

    /// The payer's `UASig` over a named UA-envelope entry's struct `typ` (words = its own fields, a dynamic one hashed) in the
    /// token's domain, relayer / fee recipient canonical (`MetaTxLib.canon`).
    function _uaSig(string memory typ, bytes memory words, MetaTxLib.UAMetaTransaction memory m)
        internal view returns (IUARegistry.UASig memory a)
    {
        address r = m.mode & MetaTxLib.MODE_RESTRICT_RELAYER != 0 ? m.relayer : address(0);
        address f = m.mode & MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT != 0 ? m.feeRecipient : address(0);
        bytes32 d = keccak256(abi.encodePacked(hex"1901", _dom(t), keccak256(bytes.concat(keccak256(bytes(typ)), m.from, words,
            abi.encode(m.batch, m.nonce, m.validUntil, m.mode, r, m.fee, f)))));
        (uint8 v, bytes32 rr, bytes32 s) = vm.sign(PAYER_PK, d);
        a.signature = abi.encodePacked(rr, s, v);
    }

    /// alice's owner signature (`zether-cli ownerAuth`: Schnorr by x under `zether-owner`) over `structHash` in the token's
    /// domain, as `UASig{signature}`.
    function _owner(bytes32 structHash) internal returns (IUARegistry.UASig memory o) {
        bytes32 d = keccak256(abi.encodePacked(hex"1901", _dom(t), structHash));
        o.signature = _cli("ownerAuth", string.concat("{", _key(0), ",", _q("digest", vm.toString(d)), "}")).readBytes(".sig");
    }
}

interface IZetherStatementsUnwrap {
    function unwrapBinding(address u, uint256 minOut) external view returns (bytes32);
}
