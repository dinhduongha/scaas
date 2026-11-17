// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ISCaaSDex} from "./ISCaaSDex.sol";
import {IPositionReader} from "./IPositionReader.sol";
import {SCaaSDexCore} from "./SCaaSDexCore.sol";
import {DexPuller} from "./DexPuller.sol";
import {TokenCall} from "./TokenCall.sol";
import {ITradeToken, ILiquidityPullToken} from "../trade/ITradeToken.sol";
import {LiquidityLib} from "../trade/LiquidityLib.sol";
import {TradeLib} from "../trade/TradeLib.sol";
import {ChainEnvCode} from "../factory/ChainEnvCode.sol";
import {IOpenFactory} from "../factory/IOpenFactory.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {IUALedger} from "../metatx/IUALedger.sol";
import {UAKinds} from "../ua/UAKinds.sol";

/// @title SCaaSDexLiquidityModule: the DEX's liquidity module (group 11; CTR-DEX-30, -31; spec
///        2026-11-10-dex-liquidity.md §6, §9): `mtxLiquidity` and `liquidityOrderDigest`, reached only by DELEGATECALL
///        from the DEX's stubs (M2), no guard of its own (the stub's `nonReentrant` holds the DEX's transient guard, M3),
///        no state of its own (M6), never another module (M7). One signed `LiquidityOrder`, atomic: (1) check, (2)
///        snapshot, (3) pull, (4) the interactions (CTR-DEX-23, and no `approve` aimed at the position manager), (5) the
///        received position against its signed, listed reader, a given one not received back spent whole, (6) every output
///        at its minimum at the DEX after the fee and again at the recipient, (7) every leftover to the signer (a refund may
///        exceed its pull), (8) conservation, (9) the event. Outcomes only: no AMM-specific execution code. Since the owner's
///        size ruling of 2026-11-10 (lever (b)) it also holds the DEX-domain cancels `mtxCancelOrders` and
///        `mtxInvalidateNonces` and their digest views, which share its signature check. UNAUDITED.
contract SCaaSDexLiquidityModule is SCaaSDexCore {
    /// @notice A module-face entry called other than by DELEGATECALL from its DEX (M2).
    error NotDelegated();

    /// @dev C9: at most eight inputs, eight outputs and eight extra tokens.
    uint256 internal constant MAX_ITEMS = 8;
    /// @dev ERC-721 `ownerOf(uint256)`, `transferFrom(address,address,uint256)` (ERC-20's selector) and the reader's views.
    bytes4 internal constant OWNER_OF = 0x6352211e;

    address private immutable _SELF = address(this);
    address private immutable _FACTORY;

    /// @dev One plan's figures, in memory (the stack limit, via_ir off).
    struct Run {
        bytes32 h;
        bytes32 to;          // the recipient after its default
        address from;        // the signer's address when native, else 0
        address submitter;
        address[] tok;       // inputs, outputs, extraTokens
        uint256[] snap;      // the DEX's balance of each
        uint256[] rsnap;     // the recipient's balance of each output
        uint256 posSnap;     // the DEX's ERC-721 balance of the position manager
        uint256[] refunded;
        uint256[] received;
        uint256[] fees;
        uint128 liquidity;
    }

    modifier onlyDelegated() {
        if (address(this) == _SELF) revert NotDelegated();
        _;
    }

    /// @param factory_ the DEX's factory (the DEX's own constructor argument; M1); the bytes are the DEX's, unused.
    constructor(address factory_, bytes memory) {
        _FACTORY = factory_;
    }

    function moduleGroup() external pure returns (uint8) { return GROUP_LIQUIDITY; }

    /// @notice The factory of the DEX releases this module serves (checked by `SCaaSDex`'s constructor).
    function factory() external view returns (address) { return _FACTORY; }

    /// @notice `h` in the DEX's domain (§4.3): under DELEGATECALL `address(this)` is the clone and `chain_uid` its env.
    function liquidityOrderDigest(ITradeToken.LiquidityOrder calldata o) external view onlyDelegated returns (bytes32) {
        return LiquidityLib.digest(o, address(this), ChainEnvCode.chainUid());
    }

    // ------------------------------------------------------------------ the DEX-domain cancels (CTR-DEX-18, -02; lever (b))

    /// @notice `CancelDexOrder(DexOrder order)` in the DEX's domain (the clone, its `chain_uid`).
    function cancelDexOrderDigest(address sellToken, ITradeToken.TradeOrder calldata o) external view onlyDelegated
        returns (bytes32)
    {
        return _cancelDigest(sellToken, o);
    }

    function invalidateNoncesDigest(address from, uint256 batch, uint256 newMin) external view onlyDelegated returns (bytes32) {
        return _invalidateDigest(from, batch, newMin);
    }

    /// @notice As before the move: a closed order or a bad signature skips that item; a starved ERC-1271 check reverts.
    function mtxCancelOrders(ISCaaSDex.DexOrder[] calldata orders, bytes[] calldata sigs) external onlyDelegated {
        if (orders.length != sigs.length) revert ISCaaSDex.LengthMismatch();
        for (uint256 i; i < orders.length; ++i) {
            ITradeToken.TradeOrder calldata o = orders[i].order;
            if (SigCheck.isValid(o.from, _cancelDigest(orders[i].sellToken, o), sigs[i], _cap(o.from))) {
                TradeLib._cancel(_dexDigest(_dexOrderHash(orders[i].sellToken, o)), o.amount, TradeLib.pad(o.from), false);
            }
        }
    }

    function mtxInvalidateNonces(address from, uint256 batch, uint256 newMin, bytes calldata sig) external onlyDelegated {
        bytes32 d = _invalidateDigest(from, batch, newMin);
        if (!SigCheck.isValid(from, d, sig, _cap(from))) revert ISCaaSDex.BadSignature(d);
        TradeLib._invalidate(TradeLib.pad(from), batch, newMin, false);
    }

    function _cancelDigest(address sellToken, ITradeToken.TradeOrder calldata o) private view returns (bytes32) {
        return _dexDigest(keccak256(abi.encode(CANCEL_DEX_ORDER_TYPEHASH, _dexOrderHash(sellToken, o))));
    }

    function _invalidateDigest(address from, uint256 batch, uint256 newMin) private view returns (bytes32) {
        return _dexDigest(keccak256(abi.encode(TradeLib.INVALIDATE_NONCES_TYPEHASH, from, batch, newMin)));
    }

    /// @dev `SaltedEIP712._hashTypedDataV4` of the DEX: its separator from `LiquidityLib`'s constant hashes (the KATs pin it).
    function _dexDigest(bytes32 structHash) private view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", LiquidityLib.separator(address(this), ChainEnvCode.chainUid()), structHash));
    }

    /// @notice CTR-DEX-30: `msg.sender` is the DEX's caller, the submitter.
    function mtxLiquidity(ISCaaSDex.LiquidityPlan calldata p, ISCaaSDex.Interaction[] calldata xs) external onlyDelegated {
        Run memory r = _check(p, msg.sender);
        _snapshot(p, r);
        _pullAll(p, r);
        _routeLiquidity(p.order, xs);
        _positions(p, r);
        _outputs(p.order, r);
        _refunds(p.order, r);
        _conserve(p.order, r);
        emit ISCaaSDex.LiquiditySettled(p.ref, r.h, p.order.from, r.to, p.pull, r.refunded, r.received, r.fees,
            p.positionId, r.liquidity);
    }

    // ------------------------------------------------------------------ 1. check

    function _check(ISCaaSDex.LiquidityPlan calldata p, address submitter) private returns (Run memory r) {
        ITradeToken.LiquidityOrder calldata o = p.order;
        r.submitter = submitter;
        r.to = o.recipient == 0 ? o.from : o.recipient;
        r.tok = _shape(p, r.to);
        if (o.relayer != address(0) && o.relayer != submitter) revert ISCaaSDex.WrongRelayer(submitter);
        bytes32 h = LiquidityLib.digest(o, address(this), ChainEnvCode.chainUid());
        r.h = h;
        if (block.timestamp > o.validUntil) revert ISCaaSDex.OrderExpired(h);
        if (o.nonce >= TradeLib.MAX_MIN_NONCE) revert ISCaaSDex.NonceAboveCap(h);
        TradeLib.TradeStorage storage t = TradeLib.$();
        if (o.nonce < t.minNonce[o.from][o.batch]) revert ISCaaSDex.NonceInvalidated(h);
        if (o.flags & ~LISTED_POOLS != 0) revert ISCaaSDex.BadFlags(h);
        if (o.fee > TradeLib.MAX_FEE_PPM) revert ISCaaSDex.FeeAboveCap(h);
        if (t.pulled[h] != 0) revert ISCaaSDex.OrderClosed(h);
        if (p.pull.length != o.inputs.length) revert ISCaaSDex.LengthMismatch();
        // kinds from the DEX's record (C6); the UA rules (CTR-UA-27): a derived signer gives SCaaS inputs with the
        // ledger on and no position; a derived recipient receives SCaaS outputs with the ledger on and no position
        bool derived = !UAKinds.inNativeSpace(o.from);
        bool verify = o.positionIn != 0;
        for (uint256 i; i < o.inputs.length; ++i) {
            if (p.pull[i] == 0) revert ISCaaSDex.ZeroFill(h);
            if (p.pull[i] > o.inputs[i].amount) revert ISCaaSDex.Overfill(h);
            address tk = o.inputs[i].token;
            if (derived && !_ledgerOn(tk)) revert ISCaaSDex.UALegNotLedger(tk);
            if (_s().kind[tk] != KIND_SCAAS || _deprecatedNow(tk)) verify = true;
        }
        if (derived && o.positionIn != 0) revert ISCaaSDex.UALegNotLedger(o.positionManager);
        if (!UAKinds.inNativeSpace(r.to)) {
            for (uint256 j; j < o.outputs.length; ++j) {
                if (!_ledgerOn(o.outputs[j].token)) revert ISCaaSDex.UAReceiveNotLedger(o.outputs[j].token);
            }
            if (o.positionPool != 0) revert ISCaaSDex.UAReceiveNotLedger(o.positionManager);
        }
        if (!derived) r.from = TradeLib.addr(o.from);
        // the DEX's own verify when anything moves outside the SCaaS tokens' own checks, or when an input's release is
        // deprecated now (the listing's kind is a snapshot; Fable D P3-4); with live SCaaS inputs only, each token verifies
        // `h` itself before the route runs
        if (verify && !SigCheck.isValid(r.from, h, p.auth.signature, _cap(r.from))) revert ISCaaSDex.BadSignature(h);
        t.pulled[h] = 1;
    }

    /// @dev A SCaaS input's release deprecated after its listing (Fable D P3-4): the factory read at use, so the skip of
    ///      the DEX's own verify never trusts a release the admin has since closed.
    function _deprecatedNow(address token) private view returns (bool) {
        (IOpenFactory.TokenKind k, uint64 v) = IOpenFactory(_FACTORY).versionOf(token);
        return IOpenFactory(_FACTORY).isTokenDeprecated(k, v);
    }

    /// @dev Shape codes 1-5 (§6 step 1); returns the plan's tokens: inputs, outputs, extraTokens.
    function _shape(ISCaaSDex.LiquidityPlan calldata p, bytes32 to) private view returns (address[] memory tok) {
        ITradeToken.LiquidityOrder calldata o = p.order;
        (uint256 ni, uint256 no, uint256 ne) = (o.inputs.length, o.outputs.length, p.extraTokens.length);
        bool received = o.positionPool != 0;
        if ((ni == 0 && o.positionIn == 0) || (no == 0 && !received)) revert ISCaaSDex.LiquidityShape(1);
        if (ni > MAX_ITEMS || no > MAX_ITEMS || ne > MAX_ITEMS) revert ISCaaSDex.LiquidityShape(2);
        tok = new address[](ni + no + ne);
        for (uint256 i; i < ni; ++i) {
            if (o.inputs[i].amount == 0) revert ISCaaSDex.LiquidityShape(3);
            tok[i] = o.inputs[i].token;
        }
        for (uint256 j; j < no; ++j) tok[ni + j] = o.outputs[j].token;
        for (uint256 k; k < ne; ++k) tok[ni + no + k] = p.extraTokens[k];
        address pm = o.positionManager;
        for (uint256 a; a < tok.length; ++a) {
            if (tok[a] == address(0) || tok[a] == pm) revert ISCaaSDex.LiquidityShape(3);
            for (uint256 b; b < a; ++b) if (tok[b] == tok[a]) revert ISCaaSDex.LiquidityShape(3);
        }
        if (pm == address(0) && (o.positionIn != 0 || received)) revert ISCaaSDex.LiquidityShape(4);
        if (received
            ? (o.positionReader == address(0) || o.tickLower >= o.tickUpper || o.minLiquidity == 0)
            : (o.positionReader != address(0) || o.tickLower != 0 || o.tickUpper != 0 || o.minLiquidity != 0)) {
            revert ISCaaSDex.LiquidityShape(4);
        }
        if ((p.positionId != 0) != received) revert ISCaaSDex.LiquidityShape(4);
        if (to == TradeLib.pad(address(this)) || to == TradeLib.pad(_s().puller) || to == TradeLib.pad(pm)) {
            revert ISCaaSDex.LiquidityShape(5);
        }
        for (uint256 a; a < tok.length; ++a) if (to == TradeLib.pad(tok[a])) revert ISCaaSDex.LiquidityShape(5);
    }

    // ------------------------------------------------------------------ 2-4. snapshot, pull, route

    function _snapshot(ISCaaSDex.LiquidityPlan calldata p, Run memory r) private view {
        ITradeToken.LiquidityOrder calldata o = p.order;
        // a token without code holds nothing yet: only the plan's own interactions can create it (a v2 pair, §8.1)
        r.snap = new uint256[](r.tok.length);
        for (uint256 i; i < r.tok.length; ++i) if (r.tok[i].code.length != 0) r.snap[i] = _bal(r.tok[i]);
        if (o.positionManager != address(0)) r.posSnap = _bal(o.positionManager); // ERC-721 `balanceOf`: one selector
        r.rsnap = new uint256[](o.outputs.length);
        for (uint256 j; j < o.outputs.length; ++j) {
            if (o.outputs[j].token.code.length != 0) r.rsnap[j] = _balOf(o.outputs[j].token, r.to);
        }
    }

    /// @dev Step 3: SCaaS inputs by the token's `mtxLiquidityPull` (it verifies `h` itself), outside inputs and a given
    ///      position through the puller; each input's balance rose by exactly its pull (a fee-on-transfer input fails here).
    function _pullAll(ISCaaSDex.LiquidityPlan calldata p, Run memory r) private {
        ITradeToken.LiquidityOrder calldata o = p.order;
        DexStorage storage s = _s();
        for (uint256 i; i < o.inputs.length; ++i) {
            address tk = o.inputs[i].token;
            if (s.kind[tk] == KIND_SCAAS) ILiquidityPullToken(tk).mtxLiquidityPull(o, p.auth, p.pull[i], r.submitter);
            else DexPuller(s.puller).pull(tk, r.from, p.pull[i]);
        }
        if (o.positionIn != 0) {
            DexPuller(s.puller).pull(o.positionManager, r.from, o.positionIn); // C7: ERC-721 `transferFrom`, one selector
            if (_ownerOf(o.positionManager, o.positionIn) != uint160(address(this))) {
                revert ISCaaSDex.PositionNotReceived(o.positionIn);
            }
        }
        for (uint256 i; i < o.inputs.length; ++i) {
            if (_bal(r.tok[i]) != r.snap[i] + p.pull[i]) revert ISCaaSDex.ConservationBroken(r.tok[i]);
        }
    }

    /// @dev Step 4: an `approve` aimed at the manager is refused here (ERC-721 `approve` shares ERC-20's selector, and the
    ///      reset `approve(spender, 0)` would name token id 0); then CTR-DEX-23's shared loop and the allowance reset.
    function _routeLiquidity(ITradeToken.LiquidityOrder calldata o, ISCaaSDex.Interaction[] calldata xs) private {
        address pm = o.positionManager;
        if (pm != address(0)) {
            for (uint256 i; i < xs.length; ++i) {
                if (xs[i].target == pm && bytes4(xs[i].data) == IERC20.approve.selector) {
                    revert ISCaaSDex.ForbiddenSelector(pm, IERC20.approve.selector);
                }
            }
        }
        _route(xs, _s().listedOnly || o.flags & LISTED_POOLS != 0);
    }

    // ------------------------------------------------------------------ 5. positions

    function _positions(ISCaaSDex.LiquidityPlan calldata p, Run memory r) private {
        ITradeToken.LiquidityOrder calldata o = p.order;
        address pm = o.positionManager;
        if (o.positionPool != 0) {
            uint256 id = p.positionId;
            if (_ownerOf(pm, id) != uint160(address(this))) revert ISCaaSDex.PositionNotReceived(id);
            address rd = o.positionReader;
            (bool ok, uint256 m) = _word(rd, abi.encodeWithSelector(IPositionReader.manager.selector));
            if (!_s().exchangeTarget[rd] || !ok || m != uint160(pm)) revert ISCaaSDex.PositionReaderNotListed(rd);
            r.liquidity = _readPosition(o, id);
            address to = TradeLib.addr(r.to); // native: a derived recipient receives no position (step 1)
            // `transferFrom`, never `safeTransferFrom`: no callback into the recipient
            if (!TokenCall.ok(pm, abi.encodeCall(IERC20.transferFrom, (address(this), to, id)))) _tokenFailed(pm);
            if (_ownerOf(pm, id) != uint160(to)) revert ISCaaSDex.PositionNotDelivered(id);
        }
        // a given position not received back is spent whole (P0-1); housekeeping only: one the DEX still owns goes back
        // to `from`; an `ownerOf` that reverts means burnt; another owner means an interaction moved it (the minima bound)
        if (o.positionIn != 0 && (o.positionPool == 0 || p.positionId != o.positionIn)) {
            (bool ok, uint256 w) = _word(pm, abi.encodeWithSelector(OWNER_OF, o.positionIn));
            if (ok && w == uint160(address(this))
                && !TokenCall.ok(pm, abi.encodeCall(IERC20.transferFrom, (address(this), r.from, o.positionIn)))) {
                _tokenFailed(pm);
            }
        }
    }

    /// @dev `reader.position(id)`: capped, its revert data dropped, at least five words; each word compared raw, so a
    ///      dirty encoding is a mismatch, never a decode revert.
    function _readPosition(ITradeToken.LiquidityOrder calldata o, uint256 id) private view returns (uint128) {
        address rd = o.positionReader;
        bytes4 sel = IPositionReader.position.selector;
        bool ok;
        uint256 pool;
        uint256 lo;
        uint256 hi;
        uint256 liq;
        uint256 enc;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, sel)
            mstore(add(m, 4), id)
            let g := gas()
            if gt(g, 500000) { g := 500000 } // C6-1: TokenCall.TOKEN_GAS
            ok := staticcall(g, rd, m, 0x24, m, 0xa0)
            ok := and(ok, gt(returndatasize(), 0x9f))
            pool := mload(m)
            lo := mload(add(m, 0x20))
            hi := mload(add(m, 0x40))
            liq := mload(add(m, 0x60))
            enc := mload(add(m, 0x80))
        }
        if (!ok || liq > type(uint128).max) revert ISCaaSDex.PositionUnreadable(rd);
        if (bytes32(pool) != o.positionPool || lo != uint256(int256(o.tickLower)) || hi != uint256(int256(o.tickUpper))
            || enc != 0) revert ISCaaSDex.PositionMismatch(id);
        if (liq < o.minLiquidity) revert ISCaaSDex.PositionBelowMin(id, uint128(liq));
        return uint128(liq);
    }

    // ------------------------------------------------------------------ 6-8. outputs, refunds, conservation

    /// @dev Step 6 (review P1-1): `got` measured at the DEX, the fee `⌈got · fee / 10⁶⌉`, `got − fee ≥ min`, the payout,
    ///      the recipient's delta ≥ min (the fee-on-transfer backstop, before the fee shares), then the shares.
    function _outputs(ITradeToken.LiquidityOrder calldata o, Run memory r) private {
        DexStorage storage s = _s();
        uint256 ni = o.inputs.length;
        r.received = new uint256[](o.outputs.length);
        r.fees = new uint256[](o.outputs.length);
        for (uint256 j; j < o.outputs.length; ++j) {
            address tk = o.outputs[j].token;
            uint256 min = o.outputs[j].amount;
            uint256 b = _bal(tk);
            if (b < r.snap[ni + j]) revert ISCaaSDex.ConservationBroken(tk);
            uint256 got = b - r.snap[ni + j];
            uint256 fee = Math.mulDiv(got, o.fee, PPM, Math.Rounding.Ceil);
            if (got - fee < min) revert ISCaaSDex.InsufficientOutput(tk);
            _sendTo(tk, r.to, got - fee);
            uint256 rb = _balOf(tk, r.to);
            if (rb < r.rsnap[j] || rb - r.rsnap[j] < min) revert ISCaaSDex.InsufficientOutput(tk);
            uint256 share = Math.mulDiv(fee, s.relayerSharePpm, PPM);
            _send(tk, r.submitter, share);
            _send(tk, s.treasury, fee - share);
            (r.received[j], r.fees[j]) = (got - fee, fee);
        }
    }

    /// @dev Step 7 (review P2-2): every input's leftover to `from`, fee-free, with no upper bound (a route may return more
    ///      than it pulled: fees a position collected).
    function _refunds(ITradeToken.LiquidityOrder calldata o, Run memory r) private {
        r.refunded = new uint256[](o.inputs.length);
        for (uint256 i; i < o.inputs.length; ++i) {
            address tk = r.tok[i];
            uint256 b = _bal(tk);
            if (b < r.snap[i]) revert ISCaaSDex.ConservationBroken(tk);
            r.refunded[i] = b - r.snap[i];
            _sendTo(tk, o.from, r.refunded[i]);
        }
    }

    /// @dev Step 8: every plan token and the position balance back at their snapshots.
    function _conserve(ITradeToken.LiquidityOrder calldata o, Run memory r) private view {
        for (uint256 i; i < r.tok.length; ++i) {
            if (_bal(r.tok[i]) != r.snap[i]) revert ISCaaSDex.ConservationBroken(r.tok[i]);
        }
        if (o.positionManager != address(0) && _bal(o.positionManager) != r.posSnap) {
            revert ISCaaSDex.ConservationBroken(o.positionManager);
        }
    }

    // ------------------------------------------------------------------ reads (W-O: capped, one word, no revert data)

    /// @dev One word from a capped `staticcall`; `ok` false when it reverted or returned less than a word.
    function _word(address target, bytes memory data) private view returns (bool ok, uint256 w) {
        assembly ("memory-safe") {
            let g := gas()
            if gt(g, 500000) { g := 500000 } // C6-1: TokenCall.TOKEN_GAS
            ok := staticcall(g, target, add(data, 0x20), mload(data), 0, 0x20)
            ok := and(ok, gt(returndatasize(), 0x1f))
            w := mload(0)
        }
    }

    /// @dev `ownerOf(id)` as a word; a failed read reverts as `_tokenFailed` does.
    function _ownerOf(address pm, uint256 id) private view returns (uint256 w) {
        bool ok;
        (ok, w) = _word(pm, abi.encodeWithSelector(OWNER_OF, id));
        if (!ok) _tokenFailed(pm);
    }

    /// @dev The balance of an id: `balanceOf` of a native one, `balanceOfUA` of a derived one.
    function _balOf(address token, bytes32 id) private view returns (uint256 w) {
        bool ok;
        (ok, w) = _word(token, UAKinds.inNativeSpace(id)
            ? abi.encodeCall(IERC20.balanceOf, (TradeLib.addr(id)))
            : abi.encodeCall(IUALedger.balanceOfUA, (id)));
        if (!ok) _tokenFailed(token);
    }
}
