// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {MetaTxBase} from "./MetaTxBase.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {IERC20Payment} from "./IERC20Payment.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeePolicy, FeeMode} from "../common/FeePolicy.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {ITradeToken} from "../trade/ITradeToken.sol";
import {TradeLib} from "../trade/TradeLib.sol";

/// @title The token base of every SCaaS token (CTR-MTX-07): ERC-20 on `MetaTxBase`.
/// @notice Adds to the generic base: the fee in this token (`_chargeFee` by fee class, CTR-MTX-20), the typed
///         `MetaTransfer` path (`mtxExecuteTransfer`, `mtxBatchTransfer`, CTR-MTX-23/24) on the same lanes, the
///         allowance rule (CTR-TOK-01) and "no tokens at the token's own address" (CTR-MTX-18). Domain
///         `("SCaaS MetaToken", "1", chainId, clone, chain_uid)` for every kind (CTR-MTX-02). The sell side of a
///         `TradeOrder` (CTR-DEX-15) through `TradeLib`.
abstract contract ERC20MetaTx is ERC20, MetaTxBase, IERC20Payment, ITradeToken {
    using MetaTxLib for MetaTxLib.MetaTransfer;

    constructor(bytes32 chainUid_) ERC20("", "") MetaTxBase("SCaaS MetaToken", chainUid_) {}

    // ------------------------------------------------------------------ views

    /// @notice `0xF3`: both flags and every fee mode (a token holds the charged balance).
    function supportedModes() public pure override(IMetaTx, MetaTxBase) returns (uint32) {
        return MetaTxLib.MODE_KNOWN_MASK;
    }

    function mtxTransferDigest(MetaTxLib.MetaTransfer calldata t) external view returns (bytes32) {
        return _hashTypedDataV4(t.hashStruct());
    }

    // ------------------------------------------------------------------ trade orders (CTR-DEX-15, CTR-DEX-02)

    function tradeOrderDigest(TradeOrder calldata o) public view returns (bytes32) {
        return _hashTypedDataV4(TradeLib.hashStruct(o));
    }

    function cancelOrderDigest(bytes32 orderHash) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(TradeLib.CANCEL_ORDER_TYPEHASH, orderHash)));
    }

    function invalidateNoncesDigest(address from, uint256 batch, uint256 newMin) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(TradeLib.INVALIDATE_NONCES_TYPEHASH, from, batch, newMin)));
    }

    function pulled(bytes32 orderHash) external view returns (uint256) {
        return TradeLib.$().pulled[orderHash];
    }

    function minNonce(address from, uint256 batch) external view returns (uint256) {
        return TradeLib.$().minNonce[from][batch];
    }

    /// @notice Only `o.dex` calls (a direct read of the caller, CTR-MTX-18); never allowlisted. Moves the fill from
    ///         `o.from` to `o.dex` and nowhere else.
    function mtxTrade(TradeOrder calldata o, bytes calldata sig, TradeFill calldata f) external nonReentrant {
        bytes32 h = tradeOrderDigest(o);
        TradeLib.precheck(o, f, h, msg.sender);
        _requireValidSignature(o.from, h, sig);
        _transfer(o.from, o.dex, TradeLib.record(o, f, h));
    }

    /// @notice Cancel signatures never expire (CTR-DEX-02); anyone may submit one.
    function mtxCancelOrder(TradeOrder calldata o, bytes calldata sig) external nonReentrant {
        bytes32 h = tradeOrderDigest(o);
        _requireValidSignature(o.from, cancelOrderDigest(h), sig);
        TradeLib.cancel(o, h);
    }

    function mtxInvalidateNonces(address from, uint256 batch, uint256 newMin, bytes calldata sig) external nonReentrant {
        _requireValidSignature(from, invalidateNoncesDigest(from, batch, newMin), sig);
        TradeLib.invalidate(from, batch, newMin);
    }

    // ------------------------------------------------------------------ typed path (CTR-MTX-23, CTR-MTX-24)

    function mtxExecuteTransfer(MetaTxLib.MetaTransfer calldata t, bytes calldata signature)
        external nonReentrant returns (bool)
    {
        _executeTransfer(t, signature);
        return true;
    }

    /// @notice Atomic, items in order; never mixed with `MetaTransaction`s (CTR-MTX-24).
    function mtxBatchTransfer(MetaTxLib.MetaTransfer[] calldata ts, bytes[] calldata signatures)
        external nonReentrant returns (bool)
    {
        uint256 n = ts.length;
        if (n == 0) revert MtxBatchEmpty();
        if (n != signatures.length) revert MtxBatchLengthMismatch();
        for (uint256 i; i < n; ++i) _executeTransfer(ts[i], signatures[i]);
        return true;
    }

    /// @dev Every typed entry (struct, batch, the named builders, receiver-pays) goes through here. Everything is
    ///      checked before the nonce and the transfers, which cannot fail afterwards. Returns the digest.
    function _executeTransfer(MetaTxLib.MetaTransfer memory t, bytes calldata signature)
        internal returns (bytes32 digest)
    {
        _checkEnvelope(t.from, t.batch, t.nonce, t.validUntil, t.mode, t.relayer);              // 1
        digest = _hashTypedDataV4(t.hashStruct());                                              // 2
        _requireValidSignature(t.from, digest, signature);
        (uint256 fee, address feeTo) = _checkTransfer(t);                                       // 3
        _useNonce(t.from, t.batch);                                                             // 4
        if (fee != 0) _transfer(t.from, feeTo, fee);                                            // 5
        _transfer(t.from, t.to, t.value);
        if (t.entryRef != 0) emit PaymentSettled(t.from, t.to, t.value, fee, feeTo, t.entryRef);
        emit MetaTransactionExecuted(t.from, msg.sender, t.batch, t.nonce, digest, feeTo, fee); // 6
    }

    /// @dev Step 3: payee, fee on `value` (capped, CTR-MTX-13), the payee check (CTR-MTX-08), balance.
    function _checkTransfer(MetaTxLib.MetaTransfer memory t) private view returns (uint256 fee, address feeTo) {
        if (t.to == address(0)) revert PayToZero();
        if (t.to == address(this)) revert TransferToSelf();
        FeeMode fm = MetaTxLib.feeModeOf(t.mode);
        feeTo = t.feeRecipient == address(0) ? msg.sender : t.feeRecipient;
        fee = FeePolicy.compute(fm, t.value, t.fee);
        FeePolicy.validateRecipient(fm, feeTo);
        if (fee != 0) {
            if (feeTo == t.to) revert FeeRecipientIsPayee();
            if (feeTo == address(this)) revert TransferToSelf();
        }
        uint256 need = t.value + fee;
        uint256 have = balanceOf(t.from);
        if (have < need) revert MetaTxInsufficientForFee(need, have);
    }

    // ------------------------------------------------------------------ fee of a self-call (CTR-MTX-20)

    /// @notice After the call: `ABSOLUTE` + `FIXED` = the signed amount, uncapped (step 3 refused `ABSOLUTE` +
    ///         `PERCENT`); anything else = `FeePolicy.compute` on the basis (≤ 1 %), so a `PERCENT` fee is never
    ///         taken as a raw amount whatever class the rule reports here. A failing transfer reverts the call.
    function _chargeFee(address from, uint256 basis, MetaTxLib.MetaTransaction memory m)
        internal override returns (uint256 fee)
    {
        FeeMode fm = MetaTxLib.feeModeOf(m.mode);
        if (fm == FeeMode.NONE) return 0;
        bool absoluteFixed = fm == FeeMode.FIXED && _mtxRule(bytes4(m.data)).feeClass == FEE_CLASS_ABSOLUTE;
        fee = absoluteFixed ? m.fee : FeePolicy.compute(fm, basis, m.fee);
        address feeTo = _feeRecipientOf(m);
        FeePolicy.validateRecipient(fm, feeTo);
        if (fee != 0) _transfer(from, feeTo, fee);
    }

    // ------------------------------------------------------------------ allowance (CTR-TOK-01)

    /// @notice Caller and spender must both be contracts: no EOA grants or holds an allowance.
    function approve(address spender, uint256 value) public virtual override(ERC20, IERC20) returns (bool) {
        address caller = _msgSender();
        if (!SigCheck.isContract(caller)) revert CallerNotContract(caller);
        if (!SigCheck.isContract(spender)) revert SpenderNotContract(spender);
        return super.approve(spender, value);
    }

    /// @notice Only a contract spends an allowance; checked before the allowance.
    function transferFrom(address from, address to, uint256 value)
        public virtual override(ERC20, IERC20) returns (bool)
    {
        address caller = _msgSender();
        if (!SigCheck.isContract(caller)) revert CallerNotContract(caller);
        return super.transferFrom(from, to, value);
    }

    // ------------------------------------------------------------------ internals

    /// @dev Tokens parked at the token's own address are what a spoofed self-call would spend (CTR-MTX-18).
    function _update(address from, address to, uint256 value) internal virtual override {
        if (to == address(this)) revert TransferToSelf();
        super._update(from, to, value);
    }

    function _isContract(address a) internal view returns (bool) {
        return SigCheck.isContract(a);
    }

    function _msgSender() internal view virtual override(Context, MetaTxBase) returns (address) {
        return MetaTxBase._msgSender();
    }
}
