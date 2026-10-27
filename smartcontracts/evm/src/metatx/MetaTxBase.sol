// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeeMode} from "../common/FeePolicy.sol";
import {SaltedEIP712} from "../common/SaltedEIP712.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {MtxPipelineLib} from "./MtxPipelineLib.sol";

/// @title The generic meta-transaction base of every SCaaS contract (CTR-MTX-22).
/// @notice The subject signs a `MetaTransaction` (CTR-MTX-15) whose `data` is one call of one of THIS contract's
///         allowlisted functions; anyone submits it through `mtxExecute`, and the contract runs it on itself
///         (CTR-MTX-16, CTR-MTX-17). The signer travels in a transient slot and one ticket admits exactly one
///         self-call (CTR-MTX-18). The allowlist is fixed per implementation (CTR-MTX-19): an implementation
///         overrides `_mtxRule` (ending in `return super._mtxRule(sel);`) and `mtxSelectors` (the base entry
///         `cancelNonce` first). A contract that holds no charged balance accepts fee mode `NONE` only
///         (`supportedModes() = 0x03`, CTR-MTX-22).
abstract contract MetaTxBase is Context, SaltedEIP712, IMetaTx {
    /// @notice Fee classes published by `mtxSelectors()` (CTR-MTX-20). 0 = not allowlisted.
    uint8 internal constant FEE_CLASS_ABSOLUTE = MtxPipelineLib.FEE_CLASS_ABSOLUTE;
    uint8 internal constant FEE_CLASS_AMOUNT = MtxPipelineLib.FEE_CLASS_AMOUNT;

    /// @param feeClass  0 (not allowlisted), FEE_CLASS_ABSOLUTE or FEE_CLASS_AMOUNT
    /// @param amountArg for FEE_CLASS_AMOUNT: index of the uint256 argument that is the fee basis
    /// @param staticLen the selector's static ABI length of `data` (4 + 32·args); 0 = has dynamic arguments
    struct MtxRule {
        uint8 feeClass;
        uint8 amountArg;
        uint32 staticLen;
    }

    // Transient slots (CTR-MTX-18), written as literals: assembly takes no keccak256 constant.
    bytes32 private constant _GUARD = 0xf92fce36488cd980109789c37ce44669ca2ec8fc93bcd6d944c3a5544f9ce252; // keccak256("scaas.mtx.guard")
    bytes32 private constant _SENDER = 0x6f8cf97d962f34e862325b04dcb64b0eb0b06cf30b06b61c33210ec760df0f0b; // keccak256("scaas.mtx.sender")
    bytes32 private constant _TICKET = 0xdea51947149e025e6ed748bbba150c788d4bf051fa2851715a58709dbd31a816; // keccak256("scaas.mtx.ticket")
    bytes32 private constant _BINDING = 0x7a352a4ca0b7d094432a2dbe626c3b7c08a75c6b3464420d2516ca3859c7c12e; // keccak256("scaas.mtx.binding")

    // The nonce map (ERC-7201 `scaas.metatx`) is `MtxPipelineLib.MetaTxStorage`, defined there only. A mapping hashes
    // an `address` key as the padded word, so the slots of native ids are those of the earlier `address`-keyed map.

    /// @param domainName "SCaaS <Contract>" (CTR-MTX-02); the domain version is always "1".
    /// @param chainUid_  the chain's genesis block hash (CTR-GEN-05)
    constructor(string memory domainName, bytes32 chainUid_) SaltedEIP712(domainName, "1", chainUid_) {}

    /// @notice One contract-wide guard; the one self-call of step 5 may enter once and consumes the ticket.
    modifier nonReentrant() {
        bool outer = _tload(_GUARD) == 0;
        if (outer) {
            _tstore(_GUARD, 1);
        } else {
            if (msg.sender != address(this) || _tload(_TICKET) != 1) revert Reentrancy();
            _tstore(_TICKET, 2);
        }
        _;
        if (outer) _tstore(_GUARD, 0);
    }

    // ------------------------------------------------------------------ views

    function mtxNonce(address from, uint256 batch) public view returns (uint256) {
        return _nonce(MetaTxLib.pad(from), batch);
    }

    function mtxDigest(MetaTxLib.MetaTransaction calldata m) external view virtual returns (bytes32) {
        return _hashTypedDataV4(MtxPipelineLib._structHash(MetaTxLib.METATX_TYPEHASH, _envelopeOf(m)));
    }

    function chainUid() external view returns (bytes32) {
        return CHAIN_UID;
    }

    /// @notice `0x03`: flags only, fee mode `NONE`. A token (which charges the fee, `ERC20MetaTx`) returns `0xF3`.
    function supportedModes() public view virtual returns (uint32) {
        return MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT;
    }

    /// @notice The allowlist (CTR-MTX-19). An override returns the base entry first, then its own.
    function mtxSelectors()
        public view virtual returns (bytes4[] memory selectors, uint8[] memory feeClass, uint8[] memory amountArg)
    {
        selectors = new bytes4[](1);
        feeClass = new uint8[](1);
        amountArg = new uint8[](1);
        selectors[0] = IMetaTx.cancelNonce.selector;
        feeClass[0] = FEE_CLASS_ABSOLUTE;
    }

    // ------------------------------------------------------------------ entry points

    function mtxExecute(MetaTxLib.MetaTransaction calldata m, bytes calldata signature)
        external nonReentrant returns (bytes memory)
    {
        return _execute(m, signature);
    }

    /// @notice EIP-1776 alias of `mtxExecute` (CTR-MTX-17); returns `true`.
    function executeMetaTransaction(MetaTxLib.MetaTransaction calldata m, bytes calldata signature)
        external nonReentrant returns (bool)
    {
        _execute(m, signature);
        return true;
    }

    /// @notice Atomic: items run in order, each with a fresh ticket; any failure reverts all (CTR-MTX-11).
    function mtxBatch(MetaTxLib.MetaTransaction[] calldata ms, bytes[] calldata signatures)
        external nonReentrant returns (bool)
    {
        uint256 n = ms.length;
        if (n == 0) revert MtxBatchEmpty();
        if (n != signatures.length) revert MtxBatchLengthMismatch();
        for (uint256 i; i < n; ++i) {
            _requireBatchable(bytes4(ms[i].data));
            _execute(ms[i], signatures[i]);
        }
        return true;
    }

    /// @notice Direct, or signed through `mtxExecute` on another lane (a subject without gas can cancel).
    function cancelNonce(uint256 batch) external nonReentrant {
        address from = _msgSender();
        emit MetaNonceCancelled(from, batch, _bumpNonce(MetaTxLib.pad(from), batch));
    }

    // ------------------------------------------------------------------ pipeline (CTR-MTX-17)

    /// @dev Every entry (generic, alias, batch, later the named builders) goes through here.
    function _execute(MetaTxLib.MetaTransaction memory m, bytes calldata signature)
        internal virtual returns (bytes memory ret)
    {
        bytes32 digest = _checkIntent(m, signature);            // 1, 2
        uint256 basis = _checkCall(m.data, m.mode);             // 3
        _useNonce(MetaTxLib.pad(m.from), m.batch);              // 4
        ret = _selfCall(MetaTxLib.pad(m.from), m.data, _envelopeBinding(m)); // 5
        uint256 fee = _chargeFee(m.from, basis, m);             // 6
        emit MetaTransactionExecuted(m.from, msg.sender, m.batch, m.nonce, digest, _feeRecipientOf(m), fee); // 7
    }

    /// @dev Steps 1 (cheap) and 2 (signature).
    function _checkIntent(MetaTxLib.MetaTransaction memory m, bytes calldata signature)
        internal view returns (bytes32 digest)
    {
        _checkEnvelope(MetaTxLib.pad(m.from), m.batch, m.nonce, m.validUntil, m.mode, m.relayer);
        digest = _hashTypedDataV4(MtxPipelineLib._structHash(MetaTxLib.METATX_TYPEHASH, _envelopeOf(m)));
        _requireValidSignature(m.from, digest, signature);
    }

    /// @dev Step 1 on the shared lane space (CTR-MTX-15, CTR-UA-26): the common envelope of every signed struct
    ///      (`MetaTransaction`, `MetaTransfer` and the UA ledger's two), `from` as an id. Not virtual: one lane, one
    ///      nonce sequence.
    function _checkEnvelope(
        bytes32 from, uint256 batch, uint256 nonce, uint256 validUntil, uint32 mode, address relayer
    ) internal view {
        if (MtxPipelineLib._checkEnvelope(from, batch, nonce, validUntil, mode, relayer)) _selfSender();
    }

    function _nonce(bytes32 from, uint256 batch) internal view returns (uint256) {
        return MtxPipelineLib._mtxStorage().nonce[from][batch];
    }

    /// @dev Step 4: consume the lane's current nonce (call after `_checkEnvelope` passed).
    function _useNonce(bytes32 from, uint256 batch) internal {
        MtxPipelineLib._useNonce(from, batch);
    }

    /// @dev `cancelNonce` and the UA ledger's `uaCancelNonce`: the lane's next nonce, returned.
    function _bumpNonce(bytes32 from, uint256 batch) internal returns (uint256 n) {
        unchecked { n = ++MtxPipelineLib._mtxStorage().nonce[from][batch]; }
    }

    /// @dev Step 3: shape, allowlist, fee class, `supportedModes()` (`MtxPipelineLib._checkCall`). Returns the fee basis.
    function _checkCall(bytes memory data, uint32 mode) internal view returns (uint256 basis) {
        bytes4 sel = bytes4(data);
        MtxRule memory r = _mtxRule(sel);
        MtxPipelineLib._checkCall(sel, data.length, r.feeClass, r.amountArg, r.staticLen, mode, supportedModes());
        if (r.feeClass == FEE_CLASS_AMOUNT) {
            uint256 basisEnd = 36 + 32 * uint256(r.amountArg);
            assembly ("memory-safe") { basis := mload(add(data, basisEnd)) }
        }
    }

    /// @dev The envelope of `m` for `MtxPipelineLib._structHash`: `from` padded, `data` as its hash.
    function _envelopeOf(MetaTxLib.MetaTransaction memory m) internal pure returns (MtxPipelineLib.Envelope memory) {
        return MtxPipelineLib.Envelope(MetaTxLib.pad(m.from), keccak256(m.data), m.batch, m.nonce, m.validUntil, m.mode,
            m.relayer, m.fee, m.feeRecipient);
    }

    /// @dev Step 5: store the ticket (and the envelope binding, when the contract has one), call self, clear the ticket;
    ///      a failed call reverts with its own revert data. The binding is read only under a live ticket; it is written
    ///      on every self-call (0 included) and cleared on exit (C5-5). `subject` is the signer as
    ///      an id: a native address padded, or a derived UA (the UA ledger, CTR-UA-26), which the body sees as
    ///      `_msgSender() == UA_POOL` and `_ticketSubject() == subject`.
    function _selfCall(bytes32 subject, bytes memory data, bytes32 binding) internal returns (bytes memory ret) {
        _tstore(_SENDER, uint256(subject));
        _tstore(_TICKET, 1);
        _tstore(_BINDING, uint256(binding)); // C5-5: unconditional, so an item with binding 0 never reads the last one
        bool ok;
        (ok, ret) = address(this).call(data);
        bool guarded = _tload(_TICKET) == 2;    // the target was `nonReentrant` and consumed the ticket
        _tstore(_TICKET, 0);
        _tstore(_SENDER, 0);
        _tstore(_BINDING, 0);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 0x20), mload(ret)) }
        if (!guarded) revert Reentrancy();      // fail closed: an allowlisted function must be `nonReentrant`
    }

    // ------------------------------------------------------------------ hooks

    /// @notice The rule of `sel`; feeClass 0 = not allowlisted. Overrides end with `return super._mtxRule(sel);`.
    function _mtxRule(bytes4 sel) internal view virtual returns (MtxRule memory r) {
        if (sel == IMetaTx.cancelNonce.selector) r = MtxRule(FEE_CLASS_ABSOLUTE, 0, 36);
    }

    /// @notice Whether `sel` may run as a `mtxBatch` / `uaBatch` item; every allowlisted selector by default, the PQZ ops
    ///         never (CTR-PQZ-21: one op is ≈ 3–11 M gas and up to ≈ 340 KB).
    function _batchable(bytes4) internal view virtual returns (bool) {
        return true;
    }

    function _requireBatchable(bytes4 sel) internal view {
        if (!_batchable(sel)) revert MtxNotBatchable(sel);
    }

    /// @notice Step 6 of this base's `_execute`, after the call: no balance to charge => every mode but `NONE` reverts
    ///         (CTR-MTX-22). A token never reaches it: its `_execute` override takes the fee amount from
    ///         `MtxPipelineLib.preCall`, before the call (owner 2026-10-27), and moves it after.
    function _chargeFee(address, uint256, MetaTxLib.MetaTransaction memory m) internal virtual returns (uint256) {
        if (MetaTxLib.feeModeOf(m.mode) != FeeMode.NONE) revert MetaTxUnknownMode(m.mode);
        return 0;
    }

    /// @notice EOA, ERC-1271 or (P1c) HIP-632, through `SigCheck` (CTR-MTX-25).
    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig) internal view virtual {
        if (!SigCheck.isValid(from, digest, sig, _erc1271Gas(from))) revert MetaTxBadSignature();
    }

    /// @notice 50 000 for every contract wallet. The tokens' rule (400 000 for a `SmartKeyAccount` clone) is
    ///         `MtxPipelineLib._erc1271Gas`.
    function _erc1271Gas(address) internal view virtual returns (uint256) {
        return SigCheck.ERC1271_GAS;
    }

    /// @notice Step 1 for `from == address(this)`: the `SelfSender` guard by default; `SmartKeyAccount`, which signs its
    ///         own `MetaTransaction`s and checks them against its own key set, overrides it with nothing (CTR-ACC-10).
    function _selfSender() internal pure virtual {
        revert SelfSender();
    }

    /// @notice The envelope binding a proof inside the self-call carries (CTR-ZTH-34): every envelope field except
    ///         `data`. 0 (none) by default; a confidential token returns its own (Zether, and PQZ with its own tag).
    ///         Step 5 writes the slot on every self-call and clears it on exit, so 0 for some envelopes is safe.
    function _envelopeBinding(MetaTxLib.MetaTransaction memory) internal view virtual returns (bytes32) {
        return bytes32(0);
    }

    /// @notice The envelope binding inside the one self-call of step 5 (live ticket), else 0: a direct call.
    function _ticketBinding() internal view returns (bytes32) {
        if (msg.sender == address(this) && _tload(_TICKET) != 0) return bytes32(_tload(_BINDING));
        return bytes32(0);
    }

    /// @notice The signer inside the one self-call of step 5 (live ticket), else `msg.sender` (CTR-MTX-18). A derived
    ///         UA signer (top 96 bits non-zero) is `UA_POOL`: its balance is the pool's sub-ledger (CTR-UA-18).
    function _msgSender() internal view virtual override returns (address) {
        if (msg.sender == address(this) && _tload(_TICKET) != 0) {
            uint256 s = _tload(_SENDER);
            return s >> 160 == 0 ? address(uint160(s)) : MetaTxLib.UA_POOL;
        }
        return msg.sender;
    }

    /// @notice The signer as an id inside the one self-call of step 5, else 0.
    function _ticketSubject() internal view returns (bytes32) {
        if (msg.sender == address(this) && _tload(_TICKET) != 0) return bytes32(_tload(_SENDER));
        return bytes32(0);
    }

    /// @dev `m.feeRecipient`, or `msg.sender` when 0 (CTR-MTX-13).
    function _feeRecipientOf(MetaTxLib.MetaTransaction memory m) internal view returns (address) {
        return m.feeRecipient == address(0) ? msg.sender : m.feeRecipient;
    }

    // ------------------------------------------------------------------ transient storage

    function _tload(bytes32 slot) private view returns (uint256 v) {
        assembly ("memory-safe") { v := tload(slot) }
    }

    function _tstore(bytes32 slot, uint256 v) private {
        assembly ("memory-safe") { tstore(slot, v) }
    }
}
