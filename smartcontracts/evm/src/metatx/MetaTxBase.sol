// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeeMode} from "../common/FeePolicy.sol";
import {SaltedEIP712} from "../common/SaltedEIP712.sol";
import {SigCheck} from "../common/SigCheck.sol";

/// @title The generic meta-transaction base of every SCaaS contract (CTR-MTX-22).
/// @notice The subject signs a `MetaTransaction` (CTR-MTX-15) whose `data` is one call of one of THIS contract's
///         allowlisted functions; anyone submits it through `mtxExecute`, and the contract runs it on itself
///         (CTR-MTX-16, CTR-MTX-17). The signer travels in a transient slot and one ticket admits exactly one
///         self-call (CTR-MTX-18). The allowlist is fixed per implementation (CTR-MTX-19): an implementation
///         overrides `_mtxRule` (ending in `return super._mtxRule(sel);`) and `mtxSelectors` (the base entry
///         `cancelNonce` first). A contract that holds no charged balance accepts fee mode `NONE` only
///         (`supportedModes() = 0x03`, CTR-MTX-22).
abstract contract MetaTxBase is Context, SaltedEIP712, IMetaTx {
    using MetaTxLib for MetaTxLib.MetaTransaction;

    /// @notice Fee classes published by `mtxSelectors()` (CTR-MTX-20). 0 = not allowlisted.
    uint8 internal constant FEE_CLASS_ABSOLUTE = 1;
    uint8 internal constant FEE_CLASS_AMOUNT = 2;

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

    /// @custom:storage-location erc7201:scaas.metatx
    struct MetaTxStorage {
        mapping(address from => mapping(uint256 batch => uint256)) nonce;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.metatx")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0x06b01547c739946503c06c80685cc72ae2fec5074fd602f84cd2fa888722ac00;

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
        return _mtxStorage().nonce[from][batch];
    }

    function mtxDigest(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32) {
        return _hashTypedDataV4(m.hashStruct());
    }

    function chainUid() external view returns (bytes32) {
        return CHAIN_UID;
    }

    /// @notice `0x03`: flags only, fee mode `NONE`. A token (which overrides `_chargeFee`) returns `0xF3`.
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
        for (uint256 i; i < n; ++i) _execute(ms[i], signatures[i]);
        return true;
    }

    /// @notice Direct, or signed through `mtxExecute` on another lane (a subject without gas can cancel).
    function cancelNonce(uint256 batch) external nonReentrant {
        address from = _msgSender();
        uint256 n;
        unchecked { n = ++_mtxStorage().nonce[from][batch]; }
        emit MetaNonceCancelled(from, batch, n);
    }

    // ------------------------------------------------------------------ pipeline (CTR-MTX-17)

    /// @dev Every entry (generic, alias, batch, later the named builders) goes through here.
    function _execute(MetaTxLib.MetaTransaction memory m, bytes calldata signature)
        internal returns (bytes memory ret)
    {
        bytes32 digest = _checkIntent(m, signature);            // 1, 2
        uint256 basis = _checkCall(m);                          // 3
        unchecked { _mtxStorage().nonce[m.from][m.batch] = m.nonce + 1; }   // 4
        ret = _selfCall(m);                                     // 5
        uint256 fee = _chargeFee(m.from, basis, m);             // 6
        emit MetaTransactionExecuted(m.from, msg.sender, m.batch, m.nonce, digest, _feeRecipientOf(m), fee); // 7
    }

    /// @dev Steps 1 (cheap) and 2 (signature).
    function _checkIntent(MetaTxLib.MetaTransaction memory m, bytes calldata signature)
        internal view returns (bytes32 digest)
    {
        if (m.mode & MetaTxLib.MODE_RESTRICT_RELAYER != 0 && m.relayer != msg.sender) {
            revert MetaTxUnauthorizedRelayer(m.relayer, msg.sender);
        }
        if (block.timestamp > m.validUntil) revert MetaTxExpired(m.validUntil, block.timestamp);
        if (m.mode & ~MetaTxLib.MODE_KNOWN_MASK != 0 || m.mode & MetaTxLib.MODE_FEE_MASK > MetaTxLib.MODE_FEE_FIXED) {
            revert MetaTxUnknownMode(m.mode);
        }
        uint256 expected = _mtxStorage().nonce[m.from][m.batch];
        if (expected != m.nonce) revert MetaTxBadNonce(expected, m.nonce);
        if (m.from == address(this)) revert SelfSender();
        digest = _hashTypedDataV4(m.hashStruct());
        _requireValidSignature(m.from, digest, signature);
    }

    /// @dev Step 3: shape, allowlist, fee class, `supportedModes()`. Returns the fee basis.
    function _checkCall(MetaTxLib.MetaTransaction memory m) internal view returns (uint256 basis) {
        bytes memory data = m.data;
        bytes4 sel = bytes4(data);
        if (data.length < 4) revert MtxDataShape(sel);
        MtxRule memory r = _mtxRule(sel);
        if (r.feeClass == 0 || r.feeClass > FEE_CLASS_AMOUNT) revert MtxSelectorNotAllowed(sel);
        uint256 basisEnd = 36 + 32 * uint256(r.amountArg);
        if ((r.staticLen != 0 && data.length != r.staticLen)
            || (r.feeClass == FEE_CLASS_AMOUNT && data.length < basisEnd)) revert MtxDataShape(sel);
        if (r.feeClass == FEE_CLASS_ABSOLUTE && MetaTxLib.feeModeOf(m.mode) == FeeMode.PERCENT) {
            revert MtxFeeClass(sel, m.mode);
        }
        if (m.mode & ~supportedModes() != 0) revert MetaTxUnknownMode(m.mode);
        if (r.feeClass == FEE_CLASS_AMOUNT) {
            assembly ("memory-safe") { basis := mload(add(data, basisEnd)) }
        }
    }

    /// @dev Step 5: store the ticket, call self, clear; a failed call reverts with its own revert data.
    function _selfCall(MetaTxLib.MetaTransaction memory m) private returns (bytes memory ret) {
        _tstore(_SENDER, uint256(uint160(m.from)));
        _tstore(_TICKET, 1);
        bool ok;
        (ok, ret) = address(this).call(m.data);
        _tstore(_TICKET, 0);
        _tstore(_SENDER, 0);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 0x20), mload(ret)) }
    }

    // ------------------------------------------------------------------ hooks

    /// @notice The rule of `sel`; feeClass 0 = not allowlisted. Overrides end with `return super._mtxRule(sel);`.
    function _mtxRule(bytes4 sel) internal view virtual returns (MtxRule memory r) {
        if (sel == IMetaTx.cancelNonce.selector) r = MtxRule(FEE_CLASS_ABSOLUTE, 0, 36);
    }

    /// @notice Step 6, after the call. Default: no balance to charge => every mode but `NONE` reverts (CTR-MTX-22).
    ///         A token overrides it to charge `fee` in this token (P1b, `ERC20MetaTx`).
    function _chargeFee(address, uint256, MetaTxLib.MetaTransaction memory m) internal virtual returns (uint256) {
        if (MetaTxLib.feeModeOf(m.mode) != FeeMode.NONE) revert MetaTxUnknownMode(m.mode);
        return 0;
    }

    /// @notice EOA, ERC-1271 or (P1c) HIP-632, through `SigCheck` (CTR-MTX-25).
    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig) internal view virtual {
        if (!SigCheck.isValid(from, digest, sig, _erc1271Gas(from))) revert MetaTxBadSignature();
    }

    /// @notice 50 000 for every contract wallet; `SmartKeyAccount` clones get 400 000 where an override knows them.
    function _erc1271Gas(address) internal view virtual returns (uint256) {
        return SigCheck.ERC1271_GAS;
    }

    /// @notice The signer inside the one self-call of step 5 (live ticket), else `msg.sender` (CTR-MTX-18).
    function _msgSender() internal view virtual override returns (address) {
        if (msg.sender == address(this) && _tload(_TICKET) != 0) return address(uint160(_tload(_SENDER)));
        return msg.sender;
    }

    /// @dev `m.feeRecipient`, or `msg.sender` when 0 (CTR-MTX-13).
    function _feeRecipientOf(MetaTxLib.MetaTransaction memory m) internal view returns (address) {
        return m.feeRecipient == address(0) ? msg.sender : m.feeRecipient;
    }

    // ------------------------------------------------------------------ storage

    function _mtxStorage() private pure returns (MetaTxStorage storage $) {
        assembly ("memory-safe") { $.slot := _STORAGE }
    }

    function _tload(bytes32 slot) private view returns (uint256 v) {
        assembly ("memory-safe") { v := tload(slot) }
    }

    function _tstore(bytes32 slot, uint256 v) private {
        assembly ("memory-safe") { tstore(slot, v) }
    }
}
