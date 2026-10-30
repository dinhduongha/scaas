// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {IERC20MetaTx} from "./IERC20MetaTx.sol";
import {IUALedger} from "./IUALedger.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeePolicy, FeeMode} from "../common/FeePolicy.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {HederaLib} from "../hedera/HederaLib.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {UAKinds} from "../ua/UAKinds.sol";

/// @title The checks of every signed meta-tx path (metatx split, variant A; CTR-MTX-07, CTR-MTX-17, CTR-MTX-23).
/// @notice Linked by the token kinds and run by DELEGATECALL in the token's context: steps 1–4 of CTR-MTX-17 and the fee
///         amount, on the address path and the UA path, for `MetaTransaction` and `MetaTransfer`; the address path's
///         signature rule and the UA authorization rule. The token passes its immutables in `Ctx` and only
///         `keccak256(data)`, never `data` (owner 2026-10-21). No state variable, no immutable, no constructor; the one
///         slot written is the nonce of `scaas.metatx`, whose constant and struct are defined here only.
/// @dev The check bodies are the internal functions; the external ones compose them for the tokens, and `MetaTxBase`
///      calls the same internal functions inlined (no link), so the wallets keep their own composition (§3.7).
library MtxPipelineLib {
    /// @notice Fee classes of `MtxRule` (CTR-MTX-20). 0 = not allowlisted.
    uint8 internal constant FEE_CLASS_ABSOLUTE = 1;
    uint8 internal constant FEE_CLASS_AMOUNT = 2;

    /// @notice The ERC-1271 cap of a `SmartKeyAccount` clone (CTR-ACC-05); every other contract wallet gets 50,000.
    uint256 internal constant SMART_KEY_1271_GAS = 400_000;

    /// The token's immutables, built once per call by the token.
    struct Ctx {
        bytes32 domainSeparator;   // _domainSeparatorV4() of this clone
        address registry;          // _REGISTRY (0 = UA ledger off)
        bytes32 skaCloneCodehash;  // _SMART_KEY_CLONE_CODEHASH (0 = none)
        bool hedera;               // IS_HEDERA
    }

    /// Every signed field of a MetaTransaction / UAMetaTransaction except `data`; `from` as an id (an address
    /// zero-padded). abi.encode of a padded id equals abi.encode of the address, so one struct hash serves both.
    struct Envelope {
        bytes32 from; bytes32 dataHash; uint256 batch; uint256 nonce; uint256 validUntil;
        uint32 mode; address relayer; uint256 fee; address feeRecipient;
    }

    /// What the token read from `data` and its own hooks.
    struct CallFacts {
        bytes4 sel; uint256 len;                            // bytes4(data) (zero-padded), data.length
        uint8 feeClass; uint8 amountArg; uint32 staticLen;  // _mtxRule(sel)
        uint256 basis;                                      // word amountArg of the arguments if present, else 0
        bool uaAllowed;                                     // _uaAllowed(sel); read on the UA path only
    }

    struct Out { bytes32 digest; uint256 fee; address feeTo; }

    /// @custom:storage-location erc7201:scaas.metatx
    /// @dev One nonce map for every path, keyed by id (CTR-UA-26): a native address zero-padded, a derived UA as itself.
    struct MetaTxStorage {
        mapping(bytes32 from => mapping(uint256 batch => uint256)) nonce;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.metatx")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 internal constant STORAGE_SLOT = 0x06b01547c739946503c06c80685cc72ae2fec5074fd602f84cd2fa888722ac00;

    // ------------------------------------------------------------------ external (the tokens, by DELEGATECALL)

    /// @notice CTR-MTX-17 steps 1-4 and the fee amount, address path (`ua = false`) or UA path (`ua = true`).
    ///         Address path: envelope (`SelfSender`), digest, signature, call shape, nonce, fee. UA path: ledger on,
    ///         envelope, digest, `authorize(PURPOSE_METATX)`, `MetaTxUnknownOp`, call shape, nonce, fee.
    function preCall(Ctx calldata c, Envelope calldata e, CallFacts calldata f, bool ua, bytes calldata auth)
        external returns (Out memory o)
    {
        if (ua && c.registry == address(0)) revert IUALedger.UALedgerOff();
        if (_checkEnvelope(e.from, e.batch, e.nonce, e.validUntil, e.mode, e.relayer)) revert IMetaTx.SelfSender();
        o.digest = MessageHashUtils.toTypedDataHash(
            c.domainSeparator, _structHash(ua ? MetaTxLib.UAMETATX_TYPEHASH : MetaTxLib.METATX_TYPEHASH, e));
        if (ua) {
            _authorize(c, e.from, UAKinds.PURPOSE_METATX, o.digest, auth);
            if (f.len < 4 || !f.uaAllowed) revert IUALedger.MetaTxUnknownOp(f.sel);
        } else {
            _requireSignature(c, _native(e.from), o.digest, auth);
        }
        _checkCall(f.sel, f.len, f.feeClass, f.amountArg, f.staticLen, e.mode, MetaTxLib.MODE_KNOWN_MASK);
        _useNonce(e.from, e.batch);
        (o.fee, o.feeTo) = _callFee(
            f.feeClass, f.basis, e.mode, e.fee, e.feeRecipient == address(0) ? msg.sender : e.feeRecipient);
    }

    /// @notice CTR-MTX-23 steps 1-4 of the typed path. `t` in the UAMetaTransfer layout; the address path passes padded
    ///         ids. `have` = the payer's balance, read by the token before the call.
    function preTransfer(Ctx calldata c, MetaTxLib.UAMetaTransfer calldata t, bool ua, uint256 have,
        bytes calldata auth) external returns (Out memory o)
    {
        if (ua && c.registry == address(0)) revert IUALedger.UALedgerOff();
        MetaTxLib.UAMetaTransfer memory m = t;
        if (_checkEnvelope(m.from, m.batch, m.nonce, m.validUntil, m.mode, m.relayer)) revert IMetaTx.SelfSender();
        o.digest = MessageHashUtils.toTypedDataHash(c.domainSeparator, _structHash(ua, m));
        if (ua) _authorize(c, m.from, UAKinds.PURPOSE_METATX, o.digest, auth);
        else _requireSignature(c, _native(m.from), o.digest, auth);
        (o.fee, o.feeTo) = _checkTransfer(c.registry, m, have);
        _useNonce(m.from, m.batch);
    }

    /// @notice The address path's signature rule (CTR-MTX-25, CTR-TOK-23).
    function requireSignature(Ctx calldata c, address from, bytes32 digest, bytes calldata sig) external view {
        _requireSignature(c, from, digest, sig);
    }

    /// @notice The UA rule under `purpose` (metatx, trade, receiver-fee).
    function authorize(Ctx calldata c, bytes32 from, bytes32 purpose, bytes32 digest, bytes calldata auth)
        external view
    {
        _authorize(c, from, purpose, digest, auth);
    }

    /// @notice The digest of a `MetaTransaction` (`METATX_TYPEHASH`) or `UAMetaTransaction` (`UAMETATX_TYPEHASH`).
    function callDigest(bytes32 domainSeparator, bytes32 typehash, Envelope calldata e)
        external pure returns (bytes32)
    {
        return MessageHashUtils.toTypedDataHash(domainSeparator, _structHash(typehash, e));
    }

    /// @notice The digest of a `MetaTransfer` (`ua = false`, padded ids) or `UAMetaTransfer`.
    function transferDigest(bytes32 domainSeparator, bool ua, MetaTxLib.UAMetaTransfer calldata t)
        external pure returns (bytes32)
    {
        return MessageHashUtils.toTypedDataHash(domainSeparator, _structHash(ua, t));
    }

    // ------------------------------------------------------------------ internal (one source per rule)

    /// @dev Step 1 on the shared lane space (CTR-MTX-15, CTR-UA-26): relayer binding, expiry, mode bits, nonce.
    ///      Returns whether `from` is this contract: the caller refuses it (`SelfSender`) or, for `SmartKeyAccount`,
    ///      accepts it (CTR-ACC-10). The last check, so the order is today's.
    function _checkEnvelope(
        bytes32 from, uint256 batch, uint256 nonce, uint256 validUntil, uint32 mode, address relayer
    ) internal view returns (bool self) {
        if (mode & MetaTxLib.MODE_RESTRICT_RELAYER != 0) {
            if (relayer != msg.sender) revert IMetaTx.MetaTxUnauthorizedRelayer(relayer, msg.sender);
            SigCheck.requireNotDelegated(msg.sender); // a bound relayer runs no delegate code (owner ruling 2026-10-30, D3)
        }
        if (block.timestamp > validUntil) revert IMetaTx.MetaTxExpired(validUntil, block.timestamp);
        if (mode & ~MetaTxLib.MODE_KNOWN_MASK != 0 || mode & MetaTxLib.MODE_FEE_MASK > MetaTxLib.MODE_FEE_FIXED) {
            revert IMetaTx.MetaTxUnknownMode(mode);
        }
        uint256 expected = _mtxStorage().nonce[from][batch];
        if (expected != nonce) revert IMetaTx.MetaTxBadNonce(expected, nonce);
        return from == MetaTxLib.pad(address(this));
    }

    /// @dev The EIP-712 struct hash of a `MetaTransaction` / `UAMetaTransaction` (by `typehash`), relayer and fee
    ///      recipient canonical-zeroed when their mode bit is off (`MetaTxLib.canon`).
    function _structHash(bytes32 typehash, Envelope memory e) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            typehash, e.from, e.dataHash, e.batch, e.nonce, e.validUntil, e.mode,
            _canon(e.mode, MetaTxLib.MODE_RESTRICT_RELAYER, e.relayer), e.fee,
            _canon(e.mode, MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT, e.feeRecipient)
        ));
    }

    /// @dev The EIP-712 struct hash of a `MetaTransfer` (`ua = false`, padded ids) / `UAMetaTransfer`.
    function _structHash(bool ua, MetaTxLib.UAMetaTransfer memory t) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            ua ? MetaTxLib.UAMETATRANSFER_TYPEHASH : MetaTxLib.METATRANSFER_TYPEHASH,
            t.from, t.to, t.value, t.entryRef, t.batch, t.nonce, t.validUntil, t.mode,
            _canon(t.mode, MetaTxLib.MODE_RESTRICT_RELAYER, t.relayer), t.fee,
            _canon(t.mode, MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT, t.feeRecipient)
        ));
    }

    /// @dev Step 3: shape, allowlist verdict, fee class against mode, `supported` (the contract's `supportedModes()`).
    ///      `sel` zero-padded when `len < 4`.
    function _checkCall(
        bytes4 sel, uint256 len, uint8 feeClass, uint8 amountArg, uint32 staticLen, uint32 mode, uint32 supported
    ) internal pure {
        if (len < 4) revert IMetaTx.MtxDataShape(sel);
        if (feeClass == 0 || feeClass > FEE_CLASS_AMOUNT) revert IMetaTx.MtxSelectorNotAllowed(sel);
        if ((staticLen != 0 && len != staticLen)
            || (feeClass == FEE_CLASS_AMOUNT && len < 36 + 32 * uint256(amountArg))) revert IMetaTx.MtxDataShape(sel);
        if (feeClass == FEE_CLASS_ABSOLUTE && MetaTxLib.feeModeOf(mode) == FeeMode.PERCENT) {
            revert IMetaTx.MtxFeeClass(sel, mode);
        }
        if (mode & ~supported != 0) revert IMetaTx.MetaTxUnknownMode(mode);
    }

    /// @dev The fee of a self-call (both paths): `ABSOLUTE` + `FIXED` = the signed amount, uncapped (step 3 refused
    ///      `ABSOLUTE` + `PERCENT`); anything else = `FeePolicy.compute` on the basis (≤ 1 %). A `UA_POOL` recipient
    ///      would credit the pool's slot.
    function _callFee(uint8 feeClass, uint256 basis, uint32 mode, uint256 signed, address feeTo)
        internal pure returns (uint256 fee, address)
    {
        FeeMode fm = MetaTxLib.feeModeOf(mode);
        if (fm == FeeMode.NONE) return (0, feeTo);
        fee = fm == FeeMode.FIXED && feeClass == FEE_CLASS_ABSOLUTE ? signed : FeePolicy.compute(fm, basis, signed);
        FeePolicy.validateRecipient(fm, feeTo);
        if (fee != 0 && feeTo == MetaTxLib.UA_POOL) revert IUALedger.UAPoolNotPayable();
        return (fee, feeTo);
    }

    /// @dev Step 3 of the typed path (both paths; the address path's ids are padded): the receiver (`_checkTo`), fee
    ///      on `value` (capped, CTR-MTX-13), the fee recipient, balance against `have`.
    function _checkTransfer(address registry, MetaTxLib.UAMetaTransfer memory t, uint256 have)
        internal view returns (uint256 fee, address feeTo)
    {
        _checkTo(registry, t.to);
        FeeMode fm = MetaTxLib.feeModeOf(t.mode);
        feeTo = t.feeRecipient == address(0) ? msg.sender : t.feeRecipient;
        fee = FeePolicy.compute(fm, t.value, t.fee);
        FeePolicy.validateRecipient(fm, feeTo);
        if (fee != 0) {
            if (MetaTxLib.pad(feeTo) == t.to) revert IERC20MetaTx.FeeRecipientIsPayee();
            if (feeTo == address(this)) revert IERC20MetaTx.TransferToSelf();
            if (feeTo == MetaTxLib.UA_POOL) revert IUALedger.UAPoolNotPayable();
            if (feeTo == MetaTxLib.SHIELD_POOL) revert IUALedger.ShieldPoolNotPayable();
        }
        uint256 need = t.value + fee;
        if (have < need) revert IERC20MetaTx.MetaTxInsufficientForFee(need, have);
    }

    /// @dev A receiver: a native id other than 0, this contract and the two pools; or a SIGNING UA of `registry`.
    function _checkTo(address registry, bytes32 to) internal view {
        if (UAKinds.inNativeSpace(to)) {
            address a = address(uint160(uint256(to)));
            if (a == address(0)) revert IERC20MetaTx.PayToZero();
            if (a == address(this)) revert IERC20MetaTx.TransferToSelf();
            if (a == MetaTxLib.UA_POOL) revert IUALedger.UAPoolNotPayable();
            if (a == MetaTxLib.SHIELD_POOL) revert IUALedger.ShieldPoolNotPayable();
            return;
        }
        uint16 kind = IUARegistry(registry).kindOf(to);
        if (kind == 0) revert IUALedger.UANotRegistered(to);
        if (!UAKinds.isSigning(kind)) revert IUALedger.UAKindNotAccepted(to, kind);
    }

    /// @dev Step 4: consume the lane's current nonce (after `_checkEnvelope` passed).
    function _useNonce(bytes32 from, uint256 batch) internal {
        unchecked { ++_mtxStorage().nonce[from][batch]; }
    }

    function _mtxStorage() internal pure returns (MetaTxStorage storage $) {
        assembly ("memory-safe") { $.slot := STORAGE_SLOT }
    }

    // ------------------------------------------------------------------ private

    /// @dev EOA, ERC-1271 (cap by the clone code hash) or, on Hedera, HIP-632 for a 64-byte signature from an address
    ///      without code (through `HederaLib`, in the token's context).
    function _requireSignature(Ctx calldata c, address from, bytes32 digest, bytes calldata sig) private view {
        if (c.hedera && sig.length == 64 && !SigCheck.isContract(from)) return HederaLib.requireValid(from, digest, sig);
        if (!SigCheck.isValid(from, digest, sig, _erc1271Gas(c, from))) revert IMetaTx.MetaTxBadSignature();
    }

    /// @dev A derived id: the registry under `purpose`. A native id (whatever the purpose): 0 and the pools refused
    ///      (C5-2, C5-3), then CTR-UA-24 (`SigCheck.isValid`) or HIP-632 on Hedera.
    function _authorize(Ctx calldata c, bytes32 from, bytes32 purpose, bytes32 digest, bytes calldata auth)
        private view
    {
        if (!UAKinds.inNativeSpace(from)) {
            return IUARegistry(c.registry).requireAuthorized(from, purpose, digest, auth);
        }
        address a = address(uint160(uint256(from)));
        if (a == address(0)) revert IUALedger.UANotRegistered(from);
        if (a == MetaTxLib.UA_POOL) revert IUALedger.UAPoolNotPayable();
        if (a == MetaTxLib.SHIELD_POOL) revert IUALedger.ShieldPoolNotPayable();
        if (c.hedera && auth.length == 64 && !SigCheck.isContract(a)) return HederaLib.requireValid(a, digest, auth);
        if (!SigCheck.isValid(a, digest, auth, _erc1271Gas(c, a))) revert IMetaTx.MetaTxBadSignature();
    }

    /// @dev The address path's signer: a native id (upper 96 bits zero), never truncated from a derived one.
    function _native(bytes32 id) private pure returns (address) {
        if (!UAKinds.inNativeSpace(id)) revert IMetaTx.MetaTxBadSignature();
        return address(uint160(uint256(id)));
    }

    function _erc1271Gas(Ctx calldata c, address from) private view returns (uint256) {
        bytes32 h = c.skaCloneCodehash;
        return h != bytes32(0) && from.codehash == h ? SMART_KEY_1271_GAS : SigCheck.ERC1271_GAS;
    }

    function _canon(uint32 mode, uint32 bit, address a) private pure returns (address) {
        return mode & bit != 0 ? a : address(0);
    }
}
