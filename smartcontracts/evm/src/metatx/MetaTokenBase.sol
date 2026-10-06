// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {MetaTxCore} from "./MetaTxCore.sol";
import {IMetaTokenV2} from "./IMetaTokenV2.sol";
import {IFactoryTokenV2} from "../factory/IFactoryTokenV2.sol";
import {IOpenFactoryV2} from "../common/IOpenFactoryV2.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeePolicy, FeeMode} from "../common/FeePolicy.sol";

/// @title Gốc chung của ba tầng token v2 (TW2 §3.3, §7). Clone EIP-1167, domain `("SCaaS MetaToken", "2")`.
/// @notice Op (`data` có tag selector, trong struct đã ghim — R2): rỗng ⇒ transfer; `pay(bytes32)`;
///         `trade(address,uint256,address)`; `approve(address,uint256)`; `unwrap(address,address,uint256)` (chỉ
///         tầng wrapper, R148 — ở đây chuyển cho hook của tầng). Hàm có tên chỉ dựng struct rồi chạy `_execute`.
///
///         Không owner, không pause, không upgrade. Hai ngoại lệ tạo lúc init và nhìn thấy được (R142) nằm ở tầng
///         wrapper: rate admin (chỉ khi `adjustable`) và guardian (chỉ `disableWrap`).
abstract contract MetaTokenBase is MetaTxCore, IMetaTokenV2, IFactoryTokenV2 {
    bytes4 public constant OP_PAY = bytes4(keccak256("pay(bytes32)"));
    bytes4 public constant OP_TRADE = bytes4(keccak256("trade(address,uint256,address)"));
    bytes4 public constant OP_APPROVE = bytes4(keccak256("approve(address,uint256)"));
    /// @dev R148: `value` = số wrapped đem đổi, `to` = recipient.
    bytes4 public constant OP_UNWRAP = bytes4(keccak256("unwrap(address,address,uint256)"));
    bytes4 internal constant MTX_UNWRAP_WITH_FEE = bytes4(keccak256(
        "mtxUnwrapWithFee(address,address,uint256,address,uint256,uint256,uint256,uint256,uint32,address,uint256,address,bytes)"));

    address public immutable FACTORY;
    address private immutable _SELF;
    /// @notice SubjectAccount implementation của chain này (0 = không có). Chỉ clone EIP-1167 của nó được 400k
    ///         gas cho ERC-1271; ví hợp đồng khác 50k.
    address public immutable SUBJECT_ACCOUNT_IMPL;
    bytes32 private immutable _SUBJECT_CLONE_CODEHASH;

    // slot 8 (một slot, 31 byte): creator ‖ version ‖ _tokenDecimals ‖ _initialized ‖ _legCount
    address public creator;
    uint64 public version;
    uint8 private _tokenDecimals;
    bool private _initialized;
    /// @dev Số chân underlying (0 ở tầng 1). Đặt ở đây để cùng slot với các trường init.
    uint8 internal _legCount;
    string private _tokenName;   // slot 9
    string private _tokenSymbol; // slot 10

    error NotFactory();
    error AlreadyInitialized();
    error MetaTxUnknownOp(bytes4 op);
    error PayToZero();
    error TradeLegNotRestricted();
    error ApproveCarriesValue();
    error ApproveSpenderMismatch();
    error UnwrapRecipientMismatch();
    error MtxModeShape(uint32 mode);
    error MtxBatchEmpty();
    error MtxBatchLengthMismatch();

    /// @dev Chạy MỘT lần trên implementation; khoá luôn implementation để không ai `initialize` nó.
    constructor(address factory_, address subjectAccountImpl_) ERC20("", "") EIP712("SCaaS MetaToken", "2") {
        FACTORY = factory_;
        _SELF = address(this);
        SUBJECT_ACCOUNT_IMPL = subjectAccountImpl_;
        _SUBJECT_CLONE_CODEHASH = subjectAccountImpl_ == address(0) ? bytes32(0) : keccak256(abi.encodePacked(
            hex"363d3d373d3d3d363d73", subjectAccountImpl_, hex"5af43d82803e903d91602b57fd5bf3"));
        _initialized = true;
    }

    /// @notice Factory gọi trong CÙNG lời gọi với CREATE2. `initData` theo tầng (TW2 §4, §5.1, §8.1).
    function initialize(address creator_, address[] calldata underlyings, uint64 version_, bytes calldata initData)
        external
    {
        if (msg.sender != FACTORY) revert NotFactory();
        if (_initialized) revert AlreadyInitialized();
        _initialized = true;
        creator = creator_;
        version = version_;
        _init(creator_, underlyings, initData);
    }

    /// @dev Tầng giải mã `initData`, gọi `_setMetadata`, kiểm `underlyings`.
    function _init(address creator_, address[] calldata underlyings, bytes calldata initData) internal virtual;

    function _setMetadata(string memory n, string memory s, uint8 d) internal {
        _tokenName = n;
        _tokenSymbol = s;
        _tokenDecimals = d;
    }

    function tokenKind() external pure virtual returns (IOpenFactoryV2.TokenKind);

    function name() public view override returns (string memory) { return _tokenName; }
    function symbol() public view override returns (string memory) { return _tokenSymbol; }
    function decimals() public view override returns (uint8) { return _tokenDecimals; }

    function factory() external view returns (address) { return FACTORY; }
    function implementation() external view returns (address) { return _SELF; }

    function payLane(bytes32 payId) public pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked("scaas.pay.lane", payId)));
    }

    // ------------------------------------------------------------------ hàm có tên (§7.1)

    function mtxTransfer(
        address from, address to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
        uint32 mode, address relayer, bytes calldata signature
    ) external nonReentrant returns (bool) {
        if (mode & ~MetaTxLib.MODE_RESTRICT_RELAYER != 0) revert MtxModeShape(mode);
        MetaTxLib.MetaTransaction memory m;
        m.from = from;
        m.to = to;
        m.value = amount;
        m.batch = batch;
        m.nonce = nonce;
        m.validUntil = validUntil;
        m.mode = mode;
        m.relayer = relayer;
        _execute(m, signature);
        return true;
    }

    function mtxTransferWithFee(
        address from, address to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
        uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes calldata signature
    ) external nonReentrant returns (bool) {
        _requireFeeShape(mode, feeRecipient);
        MetaTxLib.MetaTransaction memory m;
        m.from = from;
        m.to = to;
        m.value = amount;
        m.batch = batch;
        m.nonce = nonce;
        m.validUntil = validUntil;
        m.mode = mode;
        m.relayer = relayer;
        m.fee = fee;
        m.feeRecipient = feeRecipient;
        _execute(m, signature);
        return true;
    }

    function executeMetaTransactionWithFee(MetaTxLib.MetaTransaction calldata m, bytes calldata signature)
        external nonReentrant returns (bool)
    {
        if (m.mode & MetaTxLib.MODE_FEE_MASK == 0) revert MtxModeShape(m.mode);
        _execute(m, signature);
        return true;
    }

    function mtxPay(
        address from, address to, uint256 amount, bytes32 payId, uint256 validUntil,
        uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes calldata signature
    ) external nonReentrant returns (bool) {
        MetaTxLib.MetaTransaction memory m;
        m.from = from;
        m.to = to;
        m.value = amount;
        m.data = abi.encodePacked(OP_PAY, payId);
        m.batch = payLane(payId);
        m.validUntil = validUntil;
        m.mode = mode;
        m.relayer = relayer;
        m.fee = fee;
        m.feeRecipient = feeRecipient;
        _execute(m, signature);
        return true;
    }

    /// @dev Struct dựng từ calldata (`_unwrapCall`): 11 tham số trên stack cộng struct là stack too deep với solc
    ///      không via-IR. Decoder ABI đã kiểm độ sạch của từng tham số trước khi vào thân.
    function mtxUnwrap(
        address /* from */, address /* underlying */, uint256 /* wrapped */, address /* recipient */,
        uint256 /* minOut */, uint256 /* batch */, uint256 /* nonce */, uint256 /* validUntil */, uint32 mode,
        address /* relayer */, bytes calldata signature
    ) external nonReentrant returns (bool) {
        if (mode & ~MetaTxLib.MODE_RESTRICT_RELAYER != 0) revert MtxModeShape(mode);
        _execute(_unwrapCall(false), signature);
        return true;
    }

    /// @notice `mtxUnwrapWithFee(address,address,uint256,address,uint256,uint256,uint256,uint256,uint32,address,
    ///         uint256,address,bytes)` (`IMetaTokenV2UnwrapWithFee`). Mọi selector khác revert rỗng, như khi không
    ///         có fallback.
    fallback(bytes calldata) external nonReentrant returns (bytes memory) {
        if (msg.sig != MTX_UNWRAP_WITH_FEE) revert();
        uint32 mode;
        address feeRecipient;
        bytes calldata signature = msg.data[0:0];
        // Giải mã như decoder ABI: đủ 13 word đầu, word địa chỉ/uint32 sạch, `bytes` nằm trọn trong calldata.
        assembly ("memory-safe") {
            if lt(calldatasize(), 420) { revert(0, 0) }
            let bad := or(or(shr(160, calldataload(4)), shr(160, calldataload(36))),
                          or(shr(160, calldataload(100)), shr(160, calldataload(292))))
            bad := or(bad, or(shr(160, calldataload(356)), shr(32, calldataload(260))))
            let off := calldataload(388)
            if or(bad, gt(off, 0xffffffffffffffff)) { revert(0, 0) }
            let lenPos := add(4, off)
            if gt(add(lenPos, 32), calldatasize()) { revert(0, 0) }
            let len := calldataload(lenPos)
            if or(gt(len, 0xffffffffffffffff), gt(add(add(lenPos, 32), len), calldatasize())) { revert(0, 0) }
            signature.offset := add(lenPos, 32)
            signature.length := len
            mode := calldataload(260)
            feeRecipient := calldataload(356)
        }
        _requireFeeShape(mode, feeRecipient);
        _execute(_unwrapCall(true), signature);
        return abi.encode(true);
    }

    function mtxBatch(MetaTxLib.MetaTransaction[] calldata ms, bytes[] calldata signatures)
        external nonReentrant returns (bool)
    {
        uint256 n = ms.length;
        if (n == 0) revert MtxBatchEmpty();
        if (n != signatures.length) revert MtxBatchLengthMismatch();
        for (uint256 i; i < n; ++i) _execute(ms[i], signatures[i]);
        return true;
    }

    /// @dev Struct của `mtxUnwrap*` từ các word đầu calldata: from 4, underlying 36, wrapped 68, recipient 100,
    ///      minOut 132, batch 164, nonce 196, validUntil 228, mode 260, relayer 292, [fee 324, feeRecipient 356].
    ///      Trường struct trong memory là các word liên tiếp theo thứ tự khai báo.
    function _unwrapCall(bool withFee) private pure returns (MetaTxLib.MetaTransaction memory m) {
        address u;
        address r;
        uint256 minOut;
        assembly ("memory-safe") {
            mstore(m, calldataload(4))
            u := calldataload(36)
            mstore(add(m, 0x40), calldataload(68))
            r := calldataload(100)
            minOut := calldataload(132)
            mstore(add(m, 0x80), calldataload(164))
            mstore(add(m, 0xa0), calldataload(196))
            mstore(add(m, 0xc0), calldataload(228))
            mstore(add(m, 0xe0), calldataload(260))
            mstore(add(m, 0x100), calldataload(292))
            if withFee {
                mstore(add(m, 0x120), calldataload(324))
                mstore(add(m, 0x140), calldataload(356))
            }
        }
        m.to = r;
        m.data = abi.encodeWithSelector(OP_UNWRAP, u, r, minOut);
    }

    /// @dev Fee `PERCENT`/`FIXED`, người nhận phí do người ký ghim và khác 0 (turn 3293).
    function _requireFeeShape(uint32 mode, address feeRecipient) private pure {
        uint32 f = mode & MetaTxLib.MODE_FEE_MASK;
        if ((f != MetaTxLib.MODE_FEE_PERCENT && f != MetaTxLib.MODE_FEE_FIXED)
            || mode & MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT == 0 || feeRecipient == address(0)) {
            revert MtxModeShape(mode);
        }
    }

    // ------------------------------------------------------------------ đường gọi thẳng

    /// @notice `msg.sender` tự trả gas, phí thu THÊM, `amount` nguyên vẹn. R132: phí không tới `to`.
    function payWithFee(
        address to, uint256 amount, FeeMode feeMode, uint256 fee, address feeRecipient, bytes32 entryRef
    ) external returns (bool) {
        uint256 feeAmount = FeePolicy.compute(feeMode, amount, fee);
        FeePolicy.validateRecipient(feeMode, feeRecipient);
        if (feeAmount != 0) {
            if (feeRecipient == to) revert FeeRecipientIsPayee();
            _transfer(msg.sender, feeRecipient, feeAmount);
        }
        _transfer(msg.sender, to, amount);
        emit PaymentSettled(msg.sender, to, amount, feeAmount, feeRecipient, entryRef);
        return true;
    }

    // ------------------------------------------------------------------ op

    function _erc1271Gas(address from) internal view override returns (uint256) {
        bytes32 h = _SUBJECT_CLONE_CODEHASH;
        return h != bytes32(0) && from.codehash == h ? 400_000 : 50_000;
    }

    function _hasPayee(MetaTxLib.MetaTransaction memory m) internal pure override returns (bool) {
        uint256 len = m.data.length;
        return len == 0 || (len == 36 && _op(m.data) == OP_PAY);
    }

    /// @dev Bước 6. Tham số đọc bằng `mload` ở offset cố định sau khi kiểm độ dài; một word địa chỉ có bit cao
    ///      bẩn ⇒ `MetaTxUnknownOp` (như `abi.decode` sẽ revert), nên mỗi op chỉ có MỘT encoding, MỘT digest.
    function _checkOp(MetaTxLib.MetaTransaction memory m) internal view override {
        bytes memory d = m.data;
        uint256 len = d.length;
        if (len == 0) return;
        if (len < 4) revert MetaTxUnknownOp(bytes4(0));
        bytes4 op = _op(d);
        if (op == OP_PAY) {
            if (len != 36) revert MetaTxUnknownOp(op);
            if (m.to == address(0)) revert PayToZero();
            return;
        }
        if (op == OP_TRADE) {
            if (len != 100 || !_isAddr(d, 4) || !_isAddr(d, 68)) revert MetaTxUnknownOp(op);
            // Chân lệnh chỉ thực thi được bởi đúng contract khớp lệnh người ký chọn, và tiền chỉ vào đó.
            if (m.mode & MetaTxLib.MODE_RESTRICT_RELAYER == 0 || m.to != msg.sender) revert TradeLegNotRestricted();
            return;
        }
        if (op == OP_APPROVE) {
            if (len != 68 || !_isAddr(d, 4)) revert MetaTxUnknownOp(op);
            address spender = address(uint160(_word(d, 4)));
            if (m.value != 0) revert ApproveCarriesValue();
            if (m.to != spender) revert ApproveSpenderMismatch();
            if (!_isContract(spender)) revert SpenderNotContract(spender);
            return;
        }
        if (op == OP_UNWRAP) {
            if (len != 100 || !_isAddr(d, 4) || !_isAddr(d, 36)) revert MetaTxUnknownOp(op);
            _checkUnwrap(address(uint160(_word(d, 4))), address(uint160(_word(d, 36))), m.to, m.value, _word(d, 68));
            return;
        }
        revert MetaTxUnknownOp(op);
    }

    /// @dev Bước 8. `approve` đặt allowance; `unwrap` cho tầng; còn lại là một transfer, `pay` thêm event đối soát.
    function _executeOp(MetaTxLib.MetaTransaction memory m, uint256 feeAmount, address feeRecipient)
        internal override
    {
        bytes memory d = m.data;
        uint256 len = d.length;
        if (len == 68 && _op(d) == OP_APPROVE) {
            _approve(m.from, address(uint160(_word(d, 4))), _word(d, 36));
            return;
        }
        if (len == 100 && _op(d) == OP_UNWRAP) {
            _executeUnwrap(m.from, address(uint160(_word(d, 4))), address(uint160(_word(d, 36))), m.value);
            return;
        }
        _transfer(m.from, m.to, m.value);
        if (len == 36 && _op(d) == OP_PAY) {
            emit PaymentSettled(m.from, m.to, m.value, feeAmount, feeRecipient, bytes32(_word(d, 4)));
        }
    }

    /// @dev Hook R148 của tầng wrapper, bước 6: chân biết, recipient hợp lệ, `to == recipient`, `out` trong biên.
    ///      Tầng 1 không có underlying: op không tồn tại.
    function _checkUnwrap(address, address, address, uint256, uint256) internal view virtual {
        revert MetaTxUnknownOp(OP_UNWRAP);
    }

    /// @dev Hook R148, bước 8: burn, trừ reserve, chuyển underlying (lời gọi ngoài DUY NHẤT được fail).
    function _executeUnwrap(address from, address u, address recipient, uint256 wrapped) internal virtual {}

    function _op(bytes memory d) internal pure returns (bytes4 op) {
        assembly ("memory-safe") {
            op := and(mload(add(d, 32)), 0xffffffff00000000000000000000000000000000000000000000000000000000)
        }
    }

    /// @dev Word 32 byte bắt đầu ở byte `off` của `d` (người gọi đã kiểm độ dài).
    function _word(bytes memory d, uint256 off) internal pure returns (uint256 w) {
        assembly ("memory-safe") { w := mload(add(add(d, 32), off)) }
    }

    function _isAddr(bytes memory d, uint256 off) internal pure returns (bool) {
        return _word(d, off) >> 160 == 0;
    }
}
