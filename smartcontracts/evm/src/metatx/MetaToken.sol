// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ERC20MetaTx} from "./ERC20MetaTx.sol";
import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {IERC20Payment} from "./IERC20Payment.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeePolicy, FeeMode} from "../common/FeePolicy.sol";

/// @title MetaToken v1 — implementation của kind META, deploy bằng clone EIP-1167.
/// @notice Một implementation, hai tầng (SRS §3.1) chọn bằng `underlying`:
///         `0` ⇒ tầng 1 standalone (cung do `minter`), khác `0` ⇒ tầng 2 wrapper 1:1.
///
///         Domain EIP-712 của mọi clone là `("SCaaS MetaToken", "1", chainId, clone)`:
///         OZ `EIP712` giữ tên/version dạng immutable của implementation, và an toàn
///         replay đến từ `verifyingContract`, không từ tên (ruling R5). Client đọc
///         `eip712Domain()` (ERC-5267) chứ không đoán.
///
///         Không owner, không pause, không upgrade: token tự do (SRS §3.5.1).
contract MetaToken is ERC20MetaTx, IERC20Payment, IFactoryToken {
    using SafeERC20 for IERC20;

    /// @dev Op là `data` có tag selector, nằm TRONG struct đã ghim — không typehash thứ
    ///      hai, ví hiển thị một loại giao dịch (ruling R2).
    bytes4 public constant OP_PAY = bytes4(keccak256("pay(bytes32)"));
    bytes4 public constant OP_TRADE = bytes4(keccak256("trade(address,uint256,address)"));
    /// @dev Cấp allowance không gas (R35): người dùng uỷ quyền cho DEX bằng một meta-tx. Spender
    ///      phải là contract (R26) — cùng một `_isContract` với `approve()` gọi thẳng.
    bytes4 public constant OP_APPROVE = bytes4(keccak256("approve(address,uint256)"));

    address public immutable FACTORY;
    address private immutable _SELF;
    /// @notice SubjectAccount implementation of this chain (0 = none). Only its EIP-1167 clones get
    ///         400k gas for ERC-1271 (a passkey check without the P-256 precompile); others 50k.
    address public immutable SUBJECT_ACCOUNT_IMPL;
    bytes32 private immutable _SUBJECT_CLONE_CODEHASH;

    bool private _initialized;
    string private _tokenName;
    string private _tokenSymbol;
    uint8 private _tokenDecimals;

    address public creator;
    address public underlying;
    address public minter;
    uint64 public version;

    error NotFactory();
    error AlreadyInitialized();
    error VerifierNotAllowed();
    error WrapperHasNoMint();
    error NotMinter();
    error MetaTxUnknownOp(bytes4 op);
    error PayToZero();
    error TradeLegNotRestricted();
    error NotAWrapper();
    error ApproveCarriesValue();
    error ApproveSpenderMismatch();

    /// @dev Constructor chạy MỘT lần, trên implementation. Immutable của nó đúng cho mọi
    ///      clone; storage của nó thì không — nên khoá luôn implementation để không ai
    ///      `initialize` được chính nó (01-token-factory §1.3.5 mục 1).
    constructor(address factory_, address subjectAccountImpl_) ERC20("", "") EIP712("SCaaS MetaToken", "1") {
        FACTORY = factory_;
        _SELF = address(this);
        SUBJECT_ACCOUNT_IMPL = subjectAccountImpl_;
        // OZ Clones runtime code (45 bytes): its hash pins "a clone of exactly this implementation".
        _SUBJECT_CLONE_CODEHASH = subjectAccountImpl_ == address(0) ? bytes32(0) : keccak256(abi.encodePacked(
            hex"363d3d373d3d3d363d73", subjectAccountImpl_, hex"5af43d82803e903d91602b57fd5bf3"));
        _initialized = true;
    }

    /// @param initData `abi.encode(string name, string symbol, uint8 decimals,
    ///        uint256 initialSupply, address minter)`. Tầng 2 bỏ qua `decimals` (đọc từ
    ///        underlying) và bắt buộc `initialSupply == 0 && minter == 0`.
    function initialize(
        address creator_,
        address underlying_,
        address verifier_,
        uint64 version_,
        bytes calldata initData
    ) external {
        if (msg.sender != FACTORY) revert NotFactory();
        if (_initialized) revert AlreadyInitialized();
        if (verifier_ != address(0)) revert VerifierNotAllowed();
        _initialized = true;
        (string memory n, string memory s, uint8 d, uint256 supply, address minter_) =
            abi.decode(initData, (string, string, uint8, uint256, address));
        creator = creator_;
        underlying = underlying_;
        version = version_;
        _tokenName = n;
        _tokenSymbol = s;
        if (underlying_ == address(0)) {
            _tokenDecimals = d;
            minter = minter_;
            if (supply != 0) _mint(creator_, supply);
        } else {
            // Tầng 2: cung CHỈ đến từ wrap, nếu không bất biến dự trữ không giữ được.
            if (supply != 0 || minter_ != address(0)) revert WrapperHasNoMint();
            _tokenDecimals = ERC20(underlying_).decimals();
        }
    }

    function name() public view override returns (string memory) { return _tokenName; }
    function symbol() public view override returns (string memory) { return _tokenSymbol; }
    function decimals() public view override returns (uint8) { return _tokenDecimals; }

    function factory() external view returns (address) { return FACTORY; }
    function implementation() external view returns (address) { return _SELF; }
    function verifier() external pure returns (address) { return address(0); }

    /// @notice Tầng 1 thôi. `minter == 0` ⇒ cung cố định.
    function mint(address to, uint256 amount) external {
        if (minter == address(0) || msg.sender != minter) revert NotMinter();
        _mint(to, amount);
    }

    /// @notice Tầng 2. Mint đúng phần THỰC nhận (token phí-chuyển), để
    ///         `underlying.balanceOf(this) >= totalSupply` không bao giờ vỡ.
    function wrap(uint256 amount) external nonReentrant returns (uint256 minted) {
        address u = underlying;
        if (u == address(0)) revert NotAWrapper();
        uint256 before = IERC20(u).balanceOf(address(this));
        IERC20(u).safeTransferFrom(msg.sender, address(this), amount);
        minted = IERC20(u).balanceOf(address(this)) - before;
        _mint(msg.sender, minted);
    }

    function unwrap(uint256 amount, address recipient) external nonReentrant {
        address u = underlying;
        if (u == address(0)) revert NotAWrapper();
        _burn(msg.sender, amount);
        IERC20(u).safeTransfer(recipient, amount);
    }

    function _erc1271Gas(address from) internal view override returns (uint256) {
        bytes32 h = _SUBJECT_CLONE_CODEHASH;
        return h != bytes32(0) && from.codehash == h ? 400_000 : 50_000;
    }

    /// @dev Bước 6. Mọi thứ fail được thì fail ở đây, TRƯỚC khi thu phí.
    function _checkOp(MetaTxLib.MetaTransaction calldata m) internal view override {
        uint256 len = m.data.length;
        if (len == 0) return;
        if (len < 4) revert MetaTxUnknownOp(bytes4(0));
        bytes4 op = bytes4(m.data[:4]);
        if (op == OP_PAY) {
            if (len != 36) revert MetaTxUnknownOp(op);
            if (m.to == address(0)) revert PayToZero();
            return;
        }
        if (op == OP_TRADE) {
            if (len != 100) revert MetaTxUnknownOp(op);
            // Chân lệnh chỉ thực thi được bởi đúng contract khớp lệnh mà người ký đã
            // chọn, và tiền chỉ đi VÀO chính contract đó. Lệnh bị lộ thì vô dụng với
            // mọi người khác.
            if (m.mode & MetaTxLib.MODE_RESTRICT_RELAYER == 0 || m.to != msg.sender) {
                revert TradeLegNotRestricted();
            }
            return;
        }
        if (op == OP_APPROVE) {
            if (len != 68) revert MetaTxUnknownOp(op);
            (address spender,) = abi.decode(m.data[4:], (address, uint256));
            // `value` là lượng CHUYỂN; approve không chuyển gì. `to` phải nêu đúng spender để ví
            // hiển thị "gửi tới: DEX" khớp với thứ thực sự được uỷ quyền.
            if (m.value != 0) revert ApproveCarriesValue();
            if (m.to != spender) revert ApproveSpenderMismatch();
            if (!_isContract(spender)) revert SpenderNotContract(spender);
            return;
        }
        revert MetaTxUnknownOp(op);
    }

    /// @dev Bước 8. `approve` đặt allowance; ba op còn lại cùng một chuyển; chỉ `pay` thêm event đối soát.
    function _executeOp(MetaTxLib.MetaTransaction calldata m, uint256 feeAmount, address feeRecipient)
        internal override
    {
        if (m.data.length == 68 && bytes4(m.data[:4]) == OP_APPROVE) {
            (address spender, uint256 amount) = abi.decode(m.data[4:], (address, uint256));
            _approve(m.from, spender, amount);
            return;
        }
        _transfer(m.from, m.to, m.value);
        if (m.data.length == 36 && bytes4(m.data[:4]) == OP_PAY) {
            emit PaymentSettled(m.from, m.to, m.value, feeAmount, feeRecipient, bytes32(m.data[4:36]));
        }
    }

    /// @notice Đường gọi thẳng: `msg.sender` tự trả gas, phí thu THÊM, `amount` nguyên vẹn.
    function payWithFee(
        address to,
        uint256 amount,
        FeeMode feeMode,
        uint256 fee,
        address feeRecipient,
        bytes32 entryRef
    ) external returns (bool) {
        uint256 feeAmount = FeePolicy.compute(feeMode, amount, fee);
        FeePolicy.validateRecipient(feeMode, feeRecipient);
        if (feeAmount != 0) _transfer(msg.sender, feeRecipient, feeAmount);
        _transfer(msg.sender, to, amount);
        emit PaymentSettled(msg.sender, to, amount, feeAmount, feeRecipient, entryRef);
        return true;
    }
}
