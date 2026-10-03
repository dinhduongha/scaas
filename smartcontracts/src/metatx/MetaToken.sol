// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ERC20MetaTx} from "./ERC20MetaTx.sol";
import {IFactoryToken} from "../factory/IFactoryToken.sol";

/// @title MetaToken v1 — implementation của kind META, deploy bằng clone EIP-1167.
/// @notice Một implementation, hai tầng (SRS §3.1) chọn bằng `underlying`:
///         `0` ⇒ tầng 1 standalone (cung do `minter`), khác `0` ⇒ tầng 2 wrapper 1:1.
///
///         Domain EIP-712 của mọi clone là `("Bamboo MetaToken", "1", chainId, clone)`:
///         OZ `EIP712` giữ tên/version dạng immutable của implementation, và an toàn
///         replay đến từ `verifyingContract`, không từ tên (ruling R5). Client đọc
///         `eip712Domain()` (ERC-5267) chứ không đoán.
///
///         Không owner, không pause, không upgrade: token tự do (SRS §3.5.1).
contract MetaToken is ERC20MetaTx, IFactoryToken {
    address public immutable FACTORY;
    address private immutable _SELF;

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

    /// @dev Constructor chạy MỘT lần, trên implementation. Immutable của nó đúng cho mọi
    ///      clone; storage của nó thì không — nên khoá luôn implementation để không ai
    ///      `initialize` được chính nó (01-token-factory §1.3.5 mục 1).
    constructor(address factory_) ERC20("", "") EIP712("Bamboo MetaToken", "1") {
        FACTORY = factory_;
        _SELF = address(this);
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
}
