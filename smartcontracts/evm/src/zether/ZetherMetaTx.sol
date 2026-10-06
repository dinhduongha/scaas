// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC20MetaTx} from "../metatx/IERC20MetaTx.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeePolicy, FeeMode} from "../common/FeePolicy.sol";

/// @title Mixin meta-transaction native cho Zether token (RS2-7).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Cùng struct/typehash `MetaTxLib` (chỉ đọc), cùng
///         2D nonce, cùng R26, cùng chín bước rẻ-trước-đắt-sau của `ERC20MetaTx` — nhưng là bản riêng vì
///         `ERC20MetaTx` (luồng S4/S5 sở hữu) tính phí `FIXED` có trần 1% của `m.value`, mà op Zether có
///         `m.value = 0` (số tiền nằm trong ciphertext). Ở đây phí của op Zether là tuyệt đối, `PERCENT`
///         bị cấm (`FeePolicy.requireConfidentialSafe`, RS2-6).
///
///         Bước 6–8 (kiểm đủ → thu phí → thực thi) giao cho `_executeOp`: op Zether phải kiểm số dư phí
///         TRƯỚC verify proof, và thu phí SAU verify, TRƯỚC hiệu lực — "phí đã thu ⟺ op đã xảy ra".
abstract contract ZetherMetaTx is ERC20, EIP712, IERC20MetaTx {
    using MetaTxLib for MetaTxLib.MetaTransaction;

    mapping(address => mapping(uint256 => uint256)) private _metaNonce;

    /// keccak256("scaas.zether.reentrancy.v1")
    bytes32 private constant _REENTRANCY_SLOT = 0xdab132193f21f496e0f9f835d2fe97c7fe2ea3245c0beb12d8008784b59ee140;

    modifier nonReentrant() {
        assembly ("memory-safe") {
            if tload(_REENTRANCY_SLOT) { revert(0, 0) }
            tstore(_REENTRANCY_SLOT, 1)
        }
        _;
        assembly ("memory-safe") { tstore(_REENTRANCY_SLOT, 0) }
    }

    function metaNonce(address from, uint256 batch) public view returns (uint256) {
        return _metaNonce[from][batch];
    }

    function supportedModes() external pure returns (uint32) {
        return MetaTxLib.MODE_KNOWN_MASK;
    }

    function metaTxDigest(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32) {
        return _hashTypedDataV4(m.hashStruct());
    }

    function cancelMetaNonce(uint256 batch) external {
        unchecked { _metaNonce[msg.sender][batch] += 1; }
    }

    function executeMetaTransaction(MetaTxLib.MetaTransaction calldata m, bytes calldata signature)
        external nonReentrant returns (bool)
    {
        // 1. relayer
        if (m.mode & MetaTxLib.MODE_RESTRICT_RELAYER != 0 && m.relayer != msg.sender) {
            revert MetaTxUnauthorizedRelayer(m.relayer, msg.sender);
        }
        // 2. hạn
        if (block.timestamp > m.validUntil) revert MetaTxExpired(m.validUntil, block.timestamp);
        // 3. mode
        MetaTxLib.validateMode(m.mode);
        FeeMode feeMode = MetaTxLib.feeModeOf(m.mode);
        // 4. nonce
        uint256 expected = _metaNonce[m.from][m.batch];
        if (expected != m.nonce) revert MetaTxBadNonce(expected, m.nonce);
        // 5. chữ ký
        bytes32 digest = _hashTypedDataV4(m.hashStruct());
        _requireValidSignature(m.from, digest, signature);
        // 6–8. kiểm đủ → thu phí → thực thi (op tự sắp, xem NatSpec)
        address feeRecipient = m.feeRecipient == address(0) ? msg.sender : m.feeRecipient;
        FeePolicy.validateRecipient(feeMode, feeRecipient);
        uint256 feeAmount = _executeOp(m, feeMode, feeRecipient);
        // 9. nonce++ và emit
        unchecked { _metaNonce[m.from][m.batch] = expected + 1; }
        emit MetaTransactionExecuted(m.from, msg.sender, m.batch, m.nonce, digest, feeRecipient, feeAmount);
        return true;
    }

    /// @dev Kiểm, thu phí, thực thi; trả số phí đã thu. Không được thu phí trước khi mọi kiểm tra qua.
    function _executeOp(MetaTxLib.MetaTransaction calldata m, FeeMode feeMode, address feeRecipient)
        internal virtual returns (uint256 feeAmount);

    /// @dev Bước 6 dùng chung: số dư công khai của `from` đủ `need` — kiểm TRƯỚC mọi thứ đắt.
    function _requireBalance(address from, uint256 need) internal view {
        uint256 have = balanceOf(from);
        if (have < need) revert MetaTxInsufficientForFee(need, have);
    }

    // ------------------------------------------------------------------ allowance (R26)

    function approve(address spender, uint256 value) public virtual override(ERC20, IERC20) returns (bool) {
        if (!_isContract(spender)) revert SpenderNotContract(spender);
        return super.approve(spender, value);
    }

    function transferFrom(address from, address to, uint256 value)
        public virtual override(ERC20, IERC20) returns (bool)
    {
        if (!_isContract(msg.sender)) revert CallerNotContract(msg.sender);
        return super.transferFrom(from, to, value);
    }

    /// @dev Như `ERC20MetaTx._isContract`: code rỗng hoặc designator EIP-7702 ⇒ không phải hợp đồng.
    function _isContract(address a) internal view returns (bool) {
        uint256 len = a.code.length;
        if (len == 0) return false;
        if (len == 23) {
            bytes memory c = a.code;
            if (c[0] == 0xef && c[1] == 0x01 && c[2] == 0x00) return false;
        }
        return true;
    }

    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig) internal view {
        if (!_isContract(from)) {
            (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, sig);
            if (err != ECDSA.RecoverError.NoError || rec != from) revert MetaTxBadSignature();
        } else {
            (bool ok, bytes memory ret) = from.staticcall{gas: 50_000}(
                abi.encodeCall(IERC1271.isValidSignature, (digest, sig))
            );
            if (!ok || ret.length != 32 || abi.decode(ret, (bytes4)) != IERC1271.isValidSignature.selector) {
                revert MetaTxBadSignature();
            }
        }
    }
}
