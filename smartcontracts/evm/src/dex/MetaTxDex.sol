// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {IERC20MetaTx} from "../metatx/IERC20MetaTx.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeeMode} from "../common/FeePolicy.sol";

/// @title Khớp lệnh nguyên tử P2P (SRS §3.3) — KHÔNG allowance, KHÔNG giữ tiền.
/// @notice Mỗi lệnh là một meta-tx `trade(...)` trên token bán, ký với
///         `relayer == to == address(this)`. Token tự ép điều đó (MetaToken._checkOp), nên
///         một lệnh bị lộ chỉ chạy được ở đây, và ở đây nó chỉ chạy CÙNG chân đối ứng
///         thoả giá người ký đã đặt. Không owner, không sweep, không upgrade.
///
///         Fill-or-kill: `value` mỗi chân đã ký chính xác, nên không có khớp một phần
///         (ruling R3). Phần dư giá thuộc về người bán chân kia — nó nằm trong chữ ký.
contract MetaTxDex is ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    bytes4 public constant OP_TRADE = bytes4(keccak256("trade(address,uint256,address)"));

    struct Leg {
        IERC20MetaTx token;
        MetaTxLib.LegacyMetaTransaction m;
        bytes sig;
    }

    struct Terms {
        address counterToken;
        uint256 minCounterValue;
        address counterparty;
    }

    event TradeSettled(
        address indexed partyA,
        address indexed partyB,
        address tokenA,
        address tokenB,
        uint256 valueA,
        uint256 valueB
    );

    error NotATradeLeg();
    error SameToken();
    error SameParty();
    error CounterTokenMismatch();
    error PriceNotMet(uint256 got, uint256 min);
    error CounterpartyMismatch();
    error LegNotRoutedHere();
    error FeeWouldStick();
    error DeltaMismatch(address token, uint256 got, uint256 expected);

    function settle(Leg calldata a, Leg calldata b) external nonReentrant {
        Terms memory ta = _terms(a.m);
        Terms memory tb = _terms(b.m);
        if (address(a.token) == address(b.token)) revert SameToken();
        if (a.m.from == b.m.from) revert SameParty();
        if (ta.counterToken != address(b.token) || tb.counterToken != address(a.token)) {
            revert CounterTokenMismatch();
        }
        if (b.m.value < ta.minCounterValue) revert PriceNotMet(b.m.value, ta.minCounterValue);
        if (a.m.value < tb.minCounterValue) revert PriceNotMet(a.m.value, tb.minCounterValue);
        if ((ta.counterparty != address(0) && ta.counterparty != b.m.from)
            || (tb.counterparty != address(0) && tb.counterparty != a.m.from)) {
            revert CounterpartyMismatch();
        }
        _checkRouting(a.m);
        _checkRouting(b.m);

        _pull(a);
        _pull(b);
        IERC20(address(a.token)).safeTransfer(b.m.from, a.m.value);
        IERC20(address(b.token)).safeTransfer(a.m.from, b.m.value);
        emit TradeSettled(a.m.from, b.m.from, address(a.token), address(b.token), a.m.value, b.m.value);
    }

    function _terms(MetaTxLib.LegacyMetaTransaction calldata m) private pure returns (Terms memory t) {
        bytes calldata d = m.data;
        if (d.length != 100 || bytes4(d[:4]) != OP_TRADE) revert NotATradeLeg();
        (t.counterToken, t.minCounterValue, t.counterparty) = abi.decode(d[4:], (address, uint256, address));
    }

    /// @dev `ERC20MetaTx` gửi phí cho `msg.sender` khi `feeRecipient == 0`; ở đây
    ///      `msg.sender` là contract này, và nó không có cách nào trả lại.
    function _checkRouting(MetaTxLib.LegacyMetaTransaction calldata m) private view {
        if (m.to != address(this) || m.relayer != address(this)
            || m.mode & MetaTxLib.MODE_RESTRICT_RELAYER == 0) {
            revert LegNotRoutedHere();
        }
        if (MetaTxLib.feeModeOf(m.mode) != FeeMode.NONE
            && (m.feeRecipient == address(0) || m.feeRecipient == address(this))) {
            revert FeeWouldStick();
        }
    }

    /// @dev Đo delta thật: token phí-chuyển hay token "giả chuyển" bị từ chối ở đây.
    function _pull(Leg calldata l) private {
        IERC20 t = IERC20(address(l.token));
        uint256 before = t.balanceOf(address(this));
        l.token.executeMetaTransaction(l.m, l.sig);
        uint256 got = t.balanceOf(address(this)) - before;
        if (got != l.m.value) revert DeltaMismatch(address(t), got, l.m.value);
    }
}
