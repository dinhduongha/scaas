// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.20;

import {MockERC20} from "../../helpers/Mocks.sol";

/// Phí trả bởi NGƯỜI GỬI, cộng thêm (kiểu HTS `netOfTransfers`): người nhận nhận đủ `v`, người gửi mất `v + v/100`.
/// Wrap vẫn đúng (đo delta); unwrap thì số dư wrapper giảm hơn `out` ⇒ `UnderlyingTransferMismatch` (R143).
contract SenderPaysFeeERC20 is MockERC20 {
    constructor() MockERC20("SenderFee", "SFEE", 18) {}
    function _update(address from, address to, uint256 v) internal override {
        if (from != address(0) && to != address(0)) super._update(from, address(0), v / 100);
        super._update(from, to, v);
    }
}

/// Rebase âm / tịch thu: `slash` đốt thẳng từ một địa chỉ (wrapper), `balanceOf < reserve` sau đó.
contract SlashableERC20 is MockERC20 {
    constructor(uint8 d) MockERC20("Slash", "SLSH", d) {}
    function slash(address who, uint256 v) external { _burn(who, v); }
}

/// Blacklist: chuyển từ/tới một địa chỉ bị chặn thì revert.
contract BlacklistERC20 is MockERC20 {
    mapping(address => bool) public blocked;
    error Blocked(address);
    constructor() MockERC20("Black", "BLK", 6) {}
    function setBlocked(address a, bool b) external { blocked[a] = b; }
    function _update(address from, address to, uint256 v) internal override {
        if (blocked[from]) revert Blocked(from);
        if (blocked[to]) revert Blocked(to);
        super._update(from, to, v);
    }
}

interface ITokensReceived {
    function tokensReceived(address from, uint256 amount) external;
}

/// Kiểu ERC-777: sau mỗi lần chuyển tới một người nhận đã đăng ký hook (thay cho ERC-1820), gọi hook đó.
contract HookERC20 is MockERC20 {
    mapping(address => bool) public hooked;
    constructor() MockERC20("Hook", "HOOK", 18) {}
    function setHooked(address a) external { hooked[a] = true; }
    function _update(address from, address to, uint256 v) internal override {
        super._update(from, to, v);
        if (from != address(0) && hooked[to]) ITokensReceived(to).tokensReceived(from, v);
    }
}

/// Có code, không có `decimals()`.
contract NoDecimals {
    function balanceOf(address) external pure returns (uint256) { return 0; }
}

/// `decimals()` trả một word ngoài biên uint8.
contract BadDecimals {
    function decimals() external pure returns (uint256) { return 256; }
}

/// Rate admin là một hợp đồng (R135): forwarder tối thiểu, chủ là người deploy.
contract RateAdminForwarder {
    address public immutable owner;
    constructor() { owner = msg.sender; }
    function exec(address target, bytes calldata data) external returns (bytes memory) {
        require(msg.sender == owner, "owner");
        (bool ok, bytes memory ret) = target.call(data);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        return ret;
    }
}
