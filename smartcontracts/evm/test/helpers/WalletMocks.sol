// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// Spender/caller thật là một hợp đồng: kéo tiền bằng `transferFrom` của chính nó.
contract Puller {
    function pull(address token, address from, address to, uint256 v) external returns (bool) {
        return IERC20(token).transferFrom(from, to, v);
    }

    function approveOn(address token, address spender, uint256 v) external returns (bool) {
        return IERC20(token).approve(spender, v);
    }
}

/// Gọi `transferFrom` ngay trong constructor: lúc đó `code.length == 0` (hợp đồng chưa có code).
contract ConstructorPuller {
    constructor(address token, address from, uint256 v) {
        IERC20(token).transferFrom(from, address(this), v);
    }
}

/// Ví ERC-1271 giả: `mode` quyết định câu trả lời.
contract Mock1271Wallet {
    enum Mode { Valid, WrongMagic, Reverts, Short, Long, DirtyTail, Burn }

    Mode public mode;
    address public immutable owner;

    constructor(address owner_) { owner = owner_; }

    function setMode(Mode m) external { mode = m; }

    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        if (mode == Mode.Reverts) revert("nope");
        if (mode == Mode.Short) {
            assembly {
                mstore(0, 0x1626ba7e00000000000000000000000000000000000000000000000000000000)
                return(0, 4)
            }
        }
        if (mode == Mode.Long) {
            assembly {
                mstore(0, 0x1626ba7e00000000000000000000000000000000000000000000000000000000)
                mstore(0x20, 1)
                return(0, 0x40)
            }
        }
        if (mode == Mode.DirtyTail) {
            assembly {
                mstore(0, or(0x1626ba7e00000000000000000000000000000000000000000000000000000000, 1))
                return(0, 0x20)
            }
        }
        if (mode == Mode.Burn) {
            // burn ~46k gas, then answer valid: proves the wallet really received its 50k cap. F185: was 48k; the cold `mode`
            // read before it costs more under Amsterdam (EIP-8038), which left 48k over the cap
            uint256 g = gasleft();
            while (g - gasleft() < 46_000) {}
            return 0x1626ba7e;
        }
        if (mode == Mode.WrongMagic) return 0xffffffff;
        (bytes32 r, bytes32 s) = abi.decode(sig[:64], (bytes32, bytes32));
        return ecrecover(hash, uint8(sig[64]), r, s) == owner ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
}
