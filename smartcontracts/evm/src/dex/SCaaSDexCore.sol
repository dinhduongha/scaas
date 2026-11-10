// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ISCaaSDex} from "./ISCaaSDex.sol";
import {ITradeToken, ILiquidityPullToken} from "../trade/ITradeToken.sol";
import {ChainEnvCode} from "../factory/ChainEnvCode.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {TradeLib} from "../trade/TradeLib.sol";
import {IUALedger} from "../metatx/IUALedger.sol";
import {UAKinds} from "../ua/UAKinds.sol";
import {TokenCall} from "./TokenCall.sol";

/// @title The DEX's state accessor, constants and shared bodies (spec 2026-11-10-dex-liquidity.md §9.1; T66b rule 5,
///        written once): inherited by `SCaaSDex` and by its liquidity module `SCaaSDexLiquidityModule`, so an interaction,
///        a payout and a balance read run under the same rules in both. No state variable: the state is `scaas.dex`.
///        UNAUDITED.
abstract contract SCaaSDexCore {
    /// @notice The liquidity module's `moduleGroup()` (`script/modules/gen_faces.py` `GROUP_ID`).
    uint8 internal constant GROUP_LIQUIDITY = 11;
    uint256 internal constant PPM = 1_000_000;
    uint8 internal constant KIND_SCAAS = 1;
    uint8 internal constant KIND_OUTSIDE = 2;
    /// @dev Bytes of a failed settlement's revert data kept for `MatchFailed`: the copy costs this frame at most this
    ///      much, so a returnbomb (an outside token reverting with megabytes) cannot take the other settlements down.
    uint256 internal constant MAX_REASON = 256;
    /// @dev `TradeOrder.flags` bit: every interaction target or executor must be listed (CTR-DEX-23).
    uint8 internal constant LISTED_POOLS = 4;
    /// @dev ERC-20 `increaseAllowance(address,uint256)` and Permit2 `approve(address,address,uint160,uint48)`: refused on
    ///      every exchange interaction, so the only allowance a route grants is an `approve` the DEX resets to 0.
    bytes4 internal constant INCREASE_ALLOWANCE = 0x39509351;
    bytes4 internal constant PERMIT2_APPROVE = 0x87517c45;
    /// @dev `restorePulled(TradeOrder,uint256)` and `restorePulled(UATradeOrder,uint256)` (DX7): refused on every
    ///      interaction, which runs as the DEX (every order's `dex`) and could lower a pulled order's `pulled[h]` in the
    ///      same transaction (an over-sell).
    bytes4 internal constant RESTORE_PULLED = 0x58c18f87;
    bytes4 internal constant UA_RESTORE_PULLED = 0x8c4a5df6;
    /// @dev The retired trade entries (ua-mtx-merge T6, legacy/ua-mtx-merge/): the address `mtxTrade(TradeOrder,bytes,
    ///      TradeFill)` and `uaTrade(UATradeOrder,UASig,TradeFill)`, refused on every interaction like the merged
    ///      `mtxTrade`: a token of an earlier release keeps them, and the DEX is `o.dex` of every order.
    bytes4 internal constant OLD_MTX_TRADE = 0xfe49c984;
    bytes4 internal constant OLD_UA_TRADE = 0x6a4e2056;
    /// @dev ERC-721 `setApprovalForAll(address,bool)` (CTR-DEX-23 Change): refused on every interaction, so no operator over
    ///      the DEX's positions can be left for a later plan.
    bytes4 internal constant SET_APPROVAL_FOR_ALL = 0xa22cb465;
    /// @dev ERC-1271 gas cap for this chain's `SmartKeyAccount` clones (CTR-ACC-05); other contracts get
    ///      `SigCheck.ERC1271_GAS` (50 000).
    uint256 internal constant SMART_KEY_1271_GAS = 400_000;

    bytes32 internal constant DEX_ORDER_TYPEHASH = keccak256(
        "DexOrder(address sellToken,TradeOrder order)TradeOrder(address from,address receiveToken,uint256 amount,"
        "uint256 receiveAmount,uint256 minFill,uint256 fee,address relayer,address dex,address destination,uint8 flags,"
        "uint256 batch,uint256 nonce,uint256 validUntil)"
    );


    bytes32 internal constant CANCEL_DEX_ORDER_TYPEHASH = keccak256(
        "CancelDexOrder(DexOrder order)DexOrder(address sellToken,TradeOrder order)TradeOrder(address from,"
        "address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,uint256 fee,address relayer,address dex,"
        "address destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)"
    );

    /// @custom:storage-location erc7201:scaas.dex
    struct DexStorage {
        bool initialized;
        uint32 relayerSharePpm;
        address treasury;
        bool listedOnly;
        mapping(bytes32 pair => bool) listed;
        mapping(address token => uint8) kind;
        address puller;
        mapping(address token => uint256) listings; // listed markets the token is a side of: > 0 = known
        mapping(address target => bool) exchangeTarget;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.dex")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0xb144ea5327f344ea7e3b34dd1898f534c8ce28f9f54d0d89a1b78f8fcf7dac00;

    function _s() internal pure returns (DexStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }

    /// @dev CTR-DEX-08: 400 k for a `SmartKeyAccount` clone, else 50 k.
    function _cap(address signer) internal view returns (uint256) {
        address ska = ChainEnvCode.smartKeyAccountImpl();
        return ska != address(0) && signer.codehash == keccak256(abi.encodePacked(hex"363d3d373d3d3d363d73", ska,
            hex"5af43d82803e903d91602b57fd5bf3")) ? SMART_KEY_1271_GAS : SigCheck.ERC1271_GAS;
    }

    /// @dev An outside-token order's `DexOrder` struct hash (CTR-DEX-18).
    function _dexOrderHash(address sellToken, ITradeToken.TradeOrder memory o) internal pure returns (bytes32) {
        return keccak256(abi.encode(DEX_ORDER_TYPEHASH, sellToken, TradeLib.hashStruct(o)));
    }

    /// @dev A SCaaS token (factory-made, recorded at `setMarket`) whose UA ledger is on.
    function _ledgerOn(address token) internal view returns (bool) {
        return _s().kind[token] == KIND_SCAAS && IUALedger(token).registry() != address(0);
    }

    /// @dev Path (a)'s interactions in order, then every allowance an `approve` among them granted set back to 0.
    function _route(ISCaaSDex.Interaction[] calldata xs, bool onlyListed) internal {
        address[] memory approvedToken = new address[](xs.length);
        address[] memory approvedSpender = new address[](xs.length);
        uint256 na;
        for (uint256 i; i < xs.length; ++i) {
            bytes4 sel = _interact(xs[i], i, onlyListed);
            if (sel == IERC20.approve.selector) {
                approvedToken[na] = xs[i].target;
                (approvedSpender[na++],) = abi.decode(xs[i].data[4:], (address, uint256));
            }
        }
        // W-O, as `_send`: capped, the target's revert data dropped (a reset reverting with forged starvation bytes
        // fails only this plan of a batch)
        for (uint256 i; i < na; ++i) {
            address tk = approvedToken[i];
            if (!TokenCall.ok(tk, abi.encodeCall(IERC20.approve, (approvedSpender[i], 0)))) _tokenFailed(tk);
        }
    }

    /// @dev One interaction of path (a); returns its selector.
    function _interact(ISCaaSDex.Interaction calldata x, uint256 index, bool onlyListed) internal returns (bytes4 sel) {
        DexStorage storage s = _s();
        if (x.target == address(this) || x.target == s.puller) revert ISCaaSDex.ForbiddenTarget(x.target);
        sel = bytes4(x.data);
        if (x.data.length < 4 || sel == ITradeToken.mtxTrade.selector || sel == OLD_MTX_TRADE || sel == OLD_UA_TRADE) {
            revert ISCaaSDex.ForbiddenSelector(x.target, sel);
        }
        // controller ruling: no allowance may be raised outside `approve` (reset after the route)
        if (sel == INCREASE_ALLOWANCE || sel == PERMIT2_APPROVE) revert ISCaaSDex.ForbiddenSelector(x.target, sel);
        if (sel == RESTORE_PULLED || sel == UA_RESTORE_PULLED) revert ISCaaSDex.ForbiddenSelector(x.target, sel);
        // CTR-DEX-23 Change (CTR-DEX-30): another signer's liquidity pull, and an operator over the DEX's positions
        if (sel == ILiquidityPullToken.mtxLiquidityPull.selector || sel == SET_APPROVAL_FOR_ALL) {
            revert ISCaaSDex.ForbiddenSelector(x.target, sel);
        }
        if (onlyListed && !s.exchangeTarget[x.target]) revert ISCaaSDex.TargetNotListed(x.target);
        bytes memory data = x.data;
        address target = x.target;
        bool ok;
        bytes memory reason;
        // no return data is copied on success; on failure at most MAX_REASON bytes (DX11)
        assembly ("memory-safe") {
            ok := call(gas(), target, 0, add(data, 0x20), mload(data), 0, 0)
            if iszero(ok) {
                let n := returndatasize()
                if gt(n, MAX_REASON) { n := MAX_REASON }
                reason := mload(0x40)
                mstore(reason, n)
                returndatacopy(add(reason, 0x20), 0, n)
                mstore(0x40, add(add(reason, 0x20), and(add(n, 0x1f), not(0x1f))))
            }
        }
        if (!ok) revert ISCaaSDex.InteractionFailed(index, target, reason);
    }

    /// @dev A failed transfer never reverts with the token's own revert data (W-O): a token, or a hook it calls, must
    ///      not be able to forge the starvation errors `mtxSettle` re-raises. See `_tokenFailed`.
    function _send(address token, address to, uint256 amount) internal {
        if (amount != 0 && !TokenCall.ok(token, abi.encodeCall(IERC20.transfer, (to, amount)))) _tokenFailed(token);
    }

    /// @dev A failed token call: no return data (it ran out of gas, or the token has no code) reverts empty, which
    ///      the node reads as `out_of_gas` (NODE-DEX-06); anything else reverts `SafeERC20FailedOperation(token)`.
    ///      Empty data matches neither starvation selector, so a token still cannot forge one. Called right after the
    ///      token call: `returndatasize` is still that call's (EXTCODESIZE in `trySafe*` leaves it alone).
    function _tokenFailed(address token) internal pure {
        assembly ("memory-safe") {
            if iszero(returndatasize()) { revert(0, 0) }
        }
        revert SafeERC20.SafeERC20FailedOperation(token);
    }

    /// @dev `balanceOf(this)`, without the token's revert data or more than one word of return data (W-O, as `_send`).
    function _bal(address token) internal view returns (uint256 b) {
        bool ok;
        assembly ("memory-safe") {
            mstore(0, 0x70a08231) // balanceOf(address)
            mstore(0x20, address())
            let g := gas()
            if gt(g, 500000) { g := 500000 } // C6-1: TokenCall.TOKEN_GAS
            let s := staticcall(g, token, 0x1c, 0x24, 0, 0x20) // before returndatasize (Yul: args right to left)
            ok := and(s, gt(returndatasize(), 0x1f))
            b := mload(0)
        }
        if (!ok) _tokenFailed(token);
    }

    /// @dev To an id: a native one by `_send`, a derived one by the token's `transferToUA` from the DEX's own
    ///      balance (it lowers `balanceOf(this)` as `safeTransfer` does, so conservation is unchanged), only in a SCaaS
    ///      token with its UA ledger on; the token checks the receiver (registered SIGNING).
    function _sendTo(address token, bytes32 to, uint256 amount) internal {
        if (amount == 0) return;
        if (UAKinds.inNativeSpace(to)) return _send(token, TradeLib.addr(to), amount);
        if (!_ledgerOn(token)) revert ISCaaSDex.UAReceiveNotLedger(token);
        IUALedger(token).transferToUA(to, amount);
    }
}
