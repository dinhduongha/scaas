// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {VM, a, h, n, domainJson} from "../metatx/NamedEntry.t.sol";

/// What a wallet signs for the order structs (`eth_signTypedData_v4`): the digest of the JSON it is handed, nothing from
/// the contract's struct hash (`vm.eip712HashTypedData`), under the domain the contract publishes (ERC-5267). An order is
/// given in its one memory form; `ua` picks the id structs.
library OrderJson {
    function _idType(bool ua) private pure returns (string memory) {
        return ua ? "bytes32" : "address";
    }

    function _id(bytes32 v, bool ua) private pure returns (string memory) {
        return ua ? h(v) : a(address(uint160(uint256(v))));
    }

    function _tail() private pure returns (string memory) {
        return '{"name":"flags","type":"uint8"},{"name":"batch","type":"uint256"},{"name":"nonce","type":"uint256"},{"name":"validUntil","type":"uint256"}';
    }

    function _tradeFields(bool ua) private pure returns (string memory) {
        return string.concat('[{"name":"from","type":"', _idType(ua), '"},{"name":"receiveToken","type":"address"},{"name":"amount","type":"uint256"},',
            '{"name":"receiveAmount","type":"uint256"},{"name":"minFill","type":"uint256"},{"name":"fee","type":"uint256"},',
            '{"name":"relayer","type":"address"},{"name":"dex","type":"address"},{"name":"destination","type":"', _idType(ua), '"},', _tail(), ']');
    }

    function _wrapFields(bool ua) private pure returns (string memory) {
        return string.concat('[{"name":"from","type":"', _idType(ua), '"},{"name":"wrappedToken","type":"address"},{"name":"amount","type":"uint256"},',
            '{"name":"minMinted","type":"uint256"},{"name":"minFill","type":"uint256"},{"name":"fee","type":"uint256"},',
            '{"name":"relayer","type":"address"},{"name":"destination","type":"', _idType(ua), '"},', _tail(), ']');
    }

    function _common(ITradeToken.UATradeOrder memory o) private pure returns (string memory) {
        return string.concat('"minFill":', n(o.minFill), ',"fee":', n(o.fee), ',"relayer":', a(o.relayer));
    }

    function _end(ITradeToken.UATradeOrder memory o, bool ua) private pure returns (string memory) {
        return string.concat(',"destination":', _id(o.destination, ua), ',"flags":', n(o.flags), ',"batch":', n(o.batch), ',"nonce":', n(o.nonce),
            ',"validUntil":', n(o.validUntil), '}');
    }

    function _tradeMsg(ITradeToken.UATradeOrder memory o, bool ua) private pure returns (string memory) {
        return string.concat('{"from":', _id(o.from, ua), ',"receiveToken":', a(o.receiveToken), ',"amount":', n(o.amount), ',"receiveAmount":',
            n(o.receiveAmount), ',', _common(o), ',"dex":', a(o.dex), _end(o, ua));
    }

    function _wrapMsg(ITradeToken.UATradeOrder memory o, bool ua) private pure returns (string memory) {
        return string.concat('{"from":', _id(o.from, ua), ',"wrappedToken":', a(o.receiveToken), ',"amount":', n(o.amount), ',"minMinted":',
            n(o.receiveAmount), ',', _common(o), _end(o, ua));
    }

    function _name(string memory base, bool ua) private pure returns (string memory) {
        return ua ? string.concat("UA", base) : base;
    }

    function digest(address c, string memory primary, string memory types, string memory message) internal view returns (bytes32) {
        return VM.eip712HashTypedData(string.concat(
            '{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},',
            '{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"},{"name":"salt","type":"bytes32"}],',
            types, '},"primaryType":"', primary, '","domain":', domainJson(c), ',"message":', message, '}'));
    }

    /// `TradeOrder` / `UATradeOrder`, whatever `dex` is.
    function trade(address c, ITradeToken.UATradeOrder memory o, bool ua) internal view returns (bytes32) {
        string memory t = _name("TradeOrder", ua);
        return digest(c, t, string.concat('"', t, '":', _tradeFields(ua)), _tradeMsg(o, ua));
    }

    /// `WrapOrder` / `UAWrapOrder`: `wrappedToken = receiveToken`, `minMinted = receiveAmount`, no `dex`.
    function wrap(address c, ITradeToken.UATradeOrder memory o, bool ua) internal view returns (bytes32) {
        string memory t = _name("WrapOrder", ua);
        return digest(c, t, string.concat('"', t, '":', _wrapFields(ua)), _wrapMsg(o, ua));
    }

    function _cancel(address c, string memory primary, string memory inner, string memory fields, string memory m)
        private view returns (bytes32)
    {
        return digest(c, primary, string.concat('"', primary, '":[{"name":"order","type":"', inner, '"}],"', inner, '":', fields),
            string.concat('{"order":', m, '}'));
    }

    /// `CancelOrder` / `CancelUAOrder`, nesting the `TradeOrder`.
    function cancelTrade(address c, ITradeToken.UATradeOrder memory o, bool ua) internal view returns (bytes32) {
        return _cancel(c, ua ? "CancelUAOrder" : "CancelOrder", _name("TradeOrder", ua), _tradeFields(ua), _tradeMsg(o, ua));
    }

    /// `CancelWrapOrder` / `CancelUAWrapOrder`, nesting the `WrapOrder`.
    function cancelWrap(address c, ITradeToken.UATradeOrder memory o, bool ua) internal view returns (bytes32) {
        return _cancel(c, ua ? "CancelUAWrapOrder" : "CancelWrapOrder", _name("WrapOrder", ua), _wrapFields(ua), _wrapMsg(o, ua));
    }

    /// `CancelDexOrder`, nesting `DexOrder` nesting `TradeOrder`.
    function cancelDex(address dex, address sellToken, ITradeToken.UATradeOrder memory o) internal view returns (bytes32) {
        return digest(dex, "CancelDexOrder", string.concat(
            '"CancelDexOrder":[{"name":"order","type":"DexOrder"}],"DexOrder":[{"name":"sellToken","type":"address"},{"name":"order","type":"TradeOrder"}],',
            '"TradeOrder":', _tradeFields(false)), string.concat('{"order":{"sellToken":', a(sellToken), ',"order":', _tradeMsg(o, false), '}}'));
    }
}
