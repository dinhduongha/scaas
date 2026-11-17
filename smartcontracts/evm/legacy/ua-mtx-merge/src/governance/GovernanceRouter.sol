// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {GovernanceRouterBase, GovernanceRouterTypes as T} from "./GovernanceRouterBase.sol";
import {IWrappedToken} from "../metatx/IWrappedToken.sol";
import {ISCaaSDex} from "../dex/ISCaaSDex.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";

/// @title One per chain, CREATE2 at a predictable address (CTR-GOV-15 Change, owner 2026-11-04; spec
///        `2026-11-04-governance-ua-identity.md` §3): the closed table of governance spec §3.2 over every governed contract
///        of SCaaS whose `GOV_ROUTER` it is. The owner's and a holder's ops come from `GovernanceRouterBase`; here the powers
///        of the token kinds (`mint`, `mintToUA`, `disableWrap`, the rate entries) and of `SCaaSDex` (the market setters,
///        `setFeeSplit`). Domain `("SCaaS GovernanceRouter", "1", chainId, router, chain_uid)`. **UNAUDITED.**
contract GovernanceRouter is GovernanceRouterBase {
    constructor(bytes32 chainUid_, address registry_, address smartKeyAccountImpl_, bool hedera_)
        GovernanceRouterBase("SCaaS GovernanceRouter", chainUid_, registry_, smartKeyAccountImpl_, hedera_)
    {}

    // ------------------------------------------------------------------ the powers on the token kinds

    function mtxMint(MetaTxLib.Envelope calldata e, address target, address to, uint256 amount, bytes calldata sig)
        external
    {
        _mtx(T.MINT, e, target, IWrappedToken.mint.selector, abi.encode(to, amount), sig);
    }

    function uaMint(MetaTxLib.UAEnvelope calldata e, address target, address to, uint256 amount,
        IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_MINT, e, target, IWrappedToken.mint.selector, abi.encode(to, amount), auth);
    }

    function mtxMintToUA(MetaTxLib.Envelope calldata e, address target, bytes32 to, uint256 amount, bytes calldata sig)
        external
    {
        _mtx(T.MINT_TO_UA, e, target, IWrappedToken.mintToUA.selector, abi.encode(to, amount), sig);
    }

    function uaMintToUA(MetaTxLib.UAEnvelope calldata e, address target, bytes32 to, uint256 amount,
        IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_MINT_TO_UA, e, target, IWrappedToken.mintToUA.selector, abi.encode(to, amount), auth);
    }

    function mtxDisableWrap(MetaTxLib.Envelope calldata e, address target, address leg, bytes32 reason, bytes calldata sig)
        external
    {
        _mtx(T.DISABLE_WRAP, e, target, IWrappedToken.disableWrap.selector, abi.encode(leg, reason), sig);
    }

    function uaDisableWrap(MetaTxLib.UAEnvelope calldata e, address target, address leg, bytes32 reason,
        IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_DISABLE_WRAP, e, target, IWrappedToken.disableWrap.selector, abi.encode(leg, reason), auth);
    }

    function mtxProposeRate(MetaTxLib.Envelope calldata e, address target, address leg, uint96 num, uint96 den,
        bytes calldata sig) external
    {
        _mtx(T.PROPOSE_RATE, e, target, IWrappedToken.proposeRate.selector, abi.encode(leg, num, den), sig);
    }

    function uaProposeRate(MetaTxLib.UAEnvelope calldata e, address target, address leg, uint96 num, uint96 den,
        IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_PROPOSE_RATE, e, target, IWrappedToken.proposeRate.selector, abi.encode(leg, num, den), auth);
    }

    function mtxCancelRate(MetaTxLib.Envelope calldata e, address target, bytes calldata sig) external {
        _mtx(T.CANCEL_RATE, e, target, IWrappedToken.cancelRate.selector, "", sig);
    }

    function uaCancelRate(MetaTxLib.UAEnvelope calldata e, address target, IUARegistry.UASig calldata auth) external {
        _ua(T.UA_CANCEL_RATE, e, target, IWrappedToken.cancelRate.selector, "", auth);
    }

    function mtxExecuteRate(MetaTxLib.Envelope calldata e, address target, bytes calldata sig) external {
        _mtx(T.EXECUTE_RATE, e, target, IWrappedToken.executeRate.selector, "", sig);
    }

    function uaExecuteRate(MetaTxLib.UAEnvelope calldata e, address target, IUARegistry.UASig calldata auth) external {
        _ua(T.UA_EXECUTE_RATE, e, target, IWrappedToken.executeRate.selector, "", auth);
    }

    // ------------------------------------------------------------------ the powers on the DEX

    function mtxSetMarket(MetaTxLib.Envelope calldata e, address target, address base, address quote, bool listed,
        bytes calldata sig) external
    {
        _mtx(T.SET_MARKET, e, target, ISCaaSDex.setMarket.selector, abi.encode(base, quote, listed), sig);
    }

    function uaSetMarket(MetaTxLib.UAEnvelope calldata e, address target, address base, address quote, bool listed,
        IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_SET_MARKET, e, target, ISCaaSDex.setMarket.selector, abi.encode(base, quote, listed), auth);
    }

    function mtxSetExchangeTarget(MetaTxLib.Envelope calldata e, address target, address exchangeTarget, bool listed,
        bytes calldata sig) external
    {
        _mtx(T.SET_EXCHANGE_TARGET, e, target, ISCaaSDex.setExchangeTarget.selector, abi.encode(exchangeTarget, listed),
            sig);
    }

    function uaSetExchangeTarget(MetaTxLib.UAEnvelope calldata e, address target, address exchangeTarget, bool listed,
        IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_SET_EXCHANGE_TARGET, e, target, ISCaaSDex.setExchangeTarget.selector, abi.encode(exchangeTarget, listed),
            auth);
    }

    function mtxSetListedOnly(MetaTxLib.Envelope calldata e, address target, bool on, bytes calldata sig) external {
        _mtx(T.SET_LISTED_ONLY, e, target, ISCaaSDex.setListedOnly.selector, abi.encode(on), sig);
    }

    function uaSetListedOnly(MetaTxLib.UAEnvelope calldata e, address target, bool on, IUARegistry.UASig calldata auth)
        external
    {
        _ua(T.UA_SET_LISTED_ONLY, e, target, ISCaaSDex.setListedOnly.selector, abi.encode(on), auth);
    }

    function mtxSetFeeSplit(MetaTxLib.Envelope calldata e, address target, uint32 relayerSharePpm, address treasury,
        bytes calldata sig) external
    {
        _mtx(T.SET_FEE_SPLIT, e, target, ISCaaSDex.setFeeSplit.selector, abi.encode(relayerSharePpm, treasury), sig);
    }

    function uaSetFeeSplit(MetaTxLib.UAEnvelope calldata e, address target, uint32 relayerSharePpm, address treasury,
        IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_SET_FEE_SPLIT, e, target, ISCaaSDex.setFeeSplit.selector, abi.encode(relayerSharePpm, treasury), auth);
    }
}
