// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {IERC20MetaTx} from "./IERC20MetaTx.sol";
import {IUALedger} from "./IUALedger.sol";

/// @title The unprivileged caller of `MtxRelayFee`'s targets (CTR-MTX-27, spec §7.1).
/// @notice Created by the router's constructor (CREATE). Holds nothing, is trusted by nothing, and runs a call only for
///         its router: a target sees this address, never the router, so a `callData` that is a token's
///         `mtxExecuteTransfer` of another router-bound payment fails that payment's relayer binding.
contract MtxRelayExecutor {
    error NotRouter();

    address public immutable ROUTER;

    constructor() {
        ROUTER = msg.sender;
    }

    /// @notice `target.call(callData)` with no value; a failure reverts with the inner revert data.
    function exec(address target, bytes calldata callData) external {
        if (msg.sender != ROUTER) revert NotRouter();
        (bool ok, bytes memory ret) = target.call(callData);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 0x20), mload(ret)) }
    }
}

/// @title `MtxRelayFee`: a token fee to the relayer for a fee-less call (CTR-MTX-27, spec §7.1).
/// @notice Stateless, no owner, no constructor argument; deployed by CREATE2 (`DeployBase`), so it and its executor
///         have the same addresses on every EVM chain. It grants no authority (CTR-MTX-16): every target checks its own
///         signer, the router calls targets only through its executor, and it only binds a payment the payer signed for
///         the router (`relayer = router`) to one exact call that anyone could submit directly. Public balances only:
///         it calls the tokens' typed transfer paths, never a confidential one. It does not check `token`: the payer
///         signed in the token's own domain, so a fake token moves nothing real (a bound payee reads the expected
///         token's `PaymentSettled`).
contract MtxRelayFee is ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    /// @notice `payer` and `payee` are ids: an address zero-padded, or a derived UA id (`uaRelay`). `payee` is the one
    ///         paid: `pad(msg.sender)` in open mode, else `t.to` (padded on `relay`).
    event RelayFeePaid(bytes32 indexed ref, address indexed target, address indexed token, bytes32 payer, bytes32 payee,
                       uint256 amount);

    error RelayFeeShape();
    /// @notice The target has no code at relay time (a counterfactual address not yet deployed, an EOA, a precompile):
    ///         a call to it would succeed and the payer would pay for nothing (CTR-MTX-13).
    error RelayTargetNoCode(address target);

    address public immutable EXECUTOR;

    constructor() {
        EXECUTOR = address(new MtxRelayExecutor());
    }

    /// @notice CTR-MTX-27 steps 1-6: the shape, `target` called by the executor, then `token.mtxExecuteTransfer(t, sig)`,
    ///         then in open mode (`t.to == router`) `t.value` forwarded to `msg.sender`. Any failure reverts it all.
    function relay(address target, bytes calldata callData, address token, MetaTxLib.MetaTransfer calldata t,
                   bytes calldata sig) external nonReentrant
    {
        bytes32 ref = relayRef(target, callData);
        bytes32 to = MetaTxLib.pad(t.to);
        _shape(ref, target, t.entryRef, to, t.batch, t.nonce, t.mode, t.relayer, t.fee);
        MtxRelayExecutor(EXECUTOR).exec(target, callData);
        IERC20MetaTx(token).mtxExecuteTransfer(t, sig);
        emit RelayFeePaid(ref, target, token, MetaTxLib.pad(t.from), _payee(token, to, t.value), t.value);
    }

    /// @notice `relay` for a UA payer (`uaExecuteTransfer`); open mode is `t.to == pad(router)`.
    function uaRelay(address target, bytes calldata callData, address token, MetaTxLib.UAMetaTransfer calldata t,
                     bytes calldata auth) external nonReentrant
    {
        bytes32 ref = relayRef(target, callData);
        _shape(ref, target, t.entryRef, t.to, t.batch, t.nonce, t.mode, t.relayer, t.fee);
        MtxRelayExecutor(EXECUTOR).exec(target, callData);
        IUALedger(token).uaExecuteTransfer(t, auth);
        emit RelayFeePaid(ref, target, token, t.from, _payee(token, t.to, t.value), t.value);
    }

    /// @notice The payment reference of one call: the chain, the target and the exact call bytes.
    function relayRef(address target, bytes calldata callData) public view returns (bytes32) {
        return keccak256(abi.encodePacked("scaas.relayfee", block.chainid, target, keccak256(callData)));
    }

    /// @dev CTR-MTX-27 step 2: `entryRef == ref`, lane `payLane(ref)` (CTR-MTX-10, `MetaTokenBase.payLane`), nonce 0,
    ///      relayer bound to this router, fee mode `NONE` and fee 0 (the payment's `value` is the fee), the payee not the
    ///      executor (`to` as an id); and the target has code (conformance item 9).
    function _shape(bytes32 ref, address target, bytes32 entryRef, bytes32 to, uint256 batch, uint256 nonce, uint32 mode,
                    address relayer, uint256 fee) private view
    {
        if (entryRef != ref || batch != uint256(keccak256(abi.encodePacked("scaas.pay.lane", ref))) || nonce != 0
            || mode & MetaTxLib.MODE_RESTRICT_RELAYER == 0 || relayer != address(this)
            || mode & MetaTxLib.MODE_FEE_MASK != MetaTxLib.MODE_FEE_NONE || fee != 0
            || to == MetaTxLib.pad(EXECUTOR)) revert RelayFeeShape();
        if (target.code.length == 0) revert RelayTargetNoCode(target);
    }

    /// @dev Step 5. Open mode (`to == pad(router)`): the payment just landed here and goes on to whoever submitted the
    ///      relay; else the payee `to` was paid directly.
    function _payee(address token, bytes32 to, uint256 value) private returns (bytes32) {
        if (to != MetaTxLib.pad(address(this))) return to;
        IERC20(token).safeTransfer(msg.sender, value);
        return MetaTxLib.pad(msg.sender);
    }
}
