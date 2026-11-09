// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {IERC20MetaTx} from "./IERC20MetaTx.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";

/// @title The unprivileged caller of `RelayFeeRouter`'s targets (CTR-MTX-27, spec §7.1).
/// @notice Created by the router's constructor (CREATE). Holds nothing, is trusted by nothing, and runs a call only for
///         its router: a target sees this address, never the router, so a `callData` that is a token's
///         `mtxExecuteTransfer` of another router-bound payment fails that payment's relayer binding.
contract RelayFeeExecutor {
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

/// @title `RelayFeeRouter`: a token fee to the relayer for a fee-less call (CTR-MTX-27, spec §7.1).
/// @notice Stateless, no owner, no constructor argument; deployed by CREATE2 (`DeployBase`), so it and its executor
///         have the same addresses on every EVM chain. It grants no authority (CTR-MTX-16): every target checks its own
///         signer, the router calls targets only through its executor, and it only binds a payment the payer signed for
///         the router (`UARelayFee.relayer = router`) to one exact call that anyone could submit directly. Public balances
///         only: it calls the tokens' relay-fee paths, never a confidential one. It does not check `token`: the payer
///         signed in the token's own domain, so a fake token moves nothing real (a bound payee reads the expected
///         token's `UAPaymentSettled`). ua-mtx-merge T2 (R28): one `relay` on ids, today's `uaRelay` under this name;
///         the address `relay` and `RelayFee` are in legacy/ua-mtx-merge/, so this contract has a new CREATE2 address.
contract RelayFeeRouter is ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    /// @notice `payer` and `payee` are ids: an address zero-padded, or a derived UA id. `payee` is the one paid:
    ///         `pad(msg.sender)` in open mode, else the signed `payee`.
    event RelayFeePaid(bytes32 indexed ref, address indexed target, address indexed token, bytes32 payer, bytes32 payee,
                       uint256 amount);

    error RelayFeeShape();
    /// @notice The target has no code at relay time (a counterfactual address not yet deployed, an EOA, a precompile)
    ///         or is an EIP-7702 designator (an EOA: its delegate's code must not run, and a designator to a code-less
    ///         address would succeed empty): the payer would pay for nothing (CTR-MTX-13; owner ruling 2026-10-30, D4).
    error RelayTargetNoCode(address target);

    address public immutable EXECUTOR;

    constructor() {
        EXECUTOR = address(new RelayFeeExecutor());
    }

    /// @notice CTR-MTX-27 steps 1-6: the shape, `target` called by the executor, then `token.mtxRelayFee(…, auth)`
    ///         with this router as the struct's `relayer`, then in open mode (`payee == pad(router)`) `value` forwarded
    ///         to `msg.sender`. Any failure reverts it all. `from` and `payee` are ids: a native payer signs `UARelayFee`
    ///         with its own key, a derived one through the token's registry. `batch` / `nonce` are the payer's lane (pay-meta-
    ///         tax spec §4, O4): one signature pays once; a call is paid twice only by two signatures and a target that
    ///         runs it twice.
    function relay(address target, bytes calldata callData, address token, bytes32 from, bytes32 payee, uint256 value,
                   uint256 batch, uint256 nonce, uint256 validUntil, IUARegistry.UASig calldata auth) external nonReentrant
    {
        _shape(target, payee);
        RelayFeeExecutor(EXECUTOR).exec(target, callData);
        IERC20MetaTx(token).mtxRelayFee(from, target, keccak256(callData), payee, value, batch, nonce, validUntil, auth);
        emit RelayFeePaid(relayRef(target, callData), target, token, from, _payee(token, payee, value), value);
    }

    /// @notice The payment reference of one call: the chain, the target and the exact call bytes.
    function relayRef(address target, bytes calldata callData) public view returns (bytes32) {
        return keccak256(abi.encodePacked("scaas.relayfee", block.chainid, target, keccak256(callData)));
    }

    /// @dev CTR-MTX-27 step 2: the payee not the executor (`to` as an id; the token's `mtxRelayFee` does not know it), the
    ///      rest of the old shape being the signed `UARelayFee` itself (the token builds `ref` and the payment on the
    ///      signed lane, fee `NONE`, and takes this router as `relayer`); and the target is a contract: code, not an EIP-7702 designator
    ///      (conformance item 9).
    function _shape(address target, bytes32 to) private view {
        if (to == MetaTxLib.pad(EXECUTOR)) revert RelayFeeShape();
        if (!SigCheck.isContract(target)) revert RelayTargetNoCode(target);
    }

    /// @dev Step 5. Open mode (`to == pad(router)`): the payment just landed here and goes on to whoever submitted the
    ///      relay; else the payee `to` was paid directly.
    function _payee(address token, bytes32 to, uint256 value) private returns (bytes32) {
        if (to != MetaTxLib.pad(address(this))) return to;
        IERC20(token).safeTransfer(msg.sender, value);
        return MetaTxLib.pad(msg.sender);
    }
}
