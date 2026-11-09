// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../../src/ua/IUARegistry.sol";
import {IERC20MetaTx} from "../../../src/metatx/IERC20MetaTx.sol";
import {IUALedger} from "../../../src/metatx/IUALedger.sol";
import {IRegulatedToken} from "../../../src/regulated/IRegulatedToken.sol";

/// @title The reference service of a service pull (spec 2026-11-09-service-pull §3, §11; proposed CTR-MTX-32).
/// @notice **TEST ONLY, never deployed, not a product contract. UNAUDITED.** An escrow on one fixed SCaaS token: the payer
///         signs one `UAMetaTransfer` in the token's domain (`to` = `relayer` = this contract, `MODE_RESTRICT_RELAYER`, fee
///         `NONE`, `entryRef` = the EIP-712 digest of the operation in this contract's domain); anyone submits the
///         operation; this contract checks it (§3.3 steps 1-6), records it, pulls by `mtxExecuteTransfer` (it is the bound
///         relayer), checks the balance delta and credits the custody. `release` pays a custody back to its payer,
///         permissionless after `releaseAfter`. A payout the token refuses reverts and stays owed (§3.4, Q5). Two
///         operations: `deposit` (atomic fields) and `note` (a `string` and a `bytes`, C3's dynamic fields). The mutant
///         harness (`runs/2026-11-09-ua-mtx-merge-3i/mutants.py`) edits this file one check at a time: keep each check on
///         its own line.
contract RefServiceEscrow is EIP712, ReentrancyGuardTransient {
    struct Deposit {
        bytes32 payer;
        uint256 amount;
        uint64 releaseAfter;
        bytes32 salt;
    }

    struct Note {
        bytes32 payer;
        uint256 amount;
        string memo;
        bytes commitment;
        bytes32 salt;
    }

    struct Custody {
        bytes32 payer;
        uint256 amount;
        uint64 releaseAfter;
    }

    string internal constant DEPOSIT_TYPE = "Deposit(bytes32 payer,uint256 amount,uint64 releaseAfter,bytes32 salt)";
    string internal constant NOTE_TYPE = "Note(bytes32 payer,uint256 amount,string memo,bytes commitment,bytes32 salt)";
    bytes32 internal constant DEPOSIT_TYPEHASH = keccak256(bytes(DEPOSIT_TYPE));
    bytes32 internal constant NOTE_TYPEHASH = keccak256(bytes(NOTE_TYPE));

    /// @notice The one token every entry pulls (§3.3: immutable, never named by the caller).
    address public immutable TOKEN;
    /// @notice `TOKEN` answers `supportsInterface(type(IRegulatedToken).interfaceId)` (step 6's freeze check).
    bool public immutable REGULATED;

    /// @notice Every operation digest that landed (Q4: a seen `entryRef` is refused).
    mapping(bytes32 entryRef => bool) public used;
    mapping(bytes32 entryRef => Custody) public custody;
    /// @notice Σ custody (the invariant `TOKEN.balanceOf(this) >= owed`, except after a forced move).
    uint256 public owed;

    error ServicePullShape(uint8 code);
    error ServicePullNotReceived(uint256 expected, uint256 got);
    error ServicePullReplayed(bytes32 entryRef);
    error ServicePullFrozen();
    error NotReleasable(bytes32 entryRef);

    event Deposited(bytes32 indexed entryRef, bytes32 indexed payer, uint256 amount, uint64 releaseAfter, bytes32 salt);
    event Noted(bytes32 indexed entryRef, bytes32 indexed payer, uint256 amount, string memo, bytes commitment, bytes32 salt);
    event Released(bytes32 indexed entryRef, bytes32 indexed payer, uint256 amount);

    constructor(address token) EIP712("SCaaS RefServiceEscrow", "1") {
        TOKEN = token;
        (bool ok, bytes memory r) =
            token.staticcall(abi.encodeCall(IERC165.supportsInterface, (type(IRegulatedToken).interfaceId)));
        REGULATED = ok && r.length == 32 && abi.decode(r, (bool));
    }

    // ------------------------------------------------------------------ the entries (§3.1)

    function deposit(Deposit calldata op, MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata auth)
        external nonReentrant
    {
        bytes32 ref = depositRef(op);
        _enter(ref, op.payer, op.amount, t, auth);
        custody[ref] = Custody(t.from, t.value, op.releaseAfter);
        owed += t.value;
        _afterPull(ref);
        emit Deposited(ref, t.from, t.value, op.releaseAfter, op.salt);
    }

    function note(Note calldata op, MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata auth)
        external nonReentrant
    {
        bytes32 ref = noteRef(op);
        _enter(ref, op.payer, op.amount, t, auth);
        custody[ref] = Custody(t.from, t.value, 0);
        owed += t.value;
        _afterPull(ref);
        emit Noted(ref, t.from, t.value, op.memo, op.commitment, op.salt);
    }

    /// @notice Pays a custody back to its recorded payer (`transfer` for a native id, `transferToUA` for a derived one),
    ///         permissionless after `releaseAfter`. A refusal by the token reverts: the custody stays owed (§3.4).
    function release(bytes32 ref) external nonReentrant {
        Custody memory c = custody[ref];
        if (c.amount == 0 || block.timestamp < c.releaseAfter) revert NotReleasable(ref);
        delete custody[ref];
        owed -= c.amount;
        if (uint256(c.payer) >> 160 == 0) IERC20(TOKEN).transfer(address(uint160(uint256(c.payer))), c.amount);
        else IUALedger(TOKEN).transferToUA(c.payer, c.amount);
        emit Released(ref, c.payer, c.amount);
    }

    // ------------------------------------------------------------------ discovery (§3.1)

    /// @notice Each entry's selector, its `<Op>`'s EIP-712 `encodeType`, and the token it pulls.
    function servicePullEntries()
        external view returns (bytes4[] memory selectors, string[] memory opTypes, address[] memory tokens)
    {
        selectors = new bytes4[](2);
        opTypes = new string[](2);
        tokens = new address[](2);
        (selectors[0], opTypes[0], tokens[0]) = (this.deposit.selector, DEPOSIT_TYPE, TOKEN);
        (selectors[1], opTypes[1], tokens[1]) = (this.note.selector, NOTE_TYPE, TOKEN);
    }

    /// @notice The operation digest (§3.2): `keccak256(0x1901 ‖ domainSeparator ‖ hashStruct(op))` in this domain.
    function depositRef(Deposit calldata op) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(DEPOSIT_TYPEHASH, op.payer, op.amount, op.releaseAfter, op.salt)));
    }

    function noteRef(Note calldata op) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(NOTE_TYPEHASH, op.payer, op.amount, keccak256(bytes(op.memo)),
            keccak256(op.commitment), op.salt)));
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    // ------------------------------------------------------------------ §3.3

    /// @dev Step 9, the rest of the operation's logic: none here; N12's subclass reverts in it.
    function _afterPull(bytes32) internal virtual {}

    /// @dev Steps 1-8 of §3.3 in order; the caller credits the custody after it (step 9, §3.4).
    function _enter(bytes32 ref, bytes32 payer, uint256 amount, MetaTxLib.UAMetaTransfer calldata t,
        IUARegistry.UASig calldata auth) private
    {
        _checks(ref, payer, amount, t); // steps 1-6
        used[ref] = true; // step 7
        _pull(t, auth); // step 8
    }

    function _checks(bytes32 ref, bytes32 payer, uint256 amount, MetaTxLib.UAMetaTransfer calldata t) private view {
        if (t.to != MetaTxLib.pad(address(this))) revert ServicePullShape(1);
        if (t.mode != MetaTxLib.MODE_RESTRICT_RELAYER || t.relayer != address(this)) revert ServicePullShape(2);
        if (t.fee != 0 || t.feeRecipient != address(0)) revert ServicePullShape(2);
        if (t.entryRef != ref) revert ServicePullShape(3);
        if (t.from != payer) revert ServicePullShape(4);
        if (t.value != amount || amount == 0) revert ServicePullShape(5);
        if (used[ref]) revert ServicePullReplayed(ref);
        if (REGULATED && IRegulatedToken(TOKEN).isFrozen(MetaTxLib.pad(address(this)))) revert ServicePullFrozen();
    }

    /// @dev Step 8: the pull, no `try` / `catch` (§3.5), then the balance delta (C5).
    function _pull(MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata auth) private {
        uint256 b0 = IERC20(TOKEN).balanceOf(address(this));
        IERC20MetaTx(TOKEN).mtxExecuteTransfer(t, auth);
        uint256 b1 = IERC20(TOKEN).balanceOf(address(this));
        if (b1 < b0 || b1 - b0 != t.value) revert ServicePullNotReceived(t.value, b1 < b0 ? 0 : b1 - b0);
    }
}

/// @notice N12: the reference service whose logic after the pull reverts.
contract RefServiceEscrowFailAfter is RefServiceEscrow {
    error LogicFailed(bytes32 entryRef);

    constructor(address token) RefServiceEscrow(token) {}

    function _afterPull(bytes32 ref) internal pure override {
        revert LogicFailed(ref);
    }
}

/// @notice N11: a token stand-in whose `mtxExecuteTransfer` answers `true` and moves nothing.
contract NoopPullToken {
    mapping(address => uint256) public balanceOf;

    function mtxExecuteTransfer(MetaTxLib.UAMetaTransfer calldata, IUARegistry.UASig calldata) external pure returns (bool) {
        return true;
    }
}

/// @notice N20: a token stand-in that moves `t.value` in its own ledger and, armed, first re-enters the service with the
///         armed calldata (once). The real token never calls back (§2.2), so only this makes §3.5's guard falsifiable.
contract ReenterPullToken {
    mapping(address => uint256) public balanceOf;
    address internal target;
    bytes internal data;

    function arm(address t, bytes calldata d) external {
        (target, data) = (t, d);
    }

    function mtxExecuteTransfer(MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata) external returns (bool) {
        if (target != address(0)) {
            address s = target;
            target = address(0);
            (bool ok, bytes memory ret) = s.call(data);
            if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        }
        balanceOf[address(uint160(uint256(t.to)))] += t.value;
        return true;
    }
}

/// @notice N9 (b): a contract that hands `t` to the token with no check of its own (a service whose checks are removed).
contract NakedPuller {
    function pull(address token, MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata auth) external {
        IERC20MetaTx(token).mtxExecuteTransfer(t, auth);
    }
}
