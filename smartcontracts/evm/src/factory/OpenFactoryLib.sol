// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IOpenFactory} from "./IOpenFactory.sol";
import {IAdmin} from "../governance/IAdmin.sol";

/// @title `OpenFactoryLib`: `OpenFactory`'s router checks at `configureChain`, out of its runtime (the owner's split,
///        pre-approved 2026-11-24 and recorded 2026-11-25 in `decisions.md`'s CTR-GOV-33 Change, used when the code review's
///        G-3 took the factory over its size line; size lever 1,
///        `docs/research/evm-size-levers.md` §4).
/// @notice An external library: no storage, no `msg.sender`, no state change (`view`), so the call's context is the
///         factory's only for its errors, which pass back verbatim. The factory names itself (`self`) rather than the
///         library reading `address(this)`. Its errors are the factory's (`IOpenFactory`, `IAdmin`). **UNAUDITED.**
library OpenFactoryLib {
    bytes4 private constant _CHAIN_UID = bytes4(keccak256("chainUid()"));
    bytes4 private constant _REGISTRY = bytes4(keccak256("registry()"));
    bytes4 private constant _CLONE_HASH = bytes4(keccak256("smartKeyCloneHash()"));
    bytes4 private constant _FACTORY = bytes4(keccak256("factory()"));

    /// @notice The router's code is the admin's hash `codeHash` (not 0, not `keccak256("")`), its `chainUid()` this
    ///         chain's, its `registry()` an account with code (0 included in "no code"), its `smartKeyCloneHash()` its
    ///         registry's, its `factory()` the factory `self` (CTR-GOV-33, G-3: else G1 is off); a call that answers no
    ///         word fails closed.
    function checkRouter(address r, bytes32 codeHash, bytes32 chainUid_, address self) external view {
        if (codeHash == bytes32(0) || codeHash == keccak256("") || r.codehash != codeHash) {
            revert IOpenFactory.CodeHashMismatch(r, codeHash, r.codehash);
        }
        (bool okU, uint256 u) = _word(r, _CHAIN_UID);
        if (!okU || bytes32(u) != chainUid_) revert IAdmin.ChainUidMismatch(chainUid_, okU ? bytes32(u) : bytes32(0));
        (bool ok, uint256 w) = _word(r, _REGISTRY);
        address reg = address(uint160(w));
        if (!ok || w >> 160 != 0 || reg.code.length == 0) revert IOpenFactory.RouterRegistryInvalid(reg);
        (bool okR, uint256 a) = _word(r, _CLONE_HASH);
        (bool okG, uint256 b) = _word(reg, _CLONE_HASH);
        if (!okR || !okG || a != b) revert IOpenFactory.SmartKeyCloneHashMismatch(bytes32(a), bytes32(b));
        (bool okF, uint256 fw) = _word(r, _FACTORY);
        if (!okF || fw != uint256(uint160(self))) revert IOpenFactory.RouterFactoryMismatch(address(uint160(fw)));
    }

    /// @dev `target.sel()` as one word (`OpenFactory._word`'s copy): a revert or a return of another length is no answer.
    function _word(address target, bytes4 sel) private view returns (bool ok, uint256 w) {
        bytes memory ret;
        (ok, ret) = target.staticcall(abi.encodeWithSelector(sel));
        ok = ok && ret.length == 32;
        if (ok) w = abi.decode(ret, (uint256));
    }
}
