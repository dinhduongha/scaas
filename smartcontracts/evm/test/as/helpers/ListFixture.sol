// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {RegFixture} from "./RegFixture.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../../src/factory/IOpenFactory.sol";
import {GovernanceBits} from "../../../src/governance/GovernanceBits.sol";
import {nid} from "../../helpers/Ids.sol";
import {EnvKit} from "../../helpers/EnvKit.sol";

/// Round 3s's ops (spec 2026-11-10-token-lists.md §6.1, §7) by selector, so the suites compile before the build (red first).
interface IListOps {
    function setAllowed(bytes32[] calldata accounts, bool on) external;
    function setDenied(bytes32[] calldata accounts, bool on) external;
    function listFlagsOf(bytes32 account) external view returns (uint8);
    function enableFeature(uint8 bit, bytes32 chainUid_) external;
}

/// Round 3s (spec §4, §5, §6; CTR-GOV-24): tokens of kind 8 (`i == 0`) and 9 (`i == 1`) as `RegFixture`'s, with the list bits
/// and `KYC` of `on` set at creation, `locked` locked, no registry unless asked. `issuer` holds every list bit that is valid
/// and not locked off (the issuer seat, §6.3). Kind 8 mints `SUPPLY` to `alice` (listed by init under `ALLOWLIST`, P1-2);
/// kind 9: `alice` is listed by the issuer first, then wraps `SUPPLY`.
abstract contract ListFixture is RegFixture {
    uint8 internal constant ALLOW = GovernanceBits.ALLOWLIST;
    uint8 internal constant DENY = GovernanceBits.DENYLIST;
    uint8 internal constant KYC_BIT = 28;
    uint8 internal constant ALLOWED = 1;
    uint8 internal constant DENIED = 2;
    bytes4 internal constant NOT_ALLOWED = bytes4(keccak256("NotAllowed(bytes32)"));
    bytes4 internal constant DENIED_ERR = bytes4(keccak256("Denied(bytes32)"));
    bytes4 internal constant BATCH_INVALID = bytes4(keccak256("ListBatchInvalid(uint256)"));
    bytes4 internal constant ACCOUNT_ZERO = bytes4(keccak256("ListAccountZero()"));
    bytes4 internal constant REGISTRY_NOT_SET = bytes4(keccak256("ComplianceRegistryNotSet()"));
    bytes4 internal constant HOLDER_MISSING = bytes4(keccak256("ListHolderMissing(uint8)"));
    bytes4 internal constant NOT_ENABLEABLE = bytes4(keccak256("FeatureNotEnableable(uint8)"));
    bytes4 internal constant NOT_DISABLEABLE = bytes4(keccak256("FeatureNotDisableable(uint8)"));
    bytes4 internal constant ALREADY_SET = bytes4(keccak256("FeatureAlreadySet(uint8)"));
    bytes32 internal constant ALLOWED_SET = keccak256("AllowedSet(bytes32,bytes32,bool)");
    bytes32 internal constant DENIED_SET = keccak256("DeniedSet(bytes32,bytes32,bool)");
    bytes32 internal constant FEATURE_ENABLED = keccak256("FeatureEnabled(uint8,bytes32)");

    function _cfg(uint256 i, uint256 on, uint256 locked) internal view returns (IFactoryToken.TokenConfig memory c) {
        c = i == 0 ? _cfg8() : _cfg9();
        c.features |= on;
        c.lockedFeatures = locked;
    }

    function _create(uint256 i, IFactoryToken.TokenConfig memory c, bytes32 salt) internal returns (address t) {
        t = f.createToken(i == 0 ? IOpenFactory.TokenKind.NORMAL_REGULATED : IOpenFactory.TokenKind.WRAPPED_REGULATED, 1,
            abi.encode(c), salt);
    }

    /// A token of kind 8 or 9 with `on` (a mask of 8, 9, 28) at creation and `locked`; `alice` holds `SUPPLY`.
    function _lt(uint256 i, uint256 on, uint256 locked, bytes32 salt) internal returns (address t) {
        IFactoryToken.TokenConfig memory c = _cfg(i, on, locked);
        if (on & (1 << KYC_BIT) != 0) (c.reg.complianceRegistry, c.reg.deniedFlags) = (address(creg), SANCTIONED);
        t = _create(i, c, salt);
        if (i == 1) {
            if (on & (1 << ALLOW) != 0) _setList(t, ALLOW, nid(alice), true);
            _wrapFor(t, alice, SUPPLY);
        }
    }

    function _one(bytes32 a) internal pure returns (bytes32[] memory as_) {
        as_ = new bytes32[](1);
        as_[0] = a;
    }

    /// `issuer` writes `a`'s flag of `bit` (8 the allow list, 9 the deny list).
    function _setList(address t, uint8 bit, bytes32 a, bool on) internal {
        vm.prank(issuer);
        if (bit == ALLOW) IListOps(t).setAllowed(_one(a), on);
        else IListOps(t).setDenied(_one(a), on);
    }

    /// Under the list `bit`, `a` cannot move (`ALLOW`: unlisted; `DENY`: denied) / can move again.
    function _block(address t, uint8 bit, bytes32 a) internal {
        _setList(t, bit, a, bit == DENY);
    }

    function _open(address t, uint8 bit, bytes32 a) internal {
        _setList(t, bit, a, bit == ALLOW);
    }

    /// The refusal `L(a)` raises under `bit`.
    function _err(uint8 bit, bytes32 a) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(bit == ALLOW ? NOT_ALLOWED : DENIED_ERR, a);
    }

    function _enable(address t, uint8 bit) internal {
        vm.prank(ownerA);
        IListOps(t).enableFeature(bit, EnvKit.codeUidOf(address(IListOps(t))));
    }

    function _flags(address t, bytes32 a) internal view returns (uint8) {
        return IListOps(t).listFlagsOf(a);
    }
}
