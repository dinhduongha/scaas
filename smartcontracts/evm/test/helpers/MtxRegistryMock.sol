// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {MetaTxBase} from "../../src/metatx/MetaTxBase.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";

/// A registry-like contract on `MetaTxBase` (the "family-tree registry" of CTR-MTX-22): fee `NONE` only.
/// Allowlist: `cancelNonce(uint256)` (base), `setName(string)` (dynamic, ABSOLUTE), `bump(uint256)` (static 36,
/// AMOUNT(0)), `poke(address,bytes)` (dynamic, ABSOLUTE): a test-only probe that calls out from inside the
/// self-call. A real allowlist never forwards calldata (CTR-MTX-16).
contract MtxRegistryMock is MetaTxBase {
    error ZeroBump();

    mapping(address => string) public nameOf;
    mapping(address => uint256) public count;

    constructor(string memory domainName, bytes32 chainUid_) MetaTxBase(domainName, chainUid_) {}

    function setName(string calldata name) external nonReentrant {
        nameOf[_msgSender()] = name;
    }

    function bump(uint256 by) external nonReentrant returns (uint256) {
        if (by == 0) revert ZeroBump();
        return count[_msgSender()] += by;
    }

    function poke(address target, bytes calldata data) external nonReentrant {
        (bool ok, bytes memory ret) = target.call(data);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 0x20), mload(ret)) }
    }

    /// Not allowlisted, not guarded: shows what `_msgSender()` answers outside a self-call.
    function whoAmI() external view returns (address) {
        return _msgSender();
    }

    function exposedRule(bytes4 sel) external view returns (MtxRule memory) {
        return _mtxRule(sel);
    }

    function _mtxRule(bytes4 sel) internal view virtual override returns (MtxRule memory) {
        if (sel == this.setName.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);
        if (sel == this.bump.selector) return MtxRule(FEE_CLASS_AMOUNT, 0, 36);
        if (sel == this.poke.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);
        return super._mtxRule(sel);
    }

    function mtxSelectors()
        public view virtual override returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](4);
        c = new uint8[](4);
        a = new uint8[](4);
        (s[0], c[0]) = (IMetaTx.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
        (s[1], c[1]) = (this.setName.selector, FEE_CLASS_ABSOLUTE);
        (s[2], c[2]) = (this.bump.selector, FEE_CLASS_AMOUNT);
        (s[3], c[3]) = (this.poke.selector, FEE_CLASS_ABSOLUTE);
    }
}

/// Re-enters the registry from outside while a self-call is live.
contract ReenterHook {
    function hit(MtxRegistryMock r) external {
        r.setName("evil");
    }
}
