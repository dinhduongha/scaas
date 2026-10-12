// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    uint8 private immutable _d;
    constructor(string memory n, string memory s, uint8 d) ERC20(n, s) { _d = d; }
    function decimals() public view override returns (uint8) { return _d; }
    function mint(address to, uint256 v) external { _mint(to, v); }
}

/// Đốt 1% mỗi lần chuyển: wrapper phải mint theo số THỰC nhận, không theo số yêu cầu.
contract FeeOnTransferERC20 is MockERC20 {
    constructor() MockERC20("Fee", "FEE", 18) {}
    function _update(address from, address to, uint256 v) internal override {
        if (from != address(0) && to != address(0)) {
            uint256 burnt = v / 100;
            super._update(from, address(0), burnt);
            v -= burnt;
        }
        super._update(from, to, v);
    }
}

contract SupportedVerifier {
    function isSupportedOnThisChain() external pure returns (bool) { return true; }
    function curveName() external pure returns (string memory) { return "bn254"; }
}

contract UnsupportedVerifier {
    function isSupportedOnThisChain() external pure returns (bool) { return false; }
    function curveName() external pure returns (string memory) { return "bls12-381"; }
}
