// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
// legacy/p5 — reference only, not built: cut from `test/helpers/Mocks.sol` when the v1 line left the build (P5).
pragma solidity ^0.8.20;

import {IFactoryTokenV1} from "../../src/factory/IFactoryTokenV1.sol";

/// Implementation ZETHER giả: chỉ để chứng minh factory xử lý kind ZETHER qua cùng
/// `IFactoryTokenV1`. Không có gì bảo mật ở đây.
contract MockZetherImpl is IFactoryTokenV1 {
    address public immutable FACTORY;
    address public verifier;
    bool private _done;
    constructor(address f) { FACTORY = f; _done = true; }
    function initialize(address, address, address verifier_, uint64, bytes calldata) external {
        require(msg.sender == FACTORY && !_done, "init");
        _done = true;
        verifier = verifier_;
    }
}
