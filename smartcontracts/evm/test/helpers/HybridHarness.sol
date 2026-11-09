// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {dexArgs} from "../../script/KindModules.sol";

/// PD5: exposes the DX7 sold-part check `_takerSoldCheck`, whose `PriceLimit` case the entry cannot reach (the token
/// already checked the larger full fill against the same floor at the pull).
contract HybridHarness is SCaaSDex {
    constructor(address f) SCaaSDex(f, dexArgs(f)) {} // T66b: its admin module D

    function takerSoldCheck(bytes32 h, uint256 sold, uint256 recv, ITradeToken.UATradeOrder memory o, uint256 leftover)
        external
        pure
    {
        Calc memory c;
        (c.h, c.sold, c.recv, c.o) = (h, sold, recv, o);
        _takerSoldCheck(c, leftover);
    }
}
