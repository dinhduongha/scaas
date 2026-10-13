// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";

/// The address-shaped DEX legs the P2b suites were written in (before CTR-DEX-26 tagged them), and `wire`, which turns
/// them into shape-0 tagged legs (`order = abi.encode(TradeOrder)`) at the call. The UA suites build tagged legs
/// directly.
library DexLegs {
    struct Leg {
        address sellToken;
        ITradeToken.TradeOrder o;
        bytes sig;
        uint256 fill;
    }

    struct Settlement {
        bytes32 ref;
        Leg taker;
        Leg[] makers;
    }

    struct ExchangeLeg {
        address sellToken;
        ITradeToken.TradeOrder o;
        bytes sig;
        uint256 sellFill;
        uint256 receiveFill;
    }

    struct ExchangePlan {
        bytes32 ref;
        ExchangeLeg[] legs;
        address[] extraTokens;
    }

    function wire(Leg memory l) internal pure returns (ISCaaSDex.Leg memory) {
        return ISCaaSDex.Leg(l.sellToken, 0, abi.encode(l.o), l.sig, l.fill);
    }

    function wire(Settlement memory s) internal pure returns (ISCaaSDex.Settlement memory w) {
        w.ref = s.ref;
        w.taker = wire(s.taker);
        w.makers = new ISCaaSDex.Leg[](s.makers.length);
        for (uint256 i; i < s.makers.length; ++i) w.makers[i] = wire(s.makers[i]);
    }

    function wire(Settlement[] memory ss) internal pure returns (ISCaaSDex.Settlement[] memory w) {
        w = new ISCaaSDex.Settlement[](ss.length);
        for (uint256 i; i < ss.length; ++i) w[i] = wire(ss[i]);
    }

    function wire(ExchangePlan memory p) internal pure returns (ISCaaSDex.ExchangePlan memory w) {
        w.ref = p.ref;
        w.extraTokens = p.extraTokens;
        w.legs = new ISCaaSDex.ExchangeLeg[](p.legs.length);
        for (uint256 i; i < p.legs.length; ++i) {
            ExchangeLeg memory l = p.legs[i];
            w.legs[i] = ISCaaSDex.ExchangeLeg(l.sellToken, 0, abi.encode(l.o), l.sig, l.sellFill, l.receiveFill);
        }
    }
}
