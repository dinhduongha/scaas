// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";

/// The address-shaped DEX legs the P2b suites were written in (before CTR-DEX-26 tagged them), and `wire`, which turns
/// them into shape-0 tagged legs at the call. `leg`, `uaLeg`, `xLeg`, `uaXLeg`: tagged legs (Appendix X row 20), the other
/// shape's members zero.
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

    /// The order a wrap order is at the underlying (TS-D19): `dex == receiveToken == wrappedToken`.
    function asTrade(ITradeToken.WrapOrder memory w) internal pure returns (ITradeToken.TradeOrder memory) {
        return ITradeToken.TradeOrder(w.from, w.wrappedToken, w.amount, w.minMinted, w.minFill, w.fee, w.relayer,
            w.wrappedToken, w.destination, w.flags, w.batch, w.nonce, w.validUntil);
    }

    function asTrade(ITradeToken.UAWrapOrder memory w) internal pure returns (ITradeToken.UATradeOrder memory) {
        return ITradeToken.UATradeOrder(w.from, w.wrappedToken, w.amount, w.minMinted, w.minFill, w.fee, w.relayer,
            w.wrappedToken, w.destination, w.flags, w.batch, w.nonce, w.validUntil);
    }

    function leg(address sell, ITradeToken.TradeOrder memory o, bytes memory sig, uint256 fill)
        internal pure returns (ISCaaSDex.DexLeg memory l)
    {
        (l.sellToken, l.order, l.sig, l.fill) = (sell, o, sig, fill);
    }

    function uaLeg(address sell, ITradeToken.UATradeOrder memory o, IUARegistry.UASig memory auth, uint256 fill)
        internal pure returns (ISCaaSDex.DexLeg memory l)
    {
        (l.sellToken, l.shape, l.uaOrder, l.auth, l.fill) = (sell, 1, o, auth, fill);
    }

    /// A settlement leg as an exchange leg.
    function exchange(ISCaaSDex.DexLeg memory l, uint256 sellFill, uint256 receiveFill)
        internal pure returns (ISCaaSDex.ExchangeLeg memory x)
    {
        (x.sellToken, x.shape, x.order, x.uaOrder, x.sig, x.auth) = (l.sellToken, l.shape, l.order, l.uaOrder, l.sig, l.auth);
        (x.sellFill, x.receiveFill) = (sellFill, receiveFill);
    }

    function xLeg(address sell, ITradeToken.TradeOrder memory o, bytes memory sig, uint256 sellFill, uint256 receiveFill)
        internal pure returns (ISCaaSDex.ExchangeLeg memory)
    {
        return exchange(leg(sell, o, sig, 0), sellFill, receiveFill);
    }

    function uaXLeg(address sell, ITradeToken.UATradeOrder memory o, IUARegistry.UASig memory auth, uint256 sellFill,
        uint256 receiveFill) internal pure returns (ISCaaSDex.ExchangeLeg memory)
    {
        return exchange(uaLeg(sell, o, auth, 0), sellFill, receiveFill);
    }

    function wire(Leg memory l) internal pure returns (ISCaaSDex.DexLeg memory) {
        return leg(l.sellToken, l.o, l.sig, l.fill);
    }

    function wire(Settlement memory s) internal pure returns (ISCaaSDex.Settlement memory w) {
        w.ref = s.ref;
        w.taker = wire(s.taker);
        w.makers = new ISCaaSDex.DexLeg[](s.makers.length);
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
            w.legs[i] = xLeg(l.sellToken, l.o, l.sig, l.sellFill, l.receiveFill);
        }
    }
}
