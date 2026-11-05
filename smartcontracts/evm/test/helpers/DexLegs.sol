// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {Vm} from "forge-std/Vm.sol";

/// The address-shaped DEX legs the P2b suites were written in (before CTR-DEX-26 tagged them), and `wire`, which turns
/// them into tagged legs at the call: shape 1 on a token the order's DEX lists as SCaaS (ua-mtx-merge T6, R12: the
/// order as its `UATradeOrder`, `ua`, the address zero-padded; the signature, over that order's digest, as a native
/// id's `auth.signature`), else shape 0 (an outside token's `DexOrder`). `leg`, `uaLeg`, `xLeg`, `uaXLeg`: tagged legs
/// (Appendix X row 20), the other shape's members zero; `leg` and `xLeg` pick the shape as `wire` does, `leg0` is
/// always shape 0. The DEX's listing is read from its storage by a cheatcode (`vm.load`), not a call, so a `prank`
/// or `expectRevert` before the call that takes the leg still meets that call.
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

    /// The order a wrap order is at the underlying (TS-D19): `dex == receiveToken == wrappedToken` (the address
    /// `WrapOrder` is in legacy/ua-mtx-merge/, R39).
    function asTrade(ITradeToken.UAWrapOrder memory w) internal pure returns (ITradeToken.UATradeOrder memory) {
        return ITradeToken.UATradeOrder(w.from, w.wrappedToken, w.amount, w.minMinted, w.minFill, w.fee, w.relayer,
            w.wrappedToken, w.destination, w.flags, w.batch, w.nonce, w.validUntil);
    }

    function pad(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    /// The `UATradeOrder` a SCaaS token takes for an address-shaped order (a copy: the caller may change `o` later).
    function ua(ITradeToken.TradeOrder memory o) internal pure returns (ITradeToken.UATradeOrder memory) {
        return ITradeToken.UATradeOrder(pad(o.from), o.receiveToken, o.amount, o.receiveAmount, o.minFill, o.fee, o.relayer,
            o.dex, pad(o.destination), o.flags, o.batch, o.nonce, o.validUntil);
    }

    /// A native id's `UASig`: its own signature only (R17).
    function sigOf(bytes memory sig) internal pure returns (IUARegistry.UASig memory a) {
        a.signature = sig;
    }

    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    // `SCaaSDex`'s ERC-7201 base `scaas.dex`; `kind` is the third slot of its `DexStorage` (the layout is pinned)
    bytes32 private constant DEX_STORAGE = 0xb144ea5327f344ea7e3b34dd1898f534c8ce28f9f54d0d89a1b78f8fcf7dac00;

    /// Whether `dex` lists `token` as SCaaS (its `tokenKind == 1`, read from storage); false when `dex` is no DEX.
    function scaas(address dex, address token) internal view returns (bool) {
        return uint256(VM.load(dex, keccak256(abi.encode(token, uint256(DEX_STORAGE) + 2)))) == 1;
    }

    /// The tagged leg the DEX takes for `o` (see `wire`).
    function leg(address sell, ITradeToken.TradeOrder memory o, bytes memory sig, uint256 fill)
        internal view returns (ISCaaSDex.DexLeg memory)
    {
        if (scaas(o.dex, sell)) return uaLeg(sell, ua(o), sigOf(sig), fill);
        return leg0(sell, o, sig, fill);
    }

    /// A shape-0 leg, whatever the sell token (on a SCaaS token the DEX refuses it, R12).
    function leg0(address sell, ITradeToken.TradeOrder memory o, bytes memory sig, uint256 fill)
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
        internal view returns (ISCaaSDex.ExchangeLeg memory)
    {
        return exchange(leg(sell, o, sig, 0), sellFill, receiveFill);
    }

    function uaXLeg(address sell, ITradeToken.UATradeOrder memory o, IUARegistry.UASig memory auth, uint256 sellFill,
        uint256 receiveFill) internal pure returns (ISCaaSDex.ExchangeLeg memory)
    {
        return exchange(uaLeg(sell, o, auth, 0), sellFill, receiveFill);
    }

    function wire(Leg memory l) internal view returns (ISCaaSDex.DexLeg memory) {
        return leg(l.sellToken, l.o, l.sig, l.fill);
    }

    function wire(Settlement memory s) internal view returns (ISCaaSDex.Settlement memory w) {
        w.ref = s.ref;
        w.taker = wire(s.taker);
        w.makers = new ISCaaSDex.DexLeg[](s.makers.length);
        for (uint256 i; i < s.makers.length; ++i) w.makers[i] = wire(s.makers[i]);
    }

    function wire(Settlement[] memory ss) internal view returns (ISCaaSDex.Settlement[] memory w) {
        w = new ISCaaSDex.Settlement[](ss.length);
        for (uint256 i; i < ss.length; ++i) w[i] = wire(ss[i]);
    }

    function wire(ExchangePlan memory p) internal view returns (ISCaaSDex.ExchangePlan memory w) {
        w.ref = p.ref;
        w.extraTokens = p.extraTokens;
        w.legs = new ISCaaSDex.ExchangeLeg[](p.legs.length);
        for (uint256 i; i < p.legs.length; ++i) {
            ExchangeLeg memory l = p.legs[i];
            w.legs[i] = xLeg(l.sellToken, l.o, l.sig, l.sellFill, l.receiveFill);
        }
    }
}
