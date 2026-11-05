#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T6 (plan step 6): one mutant at a time on the T6 tree. `t6_mutants.py <name>` from smartcontracts/evm
applies one (every edit's anchor must be found exactly once); `run_t6_mutants.sh` runs test/merge, then the DEX and
trade suites, after each and restores `src` with `git checkout -- src`. `--list` prints the names. The plan's five in its
order, then three for the points carried from T3 (the cancel's registry guard, the wrap order's named error) and the
shape-0 refusal of R12."""
import sys

DEX = 'src/dex/SCaaSDex.sol'
LIB = 'src/trade/TradeLib.sol'
MUT = {
    # the DEX asks the sell token's registry of every seller, a native one too (C undone)
    'ledger-asked-of-native-seller': [(DEX,
        '            if (c.outside || (!UAKinds.inNativeSpace(uaOrder.from) && IUALedger(sellToken).registry() == address(0))) {\n',
        '            if (c.outside || IUALedger(sellToken).registry() == address(0)) {\n')],
    # `_interact` no longer refuses the merged `mtxTrade` selector
    'interact-misses-merged-mtxTrade': [(DEX,
        '        if (x.data.length < 4 || sel == ITradeToken.mtxTrade.selector || sel == OLD_MTX_TRADE || sel == OLD_UA_TRADE) {\n',
        '        if (x.data.length < 4 || sel == OLD_MTX_TRADE || sel == OLD_UA_TRADE) {\n')],
    # `destination` left out of the token's order digest (a zero word in its place)
    'destination-out-of-digest': [(LIB,
        '            typehash, o.from, o.receiveToken, o.amount, o.receiveAmount, o.minFill, o.fee, o.relayer, o.dex,\n'
        '            o.destination, o.flags, o.batch, o.nonce, o.validUntil));\n',
        '            typehash, o.from, o.receiveToken, o.amount, o.receiveAmount, o.minFill, o.fee, o.relayer, o.dex,\n'
        '            bytes32(0), o.flags, o.batch, o.nonce, o.validUntil));\n')],
    # a SCaaS leg emits the address `LegSettled` instead of `UALegSettled`
    'legsettled-on-scaas-leg': [(DEX,
        '        if (c.ua) {\n            emit UALegSettled(',
        '        if (false) {\n            emit UALegSettled(')],
    # the `ua` flag kept on the token side, set to the address form: the token hashes its order as `TradeOrder`
    'ua-flag-kept-on-token-side': [(LIB,
        '        return _tradeHash(c, UA_TRADE_ORDER_TYPEHASH);\n',
        '        return _tradeHash(c, TRADE_ORDER_TYPEHASH);\n')],
    # carried from T3: the cancel keeps the registry guard (an EOA on a token with no registry cannot cancel)
    'cancel-needs-registry': [('src/metatx/ERC20MetaTx.sol',
        '    function mtxCancelOrder(UATradeOrder calldata o, IUARegistry.UASig calldata auth) external nonReentrant {\n',
        '    function mtxCancelOrder(UATradeOrder calldata o, IUARegistry.UASig calldata auth) external nonReentrant {\n'
        '        _uaOn();\n')],
    # carried from T3: a leg with no `mtxTrade` reverts without a name again (the empty revert bubbled)
    'wrap-order-leg-unnamed': [('src/metatx/WrappedLib.sol',
        '            if (r.length == 0) revert IUALedger.UALegNotLedger(u);\n', '')],
    # R12: a shape-0 leg on a SCaaS token is no longer refused (it takes the outside path)
    'shape0-on-scaas-accepted': [(DEX, '            if (!c.outside) revert LegShapeUnknown(shape);\n', '')],
}

if sys.argv[1] == '--list':
    print(' '.join(MUT))
    sys.exit(0)
for path, a, b in MUT[sys.argv[1]]:
    s = open(path).read()
    assert s.count(a) == 1, (sys.argv[1], path, s.count(a))
    open(path, 'w').write(s.replace(a, b, 1))
