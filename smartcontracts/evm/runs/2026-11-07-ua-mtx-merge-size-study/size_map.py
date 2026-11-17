#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The measured map of T66b part 4: which contract holds which code, by function, domain and entry point.

usage: size_map.py <solc-output.json> > size-map.out      (the JSON from solc_full.py; UNAUDITED tooling, research only)

Source-map view: each instruction is charged to the innermost Solidity function / modifier of its source location, or to the
Yul utility (ABI coder) solc generated; the dispatcher has no source or only the contract's. Closure view (evmmap.py): the
bytes only one entry (or one domain of entries) reaches, an upper bound on what a move frees before the stub is added back.
"""
import json, os, sys
from collections import defaultdict
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evmmap

KINDS = ['NormalToken', 'WrappedToken', 'NormalZetherToken', 'WrappedZetherToken', 'NormalPqzToken', 'WrappedPqzToken',
         'NormalRegulatedToken', 'WrappedRegulatedToken', 'NormalZetherRegulatedToken', 'WrappedZetherRegulatedToken',
         'NormalPqzRegulatedToken', 'WrappedPqzRegulatedToken']
KIND_ID = dict(zip(KINDS, [0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13]))
OTHERS = ['SCaaSDex', 'UARegistry', 'GovernanceRouter', 'OpenFactory', 'MandateWallet', 'MtxRelayFee']
LIBS = ['UARegistryLib', 'ZetherLib', 'PqzViewLib', 'PqzTransferLib', 'WrappedLib', 'GovernanceLib', 'ZetherWrappedLib',
        'MtxPipelineLib', 'RegulatedLib', 'PqzBurnLib', 'PqzStateLib', 'PqzWrappedLib', 'TradeLib', 'HederaLib']

PAY = {'mtxPay', 'mtxPayReceiverFee', '_receiverFee', 'payWithFee', 'payWithFeeToUA', 'mtxRelayFee', '_relayRef', '_relayHash',
       'payLane', 'metaPayId', '_payMeta', 'receiverFeeDigest', 'mtxPayWithTax', 'payWithTax', '_taxSplit', '_uaSplit',
       'setTaxRate', 'setTaxRecipient', 'taxConfig'}
NAMED_TRANSFER = {'mtxTransfer', 'mtxTransferWithFee', '_requireFeeShape'}
TRADE = {'tradeOrderDigest', 'cancelOrderDigest', 'invalidateNoncesDigest', 'pulled', 'minNonce', 'mtxTrade', 'restorePulled',
         'mtxCancelOrder', 'mtxInvalidateNonces', 'mtxWrapOrder', '_wrapOrder'}
INIT = {'initialize', '_init', '_initRaw', '_requireUnused', '_setMetadata', 'constructor', 'validateEnv'}
TABLES = {'mtxSelectors', '_mtxRule', '_uaAllowed', '_batchable', '_isPqzOp', '_pqzRule', 'supportsInterface', '_validBits',
          '_roleBits', '_contractOnlyBits', '_scalarBits', '_scopeBits', 'kind'}
CORE = {'_update', '_uaMove', '_poolMove', '_uaDebit', 'approve', 'transferFrom', 'transfer', 'balanceOf', 'balanceOfUA',
        'transferToUA', '_uaMint', '_requireDerivedReceiver', '_mint', '_burn', '_transfer', '_approve', '_spendAllowance',
        'allowance', 'totalSupply', 'name', 'symbol', 'decimals', '_msgSender', '_msgData', '_contextSuffixLength'}
BY_CONTRACT = {
    'ERC20': 'erc20-core', 'Context': 'erc20-core', 'SafeERC20': 'erc20-core', 'Address': 'erc20-core',
    'MetaTxBase': 'pipeline', 'UAMetaTxBase': 'pipeline', 'ERC20MetaTx': 'pipeline', 'SaltedEIP712': 'pipeline',
    'MetaTxLib': 'pipeline', 'MtxPipelineLib': 'pipeline', 'SigCheck': 'pipeline', 'EIP712': 'pipeline',
    'MessageHashUtils': 'pipeline', 'ShortStrings': 'pipeline', 'ECDSA': 'pipeline', 'UAKinds': 'pipeline',
    'GovernanceBase': 'governance', 'GovernanceUse': 'governance', 'GovernanceLib': 'governance', 'GovernanceBits': 'governance',
    'TradeLib': 'trade', 'FeePolicy': 'pay', 'Math': 'shared-math', 'SafeCast': 'shared-math', 'Panic': 'shared-math',
    'Strings': 'shared-math',
    'MetaTokenBase': 'token-meta', 'TokenStore': 'token-meta', 'IFactoryToken': 'token-meta',
    'NormalToken': 'kind-normal', 'WrappedToken': 'wrapped', 'WrappedLib': 'wrapped',
    'ZetherLayer': 'zether', 'NormalZetherToken': 'zether', 'WrappedZetherToken': 'zether', 'ZetherLib': 'zether',
    'ZetherWrappedLib': 'zether', 'ZetherTypes': 'zether', 'ZetherStatements': 'zether', 'ZetherCurves': 'zether',
    'PqzLayer': 'pqz', 'NormalPqzToken': 'pqz', 'WrappedPqzToken': 'pqz', 'PqzCore': 'pqz', 'PqzCt': 'pqz',
    'PqzSafety': 'pqz', 'PqzWrappedLib': 'pqz', 'PqzStateLib': 'pqz', 'PqzViewLib': 'pqz', 'PqzTransferLib': 'pqz',
    'PqzBurnLib': 'pqz', 'PqzSet': 'pqz',
    'RegulatedBase': 'regulated', 'RegulatedLib': 'regulated',
}


def domain(label):
    """label of the source map -> domain."""
    if label.startswith('dispatch:'):
        return 'dispatch'
    if label.startswith('data:'):
        return 'metadata'
    if label.startswith('yul:'):
        n = label[4:]
        if n.startswith('abi_decode'):
            return 'abi-decode'
        if n.startswith('abi_encode'):
            return 'abi-encode'
        return 'yul-other'
    if label.startswith('other:'):
        return 'other'
    c, f = label.split(':', 1)[1].split('.', 1)
    if label.startswith('mod:'):
        return 'guard'
    if f in PAY or (c == 'RegulatedBase' and f in PAY):
        return 'pay'
    if f in NAMED_TRANSFER:
        return 'named-transfer'
    if f in TRADE:
        return 'trade'
    if f in INIT:
        return 'init'
    if f in TABLES:
        return 'tables'
    if f in CORE and c in ('ERC20', 'ERC20MetaTx', 'MetaTokenBase', 'MetaTxBase', 'Context'):
        return 'erc20-core'
    if c.endswith('RegulatedToken'):
        return 'regulated'
    return BY_CONTRACT.get(c, 'other:' + c)


DOMAINS = ['dispatch', 'abi-decode', 'abi-encode', 'yul-other', 'guard', 'erc20-core', 'pipeline', 'named-transfer', 'pay',
           'trade', 'governance', 'token-meta', 'init', 'tables', 'kind-normal', 'wrapped', 'zether', 'pqz', 'regulated',
           'shared-math', 'metadata']


def entry_domain(decl_contract, fname):
    if fname in PAY:
        return 'pay'
    if fname in NAMED_TRANSFER:
        return 'named-transfer'
    if fname in TRADE:
        return 'trade'
    if fname in INIT:
        return 'init'
    if fname in TABLES:
        return 'tables'
    if fname in CORE:
        return 'erc20-core'
    if decl_contract.endswith('RegulatedToken'):
        return 'regulated'
    d = BY_CONTRACT.get(decl_contract, 'other')
    return d


def sel_decls(o, name):
    base_ids, by_id = None, {}
    for p, s in o['sources'].items():
        for cd in s['ast']['nodes']:
            if cd.get('nodeType') == 'ContractDefinition':
                by_id[cd['id']] = cd
                if cd['name'] == name:
                    base_ids = cd['linearizedBaseContracts']
    out = {}
    for bid in base_ids:
        cd = by_id[bid]
        for nd in cd['nodes']:
            fs = nd.get('functionSelector')
            if not fs:
                continue
            if nd.get('nodeType') == 'FunctionDefinition' and not nd.get('implemented'):
                continue
            if fs not in out:
                out[fs] = (cd['name'], nd['name'], nd.get('stateMutability', 'view'))
    return out


def main():
    o = evmmap.load(sys.argv[1])
    src = evmmap.Sources(o)
    path_of = {n: p for p, cs in o['contracts'].items() for n in cs}
    contracts = {}
    for n in KINDS + OTHERS + LIBS:
        if n in path_of:
            contracts[n] = evmmap.Contract(o, src, path_of[n], n)
    attr = {n: c.attribute() for n, c in contracts.items()}
    dom = {n: defaultdict(int) for n in contracts}
    for n, a in attr.items():
        for lab, b in a.items():
            dom[n][domain(lab)] += b

    P = print
    P('# T66b part 4 size study: the measured map at the scratch build of ua-mtx-merge 937b454f (UNAUDITED; research)')
    P('# solc 0.8.37, optimizer 200, legacy codegen, amsterdam; runtime bytes; source-map attribution (an instruction to the')
    P('# innermost function of its source location; optimizer-merged blocks to one user), so a row is where the bytes are')
    P('# written, not what a move frees. Domains: see size_map.py.')
    P()
    P('## 1. Every contract by domain (bytes)')
    cols = [d for d in DOMAINS if any(dom[n].get(d) for n in contracts)]
    extra = sorted({d for n in contracts for d in dom[n] if d not in DOMAINS})
    cols += extra
    P('| contract | runtime | ' + ' | '.join(cols) + ' |')
    P('|' + '---|' * (len(cols) + 2))
    for n in contracts:
        P(f'| {n} | {contracts[n].size} | ' + ' | '.join(str(dom[n].get(d, 0)) for d in cols) + ' |')
    P()

    P('## 2. Functions across the twelve token kinds (bytes per kind; top 150 by the largest copy)')
    fn_rows = defaultdict(dict)
    for n in KINDS:
        for lab, b in attr[n].items():
            if lab.startswith(('fn:', 'mod:', 'yul:')):
                fn_rows[lab][n] = b
    hdr = ' | '.join(str(KIND_ID[k]) for k in KINDS)
    P(f'| function | domain | kinds holding it | sum over kinds | {hdr} |')
    P('|' + '---|' * (4 + len(KINDS)))
    rows = sorted(fn_rows.items(), key=lambda kv: -max(kv[1].values()))
    for lab, per in rows[:150]:
        P(f'| {lab[:90]} | {domain(lab)} | {len(per)} | {sum(per.values())} | ' + ' | '.join(str(per.get(k, '')) for k in KINDS) + ' |')
    P()
    P('## 3. Shared against unique, per kind (source-map bytes of labels present in all twelve kinds / in some / in this kind only)')
    P('| kind | runtime | in all 12 | in 2-11 | only here | dispatch+metadata |')
    P('|---|---|---|---|---|---|')
    for k in KINDS:
        a = attr[k]
        all12 = some = only = disp = 0
        for lab, b in a.items():
            if lab.startswith(('dispatch:', 'data:')):
                disp += b
                continue
            cnt = len(fn_rows.get(lab, {k: 1}))
            if cnt == 12:
                all12 += b
            elif cnt == 1:
                only += b
            else:
                some += b
        P(f'| {k} ({KIND_ID[k]}) | {contracts[k].size} | {all12} | {some} | {only} | {disp} |')
    P()

    P('## 4. Entry points: count by domain, and the bytes only that domain reaches (closure view)')
    P('| kind | entries | ' + ' | '.join(['pay', 'named-transfer', 'trade', 'governance', 'pipeline', 'erc20-core', 'token-meta',
                                         'tables', 'init', 'wrapped', 'zether', 'pqz', 'regulated', 'kind-normal']) + ' | dispatcher-only blocks |')
    P('|' + '---|' * 17)
    for k in KINDS + ['SCaaSDex', 'UARegistry', 'GovernanceRouter']:
        if k not in contracts:
            continue
        c = contracts[k]
        decl = sel_decls(o, k)
        cl = c.closures()
        groups = defaultdict(set)
        for sel in c.dispatch:
            dc, fnm, _ = decl.get(sel, ('?', '?', '?'))
            groups[entry_domain(dc, fnm)].add(sel)
        cells = []
        for g in ['pay', 'named-transfer', 'trade', 'governance', 'pipeline', 'erc20-core', 'token-meta', 'tables', 'init',
                  'wrapped', 'zether', 'pqz', 'regulated', 'kind-normal']:
            if groups.get(g):
                ex, reach = c.exclusive(cl, groups[g])
                cells.append(f'{len(groups[g])} / {ex}')
            else:
                cells.append('')
        P(f'| {k} | {len(c.dispatch)} | ' + ' | '.join(cells) + f' | {c.dispatcher_bytes(cl)} |')
    P('(cell: entries / bytes reachable only from them; the shared pipeline, moves and coders are reached by many domains)')
    P()

    for k in ['NormalToken', 'WrappedPqzRegulatedToken']:
        c = contracts[k]
        decl = sel_decls(o, k)
        cl = c.closures()
        P(f'## 5. {k}: every entry (declared in, mutability, domain, exclusive bytes, reachable bytes)')
        P('| declared in | entry | mutability | domain | exclusive | reachable | selector |')
        P('|---|---|---|---|---|---|---|')
        for sel in sorted(c.dispatch, key=lambda s: decl.get(s, ('', ''))[:2]):
            dc, fnm, mut = decl.get(sel, ('?', '?', '?'))
            ex, reach = c.exclusive(cl, {sel})
            P(f'| {dc} | {fnm} | {mut} | {entry_domain(dc, fnm)} | {ex} | {reach} | {sel} |')
        P()

    P('## 6. Libraries and other contracts: top functions (source map)')
    for n in LIBS + OTHERS:
        if n not in contracts:
            continue
        a = attr[n]
        top = sorted(a.items(), key=lambda kv: -kv[1])[:12]
        P(f'- **{n}** {contracts[n].size} B, entries {len(contracts[n].dispatch)}: ' +
          '; '.join(f'{lab} {b}' for lab, b in top))
    P()

    P('## 7. Yul utilities per kind: decoders, encoders, other (bytes and count)')
    P('| kind | abi_decode B / n | abi_encode B / n | other B / n |')
    P('|---|---|---|---|')
    for k in KINDS:
        acc = defaultdict(lambda: [0, 0])
        for lab, b in attr[k].items():
            if lab.startswith('yul:'):
                d = domain(lab)
                acc[d][0] += b
                acc[d][1] += 1
        P(f'| {k} | {acc["abi-decode"][0]} / {acc["abi-decode"][1]} | {acc["abi-encode"][0]} / {acc["abi-encode"][1]} | '
          f'{acc["yul-other"][0]} / {acc["yul-other"][1]} |')


if __name__ == '__main__':
    main()
