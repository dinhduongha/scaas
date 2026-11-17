#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Token-side spike: the entries of the chosen domains keep their signature, modifiers and ABI, and their body becomes one
forward of the calldata by DELEGATECALL (`_fwd`, `_fwdView`, `_fwdPure` added to `MetaTxBase`). The compiler then drops every
internal routine, coder and constant only those bodies used, so the build measures what leaving the token frees, the stub's
cost included, on every kind at once. The library side is not built here (see pay_spike / trade_spike).

usage: fwd_spike.py <solc-output.json> <evm dir> <domain>[,<domain>...]   (rewrites src/ in place; `git checkout -- src` undoes)
An entry another kept routine still calls (an internal reference, `super` or a base declaration it overrides) stays whole,
so no kept caller loses a body; the list is printed. Domains: size_map.entry_domain. UNAUDITED research tooling.
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from size_map import entry_domain

TOKEN_FILES = ('src/metatx/', 'src/zether/', 'src/pqz/', 'src/regulated/', 'src/governance/GovernanceBase.sol',
               'src/common/SaltedEIP712.sol')
KEEP_ALWAYS = {'transfer', 'transferFrom', 'approve', 'balanceOf', 'allowance', 'totalSupply', 'name', 'symbol', 'decimals',
               'kind'}
HELPERS = '''// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;
// fwd_spike (size study only): an entry's calldata to its library, unchanged; the return data back.
address constant FWD_LIB = 0x00000000000000000000000000000000DeaDBeef;
function fwdCall() {
    address l = FWD_LIB;
    assembly ("memory-safe") {
        calldatacopy(0, 0, calldatasize())
        let ok := delegatecall(gas(), l, 0, calldatasize(), 0, 0)
        returndatacopy(0, 0, returndatasize())
        if iszero(ok) { revert(0, returndatasize()) }
        return(0, returndatasize())
    }
}
function fwdView() view { function() f = fwdCall; function() view v; assembly ("memory-safe") { v := f } v(); }
function fwdPure() pure { function() f = fwdCall; function() pure v; assembly ("memory-safe") { v := f } v(); }
'''


def walk(n, parent=None):
    if isinstance(n, dict):
        yield n, parent
        for v in n.values():
            if isinstance(v, (dict, list)):
                yield from walk(v, n)
    elif isinstance(n, list):
        for v in n:
            yield from walk(v, parent)


def main():
    o = json.load(open(sys.argv[1]))
    evm = sys.argv[2]
    want = set(sys.argv[3].split(','))
    fdefs = {}      # id -> (path, contract, node)
    overrides = {}  # base id -> set of overriding ids
    for path, s in o['sources'].items():
        for cd in s['ast']['nodes']:
            if cd.get('nodeType') != 'ContractDefinition':
                continue
            for nd in cd['nodes']:
                if nd.get('nodeType') == 'FunctionDefinition':
                    fdefs[nd['id']] = (path, cd['name'], nd, cd['contractKind'])
                    for b in nd.get('baseFunctions', []):
                        overrides.setdefault(b, set()).add(nd['id'])

    def closure_ids(i):
        out, st = set(), [i]
        while st:
            x = st.pop()
            if x in out:
                continue
            out.add(x)
            st.extend(overrides.get(x, ()))
        return out

    sel = {}
    for i, (path, c, nd, ck) in fdefs.items():
        if ck != 'contract' or not path.startswith(TOKEN_FILES) or not nd.get('implemented') or nd.get('kind') != 'function':
            continue
        if nd.get('visibility') not in ('external', 'public') or (nd['name'] in KEEP_ALWAYS and 'erc20-core' not in want):
            continue
        if entry_domain(c, nd['name']) in want or (nd['name'] in KEEP_ALWAYS and 'erc20-core' in want):
            sel[i] = (path, c, nd, ck)
    # who references what (calls, super, base declarations), from where
    refs = {}  # target id -> set of referencing function ids (or -1 = not in a function)
    for path, s in o['sources'].items():
        for cd in s['ast']['nodes']:
            if cd.get('nodeType') != 'ContractDefinition' or cd['contractKind'] != 'contract':
                continue
            for nd in cd['nodes']:
                owner = nd['id'] if nd.get('nodeType') == 'FunctionDefinition' else -1
                for x, parent in walk(nd):
                    r = x.get('referencedDeclaration')
                    if r is None or x.get('nodeType') not in ('Identifier', 'MemberAccess'):
                        continue
                    if parent and parent.get('nodeType') == 'MemberAccess' and parent.get('memberName') == 'selector':
                        continue
                    if x['nodeType'] == 'MemberAccess':  # internal only: super.f, Base.f; never an external call on an instance
                        ex = x.get('expression', {})
                        ts = ex.get('typeDescriptions', {}).get('typeString', '') or ''
                        if not (ex.get('name') == 'super' or ts.startswith('type(contract ')):
                            continue
                    for t in closure_ids(r):
                        refs.setdefault(t, set()).add(owner)
    changed = True
    kept = {}
    while changed:
        changed = False
        for i in list(sel):
            outside = [r for r in refs.get(i, ()) if r not in sel and r != i]
            if outside:
                kept[i] = sel.pop(i)
                changed = True
    by_file = {}
    for i, (path, c, nd, _) in sel.items():
        a, ln, _ = map(int, nd['body']['src'].split(':'))
        mut = nd.get('stateMutability')
        call = {'view': 'fwdView', 'pure': 'fwdPure'}.get(mut, 'fwdCall')
        by_file.setdefault(path, []).append((a, a + ln, '{ ' + call + '(); }'))
    open(os.path.join(evm, 'src/FwdSpike.sol'), 'w').write(HELPERS)
    for path, reps in by_file.items():
        p = os.path.join(evm, path)
        b = open(p, 'rb').read()
        for a, e, t in sorted(reps, reverse=True):
            b = b[:a] + t.encode() + b[e:]
        rel = os.path.relpath(os.path.join(evm, 'src/FwdSpike.sol'), os.path.dirname(p))
        if not rel.startswith('.'):
            rel = './' + rel
        imp = f'import {{fwdCall, fwdView, fwdPure}} from "{rel}";\n'.encode()
        i = b.index(b'pragma solidity')
        i = b.index(b'\n', i) + 1
        b = b[:i] + imp + b[i:]
        open(p, 'wb').write(b)
    print('forwarded', len(sel), 'definitions:', ', '.join(sorted({f'{c}.{nd["name"]}' for _, c, nd, _ in sel.values()})))
    print('kept whole (a kept routine calls them):', ', '.join(sorted({f'{c}.{nd["name"]}' for _, c, nd, _ in kept.values()})) or 'none')


if __name__ == '__main__':
    main()
