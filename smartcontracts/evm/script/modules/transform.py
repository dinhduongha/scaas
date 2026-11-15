# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T66b task 4.1 (spec 2026-11-09-t66b-library-organisation.md §4.1 rule 5, §4.4): the one-shot source transform of the token
tree, run once on the pre-split sources (their solc AST from `forge build src --build-info`); its output is then the hand-kept
source, and `entries.json` the record the faces are generated from (`gen_faces.py`).

- Each entry's body becomes `internal` `_<name>Body` in its own base file: same parameters and returns, `view` / `pure` kept,
  `payable` dropped (`msg.value` reads the caller's under DELEGATECALL), the guard modifiers `nonReentrant` / `governed` dropped
  (the stub's `_forward` holds the guard, M3). A function overriding such an entry is transformed the same way wherever it is,
  so every virtual chain keeps dispatching (the shared bases' non-token users included). Internal calls and `super` calls
  follow the rename; `this.f` and `C.f` of a transformed entry go through an interface that declares it.
- Kept entries (§4.1 rule 1) stay as they are.
- Interfaces leave the token cores (a module implements none, §4.4); a member of a removed interface used unqualified is
  qualified. The kinds become `<Kind>Core` (file `<Kind>Core.sol`); their face `<Kind>` is generated in `<Kind>.sol`.
- The shared bases (`SaltedEIP712`, `MetaTxBase`, `UAMetaTxBase`, `GovernanceBase`) become `<X>Core` (bodies) and `<X>` (their
  external entries calling the bodies, constructor forwarded) for their non-token users: ABI, modifiers, behaviour unchanged.

usage (from smartcontracts/evm): python3 script/modules/transform.py <build-info.json> [--dry]   UNAUDITED tooling."""
import json
import os
import re
import subprocess
import sys
from collections import defaultdict

BI = sys.argv[1]
DRY = '--dry' in sys.argv
d = json.load(open(BI))
srcs = d['output']['sources']

KINDS = {'NormalToken': 'src/metatx/NormalToken.sol', 'WrappedToken': 'src/metatx/WrappedToken.sol',
         'NormalZetherToken': 'src/zether/NormalZetherToken.sol', 'WrappedZetherToken': 'src/zether/WrappedZetherToken.sol',
         'NormalPqzToken': 'src/pqz/NormalPqzToken.sol', 'WrappedPqzToken': 'src/pqz/WrappedPqzToken.sol',
         'NormalRegulatedToken': 'src/regulated/NormalRegulatedToken.sol',
         'WrappedRegulatedToken': 'src/regulated/WrappedRegulatedToken.sol',
         'NormalZetherRegulatedToken': 'src/regulated/NormalZetherRegulatedToken.sol',
         'WrappedZetherRegulatedToken': 'src/regulated/WrappedZetherRegulatedToken.sol',
         'NormalPqzRegulatedToken': 'src/regulated/NormalPqzRegulatedToken.sol',
         'WrappedPqzRegulatedToken': 'src/regulated/WrappedPqzRegulatedToken.sol'}
BASES = ['src/metatx/ERC20MetaTx.sol', 'src/metatx/MetaTokenBase.sol', 'src/zether/ZetherLayer.sol', 'src/pqz/PqzLayer.sol',
         'src/regulated/RegulatedBase.sol']
SHARED = {'SaltedEIP712': 'src/common/SaltedEIP712.sol', 'MetaTxBase': 'src/metatx/MetaTxBase.sol',
          'UAMetaTxBase': 'src/metatx/UAMetaTxBase.sol', 'GovernanceBase': 'src/governance/GovernanceBase.sol'}
SCOPE_FILES = set(KINDS.values()) | set(BASES) | set(SHARED.values())
KEEP = {'transfer', 'transferFrom', 'approve', 'balanceOf', 'allowance', 'totalSupply', 'name', 'symbol', 'decimals',
        'balanceOfUA', 'transferToUA', 'kind', 'factory', 'implementation', 'registry', 'chainUid', 'IS_HEDERA',
        'SMART_KEY_ACCOUNT_IMPL', 'pqzSet', 'FACTORY', 'COMPLIANCE_REGISTRY_CODEHASH', 'RATE_WINDOW'}
GUARDS = {'nonReentrant', 'governed'}

nodes, parent, fileof = {}, {}, {}


def walk(n, path, par):
    if isinstance(n, dict):
        if 'id' in n and 'nodeType' in n:
            nodes[n['id']], parent[n['id']], fileof[n['id']] = n, par, path
            par = n['id']
        for v in n.values():
            walk(v, path, par)
    elif isinstance(n, list):
        for v in n:
            walk(v, path, par)


for path, s in srcs.items():
    walk(s['ast'], path, None)
contracts = {i: n for i, n in nodes.items() if n['nodeType'] == 'ContractDefinition'}
cname = {i: n['name'] for i, n in contracts.items()}
byname = {n['name']: n for i, n in contracts.items() if fileof[i].startswith('src/')}
ANY = {n['name']: i for i, n in contracts.items()}  # every contract, interface or library by name (src wins)
ANY.update({n['name']: n['id'] for n in byname.values()})
scope_contracts = {n['name'] for i, n in contracts.items() if fileof[i] in SCOPE_FILES and n['contractKind'] == 'contract'}
RENAME = {byname[k]['id']: k + 'Core' for k in list(KINDS) + list(SHARED)}  # contract id -> its core's name


def contract_of(i):
    i = parent[i]
    while i is not None and nodes[i]['nodeType'] != 'ContractDefinition':
        i = parent[i]
    return nodes[i] if i is not None else None


def span(n, key='src'):
    s, l, _ = map(int, n[key].split(':'))
    return s, s + l


text = {}


def raw(path, a, b):
    if path not in text:
        text[path] = open(path, 'rb').read()
    return text[path][a:b].decode()


kind_sels = {}
for k in KINDS:
    path = next(p for p, cs in d['output']['contracts'].items() if k in cs and p.startswith('src/'))
    kind_sels[k] = d['output']['contracts'][path][k]['evm']['methodIdentifiers']
sels = {v for m in kind_sels.values() for v in m.values()}
fdefs = {i: n for i, n in nodes.items() if n['nodeType'] == 'FunctionDefinition' and fileof[i].startswith('src/')}
T = {i for i, n in fdefs.items() if (c := contract_of(i)) and c['name'] in scope_contracts and n.get('kind') == 'function'
     and n.get('implemented') and n.get('functionSelector') in sels and (c['name'] in SHARED or n['name'] not in KEEP)}
TOKEN_ONLY = scope_contracts - set(SHARED)
while True:
    more = {i for i, n in fdefs.items() if i not in T and n.get('implemented') and set(n.get('baseFunctions') or []) & T
            and not (contract_of(i)['name'] in TOKEN_ONLY and n['name'] in KEEP)}
    if not more:
        break
    T |= more

REMOVED = {b['baseName']['referencedDeclaration'] for name in scope_contracts for b in byname[name]['baseContracts']
           if contracts[b['baseName']['referencedDeclaration']]['contractKind'] == 'interface'}
DECLARES = defaultdict(set)  # selector -> removed interfaces declaring it (directly or through their bases)
for iid in REMOVED:
    for bid in contracts[iid]['linearizedBaseContracts']:
        for nd in contracts[bid]['nodes']:
            if nd.get('functionSelector'):
                DECLARES[nd['functionSelector']].add(cname[iid])
edits = defaultdict(list)
DECLARES_ALL = defaultdict(set)
for iid in REMOVED:
    for nd in contracts[iid]['nodes']:
        if nd.get('functionSelector'):
            DECLARES_ALL[nd['functionSelector']].add(cname[iid])
REMOVED_CLOSURE = {b for r in REMOVED for b in contracts[r]['linearizedBaseContracts']
                   if contracts[b]['contractKind'] == 'interface'}
QUAL_IMPORTS = defaultdict(set)  # file -> interfaces it now names in a qualified member


def body_name(n):
    return '_' + n['name'] + 'Body'


def ovlist(n):
    """The override list of a function after the transform: its contract bases, a renamed contract by its core's name."""
    out = set()
    for bf in n.get('baseFunctions') or []:
        c = contract_of(bf)
        if c is None or bf in fdefs and fdefs[bf]['nodeType'] != 'FunctionDefinition':
            continue
        if n['id'] not in T and bf in T:
            continue
        if c['contractKind'] == 'interface':
            if c['id'] in REMOVED or any(c['id'] in contracts[r]['linearizedBaseContracts'] for r in REMOVED):
                continue
            out.add(c['name'])
            continue
        out.add(RENAME.get(c['id'], c['name']))
    return sorted(out)


def ov_text(names):
    return '' if not names else ' override' + ('(' + ', '.join(names) + ')' if len(names) > 1 else '')


def qual_type(tn):
    t = tn['typeDescriptions']['typeString']
    t = re.sub(r' (storage|memory|calldata)( ref| pointer)?$', '', t)
    t = re.sub(r'\b(struct|enum|contract) ', '', t)
    return t.strip()


IMPORTS = {}  # the root symbol of every user-defined type in an entry's parameters or returns -> its file


def note_types(tn):
    if not isinstance(tn, dict):
        return
    if tn.get('nodeType') == 'UserDefinedTypeName':
        decl = nodes.get(tn['referencedDeclaration'])
        if decl is not None:
            sc = decl.get('scope')
            root = cname[sc] if sc in contracts and decl['nodeType'] != 'ContractDefinition' else decl['name']
            IMPORTS[root] = fileof[decl['id']]
    for v in tn.values():
        if isinstance(v, dict):
            note_types(v)


def params(plist):
    out, names = [], []
    for k, p in enumerate(plist['parameters']):
        note_types(p['typeName'])
        loc = p.get('storageLocation', 'default')
        nm = p['name'] or f'_p{k}'
        names.append(nm)
        out.append(qual_type(p['typeName']) + ('' if loc == 'default' else ' ' + loc) + ' ' + nm)
    return out, names


# 1. transformed functions: name and attributes; the shared bases' faces
face = defaultdict(list)
for i in sorted(T):
    n, path = fdefs[i], fileof[i]
    ns, ne = span(n, 'nameLocation')
    edits[path].append((ns, ne, body_name(n)))
    pe = span(n['parameters'])[1]
    bs = span(n['body'])[0]
    rp = n['returnParameters']
    if rp['parameters']:
        seg = raw(path, pe, span(rp)[0])
        ae = pe + len(seg[:seg.rfind('returns')].encode())
    else:
        ae = bs
    attrs = ' internal' + (' ' + n['stateMutability'] if n['stateMutability'] in ('view', 'pure') else '')
    attrs += ' virtual' if n.get('virtual') else ''
    attrs += ov_text(ovlist(n))
    for m in n.get('modifiers', []):
        if m['modifierName']['name'] not in GUARDS:
            attrs += ' ' + raw(path, *span(m))
    edits[path].append((pe, ae, attrs + ' '))
    c = contract_of(i)
    if c['name'] in SHARED:
        face[c['name']].append(n)

# 2. references
NEED_CORE_IMPORT = defaultdict(set)  # non-scope file -> shared bases whose core it now names
for i, n in nodes.items():
    path = fileof[i]
    if not path.startswith('src/'):
        continue
    t, rd = n['nodeType'], n.get('referencedDeclaration')
    if t == 'Identifier' and rd in T:
        edits[path].append((*span(n), body_name(fdefs[rd])))
    elif t == 'MemberAccess' and rd in T:
        ex = n['expression']
        if ex.get('nodeType') == 'Identifier' and ex['name'] == 'super':
            edits[path].append((*span(n), 'super.' + body_name(fdefs[rd])))
            continue
        fsel = fdefs[rd].get('functionSelector')
        ifs = sorted(DECLARES_ALL.get(fsel, ())) or sorted(DECLARES.get(fsel, ()))  # a declaring interface first
        if ifs:
            QUAL_IMPORTS[path].add(ANY[ifs[0]])  # the interface it now names, imported where it was not
        if ex.get('nodeType') == 'Identifier' and ex['name'] == 'this':
            if ifs and nodes[parent[i]].get('memberName') == 'selector':
                edits[path].append((*span(ex), ifs[0]))  # `this.f.selector`: the interface's, a constant (pure)
            elif ifs:
                edits[path].append((*span(ex), f'{ifs[0]}(address(this))'))
            else:
                print(f'NO INTERFACE: this.{n["memberName"]} in {path}', file=sys.stderr)
        elif (ex.get('nodeType') == 'Identifier' and ex.get('referencedDeclaration') in contracts
              and nodes[parent[i]]['nodeType'] == 'FunctionCall' and contract_of(i) is not None
              and ex['referencedDeclaration'] in contract_of(i)['linearizedBaseContracts']):
            cid = ex['referencedDeclaration']
            edits[path].append((*span(n), RENAME.get(cid, cname[cid]) + '.' + body_name(fdefs[rd])))
        elif ex.get('nodeType') == 'Identifier' and ex.get('referencedDeclaration') in contracts:
            if ifs:
                edits[path].append((*span(ex), ifs[0]))
            else:
                print(f'NO INTERFACE: {ex["name"]}.{n["memberName"]} in {path}', file=sys.stderr)
    shared_ids = {byname[x]['id'] for x in SHARED}
    if t == 'IdentifierPath' and rd in shared_ids and nodes[parent[i]]['nodeType'] == 'ModifierInvocation' \
            and path not in SCOPE_FILES:
        edits[path].append((*span(n), RENAME[rd]))  # a shared base's constructor is its core's (the face has none)
        NEED_CORE_IMPORT[path].add(cname[rd])
    if path not in SCOPE_FILES:
        continue
    if t in ('Identifier', 'IdentifierPath') and rd in RENAME and n['name'] == cname[rd]:
        if contract_of(i) is None or contract_of(i)['name'] in scope_contracts:
            imp = nodes[parent[i]]['nodeType'] == 'ImportDirective'
            # an import of a shared base keeps its face beside its core (the face of a face's base)
            edits[path].append((*span(n), (cname[rd] + ', ' if imp and cname[rd] in SHARED else '') + RENAME[rd]))
    elif t in ('Identifier', 'IdentifierPath') and rd in nodes and '.' not in n['name']:
        decl = nodes[rd]
        dc = contract_of(rd)
        if dc is not None and dc['id'] in REMOVED_CLOSURE and decl['nodeType'] in (
                'EventDefinition', 'ErrorDefinition', 'StructDefinition', 'EnumDefinition', 'VariableDeclaration',
                'UserDefinedValueTypeDefinition'):
            edits[path].append((*span(n), cname[dc['id']] + '.' + n['name']))
            QUAL_IMPORTS[path].add(dc['id'])

# 2b. those files import the core beside the face
for i, n in nodes.items():
    if n['nodeType'] == 'ImportDirective' and fileof[i] in NEED_CORE_IMPORT:
        for al in n.get('symbolAliases', []):
            nm = al['foreign']['name']
            if nm in NEED_CORE_IMPORT[fileof[i]]:
                edits[fileof[i]].append((*span(al['foreign']), nm + ', ' + nm + 'Core'))

# 3. non-transformed functions and modifiers of the scope with an override list: recomputed
for i, n in nodes.items():
    if fileof[i] in SCOPE_FILES and n['nodeType'] in ('FunctionDefinition', 'ModifierDefinition') and i not in T \
            and n.get('overrides') and contract_of(i)['name'] in scope_contracts:
        new = ov_text(ovlist(n))
        if n['nodeType'] == 'FunctionDefinition' and not (set(n.get('baseFunctions') or []) - T):
            new = ''
        edits[fileof[i]].append((*span(n['overrides']), new.strip()))

# 4. contract heads: removed interfaces out, cores renamed, abstract
for name in scope_contracts:
    c = byname[name]
    path = fileof[c['id']]
    keep = [RENAME.get(b['baseName']['referencedDeclaration'], raw(path, *span(b))) for b in c['baseContracts']
            if b['baseName']['referencedDeclaration'] not in REMOVED]
    s, e = span(c)
    head = raw(path, s, e)
    m = re.match(r"(abstract contract|contract) (\w+)( is [^{]*)?\{", head, re.S)
    if not m:
        print("HEAD?", name, repr(head[:200]), file=sys.stderr)
        continue
    edits[path].append((s, s + len(m.group(0).encode()),
                        f'abstract contract {RENAME.get(c["id"], name)}' + (' is ' + ', '.join(keep) if keep else '') + ' {'))
    # every base list entry was also visited as an IdentifierPath (renamed); the head edit replaces those spans
    edits[path] = [x for x in edits[path] if not (s < x[0] and x[1] <= s + len(m.group(0).encode()) and x[0] != s)]

# 5. imports of a kind's file from the scope: its core's file
for i, n in nodes.items():
    if n['nodeType'] == 'ImportDirective' and fileof[i] in SCOPE_FILES and n['absolutePath'] in KINDS.values():
        s, e = span(n)
        t = raw(fileof[i], s, e)
        k = os.path.basename(n['absolutePath'])[:-4]
        t = t.replace('{' + k + '}', '{' + k + 'Core}').replace('/' + k + '.sol"', '/' + k + 'Core.sol"').replace(
            '"./' + k + '.sol"', '"./' + k + 'Core.sol"')
        edits[fileof[i]] = [x for x in edits[fileof[i]] if not (s <= x[0] and x[1] <= e)]
        edits[fileof[i]].append((s, e, t))

# 6. the shared bases' faces
for name, path in SHARED.items():
    c = byname[name]
    chain = [cname[b] for b in c['linearizedBaseContracts'] if cname.get(b) in SHARED]  # itself first
    ifs = []
    for sh in reversed(chain):
        for b in byname[sh]['baseContracts']:
            bn = cname[b['baseName']['referencedDeclaration']]
            if b['baseName']['referencedDeclaration'] in REMOVED and bn not in ifs:
                ifs.append(bn)
    lines = []  # no constructor: a derived contract calls `<X>Core(...)` (once in the hierarchy)
    done = set()
    for n in [m for sh in chain for m in face[sh]]:  # the most derived definition of each entry first
        if not n.get('functionSelector') or n['functionSelector'] in done:
            continue
        done.add(n['functionSelector'])
        npath = fileof[n['id']]
        ps, names = params(n['parameters'])
        ret = raw(npath, *span(n['returnParameters'])) if n['returnParameters']['parameters'] else ''
        h = f'    function {n["name"]}({", ".join(ps)}) {n["visibility"]}'
        h += '' if n['stateMutability'] == 'nonpayable' else ' ' + n['stateMutability']
        h += ' virtual' if n.get('virtual') else ''
        ov = sorted(DECLARES_ALL.get(n['functionSelector'], set()) & set(ifs))
        h += ov_text(ov) if len(ov) > 1 else (' override' if ov else '')
        for m in n.get('modifiers', []):
            h += ' ' + raw(npath, *span(m))
        h += ' returns ' + ret if ret else ''
        lines.append(h + ' {\n        ' + ('return ' if ret else '') + f'{body_name(n)}({", ".join(names)});\n    }}')
    for bn in ifs:  # an interface of the flattened chain this file does not import yet
        QUAL_IMPORTS[path].add(ANY[bn])
    ce = span(c)[1]
    txt = (f'\n\n/// @notice `{name}Core` with its external entries, each calling its body (T66b, spec 2026-11-09-t66b-library-'
           f'organisation.md §4.4):\n///         the form its non-token users inherit, ABI and modifiers unchanged. UNAUDITED.\n'
           f'abstract contract {name} is ' + ', '.join([name + 'Core'] + ifs) + ' {\n'
           + '\n\n'.join(lines) + '\n}')
    edits[path].append((ce, ce, txt))

# 2c. a qualified member's interface is imported where it was only inherited
for path, ids in QUAL_IMPORTS.items():
    unit = next(n for n in nodes.values() if n['nodeType'] == 'SourceUnit' and fileof[n['id']] == path)
    have = {al['foreign']['name'] for imp in unit['nodes'] if imp['nodeType'] == 'ImportDirective'
            for al in imp.get('symbolAliases', [])}
    first = next(pr for pr in unit['nodes'] if pr['nodeType'] == 'PragmaDirective')
    add = ''
    for cid in sorted(ids, key=lambda x: cname[x]):
        if cname[cid] not in have:
            f = fileof[cid]
            rp = ('@openzeppelin/contracts/' + f[len('lib/openzeppelin-contracts/contracts/'):]
                  if f.startswith('lib/openzeppelin-contracts/contracts/') else os.path.relpath(f, os.path.dirname(path)))
            add += 'import {' + cname[cid] + '} from "' + rp + '";\n'
    if add:
        add = '\n'.join(('./' + l[l.index('"') + 1:] and l) if False else l for l in add.split('\n'))
        s0 = span(first)[1]
        edits[path].append((s0, s0, '\n' + add.rstrip('\n').replace('from "I', 'from "./I')))

# 7. entries.json: every kind's entries from the pre-transform AST (the faces' source of truth); the module of each by
#    `size_map.entry_domain` (spec §4.2: the study's domains, runs/2026-11-07-ua-mtx-merge-size-study/size_map.py)
sys.path.insert(0, 'runs/2026-11-07-ua-mtx-merge-size-study')
from size_map import entry_domain  # noqa: E402
GROUP = {'pipeline': 'P', 'named-transfer': 'P', 'pay': 'P', 'trade': 'T', 'governance': 'A', 'init': 'A', 'tables': 'A',
         'token-meta': 'A', 'kind-normal': 'A', 'wrapped': 'W', 'regulated': 'W', 'zether': 'Z', 'pqz': 'Q'}
def iface_of(sel):
    return sorted(DECLARES.get(sel, ()))


out = {}
for k in KINDS:
    kc = byname[k]
    seen = {}
    for bid in kc['linearizedBaseContracts']:
        for nd in contracts[bid]['nodes']:
            fs = nd.get('functionSelector')
            if not fs or fs in seen or fs not in kind_sels[k].values():
                continue
            if nd['nodeType'] == 'FunctionDefinition' and not nd.get('implemented'):
                continue
            sig = next(s for s, v in kind_sels[k].items() if v == fs)
            if nd['nodeType'] == 'VariableDeclaration':
                seen[fs] = dict(sel=fs, sig=sig, name=nd['name'], decl=cname[bid], kept=True, mut='view', guard='',
                                params=[], names=[], returns='', ifaces=iface_of(fs), domain='erc20-core', group='K')
                continue
            ps, names = params(nd['parameters'])
            rs, _ = params(nd['returnParameters'])
            guard = next((m['modifierName']['name'] for m in nd.get('modifiers', []) if m['modifierName']['name'] in GUARDS), '')
            dom = entry_domain(cname[bid], nd['name'])
            seen[fs] = dict(sel=fs, sig=sig, name=nd['name'], decl=cname[bid], kept=nd['id'] not in T or nd['name'] in KEEP, mut=nd['stateMutability'],
                            guard=guard, params=ps, names=names, returns=', '.join(rs), ifaces=iface_of(fs),
                            vis=nd['visibility'], domain=dom, group='K' if (nd['id'] not in T or nd['name'] in KEEP) else GROUP[dom])
    out[k] = sorted(seen.values(), key=lambda e: e['sig'])
ifaces = {}
for k in KINDS:
    lin = byname[k]['linearizedBaseContracts']
    ifaces[k] = [cname[b] for b in reversed(lin) if b in REMOVED]
os.makedirs('script/modules', exist_ok=True)
json.dump({'kinds': out, 'interfaces': ifaces, 'imports': dict(sorted(IMPORTS.items()))}, open('script/modules/entries.json', 'w'), indent=1)

# apply (byte offsets, back to front); the kind files move to <Kind>Core.sol
bad = 0
for path, es in edits.items():
    # an edit inside a larger one (a rebuilt head, attribute list or override list that already holds the renamed names)
    # gives way to it; any other overlap is an error
    kept = []
    for x in sorted(set(es), key=lambda x: (x[0], -x[1])):
        if kept and x[0] < kept[-1][1]:
            if x[1] <= kept[-1][1] and x[0] >= kept[-1][0] and kept[-1][1] > kept[-1][0]:
                continue
            print(f'OVERLAP {path}: {kept[-1]} / {x}', file=sys.stderr)
            bad += 1
        kept.append(x)
    data = text.get(path) or open(path, 'rb').read()
    for s, e, t in sorted(kept, key=lambda x: (-x[0], -x[1])):
        data = data[:s] + t.encode() + data[e:]
    if not DRY:
        open(path, 'wb').write(data)
if not DRY and not bad:
    for k, path in KINDS.items():
        subprocess.run(['git', 'mv', path, path[:-4] + 'Core.sol'], check=True)
print(f'{len(T)} functions transformed, {len(edits)} files, {bad} overlaps; removed interfaces '
      f'{sorted(cname[i] for i in REMOVED)}')
