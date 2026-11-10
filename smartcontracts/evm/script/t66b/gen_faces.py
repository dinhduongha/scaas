# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T66b task 4.1 (spec 2026-11-09-t66b-library-organisation.md §4.1, §4.4–4.6): each kind's token face and body modules,
generated from `script/t66b/entries.json` (every entry of every kind: signature, mutability, guard, the module it runs in).

- `<Kind>.sol`: the token face. Every entry the token does not keep is a stub: `_forward(module)` when today's entry is
  guarded (`nonReentrant` / `governed`; S1), `_forwardRaw` otherwise, `_forwardView` / `_forwardPure` for view / pure ones
  (S2); no modifier on a stub (P1-1). The module addresses are immutables from `implArgs` (`ImplArgs` /
  `RegulatedImplArgs`, decoded once); the constructor checks each module (code, kind, group, factory, the registry code hash
  on 8–13, the PQZ set on 4, 5, 12, 13; `ModuleMissing` / `ModuleMismatch`). `modules()` lists them.
- `<Kind>Modules.sol`: one contract per module, `<Kind><Group>`: the kind's core and its group's entries, each
  `onlyDelegated` (a `pure` one cannot read `address(this)`: none) and calling its body, `moduleGroup()`.

usage (from smartcontracts/evm): python3 script/t66b/gen_faces.py [--check]   (--check: the files equal what it writes)
GENERATED files: edit the entries table or this script, then regenerate. UNAUDITED tooling."""
import json
import os
import sys

from post3 import HOOKS, hook  # the pipeline hooks of rule 4

E = json.load(open('script/t66b/entries.json'))
# §4.2's splitting rule, applied where the build measured a module above 33,780 B (≈ 57 M asked; summary.txt): Q splits into
# the PQZ ops and their verdict entries (Q) and the PQZ state, setters and views (Q2).
Q2_SETTERS = {'pqzSetVerifier', 'pqzCancelVerifier', 'pqzRevokeVerifier', 'setProofStore'}
Q2_VERDICTS = {'verifyTransferAmount'}
SPLITS = {'WrappedPqzToken': {'Q'}, 'WrappedPqzRegulatedToken': {'Q'}}
# §11 (g), owner 2026-11-09: pay stays in P; a kind whose P passes 33,780 B splits P into the pipeline and named transfers (P)
# and pay with the relay fee (P2, the `pay` domain of entries.json, one clean cut). No kind's P passes it at 4.1 (30,783 B
# at most). T66B_SPLIT_PAY=1 splits every kind, for 4.4's per-kind pay-module comparison only (never committed output).
if os.environ.get('T66B_SPLIT_PAY') == '1':
    for _k in E['kinds']:
        SPLITS.setdefault(_k, set()).add('P')
for _k, _gs in SPLITS.items():
    for _e in E['kinds'][_k]:
        if 'P' in _gs and _e['group'] == 'P' and _e['domain'] == 'pay':
            _e['group'] = 'P2'
        if 'Q' in _gs and _e['group'] == 'Q' and (_e['name'] in Q2_SETTERS or (_e['mut'] in ('view', 'pure')
                                                                                 and _e['name'] not in Q2_VERDICTS)):
            _e['group'] = 'Q2'
CHECK = '--check' in sys.argv
# §4.1 rule 4: the modules that compile `MtxPipelineLib`'s code in, each overriding these hooks with the library's internal
# twins: P (and P2) the pipeline, named transfers and pay; T the trade authorisation; A the payment views. W, Z and Q keep
# the library call (their relayed named entries reach `_namedUA`: compiling the pipeline in would grow each by 3-7 KB).
PIPE = {'P': list(HOOKS), 'P2': list(HOOKS), 'T': ['Authorize'], 'A': ['PaymentCount', 'PaymentsOf']}
KFILE = {'NormalToken': 'src/metatx', 'WrappedToken': 'src/metatx', 'NormalZetherToken': 'src/zether',
         'WrappedZetherToken': 'src/zether', 'NormalPqzToken': 'src/pqz', 'WrappedPqzToken': 'src/pqz',
         'NormalRegulatedToken': 'src/regulated', 'WrappedRegulatedToken': 'src/regulated',
         'NormalZetherRegulatedToken': 'src/regulated', 'WrappedZetherRegulatedToken': 'src/regulated',
         'NormalPqzRegulatedToken': 'src/regulated', 'WrappedPqzRegulatedToken': 'src/regulated'}
GROUP_ID = {'P': 1, 'T': 2, 'A': 3, 'W': 4, 'Z': 5, 'Q': 6, 'P2': 7, 'Q2': 8, 'G': 9, 'D': 10}  # D: the DEX's (src/dex/SCaaSDexAdmin.sol)
GROUP_DOC = {'P': 'the signed pipeline, named transfers and pay', 'T': 'trade', 'A': 'admin: governance, init, tables, token meta',
             'W': 'wrapped and regulated', 'Z': 'Zether', 'Q': 'PQZ', 'P2': 'pay and the relay fee',
             'Q2': 'the PQZ state, setters and views', 'G': 'governance', 'D': 'the DEX\'s governance'}
TOKEN_KIND = {'NormalToken': 'NORMAL', 'WrappedToken': 'WRAPPED', 'NormalZetherToken': 'NORMAL_ZETHER',
              'WrappedZetherToken': 'WRAPPED_ZETHER', 'NormalPqzToken': 'NORMAL_PQZ', 'WrappedPqzToken': 'WRAPPED_PQZ',
              'NormalRegulatedToken': 'NORMAL_REGULATED', 'WrappedRegulatedToken': 'WRAPPED_REGULATED',
              'NormalZetherRegulatedToken': 'NORMAL_ZETHER_REGULATED', 'WrappedZetherRegulatedToken': 'WRAPPED_ZETHER_REGULATED',
              'NormalPqzRegulatedToken': 'NORMAL_PQZ_REGULATED', 'WrappedPqzRegulatedToken': 'WRAPPED_PQZ_REGULATED'}
REG = lambda k: 'Regulated' in k  # noqa: E731
# group 3l: the wrapped kinds' entries name `IWrappedToken`'s structs, which not every core imports
WRAPPED_IMPORT = lambda k: ('src/metatx/IWrappedToken.sol',) if k.startswith('Wrapped') else ()  # noqa: E731
PQZ = lambda k: 'Pqz' in k  # noqa: E731
HDR = '''// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

// GENERATED by script/t66b/gen_faces.py from script/t66b/entries.json (T66b, spec 2026-11-09-t66b-library-organisation.md
// §4.4): do not edit; regenerate.
'''


def rel(frm, to):
    r = os.path.relpath(to, os.path.dirname(frm))
    return r if r.startswith('.') else './' + r


def imports(k, path, extra=()):
    files = sorted(set(E['imports'].values()) | {f'{KFILE[k]}/{k}Core.sol', 'src/metatx/ITokenModule.sol', 'src/factory/IOpenFactory.sol'}
                   | ({'src/pqz/PqzSet.sol'} if PQZ(k) else set()) | set(extra))
    return ''.join(f'import "{rel(path, f)}";\n' for f in files)


def groups(k):
    seen = []
    for e in E['kinds'][k]:
        if not e['kept'] and e['group'] not in seen:
            seen.append(e['group'])
    return sorted(seen, key=lambda g: GROUP_ID[g])


def mut(e):
    return '' if e['mut'] == 'nonpayable' else ' ' + e['mut']


def ret(e):
    return f' returns ({e["returns"]})' if e['returns'] else ''


FACE_ABI = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'face_abi.json')))['kinds']


def _abi_t(i):
    t = i.get('internalType') or i['type']
    for p in ('struct ', 'enum ', 'contract '):
        t = t.removeprefix(p)
    return t


W3L_EVENTS = [
    '    event WrapLimitsSet(bytes32 indexed by, IWrappedToken.WrapLegLimits[] legs, bool netUnwrap, bool wrapList, bool unwrapList);',
    '    event WrapLimitsProposed(bytes32 indexed by, uint64 eta, IWrappedToken.WrapLegLimits[] legs, bool netUnwrap, bool wrapList, bool unwrapList);',
    '    event WrapMemberSet(bytes32 indexed account, bytes32 indexed by, bool canWrap, bool canUnwrap);',
]
W3L_ERRORS = [f'    error {e};' for e in [
    'WrapLimitExceeded(address underlying, uint8 limit, bytes32 account, uint256 amount, uint256 remaining)',
    'WrapCapExceeded(address underlying, uint8 limit, uint256 amount, uint256 remaining)',
    'UnwrapAboveNetWrapped(address underlying, bytes32 account, uint256 amount, uint256 entitlement)',
    'WrapperNotListed(bytes32 account)', 'UnwrapperNotListed(bytes32 account)', 'WrapLimitInvalid(address underlying, uint8 limit)',
    'WrapLegMismatch(uint256 index, address underlying)', 'WrapUnitInvalid(address underlying, uint8 unitExp)',
    'WrapControlNeedsHybrid(uint8 bit)', 'WrapControlActive(uint8 bit)', 'WrapSubjectZero()']]


def abi_iface(k):
    """`I<k>Abi` (controller 2026-11-09, option B): the pre-split face's events and errors that the face does not declare
    itself (face_abi.json, from d142b57c), declarations only: the face's ABI lists them as before, its runtime is unchanged."""
    d = FACE_ABI[k]
    ev = [f'    event {x["name"]}(' + ', '.join(f'{_abi_t(i)}{" indexed" if i.get("indexed") else ""}'
                                         + (f' {i["name"]}' if i['name'] else '') for i in x['inputs'])
          + (') anonymous;' if x.get('anonymous') else ');') for x in d['event']]
    er = [f'    error {x["name"]}(' + ', '.join(_abi_t(i) + (f' {i["name"]}' if i['name'] else '') for i in x['inputs']) + ');'
          for x in d['error']]
    if k.startswith('Wrapped'):  # group 3l (wrap limits spec §7): what `WrappedLib` raises and emits since the split
        ev += W3L_EVENTS
        er += W3L_ERRORS
    return f'''
/// @notice The events and errors of `{k}` before the split (d142b57c) that its core does not declare: the face's ABI lists them
///         as before (metatx-split R4: a client decodes an error a library or a module raises), declarations only, no code.
interface I{k}Abi {{
''' + '\n'.join(ev + er) + '\n}\n'


def face(k):
    gs = groups(k)
    path = f'{KFILE[k]}/{k}.sol'
    imm = '\n'.join(f'    address private immutable _M{g};' for g in gs)
    args = 'RegulatedImplArgs' if REG(k) else 'ImplArgs'
    core_args = 'abi.encode(a.registryCodehash)' if REG(k) else '""'
    sets = '\n'.join(f'        _M{g} = _module(a.modules, {i}, {GROUP_ID[g]});' for i, g in enumerate(gs))
    lst = ', '.join(f'_M{g}' for g in gs)
    checks = ''
    if REG(k):
        checks += '\n        if (ITokenModule(m).REGISTRY_CODEHASH() != REGISTRY_CODEHASH) revert ModuleMismatch(i);'
    if PQZ(k):
        checks += '\n        if (ITokenModule(m).pqzSet() != PqzSet.SELFTEST) revert ModuleMismatch(i);'
    stubs = []
    for e in E['kinds'][k]:
        if e['kept']:
            continue
        p = ', '.join(x.rsplit(' ', 1)[0] for x in e['params'])
        if e['guard']:
            body = f'_forward(_M{e["group"]});'
        elif e['mut'] == 'view':
            body = f'_forwardView(_M{e["group"]});'
        elif e['mut'] == 'pure':
            body = f'_forwardPure(_modulePure({GROUP_ID[e["group"]]}));'
        else:
            body = f'_forwardRaw(_M{e["group"]});'
        stubs.append(f'    function {e["name"]}({p}) external{mut(e)}{ret(e)} {{\n        {body}\n    }}')
    n = len(gs)
    chain = '\n'.join(f'        if (g == {GROUP_ID[g]}) return _M{g};' for g in gs[:-1]) + f'\n        return _M{gs[-1]};'
    return path, HDR + '\n' + imports(k, path, ('src/governance/IGovernance.sol', 'src/zether/ZetherTypes.sol') + WRAPPED_IMPORT(k)) + abi_iface(k) + f'''
/// @title {k}: the token face (T66b, spec 2026-11-09-t66b-library-organisation.md §4.1). It keeps the ERC-20 core, the UA
///        ledger and the identity views (`{k}Core`); every other entry forwards its calldata to the module of its group by
///        DELEGATECALL ({', '.join(f'{g} {GROUP_DOC[g]}' for g in gs)}). UNAUDITED.
contract {k} is {k}Core, I{k}Abi {{
{imm}

    /// @param implArgs `abi.encode({args}(...))`: the modules in the order {', '.join(gs)} (`modules()`).
    constructor(address factory_, bytes memory implArgs) {k}Core(factory_, _coreArgs(implArgs)) {{
        {args} memory a = abi.decode(implArgs, ({args}));
        if (a.modules.length != {n}) revert ModuleMissing(a.modules.length);
{sets}
    }}

    function _coreArgs(bytes memory implArgs) private pure returns (bytes memory) {{
        {args} memory a = abi.decode(implArgs, ({args}));
        a;
        return {core_args};
    }}

    /// Module `i` of the list, checked (§4.5): code, this kind, its group, this factory{', the registry code hash' if REG(k) else ''}{', this PQZ set' if PQZ(k) else ''}.
    function _module(address[] memory ms, uint256 i, uint8 group) private view returns (address m) {{
        m = ms[i];
        if (m.code.length == 0) revert ModuleMissing(i);
        if (ITokenModule(m).kind() != uint8(IOpenFactory.TokenKind.{TOKEN_KIND[k]}) || ITokenModule(m).moduleGroup() != group || ITokenModule(m).factory() != FACTORY) {{
            revert ModuleMismatch(i);
        }}{checks}
    }}

    /// The module of group `g` inside a `pure` stub (S2): an immutable read is not `pure`, so the reader is cast, as the stubs are.
    function _moduleView(uint8 g) private view returns (address) {{
{chain}
    }}

    function _modulePure(uint8 g) private pure returns (address m) {{
        function(uint8) view returns (address) f = _moduleView;
        function(uint8) pure returns (address) p;
        assembly ("memory-safe") {{
            p := f
        }}
        m = p(g);
    }}

    function modules() external view returns (address[] memory m) {{
        m = new address[]({n});
        ({', '.join(f'm[{i}]' for i in range(n))}) = ({lst});
    }}

''' + '\n\n'.join(stubs) + '\n}\n'


def modules(k):
    path = f'{KFILE[k]}/{k}Modules.sol'
    out = [HDR + '\n' + imports(k, path, ('src/metatx/MtxPipelineLib.sol',) + WRAPPED_IMPORT(k))]
    for g in groups(k):
        ents = []
        for e in E['kinds'][k]:
            if e['kept'] or e['group'] != g:
                continue
            body = f'_{e["name"]}Body({", ".join(e["names"])})'
            od = '' if e['mut'] == 'pure' else ' onlyDelegated'
            ents.append(f'    function {e["name"]}({", ".join(e["params"])}) external{mut(e)}{od}{ret(e)} {{\n'
                        f'        {"return " if e["returns"] else ""}{body};\n    }}')
        pipe = '\n'.join(hook(n, True, False) for n in PIPE.get(g, ()))
        if pipe:
            pipe = '\n    // rule 4 (§4.1): `MtxPipelineLib`\'s code compiled in, its internal twins in place of the library call\n' + pipe
        out.append(f'''
/// @title {k}{g}: the body module {g} of {k} ({GROUP_DOC[g]}; T66b, spec 2026-11-09-t66b-library-organisation.md §4.2):
///        reached only by DELEGATECALL from the token's stubs (M2), no guard of its own (the stub's `_forward` holds it, M3),
///        storage only its core's (M6). UNAUDITED.
contract {k}{g} is {k}Core {{
    /// @param args the kind's own constructor argument (`""`, or `abi.encode(registryCodehash)` on a regulated kind; M1).
    constructor(address factory_, bytes memory args) {k}Core(factory_, args) {{}}

    function moduleGroup() external pure returns (uint8) {{
        return {GROUP_ID[g]};
    }}
{pipe}
''' + '\n\n'.join(ents) + '\n}\n')
    return path, ''.join(out)


KIND_ID = {k: i if i < 6 else i + 2 for i, k in enumerate(KFILE)}


def helper():
    """`script/KindModules.sol`: each kind's module artifacts in its stubs' order, and their deployment (tests, DeployBase)."""
    rows = []
    for k in KFILE:
        gs = groups(k)
        names = ', '.join(f'"{k}Modules.sol:{k}{g}"' for g in gs)
        rows.append(f'    if (kind == {KIND_ID[k]}) {{\n        n = new string[]({len(gs)});\n'
                    + ''.join(f'        n[{i}] = "{k}Modules.sol:{k}{g}";\n' for i, g in enumerate(gs)) + '        return n;\n    }')
    return 'script/KindModules.sol', HDR + '''
import {Vm} from "forge-std/Vm.sol";
import {ImplArgs, RegulatedImplArgs} from "../src/metatx/ITokenModule.sol";

/// @notice The body-module artifacts of token kind `kind` (0-5, 8-13), in the order its `implArgs` lists them.
function kindModuleNames(uint8 kind) pure returns (string[] memory n) {
''' + '\n'.join(rows) + '''
    revert("no such token kind");
}

/// @notice The `implArgs` of a release of `kind` whose modules are at `modules` (`coreArgs`: "" on 0-5, `abi.encode(bytes32)` on 8-13).
function kindImplArgs(uint8 kind, address[] memory modules, bytes memory coreArgs) pure returns (bytes memory) {
    if (kind >= 8) return abi.encode(RegulatedImplArgs(abi.decode(coreArgs, (bytes32)), modules));
    return abi.encode(ImplArgs(modules));
}

/// @notice Deploys `kind`'s modules for `factory` (each `vm.deployCode`, so a test contract does not embed their init code) and
///         returns them with the release's `implArgs`.
function deployKindModules(uint8 kind, address factory, bytes memory coreArgs)
    returns (address[] memory modules, bytes memory implArgs)
{
    Vm vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    string[] memory n = kindModuleNames(kind);
    modules = new address[](n.length);
    for (uint256 i; i < n.length; ++i) modules[i] = vm.deployCode(n[i], abi.encode(factory, coreArgs));
    implArgs = kindImplArgs(kind, modules, coreArgs);
}

/// @notice `deployKindModules`' `implArgs` alone (a test's `new <Kind>(factory, kindArgs(kind, factory, coreArgs))`).
function kindArgs(uint8 kind, address factory, bytes memory coreArgs) returns (bytes memory implArgs) {
    (, implArgs) = deployKindModules(kind, factory, coreArgs);
}

/// @notice Deploys the DEX's admin module D for `factory` (T66b §4.2) and returns it with the DEX release's `implArgs`.
function deployDexModules(address factory) returns (address[] memory modules, bytes memory implArgs) {
    Vm vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    modules = new address[](1);
    modules[0] = vm.deployCode("SCaaSDexAdmin.sol:SCaaSDexD", abi.encode(factory, bytes("")));
    implArgs = abi.encode(ImplArgs(modules));
}

/// @notice `deployDexModules`' `implArgs` alone (a test's `new SCaaSDex(factory, dexArgs(factory))`).
function dexArgs(address factory) returns (bytes memory implArgs) {
    (, implArgs) = deployDexModules(factory);
}
'''


def whole(top='MetaTokenBase', base=('MetaTokenBase', 'ERC20MetaTx', 'UAMetaTxBase', 'MetaTxBase', 'SaltedEIP712',
                                     'GovernanceBase'), src='src/metatx/MetaTokenBase.sol'):
    """`test/helpers/<top>Whole.sol` (tests only): `<top>` with every entry of its chain as one external function calling its
    body, the guard modifier as before the split: a monolithic token for the bases' own tests."""
    ents = []
    for e in E['kinds']['NormalToken']:
        if e['kept'] or e['decl'] not in base:
            continue
        g = f' {e["guard"]}' if e['guard'] else ''
        body = f'_{e["name"]}Body({", ".join(e["names"])})'
        ents.append(f'    function {e["name"]}({", ".join(e["params"])}) external{mut(e)}{g}{ret(e)} {{\n'
                    f'        {"return " if e["returns"] else ""}{body};\n    }}')
    path = f'test/helpers/{top}Whole.sol'
    return path, HDR + '\n' + ''.join(f'import "{rel(path, f)}";\n' for f in sorted(set(E['imports'].values()) | {src})) + f'''
/// @notice Tests only: `{top}` with its chain's entries in one contract (no modules), for a fixture.
abstract contract {top}Whole is {top} {{
''' + '\n\n'.join(ents) + '\n}\n'


bad = 0
for path, txt in (helper(), whole(), whole('ERC20MetaTx', ('ERC20MetaTx', 'UAMetaTxBase', 'MetaTxBase', 'SaltedEIP712'),
                                                        'src/metatx/ERC20MetaTx.sol')):
    if CHECK:
        if not os.path.exists(path) or open(path).read() != txt:
            print('differs:', path)
            bad += 1
    else:
        open(path, 'w').write(txt)
for k in KFILE:
    for path, txt in (face(k), modules(k)):
        if CHECK:
            if not os.path.exists(path) or open(path).read() != txt:
                print('differs:', path)
                bad += 1
        else:
            open(path, 'w').write(txt)
print('faces', 'checked' if CHECK else 'written', len(KFILE) * 2 + 3, 'files', bad, 'differ')
sys.exit(1 if bad else 0)
