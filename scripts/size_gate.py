#!/usr/bin/env python3
"""CTR-TOK-24 size gate over `forge build src --sizes --json`.

Limits: token implementations (TOKENS) 20,480 B, every other contract 24,576 B (EIP-170), init code 49,152 B
(EIP-3860). A contract named in the baseline may exceed its limit but never its recorded size (a ratchet: it can only
shrink); `<name>.init` does the same for the init code. A baseline entry that now fits is reported, so it gets removed.
forge's report leaves out a library with no view function in its ABI, so every library of `src/` is measured from its
artifact (`out/` next to the baseline), known by solc's call protection at the head of its runtime. A library named in the
baseline keeps that entry as a ratchet even when it fits; the "remove it" note is for the contracts over their limit.

CTR-GOV-19: above every limit and every baseline row sits the ceiling of the SCaaS testnet, `maxCodeSize` 0x20000 with
EIP-7954 left out: runtime 131,072 B, init code 262,144 B (2 x maxCodeSize, measured without EIP-7954,
`pqz-core/nethermind/runs/2026-11-03-code-size-probe.txt`).
T66b (spec 2026-11-09-t66b-library-organisation.md §2): the size window is closed (no contract above 65,536 B; the
`_above64KiB` pin is gone). Every contract has a form, `release` (a token kind's face, the DEX), `module` (a body module,
script/KindModules.sol's list and the DEX's D), `library` or `plain`, and the form's T-1 line (the 60 M deploy line in runtime
bytes) is an error above it, its T-2 line (57 M) a notice: release 35,386 / 33,594, module 35,570 / 33,780, library 35,694 /
33,903, plain 35,286 / 33,516 (the registry's fit). Every baseline row names its form in `_forms` (a pin: a row whose form
differs from the computed one, or has none, is an error), and a row with a form stays a ratchet even when it fits.

usage: size_gate.py <sizes.json> <size-baseline.json>     exit 1 on a violation
"""
import glob
import json
import os
import sys

TOKENS = {'NormalToken', 'WrappedToken', 'NormalZetherToken', 'WrappedZetherToken',
          'NormalPqzToken', 'WrappedPqzToken'}
TOKEN_LIMIT, EIP170, EIP3860 = 20_480, 24_576, 49_152
CEILING, INIT_CEILING, EIP7954 = 131_072, 262_144, 65_536
LIBRARY_HEAD = '0x73' + '00' * 20 + '3014'  # PUSH20 <self, filled in at deployment> ADDRESS EQ
LINES = {'release': (35_386, 33_594), 'module': (35_570, 33_780), 'library': (35_694, 33_903), 'plain': (35_286, 33_516)}


def check(sizes, baseline, libraries=(), forms=None):
    """`forms` (name -> form): the T-1 / T-2 lines of each contract's form, and a formed row kept as a ratchet."""
    errs, notes = [], []
    forms = forms or {}
    for name, s in sorted(sizes.items()):
        rt, init = s['runtime_size'], s['init_size']
        limit = TOKEN_LIMIT if name in TOKENS else EIP170
        allowed = baseline.get(name)
        allowed_init = baseline.get(f'{name}.init')
        if rt > CEILING:
            errs.append(f'{name}: runtime {rt} > {CEILING} (the ceiling, CTR-GOV-19)')
        if name in forms:
            t1, t2 = LINES[forms[name]]
            if rt > t1:
                errs.append(f'{name}: runtime {rt} > {t1} (the {forms[name]} T-1 line, 60 M)')
            elif rt > t2:
                notes.append(f'{name}: runtime {rt} > {t2} (the {forms[name]} T-2 line, 57 M; at most {t1})')
        if init > INIT_CEILING:
            errs.append(f'{name}: init {init} > {INIT_CEILING} (the init ceiling, CTR-GOV-19)')
        if init > EIP3860 and allowed_init is None:
            errs.append(f'{name}: init {init} > {EIP3860} (EIP-3860)')
        elif allowed_init is not None and init > allowed_init:
            errs.append(f'{name}: init {init} > baseline {allowed_init} (it may only shrink)')
        elif allowed_init is not None and init <= EIP3860:
            notes.append(f'{name}: init fits ({init} <= {EIP3860}); remove {name}.init from the baseline')
        if rt > limit and allowed is None:
            errs.append(f'{name}: runtime {rt} > {limit}')
        elif allowed is not None and rt > allowed:
            errs.append(f'{name}: runtime {rt} > baseline {allowed} (it may only shrink)')
        elif allowed is not None and rt <= limit and name not in libraries and name not in forms:
            notes.append(f'{name}: fits ({rt} <= {limit}); remove it from the baseline')
    return errs, notes


def forms_of(root, sizes, libraries):
    """Each contract's form: a library by its head, a module by script/KindModules.sol's list (and the DEX's D), a release
    by its kind's modules file (`<Kind>Modules.sol` -> `<Kind>`) or the DEX, else plain."""
    import re
    src = open(os.path.join(root, 'script', 'KindModules.sol')).read()
    mods = set(re.findall(r'"\w+\.sol:(\w+)"', src))
    rel = {f.removesuffix('Modules') for f in re.findall(r'"(\w+)\.sol:\w+"', src) if f.endswith('Modules')} | {'SCaaSDex'}
    return {n: 'library' if n in libraries else 'module' if n in mods else 'release' if n in rel else 'plain' for n in sizes}


def forms_errors(rows, pinned, computed):
    """`_forms` names every row's form, the computed one."""
    if pinned is None:
        return ['_forms: missing from the baseline']
    errs = [f'{n}: a baseline row without a form in _forms' for n in sorted(rows) if n not in pinned]
    errs += [f'{n}: _forms says {f}, the contract is a {computed.get(n)}' for n, f in sorted(pinned.items())
             if computed.get(n) != f]
    return errs


def library_sizes(root):
    """Sizes of every library of `<root>/src` from `<root>/out/<file>.sol/<name>.json`, as forge's report gives them (a link
    placeholder counts as its 20 bytes)."""
    length = lambda o: (len(o['object']) - 2) // 2  # noqa: E731
    sizes = {}
    for sol in glob.glob(os.path.join(root, 'src', '**', '*.sol'), recursive=True):
        for art in glob.glob(os.path.join(root, 'out', os.path.basename(sol), '*.json')):
            j = json.load(open(art))
            if j['deployedBytecode']['object'].startswith(LIBRARY_HEAD):
                name = os.path.basename(art)[:-len('.json')]
                sizes[name] = {'runtime_size': length(j['deployedBytecode']), 'init_size': length(j['bytecode'])}
    return sizes


def main(argv):
    sizes = json.load(open(argv[1]))
    raw = json.load(open(argv[2]))
    baseline = {k: v for k, v in raw.items() if not k.startswith('_')}
    root = os.path.dirname(os.path.abspath(argv[2]))
    libraries = library_sizes(root)
    sizes.update(libraries)
    forms = forms_of(root, sizes, libraries) if os.path.exists(os.path.join(root, 'script', 'KindModules.sol')) else {}
    missing = {k.removesuffix('.init') for k in baseline} - set(sizes)
    errs, notes = check(sizes, baseline, libraries, forms)
    errs += [f'{name}: in the baseline, no such contract' for name in sorted(missing)]
    if forms:
        errs += forms_errors({k for k in baseline if not k.endswith('.init')}, raw.get('_forms'), forms)
    big = [n for n in sizes if sizes[n]['runtime_size'] > EIP7954]
    errs += [f'{n}: runtime {sizes[n]["runtime_size"]} > {EIP7954} (the size window is closed, T66b)' for n in sorted(big)]
    print('largest per form: ' + ', '.join(f'{f} ' + max(((sizes[n]['runtime_size'], n) for n in sizes if forms.get(n) == f),
                                                         default=(0, '-'))[1] for f in LINES))
    for n in notes:
        print('note:', n)
    for e in errs:
        print('error:', e)
    print(f'size gate: {len(errs)} error(s), {len(sizes)} contracts')
    return 1 if errs else 0


if __name__ == '__main__':
    if sys.argv[1:] == ['--self-test']:
        import tempfile
        s = lambda rt, init=0: {'runtime_size': rt, 'init_size': init}
        assert check({'A': s(24_576)}, {}) == ([], [])
        assert check({'A': s(24_577)}, {})[0]
        assert check({'NormalToken': s(20_481)}, {})[0]
        assert check({'WrappedZetherToken': s(20_481)}, {})[0]
        assert check({'X': s(26_000)}, {'X': 26_000}) == ([], [])
        assert check({'X': s(26_001)}, {'X': 26_000})[0]
        assert check({'X': s(20_000)}, {'X': 26_000})[1]
        assert check({'A': s(1, 49_153)}, {})[0]
        assert check({'A': s(1, 50_000)}, {'A.init': 50_000}) == ([], [])
        assert check({'A': s(1, 50_001)}, {'A.init': 50_000})[0]
        assert check({'A': s(1, 40_000)}, {'A.init': 50_000})[1]
        assert check({'L': s(9_000)}, {'L': 9_000}, {'L'}) == ([], [])
        assert check({'L': s(9_001)}, {'L': 9_000}, {'L'})[0]
        assert check({'L': s(9_000)}, {'L': 9_000})[1]
        # CTR-GOV-19: the ceiling binds with a baseline row too, runtime and init
        assert check({'X': s(131_072)}, {'X': 131_072}) == ([], [])
        assert check({'X': s(131_073)}, {'X': 131_073})[0]
        assert check({'A': s(1, 262_144)}, {'A.init': 262_144}) == ([], [])
        assert check({'A': s(1, 262_145)}, {'A.init': 262_145})[0]
        # T66b: the form's T-1 line is an error, its T-2 line a notice; a formed row stays a ratchet when it fits
        assert check({'M': s(35_570)}, {'M': 35_570}, (), {'M': 'module'})[0] == []
        assert check({'M': s(35_571)}, {'M': 35_571}, (), {'M': 'module'})[0]
        assert check({'M': s(33_781)}, {'M': 33_781}, (), {'M': 'module'})[1]
        assert check({'R': s(20_000)}, {'R': 20_000}, (), {'R': 'release'}) == ([], [])
        assert check({'R': s(35_387)}, {'R': 35_387}, (), {'R': 'release'})[0]
        assert check({'P': s(35_287)}, {'P': 35_287}, (), {'P': 'plain'})[0]
        assert check({'L': s(35_695)}, {'L': 35_695}, {'L'}, {'L': 'library'})[0]
        assert forms_errors({'A'}, {'A': 'module'}, {'A': 'module'}) == []
        assert forms_errors({'A'}, {}, {'A': 'module'})
        assert forms_errors({'A'}, {'A': 'plain'}, {'A': 'module'})
        assert forms_errors({'A'}, None, {})
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, 'src', 'a'))
            open(os.path.join(root, 'src', 'a', 'L.sol'), 'w').close()
            os.makedirs(os.path.join(root, 'out', 'L.sol'))
            for name, head in (('L', LIBRARY_HEAD), ('C', '0x6080')):
                json.dump({'bytecode': {'object': '0x' + '00' * 40}, 'deployedBytecode': {'object': head + '00' * 2}},
                          open(os.path.join(root, 'out', 'L.sol', f'{name}.json'), 'w'))
            assert library_sizes(root) == {'L': s(25, 40)}
        print('size gate self-test ok')
        sys.exit(0)
    sys.exit(main(sys.argv))
