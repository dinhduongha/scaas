#!/usr/bin/env python3
"""CTR-TOK-24 size gate over `forge build src --sizes --json`.

Limits: token implementations (TOKENS) 20,480 B, every other contract 24,576 B (EIP-170), init code 49,152 B
(EIP-3860). A contract named in the baseline may exceed its limit but never its recorded size (a ratchet: it can only
shrink); `<name>.init` does the same for the init code. A baseline entry that now fits is reported, so it gets removed.
forge's report leaves out a library with no view function in its ABI, so every library of `src/` is measured from its
artifact (`out/` next to the baseline), known by solc's call protection at the head of its runtime. A library named in the
baseline keeps that entry as a ratchet even when it fits; the "remove it" note is for the contracts over their limit.

usage: size_gate.py <sizes.json> <size-baseline.json>     exit 1 on a violation
"""
import glob
import json
import os
import sys

TOKENS = {'NormalToken', 'WrappedToken', 'NormalZetherToken', 'WrappedZetherToken',
          'NormalPqzToken', 'WrappedPqzToken'}
TOKEN_LIMIT, EIP170, EIP3860 = 20_480, 24_576, 49_152
LIBRARY_HEAD = '0x73' + '00' * 20 + '3014'  # PUSH20 <self, filled in at deployment> ADDRESS EQ


def check(sizes, baseline, libraries=()):
    errs, notes = [], []
    for name, s in sorted(sizes.items()):
        rt, init = s['runtime_size'], s['init_size']
        limit = TOKEN_LIMIT if name in TOKENS else EIP170
        allowed = baseline.get(name)
        allowed_init = baseline.get(f'{name}.init')
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
        elif allowed is not None and rt <= limit and name not in libraries:
            notes.append(f'{name}: fits ({rt} <= {limit}); remove it from the baseline')
    return errs, notes


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
    baseline = {k: v for k, v in json.load(open(argv[2])).items() if not k.startswith('_')}
    libraries = library_sizes(os.path.dirname(os.path.abspath(argv[2])))
    sizes.update(libraries)
    missing = {k.removesuffix('.init') for k in baseline} - set(sizes)
    errs, notes = check(sizes, baseline, libraries)
    errs += [f'{name}: in the baseline, no such contract' for name in sorted(missing)]
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
