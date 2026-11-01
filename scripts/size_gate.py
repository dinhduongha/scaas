#!/usr/bin/env python3
"""CTR-TOK-24 size gate over `forge build src --sizes --json`.

Limits: token implementations (TOKENS) 20,480 B, every other contract 24,576 B (EIP-170), init code 49,152 B
(EIP-3860). A contract named in the baseline may exceed its limit but never its recorded size (a ratchet: it can only
shrink); `<name>.init` does the same for the init code. A baseline entry that now fits is reported, so it gets removed.
forge's report leaves out a library with no view function in its ABI: one named in the baseline is measured from its
artifact (`out/` next to the baseline), so `UARegistryLib` keeps its ratchet.

usage: size_gate.py <sizes.json> <size-baseline.json>     exit 1 on a violation
"""
import json
import os
import sys

TOKENS = {'NormalToken', 'WrappedToken', 'NormalZetherToken', 'WrappedZetherToken',
          'NormalPqzToken', 'WrappedPqzToken'}
TOKEN_LIMIT, EIP170, EIP3860 = 20_480, 24_576, 49_152


def check(sizes, baseline):
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
        elif allowed is not None and rt <= limit:
            notes.append(f'{name}: fits ({rt} <= {limit}); remove it from the baseline')
    return errs, notes


def artifact_sizes(out, name):
    """Sizes from `out/<name>.sol/<name>.json`, as forge's report gives them (a link placeholder counts as its 20 bytes)."""
    j = json.load(open(os.path.join(out, f'{name}.sol', f'{name}.json')))
    length = lambda o: (len(o['object']) - 2) // 2  # noqa: E731
    return {'runtime_size': length(j['deployedBytecode']), 'init_size': length(j['bytecode'])}


def main(argv):
    sizes = json.load(open(argv[1]))
    baseline = {k: v for k, v in json.load(open(argv[2])).items() if not k.startswith('_')}
    out = os.path.join(os.path.dirname(os.path.abspath(argv[2])), 'out')
    for name in {k.removesuffix('.init') for k in baseline}:
        if name not in sizes:
            sizes[name] = artifact_sizes(out, name)
    errs, notes = check(sizes, baseline)
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
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, 'L.sol'))
            json.dump({'bytecode': {'object': '0x' + '00' * 9}, 'deployedBytecode': {'object': '0x' + '00' * 7}},
                      open(os.path.join(root, 'L.sol', 'L.json'), 'w'))
            assert artifact_sizes(root, 'L') == s(7, 9)
        print('size gate self-test ok')
        sys.exit(0)
    sys.exit(main(sys.argv))
