#!/usr/bin/env python3
"""CTR-TOK-24 size gate over `forge build src --sizes --json`.

Limits: token implementations (TOKENS) 20,480 B, every other contract 24,576 B (EIP-170), init code 49,152 B
(EIP-3860). A contract named in the baseline may exceed its limit but never its recorded size (a ratchet: it can only
shrink); `<name>.init` does the same for the init code. A baseline entry that now fits is reported, so it gets removed.

usage: size_gate.py <sizes.json> <size-baseline.json>     exit 1 on a violation
"""
import json
import sys

TOKENS = {'NoUnderlyingToken', 'UnderlyingToken', 'NoUnderlyingZetherToken', 'UnderlyingZetherToken'}
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


def main(argv):
    sizes = json.load(open(argv[1]))
    baseline = {k: v for k, v in json.load(open(argv[2])).items() if not k.startswith('_')}
    errs, notes = check(sizes, baseline)
    for n in notes:
        print('note:', n)
    for e in errs:
        print('error:', e)
    print(f'size gate: {len(errs)} error(s), {len(sizes)} contracts')
    return 1 if errs else 0


if __name__ == '__main__':
    if sys.argv[1:] == ['--self-test']:
        s = lambda rt, init=0: {'runtime_size': rt, 'init_size': init}
        assert check({'A': s(24_576)}, {}) == ([], [])
        assert check({'A': s(24_577)}, {})[0]
        assert check({'NoUnderlyingToken': s(20_481)}, {})[0]
        assert check({'UnderlyingZetherToken': s(20_481)}, {})[0]
        assert check({'X': s(26_000)}, {'X': 26_000}) == ([], [])
        assert check({'X': s(26_001)}, {'X': 26_000})[0]
        assert check({'X': s(20_000)}, {'X': 26_000})[1]
        assert check({'A': s(1, 49_153)}, {})[0]
        assert check({'A': s(1, 50_000)}, {'A.init': 50_000}) == ([], [])
        assert check({'A': s(1, 50_001)}, {'A.init': 50_000})[0]
        assert check({'A': s(1, 40_000)}, {'A.init': 50_000})[1]
        print('size gate self-test ok')
        sys.exit(0)
    sys.exit(main(sys.argv))
