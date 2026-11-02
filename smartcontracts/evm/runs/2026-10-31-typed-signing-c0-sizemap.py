#!/usr/bin/env python3
"""typed-signing C0 Step 2b: runtime bytes per source function of a built contract, from the solc source map.

Every instruction is charged to the innermost `function` / `modifier` of the source range the map gives it; ranges at
contract level are the external dispatcher, unmapped ones (solc's Yul utilities: the ABI coders) `<abi utilities>`. The
optimizer moves code, so a shared block lands on one of its users: read it as a breakdown, not an exact count.

usage (from smartcontracts/evm, after `forge build src`):
    sizemap.py <Contract> [lines]              top functions, totals per file
    sizemap.py --utils <src path> <Contract> [lines]
                                               solc's own per-routine sizes (functionDebugData entry points), which name
                                               the Yul utilities; forge does not keep that output, so this runs solc
    sizemap.py --self-test
"""
import glob
import json
import os
import re
import subprocess
import sys
from collections import Counter

FN = re.compile(rb'\b(function|modifier)\s+(\w+)|\b(constructor|receive|fallback)\s*\(')


def entries(smap):
    """Expand `s:l:f:j:m;…` (an empty field repeats the previous one)."""
    s = l = f = 0
    for item in smap.split(';'):
        p = item.split(':')
        if len(p) > 0 and p[0] != '': s = int(p[0])
        if len(p) > 1 and p[1] != '': l = int(p[1])
        if len(p) > 2 and p[2] != '': f = int(p[2])
        yield s, l, f


def instructions(code):
    """Byte length of each instruction of `code` (a PUSHn carries its n bytes)."""
    i = 0
    while i < len(code):
        n = 1 + (code[i] - 0x5f if 0x60 <= code[i] <= 0x7f else 0)
        yield n
        i += n


def ranges(text):
    """(start, end, name) of every function / modifier of a source, brace-matched on the raw bytes."""
    out = []
    for m in FN.finditer(text):
        i = text.find(b'{', m.end())
        semi = text.find(b';', m.end())
        if i < 0 or (0 <= semi < i):
            continue  # a declaration
        depth, j = 0, i
        while j < len(text):
            depth += {'{': 1, '}': -1}.get(chr(text[j]), 0)
            if depth == 0:
                break
            j += 1
        out.append((m.start(), j + 1, (m.group(1) or m.group(3)).decode()[:1] + ':' + (m.group(2) or m.group(3)).decode()))
    return out


def owner(table, s, l):
    best = None
    for a, b, name in table:
        if a <= s and s + l <= b and (best is None or b - a < best[1] - best[0]):
            best = (a, b, name)
    return best[2] if best else '<dispatch / contract level>'


def run(name):
    art = json.load(open(f'out/{name}.sol/{name}.json')) if os.path.exists(f'out/{name}.sol/{name}.json') else None
    if art is None:
        art = json.load(open(glob.glob(f'out/*/{name}.json')[0]))
    dep = art['deployedBytecode']
    code = bytes.fromhex(re.sub(r'__\$[0-9a-f]{34}\$__', '0' * 40, dep['object'][2:]))
    ids = None
    for bi in sorted(glob.glob('out/build-info/*.json'), key=os.path.getmtime, reverse=True):
        m = json.load(open(bi))['source_id_to_path']
        if str(art['id']) in m and any(n in m[str(art['id'])] for n in ('src/', 'lib/')):
            ids = m
            break
    tables = {}
    by_fn, by_file = Counter(), Counter()
    smap = list(entries(dep['sourceMap']))
    pc = 0
    for (n, (s, l, f)) in zip(instructions(code), smap):
        pc += n
        path = ids.get(str(f)) if f >= 0 else None
        if path is None:
            by_fn['<abi utilities>'] += n
            by_file['<abi utilities>'] += n
            continue
        if f not in tables:
            tables[f] = ranges(open(path, 'rb').read())
        short = os.path.basename(path)
        by_fn[f'{short} {owner(tables[f], s, l)}'] += n
        by_file[short] += n
    return len(code), by_fn, by_file, len(code) - pc


def utils(path, name, top):
    """Bytes per routine: the distance between the routines' entry points in the runtime."""
    prof = open('foundry.toml').read()
    rem = re.findall(r'"([^"=]+/=[^"]+)"', prof)
    runs = int(os.environ.get('RUNS', '200'))
    req = {'language': 'Solidity', 'sources': {path: {'urls': [path]}}, 'settings': {
        'remappings': rem, 'evmVersion': 'amsterdam', 'experimental': True,
        'optimizer': {'enabled': True, 'runs': runs},
        'outputSelection': {path: {name: ['evm.deployedBytecode.functionDebugData', 'evm.deployedBytecode.object']}}}}
    solc = os.path.expanduser('~/.local/share/svm/0.8.37/solc-0.8.37')
    r = subprocess.run([solc, '--standard-json', '--base-path', '.', '--allow-paths', '.,lib,' + os.path.realpath('lib/openzeppelin-contracts')],
                       input=json.dumps(req), capture_output=True, text=True)
    out = json.loads(r.stdout)
    errs = [e['formattedMessage'] for e in out.get('errors', []) if e['severity'] == 'error']
    if errs:
        sys.exit('\n'.join(errs))
    dep = out['contracts'][path][name]['evm']['deployedBytecode']
    pts = sorted((v['entryPoint'], k) for k, v in dep['functionDebugData'].items() if v.get('entryPoint'))
    end = len(dep['object']) // 2
    sizes = sorted(((b[0] if b else end) - a[0], a[1]) for a, b in zip(pts, pts[1:] + [None]))[::-1]
    head = pts[0][0] if pts else end
    print(f'{name}: {end} B; {head} B before the first routine (dispatcher + external function bodies)')
    abi = sum(n for n, k in sizes if not k.startswith('@'))
    print(f'{sum(n for n, _ in sizes)} B in {len(sizes)} routines; {abi} B of them Yul utilities')
    for n, k in sizes[:top]:
        print(f'{n:7} {k}')
    return 0


def main(argv):
    if len(argv) > 3 and argv[1] == '--utils':
        return utils(argv[2], argv[3], int(argv[4]) if len(argv) > 4 else 60)
    if argv[1:] == ['--self-test']:
        assert list(entries('1:2:3:-:0;;4')) == [(1, 2, 3), (1, 2, 3), (4, 2, 3)]
        assert list(instructions(bytes([0x60, 1, 0x00, 0x61, 1, 2]))) == [2, 1, 3]
        t = ranges(b'contract C { modifier m() { _; } function f() public { if (x) { y; } } function g() external; }')
        assert [x[2] for x in t] == ['m:m', 'f:f'] and owner(t, 13, 5) == 'm:m'
        print('sizemap self-test ok')
        return 0
    total, by_fn, by_file, tail = run(argv[1])
    top = int(argv[2]) if len(argv) > 2 else 60
    print(f'{argv[1]}: {total} B runtime ({tail} B unmapped tail: metadata)')
    print('-- per file')
    for k, v in by_file.most_common():
        print(f'{v:7} {k}')
    print('-- per function')
    for k, v in by_fn.most_common(top):
        print(f'{v:7} {k}')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
