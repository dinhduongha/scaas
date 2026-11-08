#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T13 (plan step 5): the plan's three mutants of the bytes32 id display, one at a time on a clean tree, in every
implementation with its own logic: clientkeys (the reference), ua-rs (the four wrappers only pass its text through) and the
native ports ua-py, ua-go, ua-cs, ua-dart. Mutants: `high-bit-as-address` (the native-space check skips the top byte, so an id
with bit 255 set over a padded address is shown as that address), `checksum-dropped` (the address in lower case),
`table-off-by-one` (one derived row of the language's kind table carries the next row's name: 0x0131 named fndsa512).
After each, the package's id_display test runs (heavy ones through scripts/capped), then the file is restored with
`git checkout -- <file>`. From the repo root: python3 smartcontracts/evm/runs/2026-11-04-ua-mtx-merge/t13_mutants.py
Writes smartcontracts/evm/runs/2026-11-04-ua-mtx-merge-t13-mutants.txt (mutant | tests that went red | rc); full output in
git-ignored mutant-t13-<name>.log beside this script. A mutant that does not compile is COMPILE ERROR (it kills nothing)."""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..', '..', '..'))
CAPPED = os.path.join(ROOT, 'scripts', 'capped')
FOUNDRY = os.path.expanduser('~/.foundry/bin')

# package: (directory, test command, failing-test regex, compile-error regex)
PKG = {
    'clientkeys': ('clients/clientkeys', [CAPPED, 'node', '--test', 'test/ua.test.js'], r'^✖ (.*?) \([\d.]+m?s\)$', r'SyntaxError'),
    'ua-rs': ('clients/ua-rs', [CAPPED, 'cargo', 'test', '-j2', '--test', 'vectors', 'id_display_rows'],
              r'^test (\S+) \.\.\. FAILED$', r'could not compile'),
    'ua-py': ('clients/ua-py', ['python3', '-m', 'unittest', '-v', 'tests.test_vectors'], r'^(?:FAIL|ERROR): (\S+)', r'SyntaxError'),
    'ua-go': ('clients/ua-go', [CAPPED, 'go', 'test', '-count=1', '-run', 'TestIDDisplayRows', './...'], r'^--- FAIL: (\S+)',
              r'build failed'),
    'ua-cs': ('clients/ua-cs/Scaas.Ua.Tests', [CAPPED, 'dotnet', 'test', '--filter', 'IdDisplayRows'], r'^\s+Failed (\S+) \[',
              r'error CS\d+'),
    'ua-dart': ('clients/ua-dart', [CAPPED, 'dart', 'test', '-r', 'expanded', '--plain-name', 'id_display.json rows'],
                r'\+\d+ -\d+: (.*?) \[E\]', r'Error: '),
}
EDITS = {  # mutant -> package -> (file, anchor, replacement)
    'high-bit-as-address': {
        'clientkeys': ('src/ua.js', "  if (h.startsWith('0'.repeat(24))) return { kind: 'native'",
                       "  if (h.slice(2).startsWith('0'.repeat(22))) return { kind: 'native'"),
        'ua-rs': ('src/lib.rs', "    if h.as_bytes()[..24].iter().all(|c| *c == b'0') {", "    if h.as_bytes()[2..24].iter().all(|c| *c == b'0') {"),
        'ua-py': ('scaas_ua/__init__.py', "    if h.startswith('0' * 24):\n        a = h[24:]", "    if h[2:].startswith('0' * 22):\n        a = h[24:]"),
        'ua-go': ('ua.go', '\tif strings.HasPrefix(h, strings.Repeat("0", 24)) {\n\t\ta := ',
                  '\tif strings.HasPrefix(h[2:], strings.Repeat("0", 22)) {\n\t\ta := '),
        'ua-cs': ('../Scaas.Ua/Ua.cs', "        if (h.StartsWith(new string('0', 24), StringComparison.Ordinal))\n        {\n            var a",
                  "        if (h[2..].StartsWith(new string('0', 22), StringComparison.Ordinal))\n        {\n            var a"),
        'ua-dart': ('lib/src/ua.dart', "  if (h.startsWith('0' * 24)) {\n    final a", "  if (h.substring(2).startsWith('0' * 22)) {\n    final a"),
    },
    'checksum-dropped': {
        'clientkeys': ('src/ua.js', "address: checksumAddress(h.slice(24)) }", "address: `0x${h.slice(24)}` }"),
        'ua-rs': ('src/lib.rs', 'address: checksum_address(&h[24..]) }', 'address: format!("0x{}", &h[24..]) }'),
        'ua-py': ('scaas_ua/__init__.py', "        return '0x' + ''.join(c.upper() if int(d[i], 16) >= 8 else c for i, c in enumerate(a))",
                  "        return '0x' + a"),
        'ua-go': ('ua.go', "\t\t\tif c >= 'a' && d[i/2]", "\t\t\tif false && c >= 'a' && d[i/2]"),
        'ua-cs': ('../Scaas.Ua/Ua.cs', 'a[i] = char.ToUpperInvariant(a[i]);', 'a[i] = char.ToLowerInvariant(a[i]);'),
        'ua-dart': ('lib/src/ua.dart', '? a[i].toUpperCase() : a[i]', '? a[i] : a[i]'),
    },
    'table-off-by-one': {
        'clientkeys': ('src/ua.js', "  [0x0131, 'mldsa65', [1952], 'mldsa65'],", "  [0x0131, 'fndsa512', [1952], 'mldsa65'],"),
        'ua-rs': ('src/lib.rs', '    derived(0x0131, "mldsa65", ', '    derived(0x0131, "fndsa512", '),
        'ua-py': ('scaas_ua/__init__.py', "    (0x0131, 'mldsa65', ", "    (0x0131, 'fndsa512', "),
        'ua-go': ('ua.go', '\t{0x0131, "mldsa65", ', '\t{0x0131, "fndsa512", '),
        'ua-cs': ('../Scaas.Ua/Ua.cs', '        new(0x0131, "mldsa65", ', '        new(0x0131, "fndsa512", '),
        'ua-dart': ('lib/src/table.dart', "  Kind(0x0131, 'mldsa65', ", "  Kind(0x0131, 'fndsa512', "),
    },
}


def git(*a):
    return subprocess.run(['git', '-C', ROOT, *a], capture_output=True, text=True)


def main():
    rows = ['mutant | tests that went red | rc']
    env = dict(os.environ, PATH=FOUNDRY + os.pathsep + os.environ['PATH'])
    for mutant, per in EDITS.items():
        for pkg, (rel, a, b) in per.items():
            d, cmd, red_re, compile_re = PKG[pkg]
            path = os.path.normpath(os.path.join(ROOT, d, rel))
            if git('diff', '--quiet', '--', path).returncode:
                sys.exit('%s is not clean' % path)
            s = open(path).read()
            assert s.count(a) == 1, (mutant, pkg, s.count(a))
            open(path, 'w').write(s.replace(a, b, 1))
            try:
                p = subprocess.run(cmd, cwd=os.path.join(ROOT, d), capture_output=True, text=True, env=env)
            finally:
                git('checkout', '--', path)
                if pkg == 'ua-cs':
                    subprocess.run(['dotnet', 'build-server', 'shutdown'], capture_output=True)
            log = re.sub(r'\x1b\[[0-9;]*m', '', p.stdout + p.stderr)  # dart colours its reporter
            name = '%s-%s' % (pkg, mutant)
            open(os.path.join(HERE, 'mutant-t13-%s.log' % name), 'w').write(log)
            red = sorted(set(re.findall(red_re, log, re.M)))
            if re.search(compile_re, log):
                red = ['COMPILE ERROR']
            rows.append('%s | %s | %d' % (name, '; '.join(red) or 'NONE (a finding)', p.returncode))
            print(rows[-1], flush=True)
            if git('diff', '--quiet', '--', path).returncode:
                sys.exit('%s not restored' % path)
    open(os.path.join(HERE, '..', '2026-11-04-ua-mtx-merge-t13-mutants.txt'), 'w').write('\n'.join(rows) + '\n')


if __name__ == '__main__':
    main()
