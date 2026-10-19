import re, subprocess, sys
# per function of a wasm32 `--emit=asm` listing: the 64-bit divisions / remainders (variable-latency on the engines)
fn, out = None, {}
for line in open(sys.argv[1]):
    m = re.match(r'^([A-Za-z_$.][\w$.]*):\s*$', line)
    if m and not m.group(1).startswith('.L'):
        fn = m.group(1)
        continue
    m = re.search(r'\b(i64\.(?:div|rem)_[su])\b', line)
    if m and fn:
        out.setdefault(fn, {}).setdefault(m.group(1), 0)
        out[fn][m.group(1)] += 1
names = list(out)
dem = subprocess.run(['c++filt'], input='\n'.join(names), capture_output=True, text=True).stdout.split('\n')
for n, d in zip(names, dem):
    d = re.sub(r'::h[0-9a-f]{16}$', '', d)
    print(d, out[n])
