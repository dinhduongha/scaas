"""Summarise pqzh_whir JSON-ish lines (Rust Debug for Option / tuples): python3 runs/whir-summ.py FILE..."""
import re, sys
for f in sys.argv[1:]:
    for l in open(f):
        g = lambda k: re.search(r'"%s": ([^,}]+)' % k, l).group(1)
        b = re.search(r'"binding": Some\(\("([^"]+)", ([0-9.]+)', l)
        st = lambda k: re.search(r'"%s": \{"n": \d+, "p50_ms": ([0-9.]+), "p99_ms": ([0-9.]+)' % k, l).groups()
        print(f.split('/')[-1], g('rel'), 'ext', g('ext'), 'rate', g('rate'), 'fold', g('fold'), 'pow', g('pow'), 'tgt', g('target'),
              'bits', g('bits')[5:11], 'bind', b.group(1) if b else None, 'B', g('proof_bytes'), 'prove_ms', st('prove')[0],
              'heapMB', g('peak_heap_mb'), 'vh p50/p99', st('verify_honest'), 'va p99', st('verify_adversarial')[1],
              'acc', g('accepted'), '/', g('adv_cases'))
