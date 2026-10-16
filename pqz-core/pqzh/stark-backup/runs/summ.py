"""Summarise pqzh_bench / run_wasm JSON lines: python3 runs/summ.py FILE..."""
import json, sys
for f in sys.argv[1:]:
    r = {}
    for l in open(f):
        d = json.loads(l)
        rel = d.get('rel')
        if not rel: continue
        e = r.setdefault(rel, {})
        if 'proof_bytes' in d: e['B'] = d['proof_bytes']
        t = d.get('timing')
        if t == 'prove': e['prove_s'] = round(d['stats']['p50_ms'] / 1e3, 2); e['heapMB'] = d.get('peak_heap_mb', d.get('memory_mib'))
        if t == 'verify_honest': e['vh_p50'] = d['stats']['p50_ms']; e['vh_p99'] = d['stats']['p99_ms']
        if t == 'verify_adversarial': e['va_p99'] = d['stats']['p99_ms']; e['va_n'] = d['stats']['n']
        if 'accepted' in d: e['acc'] = e.get('acc', 0) + d['accepted']; e['panics'] = e.get('panics', 0) + d['panics']
        if 'memory_mib' in d and 'wasm' in f: e['wasm_mib'] = d['memory_mib']
    print(f, json.dumps(r))
