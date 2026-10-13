"""Worst-case proof bytes over query positions (pqzh-zk-ext5.md §4): each Merkle multiproof part of a measured
breakdown is scaled by (no-sharing sibling count) / (mean pruned sibling count over random query sets).
Input trees have depth log2(largest committed height) + log_blowup; FRI layer i has depth d0 - sum of the log arities
folded so far (the arity of a layer read from its sibling bytes: (arity - 1) extension elements per query).
  python3 runs/worstcase.py FILE.jsonl QUERIES LOG_BLOWUP EXT_DEGREE ZK(0/1)"""
import json, random, sys

def pruned(d, q, trials=200):
    tot = 0
    for _ in range(trials):
        nodes = set(random.sample(range(1 << d), q)) if q < (1 << d) else set(range(1 << d))
        s = 0
        for _ in range(d):
            s += sum(1 for n in nodes if (n ^ 1) not in nodes)
            nodes = {n >> 1 for n in nodes}
        tot += s
    return tot / trials

def nosharing(d, q):
    return sum(min(q, 1 << (d - 1 - l)) for l in range(d))

f, q, lb, ext, zk = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
random.seed(1)
for l in open(f):
    d = json.loads(l)
    if 'breakdown' not in d:
        continue
    b = d['breakdown']
    log_trace = (16 if d['rel'] == 'R_TX' else 15) - 1 + zk  # largest table: Mv 2^15 (R_TX) / 2^14 (R_REG), +1 under ZK
    d0 = log_trace + lb
    extra, depth, i = 0, d0, 0
    for k, v in b.items():
        if k.startswith('round') and k.endswith('_merkle'):
            dd = d0
        elif k.startswith('fri') and k.endswith('_siblings'):
            arity = round(v / q / (8 * ext)) + 1
            depth -= arity.bit_length() - 1
            continue
        elif k.startswith('fri') and k.endswith('_merkle'):
            dd = depth
        else:
            continue
        e = pruned(dd, q)
        if e > 0:
            extra += v * (nosharing(dd, q) / e - 1)
    print(json.dumps({'file': f, 'rel': d['rel'], 'proof_bytes': b['total'], 'worst_case_bytes': round(b['total'] + extra)}))
