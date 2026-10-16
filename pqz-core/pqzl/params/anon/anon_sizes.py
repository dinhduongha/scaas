#!/usr/bin/env python3
"""P6-ANON sizing (research, docs/research/pqz-anonymity.md §7): the PQZ multi-recipient transfer R_TXM (M legs,
decoys = legs of amount 0) — statement, precompile input, calldata and gas against MAX_INPUT 393,216, the per-id
MAX_PROOF and the EIP-7825 cap; and M separate R_TX transfers for comparison.

Inputs: PQZL proof sizes from LaZer's codegen on the sketches next to this file, sized with the pinned estimator
(run_sizing.sh -> sizing-anon.txt, "codegen proof size ~N B" at beta >= 450), scaled by R_TX's measured / codegen ratio (42,799 / 44,638 B);
until a sketch's run exists, a model (+330 B per leg, +13.5 KB per randomness group); PQZH (Ligero) from R_TX's measured 230,392 B
plus 726 B per added row (t = 121 columns x 6 B), ~400 slots per extra leg (695 per row), +60 rows per extra
randomness group. Gas as pq-zero-knowledge.md §9.3: EIP-7623 floor 21,000 + 10 * tokens, 25.2 tokens per be8 coefficient,
3.99 per random byte; precompile 0.12 M gas per ms of p99 verify. Stdlib only: python3 -I anon_sizes.py
The last table (`measured`, P6-ANON S3) replaces the model by the measured numbers (pqz-ffi run s3a, L3, H2) and
applies D3.
"""
import json, math, os, re

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_INPUT, TX_CAP = 393_216, 16_777_216
MAX_PROOF = {'PQZL': 98_304, 'PQZH': 262_144}
PK, CT, U, V, HDR = 16_384, 16_512, 16_384, 128, 640
TOK_COEF, TOK_RAND = 25.2, 3.99
RTX_MEAS, RTX_CODEGEN = 42_799, 44_638
LIG_RTX, LIG_ROW = 230_392, 121 * 6
MLDSA_SIG = 3_309
ROLL = 0.55e6                       # one later roll-over per credit (pq-zero-knowledge.md §9.3: 8.9 M / 16)


def codegen_bytes(name):
    """Codegen proof bytes of a sketch from sizing-anon.txt (run_sizing.sh, pinned estimator, beta >= 450 floors)."""
    p = os.path.join(HERE, 'sizing-anon.txt')
    if not os.path.exists(p):
        return None
    m = re.search(rf'=> /tmp/w/{name}_params\.sage: .*codegen proof size ~(\d+) B', open(p).read())
    return int(m.group(1)) if m else None


def proof(system, m, g):
    if system == 'PQZL':
        k = codegen_bytes(f'txm{m}' + (f'g{g}' if g > 1 else ''))
        if k is None:   # codegen not run yet (plan Task L1): model ~ +330 B per leg (2 e2 polys, 1 binary poly in z1),
            return RTX_MEAS + 330 * (m - 1) + 13_500 * (g - 1)   # ~ +13.5 KB per group (2 big vectors, cf. R_REG vs R_TX)
        return round(k * RTX_MEAS / RTX_CODEGEN)
    return LIG_RTX + LIG_ROW * (math.ceil(400 * (m - 1) / 695) + 60 * (g - 1))


def stmt(m, g, aud=1):              # header, pk_f, M pks, [pk_a], T, u per group, M v, v_f, [M auditor v]
    return HDR + PK + m * PK + aud * PK + CT + g * U + m * V + V + aud * m * V


def gas(cal_coef, cal_rand, inp, p99_ms, n_keys, n_credits, log_bytes):
    tokens = cal_coef / 8 * TOK_COEF + cal_rand * TOK_RAND + 1_500
    floor = 21_000 + 10 * tokens
    w = inp / 32
    exe = (0.12e6 * p99_ms + 6 * w + w * w / 512 + n_keys * 6_000 + n_credits * 25_000 + 90_000
           + 8 * log_bytes + 10_000)
    return max(floor, 21_000 + 4 * tokens + exe), floor


def beta(h):                        # usvp.py table, hints approximated as dimensions removed (pq-zero-knowledge.md §4.5)
    t = {32: 466, 48: 461, 80: 451, 144: 432, 272: 392}
    ks = sorted(t)
    for a, b in zip(ks, ks[1:]):
        if a <= h <= b:
            return round(t[a] + (t[b] - t[a]) * (h - a) / (b - a))


P99 = {'PQZL': {1: 11.1, 2: 12, 4: 12.5, 8: 14, 16: 17}, 'PQZH': {1: 10.5, 2: 11, 4: 11.5, 8: 12.5, 16: 14.5}}


def one(system, m, g, aud=1):
    pr = proof(system, m, g)
    if pr is None:
        return None
    s = stmt(m, g, aud)
    inp = 5 + s + pr
    cal_coef = CT + g * U + m * V + V + aud * m * V
    cal_rand = pr + MLDSA_SIG + 32 * m
    p99 = P99[system][m] * (1 + 0.25 * (g - 1))
    total, floor = gas(cal_coef, cal_rand, inp, p99, m + 1 + aud, m, g * U + (1 + (1 + aud) * m) * V)
    return dict(stmt=s, proof=pr, inp=inp, cal=cal_coef + cal_rand, floor=floor, gas=total,
                fits=inp <= MAX_INPUT and pr <= MAX_PROOF[system] and total <= TX_CAP, hints=16 * min(m, 4 if g > 1 else m) + 16)


def main():
    print('| system | M | groups | statement B | proof B | input B | calldata | gas (floor-bound) | fits | hints → β |')
    print('|---|---|---|---|---|---|---|---|---|---|')
    for system in ('PQZL', 'PQZH'):
        for m, g in ((1, 1), (2, 1), (4, 1), (8, 1), (16, 1), (8, 2), (16, 4)):
            r = one(system, m, g)
            if r is None:
                continue
            why = [] if r['fits'] else [x for x, bad in (('input', r['inp'] > MAX_INPUT),
                                                          ('MAX_PROOF', r['proof'] > MAX_PROOF[system]),
                                                          ('gas cap', r['gas'] > TX_CAP)) if bad]
            print(f"| {system} | {m} | {g} | {r['stmt']:,} | {r['proof']:,} | {r['inp']:,} | {r['cal']/1000:.1f} KB "
                  f"| {r['gas']/1e6:.2f} M | {'yes' if r['fits'] else 'no: ' + ', '.join(why)} "
                  f"| {r['hints']} → {beta(r['hints'])} |")
    print()
    print('One M-leg transfer vs M separate transfers (auditor on; gas now + the M later roll-overs, equal in both)')
    print('| system | M | one transfer: proofs / debits / gas | M transfers: proofs / debits / gas | saved |')
    print('|---|---|---|---|---|')
    for system in ('PQZL', 'PQZH'):
        single = one(system, 1, 1)
        for m in (2, 4, 8, 16):
            g = 1 if m <= 4 else m // 4
            r = one(system, m, g)
            if r is None:
                continue
            sep = m * single['gas']
            print(f"| {system} | {m} | 1 / 1 / {r['gas']/1e6:.2f} M | {m} / {m} / {sep/1e6:.2f} M | "
                  f"{(1 - r['gas']/sep)*100:.0f} % |")


def limits():
    """Per (system, M) with groups of 4: what fits today and which limit change a non-fitting size would need."""
    print('| system | M (groups) | input B | proof B | gas | today | limit change it would need |')
    print('|---|---|---|---|---|---|---|')
    kib = lambda x: math.ceil(x / 32768) * 32768
    for system in ('PQZL', 'PQZH'):
        for m in (2, 4, 8, 16):
            g = max(1, m // 4)
            r = one(system, m, g)
            need = []
            if r['inp'] > MAX_INPUT:
                need.append(f"`MAX_INPUT` ≥ {kib(r['inp']):,} B")
            if r['proof'] > MAX_PROOF[system]:
                need.append(f"{system} `MAX_PROOF` ≥ {kib(r['proof']):,} B")
            if r['gas'] > TX_CAP:
                need.append('more than the EIP-7825 cap (16,777,216), which stays: not reachable')
            print(f"| {system} | {m} ({g}) | {r['inp']:,} | {r['proof']:,} | {r['gas']/1e6:.2f} M | "
                  f"{'fits' if not need else 'does not fit'} | {'; '.join(need) if need else 'none'} |")


def s1_grouping():
    """P6-ANON S1 (hints-anon.txt, DDGR20 worst case) with the owner's grouping (2026-10-15): 4 legs per randomness
    group with or without the auditor; 4 legs + the auditor = 80 hints, beta 446.0 (CTR-PQZ-03's accepted exception).
    Sizes per (system, M, auditor). (An interim 3-legs-with-auditor variant, beta >= 450, was withdrawn.)"""
    t = open(os.path.join(HERE, 'hints-anon.txt')).read()
    mixed = {int(h): float(b) for h, b in re.findall(r'^\s*(\d+)\s+[\d.]+\s+[\d.]+\s+([\d.]+)\s+\d+\s*$', t, re.M)}
    print('| system | M | auditor | groups | statement B | proof B | input B | gas | fits | hints → β (DDGR20, worst) |')
    print('|---|---|---|---|---|---|---|---|---|---|')
    for system in ('PQZL', 'PQZH'):
        for m in (1, 2, 4, 8, 16):
            for aud in (1, 0):
                lpg = 4
                g = -(-m // lpg)
                r = one(system, m, g, aud)
                h = 16 * min(m, lpg) + 16 * aud
                why = [x for x, bad in (('input', r['inp'] > MAX_INPUT), ('MAX_PROOF', r['proof'] > MAX_PROOF[system]),
                                        ('gas cap', r['gas'] > TX_CAP)) if bad]
                print(f"| {system} | {m} | {'on' if aud else 'off'} | {g} | {r['stmt']:,} | {r['proof']:,} | "
                      f"{r['inp']:,} | {r['gas']/1e6:.2f} M | {'no: ' + ', '.join(why) if why else 'yes'} | "
                      f"{h} → {mixed[h]:.1f} |")


CORE = os.path.join(HERE, '..', '..', '..')  # pqz-core


def jsonl(rel):
    p = os.path.join(CORE, rel)
    return [json.loads(x) for x in open(p) if x.lstrip().startswith('{')] if os.path.exists(p) else []


def multi_len(m, aud):
    return stmt(m, -(-m // 4), aud)


def measured(bench='ffi/runs/s3a-bench.jsonl'):
    """P6-ANON S3, D3 with measured numbers: built op 7 shapes through pqz-ffi (`bench`: statement, proof, PQZH exact
    bound, native p99 through `precompile`), wasm32 verify p99 from L3 (PQZL SV, research/pqzl-measure/runs/l3a-wasm-fast.jsonl) and H2
    (Ligero, pqzh/ligero/runs/l16-txm-*-wasm.jsonl); the oversize shapes from L3 / H2's bench-only runs. Worst-case
    input = 5 + statement + the id's bound (PQZL MAX_PROOF, PQZH Ligero's exact max for the shape). Gas by this
    file's calldata model with the measured proof and native p99. D3: built iff worst-case input <= MAX_INPUT, bound
    <= MAX_PROOF, verify p99 <= 60 ms native and wasm32, gas <= the EIP-7825 cap."""
    rows = {}
    for r in jsonl(bench):
        if 'm' in r:
            rows[(r['sys'], r['m'], r['auditor'])] = dict(
                stmt=r['stmt_bytes'], proof=r['proof_bytes'], bound=r['proof_bound'], p99=r['rust']['p99_ms'], src='S3 pqz-ffi')
    for r in jsonl('research/pqzl-measure/runs/l3a-native-fast.jsonl'):
        if r.get('rel', '').startswith('R_TXM16'):
            aud = not r['rel'].endswith('_0')
            rows[('PQZL', 16, aud)] = dict(stmt=multi_len(16, aud), proof=r['proof_bytes_max'], bound=MAX_PROOF['PQZL'], src='L3 oversize')
        t = r.get('timing', '')
        if t.startswith('R_TXM16') and t.endswith('verify valid'):
            rows[('PQZL', 16, not t.split()[0].endswith('_0'))]['p99'] = r['p99_ms']
    for r in jsonl('pqzh/ligero/runs/l16-txm-oversize.jsonl'):
        rel = r.get('rel', '')
        m = int(rel[5:].split('_')[0]) if rel.startswith('R_TXM') else 0
        if m in (8, 16):
            k = ('PQZH', m, not rel.endswith('_0'))
            row = rows.setdefault(k, dict(stmt=multi_len(m, k[2]), src='H2 oversize'))
            if 'max_len_exact' in r:
                row.update(proof=r['proof_bytes_max'], bound=r['max_len_exact'])
            if r.get('timing') == 'verify_honest':
                row['p99'] = r['stats']['p99_ms']
    wasm = {}
    for r in jsonl('research/pqzl-measure/runs/l3a-wasm-fast.jsonl'):
        if r.get('timing', '').endswith('verify valid'):
            wasm[('PQZL', r['timing'].split()[0])] = r['p99_ms']
    for f in ('pqzh/ligero/runs/l16-txm-oversize-wasm.jsonl', 'pqzh/ligero/runs/l16-txm-proven-wasm.jsonl'):
        for r in jsonl(f):
            if r.get('timing') == 'verify_honest':
                wasm[('PQZH', r['rel'])] = r['stats']['p99_ms']
    if not rows:
        print(f'(no measured op 7 rows: {bench} missing)')
        return
    print('| system | M | auditor | statement B | proof B (measured) | proof bound | input B | worst-case input B | '
          'verify p99 native / wasm32 ms | gas | D3 verdict | source |')
    print('|---|---|---|---|---|---|---|---|---|---|---|---|')
    for (system, m, aud), r in sorted(rows.items(), key=lambda x: (x[0][0] != 'PQZL', not x[0][2], x[0][1])):
        g = -(-m // 4)
        a = int(aud)
        inp, worst = 5 + r['stmt'] + r['proof'], 5 + r['stmt'] + r['bound']
        w = wasm.get((system, f"R_TXM{m}{'' if aud else '_0'}"))
        cal_coef = CT + g * U + m * V + V + a * m * V
        total, _ = gas(cal_coef, r['proof'] + MLDSA_SIG + 32 * m, inp, r['p99'], m + 1 + a, m, g * U + (1 + (1 + a) * m) * V)
        why = [x for x, bad in (('input', worst > MAX_INPUT), ('MAX_PROOF', r['bound'] > MAX_PROOF[system]),
                                ('p99', r['p99'] > 60 or (w or 0) > 60), ('gas cap', total > TX_CAP)) if bad]
        print(f"| {system} | {m} | {'on' if aud else 'off'} | {r['stmt']:,} | {r['proof']:,} | {r['bound']:,} | {inp:,} | "
              f"{worst:,} | {r['p99']:.2f} / {'-' if w is None else f'{w:.2f}'} | {total / 1e6:.2f} M | "
              f"{'not built: > ' + ', '.join(why) if why else 'built'} | {r['src']} |")


if __name__ == '__main__':
    main()
    print()
    limits()
    print()
    s1_grouping()
    print()
    measured()
