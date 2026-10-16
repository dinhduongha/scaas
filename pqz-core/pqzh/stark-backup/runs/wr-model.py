#!/usr/bin/env python3
"""PROBE / MODEL (pqzh-zk-whir.md §10, 2026-10-14): bytes of the HVZK-WHIR masked base case (one opening, R_TX
main-round shape: 2^22 coefficients, Goldilocks^5, rate 3, fold 4, 3 code-switching rounds of 79 / 39 / 26 queries
and 1 OOD sample, 128-bit target, mask code rate 1/16, 68 mask spot checks), first as p3-whir 0.9.0-rc.1 builds it,
checked against the measured field-by-field breakdown (runs/wr-tx.jsonl, opening 0), then for restructured base
cases that keep the checks of Construction 7.2 (ePrint 2026/391). Also the round-0 cost of one more tree in a batched
opening. Stdlib only; Merkle multiproof sizes by simulation (fixed seed).

    python3 runs/wr-model.py > runs/wr-model.txt
"""
import random

EF, F, DIG, SALT = 40, 8, 32, 32          # Goldilocks^5 element, base element, Keccak digest, 4-element leaf salt
T_ZK, RATE_ZK = 68, 4                    # mask spot checks, mask code log inverse rate (WhirParams::DEFAULT)
SOURCE_PART = 13462 + 8973 + 862 + 8973  # measured: source + fresh-main spot checks (wr-tx.jsonl opening 0)
random.seed(20261014)


def merkle_digests(t, log_leaves, trials=400):
    """mean sibling digests of a pruned multiproof for t uniform positions among 2^log_leaves leaves"""
    tot = 0
    for _ in range(trials):
        nodes = {random.randrange(1 << log_leaves) for _ in range(t)}
        for _lvl in range(log_leaves):
            parents = {}
            for x in nodes:
                parents.setdefault(x >> 1, set()).add(x & 1)
            tot += sum(1 for s in parents.values() if len(s) == 1)
            nodes = set(parents)
    return tot / trials


def opening(t, log_leaves, row_elems, elem=EF):
    """rows + salts + pruned Merkle digests of one opening of t positions on one tree"""
    return t * (row_elems * elem + SALT) + merkle_digests(t, log_leaves) * DIG


def log_dom(msg):
    """log2 of the mask code domain: next_pow2(message + T_ZK randomness) << RATE_ZK (p3 MaskCodeShape::new)"""
    return (msg + T_ZK - 1).bit_length() + RATE_ZK


def base_case(trees, single_code=None, one_fresh=False):
    """trees: carried mask trees, chronological, each a list of mask message lengths (one tree = one commitment).
    single_code: one message length for every mask (the paper's single C_zk); else each tree its own code.
    one_fresh: all fresh pads in one oracle at one shared set of positions (Construction 7.2 as written)."""
    masks = [m for tr in trees for m in tr]
    reveal = sum(((single_code or m) + T_ZK) * EF for m in masks) + (64 + 21) * EF   # + blinded source
    dom = lambda tr: log_dom(single_code or max(tr))
    carried = sum(opening(T_ZK, dom(tr), len(tr)) for tr in trees)
    if one_fresh:
        fresh = opening(T_ZK, max(dom(tr) for tr in trees), len(masks))
    else:
        fresh = sum(opening(T_ZK, dom(tr), len(tr)) for tr in trees)
    commits = DIG * (1 + (1 if one_fresh else len(trees)))
    total = reveal + carried + fresh + commits + SOURCE_PART
    return dict(trees=len(trees), masks=len(masks), reveals=round(reveal), mask_openings=round(carried + fresh),
                total=round(total))


if __name__ == "__main__":
    k, sw = 4, [80, 40, 27]                          # fold 4; code-switch mask messages = queries + OOD
    p3 = [[4] * k, [sw[0]], [4] * k, [sw[1]], [4] * k, [sw[2]], [4] * k]
    print("measured (wr-tx.jsonl opening 0): base case 361,394 B = reveals 63,560 + mask openings 265,248 "
          "+ source/fresh-main 32,270 + commitments 265")
    print("calibration: digests for 68 of 2^11 / 68 of 2^12 / 79 of 2^21:",
          [round(merkle_digests(t, d)) for t, d in ((68, 11), (68, 12), (79, 21))],
          "(measured 267-292 / 331-353 / 1,026-1,102)")
    rows = [
        ("A p3-whir as built: 7 trees (k masks per sumcheck batch, 1 per round), own code each, "
         "own pads and positions", base_case(p3)),
        ("B Construction 7.2 as written: one C_zk (message 80) for all 19 masks, one pad oracle, shared positions",
         base_case(p3, single_code=80, one_fresh=True)),
        ("C all 16 sumcheck masks as one 64-coefficient mask committed up front + 3 switch masks; own codes, "
         "own pads", base_case([[64], [sw[0]], [sw[1]], [sw[2]]])),
        ("D = C with one C_zk (message 80), one pad oracle, shared positions",
         base_case([[64], [sw[0]], [sw[1]], [sw[2]]], single_code=80, one_fresh=True)),
    ]
    for name, r in rows:
        print(f"{name}: {r}")
    # one more committed tree in a batched opening: its round-0 STIR queries (base-field leaves of 2^4, salted)
    for rate, q in ((3, 79), (4, 58)):
        for v in (20, 21, 22):
            print(f"round-0 queries of one more tree: rate {rate}, {q} queries, 2^{v} coefficients: "
                  f"{round(opening(q, v - 4 + rate, 16, F))} B")
