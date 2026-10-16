#!/usr/bin/env python3
"""P6-ANON S9: the largest op 7 (`pqzTransfer`, R_TXM) call of each proof system against the node limits of chain
7622 (docs/node/ops.md §13): `TxPool.MaxTxSize`, node `max_gas_per_tx`, EIP-7825, the gateway body limit (hex job),
the follower proxy body limit (hex raw tx), the block gas limit.

Inputs [measured]: PQZL proof max per (M, A) from P6-ANON L3 (`pqz-core/README.md` §5.4, `rel3/runs/l3a-*`); PQZH
exact bound per shape (pqzh-ligero.md §15.2); live 7622 `engine.Pqz` op 1 rows (calibrated, 0.359 M gas / ms);
verify p99 ratios R_TXM(M) / R_TXM1 (L3 `l3a-native-fast`, max of valid / adversarial p99; PQZH §15.3).
Model [estimate]: G_7 = op 1 row x p99 ratio (S8 calibrates the real table); calldata = the ABI encoding of
`pqzTransfer(bytes payload, bytes acc, bytes[] inline, bytes32[] recipients, bytes out, bytes proof, bytes authSig)`
(plan §6), COMPACT memo in the payload, ML-DSA-65 `authSig`; tokens per byte: coefficient 3.15 (25.2 per be8
coefficient), random 3.99, ABI words 1.2; EIP-7623 floor 21,000 + 10 tokens, standard (16 / 4 gas per byte)
21,000 + 4 tokens; execution besides the precompile as anon_sizes.py plus ~50 k per inline credit and the storage
mode (BUNDLE: SSTORE2 of R at 200 gas / byte + 32 k). Stdlib only: python3 -I s9_limits.py
"""
import math

MAX_TX_SIZE, NODE_GAS, EIP7825, BODY, PROXY, BLOCK = 1_048_576, 16_000_000, 1 << 24, 1_048_576, 2 << 20, 80_000_000
PK, CT, U, V = 16_384, 16_512, 16_384, 128
INLINE_MAX = 16                                  # CTR-PQZ-08
SIG = 3_309                                      # ML-DSA-65
OP1 = {('PQZL', 1): 5_409_000, ('PQZL', 0): 5_223_000, ('PQZH', 1): 4_225_000, ('PQZH', 0): 4_021_000}
# (system, M, A) -> (proof bytes max, verify p99 ms); M = 1 row is the ratio base
SHAPES = {
    ('PQZL', 1, 1): (42_784, 10.982), ('PQZL', 2, 1): (43_616, 11.031), ('PQZL', 4, 1): (45_295, 11.079),
    ('PQZL', 8, 1): (61_822, 15.833), ('PQZL', 1, 0): (42_442, 11.514), ('PQZL', 2, 0): (42_936, 10.461),
    ('PQZL', 4, 0): (43_943, 11.659), ('PQZL', 8, 0): (59_026, 14.276),
    ('PQZH', 1, 1): (235_470, 14.03), ('PQZH', 2, 1): (235_470, 15.03), ('PQZH', 4, 1): (236_196, 16.05),
    ('PQZH', 1, 0): (234_744, 13.92), ('PQZH', 2, 0): (235_470, 14.23), ('PQZH', 4, 0): (235_470, 15.29),
}
pad = lambda n: 32 * math.ceil(n / 32)


def g7(s, m, a):
    r = max(1.0, SHAPES[(s, m, a)][1] / SHAPES[(s, 1, a)][1])
    return 1000 * math.ceil(OP1[(s, a)] * r / 1000)


def call(s, m, a, n, mode='COMPACT'):
    g = -(-m // 4)
    proof = SHAPES[(s, m, a)][0]
    out = g * U + V * (m + 1) + V * m * a
    memo = 16 + 2 + 40 * m
    payload = 12 + 64 + 16 + memo
    auth = 64 + 32 + 32 + pad(SIG)
    coef = CT + n * CT + out
    rand = proof + SIG + 32 * m + 16 + memo + 64
    size = 4 + 7 * 32 + sum(32 + pad(x) for x in (payload, CT, out, proof, auth)) + 32 + 32 * n + n * (32 + CT) + 32 + 32 * m
    abi = size - coef - rand
    tokens = coef * 3.15 + rand * 3.99 + abi * 1.2
    floor = 21_000 + 10 * tokens
    stmt = 50_048 + 16_640 * m + 16_384 * g if a else 33_664 + 16_512 * m + 16_384 * g
    inp = 5 + stmt + proof
    w = inp / 32
    r_len = 16 + g * U + (32 + V + V * a) * m
    store = {'COMPACT': 25_000, 'NoBundle': 0, 'BUNDLE': 200 * r_len + 32_000}[mode]
    exe = (g7(s, m, a) + 3 * math.ceil(inp / 32) + 6 * w + w * w / 512 + (m + 1 + a) * 6_000 + m * 25_000 + 90_000
           + 8 * (g * U + (1 + (1 + a) * m) * V) + 10_000 + 50_000 * n + store)
    std = 21_000 + 4 * tokens + exe
    return dict(size=size, hexjob=2 * size + 2_048, floor=floor, std=std, gas=max(floor, std), inp=inp)


def max_inline(s, m, a, cap, mode='COMPACT'):
    return max([n for n in range(INLINE_MAX + 1) if call(s, m, a, n, mode)['gas'] <= cap], default=-1)


def main():
    print('| id | M | A | G_7 [est] | calldata B (0 inline / max inline) | gas 0 inline: floor / standard+exec | '
          'max inline ≤ 16 M (COMPACT / BUNDLE) | largest call B | hex job B |')
    print('|---|---|---|---|---|---|---|---|---|')
    worst = None
    for (s, m, a) in SHAPES:
        n = max_inline(s, m, a, NODE_GAS)
        nb = max_inline(s, m, a, NODE_GAS, 'BUNDLE')
        c0, cn = call(s, m, a, 0), call(s, m, a, max(n, 0))
        print(f"| {s} | {m} | {'on' if a else 'off'} | {g7(s, m, a)/1e6:.2f} M | {c0['size']:,} / {cn['size']:,} | "
              f"{c0['floor']/1e6:.2f} / {c0['std']/1e6:.2f} M | {n} / {nb} | {cn['size']:,} | {cn['hexjob']:,} |")
        worst = max(worst or cn, cn, key=lambda x: x['size'])
        # every built shape fits the node cap with no inline credit in COMPACT mode
        assert c0['gas'] <= NODE_GAS and c0['inp'] <= 393_216
    print()
    print(f"largest op 7 call within 16 M: {worst['size']:,} B -> MaxTxSize margin {MAX_TX_SIZE/worst['size']:.2f}x, "
          f"hex job {worst['hexjob']:,} B -> body margin {BODY/worst['hexjob']:.2f}x, raw tx hex "
          f"{2*worst['size']+300:,} B -> proxy margin {PROXY/(2*worst['size']+300):.2f}x, "
          f"block 80 M / 16 M = {BLOCK // NODE_GAS} such calls")
    # any call within the EIP-7825 cap carries <= cap / 10 tokens; PQZ bytes are >= 3.15 tokens each
    print(f"bound: a PQZ call within EIP-7825 has <= {EIP7825 / 10 / 3.15:,.0f} B of coefficient-class calldata")
    assert worst['size'] < MAX_TX_SIZE and worst['hexjob'] < BODY and 2 * worst['size'] + 300 < PROXY


if __name__ == '__main__':
    main()
