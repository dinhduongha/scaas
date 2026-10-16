#!/usr/bin/env python3
"""StarkEx-style multi-transaction split applied to PQZH (docs/research/pqzh-starkex-verifier.md). Stdlib only.

  python3 pqz-core/pqzh/stark-backup/sol/starkex_split.py                # tables -> stdout (committed as starkex_split.txt)
  python3 pqz-core/pqzh/stark-backup/sol/starkex_split.py --selftest     # asserts on the recorded receipts and the split model
  python3 pqz-core/pqzh/stark-backup/sol/starkex_split.py --fetch HASH.. # re-read receipts from a public RPC (network)

1. SHARP: one proof as it landed on Ethereum mainnet (blocks 26,189,667-669, 2026-10-14), receipts recorded below
   (gasUsed, calldata bytes / zero bytes) from eth_getTransactionReceipt / eth_getTransactionByHash.
2. The split model: a verification of total execution E and calldata T tokens is cut into k transactions, each a
   balanced share plus duplicated data (what every piece needs again) and a fact registration; every transaction pays
   21,000 + max(4 tokens + execution, 10 tokens) (EIP-7623) and must stay <= 16,777,216 (EIP-7825) and, to
   propagate through the public mempool, <= 128 KB (geth txMaxSize). Perfect divisibility is assumed (an [estimate]).
"""
import json
import math
import sys
import urllib.request

CAP = 16_777_216            # EIP-7825
TX_MAX_BYTES = 128 * 1024   # geth core/txpool/legacypool txMaxSize (public mempool)
INTRINSIC = 21_000
FACT = 22_100 + 3_000       # new storage slot (20,000 + 2,100 cold) + hashing the statement (keccak, memory)
TOK_PER_B = 3.88            # EIP-7623 tokens per proof byte (pqzh-ligero.md §11; random bytes give 3.98)
ETH_USD = 2515              # implied by Etherscan on 2026-10-14 (fee 0.000318010 ETH shown as $0.80)

# hash, method, gasUsed, input bytes, zero bytes  (recorded 2026-10-14 from ethereum-rpc.publicnode.com)
SHARP = [
    ('0x3dee0aac9d7d00850d671051724afd494645f86414822f0d30870a895b9175bc', 'verifyMerkle', 320_720, 10_724, 4_308),
    ('0x22de0f81c9de59ff60f098ccfbb1c170343a3c2afae5c19e232d0ebf1d20ea98', 'verifyMerkle', 320_720, 10_724, 4_308),
    ('0xc2253f4d13885ca582b7469de7626d4fbe24ecbd8c38308bb50ebce919e88cff', 'verifyMerkle', 320_870, 10_724, 4_303),
    ('0x38b28397b99fb616a154fcb2fca390386cc18e1b4237b7d2b0583e7e8c603691', 'verifyFRI', 408_260, 12_548, 3_822),
    ('0x5b7b04bf476902c53466fb8fdd1a62da00b38873f9aa659522bdb5bacd82276e', 'verifyFRI', 377_210, 11_492, 3_449),
    ('0x483cd96fcf156e9b6ad6e3e697d1bcf34a8c7fa81fac6b1001ffec434494cc44', 'verifyFRI', 347_150, 10_436, 3_043),
    ('0x26c4d5081f50f111936c6100b1dec84726362b8001d4250f05745a5284577bb0', 'verifyFRI', 316_610, 9_380, 2_653),
    ('0xaf7d668d041d1490e2706465bee9ec0e874cbce99e5db4396ba29baeb27d786a', 'verifyFRI', 285_860, 8_324, 2_270),
    ('0xaaa51690a3dd56f6c2e2962e5232d6476b00efa963f48fc8ccd3fb66625b9f43', 'verifyFRI', 256_250, 7_268, 1_849),
    ('0x6c078c411fa3337d2bef27c9b2635e3d289a8af150e38398d21555b8155b2d90', 'verifyFRI', 179_480, 5_156, 1_592),
    ('0xb04c1fa811740e6522ef7a864070773a0168e6b929dcfd5b533c250025c88c01', 'registerContinuousPageBatch',
     1_044_686, 24_964, 12_946),
    ('0xe548d9a38319c283f50b3879de776303a8b4a64004924391445b64d3d73b1f38', 'verifyProofAndRegister',
     3_055_832, 23_396, 6_829),
]


def tokens(nbytes, zeros):
    return zeros + 4 * (nbytes - zeros)


def floor7623(tok):
    return INTRINSIC + 10 * tok


def tx_gas(tok, execution):
    return INTRINSIC + max(4 * tok + execution, 10 * tok)


def split(exec_gas, proof_bytes, other_tok=0, other_exec=0, dup_bytes=0, dup_exec=0, mempool=True, kmax=200):
    """Smallest k whose balanced pieces fit; returns (k, total gas, gas per piece) or None.
    dup_bytes / dup_exec: data and work every piece repeats (shared vectors, statement hashing)."""
    tok_total = proof_bytes * TOK_PER_B + other_tok
    for k in range(1, kmax + 1):
        tok = tok_total / k + (dup_bytes * TOK_PER_B if k > 1 else 0)
        ex = (exec_gas + other_exec) / k + (dup_exec if k > 1 else 0) + (FACT if k > 1 else 0)
        piece = tx_gas(tok, ex)
        nbytes = proof_bytes / k + (dup_bytes if k > 1 else 0)
        if piece <= CAP and (nbytes <= TX_MAX_BYTES or not mempool):
            return k, k * piece, piece
    return None


def usd(gas, gwei):
    return gas * gwei * 1e-9 * ETH_USD


# PQZH inputs. FRI+ZK: pqzh-solidity-verifier.md §8 (EVM layout, Goldilocks^5, blowup 32, arity 8, 42 / 21 queries).
# Ligero: pqzh-ligero.md §11.1 / §11.4 / runs/e1-evm-model.txt (proven R_TX, n = 32,756, k = 817, t = 121).
OTHER_TX = (119_000, 310_000)   # the transfer's other calldata tokens and execution (pq-zero-knowledge.md §9.3)
CASES = [
    # name, proof bytes, verify exec (M gas), dup bytes per extra piece, dup exec per piece (M gas)
    ('FRI+ZK R_TX proven, this code', 506_000, 29.3, 3_000, 0.05),
    ('FRI+ZK R_TX proven, floor', 506_000, 6.2, 3_000, 0.05),
    ('FRI+ZK R_TX proven, 2x floor', 506_000, 12.4, 3_000, 0.05),
    ('FRI+ZK R_TX conjectured, this code', 282_000, 19.8, 3_000, 0.05),
    ('FRI+ZK R_TX conjectured, 2x floor', 282_000, 8.4, 3_000, 0.05),
    # Ligero as built: each column piece needs the 19 x 695 combination vectors (317 KB) and w, q, h (101 KB) again
    ('Ligero R_TX proven, as built, this code', 231_950, 530.2, 418_000, 0.5),
    ('Ligero R_TX proven, as built, floor', 231_950, 119.8, 418_000, 0.2),
    # or recomputes them per piece: the statement pass (98.8 M this code, 15.6 M floor) on every piece
    ('Ligero R_TX proven, recompute per piece, floor', 231_950, 119.8, 83_101, 15.6),
    # protocol variant of §11.4: the prover sends R_i(eta_j) (+55 KB), one batched tensor check; pieces repeat w, q, h
    ('Ligero R_TX proven, R_i(eta_j) variant, floor', 287_000, 56.2, 101_000, 0.1),
    ('Ligero R_TX proven, R_i(eta_j) variant, 2x floor', 287_000, 112.4, 101_000, 0.2),
]


def report():
    out = ['## SHARP proof on Ethereum mainnet, 2026-10-14 (blocks 26,189,667-26,189,669) [measured: receipts]', '',
           '| tx | method | gasUsed | calldata B | EIP-7623 floor | at floor? |', '|---|---|---|---|---|---|']
    tg = tb = 0
    for h, m, g, b, z in SHARP:
        f = floor7623(tokens(b, z))
        out.append(f'| {h[:10]} | {m} | {g:,} | {b:,} | {f:,} | {"yes" if g == f else "no"} |')
        tg += g
        tb += b
    out += [f'| **{len(SHARP)} txs** | | **{tg:,}** | **{tb:,}** | | |', '',
            f'Cost at 0.1 / 1 / 10 gwei: ${usd(tg, 0.1):,.2f} / ${usd(tg, 1):,.2f} / ${usd(tg, 10):,.2f} '
            f'(ETH = ${ETH_USD:,})', '',
            '## PQZH split, R_TX (21,000 + max(4 tok + exec, 10 tok) per tx, <= 16,777,216 gas, <= 128 KB) '
            '[estimate]', '',
            '| case | proof B | verify M | mempool <= 128 KB | txs | total M gas | per tx M | $ at 0.1 / 1 / 10 gwei |',
            '|---|---|---|---|---|---|---|---|']
    for name, pb, ex, db, de in CASES:
        for mp in (False, True):
            r = split(ex * 1e6, pb, OTHER_TX[0], OTHER_TX[1], db, de * 1e6, mp)
            if r is None:
                out.append(f'| {name} | {pb:,} | {ex} | {"yes" if mp else "no"} | none fits | | | |')
                continue
            k, tot, piece = r
            out.append(f'| {name} | {pb:,} | {ex} | {"yes" if mp else "no"} | {k} | {tot / 1e6:.1f} | '
                       f'{piece / 1e6:.2f} | {usd(tot, 0.1):,.0f} / {usd(tot, 1):,.0f} / {usd(tot, 10):,.0f} |')
    return '\n'.join(out)


def selftest():
    # every statement tx of the SHARP proof pays exactly the EIP-7623 floor; the two big ones do not
    for h, m, g, b, z in SHARP:
        at_floor = g == floor7623(tokens(b, z))
        assert at_floor == (m in ('verifyMerkle', 'verifyFRI')), (h, m)
    assert sum(x[2] for x in SHARP) == 7_233_648
    # one piece reproduces the single-transaction model of pqzh-solidity-verifier.md §8 (proven ZK, floor: 21.4 M)
    k, tot, _ = split(6.2e6, 506_000, *OTHER_TX, mempool=False)
    assert k == 2 and 20.5e6 < tot < 22.0e6, (k, tot)
    assert split(6.2e6, 506_000, *OTHER_TX)[0] == 4                       # 128 KB mempool limit binds instead
    assert split(119.8e6, 231_950, *OTHER_TX, 418_000, 0.2e6) is None          # Ligero as built: > 128 KB per piece
    assert usd(1e9, 1) == ETH_USD
    print('selftest ok')


def fetch(hashes, rpc='https://ethereum-rpc.publicnode.com'):
    def call(method, params):
        req = urllib.request.Request(rpc, data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method,
                                                           'params': params}).encode(),
                                     headers={'Content-Type': 'application/json', 'User-Agent': 'curl/8'})
        return json.load(urllib.request.urlopen(req, timeout=30))['result']
    for h in hashes:
        t, r = call('eth_getTransactionByHash', [h]), call('eth_getTransactionReceipt', [h])
        b = bytes.fromhex(t['input'][2:])
        print(h, int(t['blockNumber'], 16), t['input'][:10], int(r['gasUsed'], 16), len(b), b.count(0))


if __name__ == '__main__':
    if sys.argv[1:2] == ['--selftest']:
        selftest()
    elif sys.argv[1:2] == ['--fetch']:
        fetch(sys.argv[2:])
    else:
        print(report())
