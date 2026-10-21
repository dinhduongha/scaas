#!/usr/bin/env python3
"""Plan 5h Task 7b: precompile inputs and transaction calldata of every form at the 16k sizes against the Amsterdam
calldata limit (EIP-7976 floor 64 gas per calldata byte + 15,000 must stay <= 2^24, EIP-8037). Stdlib only.

  python3 -I pqz-core/pqzl/params/p16k/inputs16k.py > pqz-core/pqzl/params/p16k/inputs-amsterdam-16k.txt

Statement lengths: today's PQZL v3 rows (chain/engine-pqz.json `stmtLen`) with every 16,384-byte key / u unit grown to
20,480 (stmt = 640 + units * PK + 128 * k; checked against Task 7's R_TX 103,552, op 7 M = 4 165,760, M = 8 G = 2
269,184). Proofs: Task 7's LaZer codegen sizes (codegen-16k.txt) and PQZH Ligero bounds (ligero-16k.txt, [estimate]).
Calldata: the exact ABI layout of each entry point (`mtxExecute` relayed: 516 + the inner call padded to 32, which
matches the Foundry-measured 78,020 / 78,084 / 79,236 / 83,524 B of op 1 and op 7 M = 1 / 2 / 4).
"""
TX_LIMIT = (2**24 - 15_000) // 64  # largest calldata of one transaction (to != sender, no value, no access list)
PK, V, CT = 20_480, 128, 20_608
AUTH = 3_456  # abi.encode(bytes(""), bytes(3309)): the UA auth with an ML-DSA-65 signature


def pad(n):
    return n + (-n % 32)


def relayed(inner):
    return 516 + pad(inner)


def op1(proof, aud):
    payload = 208 + PK + V + V + (V if aud else 0)  # 6 words + salt + out
    return 4 + 160 + 32 + pad(payload) + 32 + pad(proof) + 32 + AUTH + 32


def op7(m, proof, aud, g=None):
    g = g or (m + 3) // 4
    out = PK * g + V * (m + 1) + (V * m if aud else 0)
    payload = 224 + 16 + 32 * m + out
    return 4 + 160 + 32 + pad(payload) + 32 + pad(proof) + 32 + AUTH + 32


def burn(proof):
    payload = 160 + CT
    return 4 + 224 + 32 + pad(payload) + 32 + pad(proof) + 32 + AUTH + 32


def register(proof):  # UARegistry.register(kind, mldsa65 pk 1,952, pop 3,309, pqzKey, pqzPop)
    return 4 + 160 + 32 + 1_952 + 32 + pad(3_309) + 32 + PK + 32 + pad(proof)


def disclose(proof):  # verifyTransferAmount(ref, leg, amount, kind, proof): an eth_call
    return 4 + 160 + 32 + pad(proof)


def stmt16(today):
    units = today // 16_384
    return today + units * (PK - 16_384)


# (form, today's stmtLen, proof, calldata(proof), path)
F = [
    ("R_TX op 1, auditor", 83_072, 52_624, lambda p: relayed(op1(p, True)), "relayed mtxExecute"),
    ("R_TX0 op 1, auditor off", 66_560, 52_272, lambda p: relayed(op1(p, False)), "relayed mtxExecute"),
    ("R_BURN op 2 (burn / refresh)", 50_048, 51_744, lambda p: relayed(burn(p)), "relayed mtxExecute"),
    ("R_REG op 3", 16_480, 33_734, register, "UARegistry.register"),
    ("R_DS op 4", 33_184, 34_278, disclose, "verifyTransferAmount (eth_call)"),
    ("R_DR op 5", 33_184, 35_142, disclose, "verifyTransferAmount (eth_call)"),
    ("R_TXM op 7 M = 1, auditor", 83_072, 52_624, lambda p: relayed(op7(1, p, True)), "relayed mtxExecute"),
    ("R_TXM op 7 M = 1, off", 66_560, 52_272, lambda p: relayed(op7(1, p, False)), "relayed mtxExecute"),
    ("R_TXM op 7 M = 2, auditor", 99_712, 53_504, lambda p: relayed(op7(2, p, True)), "relayed mtxExecute"),
    ("R_TXM op 7 M = 2, off", 83_072, 52_800, lambda p: relayed(op7(2, p, False)), "relayed mtxExecute"),
    ("R_TXM op 7 M = 4, auditor", 132_992, 57_202, lambda p: relayed(op7(4, p, True)), "relayed mtxExecute"),
    ("R_TXM op 7 M = 4, off", 116_096, 53_856, lambda p: relayed(op7(4, p, False)), "relayed mtxExecute"),
    ("(ruled out) op 7 M = 8 G = 1, auditor", None, 60_882, lambda p: relayed(op7(8, p, True, 1)), "relayed mtxExecute"),
    ("PQZH R_REG [estimate]", 16_480, 233_289, register, "UARegistry.register"),
    ("PQZH R_DS / R_DR [estimate]", 33_184, 233_289, disclose, "verifyTransferAmount (eth_call)"),
    ("PQZH R_TX op 1, auditor [estimate]", 83_072, 302_743, lambda p: relayed(op1(p, True)), "relayed mtxExecute"),
    ("PQZH R_TXM op 7 M = 4, auditor [estimate]", 132_992, 303_590, lambda p: relayed(op7(4, p, True)), "relayed mtxExecute"),
]


def max_proof(cd):
    lo, hi = 0, TX_LIMIT
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if cd(mid) <= TX_LIMIT:
            lo = mid
        else:
            hi = mid - 1
    return lo


assert relayed(op1(52_624, True)) == 78_020 and relayed(op7(1, 52_624, True)) == 78_084
assert relayed(op7(2, 53_504, True)) == 79_236 and relayed(op7(4, 57_202, True)) == 83_524
assert relayed(op7(8, 60_882, True, 1)) == 88_356  # Task 7's gas-16k-r208-g1.txt
assert stmt16(83_072) == 103_552 and stmt16(132_992) == 165_760 and stmt16(215_936) == 269_184

print(f"one transaction's calldata: 15,000 + 64 * n <= 2^24  =>  n <= {TX_LIMIT:,} B "
      f"(floor at the limit {15_000 + 64 * TX_LIMIT:,}); a direct call to PQZ carries its input as calldata: input <= {TX_LIMIT:,}")
print()
hdr = ("form", "stmt 16k", "proof", "input 5+stmt+proof", "direct call fits", "path", "tx calldata", "EIP-7976 floor", "fits", "max proof in one tx")
print(" | ".join(hdr))
for name, today, proof, cd, path in F:
    st = stmt16(today) if today else 248_704
    inp = 5 + st + proof
    c = cd(proof)
    print(" | ".join(str(x) for x in (name, f"{st:,}", f"{proof:,}", f"{inp:,}", "yes" if inp <= TX_LIMIT else "NO", path,
                                         f"{c:,}", f"{15_000 + 64 * c:,}", "yes" if c <= TX_LIMIT else "NO", f"{max_proof(cd):,}")))
