# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""CLI-UAL-66 mutants: the wasm32 Falcon glue, one change at a time. src/falcon/soft.rs mutants run tests/fndsa_vrfy.rs natively
(it includes soft.rs as it is); src/falcon.rs / src/lib.rs wasm32 arms run tests/fndsa/wasm/run.sh. Every one must be
killed. Through scripts/mutant_guard.py (ARCH-POS-23). From the repository root:
  WASM_BINDGEN=<wasm-bindgen 0.2.130> python3 -I clients/ua-rs/runs/2026-11-26-ua-rs-wasm-fndsa-mutants.py
`… mutants.py <name substring> …` runs only those. Prints `name | where | outcome`; rc 1 when one survives."""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
import mutant_guard as g  # noqa: E402

UA = ROOT / "clients/ua-rs"
SOFT, FALCON, LIB = UA / "src/falcon/soft.rs", UA / "src/falcon.rs", UA / "src/lib.rs"
ENV = {**os.environ, "CARGO_INCREMENTAL": "0"}
NATIVE = (
    [str(ROOT / "scripts/capped"), "cargo", "test", "--no-default-features", "--features", "vectors", "--test", "fndsa_vrfy"],
    UA,
)
WASM = (["./run.sh"], UA / "tests/fndsa/wasm")

MUTANTS = [
    # soft.rs, natively
    ("verify: compressed format", SOFT, "r3::falcon_verify(sig, r3::FALCON_SIG_PADDED,", "r3::falcon_verify(sig, r3::FALCON_SIG_COMPRESSED,", NATIVE),
    ("verify: verdict inverted", SOFT, "pk, m, &mut tmp) == 0", "pk, m, &mut tmp) != 0", NATIVE),
    ("sign: message not hashed", SOFT, "    r3::shake256_inject(&mut hash, m);\n", "", NATIVE),
    ("sign: nonce and message swapped", SOFT, "r3::shake256_inject(&mut hash, nonce);\n    r3::shake256_inject(&mut hash, m);", "r3::shake256_inject(&mut hash, m);\n    r3::shake256_inject(&mut hash, nonce);", NATIVE),
    ("sign: sampler seeded by the nonce", SOFT, "r3::shake256_init_prng_from_seed(&mut rng, seed);\n    let mut tmp = vec![0u8; r3::falcon_tmpsize_signdyn", "r3::shake256_init_prng_from_seed(&mut rng, nonce);\n    let mut tmp = vec![0u8; r3::falcon_tmpsize_signdyn", NATIVE),
    ("keygen: seed cut to 32 bytes", SOFT, "r3::shake256_init_prng_from_seed(&mut rng, seed);\n    let mut tmp = vec![0u8; r3::falcon_tmpsize_keygen", "r3::shake256_init_prng_from_seed(&mut rng, &seed[..32]);\n    let mut tmp = vec![0u8; r3::falcon_tmpsize_keygen", NATIVE),
    # the wasm32 arms, in wasm32
    ("wasm verify: always true", FALCON, "soft::verify(p.logn.into(), pk, m, sig)", "true", WASM),
    ("wasm verify: degree 512 always", FALCON, "soft::verify(p.logn.into(), pk, m, sig)", "soft::verify(9, pk, m, sig)", WASM),
    ("wasm sign: first byte of m dropped", FALCON, "soft::sign(p.logn.into(), sk, m, rnd, sig)", "soft::sign(p.logn.into(), sk, &m[1..], rnd, sig)", WASM),
    ("wasm keygen: seed cut to 32 bytes", FALCON, "soft::keypair(p.logn.into(), seed, pk, sk)", "soft::keypair(p.logn.into(), &seed[..32], pk, sk)", WASM),
    ("wasm: AVAILABLE as before (PQClean only)", FALCON, 'cfg!(any(scaas_falcon, target_arch = "wasm32"))', "cfg!(scaas_falcon)", WASM),
    (
        "wasm: build::FALCON as before",
        LIB,
        'cfg!(all(\n        feature = "pq",\n        any(scaas_falcon, target_arch = "wasm32")\n    ))',
        "cfg!(scaas_falcon)",
        WASM,
    ),
]


def main():
    g.refuse_dirty([m[1] for m in MUTANTS], ROOT)
    only = sys.argv[1:]  # name substrings: run those mutants only
    todo = [m for m in MUTANTS if not only or any(o in m[0] for o in only)]
    survived = 0
    for name, f, old, new, (cmd, cwd) in todo:
        src = f.read_bytes()
        text = src.decode()
        if text.count(old) != 1:
            print(f"[mutants] refused: {name}: the anchor is not unique in {f.relative_to(ROOT)}", flush=True)
            raise SystemExit(2)
        dl = g.limit(cmd, cwd=cwd, env=ENV)
        saved = {f: src}
        try:
            f.write_text(text.replace(old, new))
            r = g.run(cmd, dl, cwd=cwd, env=ENV, capture_output=True)
        finally:
            g.restore(saved)
        res = g.outcome(r, "killed" if r.returncode != 0 else "SURVIVED")
        survived += res == "SURVIVED"
        where = "native" if cmd is NATIVE[0] else "wasm32"
        print(f"{name} | {where} | {res}", flush=True)
    print(f"[mutants] {len(todo)} mutants, {len(todo) - survived} killed, {survived} survived", flush=True)
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
