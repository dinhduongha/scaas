# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The Fable audit of vendor-falcon-rs, its fixes' mutants (CLI-UAL-66): the checks the fixes add, one change at a time, natively
(src/wallet/pqsign.rs and src/falcon.rs through `--lib pqsign`, src/falcon/soft.rs and the length checks through tests/fndsa_vrfy.rs,
which includes soft.rs as it is). Every one must be killed. Through scripts/mutant_guard.py (ARCH-POS-23). From the repository root:
  python3 -I clients/ua-rs/runs/2026-11-26-falcon-rs-fixes-mutants.py [name substring ...]
Prints `name | outcome`; rc 1 when one survives. vendor/ is never mutated (ARCH-POS-24)."""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
import mutant_guard as g  # noqa: E402

UA = ROOT / "clients/ua-rs"
SOFT, FALCON, PQSIGN = UA / "src/falcon/soft.rs", UA / "src/falcon.rs", UA / "src/wallet/pqsign.rs"
ENV = {**os.environ, "CARGO_INCREMENTAL": "0"}
CARGO = [str(ROOT / "scripts/capped"), "cargo", "test", "--locked", "-j", "2", "--no-default-features", "--features", "vectors"]
LIB = CARGO + ["--lib", "pqsign"]
GATE = CARGO + ["--test", "fndsa_vrfy"]

MUTANTS = [
    # FR-12: verify after sign
    (
        "sign: no verify after sign",
        PQSIGN,
        "            if !falcon::verify(p, key_data, &m, &sig) {\n                return Err(Error::FalconSelfCheck);\n            }\n",
        "",
        LIB,
    ),
    # FR-11: the glue's kind dispatch and length checks
    ("kind dispatch: 0x0132 as FN-DSA-1024", PQSIGN, "0x0132 => Ok(falcon::FNDSA512),", "0x0132 => Ok(falcon::FNDSA1024),", LIB),
    ("keypair: seed length unchecked", FALCON, "if seed.len() != SEED_LEN || pk.len()", "if pk.len()", LIB),
    ("sign: secret key length unchecked", FALCON, "if sk.len() != p.sk || rnd.len()", "if rnd.len()", LIB),
    ("verify: signature length unchecked", FALCON, "if pk.len() != p.pk || sig.len() != p.sig {", "if pk.len() != p.pk {", GATE),
    ("soft sign: padded length unchecked", SOFT, "rc == 0 && len == sig.len()", "rc == 0", GATE),
    # FR-8: the guard sees a hidden module
    (
        "soft: a hidden module used",
        SOFT,
        "use zeroize::Zeroize;\n",
        "use zeroize::Zeroize;\n#[allow(unused_imports)]\nuse ::falcon::sign as _hidden;\n",
        GATE,
    ),
]


def main():
    g.refuse_dirty([m[1] for m in MUTANTS], ROOT)
    only = sys.argv[1:]
    todo = [m for m in MUTANTS if not only or any(o in m[0] for o in only)]
    survived = 0
    for name, f, old, new, cmd in todo:
        src = f.read_bytes()
        text = src.decode()
        if text.count(old) != 1:
            print(f"[mutants] refused: {name}: the anchor is not unique in {f.relative_to(ROOT)}", flush=True)
            raise SystemExit(2)
        dl = g.limit(cmd, cwd=UA, env=ENV)
        saved = {f: src}
        try:
            f.write_text(text.replace(old, new))
            r = g.run(cmd, dl, cwd=UA, env=ENV, capture_output=True, text=True)
        finally:
            g.restore(saved)
        res = g.outcome(r, "killed" if r.returncode != 0 else "SURVIVED")
        survived += res == "SURVIVED"
        out = (r.stdout or "").splitlines()
        at = next((i for i, ln in enumerate(out) if "panicked at" in ln), None)
        red = " ".join(ln.strip() for ln in out[at : at + 4]) if at is not None else ""
        print(f"{name} | {res} | {red}", flush=True)
    print(f"[mutants] {len(todo)} mutants, {len(todo) - survived} killed, {survived} survived", flush=True)
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
