# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""verifier-k256 mutants (owner 2026-11-28, CTR-PQZ-28 Change: the verdict key on k256 0.14): one at a time on a clean
tree, each applied to src/key.rs, tests/verdict_key.rs and tests/service.rs run through scripts/capped, the file restored
in the same run, then `git diff --exit-code`. Writes `mutant | test that went red | rc` to the -mutants.txt beside this
file; full outputs to git-ignored .log files. Run from scaas-pqz-verifier/: python3 runs/2026-11-28-verifier-k256-mutants.py"""

import re
import subprocess
import sys

SRC = "src/key.rs"
OUT = "runs/2026-11-28-verifier-k256-mutants.txt"
SIGN = "let (sig, rec) = self.key.sign_prehash_recoverable(hash.as_slice());"
SET_V = "out[64] = 27 + rec.to_byte();"
MUTANTS = [
    (
        "low-s normalisation dropped (s -> n - s, the recovery id flipped with it)",
        SET_V,
        SET_V
        + "\n        let n = alloy::primitives::U256::from_str_radix("
        + '"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16).unwrap();'
        + "\n        let s = alloy::primitives::U256::from_be_slice(&out[32..64]);"
        + "\n        out[32..64].copy_from_slice(&(n - s).to_be_bytes::<32>());"
        + "\n        out[64] ^= 1;",
    ),
    ("wrong recovery id", SET_V, "out[64] = 27 + (rec.to_byte() ^ 1);"),
    ("recovery id without the 27 offset", SET_V, "out[64] = rec.to_byte();"),
    (
        "hashing the wrong digest (keccak256 of the hash)",
        SIGN,
        SIGN.replace("hash.as_slice()", "keccak256(hash).as_slice()"),
    ),
]


def main():
    if subprocess.run(["git", "diff", "--quiet", "--exit-code", "--", SRC]).returncode:
        sys.exit(f"{SRC} is not clean")
    orig = open(SRC).read()
    rows = []
    for i, (name, old, new) in enumerate(MUTANTS, 1):
        assert orig.count(old) == 1, name
        log = f"runs/2026-11-28-verifier-k256-mutant-{i}.log"
        try:
            open(SRC, "w").write(orig.replace(old, new))
            with open(log, "w") as f:
                cmd = ["../scripts/capped", "cargo", "test", "--offline", "--locked", "-j4"]
                cmd += ["--no-fail-fast", "--test", "verdict_key", "--test", "service"]
                rc = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT).returncode
        finally:
            open(SRC, "w").write(orig)
        assert subprocess.run(["git", "diff", "--exit-code", "--", SRC]).returncode == 0, f"{name}: not restored"
        red = re.findall(r"^test (\S+) \.\.\. FAILED$", open(log).read(), re.M)
        rows.append(f"{name} | {', '.join(red) or 'NONE (survivor)'} | {rc}")
        print(rows[-1], flush=True)
    with open(OUT, "w") as f:
        f.write("mutant | test that went red | rc\n" + "\n".join(rows) + "\n")


main()
