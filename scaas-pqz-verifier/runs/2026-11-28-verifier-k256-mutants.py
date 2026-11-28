# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""verifier-k256 mutants (owner 2026-11-28, CTR-PQZ-28 Change: the verdict key on k256 0.14; review VK-5, VK-7): one at
a time on a clean tree, each applied to src/key.rs, the lib unit tests, tests/verdict_key.rs, tests/keystore.rs and
tests/service.rs run through scripts/capped (--no-fail-fast), the file restored in the same run, then
`git diff --exit-code`; a mutant that does not compile is reported as such, never as a kill. Writes `mutant | test that went red | rc` to the -mutants.txt beside this
file; full outputs to git-ignored .log files. Run from scaas-pqz-verifier/: python3 runs/2026-11-28-verifier-k256-mutants.py"""

import re
import subprocess
import sys

SRC = "src/key.rs"
OUT = "runs/2026-11-28-verifier-k256-mutants.txt"
SIGN = "let (sig, rec) = self.key.sign_prehash_recoverable(hash.as_slice());"
SET_V = "out[64] = v_byte(rec);"
V = "27 + u8::from(rec.is_y_odd())"
LEN = "anyhow::ensure!(secret.len() == 32,"
ADDR = "keccak256(&point.as_bytes()[1..])[12..]"
# RFC 6979 with extra data: k256's `_with_rng` form fed a constant (a fixed `ad`, as a hedged signer would add)
AD = (
    "struct Ad;\n"
    "        impl k256::elliptic_curve::rand_core::TryRng for Ad {\n"
    "            type Error = core::convert::Infallible;\n"
    "            fn try_next_u32(&mut self) -> Result<u32, Self::Error> { Ok(1) }\n"
    "            fn try_next_u64(&mut self) -> Result<u64, Self::Error> { Ok(1) }\n"
    "            fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), Self::Error> { d.fill(1); Ok(()) }\n"
    "        }\n"
    "        impl k256::elliptic_curve::rand_core::TryCryptoRng for Ad {}\n"
    "        let (sig, rec) = self.key.sign_prehash_recoverable_with_rng(&mut Ad, hash.as_slice()).unwrap();"
)
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
    ("wrong recovery id", V, "27 + u8::from(!rec.is_y_odd())"),
    ("recovery id without the 27 offset", V, "u8::from(rec.is_y_odd())"),
    ("the x-reduced bit in v (29 / 30 possible, VK-5)", V, "27 + rec.to_byte()"),
    (
        "hashing the wrong digest (keccak256 of the hash)",
        SIGN,
        SIGN.replace("hash.as_slice()", "keccak256(hash).as_slice()"),
    ),
    ("the 32-byte length check removed (VK-7)", LEN, "anyhow::ensure!(true,"),
    ("the address over the 0x04-prefixed point (VK-7)", ADDR, "keccak256(point.as_bytes())[12..]"),
    ("RFC 6979 with extra data (VK-7)", SIGN, AD),
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
                cmd += ["--no-fail-fast", "--lib", "--test", "verdict_key", "--test", "keystore", "--test", "service"]
                rc = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT).returncode
        finally:
            open(SRC, "w").write(orig)
        assert subprocess.run(["git", "diff", "--exit-code", "--", SRC]).returncode == 0, f"{name}: not restored"
        text = open(log).read()
        red = re.findall(r"^test (\S+) \.\.\. FAILED$", text, re.M)
        if not red and re.search(r"^error(\[E\d+\])?:", text, re.M) and "test result" not in text:
            red = ["COMPILE ERROR (not a kill)"]
        rows.append(f"{name} | {', '.join(red) or 'NONE (survivor)'} | {rc}")
        print(rows[-1], flush=True)
    with open(OUT, "w") as f:
        f.write("mutant | test that went red | rc\n" + "\n".join(rows) + "\n")


main()
