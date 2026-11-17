#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T8b mutants (ua-rs Polkadot junctions, the manifest's polkadotPaths, the path parser's caps); runner and modes:
2026-11-17-ua-rs-native-mutants-run.py. From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

RS = "clients/ua-rs"
SUB, MAN = RS + "/src/wallet/substrate.rs", RS + "/src/wallet/manifest.rs"
T = [os.path.abspath("scripts/capped"), "cargo", "test", "--locked", "--offline", "-j2", "--features", "vectors", "--test", "wallet_native", "--test", "fuzz_caps"]
M = [(n, f, a, b, T, RS) for n, f, a, b in [
    ("hard and soft swapped", SUB, "        sk = if j.hard {", "        sk = if !j.hard {"),
    ("SCALE prefix dropped", SUB, "        [&[u8::try_from(j.len() << 2).map_err(|_| Error::Argument)?][..], j].concat()", "        j.to_vec()"),
    ("one-byte compact length at 64", SUB, "    } else if j.len() < 64 {", "    } else if j.len() <= 64 {"),
    ("hash at 32 bytes", SUB, "    if enc.len() <= 32 {", "    if enc.len() < 32 {"),
    ("numeric junction as a string", SUB, "    let enc = if j.iter().all(u8::is_ascii_digit) {", "    let enc = if false {"),
    ("leading zero accepted", SUB, "            || (digits && j.len() > 1 && j.first() == Some(&b'0'))\n", "\n"),
    ("0x junction accepted", SUB, "            || j.starts_with(b\"0x\")\n", "\n"),
    ("polkadotPaths written when empty", MAN, "        let paths = if self.polkadot_paths.is_empty() {\n            String::new()\n        } else {",
     "        let paths = if false {\n            String::new()\n        } else {"),
    ("the 64-path cap removed", MAN, "    if polkadot_paths.len() > MAX_POLKADOT_PATHS || ", "    if "),
    ("the parser's length cap removed", SUB, "    if b.len() > MAX_PATH_BYTES {\n        return Err(Error::Argument);\n    }\n", ""),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
