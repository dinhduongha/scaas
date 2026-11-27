# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""user-profiles wave-1 code review, task R4 mutants: the clientkeys reference and the rows (review STATUS rows D-1, D-2,
D-8, D-11, A-17's preview):
python3 clients/scaas-sdk/runs/2026-11-28-user-profiles-r4-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import mutants_lib  # noqa: E402

mutants_lib.PREFIX = "2026-11-28-user-profiles-"
mutants_lib.NOT_CODE = [
    ":!clients/scaas-sdk/runs/*-mutants.txt",
    ":!clients/scaas-sdk/runs/2026-11-27-user-profiles-summary.txt",
]

P = "clients/clientkeys/src/profile.js"
S = "clients/clientkeys/src/seal.js"
X = "clients/scaas-profile/src/export.rs"


def ck(test, pattern):
    """One clientkeys test file, the tests whose name matches `pattern` (the generator's byte-for-byte run left out)."""
    return f'cd clients/clientkeys && ../../scripts/capped node --test --test-name-pattern="{pattern}" test/{test}'


REFUSALS = ck("profile.test.js", "every import refusal")
STRICT = ck("profile.test.js", "strictness")
MUTANTS = [
    ("D-1 the reference strips a leading BOM again",
     [(P, "{ fatal: true, ignoreBOM: true }", "{ fatal: true }")], REFUSALS, "every import refusal"),
    ("D-2 the reference takes settings that are not a JSON object",
     [(P, '  if (!object(settings)) fail("settings");\n', "")], REFUSALS, "every import refusal"),
    ("D-2 the reference takes an item above 16 MiB",
     [(P, '  if (items.some(([, v]) => v.length > ITEM_MAX)) fail("item");\n', "")], REFUSALS, "every import refusal"),
    ("A-17 the reference takes an item without a JSON rev",
     [(P, '  if (!items.every(([, v]) => Number.isSafeInteger(object(v)?.rev) && object(v).rev >= 0)) fail("item");\n', "")],
     REFUSALS, "every import refusal"),
    ("D-8 checkKdf accepts a field more",
     [(P, '  if (k === null || typeof k !== "object" || Object.keys(k).sort().join() !== KDF_FIELDS)\n',
       '  if (k === null || typeof k !== "object")\n')],
     ck("profile.test.js", "KDF bounds"), "KDF bounds"),
    ("D-8 the anchor's parts in an object's order (integer-like names first, numeric)",
     [(P, '  return `{"gen":${JSON.stringify(a.gen)},"envelope":${rs(a.envelope)},"parts":{${parts.join(",")}}}`;\n',
       "  const o = Object.fromEntries(Object.keys(a.parts).sort(cmpUtf8).map((k) => [k, JSON.parse(rs(a.parts[k]))]));\n"
       '  return JSON.stringify({ gen: a.gen, envelope: JSON.parse(rs(a.envelope)), parts: o }) || parts;\n')],
     STRICT, "strictness"),
    ("D-8 be() takes a value that is not a safe integer",
     [(P, '  if (typeof v !== "bigint" && !Number.isSafeInteger(v)) throw new ProfileError("Argument");\n', "")],
     STRICT, "strictness"),
    ("D-8 itemJson takes a rev above 2^53 - 1",
     [(P, '  if (!Number.isSafeInteger(rev) || rev < 0) throw new ProfileError("Argument");\n  return JSON.stringify({ rev, sealed',
       "  return JSON.stringify({ rev, sealed")],
     STRICT, "strictness"),
    ("D-11 decodeBackup accepts a key-locked secret",
     [(S, '  if (secrets.some((s) => String(s.label).startsWith("native-import-locked:")))\n'
          '    fail("Argument", "backup secret: a key-locked label");\n', "")],
     ck("keystore.test.js", "backupPayloads"), "backupPayloads"),
    ("A-17 the preview takes an item without a JSON rev",
     [(X, "        .any(|(_, b)| b.len() > MAX_BYTES || rev_of(b) == u64::MAX)\n", "        .any(|(_, b)| b.len() > MAX_BYTES)\n")],
     "cd clients/scaas-profile && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
     "--features test-hooks --test review -- --exact a17_item_without_rev_refused_at_the_preview"),
]

if __name__ == "__main__":
    mutants_lib.main("r4", MUTANTS)
