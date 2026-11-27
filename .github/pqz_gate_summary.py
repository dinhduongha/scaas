# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The step table of pqz-gate.yml's gate runs, from gate.sh's progress files (runs/gate/<set>-progress.txt).

  python3 -I .github/pqz_gate_summary.py <progress file>...     -> one table per set on stdout; exit 1 unless every set PASS
  python3 -I .github/pqz_gate_summary.py --self-test

Only the lines after a file's last `gate ... started` line count (the committed files keep earlier runs). The files of
one set (the two parts of pqz-gate.yml) merge: a step counts where it ran (ok, FAILED, skipped); a step only `resumed`
in every file was recorded as passed by the workflow for the other part and never ran, so the set is INCOMPLETE. A set is
PASS only when every file ends with gate.sh's PASS line, at one tree, and no step is left unrun. Rows are the format of
runs/<date>-pqz-gate-<sets>-summary.txt: step | commit | rc | time | parts.
"""

import re
import sys

START = re.compile(r"^\S+ gate \S+ \(set (\S+)\) started at (\S+), tree (\S+)$")
END = re.compile(r"^\S+ gate \S+ \(set \S+\): (PASS|FAIL)$")
EVENT = re.compile(r"^\S+ (ok|FAILED|resumed|skipped) +(\S+?)(?: rc=(\d+))?(?: \((.*)\))?$")


def parse(lines):
    """(set, commit, tree, end, {step: [status, rc, time, ok parts, failed parts]}) of the last run in lines."""
    i = max((n for n, line in enumerate(lines) if START.match(line)), default=None)
    if i is None:
        return None
    s, commit, tree = START.match(lines[i]).groups()
    end, steps = None, {}
    for line in lines[i + 1 :]:
        if m := END.match(line):
            end = m.group(1)
        elif m := EVENT.match(line):
            what, name, rc, rest = m.groups()
            if name.startswith("step/"):
                row = steps.setdefault(name[5:], [None, "-", "-", 0, 0])
                row[0] = what
                row[1] = {"ok": "0", "FAILED": rc or "?"}.get(what, "-")
                row[2] = rest if what in ("ok", "FAILED") else "-"
                if what == "skipped":
                    row[2] = f"skipped ({rest})"
            elif "/" in name and what in ("ok", "FAILED"):
                row = steps.setdefault(name.split("/")[0], [None, "-", "-", 0, 0])
                row[3 if what == "ok" else 4] += 1
    return s, commit, tree, end, steps


def table(runs):
    """Markdown for the runs of one set; (text, verdict)."""
    s = runs[0][0]
    merged = {}
    for _, _, _, _, steps in runs:
        for name, row in steps.items():
            if name not in merged or merged[name][0] in (None, "resumed"):
                merged[name] = row
    trees = sorted({r[2] for r in runs})
    commits = sorted({r[1] for r in runs})
    unrun = [n for n, row in merged.items() if row[0] in (None, "resumed")]
    if len(trees) != 1:
        verdict = "FAIL (parts at different trees)"
    elif any(r[3] != "PASS" for r in runs):
        verdict = "FAIL" if any(r[3] == "FAIL" for r in runs) else "INCOMPLETE (a part did not finish)"
    elif unrun:
        verdict = "INCOMPLETE (not run: " + " ".join(unrun) + ")"
    else:
        verdict = "PASS"
    out = [
        f"### set {s}: {verdict}",
        "",
        f"tree {' '.join(trees)}, commit {' '.join(commits)}, {len(runs)} part(s)",
        "",
    ]
    out += ["step | commit | rc | time | parts", "--- | --- | --- | --- | ---"]
    for name, (st, rc, t, ok, bad) in merged.items():
        if st in (None, "resumed"):
            rc, t = "-", "not run here"
        parts = f"{ok} ok" + (f", {bad} failed" if bad else "") if ok or bad else "-"
        out.append(f"{name} | {' '.join(commits)} | {rc} | {t} | {parts}")
    return "\n".join(out) + "\n", verdict


def summary(texts):
    """Tables for the progress files' texts, grouped by set; (markdown, all PASS)."""
    by_set = {}
    for text in texts:
        run = parse(text.splitlines())
        if run:
            by_set.setdefault(run[0], []).append(run)
    if not by_set:
        return "no gate run found in the progress files\n", False
    blocks = [table(runs) for _, runs in sorted(by_set.items())]
    return "\n".join(b[0] for b in blocks), all(b[1] == "PASS" for b in blocks)


def self_test():
    old = "2026-10-01T00:00:00 gate x (set s1) started at aaa, tree s1-old\n2026-10-01T00:00:01 FAILED  step/stale rc=1 (0h0m1s)\n"
    a = (
        old + "2026-11-27T00:00:00 gate s1 (set s1) started at abc, tree s1-t\n"
        "2026-11-27T00:00:00 start   step/kat\n2026-11-27T00:00:18 ok      step/kat (0h0m18s)\n"
        "2026-11-27T00:00:18 ok      diff/portable (1h0m0s)\n2026-11-27T00:00:19 ok      step/diff (1h0m1s)\n"
        "2026-11-27T00:00:20 resumed step/fuzz\n2026-11-27T00:00:20 gate s1 (set s1): PASS\n"
    )
    b = (
        "2026-11-27T00:00:00 gate s1 (set s1) started at abc, tree s1-t\n2026-11-27T00:00:00 resumed step/kat\n"
        "2026-11-27T00:00:00 resumed step/diff\n2026-11-27T00:00:01 ok      fuzz/codec (0h1m0s)\n"
        "2026-11-27T00:00:02 FAILED  fuzz/mutate rc=1 (0h1m0s)\n2026-11-27T00:00:02 FAILED  step/fuzz rc=1 (0h2m0s)\n"
        "2026-11-27T00:00:03 skipped step/xcheck (set s1 has no PQZH (set.json pqzh))\n"
        "2026-11-27T00:00:03 gate s1 (set s1): FAIL\n"
    )
    b_ok = b.replace("FAILED  step/fuzz rc=1", "ok      step/fuzz").replace("): FAIL", "): PASS")
    md, ok = summary([a, b_ok])
    assert ok and "### set s1: PASS" in md, md
    assert "kat | abc | 0 | 0h0m18s | -" in md and "diff | abc | 0 | 1h0m1s | 1 ok" in md, md
    assert (
        "fuzz | abc | 0 | 0h2m0s | 1 ok, 1 failed" in md and "xcheck | abc | - | skipped (set s1 has no PQZH" in md
    ), md
    assert "s1-old" not in md and "stale" not in md
    md, ok = summary([a, b])
    assert not ok and "s1: FAIL" in md and "fuzz | abc | 1 |" in md, md
    md, ok = summary([a])  # one part alone: fuzz never ran here
    assert not ok and "INCOMPLETE (not run: fuzz)" in md and "fuzz | abc | - | not run here" in md, md
    md, ok = summary([a, b_ok.replace("tree s1-t", "tree s1-u")])
    assert not ok and "different trees" in md, md
    md, ok = summary([a.rsplit("2026-11-27T00:00:20 gate", 1)[0], b_ok])
    assert not ok and "did not finish" in md, md
    assert summary(["nothing\n"]) == ("no gate run found in the progress files\n", False)
    print("pqz_gate_summary self-test ok")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        sys.exit(0)
    md, ok = summary([open(p, encoding="utf-8").read() for p in sys.argv[1:]])
    sys.stdout.write(md)
    sys.exit(0 if ok else 1)
