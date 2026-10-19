#!/usr/bin/env python3
"""Fix E timing table: base (0dc869d) vs new (fix E) from ct-timing.sh's jsonl files.
Per (mode, relation, step): p50 = mean of the rounds' p50, p99 = max of the rounds' p99; ratio = new / base.
Usage: python3 -I summarize.py <dir>  (prints a Markdown table)"""
import json
import sys
from collections import defaultdict

d = sys.argv[1]
rows = defaultdict(lambda: {"base": [], "new": []})
for mode in ("native-generic", "native-fast", "wasm-generic", "wasm-fast"):
    for side in ("base", "new"):
        for line in open(f"{d}/{side}-{mode}.jsonl"):
            line = line.strip()
            if not line.startswith("{"):
                continue
            r = json.loads(line)
            if "timing" in r and "adversarial" not in r["timing"]:
                rows[(mode, r["timing"])][side].append((r["p50_ms"], r["p99_ms"]))

print("| mode | step | base p50 | new p50 | ratio | base p99 | new p99 | ratio |")
print("|---|---|---:|---:|---:|---:|---:|---:|")
for (mode, step), s in rows.items():
    if not s["base"] or not s["new"]:
        continue
    b50 = sum(x[0] for x in s["base"]) / len(s["base"])
    n50 = sum(x[0] for x in s["new"]) / len(s["new"])
    b99 = max(x[1] for x in s["base"])
    n99 = max(x[1] for x in s["new"])
    print(f"| {mode} | {step} | {b50:.2f} | {n50:.2f} | {n50 / b50:.2f} | {b99:.2f} | {n99:.2f} | {n99 / b99:.2f} |")
