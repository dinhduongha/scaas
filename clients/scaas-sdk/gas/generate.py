#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The SDK gas table's generator (scaas-sdk spec §13.3, owner 2026-11-19, part 3b).

Reads an input list (default clients/scaas-sdk/gas/inputs.json: the forge runs, the base rows' entries per domain kind,
the per-byte inputs, the verify signer kinds, the assumptions) and the forge measurement file it names, and writes the
whole table (default clients/scaas-sdk/gas/reference.json). A module with its own input list and measurement runs the same
script with --inputs and --out.

  generate.py [--inputs F] [--out F]            regenerate the table from the measurement file
  generate.py --measure [--inputs F] [--out F]  first re-measure: each forge run alone, SDK_GAS_WRITE=true, via scripts/capped
  generate.py --check [--inputs F] [--out F]    the table equals what the measurement file gives (CI); exit 1 if not

A base row's figure is the worst of the kind's variants measured (`<kind>_<entry>_<fresh|used>_<variant>`), rounded up to
the next 1,000; its per-byte part the worst `<kind>_<entry>_per_byte_<variant>`; its `save` (owner 2026-11-19, ruling 1)
the worst `<kind>_<entry>_saved_<variant>` less `..._fresh_<variant>`, its `fee_extra` (ruling 3) the worst
`..._fee_<variant>` less `..._fresh_<variant>` (a wrap-in entry: less `..._held_<variant>`, the signer holding units, A6),
its `ua_extra` (A1) the worst `..._ua_<variant>` (the derived reference signer `ua_signer` of the input list) less
`..._fresh_<variant>` less that signer's verify delta, absent when not positive (a source item `a-b[-c]` is the first key less
the others); a verify row `verify_<kind>_delta`, its `sig_bytes` (ruling 2, A4: every row) `verify_<kind>_sig_bytes`, its
`margin` (ruling 2 (b) of the sampled check: a kind whose worst case cannot be determined) and `stand_in` from the input
list. Prints its run time.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))


def ceil1000(g):
    return -(-g // 1000) * 1000


def variants(m, prefix):
    """The keys `<prefix><variant>` of `m`, the split parts left out."""
    return sorted(k for k in m if k.startswith(prefix) and not k.endswith(("_regular", "_state")))


def extra(m, src, kind, entry, what, less=None):
    """The worst per-variant difference `<kind>_<entry>_<what>_<v>` less its base, `<kind>_<entry>_held_<v>` where measured
    (A6: a wrap-in entry's fee against a signer holding units) else `<kind>_<entry>_fresh_<v>`, less the key `less` if given
    (A1: the derived signer's verify row); None when nothing is measured, or (with `less`) when nothing is added."""
    pre = f"{kind}_{entry}_{what}_"
    pairs = []
    for k in variants(m, pre):
        v = k[len(pre) :]
        held = f"{kind}_{entry}_held_{v}"
        pairs.append((k, held if what == "fee" and held in m else f"{kind}_{entry}_fresh_{v}"))
    if not pairs:
        return None
    for a, b in pairs:
        if b not in m:
            raise SystemExit(f"no base row {b} for {a}")
    measured = max(m[a] - m[b] for a, b in pairs) - (m[less] if less else 0)
    tail = f"-{less}" if less else ""
    if measured <= 0:
        if less:
            return None  # A1: absent where the entry has no such cost
        raise SystemExit(f"{kind} {entry} {what}: no cost added ({measured})")
    return {
        "gas": ceil1000(measured),
        "measured": measured,
        "source": f"{src}#{','.join(f'{a}-{b}{tail}' for a, b in pairs)}",
    }


def table(inputs, m):
    src = inputs["measurements"]
    base = []
    for group in inputs["base"]:
        for kind in group["kinds"]:
            for entry in group["entries"]:
                for fresh in (True, False):
                    keys = variants(m, f"{kind}_{entry}_{'fresh' if fresh else 'used'}_")
                    if not keys:
                        raise SystemExit(f"no measurement for {kind} {entry} {'fresh' if fresh else 'used'}")
                    measured = max(m[k] for k in keys)
                    row = {
                        "entry": entry,
                        "kind": kind,
                        "fresh": fresh,
                        "gas": ceil1000(measured),
                        "measured": measured,
                        "source": f"{src}#{','.join(keys)}",
                    }
                    if entry in inputs["per_byte"]:
                        pkeys = variants(m, f"{kind}_{entry}_per_byte_")
                        if not pkeys:
                            raise SystemExit(f"no per-byte measurement for {kind} {entry}")
                        row["per_byte"] = {
                            "input": inputs["per_byte"][entry],
                            "gas": max(m[k] for k in pkeys),
                            "source": f"{src}#{','.join(pkeys)}",
                        }
                    if entry in inputs["save"]:
                        row["save"] = extra(m, src, kind, entry, "saved")
                        if row["save"] is None:
                            raise SystemExit(f"no saved-record measurement for {kind} {entry}")
                    fee = extra(m, src, kind, entry, "fee")
                    if fee is not None:
                        row["fee_extra"] = fee
                    ua = extra(m, src, kind, entry, "ua", f"verify_0x{inputs['ua_signer']:04x}_delta")
                    if ua is not None:
                        row["ua_extra"] = ua
                    base.append(row)
    verify = [
        {
            "signer": 0,
            "gas": 0,
            "measured": 0,
            "source": "the reference signer (0 by definition)",
            "sig_bytes": m["verify_native_sig_bytes"],
        }
    ]
    for signer in inputs["verify"]:
        k = f"verify_0x{signer:04x}_delta"
        if k not in m:
            raise SystemExit(f"no measurement {k}")
        row = {"signer": signer, "gas": ceil1000(m[k]), "measured": m[k], "source": f"{src}#{k}"}
        row["sig_bytes"] = m[f"verify_0x{signer:04x}_sig_bytes"]
        if str(signer) in inputs["margin"]:
            row["margin"] = inputs["margin"][str(signer)]
        if str(signer) in inputs["stand_in"]:
            row["stand_in"] = inputs["stand_in"][str(signer)]
        verify.append(row)
    return {
        "format": "scaas.gas-table",
        "v": 2,
        "name": inputs["name"],
        "family": inputs["family"],
        "assumptions": inputs["assumptions"],
        "base": base,
        "verify": verify,
    }


def measure(inputs):
    forge = os.path.join(ROOT, inputs["forge_dir"])
    env = dict(os.environ, SDK_GAS_WRITE="true")
    runs = inputs["runs"]
    for i, (path, contract, test) in enumerate(runs, 1):
        print(f"[gas] {i}/{len(runs)} {contract}.{test}", flush=True)
        cmd = [os.path.join(ROOT, "scripts", "capped"), "forge", "test", "--match-path", path]
        cmd += ["--match-contract", f"^{contract}$", "--match-test", f"^{test}\\("]
        r = subprocess.run(cmd, cwd=forge, env=env, capture_output=True, text=True, check=False)
        if r.returncode != 0 or not re.search(r"\b1 passed\b", r.stdout):
            sys.stdout.write(r.stdout[-4000:] + r.stderr[-2000:])
            raise SystemExit(f"[gas] FAIL {contract}.{test}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--inputs", default=os.path.join(ROOT, "clients", "scaas-sdk", "gas", "inputs.json"))
    p.add_argument("--out", default=os.path.join(ROOT, "clients", "scaas-sdk", "gas", "reference.json"))
    p.add_argument("--measure", action="store_true")
    p.add_argument("--check", action="store_true")
    a = p.parse_args()
    t0 = time.monotonic()
    with open(a.inputs) as f:
        inputs = json.load(f)
    if a.measure:
        measure(inputs)
    with open(os.path.join(ROOT, inputs["measurements"])) as f:
        m = json.load(f)
    text = json.dumps(table(inputs, m), indent=2) + "\n"
    took = f"{time.monotonic() - t0:.1f} s"
    if a.check:
        with open(a.out) as f:
            if f.read() != text:
                raise SystemExit(f"[gas] {a.out} differs from the measurement; run generate.py ({took})")
        print(f"[gas] check ok ({took})")
        return
    with open(a.out, "w") as f:
        f.write(text)
    t = json.loads(text)
    print(f"[gas] wrote {a.out}: {len(t['base'])} base, {len(t['verify'])} verify rows ({took})")


if __name__ == "__main__":
    main()
