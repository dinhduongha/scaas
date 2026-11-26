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
the others), the variants measured without that signer listed `unmeasured` (G2: theirs is the largest measured on another
variant), none on an entry a derived signer cannot sign (`ua_native`), and a row no variant of which was measured so takes the
largest measured for the same entry and lane state on another kind (`from_kind`, every variant `unmeasured`; none anywhere is refused),
and (Q1) where a second derived party was measured (`..._ua2_<variant>`) its `second_party`, the worst of that less the one
derived party less the verify delta; a verify row `verify_<kind>_delta`, its `sig_bytes` (ruling 2, A4: every row) `verify_<kind>_sig_bytes`, its
`margin` (ruling 2 (b) of the sampled check: a kind whose worst case cannot be determined) and `stand_in` from the input
list (a base row's: `base_stand_in`, keyed `<kind>:<entry>`, owner 2026-11-19, I2). A base or verify row whose cost grows with a count (owner 2026-11-19, I1; optional `per_item` of the input list:
`<kind>:<entry>` (kind-qualified, I1 part 2: Zether's `mtxRollOver` has no count, PQZ's has) or a signer kind's number →
the item counted, one of ITEMS) gets `item` and `per_item` {gas, base_count 0, source}: its gas the worst whole-gas slope
`<kind>_<entry>_per_item_<variant>` (a verify row: `verify_<kind>_per_item`), and its figure keys then hold the gas at a
count of 0 (the line's intercept, fitted by the forge harness); where the harness pinned the line's excess at the largest
count (`<kind>_<entry>_overshoot_<variant>`: owner rulings P1, P2; proposal P4) an assumption states the worst. A base row's
`regular` (EIP-8037, controller call, owner auto-run 2026-11-19) and a counted row's `per_item.regular` come from the
measurement's `_regular` split (`regular`). A base group `fresh_only` (the registry writes: the registry's first write of
its kind, the lane the SDK quotes) gets its `fresh` rows only. Prints its run time.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

# The counts a row's `item` may name: the SDK's `GAS_ITEMS` (src/config.rs), which reads each from the operation.
ITEMS = ("legs", "accounts", "entries", "members", "env_items", "orders")

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


def ua_row(inputs, m, src, row, pending):
    """A1 and G2 (owner 2026-11-19): the row's `ua_extra`, the worst of the variants measured with the derived reference signer
    (`<kind>_<entry>_ua_<variant>`), the variants measured without it listed `unmeasured` (theirs is that largest measured on
    another variant); none on an entry a derived signer cannot sign (`ua_native`: its kind or entry); a row with no variant
    measured is left to `ua_fallback` (`pending`)."""
    kind, entry = row["kind"], row["entry"]
    pre = f"{kind}_{entry}_"
    fresh = {k[len(pre) + 6 :] for k in variants(m, pre + "fresh_")}
    ua = {k[len(pre) + 3 :] for k in variants(m, pre + "ua_")}
    if kind in inputs["ua_native"]["kinds"] or entry in inputs["ua_native"]["entries"]:
        if ua:
            raise SystemExit(f"{kind} {entry}: listed native-only (ua_native) but measured with a derived signer")
        return
    if not ua:
        pending.append((row, sorted(fresh)))
        return
    x = extra(m, src, kind, entry, "ua", f"verify_0x{inputs['ua_signer']:04x}_delta")
    if x is not None:
        if fresh - ua:
            x["unmeasured"] = sorted(fresh - ua)
        row["ua_extra"] = x
    two = variants(m, pre + "ua2_")
    if two:
        # Q1 (owner 2026-11-19): a second derived party debited (the payee beside the payer), over the first and its verify
        less = f"verify_0x{inputs['ua_signer']:04x}_delta"
        items = [(k, pre + "ua_" + k[len(pre) + 4 :]) for k in two]
        worst = max(m[a] - m[b] - m[less] for a, b in items)
        if x is None:
            raise SystemExit(f"{kind} {entry}: a second derived party measured without the first")
        x["second_party"] = {"measured": worst, "source": f"{src}#{','.join(f'{a}-{b}-{less}' for a, b in items)}"}


def ua_fallback(base, pending):
    """G2: a row whose variants none was measured with the derived signer takes the largest `ua_extra` measured for the same
    entry and lane state on another kind (`from_kind`, every variant `unmeasured`); none measured anywhere is refused."""
    for row, unmeasured in pending:
        donors = [
            r
            for r in base
            if r["entry"] == row["entry"]
            and r["fresh"] == row["fresh"]
            and r["kind"] != row["kind"]
            and "ua_extra" in r
            and "from_kind" not in r["ua_extra"]
        ]
        if not donors:
            raise SystemExit(f"{row['kind']} {row['entry']}: no ua_extra measured for the entry on any kind (G2)")
        d = max(donors, key=lambda r: r["ua_extra"]["measured"])
        x = {k: d["ua_extra"][k] for k in ("gas", "measured", "source")}
        x["from_kind"] = d["kind"]
        x["unmeasured"] = unmeasured
        row["ua_extra"] = x


def per_item(inputs, m, src, name, prefix):
    """The row's `item` and `per_item` (I1) when the input list counts `name`: the worst slope of the keys `prefix*`."""
    item = inputs.get("per_item", {}).get(name)
    if item is None:
        return {}
    if item not in ITEMS:
        raise SystemExit(f"{name}: item {item!r} is not one of {ITEMS}")
    keys = sorted(k for k in m if k.startswith(prefix))
    if not keys:
        raise SystemExit(f"no per-item measurement {prefix}")
    return {
        "item": item,
        "per_item": {"gas": max(m[k] for k in keys), "base_count": 0, "source": f"{src}#{','.join(keys)}"},
    }


def regular(m, src, kind, entry, lane, keys, counted):
    """EIP-8037 (controller call, owner auto-run 2026-11-19): the row's regular gas, the part EIP-7825's 2^24 caps (the
    transaction's gas limit covers regular + state and is held to the block gas limit). An uncounted row: the worst
    `<key>_regular` of its variant keys `keys`, rounded up; None when a variant lacks the split. A counted row: the line over
    the points `<kind>_<entry>_n<N>_<lane>_<variant>_regular` (a count-0 key's own `_regular` the point N = 0): its slope the
    steepest between two neighbouring points of any variant and lane (the derived runs `_ua_` included), its figure the largest
    point of the row's lane less slope × N (at least 1); (None, None) without two points of one variant. Returns the row's
    `regular` part and the slope (`per_item.regular`)."""
    if not counted:
        if any(f"{k}_regular" not in m for k in keys):
            return None, None
        x = max(m[f"{k}_regular"] for k in keys)
        return {"gas": ceil1000(x), "measured": x, "source": f"{src}#{','.join(f'{k}_regular' for k in keys)}"}, None
    pat = re.compile(rf"^{re.escape(kind)}_{re.escape(entry)}_n(\d+)_(fresh|used|ua)_(.+)_regular$")
    series = {}
    for k in m:
        hit = pat.match(k)
        if hit:
            series.setdefault((hit[2], hit[3]), {})[int(hit[1])] = k
    for k in keys:  # a count-0 measurement with its split
        if f"{k}_regular" in m:
            series.setdefault((lane, k.split(f"_{lane}_", 1)[1]), {})[0] = f"{k}_regular"
    slopes = [
        -(-(m[pts[b]] - m[pts[a]]) // (b - a)) for pts in series.values() for a, b in zip(sorted(pts), sorted(pts)[1:])
    ]
    own = [(n, k) for (ln, _), pts in series.items() if ln == lane for n, k in pts.items()]
    if not slopes or not own:
        return None, None
    s = max(max(slopes), 0)
    x = max(1, max(m[k] - s * n for n, k in own))
    used = sorted(k for pts in series.values() for k in pts.values())
    return {"gas": ceil1000(x), "measured": x, "source": f"{src}#{','.join(used)}"}, s


def measured_max(m, kind, entry, lane):
    """M18 (merged-tree review, 2026-11-20): the largest count `N` a counted row's own lane was measured at
    (`<kind>_<entry>_n<N>_<lane>_<variant>`); a quote above it is refused, the line never extrapolated past its points."""
    pat = re.compile(rf"^{re.escape(kind)}_{re.escape(entry)}_n(\d+)_{lane}_")
    ns = [int(hit[1]) for k in m if (hit := pat.match(k))]
    return max(ns) if ns else None


def overshoots(m, base):
    """The counted rows whose line the harness let sit above the largest count (owner 2026-11-19, P1, P2; proposal P4):
    one assumption each, its worst excess over the variants and signers."""
    out = []
    for kind, entry in sorted({(r["kind"], r["entry"]) for r in base if "per_item" in r}):
        keys = sorted(k for k in m if k.startswith(f"{kind}_{entry}_overshoot_"))
        if keys:
            src = ", ".join(keys)
            out.append(
                f"{kind} {entry}: the per-item line (worst slope) is above the measured figure at every measured count, "
                f"by up to {max(m[k] for k in keys):,} gas at the largest ({src}); the excess is refunded."
            )
    return out


INPUTS = "clients/scaas-sdk/gas/inputs.json"


def line_rows(inputs, m, src):
    """The registry line's verify rows (spec 2026-11-19-registry-verify-only-kinds §12, CTR-UA-65), from the input list's
    `verify_line` (figures of its forge test's run log, typed into the input list): per signer kind and depth d (1..), a
    `precompile` and a `fallback` row, the kind's verify delta plus the line's figure at d less the holder's own check; per
    depth a `write` row (W1), the delta plus d times the dearest step between two depths of the write path's figures. Each
    row is marked `stand_in` (registry overhead on stand-in verifiers) and carries the kind's `sig_bytes` and `margin`."""
    vl = inputs.get("verify_line")
    if not vl:
        return []

    def row(signer, measured, source, **cols):
        r = {"signer": signer, "gas": ceil1000(measured), "measured": measured, "source": source}
        r["sig_bytes"] = m[f"verify_0x{signer:04x}_sig_bytes"]
        if str(signer) in inputs["margin"]:
            r["margin"] = inputs["margin"][str(signer)]
        r["stand_in"] = vl["stand_in"]
        r.update(cols)
        return r

    out = []
    for key, k in vl["kinds"].items():
        signer = int(key)
        delta = f"verify_0x{signer:04x}_delta"
        for path in ("precompile", "fallback"):
            for i, g in enumerate(k[path]):
                src_line = f"{INPUTS}#verify_line.kinds.{key}.{path}[{i}]-holder ({vl['forge']} {k['test']})"
                out.append(
                    row(signer, m[delta] + g - k["holder"], f"{src}#{delta} + {src_line}", path=path, depth=i + 1)
                )
    w = vl["write"]
    delta = f"verify_0x{w['signer']:04x}_delta"
    step = max(b - a for a, b in zip(w["accept"], w["accept"][1:]))
    for d in range(1, len(w["accept"]) + 1):
        src_line = f"{INPUTS}#verify_line.write.accept: depth x the dearest step ({vl['forge']} {w['test']})"
        out.append(row(w["signer"], m[delta] + d * step, f"{src}#{delta} + {src_line}", depth=d, write=True))
    return out


def table(inputs, m):
    src = inputs["measurements"]
    # the transaction's own gas (T26 B2-1): its intrinsic cost and calldata price, data the SDK reads as a base row
    tx = inputs["transaction"]
    base = [
        {
            "entry": "transaction",
            "kind": "evm",
            "fresh": False,
            "gas": tx["gas"],
            "measured": tx["gas"],
            "source": tx["source"],
            "per_byte": {"input": "calldata", "gas": tx["per_byte"], "source": tx["source"]},
        }
    ]
    pending = []
    for group in inputs["base"]:
        for kind in group["kinds"]:
            for entry in group["entries"]:
                # a group `fresh_only` (the registry writes, controller call 2026-11-19): only the lane the SDK quotes
                for fresh in (True,) if group.get("fresh_only") else (True, False):
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
                    ua_row(inputs, m, src, row, pending)
                    row.update(per_item(inputs, m, src, f"{kind}:{entry}", f"{kind}_{entry}_per_item_"))
                    lane = "fresh" if fresh else "used"
                    reg, slope = regular(m, src, kind, entry, lane, keys, "per_item" in row)
                    if reg is not None:  # EIP-8037: the part EIP-7825's cap holds
                        row["regular"] = reg
                        if slope is not None:
                            row["per_item"]["regular"] = slope
                    if "per_item" in row and (top := measured_max(m, kind, entry, lane)) is not None:
                        row["per_item"]["measured_max"] = top
                    if f"{kind}:{entry}" in inputs.get("base_stand_in", {}):  # I2: a stand-in priced the row
                        row["stand_in"] = inputs["base_stand_in"][f"{kind}:{entry}"]
                    base.append(row)
    ua_fallback(base, pending)
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
        row.update(per_item(inputs, m, src, str(signer), f"verify_0x{signer:04x}_per_item"))
        if str(signer) in inputs["stand_in"]:
            row["stand_in"] = inputs["stand_in"][str(signer)]
        verify.append(row)
    verify += line_rows(inputs, m, src)
    return {
        "format": "scaas.gas-table",
        "v": 2,
        "name": inputs["name"],
        "family": inputs["family"],
        "assumptions": inputs["assumptions"] + overshoots(m, base),
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
