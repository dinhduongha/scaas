#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""generate.py's G2 / Q1 logic (owner 2026-11-19) on a synthetic measurement: a variant without a derived run is listed
`unmeasured`, a row without any takes the largest on another kind (`from_kind`), a native-only entry has none and refuses a
derived measurement, a row with no donor is refused, `second_party` is the second derived party over the first less the
verify delta; I1 part 2 / K2: `per_item` keyed by `<kind>:<entry>` only (Zether's `mtxRollOver` has no count, PQZ's
has), the new items `env_items` and `orders` taken, an unknown one refused, an overshoot pinned by the harness stated as an
assumption. Run: python3 clients/scaas-sdk/gas/test_generate.py"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import generate

V = "verify_0x0108_delta"


def table(m, kinds=("token", "zether"), entries=("mtxPay",), native=None, per_item=None, full=False):
    inputs = {
        "per_item": per_item or {},
        "measurements": "m.json",
        "name": "t",
        "family": "evm",
        "assumptions": [],
        "ua_signer": 0x0108,
        "ua_native": native or {"kinds": [], "entries": []},
        "per_byte": {},
        "save": [],
        "verify": [],
        "margin": {},
        "stand_in": {},
        "base": [{"kinds": list(kinds), "entries": list(entries)}],
    }
    m = dict(m, verify_native_sig_bytes=96)
    m.setdefault(V, 1_000)
    t = generate.table(inputs, m)
    return t if full else {(r["kind"], r["entry"], r["fresh"]): r for r in t["base"]}


def lanes(kind, entry, variant, fresh):
    return {f"{kind}_{entry}_fresh_{variant}": fresh, f"{kind}_{entry}_used_{variant}": fresh - 100}


def refused(f):
    try:
        f()
    except SystemExit:
        return True
    return False


def main():
    m = {**lanes("token", "mtxPay", "normal", 10_000), **lanes("token", "mtxPay", "normal_reg", 12_000)}
    m.update(lanes("zether", "mtxPay", "normal", 10_000))
    m["token_mtxPay_ua_normal"] = 15_000  # 15,000 - 10,000 - 1,000 = 4,000
    t = table({**m, "zether_mtxPay_ua_normal": 12_000})  # zether: 1,000
    assert t[("token", "mtxPay", True)]["ua_extra"]["unmeasured"] == ["normal_reg"], "a variant without a derived run"
    assert "unmeasured" not in t[("zether", "mtxPay", True)]["ua_extra"], "every variant measured"
    # a kind with none measured: the largest on another kind
    t = table(
        {**m, "pqz_mtxPay_fresh_normal": 9_000, "pqz_mtxPay_used_normal": 8_000, "zether_mtxPay_ua_normal": 12_000},
        kinds=("token", "zether", "pqz"),
    )
    x = t[("pqz", "mtxPay", True)]["ua_extra"]
    assert (x["from_kind"], x["measured"], x["unmeasured"]) == ("token", 4_000, ["normal"]), x
    assert t[("pqz", "mtxPay", False)]["ua_extra"]["from_kind"] == "token", "the used lane too"
    # no donor anywhere: refused
    assert refused(lambda: table({k: v for k, v in m.items() if "_ua_" not in k})), "none measured, none to borrow"
    # a native-only entry: none, and a derived measurement of it refused
    nat = {"kinds": [], "entries": ["mtxPay"]}
    t = table({k: v for k, v in m.items() if "_ua_" not in k}, native=nat)
    assert all("ua_extra" not in r for r in t.values()), "native-only"
    assert refused(lambda: table(m, native=nat)), "a native-only entry measured with a derived signer"
    assert refused(lambda: table(m, native={"kinds": ["token"], "entries": []})), "a native-only kind likewise"
    # Q1: the second derived party
    q = {
        **lanes("token", "mtxPay", "normal", 10_000),
        "token_mtxPay_ua_normal": 15_000,
        "token_mtxPay_ua2_normal": 15_500,
    }
    s = table(q, kinds=("token",))[("token", "mtxPay", True)]["ua_extra"]["second_party"]
    assert s["measured"] == -500, s  # 15,500 - 15,000 - 1,000
    # I1 part 2: kind-qualified per-item keys; the new items; an overshoot stated
    r = {**lanes("zether", "mtxRollOver", "normal", 10_000), **lanes("pqz", "mtxRollOver", "normal", 20_000)}
    r.update({"zether_mtxRollOver_ua_normal": 11_000, "pqz_mtxRollOver_ua_normal": 21_000})
    r["pqz_mtxRollOver_per_item_normal"] = 5_574
    t = table(r, kinds=("zether", "pqz"), entries=("mtxRollOver",), per_item={"pqz:mtxRollOver": "entries"})
    assert t[("pqz", "mtxRollOver", True)]["item"] == "entries", "the PQZ rollover counted"
    assert t[("pqz", "mtxRollOver", True)]["per_item"]["gas"] == 5_574
    assert "per_item" not in t[("zether", "mtxRollOver", True)], "Zether's rollover not counted"
    assert (
        "per_item"
        not in table(r, kinds=("zether", "pqz"), entries=("mtxRollOver",), per_item={"mtxRollOver": "entries"})[
            ("pqz", "mtxRollOver", True)
        ]
    ), "an unqualified key counts nothing"
    for item in ("env_items", "orders"):
        t = table(r, kinds=("pqz",), entries=("mtxRollOver",), per_item={"pqz:mtxRollOver": item})
        assert t[("pqz", "mtxRollOver", False)]["item"] == item, item
    assert refused(lambda: table(r, kinds=("pqz",), entries=("mtxRollOver",), per_item={"pqz:mtxRollOver": "rows"}))
    r["pqz_mtxRollOver_overshoot_normal"] = 2_051
    a = table(r, kinds=("zether", "pqz"), entries=("mtxRollOver",), per_item={"pqz:mtxRollOver": "entries"}, full=True)
    assert [x for x in a["assumptions"] if x.startswith("pqz mtxRollOver:") and "2,051 gas" in x], a["assumptions"]
    assert not [x for x in a["assumptions"] if x.startswith("zether")], "no overshoot pinned for Zether's"
    print("[test_generate] ok")


if __name__ == "__main__":
    main()
