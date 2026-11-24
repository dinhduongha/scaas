#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""generate.py's G2 / Q1 logic (owner 2026-11-19) on a synthetic measurement: a variant without a derived run is listed
`unmeasured`, a row without any takes the largest on another kind (`from_kind`), a native-only entry has none and refuses a
derived measurement, a row with no donor is refused, `second_party` is the second derived party over the first less the
verify delta; I1 part 2 / K2: `per_item` keyed by `<kind>:<entry>` only (Zether's `mtxRollOver` has no count, PQZ's
has), the new items `env_items` and `orders` taken, an unknown one refused, an overshoot pinned by the harness stated as an
assumption; the registry line's verify rows (CTR-UA-65). Run: python3 clients/scaas-sdk/gas/test_generate.py"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import generate

V = "verify_0x0108_delta"
# the transaction's own row (T26 B2-1), which generate.table writes first, from the input list's `transaction`
TX = {"gas": 21_000, "per_byte": 64, "source": "t"}


def table(m, kinds=("token", "zether"), entries=("mtxPay",), native=None, per_item=None, full=False, fresh_only=False):
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
        "base": [{"kinds": list(kinds), "entries": list(entries), **({"fresh_only": True} if fresh_only else {})}],
        "transaction": TX,
    }
    m = dict(m, verify_native_sig_bytes=96)
    m.setdefault(V, 1_000)
    t = generate.table(inputs, m)
    assert t["base"][0]["entry"] == "transaction", "the transaction's row first"
    return t if full else {(r["kind"], r["entry"], r["fresh"]): r for r in t["base"][1:]}


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
    # I2: a base row priced by a stand-in carries it, keyed by kind and entry
    sb = dict(r, **lanes("zether", "mtxRollOver", "normal", 10_000))
    inputs_si = {"pqz:mtxRollOver": "the PQZ precompile's stand-in"}
    t = generate.table(
        {
            "measurements": "m.json",
            "name": "t",
            "family": "evm",
            "assumptions": [],
            "ua_signer": 0x0108,
            "ua_native": {"kinds": [], "entries": []},
            "per_byte": {},
            "save": [],
            "verify": [],
            "margin": {},
            "stand_in": {},
            "base_stand_in": inputs_si,
            "base": [{"kinds": ["zether", "pqz"], "entries": ["mtxRollOver"]}],
            "transaction": TX,
        },
        dict(sb, verify_native_sig_bytes=96, **{V: 1_000}),
    )
    tx = t["base"][0]
    assert (tx["entry"], tx["kind"], tx["gas"], tx["per_byte"]["gas"]) == ("transaction", "evm", 21_000, 64), tx
    got = {(x["kind"], x.get("stand_in")) for x in t["base"][1:]}
    assert got == {("pqz", "the PQZ precompile's stand-in"), ("zether", None)}, got
    # CTR-UA-65: the line's rows, the kind's delta plus the line's figure less the holder's; the write path d times the
    # dearest step; the kind's sig_bytes and margin, marked stand_in
    vl = {
        "forge": "f.t.sol",
        "stand_in": "si",
        "kinds": {"257": {"test": "t", "holder": 100, "precompile": [150, 170], "fallback": [300, 320]}},
        "write": {"test": "w", "signer": 257, "accept": [1_000, 1_030, 1_050]},
    }
    m = {"verify_0x0101_delta": 10, "verify_0x0101_sig_bytes": 128}
    rows = generate.line_rows({"verify_line": vl, "margin": {"257": 7}}, m, "m.json")
    got = [(r.get("path"), r["depth"], r.get("write", False), r["measured"]) for r in rows]
    want = [("precompile", 1, False, 60), ("precompile", 2, False, 80), ("fallback", 1, False, 210)]
    want += [("fallback", 2, False, 230), (None, 1, True, 40), (None, 2, True, 70), (None, 3, True, 100)]
    assert got == want, got
    assert all((r["sig_bytes"], r["margin"], r["stand_in"]) == (128, 7, "si") for r in rows), rows
    assert all(r["source"].startswith("m.json#verify_0x0101_delta + ") for r in rows), rows
    assert generate.line_rows({"margin": {}}, m, "m.json") == [], "no line in the input list"
    # EIP-8037: the regular part. Uncounted: the worst `_regular` of the variants, rounded up; a variant without it: none
    g = {**lanes("token", "mtxPay", "normal", 10_000), **lanes("token", "mtxPay", "normal_reg", 12_000)}
    g.update({k + "_regular": v - 4_500 for k, v in list(g.items())})
    g["token_mtxPay_ua_normal"] = 15_000
    t = table(g, kinds=("token",))
    assert t[("token", "mtxPay", True)]["regular"]["measured"] == 7_500, t[("token", "mtxPay", True)]
    assert t[("token", "mtxPay", True)]["regular"]["gas"] == 8_000
    del g["token_mtxPay_fresh_normal_reg_regular"]
    t = table(g, kinds=("token",))
    assert "regular" not in t[("token", "mtxPay", True)], "a variant without the split"
    assert t[("token", "mtxPay", False)]["regular"]["measured"] == 7_400, "the used lane has its own"
    # counted: the steepest neighbouring slope of any variant and lane, the largest own-lane point less slope × N
    c = {**lanes("account", "reg", "registry", 1_000), "account_reg_per_item_registry": 400}
    c["account_reg_ua_registry"] = 2_000
    pts = {2: 400, 16: 2_000, 32: 4_000, 64: 7_700}  # slopes 114.3, 125, 115.6
    for n, r in pts.items():
        c[f"account_reg_n{n}_fresh_registry_regular"] = r
        c[f"account_reg_n{n}_used_registry_regular"] = r - 50
    c["account_reg_n16_ua_registry_regular"] = 2_000
    c["account_reg_n32_ua_registry_regular"] = 4_100  # 131.25: the steepest
    t = table(c, kinds=("account",), entries=("reg",), per_item={"account:reg": "members"})
    r = t[("account", "reg", True)]
    assert r["per_item"]["regular"] == 132, r
    assert r["regular"]["measured"] == max(v - 132 * n for n, v in pts.items()), r  # 400 - 264 = 136
    assert t[("account", "reg", False)]["regular"]["measured"] == 86, "the used lane's points"
    # M18: the largest measured count beside the line; none without counted points
    assert r["per_item"].get("measured_max") == 64, r
    c2 = {k: v for k, v in c.items() if "_n" not in k}
    r = table(c2, kinds=("account",), entries=("reg",), per_item={"account:reg": "members"})[("account", "reg", True)]
    assert "regular" not in r and "regular" not in r["per_item"], "no points: none"
    assert "measured_max" not in r["per_item"], "no counted points: no bound"
    # a fresh-only group (the registry writes): its fresh rows alone, no used lane asked for; the control refuses it
    f = {"kem_register_fresh_full": 2_000, "kem_register_fresh_full_regular": 50}
    nat = {"kinds": [], "entries": ["register"]}
    assert not refused(lambda: table(f, kinds=("kem",), entries=("register",), native=nat, fresh_only=True)), (
        "no used lane"
    )
    t = table(f, kinds=("kem",), entries=("register",), native=nat, fresh_only=True)
    assert list(t) == [("kem", "register", True)] and t[("kem", "register", True)]["regular"]["gas"] == 1_000, t
    assert refused(
        lambda: table(f, kinds=("kem",), entries=("register",), native={"kinds": [], "entries": ["register"]})
    )
    print("[test_generate] ok")


if __name__ == "__main__":
    main()
