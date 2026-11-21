#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Offline checks of pq_verifiers.py's differential probe (spec 2026-11-19-registry-verify-only-kinds §9, F4; plan Task 13)
against fake nodes (no chain):
  python3 -I script/test_pq_verifiers.py      (from smartcontracts/evm)"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pq_verifiers as P  # noqa: E402

HOME, VO = "0x" + "0a" * 20, "0x" + "0b" * 20
ROWS = [("valid", b"k" * 3, b"\1" * 32, b"s" * 5, True), ("flip", b"k" * 3, b"\2" * 32, b"s" * 5, False)]
ONE, ZERO = (1).to_bytes(32, "big"), bytes(32)


def node(home_ok=True, vo_lax=False, parts_seen=None):
    """A node: the holder (on the cache, `parts` parts) and the verify-only verifier accept the row with message 1 only; `vo_lax`
    accepts every row; `home_ok` False answers the opposite at the holder."""

    def call(to, data):
        sel = data[:4].hex()
        if sel == P.SEL_PART:
            if parts_seen is not None:
                parts_seen.append(int.from_bytes(data[36:68], "big"))
            return P.abi_args(("b", b"ek"))
        good = b"\1" * 32 in data
        if to == HOME:
            return ONE if good == home_ok else ZERO
        return ONE if good or vo_lax else ZERO

    return call


def refused(fn, name):
    try:
        fn()
    except P.DiffError as e:
        assert name in str(e), (name, str(e))
        return
    raise AssertionError(f"expected {name}")


def diff_agree_precompile_and_cache():
    assert len(P.differential([node()] * 3, HOME, VO, 0, ROWS)) == 2
    seen = []
    P.differential([node(parts_seen=seen)], HOME, VO, 3, ROWS)
    assert seen == [0, 1, 2], seen  # the parts once per key, then verifyExpanded


def diff_lax_verify_only_refused():
    refused(lambda: P.differential([node(vo_lax=True)] * 3, HOME, VO, 0, ROWS), "GEN_DIFFERENTIAL_MISMATCH")


def diff_nodes_disagree_refused():
    refused(lambda: P.differential([node(), node(vo_lax=True)], HOME, VO, 0, ROWS), "GEN_DIFFERENTIAL_NODES")


def diff_majority_outvotes_one():
    assert P.differential([node(), node(), node(vo_lax=True)], HOME, VO, 0, ROWS)


def kat_rows_shape():
    r = P.kat_rows("mldsa65")
    assert r[0][4] is True and len(r) == 9 and all(not x[4] for x in r[1:])


def draft_not_probed_by_default():
    assert P.candidates(1) == ("0x" + f"{0x5CAA0013:040x}",)
    assert not P.draft_allowed(None, None) and not P.draft_allowed({"key": "x"}, {"probe_draft_precompiles_owner": "r"})
    try:
        P.draft_allowed({"probe_draft_precompiles": True}, {})
    except SystemExit as e:
        assert "DRAFT_PROBE_UNCONFIRMED" in str(e)
    else:
        raise AssertionError("the flag without the owner's confirmation")


def draft_probed_under_flag_and_book():
    assert P.draft_allowed({"probe_draft_precompiles": True}, {"probe_draft_precompiles_owner": "owner: reason"})
    c = P.candidates(1, True)
    assert c[0].endswith("5caa0013") and int(c[1], 16) == 0x13, c  # the chain's own first, the Draft after it
    k = json.load(open(os.path.join(HERE, "..", "..", "vectors", "ua", "pq_kat.json")))["kinds"]["mldsa65"]
    rows = P.edge_rows(k, "mldsa65")
    valid = bytes.fromhex(k["eip8355_probe_valid"][2:])
    assert len(rows) == len(k["mutations"]) and valid not in rows
    assert rows[0][-32:] == valid[-32:], "pq_msg as PqUA.pqMessage builds it (mutation 0 keeps ua_msg)"


def vo_args_rows():
    k = json.load(open(os.path.join(HERE, "..", "..", "vectors", "ua", "pq_kat.json")))["kinds"]["mldsa65"]
    args, rows = P.vo_args(k, "mldsa65", 1, 0, 50_000, False)
    # head: 5 words (three offsets, the form, CALL_GAS); the candidates array holds the chain's own address only by default
    assert int.from_bytes(args[96:128], "big") == 0 and int.from_bytes(args[128:160], "big") == 50_000
    off = int.from_bytes(args[0:32], "big")
    assert (
        int.from_bytes(args[off : off + 32], "big") == 1
        and int.from_bytes(args[off + 32 : off + 64], "big") == 0x5CAA0013
    )
    assert rows.startswith(bytes.fromhex(k["eip8355_probe_valid"][2:]))
    _, rows2 = P.vo_args(k, "mldsa65", 1, 0, 50_000, True)
    assert rows2 == rows, "the rows do not depend on the candidates"


for t in (
    vo_args_rows,
    draft_not_probed_by_default,
    draft_probed_under_flag_and_book,
    diff_agree_precompile_and_cache,
    diff_lax_verify_only_refused,
    diff_nodes_disagree_refused,
    diff_majority_outvotes_one,
    kat_rows_shape,
):
    t()
    print("ok", t.__name__)
print("test_pq_verifiers: ok")
