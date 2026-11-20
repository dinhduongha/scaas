#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Offline checks of pq_verifiers.py's differential probe (spec 2026-11-19-registry-verify-only-kinds §9, F4; plan Task 13)
against fake nodes (no chain):
  python3 -I script/test_pq_verifiers.py      (from smartcontracts/evm)"""

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


for t in (diff_agree_precompile_and_cache, diff_lax_verify_only_refused, diff_nodes_disagree_refused,
          diff_majority_outvotes_one, kat_rows_shape):
    t()
    print("ok", t.__name__)
print("test_pq_verifiers: ok")
