#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Offline checks of tx_gas_cap.py (spec 2026-11-19-registry-verify-only-kinds §9, owner X1, P18; plan Task 13) against fake
RPC nodes (no chain):
  python3 -I script/test_tx_gas_cap.py      (from smartcontracts/evm)

The probe's contract under test: `probe(nodes, block_gas_limit, book=None) -> (cap, rows)`. Each node is a callable
`accepts(gas) -> bool` (an `eth_call` of a cheap call with that gas limit). Every step asks every node and takes the strict
majority (owner ARCH-POS-15); no strict majority -> `GEN_TX_CAP_NODES`. `eth_call` at 2^24 and 2^24 + 1: both accepted, a
binary search up to the block gas limit; 2^24 + 1 refused, the cap is 2^24. No cap found (every gas up to the block limit
accepted) -> `GEN_TX_CAP_UNKNOWN` unless the book holds an owner-set value; a book value other than the probe's ->
`GEN_TX_CAP_MISMATCH`. UNAUDITED tooling."""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import tx_gas_cap  # noqa: E402

BLOCK = 60_000_000


def node(cap):
    """A node whose client caps a transaction at `cap` (None: no cap below the block limit)."""
    return lambda gas: cap is None or gas <= cap


def refused(fn, name):
    try:
        fn()
    except tx_gas_cap.ProbeError as e:
        assert name in str(e), (name, str(e))
        return
    raise AssertionError(f"expected {name}")


def probe_cap_2_24():
    cap, rows = tx_gas_cap.probe([node(1 << 24)] * 3, BLOCK)
    assert cap == 1 << 24, cap
    assert any(r["gas"] == (1 << 24) + 1 and not r["accepted"] for r in rows), rows


def probe_cap_30m():
    cap, _ = tx_gas_cap.probe([node(30_000_000)] * 3, BLOCK)
    assert cap == 30_000_000, cap


def probe_no_cap_unknown():
    refused(lambda: tx_gas_cap.probe([node(None)] * 3, BLOCK), "GEN_TX_CAP_UNKNOWN")
    cap, _ = tx_gas_cap.probe([node(None)] * 3, BLOCK, book={"txGasCap": BLOCK, "txGasCapOwnerSet": True})
    assert cap == BLOCK, cap


def probe_book_mismatch():
    refused(lambda: tx_gas_cap.probe([node(1 << 24)] * 3, BLOCK, book={"txGasCap": 30_000_000}), "GEN_TX_CAP_MISMATCH")
    cap, _ = tx_gas_cap.probe([node(1 << 24)] * 3, BLOCK, book={"txGasCap": 1 << 24})
    assert cap == 1 << 24


def probe_nodes_disagree_refused():
    refused(lambda: tx_gas_cap.probe([node(1 << 24), node(None)], BLOCK), "GEN_TX_CAP_NODES")
    cap, _ = tx_gas_cap.probe([node(1 << 24), node(1 << 24), node(None)], BLOCK)  # a strict majority of three
    assert cap == 1 << 24, cap


def main():
    tests = [probe_cap_2_24, probe_cap_30m, probe_no_cap_unknown, probe_book_mismatch, probe_nodes_disagree_refused]
    for t in tests:
        t()
        print(f"ok {t.__name__}")
    print(f"ok {len(tests)}/{len(tests)}")


if __name__ == "__main__":
    main()
