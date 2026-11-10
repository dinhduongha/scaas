#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Offline checks of vcheck.py's classification and decoding (no chain, no explorer):
  python3 -I script/onchain/test_vcheck.py      (from smartcontracts/evm)"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vcheck as v  # noqa: E402

IMPL = "ab" * 20
CLONE = "0x" + v.CLONE_HEAD + IMPL + v.CLONE_TAIL
META = "a2646970667358221220" + "11" * 32 + "64736f6c6343000825" + "0033"
CODE = "0x6080604052" + "00" * 8 + META

# classification: positive controls first, then one change at a time
assert v.classify(CODE, {"is_verified": True, "is_partially_verified": False, "is_fully_verified": True})[0] == "verified"
assert v.classify(CODE, {"is_verified": True, "is_partially_verified": True})[0] == "unverified"  # partial match
assert v.classify(CODE, {"is_verified": True, "is_fully_verified": False})[0] == "unverified"
assert v.classify(CODE, {})[0] == "unverified"
assert v.classify(CODE, {"is_verified": True}, genesis=True)[0] == "genesis"
assert v.classify("0x", {})[0] == "no code"
assert v.classify("0x00" + "ff" * 40, {})[0] == "data"
assert v.classify("0x363d3d37363d34f0", {})[0] == "create3 proxy"
assert v.classify("0x363d3d37363d34f000", {})[0] == "unverified"
linked = {"proxy_type": "eip1167", "implementations": [{"address_hash": "0x" + IMPL.upper()}]}
assert v.classify(CLONE, linked, impl_verified=True)[0] == "linked clone"
assert v.classify(CLONE + "beef", dict(linked, proxy_type="clone_with_immutable_arguments"), True)[0] == "linked clone"
assert v.classify(CLONE, linked, impl_verified=False)[0] == "unverified"  # implementation not verified
assert v.classify(CLONE, dict(linked, proxy_type="unknown"), True)[0] == "unverified"  # not linked
assert v.classify(CLONE, dict(linked, implementations=[]), True)[0] == "unverified"
assert v.classify(CLONE, {"is_verified": True, "is_partially_verified": False}, True)[0] == "unverified"  # a clone is never "verified"

# clone, metadata
assert v.clone_impl(CLONE) == "0x" + IMPL and v.clone_impl(CLONE + "00") == "0x" + IMPL
assert v.clone_impl("0x" + v.CLONE_HEAD + IMPL + "00" * 15) is None and v.clone_impl(CODE) is None
assert v.cbor(CODE) == META[:-4] and v.cbor("0x6080") is None and v.cbor("0x60806040" + "ff" * 4 + "0033") is None

# constructor arguments after the creation bytecode; a library placeholder is a wildcard of its length
ph = "__$" + "0" * 34 + "$__"
bc = "0x6080" + ph + "6000"
lib = "12" * 20
assert v.init_args(bc, "0x6080" + lib + "6000" + "aa" * 32) == "aa" * 32
assert v.init_args(bc, "0x6080" + lib + "6000") == ""
assert v.init_args(bc, "0x6081" + lib + "6000" + "aa" * 32) is None  # a different contract
assert v.init_args(bc, "0x6080" + lib + "6001") is None
assert v.init_args("0x", "0x6080") is None

# ABI decoding: address[], Env, contractsPage
w = lambda x: f"{x:064x}"
a1, a2 = int("11" * 20, 16), int("22" * 20, 16)
assert v.dyn_addrs("0x" + w(32) + w(2) + w(a1) + w(a2)) == ["0x" + "11" * 20, "0x" + "22" * 20]
assert v.word_addr("0x" + w(a1)) == "0x" + "11" * 20 and v.word_addr("0x" + w(0)) is None
env = w(32) + w(a1) + w(a2) + w(1) + w(7 * 32) + w(9 * 32) + w(10 * 32) + w(12 * 32)
env += w(1) + w(a1 + 1) + w(0) + w(1) + w(a2 + 1) + w(1) + w(5)  # deps [a1+1], params [], libs [a2+1], hashes [5]
assert v.env_addrs("0x" + env) == ["0x" + "11" * 20, "0x" + "22" * 20, f"0x{a1 + 1:040x}", f"0x{a2 + 1:040x}"]
page = w(64) + w(2) + w(2) + w(a1) + w(0) * 7 + w(a2) + w(0) * 7
assert v.page_addrs("0x" + page) == ["0x" + "11" * 20, "0x" + "22" * 20]
assert v.addr_words("0x" + w(a1) + w(5) + w(0)) == ["0x" + "11" * 20]
assert v.COMPILES.search("Compiling 3 files with Solc 0.8.37") and not v.COMPILES.search("No files changed, compilation skipped")
print("test_vcheck: ok")
