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
assert "2 B of data" in v.classify(CLONE + "beef", {"proxy_type": "unknown", "implementations": []}, True)[1]
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
# explorer config (NET-EVM-12): a remote target names its explorer, else VERIFY_NOT_CONFIGURED
def nc(net, env):
    try:
        v.config(net, env)
    except v.NotConfigured as e:
        return str(e)
    return None


c = v.config("scaas-testnet", {})
assert (c["kind"], c["url"], c["rpc"], c["scan"]) == ("blockscout", "http://127.0.0.1:4000/api", "http://127.0.0.1:8545", True)
assert v.config("scaas-testnet", {"RPC_7622": "http://h:1", "VERIFY_SCAN": "0"})["rpc"] == "http://h:1"
assert "no explorer" in nc("base-sepolia", {"VERIFY_RPC": "https://rpc.example"})
assert "not one of" in nc("x", {"VERIFY_EXPLORER": "routescan", "VERIFY_URL": "https://e.example/api", "VERIFY_RPC": "https://r"})
assert "VERIFY_URL" in nc("x", {"VERIFY_EXPLORER": "blockscout", "VERIFY_RPC": "https://r"})
assert "VERIFY_RPC" in nc("x", {"VERIFY_EXPLORER": "blockscout", "VERIFY_URL": "https://e.example/api"})
ES = {"VERIFY_EXPLORER": "etherscan", "VERIFY_URL": "https://api.etherscan.io/v2/api", "VERIFY_RPC": "https://r"}
assert "API key" in nc("x", ES)  # etherscan without a key
assert "API key" in nc("x", dict(ES, VERIFY_API_KEY_ENV="MY_KEY"))  # the named var unset
assert "not an env var name" in nc("x", dict(ES, VERIFY_API_KEY_ENV="$(id)"))
c = v.config("x", dict(ES, VERIFY_API_KEY_ENV="MY_KEY", MY_KEY="k123"))
assert c["key"] == "k123" and not c["scan"]
assert nc("x", {"VERIFY_EXPLORER": "sourcify", "VERIFY_URL": "https://sourcify.dev/server/", "VERIFY_RPC": "https://r"}) is None

# request shapes, offline
A = "0x" + "11" * 20
assert v.lookup_url("blockscout", "http://127.0.0.1:4000/api", 7622, A) == f"http://127.0.0.1:4000/api/v2/smart-contracts/{A}"
u = v.lookup_url("etherscan", "https://api.etherscan.io/v2/api", 8453, A, "k123")
assert u.startswith("https://api.etherscan.io/v2/api?") and "chainid=8453" in u and "module=contract" in u
assert "action=getsourcecode" in u and f"address={A}" in u and "apikey=k123" in u
assert v.lookup_url("sourcify", "https://sourcify.dev/server", 100, A) == f"https://sourcify.dev/server/v2/contract/100/{A}"
for kind, url in (("blockscout", "http://127.0.0.1:4000/api"), ("etherscan", "https://api.etherscan.io/v2/api"),
                  ("sourcify", "https://sourcify.dev/server")):
    fa = v.forge_args(kind, url, 8453)
    assert fa[:2] == ["--verifier", kind] and fa[fa.index("--chain-id") + 1] == "8453" and fa[3].startswith(url)
    assert not any("k123" in x for x in fa)  # the key never on the command line
e = v.forge_env({"PATH": "/bin", "FOUNDRY_OUT": "o", "ETHERSCAN_API_KEY": "stale"}, "k123")
assert e["VERIFIER_API_KEY"] == e["ETHERSCAN_API_KEY"] == "k123" and "FOUNDRY_OUT" not in e and e["FOUNDRY_PROFILE"] == "scaas-testnet"
assert "ETHERSCAN_API_KEY" not in v.forge_env({"ETHERSCAN_API_KEY": "stale"}, "")

# answers, normalized to Blockscout's fields, then classified
es = lambda r: v.normalize("etherscan", {"status": "1", "result": [r]}, CODE)
assert v.classify(CODE, es({"SourceCode": "pragma solidity", "ContractName": "X"}))[0] == "verified"
assert v.classify(CODE, es({"SourceCode": "", "ContractName": ""}))[0] == "unverified"
assert v.classify(CODE, es({"SourceCode": "pragma", "SimilarMatch": "0xabc"}))[0] == "unverified"  # similar, not exact
assert v.classify(CODE, v.normalize("etherscan", {"status": "0", "result": "Max rate limit reached"}, CODE))[0] == "unverified"
so = lambda m: v.normalize("sourcify", {"match": m}, CODE)
assert v.classify(CODE, so("exact_match"))[0] == "verified" and v.classify(CODE, so("match"))[0] == "unverified"
assert v.classify(CODE, v.normalize("sourcify", {}, CODE))[0] == "unverified"
assert v.classify(CLONE, v.normalize("sourcify", {}, CLONE), True)[0] == "linked clone"  # the code is the link
assert v.classify(CLONE, v.normalize("etherscan", {"result": [{}]}, CLONE), False)[0] == "unverified"
print("test_vcheck: ok")
