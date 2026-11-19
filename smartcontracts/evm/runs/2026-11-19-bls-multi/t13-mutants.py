#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""bls-multi Task 13 mutants (ua-cs 0x0121 key data). From the worktree root: python3 -I <this> [first last | check]
After the run: dotnet build-server shutdown."""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

CS = "clients/ua-cs"
F = CS + "/Scaas.Ua/KeyData.cs"
T = [os.path.abspath("scripts/capped"), "dotnet", "test", "Scaas.Ua.Tests", "--filter",
     "FullyQualifiedName~BlsMultiRows|FullyQualifiedName~ValidRows|FullyQualifiedName~InvalidRows"]
M = [(n, f, a, b, T, CS, e) for n, f, a, b, e in [
    ("uint16 weight sum", F, "            total += w;\n", "            total = (total + w) & 0xffff;\n", "BlsMultiRows"),
    ("order check <= instead of <", F, "SequenceCompareTo(k) < 0, \"order\");", "SequenceCompareTo(k) <= 0, \"order\");",
     "InvalidRows"),
    ("no identity check on apk", F, "        Need(acc is not null, \"identity\");\n        Need(d[..256].SequenceEqual(G2Bytes(acc!)), \"apk\");",
     "        Need(acc is null || d[..256].SequenceEqual(G2Bytes(acc!)), \"apk\");", "InvalidRows"),
    ("no key check per member", F, "            BlsG2(k);\n", "", "InvalidRows"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
