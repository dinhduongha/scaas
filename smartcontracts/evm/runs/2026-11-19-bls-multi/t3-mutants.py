#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""bls-multi Task 3 mutants (clientkeys 0x0121: the Task 1 and Task 2 lists). From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

CK = "clients/clientkeys"
BM, UA = CK + "/src/bls-multi.js", CK + "/src/ua.js"
T = [os.path.abspath("scripts/capped"), "node", "--test", "test/bls-multi.test.js"]
M = [(n, f, a, b, T, CK, e) for n, f, a, b, e in [
    ("verify under 0x0106's DST_SIG", BM, "    const H = G1.hashToCurve(memberMessage(d, uaMsg), { DST: DST_MULTI_SIG });",
     '    const H = G1.hashToCurve(memberMessage(d, uaMsg), { DST: "SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_" });', "dstsSeparate"),
    ("DST_MULTI_POP equal to DST_MULTI_SIG", BM, 'export const DST_MULTI_POP = "SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_MULTI_POP_";',
     'export const DST_MULTI_POP = "SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_MULTI_SIG_";', "dstsSeparate"),
    ("no memberDigest", BM, "const memberMessage = (d, uaMsg) => keccak_256(concatBytes(ua.uaOf(KIND, d), B(uaMsg)));",
     "const memberMessage = (d, uaMsg) => B(uaMsg);", "crossGroup"),
    ("min over all members", BM, "    min = Math.min(min, kd.members[i].weight);", "    min = Math.min(...kd.members.map((m) => m.weight));", "minimalRows"),
    ("weight >= t as > t", BM, "    if (w < kd.threshold || (minimal", "    if (w <= kd.threshold || (minimal", "verifyPaths"),
    ("no high-bit check", BM, "  if (v === 0n || v >> BigInt(n) !== 0n) return null;", "  if (v === 0n) return null;", "verifyPaths"),
    ("no identity check on apk(S)", BM, "    if (apkS.is0()) return false;\n", "", "EQUIVALENT"),
    ("a w_i <= t bound added", UA, '    need(w >= 1, "weight");\n    total += w;', '    need(w >= 1 && w <= u16(d, 256), "weight");\n    total += w;',
     "keyDataValidRows"),
    ("u16 weight sum in validation", UA, '    need(w >= 1, "weight");\n    total += w;', '    need(w >= 1, "weight");\n    total = (total + w) & 0xffff;', "weightSumWide"),
    ("u16 weight sum in verify", BM, "    w += kd.members[i].weight;", "    w = (w + kd.members[i].weight) & 0xffff;", "weightSumWide"),
    ("negation maps 0 to p_381", BM, "    if (y !== 0n) out.set(be(P - y, 48), o + 16);", "    out.set(be(P - y, 48), o + 16);", "subtractCancellingPair"),
    ("m_i without pk_i", BM, "export const popMemberMessage = (popMsg, key) => keccak_256(concatBytes(B(popMsg), B(key)));",
     "export const popMemberMessage = (popMsg, key) => B(popMsg);", "popRogueSharedMessage"),
    ("popMsg without d (m_i = keccak256(pk_i))", BM, "export const popMemberMessage = (popMsg, key) => keccak_256(concatBytes(B(popMsg), B(key)));",
     "export const popMemberMessage = (popMsg, key) => keccak_256(B(key));", "memberPopForOtherGroupNamed"),
    ("no per-partial check", BM, "    const pt = partOk(s, kd.members[i].key, m, DST_MULTI_SIG);",
     "    const pt = (() => {\n      try {\n        return g1Point(B(s));\n      } catch {\n        return null;\n      }\n    })();",
     "aggregateNamesBadPartial"),
    ("weights not moved with keys in the builder", BM, "    ...order.flatMap((m) => [m.key, u16b(m.weight)]),",
     "    ...order.flatMap((m, j) => [m.key, u16b(ms[j].weight)]),", "builderOrderAndIndexMap"),
    ("memberPop on a popMsg not derived from d", BM, "popMemberMessage(popMessage(d), kd.members[i].key)",
     "popMemberMessage(new Uint8Array(32), kd.members[i].key)", "memberPopForOtherGroupNamed"),
    ("aggregate defaults to surplus", BM, "  if (!surplus) {", "  if (false) {", "aggregateDefaultMinimal"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
