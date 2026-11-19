# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PqVault plan R3 (CTR-PQV-15): PqChat's 55 mutants of runs/2026-11-10-ua-mtx-merge-3c/mutants.py (T91's 40, the Fable fixes'
fable-p1-1 and fable-p1-2, the 13 p48-*), re-pointed, the one instrument allowed to change. The mutants and the runner are that
script's (imported, not copied); this file only re-points:
  STALE  two mutants whose lines round 3r renamed before this plan (owner -> admin, `PqTopicNotOwner` -> `PqTopicNotAdmin`), the
         same change on the renamed line: applied on both trees;
  MOVED  the 15 whose lines moved into src/pqgroup/PqGroupBase.sol (a `revert PqChat…(…)` there is `_fail(F_…, …)`, `e.` fields
         are the base's parameters): applied with MUT_TREE=after.
`python3 runs/2026-11-17-pqvault/mutants-r3.py table` prints `mutant | old file: old text | new file: new text` for each.
Usage (from smartcontracts/evm): MUT_TREE=before|after python3 runs/2026-11-17-pqvault/mutants-r3.py list | run <id> ... | all | table
Output: runs/2026-11-17-pqvault/r3-<tree>/mut-<id>.log (git-ignored); `mutant | tests that went red | rc` in r3-<tree>/mutants.txt.
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("m3c", os.path.join(HERE, "..", "2026-11-10-ua-mtx-merge-3c", "mutants.py"))
m3c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m3c)

T = "src/pqchat/PqChatTopics.sol"
G = "src/pqgroup/PqGroupBase.sol"
STALE = {
    "t88-writer-check": (T, "if (e.author != tp.admin && !_s().writers[e.topicId][e.author].granted) revert", "if (false) revert"),
    "t88-not-owner-signs": (T, "            if (bytes4(err) == IUARegistry.UAUnauthorized.selector) revert IPqChat.PqTopicNotAdmin(admin_);\n", ""),
}
MOVED = {
    "t85-completion-at-any-landing": (G, "if (landed == ep.wraps && n != 0) {", "if (n != 0) {"),
    "t85-wrap-hash-index": (G, "if (PqChatTypes.hashWrap(w) != hashes[i]) _fail", "if (PqChatTypes.hashWrap(w) != hashes[j]) _fail"),
    "t85-wrap-stored-twice": (G, "            if (ep.wrapAt[i] != 0) _fail(F_WRAP_STORED, uint256(epochId), i);\n", ""),
    "t86-parent-plus-one": (G, "if (epoch != pe.epoch + 1) _fail", "if (epoch <= pe.epoch) _fail"),
    "t86-admin-check": (G, "        } else if (!_has(pa, author)) {\n            _fail(F_NOT_ADMIN, uint256(author), 0);",
                        "        } else if (false) {\n            _fail(F_NOT_ADMIN, uint256(author), 0);"),
    "t86-plain-ignores-admins": (G, "if (_keeps(pe, pa, admins) && _keeps(pe, pu, _uas(members))) {", "if (_keeps(pe, pu, _uas(members))) {"),
    "t86-leaver-drop-any": (G, "            else if (!pe.left[parent[i]] && !pe.removedOf[parent[i]]) return false; // dropped without leaving or removal",
                            "            else if (false) return false;"),
    "t86-slot-not-checked": (G, "            if (c != 0) _fail(F_EPOCH_TAKEN, uint256(parentEpochId), uint256(c));", "            c;"),
    "fable-p1-2-leaver-authors-plain": (G, "type(uint256).max || pe.left[author]) _fail(F_NOT_MEMBER, uint256(author), 0);",
                                        "type(uint256).max) _fail(F_NOT_MEMBER, uint256(author), 0);"),
    "p48-author-removed": (G, "        if (pe.removed != 0 && pe.removedOf[author]) _fail(F_NOT_MEMBER, uint256(author), 0); // P48\n", ""),
    "p48-drop-is-plain": (G, "else if (!pe.left[parent[i]] && !pe.removedOf[parent[i]]) return false;", "else if (!pe.left[parent[i]]) return false;"),
    "p48-completion-check": (G, "                if (_epochs()[ep.parent].removed != 0) _noneRemoved(ep); // P48: whoever authored it\n", ""),
    "p48-admins-excluded": (G, "        for (uint256 i; i < admins.length; ++i) if (pe.removedOf[admins[i]]) _fail(F_REMOVED_KEPT, uint256(ep.parent), uint256(admins[i]));\n", ""),
}
TREE = os.environ.get("MUT_TREE", "")
if TREE not in ("before", "after"):
    raise SystemExit("MUT_TREE=before|after")
OLD = dict(m3c.MUTANTS)
for mid, (path, old, new) in {**STALE, **(MOVED if TREE == "after" else {})}.items():
    m3c.MUTANTS[mid] = (path, old, new, OLD[mid][3])
assert len(m3c.MUTANTS) == 55
OUT = os.path.join(HERE, f"r3-{TREE}")
os.makedirs(OUT, exist_ok=True)


def run(mid):
    """3c's `run` with this tree's logs, its own out/ and cache/, and the restore checked byte for byte (the sources need not be
    committed)."""
    path, old, new, match = m3c.MUTANTS[mid]
    full = os.path.join(m3c.EVM, path)
    src = open(full).read()
    if src.count(old) != 1:
        raise SystemExit(f"{mid}: the mutated text occurs {src.count(old)} times in {path}")
    logp = os.path.join(OUT, f"mut-{mid}.log")
    try:
        open(full, "w").write(src.replace(old, new))
        env = {**os.environ, "FOUNDRY_TEST": "test/pqchat", "FOUNDRY_OUT": "out/mutants-pv3", "FOUNDRY_CACHE_PATH": "cache/mutants-pv3"}
        cmd = [m3c.CAPPED, m3c.FORGE, "test", "-j", "2", "--match-path", f"test/pqchat/{match}"]
        with open(logp, "w") as log:
            rc = m3c.subprocess.call(cmd, cwd=m3c.EVM, env=env, stdout=log, stderr=m3c.subprocess.STDOUT)
    finally:
        open(full, "w").write(src)
    if open(full).read() != src:
        raise SystemExit(f"{mid}: {path} not restored")
    out = open(logp).read()
    red = m3c.red_tests(out)
    note = ", ".join(red) if red else ("compile error" if "Compiler run failed" in out else "none")
    line = f"{mid} | {note} | {rc}"
    print(line, flush=True)
    with open(os.path.join(OUT, "mutants.txt"), "a") as f:
        f.write(line + "\n")

if __name__ == "__main__":
    if sys.argv[1:2] == ["table"]:
        for mid, (path, old, new, _) in m3c.MUTANTS.items():
            if mid in STALE or mid in MOVED:
                o = OLD[mid]
                print(f"{mid} | {o[0]}: {o[1].strip()!r} -> {o[2].strip()!r} | {path}: {old.strip()!r} -> {new.strip()!r}")
    elif sys.argv[1:2] == ["list"]:
        print("\n".join(m3c.MUTANTS))
    elif sys.argv[1:2] == ["run"]:
        for mid in sys.argv[2:]:
            run(mid)
    elif sys.argv[1:2] == ["all"]:
        txt = os.path.join(OUT, "mutants.txt")
        done = {l.split(" | ")[0] for l in open(txt) if " | " in l} if os.path.exists(txt) else set()
        for mid in m3c.MUTANTS:
            if mid not in done:
                run(mid)
    else:
        raise SystemExit(__doc__)
