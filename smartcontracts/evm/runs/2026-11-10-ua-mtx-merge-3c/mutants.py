# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Mutant harness of plan 3c (PqChat, T91), in the shape of runs/2026-11-08-ua-mtx-merge-t66a/mutants.py: one mutant per run on
a clean tree, the source edit applied, test/pqchat compiled alone into its own out/ and cache/ through `scripts/capped`, the file
restored in the same process (finally), then `git diff --quiet --exit-code -- <file>` must hold (byte-equal). Killed = the run
fails (rc != 0) with a test red.

Usage (from smartcontracts/evm): python3 runs/2026-11-10-ua-mtx-merge-3c/mutants.py list | run <id> [<id> ...] | all
(or the whole batch in one slot: MUT_IN_CAPPED=1 ../../scripts/capped python3 runs/2026-11-10-ua-mtx-merge-3c/mutants.py all)
Full output: runs/2026-11-10-ua-mtx-merge-3c/mut-<id>.log (git-ignored); `mutant | tests that went red | rc` appended to
runs/2026-11-10-ua-mtx-merge-3c/mutants.txt (committed).
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.dirname(os.path.dirname(HERE))
CAPPED = os.path.join(EVM, "..", "..", "scripts", "capped")
FORGE = os.path.expanduser("~/.foundry/bin/forge")
C = "src/pqchat/PqChat.sol"
T = "src/pqchat/PqChatTopics.sol"  # the body module (CTR-TOK-30, 3C-D2): the topics and votes

# id: (file, old, new, match-path glob under test/pqchat)
MUTANTS = {
    # T85: sessions, wraps
    "t85-completion-at-any-landing": (C, "if (landed == ep.wraps && n != 0) {", "if (n != 0) {", "PqChat.t.sol"),
    "t85-wrap-hash-index": (C, "if (PqChatTypes.hashWrap(w) != hashes[i]) revert", "if (PqChatTypes.hashWrap(w) != hashes[j]) revert", "PqChat.t.sol"),
    "t85-nonce-before-sig": (C, "        _auth(reg, s.creator, PqChatTypes.hashSession(s), sig);\n        _useNonce(PqChatTypes.scopeSession(s.creator), s.nonce);",
                             "        _useNonce(PqChatTypes.scopeSession(s.creator), s.nonce);\n        _auth(reg, s.creator, PqChatTypes.hashSession(s), sig);", "PqChat.t.sol"),
    "t85-wrap-stored-twice": (C, "            if (ep.wrapAt[i] != 0) revert PqChatWrapStored(epochId, i);\n", "", "PqChat.t.sol"),
    # T86: epochs, roles
    "t86-parent-plus-one": (C, "if (e.epoch != pe.epoch + 1) revert", "if (e.epoch <= pe.epoch) revert", "PqChatEpochs.t.sol"),
    "t86-home-chain-uid-ignored": (C, "ep.home = s.homeChain == uid && s.homeChatContract == address(this);", "ep.home = s.homeChatContract == address(this);", "PqChatEpochs.t.sol"),
    "t86-admin-check": (C, "        } else if (!_has(pa, e.author)) {\n            revert PqChatNotAdmin(e.author);", "        } else if (false) {\n            revert PqChatNotAdmin(e.author);", "PqChatEpochs.t.sol"),
    "t86-plain-ignores-admins": (C, "if (_keeps(pe, pa, admins) && _keeps(pe, pu, _uas(members))) {", "if (_keeps(pe, pu, _uas(members))) {", "PqChatEpochs.t.sol"),
    "t86-leaver-drop-any": (C, "            else if (!pe.left[parent[i]] && !pe.removedOf[parent[i]]) return false; // dropped without leaving or removal", "            else if (false) return false;", "PqChatEpochs.t.sol"),
    "t86-slot-not-checked": (C, "            if (c != 0) revert PqChatEpochTaken(e.parentEpochId, c);", "            c;", "PqChatEpochs.t.sol"),
    # T87: messages, the stored range
    "t87-device-dimension": (C, "PqChatTypes.scopeMessage(m.epochId, m.sender, m.device), m.counter", "PqChatTypes.scopeMessage(m.epochId, m.sender, bytes16(0)), m.counter", "PqChatMessages.t.sol"),
    "t87-membership-check": (C, "        if (_memberAt(mk, m.sender) == type(uint256).max) revert PqChatNotMember(m.sender);\n", "", "PqChatMessages.t.sol"),
    "t87-sig-hash-write": (C, "bytes memory blob = abi.encode(m, keccak256(abi.encode(sig)));", "bytes memory blob = abi.encode(m, bytes32(0));", "PqChatMessages.t.sol"),
    "t87-stored-list-key": (C, "address[] storage list = _s().stored[hint];", "address[] storage list = _s().stored[bytes8(0)];", "PqChatMessages.t.sol"),
    "t87-range-past-end-not-empty": (C, "        address[] storage l = _s().stored[hint];\n        uint256 n = l.length;\n        if (offset >= n) return page;",
                                     "        address[] storage l = _s().stored[hint];\n        uint256 n = l.length;\n        if (n == 0) return page;\n        if (offset >= n) offset = n - 1;", "PqChatMessages.t.sol"),
    "t87-range-clamp-dropped": (C, "        if (limit > STORED_RANGE_MAX) limit = STORED_RANGE_MAX;\n", "", "PqChatMessages.t.sol"),
    "t87-range-off-by-one": (C, "for (uint256 i; i < page.length; ++i) page[i] = SSTORE2.read(l[offset + i]);", "for (uint256 i; i < page.length; ++i) page[i] = SSTORE2.read(l[i]);", "PqChatMessages.t.sol"),
    # T96: recovery
    "t96-index-kept-member": (C, "            if (i == parent.length || parent[i] != ua) _s().sessions[ua].push(e.sessionId);", "            _s().sessions[ua].push(e.sessionId);", "PqChatRecovery.t.sol"),
    "t96-chain-at-rekey": (C, "        emit PqChatEpochAdded(e.sessionId, eid, e.parentEpochId, e.epoch, e.author);",
                           "        _s().chain[e.sessionId].push(eid);\n        emit PqChatEpochAdded(e.sessionId, eid, e.parentEpochId, e.epoch, e.author);", "PqChatRecovery.t.sol"),
    "t96-sessions-past-end-not-empty": (C, "        bytes32[] storage l = _s().sessions[ua];\n        uint256 n = l.length;\n        if (offset >= n) return page;",
                                        "        bytes32[] storage l = _s().sessions[ua];\n        uint256 n = l.length;\n        if (n == 0) return page;\n        if (offset >= n) offset = n - 1;", "PqChatRecovery.t.sol"),
    "t96-epochs-past-end-not-empty": (C, "        uint256 n = epochCount(sessionId);\n        if (offset >= n) return page;\n        if (limit > EPOCHS_RANGE_MAX)",
                                      "        uint256 n = epochCount(sessionId);\n        if (n == 0) return page;\n        if (offset >= n) offset = n - 1;\n        if (limit > EPOCHS_RANGE_MAX)", "PqChatRecovery.t.sol"),
    "t96-sessions-clamp-dropped": (C, "        if (limit > SESSIONS_RANGE_MAX) limit = SESSIONS_RANGE_MAX;\n", "", "PqChatRecovery.t.sol"),
    # T88: topics (topics spec §8)
    "t88-writer-check": (T, "if (e.author != tp.owner && !_s().writers[e.topicId][e.author].granted) revert", "if (false) revert", "PqTopics.t.sol"),
    "t88-open-replies": (T, "            if (tp.openReplies) return depth;", "            return depth;", "PqTopics.t.sol"),
    "t88-parent-topic": (T, "if (pe.record == address(0) || _word(pe.record, 64) != e.topicId) revert", "if (pe.record == address(0)) revert", "PqTopics.t.sol"),
    "t88-depth-plus-one": (T, "            depth = pe.depth + 1;", "            depth = 1;", "PqTopics.t.sol"),
    "t88-edit-author": (T, "        if (_word(original, 96) != d.author) revert IPqChat.PqTopicNotAuthor(d.author);\n", "", "PqTopics.t.sol"),
    "t88-version-plus-one": (T, "        if (d.version != next) revert IPqChat.PqTopicVersion(next, d.version);\n", "", "PqTopics.t.sol"),
    "t88-writer-seq-plus-one": (T, "        if (w.seq != wr.seq + 1) revert IPqChat.PqTopicSeq(wr.seq + 1, w.seq);\n", "", "PqTopics.t.sol"),
    "t88-ref-shape": (T, "        if (!none && (r.chainUid == 0 || r.pqchat == address(0) || r.entryId == 0)) revert IPqChat.PqTopicRef();\n", "        none;\n", "PqTopics.t.sol"),
    "t88-scope-topic-dimension": (T, "_useNonce(PqChatTypes.scopeEntry(_word(original, 64), d.author), d.nonce);", "_useNonce(PqChatTypes.scopeEntry(d.entryId, d.author), d.nonce);", "PqTopics.t.sol"),
    "t88-list-key": (T, "        else s.replies[e.parentId].push(eid);", "        else s.posts[e.topicId].push(eid);", "PqTopics.t.sol"),
    "t88-byauthor-on-edits": (T, "        vs.push(_put(abi.encode(d, keccak256(abi.encode(sig))), limit));",
                              "        vs.push(_put(abi.encode(d, keccak256(abi.encode(sig))), limit));\n        _s().byAuthor[d.author].push(d.entryId);", "PqTopics.t.sol"),
    "t88-not-owner-signs": (T, "            if (bytes4(err) == IUARegistry.UAUnauthorized.selector) revert IPqChat.PqTopicNotOwner(owner_);\n", "", "PqTopics.t.sol"),
    # T89: votes
    "t89-old-count-kept": (T, "        if (vt.value == 1) --sc.up;\n        else if (vt.value == -1) --sc.down;\n", "", "PqTopicVotes.t.sol"),
    "t89-value-range": (T, "        if (v.value < -1 || v.value > 1) revert IPqChat.PqTopicVoteValue(v.value);\n", "", "PqTopicVotes.t.sol"),
    "t89-vote-seq": (T, "        if (v.seq != vt.seq + 1) revert IPqChat.PqTopicSeq(vt.seq + 1, v.seq);\n", "", "PqTopicVotes.t.sol"),
    # T92: the release surface
    "t92-initialize-any-caller": (C, "        if (msg.sender != FACTORY) revert PqChatNotFactory();\n", "", "PqChat.t.sol"),
    "t90-module-check": (C, "        if (topics_.code.length == 0 || PqChatTopics(topics_).FACTORY() != factory_) revert PqChatEnv();\n", "", "PqChat.t.sol"),
    # Fable review 2026-11-10
    "fable-p1-1-superseded-epoch": (C, "        if (child != 0) revert PqChatEpochTaken(m.epochId, child);\n", "", "PqChatMessages.t.sol"),
    "fable-p1-2-leaver-authors-plain": (C, "type(uint256).max || pe.left[e.author]) revert PqChatNotMember(e.author);",
                                        "type(uint256).max) revert PqChatNotMember(e.author);", "PqChatEpochs.t.sol"),
    # UA-7 P48 (owner 2026-11-10): removal by an admin
    "p48-admin-check": (C, "        if (!_has(admins, r.admin)) revert PqChatNotAdmin(r.admin);\n", "", "PqChatEpochs.t.sol"),
    "p48-sorted": (C, "            if (i > 0 && r.members[i] <= r.members[i - 1]) revert PqChatShape();\n", "", "PqChatEpochs.t.sol"),
    "p48-bound": (C, "        if (n == 0 || n > REMOVE_MAX) revert PqChatShape();", "        if (n == 0) revert PqChatShape();", "PqChatEpochs.t.sol"),
    "p48-member-check": (C, "            if (_memberAt(m, r.members[i]) == type(uint256).max) revert PqChatNotMember(r.members[i]);\n", "", "PqChatEpochs.t.sol"),
    "p48-nonce": (C, "        _useNonce(PqChatTypes.scopeEpoch(r.sessionId, r.admin), r.nonce);\n", "", "PqChatEpochs.t.sol"),
    "p48-next-epoch": (C, "        if (r.nextEpoch != ep.epoch + 1) revert PqChatEpochNumber(ep.epoch + 1, r.nextEpoch);\n", "", "PqChatEpochs.t.sol"),
    "p48-slot-taken": (C, "        if (child != 0) revert PqChatEpochTaken(r.epochId, child);", "        child;", "PqChatEpochs.t.sol"),
    "p48-author-removed": (C, "        if (pe.removed != 0 && pe.removedOf[e.author]) revert PqChatNotMember(e.author); // P48\n", "", "PqChatEpochs.t.sol"),
    "p48-drop-is-plain": (C, "else if (!pe.left[parent[i]] && !pe.removedOf[parent[i]]) return false;", "else if (!pe.left[parent[i]]) return false;", "PqChatEpochs.t.sol"),
    "p48-completion-check": (C, "                if (_s().epochs[ep.parent].removed != 0) _noneRemoved(ep); // P48: whoever authored it\n", "", "PqChatEpochs.t.sol"),
    "p48-admins-excluded": (C, "        for (uint256 i; i < admins.length; ++i) if (pe.removedOf[admins[i]]) revert PqChatRemovedKept(ep.parent, admins[i]);\n", "", "PqChatEpochs.t.sol"),
    "p48-count": (C, "        ep.removed += uint16(added);", "        ep.removed += 0;", "PqChatEpochs.t.sol"),
    "p48-record-kept": (C, "        _s().removals[r.epochId].push(_put(abi.encode(r, keccak256(abi.encode(sig))), limit));\n", "", "PqChatEpochs.t.sol"),
    "t92-factory-info-class": (C, "return IOpenFactory.FactoryInfo(FACTORY, ChainEnvCode.chainUid(), CLASS, KIND,",
                               "return IOpenFactory.FactoryInfo(FACTORY, ChainEnvCode.chainUid(), CLASS + 1, KIND,", "PqChat.t.sol"),
}


def red_tests(log):
    return sorted(set(re.findall(r"\[FAIL[^\]]*\] (\w+)\(", log)))


def run(mid):
    path, old, new, match = MUTANTS[mid]
    full = os.path.join(EVM, path)
    src = open(full).read()
    if src.count(old) != 1:
        raise SystemExit(f"{mid}: the mutated text occurs {src.count(old)} times in {path}")
    logp = os.path.join(HERE, f"mut-{mid}.log")
    try:
        open(full, "w").write(src.replace(old, new))
        env = {**os.environ, "FOUNDRY_TEST": "test/pqchat", "FOUNDRY_OUT": "out/mutants-3c", "FOUNDRY_CACHE_PATH": "cache/mutants-3c"}
        # MUT_IN_CAPPED=1: the whole batch already runs inside one `scripts/capped` scope (one slot for every mutant, each
        # still alone and in order); otherwise each mutant takes its own capped slot.
        cap = [] if os.environ.get("MUT_IN_CAPPED") == "1" else [CAPPED]
        cmd = cap + [FORGE, "test", "-j", "2", "--match-path", f"test/pqchat/{match}"]
        with open(logp, "w") as log:
            rc = subprocess.call(cmd, cwd=EVM, env=env, stdout=log, stderr=subprocess.STDOUT)
    finally:
        open(full, "w").write(src)
    if subprocess.call(["git", "diff", "--quiet", "--exit-code", "--", path], cwd=EVM) != 0:
        raise SystemExit(f"{mid}: {path} not restored")
    out = open(logp).read()
    red = red_tests(out)
    note = ", ".join(red) if red else ("compile error" if "Compiler run failed" in out else "none")
    line = f"{mid} | {note} | {rc}"
    print(line, flush=True)
    with open(os.path.join(HERE, "mutants.txt"), "a") as f:
        f.write(line + "\n")


if __name__ == "__main__":
    if sys.argv[1:2] == ["list"]:
        print("\n".join(MUTANTS))
    elif sys.argv[1:2] == ["run"]:
        for m in sys.argv[2:]:
            run(m)
    elif sys.argv[1:2] == ["all"]:
        done = set()
        txt = os.path.join(HERE, "mutants.txt")
        if os.path.exists(txt):
            done = {l.split(" | ")[0] for l in open(txt) if " | " in l}
        for m in MUTANTS:
            if m not in done:
                run(m)
    else:
        raise SystemExit(__doc__)
