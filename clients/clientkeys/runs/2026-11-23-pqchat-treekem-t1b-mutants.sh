#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# PqChat TreeKEM T1b mutants (plan docs/superpowers/plans/2026-11-23-pqchat-treekem.md T1b): one change at a time on a clean
# tree, test/treekem.test.js run, the file restored by `git checkout` and checked by `git diff --exit-code`. Writes one row
# per mutant, `mutant | test that went red | rc`, to runs/2026-11-23-pqchat-treekem-t1b-mutants.txt; full output to the
# git-ignored .log. M1-M17 are the plan's list; the others are the other checks of src/treekem.js.
#   ../../scripts/capped bash runs/2026-11-23-pqchat-treekem-t1b-mutants.sh   (from clients/clientkeys)
#   bash runs/2026-11-23-pqchat-treekem-t1b-mutants.sh check   (every replacement found exactly once; nothing written, nothing run)
# A hung run (owner 2026-11-24, scripts/mutant_guard.py): past 3 x the unmutated baseline (at least 10 min, or `--timeout N`
# given to the guard) its process group is killed, and the row reads `killed (timeout N s)`; the mutated file is restored on
# every exit (SIGINT / SIGTERM too); a target file that differs from HEAD refuses the run.
set -u
cd "$(dirname "$0")/.."
OUT=runs/2026-11-23-pqchat-treekem-t1b-mutants.txt
LOG=runs/2026-11-23-pqchat-treekem-t1b-mutants.log
GUARD="python3 -I ../../scripts/mutant_guard.py"
TESTS=(node --test test/treekem.test.js)
CHECK=0
[ "${1:-}" = check ] && CHECK=1
cur=
checked=0
missing=0
if [ $CHECK = 0 ]; then
    git diff --quiet HEAD -- src scripts test || {
        echo "refused: differs from HEAD (a leftover mutation: a run died): $(git diff --name-only HEAD -- src scripts test)"
        exit 2
    }
    base=$($GUARD time -- "${TESTS[@]}") || {
        echo 'the unmutated baseline is red'
        exit 2
    }
    trap '[ -z "$cur" ] || git checkout -- "$cur"' EXIT
    trap 'exit 130' INT TERM HUP
    echo "mutant | test that went red | rc" >"$OUT"
    : >"$LOG"
fi
T=src/treekem.js

# mutate <id> <description> <file> <old> <new>: the old text must occur exactly once
mutate() {
    local id=$1 what=$2 file=$3
    MUT_CHECK=$CHECK node -e '
    const fs = require("fs"); const [f, a, b] = process.argv.slice(1); const s = fs.readFileSync(f, "utf8");
    if (s.split(a).length !== 2) { console.error(`not exactly once in ${f}: ${a}`); process.exit(3); }
    if (process.env.MUT_CHECK === "1") process.exit(0);
    fs.writeFileSync(f, s.replace(a, () => b));' "$file" "$4" "$5" || {
        [ $CHECK = 1 ] && {
            missing=$((missing + 1))
            return
        }
        echo "$id $what | NOT APPLIED | 3" >>"$OUT"
        return
    }
    if [ $CHECK = 1 ]; then
        checked=$((checked + 1))
        return
    fi
    cur=$file
    local out rc red n
    out=$($GUARD exec "$base" -- "${TESTS[@]}" 2>&1)
    rc=$?
    printf '=== %s %s (rc %s)\n%s\n' "$id" "$what" "$rc" "$out" >>"$LOG"
    red=$(printf '%s\n' "$out" | sed -n '/^✖ failing tests:/,$p' | grep '^✖ ' | grep -v 'failing tests:' |
        sed -E 's/^✖ //; s/ \([0-9.]+ms\)$//' | sort -u)
    n=$(printf '%s\n' "$red" | grep -c . || true)
    if [ "$rc" -eq 124 ]; then
        echo "$id $what | $(printf '%s\n' "$out" | grep -o 'killed (timeout [0-9]* s)' | tail -1) | $rc" >>"$OUT"
    else
        echo "$id $what | ${n} red: $(printf '%s\n' "$red" | sed 's/.*/`&`/' | paste -sd ',' - | sed 's/`,`/`, `/g') | $rc" >>"$OUT"
    fi
    git checkout -- "$file"
    cur=
    git diff --exit-code --quiet HEAD -- "$file" || {
        echo "$file not restored"
        exit 4
    }
}

mutate M1 'pathContext without parentTreeHash' $T '        c.parentTreeHash,
        c.author,' '        ZERO,
        c.author,'
mutate M2 'pathContext without treeId' $T '        sc.tagPath,
        c.treeId,' '        sc.tagPath,
        ZERO,'
mutate M3 'pathContext without ctTargets' $T 'tr.ctTargetsHash(ctTargets),' 'tr.ctTargetsHash([]),'
mutate M4 'K from joiner directly' $T 'return { ctx, joiner: b(joiner), S, K: H(S, sc.key) };' 'return { ctx, joiner: b(joiner), S, K: b(joiner) };'
mutate M5 'the ciphertext aad without the target' $T \
    'const ctAad = (c) => concatBytes(b(c.treeId), b(c.epochId), u32(c.node), u32(c.target));' \
    'const ctAad = (c) => concatBytes(b(c.treeId), b(c.epochId), u32(c.node));'
mutate M6 'ctx without parentTreeHash' $T '        x.parentTreeHash,' '        ZERO,'
mutate M7 'epoch 0 under treeId' $T '  treeId: tr.genesisCtx(session),' '  treeId: tr.treeId({ ...session, wrapHashes: [], sealedInfo: "0x" }),'
mutate M8 'a refresh that re-seals the last info read' $T '  const e = r.epochs.at(-1);
  return e && e.epoch === r.pin.epoch && e.state === "followed" && e.inForce !== null && !e.flagged' '  const e = r.epochs.findLast((x) => x.inForce !== null);
  return e'
mutate M9 'the gap ignored (a device that follows again keeps the info it held)' $T '      [inForce, flagged] = [null, false];' ';'
mutate M10 'the compromise warning folded into not followed' $T \
    'if (kemHashOf(key.kemPk) !== c.nodeKeyHashes[k]) return { state: "compromise" };' \
    'if (kemHashOf(key.kemPk) !== c.nodeKeyHashes[k]) return { state: "not followed", reason: "node key mismatch" };'
mutate M11 'a tree wrap under the flat label' $T '    wrap: `${prefix}/wrap`,' '    wrap: "scaas/pqchat/v1/wrap",'
mutate M12 'a processed commit skips the derived-key comparison' $T \
    'if (kemHashOf(key.kemPk) !== c.nodeKeyHashes[k + i]) return { state: "not followed", reason: "node key mismatch" };' ';'
mutate M13 'a joiner that skips its path ciphertext' $T \
    'return r.state === "followed" ? { ...r, derived } : r;' \
    'return r.state === "followed" ? { ...r, derived: p.wrap ? [] : derived } : r;'
mutate M14 'a ciphertext index chosen from the held secrets instead of the list' $T \
    '      if (p.j >= 0) {' '      if (p.j >= 0 && p.list.ctTargets[p.j] === 2 * leaf) {'
mutate M15 "the undo stopped at the key's endEpoch" $T '  const top = head;' '  const top = endEpoch ?? head;'
mutate M16 'the own-commit test on node keys only' $T \
    'return r.state === "followed" ? { ...r, derived } : { state: "compromise" };' 'return { ...r, state: "followed", derived };'
mutate M17 'a ciphertext opened at endEpoch' $T 'const last = endEpoch === null ? head : endEpoch - 1;' \
    'const last = endEpoch === null ? head : endEpoch;'
mutate M18 'a fetched ciphertext against no hash' $T \
    'if (hex(tr.treeStructHash("PathCt", p.ct)) !== p.list.ctHashes[p.j]) corrupt(`pathCtAt(${n},${p.j})`);' ';'
mutate M19 'the list against no ctListHash' $T '      corrupt(`pathListOf(${n})`);' '      ;'
mutate M20 'the genesis wrap against no wrapHash' $T \
    'if (hex(pc.structHash("Wrap", wrap)) !== S0.wrapHashes[leaf]) corrupt(`wrapAt(0,${leaf})`);' ';'
mutate M21 'the Welcome wrap against no wrapHash' $T \
    'if (hex(pc.structHash("Wrap", p.wrap)) !== c.wrapHashes[wrapIndex]) corrupt(`wrapAt(${n},${wrapIndex})`);' ';'
mutate M22 'a signature not verified' $T '  if (!ok) corrupt(read);' ';'
mutate M23 "a record's number, id and treeId not checked" $T \
    'if (c.epoch !== n || hex(pc.epochId(sid, c.author, c.nonce)) !== ids[n] || c.treeId !== treeId) corrupt(where);' ';'
mutate M24 'the chain not checked' $T \
    'if (recs[n].parentEpochId !== ids[n - 1] || recs[n].parentTreeHash !== parentHash) corrupt(`commitOf(${n})`);' ';'
mutate M25 'the head not anchored to its signed treeHash' $T \
    '} else if (snapshotRoot(leaves, nodes) !== read(head).treeHash || t.treeHash !== recs[head].treeHash) {' \
    '} else if (!read(head)) {'
mutate M26 'an epoch-0 head taken from the views' $T \
    '      refuse("TreeGenesisLeaves");' '      ;'
mutate M27 'the pinned record hash not compared' $T '  if (recordHash(a, store.epoch) !== store.hash) refuse("TreeConflict");' ';'
mutate M28 'a head below the checkpoint' $T '  if (store.treeId !== a.treeId || a.head < store.epoch) refuse("TreeCheckpoint");' ';'
mutate M29 "a target's key against no hash before encryption" $T \
    'if (kemHashOf(k) !== (x % 2 === 0 ? n.kemHash : n.keyHash)) refuse("TreeKeyHash");' ';'
mutate M30 'the Welcome not compared with the path' $T \
    'if (!w || hex(w) !== hex(joiner)) return { state: "not followed", reason: "welcome disagrees" };' ';'
mutate M31 'the epoch usable without its sealedInfo opening (C12)' $T \
    'return info ? { state: "followed", K: sch.K, info } : { state: "not followed", reason: "info does not open" };
}

/** Another' 'return { state: "followed", K: sch.K, info: info ?? { marker: true } };
}

/** Another'
mutate M32 'rights not checked' $T '    else if (!right.get(n)) res' '    else if (false) res'
mutate M33 "a non-admin drops another UA without its evidence" $T \
    'return c.removes.every((x) => x.ua === c.author || goneAt(x.ua, n));' 'return true;'
mutate M34 "an admin's right ignored" $T '    if (adminsAt(n - 1).includes(c.author)) return true;' ';'
mutate M35 "a non-admin adds another UA" $T \
    'if (!sameList(c.admins, adminsAt(n - 1)) || c.adds.some((x) => x.ua !== c.author)) return false;' \
    'if (!sameList(c.admins, adminsAt(n - 1))) return false;'
mutate M36 "a non-admin's changed info taken" $T '        else info = "ignored";' '        else [inForce, info] = [res.info.json, "changed"];'
mutate M37 "a joiner's info never flagged" $T \
    '[inForce, flagged, info] = [res.info.json, !(admin || c.author === dev.ua), "full"];' \
    '[inForce, flagged, info] = [res.info.json, false, "full"];'
mutate M38 "the join not checked against the join commit's Adds" $T '    if (wrapIndex < 0) refuse("TreePeriod");' ';'
mutate M39 "the end not checked against the Remove" $T '  if (endEpoch !== null && !recs[endEpoch].removes.some(mine)) refuse("TreePeriod");' ';'
mutate M40 'the leaves a foreign commit added not named' $T '        leavesLeft: c.adds.filter(live).map((x) => x.leaf),' '        leavesLeft: [],'
mutate M41 'the held secrets of a blanked path kept' $T '        for (const y of tr.directPath(2 * x, c.leaves)) held.delete(y);' ';'
mutate M42 "the contract model: a wrong treeHash lands" $T '  if (applied.treeHash !== c.treeHash) refuse("PqChatTreeHash");' ';'
mutate M43 "the contract model: another target list lands" $T \
    '  if (JSON.stringify(applied.ctTargets) !== JSON.stringify(built.ctTargets)) refuse("PqChatTreeTargets");' ';'
mutate M44 "the contract model: a commit on another parent lands" $T '  if (c.parentTreeHash !== headHash(h)) refuse("PqChatTreeParent");' ';'
mutate M45 'the info bound unchecked' $T '  if (12 + pt.length + 16 > TREE_INFO_MAX) refuse("TreeInfoSize");' ';'
mutate M46 'the marker sealed as a full info' $T \
    'const pt = pc.pad(info === null ? new Uint8Array(0) : utf8ToBytes(pc.canonicalJson(info)));' \
    'const pt = pc.pad(utf8ToBytes(pc.canonicalJson(info)));'
if [ $CHECK = 1 ]; then
    echo "$checked mutants found exactly once, $missing not"
    [ $missing = 0 ]
    exit
fi
cat "$OUT"
