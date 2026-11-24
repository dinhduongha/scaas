#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# PqChat TreeKEM T1a mutants (plan docs/superpowers/plans/2026-11-23-pqchat-treekem.md T1a): one change at a time on a clean
# tree, test/pqchat-tree.test.js run, the file restored by `git checkout` and checked by `git diff --exit-code`. Writes one row
# per mutant, `mutant | test that went red | rc`, to runs/2026-11-23-pqchat-treekem-t1a-mutants.txt; full output to the
# git-ignored .log. M1-M10 and M12-M16 are the plan's list (M12-M16 owner R16); the others are the other checks of
# src/pqchat-tree.js.
#   ../../scripts/capped bash runs/2026-11-23-pqchat-treekem-t1a-mutants.sh   (from clients/clientkeys)
#   bash runs/2026-11-23-pqchat-treekem-t1a-mutants.sh check   (every replacement found exactly once; nothing written, nothing run)
# A hung run (owner 2026-11-24, scripts/mutant_guard.py): past 3 x the unmutated baseline (at least 10 min, or `--timeout N`
# given to the guard) its process group is killed, and the row reads `killed (timeout N s)`; the mutated file is restored on
# every exit (SIGINT / SIGTERM too); a target file that differs from HEAD refuses the run.
set -u
cd "$(dirname "$0")/.."
OUT=runs/2026-11-23-pqchat-treekem-t1a-mutants.txt
LOG=runs/2026-11-23-pqchat-treekem-t1a-mutants.log
GUARD="python3 -I ../../scripts/mutant_guard.py"
TESTS=(node --test test/pqchat-tree.test.js)
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
T=src/pqchat-tree.js

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

mutate M1 'resolution lists right before left' $T \
    'return [...resolution(t, left(x)), ...resolution(t, right(x))];' \
    'return [...resolution(t, right(x)), ...resolution(t, left(x))];'
mutate M2 'a blank leaf counted' $T 'if (level(x) === 0) return [];' 'if (level(x) === 0) return [x];'
mutate M3 'the filtered path keeps an empty level' $T \
    'if (targets.length) out.push({ node, child, targets });' 'out.push({ node, child, targets });'
mutate M4 'th of an empty subtree non-zero' $T 'if (!n && l === ZERO && r === ZERO) return ZERO;' ';'
mutate M5 'the leaf hash without kemHash' $T 'keyId: n.keyId, kemHash: n.kemHash' 'keyId: n.keyId, kemHash: ZERO'
mutate M6 'a sibling hash taken before the changes' $T \
    'for (const x of byLevel(todo)) h[x] = th(t, x, h);' 'for (const x of byLevel(todo)) h[x] = th(t, x, t.hash);'
mutate M7 'the admission check without the small-order list' $T \
    'if (SMALL_ORDER_X25519.includes(u)) refuse("pkX small order");' ';'
mutate M8 'the admission check clears bit 255 instead of refusing it' $T \
    'const u = k.pkX.reduceRight((a, b) => (a << 8n) | BigInt(b), 0n);
  if (u >> 255n) refuse("pkX bit 255");' \
    'const u = k.pkX.reduceRight((a, b) => (a << 8n) | BigInt(b), 0n) & ((1n << 255n) - 1n);'
mutate M9 'parentTreeHash dropped from the PqChatCommit type string' $T '"bytes32 parentTreeHash,uint32 leaf' '"uint32 leaf'
mutate M10 'genesisCtx that hashes wrapHashes' $T \
    '"MemberKey[] members,uint8 groupMode)' '"MemberKey[] members,bytes32[] wrapHashes,uint8 groupMode)'
mutate M11 'pk_X at or above p admitted' $T 'if (u >= P25519) refuse("pkX not below p");' ';'
mutate M12 'R16: own-key churn written session-wide' $T \
    'for (const n of out) if (!t.goneUa.has(n.ua)) pairOut(t, n.ua, n.kemHash);' \
    'for (const n of out) if (!t.goneUa.has(n.ua)) t.goneKey.add(n.kemHash);'
mutate M13 "R16: a going UA's keys written as pairs only" $T \
    'for (const n of out) if (t.goneUa.has(n.ua)) t.goneKey.add(n.kemHash);' \
    'for (const n of out) if (t.goneUa.has(n.ua)) pairOut(t, n.ua, n.kemHash);'
mutate M14 'R16: the level judged between the Removes and the Adds' $T '    out.push(n);' '    out.push(n);
    if (!live(t).some((m) => m.ua === n.ua)) t.goneUa.add(n.ua);'
mutate M15 'R16: the pair set ignored at an Add' $T \
    'if (t.goneOwnKey.get(hex(a.ua))?.has(hex(a.kemHash))) refuse("PqChatTreeOwnKeyReturn");' ';'
mutate M16 "R16: the keys a going UA took out earlier promoted to session-wide" $T \
    '  if (live(t).some((n) => t.goneUa.has(n.ua))) refuse("PqChatRemovedKept");' \
    '  for (const u of t.goneUa) for (const k of t.goneOwnKey.get(u) ?? []) t.goneKey.add(k);
  if (live(t).some((n) => t.goneUa.has(n.ua))) refuse("PqChatRemovedKept");'
mutate M17 'the session-wide set ignored at an Add' $T \
    'if (t.goneKey.has(hex(a.kemHash))) refuse("PqChatTreeKeyReturn");' ';'
mutate M18 'a gone UA added again' $T 'if (t.goneUa.has(k.ua)) refuse("PqChatTreeReturn");' ';'
mutate M19 'a live key or a key added twice admitted' $T \
    'if (live(t).some((n) => n.kemHash === k.kemHash)) refuse("PqChatTreeKeyLive");' ';'
mutate M20 'an Add past used admitted' $T 'if (a.leaf > t.used || t.nodes' 'if (false || t.nodes'
mutate M21 'a gone UA keeps a leaf' $T 'if (live(t).some((n) => t.goneUa.has(n.ua))) refuse("PqChatRemovedKept");' ';'
mutate M22 'the path length unchecked' $T 'if (p.length !== c.nodeKeyHashes.length) refuse("PqChatTreeTargets");' ';'
mutate M23 'the rest of the direct path not blanked' $T '  blankPath(t, 2 * c.leaf);
  p.forEach' '  p.forEach'
mutate M24 'ctTargets packed little-endian' $T \
    'Uint8Array.of(v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255)' \
    'Uint8Array.of(v & 255, (v >>> 8) & 255, (v >>> 16) & 255, v >>> 24)'
mutate M25 'the covering target: the first of the level, not the one over the leaf' $T \
    'if (mine.has(target)) return' 'if (true) return'
mutate M26 "a Remove of the author's own leaf admitted" $T 'if (r.leaf === leaf || r.leaf >= t.leaves' 'if (r.leaf >= t.leaves'
mutate M27 'the author not required live with its key' $T \
    'if (leaf >= t.leaves || !me || me.ua !== hex(author) || me.keyId !== Number(keyId)) refuse("PqChatTreeLeaf");' \
    'if (leaf >= t.leaves || !me) refuse("PqChatTreeLeaf");'
if [ $CHECK = 1 ]; then
    echo "$checked mutants found exactly once, $missing not"
    [ $missing = 0 ]
    exit
fi
cat "$OUT"
