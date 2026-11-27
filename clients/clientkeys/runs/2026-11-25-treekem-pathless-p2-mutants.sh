#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# TreeKEM path-less Adds, P2 mutants (docs/superpowers/specs/2026-11-25-treekem-pathless-add.md §13, §14 P2): one change at a time on a clean
# tree, test/treekem.test.js and test/pqchat-tree.test.js run, the file restored by `git checkout` and checked by `git diff --exit-code`. Writes one row
# per mutant, `mutant | test that went red | rc`, to runs/2026-11-25-treekem-pathless-p2-mutants.txt; full output to the
# git-ignored .log. The delta §13 client mutants that clientkeys holds (the planner and the handle lifetime are P3 / P6 / P7).
#   ../../scripts/capped bash runs/2026-11-25-treekem-pathless-p2-mutants.sh   (from clients/clientkeys)
#   bash runs/2026-11-25-treekem-pathless-p2-mutants.sh check   (every replacement found exactly once; nothing written, nothing run)
# A hung run (owner 2026-11-24, scripts/mutant_guard.py): past 3 x the unmutated baseline (at least 10 min, or `--timeout N`
# given to the guard) its process group is killed, and the row reads `killed (timeout N s)`; the mutated file is restored on
# every exit (SIGINT / SIGTERM too); a target file that differs from HEAD refuses the run.
set -u
cd "$(dirname "$0")/.."
OUT=runs/2026-11-25-treekem-pathless-p2-mutants.txt
LOG=runs/2026-11-25-treekem-pathless-p2-mutants.log
GUARD="python3 -I ../../scripts/mutant_guard.py"
TESTS=(node --test test/treekem.test.js test/pqchat-tree.test.js)
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
P=src/pqchat-tree.js

mutate P1 'next from K instead of S' $T '    next: H(S, sc.next),' '    next: H(H(S, sc.key), sc.next),'
mutate P2 'the tag from K' $T '    tag: H(S, concatBytes(sc.confirm, tagCtx)),' '    tag: H(H(S, sc.key), concatBytes(sc.confirm, tagCtx)),'
mutate P3 'the tag under the key label' $T '    tag: H(S, concatBytes(sc.confirm, tagCtx)),' '    tag: H(S, concatBytes(sc.key, tagCtx)),'
mutate P4 'the tag under the next label' $T '    tag: H(S, concatBytes(sc.confirm, tagCtx)),' '    tag: H(S, concatBytes(sc.next, tagCtx)),'
mutate P5 'the add-joiner without hash(adds)' $T 'H(next, concatBytes(sc.addJoiner, b(treeId), b(epochId), b(addsHash)));' 'H(next, concatBytes(sc.addJoiner, b(treeId), b(epochId)));'
mutate P6 'the add-joiner without epochId' $T 'H(next, concatBytes(sc.addJoiner, b(treeId), b(epochId), b(addsHash)));' 'H(next, concatBytes(sc.addJoiner, b(treeId), b(addsHash)));'
mutate P7 'the add-joiner without treeId' $T 'H(next, concatBytes(sc.addJoiner, b(treeId), b(epochId), b(addsHash)));' 'H(next, concatBytes(sc.addJoiner, b(epochId), b(addsHash)));'
mutate P8 'S without ctx' $T '  const S = H(joiner, concatBytes(sc.epoch, ctx));' '  const S = H(joiner, sc.epoch);'
mutate P9 "epoch 0's tag before genesisCtx (over ctx_0)" $T '  const tagCtx = fields.epoch === 0 ? b(fields.treeId) : ctx;' '  const tagCtx = ctx;'
mutate P10 'the label joiner for a path-less epoch' $T 'H(next, concatBytes(sc.addJoiner, b(treeId)' 'H(next, concatBytes(sc.joiner, b(treeId)'
mutate P11 'the derivation picked by the shape instead of pathless' $T '    else if (c.pathless) res = pathlessCommit(' '    else if (c.nodeKeyHashes.length === 0) res = pathlessCommit('
mutate P12 'a path commit derived by the chain (R9 broken)' $T '    else if (c.pathless) res = pathlessCommit(' '    else if (c.pathless || c.adds.length > 0) res = pathlessCommit('
mutate P13 'the walk not resetting sincePath' $P '  t.sincePath = 0;' '  ;'
mutate P14 'the joiner skipping the tag' $T '    if (!sameTag(sch, c.confirmTag)) return { state: "not followed", reason: "tag" };
    return taken(sc, a, epochId, c.sealedInfo, sch, false);' '    return taken(sc, a, epochId, c.sealedInfo, sch, false);'
mutate P15 'a member skipping the tag' $T '  if (sameTag(sch, c.confirmTag)) return taken(sc, a, epochId, c.sealedInfo, sch, chain.anchored);' '  return taken(sc, a, epochId, c.sealedInfo, sch, chain.anchored);'
mutate P16 "a path commit's tag skipped" $T '  const sch = schedule(sc, joiner, commitFields(c));
  if (!sameTag(sch, c.confirmTag)) return { state: "not followed", reason: "tag" };' '  const sch = schedule(sc, joiner, commitFields(c));'
mutate P17 "epoch 0's tag skipped" $T '  if (!sameTag(sch, a.S0.confirmTag)) return { state: "not followed", reason: "tag" };' '  ;'
mutate P18 'C45 applied by a first-run joiner' $T '  if (!chain.anchored) return { state: "not followed", reason: "welcome may not match" };' '  ;'
mutate P19 'the own-commit test reduced to the tag' $T '  if (p.own && !(dev.kemSeed && addNonceTry(sc, dev.kemSeed, c) >= 0)) return { state: "compromise" };' '  ;'
mutate P20 'another nonce than addNonce' $T '  return h.subarray(0, 8).reduce((a, x) => (a << 8n) | BigInt(x), 0n);' '  return 1n + h.subarray(0, 8).reduce((a, x) => (a << 8n) | BigInt(x), 0n);'
mutate P21 "the author's path dropped on a path-less epoch" $T '      const moved = c.pathless ? c.adds : [c, ...c.removes, ...c.adds];' '      const moved = [c, ...c.removes, ...c.adds];'
mutate P22 'the warning at W(N) - 1' $T 'Math.max(1, N - Math.ceil(N / 4)));' 'Math.max(1, N - Math.ceil(N / 4)) - 1);'
mutate P23 'the warning at W(N) + 1' $T 'Math.max(1, N - Math.ceil(N / 4)));' 'Math.max(1, N - Math.ceil(N / 4)) + 1);'
mutate P24 'W(0) = 19' $T 'export const PATHLESS_WARN_LEAVES = 20;' 'export const PATHLESS_WARN_LEAVES = 19;'
mutate P25 'the warning never shown' $T '    pathWarning: isAdmin && endEpoch === null && headTree.sincePath >= warnAt(headTree.pathBound),' '    pathWarning: false,'
mutate P26 'the warning shown to a non-admin' $T '    pathWarning: isAdmin && endEpoch === null &&' '    pathWarning: endEpoch === null &&'
mutate P27 'a handle of another parent accepted' $T '    if (!hd?.next || hex(hd.epochId) !== hex(a.parent.epochId) || hex(hd.treeHash) !== hex(a.parent.treeHash))' '    if (!hd?.next)'
mutate P28 'the bound > as >=' $P '    if (t.pathBound > 0 && t.sincePath + c.adds.length > t.pathBound)' '    if (t.pathBound > 0 && t.sincePath + c.adds.length >= t.pathBound)'
mutate P29 'the bound ignored' $P '    if (t.pathBound > 0 && t.sincePath + c.adds.length > t.pathBound)' '    if (false)'
mutate P30 'sincePath + 1 per commit' $P '    t.sincePath += c.adds.length;' '    t.sincePath += 1;'
mutate P31 'a path-less Remove accepted' $P '  if (c.pathless === true && (c.removes.length !== 0 || JSON.stringify(admins) !== JSON.stringify(head)))' '  if (c.pathless === true && JSON.stringify(admins) !== JSON.stringify(head))'
mutate P32 'a path-less admin change accepted' $P '  if (c.pathless === true && (c.removes.length !== 0 || JSON.stringify(admins) !== JSON.stringify(head)))' '  if (c.pathless === true && c.removes.length !== 0)'
mutate P33 'the path-less shape not checked' $P '  if (c.pathless === true && (!(c.adds?.length > 0) || c.nodeKeyHashes.length !== 0)) refuse("PqChatShape");' '  ;'
mutate P34 'the path walked on a path-less record' $P '  if (c.pathless === true) {
    // item 4' '  if (false) {
    // item 4'
mutate P35 'the chain dropped after an anchored epoch' $T '  chain: { next: sch.next, anchored },' '  chain: anchored ? null : { next: sch.next, anchored },'

if [ $CHECK = 1 ]; then
    echo "check: $checked found, $missing missing"
    [ $missing = 0 ]
    exit
fi
echo "done: $(grep -c . "$OUT") rows in $OUT"
