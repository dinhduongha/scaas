#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# PqChat TreeKEM T2 mutants (plan docs/superpowers/plans/2026-11-23-pqchat-treekem.md T2): one change at a time on a clean
# tree, `cargo test --features app-core,vectors --test tree` run, the file restored by `git checkout` and checked by
# `git diff --exit-code`. Writes one row per mutant, `mutant | tests that went red | rc`, to
# runs/2026-11-23-pqchat-treekem-t2-mutants.txt; full output to the git-ignored .log. M1-M17 are T1b's list in Rust; the
# others are T2's (a held node kept after a Remove, the admission skipped for an added key, a nonce reused, K refused by the
# mode-0 entries) and the other checks of src/wallet/tree.rs.
#   CAPPED_SLOTS=4 CARGO_INCREMENTAL=0 ../../scripts/capped bash runs/2026-11-23-pqchat-treekem-t2-mutants.sh   (from clients/ua-rs)
set -u
cd "$(dirname "$0")/.."
OUT=runs/2026-11-23-pqchat-treekem-t2-mutants.txt
LOG=runs/2026-11-23-pqchat-treekem-t2-mutants.log
git diff --quiet -- src tests || {
    echo 'the tree is not clean'
    exit 2
}
echo "mutant | tests that went red | rc" >"$OUT"
: >"$LOG"
T=src/wallet/tree.rs
K=src/wallet/pqchat_keys.rs
total=0
killed=0

# mutate <id> <description> <file> <old> <new>: the old text must occur exactly once
mutate() {
    local id=$1 what=$2 file=$3
    total=$((total + 1))
    python3 -I -c '
import sys
f, a, b = sys.argv[1:]
s = open(f).read()
if s.count(a) != 1:
    sys.exit(f"not exactly once in {f}: {a}")
open(f, "w").write(s.replace(a, b))' "$file" "$4" "$5" || {
        echo "$id $what | NOT APPLIED | 3" >>"$OUT"
        echo "[mutants] $id NOT APPLIED"
        return
    }
    local out rc red n
    out=$(cargo test -j 2 --features app-core,vectors --test tree 2>&1)
    rc=$?
    printf '=== %s %s (rc %s)\n%s\n' "$id" "$what" "$rc" "$out" >>"$LOG"
    red=$(printf '%s\n' "$out" | sed -nE 's/^test (.*) \.\.\. FAILED$/\1/p' | sort -u)
    n=$(printf '%s\n' "$red" | grep -c . || true)
    if printf '%s\n' "$out" | grep -q '^error\[E'; then
        red='does not compile'
        n=1
    fi
    [ "$rc" -ne 0 ] && [ "$n" -gt 0 ] && killed=$((killed + 1))
    echo "$id $what | ${n} red: $(printf '%s\n' "$red" | sed 's/.*/`&`/' | paste -sd ',' - | sed 's/`,`/`, `/g') | $rc" >>"$OUT"
    echo "[mutants] $id rc $rc, $n red ($killed of $total killed)"
    git checkout -- "$file"
    git diff --exit-code --quiet -- "$file" || {
        echo "$file not restored"
        exit 4
    }
}

echo "[mutants] start: the unmutated run"
cargo test -j 2 --features app-core,vectors --test tree >>"$LOG" 2>&1 || {
    echo 'the unmutated tree is red'
    exit 5
}

mutate M1 'pathContext without parentTreeHash' $T '        b32j(rec, "parentTreeHash")?,
        b32j(rec, "author")?,' '        ZERO,
        b32j(rec, "author")?,'
mutate M2 'pathContext without treeId' $T '        sc.tag_path(),
        b32j(rec, "treeId")?,' '        sc.tag_path(),
        ZERO,'
mutate M3 'pathContext without ctTargets' $T '        ct_targets_hash(ct_targets),' '        ct_targets_hash(&[]),'
mutate M4 'K from joiner directly' $T '    let k = h(&s[..], &sc.l("key"))?;' '    let k = s32(joiner)?;'
mutate M5 'the ciphertext aad without the target' $T '            &be32(self.node),
            &be32(self.target),
        ]' '            &be32(self.node),
        ]'
mutate M6 'ctx without parentTreeHash' $T '            self.parent_tree_hash,
            self.tree_hash,' '            ZERO,
            self.tree_hash,'
mutate M7 'epoch 0 under treeId' $T '            tree_id: genesis_ctx(sc.typed, session)?,' '            tree_id: {
                let mut x = session.clone();
                if let Some(o) = x.as_object_mut() {
                    o.entry("wrapHashes").or_insert(json!([]));
                    o.entry("sealedInfo").or_insert(json!("0x"));
                }
                tree_id(sc.typed, &x)?
            },'
mutate M8 'a refresh that re-seals the last info read' $T '        let e = self.epochs.last()?;
        (e.epoch == self.pin.epoch && e.state == State::Followed && !e.flagged)
            .then_some(e.in_force.as_deref())
            .flatten()' '        self.epochs.iter().rev().find_map(|e| e.in_force.as_deref())'
mutate M9 'the gap ignored' $T '                in_force = None;
                flagged = false;' ''
mutate M10 'the compromise warning folded into "not followed"' $T '        state: State::Compromise,' '        state: State::NotFollowed("compromise"),'
mutate M11 'a tree wrap under the flat label' $T '        self.l("wrap")' '        b"scaas/pqchat/v1/wrap".to_vec()'
mutate M12 'a processed commit that skips the derived-key comparison' $T '            if Some(keccak256(&nk.kem_pk())) != nkh.get(k + i).copied() {
                return Ok(not("node key mismatch"));
            }' ''
mutate M13 'the Welcome not compared with the path' $T '                Some(x) if *x == *joiner => {}' '                Some(_) => {}'
mutate M14 'a ciphertext index chosen from the leaf alone' $T '                p.j = p.targets.iter().position(|x| mine.contains(x));' '                p.j = p.targets.iter().position(|x| *x == 2 * leaf);'
mutate M15 'the undo stopped at the key'"'"'s endEpoch' $T '        for n in (lo + 1..=head).rev() {' '        for n in (lo + 1..=last).rev() {'
mutate M16 'the own-commit test on node keys only' $T '            r.derived = derived;
            Ok(r)
        } else {
            Ok(compromise())
        }' '            r.derived = derived;
            Ok(r)
        } else {
            Ok(r)
        }'
mutate M17 'a ciphertext opened at endEpoch' $T '        let last = end_epoch.map_or(head, |e| e - 1);' '        let last = end_epoch.map_or(head, |e| e);'
mutate M18 'a held node kept after a Remove blanked it' $T '                xs.extend(list(&c, "removes", |v| u32j(v, "leaf"))?);' ''
mutate M19 'the admission skipped for a target key' $T '                super::tree_public::admit_kem_key(&kem_pk)?;' ''
mutate M20 'a nonce reused for a rebuilt commit' $T '        self.build_commit(sc, a, u64::from_be_bytes(n), &mut os_rand)' '        self.build_commit(sc, a, u64::from_be_bytes(n) & 0, &mut os_rand)'
mutate M21 'K refused by the mode-0 entries' $K '        if !matches!(k.origin, Origin::Drawn | Origin::Unwrapped | Origin::Tree) {' '        if !matches!(k.origin, Origin::Drawn | Origin::Unwrapped) {'
mutate M22 'a non-admin taken as an admin for rights' $T '        if admins.contains(&author) {
            return Ok(true);' '        if !admins.is_empty() {
            return Ok(true);'
mutate M23 'a non-admin taken as an admin for the info' $T '                let admin = n == 0 || a.admins_at(n - 1)?.contains(&author);' '                let admin = true;'
mutate M24 'the path ciphertext not held to its list hash' $T '                    if Some(ct.hash(sc)?) != hashes.get(j).copied() {' '                    if Some(ct.hash(sc)?) == Some([9; 32]) {'
mutate M25 'a signature not checked' $T '    ok.ok_or(Error::Tree(TreeError::ReadCorrupted))' '    let _ = ok;
    Ok(())'
mutate M26 'a fetched key not held to its hash' $T '    if keccak256(&k) != want {' '    if want == [9; 32] {'
mutate M27 'the checkpoint below the pin passed' $T '        if p.tree_id != self.tree_id || self.head < p.epoch {' '        if p.tree_id != self.tree_id {'
mutate M28 'the epoch-0 leaves not compared with the signed members' $T '            if want != got || b32j(&a.t, "genesisTreeHash")? != g.tree_hash() {' '            if b32j(&a.t, "genesisTreeHash")? != g.tree_hash() {'
mutate M29 'the snapshot not compared with the head'"'"'s tree hash' $T '            if snap != b32j(&rec, "treeHash")? || b32j(&a.t, "treeHash")? != b32j(&rec, "treeHash")?' '            if b32j(&a.t, "treeHash")? != b32j(&rec, "treeHash")?'
mutate M30 'the next info bucket admitted' $T '    if 12 + pt.len() + 16 > TREE_INFO_MAX {' '    if 12 + pt.len() + 16 > 16_412 {'

echo "[mutants] done: $killed of $total killed"
echo "killed | $killed of $total" >>"$OUT"
