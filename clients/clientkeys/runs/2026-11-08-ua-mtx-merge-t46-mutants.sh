#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-mtx-merge T46 mutants (group 3f, PQZ verifier mode): one change at a time on a clean tree, the verdict and typed-ops
# suites run, the file restored by `git checkout` and checked by `git diff --exit-code`. Writes one row per mutant,
# `mutant | test that went red | rc`, to runs/2026-11-08-ua-mtx-merge-t46-mutants.txt; full output to the git-ignored .log.
#   ../../scripts/capped bash runs/2026-11-08-ua-mtx-merge-t46-mutants.sh   (from clients/clientkeys)
set -u
cd "$(dirname "$0")/.."
OUT=runs/2026-11-08-ua-mtx-merge-t46-mutants.txt
LOG=runs/2026-11-08-ua-mtx-merge-t46-mutants.log
git diff --quiet -- src scripts test || { echo 'the tree is not clean'; exit 2; }
echo "mutant | test that went red | rc" > "$OUT"
: > "$LOG"

# mutate <id> <description> <file> <old> <new>: the old text must occur exactly once
mutate() {
  local id=$1 what=$2 file=$3
  node -e '
    const fs = require("fs"); const [f, a, b] = process.argv.slice(1); const s = fs.readFileSync(f, "utf8");
    if (s.split(a).length !== 2) { console.error(`not exactly once in ${f}: ${a}`); process.exit(3); }
    fs.writeFileSync(f, s.replace(a, () => b));' "$file" "$4" "$5" || { echo "$id $what | NOT APPLIED | 3" >> "$OUT"; return; }
  local out rc red
  out=$(node --test test/pqz-verdict.test.js test/typed-ops.test.js 2>&1); rc=$?
  printf '=== %s %s (rc %s)\n%s\n' "$id" "$what" "$rc" "$out" >> "$LOG"
  red=$(printf '%s\n' "$out" | sed -n '/^✖ failing tests:/,$p' | grep '^✖ ' | grep -v 'failing tests:' \
    | sed -E 's/^✖ //; s/ \([0-9.]+ms\)$//' | sort -u)
  local n; n=$(printf '%s\n' "$red" | grep -c . || true)
  echo "$id $what | ${n} red: $(printf '%s\n' "$red" | sed 's/.*/`&`/' | paste -sd ',' - | sed 's/`,`/`, `/g') | $rc" >> "$OUT"
  git checkout -- "$file"
  git diff --exit-code --quiet -- "$file" || { echo "$file not restored"; exit 4; }
}

mutate M1 'PqzVerdict without pqzVerifierEpoch' src/evm.js \
  'bytes32 proofHash,uint32 pqzVerifierEpoch,uint64 validUntil' 'bytes32 proofHash,uint64 validUntil'
mutate M2 'UAPqzSetVerifier without target' src/evm.js \
  "UAPqzSetVerifier: { fields: 'address target,bytes32 next'" "UAPqzSetVerifier: { fields: 'bytes32 next'"
mutate M3 'the verdict appended before auth on the signed PQZ forms' src/evm.js \
  'sigParam(td, sig), ...(def.tail ? def.tail(m, x) : [])]' \
  '...(def.tail === pqzVerdictTail ? def.tail(m, x) : []), sigParam(td, sig), ...(def.tail && def.tail !== pqzVerdictTail ? def.tail(m, x) : [])]'
mutate M4 'a missing verdict sent as the empty one' src/evm.js \
  "if (v === undefined) refuse('the PQZ verdict is required (EMPTY_PQZ_VERDICT on a PRECOMPILE token)');" \
  'if (v === undefined) v = EMPTY_PQZ_VERDICT;'
mutate M5 'an empty verdict with a signature accepted' src/evm.js \
  "refuse('an empty verdict carries no signature');" ';'
mutate M6 'the verdict for another token built' src/evm.js \
  "if (!same(m.token, contract)) refuse" "if (false) refuse"
mutate M7 'statementHash and proofHash swapped in the struct' src/evm.js \
  'bytes32 statementHash,bytes32 proofHash,uint32' 'bytes32 proofHash,bytes32 statementHash,uint32'
mutate M8 'the verdict purpose at v2' src/ua.js \
  "tagHash('scaas.ua.purpose.pqz-verdict.v1')" "tagHash('scaas.ua.purpose.pqz-verdict.v2')"
mutate M9 'the verdict tuple in the calldata without its signature (PqzVerdict alone)' src/evm.js \
  "[['PqzSignedVerdict', pqzSignedVerdictOf(x.pqzVerdict)]]" "[['PqzVerdict', pqzSignedVerdictOf(x.pqzVerdict).pqzVerdict]]"
cat "$OUT"
