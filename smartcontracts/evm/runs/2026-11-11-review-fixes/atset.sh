#!/bin/sh
# test/pqz and test/research at the four PQZ sets (script/pqz/at-set.sh restores PqzSet.sol), resumable per step.
R=runs/2026-11-11-review-fixes
for s in n2048-kmax1024 n2304-kmax4096 n2560-kmax16384 n2816-kmax65536; do
  for d in research pqz ua; do
    k=atset-$s-$d
    [ -f "$R/$k.done.log" ] && { echo "skip $k"; continue; }
    echo "start $k"
    CAPPED_SLOTS=3 ../../scripts/capped sh script/pqz/at-set.sh "$s" test -j 1 --match-path "test/$d/**/*.sol" > "$R/$k.log" 2>&1
    rc=$?
    res=$(grep -E "^Ran [0-9]+ test suites" "$R/$k.log" | tail -1)
    fails=$(grep -E "^\[FAIL" "$R/$k.log" | sort -u | cut -c1-200 | tr '\n' ';')
    echo "$k | rc $rc | $res | $fails"
    [ $rc = 0 ] && echo "$k | $res" > "$R/$k.done.log"
  done
done
