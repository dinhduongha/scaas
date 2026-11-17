#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# The wallet module's gate (TODO 3zf), one job under scripts/capped:
#   scripts/capped pqz-core/ffi/wallet-wasm/run.sh [sets…]     (default: the four sets)
# per set: build.sh (the module) and the native cases (cases.rs: opening.json's credits and their one-change variants, each
# with pqz-ffi's native outcome); then clientkeys' test/pqz-wallet-wasm.test.js once over the sets (rows = vectors, wasm =
# native, the raw ABI, the loader, the key handle). Full output in target/out/*.log (git-ignored); short lines here.
# Exit 1 if any step fails.
set -u
cd "$(dirname "$0")"
O=$(pwd)/target/out
mkdir -p "$O"
SETS=${*:-n2048-kmax1024 n2304-kmax4096 n2560-kmax16384 n2816-kmax65536}
fail=0
for S in $SETS; do
  L=$O/build-$S.log
  rm -f "$O/pqz_wallet_$S.wasm" "$O/cases-$S.json"
  echo "build $S"
  if PQZ_SET=$S ./build.sh "$O" > "$L" 2>&1 &&
    CARGO_TARGET_DIR=$(pwd)/target/$S cargo run --release --offline --no-default-features --features "set-$S" --example cases \
      > "$O/cases-$S.json" 2>> "$L"; then
    echo "  ok: $(wc -c < "$O/pqz_wallet_$S.wasm") bytes, $(grep -c '"name"' "$O/cases-$S.json") cases"
  else
    echo "  FAIL build $S, see $L"; fail=1
  fi
done
L=$O/test-$(echo $SETS | tr ' ' '+').log # per set list: concurrent gates of other sets keep theirs
echo "test $SETS"
(cd ../../../clients/clientkeys && PQZ_WALLET_DIR=$O PQZ_WALLET_SETS="$SETS" node --test test/pqz-wallet-wasm.test.js) > "$L" 2>&1
r=$?
grep -E "^# n[0-9]|^ℹ (tests|pass|fail|skipped)|^✖" "$L" | sed 's/^/  /'
[ $r = 0 ] || { echo "  FAIL test rc=$r, see $L"; fail=1; }
echo "wallet-wasm/run.sh: $([ $fail = 0 ] && echo ok || echo FAILED)"
exit $fail
