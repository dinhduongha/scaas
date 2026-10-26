#!/bin/sh
# Plan 5h Task 7: ../anon/hints.sage (DDGR20 perfect hints on one shared (r, e1), per hint count 0..272 and per M / leg
# grouping) rerun at the 16k parameters: the script's N, Q, BETA_S, BETA_E lines are replaced (sed, below), nothing else.
#   scripts/capped pqz-core/pqzl/params/p16k/run_hints16k.sh <leaky-LWE-Estimator 0a9caf8> <lattice-estimator 53da598> 2560 40 182 \
#     > pqz-core/pqzl/params/p16k/hints-16k-n2560.txt
#   ... 2304 38 173 > pqz-core/pqzl/params/p16k/hints-16k-n2304.txt   (n = 2304: bounds of aprime.sage's norm_bounds)
set -eu
IMG=sagemath/sagemath@sha256:4f5589eb6c565949a006f8665de2876b8414410daf5ac554f4434a15d4f3d528   # tag 10.7
LK_PIN=0a9caf8bf0f80097724e0c6147194c52c6b90f86
LE_PIN=53da5982597709ba0fdf94ea37a84d822310fd84
LK=$(cd "$1" && pwd)
LE=$(cd "$2" && pwd)
N=$3 BS=$4 BE=$5
HERE=$(cd "$(dirname "$0")" && pwd)
[ "$(git -C "$LK" rev-parse HEAD)" = $LK_PIN ] || { echo "leaky-LWE-Estimator must be at $LK_PIN" >&2; exit 1; }
[ "$(git -C "$LE" rev-parse HEAD)" = $LE_PIN ] || { echo "lattice-estimator must be at $LE_PIN" >&2; exit 1; }
echo "p16k/run_hints16k.sh: ../anon/hints.sage with N = $N, Q = 2^50 - 42310535, BETA_S = $BS, BETA_E = $BE"
exec docker run --rm --network none --memory 5g --cpus 2 -e PYTHONPATH=/le -e LE_COMMIT=$LE_PIN -e LK_COMMIT=$LK_PIN \
  -v "$LK":/lk:ro -v "$LE":/le:ro -v "$HERE/../anon":/p:ro --entrypoint /bin/sh "$IMG" -c \
  "mkdir -p /tmp/w && sed -e 's/else (2048, 2048 + 16)/else ($N, $N + 16)/' -e 's/^Q = 2\*\*42 - 215$/Q = 2**50 - 42310535/' \
     -e 's/^BETA_S, BETA_E = 36, 164$/BETA_S, BETA_E = $BS, $BE/' /p/hints.sage > /tmp/w/hints.sage &&
   grep -c -e '($N, $N + 16)' -e '^Q = 2\*\*50 - 42310535' -e '^BETA_S, BETA_E = $BS, $BE' /tmp/w/hints.sage | grep -qx 3 &&
   cd /lk/framework && sage /tmp/w/hints.sage"
