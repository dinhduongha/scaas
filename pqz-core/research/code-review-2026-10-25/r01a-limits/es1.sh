#!/bin/sh
# e_s1 (as make.sh step_e_s1) of the specs mkspecs.py writes: ./es1.sh <set> ... -> es1-<set>.txt
H=$(cd "$(dirname "$0")" && pwd); CORE=$(cd "$H/../../.." && pwd)
T=${PQZ_TOOLS:?PQZ_TOOLS: lk / le / lz checkouts as make.sh}
IMG=sagemath/sagemath@sha256:4f5589eb6c565949a006f8665de2876b8414410daf5ac554f4434a15d4f3d528
for S in "$@"; do
D=$H/specs/$S
specs=$(for f in "$D"/*_params.sage; do printf '/set/%s ' "$(basename "$f")"; done)
CAPPED_SLOTS=4 CAPPED_MEM=3G "$CORE/../scripts/capped" docker run --rm --network none --memory 5g --cpus 2 -e PYTHONPATH=/le -e LE_COMMIT=53da5982597709ba0fdf94ea37a84d822310fd84 \
    -e LK_COMMIT=0a9caf8bf0f80097724e0c6147194c52c6b90f86 -e PYTHONUNBUFFERED=1 -v "$T/le":/le:ro -v "$T/lz/third_party":/lz/third_party:ro \
    -v "$CORE/pqzl/params/n-study":/p:ro -v "$CORE/pqzl/params":/params:ro -v "$D":/set:ro --entrypoint /bin/sh "$IMG" -c \
    "mkdir -p /tmp/w && cp -r /params/codegen /tmp/w/ && ln -s /lz/third_party /tmp/w/third_party && cp /p/*.sage /tmp/w/ &&
     cd /tmp/w/codegen && sage /tmp/w/e_s1_n.sage $specs" > "$H/es1-$S.txt" 2> "$H/es1-$S.err"
echo "$S rc=$?"
done
