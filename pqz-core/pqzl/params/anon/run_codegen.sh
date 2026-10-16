#!/bin/sh
# LaZer codegen on the R_TXM sizing sketches (P6-ANON): run_codegen.sh <LaZer 3330e48 checkout> > codegen-anon.txt
# Heavy: run under scripts/capped. Writes pqz_<spec>_params.h next to the specs.
set -u
cd "$(dirname "$0")"
for s in txm1 txm2 txm4 txm8 txm16 txm8g2 txm16g4; do
  t0=$(date +%s)
  ../codegen/run.sh "$1" ${s}_params.sage > pqz_${s}_params.h 2> $s.err
  echo "== $s rc=$? $(( $(date +%s) - t0 )) s: $(grep -A1 'Proof size' pqz_${s}_params.h | tail -1)"
  grep -E 'usvp|MSIS|beta' $s.err | head -4 | sed 's/^/   /'
  rm -f $s.err
done
