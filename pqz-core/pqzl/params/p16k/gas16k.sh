#!/bin/sh
# Plan 5h Task 7: the as-built PQZ token's gas pins (smartcontracts/evm/test/pqz/PqzStateGas.t.sol) at the 16k sizes.
# Copies smartcontracts/evm (src, test, script, foundry.toml) into <work dir>/evm, swaps only the size constants for the 16k
# candidate (below: q, Delta, PK, CT, the lane constant, ZERO_HASH, CT / 32 = 644 acc words, halves of 322, K_MAX,
# ROLL_MAX, the payload / disclosure lengths and the two 16,384-byte copies), and runs forge there. Nothing in the
# repository changes; plan Task 8 makes the same edits for real.
#   scripts/capped pqz-core/pqzl/params/p16k/gas16k.sh <work dir> <lib dir> <ROLL_MAX> [forge test args] \
#     > pqz-core/pqzl/params/p16k/gas-16k-<label>.txt
#   <lib dir>: smartcontracts/evm/lib of a full checkout (git-excluded); default forge args:
#   --match-contract 'PqzStatePinGasTest|PqzStateTrivialRollGasTest' -vv
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(git -C "$HERE" rev-parse --show-toplevel)
W=$1 LIB=$(cd "$2" && pwd) R=$3
shift 3
[ $# -gt 0 ] || set -- --match-contract 'PqzStatePinGasTest|PqzStateTrivialRollGasTest' -vv
mkdir -p "$W"
W=$(cd "$W" && pwd)
rm -rf "$W/evm/src" "$W/evm/test" "$W/evm/script"
mkdir -p "$W/evm"
cp -r "$ROOT/smartcontracts/evm/src" "$ROOT/smartcontracts/evm/test" "$ROOT/smartcontracts/evm/script" "$ROOT/smartcontracts/evm/foundry.toml" "$W/evm/"
ln -sfn "$LIB" "$W/evm/lib"
ln -sfn "$ROOT/smartcontracts/vectors" "$W/vectors"
S=$W/evm/src/pqz
# q = 2^50 - 42,310,535 (owner ruling Q1), Delta = 2^30 - 41 = floor(q / 2^20); PK = 8 * 2560, CT = PK + 128;
# ZERO_HASH = keccak256(20,608 zero bytes)
sed -i -e 's/Q = 4_398_046_510_889; .*/Q = 1_125_899_864_532_089; \/\/ 16k: 2^50 − 42,310,535/' \
  -e 's/DELTA = 67_108_863; .*/DELTA = 1_073_741_783; \/\/ 16k: 2^30 − 41/' \
  -e 's/PK = 16_384;/PK = 20_480;/' -e 's/CT = 16_512;/CT = 20_608;/' \
  -e 's/0xe21fb1ce17769d3b97b60b85064a46819cef2ccaede8163ddc683cf730e37e97/0x4954e73f7cf34b1c245d58121c1fb244696ec961a09c6b1eb0b73aa0e31b0f13/' \
  -e 's/Q4 = 0x000003ffffffff29000003ffffffff29000003ffffffff29000003ffffffff29/Q4 = 0x0003fffffd7a64790003fffffd7a64790003fffffd7a64790003fffffd7a6479/' \
  "$S/PqzCt.sol"
sed -i -e 's/\b516\b/644/g' -e 's/HALF_WORDS = 258/HALF_WORDS = 322/' -e 's/K_MAX = 1024;/K_MAX = 16_384;/' \
  -e "s/ROLL_MAX = 256;/ROLL_MAX = $R;/" -e 's/OUT_ON = 16_768/OUT_ON = 20_864/' -e 's/OUT_OFF = 16_640/OUT_OFF = 20_736/' \
  -e 's/DISCLOSE = 33_184/DISCLOSE = 41_376/' -e 's/16384)/20480)/g' -e 's/add(d, 16384)/add(d, 20480)/' "$S/PqzCore.sol"
sed -i -e 's/\b516\b/644/g' "$S/PqzStateLib.sol"
sed -i -e 's/33184)/41376)/' "$S/PqzViewLib.sol"
sed -i -e 's/withAud ? 16_768 : 16_640/withAud ? 20_864 : 20_736/' "$W/evm/test/pqz/helpers/PqzFixture.sol"
# G1=1: op 7 with one randomness group for every M <= 8 (the O9 "M = 8 uses G = 1" shape; groups of 8 legs)
if [ "${G1:-}" = 1 ]; then
  sed -i -e 's|(m + 3) / 4|(m + 7) / 8|g' -e 's|(j / 4)|(j / 8)|g' "$S/PqzCore.sol"
  sed -i -e 's|(m + 3) / 4|(m + 7) / 8|g' "$W/evm/test/pqz/PqzStateGas.t.sol" "$W/evm/test/pqz/helpers/PqzFixture.sol"
fi
echo "== p16k/gas16k.sh: repository $(git -C "$ROOT" rev-parse --short HEAD), ROLL_MAX = $R, G1 = ${G1:-0}; the 16k edits:"
for f in src/pqz/PqzCt.sol src/pqz/PqzCore.sol src/pqz/PqzStateLib.sol src/pqz/PqzViewLib.sol test/pqz/helpers/PqzFixture.sol test/pqz/PqzStateGas.t.sol; do
  diff "$ROOT/smartcontracts/evm/$f" "$W/evm/$f" | sed "s|^|   $f: |" || true
done
cd "$W/evm"
forge --version | head -1
exec forge test "$@"
