#!/bin/sh
# Spike PACK (plan 5h part B): the as-built PQZ token's gas pins at parameter set (a) under Amsterdam, today's 64-bit
# lanes or a packed layout. Copies smartcontracts/evm (src, test, script, foundry.toml) into <work dir>/evm, swaps the
# size constants for set (a) (as ../p16k/gas16k.sh did for 16k), sets `evm_version = "amsterdam"` + `experimental`,
# and with PACK=46 / PACK=51 applies pack46.patch / pack51.patch (the packed stored layouts, measurement only), then
# runs forge there. Nothing in the repository changes.
#   scripts/capped pqz-core/pqzl/params/pa-pack/gasa.sh <work dir> <lib dir> <ROLL_MAX> [forge test args] > <log>
#   <lib dir>: smartcontracts/evm/lib of a full checkout; default forge args: the pins of PqzStateGas.t.sol
# Set (a) (owner 2026-10-21): n = 2304, q = 61,275,424,977,257 (2^45.80), Delta = 233,747,196 = floor(q / 2^18),
# K_MAX 4,096; PK = 8 * 2304 = 18,432, CT = PK + 128 = 18,560 = 580 acc words (halves of 290);
# ZERO_HASH = keccak256(18,560 zero bytes); disclosure statement 288 + PK + CT = 37,280.
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
sed -i -e 's/Q = 4_398_046_510_889; .*/Q = 61_275_424_977_257; \/\/ set (a): 2^45.80/' \
  -e 's/DELTA = 67_108_863; .*/DELTA = 233_747_196; \/\/ set (a): ⌊q \/ 2^18⌋/' \
  -e 's/PK = 16_384;/PK = 18_432;/' -e 's/CT = 16_512;/CT = 18_560;/' \
  -e 's/0xe21fb1ce17769d3b97b60b85064a46819cef2ccaede8163ddc683cf730e37e97/0xc11732fdd2aa4672c880154f6c4240ddc2b2c55621b9b3ed3200b6151d8a24f1/' \
  -e 's/Q4 = 0x000003ffffffff29000003ffffffff29000003ffffffff29000003ffffffff29/Q4 = 0x000037bacbf07169000037bacbf07169000037bacbf07169000037bacbf07169/' \
  "$S/PqzCt.sol"
sed -i -e 's/\b516\b/580/g' -e 's/HALF_WORDS = 258/HALF_WORDS = 290/' -e 's/K_MAX = 1024;/K_MAX = 4096;/' \
  -e "s/ROLL_MAX = 256;/ROLL_MAX = $R;/" -e 's/OUT_ON = 16_768/OUT_ON = 18_816/' -e 's/OUT_OFF = 16_640/OUT_OFF = 18_688/' \
  -e 's/DISCLOSE = 33_184/DISCLOSE = 37_280/' -e 's/16384)/18432)/g' -e 's/16672)/18720)/' "$S/PqzCore.sol"
sed -i -e 's/\b516\b/580/g' "$S/PqzStateLib.sol"
sed -i -e 's/33184)/37280)/' "$S/PqzViewLib.sol"
sed -i -e 's/withAud ? 16_768 : 16_640/withAud ? 18_816 : 18_688/' "$W/evm/test/pqz/helpers/PqzFixture.sol"
sed -i -e "0,/^evm_version = .*/s//evm_version = \"amsterdam\"\nexperimental = true/" "$W/evm/foundry.toml"
if [ -n "${PACK:-}" ]; then
  patch -s -d "$W/evm" -p1 < "$HERE/pack$PACK.patch"
fi
echo "== pa-pack/gasa.sh: repository $(git -C "$ROOT" rev-parse --short HEAD), set (a), ROLL_MAX = $R, PACK = ${PACK:-64-bit lanes}, EVM = amsterdam; the edits:"
for f in foundry.toml src/pqz/PqzCt.sol src/pqz/PqzCore.sol src/pqz/PqzStateLib.sol src/pqz/PqzViewLib.sol test/pqz/helpers/PqzFixture.sol test/pqz/PqzStateGas.t.sol; do
  diff "$ROOT/smartcontracts/evm/$f" "$W/evm/$f" | sed "s|^|   $f: |" || true
done
cd "$W/evm"
forge --version | head -1
exec forge test "$@"
