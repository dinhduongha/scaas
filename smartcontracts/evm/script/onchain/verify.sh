#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# T66b Step 5b, NET-EVM-09 (owner 2026-11-10): the verification step on its own. Every contract on the target's chain
# (vcheck.py's discovery: a block scan, the deployment books, every broadcast, the getters that name a child) verified
# on its explorer, then the completeness check: each address verified, a linked EIP-1167 clone or SSTORE2 data, else a
# fail row and exit 1. From smartcontracts/evm, outside scripts/capped:
#   sh script/onchain/verify.sh scaas-testnet [rev ...]   RPC_7622, BLOCKSCOUT_API (defaults: loopback)
# Each rev (default HEAD, or VERIFY_REVS) is a source snapshot, cache/verify-src/<hash of its .sol and foundry.toml
# blobs>: git archive of that commit plus the pinned lib/, compiled ONCE under scripts/capped with the deploy's profile
# (FOUNDRY_PROFILE scaas-testnet, deploy.sh evm); a snapshot already built is reused. vcheck.py then runs each forge
# verify-contract in its snapshot outside capped, in a memory scope with no slot (VERIFY_MEM, default 1G), one at a
# time, bounded by VERIFY_TIMEOUT (600 s), and aborts if forge compiles. A contract deployed from other sources (an
# older commit's harness) needs that commit as a further rev. VERIFY_MODE=check: read-only, nothing sent.
# matrix.sh runs it as the group `verify` and after each scaas-testnet group. Rows: runs/…-step5b/verify-<target>.txt.
set -eu
command -v forge > /dev/null || PATH=$HOME/.foundry/bin:$PATH
tgt=${1:?target}
shift
case $tgt in
scaas-testnet) RPC=${RPC_7622:-http://127.0.0.1:8545} API=${BLOCKSCOUT_API:-http://127.0.0.1:4000/api} ;;
*) echo "[$tgt/verify] FAIL VERIFY_NOT_CONFIGURED: no explorer wired for this target"; exit 1 ;;
esac
export FOUNDRY_PROFILE=${FOUNDRY_PROFILE:-scaas-testnet}
CAPPED=$(git rev-parse --show-toplevel)/scripts/capped
bash ../../scripts/evm_libs.sh check > /dev/null
roots=
for r in ${*:-${VERIFY_REVS:-HEAD}}; do
  k=$(git ls-tree -r "$r" -- src script test foundry.toml | grep -E '\.(sol|toml)$' | git hash-object --stdin | cut -c1-12)
  d=cache/verify-src/$k
  if [ ! -f "$d/.built" ]; then
    echo "[$tgt/verify] snapshot $r ($k): compile (scripts/capped) …"
    rm -rf "$d"
    mkdir -p "$d"
    git -C ../.. archive "$(git rev-parse "$r^{commit}"):smartcontracts/evm" foundry.toml src script test | tar -x -C "$d"
    cp -a lib "$d/lib"
    # shellcheck disable=SC2046
    (cd "$d" && "$CAPPED" forge build $(find src script -name '*.sol') test/helpers/Mocks.sol test/p6f/PqzPrecompileProbe.sol \
      > build.log 2>&1) || { echo "[$tgt/verify] FAIL snapshot $r: forge build ($d/build.log)"; exit 1; }
    touch "$d/.built"
    echo "[$tgt/verify] snapshot $r ($k): $(grep -E '^Compiling' "$d/build.log" || echo compiled)"
  fi
  roots="$roots --root $d"
done
fix=--fix
[ "${VERIFY_MODE:-fix}" = fix ] || fix=
# shellcheck disable=SC2086
exec python3 -I script/onchain/vcheck.py "$tgt" "$RPC" "$API" $roots $fix
