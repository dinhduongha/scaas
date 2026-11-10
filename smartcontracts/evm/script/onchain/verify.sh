#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# T66b Step 5b, NET-EVM-12 (owner 2026-11-10; the SCaaS testnet's specifics NET-EVM-09): the verification step on its
# own. Every contract we deployed on the target's chain (vcheck.py's discovery: the deployment books, every broadcast,
# the getters that name a child; on a chain of ours a whole-chain block scan) verified on its explorer, then the
# completeness check: each address verified (a harness contract: a partial match accepted), a linked EIP-1167 clone
# (linked by the explorer, or by vcheck for a clone with appended data, owner 2026-11-10) or SSTORE2 data, else a fail
# row and exit 1.
# From smartcontracts/evm, outside scripts/capped:
#   sh script/onchain/verify.sh <target> [rev ...]
# The explorer from the environment (vcheck.py's header): VERIFY_EXPLORER blockscout | etherscan | sourcify,
# VERIFY_URL, VERIFY_RPC, VERIFY_API_KEY_ENV (the NAME of the key's env var); scaas-testnet: its Blockscout and RPC on
# loopback. A target without one fails VERIFY_NOT_CONFIGURED; VERIFY=none (with VERIFY_REASON) skips the step.
# Each rev (default HEAD, or VERIFY_REVS) is a source snapshot, cache/verify-src/<hash of its .sol and foundry.toml
# blobs>: git archive of that commit plus the pinned lib/, compiled ONCE under scripts/capped (CAPPED_SLOTS=3, owner 2026-11-10) with the deploy's profile
# (FOUNDRY_PROFILE, default scaas-testnet); a snapshot already built is reused. vcheck.py then runs each forge
# verify-contract in its snapshot outside capped, in a memory scope with no slot (VERIFY_MEM, default 1G), one at a
# time, bounded by VERIFY_TIMEOUT (600 s), and aborts if forge compiles. A contract deployed from other sources (an
# older commit's harness) needs that commit as a further rev. VERIFY_MODE=check: read-only, nothing sent.
# deploy.sh evm runs it after a remote deploy; matrix.sh as the group `verify` and after each remote group.
# Rows: runs/…-step5b/verify-<target>.txt.
set -eu
command -v forge > /dev/null || PATH=$HOME/.foundry/bin:$PATH
tgt=${1:?target}
shift
if [ "${VERIFY:-}" = none ]; then
  echo "[$tgt/verify] not verified: VERIFY=none (${VERIFY_REASON:?VERIFY=none needs VERIFY_REASON})"
  exit 0
fi
python3 -I script/onchain/vcheck.py "$tgt" --config  # VERIFY_NOT_CONFIGURED: exit 1
export FOUNDRY_PROFILE=${FOUNDRY_PROFILE:-scaas-testnet}
CAPPED=$(git rev-parse --show-toplevel)/scripts/capped
bash ../../scripts/evm_libs.sh check > /dev/null
# the SCaaS testnet's contracts by the commit whose sources built them: 6df89135, the T66b Step 5 deploy, PqChat and the
# tokens harness; 11349728, the dex group's harness (OnchainRouter, OnchainExecutor: Dex.s.sol changed after its run);
# bf6f3d04, the PQZ e2e GovernanceRouter of the 2026-11-04 reset; HEAD for what is deployed next
revs=HEAD
[ "$tgt" != scaas-testnet ] || revs="HEAD 6df89135 11349728 bf6f3d04"
roots=
for r in ${*:-${VERIFY_REVS:-$revs}}; do
  k=$(git ls-tree -r "$r" -- src script test foundry.toml | grep -E '\.(sol|toml)$' | git hash-object --stdin | cut -c1-12)
  d=cache/verify-src/$k
  if [ ! -f "$d/.built" ]; then
    echo "[$tgt/verify] snapshot $r ($k): compile (scripts/capped) …"
    rm -rf "$d"
    mkdir -p "$d"
    git -C ../.. archive "$(git rev-parse "$r^{commit}"):smartcontracts/evm" foundry.toml src script test | tar -x -C "$d"
    cp -a lib "$d/lib"
    # shellcheck disable=SC2046
    (cd "$d" && CAPPED_SLOTS=3 "$CAPPED" forge build $(find src script -name '*.sol') test/helpers/Mocks.sol test/p6f/PqzPrecompileProbe.sol \
      > build.log 2>&1) || { echo "[$tgt/verify] FAIL snapshot $r: forge build ($d/build.log)"; exit 1; }
    touch "$d/.built"
    echo "[$tgt/verify] snapshot $r ($k): $(grep -E '^Compiling' "$d/build.log" || echo compiled)"
  fi
  roots="$roots --root $d"
done
fix=--fix
[ "${VERIFY_MODE:-fix}" = fix ] || fix=
# shellcheck disable=SC2086
exec python3 -I script/onchain/vcheck.py "$tgt" $roots $fix
