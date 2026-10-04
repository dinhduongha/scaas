#!/usr/bin/env bash
# Deploy the bamboo program with keys that live OUTSIDE the repository (review M3).
#
# usage: deploy.sh <cluster-url> <program-keypair.json> <upgrade-authority-keypair.json>
#   A missing keypair file is generated (solana-keygen new). Keys under the repository (any worktree) are refused.
#   The program is built with BAMBOO_PROGRAM_ID = the program keypair's pubkey into target/deploy-<id>/ (the default
#   target/deploy/bamboo.so stays the test-id build that LiteSVM and the e2e load).
#   The test-only id BDo6exf… and the old dev authority GoTdL8T… had their keys committed: they are COMPROMISED and
#   refused anywhere but a local validator (127.0.0.1 / localhost).
# After deploy: call `initialize(network = genesis hash, admin)` signed by the upgrade authority (only it can create
# Config). Production: move the upgrade authority to a multisig. A different program id is a different domain.
set -euo pipefail
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
URL="${1:?cluster url}"; PROG_KP="${2:?program keypair}"; AUTH_KP="${3:?upgrade authority keypair}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(dirname "$(git -C "$HERE" rev-parse --path-format=absolute --git-common-dir)")"
COMPROMISED="BDo6exf1vzqX44BJc1WDf4Pw6sGZcxqmuVmQPfgUgS3d GoTdL8T8szt4DUMC2X4LhDapxiPzFxkR7UNsRoc84Hfq"

case "$URL" in http://127.0.0.1:*|http://localhost:*) LOCAL=1 ;; *) LOCAL=0 ;; esac
for kp in "$PROG_KP" "$AUTH_KP"; do
  case "$(realpath -m "$kp")" in "$REPO"|"$REPO"/*) echo "refusing a key inside the repository: $kp" >&2; exit 1 ;; esac
  [ -f "$kp" ] || { umask 077; solana-keygen new --no-bip39-passphrase --silent -o "$kp"; echo "generated $kp"; }
  pub="$(solana-keygen pubkey "$kp")"
  if [ "$LOCAL" = 0 ] && [[ " $COMPROMISED " == *" $pub "* ]]; then
    echo "refusing $pub on $URL: test-only key, published in the repository history" >&2; exit 1
  fi
done
PID="$(solana-keygen pubkey "$PROG_KP")"
OUT="$HERE/target/deploy-$PID"
BAMBOO_PROGRAM_ID="$PID" cargo build-sbf --manifest-path "$HERE/programs/bamboo/Cargo.toml" --sbf-out-dir "$OUT"
solana program deploy --url "$URL" --keypair "$AUTH_KP" --upgrade-authority "$AUTH_KP" --program-id "$PROG_KP" \
  "$OUT/bamboo.so"
echo "deployed $PID on $URL; next: initialize(network = genesis hash, admin) signed by $(solana-keygen pubkey "$AUTH_KP")"
