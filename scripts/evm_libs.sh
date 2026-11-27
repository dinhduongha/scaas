#!/bin/bash
# CTR-GEN-01: the forge libraries of smartcontracts/evm, pinned. Since TODO 8b-9 (4b) (ARCH-POS-24) they are packages of
# the root vendor/ (group core: openzeppelin-contracts fda6b85f, forge-std 88c8a288; their commits, sha256 and tree ids
# are pinned in scripts/vendor.sh) and smartcontracts/evm/lib/<name> is a link to each; this wrapper keeps the old
# command:
#   scripts/evm_libs.sh install   scripts/vendor.sh install core (the Falcon sources of ua-rs too)
#   scripts/evm_libs.sh check     scripts/vendor.sh check core
set -euo pipefail
case "${1:-}" in
    install | check) exec sh "$(dirname "$0")/vendor.sh" "$1" core ;;
    *)
        echo "usage: $0 install|check" >&2
        exit 2
        ;;
esac
