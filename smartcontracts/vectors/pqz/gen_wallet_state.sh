#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-rs-sign T15i: writes n2304-kmax4096/wallet_state.json, PQZ `balance` words rows for wallet keys of the pq_kat mnemonic
# (ua-rs tests/pqz_wallet_rows.rs, feature `vectors`, fixed draws: two runs give the same bytes). Every binding reads the file
# and decrypts each row (ua-c test_vectors.py, ua-py, ua-go, ua-cs, ua-cxx, ua-dart-frb). Run from anywhere; heavy (cargo),
# so through scripts/capped, foreground. UNAUDITED.
set -eu
root=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$root/clients/ua-rs"
"$root/scripts/capped" cargo test --locked --offline -j2 --features vectors --test pqz_wallet_rows -- --ignored --exact write_wallet_rows
