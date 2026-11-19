#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# The scaas-sdk plan's `bind-dart` step (T3 on): builds the reference library (clients/scaas-sdk/ffi) and runs the Dart tests
# against it, both through scripts/capped in the foreground. From this directory: bash ./run.sh
set -euo pipefail
W=$(git rev-parse --show-toplevel)
cap="$W/scripts/capped"
(cd ../../ffi && "$cap" cargo build --locked --offline -j2)
"$cap" dart pub get --offline --enforce-lockfile >/dev/null
"$cap" dart test --reporter expanded --no-color
