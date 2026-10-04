#!/usr/bin/env bash
# Review M3: mọi entry được relay của bamboo phải là `package entry` (chỉ tx gọi thẳng; không script/module khác gói
# lại). `wrapcheck/` gói từng hàm ⇒ biên dịch PHẢI lỗi và lỗi phải nêu đủ từng hàm. Chạy dưới `capped`.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$(aptos move compile --package-dir "$HERE/wrapcheck" --skip-fetch-latest-git-deps 2>&1)"
rc=$?
if [ "$rc" -eq 0 ]; then echo "FAIL: wrapcheck compiled — a relayed entry is callable from another module"; exit 1; fi
missing=0
for f in meta::relay_pay mandate::pay mandate::revoke_signed mandate::open dex::settle dex::cancel_signed \
         dex::invalidate_nonces_signed meta::manage_signed; do
  grep -q "$f" <<<"$out" || { echo "FAIL: no visibility error for $f"; missing=1; }
done
[ "$missing" -eq 0 ] || { echo "$out" | tail -40; exit 1; }
echo "ok: 8 relayed entries are not callable from other modules"
