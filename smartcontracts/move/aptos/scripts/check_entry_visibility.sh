#!/usr/bin/env bash
# Review M3: mọi entry được relay của scaas phải là `package entry` (chỉ tx gọi thẳng; không script/module khác gói
# lại). `wrapcheck/` gói từng hàm ⇒ biên dịch PHẢI lỗi và lỗi phải nêu đủ từng hàm (và `p256::verify_with` — review I1). Chạy dưới `capped`.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$(aptos move compile --package-dir "$HERE/wrapcheck" --skip-fetch-latest-git-deps 2>&1)"
rc=$?
if [ "$rc" -eq 0 ]; then echo "FAIL: wrapcheck compiled — a relayed entry is callable from another module"; exit 1; fi
missing=0
# `grep -w`: `meta::relay_pay` must not be satisfied by the error of `meta::relay_pay_meta`.
fns="meta::relay_pay mandate::pay mandate::revoke_signed mandate::open dex::settle dex::cancel_signed
     dex::invalidate_nonces_signed meta::manage_signed meta::relay_pay_meta meta::pay_routed
     relayfee::relay_manage_signed relayfee::relay_mandate_open relayfee::relay_revoke_signed
     relayfee::relay_cancel_signed relayfee::relay_invalidate_nonces_signed p256::verify_with"
n=0
for f in $fns; do
  n=$((n + 1))
  grep -qw "$f" <<<"$out" || { echo "FAIL: no visibility error for $f"; missing=1; }
done
[ "$missing" -eq 0 ] || { echo "$out" | tail -40; exit 1; }
echo "ok: $((n - 2)) relayed entries, meta::pay_routed and p256::verify_with are not callable from other modules"
