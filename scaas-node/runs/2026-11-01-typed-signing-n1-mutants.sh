#!/bin/bash
# typed-signing N1 mutants: one rule, one edit, the named test must fail; restore, cmp. Usage: <script> [names...]
cd /home/ha/work/ainative/scaas/.claude/worktrees/typed-signing || exit 2
S=/tmp/claude-1000/-home-ha-work-ainative-scaas/dacd2ece-9223-418f-8dc5-3794acb85386/scratchpad
run() { # name file python-replace-from python-replace-to test
  local name=$1 f=$2 from=$3 to=$4 test=$5
  cp "$f" "$S/mut.orig"
  python3 - "$f" "$from" "$to" <<'P' || { echo "$name: pattern not found"; return 1; }
import sys
p,a,b=sys.argv[1:4]
s=open(p).read()
assert a in s
open(p,'w').write(s.replace(a,b,1))
P
  scripts/capped cargo test -j2 --manifest-path scaas-node/Cargo.toml --lib --offline "$test" -- --test-threads=2 > "$S/mut.log" 2>&1
  local rc=$?
  cp "$S/mut.orig" "$f"
  cmp "$f" "$S/mut.orig" && echo "restored $f"
  local r; r=$(grep -E '^test result|^error(\[|:)' "$S/mut.log" | head -1)
  local p; p=$(grep -E 'panicked at|BAD_SIGNATURE|missing row|moved one|one call' "$S/mut.log" | head -2 | cut -c1-170 | tr '\n' ' ')
  if [ $rc -ne 0 ]; then echo "KILLED $name by $test (rc=$rc): $r | $p"; else echo "SURVIVED $name ($test): $r"; fi
}
want=" $* "
go() { [ -z "$*" ] || [[ "$want" == *" $1 "* ]]; }
if [ $# -eq 0 ] || [[ "$want" == *" sig "* ]]; then
  run sig-precheck-accepts-all scaas-node/src/guard.rs 'if typed::recovers(d, sig, *who) {' 'if true {' the_gateway_checks_the_typed_signature_before_the_simulation
fi
if [ $# -eq 0 ] || [[ "$want" == *" allow "* ]]; then
  run allowlist-drops-a-row scaas-node/src/guard.rs 'typed::rows().iter().find(|r| r.sent == sel && !r.entry.is_empty() && r.contracts.contains(&contract))' 'typed::rows().iter().find(|r| r.sent == sel && !r.entry.is_empty() && r.contracts.contains(&contract) && r.entry != "uaUnshield")' guard_allows_every_named_entry_only
  run allowlist-opens-any-selector scaas-node/src/guard.rs 'typed::rows().iter().find(|r| r.sent == sel && !r.entry.is_empty() && r.contracts.contains(&contract))' 'typed::rows().iter().find(|r| !r.entry.is_empty() && r.contracts.contains(&contract))' guard_allows_every_named_entry_only
fi
if [ $# -eq 0 ] || [[ "$want" == *" leg "* ]]; then
  run dex-leg-drops-the-sig scaas-node/src/dex.rs 'uaOrder: empty_ua_order(), sig: r.sig.clone(),' 'uaOrder: empty_ua_order(), sig: Bytes::new(),' dex::tests
  run dex-leg-other-shape scaas-node/src/dex.rs 'sellToken: r.sell, shape: 0, order: r.order.clone()' 'sellToken: r.sell, shape: 1, order: r.order.clone()' dex::tests
fi
if [ $# -eq 0 ] || [[ "$want" == *" dedup "* ]]; then
  run dedup-key-follows-the-claim scaas-node/src/submit.rs 'alloy::primitives::keccak256([&b"scaas.node.call"[..], self.to.as_slice(), &self.data].concat())' 'self.digest().unwrap_or_default()' dedup_by_typed_digest
  run dedup-no-digest-key scaas-node/src/submit.rs 'if s.contains(&d) || s.contains(&call) {' 'if s.contains(&call) && d == B256::ZERO {' one_digest_is_signed_once
fi
