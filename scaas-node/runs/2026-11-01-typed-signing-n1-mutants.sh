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
# the N1 review round
if [[ "$want" == *" door "* ]]; then
  run door-open scaas-node/src/gateway.rs 'if let Err(e) = chain_of(&s, r.chain, w.to) {' 'if let Err(e) = open_chain(&s, r.chain).map(|_| ()) {' door_a_takes_registered_tokens_only
fi
if [[ "$want" == *" len "* ]]; then
  run sig-any-length scaas-node/src/guard.rs 'if sig.len() != 65 {' 'if sig.len() > 65 {' a_signature_that_is_not_65_bytes_is_the_contracts
fi
if [[ "$want" == *" inner "* ]]; then
  run inner-takes-the-fee-recipient scaas-node/src/typed.rs 'let c = Op::parse(c, None)?;' 'let c = Op::parse(c, fee_recipient)?;' relay_fee_call_object
fi
if [[ "$want" == *" generic "* ]]; then
  run generic-runner-digest-only scaas-node/src/adapter.rs '|| adapter.call_key(&j).is_some_and(|c| inflight.contains(&c))' '' the_hedera_lane_skips_bytes_already_in_flight
fi
if [[ "$want" == *" deadline "* ]]; then
  run deadline-job-overrides scaas-node/src/typed.rs '(Some(x), Some(y)) => x.min(y),' '(Some(_), Some(y)) => y,' a_job_deadline_never_outlives_the_signed_one
fi
if [[ "$want" == *" lane "* ]]; then
  run receiver-fee-outer-digest scaas-node/src/guard.rs 'm.digest = t.lane_digest_on(chain.number, uid);' 'm.digest = t.digest;' fill_digest_keeps_the_key_and_what_the_chain_emits_apart
fi
if [[ "$want" == *" uadoor "* ]]; then
  run ua-entry-at-the-door scaas-node/src/gateway.rs '    if ua {
        return bad("FEATURE_UNSUPPORTED' '    if ua && r.chain == 0 {
        return bad("FEATURE_UNSUPPORTED' ua_entries_stay_off_the_gateway_door
fi
if [[ "$want" == *" hedera "* ]]; then
  run hedera-drops-call-key scaas-node/src/adapters/hedera.rs 'self.inner.call_key(job)' 'self.inner.call_key(job).filter(|_| job.id < 0)' the_hedera_lane_skips_bytes_already_in_flight
fi
if [[ "$want" == *" sigbound "* ]]; then
  run op-signature-unbounded scaas-node/src/gateway.rs 'if let Some(Err(e)) = r.op.get("signature")' 'if let Some(Err(e)) = r.op.get("nothing")' door_a_takes_registered_tokens_only
fi
