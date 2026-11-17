#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T35 (node rows, guard, errors, indexer, venue for the regulated kinds 8-13): one mutant at a time on the T35
tree. `t35_mutants.py <name>` from the repository root applies one (every edit's anchor must be found exactly once, and the
edit must change something; a `json:` edit rewrites one entry of `selector_audit.json`); `run_t35_mutants.sh` runs the
node's lib tests after each (`e2e-` names: the regulated e2e on a local anvil) and restores the tree with `git checkout`.
`--list` prints the names. The plan's step 5 rows first, then this task's own."""
import json
import sys

ABI = 'scaas-node/src/abi.rs'
VENUE = 'scaas-node/src/dex/venue.rs'
CHAIN = 'scaas-node/src/chain.rs'
CONFIG = 'scaas-node/src/config.rs'
INDEXER = 'scaas-node/src/indexer.rs'
TYPED = 'scaas-node/src/typed.rs'
AUDIT = 'smartcontracts/evm/test/vectors/selector_audit.json'
PQZ12 = 'smartcontracts/evm/src/regulated/NormalPqzRegulatedToken.sol'

FROZEN_DEAD = [(ABI, 'const LIFTABLE: [&str; 6] = ["Frozen", "TokenPaused",', 'const LIFTABLE: [&str; 6] = ["FrozenX", "TokenPaused",')]


def drop_signed(contract, sig):
    def f(d):
        before = len(d[contract])
        d[contract] = [r for r in d[contract] if r['sig'] != sig]
        assert len(d[contract]) == before - 1, (contract, sig)
    return f


def make_signed(contract, sig):
    def f(d):
        rows = [r for r in d[contract] if r['sig'] == sig]
        assert len(rows) == 1 and rows[0]['class'] != 'SIGNED', (contract, sig)
        rows[0]['class'] = 'SIGNED'
    return f


MUT = {
    # ------------------------------------------------------------------ plan T35 step 5
    # a kind 8-13 row missing on one side: the contract's (selector_audit.json) and the node's (typed.rs)
    'audit-row-missing-11': [('json:' + AUDIT, drop_signed('WrappedZetherRegulatedToken', 'mtxExecuteTransfer((bytes32,bytes32,uint256,bytes32,uint256,uint256,uint256,uint32,address,uint256,address),(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))'))],
    'node-row-missing': [(TYPED, '("UAFreeze", "mtxFreeze", GR,', '// ("UAFreeze", "mtxFreeze", GR,')],
    'frozen-as-dead': FROZEN_DEAD,
    'e2e-frozen-as-dead': FROZEN_DEAD,
    'market-not-halted': [(VENUE, 'Some("Paused") => self.set_paused(addr_of("contract").unwrap_or_default(), e["until"].as_u64().unwrap_or(u64::MAX)),',
                           'Some("Paused") => {}')],
    # ------------------------------------------------------------------ this task's own
    'audit-control-signed-9': [('json:' + AUDIT, make_signed('WrappedRegulatedToken', 'freeze(bytes32,bytes32,bytes32)'))],
    'router-control-on-token': [(TYPED, '("UAFreeze", "mtxFreeze", GR,', '("UAFreeze", "mtxFreeze", &["gov_router", "token"],')],
    'sol-ua-allowed-extended-12': [(PQZ12, 'return super._uaAllowed(sel);', 'return sel == this.cancelNonce.selector || super._uaAllowed(sel);')],
    'registry-unavailable-dead': [(ABI, '"RegistryUnavailable", "RegistryGasStarved"]', '"RegistryUnavailableX", "RegistryGasStarved"]')],
    'governance-errors-unnamed': [(ABI, '    if let Ok(e) = IGovernance::IGovernanceErrors::abi_decode(data) {\n        return format!("{e:?}");\n    }\n', '')],
    'interface-id-or': [(ABI, 'a[i] ^ s[i]', 'a[i] | s[i]')],
    'paused-blames-maker': [(VENUE, 'if let Some(p) = paused {', 'if let Some(p) = paused.filter(|_| false) {')],
    'precheck-no-frozen': [(VENUE, 'if t == sell && view(&self.chain, t, IRegulatedToken::isFrozenCall', 'if false && t == sell && view(&self.chain, t, IRegulatedToken::isFrozenCall')],
    'precheck-no-venue': [(VENUE, 'if let (false, reason, _) = self.leg_receivable(t, &c, self.dex.into_word(), at).await? {',
                           'if let (false, reason, _) = (true, 0u8, 0u64) {')],
    'precheck-no-attestation-shorter': [(VENUE, 'if o.validUntil > U256::from(until) {', 'if false && o.validUntil > U256::from(until) {')],
    'registry-none-allowed': [(VENUE, '        let reg = match self.registry {', '        let reg = match self.registry.or(Some(c.complianceRegistry)) {')],
    'frozen-drops-buying-too': [(VENUE, 'filter(|r| r.sell == t && r.order.from == a)', 'filter(|r| (r.sell == t || r.order.receiveToken == t) && r.order.from == a)')],
    'regulated-events-from-any-token': [(VENUE, '                    self.is_regulated(a)\n', '                    self.is_regulated(a) || a != Address::ZERO\n')],
    'halted-trade-acked': [(VENUE, 'let failed: Vec<&FailedTrade> = sr.failed.iter().filter(open).collect();',
                            'let failed: Vec<&FailedTrade> = sr.failed.iter().filter(|ft| open(ft) || true).collect();')],
    'codehash-unchecked': [(CHAIN, 'if code.is_empty() || got != pin {', 'if code.is_empty() {')],
    'codehash-empty-code-accepted': [(CHAIN, 'if code.is_empty() || got != pin {', 'if got != pin {')],
    'config-half-accepted': [(CONFIG, 'if c.compliance_registry.is_some() != c.compliance_registry_codehash.is_some() {', 'if false {')],
    'no-alert-on-paused': [(INDEXER, 'pub const ALERTS: [&str; 4] = ["OrderRecorded", "RelaxProposed", "AccountFrozen", "Paused"];',
                            'pub const ALERTS: [&str; 4] = ["OrderRecorded", "RelaxProposed", "AccountFrozen", "Unpaused"];')],
    'filter-misses-regulated': [(INDEXER, '    topics.extend(REGULATED_TOPICS);\n', '')],
    'forced-transfer-from-raw': [(INDEXER, '(v["event"], v["record_id"], v["amount"]) = (json!("ForcedTransfer"), h(e.recordId), json!(e.amount.to_string()));\n        put_id(v, "from", e.from);\n        put_id(v, "to", e.to);',
                                  '(v["event"], v["record_id"], v["amount"]) = (json!("ForcedTransfer"), h(e.recordId), json!(e.amount.to_string()));\n        v["from"] = h(e.from);\n        v["to"] = h(e.to);')],
    'derived-freeze-bit-wrong': [(INDEXER, '            5 => v["derived"] = json!("every_freeze_ended"),', '            6 => v["derived"] = json!("every_freeze_ended"),')],
}

if __name__ == '__main__':
    if sys.argv[1:] == ['--list']:
        print('\n'.join(MUT))
        sys.exit(0)
    for path, old, *new in MUT[sys.argv[1]]:
        if path.startswith('json:'):
            p = path[5:]
            d = json.load(open(p))
            old(d)
            json.dump(d, open(p, 'w'), indent=1)
            continue
        s = open(path).read()
        if s.count(old) != 1 or old == new[0]:
            sys.exit('%s: anchor found %d times in %s' % (sys.argv[1], s.count(old), path))
        open(path, 'w').write(s.replace(old, new[0]))
