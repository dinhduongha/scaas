#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T18 (plan step 5): one mutant at a time on scaas-node, run from scaas-node. `t18_mutants.py <name>` applies one
(every edit's anchor must be found exactly once); `--list` prints the names; `--tests <name>` the cargo test arguments that run
against it (the anvil e2e, ignored, one thread). `run_t18_mutants.sh` restores the files with `git checkout` after each. The
plan's three first (the Hedera `from` padded as an ECDSA alias for an ED25519 account, the e2e asserting `PaymentSettled` on a
merged path, the wallet call on `mtxExecuteAsOwnerRaw`), then two node mutants the e2e must catch on a chain (R44's registry
gate on a transfer job, the UA digest's zero rule for unbound fields)."""
import sys

E = 'tests/e2e.rs'
H = 'tests/e2e_hedera.rs'
UA_EVENTS = '    for t in [IUALedger::UAPaymentSettled::SIGNATURE_HASH, IUALedger::UAMetaTransactionExecuted::SIGNATURE_HASH] {\n'
ADDR_EVENTS = '    for t in [IToken::PaymentSettled::SIGNATURE_HASH, IToken::MetaTransactionExecuted::SIGNATURE_HASH] {\n'
SWAPPED = [(f, UA_EVENTS + '        assert!(topics.contains(&t), "{tx}: no UA event {t:#x}");\n    }\n' + ADDR_EVENTS
            + '        assert!(!topics.contains(&t), "{tx}: an address event {t:#x} on a merged path");\n',
            ADDR_EVENTS + '        assert!(topics.contains(&t), "{tx}: no UA event {t:#x}");\n    }\n' + UA_EVENTS
            + '        assert!(!topics.contains(&t), "{tx}: an address event {t:#x} on a merged path");\n') for f in (E, H)]
E2E = ['--test', 'e2e', '--', '--ignored', '--test-threads=1']
HED = ['--test', 'e2e_hedera', '--', '--ignored']
MUT = {
    # R42: the ED25519 account 0.0.N's `from` taken as the key's ECDSA alias, padded, instead of its long-zero address
    'hedera-from-padded-as-ecdsa': ([(H, '        from: native_id(),\n', '        from: key.address().into_word(),\n')], [HED]),
    # R18: the e2e expecting the address `PaymentSettled` / `MetaTransactionExecuted` on a merged path (both files' helper)
    'payment-settled-asserted-on-merged-path': (SWAPPED, [E2E + ['outbox_payment', 'eoa_mtx_transfer', 'derived_mtx'], HED]),
    # MD-11 (a): the delegate's wallet call on the flat builder `mtxExecuteAsOwnerRaw`
    'wallet-call-on-mtx-execute-as-owner-raw': ([(E, '"op": pay("mtxPayUnderMandate")', '"op": pay("mtxExecuteAsOwnerRaw")')],
        [E2E + ['mandate_payment']]),
    # R44 (step 7a): a transfer job's derived side relayed at registry() == 0 (the guard's UA-ledger gate dropped)
    'registry-gate-dropped-on-transfer': ([('src/guard.rs', '        if ua && w.typed.as_ref().is_some_and(|t| t.derived_side) {\n',
        '        if ua && w.typed.as_ref().is_some_and(|t| t.derived_side && false) {\n')], [E2E + ['registry_zero']]),
    # NODE-LANE-10 / R84: the UA digest over the wire's unbound relayer / feeRecipient (not zeroed as the token does)
    'unbound-zero-rule-dropped': ([('src/metatx.rs',
        '    pub fn digest(&self, domain: &Domain) -> B256 {\n        let mut c = self.clone();\n        c.unbound(None, None);\n        let d = domain.eip712();\n',
        '    pub fn digest(&self, domain: &Domain) -> B256 {\n        let c = self.clone();\n        let d = domain.eip712();\n')],
        [E2E + ['dex_order_with']]),
}

if sys.argv[1] == '--list':
    print(' '.join(MUT))
elif sys.argv[1] == '--files':
    print(' '.join(sorted({f for edits, _ in MUT.values() for f, _, _ in edits})))
elif sys.argv[1] == '--tests':
    for t in MUT[sys.argv[2]][1]:
        print(' '.join(t))
else:
    for path, a, b in MUT[sys.argv[1]][0]:
        s = open(path).read()
        assert s.count(a) == 1, (sys.argv[1], path, s.count(a))
        open(path, 'w').write(s.replace(a, b, 1))
