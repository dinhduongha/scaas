#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T34 (regulated vectors, clientkeys and ua-rs rows): one mutant at a time on the T34 tree. `t34_mutants.py
<name>` from the repository root applies one (every edit's anchor must be found exactly once, and the edit must change
something); `run_t34_mutants.sh` runs the reader the name's prefix names after each (`ck-` clientkeys, `gen-` the
typed-ops generator then clientkeys, `rs-` ua-rs, `sol-` the T34 forge suites) and restores the tree with `git checkout`.
`--list` prints the names. The plan's step 5 rows first, then this task's own."""
import sys

EVM = 'clients/clientkeys/src/evm.js'
REG = 'clients/clientkeys/src/regulated.js'
GEN = 'clients/clientkeys/scripts/typed-ops-vectors.mjs'
RS = 'clients/ua-rs/src/regulated.rs'
ROUTER = 'smartcontracts/evm/src/governance/GovernanceRouterBase.sol'
GLIB = 'smartcontracts/evm/src/governance/GovernanceLib.sol'
RLIB = 'smartcontracts/evm/src/regulated/RegulatedLib.sol'
RBASE = 'smartcontracts/evm/src/regulated/RegulatedBase.sol'

MUT = {
    # ------------------------------------------------------------------ plan T34 step 5
    'ck-forcetransfer-field-order': [(EVM, "UAForceTransfer: { fields: 'address target,bytes32 recordId,uint256 amount'",
                                      "UAForceTransfer: { fields: 'address target,uint256 amount,bytes32 recordId'")],
    'rs-forcetransfer-field-order': [(RS, '("UAForceTransfer", "bytes32 recordId,uint256 amount"),',
                                      '("UAForceTransfer", "uint256 amount,bytes32 recordId"),')],
    'ck-relayer-not-zeroed': [(EVM, '      if (!(BigInt(m.mode) & 1n)) m.relayer = ZERO_ADDRESS;\n', '')],
    'rs-relayer-not-zeroed': [(RS, 'canon(e.mode & 1 != 0, &e.relayer)', 'canon(true, &e.relayer)')],
    'ck-commit-action-swapped': [(REG, 'REVOKE: 3, RENOUNCE: 4,', 'REVOKE: 4, RENOUNCE: 3,')],
    'ck-commit-action-bit-swapped': [(REG, "abiEncode(['uint8', 'uint8', 'bytes32', 'bytes32'], [action, bit, account, args])",
                                      "abiEncode(['uint8', 'uint8', 'bytes32', 'bytes32'], [bit, action, account, args])")],
    'rs-commit-action-tag-swapped': [(RS, 'Some(keccak(&[&word(action as u64), &word(bit as u64), account, &args]))',
                                      'Some(keccak(&[&word(bit as u64), &word(action as u64), account, &args]))')],
    'sol-commit-action-swapped': [(GLIB, '    uint8 internal constant REVOKE = 3;\n    uint8 internal constant RENOUNCE = 4;\n',
                                   '    uint8 internal constant REVOKE = 4;\n    uint8 internal constant RENOUNCE = 3;\n')],
    # ------------------------------------------------------------------ this task's own
    'ck-feerecipient-not-zeroed': [(EVM, '      if (!(BigInt(m.mode) & 2n)) m.feeRecipient = ZERO_ADDRESS;\n', '')],
    'rs-feerecipient-not-zeroed': [(RS, 'canon(e.mode & 2 != 0, &e.fee_recipient)', 'canon(true, &e.fee_recipient)')],
    'rs-target-not-signed': [(RS, 'e.from, address_word(target)]', 'e.from, [0; 32]]')],
    'rs-record-id-order': [(RS, 'keccak(&[order_id, subject, beneficiary])', 'keccak(&[subject, order_id, beneficiary])')],
    'rs-set-terms-unbound': [(RS, 'let args = terms.map_or([0; 32], |t| {', 'let args = terms.filter(|_| false).map_or([0; 32], |t| {')],
    'rs-eligible-passes-denied': [(RS, '    if active && a.flags & denied.unwrap_or(0) != 0 {',
                                   '    if active && a.flags & ELIGIBLE_CONTRACT == 0 && a.flags & denied.unwrap_or(0) != 0 {')],
    'rs-valid-until-strict': [(RS, 'let active = a.attester_enabled && a.valid_until >= now;',
                               'let active = a.attester_enabled && a.valid_until > now;')],
    'ck-disabled-attester-reason': [(REG, "reason: until === 0n ? 1 : !attesterEnabled ? 3 : !active ? 2 : 1",
                                     "reason: until === 0n ? 1 : !active ? 2 : 1")],
    'ck-lapsed-passes': [(REG, 'const active = attesterEnabled && until >= t;', 'const active = attesterEnabled;')],
    'ck-episode-cap-off': [(REG, 'const n = t + FREEZE_SPAN < cap ? t + FREEZE_SPAN : cap;', 'const n = t + FREEZE_SPAN;')],
    'ck-unfreeze-keeps-record': [(REG, "  const end = () => Object.assign(s, { until: String(t), recordBacked: false, recordId: ZERO,",
                                  "  const end = () => Object.assign(s, { until: String(t), recordBacked: false,")],
    'ck-revoke-ends-any-freeze': [(REG, '    if (s.recordId === rid && on) end();', '    if (on) end();')],
    'ck-record-shorter-unchecked': [(REG, "    if (on && BigInt(record.freezeUntil) < BigInt(s.until)) return refused('RecordFreezeShorter(uint64)', s.until);\n",
                                     '')],
    'ck-pool-target-accepted': [(REG, '[ZERO, UA_POOL_ID, SHIELD_POOL_ID, pad(token)]', '[ZERO, pad(token)]')],
    'gen-freeze-row-other-record': [(GEN, 'ROW.UAFreeze = { account: ORDER.subject, ref: REG_REF, recordId: RECORD };',
                                     "ROW.UAFreeze = { account: ORDER.subject, ref: REG_REF, recordId: hex(hash('regulated.other')) };")],
    'sol-operator-typehash-from': [(ROUTER, '"UAOperatorTransfer(bytes32 from,address target,bytes32 account,bytes32 to,',
                                    '"UAOperatorTransfer(bytes32 from,address target,bytes32 to,bytes32 account,')],
    'sol-t4-shorter-unchecked': [(RLIB, '            if (on && o.freezeUntil < s.until) revert IRegulatedToken.RecordFreezeShorter(s.until);\n', '')],
    'sol-unfreeze-keeps-record-id': [(RLIB, '        (s.until, s.recordBacked, s.recordId, s.issuerCooldownUntil) = (now_, false, 0, now_ + FREEZE_COOLDOWN);',
                                      '        (s.until, s.recordBacked, s.issuerCooldownUntil) = (now_, false, now_ + FREEZE_COOLDOWN);')],
    'sol-bit22-not-regulated': [(RBASE, '        | (1 << GovernanceBits.MODERATE) | (1 << GovernanceBits.OPERATOR_TRANSFER);\n    uint256 internal constant REG_BITS_CONFIDENTIAL',
                                 '        | (1 << GovernanceBits.MODERATE);\n    uint256 internal constant REG_BITS_CONFIDENTIAL')],
}


def main():
    if sys.argv[1:] == ['--list']:
        print(' '.join(MUT))
        return
    name = sys.argv[1]
    for path, old, new in MUT[name]:
        s = open(path).read()
        if s.count(old) != 1:
            sys.exit(f'{name}: anchor in {path} found {s.count(old)} times')
        if old != new:
            open(path, 'w').write(s.replace(old, new))
    if all(old == new for _, old, new in MUT[name]):
        sys.exit(f'{name}: changes nothing')


if __name__ == '__main__':
    main()
