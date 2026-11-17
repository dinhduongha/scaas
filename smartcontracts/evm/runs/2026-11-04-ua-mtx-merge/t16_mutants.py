#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T16 (plan step 5): one mutant at a time on scaas-node's src/mesh/digest.rs (and src/metatx.rs for the UA
digest's zero rule), the vectors fixed. `t16_mutants.py <name>` from scaas-node applies one (every edit's anchor must be
found exactly once); `run_t16_mutants.sh` runs the mesh lib tests and `tests/mesh_vectors.rs` after each and restores the
files with `git checkout -- <file>` (clean checked first). `--list` prints the names. The plan's three first (intent id over
the address struct, the zero rule for unbound fields dropped, the old body accepted), then the derived-from refusal, R17,
the 1.3 version rule, each half of the address-body refusal and the submitter's normalization."""
import sys

D = 'src/mesh/digest.rs'
M = 'src/metatx.rs'
ADDR = '            if matches!(m, Mtx::Transfer(_)) || chain.tokens.contains(&env.contract) {\n'
MUT = {
    # NODE-MESH-08 on the address struct: a UA transfer's intent id taken over the address MetaTransfer of the same fields
    'intent-id-over-address-struct': [(D,
        '        intent_id: both!(&meta, digest, &domain).0,\n',
        '        intent_id: match &meta {\n'
        '            Meta::Ua(UaMtx::Transfer(t), _) => Mtx::Transfer(crate::metatx::MetaTransfer { from: signer, to: Address::from_word(t.to),\n'
        '                value: t.value, entryRef: t.entryRef, batch: t.batch, nonce: t.nonce, validUntil: t.validUntil, mode: t.mode,\n'
        '                relayer: t.relayer, fee: t.fee, feeRecipient: t.feeRecipient }).digest(&domain).0,\n'
        '            _ => both!(&meta, digest, &domain).0,\n'
        '        },\n')],
    # NODE-LANE-10: the UA digest hashes the wire relayer / feeRecipient as given (unbound fields not zeroed)
    'unbound-zero-rule-dropped': [(M,
        '    pub fn digest(&self, domain: &Domain) -> B256 {\n        let mut c = self.clone();\n        c.unbound(None, None);\n',
        '    pub fn digest(&self, domain: &Domain) -> B256 {\n        let c = self.clone();\n')],
    # R45: the address body accepted again (no OP_KIND_MISMATCH at all)
    'old-body-accepted': [(D, ADDR, '            if false {\n')],
    # half: an address MetaTransaction on a registered token accepted
    'token-address-call-accepted': [(D, ADDR, '            if matches!(m, Mtx::Transfer(_)) {\n')],
    # half: an address MetaTransfer accepted on a contract that is no registered token
    'address-transfer-on-any-contract-accepted': [(D, ADDR, '            if chain.tokens.contains(&env.contract) {\n')],
    # MD-10: a derived from taken (its id's low 20 bytes as the signer)
    'derived-from-accepted': [(D,
        '            let signer = native(&m.from()).ok_or(Code::DerivedFromUnsupported)?; // MD-10\n',
        '            let signer = native(&m.from()).unwrap_or(Address::from_word(m.from())); // MD-10\n')],
    # R17: a native UASig with keyData or members accepted
    'r17-dropped': [(D,
        '            if !auth.keyData.is_empty() || !auth.members.is_empty() {\n',
        '            if false {\n')],
    # NODE-MESH-18: the UA body taken under scaas-intent/1.2
    'ua-body-under-1-2-accepted': [(D, '            if env.minor() < 3 {\n', '            if env.minor() < 2 {\n')],
    # R84 at submission: the UA struct sent with the wire's unbound relayer / feeRecipient
    'submit-not-normalized': [(D,
        '            Meta::Ua(mut m, _) => {\n                m.normalize(fee_recipient);\n                m.to_wire()\n',
        '            Meta::Ua(m, _) => {\n                m.to_wire()\n')],
}

if sys.argv[1] == '--list':
    print(' '.join(MUT))
    sys.exit(0)
for path, a, b in MUT[sys.argv[1]]:
    s = open(path).read()
    assert s.count(a) == 1, (sys.argv[1], path, s.count(a))
    open(path, 'w').write(s.replace(a, b, 1))
