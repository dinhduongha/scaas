#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T12 (plan step 5): one mutant at a time on zether-prover's src/envelope.rs, the vectors fixed.
`t12_mutants.py <name>` from clients/zether-prover applies one (every edit's anchor must be found exactly once);
`run_t12_mutants.sh` runs tests/typed_ops.rs and tests/envelope_disclosure.rs after each and restores src/envelope.rs with
`git checkout -- src/envelope.rs` (clean checked first). `--list` prints the names. The plan's two first, then two of the
UASig the merged entries take."""
import sys

ENV = 'src/envelope.rs'
MUT = {
    # the UA tag swapped for the address tag in the merged entries' binding
    'ua-tag-swapped-for-address-tag': [(ENV,
        '            keccak256(b"SCAAS-ZETHER-UA-ENVELOPE-V1"),\n',
        '            keccak256(b"SCAAS-ZETHER-ENVELOPE-V1"),\n')],
    # `from` hashed as an address (the id's low 160 bits): equal for a native id, wrong for a derived one
    'from-hashed-as-address': [(ENV,
        '            abi::addr(token),\n            m.from,\n            m.batch,\n',
        '            abi::addr(token),\n            abi::addr(&m.from[12..].try_into().unwrap()),\n            m.batch,\n')],
    # the UASig's members left out of the encoding (an msig subject's signature lost)
    'ua-sig-members-dropped': [(ENV,
        'Tok::Bytes(s.signature.clone()), Tok::Array(members.len() as u64, abi::encode(&members))])',
        'Tok::Bytes(s.signature.clone()), Tok::Array(0, vec![])])')],
    # a merged entry built with the retired packed `bytes sig` in place of `UASig auth`
    'single-signs-bytes-sig': [(ENV,
        '    toks.extend([Tok::Bytes(proof.to_vec()), ua_sig_tok(auth)]);\n    call(&format!("mtxConfidentialTransferSingle(',
        '    toks.extend([Tok::Bytes(proof.to_vec()), Tok::Bytes(auth.signature.clone())]);\n    call(&format!("mtxConfidentialTransferSingle(')],
}

if sys.argv[1] == '--list':
    print(' '.join(MUT))
    sys.exit(0)
for path, a, b in MUT[sys.argv[1]]:
    s = open(path).read()
    assert s.count(a) == 1, (sys.argv[1], path, s.count(a))
    open(path, 'w').write(s.replace(a, b, 1))
