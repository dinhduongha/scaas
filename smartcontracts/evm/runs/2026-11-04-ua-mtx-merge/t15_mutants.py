#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T15 (plan step 5): one mutant at a time on scaas-node's src/gateway.rs, the vectors fixed.
`t15_mutants.py <name>` from scaas-node applies one (every edit's anchor must be found exactly once); `run_t15_mutants.sh`
runs the lib tests of gateway and guard after each and restores the file with `git checkout -- <file>` (clean checked first).
`--list` prints the names. The plan's three first (the `/v1/metatx` token refusal dropped, the registry gate applied to an
all-native request, `auth` decoded as `bytes`), then the wallet refusal dropped and `/v1/op` closed to merged entries again."""
import sys

GW = 'src/gateway.rs'
REFUSAL = '    if r.contract.as_deref() == Some("wallet") || c.tokens.read().map(|t| t.contains(&r.token)).unwrap_or(false) {\n'
MUT = {
    # the /v1/metatx token refusal dropped: a registered token's address MetaTransfer is no longer refused by name
    'metatx-token-refusal-dropped': [(GW, REFUSAL, '    if r.contract.as_deref() == Some("wallet") {\n')],
    # R44 backwards at the door: the UA-ledger gate on an all-native request (the request marked as having a derived side)
    'registry-gate-on-all-native': [(GW,
        '    w.job_id = None;\n',
        '    w.job_id = None;\n    if let Some(t) = w.typed.as_mut() {\n        t.derived_side = true;\n    }\n')],
    # R47 at the door: `auth` taken as the packed `bytes` signature, not the UASig object
    'auth-decoded-as-bytes': [(GW,
        '"m": r.m, "auth": r.auth});',
        '"m": r.m, "auth": r.auth.get("signature")});')],
    # Q6: the mandate wallet's refusal dropped (an address MetaTransfer to a wallet answered as an unknown token)
    'wallet-refusal-dropped': [(GW, REFUSAL, '    if c.tokens.read().map(|t| t.contains(&r.token)).unwrap_or(false) {\n')],
    # /v1/op closed to the merged entries again (the pre-T15 FEATURE_UNSUPPORTED)
    'op-door-closed-to-merged': [(GW,
        '    let (w, _) = match work_of_op(None, &r.op, c.fee_recipient) {\n        Ok(x) => x,\n        Err(e) => return bad(format!("{e:#}")),\n    };\n',
        '    let (w, ua) = match work_of_op(None, &r.op, c.fee_recipient) {\n        Ok(x) => x,\n        Err(e) => return bad(format!("{e:#}")),\n    };\n'
        '    if ua {\n        return bad("FEATURE_UNSUPPORTED: a ua* entry is a ua_metatx job, not a gateway request");\n    }\n')],
}

if sys.argv[1] == '--list':
    print(' '.join(MUT))
    sys.exit(0)
for path, a, b in MUT[sys.argv[1]]:
    s = open(path).read()
    assert s.count(a) == 1, (sys.argv[1], path, s.count(a))
    open(path, 'w').write(s.replace(a, b, 1))
