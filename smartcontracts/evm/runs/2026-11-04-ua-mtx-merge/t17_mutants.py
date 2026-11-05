#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T17 (plan step 5): one mutant at a time on scaas-node's src/dex.rs and src/dex/venue.rs, the vectors fixed.
`t17_mutants.py <name>` from scaas-node applies one (every edit's anchor must be found exactly once); `run_t17_mutants.sh` runs
the lib tests of dex (book and venue) after each and restores the files with `git checkout -- <file>` (clean checked first).
`--list` prints the names. The plan's three first (destination dropped from the book's digest, `LegSettled` watched for a SCaaS
leg, shape 0 accepted), each in its two places, then the venue's own rules: R17 on a native auth, a derived seller at
`registry() == 0`, the job kinds of the token-side cancel and invalidation (R43), the emitter of a token's order events."""
import sys

DX, VE = 'src/dex.rs', 'src/dex/venue.rs'
MUT = {
    # the book's digest of a SCaaS order without its signed destination
    'destination-dropped-from-digest': [(DX,
        '    o.eip712_signing_hash(token_domain)\n',
        '    UATradeOrder { destination: B256::ZERO, ..o.clone() }.eip712_signing_hash(token_domain)\n')],
    # the wire drops the destination before the token is asked for the digest
    'destination-dropped-from-wire': [(DX,
        'Ok(UATradeOrder { from: b32(&self.from)?, destination: b32(&self.destination)?, ..canon(&o) })',
        'Ok(UATradeOrder { from: b32(&self.from)?, destination: B256::ZERO, ..canon(&o) })')],
    # the watcher releases a pending fill on `LegSettled` only: a SCaaS leg's `UALegSettled` is ignored
    'legsettled-for-a-scaas-leg': [(VE,
        'Some("LegSettled" | "UALegSettled") => {',
        'Some("LegSettled") => {')],
    # the watcher does not ask the chain for `UALegSettled`
    'ua-leg-settled-not-asked': [(VE,
        '            ISCaaSDex::UALegSettled::SIGNATURE_HASH,\n            ISCaaSDex::MatchFailed::SIGNATURE_HASH,\n',
        '            ISCaaSDex::MatchFailed::SIGNATURE_HASH,\n')],
    # a SCaaS sell token takes the shape-0 form (a `signature`)
    'shape-zero-accepted': [(DX,
        '        (KIND_SCAAS, None, Some(a)) => Ok(Auth::Ua(ua_sig(a)?)),\n',
        '        (KIND_SCAAS, None, Some(a)) => Ok(Auth::Ua(ua_sig(a)?)),\n'
        '        (KIND_SCAAS, Some(s), None) => Ok(Auth::Sig(hex_bytes(s)?)),\n')],
    # a SCaaS leg sent as shape 0
    'scaas-leg-sent-shape-zero': [(DX,
        'sellToken: r.sell, shape: 1, order: trade_of(&empty_ua_order()), uaOrder: r.order.clone(),',
        'sellToken: r.sell, shape: 0, order: trade_of(&r.order), uaOrder: r.order.clone(),')],
    # R17 dropped: a native auth with keyData or members accepted
    'r17-dropped': [(VE,
        'let r17 = a.keyData.is_empty() && a.members.is_empty();',
        'let r17 = true;')],
    # a derived seller at registry() == 0 asked of address 0 instead of refused
    'registry-zero-accepted': [(VE,
        '        if registry == Address::ZERO {\n            return Ok(false);\n        }\n',
        '        if registry == Address::ZERO && false {\n            return Ok(false);\n        }\n')],
    # the token's invalidation on ids sent as an address `metatx` job
    'invalidate-job-kind-metatx': [(VE,
        '            (op["args"]["from"], op["auth"]) = (json!(format!("{id:#x}")), ua_sig_json(a));\n            "ua_metatx"\n',
        '            (op["args"]["from"], op["auth"]) = (json!(format!("{id:#x}")), ua_sig_json(a));\n            "metatx"\n')],
    # the token's cancel on ids sent as an address `metatx` job
    'cancel-job-kind-metatx': [(VE,
        'Auth::Ua(a) => jobs.push(json!({"kind": "ua_metatx", "market_id": m, "op": {"entry": "mtxCancelOrder",',
        'Auth::Ua(a) => jobs.push(json!({"kind": "metatx", "market_id": m, "op": {"entry": "mtxCancelOrder",')],
    # a token's order events taken from the DEX too
    'token-order-event-from-the-dex': [(VE,
        '                    self.kind(a) == KIND_SCAAS\n',
        '                    self.kind(a) == KIND_SCAAS || a == self.dex\n')],
}

if __name__ == '__main__':
    if sys.argv[1:] == ['--list']:
        print('\n'.join(MUT))
        sys.exit(0)
    for f, old, new in MUT[sys.argv[1]]:
        s = open(f).read()
        if s.count(old) != 1:
            sys.exit('%s: anchor found %d times in %s' % (sys.argv[1], s.count(old), f))
        open(f, 'w').write(s.replace(old, new))
