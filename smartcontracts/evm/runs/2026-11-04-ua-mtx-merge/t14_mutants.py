#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T14 (plan step 5): one mutant at a time on scaas-node's src/{typed,guard,chain,submit}.rs, the vectors fixed.
`t14_mutants.py <name>` from scaas-node applies one (every edit's anchor must be found exactly once); `run_t14_mutants.sh`
runs the lib tests of typed, guard, chain, submit and metatx after each and restores the file with `git checkout -- <file>`
(clean checked first). `--list` prints the names. The plan's five first (a row on the wrong kind, a derived subject on
`_mtxRule`, the nonce view by address on a token / a mandate wallet, the old shape accepted, a flat wallet builder left in
PLAIN), then the allow-list one side only, R44's gate both ways, the decode bound and R80's events."""
import sys

TY, GU, CH, SU = 'src/typed.rs', 'src/guard.rs', 'src/chain.rs', 'src/submit.rs'
OLD_STRUCT_JOB = '''    let mut m = Mtx::from_wire(job.struct_.as_deref(), job.metatx.as_ref().expect("metatx"))?;
    let (Some(token), Some(sig)) = (job.token, &job.signature) else { anyhow::bail!("no token / signature") };
    m.normalize(fee_recipient);
    let sig = hex_bytes(sig)?;
    let valid_until = m.valid_until().saturating_to();
    let meta = Some(MetaRef::of(token, &m, None));
    let typed = Some(transfer_typed(job.contract.as_deref(), token, m.struct_hash(), Some((m.from(), sig.clone())))?);
    let data = match pay_meta(job)? {
        None => m.calldata(sig),
        Some((salt, pm, on_chain)) => m.pay_meta_calldata(salt, pm, sig, on_chain)?,
    };
    return Ok(Work { job_id: Some(job.id), to: token, data, valid_until, meta, entry: false, typed });
'''
MUT = {
    # a merged row on kinds whose contract has no such entry: the burn also on the mandate wallet and the router
    'row-on-wrong-kind': [(TY,
        '    ("UABurn", "mtxBurn", T, "bytes32 from,uint256 amount,E", ""),\n',
        '    ("UABurn", "mtxBurn", TWG, "bytes32 from,uint256 amount,E", ""),\n')],
    # B: a derived subject let through on an address row (`_mtxRule` only)
    'derived-subject-on-mtx-rule': [(GU,
        '        if w.typed.as_ref().is_some_and(|t| t.derived_signer) && !row.ua() {',
        '        if w.typed.as_ref().is_some_and(|t| t.derived_signer) && !row.ua() && false {')],
    # the nonce view by address on a mandate wallet
    'nonce-view-by-address-on-wallet': [(SU,
        '    let addr_nonce = p.typed.contract == "account";',
        '    let addr_nonce = p.typed.contract == "account" || p.typed.contract == "wallet";')],
    # the nonce view by address on a token's address envelope (a wrap)
    'nonce-view-by-address-on-token': [(CH,
        '        if m.addr_nonce {\n',
        '        if m.addr_nonce || !m.ua {\n')],
    # the old shape accepted silently: an address MetaTransfer job relayed as before the merge
    'old-shape-accepted': [(SU,
        '''    if job.metatx.is_some() {
        // R43 / CTR-MTX-30''',
        '''    if job.metatx.is_some() {
''' + OLD_STRUCT_JOB + '''    }
    if job.metatx.is_some() {
        // R43 / CTR-MTX-30''')],
    # a flat wallet builder left in PLAIN (MD-11 (a))
    'flat-builder-left-in-plain': [(TY,
        '    ("mtxExecuteAsOwner", A, "bytes data,uint256 nonce,uint256 validUntil,bytes sig"),\n',
        '    ("mtxExecuteAsOwner", A, "bytes data,uint256 nonce,uint256 validUntil,bytes sig"),\n'
        '    ("mtxRevoke", W, "address token,uint64 epoch,uint256 validUntil,bytes sig"),\n')],
    # the allow-list on one side only: a node row no contract has
    'row-on-node-side-only': [(TY,
        '    ("mtxExecuteAsOwner", A, "bytes data,uint256 nonce,uint256 validUntil,bytes sig"),\n',
        '    ("mtxExecuteAsOwner", A, "bytes data,uint256 nonce,uint256 validUntil,bytes sig"),\n'
        '    ("mtxBurnAll", T, "bytes32 from"),\n')],
    # the allow-list on one side only: a contract entry the node lost (the Zether batch roll-over)
    'row-on-contract-side-only': [(TY,
        '    ("UARollOverBatch", "mtxRollOverBatch", Z, "bytes32 from,bytes32[] uas,E", ""),\n',
        '')],
    # R44 backwards: the UA-ledger gate on every merged entry, an all-native one too
    'registry-gate-on-all-native': [(GU,
        '''            if w.typed.as_ref().is_some_and(|t| t.derived_side) {
                return self.require_ua_ledger(chain, w.to).await;''',
        '''            if row.ua() || w.typed.as_ref().is_some_and(|t| t.derived_side) {
                return self.require_ua_ledger(chain, w.to).await;''')],
    # R44 dropped: a derived side at registry 0 not refused before the simulation
    'registry-gate-dropped': [(GU,
        '''            if w.typed.as_ref().is_some_and(|t| t.derived_side) {
                return self.require_ua_ledger(chain, w.to).await;''',
        '''            if w.typed.as_ref().is_some_and(|t| t.derived_side && false) {
                return self.require_ua_ledger(chain, w.to).await;''')],
    # the decode of a member list without its bound (a hostile UASig copied before any check)
    'member-sig-bound-dropped': [(TY,
        '        if matches!(el, "MemberSig" | "InnerSig") && a.len() > MSIG_MAX_SLOTS {',
        '        if matches!(el, "MemberSig" | "InnerSig") && a.len() > MSIG_MAX_SLOTS * 1000 {')],
    # R80 / R18: a native lane classified on the UA event only (an address-path spend missed: never dead while it may land)
    'native-lane-ua-event-only': [(CH,
        '        Some(_) => vec![ua, mtx],\n',
        '        Some(_) => vec![ua],\n')],
}

if sys.argv[1] == '--list':
    print(' '.join(MUT))
    sys.exit(0)
for path, a, b in MUT[sys.argv[1]]:
    s = open(path).read()
    assert s.count(a) == 1, (sys.argv[1], path, s.count(a))
    open(path, 'w').write(s.replace(a, b, 1))
