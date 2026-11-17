#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T28 (RegulatedLib, RegulatedBase, kinds 8 and 9): one mutant at a time on the T28 tree. `t28_mutants.py
<name>` from smartcontracts/evm applies one (every edit's anchor must be found exactly once); `run_t28_mutants.sh` runs the
regulated suites (test/as), GovDeploy and LinkClosure after each and restores `src` and `script` with `git checkout`.
`--list` prints the names. The plan's step 5 rows first (spec §9 FREEZE, Relaxation, FORCE, PAUSE, Fee legs), then this
task's own: the roots terms, the bounds, the record rules, the init path, kind 8's wiring, the deploy path."""
import sys

L = 'src/regulated/RegulatedLib.sol'
R = 'src/regulated/RegulatedBase.sol'
K8 = 'src/regulated/NormalRegulatedToken.sol'
K9 = 'src/regulated/WrappedRegulatedToken.sol'
U = 'src/metatx/UAMetaTxBase.sol'
M = 'src/metatx/MetaTokenBase.sol'
W = 'src/metatx/WrappedToken.sol'
D = 'script/DeployBase.sol'
END = '        (s.until, s.recordBacked, s.recordId, s.issuerCooldownUntil) = (now_, false, 0, now_ + FREEZE_COOLDOWN);'
MUT = {
    # ------------------------------------------------------------------ plan T28 step 5
    'unfreeze-keeps-recordid': [(L, END, '        (s.until, s.recordBacked, s.issuerCooldownUntil) = (now_, false, now_ + FREEZE_COOLDOWN);')],
    't4-no-until-check': [(L, '            if (on && o.freezeUntil < s.until) revert IRegulatedToken.RecordFreezeShorter(s.until);\n', '')],
    'revoke-keeps-backed-freeze': [(L, '        if (s.recordId == recordId && _counts(s, r.controls)) _end(s, o.subject, reasonRef);\n', '')],
    'force-roots-without-record-bit': [(L, '''        IRegulatedToken.OrderRecord storage o = _live(r, recordId);
        if (GovernanceLib.$().counts''', '''        IRegulatedToken.OrderRecord storage o = r.orders[recordId];
        if (o.subject == 0 || o.revoked) revert IRegulatedToken.OrderUnknown(recordId);
        if (GovernanceLib.$().counts''')],
    'k8-mirror-at-propose': [(K8, '        if (GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits())) _regDisabled(bit);',
                              '        GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits());\n        _regDisabled(bit);')],
    'k9-mirror-at-propose': [(K9, '''        if (!GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits())) return;
        if (bit == GovernanceBits.RATE_ADJUSTABLE) WrappedLib.dropPending();''',
                              '''        GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits());''')],
    'k9-disable-not-composed': [(K9, '''        if (bit == GovernanceBits.RATE_ADJUSTABLE) WrappedLib.dropPending();
        _regDisabled(bit);''', '''        if (bit == GovernanceBits.RATE_ADJUSTABLE) WrappedLib.dropPending();''')],
    'open-set-outer-selector': [(U, '        _regPre(m.from, bytes4(data), m.mode);', '        _regPre(m.from, msg.sig, m.mode);')],
    'burn-paused-at-fee-0': [(R, ' && sel != SEL_BURN)', ')')],
    'paywithfee-no-feeto': [(M, '''        _regFeeTo(MetaTxLib.pad(feeRecipient), feeAmount);
        if (feeAmount != 0) {''', '''        if (feeAmount != 0) {''')],
    'wraporder-no-feeto': [(W, '        _regFeeTo(MetaTxLib.pad(msg.sender), fee);\n', '')],
    'relayfee-no-feeto': [(M, '        _regFeeTo(payee, value);\n', '')],
    'pre-after-pipeline': [(U, '''        _regPre(m.from, bytes4(m.data), m.mode);
        return _uaSettle(m, MtxPipelineLib.preCallUA(_mtxCtx(), _uaEnvelopeOf(m), _callFacts(m.data, true), auth));''',
                            '''        MtxPipelineLib.Out memory o = MtxPipelineLib.preCallUA(_mtxCtx(), _uaEnvelopeOf(m), _callFacts(m.data, true), auth);
        _regPre(m.from, bytes4(m.data), m.mode);
        return _uaSettle(m, o);''')],
    # ------------------------------------------------------------------ this task's own
    'freeze-without-roots': [(L, ' && _counts(r.freezes[a], c) && GovernanceLib.$().counts[GovernanceBits.FREEZE].roots != 0;',
                              ' && _counts(r.freezes[a], c);')],
    'pause-without-roots': [(L, '''        return r.controls & C_PAUSE != 0 && r.pausedUntil > block.timestamp
            && GovernanceLib.$().counts[GovernanceBits.PAUSE].roots != 0;''',
                             '        return r.controls & C_PAUSE != 0 && r.pausedUntil > block.timestamp;')],
    'record-backed-ignores-record-bit': [(L, '        return s.until > block.timestamp && (!s.recordBacked || c & C_RECORD != 0);',
                                          '        c;\n        return s.until > block.timestamp;')],
    'freeze-span-off-by-one': [(L, 'uint64 internal constant FREEZE_SPAN = 30 days;', 'uint64 internal constant FREEZE_SPAN = 30 days + 1;')],
    'unfreeze-no-cooldown': [(L, END, '        (s.until, s.recordBacked, s.recordId) = (now_, false, 0);')],
    't3-not-refused': [(L, '                if (s.recordBacked) revert IRegulatedToken.AlreadyRecordFrozen(account);\n', '')],
    'freeze-target-this': [(L, '''        return a == MetaTxLib.pad(MetaTxLib.UA_POOL) || a == MetaTxLib.pad(MetaTxLib.SHIELD_POOL)
            || a == MetaTxLib.pad(address(this));''', '''        return a == MetaTxLib.pad(MetaTxLib.UA_POOL) || a == MetaTxLib.pad(MetaTxLib.SHIELD_POOL);''')],
    'force-executed-not-accumulated': [(L, '        o.executed = done + amount;\n', '')],
    'force-beneficiary-frozen-passes': [(L, '        if (frozen(to)) revert IRegulatedToken.Frozen(to);\n', '')],
    'force-no-record-root': [(L, '        if (GovernanceLib.$().counts[GovernanceBits.RECORD].roots == 0) revert IRegulatedToken.OrderInactive(recordId);\n', '')],
    'force-zero-accepted': [(L, '        if (amount == 0) revert IRegulatedToken.AmountZero();\n', '')],
    'force-via-uamove': [(R, '        _poolMove(from, to, amount);', '        _uaMove(from, to, amount);')],
    'pause-cooldown-dropped': [(L, '        if (now_ < r.pauseCooldownUntil) revert IRegulatedToken.PauseCooldown(r.pauseCooldownUntil);\n', '')],
    'unwrap-paused': [(R, 'sel != SEL_UNWRAP_MIN && ', '')],
    'fee-bearing-open': [(R, '''        if (mode & MetaTxLib.MODE_FEE_MASK != MetaTxLib.MODE_FEE_NONE
            || (sel != SEL_UNWRAP_MIN''', '''        if (mode == type(uint32).max
            || (sel != SEL_UNWRAP_MIN''')],
    'paused-until-zero': [(R, 'revert TokenPaused(RegulatedLib.$().pausedUntil);', 'revert TokenPaused(0);')],
    'cancelnonce-no-regpre': [(U, '        _regPre(m.from, IMetaTx.cancelNonce.selector, m.mode);\n', '')],
    'revoke-needs-use-when-disabled': [(L, '''        if (r.controls & C_RECORD != 0) {
            GovernanceUse.use(GovernanceBits.RECORD, subject, 0);
        } else if''', '''        GovernanceUse.use(GovernanceBits.RECORD, subject, 0);
        if (false) {
        } else if''')],
    'init-skips-regulatedlib': [(R, '        RegulatedLib.init(initArgs, _validBits());\n', '')],
    'k8-init-not-composed': [(K8, '''    function _initRaw(bytes calldata initArgs) internal override(MetaTokenBase, RegulatedBase) {
        super._initRaw(initArgs);''', '''    function _initRaw(bytes calldata initArgs) internal override(MetaTokenBase, RegulatedBase) {
        MetaTokenBase._initRaw(initArgs);''')],
    'k8-regmove-unwired': [(K8, '        super._regMove(from, to, value);', '        ERC20MetaTx._regMove(from, to, value);')],
    'init-force-without-record': [(L, "        if ((f & (1 << GovernanceBits.FORCE) != 0 && !record) || (record && !freeze_)",
                                   "        if ((record && !freeze_)")],
    'deploy-k8-disabled': [(D, '        f.setKindEnabled(IOpenFactory.TokenKind.NORMAL_REGULATED, true);\n', '')],
}


def main():
    if sys.argv[1] == '--list':
        print('\n'.join(MUT))
        return
    for path, old, new in MUT[sys.argv[1]]:
        s = open(path).read()
        if s.count(old) != 1:
            sys.exit('%s: anchor found %d times in %s' % (sys.argv[1], s.count(old), path))
        open(path, 'w').write(s.replace(old, new))


if __name__ == '__main__':
    main()
