#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T36 (regulated-kinds spec §8, §9): one mutant at a time. `mutants.py <name>` from smartcontracts/evm applies
one (every edit's anchor found exactly once, and the edit must change the file); `--list` prints the names. Two groups:

* `t36-*`: the spec §9 rows T24-T35 did not kill (the hook body in the base, relax without delay at the library, the mirror
  of the composed `disableFeature` on 10-13, a pool accepted by `recordOrder`, roll-over paused on Zether and on PQZ,
  `_poolMove` calling `_update` unqualified), and the mutants that aim at one invariant each (I2, I4, I7, I12).
* `port-*`: the earlier tasks' mutants whose anchor (or killing test) a later task moved (T27, T28, T29), with today's anchor; the earlier
  harness reports them `99` (anchor missing) on its re-run.

`run_mutants.sh` runs each against the regulated suites and the invariant suite and restores `src`, `script` with git."""
import sys

L = 'src/regulated/RegulatedLib.sol'
R = 'src/regulated/RegulatedBase.sol'
G = 'src/governance/GovernanceLib.sol'
E = 'src/metatx/ERC20MetaTx.sol'
K10 = 'src/regulated/NormalZetherRegulatedToken.sol'
K11 = 'src/regulated/WrappedZetherRegulatedToken.sol'
K12 = 'src/regulated/NormalPqzRegulatedToken.sol'
K13 = 'src/regulated/WrappedPqzRegulatedToken.sol'
ZL = 'src/zether/ZetherLayer.sol'
PL = 'src/pqz/PqzLayer.sol'
D = 'script/DeployBase.sol'

NORMAL_DISABLE = '        if (GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits())) _regDisabled(bit);'
WRAPPED_DISABLE = '''        if (bit == GovernanceBits.RATE_ADJUSTABLE) WrappedLib.dropPending();
        _regDisabled(bit);'''
REG_SLOT = '0xb2c09f76d73c73fd19cb676c5bc2ea2b05d0674d12ed1b6dc6508457a3913d00'

MUT = {
    # ------------------------------------------------------------------ spec §9 rows not killed in T24-T35
    # +0: the hook body moved into the base: the plain kinds' `_regMove` reads the regulated hot slot (F's first read)
    't36-plus0-hook-body-in-base': [(E,
        '    function _regMove(bytes32 /* from */, bytes32 /* to */, uint256 /* value */) internal view virtual {}',
        '    function _regMove(bytes32 from, bytes32, uint256) internal view virtual {\n'
        '        uint256 c;\n'
        '        assembly ("memory-safe") { c := sload(' + REG_SLOT + ') }\n'
        '        if ((c >> 160) & 1 != 0 && from == bytes32(uint256(1))) revert();\n'
        '    }')],
    # FREEZE: relax without delay, at the library (T27 killed the mask at 0 in the token)
    't36-relax-delayed-false': [(G, '        return delayedRelax & _bit(bit) != 0 && s.grantDelay != 0;',
                                 '        return false && delayedRelax & _bit(bit) != 0 && s.grantDelay != 0;')],
    # Relaxation: the mirror not cleared by a confidential kind's composed `disableFeature` (T28 killed kind 9's)
    't36-k10-disable-not-composed': [(K10, NORMAL_DISABLE,
                                      '        GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits());')],
    't36-k11-disable-not-composed': [(K11, WRAPPED_DISABLE,
                                      '        if (bit == GovernanceBits.RATE_ADJUSTABLE) WrappedLib.dropPending();')],
    't36-k12-disable-not-composed': [(K12, NORMAL_DISABLE,
                                      '        GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits());')],
    't36-k13-disable-not-composed': [(K13, WRAPPED_DISABLE,
                                      '        if (bit == GovernanceBits.RATE_ADJUSTABLE) WrappedLib.dropPending();')],
    # FORCE: a pool or the token accepted (as the record's beneficiary, as its subject)
    't36-record-beneficiary-pool-accepted': [(L,
        '        if (beneficiary == 0 || beneficiary == recordSubject || _pool(beneficiary)) {',
        '        if (beneficiary == 0 || beneficiary == recordSubject) {')],
    't36-record-subject-pool-accepted': [(L,
        '        if (recordSubject == 0 || _pool(recordSubject)) revert',
        '        if (recordSubject == 0) revert')],
    # PAUSE: roll-over paused (Zether ≠ PQZ: one each)
    't36-zether-rollover-paused': [(ZL, '''        if (n == 0) revert RollOverRange(n);
        ZetherLib.rollOver(ZetherTypes.UA.wrap(ua));''', '''        if (n == 0) revert RollOverRange(n);
        _regSender(bytes32(0));
        ZetherLib.rollOver(ZetherTypes.UA.wrap(ua));''')],
    't36-pqz-rollover-paused': [(PL, '        PqzStateLib.rollOver(ua, n);',
                                 '        _regSender(bytes32(0));\n        PqzStateLib.rollOver(ua, n);')],
    # Ledger: `_poolMove` calls `_update` unqualified (I9 catches it)
    't36-poolmove-update-unqualified': [(E, '            ERC20._update(fromUA ? MetaTxLib.UA_POOL',
                                         '            _update(fromUA ? MetaTxLib.UA_POOL')],
    # ------------------------------------------------------------------ one invariant each
    't36-pause-span-8d': [(L, '    uint64 internal constant PAUSE_SPAN = 7 days;', '    uint64 internal constant PAUSE_SPAN = 8 days;')],  # I4
    't36-unpause-no-cooldown': [(L, '        (r.pausedUntil, r.pauseCooldownUntil) = (now_, now_ + PAUSE_SPAN);',
                                 '        (r.pausedUntil, r.pauseCooldownUntil) = (now_, now_);')],  # I4
    't36-t1-cooldown-unchecked': [(L,
        '                if (now_ < s.issuerCooldownUntil) revert IRegulatedToken.FreezeCooldown(s.issuerCooldownUntil);\n',
        '')],  # I7
    't36-episode-span-61d': [(L, '    uint64 internal constant EPISODE_SPAN = 60 days;',
                              '    uint64 internal constant EPISODE_SPAN = 61 days;')],  # I7
    't36-force-subject-not-frozen-passes': [(L, '        if (!frozen(from)) revert IRegulatedToken.SubjectNotFrozen(from);\n',
                                             '')],  # I2
    't36-mirror-wrong-bit': [(R, '            RegulatedLib.$().controls &= ~uint8(1 << (bit - GovernanceBits.FREEZE));',
                              '            RegulatedLib.$().controls &= ~uint8(1 << (bit - GovernanceBits.FREEZE + 1));')],  # I12
    # ------------------------------------------------------------------ earlier mutants, anchors moved by a later task
    # T27, T28 `init-skips-regulatedlib`: T29 gave `RegulatedLib.init` the registry code hash
    'port-t27-t28-init-skips-regulatedlib': [(R, '        RegulatedLib.init(initArgs, _validBits(), REGISTRY_CODEHASH);\n', '')],
    # T27 `view-isfrozen-false`: T28 moved `F` into `RegulatedLib.frozen`
    'port-t27-view-isfrozen-false': [(R, 'returns (bool) { return RegulatedLib.frozen(account); }',
                                      'returns (bool) { account; return false; }')],
    # T27 `deploy-regulated-without-lib`: T28-T33 rewrote the kind 8 env (five libraries)
    'port-t27-deploy-regulated-without-lib': [(D, '''        address[] memory libs = new address[](5);
        (libs[0], libs[1], libs[2], libs[3], libs[4]) =
            (address(GovernanceLib), address(HederaLib), address(TradeLib), address(MtxPipelineLib), address(RegulatedLib));
        f.publishEnv(IOpenFactory.TokenKind.NORMAL_REGULATED, 1,''', '''        address[] memory libs = new address[](4);
        (libs[0], libs[1], libs[2], libs[3]) =
            (address(GovernanceLib), address(HederaLib), address(TradeLib), address(MtxPipelineLib));
        f.publishEnv(IOpenFactory.TokenKind.NORMAL_REGULATED, 1,''')],
    # T28 `force-zero-accepted`: T32's `operatorTransfer` has the same refusal line
    'port-t28-force-zero-accepted': [(L, '''        if (GovernanceLib.$().counts[GovernanceBits.RECORD].roots == 0) revert IRegulatedToken.OrderInactive(recordId);
        if (amount == 0) revert IRegulatedToken.AmountZero();
''', '''        if (GovernanceLib.$().counts[GovernanceBits.RECORD].roots == 0) revert IRegulatedToken.OrderInactive(recordId);
''')],
    # T29 `deploy-implargs-empty`: T30 added the Zether releases' line; kinds 8, 9 here
    'port-t29-deploy-implargs-empty': [(D, '''        bytes memory implArgs = abi.encode(_registryCodehash());
        address n = _release(f, IOpenFactory.TokenKind.NORMAL_REGULATED,''', '''        bytes memory implArgs = "";
        address n = _release(f, IOpenFactory.TokenKind.NORMAL_REGULATED,''')],
    # T27 `stub-freeze-skips-lib`: the anchor stands, but T28 built `freeze` and moved its tests out of T27's skeleton suite
    # (`test_stubsAndViewsNotBuilt`), so T27's own re-run lets it live; here against the suites that test `freeze` today
    'port-t27-stub-freeze-skips-lib': [(R, '        RegulatedLib.freeze(account, ref, recordId, _govSubject());\n', '')],
}


def main():
    if sys.argv[1] == '--list':
        print('\n'.join(MUT))
        return
    for path, old, new in MUT[sys.argv[1]]:
        s = open(path).read()
        if s.count(old) != 1:
            sys.exit('%s: anchor found %d times in %s' % (sys.argv[1], s.count(old), path))
        t = s.replace(old, new)
        if t == s:
            sys.exit('%s: the edit changes nothing in %s' % (sys.argv[1], path))
        open(path, 'w').write(t)


if __name__ == '__main__':
    main()
