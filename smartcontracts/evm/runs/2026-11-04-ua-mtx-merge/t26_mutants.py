#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T26 (plan step 5): one mutant at a time on the T26 tree. `t26_mutants.py <name>` from smartcontracts/evm
applies one (every edit's anchor must be found exactly once); `run_t26_mutants.sh` runs `test/governance/PlusZero.t.sol`
(the "+0" slot and gas pins, `test_hookSeatsCalled*`) after each and restores `src` with `git checkout -- src`. `--list`
prints the names. The plan's (the sender computed at the Zether call site; a `features` read in the base `_regMove`; a seat
dropped: `mtxCancelNonce`, `mtxWrapOrder`, the `COMPACT` multi entry), then the other seats and conditions one at a time."""
import sys

U = 'src/metatx/UAMetaTxBase.sol'
E = 'src/metatx/ERC20MetaTx.sol'
M = 'src/metatx/MetaTokenBase.sol'
W = 'src/metatx/WrappedToken.sol'
Z = 'src/zether/ZetherLayer.sol'
P = 'src/pqz/PqzLayer.sol'
COMPACT = ('''        _regZetherSender(t.yFrom);
        _regName(t.beneficiaryUA);
        return _multi(t.beneficiaryUA, ZetherTypes.TransferMode.HASH);''',
           '''        return _multi(t.beneficiaryUA, ZetherTypes.TransferMode.HASH);''')
MUT = {
    # the plan's: `uaOf` evaluated at the Zether call site (the base computes the sender, the layer hook bypassed)
    'uaof-at-zether-site': [(Z, '''        _regZetherSender(t.yFrom);
        _regName(t.beneficiaryUA);
        return _multi(t.beneficiaryUA, ZetherLib.defaultMode());''', '''        _regSender(ZetherTypes.UA.unwrap(ZetherLib.uaOf(t.yFrom)));
        _regName(t.beneficiaryUA);
        return _multi(t.beneficiaryUA, ZetherLib.defaultMode());''')],
    # the plan's: a `features` read in the base `_regMove`
    'features-read-in-base-regmove': [
        (E, 'import {MtxPipelineLib} from "./MtxPipelineLib.sol";\n',
            'import {MtxPipelineLib} from "./MtxPipelineLib.sol";\nimport {GovernanceLib} from "../governance/GovernanceLib.sol";\n'),
        (E, 'function _regMove(bytes32 /* from */, bytes32 /* to */, uint256 /* value */) internal view virtual {}',
            'function _regMove(bytes32 /* from */, bytes32 /* to */, uint256 /* value */) internal view virtual {\n'
            '        if (GovernanceLib.hasFeature(5)) revert();\n    }')],
    # the plan's: a seat dropped
    'seat-dropped-cancelnonce-pre': [(U, '        _regPre(m.from, IMetaTx.cancelNonce.selector, m.mode);\n', '')],
    'seat-dropped-cancelnonce-fee': [(U, '''            FEE_CLASS_ABSOLUTE, 0, 36, 0, true, supportedModes()), auth);
        _regFeeTo(MetaTxLib.pad(o.feeTo), o.fee);
''', '''            FEE_CLASS_ABSOLUTE, 0, 36, 0, true, supportedModes()), auth);
''')],
    'seat-dropped-wraporder-sender': [(W, '        if (o.destination != 0 && o.destination != o.from) _regSender(o.from);\n', '')],
    'seat-dropped-wraporder-fee': [(W, '        _regFeeTo(MetaTxLib.pad(msg.sender), fee);\n', '')],
    'seat-dropped-compact-multi': [(Z, *COMPACT)],
    # the other seats, one at a time
    'regmove-dropped-update': [(E, '        _regMove(f, MetaTxLib.pad(to), value);\n', '')],
    'regmove-update-pool-not-resolved': [(E, '            f = ua;\n', '')],
    'regmove-dropped-uamove': [(E, '        _regMove(from, to, value);\n        _poolMove(from, to, value);',
        '        _poolMove(from, to, value);')],
    'regpayer-dropped-approve': [(E, '        _regPayer();\n        return super.approve(spender, value);',
        '        return super.approve(spender, value);')],
    'regpre-after-pipeline-typed': [(E, '''        _regPre(t.from, 0, t.mode);
        MtxPipelineLib.Out memory o = MtxPipelineLib.preTransferUA(_mtxCtx(), t, signed, balanceOfUA(t.from), auth); // 1-4
''', '''        MtxPipelineLib.Out memory o = MtxPipelineLib.preTransferUA(_mtxCtx(), t, signed, balanceOfUA(t.from), auth); // 1-4
        _regPre(t.from, 0, t.mode);
''')],
    'regpre-outer-selector-named-ua': [(U, '        _regPre(m.from, bytes4(data), m.mode);\n', '        _regPre(m.from, msg.sig, m.mode);\n')],
    'regfee-dropped-paywithfee': [(M, '''        _regFeeTo(MetaTxLib.pad(feeRecipient), feeAmount);
        if (feeAmount != 0) {''', '''        if (feeAmount != 0) {''')],
    'regfee-dropped-relayfee': [(M, '        _regFeeTo(payee, value);\n', '')],
    'regfee-dropped-uasettle': [(U, '''        _regFeeTo(MetaTxLib.pad(o.feeTo), o.fee);
        ret = _selfCall(m.from''', '''        ret = _selfCall(m.from''')],
    'wrap-payer-unconditional': [(W, '        if (to != 0) _regPayer();\n', '        _regPayer();\n')],
    'zether-receiver-unconditional': [(Z, '        if (amount != 0) _regReceiver(recipient);\n        _requireRecipient(recipient);',
        '        _regReceiver(recipient);\n        _requireRecipient(recipient);')],
    'pqz-shieldin-payer-dropped-burn': [(P, '''        if (b.shieldIn != 0) _regPayer();
        _regName(b.beneficiaryUA);''', '''        _regName(b.beneficiaryUA);''')],
    'pqz-refresh-sender-checked': [(P, '        if (e.amount != 0) _regSender(b.fromUA);', '        _regSender(b.fromUA);')],
}

if sys.argv[1] == '--list':
    print(' '.join(MUT))
    sys.exit(0)
for path, a, b in MUT[sys.argv[1]]:
    s = open(path).read()
    assert s.count(a) == 1, (sys.argv[1], path, s.count(a))
    open(path, 'w').write(s.replace(a, b, 1))
