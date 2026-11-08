#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T2 (plan step 6): one mutant at a time on the T2 tree. `t2_mutants.py <name>` from smartcontracts/evm
applies one; `run_t2_mutants.sh` runs test/merge after each and restores `src` with `git checkout -- src`. `--list` prints
the names. A mutant whose anchor is not found exactly once fails (it would test nothing). The plan's six for T2, the
fee-before-call one on both seats it has (the relay router and receiver-pays)."""
import sys

PIPE = 'src/metatx/MtxPipelineLib.sol'
TOK = 'src/metatx/ERC20MetaTx.sol'
BASE = 'src/metatx/MetaTokenBase.sol'
ROUTER = 'src/metatx/MtxRelayFee.sol'
RELAY = ('        MtxRelayExecutor(EXECUTOR).exec(target, callData);\n'
         '        IERC20MetaTx(token).mtxRelayFee(from, target, keccak256(callData), payee, value, validUntil, auth);\n')
RF = ('        bytes32 d = _uaExecuteTransfer(t, 0, payerAuth);\n'
      '        MtxPipelineLib.authorize(_mtxCtx(), t.to, UAKinds.PURPOSE_RECEIVER_FEE,\n'
      '            receiverFeeDigest(t, fee, feeRecipient, rfValidUntil), payeeAuth);\n'
      '        _uaMove(t.to, to, fee);\n')
SETTLED = '        if (t.entryRef != 0) emit UAPaymentSettled(t.from, t.to, t.value, o.fee, o.feeTo, t.entryRef);\n'
MUT = {
    # `_checkTo` skipped on `mtxPay` (its typed path is the one `_checkTransfer`)
    'checkto-skipped-on-pay': (PIPE, '        _checkTo(registry, t.to);\n', ''),
    # invariant 5: the fee before the call (the router pays before the target runs)
    'relay-fee-before-call': (ROUTER, RELAY, RELAY.split('\n')[1] + '\n' + RELAY.split('\n')[0] + '\n'),
    # invariant 5 on receiver-pays: the payee's fee before the payer's payment it is paid out of
    'receiver-fee-before-payment': (BASE, RF, '        _uaMove(t.to, to, fee);\n' + '\n'.join(RF.split('\n')[:3]) + '\n'),
    'batch-transfer-length-check-dropped': (TOK, '        if (n != auths.length) revert MtxBatchLengthMismatch();\n', ''),
    # `relay` / `mtxRelayFee` reading `from` from calldata unsigned: the struct the payer signs no longer binds it
    'relay-from-unsigned': (BASE, 'abi.encode(UA_RELAY_FEE_TYPEHASH, from, target,', 'abi.encode(UA_RELAY_FEE_TYPEHASH, bytes32(0), target,'),
    # a native ledger move through the UA balances (`_uaBalance`): a native receiver credited in the UA ledger
    'native-credit-through-ua-ledger': (TOK, '        bool toUA = !UAKinds.inNativeSpace(to);\n', '        bool toUA = true;\n'),
    # R18: `PaymentSettled` emitted on a merged path
    'payment-settled-on-merged-path': (TOK, SETTLED, SETTLED + '        if (t.entryRef != 0 && UAKinds.inNativeSpace(t.from)) {\n'
        '            emit PaymentSettled(address(uint160(uint256(t.from))), address(uint160(uint256(t.to))), t.value, o.fee,\n'
        '                o.feeTo, t.entryRef);\n        }\n'),
}

if sys.argv[1] == '--list':
    print(' '.join(MUT))
    sys.exit(0)
path, a, b = MUT[sys.argv[1]]
s = open(path).read()
assert s.count(a) == 1, (sys.argv[1], s.count(a))
open(path, 'w').write(s.replace(a, b, 1))
