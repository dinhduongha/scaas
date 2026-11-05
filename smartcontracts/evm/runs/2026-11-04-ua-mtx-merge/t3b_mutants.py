#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T3b (plan step 6): one mutant at a time on the T3b tree. `t3b_mutants.py <name>` from smartcontracts/evm
applies one (every edit's anchor must be found exactly once); `run_t3b_mutants.sh` runs test/wallet and test/merge after
each and restores `src` with `git checkout -- src`. `--list` prints the names. The plan's eleven, in its order."""
import sys

LIB = 'src/metatx/MtxPipelineLib.sol'
W = 'src/wallet/MandateWallet.sol'
MUT = {
    # invariant 1 / B: a native subject sent to the registry when one is set (`expectCall(reg, "", 0)` red)
    'native-to-registry': [(LIB,
        '        if (!UAKinds.inNativeSpace(from)) {\n            if (c.registry == address(0)) revert IUALedger.UALedgerOff();\n',
        '        if (!UAKinds.inNativeSpace(from) || c.registry != address(0)) {\n'
        '            if (c.registry == address(0)) revert IUALedger.UALedgerOff();\n')],
    # the derived branch's `requireAuthorized` skipped (the forgery check red)
    'derived-requireAuthorized-skipped': [(LIB,
        '            return IUARegistry(c.registry).requireAuthorized(from, purpose, digest, auth);\n',
        '            return;\n')],
    # R17 dropped: a native `UASig` with `keyData` / `members` accepted
    'r17-dropped': [(LIB,
        '        if (auth.keyData.length != 0 || auth.members.length != 0) revert IMetaTx.MetaTxBadSignature();\n', '')],
    # the wallet claims the fee modes and `_uaChargeFee` accepts a fee (fee mode NONE only on the wallets)
    'fee-accepted': [(W,
        '    // ------------------------------------------------------------------ internals\n',
        '    function supportedModes() public pure override returns (uint32) { return 0xF3; }\n'
        '    function _uaChargeFee(MetaTxLib.UAMetaTransaction memory, address, uint256) internal override {}\n\n'
        '    // ------------------------------------------------------------------ internals\n')],
    # the cancel's nonce check skipped (the envelope's nonce check, which the ordered cancel runs through)
    'cancel-nonce-check-skipped': [(LIB,
        '        if (expected != nonce) revert IMetaTx.MetaTxBadNonce(expected, nonce);\n', '')],
    # `payee` left out of `UAPayUnderMandate`'s hash (the call still carries it)
    'payee-out-of-hash': [(W,
        '        return _namedUA(_UA_PAY_UNDER_MANDATE_TYPEHASH, MandateWallet.payUnderMandate.selector, e,\n'
        '            abi.encode(token, payee, amount, entryRef, epoch_), auth);\n',
        '        return _namedCallUA(_UA_PAY_UNDER_MANDATE_TYPEHASH, e, abi.encode(token, bytes32(0), amount, entryRef, epoch_),\n'
        '            abi.encodeWithSelector(MandateWallet.payUnderMandate.selector, token, payee, amount, entryRef, epoch_), auth);\n')],
    # `target` left out of `UAExecute`'s hash
    'target-out-of-hash': [(W,
        '        return _namedCallUA(_UA_EXECUTE_TYPEHASH, e, abi.encode(target, value, keccak256(data)),\n',
        '        return _namedCallUA(_UA_EXECUTE_TYPEHASH, e, abi.encode(address(0), value, keccak256(data)),\n')],
    # `_msgSender()` read for the delegate check of `payUnderMandate` instead of `_subject()`
    'delegate-by-msgsender': [(W,
        '        if (_subject() != md.delegate) revert NotDelegate();\n'
        '        if (epoch_ != epoch[token]) revert StaleEpoch(epoch[token], epoch_);\n'
        '        if (block.timestamp > md.expiry) revert MandateExpired();\n',
        '        if (MetaTxLib.pad(_msgSender()) != md.delegate) revert NotDelegate();\n'
        '        if (epoch_ != epoch[token]) revert StaleEpoch(epoch[token], epoch_);\n'
        '        if (block.timestamp > md.expiry) revert MandateExpired();\n')],
    # the derived owner answered by `isValidSignature` (ECDSA by its low 160 bits)
    'derived-owner-answered': [(W,
        '        if (!UAKinds.inNativeSpace(owner)) return bytes4(0xffffffff);\n', '')],
    # `executeMetaTransaction` left open: the `_execute` override gone (MD-11 (b))
    'execute-meta-transaction-open': [(W,
        '    /// @dev `executeMetaTransaction` refuses every call (MD-11 (b)): the EIP-1776 alias is the token\'s exception (R3).\n'
        '    function _execute(MetaTxLib.MetaTransaction memory m, bytes calldata) internal pure override returns (bytes memory) {\n'
        '        revert MtxSelectorNotAllowed(bytes4(m.data));\n'
        '    }\n\n', '')],
    # HIP-632 accepted for an account with code (the UA path's native branch)
    'hip632-for-code': [(LIB,
        '        if (c.hedera && auth.length == 64 && !SigCheck.isContract(a)) return HederaLib.requireValid(a, digest, auth);\n',
        '        if (c.hedera && auth.length == 64) return HederaLib.requireValid(a, digest, auth);\n')],
}

if sys.argv[1] == '--list':
    print(' '.join(MUT))
    sys.exit(0)
for path, a, b in MUT[sys.argv[1]]:
    s = open(path).read()
    assert s.count(a) == 1, (sys.argv[1], path, s.count(a))
    open(path, 'w').write(s.replace(a, b, 1))
