#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Lever L of the ua*/mtx* merge spec §4, T0 scratch: the token's signed bodies into `TokenBodyLib` on the `ZetherLib`
pattern (CTR-ZTH-94). Writes src/metatx/TokenBodyLib.sol from TokenBodyLib.sol.txt (beside this script) and rewrites each
moved entry's body on the token to a forward of its own calldata plus the move the token keeps. The entries' ABI and
calldata decoders stay on the token. Run once from smartcontracts/evm on M (or M + D); prints each body it rewrote and
fails on a pattern that matches nothing. Not moved, with reason: `mtxBatchTransfer` (each item's balance check reads the
moves of the item before), the generic and named UA entries (`_uaExecute`, `_namedCallUA`: their facts come from the
kind's virtual hooks), `mtxCancelNonce` (shared with the router).
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from merge_router import block  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
MTB = 'src/metatx/MetaTokenBase.sol'
E20 = 'src/metatx/ERC20MetaTx.sol'

FWD = '        _applyTransfer(_body(TokenBodyLib.{sel}.selector, true));\n        return true;\n'
BODIES = {
    MTB: {
        'mtxTransfer(': FWD.format(sel='transfer'),
        'mtxTransferWithFee(': FWD.format(sel='transferWithFee'),
        'mtxPay(': FWD.format(sel='pay'),
        'mtxPayMeta(': FWD.format(sel='payMeta'),
        'mtxPayReceiverFee(': '''        bytes32 d = _applyTransfer(_body(TokenBodyLib.payReceiverFee.selector, true));
        _uaMove(t.to, MetaTxLib.pad(feeRecipient), fee);
        emit UAReceiverFeePaid(d, t.to, feeRecipient, fee);
        return true;
''',
        'mtxRelayFee(': '        _applyTransfer(_body(TokenBodyLib.relayFee.selector, true));\n',
    },
    E20: {
        'mtxExecuteTransfer(': FWD.format(sel='executeTransfer'),
        'mtxTrade(': '''        (bytes32 from, bytes32 dex, uint256 amount) =
            abi.decode(_body(TokenBodyLib.trade.selector, false), (bytes32, bytes32, uint256));
        _uaMove(from, dex, amount);
''',
        'mtxCancelOrder(': '        _body(TokenBodyLib.cancelOrder.selector, false);\n',
        'mtxInvalidateNonces(': '        _body(TokenBodyLib.invalidateNonces.selector, false);\n',
    },
}

HELPERS = '''
    // ------------------------------------------------------------------ lever L (T0 scratch): the bodies in TokenBodyLib

    /// @dev Forward this call's calldata to `TokenBodyLib` under `sel` with the tail `abi.encode(Ctx, have)` (`have`: the
    ///      first argument's balance, the payer's), as `ZetherLayer._lib`; the library's return data, or its revert.
    function _body(bytes4 sel, bool withHave) internal returns (bytes memory r) {
        bytes memory tail = abi.encode(_mtxCtx(), withHave ? balanceOfUA(bytes32(msg.data[4:36])) : 0);
        address lib = address(TokenBodyLib);
        assembly ("memory-safe") {
            let p := mload(0x40)
            let n := calldatasize()
            mstore(p, sel)
            calldatacopy(add(p, 4), 4, sub(n, 4))
            let t := mload(tail)
            mcopy(add(p, n), add(tail, 32), t)
            let ok := delegatecall(gas(), lib, p, add(n, t), 0, 0)
            r := p
            mstore(r, returndatasize())
            returndatacopy(add(r, 32), 0, returndatasize())
            mstore(0x40, add(add(r, 32), and(add(returndatasize(), 31), not(31))))
            if iszero(ok) { revert(add(r, 32), returndatasize()) }
        }
    }

    /// @dev The moves and events of a typed transfer the library checked (steps 5-6 of `_uaExecuteTransfer`).
    function _applyTransfer(bytes memory r) internal returns (bytes32) {
        (MtxPipelineLib.Out memory o, MetaTxLib.UAMetaTransfer memory t) =
            abi.decode(r, (MtxPipelineLib.Out, MetaTxLib.UAMetaTransfer));
        if (o.fee != 0) _uaMove(t.from, MetaTxLib.pad(o.feeTo), o.fee);
        _uaMove(t.from, t.to, t.value);
        if (t.entryRef != 0) emit UAPaymentSettled(t.from, t.to, t.value, o.fee, o.feeTo, t.entryRef);
        emit UAMetaTransactionExecuted(t.from, msg.sender, t.batch, t.nonce, o.digest, o.feeTo, o.fee);
        return o.digest;
    }
'''


def rebody(s, head, body):
    m = re.search(r'^[ \t]*function ' + re.escape(head), s, re.M)
    assert m, head
    a, b = block(s, m)
    j = s.index('{', m.end())
    # the body's opening brace: the first `{` after the closing `)` of the header that ends a line
    while not s[j + 1:j + 2] == '\n':
        j = s.index('{', j + 1)
    end = s.rindex('}', a, b)
    return s[:j + 2] + body + '    ' + s[end:]


def main():
    open('src/metatx/TokenBodyLib.sol', 'w').write(open(os.path.join(HERE, 'TokenBodyLib.sol.txt')).read())
    for p, bodies in BODIES.items():
        s = open(p).read()
        for head, body in bodies.items():
            s = rebody(s, head, body)
            print(p, 'body forwarded:', head)
        if p == E20:
            anchor = '    // ------------------------------------------------------------------ allowance (CTR-TOK-01)'
            assert anchor in s
            s = s.replace(anchor, HELPERS.lstrip('\n') + '\n' + anchor)
            s = s.replace('import {MtxPipelineLib} from "./MtxPipelineLib.sol";\n',
                          'import {MtxPipelineLib} from "./MtxPipelineLib.sol";\nimport {TokenBodyLib} from "./TokenBodyLib.sol";\n')
        else:
            s = s.replace('import {MtxPipelineLib} from "./MtxPipelineLib.sol";\n',
                          'import {MtxPipelineLib} from "./MtxPipelineLib.sol";\nimport {TokenBodyLib} from "./TokenBodyLib.sol";\n')
        open(p, 'w').write(s)
    c = 'test/helpers/Catalogue.sol'
    s = open(c).read()
    a = 'l = new address[](4 + (und ? 1 : 0)'
    assert a in s
    s = s.replace(a, 'l = new address[](5 + (und ? 1 : 0)')
    a = '    uint256 n = 4;\n'
    assert a in s
    s = s.replace(a, '    l[4] = address(TokenBodyLib);\n    uint256 n = 5;\n')
    s = s.replace('import {MtxPipelineLib}', 'import {TokenBodyLib} from "../../src/metatx/TokenBodyLib.sol";\nimport {MtxPipelineLib}', 1)
    open(c, 'w').write(s)
    print(c, 'closure + TokenBodyLib')


if __name__ == '__main__':
    main()
