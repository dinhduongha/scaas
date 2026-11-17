#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Lever D of the ua*/mtx* merge spec §4 (lever 3 of docs/research/evm-size-levers.md), by deletion, T0 scratch: the
read-only views leave the token and a `fallback` takes them, the module not written (plan T0 step 4, as the spike).
Ported from the spike's merge-harness/lever3_delete.py to today's names: the digest twins are merged, the two
`envelopeBinding` views are one. Kept on the token, by spec §4: `hasRole`, `pendingOwner`, and every view another
contract reads on chain (`factory` (`OpenFactory._checkImplementation`), `underlyings`, `registry`, `tradeOrderDigest`, and on the Zether kinds `verifier`,
`confidentialFee`, `minDecoyFee`, `auditorMode`, `disclosureMode`, `maxDecryptableShielded`, `auditorKey`,
`accountState`, `transferEntry`: `ZetherStatements`, `ZetherDisclosure`, `SCaaSDex`, `OpenFactory` read them).
The fallback is invariant 7's shape: an outside call re-enters the token by STATICCALL, and only that static frame
DELEGATECALLs the module. Run once from smartcontracts/evm on M or M + L; prints the count, fails on a view not found.
"""
import re

VIEWS = {
    'src/metatx/ERC20MetaTx.sol': ['mtxTransferDigest', 'mtxDigest'],
    'src/metatx/IUALedger.sol': ['mtxDigest', 'mtxTransferDigest'],
    'src/metatx/UAMetaTxBase.sol': ['mtxDigest'],
    'src/metatx/MetaTokenBase.sol': ['implementation', 'creator', 'version'],
    'src/metatx/WrappedToken.sol': ['underlying', 'legOf', 'collateralValue', 'previewWrap', 'previewUnwrap',
                                    'rateAdjustable', 'rateDelay', 'maxRateStepBps', 'pendingRate', 'mtxSelectors'],
    'src/metatx/IWrappedToken.sol': ['underlying', 'legOf', 'collateralValue', 'previewWrap', 'previewUnwrap',
                                     'rateAdjustable', 'rateDelay', 'maxRateStepBps', 'pendingRate'],
    'src/metatx/NormalToken.sol': ['mtxSelectors'],
    'src/pqz/PqzLayer.sol': ['verifier', 'precompile', 'proofSystemId', 'maxShielded', 'confidentialFee', 'minDecoyFee',
                             'auditorUA', 'auditorMode', 'disclosureMode', 'totalShielded', 'pqzAccount', 'pqzPending',
                             'pqzAcc', 'pqzPendingCt', 'pqzEntryBlob', 'transferCiphertextHash', 'transferEntry',
                             'transferStatement', 'transferSingleStatement', 'burnStatement', 'disclosureStatement',
                             'verifyTransferAmount', 'envelopeBinding'],
    'src/pqz/IPqzToken.sol': ['pqzAccount', 'pqzPending', 'pqzAcc', 'pqzPendingCt', 'pqzEntryBlob'],
    'src/pqz/WrappedPqzToken.sol': ['unshieldUnwrapStatement', 'mtxSelectors'],
    'src/pqz/NormalPqzToken.sol': ['mtxSelectors'],
    'src/zether/ZetherLayer.sol': ['curve', 'totalShielded', 'transferMemo', 'sendCounter', 'registered',
                                   'envelopeBinding'],
    'src/zether/IZetherToken.sol': ['curve', 'totalShielded', 'transferMemo', 'sendCounter', 'registered',
                                    'envelopeBinding'],
    'src/zether/WrappedZetherToken.sol': ['mtxSelectors'],
    'src/zether/NormalZetherToken.sol': ['mtxSelectors'],
}

FALLBACK = '''
    /// @dev T0 lever D (by deletion, no module built): the release's view module; a real one is pinned in `env.deps`.
    address internal immutable _VIEWS = address(0x10);

    /// @dev Invariant 7's shape: an outside call re-enters this contract by STATICCALL; only that static frame
    ///      DELEGATECALLs the module, which can then read the token's storage and can write, log or call nowhere.
    fallback() external {
        address m = _VIEWS;
        assembly ("memory-safe") {
            calldatacopy(0, 0, calldatasize())
            let ok
            switch eq(caller(), address())
            case 1 { ok := delegatecall(gas(), m, 0, calldatasize(), 0, 0) }
            default { ok := staticcall(gas(), address(), 0, calldatasize(), 0, 0) }
            returndatacopy(0, 0, returndatasize())
            if iszero(ok) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }
'''


def delete_fn(path, name):
    """Delete every function `name`, its doc comment and its body (or `;` in an interface)."""
    s = open(path).read()
    hit = 0
    while True:
        m = re.search(r'^[ \t]*function ' + name + r'\(', s, re.M)
        if not m:
            break
        lines = s[:m.start()].split('\n')
        while len(lines) > 1 and lines[-2].lstrip().startswith('///'):
            lines.pop(-2)
        start = len('\n'.join(lines))
        j = m.end()
        while s[j] not in '{;':
            j += 1
        if s[j] == ';':
            end = j + 1
        else:
            depth = 0
            while True:
                depth += {'{': 1, '}': -1}.get(s[j], 0)
                j += 1
                if depth == 0:
                    break
            end = j
        s = s[:start] + s[end + (s[end:end + 1] == '\n'):]
        hit += 1
    open(path, 'w').write(s)
    return hit


def main():
    names = {n for ns in VIEWS.values() for n in ns}
    for p, ns in VIEWS.items():
        for n in ns:
            assert delete_fn(p, n), (p, n)
    p = 'src/metatx/MetaTokenBase.sol'
    s = open(p).read()
    head = 'abstract contract MetaTokenBase is ERC20MetaTx, IMetaTokenV2, IFactoryToken, IERC165, GovernanceBase, IRescuable {\n'
    assert head in s
    open(p, 'w').write(s.replace(head, head + FALLBACK))
    # the one test helper the T0 runs compile that reads a moved view: through a low-level read (D runs: the module is
    # not built, so it is never called there)
    f = 'test/zether/helpers/ZetherFixture.sol'
    s = open(f).read()
    a = 't.totalShielded()'
    assert s.count(a) == 2, s.count(a)
    s = s.replace(a, '_totalShieldedOf(address(t))')
    a = '    function _assertConservation(ZetherLayer t, uint256 max) internal view virtual {\n'
    assert a in s
    s = s.replace(a, '''    function _totalShieldedOf(address t) internal view returns (uint256) {
        (, bytes memory r) = t.staticcall(abi.encodeWithSignature("totalShielded()"));
        return abi.decode(r, (uint256));
    }

''' + a)
    open(f, 'w').write(s)
    print(len(names), 'view names deleted (the merged digest pair counts once per name);', f, 'reads totalShielded low-level')


if __name__ == '__main__':
    main()
