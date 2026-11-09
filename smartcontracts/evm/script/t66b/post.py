# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T66b task 4.1: the hand edits after `transform.py` (spec 2026-11-09-t66b-library-organisation.md §4.5, §4.6): the module
errors, `onlyDelegated` and the `_forward*` stubs' helpers in `MetaTokenBase`; `ITokenModule.sol` (the `implArgs` structs, the
module identity views); `pqzSet()` and the self-call interface of `PqzLayer`; the `burn` selector of the normal kinds (its
entry is the face's). One run, after transform.py, before gen_faces.py. usage (from smartcontracts/evm): python3
script/t66b/post.py   UNAUDITED tooling."""
import json


def edit(p, pairs):
    s = open(p).read()
    for a, b in pairs:
        assert s.count(a) == 1, (p, a)
        s = s.replace(a, b)
    open(p, 'w').write(s)


D = json.loads(open('script/t66b/post.json').read())
edit('src/metatx/MetaTokenBase.sol', [
    ('    error UnderlyingCountInvalid(uint256 n);\n', '    error UnderlyingCountInvalid(uint256 n);\n' + D['blk1']),
    ('    /// @dev One guard over every entry point (CTR-MTX-18)', D['blk2'] + '    /// @dev One guard over every entry point (CTR-MTX-18)')])
s = open('src/metatx/NormalTokenCore.sol').read().replace('this.burn.selector', 'BURN_SELECTOR')
s = s.replace('abstract contract NormalTokenCore is MetaTokenBase {', 'abstract contract NormalTokenCore is MetaTokenBase {\n'
              '    /// @dev `burn(uint256)`\'s selector: the entry is the face\'s (T66b), so the core names it by its signature.\n'
              '    bytes4 internal constant BURN_SELECTOR = bytes4(keccak256("burn(uint256)"));\n', 1)
open('src/metatx/NormalTokenCore.sol', 'w').write(s)
s = open('src/pqz/NormalPqzTokenCore.sol').read().replace('this.burn.selector', 'BURN_SELECTOR')
open('src/pqz/NormalPqzTokenCore.sol', 'w').write(s)
s = open('src/pqz/PqzLayer.sol').read()
s = s.replace('try this.disclosureStatement(', 'try IPqzDisclosureStatement(address(this)).disclosureStatement(')
s = s.replace('/// @title The PQZ layer', D['iface'] + '/// @title The PQZ layer', 1)
s = s.replace('abstract contract PqzLayer is MetaTokenBase {\n', 'abstract contract PqzLayer is MetaTokenBase {\n' + D['pqzset'], 1)
if 'import {PqzSet}' not in s:
    s = s.replace('import ', 'import {PqzSet} from "./PqzSet.sol";\nimport ', 1)
open('src/pqz/PqzLayer.sol', 'w').write(s)
open('src/metatx/ITokenModule.sol', 'w').write(D['itm'])
# P2-B: `IS_HEDERA` stays in the token (its body is `UAMetaTxBase`'s, a shared base's, so the kept view is written here)
edit('src/metatx/MetaTokenBase.sol', [('    function implementation() external view returns (address) { return _SELF; }\n',
    '    function implementation() external view returns (address) { return _SELF; }\n'
    '    function IS_HEDERA() external view returns (bool) { return _IS_HEDERABody(); }\n')])
print('post: done')
