# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T66b task 4.1, rule 4 (spec 2026-11-09-t66b-library-organisation.md §4.1 rule 4, §4.3): module T compiles `TradeLib`'s code
in. `TradeLib`'s public functions become thin wrappers of `internal` twins (`_<name>`), so the DEX's library calls and their ABI
are unchanged; the token's trade bodies (`ERC20MetaTx`) call the twins: one cold account less on a trade (no DELEGATECALL to
`TradeLib`), and `TradeLib` leaves the token kinds' link closure. One run on the tree after post.py (recipe: transform.py,
post.py, post2.py, gen_faces.py). usage (from smartcontracts/evm): python3 script/t66b/post2.py   UNAUDITED tooling."""
import re


def edit(p, pairs):
    s = open(p).read()
    for a, b in pairs:
        assert s.count(a) == 1, (p, a)
        s = s.replace(a, b)
    open(p, 'w').write(s)


# TradeLib: each public function `f` becomes `_f` (internal, same body) and a public `f` calling it
TL = 'src/trade/TradeLib.sol'
s = open(TL).read()
for name in ('cancelHash', 'precheck', 'record', 'restore', 'cancel', 'invalidate'):
    m = re.search(r'    function ' + name + r'\((?P<params>[^)]*)\)(?P<mods>[^{]*?)\{', s)
    assert m, name
    params, mods = m.group('params'), m.group('mods')
    rets = re.search(r'returns \(([^)]*)\)', mods)
    mods_int = mods.replace(' public', ' internal')
    names = ', '.join(p.split()[-1] for p in params.replace('\n', ' ').split(',') if p.strip())
    call = f'_{name}({names})'
    wrap = f'    function {name}({params}){mods}{{\n        {"return " if rets else ""}{call};\n    }}\n\n'
    doc = f'    /// @dev The body of `{name}` (T66b rule 4): a token\'s module T compiles it in; `{name}` is the DEX\'s library call.\n'
    s = s[:m.start()] + wrap + doc + f'    function _{name}({params}){mods_int}{{' + s[m.end():]
open(TL, 'w').write(s)

edit('src/metatx/ERC20MetaTx.sol', [
    ('TradeLib.cancelHash(o)', 'TradeLib._cancelHash(o)'),
    ('        TradeLib.precheck(c, f, h, msg.sender, address(this));', '        TradeLib._precheck(c, f, h, msg.sender, address(this));'),
    ('TradeLib.record(c, f, h, true)', 'TradeLib._record(c, f, h, true)'),
    ('        TradeLib.restore(o, _tradeOrderDigestBody(o), amount, msg.sender);',
     '        TradeLib._restore(o, _tradeOrderDigestBody(o), amount, msg.sender);'),
    ('        TradeLib.cancel(_tradeOrderDigestBody(o), o.amount, o.from, true);',
     '        TradeLib._cancel(_tradeOrderDigestBody(o), o.amount, o.from, true);'),
    ('        TradeLib.invalidate(from, batch, newMin, true);', '        TradeLib._invalidate(from, batch, newMin, true);'),
])
print('post2: done')
