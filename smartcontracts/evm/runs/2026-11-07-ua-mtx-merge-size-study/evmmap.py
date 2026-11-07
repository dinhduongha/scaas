#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Byte attribution of solc runtime code: per source function (source map) and per entry-point closure (a static CFG).

Library used by size_map.py and the spike tables. Two views, because each hides something:
- source map: an instruction is charged to the innermost function, modifier or Yul utility of its source location. Blocks the
  optimizer merged are charged to one user only.
- closure: blocks reachable from a selector's dispatch target, following every PUSH2 of a JUMPDEST and the fall-through. A block
  reachable from entries of one group only is what removing the group frees, before re-optimisation (an upper bound on a move
  to a library, the stub stays). A constant that happens to equal a JUMPDEST only adds an edge, so "exclusive" errs low.
"""
import bisect, json, re, sys
from collections import defaultdict

OPS_END = {0x00, 0x56, 0xf3, 0xfd, 0xfe, 0xff}  # STOP JUMP RETURN REVERT INVALID SELFDESTRUCT: no fall-through


def load(path):
    return json.load(open(path))


def code_bytes(hexobj):
    return bytes.fromhex(re.sub(r'__\$[0-9a-fA-F]{34}\$__', '00' * 20, hexobj.removeprefix('0x')))


def decode_sourcemap(sm):
    out, cur = [], [0, 0, -1, '-', 0]
    for item in sm.split(';'):
        parts = item.split(':')
        for i, p in enumerate(parts):
            if p != '':
                cur[i] = p if i == 3 else int(p)
        out.append(tuple(cur))
    return out


def instructions(code, n_map):
    """(pc, op, size) for the n_map instructions of the source map; the rest of the object is data."""
    out, pc = [], 0
    while pc < len(code) and len(out) < n_map:
        op = code[pc]
        size = 1 + (op - 0x5f if 0x60 <= op <= 0x7f else 0)
        out.append((pc, op, size))
        pc += size
    return out, pc


class Sources:
    """Innermost function / modifier of a source location, per file."""

    def __init__(self, solc_out):
        self.id_to_path = {int(k): v for k, v in solc_out['source_id_to_path'].items()}
        self.fn = defaultdict(list)
        self.sel = {}  # selector hex -> (contract, name, path) by declaring definition
        self.contract_of = {}
        for path, s in solc_out['sources'].items():
            fid = s['id']
            for c in s['ast']['nodes']:
                if c.get('nodeType') != 'ContractDefinition':
                    continue
                st, ln, _ = map(int, c['src'].split(':'))
                self.fn[fid].append((st, st + ln, f"{c['name']}.<contract>", path, 'contract'))
                for n in c['nodes']:
                    if n.get('nodeType') in ('FunctionDefinition', 'ModifierDefinition'):
                        a, b, _ = map(int, n['src'].split(':'))
                        nm = n.get('name') or n.get('kind', '')
                        kind = 'modifier' if n['nodeType'] == 'ModifierDefinition' else 'function'
                        self.fn[fid].append((a, a + b, f"{c['name']}.{nm}", path, kind))
                    elif n.get('nodeType') == 'VariableDeclaration':
                        a, b, _ = map(int, n['src'].split(':'))
                        self.fn[fid].append((a, a + b, f"{c['name']}.{n['name']}", path, 'variable'))
            for n in s['ast']['nodes']:
                if n.get('nodeType') == 'FunctionDefinition':  # free function
                    a, b, _ = map(int, n['src'].split(':'))
                    self.fn[fid].append((a, a + b, f"<free>.{n['name']}", path, 'function'))
        self.cache = {}

    def locate(self, s, l, f):
        key = (s, l, f)
        if key in self.cache:
            return self.cache[key]
        best = None
        for a, b, label, path, kind in self.fn.get(f, ()):
            if a <= s and s + l <= b and (best is None or b - a < best[1] - best[0]):
                best = (a, b, label, path, kind)
        r = (best[2], best[3], best[4]) if best else None
        self.cache[key] = r
        return r


def yul_functions(generated):
    """id -> sorted [(start, end, name)]"""
    out = {}
    for g in generated or []:
        fs = []

        def walk(n):
            if isinstance(n, dict):
                if n.get('nodeType') == 'YulFunctionDefinition':
                    a, b, _ = map(int, n['src'].split(':'))
                    fs.append((a, a + b, n['name']))
                for v in n.values():
                    if isinstance(v, (dict, list)):
                        walk(v)
            elif isinstance(n, list):
                for v in n:
                    walk(v)
        walk(g['ast'])
        out[g['id']] = sorted(fs)
    return out


class Contract:
    def __init__(self, solc_out, sources, path, name):
        c = solc_out['contracts'][path][name]['evm']
        db = c['deployedBytecode']
        self.path, self.name = path, name
        self.code = code_bytes(db['object'])
        self.size = len(self.code)
        self.map = decode_sourcemap(db['sourceMap'])
        self.ins, self.code_end = instructions(self.code, len(self.map))
        self.methods = c.get('methodIdentifiers', {})
        self.sel_to_sig = {v: k for k, v in self.methods.items()}
        self.yul = yul_functions(db.get('generatedSources'))
        self.src = sources
        self.link_refs = db.get('linkReferences', {})
        self.immutables = db.get('immutableReferences', {})
        self.dbg = db.get('functionDebugData', {})
        self._cfg()

    # ---------------------------------------------------------------- source map view
    def attribute(self):
        """label -> bytes. Labels: fn:<Contract.f>, yul:<utility>, dispatch, data."""
        out = defaultdict(int)
        for (pc, op, size), (s, l, f, j, m) in zip(self.ins, self.map):
            out[self.label(s, l, f)] += size
        out['data:metadata+auxdata'] = self.size - self.code_end
        return out

    def label(self, s, l, f):
        if f == -1:
            return 'dispatch:no-source'
        if f in self.yul:
            fs = self.yul[f]
            best = None
            for a, b, nm in fs:
                if a <= s and s + l <= b and (best is None or b - a < best[1] - best[0]):
                    best = (a, b, nm)
            return 'yul:' + (best[2] if best else '<top>')
        loc = self.src.locate(s, l, f)
        if not loc:
            return 'other:' + self.src.id_to_path.get(f, str(f))
        label, path, kind = loc
        if kind == 'contract':
            return 'dispatch:' + label
        return ('mod:' if kind == 'modifier' else 'fn:') + label

    # ---------------------------------------------------------------- CFG / closure view
    def _cfg(self):
        ins = self.ins
        self.jumpdests = {pc for pc, op, _ in ins if op == 0x5b}
        self.blocks = []  # (start_index, end_index)
        starts = [0]
        for i, (pc, op, size) in enumerate(ins):
            if op == 0x5b and i != 0:
                starts.append(i)
            elif op in OPS_END or op == 0x57:
                if i + 1 < len(ins):
                    starts.append(i + 1)
        starts = sorted(set(starts))
        self.block_start_pc = []
        self.block_size = []
        self.block_refs = []
        self.pc_to_block = {}
        for k, st in enumerate(starts):
            en = starts[k + 1] if k + 1 < len(starts) else len(ins)
            size, refs = 0, set()
            last = None
            for i in range(st, en):
                pc, op, sz = ins[i]
                size += sz
                if op == 0x61:  # PUSH2
                    v = int.from_bytes(self.code[pc + 1:pc + 3], 'big')
                    if v in self.jumpdests:
                        refs.add(v)
                elif op == 0x62:  # PUSH3: a build above 65,535 B
                    v = int.from_bytes(self.code[pc + 1:pc + 4], 'big')
                    if v in self.jumpdests:
                        refs.add(v)
                last = op
            self.pc_to_block[ins[st][0]] = k
            self.block_start_pc.append(ins[st][0])
            self.block_size.append(size)
            ft = last not in OPS_END
            self.block_refs.append((refs, ft))
        self.dispatch = self._dispatch()

    def _dispatch(self):
        """selector -> target pc: PUSH4 sel, EQ (DUP before), PUSH2 tag, JUMPI, in the dispatcher."""
        out = {}
        ins = self.ins
        for i in range(len(ins) - 3):
            pc, op, _ = ins[i]
            if op == 0x63:
                sel = self.code[pc + 1:pc + 5].hex()
                if sel in self.sel_to_sig and ins[i + 1][1] == 0x14 and ins[i + 2][1] in (0x61, 0x62) and ins[i + 3][1] == 0x57:
                    p = ins[i + 2][0]
                    w = ins[i + 2][2] - 1
                    out.setdefault(sel, int.from_bytes(self.code[p + 1:p + 1 + w], 'big'))
        return out

    def closure(self, pc):
        seen, st = set(), [self.pc_to_block[pc]]
        while st:
            k = st.pop()
            if k in seen:
                continue
            seen.add(k)
            refs, ft = self.block_refs[k]
            for v in refs:
                st.append(self.pc_to_block[v])
            if ft and k + 1 < len(self.block_size):
                st.append(k + 1)
        return seen

    def closures(self):
        return {sel: self.closure(t) for sel, t in self.dispatch.items()}

    def exclusive(self, closures, group):
        """Bytes reachable only from `group` (selectors), and bytes reachable from it at all."""
        g, others = set(), set()
        for sel, c in closures.items():
            (g if sel in group else others).update(c)
        return sum(self.block_size[k] for k in g - others), sum(self.block_size[k] for k in g)

    def dispatcher_bytes(self, closures):
        """Blocks no entry reaches: the dispatcher itself, receive/fallback, dead code."""
        all_ = set()
        for c in closures.values():
            all_.update(c)
        return sum(s for k, s in enumerate(self.block_size) if k not in all_)
