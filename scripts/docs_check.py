#!/usr/bin/env python3
"""SCaaS docs checker (stdlib only). Plan: docs/superpowers/plans/2026-10-07-docs-reorg.md §3.4, §6.3.

  docs_check.py inventory                 freeze old ruling ids -> docs/history/ruling-ids.txt
  docs_check.py check [--area A]          checks C1-C10 (+ budgets); exit 1 on error
  docs_check.py --write                   regenerate the alias index in docs/decisions.md
  docs_check.py resolve ID                old id -> new id(s) / new id -> old ids
  docs_check.py facts extract [--reset]   (keeps existing dispositions unless --reset)
  docs_check.py facts check [--area A] | facts trace SOURCE
  --docs DIR                              docs root (default: <repo>/docs; tests use a temp tree)

A check whose inputs do not exist yet (Phase 0: no decisions.md, no component docs) prints "pending" and
passes; it turns into a real check as soon as its inputs appear.
"""
import collections, csv, hashlib, re, sys
from pathlib import Path

DOCS = Path(__file__).resolve().parent.parent / 'docs'
OLD = r'CR-[A-Z0-9]+-\d+[a-z]?|RS-NV64-\d+|RS\d+-\d+[a-z]?|R\d+-\d+[a-z]?|R\d+[a-z]?'
DEF = re.compile(r'^\s*(?:\|\s*|[-*]\s+)(?:~~)?\*{0,2}(' + OLD + r')(?:\s*\((?:owner|[Ss]uperseded)[^)]*\))?(?:\*\*|\s*\||\s)')
OLD_TOK = re.compile(r'(?<![A-Za-z0-9-])(' + OLD + r')(?![A-Za-z0-9])')
NEW = r'(?:ARCH|NODE|CTR|NET|CLI|INT)-[A-Z]{2,4}-\d{2}[a-z]?'
NEW_TOK = re.compile(r'\b(' + NEW + r')\b')
ANCHOR = re.compile(r'<a id="(' + NEW + r')"></a>')
QUAL = re.compile(r'^[\w.-]+:\S+$')          # qualified alias: SCaaS:N4, UD:§23, owner:2026-10-06:families
STATUSES = {'current', 'superseded', 'withdrawn', 'unused', 'open'}
AREAS = {'node': (['node/'], ['NODE-']), 'contracts': (['contracts/'], ['CTR-']),
         'netcli': (['networks/', 'clients/', 'integration.md', 'integration-odoo-example.md'], ['NET-', 'CLI-', 'INT-'])}
NOT_CURRENT = ('history/', 'research/', 'reviews/', 'superpowers/', '_work/')
BUDGET = {'README.md': 100, 'SCaaS-v2.md': 150, 'architecture.md': 450, 'decisions.md': 3000, 'integration.md': 950,
          'node/README.md': 250, 'node/store.md': 600, 'node/job-api.md': 550, 'node/submit-lanes.md': 550,
          'node/indexer-feeds.md': 400, 'node/gateway.md': 300, 'node/admin-auth.md': 400, 'node/sponsorship.md': 250,
          'node/dex-venue.md': 400, 'node/mesh.md': 650, 'node/gossip.md': 600, 'node/ops.md': 550,
          'node/runbooks.md': 500, 'node/threat-model.md': 250, 'contracts/README.md': 250, 'contracts/metatx.md': 650,
          'contracts/token-wrappers.md': 650, 'contracts/accounts-mandates.md': 350, 'contracts/dex.md': 400,
          'contracts/tender.md': 400, 'contracts/asset-suite.md': 750, 'contracts/zether.md': 700,
          'contracts/pq-zether.md': 950, 'contracts/universal-account.md': 950, 'networks/README.md': 400,
          'networks/evm.md': 200, 'networks/hedera.md': 250, 'networks/cosmos.md': 220, 'networks/soroban.md': 230,
          'networks/sui.md': 300, 'networks/aptos.md': 500, 'networks/solana.md': 550, 'networks/ton.md': 280,
          'clients/app.md': 750, 'clients/signers-clientkeys.md': 650}
BANNER = '> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**'


def rng(p, a, b):
    return [f'{p}{i}' for i in range(a, b + 1)]


# §0 of the plan: numbered ids the definition regex must find, plus the prose-defined ones and the unused
# R36-R49, R68-R69 in ruling-ids.extra.txt (registered as status unused).
EXPECTED = set(
    rng('R', 1, 69) + rng('CR-PD-', 1, 6) + rng('CR-ADW-', 1, 4) + rng('CR-R3-', 1, 11)
    + rng('RS2-', 1, 26) + rng('RS-NV64-', 1, 2) + rng('RS4-', 1, 16) + rng('RS5-', 1, 21) + rng('R6-', 1, 11)
    + rng('RS7-', 1, 14) + rng('R8-', 1, 15) + rng('R9-', 1, 8) + rng('R10-', 1, 17) + rng('RS11-', 1, 26)
    + rng('RS12-', 1, 25) + [f'RS12-{n}a' for n in (4, 9, 11, 12, 16, 18)] + rng('R', 70, 128) + ['R106a']
    + rng('R', 129, 179) + ['R173a', 'R173b', 'R173c'] + rng('R', 180, 217) + rng('R', 230, 247)
    + rng('R', 250, 318) + rng('R', 320, 328) + rng('R', 330, 331) + rng('R', 340, 349) + rng('CR-WSF-', 1, 2))


def d(*p):
    return DOCS.joinpath(*p)


def rel(p):
    return p.relative_to(DOCS).as_posix()


def read(p):
    return p.read_text(encoding='utf-8') if p.exists() else ''


def natkey(s):
    return [int(t) if t.isdigit() else t for t in re.split(r'(\d+)', s)]


def scheme(i):
    if QUAL.match(i):
        return i.split(':')[0] + (':' + re.sub(r'\d+$', '', i.split(':')[-1]) if i.startswith(('SCaaS', 'net-', 'MESH', 'NI', 'UA', 'APP', 'S4F', 'ZL', 'reorg')) else '')
    m = re.match(r'(CR-[A-Z0-9]+-|RS-NV64-|RS\d+-|R\d+-(?=\d))', i)
    return m.group(1) if m else 'R'


def current_docs(area=None):
    out = []
    for p in sorted(DOCS.rglob('*.md')):
        r = rel(p)
        if r.startswith(NOT_CURRENT):
            continue
        if area and not any(r.startswith(x) for x in AREAS[area][0]):
            continue
        out.append(p)
    return out


def strip_fences(text):
    """Yield (lineno, line, in_fence)."""
    fence = False
    for n, line in enumerate(text.split('\n'), 1):
        if re.match(r'^\s*(```|~~~)', line):
            fence = not fence
            yield n, line, True
            continue
        yield n, line, fence


# ---------------------------------------------------------------------------------------------- inventory
def inventory_sources():
    s = sorted(d('history', 'specs').glob('*.md'))
    return s + [d('history', 'plans', '2026-10-03-r3-passkey-seed.md'), d('history', 'SCaaS-2026-10-07.md')]


def load_inventory():
    inv = {}
    for line in read(d('history', 'ruling-ids.txt')).splitlines():
        if line and not line.startswith('#'):
            k, v = (line.split('\t') + [''])[:2]
            inv[k] = v
    return inv


def cmd_inventory():
    found = {}
    for f in inventory_sources():
        for n, line in enumerate(read(f).split('\n'), 1):
            m = DEF.match(line)
            if m and m.group(1) not in found:
                found[m.group(1)] = f'{rel(f)}:{n}'
    extra = {}
    for line in read(d('history', 'ruling-ids.extra.txt')).splitlines():
        if line and not line.startswith('#'):
            a, at = line.split('\t')[:2]
            extra[a] = at
    numbered = set(found) | {a for a in extra if not QUAL.match(a)}
    missing, unexpected = sorted(EXPECTED - numbered, key=natkey), sorted(numbered - EXPECTED, key=natkey)
    allids = {**extra, **found}
    lines = ['# Frozen old-id inventory (docs_check.py inventory, 2026-10-07). id<TAB>defined-at (file:line under docs/)']
    lines += [f'{i}\t{allids[i]}' for i in sorted(allids, key=natkey)]
    d('history', 'ruling-ids.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    c = collections.Counter(scheme(i) for i in allids)
    for k in sorted(c, key=natkey):
        print(f'  {k:28} {c[k]}')
    print(f'numbered: {len(numbered)} (regex {len(found)}, prose {len(numbered) - len(found)}); '
          f'qualified extras: {len(allids) - len(numbered)}; total {len(allids)}')
    if missing or unexpected:
        print('MISMATCH vs plan §0: missing', missing, 'unexpected', unexpected)
        return 1
    return 0


# ---------------------------------------------------------------------------------------------- register
Entry = collections.namedtuple('Entry', 'new title old status owner date normative sup file line')


def register_files():
    if d('decisions.md').exists():
        return [d('decisions.md')]
    return sorted(d('_work').glob('decisions-*.md'))


def parse_register(files=None):
    entries, errs = [], []
    for f in files if files is not None else register_files():
        lines = read(f).split('\n')
        for n, line in enumerate(lines):
            m = re.match(r'^### (\S+) — (.+)$', line)
            if not m:
                continue
            meta = next((x for x in lines[n + 1:n + 4] if x.startswith('- old:')), None)
            if meta is None:
                errs.append(f'{rel(f)}:{n + 1}: entry {m.group(1)} has no "- old:" meta line')
                continue
            kv = dict((p.split(':', 1) + [''])[:2] for p in meta[2:].split(' · '))
            kv = {k.strip(): v.strip() for k, v in kv.items()}
            olds = [x.strip() for x in kv.get('old', '').split(',') if x.strip() and x.strip() != '—']
            sup = [x.strip() for x in kv.get('superseded-by', '').split(',') if x.strip() not in ('', '—')]
            entries.append(Entry(m.group(1), m.group(2), olds, kv.get('status', ''), kv.get('owner', ''),
                                 kv.get('date', ''), kv.get('normative', ''), sup, rel(f), n + 1))
    return entries, errs


def load_idmap():
    p = d('_work', 'id-map.tsv')
    if not p.exists():
        return []
    with p.open(encoding='utf-8') as fh:
        return [r for r in csv.DictReader(fh, delimiter='\t') if r.get('old')]


def alias_rows(entries):
    m = collections.defaultdict(list)
    for e in entries:
        for o in e.old:
            base = re.sub(r'\(.*\)$', '', o)
            m[base].append((e.new, e.status, o[len(base):]))
    rows = []
    for o in sorted(m, key=natkey):
        news = ', '.join(f'{n}{c}' for n, _, c in m[o])
        st = '/'.join(sorted({s for _, s, _ in m[o]}))
        rows.append(f'| {o} | {news} | {st}{" (split)" if len(m[o]) > 1 else ""} |')
    return ['| Old id | New id(s) | Status |', '|---|---|---|'] + rows


AI_BEGIN = '<!-- BEGIN alias-index (generated by scripts/docs_check.py --write) -->'
AI_END = '<!-- END alias-index -->'


def cmd_write():
    p = d('decisions.md')
    if not p.exists():
        print('pending: docs/decisions.md does not exist yet (Phase 2)')
        return 0
    entries, _ = parse_register([p])
    s = read(p)
    block = AI_BEGIN + '\n' + '\n'.join(alias_rows(entries)) + '\n' + AI_END
    s = re.sub(re.escape(AI_BEGIN) + r'.*?' + re.escape(AI_END), lambda _: block, s, flags=re.S) if AI_BEGIN in s \
        else s.rstrip('\n') + '\n\n## Alias index\n\n' + block + '\n'
    p.write_text(s, encoding='utf-8')
    print(f'alias index: {len(entries)} entries')
    return 0


def cmd_resolve(i):
    entries, _ = parse_register()
    hits = [e for e in entries if e.new == i or any(re.sub(r'\(.*\)$', '', o) == i for o in e.old)]
    for e in hits:
        print(f'{e.new}  [{e.status}]  old: {", ".join(e.old)}  -> docs/{e.normative or "decisions.md#" + e.new}'
              + (f'  superseded-by: {", ".join(e.sup)}' if e.sup else ''))
    if not hits:
        for r in load_idmap():
            if i in (r['old'], r['new']):
                print(f"{r['new']}  [{r['status']}]  old: {r['old']}{r['clause']}  target: {r['target']}  (id-map, pre-register)"
                      + (f"  superseded-by: {r['superseded_by']}" if r['superseded_by'] else ''))
                hits.append(r)
    if not hits:
        print(f'{i}: unknown')
    return 0 if hits else 1


# ---------------------------------------------------------------------------------------------- checks
def slug(h):
    h = re.sub(r'<[^>]+>', '', h).strip().lower()
    h = re.sub(r'[^\w\- ]', '', h)
    return h.replace(' ', '-')


def anchors_of(p, cache={}):
    if p not in cache:
        seen, out = collections.Counter(), set(re.findall(r'<a id="([^"]+)"', read(p)))
        for _, line, fence in strip_fences(read(p)):
            m = None if fence else re.match(r'^#{1,6}\s+(.*?)\s*#*\s*$', line)
            if m:
                s = slug(m.group(1))
                out.add(s if not seen[s] else f'{s}-{seen[s]}')
                seen[s] += 1
        cache[p] = out
    return cache[p]


def example_mask(text):
    """Lines inside <!-- example:odoo --> ... <!-- /example --> or the alias index are exempt from C9."""
    mask, on = set(), False
    for n, line in enumerate(text.split('\n'), 1):
        if '<!-- example:' in line or AI_BEGIN in line:
            on = True
        if on:
            mask.add(n)
        if '<!-- /example -->' in line or AI_END in line:
            on = False
    return mask


C9 = [r'\bSRS\b', r'bamboo', r'\bDMS\b', r'\bNPP\b', r'\bcanon\s*(?:§|C\d)|CANON', r'_USER-DECISIONS', r'\bUD §', r'\b(round|vòng) \d',
      r'\bspec [A-F]\b', r'\b(PD|ADW|R3D|WSF|INFRA|ZD|NI|MESH|A2|TW2|APP|TSS|AS|OPS|S4F|PQZ)\s*(§|rev\b|R\d)',
      r'\bdms_', r'res\.company', r'\bOdoo\b', r'\bNhóm \d', r'CHƯƠNG', r'§\s*(6\.21|10\.[1-5](\.\d)?|14\.2\.8)\b']
C9_RE = re.compile('|'.join(f'(?:{x})' for x in C9))
STREAM_RE = re.compile(r'\b(P\d+b?|NR\d|OP\d|S\d+′*|G\d|T\d|TB\d|RP\d|CS\d|PL\d|SP\d|AS\d|F\d+|N\d|A\d+(-\w+)?|E-S\d+|D\d)\b')
VI_RE = re.compile('[ăâđêôơưạảấầẩẫậắằẳẵặẹẻẽếềểễệỉịọỏốồổỗộớờởỡợụủứừửữựỳỵỷỹ]', re.I)
VI_KEY = re.compile(VI_RE.pattern[:-1] + 'àáèéìíòóùúýãõ]', re.I)   # a fact key in Vietnamese can never land


def run_checks(area=None):
    errs, warns, notes = [], [], []
    inv = load_inventory()
    docs = current_docs(area)
    prefixes = AREAS[area][1] if area else None
    entries, perr = parse_register()
    errs += perr
    if area:
        entries = [e for e in entries if any(e.new.startswith(x) for x in prefixes)]
    reg = {}
    for e in entries:
        if e.new in reg:
            errs.append(f'C2 {e.file}:{e.line}: {e.new} defined twice in the register')
        reg[e.new] = e

    # C1 coverage (register, or the id map while the register does not exist)
    if not inv:
        notes.append('C1 pending: docs/history/ruling-ids.txt missing (run inventory)')
    elif entries:
        cov = collections.defaultdict(list)
        for e in entries:
            for o in e.old:
                cov[re.sub(r'\(.*\)$', '', o)].append(o)
                if re.sub(r'\(.*\)$', '', o) not in inv:
                    errs.append(f'C1 {e.file}:{e.line}: old id {o} not in the inventory')
        if not area:
            for i in inv:
                c = cov.get(i, [])
                if not c:
                    errs.append(f'C1 old id {i} ({inv[i]}) is in no register entry')
                elif len(c) > 1 and (i in c or len(set(c)) < len(c)):
                    errs.append(f'C1 old id {i} split without distinct clauses: {c}')
    else:
        im = load_idmap()
        if not im:
            notes.append('C1 pending: no register and no docs/_work/id-map.tsv')
        else:
            seen = collections.defaultdict(list)
            for r in im:
                seen[r['old']].append(r['clause'])
                if r['old'] not in inv:
                    errs.append(f"C1 id-map: {r['old']} not in the inventory")
                if not re.fullmatch(NEW, r['new'] or ''):
                    errs.append(f"C1 id-map: {r['old']}{r['clause']} new id {r['new']!r} malformed")
                if r['status'] not in STATUSES:
                    errs.append(f"C1 id-map: {r['old']} status {r['status']!r}")
            for i in inv:
                c = seen.get(i)
                if not c:
                    errs.append(f'C1 id-map: inventory id {i} not mapped')
                elif len(c) > 1 and ('' in c or len(set(c)) < len(c)):
                    errs.append(f'C1 id-map: {i} split without distinct clauses {c}')
            olds = {r['old'] for r in im}
            news = collections.defaultdict(set)
            for r in im:
                news[r['new']].add(r['status'] if r['status'] != 'open' else 'current')
            for n, s in news.items():
                if len(s) > 1:
                    errs.append(f'C1 id-map: new id {n} mixes statuses {sorted(s)}')
                num = int(re.search(r'(\d{2})[a-z]?$', n).group(1))
                if ('current' in s) != (num < 80):
                    errs.append(f'C1 id-map: {n} numbering (01-79 current/open, 80-99 superseded/withdrawn/unused)')
            notes.append(f'C1 (id-map, pre-register): {len(olds)} old ids -> {len(news)} new ids; {len(inv)} in inventory')

    # C2 register integrity
    if not entries:
        notes.append('C2 pending: no register entries yet')
    defined = collections.defaultdict(list)
    for p in current_docs():
        for n, line, fence in strip_fences(read(p)):
            if not fence:
                for a in ANCHOR.findall(line):
                    defined[a].append(f'{rel(p)}:{n}')
    for e in entries:
        if not re.fullmatch(NEW, e.new):
            errs.append(f'C2 {e.file}:{e.line}: malformed id {e.new}')
        if e.status not in STATUSES:
            errs.append(f'C2 {e.file}:{e.line}: {e.new} status {e.status!r}')
        if e.status in ('current', 'open'):
            f = e.normative.split('#')[0]
            if f == 'decisions.md':
                pass                                      # self-defining entry (ARCH-POS, register policy)
            elif not f or not d(f).exists():
                errs.append(f'C2 {e.file}:{e.line}: {e.new} normative file {f!r} missing')
            elif len([x for x in defined.get(e.new, []) if x.startswith(f + ':')]) != 1:
                errs.append(f'C2 {e.file}:{e.line}: {e.new} must be defined exactly once in {f} (<a id>)')
        if e.status == 'superseded':
            if not e.sup:
                errs.append(f'C2 {e.file}:{e.line}: {e.new} superseded without superseded-by')
            for s in e.sup:
                if s not in reg and not area:
                    errs.append(f'C2 {e.file}:{e.line}: {e.new} superseded-by {s} does not exist')
        if e.status in ('superseded', 'withdrawn', 'unused') and e.new in defined:
            errs.append(f'C2 {e.new} is {e.status} but defined at {defined[e.new]}')

    # C3 doc ids, C4 old ids, C6 links, C8, C9, C10
    if not docs:
        notes.append('C3/C4/C6/C8/C9/C10-links pending: no current docs' + (f' in area {area}' if area else ''))
    for a, where in defined.items():
        if len(where) > 1:
            errs.append(f'C3 {a} defined more than once: {where}')
        if (not area or any(a.startswith(x) for x in prefixes)) and entries and \
                (a not in reg or reg[a].status not in ('current', 'open')):
            errs.append(f'C3 {where[0]}: {a} is not a current/open register entry')
    allreg = {e.new: e for e in parse_register()[0]}
    for p in docs:
        r, text = rel(p), read(p)
        exempt = example_mask(text)
        for n, line, fence in strip_fences(text):
            if fence:
                continue
            meta = r == 'decisions.md' and (line.startswith('- old:') or line.startswith('**Source.**'))
            for t in NEW_TOK.findall(line):
                if allreg and t not in allreg:
                    errs.append(f'C3 {r}:{n}: cites unknown id {t}')
                elif t in allreg and allreg[t].status in ('superseded', 'withdrawn') and r != 'decisions.md':
                    errs.append(f'C3 {r}:{n}: cites {allreg[t].status} id {t}')
            if r != 'decisions.md':
                for t in OLD_TOK.findall(line):
                    if t in inv:
                        errs.append(f'C4 {r}:{n}: old id {t}')
                for t in inv:
                    if QUAL.match(t) and t in line:
                        errs.append(f'C4 {r}:{n}: old alias {t}')
            if n not in exempt and not meta:
                m = C9_RE.search(line)
                if m:
                    errs.append(f'C9 {r}:{n}: banned {m.group(0)!r}')
                if re.search(r'\bstreams?\b', line, re.I) and STREAM_RE.search(line):
                    errs.append(f'C9 {r}:{n}: stream id next to "stream"')
                if VI_RE.search(line):
                    errs.append(f'C9 {r}:{n}: Vietnamese text')
            for target in re.findall(r'\]\(([^)\s]+)\)', line):
                if re.match(r'^[a-z]+:', target):
                    continue
                path, _, frag = target.partition('#')
                tp = (p.parent / path).resolve() if path else p
                trel = tp.relative_to(DOCS.resolve()).as_posix() if str(tp).startswith(str(DOCS.resolve())) else None
                if trel and trel.startswith('research/') and not (r == 'decisions.md' and line.startswith('**Source.**')):
                    errs.append(f'C10 {r}:{n}: link into research/ outside a decisions.md Source line')
                if not tp.exists():
                    errs.append(f'C6 {r}:{n}: broken link {target}')
                elif frag and tp.suffix == '.md' and frag not in anchors_of(tp):
                    errs.append(f'C6 {r}:{n}: missing anchor {target}')
        if r in ('architecture.md', 'README.md', 'SCaaS-v2.md') and ANCHOR.search(text):
            errs.append(f'C8 {r}: defines ruling ids (non-normative file)')
        lim = BUDGET.get(r)
        if lim and text.count('\n') > lim * 1.3:
            warns.append(f'budget {r}: {text.count(chr(10))} lines > 1.3 x {lim}')

    # C5 alias index
    if d('decisions.md').exists() and not area:
        s = read(d('decisions.md'))
        want = '\n'.join(alias_rows(parse_register([d('decisions.md')])[0]))
        got = s.split(AI_BEGIN)[1].split(AI_END)[0].strip() if AI_BEGIN in s else None
        if got != want:
            errs.append('C5 alias index stale or missing: run docs_check.py --write')
    else:
        notes.append('C5 pending: no docs/decisions.md')

    # C7 artifacts
    c7 = c7_misses(docs) if docs and not area else None
    if c7 is None:
        notes.append('C7 pending: needs current docs and docs/_work/facts (full check only)')
    else:
        errs += [f'C7 load-bearing token {k!r} ({src}) in no current doc and not in history/dropped-artifacts.tsv'
                 for k, src in c7]

    # C10 research banners
    for p in sorted(d('research').glob('*.md')):
        if not read(p).startswith(BANNER):
            errs.append(f'C10 {rel(p)}: missing the non-normative banner')
    return errs, warns, notes


def c7_misses(docs):
    facts = load_facts()
    if not facts:
        return None
    corpus = norm_text('\n'.join(read(p) for p in docs))
    dropped = {l.split('\t')[0] for l in read(d('history', 'dropped-artifacts.tsv')).splitlines() if l.strip()}
    out, seen = [], set()
    for f in facts:
        if not f['disposition'].startswith('target:'):
            continue
        for k in f['keys'].split(' ¦ '):
            if k.startswith('`') and k not in seen:
                seen.add(k)
                if norm_text(k.strip('`')) not in corpus and k.strip('`') not in dropped:
                    out.append((k, f['fact_id']))
    return out


def cmd_check(area):
    errs, warns, notes = run_checks(area)
    for x in notes:
        print('  note:', x)
    for x in warns:
        print('  warn:', x)
    for x in errs:
        print('  ERROR:', x)
    print(f'check{" --area " + area if area else ""}: {len(errs)} error(s), {len(warns)} warning(s), {len(notes)} note(s)')
    return 1 if errs else 0


# ---------------------------------------------------------------------------------------------- facts (§6.3)
RESET = False
FACT_COLS = ['fact_id', 'section', 'kind', 'excerpt', 'keys', 'disposition', 'hint']
NORMATIVE = re.compile(r'\b(must|never|only|always|exactly|at most|refuses?|rejects?|MUST|NEVER)\b|phải|không bao giờ|'
                       r'\bchỉ\b|\bluôn\b|từ chối|tối đa')
FORMULA = re.compile(r'[=≤≥×]|2\^|\bmod\b|0x[0-9a-fA-F]{4,}|\b\d[\d., ]*\s?(?:ms|s|gas|B|KiB|MiB|%|wei|days?|ngày|h|min)\b')
REFS = re.compile(r'vectors?/|_kat\b|\.json\b|tests?/|\bT\d{1,2}\b|\(owner\)|owner:')
MEASURE = re.compile(r'measured|\bđo\b|đã đo|gas report|forge|anvil|benchmark', re.I)
ADMIN = [(re.compile(r'review log|disposition|claude review|codex review|agy\b|antigravity|grok', re.I), 'history:review'),
         (re.compile(r'revision history|lịch sử bản|revisions?\b', re.I), 'history:revision'),
         (re.compile(r'code streams|luồng code|\bstreams?\b|work breakdown|stream plan', re.I), 'history:streams'),
         (re.compile(r'superseded|bị thay', re.I), 'target:decisions.md'),
         (re.compile(r'amendments needed|doc corrections|changes to existing specs|needed from other', re.I),
          'history:amendments-executed'),
         (re.compile(r'execution results|kết quả thực thi', re.I), 'history:execution-log')]
SUP = str.maketrans('⁰¹²³⁴⁵⁶⁷⁸⁹', '0123456789')


def fact_sources():
    h = d('history')
    out = sorted((h / 'specs').glob('*.md')) + [h / 'SCaaS-2026-10-07.md', h / 'integration-2026-10-07.md',
                                                h / 'plans' / '2026-10-03-r3-passkey-seed.md',
                                                h / 'HANDOFF-blockchain.md', h / 'blockchain.md',
                                                d('research', '_USER-DECISIONS.md')]
    other = [p for p in sorted(d('research').glob('*.md')) if p.name not in ('_USER-DECISIONS.md', 'README.md')]
    return [p for p in out if p.exists()], other


def norm_num(t):
    t = re.sub('[⁰¹²³⁴⁵⁶⁷⁸⁹]+', lambda m: '^' + m.group(0).translate(SUP), t)
    t = re.sub(r'(?<=\d)[ ,_  ](?=\d{3}\b)', '', t)
    return t


def norm_text(s):
    return re.sub(r'\s+', ' ', norm_num(s))


def keys_of(text, kind):
    ks = ['`' + k + '`' for k in re.findall(r'`([^`\n]{1,80})`', text)]
    ks += OLD_TOK.findall(text)
    t = re.sub(r'`[^`]*`', ' ', text)
    t = OLD_TOK.sub(' ', t)
    t = re.sub(r'§\s*[\w.]+|\b\d{4}-\d{2}-\d{2}\b|\b[A-Z]+-?\d+(\.\d+)*\b', ' ', t)
    ks += ['0x' + h for h in re.findall(r'0x([0-9a-fA-F]+)', t)]
    ks += [norm_num(x) for x in re.findall(r'2\^\d+|2[⁰¹²³⁴⁵⁶⁷⁸⁹]+|\b\d{1,3}(?:[ , ]\d{3})+\b|\b\d+(?:\.\d+)?\b', t)
           if len(re.sub(r'\D', '', x)) >= 2]
    ks += ['"' + q + '"' for q in re.findall(r'"([^"\n]{2,60})"', t)]
    if kind == 'code':
        ks += sorted(set(re.findall(r'\b[a-z]+_[a-z0-9_]+\b|\b[a-z]+[A-Z]\w+\b|\b[A-Z][A-Z0-9]*_[A-Z0-9_]+\b', text)))[:40]
    seen, out = set(), []
    for k in ks:
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def heading_num(title):
    m = re.match(r'^(?:§\s*)?((?:[A-Z]\d*|\d+)(?:\.\d+)*)(?:[.)]|\s|$)', title)
    return m.group(1) if m else ''


def split_facts(path, measure_only=False, every_paragraph=False):
    """Yield dict(fact_id, chain, kind, excerpt, text)."""
    lines = read(path).split('\n')
    chain = []        # [(level, num, title)]
    r = rel(path)
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        m = re.match(r'^(#{1,6})\s+(.*)$', line)
        if m:
            lvl = len(m.group(1))
            chain = [c for c in chain if c[0] < lvl] + [(lvl, heading_num(m.group(2).strip()), m.group(2).strip())]
            i += 1
            continue
        start = i
        if re.match(r'^\s*(```|~~~)', line):
            i += 1
            while i < n and not re.match(r'^\s*(```|~~~)', lines[i]):
                i += 1
            i += 1
            kind, text = 'code', '\n'.join(lines[start:i])
        elif line.lstrip().startswith('|'):
            i += 1
            if re.match(r'^\s*\|[\s:|-]+\|\s*$', line) or (i < n and re.match(r'^\s*\|[\s:|-]+\|\s*$', lines[i])):
                continue                                  # separator or header row
            kind, text = 'table-row', line
        elif re.match(r'^\s*([-*+]|\d+[.)])\s+', line):
            ind = len(line) - len(line.lstrip())
            i += 1
            while i < n and lines[i].strip() and not re.match(r'^\s*([-*+]|\d+[.)])\s+', lines[i]) \
                    and not lines[i].startswith('#') and (len(lines[i]) - len(lines[i].lstrip())) > ind:
                i += 1
            kind, text = 'list-item', '\n'.join(lines[start:i])
        elif line.strip():
            i += 1
            while i < n and lines[i].strip() and not re.match(r'^(#|\s*\||\s*([-*+]|\d+[.)])\s|\s*```)', lines[i]):
                i += 1
            text = '\n'.join(lines[start:i])
            kind = ('formula' if FORMULA.search(text) else 'reference' if REFS.search(text)
                    else 'prose' if NORMATIVE.search(text) else 'text' if every_paragraph else None)
            if kind is None:
                continue
        else:
            i += 1
            continue
        if DEF.match(text.split('\n')[0]):
            kind = 'ruling'
        if measure_only and not (MEASURE.search(text) or MEASURE.search(' '.join(c[2] for c in chain))) \
                or measure_only and not re.search(r'\d', text):
            continue
        if measure_only:
            kind = 'measurement'
        yield {'fact_id': f'{r}:{start + 1}', 'chain': chain, 'kind': kind,
               'excerpt': re.sub(r'\s+', ' ', text.strip())[:200], 'text': text}


def load_section_map():
    rows = collections.defaultdict(list)
    p = d('_work', 'section-map.tsv')
    if p.exists():
        with p.open(encoding='utf-8') as fh:
            for row in csv.DictReader(fh, delimiter='\t'):
                rows[row['source']].append(row)
    return rows


def expand(sec):
    """'3.1–3.5, 4' -> {'3.1',…,'3.5','4'}; '10.x' -> {'10'}; tokens that are not ranges are kept as they are."""
    out = set()
    for part in re.split(r',\s*', sec):
        part = part.strip()
        m = re.fullmatch(r'(\S+?)\s*[–-]\s*(\S+)', part)
        if m:
            lp, _, ln = m.group(1).rpartition('.')
            rp, _, rn = m.group(2).rpartition('.')
            if rn == 'x' or ln == 'x':
                out.add(lp)
            elif ln.isdigit() and rn.isdigit() and rp in ('', lp):
                out |= {f'{lp + "." if lp else ""}{k}' for k in range(int(ln), int(rn) + 1)}
            else:
                out.add(part)
        elif re.fullmatch(r'\S+\.x', part):
            out.add(part[:-2])
        elif part:
            out.add(part)
    return out


def section_default(rows, chain):
    """Deepest heading whose number (or title, for '~regex' rows) matches a section-map row."""
    for lvl in range(len(chain), 0, -1):
        _, num, title = chain[lvl - 1]
        for row in rows:
            s = row['sec']
            if s.startswith('~'):
                if re.search(s[1:], title, re.I):
                    return row
            elif num and num in expand(s):
                return row
    return None


def load_facts(area=None):
    out = []
    for p in sorted(d('_work', 'facts').glob('*.tsv')):
        with p.open(encoding='utf-8') as fh:
            out += [r for r in csv.DictReader(fh, delimiter='\t', quoting=csv.QUOTE_NONE, escapechar='\\')]
    if area:
        out = [f for f in out if any(t.startswith(x) for t in targets(f['disposition']) for x in AREAS[area][0])]
    return out


def targets(disp):
    return [t[len('target:'):].split('#')[0] for t in disp.split(';') if t.startswith('target:')]


def ruling_disposition(idmap, old):
    rows = [r for r in idmap if r['old'] == old]
    if not rows:
        return ''
    out = []
    for r in rows:
        if r['status'] in ('current', 'open') and r['target']:
            out.append(f"target:{r['target']}#{r['new']}")
        else:
            out.append(f"superseded:{r['new']}" if r['status'] == 'superseded' else 'target:decisions.md')
    return ';'.join(dict.fromkeys(out))


def cmd_facts_extract():
    smap, idmap = load_section_map(), load_idmap()
    main, other = fact_sources()
    outdir = d('_work', 'facts')
    outdir.mkdir(parents=True, exist_ok=True)
    total = collections.Counter()
    for p, measure in [(x, False) for x in main] + [(x, True) for x in other]:
        name = p.stem if not p.parent.name == 'research' else 'research-' + p.stem
        out = outdir / f'{name}.tsv'
        old = {}
        if out.exists():
            with out.open(encoding='utf-8') as fh:
                old = {r['fact_id']: r for r in csv.DictReader(fh, delimiter='\t', quoting=csv.QUOTE_NONE, escapechar='\\')}
        rows_map = smap.get(p.name, [])
        rows = []
        for f in split_facts(p, measure, every_paragraph=p.name == 'blockchain.md'):
            titles = ' / '.join(c[2] for c in f['chain'])
            sec = f['chain'][-1] if f['chain'] else (0, '', '(top)')
            disp, hint = '', ''
            for rx, cls in ADMIN:
                if any(rx.search(c[2]) for c in f['chain'][1:]):
                    disp = cls
                    break
            row = section_default(rows_map, f['chain'])
            if row:
                hint = row['target_text']
                disp = disp or row['default']
            elif len(f['chain']) <= 1 and p.name != 'blockchain.md':
                hint, disp = 'preamble (status/rev notes): confirm', disp or 'history:H'
            if f['kind'] == 'ruling':
                rid = DEF.match(f['text'].split('\n')[0]).group(1)
                disp = ruling_disposition(idmap, rid) or disp
            keys = keys_of(f['text'], f['kind'])
            prev = old.get(f['fact_id'])
            if prev and prev['disposition'] and not RESET:
                disp = prev['disposition']                # keep a writer's choice (--reset recomputes)
            rows.append({'fact_id': f['fact_id'], 'section': (f'§{sec[1]} ' if sec[1] else '') + sec[2][:70],
                         'kind': f['kind'], 'excerpt': f['excerpt'].replace('\t', ' '),
                         'keys': ' ¦ '.join(keys).replace('\t', ' '), 'disposition': disp,
                         'hint': hint.replace('\t', ' ')})
            total[(name, f['kind'])] += 1
        with out.open('w', encoding='utf-8', newline='') as fh:
            w = csv.DictWriter(fh, FACT_COLS, delimiter='\t', quoting=csv.QUOTE_NONE, escapechar='\\',
                               lineterminator='\n')
            w.writeheader()
            w.writerows(rows)
        undisposed = sum(1 for r in rows if not r['disposition'])
        print(f'  {name:58} {len(rows):5} facts, {undisposed:5} without default')
    print(f'facts: {sum(total.values())} in {len(main) + len(other)} sources')
    return 0


def cmd_facts_check(area):
    facts = load_facts(area)
    if not facts:
        print('pending: no docs/_work/facts (run facts extract)')
        return 0
    entries = {e.new: e for e in parse_register()[0]}
    byid = {f['fact_id']: f for f in facts}
    errs, pend = [], collections.Counter()
    texts = {}
    corpus = None
    for f in facts:
        disp = f['disposition']
        if not disp:
            pend['no disposition'] += 1
            continue
        for part in disp.split(';'):
            if part.startswith('target:'):
                tf = part[7:].split('#')[0]
                if not d(tf).exists():
                    pend['target file not written yet'] += 1
                    continue
                if tf not in texts:
                    texts[tf] = norm_text(read(d(tf)))
                if corpus is None:
                    corpus = norm_text('\n'.join(read(p) for p in current_docs()))
                for k in f['keys'].split(' ¦ '):
                    if not k:
                        continue
                    kk = norm_text(k.strip('`"'))
                    if OLD_TOK.fullmatch(k) or VI_KEY.search(k):
                        continue                          # old ids live in decisions.md; C9 bans Vietnamese text
                    if kk not in texts[tf] and not (k.startswith('`') and kk in corpus):
                        errs.append(f"{f['fact_id']} [{f['section']}] key {k} not in {tf}")
            elif part.startswith('superseded:'):
                e = entries.get(part[11:])
                if entries and (not e or e.status != 'superseded'):
                    errs.append(f"{f['fact_id']}: {part} is not superseded in the register")
                elif not entries:
                    pend['superseded check waits for the register'] += 1
            elif part.startswith('history:duplicate-of:'):
                ref = part[len('history:duplicate-of:'):]
                if ref in byid and not byid[ref]['disposition']:
                    errs.append(f"{f['fact_id']}: duplicate-of {ref}, which is not placed")
    for k, v in sorted(pend.items()):
        print(f'  pending: {v:6} {k}')
    for e in errs[:500]:
        print('  MISS:', e)
    print(f'facts check{" --area " + area if area else ""}: {len(facts)} facts, {len(errs)} miss(es), '
          f'{sum(pend.values())} pending')
    return 1 if errs or pend['no disposition'] else 0


def cmd_facts_trace(source):
    name = Path(source).stem
    facts = [f for f in load_facts() if f['fact_id'].split(':')[0].endswith(Path(source).name)]
    if not facts:
        print(f'no facts for {source}')
        return 1
    print(f'# Requirement trace — {name}\n\n| Item | Excerpt | Status / target |\n|---|---|---|')
    for f in facts:
        print(f"| {f['fact_id']} | {f['excerpt'][:120].replace('|', '/')} | {f['disposition'] or '**undisposed**'} |")
    return 0


def main(argv):
    global DOCS
    if '--docs' in argv:
        k = argv.index('--docs')
        DOCS = Path(argv[k + 1]).resolve()
        argv = argv[:k] + argv[k + 2:]
    area = None
    if '--area' in argv:
        k = argv.index('--area')
        area = argv[k + 1]
        if area not in AREAS:
            sys.exit(f'--area must be one of {sorted(AREAS)}')
        argv = argv[:k] + argv[k + 2:]
    if argv == ['inventory']:
        return cmd_inventory()
    if argv == ['check']:
        return cmd_check(area)
    if argv == ['--write']:
        return cmd_write()
    if len(argv) == 2 and argv[0] == 'resolve':
        return cmd_resolve(argv[1])
    if argv[:2] == ['facts', 'extract']:
        global RESET
        RESET = '--reset' in argv
        return cmd_facts_extract()
    if argv[:2] == ['facts', 'check']:
        return cmd_facts_check(area)
    if len(argv) == 3 and argv[:2] == ['facts', 'trace']:
        return cmd_facts_trace(argv[2])
    print(__doc__)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
