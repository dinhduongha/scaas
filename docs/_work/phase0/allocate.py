"""Allocate new ids from the classifier outputs -> docs/_work/id-map.tsv (Phase 0, one-off)."""
import csv, collections, re, sys
SP = __import__('os').path.dirname(__file__) + '/'
sys.path.insert(0, __import__('os').path.dirname(__file__) + '/../../../scripts')
import docs_check as dc

inv = dc.load_inventory()
TOPICS = set('ARCH-POS NODE-GEN NODE-STO NODE-JOB NODE-LANE NODE-IDX NODE-GW NODE-ADM NODE-SPN NODE-DEX NODE-MESH NODE-GSP '
             'NODE-OPS NODE-RUN NODE-SEC CTR-GEN CTR-MTX CTR-TOK CTR-ACC CTR-DEX CTR-TND CTR-AS CTR-ZTH CTR-PQZ CTR-UA '
             'NET-ALL NET-EVM NET-HED NET-COS NET-SOR NET-SUI NET-APT NET-SOL NET-TON CLI-APP CLI-SGN INT-ERP INT-ODOO'.split())
rows, log = [], []


def load(name, ud=False):
    with open(SP + name, encoding='utf-8') as fh:
        for r in csv.DictReader(fh, delimiter='\t', quoting=csv.QUOTE_NONE):
            r = {k: (v or '').strip() for k, v in r.items() if k}
            if ud:
                if r['class'] != 'decision':
                    continue
                r = {'old': r['alias'], 'clause': '', 'topic': r['topic'], 'status': r['status'],
                     'superseded_by': r['superseded_by'], 'merge_into': r['merge_into'], 'owner': r['owner'] or 'yes',
                     'date': r['date'], 'target': r['target'], 'title': r['title'], 'note': r['note'], 'src': name}
            r['src'] = name
            rows.append(r)


for n in ['idmap-node.tsv', 'idmap-contracts.tsv', 'idmap-netcli.tsv', 'idmap-me.tsv']:
    load(n)
import os
if os.path.exists(SP + 'ud-units.tsv'):
    load('ud-units.tsv', ud=True)

# sanity
by = collections.defaultdict(list)
for r in rows:
    by[r['old']].append(r)
    if r['topic'] not in TOPICS:
        log.append(f"bad topic {r['topic']!r} for {r['old']} ({r['src']})")
    if r['status'] not in dc.STATUSES:
        log.append(f"bad status {r['status']!r} for {r['old']}")
missing = [i for i in inv if i not in by]
extra = [i for i in by if i not in inv]
if missing:
    log.append(f'NOT CLASSIFIED: {missing}')
if extra:
    log.append(f'NOT IN INVENTORY: {extra}')


def root(r, depth=0):
    m = r['merge_into']
    if not m or depth > 10:
        return r
    m0 = re.sub(r'\(.*\)$', '', m)
    cands = by.get(m0)
    if not cands:
        log.append(f"merge_into {m} of {r['old']} unknown")
        return r
    cl = m[len(m0):]
    c = [x for x in cands if x['clause'] == cl] or [x for x in cands if x['topic'] == r['topic']] or cands
    return root(c[0], depth + 1)


for r in rows:
    r['_root'] = root(r)
    rt = r['_root']
    if rt is not r and (rt['topic'], dc.STATUSES and rt['status']) != (r['topic'], r['status']):
        log.append(f"merge {r['old']}{r['clause']} -> {rt['old']}{rt['clause']}: topic/status {r['topic']}/{r['status']}"
                   f" forced to {rt['topic']}/{rt['status']}")
        r['topic'], r['status'] = rt['topic'], rt['status']


def order(r):
    at = inv.get(r['old'], 'zzz:0')
    f, l = at.rsplit(':', 1)
    return (f, int(l or 0), dc.natkey(r['old']), r['clause'])


nxt = collections.defaultdict(lambda: [1, 80])
for r in sorted([r for r in rows if r['_root'] is r], key=order):
    c = nxt[r['topic']]
    if r['status'] in ('current', 'open'):
        n = c[0]; c[0] += 1
        if n > 79:
            log.append(f"OVERFLOW current {r['topic']}")
    else:
        n = c[1]; c[1] += 1
        if n > 99:
            log.append(f"OVERFLOW superseded {r['topic']}")
    r['new'] = f"{r['topic']}-{n:02d}"
for r in rows:
    r['new'] = r['_root']['new']
    if r['_root'] is not r and r['_root']['target']:
        r['target'] = r['_root']['target']      # one entry, one normative home


def current_new(ref, seen=()):
    """new ids that carry old id `ref` (optionally clause-qualified) in force."""
    r0 = re.sub(r'\(.*\)$', '', ref)
    cl = ref[len(r0):]
    cands = [x for x in by.get(r0, []) if not cl or x['clause'] == cl] or by.get(r0, [])
    out = []
    for x in cands:
        if x['status'] in ('current', 'open'):
            out.append(x['new'])
        elif x['superseded_by'] and r0 not in seen:
            for s in re.split(r'[,;]\s*', x['superseded_by']):
                out += current_new(s.strip(), seen + (r0,))
    return out


for r in rows:
    if r['status'] == 'superseded':
        news = []
        for s in [x.strip() for x in re.split(r'[,;]\s*', r['superseded_by']) if x.strip()]:
            n = current_new(s)
            if not n:
                log.append(f"superseded_by {s!r} of {r['old']}{r['clause']} resolves to nothing current")
            news += n
        if not r['superseded_by']:
            log.append(f"{r['old']}{r['clause']} superseded without superseded_by")
        r['sup_new'] = ', '.join(dict.fromkeys(news))
    else:
        r['sup_new'] = ''

cols = ['old', 'clause', 'new', 'status', 'superseded_by', 'target', 'owner', 'date', 'title', 'defined_at',
        'superseded_by_old', 'note']
with open(SP + '../id-map.tsv', 'w', encoding='utf-8') as fh:
    fh.write('\t'.join(cols) + '\n')
    for r in sorted(rows, key=lambda r: (dc.natkey(r['old']), r['clause'])):
        vals = [r['old'], r['clause'], r['new'], r['status'], r['sup_new'], r['target'] if r['status'] in ('current', 'open') else '',
                r['owner'], r['date'], r['title'], inv.get(r['old'], ''), r['superseded_by'], r['note']]
        fh.write('\t'.join(v.replace('\t', ' ') for v in vals) + '\n')

cnt = collections.Counter(r['status'] for r in rows)
news = {r['new'] for r in rows}
per = collections.Counter(r['new'].rsplit('-', 1)[0] for r in rows if r['_root'] is r)
print('rows', len(rows), 'old ids', len(by), 'new ids', len(news), dict(cnt))
print('new ids per topic', dict(sorted(per.items())))
print('max numbers', {t: (c[0] - 1, c[1] - 1) for t, c in sorted(nxt.items())})
print('\n'.join(log))
