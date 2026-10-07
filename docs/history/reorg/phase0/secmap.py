import re, csv, collections
L = open('/home/dockers/odoo19/custom-addons/bamboo-dms/scaas/docs/history/plans/2026-10-07-docs-reorg.md', encoding='utf-8').read().split('\n')
s = next(i for i,l in enumerate(L) if l.startswith('## 2. Source map')); e = next(i for i,l in enumerate(L) if l.startswith('### 2.4 '))
FILES = {'2.1': ['SCaaS-2026-10-07.md'], '2.2': ['integration-2026-10-07.md']}
NET = {f: f'2026-10-0{"4" if f in ("aptos","solana") else "3"}-net-{f}.md' for f in ['hedera','cosmos','soroban','sui','ton','aptos','solana']}
def default(t):
    t0 = t.strip()
    paths = re.findall(r'(?<![\w/])((?:node|contracts|networks|clients|history)/[\w<>.-]+|integration|architecture|README|decisions)(?:#([\w<>-]+))?', t0)
    out = []
    for p, a in paths:
        if p.startswith('history/'): continue
        f = p if p.endswith('.md') else p + '.md'
        out.append(f'target:{f}' + (f'#{a}' if a else ''))
    if out: return ';'.join(dict.fromkeys(out))
    if paths: return 'history:H'
    if re.match(r'^(H, D|admin)', t0): return ''
    if re.match(r'^D\b', t0) or 'decisions' in t0 or '→ D' in t0: return 'target:decisions.md'
    if re.match(r'^T\b', t0): return 'history:streams'
    if re.match(r'^X\b', t0): return 'history:amendments-executed'
    if re.match(r'^H\b', t0): return 'history:H'
    return ''
rows = []
cur = []
for i in range(s, e):
    l = L[i]
    m = re.match(r'^#{3,4} (.*)', l)
    if m:
        h = m.group(1)
        if h.startswith('2.1 '): cur = FILES['2.1']
        elif h.startswith('2.2 '): cur = FILES['2.2']
        elif 'Network specs' in h: cur = ['NET']
        elif h.startswith('`2026-10-03-zether-design.md`'): cur = ['ZD']
        else:
            fs = re.findall(r'`([^`]+\.md)`', h); cur = [f.split('/')[-1] for f in fs]
        continue
    if not cur or not l.startswith('|') or re.match(r'^\|[\s:|-]+\|$', l) or l.startswith('| §') or l.startswith('| Spec §'): continue
    cells = [c.strip() for c in l.strip().strip('|').split('|')]
    if cur == ['NET']: continue
    sec, label, target = (cells + ['', '', ''])[:3] if len(cells) >= 3 else (cells[0], '', cells[-1])
    files = cur
    if cur == ['ZD']:
        m2 = re.match(r'(ZD|Limits|ConsenSys-max)\s+(.*)', sec)
        if not m2: print("ZDFAIL", repr(sec), l[:80]); continue
        files = [{'ZD': '2026-10-03-zether-design.md', 'Limits': '2026-10-05-zether-limits.md', 'ConsenSys-max': '2026-10-05-zether-consensys-max.md'}[m2.group(1)]]
        sec = m2.group(2)
    sec = re.sub(r'(\d)\s+intro', r'\1', sec)
    for f in files:
        rows.append({'source': f, 'sec': sec, 'label': label, 'target_text': target, 'default': default(target)})
# network specs: keyword rows + family-specific
NETROWS = [
 (r'bài học|lessons', 'networks/README#design-lessons', 'target:networks/README.md#design-lessons'),
 (r'cần từ|needed from', 'H (executed)', 'history:amendments-executed'),
 (r'câu hỏi mở|open question|quyết định owner|owner decision', 'D', 'target:decisions.md'),
 (r'kết quả thực thi|execution result', 'H', 'history:execution-log'),
 (r'ruling|quy tắc node chung', 'D; texts per §3.2', 'target:decisions.md'),
 (r'^(\d+\.\s*)?(nguồn|sources|tham khảo|references)', 'networks/<family>#references', 'target:networks/<f>.md#references'),
 (r'odoo|portal', 'integration#families + example; clients/signers-clientkeys#connectors', 'target:integration.md#families;target:clients/signers-clientkeys.md#connectors'),
 (r'kiểm thử|\btests?\b|devnet|vector', 'networks/<family>#conformance', 'target:networks/<f>.md#conformance'),
 (r'thanh toán bảo mật|confidential|zether', 'contracts/zether#families', 'target:contracts/zether.md#families'),
 (r'rủi ro|risk|\bgaps?\b|seam|khoảng trống|hạn chế|limitation', 'networks/<family>#limitations', 'target:networks/<f>.md#limitations'),
 (r'payload|metaop|chữ ký|signature|passkey|ký\b', 'networks/<family>#payload, #signatures', 'target:networks/<f>.md#payload;target:networks/<f>.md#signatures'),
 (r'relayer|adapter|phí|\bfees?\b|khoá|keys|simulat|submit|crash|finality|event|indexer|cấu hình node|node config|head-of-line', 'networks/<family>#relayer (node-common rules stay in node/*)', 'target:networks/<f>.md#relayer'),
 (r'contract|object|account|instruction|lane|mandate|dex|admin|hợp đồng|program|module|package|token', 'networks/<family>#contracts (+ #dex, #mandate)', 'target:networks/<f>.md#contracts'),
 (r'phạm vi|scope|tóm tắt|summary|quyết định|decisions|^\s*0\.', 'networks/<family>#overview', 'target:networks/<f>.md#overview'),
]
SPEC = {'hedera': [('5', 'networks/hedera#relayer + README head-of-line row (R6-1)', 'target:networks/hedera.md#relayer;target:networks/README.md#head-of-line'),
                   ('7', 'networks/hedera#hts', 'target:networks/hedera.md#hts'), ('10', 'networks/hedera#wrappers', 'target:networks/hedera.md#wrappers')],
        'soroban': [('1.2', 'networks/soroban#payload (R8-1)', 'target:networks/soroban.md#payload')],
        'sui': [('2.1', 'networks/sui#signatures (flags)', 'target:networks/sui.md#signatures')],
        'solana': [('2.4', 'networks/solana#write-locks (RS12-2)', 'target:networks/solana.md#write-locks'), ('3.6', 'networks/solana#tokens', 'target:networks/solana.md#tokens'), ('5.5', 'networks/solana#toolchain', 'target:networks/solana.md#toolchain')],
        'aptos': [('3.2', 'networks/aptos (balances)', 'target:networks/aptos.md'), ('3.3', 'networks/aptos (keys/guardian)', 'target:networks/aptos.md'), ('4.2', 'networks/aptos (signMessage envelope)', 'target:networks/aptos.md')],
        'ton': [('3.4', 'networks/ton (escrow DEX)', 'target:networks/ton.md#dex'), ('3.5', 'networks/ton (passkey)', 'target:networks/ton.md#signatures'), ('4', 'networks/ton (anti-lock)', 'target:networks/ton.md')]}
for fam, f in NET.items():
    for sec, tt, dd in SPEC.get(fam, []):
        rows.append({'source': f, 'sec': sec, 'label': 'family-specific (§2.3)', 'target_text': tt, 'default': dd})
    for rx, tt, dd in NETROWS:
        rows.append({'source': f, 'sec': '~' + rx, 'label': 'network pattern (§2.3)', 'target_text': tt.replace('<family>', fam), 'default': dd.replace('<f>', fam)})
# label rows (non-numeric §) -> regex on heading titles, hand-mapped
LABEL = {('2026-10-03-blockchain-payments-addendum-wallets.md', 'Rulings, CR-ADW-1…4'): r'^(rulings?|ruling)\b|quyết định',
         ('2026-10-03-blockchain-infrastructure-service.md', 'intro, comparison IaaS/BaaS/blockchain service'): r'iaas|so sánh',
         ('2026-10-03-blockchain-infrastructure-service.md', 'Owner ruling (CR-R3-11 restated)'): r'owner ruling',
         ('round3-wallet-signing-formats.md', 'Rulings CR-WSF-1/2'): r'^rulings$',
         ('round3-wallet-signing-formats.md', 'Signing-domain inputs per family (M4)'): r'signing-domain',
         ('round3-wallet-signing-formats.md', 'Passkey format (M2)'): r'passkey format',
         ('round3-wallet-signing-formats.md', 'Aptos and Solana (L3)'): r'aptos and solana',
         ('2026-10-06-node-independence-design.md', 'header'): None, ('SCaaS-2026-10-07.md', 'header, status tags'): None,
         ('2026-10-06-tender-sponsorship-shredding.md', 'header table of NI amendments'): None,
         ('2026-10-06-pq-zether-design.md', 'header source table'): None,
         ('2026-10-06-node-independence-design.md', 'header (rev notes)'): None,
         ('2026-10-03-blockchain-infrastructure-service.md', 'Claude review 1, superseded, amendments, streams, revisions'): None}
out = []
for r in rows:
    if not r['sec'].startswith('~') and not re.match(r'^([A-Z]\d*(\.|$|\s|,)|[A-Z]\d|\d)', r['sec']):
        k = (r['source'], r['sec'])
        if k in LABEL:
            if LABEL[k] is None: continue
            r['sec'] = '~' + LABEL[k]
        elif r['sec'].startswith(('Review', 'admin', 'Superseded')):
            continue    # admin: handled by the ADMIN keyword classes in docs_check.py
        else:
            print('UNMAPPED LABEL', k, r['target_text'][:60]); continue
    out.append(r)
# collapse duplicate (source, sec): first default wins, hints joined
col = collections.OrderedDict()
for r in out:
    k = (r['source'], r['sec'])
    if k in col:
        col[k]['target_text'] += ' || ' + r['label'] + ': ' + r['target_text']
    else:
        r = dict(r); r['target_text'] = (r['label'] + ': ' if r['label'] else '') + r['target_text']; col[k] = r
with open('/home/dockers/odoo19/custom-addons/bamboo-dms/scaas/docs/_work/section-map.tsv', 'w', encoding='utf-8') as fh:
    w = csv.DictWriter(fh, ['source', 'sec', 'default', 'target_text'], delimiter='\t', extrasaction='ignore', lineterminator='\n')
    w.writeheader()
    for r in col.values(): w.writerow({k: r[k].replace('\t', ' ') for k in ['source', 'sec', 'default', 'target_text']})
print(len(col), 'rows;', collections.Counter(r['source'] for r in col.values()))
nodef = [r for r in col.values() if not r['default']]
for r in nodef: print('NODEFAULT', r['source'][:40], r['sec'], '|', r['target_text'][:90])
# --- blockchain.md (§2.5 hints, no default: Phase 1/2 dispose), HANDOFF-blockchain, RS4 plan
L2 = L[next(i for i,l in enumerate(L) if l.startswith('### 2.5 ')):next(i for i,l in enumerate(L) if l.startswith('### 2.6 '))]
hint = collections.OrderedDict()
for l in L2:
    if not l.startswith('| ') or l.startswith('| blockchain.md part'): continue
    c = [x.strip() for x in l.strip().strip('|').split('|')]
    part = c[0]
    key = ('~^TOKEN$' if part.startswith('TOKEN') else '~^BLOCKCHAIN$' if part.startswith('BLOCKCHAIN') else
           '6.21' if part.startswith('6.21') else '~CHƯƠNG 10' if part.startswith('Ch.10') else
           '10.2.2–10.2.6' if part.startswith('10.2.2') else '~CHƯƠNG 14|14.2.8' if part.startswith('14.2.8') else
           'D' if part.startswith('Appendix D') else re.match(r'(10\.\d(?:\.\d)?)', part).group(1))
    hint.setdefault(key, []).append(f'{part}: {c[2]}')
    if part.startswith('10.1 (3), 10.3 (2)'): hint.setdefault('10.3', []).append(f'{part}: {c[2]}')
if '10.1' in hint: hint['10.1'] = hint.pop('~CHƯƠNG 10', []) + hint['10.1']
with open('/home/dockers/odoo19/custom-addons/bamboo-dms/scaas/docs/_work/section-map.tsv', 'a', encoding='utf-8') as fh:
    w = csv.writer(fh, delimiter='\t', lineterminator='\n')
    for k, v in hint.items():
        w.writerow(['blockchain.md', k, '', ' || '.join(v).replace('\t', ' ')])
    w.writerow(['blockchain.md', '~CHƯƠNG 10', '', 'Ch.10 intro: architecture#components'])
    for sec, dflt, tt in [
        ('1', 'history:streams', 'owner/operator gates O1-O11: items in scaas/TODO.md §2; standing production rules -> node/runbooks#production-gates'),
        ('2', 'history:streams', 'scheduled, not built: scaas/TODO.md'),
        ('3', 'history:H', 'merge with the territory branch (client-repo coordination): history only'),
        ('4', 'target:contracts/README.md#unaudited;target:contracts/zether.md#safety-gate', 'Zether gates Z1-Z6: UNAUDITED rule -> contracts/README#unaudited, contracts/zether#safety-gate; tasks -> scaas/TODO.md')]:
        w.writerow(['HANDOFF-blockchain.md', sec, dflt, tt])
    w.writerow(['2026-10-03-r3-passkey-seed.md', '~^task$', 'history:execution-log', 'implementation tasks of BUILT work: history'])
    w.writerow(['2026-10-03-r3-passkey-seed.md', '~quyết định thiết kế', 'target:decisions.md', 'RS4 rulings (texts per plan §3.2: CTR-ACC / CLI-SGN / INT-ODOO)'])
print('blockchain hints', list(hint))
