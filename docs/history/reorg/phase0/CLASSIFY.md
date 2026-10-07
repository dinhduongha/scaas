# Ruling classification for the SCaaS docs reorg (Phase 0, id pre-allocation)

Repo: /home/dockers/odoo19/custom-addons/bamboo-dms/scaas (paths below are relative to its `docs/`).
Plan: `docs/history/plans/2026-10-07-docs-reorg.md` — read §1 (target file tree), §3.1–§3.2 (id scheme and
allocation defaults), §4 (conflicts K1–K24) and §8 (owner questions) before starting. The owner answered **every**
§8 question with its stated default on 2026-10-07.

Old docs are frozen under `docs/history/` (specs in `docs/history/specs/`, system spec `docs/history/SCaaS-2026-10-07.md`,
integration guide `docs/history/integration-2026-10-07.md`, plans in `docs/history/plans/`). Research is `docs/research/`.
Never read `bamboo_dms/docs/dms/`. Read-only: do not edit any repo file. No builds. Use `/usr/bin/grep` (not plain `grep`).

## Input

A TSV (path given in your task) with one row per old ruling id:
`old · defined_at (file:line under docs/) · default_topic (from plan §3.2) · plan_note · heuristic · text`
(`text` = the definition line, truncated; read the source for the full text).

## What to decide, per old id

Read the definition at `defined_at` in full. Then search for later changes: `/usr/bin/grep -n '<id>\b'` across
`docs/history/specs/*.md` and `docs/history/SCaaS-2026-10-07.md` — look especially at each spec's
"Superseded rulings and statements" / "bị thay" tables, "Rulings rev 1.1" tables, NI rev 3.x amendments,
SCaaS.md §0.1 "Superseded positions" and §15.3 contradictions. Decide:

1. **topic** — the new-id prefix: `ARCH-POS`, `NODE-{GEN,STO,JOB,LANE,IDX,GW,ADM,SPN,DEX,MESH,GSP,OPS,RUN,SEC}`,
   `CTR-{GEN,MTX,TOK,ACC,DEX,TND,AS,ZTH,PQZ,UA}`, `NET-{ALL,EVM,HED,COS,SOR,SUI,APT,SOL,TON}`, `CLI-{APP,SGN}`,
   `INT-{ERP,ODOO}` — the file that will define the rule (plan §1). Keep the §3.2 default unless reading the rule
   says otherwise (say why in `note`). `INT-ODOO` only for rules that are about the Odoo example itself.
2. **status** — `current` (still in force, possibly amended — the new text will be the amended one),
   `superseded` (replaced by a later ruling or owner decision), `withdrawn` (dropped, nothing replaces it),
   `open` (owner question with a default applied; e.g. NI interpretations I1–I8, plan Q2/K21).
3. **superseded_by** — for `superseded`: the old id(s) / alias(es) that replace it (comma-separated, e.g. `R87`,
   `R114`, `CR-PD-2`, `reorg:Q3`). Empty otherwise.
4. **clause splits** — if one ruling's clauses go to different topics, or one clause is superseded while the rest
   stays: one output row per clause, `clause` = `(a)`, `(b,c)`, `(cost)`, `(node)` … (short labels; letters when
   the source letters them). The union of clauses must cover the whole ruling; an unsplit ruling has `clause` empty.
5. **merges** — if this ruling states the same rule as another old id (plan §3.2 names some: `CR-PD-2`+`CR-R3-2`,
   `CR-PD-4`+`CR-R3-8`, `net-aptos:Ln`=`net-solana:Ln`, `R20`→`R95`): `merge_into` = the old id whose new id this row
   shares (that row has `merge_into` empty). Merged rows must have the same topic and status. A ruling that a later
   one **replaces** is `superseded`, not merged; a ruling a later one only **restates** (same rule, e.g. a
   qualified alias confirming an R-id) is merged.
6. **owner** — `yes` if the ruling (or the clause kept) is an owner ruling (marked `(owner)`, "owner:", owner
   answers tables, owner decision lists), else `no`. **date** — date of the text that is current (rev date of the
   amendment if amended), `YYYY-MM-DD`.
7. **target** — suggested normative home `<file>#<anchor-slug>` in the new tree (e.g. `node/job-api.md#call-table`,
   `contracts/metatx.md#digest`, `networks/ton.md#dex`); for superseded rows leave empty.
8. **title** — ≤ 8 English words naming the rule (for the decisions.md heading).
9. **note** — ≤ 30 words, only for non-obvious calls (topic changed, split/merge reason, which owner answer applied,
   conflict K-n resolution, "amended by Rx").

Owner answers that change statuses (2026-10-07, all = plan defaults): Q1/K1 call-table rows as proposed, factory
excluded; Q2/K21 NI I1–I8 = `open`; Q3/K2 TON domain binding = per-wallet domain set **CR-R3-7** (the R10-14
domain-in-init clause → superseded by `reorg:Q3`); Q4/K3 TON bounced payouts = **CR-R3-9** claim model (R10-17's
bounced/`RefundBounced` clause → superseded by `reorg:Q4`; its other clauses stay current); Q5/K16–K17 chain 7622 is
not a classical-Zether dev chain, production curve open; Q6/K18 Soroban stays job-API only (not on the mesh);
Q7/K19 second event source PLANNED; Q8/K20 OPS defaults approved as stated; K5 JWS/crypto library = `aws-lc-rs`
(R106a's `ring` clause → superseded by `R114`); K7 MESH text predating NI/A2 (standalone mode, `[odoo]`, R79,
`rusqlite`, `ring`) is superseded per NI §13.1 and A2 §18.1/§18.2.

## Output

Write `<output path given in your task>` as TSV with header
`old	clause	topic	status	superseded_by	merge_into	owner	date	target	title	note`
— every input id at least once, no tabs inside fields. Then reply with: counts by status and by topic, the list of
splits and merges, and every judgment call you were unsure of (one line each). Keep the reply under 60 lines.
