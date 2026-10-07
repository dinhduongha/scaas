# Mining `_USER-DECISIONS.md` into the id map (SCaaS docs reorg, Phase 0)

Repo: /home/dockers/odoo19/custom-addons/bamboo-dms/scaas. Source: `docs/research/_USER-DECISIONS.md` (2 705 lines,
Vietnamese, the owner's decisions + findings from code; line numbers include the 2-line banner at the top).
Plan: `docs/superpowers/plans/2026-10-07-docs-reorg.md` — read §2.6 (row `_USER-DECISIONS.md`), §3.1–§3.2 (id scheme;
the last row of the §3.2 table is about UD units) and §8 Q14 (owner answered: UD decisions later replaced by specs are
recorded as **superseded owner rulings**, not re-opened; remaining **unruled** UD items become `open` entries).
Current rulings live in the frozen specs `docs/history/specs/*.md` and `docs/history/SCaaS-2026-10-07.md`
(ids `R1…R349`, `RS2-*`, `RS5-*`, `CR-*`, …; `docs/history/ruling-ids.txt` lists every old id with its definition
line). Read-only: do not edit repo files. Never read `bamboo_dms/docs/dms/`. Use `/usr/bin/grep`.

## Task

Read `_USER-DECISIONS.md` fully. Split it into **units**: every `##`/`###` section that states a choice (decision)
or a finding. For each unit decide:

- `alias` — `UD:§<n>` with the section number as written (`UD:§3.2`, `UD:§3.4b`, `UD:§12.7.3`, `UD:§24.1`); a
  section without a number gets its parent's number plus a short suffix (`UD:§15:D14`, `UD:§10:fee-tiers`). If the
  unit is one of the canon D-decisions (§15 D1/D2/D7/D12/D14/D17, §14/§17/§19 D1 history), add a second row with
  alias `canon:D<n>` (`merge_into` = the `UD:` alias of the unit that states its current form).
- `line` — heading line number.
- `class` — `decision` or `finding` (pure findings: §7 code findings, §8 Grok conversation, §9 environment, and
  any analysis that rules nothing).
- `status` — for decisions: `current` (still the rule; no spec ruling states it), `superseded` (a later spec
  ruling or a later UD section replaced it — e.g. §5 "wildcard, no mode bitmask" → §24 keep `mode`; §23 `[odoo]`
  control plane → NI `R87`; §18 genesis of chain 9000 → `owner:2026-10-07:chain-7622`), or `open` (an unruled
  item the owner left open, e.g. §3.3 tiered-fee leakage, §22.10 "còn phải quyết"). For findings: `history`.
- `merge_into` — if a spec ruling **restates** this decision (same rule), the old id it restates (e.g. `R2`,
  `RS2-9`, `R135`); the unit then shares that ruling's new id. Leave empty if it needs its own entry.
- `superseded_by` — for `superseded`: old id(s) / alias(es) that replace it.
- `topic` — new-id prefix per plan §3.1/§3.2 (fees → `CTR-MTX`; Zether → `CTR-ZTH`; relayer/mesh →
  `NODE-MESH`/`NODE-GSP`; one binary → `NODE-GEN`; factory → `CTR-TOK`; first chain private → `NET-EVM`; …).
  Empty for findings.
- `owner` — `yes` for decisions (it is the owner's file), `no` for findings. `date` — the date stated in or near
  the unit (`YYYY-MM-DD`), else `2026-08-31` (the file's last dated edit; check the text).
- `target` — for `current`/`open`: suggested normative home `<file>#<anchor>` in the new tree (plan §1); empty
  otherwise. `title` — ≤ 8 English words. `note` — ≤ 30 words for non-obvious calls (which ruling restates or
  replaces it, why open).

Be precise about `merge_into` vs `superseded_by`: grep the specs for the concept before deciding; most decisions
should turn out to be restated by a spec ruling (merge) or replaced (superseded). Only a decision no spec covers is
`current` with its own entry.

## Output

Write `/tmp/claude-1000/-home-dockers-odoo19-custom-addons-bamboo-dms/4f1b7683-90d3-4f8a-97be-41d1bd9848db/scratchpad/ud-units.tsv`
with header `alias	line	class	status	merge_into	superseded_by	topic	owner	date	target	title	note`
(no tabs inside fields), covering every `##`/`###` section of the file (findings included, so the fact ledger can
default them). Reply with counts by class/status, the list of `current` and `open` units, and doubtful calls
(one line each), under 50 lines.
