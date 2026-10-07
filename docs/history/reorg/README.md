# history/reorg — reorganization ledgers (frozen after Phase 2)

Plan: `docs/history/plans/2026-10-07-docs-reorg.md`. Phase 0 output, edited in Phases 1–2, moved here from `docs/_work/` at the end of Phase 2 (the register fragments `decisions-*.md` were merged into `docs/decisions.md` and removed). `scripts/docs_check.py` reads these files for C1 (pre-register), C7 and `facts check`/`facts trace`; Phase 4 reviewers use them as their work list.

| File | What | Who edits |
|---|---|---|
| `id-map.tsv` | Every old id → pre-allocated new id. Columns: `old · clause · new · status · superseded_by` (new ids) `· target` (suggested normative home) `· owner · date · title · defined_at · superseded_by_old · note`. Several rows with the same `new` = one register entry (merge); one `old` on several rows = a clause split. | Phase 1 agents may add rows for new ids (next free number in their own prefixes) and correct `target`/`title`; never renumber. |
| `facts/<source>.tsv` | Fact ledger (§6.3): `fact_id (file:line under docs/) · section · kind · excerpt · keys · disposition · hint`. `disposition` is a section default from `section-map.tsv` (or, for ruling lines, the id map); `hint` is the plan §2 target text. Empty disposition = the writer decides. | Each Phase 1 agent edits the dispositions of facts that land in its area. `facts extract` keeps edited dispositions (`--reset` recomputes everything). |
| `section-map.tsv` | Plan §2 / §2.5 / §2.6 tables as data: `source · sec` (section numbers, ranges, or `~regex` on heading titles) `· default · target_text`. | Rarely; rerun `facts extract` after a change. |
| `phase0/` | Classifier outputs and the one-off scripts that produced `id-map.tsv` (`allocate.py`) and `section-map.tsv` (`secmap.py`); `ud-units.tsv` = every `_USER-DECISIONS.md` unit incl. findings. | Nobody (provenance). |

Disposition values: `target:<file>#<anchor>` (several joined with `;`), `superseded:<new id>`,
`history:{review,revision,streams,execution-log,amendments-executed,research-finding,estimate,superseded-measurement,duplicate-of:<fact_id>}`,
`history:H` (plan §2 says "H": confirm or replace with a precise class), and for `history/blockchain.md` also
`rejected:<new id>`, `open:<new id>`, `out-of-scope:<new id>`.

Commands: `python3 scripts/docs_check.py resolve R91` · `check --area node|contracts|netcli` ·
`facts check --area …` · `facts trace history/blockchain.md`.
