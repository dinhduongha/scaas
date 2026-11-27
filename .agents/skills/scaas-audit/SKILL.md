---
name: scaas-audit
description: Use when starting, resuming or closing a round of the SCaaS AI audit (the pre-freeze audit, a non-EVM add-on audit, or the gate before mainnet), when the owner says Codex credits reset, or when relabelling code AI-AUDITED.
---

# SCaaS AI audit

The plan is `docs/audit/README.md`, the units are in `docs/audit/INDEX.md`, and the prompts are in `docs/audit/prompts/`. The
rules are ARCH-POS-14 and ARCH-POS-22. This skill is the procedure; on any difference, the README wins.

## Start a round

1. **Tag and worktree.**
   - The tag exists on `main`; record its full SHA.
   - Create the frozen, detached worktree `.claude/worktrees/audit-<TAG>`.
   - The ignored inputs must be real directories, not symlinks to another checkout: `vendor/` via `scripts/vendor.sh install`
     then `check` (unit `vendor-falcon-rs` reads it; `install` also links `smartcontracts/evm/lib/<name>` to the forge
     libraries in `vendor/`, the only links allowed), and `clients/clientkeys/node_modules`.
2. **Prompts.**
   - Copy `docs/audit/prompts/` to `scratchpad/ai-audit/run-<TAG>/`.
   - Fill in `<TAG>` and `<SHA>` there, and the tag's gate evidence.
   - The committed prompts keep their placeholders.
   - Finalize or mark every FRAME part.
3. **Ledger.**
   - Use `scratchpad/ai-audit/LEDGER.md`, which is local.
   - Its header holds the tag, the SHA, and each tool's **model and effort as read from its config at run time**. Never write a
     model from memory: the owner changes them.
   - It has one `queued` row per unit per tool.
4. **Run everything.**
   - **Fable, agy and Claude:** all units in parallel.
   - **Codex:** **all units too**, never a subset to save credits, one after another in the README's tier order (Running order).
     Before the first Codex run, do the free `codex sandbox` check.

## Tools, configs and invocation

| Tool | Model and effort come from | How a unit runs |
|---|---|---|
| Codex | `~/.codex/config.toml` (`model`, `model_reasoning_effort`) | read-only sandbox, from the main checkout's root, the filled prompt file as the prompt; no model or effort override |
| agy | `~/.gemini/antigravity-cli/settings.json` (the `antigravity:model` skill shows it) | `--print` with the filled prompt |
| Fable, Claude | the agent's model, as the harness reports it | one fresh read-only agent per unit, the filled prompt as its brief |

- Every prompt names the frozen worktree `.claude/worktrees/audit-<TAG>`. Reviewers read only there; the run itself starts from
  the main checkout's root.
- The gate evidence is the tag's closing-gate summaries: the `runs/*summary*` rows at `<SHA>`.
- "A unit with a Fable P0 or P1 goes first": before each Codex tier starts, read the Fable reports that exist. Units with a P0
  or P1 move to the front of that tier; the others keep the listed order.

## Resume, for example after "Codex credits reset"

- The next unit is the first one in tier order with no `done` row for that tool at that tag.
- A run stopped by credits is marked `aborted-credits` and reruns whole; partial output is not trusted.
- After each run, update its row: status, P0–P3 counts, date, result file.

## Results

- Results go to `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-<unit>.md`.
- Results, the ledger and the closure tables are local and never committed (owner 2026-11-24).
- If a tool's sandbox cannot write files, save its printed report under that name.
- Send any P0 to the owner at once.

## Close a round

1. **Adjudicate.** A fresh Fable agent checks every P0–P2 against the frozen tree; it did not write the reports it judges.
2. **Rule.** The owner rules on each finding.
3. **Fix and re-audit.**
   - Fixes go on `main` through PRs; every check is red first, then its mutant.
   - Only the units whose scope files changed rerun, reading the tag→fix diff plus the unit.
   - An unchanged unit keeps its result as "unchanged since `<SHA>`".
4. **Gates and label.**
   - Run the gates at the four sets, then update ARCH-POS-14's audit-rounds table.
   - Relabel the covered code `AI-AUDITED (<models of the round, from the ledger>)`. It is never "independent" or "external".
   - Code changed after its round is `UNAUDITED` again.

## Common mistakes

| Mistake | Correct |
|---|---|
| Codex runs only tier 1 "to save credits" | Codex runs all units in tier order (owner 2026-11-24) |
| Fable is left out, "for the owner to run" | Fable, agy and Claude run all units in parallel |
| A fixed model name from an old doc | the model is read from each tool's config and recorded in the ledger |
| Results under `docs/audit/results/` or a system temp directory | `scratchpad/ai-audit/results/` |
| Re-auditing everything after the fixes | only units whose scope changed, by diff |
| Using `ps` to find stuck runs | the rtk hook truncates `ps`; use `rtk proxy ps -eo pid,etime,args`, then kill by PID |
