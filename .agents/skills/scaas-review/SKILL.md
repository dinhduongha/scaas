---
name: scaas-review
description: Use when preparing, running or fixing a review of a SCaaS spec, plan or code change (Fable, Codex, agy or Claude reviewers), or when asked to "review", "brief reviewers" or "check this branch" in the scaas repository.
---

# SCaaS review

The rule is [ARCH-POS-22](../../../docs/review.md): every review covers the 13 dimensions of `docs/review.md` §1, divided into
areas. This skill is the procedure; `docs/review.md` is the authority. If the current checkout lacks it, read it from the
integration branch: `git show origin/ua-rs-sign:docs/review.md`, or `origin/dev` once that branch is renamed.

**Words used below.**
- `<subject>`: the change's short name, usually its branch, e.g. `pqchat-treekem`.
- `<integration>`: the branch the change merges into (`ua-rs-sign`, later `dev`).
- Paths are relative to the repo root.

## Procedure

1. **Pin the tree and the scope.**
   - Create a detached, read-only worktree at the exact commit: `git worktree add --detach .claude/worktrees/<subject>-review <SHA>`.
   - Reviewers never read a moving branch.
   - The change is the diff from the merge base, never from `main` (from `main` it also counts every unmerged round on the
     integration branch): `git diff --stat $(git merge-base origin/<integration> <SHA>) <SHA>`.
   - The areas' files come from that list. Add the vectors and tests the change reads, since dimensions 8 and 12 need them.
2. **Make the directory.**
   - `scratchpad/<subject>-review-<YYYYMMDD-HHMM>/`, in local time. It is git-ignored and never pushed.
   - Reports and `STATUS.md` go there, never under a system temp directory or `docs/`.
3. **Copy the template mechanically**, then fill in every `<…>`. Never write a brief from scratch:
   `sed -n '/^````markdown$/,/^````$/p' docs/review.md | sed '1d;$d' > <dir>/BRIEF.md`.
4. **Choose the areas** (`docs/review.md` §2, §4):
   - one area per layer touched;
   - **cross-layer** when more than one layer is touched;
   - **cryptography** when crypto is touched: one primitive at a time through every implementation;
   - **adversarial** for crypto, value or access control.
5. **Fill the dimension table.**
   - All 13 rows stay in order.
   - Each row gets a lead area and the change-specific things to hunt.
   - A row may say `N/A: <reason>`; it is never deleted.
   - Rows 2 (cryptography) and 3 (security) are never N/A for contract code.
6. **List rulings.** Add the owner rulings not to reopen and the accepted risks, from `docs/decisions.md` (`owner: yes`) and the
   spec.
7. **Dispatch.** One reviewer per area, in parallel. The prompt is one line: "Read `<dir>/BRIEF.md`. Your area is `<X>`. Write
   `<dir>/<reviewer>-<X>.md`." Here `<reviewer>` is the tool in lower case (`fable`, `codex`, `agy`) and `<X>` is the area's
   letter, e.g. `fable-A.md`. Codex runs only when the owner asks, with the model and effort from its config.
8. **Collect.** Write `<dir>/STATUS.md`, one row per finding, in the §5 row format. Rule on each finding: fix, reject (with a
   reason), or ask the owner.
9. **Fix**, task by task, on a work branch.
   - Each new check gets its test **red first**, with the red line pasted in the commit, then a mutant.
   - Gates are sized to the change (AGENTS.md "Verify").
   - Update STATUS.md with the commit.

## Check before dispatch

| Check | Wrong if |
|---|---|
| Tree | it names a branch, not a commit and a worktree |
| Directory | it is not `scratchpad/<subject>-review-<ts>/` |
| Dimension table | it has fewer than 13 rows, or a row is missing its lead area |
| Areas | crypto is touched with no cryptography area; several layers are touched with no cross-layer area |
| Finding format | it lacks the dimension number or the rule id |
| Limits | it invents a time box or a scope the owner did not set |
| Machine rules | `capped` runs in the foreground, no background shells, testnet wallet never printed |

## Common mistakes

- **Spreading crypto across the layer areas.** One cryptography area reads the primitive vertically. This catches a bug class
  everywhere at once.
- **A brief limited to "design, security and crypto".** That leaves out performance, misuse, operations, privacy and failure
  handling.
- **Results in a system temp directory.** It is lost on reboot; `scratchpad/` in the repo is kept.
