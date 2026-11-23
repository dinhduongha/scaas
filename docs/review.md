# Reviews: the dimensions and the areas

Status: **BUILT** as a process rule: every review brief since the TreeKEM code review uses it. A checker for the brief
is **PLANNED**.

<a id="ARCH-POS-22"></a>**ARCH-POS-22**: **a review covers every dimension below, divided into areas.**

- **Who decides.** The owner, 2026-11-24.
- **Briefs.** Every review brief names, for each dimension, the area that covers it, or says why the dimension does not
  apply. A dimension may never be dropped in silence.
- **What it applies to.** This holds for:
  - a spec review and a code review;
  - a review by Fable, Codex or agy;
  - the AI audit rounds of [ARCH-POS-14](decisions.md#ARCH-POS-14).
- **Reviewers.** Fable reviews every crypto spec and its code. Codex runs only when the owner asks.
- **Reports.** They go to `scratchpad/<subject>-review-<YYYYMMDD-HHMM>/`, one file per reviewer and area. The fixes are
  tracked there in `STATUS.md`.

**Contents**

1. [Dimensions](#1-dimensions)
2. [Areas](#2-areas)
3. [Brief and report](#3-brief-and-report)
4. [Scale](#4-scale)

## 1. Dimensions

Status: **BUILT**.

Each dimension lists what a reviewer looks for. The [rules that do not bend](../AGENTS.md#rules-that-do-not-bend) are
dimension 3, and no review skips them.

1. **Conformance.**
   - The code does what the spec and the owner rulings say, rule by rule (by id), and no more.
   - A rule marked BUILT has code and a test.
   - Code has a rule.
   - The code and the docs agree, including the status tags.
2. **Security and cryptography.**
   - Forgery, replay, signature and authorship.
   - Key schedule, domain separation, binding to the context.
   - Forward secrecy and post-compromise security claims.
   - What a removed or new party can learn.
   - Downgrade between modes or versions.
   - Constant time where a secret is used.
3. **Rules that do not bend.**
   - Never lose ciphertext.
   - No decryption oracle ([ARCH-POS-13](decisions.md#ARCH-POS-13)).
   - Explicit parameters.
   - Every `mtx*` call is relayable.
   - No EIP-7702.
   - No assumption about a chain.
   - Maximal support ([ARCH-POS-18](decisions.md#ARCH-POS-18)).
   - One rule on every chain.
   - Every RPC consumer takes a list of nodes ([ARCH-POS-15](decisions.md#ARCH-POS-15)).
   - The node is open.
   - Nothing deployed is upgraded.
4. **Secrets and privacy.**
   - A key, seed, plaintext or decrypted content must not leave its place: the vault, the arena, a `SecretBytes` handle,
     a binding, a log, `Debug` output or an error text.
   - Zeroizing.
   - Metadata a public observer learns from state, events, calldata, sizes or timing.
   - Business identifiers in clear ([ARCH-POS-17](decisions.md#ARCH-POS-17)).
5. **Robustness and denial of service.**
   - Every untrusted decode is bounded by length and by depth.
   - Gas and storage griefing.
   - An input that makes the state unusable for others.
   - Unbounded loops.
   - The block limit and the inclusion rule of EIP-8037.
   - Queue and backlog exhaustion.
6. **Failure handling.**
   - Everything fails closed, with a named error.
   - No partial state after a refusal.
   - Reentrancy.
   - Retries, reorgs and finality.
   - The node never reports `dead` while a transaction may still land.
   - Recovery from state alone.
7. **Consistency across languages and layers.**
   - The same bytes in every language: `clientkeys`, every `ua-*`, the SDK, the node and the contracts, all from the
     vectors.
   - Allow-lists equal to the contract's in both directions.
   - A record the contract accepts can be followed by clients, and the reverse; no fork.
   - A check present in one path is also present in its siblings.
8. **Contract specifics.**
   - The storage layout and its pins.
   - Typehash pins.
   - Module and library splits: DELEGATECALL storage, `this`, `msg.sender`, return data.
   - The size gate.
   - Gas pins that move with old → new figures.
   - Immutability and the factory catalogue.
9. **Performance and cost.**
   - Gas per entry, against the figures the docs quote.
   - Client CPU and memory, including wasm and mobile budgets.
   - RPC round trips.
   - Proof and verify time.
   - Storage growth over a long life.
   - Who pays.
10. **Interfaces and misuse.**
    - Is the API hard to misuse?
    - Prepare → review → sign shows every field.
    - Defaults are the safe choice.
    - Error codes are stable.
    - The CLI and the bindings match the SDK.
    - Changing a job shape needs an operator note.
11. **Tests.**
    - A test that cannot fail.
    - Every refusal has a positive twin.
    - Mutants cover every check, and the survivors are explained.
    - Vectors are checked by every reader.
    - Gates are sized to the change (AGENTS.md "Verify").
12. **Operations and the supply chain.**
    - Config holds no secret.
    - Logs and the metrics are useful and leak nothing.
    - New dependencies: their licence, `cargo deny` / `npm audit`, the size they add, the pins.
    - SPDX headers.
    - No machine path ([ARCH-POS-16](decisions.md#ARCH-POS-16)).
    - Nothing a secret scan of the push would hit.

## 2. Areas

Status: **BUILT**.

A review is divided into areas, one reviewer each. Every area applies all twelve dimensions within its scope.

- **One area per layer touched.** The layers are the contracts, `ua-rs` and the other signers, the SDK and its
  bindings, `clientkeys` with its generators and vectors, the node, and `pqz-core`. A big layer can be split.
- **One cross-layer area**, always when more than one layer is touched. It covers dimension 7 end to end: spec ↔
  contract ↔ clients ↔ node. It looks for places where two layers read the same rule differently.
- **One adversarial area**, always for crypto, value or access control. It plays every role against the whole change:
  - a malicious member or holder;
  - a malicious admin;
  - a relayer that refuses, delays or reorders;
  - an RPC node that lies;
  - a front-runner;
  - a party that has left or been removed.

  It tries to break each rule and to recover from state alone.

## 3. Brief and report

Status: **BUILT**.

The **brief** holds:
- the tree, at an exact commit and read-only;
- the area;
- the files to read;
- the owner rulings that are not to be reopened, and the accepted risks not to raise again;
- the dimension table of §1;
- the machine rules: runs go through `scripts/capped` in the foreground, with no background shell.

Each **finding** has:
- an id `<area>-<n>`;
- a severity:
  - P0: loss of a key or plaintext, a forgery, an oracle;
  - P1: a broken rule with security impact;
  - P2: a correctness or design defect;
  - P3: docs or tests;
- the location, `file:line`;
- the rule id it breaks;
- the dimension number;
- a concrete failure scenario;
- a fix in one or two lines.

Only verified findings count; a doubtful one is marked `UNSURE`, with what would settle it.

Each report ends with:
- what was read and what was not;
- a verdict: approve, approve with fixes, or rework.

**Fixes** go task by task. Every check gets its test red first, then a mutant. `STATUS.md` holds one row per finding
with its commit.

## 4. Scale

Status: **BUILT**.

- **A small change** (AGENTS.md "Verify": edit, one test, the touched gates) needs no review round.
- **A spec or a code change of one layer**: one area, plus the adversarial area if it touches crypto, value or access
  control.
- **A round across several layers**: one area per layer, plus the cross-layer area, plus the adversarial area.
- **The pre-freeze audit**: the same areas over the whole scope of [ARCH-POS-14](decisions.md#ARCH-POS-14).
