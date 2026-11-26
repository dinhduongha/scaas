# AI audit prompt, unit `evm-dex-gov` (DRAFT, 2026-11-16)

Contracts audit at the pre-freeze target (owner rulings 2026-11-12: pre-freeze -> audit -> audit fixes -> freeze). This file is
self-contained: run it as it is, with any tool (Codex, agy, a Claude workflow, Fable, ...). Placeholders the controller fills
before the run: `<TAG>`, `<SHA>`.

## 1. Role and limits

You are one AI reviewer of the SCaaS contracts audit. The audit is an AI audit (decision ARCH-POS-14): reports name the tool and
model that wrote them. Everything under audit is `UNAUDITED`. Nothing is live with value; every chain is test-only.

**STRICTLY READ-ONLY.** Allowed: reading files; `git -C T log | show | diff | grep | blame | rev-parse`; `grep` / `rg` / `sed -n` /
`cat`; `python3 scripts/docs_check.py resolve <id>` (it only prints). Not allowed: any build, test, fuzz, benchmark, gas or timing
run (`forge`, `cargo`, `npm`, `dotnet`, `anvil`, `docker`, `gate.sh`, `at-set.sh`, which rewrites `PqzSet.sol` in place); any
edit, file creation (except the one result file below), deletion, commit, checkout, stash or push; any network access to a
chain or RPC. The machine runs other heavy jobs: a large build here gets the terminal killed.

## 2. Target

- Run from the root of the main checkout of the SCaaS repository (public).
- Code under audit: the detached worktree `.claude/worktrees/audit-<TAG>` at tag `<TAG>`, commit `<SHA>`. Below, `T/` means that
  directory. Read code and docs **only** under `T/`; the main checkout's own tree may be on another branch.
- First step: `git -C .claude/worktrees/audit-<TAG> rev-parse HEAD` must print `<SHA>`. If it does not, stop and write only that.
- Prior reports named below live in the main checkout's `scratchpad/` (git-ignored, local; not under `T/`).
- The whole unit is in scope, including code that did not change since an earlier review.

## 3. Result file

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-evm-dex-gov.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.2-astra-high-evm-dex-gov.md`, `20261120-09-agy-gemini-4-argon-high-evm-dex-gov.md`). Use the tool's
  configured model and effort (read from its config at run time; the owner may change any reviewer's model); do not
  override them. Name that model in the report's title line; the ledger records it. The unit name is always last.
- If your sandbox cannot write files, print the whole report as your final message; the runner saves it under that name.

## 4. Which source wins

1. Owner rulings: entries in `T/docs/decisions.md` with `owner: yes`, and their dated `Change` lines. They override code that has
   not caught up: **a difference between code and an owner ruling is a finding against the code.**
2. Component docs: `T/docs/contracts/`, `T/docs/clients/`, `T/docs/node/`, `T/docs/networks/`, `T/docs/integration.md`.
3. Code, for pinned byte formats only; `T/smartcontracts/vectors/` is the authority for bytes.
4. `T/docs/history/`; 5. `T/docs/research/`: background only.

`T/docs/decisions.md` is about 1.8 MB: search it by rule id (`### CTR-UA-37`, `<a id="...">`), never read it whole. An old id in a
comment resolves with `python3 scripts/docs_check.py resolve <id>`. Follow a stated rule as stated; do not propose reopening it.

## 5. Absolute rules (a break of any one is at least P1)

1. **Never lose ciphertext.** PQZ and Zether ciphertexts stay in contract state, never only a hash plus calldata or events (logs
   and history expire; state does not).
2. **No decryption oracle** (ARCH-POS-13). Nothing decrypts a ciphertext someone else chose and leaks anything about the result
   (a revert, a status, an error code, a timing, a signed verdict). Scoped exceptions are under section 7.
3. **Explicit parameters** (CTR-MTX-28, CTR-MTX-29, CTR-UA-36). Named, typed parameters and typed EIP-712, one entry point per
   operation; no packed `bytes` holding several fields, no hex bundles. Only a single crypto object stays `bytes` (a proof, a
   ciphertext, a key, a signature). Node JSON uses named fields; the old hex forms are refused (`HEX_ARGS_REFUSED`,
   `HEX_DATA_REFUSED`).
4. **Every state-changing `mtx*` is relayable**, with a fee of 0 too. A relayer can refuse or delay, never forge or alter.
5. **No EIP-7702.** An EOA signs with its own key and runs no code; a 7702 delegate never authorises (no ERC-1271 through it) and
   a delegated caller is refused (CTR-UA-24 and its Change of 2026-10-30, NET-EVM-07).
6. **No assumption about a chain:** no gas price 0, no block gas limit of ours; the PQZ / ML-DSA precompiles may ship to customer
   chains. **One rule on every chain:** never a rule split by L1, L2 or chain kind.
7. **EIP-8037 inclusion:** a transaction fits only if its regular gas plus its state gas fit the block gas limit;
   `gas_used = max(...)` is accounting, not inclusion. Do not conclude from it that a large deploy or call fits.
8. **EIP-7825 cap:** regular gas per transaction is at most 2^24 = 16,777,216 on Osaka and later (Nethermind enforces it, in
   `eth_call` too). forge / anvil 1.8.5 do not enforce it by default, so a path that is green in `forge test` above 2^24 fails on
   a chain (example found 2026-11-15: pure-Solidity ML-DSA-65 verify on an uncached key, about 19.0 M).
9. **Nothing deployed is upgraded.** Contracts are immutable; versions live in the factory's catalogue.
10. **Authorization lives in contracts.** Off-chain checks are extra, never the only guard. Fail closed: a refusal, a named error,
    zero sends.
11. **Zether is not PQZ** (separate systems, separate rules); **NEAR is not Algorand**.

A green gate is not evidence of soundness: three P0s in this repository sat behind green tests. Do not trust a test because it
passes; check that a negative test can fail. When you find a transcript, statement, digest or signature bug, check the same class
everywhere it can recur (C, Rust, wasm32, generic and specialised verifiers, Solidity, clients) and list each place.

## 6. Threat model

Attackers: any EOA or contract; a relayer (may refuse or delay, must never forge or alter); a front-runner; a colluding key holder
or `msig` member; a malicious token, DEX, executor, verifier or factory caller; a role holder exceeding its grant; a replayer
across chain id, `chainUid`, registry generation, token, release, kind, operation or nonce lane; a chain whose gas, block limit or
precompiles differ from the SCaaS testnet. Goals: forgery, theft, an unbacked mint, a leak of amounts or balances, a permanent
lock, replay, griefing that blocks others, a call that cannot fit a block (EIP-8037, EIP-7825). Prefer a concrete call sequence
to a pattern match. Across units: every optimisation that replaced code with shared code, a library or a module (DELEGATECALL)
must keep behaviour; say so when it does not.

## 7. Do not report (accepted by the owner; skip unless the code does something worse than the accepted behaviour)

- **Hybrid wrapped tokens:** a minter may mint unbacked units and unwrap them against the reserve users deposited (CTR-GOV-30,
  CTR-TOK-05 "not claimed on a hybrid"; owner 2026-11-13, USDC -> VND CBDC).
- **`BURNER`:** holders cannot stop a user sending to an unspendable address (not a burn; CTR-GOV-29).
- **Own-key `OFFCHAIN` PQZ token** (`pqzOwnKey = true`, `pqzOpening = false`): whoever can make that token's verifier sign can
  recover that token's key; the risk lies in that token only (ARCH-POS-13 Change 2026-11-13, CTR-PQZ-37).
- **The hybrid KEM** (ML-KEM-1024 + X25519, IND-CCA by its combiner): a decapsulation of a sender-chosen ciphertext and its
  one-shot AEAD are outside ARCH-POS-13 (Change 2026-11-13). Still report any PQZ or Zether key applied to a value that was
  not first shown well formed by re-encryption and byte comparison.
- **Shared-key `OFFCHAIN` class (class 2):** `msig` refused and op 7 unsupported at first; the auditor guarantee as ruled (an
  honest recipient cannot spend an unreadable credit; collusion leaves a named unreadable leg) (three-key spec, Q8 / Q9).
- **CTR-DEX-19:** `dex` must be a contract, nothing more; a contract made to look like a DEX can report any fill and take the
  signed amount (owner-accepted residual risk).
- **CTR-TOK-31:** R10 Sybil on the net wrap / unwrap rule; Q17 (a) the shielded id of a confidential kind is not always the
  public id (disclosed).
- **Classical Zether:** handing `s` over opens every leg, decoys included (CTR-ZTH-37); the sender may leave the auditor out of
  one transfer (CTR-ZTH-42); `fund` burns public Zether units from the caller (CTR-ZTH-35).
- **`msig`:** one with no `pop` is unusable until enough weight accepted, on each registry (CTR-UA-37).
- **`fndsa1024`:** built on the Falcon round-3 specification v1.2, the FIPS 206 risk accepted (CTR-UA-40 Q1).
- **`PqChat`:** a member can take the slot first and make the admin rekey again (CTR-CHAT-09, O2); what an open topic accepts
  cannot be removed, and its state-gas cost per KiB is accepted (CTR-CHAT-16, D20).
- **`OPERATOR_TRANSFER` / grants:** a `WHOLE` holder is unbounded by design (CTR-GOV-20).
- **PQZ rollover floor C0-6** of the 2026-10-26 review: accepted, spec corrected (CTR-PQZ-08 (a)).
- **Sizes and deploy gas:** the code-size ceiling is 64 KiB (Amsterdam / Glamsterdam is required on every chain, NET-EVM-06):
  never report the old 24 KiB limit. `WrappedToken`, `WrappedRegulatedToken` and the confidential regulated releases miss 60 / 70 M
  public blocks and deploy where the block takes them (owner 2026-11-05). Report a size only if it breaks EIP-8037 / EIP-7825 on
  a path a user must take.
- **Gas prices:** the schedule's provisional rows and calibration figures are the owner's (no timing runs here).
- The `UNAUDITED` label itself, Vietnamese source comments, style, naming, gas opinions that break no rule.
- Findings an earlier report below lists as fixed: report them only if the fix is wrong, incomplete or undone since; findings a
  triage marked REJECT or accepted (the ledgers named below): skip unless you have new evidence.

## 8. Your unit: `evm-dex-gov`

The DEX (settlement, liquidity, executors, position readers), the trade library, and governance (roles, grants, the router, rescue).

**Scope (paths under `T/`):**
- `smartcontracts/evm/src/dex/` (incl. `uniswap/`), `src/trade/`
- `smartcontracts/evm/src/governance/`

**Specifications and rules to read first:**
- `T/docs/contracts/dex.md` (CTR-DEX-*), `T/docs/contracts/settlement.md`; decisions CTR-DEX-13, -15, -19, -25, -26, -30 and the 2026-11-12 DEX rulings (open markets, `CLOSED_MARKETS` default off, settle by outcome)
- governance: decisions CTR-GOV-01 to -33 (identity by UA `bytes32`, bit bands 0-127 SCaaS and 128-255 customer with none refused, one `GovernanceRouter` per chain, CTR-GOV-25 rescue, -28 `chainUid`, -29 `BURNER`, -30 supply caps, -31 `AUDITOR`, -32 router versions, -33 G1: one router for every registry generation); CTR-UA-73

**Invariants to check (beyond section 5):**
1. Settle by outcome: each recipient's own delta >= its signed floor, the seller's debit <= the fill, pay out what arrived pro rata; refunds and `restorePulled` with EIP-1153 transient state; approve reset; executor trust (`UniswapExecutor` returns unspent `tokensOut`).
2. Typed orders and cancels (EIP-712, nonces, invalidation), the liquidity order (CTR-DEX-30), the p256 / webauthn verify cap 400,000; `DexPuller` only pulls what was signed.
3. Governance: two-step admin transfer; grants with terms (min / max / total / perWindow + window / maxUses / validUntil / delegable narrower) enforced on every use; `grantDelay`; `disableFeature` one-way; `renounceRole` and every direct admin or role-holder entry carry `chainUid` (`acceptAdmin` without); router ops bind the target, op and word.
4. `RescueVault`: two roles, a chain-neutral owner change with a sequence number, the CREATE2 deployer address; `rescue(asset)` moves only to the constant.
5. **The G1 router and its keyed cancel** (added 2026-11-26; CTR-GOV-32, -33, CTR-UA-73; G-7 of the re-review):
   `GovernanceRouterBase` names the chain's `OpenFactory` (`factory()`, immutable); a derived signer's op is checked on
   `registryFor(target)` (the env registry the factory wrote into a clone it made, else the router's own) and its nonce keyed
   `(registry, id, lane)` in `scaas.govrouter.nonce` (`mtxNonceFor`); `mtxCancelNonceFor` refuses a target with no code
   (`TargetHasNoCode`) before anything moves (G-7: a keyed cancel for a predicted address ran in the router's own map and
   again in the keyed map once the target existed). Hunt: one signature that runs in two maps, a cancel that bumps another
   lane, a bad env registry (a malicious factory admin or registrar) admitting a signer the router's registry refuses.

**Prior reports (do not re-report what they list as fixed; give the closure table):**
- `T/pqz-core/research/code-review-2026-10-26/README.md` (whole-contract review at `64549aa4`) and `code-review-2026-10-19/README.md`
- `T/docs/research/security-review-record.md` (index of every review, and what no review covered)
- `scratchpad/review-ua-mtx-merge/` (A-regulated, B-metatx-ua, C-pqz-zether, D-factory-gov-dex-pqchat, recheck-*, recheck2-*)
- the review-fix round (2026-11-24 to -26, local): the TreeKEM and G1 code review
  `scratchpad/treekem-g1-review-20261124-1550/` (`BRIEF.md`, Fable areas A-G at `8cac68125`; its fixes, red tests and
  mutants in `T/smartcontracts/evm/runs/2026-11-24-review-fix-contract-summary.txt`), the re-review
  `scratchpad/review-fix-review-20261125-1959/` (`STATUS.md`: verdict, branch, fix commit, red test and mutant per finding;
  `fable-{A..G}.md`) and the fix check `scratchpad/review-fix-check-20261126-0429/` (`STATUS.md`, `fable-{A,R,C}.md`)

**Gate evidence at the tag (read for what was run; a green gate proves nothing by itself):**
- the tag's closing gate summary under `T/smartcontracts/evm/runs/` (every forge directory at the default set, the set-sensitive tests at the other three sets)
- `T/smartcontracts/evm/runs/2026-11-15-3zh-core-g2.txt`, `2026-11-15-burner-wrap-caps.txt`, `2026-11-15-pqz-three-keys-round/summary.txt`, `2026-11-13-fix3-chainuid/summary.txt`, `2026-11-14-msig-members/mutants.txt`, `2026-11-15-3zh-mldsa.txt`
- G1 and the keyed cancel: `T/smartcontracts/evm/runs/2026-11-24-router-g1-summary.txt`, `2026-11-24-router-cancel-summary.txt`,
  the runner `T/smartcontracts/evm/script/governance/g1_mutants.py`
- the review-fix round: `T/smartcontracts/evm/runs/2026-11-24-review-fix-contract-summary.txt` (with
  `2026-11-24-review-fix-contract-mutants.py`), `2026-11-26-review-fix4-contract-summary.txt`, and the round's closing
  matrix (`2026-11-26-round-matrix.sh` and its summary)
- `T/smartcontracts/evm/size-baseline.json` with `T/scripts/size_gate.py` (the size ratchet, ceiling 64 KiB)

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1; added 2026-11-24). Apply every dimension within this unit's
scope; each row says what to hunt here. A row marked `N/A` gives its reason and stays. Every finding names its dimension
number (section 9).

| # | Dimension | What to hunt in this unit |
|---|---|---|
| 1 | Conformance | CTR-DEX-13, -15, -19, -25, -26, -30, the 2026-11-12 DEX rulings, CTR-GOV-01 to -33 and CTR-UA-73 against `src/dex/`, `src/trade/`, `src/governance/`; `dex.md`, `settlement.md` BUILT rows with tests. |
| 2 | Cryptography | Typed orders, cancels and the liquidity order (EIP-712 domain, typehashes, nonces); the router op word binding target, op and word; the `RescueVault` owner change with a sequence number; the p256 / webauthn verify cap 400,000. |
| 3 | Security | Leads within the unit: settle by outcome (each recipient's delta >= its signed floor, the seller's debit <= the fill); executor trust; `DexPuller` pulls only what was signed; governance grants (terms enforced on every use, `grantDelay`, `disableFeature` one-way, two-step admin, `renounceRole` with `chainUid`); front-running a fill or a grant; the G1 keyed nonce map and the keyed cancel (invariant 5). |
| 4 | Rules that do not bend | Relayable with fee 0; explicit parameters; one `GovernanceRouter` per chain; bit bands 0-127 / 128-255 none refused; no chain assumption; nothing upgradable; `rescue(asset)` only to the constant. |
| 5 | Secrets and privacy | What orders and fills reveal (makers, amounts, as designed); business identifiers in governance events. |
| 6 | Robustness and denial of service | Order books and position readers without bound; a fill that leaves dust that blocks a market; executor return data griefing. |
| 7 | Failure handling | Named errors; refunds and `restorePulled` with EIP-1153 transient state; approve reset; reentrancy through the executor and the DEX; no partial settlement. |
| 8 | Consistency across languages and layers | Order and cancel typehashes equal `T/smartcontracts/evm/test/vectors/dex_order_kat.json` and clientkeys / `ua-rs` `wallet/entries/dex.rs`; governance ops equal `ua-rs` `admin.rs`; the node's DEX venue rows. |
| 9 | Contract specifics | Layout pins `SCaaSDex.json`, `SCaaSDexLiquidityModule.json`, `GovernanceRouter.json`; typehash pins; module split; the size gate; gas pins. |
| 10 | Performance and cost | Settlement gas per fill; who pays the executor call. |
| 11 | Interfaces and misuse | Order fields a maker can sign by mistake (a floor of 0); stable error codes for the venue. |
| 12 | Tests | Settle-by-outcome tests with a lying executor; grant-term tests per term; mutants. |
| 13 | Operations and the supply chain | N/A for config; the Uniswap interfaces under `src/dex/uniswap/` against their pinned upstream; SPDX headers. |

## 9. Report format (Markdown, English)

```
# evm-dex-gov: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### DXG-1 [P1] <short title>
- Where: T/<path>:<line>[-<line>] (every place, if the class recurs)
- Rule or invariant: <rule id or invariant from section 8>
- Dimension: <number and name, from the dimension table of section 8 (`docs/review.md` §1)>
- Claim: <one or two sentences>
- Failure scenario: <concrete inputs or call sequence -> wrong outcome (forgery, loss, leak, lock, crash, divergence)>
- Evidence: <quoted code, doc or standard clause, and the reasoning>
- Fix: <concrete change>
- Confidence: CONFIRMED (traced end to end) | PLAUSIBLE (say what is not traced)

## Earlier findings in this unit
<for each finding of the prior reports in section 8 that touches this unit: closed / open / regressed, with file:line>

## Checked and sound
<what you checked and found holding, with file:line, so a reader knows the coverage>

## Not covered
<what you did not reach>
```

Severity: **P0** forgery, theft or loss of funds, an unbacked mint, a break of privacy of amounts, balances or keys, a permanent
lock, a decryption oracle, a lost ciphertext, a consensus split; **P1** a break of a section-5 rule or an owner ruling with a
real path, a relayer able to alter an intent, a DoS of a whole contract or node; **P2** a bounded loss, griefing, a wrong
refusal that blocks a legitimate user, a missing check with a defence elsewhere; **P3** low impact; **info** a note with a security
angle. No padding: no style findings, no generic advice. A claim that something is sound is a result too: say what you checked.
Say "no findings" explicitly if there are none.

Every finding names its dimension number (ARCH-POS-22, `T/docs/review.md` §3); a finding that touches several names
the main one first. Under "Not covered", name each row of the dimension table you did not reach.
