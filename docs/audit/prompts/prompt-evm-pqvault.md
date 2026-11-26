# AI audit prompt, unit `evm-pqvault` (DRAFT, 2026-11-22)

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

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-evm-pqvault.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.2-astra-high-evm-pqvault.md`, `20261120-09-agy-gemini-4-argon-high-evm-pqvault.md`). Use the tool's
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

## 8. Your unit: `evm-pqvault`

The `PqVault` contract (post-quantum notes and passwords in contract state; on `main` since PR #27): vaults, epochs, wraps,
members and admins, items and versions, batches, the two modes, recovery from state alone.

**Shared base.** `src/pqgroup/PqGroupBase.sol` (CTR-PQV-12: the group code PqChat and PqVault share, one abstract base
without state of its own) **is audited once, in unit `evm-pqchat`**. This unit reads it only for PqVault's use of it: every
hook and override PqVault supplies (`_parentOf`, the admin and member checks, the home slot, removals), every base rule
PqVault relies on with other names or limits, and every place PqVault's behaviour differs from PqChat's on the same base
(CTR-PQV-13: only admins rekey). A defect in the base itself goes in `evm-pqchat`'s report; if you find one here, report it
with its id and say it belongs to the base.

**Scope (paths under `T/`):**
- `smartcontracts/evm/src/pqvault/` (`PqVault.sol`, `IPqVault.sol`, `PqVaultTypes.sol`)
- read-only: `src/pqgroup/PqGroupBase.sol` (above), `src/ua/UARegistry*.sol` for `requireAuthorized` / `requirePortable`, the KEM
  records and `msig` expansion, `src/factory/` for the class-4 generic creation (CTR-PQV-02), `src/pqchat/IPqChat.sol`
  (`Wrap`)
- the pins: `T/smartcontracts/evm/test/v2/layout/PqVault.json` (storage layout), `test/pqvault/PqVaultTypes.t.sol`
  (typehashes and ids), `test/pqvault/` (read for what a test can and cannot fail), `T/smartcontracts/vectors/pqvault/`

**Specifications and rules to read first:**
- `T/docs/contracts/pqvault.md` (CTR-PQV-01 to -17), `T/docs/contracts/pqchat.md` (CTR-CHAT-06 to -10, -14, -20, which
  PqVault follows)
- spec `T/docs/superpowers/specs/2026-11-17-pqvault.md` §3 (rulings and controller calls), §5 (the contract), §6.4
  (`sealedInfo`), §6.7 (rotation, sharing), §15 (rule ids), §16-§17 (review findings and their fixes)
- decisions: the PqVault entries (owner rulings V1-V10, O1 (c), O3 (b), the admin model "(b)" of 2026-11-21, the Fable
  code review F1-F15 Changes), ARCH-POS-13, NET-ALL-25 (`T/docs/networks/README.md`), CTR-UA-46 (the open portable app namespace)

**Invariants to check (beyond section 5):**
1. **The admin model (b)** (owner 2026-11-21, "keep (b)"): a vault keeps several admins; only an admin of the parent epoch
   who was not removed from it and did not leave rekeys (`PqVaultNotAdmin`); members read, write and leave; the creator is an
   admin and a member at creation; with no admin left, membership and keys are frozen and items stay writable under the last
   epoch; an admin that is no member (an `msig`) is removable; a child whose author was removed from the parent no longer
   completes (`PqVaultRemovedKept`). Every write's authorization: `UASig` over the typed record in the vault's domain
   (CTR-PQV-03), the signer the record names, `requireAuthorized` / `requirePortable` by mode (CTR-PQV-16, -17).
2. **Membership and wraps** (CTR-PQV-06, CTR-CHAT-06 to -10): at least one member, lists strictly sorted, one wrap hash per
   member, wraps in chunks by hash (`addVaultWraps` unsigned, each wrap hashing to its signed hash), the home-instance slot
   and `childOf`, `epoch = parent + 1`, leave and remove (1..`REMOVE_MAX`, sorted, at home only), `removalAt` past the end
   `PqVaultUnknown` (F15). Item writes (CTR-PQV-07, -08, -09, -14): a member of a complete epoch with no complete child at
   home, never one removed from it or one that left; `editItem` exactly `count + 1`; a batch's items share its vault, epoch
   and author.
3. **`sealedInfo` bounds:** 28 to 16,412 B on chain, `PqVaultShape` outside, on both the vault and the epoch record
   (`INFO_MIN`, `INFO_MAX`); the client pads to 1,024 B (owner ruling, CLI-PQV-09; the chain does not enforce it).
   Ciphertexts 32 to 16,416 B (CTR-PQV-14). Each bound checked before any unbounded read or copy.
4. **Ciphertexts kept in state, never only a hash** (CTR-PQV-05; section 5 rule 1): every accepted record, wraps and
   `sealedInfo` included, kept in full in SSTORE2 blobs within the code-size limit; events only notify; `vaultOf`,
   `epochOf`, `wrapAt`, the item reads return the stored bytes (CTR-PQV-10: a client keeps no vault list and reads no event).
5. **No decryption oracle** (ARCH-POS-13): the contract never reads a ciphertext or `sealedInfo` beyond its length, and no
   refusal, status or gas difference depends on what a ciphertext holds.
6. **Every state-changing entry is relayable by anyone with a fee of 0** (CTR-PQV-11): no record carries a fee, deadline or
   submitter; the seven signed writes and the unsigned `addVaultWraps`; nonce scopes (CTR-PQV-04: ids from the signer and its
   nonce under the `scaas/pqvault/v1/…` tags; the batch and item scopes of CTR-PQV-09) so a relayer can neither replay nor
   reorder into a different outcome; class 4, kind 0, no write selector shared with PqChat (CTR-PQV-13).
7. **The home-chain shared-genesis refusal** (NET-ALL-25): PqVault's records name their home by `homeChain` (a `chain_uid`)
   and a contract address, which a shared genesis with a deterministic factory makes hold on both chains. Check what the
   contract binds (`_checkCreate`: `homeChain == chainUid()` and `homeVaultContract == address(this)`; mode 1 only at home),
   and that the deploy gate's refusal (`script/deploybook.py`, `script/DeployBook.sol`: a kind that keeps `homeChain` records
   on a profile whose pair or genesis is shared) covers PqVault; a replica's version counts only as CTR-PQV-14 states.
8. **Typehash and layout pins:** every typehash equals the struct the clients sign (clientkeys `pqvault.js`, `ua-rs`
   `pqvault_keys`, the vectors), each pinned (`PqVaultTypes.t.sol`); the layout equals `test/v2/layout/PqVault.json`; the
   factory's `FactoryInfo` (class, kind, version) as CTR-PQV-02 / -13.
9. **The share box for single notes** (owner O1 (c), 2026-11-17; CLI-PQV share box in `T/docs/clients/ua-libraries.md`): a
   personal vault is never rekeyed to add a member; sharing from it is a new shared vault (the sealed `shared` flag, copied
   unchanged by every rekey) and a `createItems` copy. The contract is unchanged by O1 (c) (the flag is sealed): check that
   nothing in the contract lets a personal vault's history, tombstones, passphrase fields or per-vault UA reach a shared
   vault's members, and that `createItems` takes the copy within the bounds of invariant 3.
10. Fit: `createItems` and the largest records within the chain's block gas limit (regular + state, EIP-8037) and regular gas
   under 2^24 where EIP-7825 applies (CTR-PQV-09: no protocol bound on the count; the client sizes the batch).
11. **Exits at the head and the round's fixes** (added 2026-11-26; the PqVault Changes of 2026-11-24 to -26, CTR-CHAT-10 /
   -20's with `PqVault*` errors, one rule for the group code): `leaveVault` and `removeVaultMembers` at home name the head
   or a complete ancestor within `EXIT_LAG_MAX` = 16 (`PqVaultExitLag`), checked and applied at the head, the signer and
   the named UAs also in the named epoch's lists when it is not the head (E-2), a repeat or an exit that newly flags nobody
   `PqVaultNotMember`, no withdrawal; a replica keeps the epoch named and takes a repeat (A-16); an `addVaultWraps` with no
   wrap is `PqVaultShape` (A-15); a replica's copy of an `msig` author's record carries the replica registry's current
   version tag (CTR-UA-74, A-1, `test_a1_replicaCopyCarriesTheReplicaTag` in `PqVaultEpochs`), so CTR-PQV-14's comparison
   of a replica with its home strips the tags. Only admins rekey (CTR-PQV-13): check that an admin about to be removed can
   no longer strand its removal by an admin rekey, and that the base's walk serves PqVault as it serves PqChat.

**Prior reports (do not re-report what they list as fixed; give the closure table):**
- the Fable code review of PqVault (F1-F15) and the spec reviews r1 / r2, as recorded in the spec's §16-§17 and the decisions
  Changes of 2026-11-21; `scratchpad/pqvault-review/20261121-fable-code-review-v1-v8.md` (local)
- the review-fix round (2026-11-24 to -26, local): the TreeKEM and G1 code review
  `scratchpad/treekem-g1-review-20261124-1550/` (`BRIEF.md`, Fable areas A-G at `8cac68125`; its fixes, red tests and
  mutants in `T/smartcontracts/evm/runs/2026-11-24-review-fix-contract-summary.txt`), the re-review
  `scratchpad/review-fix-review-20261125-1959/` (`STATUS.md`: verdict, branch, fix commit, red test and mutant per finding;
  `fable-{A..G}.md`) and the fix check `scratchpad/review-fix-check-20261126-0429/` (`STATUS.md`, `fable-{A,R,C}.md`)
- `T/docs/research/security-review-record.md`

**Gate evidence at the tag (read for what was run; a green gate proves nothing by itself):**
- the tag's closing gate summary under `T/smartcontracts/evm/runs/` (every forge directory at the default set, the
  set-sensitive tests at the other three sets); `T/smartcontracts/evm/runs/2026-11-21-pqvault/` (gates, mutants, node mutants)
- the review-fix round: `T/smartcontracts/evm/runs/2026-11-24-review-fix-contract-summary.txt` (with
  `2026-11-24-review-fix-contract-mutants.py`), `2026-11-26-review-fix4-contract-summary.txt`, and the round's closing
  matrix (`2026-11-26-round-matrix.sh` and its summary)
- `T/smartcontracts/evm/size-baseline.json` with `T/scripts/size_gate.py` (the size ratchet, ceiling 64 KiB)

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1; added 2026-11-24). Apply every dimension within this unit's
scope; each row says what to hunt here. A row marked `N/A` gives its reason and stays. Every finding names its dimension
number (section 9).

| # | Dimension | What to hunt in this unit |
|---|---|---|
| 1 | Conformance | CTR-PQV-01 to -17, CTR-CHAT-06 to -10, -14, -20 as PqVault follows them, owner rulings V1-V10, O1 (c), O3 (b), the admin model (b), the F1-F15 Changes, NET-ALL-25, CTR-UA-46 against `src/pqvault/`; spec §15 rule ids each with code and test; the exit Changes of 2026-11-24 to -26 (invariant 11), CTR-PQV-18, CTR-UA-74's replica copy. |
| 2 | Cryptography | The typehashes and domain of the seven signed writes (`DS_V`), the `scaas/pqvault/v1/…` id and nonce tags (CTR-PQV-04), wrap hashes, item AAD binding, `sealedInfo` as an opaque blob; what each typed hash binds (vault, epoch, item, version, author); the `groupMode` refusal (`PqVaultModeUnsupported`). |
| 3 | Security | The admin model (b): who rekeys, who removes, an admin that is no member removable, `PqVaultRemovedKept`, frozen membership with no admin; `requireAuthorized` / `requirePortable` by mode; replay and reorder by a relayer into a different outcome; the share box (O1 (c)): nothing of a personal vault reaches a shared vault's members; exits at the head and the replica rule (invariant 11). |
| 4 | Rules that do not bend | Ciphertexts and `sealedInfo` in state (CTR-PQV-05); no decryption oracle; explicit parameters; every write relayable with fee 0 (CTR-PQV-11); the home-chain shared-genesis refusal (NET-ALL-25) at create and in the deploy gate; nothing upgradable. |
| 5 | Secrets and privacy | Metadata: member lists, item counts and sizes (padding to 1,024 B is the client's), edit cadence; what `vaultsOf` reveals. |
| 6 | Robustness and denial of service | `sealedInfo` 28 to 16,412 B, ciphertexts 32 to 16,416 B, each bound before any copy; `REMOVE_MAX`; `createItems` sized by the client within EIP-8037 and 2^24. |
| 7 | Failure handling | Named errors (`PqVaultShape`, `PqVaultUnknown`, `PqVaultNotAdmin`); no partial batch; recovery from state alone (CTR-PQV-10). |
| 8 | Consistency across languages and layers | Typehashes equal clientkeys `pqvault.js`, `ua-rs` `wallet/pqvault.rs`, pqvault-core `records.rs` and `T/smartcontracts/vectors/pqvault/` (incl. the `groupMode` 1 refusal row, TODO 8b-8 (1)); the node's `pqvault_rows_equal_the_contract_both_directions`. |
| 9 | Contract specifics | Layout `test/v2/layout/PqVault.json`, typehash pins `PqVaultTypes.t.sol`, `FactoryInfo` (class 4, kind 0), size gate, gas pins (`PqVaultGas.t.sol`). |
| 10 | Performance and cost | Gas per write against `docs/contracts/pqvault.md`; storage growth per item version. |
| 11 | Interfaces and misuse | No write selector shared with PqChat (CTR-PQV-13); stable error codes. |
| 12 | Tests | Mutants of `runs/2026-11-21-pqvault/`; each bound at the edge (accept) and one above (refuse). |
| 13 | Operations and the supply chain | N/A for config (pure Solidity); `script/deploybook.py` / `DeployBook.sol`'s NET-ALL-25 refusal covers PqVault; SPDX headers. |

## 9. Report format (Markdown, English)

```
# evm-pqvault: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### PQV-1 [P1] <short title>
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
