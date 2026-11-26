# AI audit prompt, unit `cross-layer` (DRAFT, 2026-11-24)

Contracts audit at the pre-freeze target (owner rulings 2026-11-12: pre-freeze -> audit -> audit fixes -> freeze). This file is
self-contained: run it as it is, with any tool (Codex, agy, a Claude workflow, Fable, ...). Placeholders the controller fills
before the run: `<TAG>`, `<SHA>`.

## 1. Role and limits

You are one AI reviewer of the SCaaS contracts audit. The audit is an AI audit (decision ARCH-POS-14): reports name the tool and
model that wrote them. Everything under audit is `UNAUDITED`. Nothing is live with value; every chain is test-only.

**STRICTLY READ-ONLY.** Allowed: reading files; `git -C T log | show | diff | grep | blame | rev-parse`; `grep` / `rg` / `sed
 -n` /
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

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-cross-layer.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.2-astra-high-cross-layer.md`, `20261120-09-agy-gemini-4-argon-high-cross-layer.md`). Use the tool's
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

The whole system, read across its layers: the contracts (EVM, and the Soroban registry where a rule claims one rule on every
chain), `pqz-core` and the Nethermind precompiles, the signers (`ua-rs`, clientkeys and every `ua-*` wrapper), the SDK and its
bindings, the app cores, and the open node. Attackers: any EOA or contract; a relayer (may refuse, delay or reorder, never
forge or alter); a front-runner; a malicious subject, holder or group member; a malicious admin or role holder exceeding its
grant; a colluding key holder or `msig` member; a party that left or was removed; a malicious token, DEX, executor, verifier,
gateway, bundler or node; an RPC endpoint that lies, lags or forks, alone or with others; a malicious app calling the SDK or a
binding out of order; a local reader of logs, errors, metrics, stores or backups; a replayer across chain id, `chainUid`,
registry generation, token, release, kind, operation, purpose or nonce lane; a chain whose gas, block limit, precompiles or
host functions differ from the SCaaS testnet. Goals: forgery, theft, an unbacked mint, a leak of amounts, balances, keys or
plaintext, a permanent lock, replay, griefing that blocks others, a call that cannot fit a block (EIP-8037, EIP-7825), a
decryption oracle through any layer, a secret out of its place, and **a fork between layers**: a record the contract accepts
that clients cannot follow, a record clients build that the contract refuses, or a check that one path makes and its sibling
skips. Prefer a concrete call sequence to a pattern match. Across units: every optimisation that replaced code with shared code,
a library or a module (DELEGATECALL) must keep behaviour; say so when it does not.

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
  never report the old 24 KiB limit. `WrappedToken`, `WrappedRegulatedToken` and the confidential regulated releases miss 60 /
  70 M
  public blocks and deploy where the block takes them (owner 2026-11-05). Report a size only if it breaks EIP-8037 / EIP-7825 on
  a path a user must take.
- **Gas prices:** the schedule's provisional rows and calibration figures are the owner's (no timing runs here).
- The `UNAUDITED` label itself, Vietnamese source comments, style, naming, gas opinions that break no rule.
- Findings an earlier report below lists as fixed: report them only if the fix is wrong, incomplete or undone since; findings a
  triage marked REJECT or accepted (the ledgers named below): skip unless you have new evidence.

## 8. Your unit: `cross-layer`

The cross-layer area of `T/docs/review.md` §2: it **leads dimension 8 end to end**, spec ↔ contract ↔ clients ↔ node. It
looks for places where two layers read the same rule differently. The layer units audit each layer alone; this unit reads
the seams between them. Size it to the seams, not to the layers: read a layer's code only as far as a byte format, an
allow-list, a record or a check crosses into another layer.

**Scope (paths under `T/`):**
- the vectors, the authority for bytes: `smartcontracts/vectors/` (every directory: `typed/`, `ua/`, `metatx/`, `pqz/`,
  `pqchat/`, `pqvault/`, `zether/`, `governance/`, `keys/`, `keystore/`, `native/`, `families/`, `factory/`, `appcore/`,
  `arweave/`, `wraplimits/`) and `smartcontracts/evm/test/vectors/` (`selector_audit.json`, `erc7739_kat.json`,
  `metatx_kat.json`, `dex_order_kat.json`, `mandate_kat.json`, `smart_key_account_kat.json`, `webauthn_soft.json`), with
  their generators (clientkeys `scripts/*-vectors.mjs`, `pqz-core/ffi/src/bin/pqz-vectors.rs`, `vectors/*/gen_*.py`,
  `clients/zether-prover/src/vectors.rs`)
- the writers and readers of those bytes: the contracts (`smartcontracts/evm/src/`, typehash constants, `MetaTxLib.canon`,
  `SaltedEIP712`, `UAKinds.uaMessage`, `mtxSelectors()`, `_uaAllowed`), clientkeys (`clients/clientkeys/src/`), `ua-rs`
  (`clients/ua-rs/src/wallet/eip712.rs`, `uasig.rs`, `ua_portable.rs`, `keydata.rs`, the facades), every `ua-*` wrapper's vector
  reader (`clients/ua-{c,cxx,qt,cs,py,go,dart,dart-frb}/` tests), the SDK (`clients/scaas-sdk/src/op/`, `account/`, `line.rs`,
  `app_core.rs`), the app cores (`clients/pqchat-core/`, `clients/pqvault-core/` records), the node (`scaas-node/src/typed.rs`,
  `guard.rs`, `metatx.rs`, `abi.rs`, the adapters' payload decoders), `scaas-pqz-verifier/src/lib.rs` (`verdict_digest`)
- the Soroban registry and token (`smartcontracts/soroban/contracts/`) where a rule claims one form on every chain
- not in scope: the cryptography of a primitive (the `crypto-*` units), a single layer's internal logic (the layer units)

**Specifications and rules to read first:**
- `T/docs/review.md` (ARCH-POS-22: dimension 8, the cross-layer area), `T/docs/integration.md`, `T/AGENTS.md` "Clients and
  vectors" (byte formats change everywhere at once; editing one reproducer alone is a defect)
- `T/docs/contracts/metatx.md`, `accounts.md`, `pqchat.md`, `pqvault.md`, `pq-zero-knowledge.md`, `zether.md`;
  `T/docs/clients/ua-libraries.md`, `signers-clientkeys.md`, `scaas-sdk.md`, `pqchat-core.md`; `T/docs/node/job-api.md`,
  `gateway.md`; `T/docs/networks/README.md`
- decisions CTR-MTX-28, -29, CTR-UA-07, -31, -36, -65, -70, CTR-GOV-28, NODE-JOB-01, -19, -20, -26, -27, NODE-GW-03,
  NET-ALL-27, CLI-PQC-11, CLI-SDK-08, -16

**Invariants to check (beyond section 5; each a finding when it fails):**

a. **One byte format per object, from the vectors.** For every EIP-712 typehash, domain, digest, record and canonical form:
   the contract's constant, clientkeys, `ua-rs`, every `ua-*` reader, the SDK, the app cores, the node and the verifier
   service produce or check the same bytes, and all of them read the same vector rows. List each object with its writers and
   readers by path. A reader that skips a row, a generator that writes a row no reader reads, a vector set that only holds
   canonical inputs (an unbound `relayer` / `feeRecipient` always zero; reproduce `MetaTxLib.canon` with a **non-zero**
   unbound value), and a hand-kept constant beside a generated one are findings.
b. **Allow-lists equal to the contracts' in both directions.** `scaas-node` `typed.rs` `TYPED` / `PLAIN` rows and `guard.rs`
   per-kind rules against each kind's `mtxSelectors()`, `_uaAllowed` and `selector_audit.json` (its `SIGNED`, unsigned-write
   and `GUARDIAN` classes; the six PqChat tree rows once merged); `selector_audit.json` generated from the contracts, not hand
   kept; the non-EVM adapters' accepted functions against each family contract (NET-ALL-27). Check that the tests claiming
   this compare both directions and can fail.
c. **A record the contract accepts can be followed by clients, and the reverse; no fork.** For each record kind (UA
   registration, `msig`, KEM and PQZ key versions, PQZ debits and credits, Zether transfers, PqChat sessions, epochs, messages,
   topics and tree commits, PqVault vaults, epochs and items, pay records): every bound the contract enforces is enforced by
   the client before signing (or the client's refusal is documented), every bound the client enforces is one the contract
   enforces or a documented client-only rule (CLI-PQC-17), and a client that recovers from state alone (CTR-CHAT-14,
   CTR-PQV-10, the PQZ proof path) reads exactly what the contract stored. A contract that accepts what no client can follow
   (a staged state nobody can complete, a wrap a reader cannot open) and a client that builds what the contract refuses are
   both findings.
d. **A check present in one path is present in its siblings.** The same rule in: the typed entry and the generic execute path;
   the EVM contract and the Soroban contract; the node's EVM door and its `/v1/ops` door; `ua-rs` and clientkeys; the SDK's
   self-relay and its node path; the PQZ precompile mode and the OFFCHAIN verdict; PqChat and PqVault on `PqGroupBase`. A
   check fixed in one place and missing in a sibling is a finding: name both places.
e. **The registry line is read the same way.** `holderOf` / `pqzHome` (CTR-UA-65, -70) by the SDK (`line.rs`), pqchat-core,
   pqvault-core, the verifier service and the node, each at one block on one endpoint, never assuming the bound registry holds
   the record.
f. **Errors and refusals named the same** across the contract, `ua-rs`, the SDK and the node where one maps the other's (a
   contract error the SDK turns into a generic one hides the rule from the user).
g. **The review-fix round's seams** (added 2026-11-26): the `msig` version tag (CTR-UA-74) written and read the same way by
   the registry, `ua-rs` (`uasig.rs`, `ua_portable.rs`, `wallet/tree.rs`), clientkeys (`ua-verify.js`, `treekem.js`), the SDK
   (`account/msig.rs`: one `msigAt` read per version a record names, at most 17), pqchat-core (`reads.rs` walk) and
   pqvault-core (`vault.rs` `verify`, `epoch_agrees`), and passed through unchanged by the node; step 6 wherever a chain of
   records is read; a replica record compared with its home's with the tags stripped (A-1). The tree bounds after R8 512 /
   C10 20 equal in the contract, the node's `typed.rs`, `ua-rs` and clientkeys; the exit lag of 16 equal in the contracts,
   pqchat-core's `ExitLag`, the SDK's and `ua-rs`'s review lines; an empty `addWraps` / `addVaultWraps` refused by the
   contract and the node alike (A-5); the group kinds 0x0110-0x0113 judged alike by Solidity, `ua-rs` `groups.rs` and
   clientkeys `ua-group.js` on `vectors/ua/groups.json`; Falcon keys and signatures equal natively and on wasm32
   (CLI-UAL-66).

**Prior reports (do not re-report what they list as fixed; give the closure table):**
- `T/docs/research/security-review-record.md` (index of every review, and what no review covered)
- `T/pqz-core/research/code-review-2026-10-26/README.md`, `code-review-2026-10-19/README.md`
- `scratchpad/review-ua-mtx-merge/` (A to E, recheck-*, recheck2-*), `scratchpad/review-3w/` (`triage.md`),
  `scratchpad/review-3zh/`, `scratchpad/review-t21/` (`ledger.md`, O1-O8), `scratchpad/sdk-complete-review/`,
  `scratchpad/sdk-review-20261123-0621/` (T26, `STATUS.md`), `scratchpad/pqvault-review/`,
  `scratchpad/treekem-review-20261123-1426/`
- the review-fix round (2026-11-24 to -26, local): the TreeKEM and G1 code review
  `scratchpad/treekem-g1-review-20261124-1550/` (`BRIEF.md`, Fable areas A-G at `8cac68125`; its fixes, red tests and
  mutants in `T/smartcontracts/evm/runs/2026-11-24-review-fix-contract-summary.txt`), the re-review
  `scratchpad/review-fix-review-20261125-1959/` (`STATUS.md`: verdict, branch, fix commit, red test and mutant per finding;
  `fable-{A..G}.md`) and the fix check `scratchpad/review-fix-check-20261126-0429/` (`STATUS.md`, `fable-{A,R,C}.md`)
- the reports of the layer units of this round under `scratchpad/ai-audit/results/` when they exist: read them for leads,
  do not repeat their findings; a finding of yours that a layer unit already reported names that unit's id

**Gate evidence at the tag (read for what was run; a green gate proves nothing by itself):**
- `T/smartcontracts/evm/runs/2026-11-18-prefreeze-matrix-summary.txt`, `2026-11-19-pr-a-matrix-summary.txt`, and the tag's own
  closing matrix (every forge directory at the default set, the set-sensitive tests at the other three sets, node and e2e,
  clients, vectors)
- `T/pqz-core/runs/gate/3zh-g2-<set>-summary.txt` for the four sets
- `T/clients/clientkeys/` vector `--check` rows, `T/clients/ua-rs/` `vectors` test rows and each wrapper's vector rows in the
  tag's client gate summary
- the review-fix round: `T/smartcontracts/evm/runs/2026-11-24-review-fix-contract-summary.txt` (with
  `2026-11-24-review-fix-contract-mutants.py`), `2026-11-26-review-fix4-contract-summary.txt`, and the round's closing
  matrix (`2026-11-26-round-matrix.sh` and its summary)
- the review-fix round's client rows: `T/clients/runs/2026-11-25-review-fix-client-summary.txt`,
  `2026-11-26-review-fix3-client-summary.txt`, `2026-11-26-review-fix4-client-summary.txt` (with their `-mutants.py`
  runners)

**Also accepted for this unit (do not report as such):** what a doc marks SPECIFIED or PLANNED and is unbuilt; the non-EVM
families other than Soroban are deferred (owner 2026-10-31, confirmed 2026-11-24): name a fork with them only if a built EVM
or client path already depends on it.

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1; added 2026-11-24). Apply every dimension within this unit's
scope; each row says what to hunt here. A row marked `N/A` gives its reason and stays. Every finding names its dimension
number (section 9).

| # | Dimension | What to hunt in this unit |
|---|---|---|
| 1 | Conformance | Every rule that names more than one layer, read once per layer: CTR-MTX-28/-29 (explicit parameters) in contract, signer, SDK and node; CTR-UA-07/-31 portability; CTR-GOV-28 `chainUid`; NODE-JOB-02/-20 rebuilt bytes; a rule BUILT in one layer and SPECIFIED in another, said BUILT everywhere. |
| 2 | Cryptography | N/A for primitives (the `crypto-*` units lead dimension 2); here only the hashing and encoding that cross layers: typehash strings, domain fields and order, `uaMessage(kind, purpose, typedDigest)`, the purpose tags, `kemHash`, wrap hashes, canonical JSON (±(2^53 − 1)). |
| 3 | Security | A relayer altering a field that one layer binds and another does not; replay across a field that a client omits from a digest the contract builds with it; the node accepting a selector the contract refuses (lane gas) or refusing one the contract accepts (a write that cannot be relayed). |
| 4 | Rules that do not bend | Explicit parameters in every layer (named fields in node JSON, `HEX_ARGS_REFUSED`); every `mtx*` relayable by the node with fee 0; one rule on every chain (the Soroban forms against the EVM forms); the node is open (no consumer-specific rule). |
| 5 | Secrets and privacy | A field one layer treats as public and another as secret (a business identifier in clear in a record, ARCH-POS-17); padding a client applies that the contract or the node then reveals by length. |
| 6 | Robustness and denial of service | A bound one layer enforces and another does not (sizes, counts, depth): a client that builds a record the contract refuses at the end of a multi-transaction flow, after the user paid for the first pieces. |
| 7 | Failure handling | Errors that change meaning across a layer (invariant f); a partial flow the contract accepts and the client cannot recover from state alone. |
| 8 | Consistency across languages and layers | **Leads this dimension, end to end.** Invariants a to e: the same bytes everywhere from the vectors, the allow-lists both ways, records followed both ways, sibling checks, the registry line. |
| 9 | Contract specifics | Typehash pins (`*TypehashIsPinned`) equal to the vectors; `selector_audit.json` generated from the contracts; the layout pins of every contract a client reads by slot (if any). |
| 10 | Performance and cost | N/A except where a layer mismatch costs gas (a client sizing a batch by a bound the contract does not use). |
| 11 | Interfaces and misuse | The SDK and the CLI show every field the contract binds (prepare -> review -> sign); a binding that drops or renames a field. |
| 12 | Tests | Vectors checked by every reader (name the readers that skip rows); a test that compares a layer with itself; the both-directions tests can fail. |
| 13 | Operations and the supply chain | N/A for config and dependencies (the layer units); a generator with network or clock input that makes vectors unreproducible. |

## 9. Report format (Markdown, English)

```
# cross-layer: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### XLY-1 [P1] <short title>
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
refusal that blocks a legitimate user, a missing check with a defence elsewhere; **P3** low impact; **info** a note with a
security
angle. No padding: no style findings, no generic advice. A claim that something is sound is a result too: say what you checked.
Say "no findings" explicitly if there are none.

Every finding names its dimension number (ARCH-POS-22, `T/docs/review.md` §3); a finding that touches several names
the main one first. Under "Not covered", name each row of the dimension table you did not reach.
