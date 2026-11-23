# AI audit prompt, unit `pqz-verifier-deploy` (DRAFT, 2026-11-24)

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

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-pqz-verifier-deploy.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.1-sol-high-pqz-verifier-deploy.md`, `20261120-09-agy-gemini-4-argon-high-pqz-verifier-deploy.md`). Use the tool's
  configured model and effort; do not override them. The unit name is always last.
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

`scaas-pqz-verifier` signs the typed `PqzVerdict` an `OFFCHAIN` PQZ token accepts in place of the precompile's answer: it holds
a UA signing key and reads the chain. Attackers: a submitter posting a crafted proof, statement or named arguments; a token
made to look like a configured release; a lying, lagging or forked RPC endpoint; a local reader of the keystore, its
password variable, logs and errors. Goals: a verdict for a false statement, or for another token, epoch, op, chain or
`chainUid`; a verdict signed over a hash an RPC or a contract returned; the verifier key out of its place; a decryption oracle
through the answer (its status, body or timing). The deploy scripts and books decide which code lives at which address on
every chain. Attackers and failure modes: a wrong or missing environment value; a front-runner of a CREATE2 / CREATE3 deploy
or an `initialize`; a book overwritten or read from another chain; a release whose init code is not the source's. Goals: a
release at a wrong address or with a wrong parameter (registry, `chainUid`, parameter set, verifier, precompile address,
owner), an upgradable or re-initialisable deployment, a catalogue entry pointing at the wrong code, a book that misleads
clients and the node. Prefer a concrete call sequence to a pattern match. Across units: every optimisation that replaced code
with shared code, a library or a module (DELEGATECALL) must keep behaviour; say so when it does not.

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

## 8. Your unit: `pqz-verifier-deploy`

The OFFCHAIN PQZ verifier service, and the EVM deploy scripts with the factory catalogue and the deployment books (owner
2026-11-24).

**Scope (paths under `T/`):**
- `scaas-pqz-verifier/`: `src/lib.rs` (`offchain`, `PROBE_STATEMENT`, `purpose_pqz_verdict`, `pqz_key_hash`,
  `statement_lengths`, `body_limit`, `Config`, `RpcPolicy`, `VerdictRequest`, `Op`, `DisclosureArgs`, `Signed`, `WireSig`,
  `verdict_digest`, `registry_domain`, `verdict_auth_digest`, the release and proxy checks), `src/chain.rs`, `src/http.rs`,
  `src/abi.rs`, `src/main.rs`, `pqz-verifier.example.toml`, `Cargo.toml`, `Cargo.lock`, `README.md`; tests
  `tests/{anvil,bounds,service}.rs`
  (read for what a test can and cannot fail)
- the deploy scripts `smartcontracts/evm/script/`: `Deploy.s.sol`, `DeployBase.sol` (the release list `RELEASES_JSON`,
  `RELEASES_WRITE`, `_releaseRow` with `codeHash`, `initcodeHash`, `implArgsHash`), `DeployBook.sol`, `deploybook.py` (books
  `deployments/<key>.json`, NET-EVM-13), `DeployGas.sol`, `DeploySend.s.sol`, `DeployUAGen.s.sol`, `DeployRescueVault.s.sol`,
  `KindModules.sol`, `PqPrecompileProbe.sol`, `UAPrecompileProbe.sol`, `deploy_batch.py`, `deploy_pqchatstore.py`
  (`initCodeHash` checks), `forkcheck.py`, `tx_gas_cap.py`, `pq_verifiers.py`, `verify-blockscout.sh`, `hedera/`, `modules/`,
  `onchain/`, `pqz/`, `ua/`, `wraplimit/`, and their `test_*.py`
- the factory catalogue as the scripts use it: `smartcontracts/evm/src/factory/` (read; unit `evm-metatx-factory` audits the
  contract), `smartcontracts/evm/release-data/`, `test/governance/ReleaseList.t.sol`
- the books: `smartcontracts/evm/deployments/` is git-ignored and is **not under `T/`**; read the committed copies under
  `T/smartcontracts/evm/runs/*/deployments-*.json` and the book format in `deploybook.py`. If the controller adds the tag's
  live books to the run, they are in the main checkout's `smartcontracts/evm/deployments/`: read them, they hold addresses
  and hashes only
- not in scope: `smartcontracts/evm/test/` (except what a script test claims), the SCaaS testnet stack, `*/legacy/`

**Specifications and rules to read first:**
- `T/scaas-pqz-verifier/README.md`, spec `T/docs/superpowers/specs/2026-11-06-attested-verify.md` (§5 the verdict, §6 keys,
  §11.2), `2026-11-13-pqz-three-keys.md`; decisions ARCH-POS-13, CTR-PQZ-36, -37, CTR-UA-43, KV-12
- `T/docs/networks/README.md` (NET-ALL-25, NET-EVM-06, -11, -13), `T/docs/contracts/asset-suite.md` (the factory, CTR-TOK-29
  chain-neutral releases), `T/smartcontracts/evm/script/onchain/README.md`, CTR-GOV-19 (the size ceiling)

**Invariants to check (beyond section 5; each a finding when it fails):**

a. **The verifier signs only a verdict it rebuilt.** The only thing signed is the `UAAuth` digest of a `PqzVerdict` built from
   the pinned `chain_id`, `chain_uid`, registry and generation (`verdict_digest`, `verdict_auth_digest`); never a hash an RPC or
   a contract returned (Fable C-1). The token is a proxy of a configured release (`PROXY_HEAD` / `PROXY_TAIL`), names the
   configured registry, `chainUid` and this verifier, is `OFFCHAIN`, at the request's `pqzVerifierEpoch`; the statement has one
   of the set's lengths, word 32 is the token's `proofSystemId`, and the token's own statement view rebuilds exactly these
   bytes; `pqz-offchain` answers `…01`.
b. **Keys per the three-key model.** Every key the statement names passes spec §6 per key version: its `pqzPop` stored and
   hashing to `pqzPopHash`, its `R_REG` proof verified, no other UA or version owning it; scoped records by class
   (`pqzScopedKeyOf` / `pqzScopedKeyAt` / `pqzScopedPopOf`, CTR-UA-43).
c. **No decryption oracle** (ARCH-POS-13, CTR-PQZ-37): the service decrypts nothing; no answer, error, status or timing
   depends on a decryption; the opening token's case as ruled.
d. **The service key.** Held in a keystore whose password comes from a named environment variable; never in config, logs,
   errors, metrics or replies; `pqz-verifier.example.toml` holds names only.
e. **Reads.** Every chain read under `RpcPolicy` (ARCH-POS-15): a list of nodes, one endpoint per read, the pinned chain id
   checked at start; bounded bodies (`body_limit`), JSON depth (`MAX_DEPTH`), caches bounded (`CACHE_MAX`, `OWNER_MAX`).
f. **Deploy addresses and parameters.** Every release at the address the chain-neutral rule gives (CTR-TOK-29: one address per
   release on every chain), every clone's chain values in its code; every constructor and `initialize` argument from a named,
   checked source (registry, `chainUid`, parameter set, verifier UA, precompile addresses, owners, `sigStore` 2 by default for
   PqChat); a missing environment value refused, never defaulted to a test value outside a dev profile.
g. **Immutability and initialisation.** No deploy leaves an upgradable proxy, an admin able to swap code, or an `initialize`
   that a front-runner can call first or that can run twice; the deploy order makes every clone initialised in the
   transaction that creates it, or says why not.
h. **The catalogue and the init-code hash.** The release list's `codeHash`, `initcodeHash` and `implArgsHash` equal what the
   source builds (`bytecode_hash = "none"`), checked when the file exists (`RELEASES_WRITE` only on the first chain);
   `deploy_pqchatstore.py`'s `CHATSTORE_INIT_HASH` check; the factory catalogue's entries equal the books.
i. **The books.** `deployments/<key>.json` named by the chain key (NET-EVM-13), the old name refused or migrated as stated;
   the shared-genesis refusal (NET-ALL-25) for kinds that keep `homeChain` records; a book cannot be written for one chain from
   another chain's run; `verify-blockscout.sh` covers every contract deployed, children included.
j. **Fit.** Every deploy transaction within EIP-8037 and 2^24 regular gas where EIP-7825 applies (`tx_gas_cap.py`); the
   size gate's ceiling (CTR-GOV-19).

**Prior reports (do not re-report what they list as fixed; give the closure table):**
- the attested-verify reviews `T/docs/research/attest-codex-review.md`, `attest-fable-review.md` (Fable C-1)
- `scratchpad/review-3w/` (three-keys u3 / u4 rows on the verifier), `scratchpad/chains-arweave-review/` (NET-ALL-25)
- `T/docs/research/security-review-record.md`

**Gate evidence at the tag (read for what was run; a green gate proves nothing by itself):**
- the verifier's rows in the tag's gate summary (`cargo test`, the anvil test), `T/smartcontracts/evm/runs/` deploy and reset
  summaries (reset 4 / 5 and the pre-tag reset of TODO 8b-6), `python3 script/test_*.py` in CI, the size gate

**Also accepted for this unit (do not report):** the own-key OFFCHAIN token risk (CTR-PQZ-37); gas prices and calibration
figures; the SCaaS testnet's RPC exposure; deploy scripts under `*/legacy/`.

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1; added 2026-11-24). Apply every dimension within this unit's
scope; each row says what to hunt here. A row marked `N/A` gives its reason and stays. Every finding names its dimension
number (section 9).

| # | Dimension | What to hunt in this unit |
|---|---|---|
| 1 | Conformance | The verifier against its README and the attested-verify spec §5, §6, §11.2; the deploy scripts against NET-EVM-11, -13, NET-ALL-25, CTR-TOK-29; a script behaviour no doc states. |
| 2 | Cryptography | The `PqzVerdict` digest and its `UAAuth` wrapping (domains, salt `chainUid`, `PURPOSE_PQZ_VERDICT`), the `R_REG` check per key version, `pqz_key_hash`; the init-code and runtime hashes the release list pins. |
| 3 | Security | **Leads within the unit.** Invariants a, b, f, g: a verdict for another token, epoch or chain; a proxy that only looks like a release; a front-run `initialize` or CREATE2 / CREATE3 deploy; a deploy that grants a role to the wrong address. |
| 4 | Rules that do not bend | No decryption oracle in the service; every RPC consumer (the service, the scripts' reads) on a list of nodes; nothing deployed upgradable; no chain assumption in the scripts (gas price, block limit); one rule on every chain. |
| 5 | Secrets and privacy | The service's keystore and password variable; deploy keys never in a script, a book or a log; books hold addresses and hashes only. |
| 6 | Robustness and denial of service | Bounded request bodies and JSON depth; caches bounded; a request flood against the verifier. |
| 7 | Failure handling | The service refuses by name and signs nothing on any error; a deploy that fails halfway leaves a book that says so, never a book that claims a release that did not land. |
| 8 | Consistency across languages and layers | The verdict digest equal to the contract's check and the SDK's `confidential/verdict.rs`; the books' addresses equal what clients and the node read (profiles, `node.example.toml` names). |
| 9 | Contract specifics | Immutability, `initialize` once, the catalogue, the init-code hash, the size gate and `_above64KiB` as deployed. |
| 10 | Performance and cost | Deploy gas per release against the books and `DeployGas.sol`; who pays the verifier fee (CTR-PQZ-36). |
| 11 | Interfaces and misuse | The verifier's HTTP API (named fields, stable error codes); the scripts' environment hard to misuse (a dev default refused on a public chain). |
| 12 | Tests | `tests/{anvil,bounds,service}.rs` and `script/test_*.py` can fail; a test per refusal. |
| 13 | Operations and the supply chain | `Cargo.lock` and advisories of the service; the example config holds no secret; the scripts read no network beyond the named RPC; `verify-blockscout.sh` and no machine path in a committed book copy. |

## 9. Report format (Markdown, English)

```
# pqz-verifier-deploy: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### PVD-1 [P1] <short title>
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
