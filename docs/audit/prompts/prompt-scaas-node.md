# AI audit prompt, unit `scaas-node` (DRAFT, 2026-11-22)

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

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-scaas-node.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.2-astra-high-scaas-node.md`, `20261120-09-agy-gemini-4-argon-high-scaas-node.md`). Use the tool's
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

The node is an **open relayer and indexer in front of the contracts**: every input it reads is untrusted, and its guarantees
belong in the node and its spec, never in one consumer. Attackers: anyone who posts to the gateway (door A) or holds a job-API
key (a malicious subject, a griefer, a spammer); a malicious, lagging or forked RPC endpoint, or one on another chain; a
malicious mesh or gossip peer; a malicious PQZ verifier endpoint; a contract made to look like a SCaaS token, DEX or registry; a
local reader of logs, metrics, errors, the store or the config. Goals: the node relays bytes the subject did not sign, or alters a
signed field (a relayer may refuse or delay, never forge or alter); the lane pays without bound (gas drain, a billed failure
repeated, a deposit that does not come back); a lane key reaches a contract role; a job reported `dead` that later lands (the
client re-signs and pays twice) or reported landed that did not; the node aborts or exhausts memory on an input (a stack
overflow aborts the whole process and every chain with it); the indexer emits an event that is not final, or one a lying
endpoint invented; a secret (lane key, mnemonic, keystore passphrase, gateway secret, API master key, a credential in an RPC
URL) reaches a log, an error, a metric or a reply; the node decrypts, or becomes a channel that leaks the result of a
decryption somebody else runs. Authorization lives in the contracts: a node check is extra, never the only guard, and a node
check that is weaker than the contract's still matters when it makes the lane pay or reports a wrong state.

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

## 8. Your unit: `scaas-node`

The open relayer and indexer: one Rust binary with the gateway, the job API, the submit lanes, the indexer, the mesh, the DEX
venue and one adapter per family. Every input is untrusted (section 6). The node holds gas, never subject funds or keys.

**Scope (paths under `T/`):**
- `scaas-node/src/` in full: `gateway.rs`, `gwauth.rs`, `admin.rs`, `typed.rs`, `guard.rs`, `metatx.rs`, `abi.rs`, `submit.rs`,
  `nonce.rs`, `signer.rs`, `keys.rs`, `chain.rs`, `breaker.rs`, `drift.rs`, `finality.rs`, `indexer.rs`, `external_pull.rs`,
  `service.rs`, `pqz.rs`, `tree_set.rs`, `dex.rs`, `dex/venue.rs`, `mesh/`, `store/`, `config.rs`, `addresses.rs`, `adapter.rs`, `main.rs`,
  `adapters/{evm,hedera,soroban,cosmos,near,algorand,aptos,solana,sui,ton}.rs`
- `scaas-node/migrations/`, `scaas-node/node.example.toml`, `Cargo.toml`, `Cargo.lock`; `scaas-node/tests/` and the in-file
  `mod tests` (read for what a test can and cannot fail)
- read-only, as the other side of a check: `T/smartcontracts/evm/test/vectors/selector_audit.json`, the contracts'
  `mtxSelectors()` and `_uaAllowed` (`T/smartcontracts/evm/src/`), each non-EVM family contract's entry list
  (`T/smartcontracts/<family>/`), `T/clients/scaas-rpc/src/pool.rs` (the node's indexer quorum is `scaas_rpc::pool::quorum_ok`)
- not in scope: `scaas-node/legacy/`, `scaas-pqz-verifier` (read only for the answer shape the node parses), the SCaaS testnet
  stack (outside this repository)

Size: about 120 K lines with the in-file tests; the adapters are about half. Suggested order, so a run that stops early has
covered the shared paths: `gateway.rs` / `gwauth.rs` → `typed.rs` / `guard.rs` → `submit.rs` / `nonce.rs` / `chain.rs` →
`pqz.rs` → `store/` → `indexer.rs` / `finality.rs` → `adapters/evm.rs`, `hedera.rs`, `soroban.rs` → the other adapters → `mesh/`,
`dex/`. List under "Not covered" every file you did not read in full.

**Specifications and rules to read first:**
- `T/docs/node/README.md`, `job-api.md`, `submit-lanes.md`, `gateway.md`, `store.md`, `ops.md`, `threat-model.md`
  (NODE-SEC-01); as needed `indexer-feeds.md`, `admin-auth.md`, `mesh.md`, `gossip.md`, `dex-venue.md`, `sponsorship.md`
- `T/docs/networks/README.md` (NET-ALL-*) and `T/docs/networks/<family>.md` for each adapter
- decisions ARCH-POS-13, ARCH-POS-15 (and its Changes of 2026-11-12, the node's failover), CTR-MTX-30, CTR-PQZ-36, CTR-PQZ-37
- `T/TODO.md`, item P6i (what is built and what is left in the node) and the node items under the EVM node's UA job path

**Invariants to check (beyond section 5; each a finding when it fails):**

a. **Allow-lists equal the contracts', per kind, in both directions.** `typed.rs` `TYPED` / `PLAIN` rows and `guard.rs`'s
   per-kind rules (`Rule::*`, `NOT_ROWS`) against each kind's `mtxSelectors()`, `_uaAllowed` and `selector_audit.json` (its
   `SIGNED`, unsigned-write and `GUARDIAN` classes). A node row the contract lacks, or a contract entry the node lacks, is a
   finding. Check that the tests that claim this (`allow_lists_equal_the_selector_audit_both_directions`,
   `pqvault_rows_equal_the_contract_both_directions`, `pqchat_rows_equal_the_contract_both_directions`, `service.rs`
   `entries_equal_both_directions`, the PQZ kind test) compare both directions and can fail, and that `selector_audit.json` is
   generated from the contracts, not hand-kept. Non-EVM: a `signed_op` naming another function is `SELECTOR_NOT_ALLOWED`
   (NET-ALL-27); compare each family adapter's accepted functions with that family's contract. Rules: NODE-JOB-01, NODE-JOB-19,
   NODE-JOB-20, NODE-JOB-26, NODE-JOB-27, NODE-GW-03.
b. **Every untrusted decode is bounded by length and depth** (a stack overflow aborts the node). The gateway body caps
   (NODE-GW-08: `OP_BODY_MAX` 1,310,720 B on `/v1/op`, `BODY_MAX` 64 KiB elsewhere; check the route layer really overrides the
   router layer, and that the HMAC check reads each route only up to its own cap), serde_json's depth limit on every path that
   parses JSON (`Json<_>`, `serde_json::from_slice` / `from_value`, the PQZ verifier's answer, `UASig` two levels / 16 slots),
   the job API body (1 MiB), the family decoders (BOC: cell count, refs, and every recursive walk over cells, drop included, on a
   tokio worker stack; Algorand msgpack `MP_MAX_DEPTH`; XDR, Borsh, BCS, protobuf), every adapter's RPC answer, the indexer's
   logs and `eth_getLogs` spans, mesh envelopes and gossip frames (NODE-MESH-16: verify before decode), and the store's reads
   of its own rows. A panic on input (an `expect`, an index, an `unwrap` on untrusted data) is a finding.
c. **Job bytes are rebuilt by the node from named fields;** the host or contract verifies over what the node rebuilt
   (NODE-JOB-02, NODE-JOB-20, NODE-LANE-10, NODE-LANE-16). Old hex forms are refused `HEX_ARGS_REFUSED` / `HEX_DATA_REFUSED`;
   `struct = call` is refused; no input is packed bytes holding several fields (only one crypto object stays `bytes`). Check the
   non-EVM `signed_op` too, whose `payload` is the exact signed bytes the node decodes `from`, lane, nonce, `valid_until` and
   relayer from (job-api.md, payload by kind); and `POST /v1/ops` step 3: gateway.md says that outside Soroban the families take
   the op's own `digest` (the node's own digest for them is SPECIFIED), so say what the intent id, the origin key, the G2
   in-flight key and `Accept::DuplicateDigest` guarantee when one op arrives under two digests, or two ops under one digest.
d. **Never report `dead` while a transaction may still land.** The lanes (`submit.rs`, `nonce.rs`, `chain.rs`), replacement
   and fee bumps (NODE-LANE-09: consumption checked before every bump), nonce gaps and gap fills (NODE-LANE-04: an outer nonce
   is never abandoned), the three expiry verdicts, failover answers (`FAILOVER_ANSWER`: no failover endpoint's answer makes a
   job `dead`; ops.md), restart recovery (a tracked transaction the RPC no longer knows), cancel (NODE-JOB-07, NODE-JOB-11:
   `cancelled` is reported `dead`), lane binding (NODE-JOB-08), PQZ debits held above the lane's cap (NODE-JOB-24), and every
   family adapter's own receipt and expiry reading. The known open case: TODO P6i's "Open for T22 / owner" note, **a cancel one
   nonce ahead is reported `dead` `MetaTxBadNonce` although the signed message could land once the gap fills**; trace it and
   every case of the same class (a nonce, sequence or seqno ahead of the chain's, on every family). The in-flight cap
   `max_inflight` (NODE-LANE-24, default 16): enforced per lane, and what happens at the cap (queued, never `dead`).
e. **The node holds no subject funds or keys.** A lane key holds gas only and never a contract role (NODE-LANE-03,
   NODE-LANE-08, NODE-LANE-20; `keys.rs`, `signer.rs`): check that no config, deploy default or code path makes a lane address a
   role holder, a fee recipient that is a lane where the spec forbids it, or a payee. Lane-funded deposits come back
   (NODE-LANE-18); value out per job is capped (NODE-LANE-17). `node.example.toml` holds no secret, only env names, files or
   keystores. Config loading (`config.rs`: file modes, the keystore, `*_env`), `Debug` / `Display` of config and key types,
   logs (NODE-OPS-10), metrics labels, `/readyz`, gateway and job-API errors (`redact_urls`: a credential in an RPC or verifier
   URL), the audit log's `before` / `after` rows (`boot_audit`) carry no secret.
f. **No decryption oracle (ARCH-POS-13).** Nothing in the node decrypts or opens a ciphertext someone else chose. The PQZ
   `OFFCHAIN` verdict path (`pqz.rs`: `offchain_config`, `key_scope`, the verdict rebuild, `fetch` / `ask`, `check_shield`) and
   `pqz_fee` (CTR-PQZ-36, `PQZ_FEE_MISMATCH`) leak nothing about a plaintext: check what of a verifier endpoint's answer (its
   HTTP status, its body, its timing, which endpoint answered) reaches the submitter through a job error, a gateway reply, a
   job state or a timing difference, and whether any of it can depend on a decryption the verifier ran (CTR-PQZ-37: the opening
   token's verifier opens). The node signs no verdict and holds no verifier key.
g. **RPC node lists (ARCH-POS-15).** `Chain::read` (`chain.rs`): one endpoint answers a whole read, never a mix; a failover
   endpoint is used only on the chain's id and block 0, at or above the highest head seen; a revert from a failover endpoint
   is a transport error. Writes send the same signed bytes (never re-signed per endpoint), journal before broadcast, one
   transaction per nonce (NODE-LANE-12). The indexer's quorum (NODE-IDX-01, `finality_quorum`, `quorum_ok`): what it counts
   and whether it is a strict majority where the config claims one. A read that feeds a decryption may use a discovered node
   only under the majority option with at least three nodes: name every node read whose bytes could feed one (there should
   be none in the node; say so if that holds). The same per family adapter (each one's `ARCH-POS-15` failover block).
h. **The gateway** (`gateway.rs`, `gwauth.rs`, gateway.md): auth (NODE-GW-02: `none` refused off loopback, bearer compared in
   constant time, HMAC over ts, nonce, method, path and body, skew 300 s, nonce replay window, header case), CORS only with
   auth `none` (NODE-GW-04), the concurrency limit, per-IP rate limits being the reverse proxy's (runbooks), no HTTP redirect
   followed by the node's own clients (verifier endpoints, RPC, mesh), the error contract (NODE-GW-06: `{error, code, detail}`;
   which routes still answer `{error}` without `code`), `POST /v1/op`, `POST /v1/ops` (plan T28: the accept checks in order,
   the `~gateway` row, `bus_scope = restricted`), `POST /v1/ua-metatx`, `POST /v1/metatx` (refused by name), `GET
   /v1/intents/{intent_id}` (gateway-origin rows only; 404 alike for peers, job-API rows and unknown ids, no oracle on which
   ids exist), the DEX routes (dex-venue.md routes, `max_open_per_maker`, TTL bounds). Door A is no free gas tap (NODE-GW-01).
   The EVM doors still feed an in-memory queue, not journaled (gateway.md, "Transitional"): what is lost on a restart.
i. **The indexer** (`indexer.rs`, `finality.rs`, `external_pull.rs`, indexer-feeds.md) reads at or below the final block only
   (NODE-IDX-02: `finality_mode` `depth` / `tag`; no tag means wait, never guess), handles reorgs as NODE-IDX-03 states (none
   after hard finality; what `depth` mode claims on a chain without it), emits only logs from the expected emitter, keeps the
   cursor monotonic, and bounds pruned rounds and tombstones (NODE-IDX-07, NODE-JOB-11).
j. **Family adapters** (`adapters/*.rs`), each against its `T/docs/networks/<family>.md`: evm, hedera, soroban, cosmos, near,
   algorand, aptos, solana, sui, ton. For each: the family's chain-specific traps (fee and resource caps, storage rent and TTL,
   sequence and nonce rules, simulation versus inclusion, receipts and finality, the forward-value cap), the signature check
   before simulation (NET-ALL-14: a `None` verifier goes to simulation), NET-ALL-25 at lane start (the chain pair), the hex
   forms (Soroban job leaf bytes need `0x`, a `u256` takes digits only). Mesh has no Soroban arm (`FAMILY_NOT_SUPPORTED`,
   NODE-MESH-07). TON (GRAM) is refused by name on `/v1/ops` until NET-TON-14's node half is in code: check that no other
   gateway path reaches a GRAM lane and that the pull path enforces the forward cap.
k. **The store** (`store/mod.rs`, `store/sqlite.rs`, `migrations/`, store.md): SQLite as built (NODE-STO-06 names PostgreSQL /
   MySQL: say which are built), the audit log hash chain (`audit_hash`: the canonical form, length prefixes, NULL marker;
   `verify_audit`; `boot_audit` rows at start; what the chain detects and what an attacker with write access to the file can
   still do; NODE-ADM-07), the job state machine (every transition the code allows against `scaas-node/tests/api/transitions.json`
   and job-api.md; no transition out of a final state; the CAS claims NODE-JOB-06, NODE-JOB-14, NODE-JOB-21), idempotency
   (NODE-JOB-04, JCS `payload_hash`; the gateway's `keccak256` of its own serialisation), quotas.
l. **The payer service** NODE-SPN-05 (the Arweave credit payer): SPECIFIED, nothing built. **Out of scope until built**; say
   so in "Not covered", and report only code that already acts as a payer.
m. **The review-fix round's rows** (added 2026-11-26): an empty `addWraps` / `addVaultWraps` refused by name, as the
   contract does (A-5, `typed.rs` `empty_wraps_refused`); the tree bounds equal to the contract's after R8 512 and C10 20
   (`typed.rs`: leaves 512, targets 511, node keys 9, changes 20; both directions); `meta_executed` (`chain.rs`) picks the log
   that matches the digest, not the first with the nonce (E-6, `pick_executed_matches_the_digest`); a router op of a derived
   subject reads `mtxNonceFor(target, from, lane)` (`subject_nonce`, CTR-GOV-33); the `msig` version tag travels inside the
   signature object (CTR-UA-74), so the node forwards it unchanged and a job with a stale tag fails on chain
   `UAUnauthorized`, as `T/docs/node/job-api.md`'s operators' note says (A-4); a reverted exit within the lag is a SPECIFIED
   plan row (D2-5, TreeKEM plan T4): report it only where code claims it.
n. **The whole-set guard and path-less commits** (added 2026-11-28; `T/docs/node/job-api.md#tree-set-guard`, CTR-CHAT-27's
   Changes of 2026-11-26 / -27, the path-less delta spec R17-R20): `tree_set.rs` with `submit.rs` relays a tree commit as one
   `commit` job holding its whole set; every piece checked against its signed hash and every node key against the admission
   check before any send (`TREE_SET_REFUSED`, zero sends); the parts sent in C37's order, each only after the one before is
   in state at the final block, the job `queued` under `TREE_SET_SENDING` meanwhile and never `dead` while a part may land; a
   path-less commit (no path list) passes the same guard with the rows the contract accepts and no more.
o. **PENDING LANDING (`pqchat-core-confirm`): door A takes the six signed `PqChat` topic records** (NODE-GW-09, CLI-PQC-18 F3):
   `gateway.rs` and `guard.rs`: only `createTopic`, `updateTopic`, `setTopicWriter`, `postEntry`, `editEntry`, `voteEntry`,
   each with its `UASig` and `validUntil`, on a target the chain's `token_factory` lists as class 3 with a release
   (`CALL_TARGET_REFUSED` otherwise); every other `PqChat` write stays a job of a namespace with the grant; the intake (the
   operator's switch `params.relay_pqchat_topics`, `PQCHAT_TOPICS_NOT_RELAYED`; the hourly bucket per signing key
   `PQCHAT_TOPICS_RATE`; a repeat in the hour answered `queued` without a second queueing) bounded in memory; the allow-list
   equal to the contract's both ways (`typed.rs`, `selector_audit.json`); the bytes sent are the signed record rebuilt from
   named fields, nothing else.

**Prior reports (do not re-report what they list as fixed; give the closure table):**
- `scratchpad/review-ua-mtx-merge/E-node-clients.md`, `recheck-node.md`, `recheck2-node.md` (Fable E N-1 to N-11 and the
  rechecks; their fixes are the ARCH-POS-15 and NODE-GW-* Changes of 2026-11-12 in `T/docs/decisions.md`)
- `scratchpad/review-fix2/node.md` (Fable check of fix round 2, node part); `scratchpad/node-ua-jobs-review.md`,
  `scratchpad/node-ua-jobs-report.md`; `scratchpad/governance-review-node-clients-docs-2026-11-04.md`;
  `scratchpad/ua-mtx-merge-review-codex-2026-11-04.md`, `scratchpad/ua-mtx-merge-review-fable-2026-11-04.md` (node findings)
- `scratchpad/sdk-complete-review/` (the T13-T20 reviews: the node rows of the SDK round), `scratchpad/chains-arweave-review/20261121-fable-contract-review.md`
  (the node's `PqChatStore` row, NET-ALL-25 at lane start)
- the review-fix round (2026-11-24 to -26, local; the node rows: area D of the code review, E-6, D2-5, A-4, A-5): the TreeKEM and G1 code review
  `scratchpad/treekem-g1-review-20261124-1550/` (`BRIEF.md`, Fable areas A-G at `8cac68125`; its fixes, red tests and
  mutants in `T/smartcontracts/evm/runs/2026-11-24-review-fix-contract-summary.txt`), the re-review
  `scratchpad/review-fix-review-20261125-1959/` (`STATUS.md`: verdict, branch, fix commit, red test and mutant per finding;
  `fable-{A..G}.md`) and the fix check `scratchpad/review-fix-check-20261126-0429/` (`STATUS.md`, `fable-{A,R,C}.md`)
- `T/docs/research/security-review-record.md` (part 3, the node relay, not done before this unit)
- added 2026-11-28 (local, `STATUS.md` in each): the TreeKEM client round's review `scratchpad/treekem-t4-t9-review-20261126-1808/`
  and re-check `scratchpad/treekem-t4-t9-recheck-20261126-2332/` (the node's whole-set guard); the path-less review
  `scratchpad/treekem-pathless-review-20261127-1527/`; pending landing: `scratchpad/pqchat-core-confirm-review-20261128-0133/`
  (NODE-GW-09: C-1 = E-3, C-2)

**Gate evidence at the tag (read for what was run; a green gate proves nothing by itself):**
- `T/smartcontracts/evm/runs/2026-11-18-prefreeze-matrix-summary.txt`, `2026-11-19-pr-a-matrix-summary.txt` (node test,
  clippy, e2e and the per-family e2e rows), and the tag's own node gate summary
- `T/scaas-node/runs/2026-11-12-fix2-node-mutants.txt`, `2026-11-08-ua-mtx-merge-t47-summary.txt`,
  `T/smartcontracts/evm/runs/2026-11-21-pqvault/node_mutants.py`
- `T/runs/2026-11-23-pqchat-treekem-t4-summary.txt` and `-t4-mutants.txt` (the node's tree rows)
- the review-fix round: `T/smartcontracts/evm/runs/2026-11-24-review-fix-contract-summary.txt` (with
  `2026-11-24-review-fix-contract-mutants.py`), `2026-11-26-review-fix4-contract-summary.txt`, and the round's closing
  matrix (`2026-11-26-round-matrix.sh` and its summary)
- added 2026-11-28: `T/runs/2026-11-27-treekem-pathless-combined-summary.txt`, `-matrix-summary.txt`,
  `-nethermind-rows.txt`; pending landing: the `pqchat-core-confirm` rows of `T/clients/pqchat-core/runs/2026-11-17-pqchat-core-summary.txt`
  and `2026-11-28-pqchat-core-confirm-mutants.txt` (the gateway's door-A rows)

**Also accepted or known for this unit (do not report as such):**
- Documented status: what a node doc marks SPECIFIED or PLANNED is not a finding for being unbuilt (the start-up probe
  `has_pqz_precompile`, NODE-GW-07's chain binding, job kind `pqz_call`, the rollover keeper, `/v1/gateway`, `/v1/ua/register`,
  the UA record cache, the payer). Report it when code already claims it, or when its absence breaks a section-5 rule on a
  built path.
- The flat `params.relay_fee.min_amount` until before mainnet (owner ruling 2026-10-31: option (c), the per-token price, is
  built with P6i; option (d), a floor in the router contracts, is ruled out).
- Open in TODO and known: the restart fee basis churn, the forgotten transaction after a restart (gap-filled, no subject hold;
  a small I2 window), relay-fee starvation of one subject, the Soroban per-job resource-fee cap (an operator policy). Report
  only a consequence worse than TODO states, or a new path.
- Mesh without a Soroban arm and TON refused on `/v1/ops` are by design (above). The SCaaS testnet's RPC exposure is not a finding.

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1; added 2026-11-24). Apply every dimension within this unit's
scope; each row says what to hunt here. A row marked `N/A` gives its reason and stays. Every finding names its dimension
number (section 9).

| # | Dimension | What to hunt in this unit |
|---|---|---|
| 1 | Conformance | NODE-JOB-*, NODE-LANE-*, NODE-GW-*, NODE-IDX-*, NODE-STO-*, NODE-MESH-*, NODE-SEC-01, NET-ALL-*, ARCH-POS-15 and its 2026-11-12 Changes against `scaas-node/src/`; each BUILT section of `docs/node/` with code and a test; what is SPECIFIED not claimed by code (section 8 "Also accepted"). |
| 2 | Cryptography | The digests the node rebuilds (EVM typed data in `typed.rs` / `metatx.rs`, the non-EVM `signed_op` payloads) equal the contracts'; the gateway HMAC (ts, nonce, method, path, body) and the constant-time bearer compare; the audit log hash chain (`audit_hash`); the `PqzVerdict` answer the node parses but never signs. |
| 3 | Security | Leads within the unit: the node relays only bytes the subject signed (invariant c); allow-lists both ways (invariant a); lane keys hold gas only (invariant e); gateway auth and door A (invariant h); a lying or forked RPC endpoint (invariant g). |
| 4 | Rules that do not bend | The node is open (no consumer-specific rule); never `dead` while a transaction may land (invariant d); no decryption oracle (invariant f); every RPC consumer takes a list (invariant g); explicit parameters and `HEX_ARGS_REFUSED`; no chain assumption per adapter; one rule on every chain. |
| 5 | Secrets and privacy | No lane key, mnemonic, keystore passphrase, gateway secret or RPC credential in a log, metric, error or reply (`redact_urls`, `boot_audit`); `node.example.toml` holds names only. |
| 6 | Robustness and denial of service | Every untrusted decode bounded by length and depth (invariant b); lane drain and billed failures; `max_inflight`; queue backlog; the in-memory EVM door queue across a restart. |
| 7 | Failure handling | Never `dead` while a transaction may land (invariant d, the cancel one nonce ahead); restart recovery; reorgs and finality (invariant i); the job state machine with no transition out of a final state (invariant k). |
| 8 | Consistency across languages and layers | Allow-lists equal to the contracts' (`typed.rs`, `guard.rs`, `selector_audit.json`, `mtxSelectors()`, `_uaAllowed`) and each family adapter's accepted functions equal its contract; the job API JSON shape equal to the SDK's `NodeClient`. |
| 9 | Contract specifics | N/A: no contract code (the contracts are the other side of invariant a). |
| 10 | Performance and cost | Lane gas per job and who pays; RPC round trips per job; store growth (pruned rounds, tombstones). |
| 11 | Interfaces and misuse | The job API and gateway errors (`{error, code, detail}`, NODE-GW-06) stable; a job shape change carries an operator note. |
| 12 | Tests | The allow-list tests compare both directions and can fail; node mutants (`runs/2026-11-12-fix2-node-mutants.txt`, the PqVault node mutants); `transitions.json` against the code. |
| 13 | Operations and the supply chain | Config without secrets; logs and metrics leak nothing; `Cargo.lock` pins and advisories; migrations; SPDX headers. |

## 9. Report format (Markdown, English)

```
# scaas-node: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### SND-1 [P1] <short title>
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
