# AI audit prompt, unit `scaas-sdk` (DRAFT, 2026-11-22)

Contracts audit at the pre-freeze target (owner rulings 2026-11-12: pre-freeze -> audit -> audit fixes -> freeze). This file is
self-contained: run it as it is, with any tool (Codex, agy, a Claude workflow, Fable, ...). Placeholders the controller fills
before the run: `<TAG>`, `<SHA>`. For the uniffi bindings only, if they are not merged at the tag: `<BINDING_SHA>` (section 8).

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

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-scaas-sdk.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.2-astra-high-scaas-sdk.md`, `20261120-09-agy-gemini-4-argon-high-scaas-sdk.md`). Use the tool's
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

`scaas-sdk` is the only API apps call (CLI-SDK-01): it signs through `ua-rs`, reads and sends through `scaas-rpc`, and is
exposed to every language through its bindings. Attackers: a malicious, lagging or forked RPC endpoint (named, default or
discovered), a malicious SCaaS node, gateway, bundler or Arweave gateway feeding answers to the SDK; a malicious counterparty
handing over a signed operation or a ciphertext; a malicious app or app core calling the API or a binding out of order
(a handle used after free, from another vault, on another thread); a local attacker who reads memory, logs, errors, the
write-ahead rows or a backup. Goals: the user signs something other than what was quoted and shown, or a digest valid
elsewhere (another chain, `chain_uid`, token, kind, op, nonce lane, relayer); a signature is made where a refusal was due; a
balance or a decryption rests on one lying node or on a block that is not final; a decryption failure on attacker-chosen data
becomes observable (an error, a status, a timing, a later send); a secret crosses the FFI as raw bytes or reaches an error, a
log or a `Debug` print; a decode crashes or exhausts memory (bounded by length and depth); a profile with a missing or unknown
field loads with a default; a payer request links a user to the content it pays for.

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

## 8. Your unit: `scaas-sdk`

The SDK crate, its FFI crate and bindings, and the RPC layer under it: quotes, refusals, digests, submission, the reading
layer, the confidential reads, the app-core surface.

**Scope (paths under `T/`):**
- `clients/scaas-sdk/src/` in full (`account/`, `admin/`, `admin.rs`, `app_core.rs`, `confidential/`, `config.rs`, `dex.rs`,
  `error.rs`, `events.rs`, `frb.rs`, `lib.rs`, `line.rs`, `op/`, `platform.rs`, `pqchat_keys.rs`, `pqchat_records.rs`,
  `surface.rs`, `text.rs`, `vault/`, `wallet/`, `watch.rs`, and `binding.rs`, `binding_list.rs` once merged)
- `clients/scaas-sdk/ffi/` (the flutter_rust_bridge crate; `frb_generated.rs` is generated: read the surface it exposes),
  `clients/scaas-sdk/bindings/` (the Dart binding; the uniffi bindings and their hand-written glue for C++, C#, Python, Kotlin,
  Java, Swift, JS / TS and Go: `copycall.*` / `CopyCall.*`, `fix_generated.py`, `lib.sh`, `rows.py`, the smoke tests)
- `clients/scaas-rpc/src/` in full (`pool.rs`, `endpoint.rs`, `http.rs`, `node.rs`, `error.rs`, `evm.rs` and each family file)
- `clients/scaas-sdk/{Cargo.toml,Cargo.lock,deny.toml,.cargo/audit.toml}`, `clients/scaas-rpc/{Cargo.toml,Cargo.lock,deny.toml}`,
  `clients/scaas-sdk/gas/` (the gas table generator: data, not code paths, CLI-SDK rules on gas tables), `tests/` of both
  crates (read for what a test can and cannot fail)
- read-only, as the other side of a check: `T/clients/ua-rs/` (the signer; audited in the `ua-rs-*` units),
  `T/smartcontracts/evm/src/common/MetaTxLib.sol` (`canon`), `T/smartcontracts/vectors/`
- **The uniffi bindings** are on branch `sdk-binding` (not merged on `main` at the time of writing). If `T/` has no
  `clients/scaas-sdk/bindings/{cpp,cs,go,java,js,kotlin,python,swift}/`, the controller fills `<BINDING_SHA>` before the run (the
  `sdk-binding` commit that holds them) and you read those paths with `git -C T show <BINDING_SHA>:<path>`; if neither exists, list them under
  "Not covered".

Size: `scaas-sdk/src` about 35 K lines, `scaas-rpc/src` about 8 K, the FFI crate about 39 K (mostly generated), the uniffi
glue small beside its generated code. Order: `scaas-rpc` `pool.rs` / `endpoint.rs` → `op/` → `confidential/` → `account/` →
`app_core.rs` → `config.rs` → the FFI surface and the bindings → the rest.

**Specifications and rules to read first:**
- `T/docs/clients/scaas-sdk.md` (CLI-SDK-01 to -21), `T/docs/clients/scaas-rpc.md` (CLI-RPC-01 to -14), `T/docs/clients/ua-libraries.md`
  (CLI-UAL-64, -65 for the Arweave seal), `T/docs/clients/signers-clientkeys.md`
- specs `T/docs/superpowers/specs/2026-11-17-scaas-sdk.md` (§27.5: self-relay, the hand-off), `2026-11-17-scaas-rpc.md`,
  `2026-11-21-avax-polkadot-arweave.md` (part D, Arweave)
- decisions ARCH-POS-13, ARCH-POS-15, ARCH-POS-18, ARCH-POS-19, ARCH-POS-20, CLI-SDK-30 to -33 (owner rulings and controller
  calls of the SDK, the done rule, Q-R3 and the hand-off in CLI-SDK-32 / -33's Changes of 2026-11-22), CLI-RPC-04, CLI-RPC-06;
  `T/docs/networks/README.md` NET-ALL-25; `T/docs/node/sponsorship.md` NODE-SPN-05

**Invariants to check (beyond section 5; each a finding when it fails):**

a. **Reads that feed a decryption or a balance proof** run as `Purpose::FeedsDecryption` (CLI-RPC-06): a discovered endpoint
   only under the strict-majority option with at least three nodes (`AgreementNeedsThree`, `NoTrustedEndpoint`), a pinned
   `chain_uid`, agreement per node over the whole read at one block by hash, at the profile's final block. Failover never
   mixes nodes inside one read (ARCH-POS-15, CLI-RPC-04): check `scaas-rpc` `pool.rs` (`usable`, `failover`, the agreement
   path, the freshness window, `agreed_floor`) and every SDK caller: `confidential/{read,pqz,pqz_debit,words,zether,verdict}.rs`
   and `app_core.rs`, where the app core chooses the purpose of a view read (`trusted`): list every read whose bytes enter a
   decryption, a balance shown as proven or a PQZ / Zether proof, and say each one is marked; a `Plain` read that feeds one is a
   finding.
b. **Digests and typed data equal the contracts' and `ua-rs`'s.** Every EIP-712 struct, domain (`salt` = `chain_uid`) and
   non-EVM digest the SDK builds or hands to `ua-rs`: unbound `relayer` / `feeRecipient` zeroed as `MetaTxLib.canon` does, and
   tested with a **non-zero** unbound value (vectors already canonical cannot show a client that forgets). The SDK never signs a
   digest it did not rebuild from named fields: trace each signing call (`op/prepared.rs`, `op/submit.rs`, `account/`,
   `admin.rs`, `dex.rs`, `app_core.rs`) from its named inputs to the `ua-rs` call. CLI-SDK-08, CLI-SDK-16.
c. **Every refusal happens before signing.** `KindDisabled` / `RegistrationKindDisabled`, `FeatureMissing`, `FeeAboveCap`
   (including the OP-stack L1 data fee in the quote, `tests/l1_fee.rs`), `GasAboveTxCap` / `GasAboveBlockShare` /
   `Limits::max_gas` (EIP-7825, EIP-8037), the profile checks, the chain pair `(chainId, chain_uid)` (NET-ALL-25), and
   simulate-before-submit on self-relay. A quote makes no signature. For each signing path, show that no signature, and no
   write-ahead row holding one, exists when a refusal is due (CLI-SDK-09, CLI-SDK-15, CLI-SDK-18).
d. **No decryption oracle (ARCH-POS-13).** In `src/confidential/`, the PQZ and Zether reads, the app-core handles
   (`app_core.rs`, `pqchat_keys.rs`, `pqchat_records.rs`, `vault/`), a decryption failure never reaches a source and nothing the
   client sends depends on it (CLI-SDK-10); the same in the Arweave `fetch_file` / `open_file` path once it lands (CLI-SDK-21:
   the read check, then the open in `ua-rs`, `FileHashMismatch` shown on the device only): no error, status, timing or later
   action distinguishes attacker-chosen ciphertexts.
e. **Secrets never cross the FFI as raw bytes;** they cross as handles (CLI-SDK-02, CLI-SDK-12, CLI-SDK-20). Error strings
   and logs carry no secret (CLI-SDK-13). Handle lifetime in each binding's GC or finalizer: zeroize on drop, no use after free,
   no double free, a handle from another vault refused, thread rules as documented. The uniffi surface plus the hand-written
   glue per language: C++, C#, Python, Kotlin, Java, Swift, JS / TS, Go; and the Dart (flutter_rust_bridge) surface.
f. **Every untrusted decode is bounded by length and depth:** RPC answers (each family file of `scaas-rpc`), node answers
   (`node.rs` `NodeClient`, `OP_BODY_MAX` before sending), gateway and bundler answers, profiles, app-core inputs
   (`READ_DEPTH`, `type_depth`), the bindings' inputs. A panic on input is a finding.
g. **Profile loading fails closed** (`config.rs`, CLI-SDK-15): a missing finality depth, an unknown kind name, an unknown
   fork and an overlay are refused as specified (`deny_unknown_fields` where it should be, no `#[serde(default)]` that turns a
   missing safety field into a value); the chain is asked, never assumed.
h. **Hand-off / `import_signed`** (if landed by the tag; CLI-SDK-33's Change of 2026-11-22, item (23), and the owner's Q-R3
   of the same day under CLI-SDK-32): the payee imports a `SignedOpBlob` of named fields (at most 256 KiB, depth 8, unknown
   fields refused) only for an op whose `relayer` is unbound, or bound to the importer's own payer as item (23) allows (bound
   offered first); the imported bytes are verified against the digest the SDK rebuilt; the per-kind checks run in order with
   their named refusals (`ImportKindRefused`, `ImportNotPayee`, `ImportRelayerBound`, `ImportFeeRefused`, `ImportExpired`,
   `ImportConsumed`, `ImportedOpRefused`), the importer's simulation first; a kind the family cannot check before sending is
   refused; a payment counts as received only on `Landed`.
i. **Arweave payment paths** (if landed by the tag; CLI-SDK-21, NODE-SPN-05): the operator path sends only the upload address,
   the signature type and the bucket, plus the gateway credential; no UA, no UA signature, no content; the client holds no
   operator credential; the bounded re-post schedule re-sends the same bytes only; self-pay's linkage is warned to the user
   before the first upload.

j. **The T26 review fixes and the F2 shared line reader** (plan T26, the SDK review of 2026-11-23; added 2026-11-24).
   `T/clients/scaas-sdk/src/line.rs` is the one off-chain reader of the registry line (spec
   `T/docs/superpowers/specs/2026-11-19-registry-verify-only-kinds.md` §11.1, §11.2, §12; CTR-UA-65, CTR-UA-70):
   `holderOf(ua)` resolved once on the profile's bound registry, the record read at `holder`, the PQZ attachment at
   `pqzHome`, the walk at most `MAX_GENERATION` (16) generations, `read_line` / `Line` on one endpoint at one block, a
   revert or an unchecked holder or generation never a silent fallback (A-7, folded into F2), the decoy candidates
   `decoy_candidates` within `DECOYS_MAX`. Check every caller that must go through it does: `require_signed_records`
   (`app_core/agreed.rs`, TODO 8b-8 (4)), `line::receiver_registered` from all four payment prepares (B2-9), the
   kept-signature check V1 (TODO 8b-8); and list the reads that still use a single forwarded view of the bound registry
   (`prepare_register`'s `isRegistered`, `expandedKeyOf`, `pqzPopOf`, `kemKeyAt`; `account/sponsor.rs`; `read_record`;
   pqchat-core's `kemKeyOf` / `kemKeyAt` / `checkedOf` / `msigOf`), each said correct by CTR-UA-70: check that claim, read by
   read. The other T26 fixes, each against its finding: A-5 / A-5 part b (`AppPrepared`, `PqChatPrepared`,
   `PqCardPrepared`: prepare returns the review and the digest, the key opened only at `sign()`), A-6
   (`Vault::accept_rollback`, in `binding_list.rs`), A-9 (the PqChat scope on every record entry), A-10 (`infoOf` at the
   final block), B-17 (`read_app` always `FeedsDecryption`, `read_app_plain` the explicit plain read), A2-1 (`seal.rs`
   `msig_ok` / `accepted_ok` with `Current`), A2-4 (`_usable` = `proven || OFFCHAIN` for the holder too), B-20
   (`http::read_capped`, one capped read on both targets), B-22 (`Depth(0)` refused at `Sdk::open` outside chain 31337 or
   feature `dev-profiles`), B2-15 (`TokenBalance.unknown`); and the findings left open in `STATUS.md` (A2-2, A2-3, A2-7, B2-7,
   B-19's Aptos point): say which are still open at the tag. Every fix should have a red-first test and a killed mutant
   (`T/clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t26-mutants.py`): name a fix whose test cannot fail.
k. **The review-fix round's rows** (added 2026-11-26; CTR-UA-74, CLI-SDK-34): `account/msig.rs` signs an `msig` with the tag
   of the version current at signing time and reads one `msigAt` per version a verified record names (at most 17);
   `app_core.rs`, `pqchat_records.rs`, `pqchat_keys.rs` keep the versions a verified record names and refuse a decrease along
   a chain (step 6, C-3 of the fix check: the test at `tests/app_core.rs` asserts the refusal); the exit review lines say the
   lag ("applies if it lands within 16 epochs", F-4); before signing, the target's registry generation knows every derived
   UA named (CLI-SDK-34); the gas reference table (`gas/reference.json`) re-measured after the registry change.

**Prior reports (do not re-report what they list as fixed; give the closure table):**
- the T26 review: `scratchpad/sdk-review-20261123-0621/` (`BRIEF.md`, `fable-A.md`, `fable-A2.md`, `fable-B.md`,
  `fable-B2.md`, `fable-C.md`, `STATUS.md` with the fix commits and the controller decisions (103)-(161), of which (150) and
  (151) are owner rulings)
- `scratchpad/sdk-complete-review/20261120-fable-review-t13-t20.md`, `20261120-fable-review-t13-t20-tests.md`,
  `20261120-fable-review-merged.md`; `scratchpad/sdk-binding-review/20261120-fable-review-t20b-h.md`
- `scratchpad/pr-a-review/20261119-claude-review.md`; `scratchpad/avax-dot-arweave-review/20261121-fable-spec-review.md`;
  `scratchpad/sdk-keys-research-fable-review.md`
- the review rows recorded in `T/docs/decisions.md` under CLI-SDK-31 / -33 and CLI-RPC-*
- the review-fix round (2026-11-24 to -26, local; the SDK rows: F-4, D2-*, C-3, R-2): the TreeKEM and G1 code review
  `scratchpad/treekem-g1-review-20261124-1550/` (`BRIEF.md`, Fable areas A-G at `8cac68125`; its fixes, red tests and
  mutants in `T/smartcontracts/evm/runs/2026-11-24-review-fix-contract-summary.txt`), the re-review
  `scratchpad/review-fix-review-20261125-1959/` (`STATUS.md`: verdict, branch, fix commit, red test and mutant per finding;
  `fable-{A..G}.md`) and the fix check `scratchpad/review-fix-check-20261126-0429/` (`STATUS.md`, `fable-{A,R,C}.md`)

**Gate evidence at the tag (read for what was run; a green gate proves nothing by itself):**
- `T/clients/scaas-sdk/runs/2026-11-17-scaas-sdk-summary.txt`, `2026-11-20-m20-nethermind-summary.txt`;
  `T/clients/scaas-rpc/runs/2026-11-17-scaas-rpc-summary.txt`, `2026-11-22-evm-probes-summary.txt`;
  `T/smartcontracts/evm/runs/2026-11-19-pr-a-matrix-summary.txt`, and the tag's own client gate summary (bindings included)
- T26: the gate rows in `T/clients/scaas-sdk/runs/2026-11-17-scaas-sdk-summary.txt` at the T26 merge, and the T26 mutant
  records (`2026-11-17-scaas-sdk-t26-mutants.py` and its record: area A 26 of 26, area B every row killed after the reruns)
- the review-fix round's client rows: `T/clients/runs/2026-11-25-review-fix-client-summary.txt`,
  `2026-11-26-review-fix3-client-summary.txt`, `2026-11-26-review-fix4-client-summary.txt` (with their `-mutants.py`
  runners), and the round's closing matrix (`T/smartcontracts/evm/runs/2026-11-26-round-matrix.sh` and its summary)

**Also accepted or known for this unit (do not report as such):**
- What the SDK docs mark SPECIFIED or PLANNED is not a finding for being unbuilt (invariants (h) and (i) apply only if landed).
  Report it when code already claims it, or when its absence breaks a section-5 rule on a built path.
- No gas figures in SDK code: per-chain measured rows live in release data; the forge reference table is an opt-in data file.
- The owner rulings recorded in CLI-SDK-30 and CLI-SDK-32 as ruled.

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1; added 2026-11-24). Apply every dimension within this unit's
scope; each row says what to hunt here. A row marked `N/A` gives its reason and stays. Every finding names its dimension
number (section 9).

| # | Dimension | What to hunt in this unit |
|---|---|---|
| 1 | Conformance | CLI-SDK-01 to -21 and -30 to -33, CLI-RPC-01 to -14, ARCH-POS-13, -15, -18, -19, -20, NET-ALL-25 against `clients/scaas-sdk/src/`, `scaas-rpc/src/`; the T26 decisions (103)-(161) as recorded; BUILT rows with tests; CLI-SDK-34 and CTR-UA-74 on the SDK side (invariant k). |
| 2 | Cryptography | The digests and typed data the SDK rebuilds (invariant b); the registry line it resolves before a key is chosen (`line.rs`, invariant j); the KEM wraps and app-core handles it hands to `ua-rs`; the Arweave seal's `ctSha256` check. |
| 3 | Security | Leads within the unit: every refusal before signing (invariant c); a signature only over bytes rebuilt from named fields; the hand-off import (invariant h); a lying node, gateway or bundler. |
| 4 | Rules that do not bend | No decryption oracle (invariant d); every RPC read that feeds a decryption under `FeedsDecryption` with the majority option (invariant a; B-17's `read_app` default); explicit parameters; maximal support across families; one rule on every chain. |
| 5 | Secrets and privacy | Secrets cross the FFI as handles (invariant e); no secret in errors or logs; what the Arweave payer path reveals (invariant i). |
| 6 | Robustness and denial of service | Every untrusted decode bounded (invariant f; B-20 `http::read_capped` on both targets); profile loading fails closed (invariant g). |
| 7 | Failure handling | Named refusals; no write-ahead row holding a signature when a refusal is due; `Landed` only after finality; failover never mixes nodes inside one read. |
| 8 | Consistency across languages and layers | Leads within the unit for the SDK side: digests equal `ua-rs` and the contracts, tested with a non-zero unbound value; the line reads equal the registry views; every binding (uniffi, Dart) exposes the same surface as `binding_list.rs`. |
| 9 | Contract specifics | N/A: no contract code (`MetaTxLib.canon` read only). |
| 10 | Performance and cost | RPC round trips per op and per line walk (`MAX_GENERATION`, `DECOYS_MAX`); wasm and mobile memory; quotes against the gas table data. |
| 11 | Interfaces and misuse | Leads within the unit: prepare -> review -> sign shows every field (`AppPrepared`, `PqChatPrepared`); defaults safe (`read_app` trusted); stable error codes; the CLI and bindings match the SDK. |
| 12 | Tests | The T26 red-first tests and mutants (invariant j); tests that cannot fail (a canonical-only vector row). |
| 13 | Operations and the supply chain | `deny.toml`, `.cargo/audit.toml`, `wasm-streams =0.4.2` (B-20, owner-agreed), lockfiles; SPDX headers. |

## 9. Report format (Markdown, English)

```
# scaas-sdk: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### SDK-1 [P1] <short title>
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
