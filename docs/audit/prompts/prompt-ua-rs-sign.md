# AI audit prompt, unit `ua-rs-sign` (DRAFT, 2026-11-16)

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

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-ua-rs-sign.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.2-astra-high-ua-rs-sign.md`, `20261120-09-agy-gemini-4-argon-high-ua-rs-sign.md`). Use the tool's
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

Attackers: a malicious counterparty, relayer, node or RPC feeding data to the library; a malicious caller of the JSON, C ABI or
binding boundary; a local attacker who reads memory, swap, logs, errors or a backup; a lost or reinstalled device. Goals: the
user signs something other than what it sees, or a digest valid elsewhere (another chain, `chainUid`, token, kind, op, nonce
lane); a key, seed, nonce or share leaks; a nonce is reused; a decode crashes or exhausts memory (bounded by length AND depth);
a secret reaches an error, a log or a `Debug` print; a decryption oracle on the client. ua-rs is the only signer every client
uses (owner 2026-11-05).

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

## 8. Your unit: `ua-rs-sign`

ua-rs single-signer schemes (classical and PQ) and the group schemes (MuSig2, FROST, DKG).

**Scope (paths under `T/`):**
- `clients/ua-rs/src/wallet/{sign,signer,pqsign,uasig,webauthn,tx}.rs`, `src/{falcon,pq,verify,keydata}.rs`
- `src/falcon/soft.rs` (the wasm32 glue over falcon-rs, CLI-UAL-66) and the `build.rs` / `Cargo.toml` routing of the two
  Falcon paths (added 2026-11-26; the falcon-rs tree is unit `vendor-falcon-rs`)
- `src/ua_portable.rs` (added 2026-11-26, as no layer unit held it: portable records and the `msig` reader rule by version,
  CTR-UA-74)
- `clients/ua-rs/src/{musig2,frost,groups}.rs`, `src/ua8.rs` where it builds group keys
- tests: `wallet_sign`, `wallet_pq`, `wallet_uasig`, `wallet_webauthn`, `wallet_tx`, `signatures`, `pq`, `groups`, `groups_verify`, `ua8`, `nested`, `fndsa_vrfy`, `fndsa/`, the `msig` reader rows

**Specifications and rules to read first:**
- spec `T/docs/superpowers/specs/2026-11-05-ua-rs-sign.md`, plan `T/docs/superpowers/plans/2026-11-05-ua-rs-sign.md`
- `T/docs/clients/ua-libraries.md`, `signers-clientkeys.md` (CLI-SGN-*, CLI-UAL-*), decisions ARCH-POS-13
- the contracts' verifiers as the reference of what verifies: `T/smartcontracts/evm/src/ua/`

**Invariants to check (beyond section 5):**
1. Nonces per kind: RFC 6979 ECDSA, BIP-340, the scaas Schnorr on bn254 / BLS12-381 with its 512-bit map, hedged ML-DSA, SLH-DSA, Falcon keygen from the seed; no release signature takes a caller RNG where the spec forbids it.
2. Low-s and malleability equal to the contracts; `UASig` and the `msig` minimal form; `sign_transaction` cannot produce a type-4 (EIP-7702) transaction.
3. MuSig2 / FROST: no nonce reuse (secret nonces consumed, not `pub` in release), session state, rogue-key defence, binding factors, DKG complaints, serialization bounds.
4. Imported keys map to the right kinds (secp256k1 -> 0x0108, ed25519 seed -> 0x0102).
5. **The `msig` version tag** (added 2026-11-26; CTR-UA-74): a new `msig` signature carries the tag of
   `msigStateOf(ua).version` read at signing time, and each `msig` member's own (`uasig.rs`); `ua_portable.rs` applies the
   reader rule's seven steps (the tag's forms, 8 zero bytes refused; `msigAt`; version 0 checked by `uaOf`; `enabled ∧
   accepted`; one level down for an `msig` member; step 6 along a chain; never another version, never `msigOf` for a kept
   record); a replica record compared with the home's with the tags stripped.
6. **Falcon on wasm32** (added 2026-11-26; CLI-UAL-66): `soft.rs` keys, signs and verifies through falcon-rs on wasm32 only,
   never natively, and fails closed by name; its wipes (FR-10), the padded retry, the public `ua_msg` as the only message of
   the variable-time hash-to-point (FR-7), the dependency's target gating (FR-12).

**Prior reports (do not re-report what they list as fixed; give the closure table):**
- `scratchpad/review-t21/` (T21 at `806f4f2c2`: `scope.md`, `ledger.md` with its FIX-NOW / OWNER / LATER / REJECT rows and the owner decisions O1-O8, the Fable and Codex part reports); the fix waves landed after it (`git -C T log --grep 't21'`)
- `T/docs/research/ua-rs-sign-fable-review.md`, `ua-rs-sign-codex-review.md`
- the review-fix round (2026-11-24 to -26, local; `ua-rs`: F-1, B2-1, C-4, R-1, R-3): the TreeKEM and G1 code review
  `scratchpad/treekem-g1-review-20261124-1550/` (`BRIEF.md`, Fable areas A-G at `8cac68125`; its fixes, red tests and
  mutants in `T/smartcontracts/evm/runs/2026-11-24-review-fix-contract-summary.txt`), the re-review
  `scratchpad/review-fix-review-20261125-1959/` (`STATUS.md`: verdict, branch, fix commit, red test and mutant per finding;
  `fable-{A..G}.md`) and the fix check `scratchpad/review-fix-check-20261126-0429/` (`STATUS.md`, `fable-{A,R,C}.md`)
- `T/docs/audit/audited/vendor-falcon-rs.md` (FR-6 to FR-12 touch the glue)

**Gate evidence at the tag (read for what was run; a green gate proves nothing by itself):**
- `T/smartcontracts/evm/runs/2026-11-16-ua-rs-sign-t21-summary.txt`, `2026-11-16-ua-rs-sign-sync7-summary.txt`, `2026-11-09-ua-rs-sign-t20d-summary.txt`, and the tag's own client gate summary
- `T/clients/runs/2026-11-26-ua-rs-wasm-fndsa-summary.txt`, `T/clients/ua-rs/runs/2026-11-26-ua-rs-wasm-fndsa-mutants.py` (12 glue
  mutants)
- the review-fix round's client rows: `T/clients/runs/2026-11-25-review-fix-client-summary.txt`,
  `2026-11-26-review-fix3-client-summary.txt`, `2026-11-26-review-fix4-client-summary.txt` (with their `-mutants.py`
  runners), and the round's closing matrix (`T/smartcontracts/evm/runs/2026-11-26-round-matrix.sh` and its summary)

**Also accepted for this unit (do not report):**
- T21 ledger rows marked REJECT or LATER, and the owner decisions O1-O8 as ruled (e.g. O2: the link key must arrive over an authenticated channel, the fingerprint compare is LATER)
- `crypto-bigint` 0.5.5 (RUSTSEC-2026-0387) through `frost-secp256k1` =3.0.0 is a known, ignored advisory (`T/clients/ua-rs/deny.toml`, reason recorded): report only a new path to it from a release signer

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1; added 2026-11-24). Apply every dimension within this unit's
scope; each row says what to hunt here. A row marked `N/A` gives its reason and stays. Every finding names its dimension
number (section 9).

| # | Dimension | What to hunt in this unit |
|---|---|---|
| 1 | Conformance | The ua-rs spec and plan (T21 parts 1, 2), CLI-SGN-*, CLI-UAL-* against `wallet/{sign,signer,pqsign,uasig,webauthn,tx}.rs`, `src/{falcon,pq,verify,keydata,musig2,frost,groups}.rs`; CTR-UA-74's reader rule and CLI-UAL-66 (invariants 5, 6). |
| 2 | Cryptography | Leads within the unit (with `crypto-signatures`): nonces per kind (RFC 6979, BIP-340, scaas Schnorr bn254 / BLS12-381 with its 512-bit map, hedged ML-DSA, SLH-DSA, Falcon keygen from the seed through vendored PQClean natively and falcon-rs on wasm32); low-s and malleability equal to the contracts; MuSig2 / FROST nonce handling, rogue-key defence, binding factors, DKG complaints; the `pq_msg` tag per kind; domain separation of `UASig`. |
| 3 | Security | Imported keys mapped to the right kinds (secp256k1 -> 0x0108, ed25519 seed -> 0x0102); `sign_transaction` cannot produce a type-4 (7702) transaction; a signature for one purpose usable for another. |
| 4 | Rules that do not bend | No EIP-7702; explicit parameters into each signer; every kind the contracts accept is signable (maximal support). |
| 5 | Secrets and privacy | Secret nonces consumed, never `pub` in release; keys in the arena only; no secret in errors or `Debug`. |
| 6 | Robustness and denial of service | Serialization bounds of group messages; no panic on a malformed share. |
| 7 | Failure handling | Named errors; a refused signing leaves no half-consumed nonce state. |
| 8 | Consistency across languages and layers | Every kind's signature verifies in the Solidity verifiers (`T/smartcontracts/evm/src/ua/`) and matches clientkeys rows (`pq.js`, `ua.js`) and the vectors; the reader rule equal to clientkeys `ua-verify.js` on the `msig` rows. |
| 9 | Contract specifics | N/A: no contract code. |
| 10 | Performance and cost | Sign time and memory of SLH-DSA and Falcon on mobile and wasm (Falcon on wasm32 through falcon-rs `fpemu`, integer-emulated floats). |
| 11 | Interfaces and misuse | Signer API: no caller RNG where the spec forbids one; prepare -> review -> sign shows every field. |
| 12 | Tests | Tests `wallet_sign`, `wallet_pq`, `groups`, `groups_verify`, the MuSig2 / FROST vector files; a negative test per malleability check. |
| 13 | Operations and the supply chain | `vendor/pqclean-falcon-seeded` and `vendor/falcon-rs-0.3.1` (repository root, git-ignored, installed and checked by `scripts/vendor.sh`, ARCH-POS-24) provenance and pins; `frost-*` =3.0.0 with the known advisory; `deny.toml` reasons; SPDX headers. |

## 9. Report format (Markdown, English)

```
# ua-rs-sign: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### URS-1 [P1] <short title>
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
