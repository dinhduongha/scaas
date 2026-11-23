# AI audit prompt, unit `ua-rs-custody` (DRAFT, 2026-11-16)

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

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-ua-rs-custody.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.1-sol-high-ua-rs-custody.md`, `20261120-09-agy-gemini-4-argon-high-ua-rs-custody.md`). Use the tool's
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

## 8. Your unit: `ua-rs-custody`

ua-rs wallet custody: vault, store, AEAD, seal / open, KEM, derivation, pairing, manifest, policy.

**Scope (paths under `T/`):**
- `clients/ua-rs/src/wallet/{vault,store,aead,seal,kem,derive,pairing,manifest,bounded,policy,service_pull}.rs`, `src/wallet/mod.rs`
- tests: `wallet_vault`, `wallet_seal`, `wallet_kem`, `wallet_keys`, `wallet_custody`, `wallet_memory`, `wallet_pairing`, `wallet_link`, `wallet_import_ua`, `wallet_external`, `wallet_nonce_wipe`
- the sealed PQZ leaf (invariant 6, added 2026-11-24): `src/facade/pqz.rs` (`derive`, `pqz_leaf_label`, `PqzKey::open_leaf`),
  `clients/ua-c/` (`scaas_ua_wallet_seal_pq_key`, `scaas_ua_pqz_open_leaf`), clientkeys `src/pq.js` (read as the other side),
  `smartcontracts/vectors/ua/pqz_leaf.json`; tests `pqz_leaf`, `vectors_marker`

**Specifications and rules to read first:**
- spec `T/docs/superpowers/specs/2026-11-05-ua-rs-sign.md`, plan `T/docs/superpowers/plans/2026-11-05-ua-rs-sign.md`
- `T/docs/clients/ua-libraries.md`, `signers-clientkeys.md` (CLI-SGN-*, CLI-UAL-*), decisions ARCH-POS-13

**Invariants to check (beyond section 5):**
1. Vault: scrypt bounds, NFKC, AEAD labels and AAD, single-use keys, `mlock`, zeroize, a foreign vault refused.
2. BIP-39 / HKDF derivation as specified; the UA KEM key (ML-KEM-1024 + X25519): small-order points, implicit rejection.
3. Seal / open: labels, AAD bound into the key derivation, the link window on the opener's clock (O3), equal backup generation (O4), handles revoked on lock.
4. Backup and export paths; signing policy `Expect`; `ExternalKey` verifies the signature before returning it.
5. No secret in an error, a log or a `Debug` print.
6. **The sealed PQZ leaf, `sealPqKey` / `openPqKey` (P6h (3), CLI-SGN-55)** (added 2026-11-22; finalized 2026-11-24 on the
   landed code, owner ruling 2026-11-22: P6h (3) lands before the pre-freeze tag). A new byte format in clientkeys, `ua-rs`,
   the vectors and every `ua-*` at once. Spec: `T/docs/clients/signers-clientkeys.md` CLI-SGN-55 (with CLI-SGN-02 vault v2,
   CLI-SGN-21 envelope bounds, CLI-SGN-49 key versions, CLI-SGN-50 leaf keys), `T/docs/contracts/pq-zero-knowledge.md` (seed
   custody, CTR-PQZ-13, CTR-PQZ-37). Code: `ua-rs` `src/wallet/mod.rs` (`Wallet::seal_pq_key`, `export_pqz_leaf_raw` /
   `export_pqz_leaf_raw_version` behind `AllowSecretExport`), `src/facade/pqz.rs` (`derive`, `pqz_leaf_label`,
   `PqzKey::open_leaf`), `src/wallet/vault.rs` (`Vault::seal`, the open path); `ua-c` `src/lib.rs` /
   `include/scaas_ua.h` (`scaas_ua_wallet_seal_pq_key`, `scaas_ua_pqz_open_leaf`) and the wrappers over them (`ua-cxx`,
   `ua-cs`, `ua-py`, `ua-go`, `ua-dart-frb`); clientkeys `src/pq.js` (`pqzKeySeed`, `pqzLeafLabel`, `sealPqKey`, `openPqKey`);
   rows `T/smartcontracts/vectors/ua/pqz_leaf.json` from `clients/clientkeys/scripts/pqz-leaf-vectors.mjs [--check]`; tests
   `clients/ua-rs/tests/pqz_leaf.rs`, `tests/vectors_marker.rs`, `clients/clientkeys/test/pqz-leaf.test.js`,
   `clients/ua-c/tests/test_vectors.py`, `clients/ua-cxx/tests/wallet_test.cpp`, `clients/ua-py/tests/test_wallet.py`.
   - The derivation: `seed32_v` = HKDF-SHA256(BIP-39 seed, salt `scaas.ua.pq.v1`, info `scaas.ua.pqz-mlwe.v1` ‖ u32
     account ‖ u32 index [‖ be64 v for v ≥ 1]) (CLI-SGN-49), derived once where the seed is (the arena in `ua-rs`, the key
     worker in clientkeys), both indices below 2^31 (`Argument` above); only the `registry` key class has a leaf
     (CTR-PQZ-37): the `offchain-shared` and `offchain-token` keys stay in their handles (CLI-SGN-51).
   - The bytes: a vault v2 of exactly 32 bytes under the label `pqz:registry:<account>:<index>:<version>` (decimal,
     canonical), stored under `vault:` + the label, its `id` the seed vault's so the AAD binds the leaf to its seed; the new
     passphrase policy and the PRF envelope as any vault. Check that the label is canonical (no leading zero, no sign, no
     second spelling of one triple) and that no other vault leaf's label can equal a leaf label.
   - The open: the vault must carry exactly the label of the asked `(account, index, version)` and a 32-byte payload; a
     wrong passphrase or PRF output, another leaf's label, an altered or truncated box or JSON, another payload length,
     another vault version or the tombstone, envelope parameters outside CLI-SGN-21 (refused before scrypt runs) and an id
     that is not a UUID v4 are all `VaultOpen` and nothing else (ARCH-POS-13): no error text, code, timing or later action
     tells them apart; check the JS side (`openPqKey` turns every inner error into one class) and the C ABI's status code.
   - clientkeys and `ua-rs` byte-equal on `pqz_leaf.json`, both ways: each seals what the other opens and each refuses the
     other's negative rows; every `ua-*` wrapper reads the same rows (name a wrapper that skips them).
   - The key material only inside the arena: `PqzKey::open_leaf` puts the leaf in a store of its own (`mlock`, zeroized on
     drop) and returns a handle, with no wallet and no seed; `Wallet::seal_pq_key` copies the leaf only into the sealing
     call; the one raw export (`export_pqz_leaf_raw*`, for `pqz-cli` or a key oracle) needs the `AllowSecretExport` marker and
     returns `Zeroizing`: check that no binding or C ABI call exposes it without that marker, and that clientkeys `wipe`s the
     leaf after `sealPqKey`.
   - Rule ids: the code comments of `src/pq.js` and `scripts/pqz-leaf-vectors.mjs` cite CLI-SGN-52 for the leaf, which
     `signers-clientkeys.md` defines as another rule (native networks); the leaf's rule is CLI-SGN-55. Report a stale id that
     `python3 scripts/docs_check.py resolve` does not map (dimension 1).
   - No secret in errors, logs, `Debug` prints or binding exceptions.

**Prior reports (do not re-report what they list as fixed; give the closure table):**
- `scratchpad/review-t21/` (T21 at `806f4f2c2`: `scope.md`, `ledger.md` with its FIX-NOW / OWNER / LATER / REJECT rows and the owner decisions O1-O8, the Fable and Codex part reports); the fix waves landed after it (`git -C T log --grep 't21'`)
- `T/docs/research/ua-rs-sign-fable-review.md`, `ua-rs-sign-codex-review.md`

**Gate evidence at the tag (read for what was run; a green gate proves nothing by itself):**
- `T/smartcontracts/evm/runs/2026-11-16-ua-rs-sign-t21-summary.txt`, `2026-11-16-ua-rs-sign-sync7-summary.txt`, `2026-11-09-ua-rs-sign-t20d-summary.txt`, and the tag's own client gate summary

**Also accepted for this unit (do not report):**
- T21 ledger rows marked REJECT or LATER, and the owner decisions O1-O8 as ruled (e.g. O2: the link key must arrive over an authenticated channel, the fingerprint compare is LATER)
- `crypto-bigint` 0.5.5 (RUSTSEC-2026-0387) through `frost-secp256k1` =3.0.0 is a known, ignored advisory (`T/clients/ua-rs/deny.toml`, reason recorded): report only a new path to it from a release signer

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1; added 2026-11-24). Apply every dimension within this unit's
scope; each row says what to hunt here. A row marked `N/A` gives its reason and stays. Every finding names its dimension
number (section 9).

| # | Dimension | What to hunt in this unit |
|---|---|---|
| 1 | Conformance | CLI-SGN-*, CLI-UAL-* custody rules, vault v1 / v2 (CLI-SGN-02, -30), owner decisions O1-O8 against `wallet/{vault,store,aead,seal,kem,derive,pairing,manifest,bounded,policy,service_pull}.rs`. |
| 2 | Cryptography | Leads within the unit (with `crypto-kem-seal`): scrypt bounds, NFKC, AEAD labels and AAD, single-use keys; BIP-39 / HKDF derivation labels; the UA KEM key (ML-KEM-1024 + X25519): small-order X25519 points, implicit rejection, the combiner; seal / open labels and AAD bound into the key derivation; the sealed PQZ leaf `sealPqKey` / `openPqKey` (invariant 6: the label `pqz:registry:<account>:<index>:<version>`, the AAD binding the seed vault's id, one `VaultOpen` class). |
| 3 | Security | A foreign vault refused; the link window on the opener's clock (O3); equal backup generation (O4); handles revoked on lock; `ExternalKey` verifies before returning; signing policy `Expect`. |
| 4 | Rules that do not bend | No decryption oracle: a wrong key, wrong version or truncated blob refused with one error class, no timing or later action telling them apart (invariant 6). |
| 5 | Secrets and privacy | Leads within the unit: keys and seeds only in `mlock`ed, zeroizing buffers (`secret.rs`), never copied into a `Vec` reallocation, `String` or FFI buffer; no secret in errors, logs, `Debug`. |
| 6 | Robustness and denial of service | Bounded decode of vault blobs, manifests and pairing messages (`bounded.rs`); no panic on a corrupt store. |
| 7 | Failure handling | A failed open leaves the vault locked and unchanged; store writes atomic; backup paths fail closed. |
| 8 | Consistency across languages and layers | Vault, seal and KEM bytes equal clientkeys `vault.js`, `seal.js`, `kem.js`, `seed.js`, `pq.js` (`sealPqKey`) and the vectors (`T/smartcontracts/vectors/keys/`, `keystore/`, the PQZ leaf rows), both ways; every `ua-*` wrapper reads the same rows. |
| 9 | Contract specifics | N/A: no contract code. |
| 10 | Performance and cost | scrypt / Argon2 cost on mobile within the documented budget (no timing runs). |
| 11 | Interfaces and misuse | Custody API hard to misuse: a handle from another vault refused; defaults safe (`mlock` on). |
| 12 | Tests | `wallet_vault`, `wallet_seal`, `wallet_kem`, `wallet_memory`, `pqz_leaf` tests; negative rows read by both languages. |
| 13 | Operations and the supply chain | `aes-gcm`, `ml-kem`, `scrypt`, `argon2`, `bip39` pins and advisories; SPDX headers. |

## 9. Report format (Markdown, English)

```
# ua-rs-custody: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### URC-1 [P1] <short title>
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
