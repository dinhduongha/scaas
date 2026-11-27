# AI audit prompt, unit `scaas-tui` (2026-11-28)

**PENDING LANDING: branch `scaas-tui` (section 8).** The round pins its commit at the tag.

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

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-scaas-tui.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.2-astra-high-scaas-tui.md`, `20261120-09-agy-gemini-4-argon-high-scaas-tui.md`). Use the tool's
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

`scaas-tui` is the terminal front-end over `scaas-sdk` (CLI-TUI-01, -17): a thin layer in which every call goes to the SDK,
with the vault screens over `pqvault-core` and the public topics over `pqchat-core` behind features. It holds no key of its
own except, through the SDK, one EVM payer key (CLI-TUI-13). Attackers: anyone who controls text the TUI draws (a token
name, a topic, an entry body, a vault item, a node's error, an endpoint's reply) and uses terminal escape sequences, bidi or
look-alike characters to hide or forge what the review shows; a malicious RPC endpoint, node or profile file; another user
of the terminal, its scrollback, a screen recorder, the clipboard or a log; a crash at any point. Goals: a signature over
fields the user did not see on the review (CLI-TUI-02, -08); a write the user did not start (CLI-TUI-03); a secret (seed
words, a passphrase, a key, a vault secret field) on screen, in scrollback, on the clipboard, in a log or a crash report
(CLI-TUI-04, -14, -15, -16); a terminal left in raw mode with a secret on it after a panic (CLI-TUI-10); fee or gas caps
raised past the build's (CLI-TUI-12); a profile or endpoint file that redirects the TUI in a release build (CLI-TUI-06, -11);
a build that reaches SDK surface the TUI must not (`native-networks`, `raw-native`, `opaque-calls`, `vectors`, CLI-TUI-17).

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

## 8. Your unit: `scaas-tui`

**Added 2026-11-28 (controller call under the owner's auto-run grant of 2026-11-25; the owner may veto). PENDING LANDING:
branch `scaas-tui`, not on `dev` when this prompt was written** (it carries `pqchat-core-confirm` merged). The round's
commit pin is set at the tag, as for every unit. Before the run the controller checks that the branch landed in the tag; if
it did not, this unit is not run and the round's summary lists it as not covered. The file list below is the branch's;
confirm each path under `T/` and list a missing one under "Not covered".

**Scope (paths under `T/`):**
- `clients/scaas-tui/`: `src/lib.rs`, `src/main.rs`, `src/app.rs` with `src/app/{topics,vault}.rs` (the screens' state and
  every action), `src/runner.rs` (the event loop, workers, the panic path, CLI-TUI-10), `src/term.rs` (raw mode, the
  alternate screen, the restore), `src/input/{mod,secret}.rs` (key input, the secret field), `src/idle.rs` (the idle lock),
  `src/config.rs`, `src/profiles.rs` (release profiles, `dev-profiles`, CLI-TUI-11), `src/log.rs`, `src/topics.rs`,
  `src/vault.rs`, `src/ui/` (every screen; `ui/text.rs` the allow-list for text the TUI did not write, CLI-TUI-05;
  `ui/review.rs` the signing screen), `src/vm/` (the view models: `review.rs`, `send.rs`, `ops.rs`, `seeds.rs`, `vault.rs`,
  `topics.rs`, `dex.rs`, `admin.rs`, `endpoints.rs`, `accounts.rs`, `activity.rs`, `balances.rs`, `confidential.rs`,
  `backup.rs`, `receive.rs`, `settings.rs`); `build.rs`, `Cargo.toml` (the features and the SDK features it may not take,
  CLI-TUI-17), `Cargo.lock`, `deny.toml`, `.cargo/audit.toml`, `profiles/release.json`; tests `tests/` (`feature_tree.rs`, `review.rs`,
  `seeds.rs`, `vault.rs`, `topics.rs`, `pty.rs`, `render.rs`, `keymap.rs`, `text.rs`, `term.rs`, `profiles.rs`, `support/`,
  the golden screens `tests/golden/`); `runs/2026-11-17-scaas-tui-summary.txt`, `-gates.sh`, the mutant records
  `-t1-` to `-t11-`, `-t14a-`, `-t14c-`, `-gaps-`, `-r1128-mutants.txt`
- read only (each audited in its own unit): the SDK surface it calls (`scaas-sdk`), `pqvault-core` and `pqchat-core`
  (`app-cores`), `scaas-rpc`'s endpoint types

**Specifications and rules to read first:** `T/docs/clients/scaas-tui.md` (CLI-TUI-01 to -18); decisions CLI-TUI-01 to -19,
CLI-TUI-31 with their Changes; spec `T/docs/superpowers/specs/2026-11-17-scaas-tui.md`, plan
`T/docs/superpowers/plans/2026-11-17-scaas-tui.md`; CLI-SDK-35 (one `SignReview` model), CLI-SDK-36 (sign after confirm).

**Invariants to check (beyond section 5; each a finding when it fails):**

a. **A thin layer** (CLI-TUI-01, -17): every call goes to the SDK (or an app core through it); no cryptography, encoding or
   signing in the TUI; the build never enables `native-networks`, `raw-native`, `opaque-calls` or `vectors`
   (`tests/feature_tree.rs` or its successor can fail); `test-hooks` and `dev-profiles` never in a release build.
b. **The review** (CLI-TUI-02, -08, -09, CLI-SDK-35): the signing screen shows every named field of the SDK's review before
   anything is signed, at every terminal size (scrolling included); confirm is a deliberate key at a settled prompt after
   the last line; after confirm there are two outcomes only, nothing signed or an activity row; a second confirm cannot sign
   twice.
c. **Every write starts from a user action** (CLI-TUI-03): no background write, retry or refresh that signs.
d. **No secret on the terminal** (CLI-TUI-04, -15, -16): seed words revealed only after `reveal` is typed, with the
   warning; secret fields masked in input and in every redraw; nothing secret in scrollback (the alternate screen), a log, a
   crash report, a golden file or the clipboard (CLI-TUI-14: public values only, opt-in); the idle lock clears the screen.
e. **Text the TUI did not write** (CLI-TUI-05): drawn only through the typed allow-list, so no screen can skip it; escape
   sequences, control characters, bidi overrides and look-alikes in names, topics, entries, vault items and node errors
   cannot move the cursor, hide a line of the review or forge one.
f. **Panic and `Internal`** (CLI-TUI-10): the process ends after the terminal is restored, with no secret left on screen.
g. **Profiles and endpoints** (CLI-TUI-06, -11): release profiles integrity-pinned; a profile file from the command line only
   in a development build under a banner; user endpoints named, none discovered, no full URL shown.
h. **Fee and gas caps** (CLI-TUI-12): from the build, lowered and never raised, shown on the review.
i. **The payer key** (CLI-TUI-13): the one native key is an EVM payer key, held and used through the SDK only.
j. **Topics and tree sessions** (CLI-TUI-31): the public topics read and written through `pqchat-core`'s `Prepared` and
   confirm (CLI-PQC-21), relayed by default; TreeKEM mode 1 sessions as `pqchat-core` exposes them.

**Prior reports (do not re-report what they list as fixed; give the closure table):** the build's review rounds as recorded in
the Changes under CLI-TUI-01 to -31 and in the mutant records (`-gaps-`, `-r1128-`); the local notes
`scratchpad/scaas-tui/` (`arch.md`, `t13-findings.md`).

**Gate evidence at the tag (read for what was run; a green gate proves nothing by itself):**
`T/clients/scaas-tui/runs/2026-11-17-scaas-tui-summary.txt` (rows `tui-test`, `tui-min`, `tui-vault`, `tui-chat`) with its
mutant records; the tag's own client gate summary.

**Areas** (ARCH-POS-22, `T/docs/review.md` §2). This unit is one layer; it names the other areas so its findings land
where they belong.

| Area | Scope here |
|---|---|
| Layer | `clients/scaas-tui/` |
| Cross-layer | the review lines the SDK produces against what each screen draws (every field, every size); `pqchat-core`'s and `pqvault-core`'s `Prepared` / confirm against the TUI's flows; end to end: unit `cross-layer` |
| Cryptography | none: the TUI holds no cryptography (invariant a); a primitive found here is itself a finding |
| Adversarial | text controlled by others, a lying endpoint or profile file, a terminal observer, a crash (section 6); across the system: unit `adversarial` |

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1 and the brief template of §5). Apply every dimension within this
unit's scope; each row says what to hunt here and which area leads it. A row marked `N/A` gives its reason and stays. Every
finding names its dimension number (section 9).

| # | Dimension | Lead area | What to hunt in this unit |
|---|---|---|---|
| 1 | Conformance | Layer | CLI-TUI-01 to -19 and -31 against the code; the doc's status tags against the built code. |
| 2 | Cryptography | Cryptography | N/A as a primitive (invariant a); hunt any cryptography, encoding or digest done in the TUI instead of the SDK. |
| 3 | Security | Adversarial | The review shows every field before signing (invariant b); terminal injection through foreign text (invariant e); writes only from a user action (invariant c). |
| 4 | Rules that do not bend | Layer | No blind signing; fail closed; the TUI adds no guarantee the SDK or a contract does not hold. |
| 5 | Secrets and privacy | Layer | Seeds, passphrases, keys and vault secret fields off the terminal, the scrollback, logs, golden files and the clipboard (invariant d). |
| 6 | Robustness and denial of service | Layer | Huge or hostile text, endless lists, a slow endpoint: the UI stays responsive and bounded. |
| 7 | Failure handling | Layer | Panic and `Internal` (invariant f); a failed or unknown outcome after confirm shown as the SDK reports it, never as success. |
| 8 | Consistency across languages and layers | Cross-layer | The review model is the SDK's (CLI-SDK-35); the view-model link to scaas-app's fixtures (CLI-TUI-19) where the code claims it. |
| 9 | Contract specifics | N/A | No contract code. |
| 10 | Performance and cost | Layer | Redraw and read loops (no RPC storm per frame); no timing runs. |
| 11 | Interfaces and misuse | Layer | Two key maps without prefix keys (CLI-TUI-18); confirm cannot be hit by a held or repeated key (invariant b); keyboard-only, no-colour use (CLI-TUI-07). |
| 12 | Tests | Layer | The PTY tests and golden screens can fail; the mutant records kill each check; the forbidden SDK features checked by a test. |
| 13 | Operations and the supply chain | Layer | `Cargo.lock`, `cargo deny` / `cargo audit`, the `ratatui` / `crossterm` pins, release profiles pinned (invariant g), no `dev-profiles` or `test-hooks` in a release; SPDX headers. |

## 9. Report format (Markdown, English)

```
# scaas-tui: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### TUI-1 [P1] <short title>
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
