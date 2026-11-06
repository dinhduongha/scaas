> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Review matrix: parts, lenses, models (owner question, 2026-11-05)

What each part under work needs reviewed, from which angle, by which model. It extends the EVM audit plan
([contracts-audit-2026-11](contracts-audit-2026-11/README.md)) to the parts added since: the `ua*` / `mtx*` merge, the regulated
kinds, the `PqChat` contract, `ua-rs` as the only signer, and the clients around them. Status: a matrix to plan from, not a plan.
The reviewers are AI models, none independent of the project; everything cryptographic stays `UNAUDITED`.

## Lenses

| Id | Lens | What it looks for |
|---|---|---|
| L1 | Cryptography | constructions, domain separation, nonces, KEM / AEAD / KDF use, signature schemes per kind, standards conformance |
| L2 | Keys and memory | custody, derivation, zeroize, locking, export paths, handle lifetimes, secrets in logs or errors |
| L3 | API / C ABI misuse | can a caller sign or open the wrong thing; explicit parameters; ownership, double free, threads, panics across FFI |
| L4 | `clientkeys` and vectors | byte-equal reproduction in every language; vectors generated, not edited; the non-zero unbound value rule |
| L5 | Architecture | layering, one rule one place, dependencies, what is missing |
| L6 | Authorization and call flow | who may call what, roles and governance, subject vs `msg.sender`, privilege escalation |
| L7 | State, reentrancy, external calls | order of effects, DELEGATECALL into libraries (storage, `this`, return data), tokens that call back |
| L8 | Economics and manipulation | front-running / MEV, relayer griefing, rates and rounding, fee 0, storage spam (`storeMessage`) |
| L9 | Gas, DoS, chain limits | unbounded loops, EIP-8037 inclusion (regular + state ≤ block limit), the 2^24 regular cap, ROLL_MAX margins |
| L10 | Proof-system soundness | soundness and zero knowledge, Fiat-Shamir transcripts, parameter sets, C oracle = Rust, wasm32 |
| L11 | Privacy and metadata | what leaks: amounts, links between messages, IPs, timing, sizes, decoys |
| L12 | Node and relayer | allow-lists equal to the contract both ways, bounded decoders (length and depth), lane keys hold gas only, never `dead` too early |
| L13 | Same rule on every family | the same records, ids and bytes on EVM, Soroban, NEAR, Algorand, … |
| L14 | Wallet display | does the user see what they sign: `bytes32` ids, typed structs, phishing shapes |
| L15 | Spec ↔ code ↔ rules | code matches the spec and the `decisions.md` rules; docs not stale |
| L16 | Test quality | negatives that can fail, positive controls, mutants, fuzz; a green gate is not evidence |
| L17 | Supply chain, build, operations | pinned crates / npm, `cargo deny` / audit, reproducible builds, secrets in a public repo, deploy scripts, chainspec, deploy keys |

## Models

| Model | Strength here | Notes |
|---|---|---|
| **Claude workflow** (Opus, several lenses, adversarial verify of each finding) | breadth, spec ↔ code, blast radius, test quality | needs the owner's explicit go (token cost) |
| **Fable** (independent counter-review) | design flaws, what is missing, architecture, economics; **and, on every spec with security or cryptographic content, a full security and cryptography review beside Codex's** (owner 2026-11-06: two independent reviewers miss different things) | given the code and the spec, not our conclusions; never Codex's report |
| **Codex** (security review) | code-level crypto, signatures / EIP-712, keys, FFI, reentrancy | only on the owner's word (credits); free `codex sandbox` check first; output inside the worktree |
| **agy** (Gemini, web search) | standards and known CVEs of dependencies, cross-checks of parameters, a second crypto opinion | read-only; cite sources |

## Matrix: part × lens → model

● main reviewer · ○ second reviewer · blank: not needed.

| Part | L1 | L2 | L3 | L4 | L5 | L6 | L7 | L8 | L9 | L10 | L11 | L12 | L13 | L14 | L15 | L16 | L17 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **Merge M**: EVM contracts (spec + code, round T22) | ○ Codex | | | ● Claude | ○ Fable | ● Codex | ● Codex | ○ Fable | ● Claude | | | | ○ Claude | ● Claude | ● Claude | ● Claude | |
| **Regulated kinds** (3b) | | | | ○ Claude | ● Fable | ● Codex | ● Codex | ● Fable | ○ Claude | | ○ Fable | | ○ Claude | ○ Claude | ● Claude | ● Claude | |
| **`PqChat` contract + registry change** (3c) | ● Codex | | | ● Claude | ● Fable | ● Codex | ○ Codex | ● Fable | ● Claude | | ● Fable | ○ Claude | ○ Claude | ○ Claude | ● Claude | ● Claude | |
| **`ua-rs` signer and crypto core** (3d) | ● Codex, ○ agy | ● Codex | ● Codex, ○ Claude | ● Claude | ● Fable | | | | | | | | | ○ Claude | ● Claude | ● Claude | ● agy |
| **`pqchat-core` + `scaas-wallet`** (item 11) | ● Codex | ● Codex | ● Claude | ● Claude | ● Fable | | | ○ Fable | | | ● Fable | ○ Claude | ○ Claude | ● Claude | ● Claude | ● Claude | ● agy |
| **`pqz-core`** (core reviewed 2026-10-25; prover / relay pending) | ● Codex, ○ agy | ○ Codex | ○ Codex | ● Claude | ○ Fable | | | | ● Claude | ● Codex, ○ Fable | ● Fable | | | | ● Claude | ● Claude | ○ agy |
| **`zether-prover`** | ● Codex | ○ Codex | ○ Claude | ● Claude | | | | | | ● Codex | ○ Fable | | | | ● Claude | ● Claude | ○ agy |
| **`scaas-node`** (relay, indexer, gateway) | | ○ Codex | ● Codex | ● Claude | ○ Fable | ○ Codex | | ● Fable | ● Claude | | ○ Fable | ● Codex, ● Claude | ● Claude | | ● Claude | ● Claude | ● agy |
| **`clientkeys` + vectors + other `ua-*`** | ○ Codex | ● Codex | ○ Claude | ● Claude | | | | | | | | | ● Claude | ● Claude | ● Claude | ● Claude | ● agy |
| **Deploy, chainspec, operations** | | ● Codex | | | ○ Fable | ○ Codex | | | ● Claude | | | ○ Claude | | | ● Claude | | ● agy |

Notes:
- The merge round's spec already had Claude (4 lenses), Fable and Codex (2026-11-04); its §2.7 (mandate wallets, Q6) and MD-11
  came after them and are reviewed with the code at T22.
- `ua-rs-sign`'s spec had Fable and Codex (2026-11-05); its code gets T21 of its own plan.
- A finding on one kind, family or language is checked on every other (the same-class rule, AGENTS.md).

## Prompt for T22 (and any part above)

Fill the braces; give the reviewer the code and the spec, not our conclusions. One reviewer, one part, one set of lenses.

```text
You are an independent reviewer of the SCaaS repository (public; nothing live with value; everything cryptographic is
UNAUDITED). Worktree: your current directory, commit {COMMIT}. READ-ONLY: do not build, test, run, benchmark or edit; write
only your report to {REPORT_PATH}.

Part under review: {PART} — files {SCOPE}; specification {SPECS}; the diff that matters {DIFF} (the whole part is in scope,
not only the diff). Lenses for you: {LENSES} (from docs/research/review-matrix-2026-11.md). Previous reviews of this part:
{PREVIOUS} — do not repeat what they found unless the fix is wrong, incomplete or undone.

Rules the design must hold (owner rulings): ciphertexts stay in contract state; every state-changing mtx* is relayable,
fee 0 too; explicit named parameters, one signed entry per operation, no packed bytes; an EOA signs with its own key, no
EIP-7702; no assumption of gas price 0 or of a chain's block limit; one rule on every chain; nothing deployed is upgraded;
the node is open and never holds subject funds or keys; ua-rs is the only signer. Invariants of this part: {INVARIANTS}.

Find what breaks. Think as an attacker with a budget, a relayer, a colluding key holder, a malicious token, contract,
chain or container. Prefer a concrete call sequence or input to a pattern match; check every claim against the code and
the cited standard.

Report (Markdown): for each finding an id {ID}-n, severity P0 (forgery, theft or loss, privacy break, permanent lock,
key disclosure) | P1 | P2 | P3, lens, file:line(s), the claim, the evidence (quoted code or clause, the reasoning or the
sequence), the fix, and a failing test that would show it. Then "Checked and sound" (what you verified), then "Not
covered". No style findings; no gas opinions unless a rule above breaks.
```

After the reports: findings are deduplicated, each is verified by a second reader who tries to refute it, confirmed ones
get a failing test first and a fix in their owning task (T22 step 3 of the merge plan).
