> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# EVM contracts audit, 2026-11

**Request (owner 2026-11-02).** AI audit of the EVM contracts first, with several different models: Codex, the Claude Code workflow
at UltraCode effort, agy and Fable. The name stays "Contracts audit"; the audit's reviewers are AI models, none of them
independent of the project. Soroban follows after `zether-soroban`; NEAR, Algorand and the other families get add-on audits when
their UA rounds finish. The node and the clients stay part 3.

**Status:** plan, target not frozen. **Scope widened (owner 2026-11-05):** the regulated kinds (work order 3b), the `PqChat`
contract and its registry change (3c) and `ua-rs` as the only signer (3d) are built before the EVM freeze, so this audit
covers them too (units A7, A8, B1 below). Lenses and models per part: [review-matrix-2026-11.md](../review-matrix-2026-11.md).

## Why

The last whole-contract review is [2026-10-26](../../../pqz-core/research/code-review-2026-10-26/README.md) at `64549aa4`.
Since then `smartcontracts/evm/src` moved in 84 files, +6,624 / −2,597, counting `typed-signing`: the metatx split, UA-8, the DEX
round, merged MSM, the size levers, `UARegistryLib` and every typed entry had round reviews only. Codex never saw units C3-C6 of
2026-10-26. Merged MSM was reviewed by Claude models alone.

## Target

One frozen detached worktree, `.claude/worktrees/audit-evm-2026-11`, at `typed-signing` after:

1. the `debit_min_gas` re-pin;
2. `ua8-soroban` M2's minimal `msig` rule (`5383ac7b`, 7 lines in `UARegistry._msig`) ported to `UARegistryLib` with its negative,
   so that the audit reads the final EVM code. It is the only EVM source change on `ua8-soroban`.

`typed-signing` holds every EVM source commit of `main`, so nothing needs merging for the audit to start. The whole of `src` is in
scope (18,954 lines), not the delta. Reviewers are read-only: no builds, tests, gas runs or commits. Figures come from CG's logs.

## Units

| Unit | Scope under `smartcontracts/evm/src/` | Invariants, beyond those of [2026-10-26](../../../pqz-core/research/code-review-2026-10-26/README.md) |
|---|---|---|
| A0 design | `docs/contracts/{pq-zero-knowledge,zether,accounts,metatx}.md`, `pqz/PqzCore.sol`, `PqzLayer.sol`, `zether/`, `ua/UAKinds.sol`, `UARegistry.sol`, `UARegistryLib.sol` | every statement and typed struct binds what the relation needs; one accepted form per operation; replay across chain, token, generation, op, kind; what the chain reveals |
| A1 verifiers | `ua/{MlDsa,FnDsa,SlhDsa,Shake,PqNtt,PqUA}.sol`, `ua/verifiers/`, `common/{Bls12381,HashToCurve,Ed25519,Sha512,CurveSigs,SigCheck,WebAuthnClientData,MultiSig}.sol`, Zether verifier math | each accepts exactly its standard's valid signatures; merged MSM (CTR-ZTH-53, `zether-msm-crypto-review.md`, its preconditions and its "Not done" list); precompile checks; assembly bounds |
| A2 PQZ token | `pqz/`, `confidential/` | statement bytes per op at **all four sets** (not recomputed in 2026-10); named entries' explicit parameters equal the packed statement; `PqzAuth`; `PQZ_DEBIT_MIN_GAS` bound; ciphertexts in state; `mtxPrepareAcc` halves against 2^24 |
| A3 Zether token | `zether/` | fold scalars and slots from the token's calls; every named parameter bound; records in state; statement and transcript order equal to `clients/zether-prover` |
| A4 UA | `ua/` non-verifier files, `account/`, `wallet/`, `hedera/` | `UARegistry` / `UARegistryLib` split: DELEGATECALL storage, `this`, `msg.sender`, reverts; PoP and portable records; KEM scheme; `msig` minimal rule, `G…` and relayer-checked slots; generations; no EIP-7702 path; `0x0105` / `0x0141` shared key question |
| A5 meta-tx | `metatx/`, `factory/`, `common/{MetaTxLib,FeePolicy,SaltedEIP712,SSTORE2}.sol` | the metatx split; typed entries against `executeMetaTransaction`: can one intent run twice; `MtxRelayFee` and its executor; lever 1 chained libraries, `LinkClosure`, release pins; lever 2 `nonReentrant` across DELEGATECALL libraries; library call return data, memory, storage slots |
| A6 DEX | `dex/`, `trade/` | matching modes; `restorePulled` and EIP-1153; refunds; executor trust; approve reset; typed orders and cancels |
| A7 regulated kinds | the six regulated releases (kinds 8–13) and their libraries, `governance/` flags 5–9 | CTR-GOV-03 (a plain transfer stays +0: no new read on the hot path), CTR-GOV-16, CTR-GOV-17 (FREEZE / FORCE / PAUSE / ALLOW / DENY on the confidential kinds: a frozen account still receives as a decoy, FORCE on public balances only), CTR-AS-17, CTR-AS-07 (compliance keyed by `bytes32`, the hook on the UA ledger); sizes against the ceiling |
| A8 `PqChat` + registry | `pqchat/`, `ua/` (`requirePortable`, the KEM record refused for an `msig`) | UA-7 spec P1–P31 (branch `ua7-research`): portable typed records, `epoch = parent + 1` and the home-chain child slot (the removal attack refused), admins, chunked wraps by hash, `postMessage` membership and nonce scopes, `storeMessage` unsigned and bounded, bytes in state (never only an event), no fee in a record, relay of unsigned writes only when paid; `requirePortable` over `uaMessage(kind, purpose, typedDigest)` incl. `msig` minimal form |

**Outside `src/`, one unit (it is the signer every client uses, and it holds keys):**

| Unit | Scope | Invariants |
|---|---|---|
| B1 `ua-rs` | `clients/ua-rs` (signing, KEM, seal / open, vault, the Zether and PQZ facades), `clients/ua-c` (C ABI v6), the shared vectors `smartcontracts/vectors/ua/` and their `clientkeys` generator | spec `ua-rs-sign` (with its Fable and Codex reviews in `docs/research/ua-rs-sign-*-review.md`): no release signature takes an RNG; seal / open labels, AAD and single-use keys; the Schnorr nonce map and blinding path; handles revoked on lock; containers checked against an expected sender; vault scrypt bounds and NFKC; decoders bounded by length and depth; byte-equal with `clientkeys` where the spec says so; no secret in an error or log |

Across units: every optimisation that replaced code with shared code or libraries must keep behaviour; say so when it does.

## Reviewers

| Reviewer | Units | How |
|---|---|---|
| **Codex** (CLI 0.166.0, read-only sandbox) | A3, A4, A5, A1, A0, A2, A6, then B1, A8, A7, **one at a time** | credits limited: the order puts first what Codex never saw. A unit it does not reach is listed as not covered |
| **agy** (Gemini) | all | same prompts, in parallel with Codex |
| **Claude workflow, UltraCode** | all | per unit: finders by lens, three independent refuters on each finding, rounds until two add nothing, a completeness critic |
| **Fable** | all | same prompts, one read-only agent per unit, written before reading any other reviewer's report |
| **Fable, a fresh agent** | adjudication and consolidation | every P0-P2 reported by one source checked against the frozen tree; it did not write the unit reports it judges |

Same model family as the implementers: fresh context and refutation reduce that; Codex and agy are what is different.

## Output

Raw reports `<reviewer>-<unit>.md` here, prompts `prompt-<unit>.txt`. One README section: findings P0-P3 with file:line, found by,
status; refuted findings with the reason; "Not covered by any reviewer". Then owner rulings, a fix round on `main`, one
re-review, gates at four sets, and [the review record](../security-review-record.md) updated.

## Open

Whether Codex's credits reach all ten units is unknown until they run out. The frozen target moves to `main` after the
`ua*` / `mtx*` merge, 3b, 3c and 3d have landed (the Target section above predates that and is rewritten when the tree freezes).
