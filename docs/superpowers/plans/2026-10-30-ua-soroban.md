# UA-Soroban UA base (+ the classical Zether track) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Soroban becomes the first non-EVM family with Universal Accounts of every kind it can verify: a stand-alone
`UaRegistry` with the portable UA-8 `register`, the UA ledger in the Soroban token, UA holders in the mandate, the DEX
and the relay-fee router, the node's `ua_metatx` jobs, `clientkeys` encodings and shared vectors (Part UA-Soroban); then, on
its own branch, the classical Zether token on Soroban (Part Z, spec S13a).

**Architecture:** Part UA-Soroban on branch `ua-soroban` (worktree `.claude/worktrees/ua-soroban`) from `main` (S18; the
token-family rename merged as `1a68427a`, so the precondition holds). Order: the network spike and its HARD GATE (T0),
the SDK pin (T1), the shared crate and the verifiers (T2), the registry (T3), the vectors (T4), the token / mandate /
DEX / router (T5–T8), the node (T9), the local e2e (T10), docs (T11), gates (T12), whole-branch review (T13); the
Stellar testnet e2e (T14) is the round's last step, after Part B and Part Z. UA-8 Part B (`ua8-soroban`, the UA-8 plan
B0–B10) starts after the owner's go merges `ua-soroban`; it is not in this plan except the items listed under "Part B
items this plan builds". Part Z on branch `zether-soroban` from `main` after `ua-soroban` merges (it needs the UA ledger
and the registry); Part B and Part Z may then run in parallel worktrees, their docker steps never at the same time.
Code and tests run on SDK testutils at protocol 30 and a local `stellar/quickstart` at Protocol 30; the testnet only
after 2026-11-03 with protocol 30 read from the RPC.

**Tech Stack:** Rust `soroban-sdk = "=30.0.0-rc.1"` (cargo workspace `smartcontracts/soroban/`, toolchain 1.97.1,
target `wasm32v1-none`; CAP-0087 `ml_dsa_{44,65}_verify`, CAP-59 BLS12-381 host functions), `stellar/quickstart`
pinned by digest (docker), `stellar-cli` pinned at T0; Rust `scaas-node` (`stellar-xdr`); Node `node --test` with
`@noble/curves` 2.4.0 / `@noble/post-quantum` 0.7.1 (`clients/clientkeys`); Python 3 stdlib (the spike's measurement
script); Part Z: `clients/zether-prover` (Rust, wasm), Foundry only for the existing `zether-cross` check.

**Spec:** `docs/superpowers/specs/2026-10-30-ua-soroban-design.md` (§0 rows S1–S18 with S13a / S13b, §1–§13;
§11 conflict rulings C11–C17, owner accepted 2026-10-30, S6 and S10 confirmed; S13a in this round by the owner the same
day). Background: the UA-8 plan `docs/superpowers/plans/2026-10-30-ua8-portable-registrations.md` (Part B);
`docs/contracts/accounts.md` (CTR-UA-03/-04/-07/-09/-12/-15/-17/-18/-23/-26/-27/-28/-29/-31); `docs/networks/soroban.md`
(NET-SOR-01…16); `docs/networks/README.md` NET-ALL-20/-21/-83/-84; `docs/contracts/zether.md` (Part Z);
`docs/contracts/metatx.md` CTR-MTX-26/-27.

## Global Constraints

Binding rules of the spec (quoted or restated without change):

- S2: "`register(kind, key_data, attrs, pop, pqz_pop, relayer)` on the CTR-UA-07 digests"; "UA-Soroban accepts only empty
  `attrs` (error `Attrs`)"; "UA-Soroban already defines the full `Registration` type, so Part B changes no layout".
- S3: enabled kinds `webauthn-p256` 0x0100, `p256` 0x0101, `ed25519` 0x0102, `secp256k1` 0x0108, `msig` 0x0120,
  `mldsa44` 0x0130, `mldsa65` 0x0131; "Every other derived kind is disabled (`KindDisabled`)". Part Z adds
  `zether-bls12381` 0x0141 together with the Zether token (S13a).
- S4: ML-DSA only through the CAP-0087 host functions; "one verifier module (`verify.rs` in `ua-registry`)".
- S5: "`soroban-sdk = "=30.0.0-rc.1"` for the whole Soroban workspace (every crate rebuilds and re-tests); swapped to
  30.0.0 when released, **before** the testnet e2e"; quickstart "pinned by digest, run `--local --protocol-version 30
  --limits testnet`".
- S6–S9: the UA ledger is "a `UaBalance(ua)` ledger with separate `ua_*` entries"; lanes `UaNonce(ua, lane) → u64` in
  persistent storage, `ua_pay` uses `lane = payLane(pay_ref)`, `nonce = 0`; `relayer: Option<Address>`, `Some(r)` ⇒
  `r.require_auth()`; only a UA that can spend here may receive (`UaNotReceivable`).
- S10: MEMBER = the enabled single-key kinds plus `stellar-account` 0x0011 and `soroban-contract` 0x0012 (host-verified,
  `member.require_auth_for_args((ua, purpose, digest))`); `evm-eoa` 0x0001 members verified for the portable purposes
  only and "zero signing weight for every other purpose"; `evm-contract` 0x0002 members "never chain-verified here".
- S11: "persistent, one entry per key"; instance storage only for constructor constants; temporary only for SEP-41
  allowances; "`extend_ttl(30 days, 60 days)` on each write and each in-transaction read"; "no node TTL job".
- S12: "the relayer" pays fees, rent and restores; "users and UAs hold no XLM".
- S13a (owner 2026-10-30): classical Zether, never built on Soroban, is in this round on its own track; "Measure first
  (T0): a verify that does not fit the per-transaction CPU / memory budget is a **STOP** for the owner"; "ciphertexts
  stay in contract state". S13b: PQZ — "none on Soroban", PQZ attributes stored unproven by Part B. Classical Zether
  and PQZ are separate items in every task, test and doc of this plan.
- S14: "an account signs with its own key; no delegated code authority"; "the node never lends a lane's authority".
- S15: `ua_metatx` for the UA-ledger, mandate and DEX UA entries; `call` for the registry writes (UA8-D23, Part B).
- S16: `UaRegistry` has "no admin, no upgrade function", the relayer list a constructor argument; tokens bind the
  registry at construction, immutable; `None` = `UaLedgerOff`.
- S17: unit tests at protocol 30 → local quickstart at Protocol 30 → Stellar testnet "only after 2026-11-03 and only
  when the RPC reports protocol 30".
- §1 anti-goals (each has a test below): a derived UA shown or usable as `G…` / `C…`; a nonce, pay ref or record in
  temporary storage; an archived entry read as absent; a UA that can receive but never spend; a lane's authority spent
  by a call it did not mean to authorise; any admin or upgrade path in the registry.

Owner rulings and house rules that bind every task:

- **Concurrency.** At most 3 agents at once. Heavy commands (cargo, npm, forge, `stellar contract build`) only through
  `scripts/capped` (2 heavy slots), **never wrapped in `timeout`**; cargo `-j2` / `CARGO_BUILD_JOBS=2`. While a docker
  container runs, capped commands use `CAPPED_SLOTS=1` (owner 2026-10-23).
- **Docker.** Every container gets `--memory` (≤ 4g; the quickstart runs with `--memory 3g`); **one quickstart at a time**
  (container name `scaas-stellar`; `quickstart.sh up` refuses to start a second one); stop it on every exit path.
- **Gates.** Never two full gate runs at once (this plan's, the UA-8 runner, the metatx-split runner or a pqz-core gate).
  Every multi-step gate logs per step (`# <step> at commit <sha>` first, `rc=<n>` last) and skips a step done at the
  same commit with a clean tree (resume, never restart; on resume read the latest logs first).
- **Branches.** Subagents stop at the branch: commit per task, **no merge, no push** (owner's go only). Commit messages
  `UA-Soroban T<n>: …` / `zether-soroban Z<n>: …`, ending with the `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` line.
- English for code, comments, docs and commits. Parameter sets only in the `n2304-kmax4096` form (none is touched here).
  "SCaaS testnet" names chain 7622 in prose; it is not touched by this plan. EVM token names are the renamed ones
  (`NormalToken`, `WrappedToken`, `NormalZetherToken`, `WrappedZetherToken`).
- Decisions are recorded in full in `docs/decisions.md` (content, who: "owner <date>" or "controller proposal, owner may
  override", status, commit); never a bare label.
- No zero-gas / no block-limit assumption: every Soroban limit is read from the network (`stellar network settings`),
  never assumed; every cost figure is measured and logged.
- All chains are test-only: new deployments, no migration; superseded built code goes to a legacy area, never deleted.
- One rule for every chain kind; every state-changing `ua_*` / `mtx_*` entry is relayable (fee may be 0).

## Review Focus

1. A lane's authority must never be spent by a call it did not mean to authorise: a simulation that records any
   `SourceAccount` entry other than the one rooted at the job's top-level call fails the job —
   `ua_metatx_refuses_extra_source_account_auth` (T9), `e2e_soroban_ua_lane_authority_not_lent` (T10).
2. An archived lane must never read as 0: re-submitting a spent nonce after the lane entry archived is refused —
   `ua_entry_archived_nonce_restored_not_reset` (T5).
3. A UA that cannot spend on Soroban must never receive: an `msig` whose Soroban-signable weight is below its
   threshold, an unregistered id and (Part Z) a Zether UA on the public ledger — `msig_unsignable_not_receivable` (T3),
   `ua_receiver_not_registered_or_not_receivable` (T5), `zether_ua_not_receivable_on_ua_ledger` (Z2).
4. The pool is the token's own address: replaying the SEP-41 events reproduces every `balance()` including the pool,
   and nothing native is ever paid to it — `sep41_events_match_balance_with_ua_moves`, `pool_address_not_payable` (T5).
5. A UA order fills partially without re-signing but never beyond `sell_amount`, and only the DEX it names can pull —
   `ua_trade_dex_only_partial_fill_no_resign` (T7). Part Z: a ciphertext is never lost (persistent, restored, never
   absent) — `zether_ciphertexts_in_persistent_state` (Z3).

---

## Decisions

### Spec §0 rows: where each is built and recorded

Each row is recorded in full in `docs/decisions.md` by T11 (Part Z rows by Z8) under the NET-SOR id named here, with the
spec's "who" column copied: "controller proposal, owner may override" or the owner ruling.

| Row | Built by | NET-SOR id (normative `networks/soroban.md`) | Who (spec) |
|---|---|---|---|
| S1 registry contract `ua-registry` | T3 | NET-SOR-17 | controller call |
| S2 portable `register` | T3 | NET-SOR-17 | owner P1 / P2 (2026-10-25); split controller call |
| S3 kinds of generation 1 | T2, T3 (0x0141 by Z2) | NET-SOR-18 | controller call within the owner's list |
| S4 ML-DSA via CAP-0087 | T2 | NET-SOR-17 | controller call |
| S5 SDK / network pins | T0, T1, T14 | NET-SOR-24 | controller call |
| S6 UA ledger with `ua_*` entries | T5 | NET-SOR-20 | owner confirmed 2026-10-30 |
| S7 lanes in persistent storage | T5 | NET-SOR-20 | controller call |
| S8 `relayer: Option<Address>` | T5–T8 | NET-SOR-20 | controller call |
| S9 receivability | T3, T5 | NET-SOR-19 | controller call |
| S10 `msig` members | T3 | NET-SOR-18 | owner confirmed 2026-10-30 |
| S11 storage class and TTL | T3, T5–T8 | NET-SOR-22 | controller call (UA8-D22) |
| S12 who pays | T9 | NET-SOR-22 | owner precedent 2026-10-28, applied here |
| S13a classical Zether | Part Z | NET-SOR-25 | owner 2026-10-30 (in scope); port design controller proposal |
| S13b PQZ | — (Part B stores attributes unproven) | NET-SOR-26 | owner (UA-8 P8, P10; never-lose rule) |
| S14 code authority | T9 | NET-SOR-23 | owner (D1–D5, 2026-10-30) |
| S15 node job kinds | T9 | NET-SOR-23 | controller call |
| S16 no admin / upgrade | T3, T5 | NET-SOR-17 | CTR-UA-15 (owner) |
| S17 test order | T0, T10, T14 | NET-SOR-24 | owner 2026-10-29 |
| S18 order inside the round | this plan | NET-SOR-24 | plan (controller), unchanged |

### Plan decisions (controller proposals, owner may override; recorded in full by T11 / Z8)

| # | Decision | Choice and why |
|---|---|---|
| SOR-D1 | Shared types | New lib crate `smartcontracts/soroban/contracts/ua-common/` (package `scaas-ua-common`, `crate-type = ["rlib"]`, no `#[contract]`): `Holder`, `Order`, `Checked`, `UaAttrs`, `Registration`, the `UaRegistryClient` (`#[contractclient]` trait), purpose tags, `op_digest`, `pay_lane`, `meta_pay_id`. A contract crate as a dependency would export its entry points into the dependent's Wasm; one type definition keeps the XDR identical in every contract. |
| SOR-D2 | Task order vs spec §10 | Spec T0–T12 map to plan T0, T1, T2, T3, T5, T6, T7, T8, T9, T4 (clientkeys before the token: the token, mandate, DEX and router tests reproduce `ua-ops.json`), T11, T12, T14; new: T10 local e2e, T13 review. Spec C16b's "UA-Soroban T12" (the testnet task) is this plan's **T14**. |
| SOR-D3 | The spike crate | `smartcontracts/soroban/spike/` is its own cargo workspace (package `scaas-ua-spike`, pinned `=30.0.0-rc.1`), outside `contracts/*`, so T0 runs before T1 touches the workspace. Kept, never deployed; Part B's B0 extends it for the full PQZ + KEM registration (C11); Part Z's Z0 extends it with the real verifier. |
| SOR-D4 | Quickstart | One script `smartcontracts/soroban/scripts/quickstart.sh up|down|wait` holds the pinned image digest and the command `docker run -d --rm --memory 3g --name scaas-stellar -p 127.0.0.1:31980:8000 <image@digest> --local --protocol-version 30 --limits testnet --enable core,rpc,horizon`; `up` exits 3 when a `scaas-stellar` container already runs; `wait` polls `getNetwork` until `protocolVersion == 30` (else fails). `smartcontracts/scripts/devnet.sh soroban` dispatches to it. |
| SOR-D5 | stellar-cli | Pinned at T0 (`scripts/capped cargo install --locked stellar-cli --version =<v>`; the installed 22.2.0 predates Protocol 30): the first release whose `stellar-xdr` supports Protocol 30, version recorded in the run log and `quickstart.sh`. |
| SOR-D6 | UA-Soroban and unverifiable parts | In UA-Soroban a signature part the chain cannot verify (an `evm-contract` member's slot, any `MemberSig` of a kind outside MEMBER) is `NotVerifiable`, whatever `relayer` says; `relayer` is accepted and ignored for chain-verified parts (UA8-D18). Part B's B4 adds the relayer-checked mode on top, with no caller change (C13). |
| SOR-D7 | `ua_ref_used` | Derived, no own entry: `ua_ref_used(ua, pay_ref) = ua_nonce(ua, pay_lane(pay_ref)) > 0` (`ua_pay` is nonce 0 of its pay lane, S7). |
| SOR-D8 | Constructors | Token `__constructor(admin, decimals, name, symbol, registry: Option<Address>)`; mandate `__constructor(owner: Holder, registry: Option<Address>)`; DEX `__constructor(admin, fee_recipient, registry: Option<Address>)` (its `ua_cancel` verifies a UA); the router stays stateless (its `ua_relay` reaches the registry through `token.ua_pay`). |
| SOR-D9 | Mandate names | The mandate takes the NET-SOR-16 names in this deployment (spec §5.2): `mtx_set_mandate`, `mtx_set_payee`, `mtx_revoke`, `mtx_withdraw`, `mtx_mandate_pay` — one entry each for a native and a UA holder. Owner entries end in `(lane, nonce, valid_until, relayer, auth)`; a native holder authorises by host auth (`auth` must be empty, `BadAuth`), its lane is not consumed; expiry and `relayer` are checked for both. The token's `pay` and the DEX's `settle` / `cancel` keep their names (their NET-SOR-16 renames stay SPECIFIED, outside UA-Soroban). Change note (owner ruling 2026-10-30, T6b): the mandate epoch of CTR-ACC-07 — `epoch(token)` +1 on every `mtx_set_mandate` and every revoke; the delegate's `mtx_revoke(token, by, epoch, …)` and `mtx_mandate_pay(token, payee, amount, pay_ref, epoch, …)` sign it and are refused `StaleEpoch` unless current; the owner's `epoch` argument is not checked. |
| SOR-D10 | DEX `ua_cancel` purpose | Purpose `trade` over `op_digest(dex, "ua_cancel", (order,))`, verified by the DEX through the registry (the spec names the entry, not its purpose; the function name in the digest separates it from the order signature). |
| SOR-D11 | `RelayFeePaid` | `payer` **and** `payee` become `Holder` (a bound payee of `ua_relay` may be a UA; one event shape for `relay` and `ua_relay`). |
| SOR-D12 | `ua-ops.json` | Generated by clientkeys (`scripts/soroban-ua-ops-vectors.mjs`, the deterministic signers of `scripts/ua-signers.mjs`), network passphrase `Standalone Network ; February 2017`, fixed contract ids; `--check` mode; the contract tests (registered at those ids with that network id), the adapter and clientkeys reproduce it. |
| SOR-D13 | e2e signing | The e2e signs through `node clients/clientkeys/scripts/soroban-sign.mjs` (the vector signers, already the reference); no Rust ML-DSA / WebAuthn signing crate is added. |
| SOR-D14 | Soroban `ua_metatx` job | `{kind: "ua_metatx", op: {contract, function, args: "<hex XDR ScVec>", auth?: [{payload, from, signature}], valid_until}}`; allow-list by function and contract class (below, T9); chain param `params.max_deposit_per_job` (stroops; absent = 0 = no restore accepted). |
| SOR-D15 | `receivable` | `false` for an unregistered id too; the token tells the two errors apart on the failure path only (`record_of(ua).is_none()` ⇒ `UaNotRegistered`, else `UaNotReceivable`). |
| SOR-D16 | Error codes | Registry: `KindDisabled = 1, KeyData = 2, IdInNativeSpace = 3, AlreadyRegistered = 4, KeyInUse = 5, MemberUnknown = 6, Attrs = 7, Pop = 8, NotRegistered = 9, Unauthorized = 10, NotVerifiable = 11, RelayerNotListed = 12` (Part B continues at 13: `PqzHolder, KemHolder, KemVersion, KemKeyLength, PqzPopHash`). Token (after the built 1–7): `UaLedgerOff = 8, UaNotRegistered = 9, UaNotReceivable = 10, UaPoolNotPayable = 11, BadNonce = 12`; T5 appends `BadOrder = 13` (`ua_trade`: maker not a UA, foreign `sell_token`, `dex` not a deployed contract, `UaPulled` over `sell_amount`) and a replayed `ua_cancel_nonce` digest (`UaCancelUsed`) is `BadNonce` (controller ruling 2026-10-30, owner may override); mandate adds `BadAuth` after its built codes, then `Expired = 10, BadNonce = 11, UaLedgerOff = 12` and (T6b, owner ruling 2026-10-30) `StaleEpoch = 13`. A host crypto failure (ed25519 / P-256 / ML-DSA verify panics) is a host error, not `Pop` (finding F1). |
| SOR-D17 | Testnet task placement | T14 runs once, as the round's last step, after Part B's B9 and Part Z's Z10, on branch `ua8-soroban` (or `zether-soroban` if Part B stopped at B0); its commits keep the prefix `ua-soroban T14:`; B10 follows it. |
| SOR-D18 | Registry interface check | `smartcontracts/soroban/scripts/check-registry-interface.sh` compares `stellar contract info interface` of the built `ua-registry` Wasm with the exact function list of T3 (no admin, no upgrade, no setter); run by the `e2e-soroban-local` gate step. |

Part Z decisions are ZS-D1–ZS-D9 in Part Z's header.

### Part B items this plan builds (spec §11; the UA-8 plan gets one pointer line, nothing else)

| UA-8 Part B item | Moves to | What is left in Part B |
|---|---|---|
| B0 network spike (C11) | **T0** (`smartcontracts/soroban/spike/`, gate step `soroban-spike-local`), with the SDK pin (T1) and the image pin (T0) | B0 re-runs the spike for the full PQZ + KEM registration on the real registry; its "pin the SDK and the image" becomes "check the UA-Soroban pins" |
| B1 portable digests (C11) | **T2** (`portable_pop_digest`, `registration_digest`, `ua_message` in `ua-registry/src/digest.rs`) | the KEM record digest and the `portable.json` KEM check |
| B2 `register` and `Registration` (S2) | **T3** (entry, full layout incl. `attrs`, `pop_checked`, `pqz_pop_checked`, `proven`, `signable`, `index`, `ledger`) | lift `Attrs`, the PQZ / KEM entries, `Checked::Relayer` |
| B4 relayer list (C13) | **T3** (constructor `relayers: Vec<Address>`, `relayers()` view, `register(…, relayer: Option<Address>)`) | the relayer-checked mode; no caller changes |
| B3 `NotRegistered` (C17) | **T3** (error 9) | reused |
| B10 SDK swap (C16b) | **T14** step 1 | B10 follows T14 |

Names: Part B's "factory crate" is `ua-registry`; its entries `UA` / `KEY` / `PQZK` / `PQZP` / `KEM` / `KEMMAX` are
`Ua` / `Key` / `PqzK` / `PqzP` / `Kem` / `KemMax` (spec §4; "the UA-Soroban name wins").

---

## File Structure

| Path | Responsibility |
|---|---|
| `smartcontracts/soroban/Cargo.toml`, `Cargo.lock` | workspace SDK pin `=30.0.0-rc.1` (T1) |
| `smartcontracts/soroban/spike/{Cargo.toml,Cargo.lock,ua-spike/,run.sh,measure.py}` | T0 spike (own workspace), the local measurement |
| `smartcontracts/soroban/scripts/{quickstart.sh,e2e-local.sh,check-registry-interface.sh}` | pinned quickstart, the local e2e step, the registry interface check |
| `smartcontracts/soroban/runs/` | run logs (T0, T10, T14, Z0, Z8) |
| `smartcontracts/soroban/contracts/ua-common/src/lib.rs` | shared types, client trait, tags, `op_digest`, `pay_lane`, `meta_pay_id` |
| `smartcontracts/soroban/contracts/ua-registry/src/{lib.rs,digest.rs,verify.rs,webauthn.rs,abi.rs,test.rs,test_verify.rs}` | `UaRegistry` |
| `smartcontracts/soroban/contracts/token/src/{lib.rs,ua.rs,test.rs,test_ua.rs}` | SEP-41 token + UA ledger (+ Part Z `zether.rs`, `test_zether.rs`) |
| `smartcontracts/soroban/contracts/{mandate,dex,relay-fee}/src/{lib.rs,test.rs}` | UA holders |
| `smartcontracts/soroban/vectors/ua-ops.json` | op digest / `ua_msg` / signatures per entry and kind (T4) |
| `clients/clientkeys/src/soroban.js`, `scripts/{soroban-ua-ops-vectors.mjs,soroban-sign.mjs}`, `test/soroban.test.js` | Soroban encodings, generator, e2e signer |
| `scaas-node/src/adapters/soroban.rs`, `node.example.toml`, `tests/e2e_soroban_ua.rs` | adapter, e2e |
| `smartcontracts/scripts/{devnet.sh,deploy.sh}` | `soroban` entries |
| `docs/networks/soroban.md`, `docs/contracts/accounts.md`, `docs/node/job-api.md`, `docs/decisions.md`, the spec, `TODO.md` | docs |
| `smartcontracts/evm/runs/2026-10-30-ua-soroban-gates.sh` + logs; `smartcontracts/evm/runs/2026-10-27-metatx-split-gates.sh` (two new step commands) | gates |
| Part Z: `smartcontracts/soroban/contracts/zether-verifier/`, `clients/zether-prover/src/{zether.rs,api.rs,vectors.rs}`, `smartcontracts/vectors/zether/soroban/` | Part Z |

## Setup (before T0)

- [ ] `git -C /home/ha/work/ainative/scaas worktree add -b ua-soroban /home/ha/work/ainative/scaas/.claude/worktrees/ua-soroban main`;
  check `git log main --oneline | grep -m1 'token-family rename'` (S18 precondition; merged as `1a68427a`) and
  `ls smartcontracts/vectors/ua/portable.json` (UA-8 Part A on `main`).

---

# Part UA-Soroban — Soroban UA base (branch `ua-soroban`)

### Task T0: network spike at Protocol 30 — HARD GATE (spec §10 T0, C11, S5, S17; S13a host primitives)

**Files:**
- Create: `smartcontracts/soroban/spike/Cargo.toml` (`[workspace] members = ["ua-spike"]`, the release profile of the
  main workspace), `spike/ua-spike/{Cargo.toml,src/lib.rs,src/test.rs}`, `spike/run.sh`, `spike/measure.py`,
  `smartcontracts/soroban/scripts/quickstart.sh`, `smartcontracts/soroban/runs/<run-date>-ua-soroban-t0-spike.txt`
- Modify: `smartcontracts/scripts/devnet.sh` (`soroban) exec "$SC/soroban/scripts/quickstart.sh" "$@"`),
  `smartcontracts/soroban/Cargo.toml` (`exclude = ["spike"]` only),
  `smartcontracts/soroban/.gitignore` (`spike/target/`)

**Interfaces:**
- Produces: contract `UaSpike` (never deployed outside the spike) with model entries, each doing the work of the real
  call it stands for:
  `verify_only(kind: u32, pk: Bytes, msg: Bytes, sig: Bytes)` (ML-DSA-44/65 via `env.crypto().ml_dsa_{44,65}_verify`,
  empty context);
  `register_model(pk: BytesN<1952>, msg: Bytes, sig: BytesN<3309>) -> BytesN<32>` (keccak id, one `mldsa65` verify,
  writes `Ua(id)` holding key data **and** `pop` (≈ 5.3 KB), `Key(hash)`, `List(kind, i)`, `Count(kind)`, an event);
  `msig_model(n: u32, member_ids: Vec<BytesN<32>>, pk, msg, sig)` (reads `n` member records, `n` verifies, writes an
  `msig` record whose `pop` holds the `n` signatures);
  `ua_pay_model(key: BytesN<65>, rp_id_hash: BytesN<32>, authenticator_data: Bytes, client_data_json: Bytes, sig: BytesN<64>, digest: BytesN<32>)`
  (the WebAuthn checks of spec §3, `secp256r1_verify`, reads a 96 B record, two balance writes, a lane write, three events);
  `bls_g1_msm(n: u32)`, `bls_g2_msm(n: u32)`, `bls_pairing(n_pairs: u32)`, `bls_fr_ops(n: u32)` (CAP-59 primitives
  over fixed valid points); `zether_transfer_model(m: u32)` (the host operations `ZetherVerifier.sol` `verifyTransfer`
  performs for `m` recipients — its MSM sizes, scalar multiplications, field inversions and keccak transcript calls,
  counted from the Solidity source and listed in the run log — over fixed valid points; a cost model, not a verifier).
- Produces: `quickstart.sh` (SOR-D4) with `QS_IMAGE=stellar/quickstart@sha256:<digest>`; `run.sh` = the spike's
  `cargo test -j2` (capped), then `quickstart.sh up`,
  trap `quickstart.sh down` on every exit, `wait`, `stellar network settings --output json > <log dir>/settings.json`,
  friendbot, `stellar contract deploy` of the spike Wasm, then `python3 -I measure.py` per call;
  `measure.py <settings.json>` builds each call with `stellar contract invoke … --build-only`, posts
  `simulateTransaction`, decodes `transactionData` with `stellar xdr decode --type SorobanTransactionData`, prints per call
  `instructions`, disk read / write bytes, transaction size, the largest written entry, the resource fee, and the network
  limit next to each; exits 1 on a simulation error or a figure over its limit.

- [ ] **Step 1: Failing tests** (`ua-spike/src/test.rs`, SDK testutils at protocol 30, each prints
  `env.cost_estimate().budget()` CPU and memory): `spike_mldsa44_verify_budget`, `spike_mldsa65_verify_budget` (the
  `portable.json` `mldsa44` / `mldsa65#1` `pop` over `popMessage` verifies; a flipped byte panics),
  `spike_register_mldsa65_model_budget`, `spike_msig3_mldsa65_model_budget`, `spike_ua_pay_passkey_model_budget`
  (`signatures.json` `webauthn-p256` `metatx` row), `spike_bls_g1_msm_budget` (n = 64, 128, 256),
  `spike_bls_g2_msm_budget` (n = 2, 8), `spike_bls_pairing_budget` (2 pairs), `spike_zether_transfer_model_budget`
  (m = 1, 2, 4, 8).
- [ ] **Step 2:** `cd smartcontracts/soroban/spike && ../../../scripts/capped cargo test -j2` — FAIL (no crate).
- [ ] **Step 3: Implement.** Pull the Core v30 quickstart (`latest` if it carries Core v30.0.0, else the tag that
  does), pin its digest; install the pinned `stellar-cli` (SOR-D5); record in the run log: image digest, Core and RPC
  versions, CLI version, the exact Rust signatures of `ml_dsa_44_verify` / `ml_dsa_65_verify` and of the BLS12-381
  functions used.
- [ ] **Step 4:** Step 2's command, then `CAPPED_SLOTS=1 smartcontracts/soroban/spike/run.sh 2>&1 | tee -a smartcontracts/soroban/runs/<run-date>-ua-soroban-t0-spike.txt`.
  Also scan `msig_model` for n = 1…16 and log the largest `n` whose simulation fits (data, not a gate).
  **Gate:** every unit test passes and every UA-Soroban network figure (`register_model`, `msig_model(3)`, `ua_pay_model`) is
  within the limits read from the network ⇒ continue. Otherwise ⇒ **STOP**: commit the spike and the log, report the
  figures and limits to the controller for the owner, start no further task until the owner rules. The BLS12-381 and
  Zether-model figures are logged as the S13a early estimate (Z0 is the Zether HARD GATE); a Zether model over a limit
  is reported, it does not stop UA-Soroban.
- [ ] **Step 5: Commit** `ua-soroban T0: Protocol 30 spike (ML-DSA, register / msig / ua_pay models, BLS12-381 primitives), quickstart pinned`.

### Task T1: SDK `=30.0.0-rc.1` on the whole workspace (S5)

**Files:**
- Modify: `smartcontracts/soroban/Cargo.toml` (`soroban-sdk = "=30.0.0-rc.1"`; `rust-version` only if the SDK needs a
  newer one), `smartcontracts/soroban/contracts/relay-fee/Cargo.toml` (`soroban-ledger-snapshot = "=30.0.0-rc.1"`),
  `Cargo.lock`, `contracts/token/src/test.rs`, any test the SDK change breaks (fix in place, behaviour unchanged);
  `scaas-node/Cargo.toml` (`stellar-xdr`) only if Step 4's node run cannot decode Protocol 30 data

**Interfaces:**
- Produces: every crate builds and tests on the pinned SDK; `Env::default()` at protocol 30.

- [ ] **Step 1: Failing test:** `env_default_protocol_30` (token tests: `env.ledger().protocol_version() == 30`).
- [ ] **Step 2:** `CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh soroban` — FAIL (protocol 26).
- [ ] **Step 3: Implement** the pin; `cd smartcontracts/soroban && ../../scripts/capped cargo update -p soroban-sdk -p soroban-ledger-snapshot`.
- [ ] **Step 4:** Step 2's command — PASS (every existing test, real-auth tests included); `scripts/capped
  smartcontracts/scripts/build.sh soroban`; then the existing node e2e against the Protocol 30 quickstart:
  `smartcontracts/soroban/scripts/quickstart.sh up && smartcontracts/soroban/scripts/quickstart.sh wait && (cd scaas-node && CAPPED_SLOTS=1 STELLAR_BIN=$(command -v stellar) ../scripts/capped cargo test -j2 --test e2e_soroban -- --ignored --test-threads=1); rc=$?; smartcontracts/soroban/scripts/quickstart.sh down; exit $rc`
  — PASS (a `stellar-xdr` decode failure ⇒ bump it to the release with Protocol 30 XDR, re-run `cargo-scaas-node`).
- [ ] **Step 5: Commit** `ua-soroban T1: soroban-sdk =30.0.0-rc.1 workspace-wide`.

### Task T2: `ua-common` and the registry's digests and verifiers (spec §2, §3; S3, S4, S10; C11)

**Files:**
- Create: `smartcontracts/soroban/contracts/ua-common/{Cargo.toml,src/lib.rs}`,
  `smartcontracts/soroban/contracts/ua-registry/{Cargo.toml,src/lib.rs,src/digest.rs,src/verify.rs,src/webauthn.rs,src/abi.rs,src/test_verify.rs}`
- Modify: `contracts/token/src/lib.rs` (`op_digest`, `meta_pay_id` imported from `ua-common`; behaviour unchanged)

**Interfaces:**
- Produces (`scaas_ua_common`):

```rust
#[contracttype] pub enum Holder { Addr(Address), Ua(BytesN<32>) }        // Ua = a derived id, never a native one
#[contracttype] pub enum Checked { None, Chain, Relayer(Address) }        // code points 0 / 1 / 2 (portable.json `checked`)
#[contracttype] pub struct UaAttrs { pub pqz_key: Bytes, pub pqz_pop_hash: BytesN<32>, pub kem_version: u64, pub kem_pk: Bytes }
#[contracttype] pub struct Registration { pub kind: u32, pub key_data: Bytes, pub attrs: UaAttrs, pub pop: Bytes,
    pub pop_checked: Checked, pub pqz_pop_checked: Checked, pub proven: bool, pub signable: bool, pub index: u32, pub ledger: u32 }
#[contracttype] pub struct Order { pub maker: Holder, pub destination: Holder, pub relayer: Address, pub sell_token: Address,
    pub sell_amount: i128, pub buy_token: Address, pub buy_amount: i128, pub max_fee_ppm: u32, pub expiry: u64, pub salt: u64 }
#[contractclient(name = "UaRegistryClient")]
pub trait UaRegistryApi {
    fn require_authorized(env: Env, ua: BytesN<32>, purpose: BytesN<32>, digest: BytesN<32>, auth: Bytes);
    fn receivable(env: Env, ua: BytesN<32>) -> bool;
    fn record_of(env: Env, ua: BytesN<32>) -> Option<Registration>;
}
pub const PURPOSE_METATX: [u8; 32]; PURPOSE_METATX_CANCEL; PURPOSE_TRADE; PURPOSE_MEMBER; PURPOSE_POP_V2; PURPOSE_KEM; PURPOSE_PQZ_KEY;
pub fn op_digest(env: &Env, contract: &Address, function: &str, args: Vec<Val>) -> BytesN<32>;   // NET-SOR-16 digest, spec §2
pub fn pay_lane(env: &Env, pay_ref: &BytesN<32>) -> BytesN<32>;   // keccak256("scaas.pay.lane" ‖ pay_ref), as EVM `payLane`
pub fn meta_pay_id(env: &Env, salt: &BytesN<32>, meta: &Bytes) -> BytesN<32>;
```

  `op_digest` takes the contract explicitly (the token passes its own address; `ua_trade` passes itself with function
  `"ua_order"`, spec §5.3).
- Produces (`ua-registry`, crate-private): `digest::{TAG(kind) -> BytesN<32>, ua_of(env, kind, key_data) -> BytesN<32>,
  ua_message(env, kind, purpose, digest), pq_message(env, kind, ua_msg), member_digest(env, structure_ua, ua_msg),
  portable_pop_digest(env, ua, pqz_key_hash, kem_record_hash), registration_digest(env, portable, pqz_pop_hash)}` —
  `env.crypto().keccak256`, CTR-UA-04 / -12 / -23 and UA8-D1 words; `verify::check(env, kind, key_data, msg: &Hash<32>, sig: &Bytes)`
  per S3 kind (spec §3 table; the signature bytes are the EVM encodings the vectors carry: WebAuthn
  `abi.encode(bytes authenticatorData, bytes clientDataJSON, bytes32 r, bytes32 s)`, P-256 `r ‖ s`, ed25519 64 B,
  secp256k1 `r ‖ s ‖ v`, ML-DSA raw), panicking on failure; `verify::check_evm_eoa_personal_sign(env, id20, member_digest, sig)`
  (S10, `secp256k1_recover` of the EIP-191 `personal_sign` hash, address = last 20 B of `keccak256(pubkey)`);
  `webauthn::check(…)` (spec §3 row 1: NET-ALL-04 grammar, challenge = base64url(`ua_msg`), `crossOrigin` absent or
  false, no `topOrigin`, `authData[0..32] == rpIdHash`, UP and UV, **no origin compare**); `abi::decode_member_sigs(bytes) -> Vec<MemberSig>`
  (`{u16 index, bytes keyData, bytes sig}`, UA8-D5) refusing any input that does not re-encode to the same bytes.
  `ua_message` is never taken from an argument and the `hazmat` feature is never enabled (spec §2).

- [ ] **Step 1: Failing tests** (`test_verify.rs`, vectors by `include_str!` from `smartcontracts/vectors/ua/`):
  `tags_match_kinds_json` (`kinds[].TAG` of the S3 kinds), `purpose_tags_match_kinds_json`,
  `ua_message_matches_kinds_json` (every `messages[]` row of an S3 kind), `portable_digests_match_portable_json` (every
  `registrations[]` `portablePopDigest` / `registrationDigest` / `popMessage`), `op_digest_matches_token_cross_vector`
  (the existing `cross_implementation_vector` of `token/src/test.rs`); per S3 single-key kind
  `kind_webauthn_p256_vectors_verify` / `kind_webauthn_p256_negatives_fail`, `kind_p256_vectors_verify` /
  `kind_p256_negatives_fail`, `kind_ed25519_vectors_verify` / `kind_ed25519_negatives_fail`,
  `kind_secp256k1_vectors_verify` / `kind_secp256k1_negatives_fail` (`signatures.json` `derived[]` `sigs` and
  `negatives`; a negative must panic or return `Err`), `kind_ed25519_rfc8032_vectors` (`ed25519Rfc8032`, `valid` as
  given), `kind_mldsa44_vectors_verify` / `kind_mldsa44_negatives_fail`, `kind_mldsa65_vectors_verify` /
  `kind_mldsa65_negatives_fail` (`pq_signatures.json` `kinds[]`); `member_sigs_abi_canonical_only` (a valid encoding
  decodes; trailing byte, non-minimal offset, unsorted index refused); `evm_eoa_member_personal_sign_recovers` (the
  `portable.json` `msig-pq-native` member 0 signature); `webauthn_origin_not_compared` (two origins, same key: both
  verify); `webauthn_cross_origin_refused` (`"crossOrigin":true` and a `topOrigin` refused, NET-SOR-13).
- [ ] **Step 2:** `cd smartcontracts/soroban && ../../scripts/capped cargo test -j2 -p scaas-ua-registry` — FAIL.
- [ ] **Step 3: Implement.** Ed25519 key validation (`y < p`, the eight small-order encodings) in the contract unless
  `kind_ed25519_negatives_fail` and the `kinds.json` `invalid` rows show the host already refuses them (record which).
- [ ] **Step 4:** `CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh soroban` — PASS.
- [ ] **Step 5: Commit** `ua-soroban T2: ua-common + registry digests and per-kind verifiers (vectors)`.

### Task T3: `UaRegistry` — `register`, `require_authorized`, lists, views (spec §3, §4; S1, S2, S9, S10, S11, S16; C13, C17)

**Files:**
- Modify: `contracts/ua-registry/src/lib.rs`; Create: `contracts/ua-registry/src/test.rs`,
  `smartcontracts/soroban/scripts/check-registry-interface.sh` (SOR-D18)

**Interfaces:**
- Produces (exactly these exported functions; spec §4):

```rust
fn __constructor(env: Env, relayers: Vec<Address>);                          // instance storage, immutable (C13)
fn register(env: Env, kind: u32, key_data: Bytes, attrs: UaAttrs, pop: Bytes, pqz_pop: Bytes, relayer: Option<Address>) -> BytesN<32>;
fn require_authorized(env: Env, ua: BytesN<32>, purpose: BytesN<32>, digest: BytesN<32>, auth: Bytes);
fn registration_of(env: Env, ua: BytesN<32>) -> Option<(u32, Bytes, UaAttrs, Bytes, Bytes)>;
fn record_of(env: Env, ua: BytesN<32>) -> Option<Registration>;
fn key_owner(env: Env, key_hash: BytesN<32>) -> Option<BytesN<32>>;
fn ua_of(env: Env, kind: u32, key_data: Bytes) -> BytesN<32>;
fn receivable(env: Env, ua: BytesN<32>) -> bool;                              // = signable; false when unregistered (SOR-D15)
fn relayers(env: Env) -> Vec<Address>;
fn ua_count(env: Env, kind: u32) -> u32;
fn ua_at(env: Env, kind: u32, i: u32) -> BytesN<32>;
fn ua_page(env: Env, kind: u32, start: u32, n: u32) -> Vec<BytesN<32>>;     // clamped to the list
```

  Persistent keys `Ua(ua) → Registration`, `Key(key_hash) → ua`, `List(kind, i) → ua`, `Count(kind) → u32`; every write
  and every in-transaction read extends the entry (`extend_ttl(30 * DAY, 60 * DAY)`, `DAY = 17_280`). Event
  `UaRegistered { #[topic] ua, #[topic] kind, record, checked }` where `record` is the `Registration` with `pop` replaced by
  `pop_hash = keccak256(pop)` (`BytesN<32>`); `pop` stays in `Ua(ua)` (owner ruling 2026-10-30 after T0: the 16 384 B
  contract-events limit). `register` checks in spec §3's order;
  `pop_checked = Chain`, `pqz_pop_checked = None`, `proven = false`, `signable` per spec §4 (`msig`: the summed weight of
  members Soroban can verify for signing — registered signable S3 members, 0x0011, 0x0012; `evm-eoa` and
  `evm-contract` weigh 0 — must reach the threshold); `index` = the list position (CTR-UA-29); `ledger` = the sequence.
  `msig` key data per CTR-UA-09 (threshold, members sorted strictly by id, `count ≤ 16`); a member is a registered S3
  single-key UA, 0x0011, 0x0012, `evm-eoa` 0x0001 or `evm-contract` 0x0002, else `MemberUnknown`; the `msig` `pop` is
  `abi.encode(MemberSig[])` under purpose `member` (`member_digest(ua, uaMessage(MSIG, POP_V2, registrationDigest))`),
  a registered member's slot with an **empty `keyData`** (its key read from the member's record; non-empty ⇒ `Pop`;
  owner ruling 2026-10-30 after T0):
  derived members by `verify::check`, `evm-eoa` by `personal_sign`, native Soroban members by
  `member.require_auth_for_args((ua, purpose, digest))` with an empty slot, an `evm-contract` slot ⇒ `NotVerifiable`
  (SOR-D6). `require_authorized`: `NotRegistered`, then `Unauthorized` unless `signable` and `purpose ∉ {POP_V2, KEM,
  PQZ_KEY}`, then the kind's check over `ua_message(kind, purpose, digest)` (ML-DSA over `pq_message`), `msig` members
  under purpose `member` until the threshold (an `evm-eoa` member never counts); extends `Ua(ua)`.

- [ ] **Step 1: Failing tests** (`test.rs`; real authorization only, `mock_all_auths` never for the property under test):
  `register_portable_pop_from_portable_json` (every `registrations[]` row of an S3 kind with empty `attrs`:
  `webauthn-p256`, `p256`, `ed25519`, `secp256k1`, `mldsa44`, `mldsa65#1`, `mldsa65#2`; `registration_of` equals the row);
  `register_any_submitter` (no source-account auth recorded); `register_front_run_identical` (second submit ⇒
  `AlreadyRegistered`, the stored record equal); `register_disabled_kind_refused` (`bip340`, `fndsa512`, `slhdsa128s`,
  `zether-bls12381` rows ⇒ `KindDisabled`); `register_attrs_refused_4b` (`mldsa65/n2304-kmax4096`, `msig-pq/n2304-kmax4096`
  ⇒ `Attrs`); `register_unverifiable_part_refused_4b` (an `msig` with an `evm-contract` member in its signing set ⇒
  `NotVerifiable`, also with `relayer = Some(listed)`); `id_in_native_space_refused`; `key_hash_unique` (`KeyInUse`);
  `key_data_invalid_rows_refused` (`kinds.json` `invalid[]` rows of S3 kinds: refused; `KeyData` where the contract
  checks); `registration_of_returns_register_args`; `msig_member_unknown_refused` (`msig-classical`: members of
  disabled kinds); `kind_msig_vectors_verify` / `kind_msig_negatives_fail` (a 2-of-3 `msig` of `ed25519`, `p256`,
  `mldsa65#1` registered in-test: `require_authorized` with 2 members passes, 1 member, a swapped index, a
  non-canonical encoding fail); `msig_soroban_native_member_host_auth` (a `G…` member signs a real ed25519 auth entry
  for `(ua, purpose, digest)`, as `relay_g_account_payer_real_signed_entries`; without it the call fails);
  `msig_evm_eoa_member_portable_only` (`msig-pq-native` registers by its `personal_sign` pop; `require_authorized` with
  the EOA member's signature does not count it); `msig_unsignable_not_receivable` (`msig-pq-native`: `signable = false`,
  `receivable = false`, `require_authorized` ⇒ `Unauthorized`); `require_authorized_each_kind_and_purpose` (every S3
  kind under `metatx`, `trade`, `metatx-cancel`, `member`: `signatures.json` / `pq_signatures.json` rows; wrong purpose
  fails); `require_authorized_refuses_portable_purposes` (`pop` v2, `kem`, `pqz-key` ⇒ `Unauthorized`);
  `require_authorized_not_registered`; `ua_lists_per_kind` (`ua_count`, `ua_at`, `ua_page` clamping,
  `Registration.index`); `entries_extend_ttl` (TTL of `Ua`, `Key`, `List`, `Count` after write; `Ua` after
  `require_authorized`); `relayers_from_constructor` (empty and two-element lists returned unchanged).
- [ ] **Step 2:** `cd smartcontracts/soroban && ../../scripts/capped cargo test -j2 -p scaas-ua-registry` — FAIL.
- [ ] **Step 3: Implement**; write `check-registry-interface.sh <wasm>` (exit 1 unless the exported functions are
  exactly the list above).
- [ ] **Step 4:** `CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh soroban` — PASS;
  `scripts/capped smartcontracts/scripts/build.sh soroban && smartcontracts/soroban/scripts/check-registry-interface.sh smartcontracts/soroban/target/wasm32v1-none/release/scaas_ua_registry.wasm` — `registry interface: ok`.
- [ ] **Step 5: Commit** `ua-soroban T3: UaRegistry (portable register, require_authorized, msig members S10, lists, no admin)`.

### Task T4: clientkeys Soroban encodings and `ua-ops.json` (spec §2, §10; SOR-D12, SOR-D13)

**Files:**
- Create: `clients/clientkeys/src/soroban.js`, `clients/clientkeys/scripts/soroban-ua-ops-vectors.mjs` →
  `smartcontracts/soroban/vectors/ua-ops.json`, `clients/clientkeys/scripts/soroban-sign.mjs`,
  `clients/clientkeys/test/soroban.test.js`

**Interfaces:**
- Produces (`soroban.js`): typed ScVal values and their XDR — `sym(s)`, `bytes(u8)`, `bytesN(u8)`, `addr(strkey)`,
  `i128(n)`, `u64(n)`, `u32(n)`, `bool(b)`, `vec([...])`, `none()`, `some(v)` (= `v`), `holderAddr(strkey)`,
  `holderUa(id)` (contracttype enum = `Vec[Symbol(variant), payload]`), `struct({field: v})` (= `Map` of `Symbol(field)
  → v`, keys sorted), `scvalXdr(v) → Uint8Array`; `networkId(passphrase) = sha256(passphrase)`;
  `opDigest({ networkId, contract, fn, args }) = sha256(xdr(Vec[Symbol("scaas_metaop_v1"), Bytes(networkId),
  Address(contract), Symbol(fn), Vec(args)]))`; `uaOpMessage(kind, purpose, digest)` (= `ua.uaMessage`);
  `uaUrn(kind, id) = "urn:scaas:ua:v1:<kind>:<hex32>"`, `parseRecipient(text) → { addr } | { ua, kind }`,
  `assertNativeRecipient(text)` (throws `UAError('UaNotNative')` on a URN; spec §2, NET-ALL-21); strkeys via
  `seed.js` `strkey`.
- Produces `ua-ops.json`: `{ note, version: 1, network: { passphrase, networkId }, contracts: { registry, token, mandate,
  dex, router }, registrations[] (the S3 rows used plus a 2-of-3 msig of ed25519 / p256 / mldsa65#1 with its portable
  pop), entries[] }`; `entries[]` rows `{ name, contract, fn, args (typed, hex XDR), digest, purpose, perKind: [{ kind,
  ua, uaMsg, auth }] }` for `ua_transfer`, `ua_pay`, `ua_pay_meta`, `ua_burn`, `ua_cancel_nonce`, `ua_order` (the
  `ua_trade` digest), `ua_cancel` (DEX), `ua_relay` (its inner `ua_pay` with `relayer = Some(router)`, `pay_ref = ref`),
  `mtx_mandate_pay`, `mtx_set_mandate`; `perKind` = the six single-key S3 kinds and the msig (seeds: account 0 of
  `ua-signers.mjs`, `mldsa65` index 1 and 2 as in `portable.json`; ML-DSA `extraEntropy: false`).
- Produces `soroban-sign.mjs <kind> <keyIndex> <hex digest> <purpose>` → JSON `{ ua, keyData, auth }` (the e2e signer).

- [ ] **Step 1: Failing tests** (`soroban.test.js`): `soroban op digest: the token cross vector reproduced` (the
  `PREIMAGE` of `scaas-node/src/adapters/soroban.rs` and its sha256), `soroban ua-ops.json reproduced byte for byte`,
  `soroban ua-ops: every auth verifies under its kind` (the clientkeys verifiers of `test/ua-verify.js`),
  `soroban URN: derived ids never as strkey; a native send to a URN is refused`.
- [ ] **Step 2:** `cd clients/clientkeys && ../../scripts/capped npm test` — FAIL.
- [ ] **Step 3: Implement**; `node scripts/soroban-ua-ops-vectors.mjs` writes the file (`--check` compares).
- [ ] **Step 4:** Step 2's command — PASS; `node scripts/soroban-ua-ops-vectors.mjs --check` — exit 0.
- [ ] **Step 5: Commit** `ua-soroban T4: clientkeys Soroban encodings, ua-ops.json, e2e signer`.

### Task T5: the token's UA ledger (spec §5.1, §5.5; S6, S7, S8, S9, S11, S16)

**Files:**
- Create: `contracts/token/src/ua.rs`, `contracts/token/src/test_ua.rs`
- Modify: `contracts/token/src/lib.rs` (constructor, pool refusal, `mod ua`), `contracts/token/Cargo.toml`
  (`scaas-ua-common`; dev: `scaas-ua-registry`), every test and script that constructs the token
  (`contracts/{token,dex,mandate,relay-fee,smart-key-account}/src/test.rs`, `scaas-node/tests/e2e_soroban.rs`
  `deploy_token`, `smartcontracts/scripts/deploy.sh`)

**Interfaces:**
- Consumes: T2 `ua-common`; T3 registry; T4 `ua-ops.json`.
- Produces (`registry: Option<Address>` set at construction, instance storage):

```rust
fn registry(env: Env) -> Option<Address>;
fn ua_balance(env: Env, ua: BytesN<32>) -> i128;
fn ua_nonce(env: Env, ua: BytesN<32>, lane: BytesN<32>) -> u64;
fn ua_ref_used(env: Env, ua: BytesN<32>, pay_ref: BytesN<32>) -> bool;                       // SOR-D7
fn transfer_to_ua(env: Env, from: Address, to: BytesN<32>, amount: i128);                     // from.require_auth()
fn pay_to_ua(env: Env, from: Address, to: BytesN<32>, amount: i128, pay_ref: BytesN<32>, valid_until: u64); // PayRef(from, pay_ref) once
fn mint_to_ua(env: Env, to: BytesN<32>, amount: i128);                                        // admin
fn ua_transfer(env: Env, from: BytesN<32>, to: Holder, amount: i128, lane: BytesN<32>, nonce: u64, valid_until: u64, relayer: Option<Address>, auth: Bytes);
fn ua_pay(env: Env, from: BytesN<32>, to: Holder, amount: i128, pay_ref: BytesN<32>, valid_until: u64, relayer: Option<Address>, auth: Bytes);
fn ua_pay_meta(env: Env, from: BytesN<32>, to: Holder, amount: i128, salt: BytesN<32>, meta: Bytes, valid_until: u64, relayer: Option<Address>, auth: Bytes);
fn ua_burn(env: Env, from: BytesN<32>, amount: i128, lane: BytesN<32>, nonce: u64, valid_until: u64, relayer: Option<Address>, auth: Bytes);
fn ua_cancel_nonce(env: Env, ua: BytesN<32>, lane: BytesN<32>, valid_until: u64, auth: Bytes);
fn ua_trade(env: Env, dex: Address, order: Order, auth: Bytes, amount: i128);
```

  Rules: `registry() == None` ⇒ every UA entry `UaLedgerOff`; the signed digest of an entry is
  `op_digest(token, "<fn>", args without auth)` under purpose `metatx` (`metatx-cancel` for `ua_cancel_nonce`); for
  `ua_trade` `op_digest(token, "ua_order", (dex, order))` under `trade`, plus `dex.require_auth()`, `order.maker ==
  Holder::Ua(ua)`, `order.sell_token == token`, `now ≤ order.expiry`, no nonce (the DEX's `filled` bounds it);
  `valid_until` ⇒ `Expired`; lane: `nonce == ua_nonce(from, lane)` else `BadNonce`, then `nonce + 1` (`ua_pay` /
  `ua_pay_meta`: `lane = pay_lane(pay_ref)`, `nonce = 0`); `ua_cancel_nonce` bumps the lane by one and emits
  `UaNonceCancelled { #[topic] ua, #[topic] lane, new_nonce }`; `Some(r)` ⇒ `r.require_auth()`; receivers
  `Holder::Ua` through `receivable` (SOR-D15); the **pool is the token's own address**: native ↔ UA moves go through the
  real balance `Balance(token)`, so `balance(token) = Σ UaBalance`; native `transfer`, `transfer_from`, `pay`, `pay_meta`,
  `mint`, `transfer_to_ua`'s `from`, a `Holder::Addr(token)` receiver ⇒ `UaPoolNotPayable`. Events: SEP-41
  `transfer` / `mint` / `burn` with the pool as the native endpoint of every native ↔ UA move;
  `UaTransfer { #[topic] from: Holder, #[topic] to: Holder, amount }` on every UA move (`mint_to_ua` from
  `Holder::Addr(token)`, `ua_burn` to `Holder::Addr(token)`); a payment also `UaPaymentSettled { #[topic] from: Holder,
  #[topic] to: Holder, amount, pay_ref }` (`ua_pay_meta`: `PaymentMeta` first); every signed entry
  `UaMetaTransactionExecuted { #[topic] from: BytesN<32>, digest }`. Persistent `UaBalance(ua)`, `UaNonce(ua, lane)`,
  extended on each write and read.

- [ ] **Step 1: Failing tests** (`test_ua.rs`; the registry deployed in-test; real UA signatures from T4's signer
  rows or in-test ed25519 / P-256 keys registered first): `transfer_to_ua_then_ua_transfer`, `ua_transfer_replay_refused`,
  `ua_pay_once_per_ref` (`ua_ref_used` before / after; a second `ua_pay` with the same ref ⇒ `BadNonce`),
  `ua_pay_meta_emits_meta_first`, `ua_burn_and_cancel_nonce`, `ua_expired_refused`,
  `ua_entry_archived_nonce_restored_not_reset` (advance the ledger past the lane entry's TTL, re-submit the spent nonce:
  `is_err()`; when the testutils restore the entry, the next nonce continues from the stored value, never 0),
  `pool_address_not_payable` (each native path to the token's address ⇒ `UaPoolNotPayable`),
  `sep41_events_match_balance_with_ua_moves` (replay `transfer` / `mint` / `burn` events over a mixed sequence: every
  `balance()` incl. the pool matches; `balance(token) == Σ ua_balance`), `relayer_bound_needs_auth` (`Some(r)` without
  `r`'s auth fails; with it passes; `None` passes), `ua_ledger_off_refused`,
  `ua_receiver_not_registered_or_not_receivable`, `mint_to_ua_admin_only`, `ua_entries_extend_ttl`,
  `ua_ops_vectors_token_rows` (the token registered at `ua-ops.json`'s id and network id: each token row's `digest`
  recomputed, each `perKind` `auth` accepted by `ua_transfer` / `ua_pay` / `ua_pay_meta` / `ua_burn` /
  `ua_cancel_nonce`), `ua_trade_only_named_dex` (another contract as `dex` fails; the named DEX moves `amount` from the
  UA ledger to its own balance).
- [ ] **Step 2:** `cd smartcontracts/soroban && ../../scripts/capped cargo test -j2 -p scaas-token` — FAIL.
- [ ] **Step 3: Implement**; update every constructor call site (`registry = None` where a test does not need the UA
  ledger; the CLI `deploy` passes `--registry` only when set).
- [ ] **Step 4:** `CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh soroban` — PASS.
- [ ] **Step 5: Commit** `ua-soroban T5: token UA ledger (ua_* entries, lanes, pool = token address, relayer binding)`.

### Task T6: mandate with UA owner, delegate and payees (spec §5.2; SOR-D9)

**Files:**
- Modify: `contracts/mandate/src/{lib.rs,test.rs}`, `contracts/mandate/Cargo.toml`, `contracts/relay-fee/src/test.rs`
  (mandate call sites)

**Interfaces:**
- Produces: `__constructor(owner: Holder, registry: Option<Address>)`; `owner() -> Holder`;
  `mtx_set_mandate(token, delegate: Holder, max_per_payment, max_per_period, period_seconds, expiry, lane, nonce, valid_until, relayer, auth)`,
  `mtx_set_payee(token, payee: Holder, allowed: bool, lane, nonce, valid_until, relayer, auth)`,
  `mtx_revoke(token, by: Holder, epoch, lane, nonce, valid_until, relayer, auth)` (`by` = owner or delegate; `epoch` from T6b),
  `mtx_withdraw(token, to: Holder, amount, lane, nonce, valid_until, relayer, auth)` (a UA `to` by `transfer_to_ua`),
  `mtx_mandate_pay(token, payee: Holder, amount, pay_ref, epoch, valid_until, relayer, auth)` (the delegate signs; a UA payee
  by `token.pay_to_ua(self, …)`; `pay_ref` once per mandate as today), `paid(pay_ref) -> bool` (for the node's
  `op_consumed`); `Mandate.delegate: Holder`, `Payee(token, Holder)`; mandate-own persistent lanes `UaNonce(ua, lane)`
  and view `ua_nonce(ua, lane)`; the UA digest `op_digest(mandate, "<fn>", args without auth)` under `metatx`. The old
  names (`set_mandate`, `set_payee`, `revoke`, `withdraw`, `pay_under_mandate`) are gone (new deployment).

- [ ] **Step 1: Failing tests:** `mandate_ua_owner_delegate_payee` (UA owner sets a mandate for a UA delegate and a UA
  payee; the delegate pays; the payee's `ua_balance` rises), `mandate_native_owner_unchanged_semantics` (the existing
  mandate tests on the new names with native holders: caps, period, expiry, payee list), `mandate_ua_owner_lane_replay_refused`,
  `mandate_pay_ref_once`, `mandate_withdraw_to_ua`, `ua_ops_vectors_mandate_rows` (`mtx_mandate_pay`, `mtx_set_mandate`).
- [ ] **Step 2:** `cd smartcontracts/soroban && ../../scripts/capped cargo test -j2 -p scaas-mandate` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** `CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh soroban` — PASS.
- [ ] **Step 5: Commit** `ua-soroban T6: mandate UA holders (mtx_* names, UA lanes, UA payees)`.

### Task T7: DEX UA legs (spec §5.3; SOR-D10)

**Files:**
- Modify: `contracts/dex/src/{lib.rs,test.rs}`, `contracts/dex/Cargo.toml`, `contracts/smart-key-account/src/test.rs`
  (DEX call sites)

**Interfaces:**
- Consumes: `Order` (T2), `token.ua_trade` (T5).
- Produces: `settle(maker: Order, taker: Order, maker_fill: i128, maker_auth: Bytes, taker_auth: Bytes)`: both orders'
  `relayer.require_auth()` (NET-SOR-10); per leg: `Holder::Addr(a)` ⇒ `a.require_auth_for_args((order,))`, `auth` empty,
  funds by `transfer_from`; `Holder::Ua(u)` ⇒ `sell_token.ua_trade(dex, order, auth, fill)`; proceeds to each order's
  `destination` (native `transfer`, UA `transfer_to_ua` from the DEX); fees as today; `filled[order_hash]` bounds every
  fill (overfill rule unchanged); `cancel(order)` for native makers; `ua_cancel(order: Order, auth: Bytes)` (SOR-D10) sets
  `filled = sell_amount`.

- [ ] **Step 1: Failing tests:** `ua_trade_dex_only_partial_fill_no_resign` (a UA maker's one signature fills in three
  settles up to `sell_amount`, a fourth ⇒ `Overfill`; a second DEX instance cannot use it),
  `dex_ua_maker_native_taker_settles`, `dex_native_orders_bind_relayer` (an order settled by another relayer fails),
  `dex_ua_cancel_sets_filled`, `dex_ua_destination_receives_proceeds` (UA and native destinations),
  `ua_ops_vectors_ua_trade_rows` (`ua_order` and `ua_cancel` rows).
- [ ] **Step 2:** `cd smartcontracts/soroban && ../../scripts/capped cargo test -j2 -p scaas-dex` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** `CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh soroban` — PASS.
- [ ] **Step 5: Commit** `ua-soroban T7: DEX UA legs (ua_trade, destinations, ua_cancel, bound relayer)`.

### Task T8: relay-fee router `ua_relay` (spec §5.4, §5.5; CTR-MTX-27; SOR-D11)

**Files:**
- Modify: `contracts/relay-fee/src/{lib.rs,test.rs}`, `contracts/relay-fee/Cargo.toml`

**Interfaces:**
- Produces: `ua_relay(payer: BytesN<32>, target: Address, func: Symbol, args: Vec<Val>, salt: BytesN<32>, token: Address, to: Holder, amount: i128, valid_until: u64, relayer: Address, auth: Bytes)`:
  `relayer.require_auth()`; `TargetNoCode` as `relay`; `ref = relay_ref(target, func, args, salt)` (unchanged formula);
  `env.invoke_contract(target, func, args)`; then `token.ua_pay(payer, to, amount, ref, valid_until, Some(router), auth)`;
  open mode `to == Holder::Addr(router)` forwards to `relayer`; `RelayFeePaid { call_ref, target, token, payer: Holder,
  payee: Holder, amount }` for both `relay` and `ua_relay`.

- [ ] **Step 1: Failing tests:** `ua_relay_router_only` (the same `ua_pay` auth submitted directly to the token fails:
  `router.require_auth()` unmet), `ua_relay_open_mode_pays_submitter`, `ua_relay_bound_ua_payee`,
  `ua_relay_ref_commits_to_call` (other args or salt ⇒ the UA signature fails), `relay_fee_paid_holder_fields`,
  `ua_ops_vectors_ua_relay_row`; the existing relay tests stay green on the new event.
- [ ] **Step 2:** `cd smartcontracts/soroban && ../../scripts/capped cargo test -j2 -p scaas-relay-fee` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** `CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh soroban` — PASS.
- [ ] **Step 5: Commit** `ua-soroban T8: relay-fee ua_relay, Holder payer / payee`.

### Task T9: `scaas-node` Soroban adapter (spec §8, §9; S12, S14, S15; SOR-D14)

**Files:**
- Modify: `scaas-node/src/adapters/soroban.rs`, `scaas-node/src/config.rs` (only if `params` needs a typed field),
  `scaas-node/node.example.toml` (Soroban `params.max_deposit_per_job`, `params.dex`)

**Interfaces:**
- Produces: `build` dispatches on `job.kind`: `"ua_metatx"` ⇒ `ua_metatx_job`, `None` / `"signed_op"` ⇒ the existing
  `job_call`, anything else ⇒ refused (`unknown job kind`). `pub fn ua_metatx_job(network: &[u8; 32], op: &Value, lane: &ScAddress, policy: &RelayFeePolicy) -> Result<(InvokeContractArgs, Vec<SorobanAuthorizationEntry>, [u8; 32])>`
  (call, auth, op digest): allow-list — token ∈ `policy.tokens`: `ua_transfer`, `ua_pay`, `ua_pay_meta`, `ua_burn`,
  `ua_cancel_nonce`; router = `policy.router`: `ua_relay` (its `relayer` argument = this lane); DEX = `params.dex`:
  `settle`, `ua_cancel`; any contract: `mtx_set_mandate`, `mtx_set_payee`, `mtx_revoke`, `mtx_withdraw`,
  `mtx_mandate_pay`; a per-function table gives arity and the indexes of `valid_until`, `relayer`, `from` / `lane` /
  `nonce` / `pay_ref`; `relayer` must be `None` or this lane (`ua_relay`: this lane); `valid_until` and the contract come
  from the signed arguments (NET-SOR-15); `op.auth` entries only for native legs (`host_call`'s decoder); when the
  relayer is this lane, one `SourceAccount` entry rooted at exactly the call (as `relay_fee_job`); the digest
  `op_digest` over the arguments without `auth` (none for `settle`). `fn check_recorded_auth(sim: &Value, call: &InvokeContractArgs) -> Result<()>`:
  a simulation result whose auth contains a `SourceAccount` entry not rooted at exactly `call` fails the job before
  submission (S14, spec §8). `op_consumed` for `ua_metatx` jobs: simulate the view (`ua_nonce(ua, lane) > nonce`,
  `ua_ref_used(ua, pay_ref)`, mandate `paid(pay_ref)`); a view that needs a restore ⇒ unknown (`Ok(None)`), never
  "not consumed". Archived footprint (Protocol 23 `transactionData` with archived entries): accepted when the resource
  fee ≤ `params.max_deposit_per_job` (stroops), else `Revert("restore over max_deposit_per_job")`; a legacy
  `restorePreamble` stays `Revert`. `pays_router` also covers `ua_pay` / `ua_pay_meta` with `to = Holder::Addr(router)`
  outside `ua_relay`. `decode_event`: `UaTransfer`, `UaPaymentSettled`, `UaMetaTransactionExecuted`, `UaNonceCancelled`,
  `UaRegistered`, and `RelayFeePaid` with `Holder` fields (`{"addr": "G…"}` / `{"ua": "0x…"}`).
  `params.ua_registry` and the `relayers()` start-up check are Part B (B6).

- [ ] **Step 1: Failing tests** (`adapters::soroban::tests`): `ua_metatx_refuses_extra_source_account_auth`,
  `ua_metatx_allowlist` (each class / function; a token function on an unlisted contract, an unknown function refused),
  `ua_metatx_relayer_must_be_lane`, `ua_metatx_digest_matches_ua_ops_vectors`, `op_consumed_ua_lane`,
  `op_consumed_ua_pay_ref`, `auto_restore_within_deposit_cap` (fixture simulation JSON: within / over the cap / cap
  absent), `restore_preamble_still_reverts`, `pays_router_covers_ua_pay`, `decode_ua_events`,
  `decode_relay_fee_paid_holder`, `soroban_unknown_job_kind_refused`.
- [ ] **Step 2:** `cd scaas-node && ../scripts/capped cargo test -j2 adapters::soroban` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** `cd scaas-node && ../scripts/capped sh -c 'cargo clippy -j2 --all-targets -- -D warnings && cargo test -j2'` — PASS.
- [ ] **Step 5: Commit** `ua-soroban T9: scaas-node Soroban ua_metatx jobs, lane-authority rule, auto-restore cap, UA events`.

### Task T10: local e2e on the Protocol 30 quickstart (spec §10 e2e; S17)

**Files:**
- Create: `scaas-node/tests/e2e_soroban_ua.rs` (`#[ignore]`), `smartcontracts/soroban/scripts/e2e-local.sh`,
  `smartcontracts/soroban/runs/<run-date>-ua-soroban-e2e-local.txt`
- Modify: `scaas-node/tests/e2e_soroban.rs` (the T5 constructor; env `STELLAR_PASSPHRASE`, `STELLAR_FRIENDBOT` with the
  local defaults, shared with the new file)

**Interfaces:**
- Produces: `e2e-local.sh` = build Wasm (capped), `check-registry-interface.sh`, `quickstart.sh up && wait`, trap `down`,
  then `CAPPED_SLOTS=1` capped `cargo test -j2 --test e2e_soroban -- --ignored --test-threads=1` and
  `--test e2e_soroban_ua -- --ignored --test-threads=1 --nocapture`; env `STELLAR_URL`, `STELLAR_PASSPHRASE`,
  `STELLAR_FRIENDBOT`, `STELLAR_BIN` (T14 reuses it against the testnet). The e2e deploys the registry (relayers = the
  two lanes), a token bound to it, a mandate, the DEX and the router; registrations are submitted directly by the lane
  key through the CLI (anyone may submit; the node's `call` job is Part B B6); UA signatures come from
  `soroban-sign.mjs` (SOR-D13).

- [ ] **Step 1: Failing tests:** `e2e_soroban_ua_register_passkey_and_mldsa65`,
  `e2e_soroban_ua_transfer_to_ua_and_ua_pay_relayed` (a `ua_metatx` job through `lane_step`, finality and the
  `UaPaymentSettled` row through `index_step`), `e2e_soroban_ua_relay_fee` (`ua_relay`, open mode),
  `e2e_soroban_ua_mandate_pays_ua_payee`, `e2e_soroban_ua_dex_leg` (one UA maker leg against a native taker),
  `e2e_soroban_ua_lane_authority_not_lent` (a job whose call would need the lane's auth elsewhere is refused before
  submission; the lane's sequence is unchanged); each logs CPU instructions and fees.
- [ ] **Step 2:** `smartcontracts/soroban/scripts/e2e-local.sh` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** `smartcontracts/soroban/scripts/e2e-local.sh 2>&1 | tee smartcontracts/soroban/runs/<run-date>-ua-soroban-e2e-local.txt` — PASS.
- [ ] **Step 5: Commit** `ua-soroban T10: local Protocol 30 e2e (registry, UA ledger, relay fee, mandate, DEX leg)`.

### Task T11: docs, decisions, TODO (spec §1 docs list; every §0 row)

**Files:**
- Modify: `docs/networks/soroban.md` — new section "UA base (UA-Soroban)" with NET-SOR-17 (registry: S1, S2, S4, S16, ids and
  URN display of spec §2, the `register` order, errors), NET-SOR-18 (kinds S3, `msig` members S10), NET-SOR-19
  (receivability S9), NET-SOR-20 (UA ledger S6, S7, S8, the pool, events), NET-SOR-21 (mandate, DEX, router UA holders,
  spec §5.2–§5.5), NET-SOR-22 (storage, TTL, archival, who pays: S11, S12), NET-SOR-23 (node: S14, S15, spec §8, §9),
  NET-SOR-24 (pins and order: S5, S17, S18; the T0 limits and figures with the run logs, the largest `msig`),
  NET-SOR-25 (classical Zether, S13a: in this round, Part Z, status SPECIFIED), NET-SOR-26 (PQZ, S13b); NET-SOR-11 (the
  node's restore half BUILT), NET-SOR-16 (the mandate names built), §8 conformance (the new tests); §9 "Confidential
  payments" points to NET-SOR-25. `docs/contracts/accounts.md` — the Soroban row of the non-EVM table ("registry =
  `UaRegistry`, persistent entries") and of "Where the records live" (`UaRegistry` `Ua(ua)` / `Key(keyHash)`, TTL
  extended by use, **no node job**), the CTR-UA-31 family table (Soroban: UA-Soroban built, Part B next).
  `docs/node/job-api.md` — the Soroban `ua_metatx` payload (SOR-D14) and allow-list. `docs/decisions.md` (section 30,
  Networks — Soroban) — NET-SOR-17…26 entries, each spec row S1–S18 (S13a, S13b separate) **in full** with its "who",
  and SOR-D1–D18 in full ("controller proposal, owner may override", status, commit). The spec's status line ("UA-Soroban built
  on `ua-soroban` …"); `TODO.md` step 4 (UA-Soroban built, next: review, owner go, then Part B and Part Z).
- [ ] **Step 1:** Write every change (measured figures only, no `[estimate]` for a measured one).
- [ ] **Step 2:** `python3 scripts/test_docs_check.py && python3 -I scripts/docs_check.py check` — 0 errors.
- [ ] **Step 3: Commit** `ua-soroban T11: docs (soroban NET-SOR-17..26, accounts, job API, decisions S1-S18 and SOR-D1..D18, TODO)`.

### Task T12: gate runner (resumable per step)

**Files:**
- Create: `smartcontracts/evm/runs/2026-10-30-ua-soroban-gates.sh` (sets `P=2026-10-30-ua-soroban`, `STEPS`,
  `FAMILIES`, `NEW_TESTS`, then sources `2026-10-27-metatx-split-gates.sh`, as `2026-10-30-ua8-gates.sh` does)
- Modify: `smartcontracts/evm/runs/2026-10-27-metatx-split-gates.sh` (`run_step` gains two commands, nothing else:
  `soroban-spike-local) CAPPED_SLOTS=1 smartcontracts/soroban/spike/run.sh ;;` (its first action is the spike's
  `cargo test`, capped) and `e2e-soroban-local) smartcontracts/soroban/scripts/e2e-local.sh ;;`)

**Interfaces:**
- Produces: `STEPS="docs soroban clientkeys cargo-scaas-node soroban-spike-local e2e-soroban-local named-tests"`,
  `FAMILIES="soroban soroban-spike-local e2e-soroban-local"`; `NEW_TESTS` = every test name of T0–T10 in its step and
  form: `soroban-spike-local|cargo|<T0 name>`, `soroban|cargo|<T1–T3, T5–T8 name>`, `clientkeys|node|<T4 name>`,
  `cargo-scaas-node|cargo|<T9 name>`, `e2e-soroban-local|cargo|<T10 name>`. The step contract is the base runner's
  (`--only <step>`, `GATES_FRESH=1`, logs `smartcontracts/evm/runs/2026-10-30-ua-soroban-<step>.txt`, skip at the same
  commit with a clean tree, stop at the first failure). `cargo-scaas-node` needs the Algorand artifacts once per
  checkout (`ALGORAND_ARTIFACTS_CHECK=1 scripts/capped smartcontracts/scripts/build.sh algorand`).

- [ ] **Step 1:** Write the runner and the names.
- [ ] **Step 2: Self-check the guard:** `NAMED_TESTS_LOG_DIR=<scratch copy of the logs with one soroban name removed> smartcontracts/evm/runs/2026-10-30-ua-soroban-gates.sh --only named-tests` exits non-zero.
- [ ] **Step 3: Run** `smartcontracts/evm/runs/2026-10-30-ua-soroban-gates.sh` (no other gate runner and no other
  quickstart running). Expected: every step `rc=0`. On a failure: fix in the owning task's files, commit, re-run (done
  steps are skipped only at the same commit).
- [ ] **Step 4: Commit** the runner and the logs: `ua-soroban T12: Soroban UA-Soroban gate runner, logs`.

### Task T13: whole-branch review and fix wave

- [ ] **Step 1:** Dispatch one reviewer (superpowers:requesting-code-review; Claude, not Codex — Codex only on the
  owner's request) over `git diff main...ua-soroban`, with the spec, this plan and the Review Focus list; two parts if
  the diff is large (contracts; node + clients + docs).
- [ ] **Step 2:** Fix every Critical / Important finding in the owning files (commits `UA-Soroban fix: …`); record each
  disposition (fixed / ruled with reason) in `.superpowers/sdd/2026-10-30-ua-soroban/final-review.md`; a finding that
  changes a §0 row goes to the controller for the owner, not into code.
- [ ] **Step 3:** Re-run the gate runner (it re-runs only what changed commit); every step `rc=0`; commit the logs
  `ua-soroban T13: review fixes, gate logs`.
- [ ] **Step 4:** Report to the controller: commits, the T0 figures and limits, the largest `msig`, findings and
  dispositions; ask for the owner's go to merge (push only on the owner's word).

### Task T14: Stellar testnet e2e — the round's last step, only after 2026-11-03 (S5, S17; C16b; SOR-D17)

Runs after Part B's B9 and Part Z's Z10, before B10, on the branch named in SOR-D17.

- [ ] **Step 1: SDK swap (C16b):** `soroban-sdk = "=30.0.0"` (and `soroban-ledger-snapshot`) in the workspace and the
  spike; `cargo update`; the gate steps `soroban`, `soroban-spike-local`, `e2e-soroban-local` (and Part B's / Part Z's
  Soroban steps) at the new commit — PASS. If 30.0.0 is not released, stop and leave T14 open in `TODO.md`.
- [ ] **Step 2: Precondition:** today ≥ 2026-11-03 and the testnet RPC's `getNetwork` reports `protocolVersion == 30`
  (read, never assumed; re-check the vote dates of the spec's sources). Otherwise stop and leave T14 open.
- [ ] **Step 3:** Lanes funded by the testnet friendbot; then
  `STELLAR_URL=<testnet rpc> STELLAR_PASSPHRASE='Test SDF Network ; September 2015' STELLAR_FRIENDBOT=https://friendbot.stellar.org scripts/capped sh -c 'cd scaas-node && cargo test -j2 --test e2e_soroban_ua -- --ignored --test-threads=1 --nocapture'`
  (plus Part Z's `e2e_soroban_zether` when Part Z is merged) — PASS.
- [ ] **Step 4:** Log `smartcontracts/soroban/runs/<run-date>-ua-soroban-e2e-testnet.txt` (ledgers, contract ids, CPU, fees,
  the network settings of the day); add the testnet figures to NET-SOR-24; docs check — 0 errors.
- [ ] **Step 5: Commit** `ua-soroban T14: soroban-sdk 30.0.0, Stellar testnet e2e (Protocol 30)`; report to the controller;
  B10 follows.

---

# Part Z — classical Zether on Soroban (branch `zether-soroban`; spec S13a)

**Starts only when** `ua-soroban` is merged into `main` (owner's go). Branch `zether-soroban`, worktree
`.claude/worktrees/zether-soroban`. Classical Zether is ported; **PQZ stays out** (S13b) and is never mentioned as part
of this track. Source of truth for the protocol: `docs/contracts/zether.md` (CTR-ZTH-*), the EVM sources
`smartcontracts/evm/src/zether/` and `clients/zether-prover` (one prover, two verifiers).

**Part Z decisions (controller proposals, owner may override; recorded in full by Z8 under NET-SOR-25):**

| # | Decision | Choice and why |
|---|---|---|
| ZS-D1 | Verifier placement | A stand-alone stateless contract `smartcontracts/soroban/contracts/zether-verifier/` (`verify_transfer`, `verify_transfer_multi`, `verify_burn`, `verify_range` and the disclosure views), as EVM's separate verifier: the token stays under the network's Wasm size limit (read at T0) and calls it synchronously; immutable, no admin. |
| ZS-D2 | Token placement | The Zether layer lives in the `token` crate (`src/zether.rs`), switched on per deployment: constructor argument `zether: Option<ZetherCfg>`; `Some` with `underlying = None` is the `NormalZetherToken` kind, with `Some(underlying)` the `WrappedZetherToken` kind (SEP-41 underlying, SAC included); `None` is the plain token. One token crate keeps one UA ledger implementation. |
| ZS-D3 | Points and proof bytes | Proof, payload and statement bytes are byte-identical to `zether-prover`'s BLS12-381 form (`P` = 128 B, the EIP-2537 encoding of zether.md §3); the verifier converts each point to the host's 96 B uncompressed form, checks subgroup membership, and absorbs the 128 B form in the transcript. |
| ZS-D4 | Statement header on Soroban | zether.md §7 header with: word 2 `chainId` = 0, word 3 `chainUid` = the network id (`sha256(passphrase)`), word 4 the token's 32-byte contract id (EVM: 12 zero bytes ‖ address); `zether-prover`'s header carries word 4 as 32 bytes (EVM bytes unchanged). `bindingTag` = `ZTX_V1_DIRECT` and `envelopeBinding` = 0 (the proof alone authorises, UA-6), except `unshield_unwrap`'s `unwrapBinding(u, minOut)`. |
| ZS-D5 | Generators | The NUMS generators compiled into the verifier, checked byte-for-byte against `smartcontracts/evm/test/vectors/zether/generators_bls12381.json` by a test. |
| ZS-D6 | Entries | `shield(from: Address, to_ua, amount)` (host auth), `ua_shield(from: BytesN<32>, to_ua, amount, lane, nonce, valid_until, relayer, auth)`, `confidential_transfer(payload, proof, beneficiary)` (multi, `M ≥ 1`, CTR-ZTH-37) and `confidential_transfer_single(payload, proof, beneficiary)`, `unshield(payload, proof, beneficiary, amount, recipient: Holder)`, `wrap_shield(amount_in, to_ua)` / `unshield_unwrap(payload, proof, beneficiary, unwrap: Unwrap)` (Wrapped kind), `roll_over(ua, n)`, `roll_over_batch(uas)`, `roll_over_signed(ua, …, auth)`, `set_roll_over_mode(ua, mode, …, auth)`; the EVM `…Compact` (commit-reveal calldata) forms are not ported unless Z0's transaction-size figure needs them (then a recorded cut, owner informed). |
| ZS-D7 | State | Per-UA ElGamal `acc` / `pending` (C, D), `accSeq`, `sendCounter`, `pendingSeq`, `rollOverMode`, `totalShielded`, transfer entries and bundles: persistent entries, one per key, TTL as S11; a restore is the relayer's (S12); never temporary, never only a hash (never-lose rule). |
| ZS-D8 | Zether UAs | Kind 0x0141 `zether-bls12381` is enabled in `ua-registry` with the token (Schnorr PoP over BLS12-381 G1, `schnorr_bls12381.json` / `portable.json` row); `receivable(ua) = false` for it (a Zether UA never holds a public UA-ledger balance, EVM T-V3-3b); owner operations use `require_authorized` under `zether-owner` / `zether-auth`. No deployed registry exists before the round's testnet step, so this is a code change, not a new generation. If Part B merged first, its `checked` table row for 0x0141 changes from `Relayer` to `Chain` in the same commit. |
| ZS-D9 | Node jobs | Zether proof entries and `ua_shield` are `ua_metatx` jobs (allow-list extended; the proof or the UA signature authorises; no subject auth entry); native `shield` is a `signed_op` host-auth job; `op_consumed`: `accSeq` / `sendCounter` past the proved values. |

### Task Z0: Zether verifier on Soroban — HARD GATE (S13a "measure first")

**Files:**
- Create: `contracts/zether-verifier/{Cargo.toml,src/lib.rs,src/curve.rs,src/transcript.rs,src/sigma.rs,src/bulletproofs.rs,src/test.rs}`;
  `smartcontracts/soroban/spike/zether.sh` (quickstart measurement of the deployed verifier, reusing `measure.py`);
  `smartcontracts/soroban/runs/<run-date>-zether-z0.txt`

**Interfaces:**
- Produces: `verify_transfer(statement: Bytes, proof: Bytes) -> bool`, `verify_transfer_multi(statement: Bytes, proof: Bytes) -> bool`,
  `verify_burn(statement: Bytes, proof: Bytes) -> bool`, `proof_system_id() -> BytesN<32>`, `proof_system_id_multi()`,
  `generators() -> Bytes` — the port of `ZetherVerifier.sol` (Σ-protocol E1–E8, two `BP(64)` with the inner-product
  argument folded into one `g1_msm`, the multi-recipient form), on the CAP-59 host functions (`g1_add`, `g1_mul`,
  `g1_msm`, `fr_*`), transcript per zether.md §5 with the host keccak.

- [ ] **Step 1: Failing tests:** `zether_generators_match_evm`, `zether_transcript_matches_vectors`
  (`transcript_s3.json`), `zether_transfer_vectors_verify` / `zether_transfer_negatives_fail` (the `zether-prover`
  BLS12-381 transfer vectors and their mutated proofs), `zether_multi_vectors_verify` (M = 1, 2, the EVM maximum),
  `zether_burn_vectors_verify` (`burn_bls12381.json`), `zether_point_checks_refuse_invalid` (off-curve, not in the
  subgroup, non-canonical encodings of zether.md §3).
- [ ] **Step 2:** `cd smartcontracts/soroban && ../../scripts/capped cargo test -j2 -p scaas-zether-verifier` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** Step 2's command — PASS; then `CAPPED_SLOTS=1 smartcontracts/soroban/spike/zether.sh | tee smartcontracts/soroban/runs/<run-date>-zether-z0.txt`
  (quickstart up / down as T0): simulate `verify_transfer` (auditor off and on), `verify_transfer_multi` (M = 1, 2, 4,
  the EVM maximum) and `verify_burn` on real proofs; log instructions, memory, transaction size, Wasm size against the
  network settings. **Gate:** a single-recipient transfer, a burn and a 2-recipient transfer fit ⇒ continue (the largest
  fitting M is recorded and becomes the Soroban maximum). Otherwise ⇒ **STOP**: commit, report to the controller for
  the owner with the spec's options (split the verification over transactions, a smaller range, Groth16 over a
  Zether-like circuit, wait for cheaper host functions); no token code until the owner rules.
- [ ] **Step 5: Commit** `zether-soroban Z0: Zether verifier on CAP-59, quickstart measurement`.

### Task Z1: `zether-prover` Soroban header and shared vectors (ZS-D4)

**Files:**
- Modify: `clients/zether-prover/src/{zether.rs,api.rs,vectors.rs}`, `clients/zether-prover/tests/{vectors.rs,zether_proofs.rs}`
- Create: `smartcontracts/vectors/zether/soroban/{transfer_bls12381.json,burn_bls12381.json,disclosure_bls12381.json}`
  (written by the crate's generator; `--check` in tests)

**Interfaces:**
- Produces: header `token: [u8; 32]` (EVM callers pass `12 zero ‖ address`; EVM vectors unchanged byte for byte);
  `Header::soroban(network_id: [u8; 32], contract: [u8; 32], …)`; the wasm API takes `family: "evm" | "soroban"`.

- [ ] **Step 1: Failing tests:** `soroban_header_layout` (words 2–4 per ZS-D4), `soroban_vectors_reproduced`,
  `evm_vectors_unchanged` (the existing vector files reproduced byte for byte).
- [ ] **Step 2:** `cd clients/zether-prover && ../../scripts/capped cargo test -j2` — FAIL.
- [ ] **Step 3: Implement**; regenerate with `zether-cli vectors <dir>`.
- [ ] **Step 4:** Step 2's command, the wasm smoke and `zether-cross` (base runner steps `wasm-zether-prover`,
  `zether-cross`) — PASS; Z0's verifier tests also verify the Soroban vectors (`zether_soroban_vectors_verify`).
- [ ] **Step 5: Commit** `zether-soroban Z1: zether-prover Soroban header, shared Soroban vectors`.

### Task Z2: kind 0x0141 on the Soroban registry (ZS-D8)

**Files:**
- Modify: `contracts/ua-registry/src/{verify.rs,lib.rs,test.rs,test_verify.rs}`, `contracts/token/src/test_ua.rs`

- [ ] **Step 1: Failing tests:** `kind_zether_bls12381_vectors_verify` / `kind_zether_bls12381_negatives_fail`
  (`signatures.json` `zether-bls12381`), `register_zether_from_portable_json`, `zether_ua_not_receivable_on_ua_ledger`
  (registry `receivable = false`; token `transfer_to_ua` ⇒ `UaNotReceivable`), `require_authorized_zether_owner`;
  `register_disabled_kind_refused` loses its 0x0141 case.
- [ ] **Step 2:** `cd smartcontracts/soroban && ../../scripts/capped cargo test -j2 -p scaas-ua-registry -p scaas-token` — FAIL.
- [ ] **Step 3: Implement**; `check-registry-interface.sh` unchanged (no new function).
- [ ] **Step 4:** `CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh soroban` — PASS.
- [ ] **Step 5: Commit** `zether-soroban Z2: zether-bls12381 (0x0141) enabled on the Soroban registry`.

### Task Z3: Zether layer state, shield, roll-over (ZS-D2, ZS-D6, ZS-D7)

**Files:**
- Create: `contracts/token/src/zether.rs`, `contracts/token/src/test_zether.rs`
- Modify: `contracts/token/src/lib.rs` (constructor `zether: Option<ZetherCfg>`), constructor call sites

**Interfaces:**
- Produces: `#[contracttype] pub struct ZetherCfg { verifier: Address, auditor_key: Bytes, auditor_mode: u32, disclosure_mode: u32,
  shield_scale: i128, max_decryptable_shielded: u64, confidential_fee: u64, min_decoy_fee: u64, underlying: Option<Address> }`
  (immutable; the EVM `initialize` checks: `max ≤ 2^54`, `fee < 2^64` and `< max`); `shield`, `ua_shield`,
  `roll_over`, `roll_over_batch`; views `account_state(ua)`, `total_shielded()`, `zether_cfg()`; events `Shielded`,
  `RolledOver` (zether.md CTR-ZTH-45 shapes, ids as `BytesN<32>`); `Y` read from the registry record of the 0x0141 UA.

- [ ] **Step 1: Failing tests:** `zether_shield_native_and_ua`, `zether_roll_over_public_mode`,
  `zether_total_shielded_cap`, `zether_ciphertexts_in_persistent_state` (every ciphertext entry persistent with TTL;
  after archival the next use restores it, never reads it as absent), `zether_plain_token_has_no_layer`.
- [ ] **Step 2:** `cd smartcontracts/soroban && ../../scripts/capped cargo test -j2 -p scaas-token zether` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** `CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh soroban` — PASS; release Wasm of the
  token within the network's Wasm size limit (logged).
- [ ] **Step 5: Commit** `zether-soroban Z3: Zether layer state, shield, roll-over`.

### Task Z4: confidential transfers (CTR-ZTH-37/-38; auditor; beneficiary fee)

**Files:**
- Modify: `contracts/token/src/{zether.rs,test_zether.rs}`

- [ ] **Step 1: Failing tests** (proofs from `smartcontracts/vectors/zether/soroban/`): `zether_transfer_single_from_prover`,
  `zether_transfer_multi_with_decoys`, `zether_transfer_auditor_legs` (each mode of `auditor_mode`),
  `zether_transfer_replay_refused` (stale `accSeq` / `sendCounter`), `zether_transfer_expired_refused`,
  `zether_beneficiary_fee_public_units` (fee to the beneficiary's UA-ledger balance from the shield pool),
  `zether_transfer_entry_stored` (bundles per `entryRef`, `disclosure_mode`).
- [ ] **Step 2:** `cd smartcontracts/soroban && ../../scripts/capped cargo test -j2 -p scaas-token zether` — FAIL.
- [ ] **Step 3: Implement** (the token builds the statement from state + payload per zether.md §7 with ZS-D4).
- [ ] **Step 4:** `CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh soroban` — PASS.
- [ ] **Step 5: Commit** `zether-soroban Z4: confidential transfers (single, multi, auditor, fee)`.

### Task Z5: unshield, Wrapped kind, roll-over modes, disclosure

**Files:**
- Modify: `contracts/token/src/{zether.rs,test_zether.rs}`, `contracts/zether-verifier/src/{lib.rs,test.rs}`

**Interfaces:**
- Produces: `unshield` (recipient `Holder`: native or a receivable UA, CTR-ZTH-51), `wrap_shield`, `unshield_unwrap`
  (SEP-41 underlying, `shield_scale` rounding as CTR-ZTH-04 / CTR-ZTH-35), `roll_over_signed`, `set_roll_over_mode`
  (`PUBLIC` / `OWNER_ONLY`, `require_authorized` under `zether-owner`), verifier views
  `verify_transfer_amount(token, entry_ref, index, opening_kind, opening) -> bool`, `transfer_ciphertext(token, entry_ref, index)`
  (the three openings `SENDER_S`, `RECEIVER_X`, `AUDITOR`, plus `SENDER_CP` where EVM has it).

- [ ] **Step 1: Failing tests:** `zether_unshield_to_native_and_ua`, `zether_wrapped_shield_unshield_unwrap`,
  `zether_burn_proof_refused_on_bad_amount`, `zether_owner_only_roll_over_signed`,
  `zether_set_roll_over_mode_authorized`, `zether_disclosure_openings` (`disclosure_bls12381.json` Soroban rows),
  `zether_transfer_ciphertext_view`.
- [ ] **Step 2:** `cd smartcontracts/soroban && ../../scripts/capped cargo test -j2 -p scaas-token -p scaas-zether-verifier zether` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** `CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh soroban` — PASS.
- [ ] **Step 5: Commit** `zether-soroban Z5: unshield, Wrapped kind, roll-over modes, disclosure`.

### Task Z6: node — Zether jobs (ZS-D9)

**Files:**
- Modify: `scaas-node/src/adapters/soroban.rs`

- [ ] **Step 1: Failing tests:** `zether_jobs_allowlist` (each Zether entry on a configured Zether token; on a plain
  token refused), `op_consumed_zether_acc_seq`, `decode_zether_events`.
- [ ] **Step 2:** `cd scaas-node && ../scripts/capped cargo test -j2 adapters::soroban` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** `cd scaas-node && ../scripts/capped sh -c 'cargo clippy -j2 --all-targets -- -D warnings && cargo test -j2'` — PASS.
- [ ] **Step 5: Commit** `zether-soroban Z6: node Zether jobs on Soroban`.

### Task Z7: local e2e

**Files:**
- Create: `scaas-node/tests/e2e_soroban_zether.rs` (`#[ignore]`); Modify: `smartcontracts/soroban/scripts/e2e-local.sh`
  (runs it too), `smartcontracts/soroban/runs/<run-date>-zether-e2e-local.txt`

- [ ] **Step 1: Failing test:** `e2e_soroban_zether_lifecycle` (register two 0x0141 UAs; shield; a 2-recipient transfer
  with a decoy proved by `zether-cli` at run time; roll-over; unshield to a native address; one disclosure opening
  checked by the view; logs CPU and fees per step).
- [ ] **Step 2:** `smartcontracts/soroban/scripts/e2e-local.sh` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** Step 2's command (tee the log) — PASS.
- [ ] **Step 5: Commit** `zether-soroban Z7: local Protocol 30 Zether e2e`.

### Task Z8: docs, decisions, TODO

**Files:**
- Modify: `docs/networks/soroban.md` (NET-SOR-25 rewritten as BUILT: entries, limits, the Soroban maximum M, figures;
  §9 "Confidential payments" line), `docs/contracts/zether.md` (CTR-ZTH-01 "Non-EVM families": Soroban built; §19 a
  Soroban figures table from Z0 / Z7; §22 Soroban row), `docs/contracts/accounts.md` (0x0141 on Soroban),
  `docs/node/job-api.md` (Zether `ua_metatx` functions), `docs/decisions.md` (NET-SOR-25 with S13a in full — owner
  2026-10-30 in scope, the port design as controller proposal — and ZS-D1–D9 in full), `TODO.md`.
- [ ] **Step 1:** Write every change.
- [ ] **Step 2:** `python3 scripts/test_docs_check.py && python3 -I scripts/docs_check.py check` — 0 errors.
- [ ] **Step 3: Commit** `zether-soroban Z8: docs (NET-SOR-25 built, zether.md Soroban, decisions ZS-D1..D9)`.

### Task Z9: gate runner

**Files:**
- Create: `smartcontracts/evm/runs/<date>-zether-soroban-gates.sh` (as T12: `P=<date>-zether-soroban`), sourcing the base runner
- Modify: the base runner's `run_step` only if a new command is needed (`zether-verify-local) CAPPED_SLOTS=1 smartcontracts/soroban/spike/zether.sh ;;`)

**Interfaces:**
- Produces: `STEPS="docs soroban cargo-zether-prover wasm-zether-prover zether-cross clientkeys cargo-scaas-node zether-verify-local e2e-soroban-local named-tests"`,
  `FAMILIES="soroban cargo-zether-prover zether-verify-local e2e-soroban-local"`, `NEW_TESTS` = every Z0–Z7 name (and
  the UA-Soroban names, which re-run at the new commit).

- [ ] **Step 1:** Write the runner and the names.
- [ ] **Step 2:** Guard self-check as T12 Step 2 (one Z name removed).
- [ ] **Step 3:** Run (no other gate runner, no other quickstart) — every step `rc=0`.
- [ ] **Step 4: Commit** `zether-soroban Z9: gate runner, logs`.

### Task Z10: whole-branch review and fix wave

- [ ] As T13 over `git diff main...zether-soroban`, focus: the ported verification equations (each E1–E8 and the
  Bulletproof checks against `ZetherVerifier.sol`), point checks, the never-lose rule, the statement header, the
  disclosure openings. Fixes `zether-soroban fix: …`; gate re-run; commit
  `zether-soroban Z10: review fixes, gate logs`; report to the controller (Z0 figures, Soroban maximum M, findings); ask
  for the owner's go. T14 then runs the round's testnet step for UA-Soroban, Part B and Part Z.

---

## Findings in the spec (reported, not changed)

- **F1 — `Pop` cannot be returned for host-verified kinds.** The host's `ed25519_verify`, `secp256r1_verify` and
  `ml_dsa_{44,65}_verify` panic on a bad signature, so `register` fails with a host error, not the contract error
  `Pop`, for those kinds. Resolution applied: tests assert "refused" (`is_err()`) for host-checked parts and the exact
  `Pop` only for contract-checked ones (secp256k1 recovery compare, WebAuthn grammar, `msig` weight).
- **F2 — "the NET-SOR-16 renames apply" only for the mandate.** Spec §5.2 applies them to the mandate; §5.1 / §5.3 keep
  the token's `pay` and the DEX's `settle` / `cancel`. Resolution: SOR-D9 (mandate renamed, token and DEX not).
- **F3 — `ua_cancel` purpose unstated** (§5.3). Resolution: SOR-D10.
- **F4 — `RelayFeePaid.payee`.** §5.4 makes `payer` a `Holder`, but a bound `ua_relay` payee may be a UA. Resolution:
  SOR-D11 (both `Holder`).
- **F5 — spec §10 task numbers.** C16b names the testnet task "UA-Soroban T12"; with the vectors moved before the token and the
  local e2e / review added, it is T14 here (SOR-D2, SOR-D17).
- **F6 — a "real proof verified" in T0 needs the verifier.** A real `zether-prover` proof cannot be verified before the
  verifier is ported, so UA-Soroban T0 measures the CAP-59 primitives at the verifier's sizes (an early estimate) and Part Z's
  Z0 verifies real proofs on the quickstart as the S13a HARD GATE, before any Zether token code.
- **F7 — 0x0141 and Part B's `checked` table.** UA8-D20 marks every kind UA-Soroban does not verify as `Relayer`; once Z2
  enables 0x0141 it is `Chain`. Resolution: ZS-D8 (Z2 updates that row if Part B merged first).
- **F8 — the spec's statement header for Soroban.** zether.md §7's `chainId` / `chainUid` / 20-byte token word have no
  Soroban meaning; ZS-D4 fixes the Soroban values and widens the prover's token word to 32 bytes (EVM bytes unchanged).
