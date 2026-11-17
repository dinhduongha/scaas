# Spec: ML-DSA on the EVM, precompile or expanded-key cache

2026-11-15. Status: the contract sections (MD-1 .. MD-13, MD-15) **BUILT** on branch `3zh-mldsa` (`ba98edc41`, merged
into `ua-mtx-merge` `0df1aea32`); MD-14 (the node job and the client builders) **BUILT** in the `ua-rs-sign`
port round (the node's lane `2064e707d`, `clientkeys` `bd23168d7`, `ua-rs` `97b96e967`; NODE-JOB-29). The measured figures below come from that build (forge 1.8.5, Amsterdam, `isolate`, regular =
`lastCallGas` × 64/63; MD-13's re-measured in 3zh-core group 2), the rest is marked [estimate]. Everything cryptographic is **UNAUDITED**. Rule ids here are local
(`MD-n`); the build round turns them into Changes of CTR-UA-23 / CTR-UA-39 and NET-EVM-06 / -11 and a `decisions.md`
entry with §0 verbatim. **Scope: EVM.** A grep of every other family (soroban, solana, near, algorand, move, ton, cosmos)
and of `scaas-node/src` finds no 66 % rule and no ML-DSA cap (ML-DSA appears only in Soroban's `spike/` and `runs/`):
no other family changes in this round; the EVM node and clients are SPECIFIED here (MD-14) and built in the `ua-rs-sign`
port round; a family that gets ML-DSA takes the same rules in its own round. TODO item 3zh.

## 0. Owner rulings this spec implements (2026-11-15)

1. "Có thể tạm không phụ thuộc Hedera. Nâng rule lên 70%, hoặc giá trị nào đó khớp." then "1. OK" to **75 %** (MD-1).
2. "Xác định đi theo 2 đường: có precompiler; không precompiler thì phải có cache cho mldsa65 và 87 … đăng ký cache trước,
   register sau? Register mà thiếu cache là revert." (MD-2, MD-3); extended to mldsa44 (its uncached verify is over the
   75 % rule too).
3. mldsa87 cache: "Cần tính cho sau Glamsterdam (vì còn giới hạn 64 k code), 2 part có được không?", then, on MD-5's
   60 M-block finding, "MD-5: Chia 3 part?": **3 parts** (MD-4). mldsa65: "Cân nhắc mldsa65 dùng 1 part" then kept at 2 parts (3 % margin at 1 part) (MD-4).
4. "Thế forge không cần bật trần nữa": forge's `enable_tx_gas_limit` stays off; explicit asserts instead (MD-9).
5. `verifyCached` trusts its pointers: "Ghi docs." (documented, not restricted in code) (MD-10).
6. "Ok, dùng pre-compiler cho 0x0131"; then option B: "Theo tôi thì option cho mldsa trên scaas testnet: dùng
   precompiler hoặc không, để còn biết so với các mạng khác." "Ok, theo B" (MD-6, MD-7, MD-8).
7. On the Fable review (2026-11-15): "Còn lại như đề xuất", then "F-3: như đề xuất." — F-1: the PQZ debit bound for every
   holder kind (MD-13); F-3: the contracts in this round, the node job and the client builders SPECIFIED here and built in
   the `ua-rs-sign` port round after 3zh (MD-14); F-7: a probe call that fails
   refuses the deploy by name (MD-15); the other findings as proposed (§7).
8. "Dời baseline": `UARegistryCoreLib`'s size baseline moves with this round's reason (MD-12). "Giữ như hiện tại" on the
   funds-before-register question: the build round answers it (§6).
9. Order: this round first, pushed and merged into `ua-mtx-merge` (PR #18 carries it, "Đi chung"), then the pqz-core
   batch (3zh-core).

## 1. The finding

Reset 4b's matrix (`verifiers` group): `MldsaVerifier(0x0131)` without a precompile ran out of gas on the SCaaS testnet.
Cause: EIP-7825's per-transaction cap 2^24 = 16,777,216. The testnet chainspec has `eip7825TransitionTimestamp` 0 and
`eip8037` / `eip8038` from block 1, so after Glamsterdam the cap is on the **regular** gas only (state gas has its own
reservoir, `tx.gas` ≤ 2^32 − 1). Nethermind applies it in `eth_call` / `eth_estimateGas` too and stops at exactly
16,777,216; a step-by-step trace against anvil is identical up to there. forge / anvil 1.8.5 do not enforce the cap
(`--enable-tx-gas-limit`, off by default), so forge-measured paths over 2^24 passed every test.

| (forge, regular) | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| verify on the FIPS 204 key (uncached) | 11,632,672 | **19,299,937** | **32,553,838** |
| `verifyCached` as its own tx | 4,229,724 | 5,973,470 | 8,853,751 |
| least working `verifyCached` gas, cold (± 1,000) | 4,180,987 | 5,903,432 | 8,760,705 |
| cache part 0 tx: regular / state | 8,768,943 / 31.7 M | 6,593,505 / 23.8 M | 2-part WIP, superseded by MD-4: 15,243,544 / 55.1 M |
| cache part 1 tx: regular / state | — | 9,225,118 / 33.3 M | 2-part WIP, superseded: 12,705,179 / 45.8 M |
| `register` after the cache | 4,417,802 | 6,183,329 | 9,084,605 |

The registry already calls a verifier with the kind's cap as its gas (`_verifierCall`, `UARegistry.sol`), which is the
cached cap without a precompile: the uncached fallback fails closed for every ML-DSA kind today (as a generic PoP false).

## 2. Rules

**MD-1 (CTR-UA-23 Change).** A PQ kind is enabled on a chain only if its measured cap ≤ **75 %** of the chain's
`UA_VERIFY_BUDGET = min(12,000,000, ⌊0.7 × per-tx gas cap⌋)`: `DeployBase._pqKindFits`, integer-exact
`cap * 100 <= budget * 75` (12 M: 9,000,000; Hedera 10.5 M: 7,875,000). Was 66 % (ruling 2026-10-31). One rule, per chain
budget, no chain named: mldsa87's cached cap (MD-4) is enabled at 12 M and off at Hedera's budget by the rule itself. A
check holds `cap + cap/63 + margin` (`UAStore.sol`): at a 9.0 M cap 7.63 M of 2^24 remain for the operation, at 8.8 M 7.84 M;
that is not sufficient for every operation by itself: MD-13.

**MD-2 (two paths).** An ML-DSA kind (0x0130 mldsa44, 0x0131 mldsa65, 0x0134 mldsa87) verifies through exactly one of: (a) the
chain's EIP-8355-layout precompile, chosen by the `MldsaVerifier` constructor's probe (exact word 1 on the valid KAT input,
exact 0 on the flipped one), or (b) without a precompile, the registry's expanded-key cache (`verifyCached`). The uncached
FIPS-key verify is never a registry path. `MldsaVerifier.verify` stays (the precompile path, outside callers).

**MD-3 (cache before register).** Without a precompile, every check of an ML-DSA kind's signature — the registration PoP
included — needs the kind's full cache under the UA id: `cacheExpandedKey(kind, pk, part)` for every part (open to anyone,
one transaction per part, idempotent, derived on-chain from `pk` by `MldsaVerifier.expandedKeyPart`, never from a caller),
then `register`. A check with an incomplete cache reverts **`UAKeyNotCached(bytes32 ua)`** (new; in `_sigOk`, when the
verifier's `PRECOMPILE()` is 0). With a precompile, `cacheExpandedKey` stays refused (no second path on one chain).

**MD-4 (parts).** `expandedKeyParts()`: mldsa44 1 (20,544 B), mldsa65 2 (rows 0–2 | rows 3–5 ‖ tr ‖ t̂1; 15,360 / 21,568 B;
kept, a single part would be 15.47 M regular, × 1.05 = 16.25 M: 3 % margin), **mldsa87 3: rows 0–2 | rows 3–5 | rows 6–7 ‖ tr ‖
t̂1 (21,504 / 21,504 / 22,592 B)**, each one SSTORE2 blob, each under EIP-170's 24,576 B (research note
`mldsa87-evm-gas.md`: regular ≈ 9.03 / 9.03 / 9.52 M, state 33.2 / 33.2 / 34.8 M [estimate until re-measured]; so every
part's total × 1.05 ≈ 44–47 M fits a 60 M block, where a 2-part split's part 0 (≈ 70.4 M total) does not). Storage:
`UAStore.ekPtr` goes from `mapping(bytes32 => address[2])` to `address[3]`: a mapping value's array keeps slots base+0 and
base+1 where they are and adds base+2, so no existing slot moves; the registry's layout pin `test/ua/UAStoreLayout.t.sol` gains `ekPtr[u][2]` at base + 2 (the
existing pins stay true) with this reason (nothing deployed holds value; a new deploy, nothing upgraded). mldsa87's
verifier is constructible without a precompile (`UAMldsaNoPrecompile` retired; the old file kept under `legacy/`).

**MD-5 (a kind is enabled only where its cache fits) — derived from CTR-UA-23 "never registrable but unusable"; owner to
confirm.** Without a precompile, `DeployBase` enables an ML-DSA kind only if (i) its cap passes MD-1 and (ii) every cache
part transaction fits the chain: regular × 1.05 < 2^24 (EIP-7825) **and** (regular + state) × 1.05 ≤ the chain's block gas
limit (EIP-8037 inclusion, NET-EVM-06's rule), from the measured figures. With MD-4's parts every ML-DSA cache part is ≈ 40–45 M total
(× 1.05 ≤ ≈ 47 M), so all three kinds fit a 60 M block (the measured 2-part mldsa87 part 0, 15.24 M regular + 55.1 M state,
needed ≈ 74 M and was the reason for 3 parts); the gate still matters on a chain with a smaller block. A chain whose block cannot hold a part gets the kind disabled
(verifier 0), never a kind whose keys cannot be cached.

**MD-6 (`MLDSA_PRECOMPILE=on|off`, a deploy flag; no codegen).** `on` (default): each ML-DSA kind uses the precompile where
the chain's probe passes, else the cache (on a chain without a precompile `on` deploys what `off` deploys). `off`: every
ML-DSA kind uses the cache (pure Solidity), as a chain without a precompile; any `MLDSA44/65/87_VERIFIER` env is refused by
name. Precompile candidates by probe, never by assumption: `0x12` / `0x13` / `0x14`, then the SCaaS testnet's
`0x…5caa0012` / `13` / `14`. The deploy JSON records `mldsa44/65/87_verifier` and `mldsa_precompile`.

**MD-7 (the precompile verifiers on the real chain).** forge's EVM has no ML-DSA precompile, so a precompile-backed
`MldsaVerifier` cannot be built inside `Deploy.s.sol`'s simulation. `script/pq_verifiers.py` (deploy.sh evm's first step,
CREATE2 with `DEPLOY_SALT`) deploys **0x0130, 0x0131 and 0x0134** on the chain where each probe passes (it already does
0x0134 and `PqzKeyVerifier` 0x0142); `DeployBase` takes them by env `MLDSA44_VERIFIER` / `MLDSA65_VERIFIER` /
`MLDSA87_VERIFIER` and checks `KIND()` and `PRECOMPILE() != 0` as it does for 0x0134 today. With `on`, a chain whose own probe
passes but no precompile verifier was handed in refuses by name. Each release passes the release gas gate of the declared
`RELEASE_GAS_GATE` (2d571593b).

**MD-8 (matrix).** `verifiers` asks every ML-DSA kind through the registry's path on that deploy (cached without a precompile;
never the uncached FIPS-key verify for 65 / 87). A new PQ group (`mldsaalt`) deploys a throwaway registry with `DeployBase` in
the **opposite** `MLDSA_PRECOMPILE` mode and runs the same cases: cache parts, register, verify, the `UAKeyNotCached`
refusal with no cache and with one part missing. One matrix run thus measures precompile against cache on the same chain
under Nethermind's real cap. Compiled under `scripts/capped` with `forge build src <script>`; in `coverage.py`. On anvil (no
precompile) the precompile side is skipped by name.

**MD-9 (gas asserts, forge cap off).** forge's `enable_tx_gas_limit` stays off (it caps the whole test function). Tests
assert, for 44 / 65 / 87: every cache part transaction regular × 1.05 < 2^24, `verifyCached` and `register` likewise; the
uncached FIPS-key verify of 65 and 87 **over** 2^24 (pinned as a fact); total gas per part within the block-limit figure of
MD-5.

**MD-10 (`verifyCached` trusts its pointers).** Documented, not restricted in code: `verifyCached` is `external` and reads
whatever pointers it is given; only the registry, which wrote the parts itself from an authenticated `pk`, may rely on its
verdict. An integrator calling it directly gets a meaningless verdict.

**MD-13 (the PQZ debit bound for every holder kind; F-1, owner 2026-11-15).** `_pqzHolder` today bounds the debit of an
`msig` PQZ holder only. It applies to **every** holder kind, with the kind's own cap as `w` (single keys: `cfg >> 160`):
`register` / `setPqzKey` refuses `UAPqzHolder` where `w + w/63 + margin + PQZ_DEBIT_MIN_GAS + calldata > 2^24`, so a kind
that can receive PQZ credits can always spend them. Arithmetic at cap 8.8 M: 16.24 / 16.46 / 16.67 / 16.91 M at the four sets
(`PQZ_DEBIT_MIN_GAS` 7.30 / 7.52 / 7.73 / 7.97 M): a cached mldsa87 is a signing kind everywhere but **not a PQZ holder at
n2816-kmax65536** (and within 0.6 % at n2560): stated in CTR-UA-16 / CTR-PQZ-12. Measured as built (3zh-mldsa, `DeployBase`'s
cap 8,850,000, `test_register_cachedHolders_thisSet`): 16,372,788 / 16,588,788 / 16,801,788 / 17,042,788, a holder at n2048 and
n2304 only. **Re-measured 3zh-core group 2 (2026-11-15)**, `PQZ_DEBIT_MIN_GAS` 7,364,000 / 6,074,000 / 7,793,000 / 8,033,000
(ML-DSA-65 at 100,006; n2304 at its calibrated rows): the bound 16,436,788 / **15,146,788** / 16,865,788 / 17,105,788, the
largest single mldsa87 cap that fits 9,185,109 / 10,454,953 / 8,762,812 / 8,526,562 (`test_register_singleHolderBoundary_mldsa87`);
the 44 / 65 cached caps 11.73 / 13.47 M at n2048 … 12.40 / 14.14 M at n2816. **What fits per single kind is unchanged**: a
cached mldsa87 is a PQZ holder at n2048-kmax1024 and n2304-kmax4096, not at n2560-kmax16384 / n2816-kmax65536. **One `msig`
verdict changes at n2304-kmax4096**: the room for a holder's worst authorization grows from ≈ 9.26 M to ≈ 10.70 M, so
`{fndsa512 × 4}, t = 4` (≈ 10.2 M) now fits there. Owner 2026-11-15 ("Ok, theo đề xuất"): the rule stays; the negative
`test_register_msigHolderOverBound` takes a holder over the bound at every set (2-of-2 `fndsa1024` at 5,250,000: bound
18,255,960 / 16,965,960 / 18,684,960 / 18,924,960, beside `{fndsa512 × 4, slhdsa128s}, t = 5`), its `UAPqzHolder` assertion
unchanged; the new `test_register_msigHolder_fndsa512x4_perSet` states the per-set boundary: a PQZ holder at n2304-kmax4096,
`UAPqzHolder` at the three other sets. Tests per set: the cheapest debit and a
`ROLL_MAX` rollover with a cached mldsa87 holder and a cached ML-DSA fee signer, measured; the refusal where it does not fit.

**MD-14 (who sends the cache parts; F-3, owner "như đề xuất") — BUILT in the `ua-rs-sign` port round after 3zh
([NODE-JOB-29](../../node/job-api.md#NODE-JOB-29); the gateway route `POST /v1/ua/register` stays SPECIFIED).** The node sends them on its submit lane, as
a job of its own (`docs/node/job-api.md`: named fields `kind`, `pk`, `part`; the node builds the calldata; an explicit gas
limit per NET-EVM-11; allow-lists equal to the contract's in both directions: `guard.rs`, `CALL_TABLE`, `typed.rs`), before
the `register` job of the same key, and maps `UAKeyNotCached` to a named node error; the guarantee is the node's (open
node), with its spec section in `docs/node/` and `docs/integration.md`. Clients: `clientkeys` and `ua-rs` get a builder for
the part transactions (plain calls, no signature; the subject or anyone may send them) and the cache-then-register order;
vectors only if a byte format changes (none expected: the call is `cacheExpandedKey(uint16, bytes, uint256)`).

**MD-15 (probe failure; F-7, owner 2026-11-15).** With `MLDSA_PRECOMPILE=on`, a probe whose RPC / call fails (as distinct
from a probe that answers "no") refuses the deploy by name; it never falls back to the cache silently. The deploy JSON records
the path each ML-DSA kind took (`precompile <address>` or `cache`), beside the flag.

**MD-12 (size).** `UARegistryCoreLib`'s ratchet baseline in `size-baseline.json` moves to the round's measured size
(WIP: 35,165 → 35,262 B, +97 B, under its 35,694 B line) with this reason in the commit (owner "Dời baseline"); re-measured
after the 3-part change. No module split without asking.

**MD-11 (caps).** Cache caps: 44 4,250,000 and 65 5,950,000 (unchanged), **87 8,800,000** (the least multiple of 50,000 at
least 30,000 above the least working gas 8,760,705, the 44 / 65 margin policy; 73.3 % of 12 M). Precompile-path caps are set
from T-GAS on the SCaaS testnet (the reset-4 run measured `MldsaVerifier(0x0134).verify` ≈ 140,360 at precompile 135,006),
not from an estimate; the WIP's 200,000 / 200,000 / 250,000 are placeholders to be replaced by measurement.

## 3. Security

- **No forgery path is added.** The expanded key is derived on-chain by the verifier from the `pk` whose id the registry
  stores; no caller supplies it (owner 2026-10-12). SSTORE2 blobs are immutable code starting `0x00` (not executable), the
  pointers are CREATEd by the registry, no admin path writes them; key rotation means a new `pk`, a new id, a new cache.
  Caching ahead of the owner, or someone else's key, writes the one deterministic value; front-running costs only the
  sender's gas.
- **Incomplete cache fails closed** (`UAKeyNotCached`), never a partial verdict.
- **One path per registry:** where a precompile is used the cache is refused, so within one registry a signature cannot get
  two verdicts (MD-8's `mldsaalt` registry is a second registry on the same chain, in the other mode, by design).
- **Equivalence is the safety assumption.** The cached path is ML-DSA only if `expandKey` (ExpandA, `tr` = H(pk) 64 B,
  `NTT(t1·2^d)`) equals FIPS 204's; a wrong expansion loses liveness (valid signatures refused) or makes the check
  non-standard. Required: parts concatenated == `expandedKey(pk)` byte for byte (65, 87); NIST ACVP ML-DSA-87 sigVer
  (30 cases) through the same pointer read as `verifyCached` (a harness, since `verifyCached` formats the UA message itself);
  the existing KATs for 44 / 65. UNAUDITED.
- **Public data only:** the expanded key is derived from a public key.
- **Repricing:** caps sit 0.4–1.7 % above the measured least working gas and are immutable: a repricing that raises the
  cost breaks a kind regardless of MD-1, as for every kind today; the remedy is a new registry generation.
- **msig:** `UA_VERIFY_BUDGET` covers one msig check: one mldsa87 member (8.8 M) plus any other PQ member exceeds 12 M, so an
  msig holds at most one mldsa87 member beside light classical members.

## 4. Tests and mutants

Tests: MD-9's asserts; `UAKeyNotCached` with no cache and with one part missing, for each kind; mldsa87 built without a
precompile; part lengths and concatenation of the 3 parts (MD-4); ACVP-87 through the pointer read; `MLDSA_PRECOMPILE` on / off / refused env
in `UADeploy` / `GovDeploy`; the 75 % boundary; MD-5's block-limit gate (a block under ≈ 47 M disables the kind whose largest part does not fit; 200 M enables all).
Old tests that change meaning: `UADeploy.test_mldsa87OnlyWithAPrecompile` and the 66 % asserts (moved to the new rule with
old → new in the commit); CREATE2 address pins (moved with the reason). Mutants that must be caught: a part boundary of the 87 3-way split off by one row; the third `ekPtr` slot ignored; a missing part accepted; the `UAKeyNotCached` check removed; the 75 % check at 74 / 76; MD-5's block check removed;
`off` accepting a precompile verifier.

## 5. Docs

CTR-UA-23 (MD-1, MD-3, MD-5), CTR-UA-39 (Q1: the cache without a precompile; MD-4, MD-11), accounts.md gas table (the 87
cached rows and the uncached-over-2^24 facts), NET-EVM notes for `MLDSA_PRECOMPILE` and `pq_verifiers.py`, the matrix group,
`verifyCached`'s note (MD-10), §3 in short; `decisions.md` entry with §0; `legacy/README.md` entry for the retired
`UAMldsaNoPrecompile` path. Status tags: BUILT only with code and tests.

## 6. Open, for the owner

1. MD-5 stands with MD-4's 3 parts for mldsa87 (owner "Chia 3 part?"); the per-part figures are re-measured in the build.
2. Size: decided, MD-12.
3. **Funds before `register`:** can a UA id receive tokens / PQZ / Zether before it is registered? If yes, MD-3's ordering
   matters for users (cache, then register, before anyone pays the id); to be answered by the build round with a test or a
   code reading.
4. Precompile-path caps from T-GAS (MD-11): measured in the reset after this round.

## 7. Revision 1, after the Fable review (2026-11-15; report `20261115-12-fable-fable5.2-high-spec-mldsa.md`, outside the repo)

Verdict before this revision: 0 P0, 2 P1, 8 P2, 4 P3. Every finding is resolved here; where this section and §1–§6 differ,
this section wins.

| Finding | Resolution |
|---|---|
| F-1 (P1) cached mldsa87 PQZ holder cannot debit within 2^24 | MD-13 (owner) |
| F-2 (P1) cap from one signature | MD-11 measured over the **worst accepting input**: least working gas cold (3 pointers for 87) over every valid ACVP case of the level, the `pq_kat.json` rows and a generated batch including a signature with exactly ω hints (75 / 55 / 80 for 87 / 65 / 44); `PqGas.t.sol` asserts `max + 30,000 <= cap` for 44, 65, 87; the cap and the max stated in MD-11 / accounts.md |
| F-3 (P2) nobody sends `cacheExpandedKey` | MD-14, SPECIFIED; built in the `ua-rs-sign` port round (owner "F-3: như đề xuất"); until then a subject caches with its own gas or anyone sends the parts (open call) |
| F-4 (P2) `UAStore.expanded` dropped its kind check | the kind check comes back, as a per-kind part count (1 / 2 / 3) — one shared function used by `MldsaVerifier.expandedKeyParts`, `UARegistryAuxLib._ekParts` and `UAStore.expanded`, or a test that the three agree per kind (F-12) |
| F-5 (P2) MD-5 gate not built, measures used gas, deploy-time snapshot | built in `DeployBase`; it compares each part's **least working gas limit** (regular and total) with 2^24 and the block gas limit read from the chain; documented as a deploy-time check (a later block-limit cut is the chain operator's change, named in the runbook) |
| F-6 (P2) handed-in verifier trusted on two getters; precompile caps placeholders | `DeployBase` recomputes each env verifier's CREATE2 address from `DEPLOY_SALT` and the init code with its arguments and requires equality (beside `KIND` / `PRECOMPILE`); precompile caps from T-GAS (MD-11), placeholders refused by a test once measured |
| F-7 (P2) failed probe silently selects the cache | MD-15 (owner) |
| F-8 (P2) `requireAuthorized` keeps the uncached call | without a precompile an ML-DSA check without the full cache reverts `UAKeyNotCached` in code on every path (`_sigOk` and `requireAuthorized`), not only by invariant; the uncached call stays only for a verifier with a precompile |
| F-9 (P2) equivalence tests self-referential, few keys, copied read | an independent reference: the expanded key from `@noble/post-quantum` 0.7.1 (or the C/Rust reference already used for KATs) compared byte for byte with `expandedKey(pk)` and the parts, over ≥ 10 keys per level; the ACVP harness reads through the same library function as `verifyCached`, not a copy |
| F-10 (P3) one path per chain | §3 reworded; `mldsaalt` uses its own `DEPLOY_SALT` per run (no CREATE2 collision with the main deploy or a re-run) |
| F-11 (P3) remaining-gas figure | MD-1 reworded with the hold |
| F-12 (P3) part count in three places; `verifyCached(bytes chunks)` | one source for the count (F-4); `chunks` documented in MD-10 as an internal verifier interface (packed pointers, written only by the registry) |
| F-13 (P3) docs missed | CTR-UA-39 gets a Change with old → new (its title "enabled only through a precompile" is reversed); its "Cost if wrong" says the 3-part cache is now built; `IUARegistry.sol` comments (`UAKeyCache`, part list "0, 1, 2" for 87); CTR-UA-16 / CTR-PQZ-12 for MD-13 |
| F-14 (P2) 3-part ABI change, stale text, pin path | `expandedKeyOf(bytes32)` returns `address[3]` (same selector, 96 B instead of 64: every caller in tests and `script/onchain/*.s.sol` updated; named in §5); pin path fixed (MD-4); tests with only parts 0 + 1 and only 0 + 2 stored expect `UAKeyNotCached`; stale 2-part rows marked superseded |

Funds before `register` (§6.3), Fable's reading: the token ledger refuses an unregistered id (`_checkTo` reverts
`UANotRegistered`); PQZ and Zether need a registered key. The build round confirms with a test and traces DEX, wallet and
governance role assignment.
