# NEAR and Algorand family bring-up Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** NEAR and Algorand as full SCaaS families with the metatx-split semantics from day one: token with `mtx_pay` / `mtx_pay_meta`, accounts / UA, mandate, DEX, relay fee, `scaas-node` adapters, clients, devnets, vectors and docs.

**Architecture:** Branch `near-algorand` (worktree `.claude/worktrees/near-algorand`) from `metatx-split` once its Task 16 is committed; rebased onto `metatx-split` once its Task 18 is committed (at the latest before Task 16 here, which uses metatx-split T17's `max_pay_meta_bytes` and T18's `scaas_ua::{meta_pay_id, pay_lane, relay_ref}`). Order: the NEAR P-256 gate (Task 1), the shared UA kinds and family vectors (Tasks 2–3), NEAR contracts (Tasks 4–10), Algorand apps (Tasks 11–15), node adapters (16–17), clients (18), deploy + devnet + node e2e (19–20), docs (21), gate steps in metatx-split Task 20's runner (22). NEAR: one `token` contract per token holds every fee-less signed entry, atomic wrappers `relay_fee_<entry>`, an escrow router for cross-contract targets. Algorand: app-held box ledger (not an ASA), one `account` app, an atomic-group router with a keyless executor LogicSig.

**Tech Stack:** Rust `near-sdk` + `near-workspaces` on `near-sandbox` (cargo workspace `smartcontracts/near/`); Algorand Python (Puya `puyapy`) + `algorand-python-testing` + `algokit-utils` + `pytest` on a localnet (`smartcontracts/algorand/`); Python 3 generators with `pycryptodome` + `cryptography` (as `smartcontracts/move/aptos/scripts/gen_vectors.py`); Rust `scaas-node` (no new chain SDK: Borsh and canonical msgpack hand-encoded as the Aptos BCS encoder; controller call); Node `node --test` (`clients/clientkeys`), Rust `clients/ua-rs`, Qt 6.12 (`clients/ua-qt`); Solidity / Foundry only for `UAKinds`. Each tool's version is pinned (lock file / `requirements.txt` / `rust-toolchain.toml`) in the first task that uses it.

**Spec:** `docs/superpowers/specs/2026-10-28-near-algorand-design.md` (§0 decisions, §2 rule table rows 1–17, §3 NEAR, §4 Algorand, §5 adapters, §6 clients, §7 devnets, §8 vectors, §9 docs, §10 risks R1–R11, §11 open items). Background: `docs/research/near-algorand.md`; the metatx-split plan `docs/superpowers/plans/2026-10-27-metatx-split.md` (Tasks 14, 16, 20).

## Global Constraints

- "Same feature set as the other families: token with `mtx_pay`, the relayed pay, `mtx_pay_meta` (CTR-MTX-26); mandate; DEX; smart-key / passkey UA accounts; relay-fee router (CTR-MTX-27) from the start" (§0).
- "The relayer pays storage (NEAR storage staking, Algorand MBR). Users, UA users included, hold no NEAR / ALGO." (§0)
- "Standard-compatible where possible: NEAR NEP-141 + NEP-145 + NEP-148; Algorand ARC-200." (§0)
- "Balances and records are permanent (no TTL, no deletion, no refund)"; lanes are kept (both families non-pruning); "only NEAR escrow entries are pruned" (§0).
- "No admin on the router; no contract upgradeable: NEAR accounts keep no access key; Algorand approval programs reject update and delete" (§0).
- Out of scope: "Zether and PQZ", PQ signers, "the asset suite, token wrappers, tender", "the mesh (job API only)", "NET-ALL-26 `MetaCall` / `MetaTransfer`", "public testnets and mainnet; receiver-pays" (§1).
- Signed op = `MetaOp` v1, names `mtx_*`, digest `sha256` (§2 row 1); `payId` / `payLane` / `ref` "byte-for-byte the EVM derivation" (§2 rows 3, 8); "salt = the payment op's payer-signed `extra`, always" (§2 row 8).
- "it fits one transaction's protocol gas limit, 300 Tgas (not 1 PGas from nearcore 2.11: no chain's own limit is assumed)" (§3.5); no gas price 0 assumed anywhere.
- "Every gas, budget, storage and MBR figure: measured and pinned, with run logs" (§11); run logs under `smartcontracts/{near,algorand}/runs/2026-10-28-*.txt`.
- Lane keys fully hardened: "NEAR `m/44'/397'/0'/0'/i'`, Algorand `m/44'/283'/0'/0'/i'`" (§11).
- Native UA kinds `0x0017 near-account`, `0x0018 algorand-address`; "the `UAKinds` change alters EVM bytecode, so it runs forge at the four sets (`at-set.sh`), the size gate and `docs_check`, not the full pqz-core gate, and the SCaaS testnet registry is redeployed at its next reset" (§8).
- Every state-changing `mtx_*` is relayable (through the relayer; the outer fee may be 0). One rule for every chain kind.
- Devnets `near-sandbox` and an Algorand localnet "run through `scripts/capped` and docker with `--memory`" (§0); heavy commands (cargo, npm, puyapy, pytest on localnet, forge, cmake) only through `scripts/capped`, never inside `timeout`; cargo `-j2`; every container gets a memory cap.
- Parameter-set names, if any appear, only `n2048-kmax1024` / `n2304-kmax4096` / `n2560-kmax16384` / `n2816-kmax65536`.
- Decisions recorded in full in `docs/decisions.md` (content, who: "owner 2026-10-28" or "controller call, owner may override", status, commit); no bare labels.
- Every multi-step gate logs per step (`# <step> at commit <sha>` first line, `rc=<n>` last line) and skips steps already done.
- Commit per task on `near-algorand`, message `near-algorand T<n>: …` ending `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; no merge, no push (owner's go only).

## Review Focus

1. A `valid_until` in seconds compared with NEAR's nanosecond `block_timestamp` or Algorand's rounds: an op one second past expiry must be refused, one second before accepted — `near_valid_until_is_seconds` (Task 6), `test_valid_until_seconds` (Task 11), `algorand_last_valid_within_valid_until` (Task 17).
2. A relayer deposit / MBR payment that is off by one unit must fail, and exactly the reported figure must succeed, else the node burns gas on every retry — `near_check_storage_needed_is_exact` (Task 6), `test_mbr_payment_exact` (Task 11).
3. The real largest two-passkey wrapper, not the spike's model, must fit 300 Tgas — `near_relay_fee_two_passkey_within_300_tgas` (Task 9).
4. A NEAR router payment to a bound payee not registered on the token must still release (never a stuck `pending`) — `near_router_release_to_unregistered_payee` (Task 10).
5. Amounts above 2^53 (JSON) and the ARC-200 `uint256` against the `MetaOp` `u128` must not truncate — `near_amount_above_2_pow_53_round_trips` (Task 16), `test_amount_u128_max_and_supply_cap` (Task 11).

---

## File Structure

| Path | Responsibility |
|---|---|
| `smartcontracts/near/Cargo.toml`, `rust-toolchain.toml` | cargo workspace: `common`, `token`, `dex`, `relayfee`, `relayexec`, `spike-p256`, `integration` |
| `smartcontracts/near/common/src/{lib.rs,metaop.rs,auth.rs,webauthn.rs,hash.rs,ua.rs}` | `MetaOp` / `Holder` Borsh + digest, `Auth` + verify (NEP-413 ed25519, ecrecover, P-256), `meta_pay_id` / `pay_lane` / `relay_ref`, `ua_of` |
| `smartcontracts/near/token/src/{lib.rs,ft.rs,storage.rs,account.rs,metatx.rs,mandate.rs,trade.rs,relayfee.rs,escrow.rs}` | the per-token contract (§3.1 row 1) |
| `smartcontracts/near/{dex,relayfee,relayexec}/src/lib.rs` | escrow DEX; escrow router; executor |
| `smartcontracts/near/spike-p256/` | Task 1 measurement contract (kept, never deployed) |
| `smartcontracts/near/integration/tests/*.rs` | `near-workspaces` sandbox tests, one file per task |
| `smartcontracts/near/scripts/{gen_vectors.py,check_no_authority.sh,deploy.sh}`, `vectors/near-vectors.json`, `runs/` | vectors, authority check, keyless deploy, logs |
| `smartcontracts/algorand/contracts/{common.py,token.py,account.py,mandate.py,dex.py,relayfee.py,executor.py}` | Puya apps + executor LogicSig |
| `smartcontracts/algorand/tests/{conftest.py,test_*.py}`, `requirements.txt` | localnet + unit tests |
| `smartcontracts/algorand/{devnet/docker-compose.yml,scripts/devnet.sh,scripts/gen_vectors.py,scripts/deploy.py,artifacts.json,vectors/algorand-vectors.json,runs/}` | localnet, vectors, deploy, bytecode hash pins |
| `smartcontracts/scripts/{build.sh,test.sh,deploy.sh,devnet.sh}` | `near` / `algorand` entries |
| `scaas-node/src/adapters/{near.rs,algorand.rs,mod.rs}`, `src/{adapter.rs,keys.rs,addresses.rs}`, `node.example.toml`, `tests/e2e_{near,algorand}.rs` | adapters |
| `clients/clientkeys/src/{near.js,algorand.js,ua.js}`, `clients/ua-rs/src/{near.rs,algorand.rs,lib.rs}`, `clients/ua-qt/src/ua_kinds.rs`, `clients/{ua-py,ua-go,ua-cs,ua-dart}` | clients |

## Shared decisions (every task)

- **Op codes** (controller call; `MetaOp.op`, both families): 0 pay, 1 trade, 2 mandate_pay, 3 revoke (as built elsewhere), 4 transfer, 5 execute_transfer, 6 add_key, 7 remove_key, 8 add_origin, 9 remove_origin, 10 set_guardian, 11 start_recovery, 12 cancel_recovery, 13 mandate_open, 14 cancel, 15 invalidate_nonces. Ops other than pay / transfer / execute_transfer bind their parameters by `extra = sha256(encoding of the op's own parameters)` (Borsh on NEAR, ARC-4 on Algorand).
- **Signed text** (both): `"scaas.metaop.v1:" ‖ hex(digest)` (NET-ALL-23 first build); passkey challenge = b64url(digest).
- **Recovery** (controller call; §3.3 names only set / cancel): `mtx_start_recovery` (guardian-signed, op 11) and permissionless `finish_recovery(subject)` after `RECOVERY_DELAY` = 172,800 s, as Aptos `start_recovery` / `finish_recovery`.
- **NEAR argument encoding** (controller call): every `mtx_*`, `relay_*`, `*_check` and escrow method takes and returns Borsh (`#[serializer(borsh)]`, `#[result_serializer(borsh)]`); NEP methods stay JSON with `U128` strings.
- NEAR sandbox runs (`--test <file>` below): `cd smartcontracts/near && ../../scripts/capped ../scripts/build.sh near && ../../scripts/capped cargo test -j2 -p scaas-near-integration --test <file>`; the whole family: `scripts/capped smartcontracts/scripts/test.sh near`.
- WebAuthn vector: `smartcontracts/evm/test/vectors/webauthn_soft.json` (the spec's `smartcontracts/test/vectors/webauthn_kat.json` does not exist; controller call).

---

### Task 1: NEAR P-256-in-wasm spike — HARD GATE (§3.5; R8)

**Files:**
- Create: `smartcontracts/near/{Cargo.toml,rust-toolchain.toml}`, `smartcontracts/near/common/{Cargo.toml,src/lib.rs,src/webauthn.rs}`, `smartcontracts/near/spike-p256/{Cargo.toml,src/lib.rs}`, `smartcontracts/near/integration/{Cargo.toml,tests/p256_spike.rs}`, `smartcontracts/near/runs/2026-10-28-p256-spike.txt`
- Modify: `smartcontracts/scripts/build.sh`, `smartcontracts/scripts/test.sh` (`near`: `build.sh near && (cd near && cargo test -j2)`), `docs/research/near-algorand.md` (§ "P-256 spike, 2026-10-28": harness, figures, verdict)

**Interfaces:**
- Produces: `scaas_near_common::webauthn::verify(key: &[u8; 64], challenge: &[u8; 32], authenticator_data: &[u8], client_data_json: &[u8], sig: &[u8; 64], rp_id_hash: &[u8; 32], origins: &[String]) -> Result<(), AuthError>` (NET-ALL-04: `type == "webauthn.get"`, challenge, origin ∈ origins, rpIdHash, UP flag, low-s; RustCrypto `p256`); `build.sh near` writes `smartcontracts/near/target/near/<crate>.wasm` for every contract crate.

- [ ] **Step 1: Failing tests** (`integration/tests/p256_spike.rs`): `webauthn_vector_accepted` (the vector file passes; one flipped bit in `signature`, `clientDataJSON` or `authenticatorData` fails; the high-s form fails); `p256_two_passkey_relay_fee_fits_300_tgas` — `spike.two_passkey(a, b, call)` with 300 Tgas attached does two full `verify` calls, `env::keccak256` over a 4,096 B `call`, writes an 8-key account record, one lane, two balances and two NEP-297 logs (the largest wrapper's work, §3.8); assert `outcome.is_success()` and `outcome.total_gas_burnt <= Gas::from_tgas(300)`; print burnt gas total and per `verify`.
- [ ] **Step 2:** `scripts/capped smartcontracts/scripts/test.sh near` — FAIL (no crates).
- [ ] **Step 3: Implement** `verify` and `spike-p256` (`two_passkey(a: PasskeyCase, b: PasskeyCase, call: Vec<u8>)`, Borsh). Pin the toolchain and the wasm build (`cargo near build non-reproducible-wasm --no-abi` per crate) that the sandbox accepts in `build.sh near`.
- [ ] **Step 4:** Run again, tee into the run log. **Gate:** PASS ⇒ continue. FAIL (not success, or burnt > 300 Tgas) ⇒ **STOP**: commit the spike and log, report the figures to the owner, start no further task until the owner rules.
- [ ] **Step 5: Commit** `near-algorand T1: NEAR P-256 spike (two-passkey wrapper model vs 300 Tgas)`.

### Task 2: Native UA kinds `0x0017` / `0x0018` (§3.3, §4.3, §8)

**Files:**
- Modify: `clients/clientkeys/src/ua.js` (`NATIVE` rows `[0x0017, 'near-account', [32]]`, `[0x0018, 'algorand-address', [32]]`), `clients/clientkeys/scripts/ua-vectors.mjs` (`nativeInvalid` + `[0x0017, 31 B, 'UAKeyData']`, `[0x0018, 33 B, 'UAKeyData']`), `smartcontracts/vectors/ua/kinds.json` (regenerated), `smartcontracts/evm/src/ua/UAKinds.sol` (native range `0x0010..0x0018`, names), `smartcontracts/evm/test/ua/UAKinds.t.sol`, `clients/ua-rs/src/lib.rs`, `clients/ua-py/scaas_ua/__init__.py`, `clients/ua-go/ua.go`, `clients/ua-cs/Scaas.Ua/Ua.cs`, `clients/ua-dart/lib/src/table.dart` (it reads `kinds.json` natives too; controller call), `smartcontracts/evm/size-baseline.json` (comment entry), `docs/contracts/accounts.md` (§1.6 table rows), `TODO.md` (registry redeploy at the next 7622 reset)

**Interfaces:**
- Produces: `kinds.json` natives rows for kinds 23 and 24 (32 B, `member: false`); `UAKinds.isNative(0x0017) == isNative(0x0018) == true`, `isNative(0x0019) == false`.

- [ ] **Step 1: Failing tests:** `UAKinds.t.sol` `test_nearAlgorandNatives` (both native, names `near-account` / `algorand-address`, `0x0019` unknown); the existing vector tests of every reproducer (`ua.test.js`, ua-rs, ua-py, ua-go, ua-cs, ua-c, ua-cxx, ua-dart) against the regenerated `kinds.json`.
- [ ] **Step 2:** `cd clients/clientkeys && node scripts/ua-vectors.mjs` then each reproducer's test (commands: the header of `.github/workflows/ci.yml`) — FAIL on the new rows.
- [ ] **Step 3: Implement** the table rows in every reproducer.
- [ ] **Step 4:** PASS: every reproducer; forge at the four sets (`smartcontracts/evm/scripts/at-set.sh`, one run at a time), `python3 scripts/size_gate.py`, `python3 -I scripts/docs_check.py check` — 0 errors. Run `dotnet build-server shutdown` after the capped `dotnet test`.
- [ ] **Step 5: Commit** `near-algorand T2: native UA kinds 0x0017 near-account, 0x0018 algorand-address (all reproducers)`.

### Task 3: Family vector generators (§2 rows 1, 3, 8; §8)

**Files:**
- Create: `smartcontracts/near/scripts/gen_vectors.py` → `smartcontracts/near/vectors/near-vectors.json`; `smartcontracts/algorand/scripts/gen_vectors.py` → `smartcontracts/algorand/vectors/algorand-vectors.json` (both `--check`)

**Interfaces:**
- Consumes: `paymeta.json` (payId / payLane rows), `kinds.json` (`uaOf`), `webauthn_soft.json`.
- Produces (read by Tasks 4–20): JSON sections `metaops` (per op code: fields, `encoding`, `digest`), `signing` (NEAR: NEP-413 payload Borsh + `sha256(u32le(2147484061) ‖ payload)` + an ed25519 signature from a fixed seed; Algorand: `"MX" ‖ text` + signature), `secp256k1` (raw-digest signatures, low-s), `nativeIds` (NEAR: a 64-hex implicit id → raw 32 B; a named and an ETH-implicit id → `sha256(account_id)`; Algorand: address ↔ 32 B key), `relayRefs` (NEAR wrapper and router, Algorand router: a short and a 4,096 B call each), `routerCall` (Algorand `call` bytes), `mbr` (Algorand: per box kind, name and value length and `2500 + 400·(name+value)` µALGO).
- Encodings pinned here (builder detail of §11): NEAR `encode = b"scaas.metaop.v1" ‖ borsh(MetaOp)`, `Holder` Borsh enum 0 `Near(AccountId)` / 1 `Ua([u8;32])`, `relayer: Option<AccountId>`; Algorand `encode = b"scaas.metaop.v1" ‖ ARC-4 static tuple` (holder = u8 kind ‖ 32 B, `relayer` 32 B, zero = any; amounts `uint128`).

- [ ] **Step 1: Failing check:** each generator's `--check` mode fails when the JSON is missing; a self-test in each generator asserts its `metaPayId` / `payLane` equal every `paymeta.json` row and its `relay_ref` equals `keccak256("scaas.relayfee" ‖ network ‖ target ‖ keccak256(call) ‖ salt)` recomputed independently.
- [ ] **Step 2:** `python3 -I smartcontracts/near/scripts/gen_vectors.py --check` — FAIL (no file); same for Algorand.
- [ ] **Step 3: Implement** the generators (stdlib + `pycryptodome` + `cryptography`; fixed seeds; P-256 rows marked non-deterministic and skipped by `--check`).
- [ ] **Step 4:** write, then `--check` — PASS (both).
- [ ] **Step 5: Commit** `near-algorand T3: NEAR + Algorand vector generators (MetaOp, signing forms, refs, native ids, MBR)`.

### Task 4: NEAR token — NEP-141 / NEP-145 / NEP-148, UA ledger, storage (§3.2; R6)

**Files:**
- Create: `smartcontracts/near/token/{Cargo.toml,src/lib.rs,src/ft.rs,src/storage.rs}`, `smartcontracts/near/integration/tests/token.rs`, `smartcontracts/near/scripts/check_no_authority.sh`
- Modify: `smartcontracts/near/Cargo.toml`, `smartcontracts/scripts/test.sh` (`near` also runs `check_no_authority.sh`), `smartcontracts/near/scripts/gen_vectors.py` (`MEASURED_STORAGE_BYTES` per record kind → `storage` section of `near-vectors.json`; Tasks 5–10 add their record kinds)

**Interfaces:**
- Produces: `Token::new(network: [u8; 32], admin: AccountId, metadata: FungibleTokenMetadata)` (`#[init]`, Borsh); NEP-141 / NEP-145 / NEP-148 methods; `transfer_to_ua(id: [u8; 32], amount: U128)` (1 yocto); `ua_balance_of(id: [u8; 32]) -> U128`; `mint(to: AccountId, amount: U128)` (admin only); `network() -> [u8; 32]`; internal `fn credit(&mut self, to: &Holder, amount: u128)`, `fn debit(&mut self, from: &Holder, amount: u128)`; events in standard `nep141` and `"scaas"`; `check_no_authority.sh` fails on `deploy_contract|add_full_access_key|add_access_key|delete_key|delete_account|deploy_global_contract|use_global_contract` in any contract crate.

- [ ] **Step 1: Failing tests** (`token.rs`): `ft_transfer_registered_needs_one_yocto`; `ft_transfer_unregistered_auto_registers` (attached ≥ `storage_balance_bounds().min` registers the receiver, the excess refunded to the predecessor; 1 yocto below panics); `storage_bounds_min_equals_max_equals_measured` (= measured registration bytes × `env::storage_byte_cost()`); `storage_withdraw_positive_panics`; `storage_unregister_registered_panics_force_included` (unregistered → `false`); `ft_transfer_call_resolves_as_nep141`; `transfer_to_ua_credits_ua_ledger`; `mint_admin_only`; `token_refuses_transfer_to_self`; `check_no_authority_finds_forbidden_api` (the script fails on a fixture line, passes on the tree).
- [ ] **Step 2:** `cd smartcontracts/near && ../../scripts/capped ../scripts/build.sh near && ../../scripts/capped cargo test -j2 -p scaas-near-integration --test token` — FAIL.
- [ ] **Step 3: Implement** per §3.2 (near-sdk `near-contract-standards` core where it fits, the two deviations by hand). Storage size constant `ACCOUNT_STORAGE_BYTES` = the measured figure in the run log.
- [ ] **Step 4:** PASS; append measured bytes to `runs/2026-10-28-near-storage.txt`.
- [ ] **Step 5: Commit** `near-algorand T4: NEAR token NEP-141/145/148 + UA ledger + storage rules`.

### Task 5: NEAR accounts / UA, signatures, key ops (§3.3, §3.5; R7)

**Files:**
- Create: `smartcontracts/near/common/src/{metaop.rs,auth.rs,hash.rs,ua.rs}`, `smartcontracts/near/token/src/account.rs`, `smartcontracts/near/integration/tests/account.rs`

**Interfaces:**
- Consumes: Task 1 `webauthn::verify`; Task 3 vectors.
- Produces: `MetaOp { network: [u8;32], contract: AccountId, op: u8, from: Holder, to: Holder, relayer: Option<AccountId>, amount: u128, pay_ref: [u8;32], lane: [u8;32], nonce: u64, valid_until: u64, extra: [u8;32] }` with `fn encode(&self) -> Vec<u8>`, `fn digest(&self) -> [u8;32]`; `enum Auth { Ed25519 { key: [u8;32], sig: [u8;64] }, Secp256k1 { key: [u8;64], sig: [u8;64], v: u8 }, Passkey { key: [u8;64], authenticator_data: Vec<u8>, client_data_json: Vec<u8>, sig: [u8;64] }, Msig { key_data: Vec<u8>, sigs: Vec<(u8, Auth)> } }`; `fn native_id(account: &AccountId) -> [u8;32]`; `fn ua_of(kind: u16, key_data: &[u8]) -> [u8;32]`; token `fn authorize(&mut self, op: &MetaOp, auth: &Auth) -> Holder` (domain, network, contract, expiry, relayer rule 7, signature; lazy UA open); entries `mtx_add_key`, `mtx_remove_key`, `mtx_add_origin`, `mtx_remove_origin`, `mtx_set_guardian`, `mtx_start_recovery`, `mtx_cancel_recovery`, `finish_recovery(subject: Holder)`, `add_key_native(key: KeyRecord)` (a `Near` holder by direct call), each `(op: MetaOp, auth: Auth, params…)` with `*_check(…) -> Check { error: Option<String>, storage_needed: U128 }`; `pub const MAX_KEYS: usize = 8`, `RECOVERY_DELAY_S: u64 = 172_800`, `MSIG_MAX_MEMBERS: usize` (= floor(250 Tgas / per-verify gas of the Task 1 log), proven in Task 9).

- [ ] **Step 1: Failing tests:** unit `metaop_vectors_match`, `nep413_vectors_match`, `ua_of_matches_kinds_json_valid_rows`, `native_id_forms` (implicit raw, named and ETH-implicit `sha256`, an upper-case id refused); sandbox `ua_opened_lazily_relayer_pays_storage`, `ed25519_secp256k1_passkey_each_accepted`, `secp256k1_high_s_refused`, `ninth_key_refused`, `origin_and_rp_checked`, `policy_passkey_for_value`, `recovery_after_delay_only` (finish before 172,800 s refused), `cancel_recovery_by_key`, `msig_native_member_only_as_predecessor`, `access_key_signature_never_accepted` (an ed25519 sig by the implicit account's own key with no SCaaS key → refused), `wrong_network_or_contract_refused`.
- [ ] **Step 2:** `cd smartcontracts/near && ../../scripts/capped cargo test -j2 -p scaas-near-common && ../../scripts/capped cargo test -j2 -p scaas-near-integration --test account` — FAIL.
- [ ] **Step 3: Implement** per §3.3 / §3.5 (`env::ed25519_verify` over the NEP-413 hash, `env::ecrecover` with malleability flag set, `webauthn::verify`).
- [ ] **Step 4:** PASS.
- [ ] **Step 5: Commit** `near-algorand T5: NEAR subject accounts, UA, signatures, key ops`.

### Task 6: NEAR metatx — lanes, `mtx_pay`, `mtx_pay_meta`, transfers (§2 rows 4–7, 10, 12, 15–16; §3.4, §3.7)

**Files:**
- Create: `smartcontracts/near/token/src/metatx.rs`, `smartcontracts/near/integration/tests/metatx.rs`
- Modify: `smartcontracts/near/common/src/hash.rs`

**Interfaces:**
- Consumes: Task 5 `authorize`, Task 4 `credit` / `debit`.
- Produces: `hash::{meta_pay_id(salt: &[u8;32], meta: &[u8]) -> [u8;32], pay_lane(p: &[u8;32]) -> [u8;32], relay_ref(network: &[u8;32], target: &[u8], call: &[u8], salt: &[u8;32]) -> [u8;32]}`; entries `mtx_pay(op, auth)`, `mtx_pay_meta(op, auth, salt: [u8;32], meta: Vec<u8>)`, `mtx_transfer(op, auth)`, `mtx_execute_transfer(op, auth)` + `*_check`; `lane_nonce(holder: Holder, lane: [u8;32]) -> u64`; private `fn settle_pay(&mut self, op: &MetaOp, from: &Holder)` (shared by Tasks 9–10); events `payment_meta` before `payment_settled`, `meta_transaction_executed`.

- [ ] **Step 1: Failing tests:** unit `pay_meta_vectors_match` (every `paymeta.json` row via `env::keccak256`); sandbox `pay_meta_emits_meta_then_settled`, `near_pay_meta_mismatch_and_replay` (wrong salt / lane / nonce ≠ 0 refused; a second pay-meta of the same `(from, pay_ref)` refused), `pay_once_per_lane`, `relayer_bound_to_predecessor`, `near_wrapper_bound_pay_refused_direct` (`relayer == token id` refused on `mtx_pay`), `pay_to_token_itself_refused`, `transfer_to_unregistered_native_registers_from_deposit`, `near_valid_until_is_seconds` (`valid_until = now_s − 1` refused, `now_s + 1` accepted, `now_s = block_timestamp / 10^9`), `near_check_storage_needed_is_exact` (per entry: attached = `storage_needed` succeeds, `storage_needed − 1` yocto panics, `storage_needed + k` refunds `k`), `batch_of_actions_atomic` (two `mtx_pay` actions in one tx, the second fails ⇒ neither applies).
- [ ] **Step 2:** `../../scripts/capped cargo test -j2 -p scaas-near-integration --test metatx` — FAIL.
- [ ] **Step 3: Implement** per §2 / §3.4; lanes `LookupMap<(Holder, [u8;32]), u64>`, never removed.
- [ ] **Step 4:** PASS.
- [ ] **Step 5: Commit** `near-algorand T6: NEAR mtx_pay / mtx_pay_meta / transfers, lanes, checks`.

### Task 7: NEAR mandate (§3.6)

**Files:**
- Create: `smartcontracts/near/token/src/mandate.rs`, `smartcontracts/near/integration/tests/mandate.rs`

**Interfaces:**
- Produces: `mtx_mandate_open(op, auth, terms: MandateTerms)`, `mtx_mandate_pay(op, auth)`, `mtx_revoke(op, auth)` + `*_check`; `MandateTerms { payee: Holder, per_payment: u128, per_period: u128, period_s: u64, expiry: u64, funding: u128 }`; mandate id = `sha256(Borsh(from, terms, lane, nonce))`; funds held under the mandate id in the token ledger.

- [ ] **Step 1: Failing tests:** `mandate_pay_within_limits`, `per_payment_and_per_period_exceeded_refused`, `wrong_payee_refused`, `expired_refused`, `revoked_refused_then_funds_back`, `pay_ref_once_per_mandate`, `mandate_has_no_pay_meta_entry` (no method `mtx_mandate_pay_meta`).
- [ ] **Step 2:** `--test mandate` — FAIL.
- [ ] **Step 3: Implement** per §3.6 (README §3 item 2).
- [ ] **Step 4:** PASS.
- [ ] **Step 5: Commit** `near-algorand T7: NEAR mandate`.

### Task 8: NEAR escrow DEX, relayer-bound (§3.6; CTR-DEX-09/-10)

**Files:**
- Create: `smartcontracts/near/token/src/trade.rs`, `smartcontracts/near/dex/{Cargo.toml,src/lib.rs}`, `smartcontracts/near/integration/tests/dex.rs`

**Interfaces:**
- Produces: `Order { sell_token: AccountId, buy_token: AccountId, sell_amount: u128, min_buy: u128, relayer: Option<AccountId>, expiry: u64 }` (op 1, `to = Near(dex)`, `relayer = Some(dex)`, `amount = sell_amount`, `extra = sha256(Borsh(Order))`, the order travels verbatim); token `mtx_trade(op, auth, order: Order)` (predecessor must be the order's DEX), `mtx_cancel(op, auth, target_lane: [u8;32], target_nonce: u64)`, `mtx_invalidate_nonces(op, auth, lane: [u8;32], min_nonce: u64)` (`min_nonce < 2^63`), `filled(holder, lane, nonce) -> bool`; dex `settle(order_a, op_a, auth_a, order_b, op_b, auth_b)`, `on_legs(settle_id: [u8;32])` (`#[private]`), `refund_expired(settle_id: [u8;32])` (anyone after both expiries); fill-or-kill: `a.sell_amount ≥ b.min_buy` and `b.sell_amount ≥ a.min_buy`, each side receives the other's full `sell_amount`.

- [ ] **Step 1: Failing tests:** `settle_pays_both_legs` (native via `ft_transfer`, UA via `transfer_to_ua`), `one_leg_fails_other_refunded`, `order_relayer_mismatch_refused`, `leg_called_by_non_dex_refused`, `refund_expired_after_lost_callback`, `refund_before_expiry_refused`, `cancel_filled_order_refused`, `min_nonce_cap_refused` (`2^63`), `no_partial_fill`.
- [ ] **Step 2:** `--test dex` — FAIL.
- [ ] **Step 3: Implement** per §3.6 (join callback on both `mtx_trade` promises; refund wins).
- [ ] **Step 4:** PASS; gas of `settle` → `runs/2026-10-28-near-gas.txt`.
- [ ] **Step 5: Commit** `near-algorand T8: NEAR escrow DEX (relayer-bound, fill-or-kill)`.

### Task 9: NEAR relay-fee wrappers `relay_fee_<entry>` (§3.8 wrappers; R2)

**Files:**
- Create: `smartcontracts/near/token/src/relayfee.rs`, `smartcontracts/near/integration/tests/relay_fee_wrappers.rs`

**Interfaces:**
- Consumes: `settle_pay`, `relay_ref`, the Task 5–8 entries.
- Produces: `relay_fee_add_key`, `relay_fee_remove_key`, `relay_fee_add_origin`, `relay_fee_remove_origin`, `relay_fee_set_guardian`, `relay_fee_start_recovery`, `relay_fee_cancel_recovery`, `relay_fee_mandate_open`, `relay_fee_revoke`, `relay_fee_cancel`, `relay_fee_invalidate_nonces` (names: entry without `mtx_`; controller call), each `(entry arguments…, pay_op: MetaOp, pay_auth: Auth)`; `call = u8 len ‖ entry name ‖ Borsh(entry arguments)`, target = `u8 len ‖ token account id`; event `relay_fee_paid`.

- [ ] **Step 1: Failing tests:** one success test per wrapper; `wrapper_open_mode_pays_predecessor`, `wrapper_bound_payee_paid_directly`, `refused_entry_pays_nothing` (cancel of a filled order panics, payer balance unchanged), `pay_op_shape_enforced` (`pay_ref ≠ ref`, `lane ≠ payLane(ref)`, `nonce ≠ 0`, `relayer ≠ token id` each refused), `relay_ref_vectors`, `near_relay_fee_two_passkey_within_300_tgas` (the costliest wrapper with a passkey entry auth and a passkey payment: success at 300 Tgas, burnt ≤ 300 Tgas / 1.2), `relay_fee_msig_cap_fits_300_tgas` (entry auth = msig of `MSIG_MAX_MEMBERS` passkey members).
- [ ] **Step 2:** `--test relay_fee_wrappers` — FAIL.
- [ ] **Step 3: Implement** per §3.8 (entry, then `settle_pay` with `pay_ref = ref`, one receipt; no promise).
- [ ] **Step 4:** PASS; figures → `runs/2026-10-28-near-gas.txt`.
- [ ] **Step 5: Commit** `near-algorand T9: NEAR relay_fee_<entry> wrappers`.

### Task 10: NEAR escrow router `relayfee` + `relayexec` (§3.8 router; R1, R3, R4)

**Files:**
- Create: `smartcontracts/near/{relayfee,relayexec}/{Cargo.toml,src/lib.rs}`, `smartcontracts/near/token/src/escrow.rs`, `smartcontracts/near/integration/tests/relay_router.rs`, a test-only target crate `smartcontracts/near/integration/target-fixture/` (never deployed)

**Interfaces:**
- Produces: router `new(executor: AccountId)`, `relay(target: AccountId, method: String, args: Vec<u8>, target_gas: Gas, target_deposit: U128, token: AccountId, op: MetaOp, auth: Auth)`, `on_hold(ref: [u8;32])`, `on_call(ref: [u8;32])`, `on_settle(ref: [u8;32], released: bool)` (all `#[private]`), `relay_timeout(ref: [u8;32])`, view `pending(ref) -> Option<Pending>`; `Pending { token, payer: Holder, payee: Option<Holder>, relayer: AccountId, target_deposit: u128, deadline: u64 }`; `RELAY_TIMEOUT_S: u64 = 3_600`; executor `exec(target, method, args, target_gas)` and `return_deposit(to: AccountId, amount: U128)` (router only); token `relay_hold(op, auth)` (predecessor = router; registers an unregistered native payee from the attached deposit), `relay_release(ref, payee: Holder)`, `relay_refund(ref)` (holding router only); gas constants `GAS_HOLD`, `GAS_ON_HOLD`, `GAS_EXEC`, `GAS_ON_CALL`, `GAS_RELEASE`, `GAS_ON_SETTLE` = measured max (both branches) × 1.5.

- [ ] **Step 1: Failing tests:** `release_on_success`; `refund_on_target_panic`; `refund_on_missing_code`; `hold_failure_clears_pending`; `timeout_refund_refused_before_deadline`; `timeout_refunds_after_deadline`; `release_and_refund_exclusive` (late `on_call` after timeout pays nothing); `pending_empty_and_router_balance_unchanged_after_each_branch`; `executor_holds_only_its_stake_after_each_branch`; `target_deposit_forwarded_and_returned_on_failure`; `short_prepaid_gas_refused`; `near_router_bound_pay_refused_direct`; `target_router_or_executor_refused`, `payee_executor_refused`; `forwarded_call_cannot_spend_router_bound_payment` (target = token `relay_hold` / `mtx_pay` of another router-bound op → fails, predecessor = executor); `near_router_release_to_unregistered_payee` (bound native payee unregistered at `relay` → registered at hold, released, `pending` cleared); `gas_pins_hold` (each measured figure ≤ pinned / 1.2); `relay_ref_vectors`.
- [ ] **Step 2:** `--test relay_router` — FAIL.
- [ ] **Step 3: Implement** the seven steps of §3.8's table; `relay` refuses unless prepaid gas ≥ `GAS_HOLD + GAS_ON_HOLD + GAS_EXEC + target_gas + GAS_ON_CALL + GAS_RELEASE + GAS_ON_SETTLE`; `pending` deleted on settle with its storage deposit returned to the staking relayer.
- [ ] **Step 4:** PASS; figures → `runs/2026-10-28-near-gas.txt`.
- [ ] **Step 5: Commit** `near-algorand T10: NEAR escrow relay-fee router + executor`.

### Task 11: Algorand token + metatx for native addresses, localnet (§4.1, §4.2, §4.4–§4.6, §4.9; R5)

**Files:**
- Create: `smartcontracts/algorand/{requirements.txt,contracts/common.py,contracts/token.py,tests/conftest.py,tests/test_token.py,tests/test_vectors.py,devnet/docker-compose.yml,scripts/devnet.sh,artifacts.json}`
- Modify: `smartcontracts/scripts/{build.sh,test.sh,devnet.sh}` (`algorand`: `build.sh algorand` = `puyapy --output-bytecode` into `smartcontracts/algorand/out/` and rewrite `artifacts.json`; `test.sh algorand` = build, `devnet.sh algorand up`, `pytest -q`)

**Interfaces:**
- Produces: `common.py` `MetaOp` ARC-4 struct, `digest(op) -> Bytes32`, `verify_native(addr: Account, digest, sig) -> bool` (current authority: `AcctAuthAddr` if set else the address; `ed25519verify_bare` over `"MX" ‖ text`; constant `SIGN_PREFIX = b"MX"` in one place), `meta_pay_id`, `pay_lane`, `relay_ref`; token ABI `create(name, symbol, decimals: uint8, admin: address)`, ARC-200 methods, `mint(to, amount: uint256)` (admin; total supply ≤ 2^128 − 1), `transfer_to_ua(id: byte[32], amount: uint256)` (controller call: the NEAR `transfer_to_ua` on Algorand), `ua_balance_of(id: byte[32]) -> uint256`, `mtx_pay(op, auth, open_payee: address)`, `mtx_pay_meta(op, auth, salt: byte[32], meta: byte[])`, `mtx_transfer`, `mtx_execute_transfer`, read-only `mbr_needed(op) -> uint64`, `lane_nonce(kind: uint8, holder: byte[32], lane: byte[32]) -> uint64`; boxes `"b" ‖ address`, `"u" ‖ id`, lane `"l" ‖ sha256(kind ‖ holder ‖ lane)`; ARC-28 events of §4.2. No router app id at creation (rules 7, 10, 12 need none; controller call, §4.1 wording). `artifacts.json` `{app: {approval_sha512_256, clear_sha512_256}}`.
- Localnet: the repo's own compose (AlgoKit localnet's algod, conduit, indexer, postgres images at pinned digests) with `mem_limit` per service: algod 2g, others 512m (controller call: AlgoKit's CLI takes no memory cap).

- [ ] **Step 1: Failing tests:** `test_metaop_vectors`, `test_sign_bytes_vectors`, `test_pay_meta_vectors` (every `paymeta.json` row via `op.keccak256`); localnet `test_arc200_transfer_new_receiver_needs_exact_mbr`, `test_mbr_payment_exact` (payment = `mbr_needed` passes; ±1 µALGO refused; a payment when 0 is needed refused; equals the app's `AcctMinBalance` delta), `test_pay_meta_emits_meta_then_settled`, `test_algorand_pay_meta_mismatch_and_replay`, `test_rekeyed_address_signs_with_auth_addr` and `test_rekeyed_to_logicsig_refused_natively`, `test_relayer_bound_to_sender`, `test_pay_to_token_app_refused`, `test_approve_only_app_to_app`, `test_update_and_delete_refused` (creator included), `test_optin_refused`, `test_wrong_network_refused` (an op signed for another `GenesisHash`), `test_box_prefixes_disjoint`, `test_valid_until_seconds` (`Global.latest_timestamp`: −1 s refused, +1 s accepted), `test_amount_u128_max_and_supply_cap` (a pay of 2^128 − 1 round-trips; mint above the cap refused), `test_pay_meta_cap_measured` (largest `meta` within 2,048 B args and 1,024 B logs → `MAX_PAY_META_BYTES` pinned in `runs/2026-10-28-algorand-limits.txt`).
- [ ] **Step 2:** `scripts/capped smartcontracts/scripts/test.sh algorand` — FAIL.
- [ ] **Step 3: Implement** per §4.2 / §4.4 / §4.6 / §4.9 (MBR check: `AcctMinBalance(app)` after minus before == the preceding payment's amount).
- [ ] **Step 4:** PASS; `devnet.sh algorand down`.
- [ ] **Step 5: Commit** `near-algorand T11: Algorand ARC-200 token + mtx_pay / pay_meta, localnet`.

### Task 12: Algorand `account` app + UA (§4.3, §4.6; R7)

**Files:**
- Create: `smartcontracts/algorand/contracts/account.py`, `smartcontracts/algorand/tests/test_account.py`
- Modify: `smartcontracts/algorand/contracts/token.py` (`create(…, account_app: uint64)`; UA holders verified by inner call), `smartcontracts/algorand/tests/test_token.py`

**Interfaces:**
- Produces: account ABI `verify(holder_kind: uint8, holder: byte[32], digest: byte[32], auth: byte[]) -> bool` (ed25519 `ed25519verify_bare`, `ecdsa_verify Secp256k1` low-s, `ecdsa_verify Secp256r1` over `sha256(authData ‖ sha256(clientDataJSON))` low-s + `clientDataJSON` grammar, msig kind 288 from key data), the key-op entries of the shared op table (op 6–12) + `finish_recovery`, `add_key_native` (sender = the address); `MAX_KEYS = 8`, `RECOVERY_DELAY_S = 172_800`; `MSIG_MAX_MEMBERS` (measured: largest all-passkey msig whose `mtx_add_key` fits 2,048 B args and the pooled group budget).

- [ ] **Step 1: Failing tests:** `test_ua_opened_lazily_relayer_pays_mbr`, `test_each_kind_accepted` (ed25519, secp256k1, passkey vector), `test_high_s_refused` (secp256k1, P-256), `test_ninth_key_refused`, `test_recovery_after_delay_only`, `test_msig_native_member_by_current_authority`, `test_msig_cap_fits_limits`, `test_budget_per_kind_pinned` (simulate's budget per kind ≤ pinned in `runs/2026-10-28-algorand-limits.txt`), `test_token_ua_pay_via_account_verify`, `test_keys_shared_by_two_tokens`.
- [ ] **Step 2:** `scripts/capped smartcontracts/scripts/test.sh algorand` — FAIL.
- [ ] **Step 3: Implement** per §4.3 / §4.6.
- [ ] **Step 4:** PASS.
- [ ] **Step 5: Commit** `near-algorand T12: Algorand account app (keys, passkey, msig) + UA path in token`.

### Task 13: Algorand mandate app (§4.7)

**Files:**
- Create: `smartcontracts/algorand/contracts/mandate.py`, `smartcontracts/algorand/tests/test_mandate.py`

**Interfaces:**
- Produces: `create(account_app: uint64)`; `mtx_mandate_open(token: uint64, op, auth, terms: MandateTerms)`, `mtx_mandate_pay(token, op, auth)`, `mtx_revoke(token, op, auth)`; `MandateTerms` as Task 7 in ARC-4; funds in the token ledger under the mandate app address.

- [ ] **Step 1: Failing tests:** as Task 7 (`test_mandate_pay_within_limits`, `test_limits_exceeded_refused`, `test_wrong_payee_refused`, `test_expired_refused`, `test_revoked_refused_then_funds_back`, `test_pay_ref_once`, `test_no_pay_meta_entry`).
- [ ] **Step 2:** `scripts/capped smartcontracts/scripts/test.sh algorand` — FAIL.
- [ ] **Step 3: Implement** per §4.7 (inner calls to `token` and `account`).
- [ ] **Step 4:** Same command — PASS.
- [ ] **Step 5: Commit** `near-algorand T13: Algorand mandate app`.

### Task 14: Algorand DEX app (§4.7; CTR-DEX-09/-10)

**Files:**
- Create: `smartcontracts/algorand/contracts/dex.py`, `smartcontracts/algorand/tests/test_dex.py`
- Modify: `smartcontracts/algorand/contracts/token.py` (`mtx_trade`, `mtx_cancel`, `mtx_invalidate_nonces`, `filled`)

**Interfaces:**
- Produces: `Order` as Task 8 in ARC-4; token `mtx_trade(op, auth, order)` (funds move only into the DEX app address; caller must be the order's DEX), `mtx_cancel`, `mtx_invalidate_nonces` (`min_nonce < 2^63`); dex `settle(order_a, op_a, auth_a, order_b, op_b, auth_b)`: both legs in one group (EVM shape), fill-or-kill rule of Task 8.

- [ ] **Step 1: Failing tests:** `test_settle_both_legs_atomic`, `test_one_leg_fails_group_fails`, `test_order_relayer_mismatch_refused`, `test_leg_by_non_dex_refused`, `test_cancel_filled_refused`, `test_min_nonce_cap_refused`, `test_no_partial_fill`.
- [ ] **Step 2:** `scripts/capped smartcontracts/scripts/test.sh algorand` — FAIL.
- [ ] **Step 3: Implement** per §4.7 (both legs' `mtx_trade` inner calls in the one `settle` call).
- [ ] **Step 4:** Same command — PASS.
- [ ] **Step 5: Commit** `near-algorand T14: Algorand DEX app + trade legs`.

### Task 15: Algorand relay fee — router + executor LogicSig (§4.8; R2, R3)

**Files:**
- Create: `smartcontracts/algorand/contracts/{relayfee.py,executor.py}`, `smartcontracts/algorand/tests/test_relayfee.py`
- Modify: `smartcontracts/scripts/build.sh` (`algorand`: split the compiled executor into `EXEC_PREFIX` / `EXEC_SUFFIX` around its 8-byte router-id constant and bake both into `relayfee.py`'s build)

**Interfaces:**
- Produces: executor LogicSig with template `ROUTER_APP_ID: bytes[8]` (big-endian; approves only an `ApplicationCall` NoOp whose `gtxn[GroupIndex+1]` is `relay` on that app, `RekeyTo` / `CloseRemainderTo` / `AssetCloseTo` zero, fee 0); router ABI `relay(token: uint64, op: MetaOp, auth: byte[]) -> void`, `relay_ref(call: byte[], salt: byte[32]) -> byte[32]`, `executor() -> address` = `sha512_256(b"Program" ‖ EXEC_PREFIX ‖ itob(Global.current_application_id) ‖ EXEC_SUFFIX)`; `call = target app id (u64) ‖ u8 n ‖ (u16 len ‖ arg)×n` of `gtxn[GroupIndex−1]` (sender must be the executor); inner group `[MBR forward to token (if any)] [token.mtx_pay(op, auth, open_payee = Txn.Sender)]`; event `RelayFeePaid`.

- [ ] **Step 1: Failing tests:** `test_relay_open_mode_pays_lane`, `test_relay_bound_payee`, `test_target_failure_rejects_group`, `test_algorand_router_bound_pay_refused_direct`, `test_target_not_by_executor_refused`, `test_clearstate_target_refused`, `test_missing_app_refused`, `test_target_relayfee_refused`, `test_payee_executor_refused`, `test_executor_rejects_rekey_close_fee`, `test_executor_without_relay_next_rejected`, `test_target_pay_naming_router_fails` (sender ≠ router), `test_lane_transfer_as_target_refused` and `test_executor_transfer_moves_nothing`, `test_executor_address_matches_offchain_derivation`, `test_relay_ref_vectors`, `test_router_holds_nothing_after_relay`, `test_inner_txns_never_rekey_or_close` (every inner transaction of every app in the suite has `RekeyTo` / `CloseRemainderTo` / `AssetCloseTo` zero).
- [ ] **Step 2:** `scripts/capped smartcontracts/scripts/test.sh algorand` — FAIL.
- [ ] **Step 3: Implement** per §4.8.
- [ ] **Step 4:** Same command — PASS.
- [ ] **Step 5: Commit** `near-algorand T15: Algorand relay-fee router + executor LogicSig`.

### Task 16: `scaas-node` NEAR adapter (§5; R1, R5, R10)

**Files:**
- Create: `scaas-node/src/adapters/near.rs`
- Modify: `scaas-node/src/adapter.rs` (`Family::Near`, `"near"`), `scaas-node/src/adapters/mod.rs` (`build`, `example_config_builds_every_family` set), `scaas-node/src/keys.rs` (`"near" => (Curve::Ed25519, "m/44'/397'/0'/0'/{i}'")`), `scaas-node/src/addresses.rs` (`"near"`: lower-case named or 64-hex implicit, `canonical`), `scaas-node/node.example.toml` (a `family = "near"` chain)

**Interfaces:**
- Consumes: metatx-split T17 `max_pay_meta_bytes`; Task 3 vectors; the Task 5–10 Borsh entries and `*_check` views.
- Produces: `NearAdapter::new(cfg: &ChainCfg, signers: &[LocalSigner]) -> Result<Self>`; `RelayFeePolicy::from_cfg(cfg, …)` (`params.relay_fee = { router, executor, min_amount }`, startup error on a malformed or mismatching value, as Aptos); `pub fn entry(policy: &RelayFeePolicy, op: &MetaOp, o: &Value) -> Result<Entry>` with `Entry::{Pay, PayMeta { salt, meta }, FeeWrapper { entry: String, args: Vec<u8> }, FeeRouter { target, method, args, target_gas, target_deposit }}`; job `op.kind` ∈ {none, `pay_meta`, `relay_fee`}, relay fee `op.extra.call` hex + `op.extra.route` ∈ {`wrapper`, `router`} (+ `target_gas`, `target_deposit` decimal strings); any other kind refused.

- [ ] **Step 1: Failing tests:** `lane_path_near` (exact path string for i = 0, 1), `near_metaop_decode_vectors`, `near_pay_meta_job_checks_commitment`, `near_relay_fee_job_checks_ref` (wrapper and router), `relay_fee_target_router_or_executor_refused`, `relay_fee_target_without_code_refused` (`view_code` empty), `unknown_job_kind_is_refused`, `quote_covers_gas_and_storage_needed` (fee ≥ pinned gas × node price + `storage_needed` + `target_deposit`), `deposit_equals_storage_needed_plus_nep_yocto`, `start_check_genesis_mismatch_errors`, `start_check_access_key_present_halts`, `start_check_lane_unregistered_errors`, `escrow_tracking_times_out_after_deadline`, `near_amount_above_2_pow_53_round_trips` (amount 2^127 + 1 survives decode → `*_check` args → submit args), proptest `near_jobs_never_panic` (job, RPC and event bytes).
- [ ] **Step 2:** `cd scaas-node && ../scripts/capped cargo test -j2 adapters::near` — FAIL.
- [ ] **Step 3: Implement** per §5 NEAR column: Borsh transaction + ed25519 lane signature hand-encoded; sequence = the lane access key's nonce; simulate = the entry's `*_check` view, gas = pinned per-job constants; finality `final`; events = NEP-297 logs of receipts executed on configured contracts in final blocks.
- [ ] **Step 4:** PASS, whole crate.
- [ ] **Step 5: Commit** `near-algorand T16: scaas-node NEAR adapter`.

### Task 17: `scaas-node` Algorand adapter (§5; R5, R10)

**Files:**
- Create: `scaas-node/src/adapters/algorand.rs`
- Modify: `scaas-node/src/adapter.rs` (`Family::Algorand`), `scaas-node/src/adapters/mod.rs`, `scaas-node/src/keys.rs` (`"algorand" => (Curve::Ed25519, "m/44'/283'/0'/0'/{i}'")`), `scaas-node/src/addresses.rs` (58-char base32 with checksum), `scaas-node/node.example.toml`

**Interfaces:**
- Consumes: `smartcontracts/algorand/artifacts.json` (`include_str!`), Task 3 vectors, Task 11–15 ABI.
- Produces: `AlgorandAdapter::new(cfg, signers) -> Result<Self>`; params `account_app`, `mandate_app`, `dex_app`, `relayfee_app` (u64), tokens = app ids; `entry(…) -> Result<Entry>` with `Entry::{Pay, PayMeta, Fee { target_app: u64, args: Vec<Vec<u8>> }}`; job `op.extra.call` = the router `call` bytes, resource references in `op.extra.{accounts,apps,boxes}`.

- [ ] **Step 1: Failing tests:** `lane_path_algorand`, `algorand_metaop_decode_vectors`, `algorand_pay_meta_job_checks_commitment` (cap = `MAX_PAY_META_BYTES` of Task 11's log, below `max_pay_meta_bytes`), `algorand_relay_fee_job_checks_ref`, `relay_fee_target_app_missing_or_clearstate_refused`, `group_has_exact_mbr_payment_and_budget_calls`, `executor_address_matches_contract`, `start_check_approval_hash_mismatch_halts`, `start_check_genesis_mismatch_errors`, `start_check_lane_below_min_balance_errors`, `algorand_last_valid_within_valid_until` (`LastValid` ≤ last round whose estimated time ≤ `valid_until`, round time read from algod, never assumed), `unknown_job_kind_is_refused`, proptest `algorand_jobs_never_panic`.
- [ ] **Step 2:** `../scripts/capped cargo test -j2 adapters::algorand` — FAIL.
- [ ] **Step 3: Implement** per §5 Algorand column: canonical msgpack + `"TX"` signature hand-encoded; simulate = algod `simulate`; events = ARC-28 logs from algod blocks; one-round finality.
- [ ] **Step 4:** PASS, whole crate.
- [ ] **Step 5: Commit** `near-algorand T17: scaas-node Algorand adapter`.

### Task 18: Clients — `clientkeys`, `ua-rs`, `ua-qt` (§6; R9)

**Files:**
- Create: `clients/clientkeys/src/{near.js,algorand.js}`, `clients/clientkeys/test/{near.test.js,algorand.test.js}`, `clients/ua-rs/src/{near.rs,algorand.rs}`
- Modify: `clients/ua-rs/src/lib.rs` (modules), `clients/ua-qt/src/ua_kinds.rs`, `clients/ua-qt/tests/tst_ua.qml`

**Interfaces:**
- Consumes: Task 3 vectors; metatx-split T18 `scaas_ua::{meta_pay_id, pay_lane}`.
- Produces: `near.js` / `algorand.js` `encodeMetaOp(op) -> Uint8Array`, `digest(op)`, `signText(digest) -> string`, `nep413Hash(text, recipient, nonce)` (NEAR) / `signBytes(text)` (Algorand), `passkeyAssertion(digest, cred)`, `relayRef(network, target, call, salt)`, `buildPayMeta(op, salt, meta)` (throws `PayMetaMismatch` unless `pay_ref == metaPayId(salt, meta)`), `buildRelayFee(entryOrTarget, payOp)` (open mode, one prompt object with both intents), `nativeId(accountId)` (NEAR), `keyOpFanOut(keyOp, tokens) -> MetaOp[]` (NEAR: one op per held token), `send` throws `NativeToUa` for a native send to a UA id (NET-ALL-21); `scaas_ua::near::{metaop_digest(op: &[u8]) -> [u8;32], relay_ref(network: &[u8;32], target: &[u8], call: &[u8], salt: &[u8;32]) -> [u8;32], native_id(account: &str) -> Result<[u8;32]>}`, `scaas_ua::algorand::{metaop_digest, relay_ref, address_to_key(addr: &str) -> Result<[u8;32]>}`; QML `UaKinds.nearDigest(hex)`, `nearRelayRef(…)`, `algorandDigest(hex)`, `algorandRelayRef(…)` (hex strings).

- [ ] **Step 1: Failing tests:** `near vectors` / `algorand vectors` (every row of the family file), `refuses pay-meta mismatch`, `relay fee prompt carries both intents`, `refuses native send to a UA id`, `near key op fans out to every held token`; ua-rs `near_vectors`, `algorand_vectors`; `tst_ua.qml` cases for the four invokables.
- [ ] **Step 2:** `cd clients/clientkeys && ../../scripts/capped npm test`; `cd clients/ua-rs && ../../scripts/capped cargo test -j2`; ua-qt as metatx-split Task 18 Step 2 — FAIL.
- [ ] **Step 3: Implement** the Produces list (noble / `sha2` / `sha3`, no new dependency).
- [ ] **Step 4:** The Step 2 commands — all PASS.
- [ ] **Step 5: Commit** `near-algorand T18: clients — NEAR + Algorand (clientkeys, ua-rs, ua-qt)`.

### Task 19: NEAR keyless deploy, devnet, node e2e (§3.7, §3.9, §7; R10, R11)

**Files:**
- Create: `smartcontracts/near/scripts/deploy.sh`, `scaas-node/tests/e2e_near.rs`
- Modify: `smartcontracts/scripts/{deploy.sh,devnet.sh}` (`near`)

**Interfaces:**
- Produces: `deploy.sh near <rpc-url>`: deploys and initialises token(s), dex, relayfee, relayexec, registers every lane on every token (`storage_deposit`), then deletes every access key; fails unless `view_access_key_list` is empty for each; writes `smartcontracts/near/deployments/<genesis-hash>.json`. `e2e_near.rs` (`#[ignore]`) starts `near-sandbox` itself under the same capped run.

- [ ] **Step 1: Failing tests:** `deploy_gate_fails_with_a_key_left`; e2e `near_pay_relay_finalize`, `near_pay_meta_job`, `near_relay_fee_wrapper_job`, `near_router_release`, `near_router_refund`, `near_router_timeout`, `near_events_include_native_ft_transfer`, `near_lanes_do_not_block_each_other`.
- [ ] **Step 2:** `cd scaas-node && ../scripts/capped cargo test -j2 --test e2e_near -- --ignored` — FAIL.
- [ ] **Step 3: Implement** `deploy.sh near` and the e2e (fake Odoo as `e2e_aptos.rs`).
- [ ] **Step 4:** Same command — PASS; log `smartcontracts/near/runs/2026-10-28-near-e2e.txt`.
- [ ] **Step 5: Commit** `near-algorand T19: NEAR keyless deploy + node e2e on near-sandbox`.

### Task 20: Algorand deploy, devnet, node e2e (§4.9, §7; R10, R11)

**Files:**
- Create: `smartcontracts/algorand/scripts/deploy.py`, `scaas-node/tests/e2e_algorand.rs`
- Modify: `smartcontracts/scripts/deploy.sh` (`algorand`)

**Interfaces:**
- Produces: `deploy.sh algorand <algod-url>`: creates account, relayfee, token(s), mandate, dex in that order; fails unless each deployed approval program's `sha512_256` equals `artifacts.json`; writes `smartcontracts/algorand/deployments/<genesis-hash>.json`. `e2e_algorand.rs` (`#[ignore]`, needs `devnet.sh algorand up`).

- [ ] **Step 1: Failing tests:** `deploy_gate_fails_on_hash_mismatch` (an update-accepting approval program); e2e `algorand_pay_relay_finalize`, `algorand_pay_meta_job`, `algorand_relay_fee_job` (target = an `account` key op and a third-party fixture app), `algorand_events_ingested`.
- [ ] **Step 2:** `scripts/capped smartcontracts/scripts/devnet.sh algorand up && cd scaas-node && ../scripts/capped cargo test -j2 --test e2e_algorand -- --ignored` — FAIL.
- [ ] **Step 3: Implement** `deploy.py` and the e2e (fake Odoo as `e2e_aptos.rs`).
- [ ] **Step 4:** Same command — PASS; `devnet.sh algorand down`; log `smartcontracts/algorand/runs/2026-10-28-algorand-e2e.txt`.
- [ ] **Step 5: Commit** `near-algorand T20: Algorand deploy gate + node e2e on localnet`.

### Task 21: Docs, decisions, TODO (§9)

**Files:**
- Create: `docs/networks/near.md` (NET-NEAR-*), `docs/networks/algorand.md` (NET-ALG-*), both in `aptos.md`'s section order (incl. the wallet-support check of spec §11 — NEP-413 `signMessage`, ARC-60 / ARC-47 sign-bytes — and the NEAR README §11 row "no partial fill", the msig member caps, NET-ALL-03 head-of-line statements, every measured figure with its run log)
- Modify: `docs/networks/README.md` (§1 rows BUILT, the Algorand path `m/44'/283'/0'/0'/i'`, §4, §5, §7, §8, §9, §11, §12), `docs/contracts/metatx.md` (CTR-MTX-26 / -27 family tables, §12 payers), `docs/contracts/accounts.md` (NEAR / Algorand rows of the family table), `docs/decisions.md` (each spec §0 row and each "controller call" of this plan in full, status, commits), `docs/node/job-api.md`, `docs/node/submit-lanes.md`, `scripts/docs_check.py` (`BUDGET` `networks/near.md`: 500, `networks/algorand.md`: 500), `TODO.md`, `HANDOFF.md`

- [ ] **Step 1:** Write every change (no `[estimate]` for a measured figure).
- [ ] **Step 2:** `python3 scripts/test_docs_check.py && python3 -I scripts/docs_check.py check` — 0 errors.
- [ ] **Step 3: Commit** `near-algorand T21: docs (near.md, algorand.md, README, metatx, decisions, TODO)`.

### Task 22: Gate steps in metatx-split's resumable runner + CI

**Files:**
- Modify: `smartcontracts/evm/runs/2026-10-27-metatx-split-gates.sh` (metatx-split Task 20; if not yet committed there, rebase onto `metatx-split` once it is), `.github/workflows/ci.yml` (jobs `near`: unit + sandbox; `algorand`: build + unit; header comment lines)

**Interfaces:**
- Consumes: the runner's step contract (`--only <step>`, `GATES_FRESH=1`, `# <step> at commit <sha>` / `rc=<n>`, skip when `rc=0` at the current HEAD with a clean tree, stop at the first failure).
- Produces: new steps `ua-py ua-go ua-cs ua-c ua-cxx ua-dart near algorand e2e-near e2e-algorand` (commands: Task 2 / the ci.yml header; `scripts/capped smartcontracts/scripts/test.sh near|algorand`; the Task 19 / 20 e2e commands with `devnet.sh algorand up` / `down` inside the step); `named-tests` extended with every test name of Tasks 1–20 in its tool's pass form (cargo `test <name> ... ok`, pytest `PASSED`, node `✔ <name>`, ctest).

- [ ] **Step 1:** Add the steps and names.
- [ ] **Step 2: Self-check the guard:** `--only named-tests` with one new name removed from a scratch copy of the `near` log (`NAMED_TESTS_LOG_DIR`) exits non-zero.
- [ ] **Step 3: Run** the runner. Expected: every step `rc=0` (the forge-at-set, `sizes` and `docs` steps cover Task 2's EVM change). On a failure: fix in the owning task's files, commit, re-run.
- [ ] **Step 4: Commit** the runner change, CI and logs: `near-algorand T22: NEAR + Algorand gate steps, CI jobs`.
- [ ] **Step 5:** Report to the controller: commits, the Task 1 figure, the measured caps and gas pins, open items of spec §11; ask for the owner's go to merge / push.
