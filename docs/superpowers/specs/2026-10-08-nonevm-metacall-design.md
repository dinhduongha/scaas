# Non-EVM families: a generic signed call and a typed transfer, per VM

**Status:** DRAFT rev 3, every owner question answered (§6); to be folded. Provisional ids `NM-n`; real ids are
allocated in `docs/decisions.md` on acceptance (docs/README "Ids").
**Date:** 2026-10-08. **Scope:** Aptos, Sui (Move), Soroban, CosmWasm, TON, Solana. Follows the EVM drafts
[`2026-10-08-metatx-generic-call-design.md`](2026-10-08-metatx-generic-call-design.md) (G1–G10: a generic
`MetaTransaction` for any contract + a typed `MetaTransfer`, no on-chain fee for non-token contracts) and
[`2026-10-07-metatx-generic.md`](../../history/specs/2026-10-07-metatx-generic.md) (`mtx` names, `chain_uid`), which
left this question to a separate draft (TODO §00). Nothing is deployed: changes in place.

## 1. Where the families stand

Every family signs one `MetaOp` v1 field set ([NET-ALL-02](../../networks/README.md#NET-ALL-02) and the `MetaOp` table
of [networks/README.md](../../networks/README.md)) in its own encoding, over a **closed** op set:

| Family | Payload, encoding | Ops | Op selection | Other signed structs | Generic call possible? |
|---|---|---|---|---|---|
| Aptos | `MetaOp`, 309 B BCS, `aptos:signMessage` | pay, (trade reserved), mandate_pay, revoke | `u8` + one entry per op | `KeyOp`, `MandateInit`, DEX `Order`/`Cancel` | no dynamic dispatch, no struct arguments: only a closed switch, or typed entries |
| Sui | `MetaOp` BCS, `signPersonalMessage` | same | `u8` + one entry per op | `KeyOp`, `ForwardOp`, DEX | as Aptos |
| Soroban | the host preimage (`function_name`, `args`) | `pay`, `pay_under_mandate`, `revoke`, `settle`, `cancel`, `add_key`… | function name | none: host auth | **already generic**: `require_auth` on any function; restriction is the missing part ([NET-SOR-04](../../networks/soroban.md#NET-SOR-04)) |
| CosmWasm | sorted JSON, ADR-036, `Relay{payload, auth}` | `"pay"`, `"trade"`, `"revoke"` | op string | mandate JSON (`scaas.mandate.v1`) | an inner `ExecuteMsg` matched internally (a self-message would lose the subject as sender) |
| TON | `MetaOp` cell in `SignedOp`, `signData` | pay, trade, mandate_pay, revoke, set_key | `u8` in one message | `MandatePay` | the wallet can interpret allowlisted body opcodes; nothing is atomic across contracts |
| Solana | `MetaOp` 336 B LE | pay, (trade reserved), mandate_pay, revoke | `u8` + one instruction per op | `KeyOp`, `MandateInit`, close, DEX | an inner discriminator matched internally; accounts declared up front, fixed write-sets ([NET-SOL-04](../../networks/solana.md#NET-SOL-04)) |

No relayer fee anywhere (the lane pays native gas); per-contract `(subject, lane) → nonce` (Soroban: host nonce +
`(from, pay_ref)` once); no entry point named `mtx…` ([CTR-MTX-21](../../contracts/metatx.md#CTR-MTX-21) keeps the op
names). A third-party SCaaS contract — the owner's family-tree example — has no way to accept a signed call today.

## 2. Principle: verify generically, dispatch statically

A dynamic call-by-selector (the EVM self-call) does not exist in Move and costs a fixed write-set on Solana. The
generic part every VM can share is **verification**: one library per family that checks a signed `MetaCall` —
domain, expiry, relayer binding, lane nonce, signature (key, passkey, account) — and returns the authorised subject.
Each allowlisted function stays a **typed entry** of its own contract that calls the library with its own name and the
hash of its own arguments. The allowlist is the set of entries that call the verifier; a contract adds a gasless
function by adding one entry, with no change to the library.

## 3. Design

### NM-1 — Two signed kinds, as on EVM (G1)

```text
MetaCall      { domain "scaas.metacall.v1",     network, contract, function, args_hash, from, lane, nonce, valid_until, relayer }
MetaTransfer  { domain "scaas.metatransfer.v1", network, contract, asset, from, to, amount, entry_ref, lane, nonce, valid_until, relayer }
```

- `function`: the entry's stable name, per family: Move `module::function`, CosmWasm the `ExecuteMsg` variant,
  TON the internal opcode (`uint32`), Solana the 8-byte Anchor discriminator. `args_hash` = the family hash
  (`sha3_256` Aptos, `blake2b256` Sui, `sha256` CosmWasm/Solana, cell hash TON) of the canonical encoding of the
  entry's arguments **other than** the `MetaCall` itself and the auth.
- `MetaTransfer` is today's `pay` op with `entry_ref` (= `pay_ref`; 0 = a plain transfer, a new shape where the family
  allows it). It keeps the typed fields wallets and the indexers read.
- `network` = the chain profile's `chain_uid` where the runtime exposes one (Solana genesis hash, Soroban network id)
  and the profile constant elsewhere ([NET-ALL-22](../../networks/README.md#NET-ALL-22)).
- No fee fields: off EVM the lane pays native gas (G2 (i)); a family that later charges a token fee adds it to
  `MetaTransfer` only.
- One lane space per contract for both kinds; `MetaOp` v1 and its `op` byte are retired.

### NM-2 — Per family

| Family | Library | Generic entry form | `MetaTransfer` entry |
|---|---|---|---|
| Aptos | `scaas::metacall::verify(account_root, call_bytes, auth, function, args_hash): address` (a `public` Move function; other packages call it) | each allowlisted function `mtx_<name>(lane_signer, from, args…, nonce, lane, valid_until, relayer, auth)` rebuilds `MetaCall` from its typed arguments (as `relay_pay` does today) and calls `verify` | `mtx_transfer` (replaces `relay_pay`) |
| Sui | `scaas::metacall::verify` (same; `public`, generic over the caller's `Account<T>`) | same | `mtx_transfer<T>` |
| Soroban | none: the host verifies; `__check_auth` of `scaas-account` gains **context checks** (the allowlist of `(contract, function)` per key, NET-SOR-04 seam) | the function itself, `from.require_auth_for_args(args)`; named `mtx_<name>` | `mtx_transfer` / `mtx_pay` |
| CosmWasm | `scaas-metacall` crate: `verify(deps, env, info, payload, auth) -> Addr` | `ExecuteMsg::MtxExecute{payload, auth}`, `payload.msg` = the inner allowlisted message as JSON; the contract matches it in its own `execute` with `from` from `verify` (internal dispatch, never a self-message) | `ExecuteMsg::MtxTransfer{payload, auth}` (replaces `Relay`) |
| TON | a Tact trait `MetaCallVerifier` | `MtxExecute{call: Cell, auth: Cell, body: Cell}`: the contract checks `hash(body) == args_hash`, then dispatches `body`'s opcode over its allowlist | `MtxTransfer` (replaces `SignedOp` op pay) |
| Solana | `scaas-metacall` crate (instruction-sysvar signature check, lane PDA) | one instruction per allowlisted function, `mtx_<name>`, each with its fixed accounts; the library checks `function` = its own discriminator | `mtx_transfer` (replaces `relay_pay`) |

Names follow `mtx` in each family's case convention (`mtx_` snake case in Move, Soroban, Solana; `Mtx` Pascal case for
CosmWasm `ExecuteMsg` variants and TON messages) — Q1.

### NM-3 — What moves onto `MetaCall`

As on EVM (G3): mandate pay and revoke, key management (`KeyOp`, `set_key`) and mandate open/close become `MetaCall`
entries of their contracts; the account signs as itself where its keys have no address of their own (G9). DEX orders
keep their own `Order`/`Cancel` structs, as EVM keeps `TradeOrder` ([CTR-DEX-13](../../contracts/dex.md#CTR-DEX-13)).
The reserved `trade` op disappears (Cosmos and TON settle DEX legs through their DEX's order structs).

### NM-4 — A third-party contract

The family-tree contract on Aptos: `public entry fun mtx_add_person(lane: &signer, from: address, parent: u64, data:
vector<u8>, nonce: u64, lane_id: vector<u8>, valid_until: u64, relayer: address, auth: Auth)` →
`let who = metacall::verify(…, b"family::add_person", sha3_256(bcs(parent, data)))`, then the usual body with `who` as
the caller. The relayer lane pays gas. The same shape on every family: one typed entry, one call into the library.

### NM-5 — Parity with EVM (owner Q4)

The typed path offers what EVM offers (GC-5 of [the EVM draft](2026-10-08-metatx-generic-call-design.md)), in each family's form:

| EVM | Non-EVM | Notes |
|---|---|---|
| `mtxTransfer` | `mtx_transfer` / `MtxTransfer` | `MetaTransfer{entry_ref: 0}`; a transfer without reference becomes possible everywhere |
| `mtxPay` | `mtx_pay` / `MtxPay` | `entry_ref = payId`, lane derived on chain as `H("scaas.pay.lane" ‖ payId)`, `nonce = 0` (today's `relay_pay` uses a client-chosen random lane) |
| `mtxExecuteTransfer` | `mtx_execute_transfer` / `MtxExecuteTransfer` | `MetaTransfer` on a client-chosen lane; on Move the struct travels as typed arguments (entry functions take no structs) |
| `mtxBatchTransfer`, `mtxBatch` | native multi-message transactions where they exist (Cosmos messages, Solana instructions, Sui PTB commands, TON internal messages from one lane); Aptos gets `mtx_batch_transfer` with parallel vectors (one entry per transaction) | atomic per transaction as on EVM |
| `mtxTransferWithFee`, `mtxExecuteWithFee`, `mtxPayReceiverFee` | none while non-EVM tokens charge no relayer fee (G2) | added with a token fee, if one is ever specified |

## 4. Wallet display

`MetaCall` is shown as `function` + decoded arguments by the app and `clientkeys`, which hold each contract's
allowlist (as EVM `mtxSelectors()`); wallets that sign raw text (Aptos `signMessage`, Solana OCMS, TON `signData`)
show the domain line and the digest, as today. `MetaTransfer` keeps the typed text line that NET-ALL-23 asks for
(amount, asset, recipient, reference).

## 5. Changes to current rules (on acceptance)

| Rule | Change |
|---|---|
| [NET-ALL-02](../../networks/README.md#NET-ALL-02), the `MetaOp` table | `MetaCall` + `MetaTransfer`; `MetaOp` v1 retired |
| [CTR-MTX-21](../../contracts/metatx.md#CTR-MTX-21) | non-EVM entry names get the `mtx` prefix in family case (Q1) |
| per-family docs (`networks/{aptos,sui,soroban,cosmos,ton,solana}.md`) | NM-2/NM-3 entries; `KeyOp`, mandate structs → `MetaCall` |
| [NET-SOR-04](../../networks/soroban.md#NET-SOR-04) | context allowlist per key becomes required |
| vectors | `metacall`/`metatransfer` vectors per family replace the `MetaOp` vectors |
| node | adapters build both kinds; call table rows per `function` ([NODE-JOB-20](../../node/job-api.md#NODE-JOB-20)) |
| `TODO.md` | new stream per family (immutable programs ⇒ new deploys, [CTR-GEN-02](../../contracts/README.md#CTR-GEN-02)) |

## 6. Open questions for the owner

| # | Question | Recommendation |
|---|---|---|
| Q1 | Rename non-EVM signed entry points with the `mtx` prefix (in family case), reversing the "keep op names" line of CTR-MTX-21? | **answered: yes** |
| Q2 | Generic verification + typed entries (NM-2) instead of one dispatching entry? | **answered: OK** |
| Q3 | Move key management and mandate structs onto `MetaCall` now (NM-3)? | **answered: yes, `MetaCall`** (`KeyOp` is a SCaaS struct, `"scaas.keyop.v1"`, not a chain standard; native key rotation — Aptos `rotate_authentication_key` — is untouched): `mtx_add_key`, `mtx_remove_key`, `mtx_set_guardian`, … |
| Q4 | `MetaTransfer` with `entry_ref = 0` as a plain transfer off EVM (today only `pay` exists)? | **answered: do the EVM equivalent** (NM-5) |

## 7. Revision history

| Rev | Date | What |
|---|---|---|
| 1 | 2026-10-08 | First draft from the per-family survey of the current docs |
| 2 | 2026-10-08 | Owner: Q1 yes, Q2 OK, Q4 EVM parity (NM-5) |
| 3 | 2026-10-08 | Owner Q3: `KeyOp` and the mandate structs become `MetaCall` entries; no open question left |
