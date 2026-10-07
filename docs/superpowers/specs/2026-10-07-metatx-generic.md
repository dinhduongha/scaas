# Meta-transactions: generic self-call, `mtx` names, `chain_uid` in every token domain

**Status:** DRAFT for owner review — nothing in the component docs or the code changes until it is accepted.
Provisional ids `MG-n`; real ids are allocated in `docs/decisions.md` on acceptance (docs/README "Ids").
**Date:** 2026-10-07. **Scope:** EVM and Hedera tokens (today `ERC20MetaTx`/`MetaToken` and `MetaTxCore`/`MetaTokenBase`
with the three tiers — folded into one base by MG-9 — and `ZetherMetaTx`), the DEX settlement (`OrderBookDex`,
`MetaTxDex`), the EVM signed entry points of `MandateWallet`, `SubjectAccount` and `ZetherToken`,
and what the node, clients and the docs must change with them. Nothing is deployed anywhere, so the design changes in
place: no version coexistence, no migration.

## 1. Why

The owner's ruling of 2026-08-31 (`research/_USER-DECISIONS.md` §24) removed the forwarder, `feeToken` and
`innerGasLimit`, kept `mode`, and asked for an explicit `to`/`value`/`data` instead of an `op` code plus opaque
arguments. It did **not** restrict `data` to a fixed set of operations. The implementation that followed did:
`executeMetaTransaction` accepts only empty `data` (transfer), `pay(bytes32)`, `trade(address,uint256,address)`,
`approve(address,uint256)` and, on v2 tiers, `unwrap(…)` (Zether adds `OP_ZTRANSFER`/`OP_ZBURN`); any other selector
reverts `MetaTxUnknownOp` (`MetaToken.sol:147-194`). Functions such as `wrap`, `burn`, `addReserve` or the rate-admin
calls cannot be made gasless at all. The README "How the design evolved" also misreads the prototype lesson: the
prototype's flaw was `to.call(data)` — a call **out** to another contract, where the callee sees the token as
`msg.sender` — not the idea of executing calldata.

The same session also showed that two token v1/v2 domains lack `chain_uid`, and that meta-transaction entry points
have no common naming.

## 2. Owner answers (2026-10-07)

| # | Question | Answer |
|---|---|---|
| A1 | "Execute any function with calldata": which functions? | Functions of **the token itself** (a self-call), not of other contracts — no forwarder |
| A2 | Allowlist? | A fixed **per-implementation selector allowlist** (recommended option chosen with A1) |
| A3 | Names | Every meta-transaction entry point starts with `mtx`; keep `executeMetaTransaction` as an alias (the EIP-1776 name, for outside tools) |
| A4 | Compatibility | None needed — nothing is deployed |
| A5 | `approve` | **Only a contract may call `approve`** (to let it call another contract); an EOA never approves a SCaaS token, in any form. Long-standing owner rule, set after a security hole the owner pointed out; the current code checks only the spender and also offers an `approve` meta-tx op to EOAs — both are wrong |
| A6 | External tokens | The rule covers SCaaS tokens. An EOA may still approve our wrapper on an outside token (e.g. USDT) to wrap it |
| A7 | DEX without maker allowances | **Both paths** (MG-8): token-verified signed orders for resting orders, and pull-into-the-DEX-then-refund legs for immediate orders — each in one call with one taker and many makers, as in the owner's `ERC1776Dex` |
| A8 | One base | Fold everything into one base named **`ERC20MetaTx`**; delete the v1 line |

Open questions: §7 (defaults applied, owner may override).

## 3. Design

### MG-1 — `mtxExecute`: the token calls itself with the signer's calldata

```solidity
function mtxExecute(MetaTransaction calldata m, bytes calldata signature) external returns (bytes memory);
function executeMetaTransaction(MetaTransaction calldata m, bytes calldata signature) external returns (bytes memory); // alias
```

Pipeline (one transaction, all or nothing):

1. Check `validUntil`, the `(from, batch)` nonce, `mode` (constraint flags; fee mode `NONE`/`PERCENT`/`FIXED`), the
   relayer binding (`MODE_RESTRICT_RELAYER` ⇒ `msg.sender == relayer`) and the fee-recipient binding, exactly as today.
2. Verify the signature over the EIP-712 digest: EOA (`ECDSA.tryRecover`, low-s), ERC-1271 for contract accounts
   (and, when the UA ledger lands, the registry for derived kinds).
3. Bump the nonce.
4. If `data` is empty: transfer `value` from `from` to `to` (the plain transfer, unchanged).
5. Else: require `bytes4(data)` ∈ the implementation's **selector allowlist** (MG-2), set a transient flag
   `_mtxSender = from` (EIP-1153), and call `address(this).call(data)`; clear the flag.
6. Take the fee from `from` in this token (same `FeePolicy`, cap 1 %).
7. If step 5 failed, **revert the whole transaction** with the inner error. No error is ever swallowed: the user never
   pays for an operation that did not happen; the relayer, which simulates before broadcasting, bears gas only for a
   transaction that changed state between its simulation and its inclusion.

`_msgSender()` returns `_mtxSender` when `msg.sender == address(this)` **and** the transient flag is set, else
`msg.sender`. The flag, not appended calldata, carries the signer: no function can be tricked by 20 trailing bytes,
and a self-call that does not come from step 5 sees `msg.sender` as usual. OpenZeppelin `ERC20` already routes every
balance and allowance operation through `_msgSender()`, so `transfer`, `approve`, `burn` and the rest act for the
signer without new code. EIP-1153 is already a dependency (`ReentrancyGuardTransient` in the DEX).

This replaces the hand-written op dispatch (`_checkOp`/`_executeOp`, `OP_PAY`, `OP_TRADE`, `OP_APPROVE`,
`OP_UNWRAP`): `pay` and `unwrap` become ordinary public functions of the token that also work through `mtxExecute`;
the `trade` op is replaced by MG-8; the EOA `approve` op disappears (MG-7).

### MG-2 — Selector allowlist per implementation

Each implementation declares, as constants, the selectors `mtxExecute` may call. The list is part of the immutable
code, published by a view (`mtxSelectors()`) and pinned by a test. Proposed lists:

| Implementation | Allowed through `mtxExecute` |
|---|---|
| every token | `transfer`, `pay(address to, uint256 amount, bytes32 entryRef)`, `burn` (where the tier has it), `approve` **only when the signer is a contract account** (MG-7) |
| wrapper tiers | `wrap`, `unwrap`, `addReserve` |
| roles fixed at creation | `proposeRate`, `cancelRate`, `executeRate`, `renounceRateAdmin`, `disableWrap`, `renounceMinter`, `mint` (role holders sign; the role check runs on `_msgSender()`) |
| `ZetherToken` | `fund`, `transferConfidential`, `burn` — each still verifies its own proof and Zether authorization; `from` is the outer-fee payer, bound by the envelope binding (today's `OP_ZTRANSFER`/`OP_ZBURN`). `rollOver…` and `setRollOverMode` keep their own signed entry points (MG-3) |

Never allowed: `mtxExecute`/`executeMetaTransaction` themselves (no nesting), `initialize`, views, and any function
that itself performs `address(this).call` with caller data. `transferFrom` stays callable only by contracts
(CTR-TOK-01), checked on `_msgSender()`, so it is effectively not reachable through `mtxExecute` from a person.

### MG-3 — The `mtx` names

Every external function whose authority comes from a subject's signature (a relayer only submits) starts with `mtx`:

| Contract | Today | Target |
|---|---|---|
| tokens | `executeMetaTransaction` | `mtxExecute` (+ alias `executeMetaTransaction`) |
| tokens | `executeMetaTransactionWithFee` | `mtxExecuteWithFee` |
| tokens | `cancelMetaNonce` (a direct call by the owner) | `mtxCancelNonce` |
| tokens | `metaNonce`, `metaTxDigest` (views) | `mtxNonce`, `mtxDigest` |
| tokens | `mtxTransfer`, `mtxTransferWithFee`, `mtxPay`, `mtxUnwrap`, `mtxUnwrapWithFee`, `mtxBatch` | unchanged (typed shortcuts that build the same struct and run MG-1) |
| `ZetherToken` | `rollOverSigned`, `setRollOverMode` (signed) | `mtxRollOver`, `mtxSetRollOverMode` |
| `MandateWallet` | `payUnderMandate`, `revokeWithSig`, `executeAsOwner` | `mtxPayUnderMandate`, `mtxRevoke`, `mtxExecuteAsOwner` |
| `SubjectAccount` | `executeAsOwner` | `mtxExecuteAsOwner` |

The EIP-712 type names (`MetaTransaction`, `PayUnderMandate`, `OwnerCall`, …) are what the user signs and are named
for what is signed, not for the entry point; they stay as they are unless §7 changes the struct. Non-EVM families
keep their op names (`relay`, `Relay`, `SignedOp`) — their equivalent of this rule is a separate question (§7, Q4).

### MG-4 — `chain_uid` in every token domain

Every token's EIP-712 domain is `(name, version, chainId, verifyingContract = the token, salt = chain_uid)`.
`chain_uid` is the chain's genesis block hash (NET-ALL-22): `chainId` is self-declared and not unique (9000 was also
Evmos Testnet; forks and re-created PoA chains keep their id), and a CREATE2 clone can have the same address on two
chains, so `chainId` plus address alone does not stop a replay between two such chains.

- **Where it lives:** a constructor immutable of each **implementation**, deployed per chain. Clones run the
  implementation's code through `DELEGATECALL`, so every clone uses it with no storage and no `initialize`
  argument, and cannot declare another value. Because it is a constructor argument, the implementation address — and
  with it every CREATE2 clone address — differs per chain.
- **Who makes it right:** the deploy script reads the genesis hash from the RPC; the deploy gate and the node, at
  chain activation and at every start, require implementation `chainUid()` = the RPC's genesis hash = the chain
  profile, and refuse a mismatch. A contract cannot read its own genesis hash after block 256, so this is checked
  off chain; a wrong value only makes correct signatures fail (fail-safe).
- **Who fills it in when signing:** the software that builds the signing request — our app, portal or clientkeys —
  puts `chain_uid` into `domain.salt`, from the chain profile (works offline) or from the token's `eip712Domain()`
  (ERC-5267, read once and cached). Wallets such as MetaMask do not look it up: they sign the domain they are given
  and check only `chainId`. clientkeys additionally refuses a `salt` that differs from the profile.
- **What protects:** the contract, not the wallet — a token on chain B computes its digest with B's `chain_uid`, so a
  signature made for chain A reverts there, whichever wallet produced it.

### MG-5 — Fees with a generic call

`FIXED` and `NONE` work for any call. `PERCENT` is computed on the signed `value`. Proposal: when `data` is not empty,
`value` is the amount the signer declares as the fee basis and must equal the call's own amount for the selectors that
move value (`transfer`, `pay`, `unwrap`, `wrap`); for other selectors `PERCENT` is refused (`FIXED` or `NONE` only).

### MG-6 — What else changes

| Area | Change |
|---|---|
| Node | Pricing, breaker and display read the selector from `data`; a per-implementation selector table replaces the fixed op list; the call table (NODE-JOB-01/19) uses the `mtx` names; `chain_uid` checked against `chainUid()` |
| Clients | clientkeys and the app encode `mtxExecute` calldata, decode `data` to show "what you sign" (selector + arguments), fill `domain.salt` |
| ERP connector example | encoders and selectors follow the new names |
| Vectors | new KATs for the domain with `salt` and for `mtxExecute` calldata |
| Docs | `contracts/metatx.md` (pipeline, ops, names), CTR-MTX-15/16 rationale ("fee ⇔ operation" becomes "all or nothing, never swallowed"), `contracts/token-wrappers.md` (CTR-TOK-01: caller of `approve` must be a contract; factory and tiers after MG-9), `contracts/dex.md` (MG-8), `contracts/mandates.md`, `contracts/accounts.md`, `contracts/zether.md`, `node/job-api.md`, `networks/README.md`, README §6/§7/§14 |

### MG-7 — Only a contract calls `approve`

In every SCaaS token `approve` (and any allowance-granting path) requires the **caller** — `_msgSender()` — to be a
contract, as well as the spender; `transferFrom` stays callable only by a contract. "Contract" uses the explicit
rules of CTR-TOK-01: an account with no code, a contract inside its constructor and an EIP-7702-delegated EOA are all
treated as EOAs. Consequences:

- An EOA never holds or grants an allowance on a SCaaS token, directly, through `mtxExecute`, or by any permit.
- Contract accounts (`SubjectAccount`, Safe, `MandateWallet`) may approve, typically inside one batched call that
  then uses the allowance.
- Payments never needed allowances (`pay`, `payWithFee`); the DEX stops needing them (MG-8).
- Outside tokens are not ours to enforce: wrapping USDT still needs the holder to approve our wrapper on USDT (A6).

### MG-8 — DEX settlement without maker allowances: two paths

Both paths settle **one taker against many makers in one call**, move no funds through a standing allowance, and
bind each signature to the DEX contract named in it.

**Path A — resting orders (the order book).** The maker signs a `TradeOrder` in the **sell token's** EIP-712 domain
(the "tradable token" of the original `ERC1776Tradeable`):

```solidity
struct TradeOrder {
    address maker;
    address buyToken;     // what the maker wants
    uint256 sellAmount;   // at most this much of this token
    uint256 buyAmount;    // limit price: sellAmount for at least buyAmount
    address dex;          // the only contract that may execute it
    address taker;        // 0 = anyone
    uint256 nonce;        // per maker; cancel by raising minNonce
    uint256 validUntil;
}
function mtxTrade(TradeOrder calldata o, bytes calldata sig, uint256 sellFill, uint256 buyFill, address to) external;
```

The token checks: `msg.sender == o.dex`; signature (EOA or ERC-1271); expiry; `nonce ≥ minNonce[maker]`;
`pulled[orderHash] + sellFill ≤ sellAmount`; the price limit `sellFill · buyAmount ≤ buyFill · sellAmount`; then
moves exactly `sellFill` from the maker to `to` and records it. The DEX, in the same call, pulls the counter leg the
same way from the taker's order (or the taker's signed leg) so that the maker receives `buyFill`; one failing leg
reverts the pair. Partial fills over many settlements work; the DEX never holds funds; the token never moves more
than the order allows.

**Path B — immediate orders (IOC/FOK) and families that cannot keep fill state.** Each party signs an ordinary
meta-transaction `transfer` of its full amount **to the DEX** with `MODE_RESTRICT_RELAYER = dex` (only the DEX can
submit it). The DEX, in one call, runs every leg through `mtxExecute`, matches the taker against the makers at each
maker's price, pays every side, and **refunds every unmatched remainder before returning** — the owner's
`ERC1776Dex.mtxTrade(feeRecipient, taker, count, makers[])` shape. A leg is single-use, so an unmatched remainder is
refunded and needs a new signature to rest. The non-EVM DEXes already follow this shape (two signed legs per pair;
TON through escrow).

`OrderBookDex` keeps its book semantics (price-time priority, limit + IOC/FOK, partial fills in the node's book) and
replaces its `safeTransferFrom(maker, …)` legs with Path A or Path B; the legacy `MetaTxDex` is deleted.

### MG-9 — One base: `ERC20MetaTx`

`MetaTxCore` is renamed **`ERC20MetaTx`** and becomes the only meta-transaction base: MG-1…MG-8 live there. The v1
line — the current `ERC20MetaTx`, `MetaToken`, `HederaMetaToken`, `OpenFactory` — is deleted; issuer tokens use
`NoUnderlyingToken`, 1:1 wrappers use `SingleUnderlyingToken`, and the v2 factory (renamed `OpenFactory`) is the only
factory. `ZetherMetaTx` reuses the same base or a shared library for the envelope, nonce and fee steps instead of a
third copy. One domain version for all tokens.

## 4. Security notes

| Risk | Rule |
|---|---|
| Sender spoofing (the ERC-2771 + multicall class) | The signer travels in a transient flag, never in calldata; `_msgSender()` trusts it only during step 5; no function in a token may read `msg.sender` directly (lint/test); no other self-call path |
| Nesting | `mtxExecute` and its alias are not in any allowlist; the transient flag is set once and a nested set reverts |
| Re-entrancy | `nonReentrant` (transient) on every `mtx…` entry point |
| Role functions made gasless | Allowed only for roles fixed at creation, checked on `_msgSender()`; the signature is the role holder's |
| EOA allowances | `approve` refused unless `_msgSender()` is a contract (MG-7); no EOA `approve` path anywhere |
| DEX legs | `mtxTrade` callable only by `o.dex`; cumulative `pulled[orderHash]` cap and price limit in the token; Path B legs bound to the DEX by `MODE_RESTRICT_RELAYER`, remainders refunded in the same call |
| Opaque `data` in wallets | EIP-712 still shows every field; clients decode `data` against the published allowlist ABI before asking for a signature |

## 5. Not in scope

Calls to other contracts (that is the account layer: `SubjectAccount.execute`, `Safe.execTransaction`); a generic
forwarder; non-EVM families (§7, Q4).

## 6. Work plan after acceptance

1. Allocate ids, fold MG-1…MG-6 into the component docs, update decisions.md (owner: yes) and the README.
2. Contracts: MG-9 first (one base `ERC20MetaTx`, delete the v1 line), then MG-1/MG-2/MG-4/MG-7 in it, MG-8 (`mtxTrade`
   in the tokens, `OrderBookDex` Path A/B, delete `MetaTxDex`), `ZetherMetaTx` on the shared base, then MG-3 renames in
   `MandateWallet`, `SubjectAccount`, `ZetherToken`; tests for every allowlisted selector through `mtxExecute`,
   spoofing and nesting tests, EOA-approve refusal, DEX one-taker-many-makers on both paths, domain-with-salt KATs.
3. Node, clientkeys, app and the ERP connector follow; vectors regenerated.

## 7. Open questions — defaults applied

The owner said "tiếp tục" (continue) on 2026-10-07 without choosing; the recommendations below are applied as
**defaults** and can still be overridden before the fold.

| # | Question | Default applied |
|---|---|---|
| Q1 | Add `token` (and `chainId`/`chain_uid`) to the signed struct, so a payload names its own chain and contract? | No: the domain already binds them and the node routes by the envelope (`chain_key`, contract) and verifies the digest; a field adds self-description only |
| Q2 | Meaning of `to`/`value` when `data` is not empty (MG-5) | `value` = declared fee basis, equal to the call's amount for value-moving selectors; `to` = declared counterparty, equal to the call's recipient where it has one, else 0 |
| Q3 | The allowlists of MG-2 (role functions included or not) | As proposed |
| Q4b | Path A order fields (MG-8): DEX fee inside the order, `taker` binding, batch/lane instead of a single nonce | Fee ppm in the order (as today), `taker` optional, `minNonce` bulk cancel |
| Q4 | Same rule for non-EVM families (generic op dispatch where the VM allows it; `mtx` names) | Separate draft after this one |
