# Meta-transactions: generic self-call, `mtx` names, `chain_uid` in every domain, token-verified trade orders

**Status:** DRAFT **rev 5** for owner review — nothing in the component docs or the code changes until it is accepted.
Provisional ids `MG-n`; real ids are allocated in `docs/decisions.md` on acceptance (docs/README "Ids").
**Date:** 2026-10-07. **Scope:** EVM and Hedera tokens (today v1 `ERC20MetaTx`/`MetaToken`/`HederaMetaToken`, v2
`MetaTxCore`/`MetaTokenBase` with three tiers, `ZetherMetaTx`/`ZetherToken` — folded into one base by MG-9), the DEX
settlement (`OrderBookDex`, `MetaTxDex`), the EVM signed entry points of `MandateWallet` and `SubjectAccount`, every
EIP-712 domain we deploy, the deploy scripts, and what the node, clients and docs must change with them. Nothing is
deployed anywhere, so the design changes in place: no version coexistence, no migration. Code paths below are relative
to `smartcontracts/evm/src/`.

Rev 2 folded in review 1 (verdict BLOCK: 1 Critical, 9 High, 11 Medium, 9 Low) and three owner inputs of the same day
(A9–A11). Disposition: [§12](#12-review-1-disposition).

## 1. Why

The owner's ruling of 2026-08-31 (`research/_USER-DECISIONS.md` §24) removed the forwarder, `feeToken` and
`innerGasLimit`, kept `mode`, and asked for an explicit `to`/`value`/`data` instead of an `op` code plus opaque
arguments. It did **not** restrict `data` to a fixed set of operations. The implementation that followed did:
`executeMetaTransaction` accepts only empty `data` (transfer), `pay(bytes32)`, `trade(address,uint256,address)`,
`approve(address,uint256)` and, on v2 tiers, the pseudo-op `unwrap(address,address,uint256)` (Zether adds
`OP_ZTRANSFER`/`OP_ZBURN`); any other selector reverts `MetaTxUnknownOp` (v2 `MetaTokenBase.sol:295-330`, v1
`MetaToken.sol:147-194`). `wrap`, `burn`, `addReserve` or Zether `fund` cannot be made gasless at all. The README
"How the design evolved" also misreads the prototype lesson: the prototype's flaw was `to.call(data)` — a call **out**
to another contract, where the callee sees the token as `msg.sender` — not the idea of executing calldata.

The same session showed that token v1/v2 domains lack `chain_uid`, that meta-transaction entry points have no common
naming, and that EOAs can still grant allowances (an `approve` meta-tx op, and spender-only checks).

## 2. Owner answers (2026-10-07, A12–A15 2026-10-08)

| # | Question | Answer |
|---|---|---|
| A1 | "Execute any function with calldata": which functions? | Functions of **the token itself** (a self-call), not of other contracts — no forwarder |
| A2 | Allowlist? | A fixed **per-implementation selector allowlist** |
| A3 | Names | Every meta-transaction entry point starts with `mtx`; keep `executeMetaTransaction` as an alias (the EIP-1776 name, for outside tools) |
| A4 | Compatibility | None needed — nothing is deployed |
| A5 | `approve` | **Only a contract may call `approve`** (to let it call another contract); an EOA never approves a SCaaS token, in any form. The current code checks only the spender and offers an `approve` meta-tx op — both wrong |
| A6 | External tokens | The rule covers SCaaS tokens. An EOA may still approve our wrapper on an outside token (e.g. USDT) to wrap it |
| A7 | DEX without maker allowances | **Both paths** (MG-8): Path A token-verified orders with `pulled[orderHash]` for resting orders; Path B legs pulled into the DEX then refunded for IOC/FOK — each with one taker and many makers per call, as in the owner's `ERC1776Dex` |
| A8 | One base | Fold everything into one base named **`ERC20MetaTx`**; delete the v1 line |
| A9 | Wrapping a **SCaaS** underlying by an EOA (review M6) | **Accepted:** a signature-based wrap, no EOA approve — the wrapper pulls the underlying through the underlying's own signed path and mints in the same call (MG-7b) |
| A10 | `TradeOrder` | **The owner's `MtxTradeOrder` modernized** — one struct for both paths, fields mapped in MG-8.1. Owner correction: `relayer` keeps its meaning (the matching party, 0 = anyone, paid the relayer fee); a separate `dex` (the old `to`) is the settlement contract and the only place funds go (rev 3); the order carries no role and no counterparty field (rev 3) |
| A11 | Deployment | **CREATE2 everywhere:** implementations, factories, registry and DEX are deployed through a deterministic CREATE2 deployer with a fixed salt (MG-4) |
| A12 | `TradeOrder` field names | The old names: `amount`, `receiveToken`, `receiveAmount` (not `sellAmount`/`buyToken`/`buyAmount`) |
| A13 | Minimum fill | Keep `minFill` (the signer's minimum per settlement) **with a protocol floor** `MIN_FILL` = 50 % (the old `MIN_RECEIVE_PERCENTAGE`): effective minimum `max(minFill, ceil(amount/2))`, for **every** order in a settlement, taker and makers alike, to avoid junk fills; `minFill = amount` ⇒ fill-or-kill; the last remainder of a Path A order may close below it. Who is taker or maker is arranged by the node / submitter, not in the order |
| A14 | `destination` | **Accepted** (closes rev 2's OQ6): who receives the proceeds in `receiveToken`; 0 = `from` |
| A15 | Fees | **One** field `fee` (ppm, the old name): the DEX fee rate the signer agrees to pay. No `maxFeePpm`, `relayerFee`, `relayerFeeRecipient`. The DEX collects it and distributes it in the same call per its admin's configuration (relayer share and/or treasury); the admin changes only the split and recipients, never the amount; cap 1 % |

Fixed constraints this revision never weakens: no compatibility text; the token gateway only calls the token itself;
only a contract calls `approve`; `executeMetaTransaction` alias and `mtx` names; one base `ERC20MetaTx`; the DEX on
both paths; `chain_uid` in signing domains. No review fix conflicted with them (two readings are stated in §4).

## 3. Design

### MG-1 — `mtxExecute`: the token calls itself with the signer's calldata

```solidity
function mtxExecute(MetaTransaction calldata m, bytes calldata signature) external returns (bytes memory ret);
function executeMetaTransaction(MetaTransaction calldata m, bytes calldata signature) external returns (bool); // alias
```

The alias runs the same pipeline and returns `true` (the EIP-1776 / `IERC20MetaTx` return type that tender and outside
tools decode); only `mtxExecute` returns the inner call's bytes.

`data` has three shapes:

| `data` | Shape | Runs as |
|---|---|---|
| empty | **transfer** `value` from `from` to `to` | internal `_transfer`, as today |
| `pay(bytes32 entryRef)` (exactly 36 bytes) | **payment** (CTR-MTX-01) — `to`/`value` are payee/amount | internal `_transfer` + `PaymentSettled` with the fee, as today; tender's deposit shape (CTR-TND-01) is unchanged |
| anything else | **self-call** | `address(this).call(data)` under the ticket below; `to` and `value` must be 0 |

Pipeline (one transaction, all or nothing):

1. Relayer binding (`MODE_RESTRICT_RELAYER` ⇒ `msg.sender == relayer`), `validUntil`, `mode`, the `(from, batch)`
   nonce, the fee-recipient binding — as today. Refuse `from == address(this)`.
2. Signature over the EIP-712 digest: EOA (`ECDSA.tryRecover`, low-s) or ERC-1271 `staticcall` with the 50 k/400 k
   gas cap (contract accounts). Derived UAs use the separate `ua*` path (MG-9).
3. Shape check. Transfer/payment: as today (`to ≠ 0`, R132). Self-call: `data.length ≥ 4`; `bytes4(data)` ∈ the
   allowlist (MG-2) else `MtxSelectorNotAllowed(selector)`; `data.length` equals the selector's static ABI length
   where it has one (`MtxDataShape`); `to == 0 && value == 0` (`MtxEnvelopeShape`); the fee mode is allowed by the
   selector's fee class (MG-5).
4. Bump the nonce.
5. Execute. Transfer/payment: take the fee, then transfer (cannot fail after step 3, as today). Self-call: store the
   transient ticket (`_mtxSender = from`, `_mtxTicket = 1`, `_mtxBinding = envelopeBinding(m)`), call
   `address(this).call(data)`, clear all three; if the call failed, **revert with its revert data** (bubbled).
6. Self-call only: take the fee from `from` in this token, **after** the call (so a wrap can pay from minted units).
   A failing fee transfer reverts everything.
7. Emit `MetaTransactionExecuted` (unchanged fields; the selector is in the transaction input).

No error is ever swallowed: the user never pays for an operation that did not happen; the relayer, which simulates
before broadcasting, bears gas only for a transaction whose state changed between simulation and inclusion (the node
breaker of MG-6 covers repeat offenders).

**The ticket (review H1).** One contract-wide transient guard covers every entry point. `nonReentrant` becomes:

```solidity
modifier nonReentrant() {
    if (tload(GUARD) != 0) {
        // the one self-call issued by step 5 may enter, once
        if (msg.sender != address(this) || tload(TICKET) != 1) revert Reentrancy();
        tstore(TICKET, 2);            // consumed: any further entry reverts, whoever calls
        _;
    } else {
        tstore(GUARD, 1); _; tstore(GUARD, 0);
    }
}
```

So `wrap`, `unwrap`, `addReserve`, Zether `fund`/`transferConfidential`/`burn` keep their guard and still run through
`mtxExecute`; a re-entry from an underlying's hook during the self-call reverts (`msg.sender` is the underlying, or
the ticket is spent). Every allowlisted function carries `nonReentrant` (MG-2), so the one entry always consumes the
ticket and no allowlisted function runs with a live one. `mtxBatch` sets a fresh ticket per item.

**The sender (review H2).** `_msgSender()` returns `_mtxSender` when `msg.sender == address(this)` and `_mtxTicket ≠ 0`,
else `msg.sender`. The signer travels in transient storage, never in calldata, so no function can be tricked by 20
trailing bytes, and the only self-call path is step 5. OpenZeppelin `ERC20` already uses `_msgSender()` for
`transfer`/`approve`/`transferFrom`; **our own code does not** — every direct `msg.sender` read is listed in §3.1 with
its treatment. Lint (a test greps the sources): authority and balance owners are read through `_msgSender()`; the
reads that stay `msg.sender` are exactly those named "stays" in §3.1.

Defence in depth: `from ≠ address(this)` (step 1), and `_update` refuses transfers and mints **to** `address(this)`
(tokens stuck at the token's own address were the H2 exploit's fuel).

This replaces the hand-written op dispatch (`_checkOp`/`_executeOp`, `OP_TRADE`, `OP_APPROVE`, `OP_UNWRAP`,
Zether `OP_ZTRANSFER`/`OP_ZBURN` and `relayed*`). The trade op is replaced by MG-8; the EOA `approve` op disappears
(MG-7).

### 3.1 Direct `msg.sender` reads and their treatment

Files that MG-9 deletes (v1 `ERC20MetaTx.sol`, `MetaToken.sol`, `HederaMetaToken.sol`) are not listed. Hedera v2
tiers (`HederaTokensV2.sol`) read none.

| File:line | What | Treatment |
|---|---|---|
| `MetaTxCore.sol:61-62` | `cancelMetaNonce` lane owner | `_msgSender()` (now `cancelNonce`, allowlisted, L3) |
| `MetaTxCore.sol:75-76` | relayer binding | **stays** `msg.sender` (the outer submitter) |
| `MetaTxCore.sol:90` | default fee recipient | **stays** `msg.sender` |
| `MetaTxCore.sol:104` | event `relayer` | **stays** `msg.sender` |
| `MetaTxCore.sol:119` | `transferFrom` caller must be a contract | `_msgSender()` (not allowlisted, so equal to `msg.sender` in practice) |
| `MetaTokenBase.sol:74` | `initialize` factory check | **stays** `msg.sender` |
| `MetaTokenBase.sol:274, 276, 277` | `payWithFee` payer | `_msgSender()` (not allowlisted; uniform rule) |
| `MetaTokenBase.sol:313` | `OP_TRADE` check | deleted with the op |
| `NoUnderlyingToken.sol:49` | `burn` holder | `_msgSender()` |
| `NoUnderlyingToken.sol:53` | minter check | `_msgSender()` (not allowlisted, H4) |
| `SingleUnderlyingToken.sol:179` | `addReserve` event | `_msgSender()` |
| `SingleUnderlyingToken.sol:189-190` | `wrap` mint target / event | `_msgSender()` |
| `SingleUnderlyingToken.sol:200` | `_pull` source of the underlying | `_msgSender()` |
| `SingleUnderlyingToken.sol:210` | `_unwrap` burn source | `_msgSender()` |
| `SingleUnderlyingToken.sol:263` | rate admin check | `_msgSender()` (not allowlisted, H4) |
| `MultiUnderlyingToken.sol:91, 101` | guardian event / check | `_msgSender()` (not allowlisted, H4) |
| `ZetherToken.sol:127` | `initialize` factory check | **stays** `msg.sender` |
| `ZetherToken.sol:190-191` | public `wrap` source / mint | `_msgSender()` |
| `ZetherToken.sol:196` | public `unwrap` burn | `_msgSender()` |
| `ZetherToken.sol:208` | `fund` source | `fund` no longer pulls the underlying (OQ5, MG-7b): it burns `amount · shieldScale` public units from `_msgSender()` |
| `ZetherToken.sol:288, 299` | `OuterFee(msg.sender, …)` in direct calls | `OuterFee` deleted: the outer fee is MG-1 step 6 (H6) |
| `ZetherToken.sol:469, 475, 488` | `relayed*` self-only checks | deleted with `relayed*` (H6) |
| `ZetherToken.sol:589` | `attestTransferAmount` attester | `_msgSender()` (not allowlisted) |
| `ZetherMetaTx.sol:52` | `cancelMetaNonce` | `_msgSender()` (file folded into the base, MG-9) |
| `ZetherMetaTx.sol:59-60, 74, 79` | relayer binding, default fee recipient, event | **stay** `msg.sender` (folded) |
| `ZetherMetaTx.sol:103` | `transferFrom` caller | `_msgSender()` (folded) |
| new `mtxTrade` (MG-8.2) | `msg.sender == o.dex` | **stays** `msg.sender`; not allowlisted |
| new `mtxWrap` (MG-7b) | relayer binding and the `wrapFee` payee (toward the underlying the wrapper is `o.dex`) | **stay** `msg.sender`; not allowlisted |

### MG-2 — Selector allowlist per implementation

Each implementation declares its allowlist as constants: exact selectors (overloads listed one by one, L1), each with
a fee class (MG-5). `mtxSelectors() returns (bytes4[] selectors, uint8[] feeClass, uint8[] amountArg)` publishes it; a
test pins it.

| Implementation | Self-call selector | Fee class |
|---|---|---|
| every token | `cancelNonce(uint256)` | `ABSOLUTE` |
| `NoUnderlyingToken` | `burn(uint256)` | `AMOUNT(0)` |
| `SingleUnderlyingToken` | `wrap(uint256)` | `ABSOLUTE` (fee from minted units) |
| | `unwrap(uint256,address,uint256)` | `AMOUNT(0)` — the 2-argument `unwrap(uint256,address)` is **not** listed: the same intent with a second digest and no `minOut` (review 2 L-2) |
| | `addReserve(address,uint256)` | `ABSOLUTE` |
| `MultiUnderlyingToken` | `wrap(address,uint256)` | `ABSOLUTE` |
| | `unwrap(address,uint256,address,uint256)` | `AMOUNT(1)` |
| | `addReserve(address,uint256)` | `ABSOLUTE` |
| `ZetherToken` | `wrap(uint256)` | `ABSOLUTE` |
| | `unwrap(uint256,address)` (public balance) | `AMOUNT(0)` |
| | `fund(bytes,uint256)` — draws from the public balance (OQ5, MG-7b) | `ABSOLUTE` |
| | `transferConfidential(bytes,bytes,bytes,bytes32)`, `burn(bytes,uint256,address,bytes32,bytes,bytes)` | `ABSOLUTE`; envelope binding via `_mtxBinding` (MG-2.1) |

Transfer and payment are the two built-in shapes of MG-1 (empty `data`, `pay(bytes32)`); the `transfer` selector is
**not** allowlisted, so one transfer has one encoding and one digest (L2). Multi's v1-shaped `wrap(uint256)`/`unwrap`
overrides that always revert are not listed.

**Never allowlisted:** `approve` and `transferFrom` (MG-7, H3, M10 — contract accounts approve and spend through their
own `execute`); every role function — `mint`, `renounceMinter`, `proposeRate`, `cancelRate`, `executeRate`,
`renounceRateAdmin`, `disableWrap`, `renounceGuardian` (H4: role holders act through their own contract, NODE-JOB-01/19;
**this flips rev 1's default Q3**, see OQ1); `transfer`; `payWithFee` (it charges its own fee); `mtxExecute`, its
alias and every other `mtx…` entry (no nesting); `mtxTrade`/`mtxWrap` (`msg.sender` must be a contract other than the
token); `initialize`; views; `attestTransferAmount`; Zether `mtxRollOver`/`mtxSetRollOverMode` (they carry their own
signature, MG-3).

**Every allowlisted function is `nonReentrant`**, `burn(uint256)` and `cancelNonce` included; a test pins it, so a
future selector cannot inherit a live ticket (review 2 L-1).

For selectors with dynamic arguments (Zether) the contract cannot cheaply pin one encoding; the node re-encodes the
decoded arguments and refuses non-canonical `data` before it computes the mesh `intent_id`. A non-canonical duplicate
that reaches the chain is harmless: only the signer can produce a variant (`data` is signed), and the sequential
`(from, batch)` nonce lets only one variant execute.

#### MG-2.1 — Zether through the self-call (review H6)

`transferConfidential` and `burn` compute `binding = (msg.sender == address(this) && _mtxTicket ≠ 0) ?
_mtxBinding : 0`, so the statement tag is `TAG_RELAYED` with the envelope's binding inside `mtxExecute`, and
`TAG_DIRECT` with binding 0 otherwise. A proof lifted from a pending meta-tx therefore fails as a direct call: the
envelope-stripping attack stays closed. The internal `OuterFee` (payer, recipient, amount) and `relayedTransfer`/
`relayedBurn`/`relayedBurnDecoded` are deleted; the outer fee is step 6, `FIXED` absolute or `NONE`. The inner fee
(`confidentialFee` to the beneficiary) is unchanged.

### MG-3 — The `mtx` names

Every external function whose authority comes from a subject's signature (a submitter only relays) starts with `mtx`:

| Contract | Today | Target |
|---|---|---|
| tokens | `executeMetaTransaction` | `mtxExecute` (+ alias `executeMetaTransaction`, returns `bool`) |
| tokens | `executeMetaTransactionWithFee` | `mtxExecuteWithFee` (returns `bytes`, as `mtxExecute`) |
| tokens | `cancelMetaNonce` (a direct call) | `cancelNonce(uint256 batch)` — direct, or signed through `mtxExecute` on another lane (L3) |
| tokens | `metaNonce`, `metaTxDigest` (views) | `mtxNonce`, `mtxDigest` |
| tokens | `mtxTransfer`, `mtxTransferWithFee`, `mtxPay`, `mtxBatch` | unchanged (typed builders of the transfer/payment shapes) |
| tokens | `mtxUnwrap`, `mtxUnwrapWithFee` (+ their `fallback` decoder) | **deleted**: the `unwrap` pseudo-op is gone; `mtxExecute` with real `unwrap` calldata replaces them |
| tokens | — | `mtxTrade`, `mtxCancelOrder`, `mtxInvalidateNonces` (MG-8), `mtxWrap` on `SingleUnderlyingToken`, `MultiUnderlyingToken` and `ZetherToken` (MG-7b) |
| `ZetherToken` | `rollOverSigned`, `setRollOverMode` (signed) | `mtxRollOver`, `mtxSetRollOverMode` |
| `MandateWallet` | `payUnderMandate`, `revokeWithSig`, `executeAsOwner` | `mtxPayUnderMandate`, `mtxRevoke`, `mtxExecuteAsOwner` |
| `SubjectAccount` | `executeAsOwner` | `mtxExecuteAsOwner` |
| `OrderBookDex` | `settle`, `cancel`, `invalidateNonces` | `mtxSettle`, `mtxCancelOrders`, `mtxInvalidateNonces` (outside-token orders only, MG-8.4) |

The EIP-712 type names (`MetaTransaction`, `PayUnderMandate`, `OwnerCall`, …) name what is signed, not the entry
point; they stay. Non-EVM families keep their op names (`relay`, `Relay`, `SignedOp`) — Q4.

### MG-4 — `chain_uid` in every EIP-712 domain of SCaaS contracts (review H9, M4)

Every EIP-712 domain we deploy is `(name, version, chainId, verifyingContract, salt = chain_uid)`; `eip712Domain()`
(ERC-5267) returns fields `0x1f`. One helper, `SaltedEIP712` (OpenZeppelin `EIP712` has no salt), is used by all.
`chain_uid` is the chain's genesis block hash as its RPC reports it (NET-ALL-22).

| Contract | Domain | Where `chain_uid` comes from |
|---|---|---|
| token implementations (`NoUnderlying`/`Single`/`Multi`, Hedera tiers, `ZetherToken`) | `("SCaaS MetaToken","1",…)`, `("SCaaS ZetherToken","1",…)`, `verifyingContract` = the clone | constructor immutable of the **implementation**; clones run its code by `DELEGATECALL`, so they use it with no storage and no `initialize` argument and cannot declare another value |
| `OpenFactory` | (no domain) | constructor immutable; `registerImplementation` refuses an implementation whose `chainUid()` differs |
| `SubjectAccount` | `("SCaaS SubjectAccount","1",…)` | the factory's constructor argument, passed to `new SubjectAccount(chainUid)` |
| `MandateWallet` (and `HederaMandateWallet`) | `("SCaaS MandateWallet","1",…)` | constructor argument, from the chain profile |
| `OrderBookDex` | `("SCaaS OrderBookDex","1",…)` | constructor argument |
| `UniversalAccountRegistry` (built; Zether authorizes against it) | no EIP-712 domain: `requireAuthorized` checks **raw digests** (`UniversalAccountRegistry.sol:118-135`); its PoP challenge (`:95-97`) | constructor immutable (today it takes none, `:54`, so under A11 its address would be the same on every chain); the PoP challenge adds `chainUid`; because the registry checks raw digests, **every caller's digest must carry `chainUid` itself** |
| `UARegistry` (planned) | its CTR-UA-07 domain | constructor immutable (NET-ALL-22, unchanged) |
| any future contract with a signature (tender, asset suite) | — | the same helper, constructor argument |

Non-EIP-712 chain bindings of `ZetherToken`, which today carry `block.chainid` only, add `chainUid` beside it: the
statement header (`_header`, `:379`), `envelopeBinding` (`:496-500`), the disclosure challenge (`:581`), the rollover
digest `TAG_ROLLOVER` (`:247`, `mtxRollOver`), the mode digest `TAG_SET_MODE` (`:259`, `mtxSetRollOverMode`) and
`entryRef` (`TAG_ENTRY`, `:328`). Without it, a re-created chain restarts `modeNonce`, `accSeq` and block numbers, and
a captured mode or rollover signature replays (review 2 N-M4). `entryRef` gains it so that references never collide
across chains; Odoo still keys reconciliation by `(chain_key, entryRef)`.

- **Who makes it right:** the deploy script reads the genesis hash from the RPC; the deploy gate and the node, at chain
  activation and every start, require each contract's `chainUid()` = the RPC's genesis hash = the chain profile, and
  refuse a mismatch (the node also refuses to relay for a wallet or account whose `chainUid()` differs). A contract
  cannot read its own genesis hash after block 256, so this is checked off chain. A wrong value makes correct
  signatures fail; it is unsafe only if it equals **another** chain's `chain_uid`, which the per-contract check
  against the RPC's genesis hash excludes. `MandateWallet` is deployed per user with a deployer-chosen value, so the
  node checks its `chainUid()` before relaying anything for it. The factory check removes the second source the review found (M4): a clone's value is
  its implementation's, and the factory only registers implementations that match its own.
- **Addresses (owner A11, CREATE2):** the deploy scripts move from `new` (CREATE, address = f(deployer, nonce)) to a
  deterministic CREATE2 deployer with a fixed salt. A contract whose constructor takes `chain_uid` (implementations,
  factories, `SubjectAccountFactory`, `OrderBookDex`, `UARegistry`) gets a **different address on each chain**,
  because its init code differs; so does every clone, whose CREATE2 address depends on the implementation and the
  factory. A user's `SubjectAccount` therefore has a different address on each chain (`SubjectAccountFactory.sol:21-27`);
  the node and app predict it per chain. A contract with no chain-specific constructor argument gets the **same
  address on every chain**. Safety does not rest on the address: the salt is in every digest.
- **`SaltedEIP712` and clones:** clones share the implementation's immutables, so the helper rebuilds the domain
  separator whenever `address(this)` differs from the cached one, as OpenZeppelin's `EIP712` does.
- **Who fills it in when signing:** our app, portal and clientkeys put `chain_uid` into `domain.salt`, from the chain
  profile (works offline) or from `eip712Domain()` (read once, cached). Wallets such as MetaMask sign the domain they
  are given and check only `chainId`; clientkeys additionally refuses a `salt` that differs from the profile.
- **What protects:** the contract — a contract on chain B computes its digest with B's `chain_uid`, so a signature for
  chain A reverts there, whichever wallet produced it.
- **What it does not cover (honest limit, review M4):** a genesis hash separates chains with different genesis blocks
  that share a chain id (another network on 9000, a private chain re-created with a new genesis). It does **not**
  separate (a) two branches of a fork — they share genesis; only a chain-id change after the fork (EIP-155 practice)
  separates them — nor (b) a PoA chain re-created from the **same** `genesis.json`. (b) is closed by an ops rule
  enforced by the deploy gate: every private chain's genesis carries a unique `extraData` nonce, and a genesis hash
  already present in any chain profile is refused. (a) is ruled by OQ3 (accepted): a fork of a chain we run is a new
  chain — new chain id and `chain_key` — enforced by the deploy gate; on public chains it is a documented residual.
- **Hedera (L9):** `chain_uid` is the relay's block-0 hash; the Hedera profile must confirm it is stable across
  mirror-node and relay restarts before it is fixed (work plan step 1).

### MG-5 — Fees with a generic call (review H5, M8)

Each allowlisted selector has a fee class:

| Class | `PERCENT` | `FIXED` | Basis | Used by |
|---|---|---|---|---|
| `AMOUNT(i)` | yes, ≤ 1 % | yes, ≤ 1 % of the basis | argument `i` of the call, in this token's units | `burn(uint256)`, public `unwrap` |
| `ABSOLUTE` | refused (`requireConfidentialSafe`) | yes, the signed amount, **no 1 % cap** | — | `wrap`, `addReserve`, `cancelNonce`, every Zether selector |
| (always) | — | — | `NONE` is allowed for every selector | — |

Transfer and payment keep today's rule (basis `value`, both modes, 1 % cap). For a self-call `to` and `value` are 0,
so today's balance check (`balanceOf(from) ≥ value + fee`) covers nothing but the fee, and step 6 charges it after the call. `ABSOLUTE` extends the
owner's confidential rule (CTR-ZTH-07: `FIXED` absolute, uncapped, because there is no public amount to take a
percentage of) to public calls that move no amount of this token; the wallet shows the exact fee. This narrows
CTR-MTX-13 (OQ4).

`PaymentSettled` keeps its fee amount and recipient because payment is a built-in shape, not a self-call (M8).

### MG-6 — What else changes

| Area | Change |
|---|---|
| Node | Pricing and display decode `data` with the published allowlist (selector → fee class, amount argument); canonical re-encoding check for dynamic selectors (MG-2); a **breaker per `(from, selector)`** for self-calls that pass simulation and fail on chain (M11: rate-change pauses, Zether `sendCounter`, reserve level, a signer front-running its own intent); `mtxCancelOrder`, `mtxInvalidateNonces` (token) and `mtxWrap` (wrapper) become metatx-job entry points (`mtxTrade` is called only by the DEX or a wrapper); call table (NODE-JOB-01/19) renamed rows (`mtxExecuteAsOwner`, `mtxPayUnderMandate`, `mtxRevoke`, `OrderBookDex.mtxSettle`/`mtxCancelOrders`/`mtxInvalidateNonces`); `chainUid()` checks (MG-4); routes orders only to DEXes on the chain profile's DEX list and never for an unlisted `dex` (N-H1); predicts `SubjectAccount` addresses per chain (A11); checks a `MandateWallet`'s `chainUid()` before relaying |
| Clients | clientkeys and the app encode `mtxExecute` calldata, decode `data` to show "what you sign" (selector + arguments), fill `domain.salt`. For a `TradeOrder` (app, clientkeys, portal): show `dex`, `relayer`, `destination` and the effective minimum fill; **by default refuse to build or sign** when `dex` is not on the chain profile's DEX list (for `mtxWrap`: not a registered wrapper of that underlying), with a warning (N-H1); warn when `destination ≠ from` (review 2 L-11); default `relayer` to the venue node (L-10); label the meta-tx lane and the order lane (both `batch`). The Zether prover builds statements with `chainUid` |
| ERP connector example | encoders and selectors follow the new names |
| Deploy | scripts move to a CREATE2 deployer (A11); deploy gate checks `chainUid()` and refuses a known genesis hash (MG-4) |
| Vectors | KATs for every salted domain, `mtxExecute` calldata, `TradeOrder`/`DexOrder`/`CancelOrder`/`InvalidateNonces`; Zether statement, envelope, rollover, mode and `entryRef` vectors regenerated with `chainUid` (review 2 L-12d) |
| Docs | `contracts/metatx.md`, `token-wrappers.md`, `dex.md`, `mandates.md`, `accounts.md`, `zether.md`, `tender.md` (CTR-TND-07 after the v1 factory goes; CTR-TND-01 shape unchanged), `node/job-api.md`, `networks/README.md`, README §6/§7/§14 — every rule in §7 |

### MG-7 — Only a contract calls `approve`

In every SCaaS token `approve` requires the **caller** (`_msgSender()`, equal to `msg.sender` since `approve` is not
allowlisted) to be a contract, as well as the spender; `transferFrom` stays callable only by a contract. "Contract"
uses CTR-TOK-01's classifier: no code, a contract inside its constructor and an EIP-7702-delegated EOA all count as
EOAs. Consequences:

- An EOA never holds or grants an allowance on a SCaaS token — directly, through `mtxExecute` (`approve` is in no
  allowlist), or by any permit.
- **Allowance-like grants obey the same rule:** a `TradeOrder` names its executor `dex`, which must be a contract
  (`mtxTrade` checks `_isContract(o.dex)` and `msg.sender == o.dex`, H7). Signing `dex = EOA` therefore grants
  nothing. A contract is not proof of honesty: naming a phishing contract as `dex` is an owner-accepted residual risk,
  mitigated off chain (§4, review 2 N-H1).
- Contract accounts approve through **their own call path** (H3): `SubjectAccount.mtxExecuteAsOwner →
  execute(token, approve)`, a Safe `execTransaction`, or a Safe MultiSend that approves and uses the allowance in one
  transaction. The token then sees `msg.sender` = the account, which is the owner's rule literally. A signature
  check (`isValidSignature`) is not the account's execution policy: Safe guards, modules and thresholds run only on
  execution, so a gasless `approve` by ERC-1271 would let one key bypass them.
- Payments never needed allowances (`pay`, `payWithFee`); the DEX stops needing them for SCaaS tokens (MG-8).
- **Mandates are not allowances (L6):** a `MandateWallet` delegate (possibly an EOA) pays from the wallet under
  per-payment and per-period caps and a payee allowlist (CTR-ACC-06); the wallet, a contract, is the token's
  `msg.sender`. The rule does not ban it.
- Outside tokens are not ours to enforce: wrapping USDT still needs the holder to approve our wrapper on USDT (A6).
- Hedera HIP-632 signers are non-contracts, so they cannot `approve` (consistent, L9).

#### MG-7b — Signature wrap of a SCaaS underlying (owner A9, review M6, review 2 L-3)

When a wrapper's underlying is itself a SCaaS token, an EOA cannot approve the wrapper. It signs a `TradeOrder` (MG-8)
in the **underlying's** domain with `dex = the wrapper`, `receiveToken = the wrapper`, `receiveAmount` = the minimum
it accepts to receive (its `minOut`), `minFill = amount`:

```solidity
function mtxWrap(address underlying, TradeOrder calldata o, bytes calldata sig) external nonReentrant returns (uint256 minted);
```

On `SingleUnderlyingToken`, `MultiUnderlyingToken` and `ZetherToken`. The wrapper:

1. resolves the leg: `_legOf(underlying)` (Single/Multi; Zether: `underlying == this.underlying()`), which refuses an
   unknown "underlying" whose `mtxTrade` could be a no-op; requires `wrapEnabled`, no pending rate change
   (`SingleUnderlyingToken.sol:184-185`) and no reserve shortfall (`:199`);
2. checks `o.receiveToken == address(this)` and `o.relayer == 0 || o.relayer == msg.sender`;
3. quotes `minted = floor(o.amount · num / den)` (Zether: `o.amount`, 1:1) and `wrapFee = ceil(minted · o.fee /
   10⁶)` (CTR-DEX-11 rounding; `fee = 0` ⇒ 0);
4. calls `underlying.mtxTrade(o, sig, TradeFill(o.amount, minted, wrapFee, msg.sender))` — the underlying checks the
   signature, that the wrapper is `o.dex`, the price `amount·receiveAmount ≤ minted·amount` and the fee bound, and
   moves the funds **only into the wrapper** (MG-8.2);
5. requires `received == o.amount` (balance delta, as `_pull`), records the reserve, mints `minted − wrapFee` to
   `destination` (or `from`) and `wrapFee` to `msg.sender`, the submitting relayer — the order's `fee` is how a
   gasless wrap pays its relayer.

No allowance; only the named wrapper can pull, and only at the signed minimum. The wrapper's call to its underlying
is a wrap function talking to its underlying, as `_pull` does today, not the meta-tx gateway calling out (§4). Its own
`msg.sender` reads are the relayer binding and the `wrapFee` payee (§3.1).

**Zether `fund` (OQ5, accepted).** `fund(encodedY, amount)` always draws `amount · shieldScale` from the caller's
**public** Zether balance (`_burn(_msgSender(), amount · shieldScale)`, `totalShielded += amount`) instead of pulling
the underlying a second time — one path for every Zether token. The escrow invariant (`underlying held ≥ totalSupply
+ totalShielded · shieldScale`, `ZetherToken.sol:619-623`) is unchanged by construction: the underlying is already
held for those public units. A holder of an outside underlying wraps, then funds — two direct calls, or one gasless
`mtxBatch` of `mtxExecute(wrap)` and `mtxExecute(fund)`; an EOA holding a SCaaS underlying `mtxWrap`s by signature,
then funds. This replaces `contracts/zether.md:213-215` ("pulls `amount·shieldScale` underlying … through
`transferFrom`").

### MG-8 — DEX settlement without allowances: one struct, two paths (review C1, H7, H8, M1–M3)

#### MG-8.1 — `TradeOrder` = the owner's `MtxTradeOrder` modernized (owner A10, A12–A15)

A signed order is **one blob with no role in it**: whether it acts as taker or maker is decided at settlement time by
the node or whoever submits the settlement, so the same order can rest as a maker and later take, or the reverse.
Hence `from` (the signer), never `maker`/`taker`, in the struct. There is no counterparty field (the old struct had
none; rev 2's RFQ `taker` was withdrawn by the owner): who may match an order is the job of `relayer` (0 = anyone).
The field names are the old ones (A12).

```solidity
struct TradeOrder {
    address from;          // signer; this token's balance is sold
    address receiveToken;  // what the signer receives
    uint256 amount;        // at most this much of THIS token in total
    uint256 receiveAmount; // signed price limit: `amount` for at least `receiveAmount` (gross, before the DEX fee)
    uint256 minFill;       // signer's minimum fill per settlement; effective = max(minFill, ceil(amount/2)); = amount ⇒ fill-or-kill
    uint256 fee;           // DEX fee rate in ppm the signer agrees to pay on what it receives; ≤ 10 000 (1 %)
    address relayer;       // the matching party allowed to submit the settlement (0 = anyone)
    address dex;           // the only contract that may pull this order's funds, and the only place they go; a contract
    address destination;   // receives the proceeds in receiveToken; 0 = from
    uint8   flags;         // IOC 1 | ESCROW 2 (Path B; implies IOC)
    uint256 batch;         // order lane (minNonce), not the meta-tx lane of the same name
    uint256 nonce;         // valid while nonce ≥ minNonce[from][batch]
    uint256 validUntil;
}
// "TradeOrder(address from,address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,uint256 fee,"
// "address relayer,address dex,address destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)"

uint256 constant MIN_FILL_PPM = 500_000; // 50 % floor under every order's minFill, in every settlement, whatever its role (A13)
```

Signed in the **sell token's own** domain — `("SCaaS MetaToken","1",…)` or `("SCaaS ZetherToken","1",…)`, with
`chainId`, `verifyingContract` = the token, `salt` = `chain_uid` (review 2 L-7).

**Minimum fill (owner A13).** Each order signs `minFill`, its minimum fill per settlement; the protocol floor
`MIN_FILL` = 50 % (the old `MIN_RECEIVE_PERCENTAGE`) sits under it. The **effective minimum** is

```
m = max(minFill, ceil(amount · MIN_FILL_PPM / 10⁶))          // = max(minFill, ceil(amount / 2))
```

and in one settlement call **every** order — the taker and each maker alike — must satisfy

```
sellFill ≥ m                                       or  sellFill == amount − pulled[h]   (the remainder closes)
receiveFill · 10⁶ ≥ receiveAmount · MIN_FILL_PPM   or  sellFill == amount − pulled[h]   (received side, as the old taker check)
```

`minFill > amount` is refused (`BadMinFill`). An order signed with `minFill` below 50 % is **treated as 50 %**, not
refused: the contract applies `m`, and clients
show the effective value before signing (so orders built by outside tools still work). `minFill = amount` is
fill-or-kill (with `pulled == 0`, the remainder clause cannot apply). The received-side line follows from the
sold-side line and the price limit; it is asserted anyway, as the old `ERC1776Dex` did for its taker (`:110-111`).
Purpose: no junk fills — a maker matched for 1 % would have to re-create its order. Consequences: a Path A order fills
in at most two settlements, and an order can only be matched against counterparts that take at least half of it.

| Old `MtxTradeOrder` (`MtxTradeOrderLib.sol`) | New `TradeOrder` | Note |
|---|---|---|
| `from` | `from` — kept | the signer; no role in the order |
| `to` (always the DEX) | `dex` | the only contract that may pull the order's funds and the only address they go to; must be a contract, never 0 (checked by the token: `msg.sender == o.dex`, H7) |
| `amount` | `amount` — kept | Path B pulls all of it; Path A pulls fills up to it (`pulled[orderHash]`) |
| `receiveToken` | `receiveToken` — kept | — |
| `receiveAmount` | `receiveAmount` — kept | the signed price limit, checked cross-multiplied |
| `relayer` (0 = anyone) | `relayer` — kept | the matching party: when ≠ 0 only it may submit the settlement (checked by the DEX against its `msg.sender`, and by the token against the submitter the DEX reports) — the meaning of `MetaTransaction.relayer` / `MODE_RESTRICT_RELAYER` |
| `fee` (ppm, DEX fee) | `fee` — kept | the DEX fee rate the signer agrees to pay on what it receives; the DEX never charges more and distributes it per its admin's split (MG-8.3) |
| `batch`, `nonce`, `validUntil` | kept | `nonce` is no longer consumed per fill: it is the cancel handle (`minNonce` per lane); per-order cancel added |
| `chainId`, `contract` | EIP-712 domain | `chainId`, `verifyingContract` = the token, `salt` = `chain_uid` |
| `MIN_RECEIVE_PERCENTAGE` = 50 % (`ERC1776Dex.sol:10, 110-111`), taker only | `MIN_FILL_PPM` = 50 % | a protocol floor, now for **every** order in a settlement, sold and received side |
| — | `minFill` — new | the signer's minimum per settlement, raised to the 50 % floor; `= amount` ⇒ fill-or-kill |
| — | `destination` — new (owner-accepted, A14) | who receives the proceeds (0 = the signer) |
| — | `flags` — new | IOC / ESCROW (Path B) |
| `signature` (in the struct) | separate `bytes sig` argument | a signature cannot be inside what it signs |

Not reused from the old code, and why:

| Old | Why not |
|---|---|
| `toEthSignedMessageHash` prefix (`SignatureValidator.sol:10`) | `personal_sign` shows 32 opaque bytes; EIP-712 shows every field (CTR-MTX-14) |
| `contract` field | a reserved word in Solidity ≥ 0.5, and redundant with `verifyingContract` |
| `ERC1776` base (`ERC1776Tradeable.sol:4`, file absent) | the base is `ERC20MetaTx` (MG-9) |
| `PRECISION` rate division (`ERC1776Dex.sol:41, 64, 78`) | rounds against the maker; replaced by exact cross-multiplied limits rounded in each signer's favour |
| `to` not tied to the caller nor required to be a contract (`ERC1776Tradeable.sol:23, 49, 53`) | with `relayer = 0` any caller could move the leg to any `to` the signer named, an EOA included; `dex` is both the only caller and the only recipient, and a contract |
| fee kept by the DEX when no `feeRecipient` (`ERC1776Dex.sol:141`) | fees would accumulate in the DEX; the DEX pays every fee out in the same call per its admin's split (MG-8.3) |
| `Rescuable` admin sweep | the DEX never holds funds after a call (conservation invariant below); no sweep |

#### MG-8.2 — The token's side: funds go only into `dex`

```solidity
struct TradeFill { uint256 sellFill; uint256 receiveFill; uint256 dexFee; address submitter; }
function mtxTrade(TradeOrder calldata o, bytes calldata sig, TradeFill calldata f) external nonReentrant;
function mtxCancelOrder(TradeOrder calldata o, bytes calldata sig) external nonReentrant;   // CancelOrder(bytes32 orderHash)
function mtxInvalidateNonces(address from, uint256 batch, uint256 newMin, bytes calldata sig) external nonReentrant;
                                                       // InvalidateNonces(address from,uint256 batch,uint256 minNonce)
mapping(bytes32 => uint256) public pulled;                         // orderHash => amount pulled (amount = closed)
mapping(address => mapping(uint256 => uint256)) public minNonce;   // from => order lane => min valid nonce
```

`mtxTrade` checks, in order (error in brackets):

1. Caller and identities: `msg.sender == o.dex` (`NotDex`) and `_isContract(o.dex)` (`DexNotContract`);
   `o.from ≠ address(this)`, `o.dex ≠ address(this)`, `o.receiveToken ≠ address(this)` (`SelfOrder`). The DEX
   implements no ERC-1271, so it can never be an order's `from`.
2. `o.relayer == 0 || o.relayer == f.submitter` (`WrongRelayer`; the DEX reports its own `msg.sender`).
3. Order shape: `block.timestamp ≤ validUntil` (`OrderExpired`); `o.nonce ≥ minNonce[from][batch]`
   (`NonceInvalidated`); known flags, `ESCROW` requires `IOC` (`BadFlags`); `amount > 0`, `receiveAmount > 0`
   (`ZeroAmount`); `minFill ≤ amount` (`BadMinFill` — a larger value is refused, not read as fill-or-kill);
   `fee ≤ 10 000` (`FeeAboveCap`).
4. Signature over `h` = the order's digest through the virtual `_requireValidSignature` (EOA low-s, ERC-1271 with the
   50 k/400 k cap; Hedera's override adds HIP-632).
5. With `p = pulled[h]`: `p < amount` (`OrderClosed` — covers filled, cancelled and already-pulled IOC orders).
6. **Path A** (`ESCROW` clear) — the token enforces every bound the signer set, against the figures the DEX passes:
   `f.sellFill > 0` (`ZeroFill`); `p + f.sellFill ≤ amount` (`Overfill`); the effective minimum `m` and the
   received-side floor (MG-8.1, `BelowMinFill`); price `f.sellFill · receiveAmount ≤ f.receiveFill · amount`, checked
   multiplication (`PriceLimit`); `f.dexFee ≤ ceil(f.receiveFill · fee / 10⁶)` (`FeeAboveSigned`) — the signed rate,
   rounded up per CTR-DEX-11 (less than one smallest unit). It moves exactly `f.sellFill` from `from` **to `o.dex`**.
7. **Path B** (`ESCROW` set): `p == 0`; `f.sellFill == amount`; `f.receiveFill == 0` and `f.dexFee == 0`
   (`EscrowFillShape`); it moves `amount` from `from` **to `o.dex`**. The DEX enforces price, the effective minimum
   and the fee on the matched part (MG-8.3).
8. Effects before the transfer: `pulled[h] = IOC ? amount : p + f.sellFill` (an IOC order is pulled **once**). Emit
   `TradeFilled(h, from, sellFill, receiveFill, dexFee)`. For a Path B leg this shows `sellFill = amount,
   receiveFill = 0`; the DEX's `LegSettled` event (MG-8.3) is the accounting record of what was matched and refunded.

The token has exactly one recipient, `o.dex`; it splits nothing and pays no fee itself. Price and received-side
checks need no extra zero test: with `sellFill > 0` and `receiveAmount > 0` they force `receiveFill > 0`.

`mtxCancelOrder` sets `pulled[h] = amount` (emit `OrderCancelled(h, from)`; an already-closed order is a no-op, not an
error); `mtxInvalidateNonces` raises `minNonce[from][batch]` (strictly increasing, capped 2¹²⁸, emit
`NoncesInvalidated`). Neither signature expires (CTR-DEX-02 kept). A signer with orders on several tokens cancels per
token; the off-chain book drops them at once. The order's `batch` is an **order lane** (`minNonce`), separate from the
meta-tx lane of the same name (`cancelNonce`); clients label the two.

#### MG-8.3 — The DEX's side: `mtxSettle`

```solidity
struct Leg { address sellToken; TradeOrder o; bytes sig; uint256 fill; }  // fill = sellFill of this leg in this call
struct Settlement { bytes32 ref; Leg taker; Leg[] makers; }               // ref: chosen by the submitter, echoed in events only
function mtxSettle(Settlement[] calldata s) external nonReentrant returns (bool[] memory ok); // each settlement atomic (try)
```

`taker`/`makers` is a call-time arrangement — one taker against many makers — chosen by the node or the submitter,
not a property of the orders.

1. **Check.** Every leg's `relayer` is 0 or `msg.sender` (`WrongRelayer`); each maker's `sellToken` is the taker's
   `receiveToken` and vice versa (`TokenMismatch`); no self-trade, `from`s differ (`SelfTrade`); the market is listed
   (`MarketNotListed`).
2. **Match first.** Fills at each maker's signed price, rounded in that maker's favour; **every** order in the
   settlement meets its effective minimum `max(minFill, 50 %)` and the received-side floor (MG-8.1) — the taker's
   received total ≥ 50 % of its `receiveAmount`, as the old code checked, and each maker likewise (`BelowMinFill`);
   each order is pulled at most once per call.
3. **Pull** every leg into the DEX: SCaaS sell tokens through their `mtxTrade` (Path A with the exact fill and fee
   figures, Path B whole); outside sell tokens per MG-8.4. The DEX decides which is which from its listing, never from
   the leg.
4. **Pay** out of what was pulled, in the same call: each party's `destination` (or `from`) receives `receiveFill −
   dexFee` in its `receiveToken`; each `dexFee` is split per the admin's configuration (below); Path B remainders are
   refunded to `from`. Emit `LegSettled(ref, orderHash, from, destination, sold, received, dexFee, refund,
   relayerShare, treasuryShare)` per leg.
5. **Invariant**, asserted at the end of each settlement: the DEX's balance of every token touched is unchanged
   (`ConservationBroken(token)`).

**No per-party proceeds check (review 2 N-M3).** Rev 4's `ProceedsShort` (each `destination`'s balance delta ≥ its
proceeds) is dropped. Its expected figure is computed by the same DEX code that makes the payment, so it adds nothing
against a DEX bug; per-party deltas are also wrong when addresses are shared — two makers with one `destination`, a
taker's `destination` that is a maker's `from` debited in the same token, a relayer or treasury that is also a
`destination`. What a delta check could still catch is a token that credits less than it was told to transfer, and
that is covered by conservation plus listing only **exact-transfer** tokens: SCaaS tokens are exact by construction;
fee-on-transfer, rebasing and hook (ERC-777) outside tokens are not listed, and if one slips through, the DEX's own
balance moves and conservation reverts the settlement.

| Leg | Pulled into the DEX | Bounds checked by |
|---|---|---|
| SCaaS token, Path A, any role | exactly `sellFill` | the signer's token, against the fill figures the DEX passes (amount, effective minimum, price, `fee`) |
| SCaaS token, Path B, any role | all of `amount`; the remainder refunded in the same call | the DEX, on the matched part, against the signed order |
| outside token, any role | exactly the fill, by `safeTransferFrom` (allowance, A6) | the DEX, against the `DexOrder` (MG-8.4) |

**Why everything goes through the DEX (owner ruling, review M1).** (a) One choke point: a single contract sees every
unit that enters and leaves a settlement and makes every payment, instead of the token trusting a `receiveFill` it
cannot see arrive somewhere else. (b) One simple invariant: "the DEX's balance of every token is the same before and
after the call" — no dust, no donated tokens paid out, nothing stuck. (c) The token stays minimal: one recipient
(`dex`), no fee splitting, no route chosen by the caller; a signer reads one address to know where its funds can go.
The cost is two transfers per leg instead of one. In Path A the signer relies on the named DEX for delivery; in Path
B, chosen by `ESCROW`, for price as well. Whether that DEX is ours is checked off chain (§4, N-H1).

**Fees (owner A15).** One field, `fee`: the DEX fee rate (ppm, ≤ 1 %) the signer agrees to pay on what it receives,
whatever role the order plays. The DEX charges `dexFee = ceil(receiveFill · fee / 10⁶)` (CTR-DEX-11) — never more —
**once per order per settlement, on its aggregate `receiveFill`** (a taker filled by several makers is charged once on
the total; a sum of per-maker ceilings could exceed the bound its token checks), in the `receiveToken`, deducts it
before paying `destination`, and **distributes it in the same call** per its own configuration, as the old
`ERC1776Dex` sent fees to a `feeRecipient` (`:141-147`): `relayerShare = floor(dexFee · relayerSharePpm / 10⁶)` to the
relayer that submitted the settlement (`msg.sender`), the rest to `treasury`. No separate relayer fee exists: the
relayer is paid from its share. With `relayer = 0`, whoever submits earns the share of **every** fee in the
settlement — a taker that submits its own match is rebated part of the maker's fee, and a pending `mtxSettle` can be
copied from the mempool for the share; clients therefore default `relayer` to the venue node (review 2 L-10).
Role-based pricing (maker vs taker rates) is the node's intake policy — it does not match an order whose signed `fee`
is below its venue's rate for the role it would play — not an on-chain setting.

**Admin powers.** The DEX `admin` stays immutable (a Safe, CTR-DEX-03) and can do exactly two things: list or delist a
market (`setMarket(base, quote, listed)`, which also records each token's kind, MG-8.4) and set the split
(`setFeeSplit(relayerSharePpm, treasury)`; `treasury ∉ {0, DEX}` unless the share is 100 %). It can change who
receives fees and in what proportion, **never the amount**: the amount comes only from the signed `fee`. No access to
funds, no upgrade, no sweep, no pause.

#### MG-8.4 — Outside-token legs (`DexOrder`, review 2 N-M2)

A leg whose sell token is not a SCaaS token cannot verify a `TradeOrder`, so the DEX does it, with the same rules:

| Item | Rule |
|---|---|
| Classification | At `setMarket`, the DEX records each token's kind: **SCaaS** iff the chain's factory reports it was made from a registered, non-deprecated implementation (`versionOf`, as CTR-TND-07), else **outside**. Never taken from the leg: a submitter-chosen kind could send a WETH9-style fallback "token" down the `mtxTrade` path |
| Signed struct | the same `TradeOrder`, signed in the **DEX's** domain as `DexOrder(address sellToken,TradeOrder order)TradeOrder(…)`; `o.dex == address(this)` is required (the domain already binds the DEX; a different `dex` field would be a second, conflicting truth) |
| Fill state | on the DEX: `pulled[h]` and `minNonce[from][batch]`, `h` = the `DexOrder` digest |
| Checks | the full MG-8.2 list, enforced by the DEX: relayer binding, expiry, nonce, flags, zero amounts, `minFill ≤ amount`, fee cap, signature (`_validSig` with the ERC-1271 cap, CTR-DEX-08), `p < amount`, `sellFill > 0`, overfill, effective minimum, price, fee bound |
| Flags | `IOC` allowed; **`ESCROW` refused** (`BadFlags`) — the fill is already pulled exactly into the DEX, so escrow adds nothing |
| Pull | `safeTransferFrom(from, DEX, sellFill)` under the party's allowance to the DEX (A6: an EOA may approve a contract on an outside token) |
| Cancel | `mtxCancelOrders(DexOrder[] orders, bytes[] sigs)` (`CancelOrder(bytes32 orderHash)` in the DEX domain; closed or bad-signature items skipped, as today's `cancel`) and `mtxInvalidateNonces(from, batch, newMin, sig)` (`InvalidateNonces(address from,uint256 batch,uint256 minNonce)` in the DEX domain) |
| Backstop | conservation (MG-8.3 step 5) |

`OrderBookDex` keeps its book semantics (price-time priority, limit + IOC/FOK, partial fills above the effective
minimum, the node's book) with `mtxSettle` replacing `settle`; its DEX-domain `Order` survives only as `DexOrder`.
The legacy `MetaTxDex` is deleted. Non-EVM DEXes keep their own leg shapes (Q4).

### MG-9 — One base: `ERC20MetaTx`

`MetaTxCore` is renamed **`ERC20MetaTx`** and becomes the only meta-transaction base: MG-1…MG-8 live there. The v1
line — the current `ERC20MetaTx`, `MetaToken`, `HederaMetaToken`, `OpenFactory` — is deleted; issuer tokens use
`NoUnderlyingToken` (⊇ v1 tier 1, adds `burn`/`renounceMinter`), 1:1 wrappers use `SingleUnderlyingToken` with `num =
den = 1` (⊇ v1 wrapper, except that v2 lets the issuer choose `decimals`, CTR-TOK-08, where v1 forced the
underlying's), and the v2 factory (renamed `OpenFactory`) is the only factory; `IFactoryToken.verifier()` stays only on
the Zether kind (tender decodes one enum, CTR-TND-07). `ZetherToken` uses the same base — nonce, envelope, fee and
ticket steps — so `ZetherMetaTx` disappears. One domain version (`"1"`) for every token.

**UA ledger (M5).** `_msgSender()` is an `address`; a derived UA is a `bytes32`, so a self-call cannot act for it. The
`ua*` functions of CTR-UA-18/19 keep their explicit shapes (transfer, `pay`, `unwrap`) and their own struct
`UAMetaTransaction`, in the same base and the same token domain (`"1"`, salted; the typehash separates the two
structs); `approve` and trade stay refused there. A `bytes32` sender for self-calls is out of scope.

## 4. Security notes

| Risk | Rule |
|---|---|
| Sender spoofing (ERC-2771 + multicall class) | Signer in transient storage, never calldata; `_msgSender()` trusts it only for `msg.sender == this` with a live ticket; every direct `msg.sender` read listed and treated (§3.1); lint pins the "stays" set; `from ≠ this`; no transfers to `this` |
| Nesting, re-entry | No `mtx…` entry in any allowlist; one-shot ticket (MG-1): one guarded entry per self-call, any re-entry reverts |
| Gateway calling out | The gateway's only outward call is the read-only ERC-1271 `staticcall` (signature check), as today. Allowlisted wrap/unwrap/fund call their underlying, as their direct versions do; `mtxWrap` calls the underlying's `mtxTrade` (MG-7b). Neither is the gateway forwarding calldata |
| Role functions gasless | None allowlisted (H4); role holders use their own contract (NODE-JOB-01/19) |
| EOA allowances | `approve` needs a contract caller; not allowlisted; `TradeOrder.dex` must be a contract (H3, H7) |
| Phishing `dex` (review 2 N-H1) — **owner-accepted residual risk (2026-10-08)** | The token requires only that `dex` is a contract; there is no factory DEX registry and no codehash allowlist. A phishing contract named as `dex` can report any `receiveFill` and take the signed `amount`. Mitigations: the app, clientkeys and the portal warn about, and **by default refuse to build or sign**, a `TradeOrder` whose `dex` is not on the chain profile's DEX list (for `mtxWrap`: a registered wrapper of that underlying); the wallet's EIP-712 view shows `dex`; the node never routes orders for unlisted DEXes |
| Zether envelope stripping | Binding passed by transient slot; direct calls prove with binding 0 (MG-2.1) |
| Fees on non-value calls | Per-selector fee class (MG-5) |
| DEX legs | Orders carry no role (`from`, no `maker`/`taker`, no counterparty field); price limit, settlement contract (`dex`), matching party (`relayer`) and fee rate (`fee`) signed; effective minimum fill `max(minFill, 50 %)` for every order in every settlement; the token moves funds **only into `dex`** (a contract) and checks closed orders, zero fills, amount, minimum, price and the fee figure against the signed values (Path A); the named DEX checks Path B and outside-token legs (MG-8.4); token kinds come from the listing, not the leg; one pull per order per call; the DEX pays every `destination`, fee share and refund in the same call and asserts conservation; the admin sets only the fee split, never the amount |
| Cross-chain replay | `salt = chain_uid` in every domain and Zether binding (MG-4), with the fork limit stated |
| Opaque `data` in wallets | EIP-712 shows every field; clients decode `data` against the published allowlist before asking for a signature |

## 5. Not in scope

Calls to other contracts (the account layer: `SubjectAccount.execute`, `Safe.execTransaction`); a generic forwarder;
a `bytes32` sender for self-calls; non-EVM families (Q4).

## 6. Work plan after acceptance

1. Allocate ids, fold MG-1…MG-9 into the component docs (§7 list), update `decisions.md` and the README; confirm the
   Hedera block-0 hash is stable (MG-4).
2. Deploy: scripts on a CREATE2 deployer with fixed salts, `chain_uid` constructor arguments, deploy-gate checks.
3. Contracts: MG-9 first (one base `ERC20MetaTx`, delete the v1 line and `ZetherMetaTx`), `SaltedEIP712` in every
   domain (MG-4), MG-1/MG-2/MG-5/MG-7 in the base, `msg.sender` sweep (§3.1), MG-8 (`mtxTrade`/cancel in the base,
   `OrderBookDex.mtxSettle`, delete `MetaTxDex`), MG-7b `mtxWrap`, Zether on the base (MG-2.1), MG-3 renames in
   `MandateWallet`, `SubjectAccount`, `ZetherToken`, `OrderBookDex`; NatSpec sweep (`IERC20MetaTx` step list, Zether
   headers, L8).
4. Tests: every allowlisted selector through `mtxExecute`; spoofing (tokens parked at the token address), nesting,
   ticket re-entry from an underlying hook (H1); EOA-approve refusal; `dex` = EOA refused; Path A/B one taker × many
   makers, conservation; `mtxTrade` on a closed, cancelled or IOC-pulled order and with `sellFill = 0` reverts
   (review 2 N-M1); Path B `sellFill ≠ amount` reverts; `DexOrder` legs (MG-8.4) incl. a fallback "token" classified
   outside; taker fee charged once on the aggregate; every allowlisted function `nonReentrant`; `unwrap(uint256,address)`
   refused; `mtxWrap` on Single and Zether; Zether `fund` from the public balance with the escrow invariant;
   salted-domain and Zether-digest KATs; tender deposit through the alias.
5. Node, clientkeys, app and the ERP connector follow; vectors regenerated.

## 7. Changes to current rules

Every current rule this draft reverses or narrows; each needs the owner's acceptance by name when folded.

| Rule | Today | After |
|---|---|---|
| `_USER-DECISIONS.md` §24.1 (owner) | "the token does two things — public transfer and Zether confidential transfer" | it also runs allowlisted functions of itself (A1) |
| §24.3 (owner) / CTR-MTX-16 | "fee collected ⇔ operation completed": everything checked **before** the fee, nothing can fail after | self-calls run **then** pay the fee; any failure reverts all. Still all-or-nothing, but the order is reversed (OQ2) |
| CTR-MTX-16 | "no `_msgSender()` suffix, no target allowlist" | still no suffix and no target; `_msgSender()` from a transient slot and a **selector** allowlist on the token itself |
| CTR-MTX-15 | `data` = op list incl. `trade`, `approve`; `to` = recipient/op target | `data` = empty, `pay(bytes32)` or an allowlisted self-call; `to = value = 0` for a self-call |
| CTR-MTX-02 | domain `(name, "1"/"2", chainId, clone)` | `(name, "1", chainId, clone, salt = chain_uid)` |
| CTR-MTX-07 | v2 base `MetaTxCore` beside a frozen v1 | one base `ERC20MetaTx`; v1 deleted |
| CTR-MTX-09 | named functions incl. `mtxUnwrap*` | `mtxUnwrap*` deleted; `cancelMetaNonce` → `cancelNonce` |
| CTR-MTX-11 | no second typehash | exceptions in the token domain: `TradeOrder`, `CancelOrder`, `InvalidateNonces` (different structs, as CTR-UA-19) |
| CTR-MTX-12 | gasless unwrap via the `unwrap` pseudo-op (R148) | via `mtxExecute(unwrap(…))` |
| CTR-MTX-13 | `FIXED` capped at 1 % of `value` for public tokens | the cap applies to `AMOUNT` selectors; `ABSOLUTE` selectors are uncapped (OQ4) |
| CTR-TOK-01 | spender must be a contract; only contracts call `transferFrom` | also the **caller** of `approve`; `TradeOrder.dex` must be a contract — and only that: no DEX registry (owner 2026-10-08, residual risk §4) |
| CTR-TOK-14 | gasless wrap planned via a permit op | `mtxExecute(wrap)` (underlying allowance) or `mtxWrap` (SCaaS underlying, signature) |
| CTR-TOK-03/12 | factory v2 beside factory v1 and v1 clones | one factory `OpenFactory` (the v2 code) |
| CTR-DEX-01 | DEX checks two DEX-domain orders (`maker`/`taker` fields), is the only spender; DEX fee per market (`makerPpm`/`takerPpm`) on the received part | SCaaS legs are token-verified, role-free `TradeOrder`s (`from`; the role is chosen at settlement); the token moves funds only into the DEX, no allowance; the DEX pays out and must end each call with unchanged balances; the fee **rate** is the order's signed `fee` (no market rate on chain; maker/taker pricing is node intake policy), still on the received part; partial fills ≥ `max(minFill, 50 %)` per settlement; DEX-domain order only for outside tokens |
| CTR-DEX-03 | admin's one power: `setMarket(base, quote, listed, feeOn, makerPpm, takerPpm, feeRecipient)` | two powers: `setMarket(base, quote, listed)` and `setFeeSplit(relayerSharePpm, treasury)` — recipients and proportions only, never the amount |
| `dex.md` signed-order fields (`taker`: "non-zero = only this counterparty (RFQ)") | RFQ counterparty binding | **dropped** (owner): no counterparty field; `relayer` decides who may match |
| CTR-DEX-02 | `CancelOrder`/`InvalidateNonces` on the DEX | the same, per token (`mtxCancelOrder`, `mtxInvalidateNonces` per lane); never expire |
| CTR-DEX-04/05 | IOC closed and FOK checked by the DEX | the token closes IOC at its single pull; FOK = `minFill = amount`; every fill ≥ `max(minFill, 50 %)` of the order, except the last remainder of a Path A order, which may close below it |
| CTR-DEX-06 | relayer fee `feeMode`/`fee`/`feeToken`, separate from the DEX fee, paid by `transferFrom`; `relayer` binding | **no separate relayer fee**: the relayer is paid its admin-configured share of the DEX fee; `relayer` binding kept |
| CTR-DEX-07 | `MetaTxDex` legacy | deleted |
| CTR-UA-19 | domain version `"3"`; clone copies `registry.chainUid()` at `initialize` | version `"1"`; `chain_uid` is the implementation's constructor immutable |
| `accounts.md` signer table (`MetaTxDex`, `OrderBookDex` rows) | `settle`, `MetaTxDex.settle(a, b)` | `mtxSettle`, token `mtxTrade`; `MetaTxDex` row removed |
| NET-ALL-22 | `chain_uid` in UA domains; "constructor argument makes the CREATE2 address differ" | in **every** SCaaS domain and Zether binding; CREATE2 deployer stated (A11); fork limit stated |
| NODE-JOB-01/19 | call-table rows `executeAsOwner`, `payUnderMandate`, `revokeWithSig`, `OrderBookDex.settle/cancel/invalidateNonces` | renamed (MG-3); role calls still only through role-holder contracts, now also for gasless token calls |
| CTR-TND-07 | deposit token from factory v1 or v2 | from the one factory |
| CTR-ZTH-11 | `fund` direct only; only transfer and burn have envelope ops | `fund`, public `wrap`/`unwrap` also via `mtxExecute` |
| `zether.md:213-215` (CTR-ZTH-03, `fund` bullet) | `fund` pulls `amount·shieldScale` underlying from `msg.sender` by `transferFrom` | `fund` burns `amount·shieldScale` public Zether units from the caller; escrow unchanged; an outside-underlying holder wraps first (OQ5) |
| CTR-ZTH Zether digests, NET-ALL-22 | rollover, mode, `entryRef`, statement, envelope and disclosure digests carry `block.chainid`; the registry has no `chainUid` | all add `chainUid`; `UniversalAccountRegistry` takes `chainUid` as a constructor immutable and in its PoP challenge (review 2 N-M4) |
| CTR-ZTH-06 | binding passed by `relayed*` | passed by transient slot; `relayed*` deleted |
| CTR-ZTH-16/17 names | `rollOverSigned`, `setRollOverMode` | `mtxRollOver`, `mtxSetRollOverMode` (rules unchanged) |
| CTR-ACC-07 name | `revokeWithSig` | `mtxRevoke` (rule unchanged) |

## 8. Defaults (rev 1 §7, updated)

| # | Question | Default (rev 5) |
|---|---|---|
| Q1 | Add `token` / `chainId` / `chain_uid` to the signed struct? | No: the domain binds them; the node routes by `(chain_key, contract)` and verifies the digest |
| Q2 | Meaning of `to`/`value` when `data` is a self-call | **Changed:** both must be 0; the fee basis comes from the selector's fee class (MG-5) |
| Q3 | Role functions in the allowlists | **Changed (H4): none** — OQ1 |
| Q4b | Order fields | Replaced by MG-8.1 (A10, A12–A15). Rev 1's "fee ppm in the order" kept as `fee`; "`taker` optional" **withdrawn by the owner** (no counterparty field; `relayer` decides who may match); "`minNonce` bulk cancel" kept per lane, plus per-order cancel; `minFill` kept with a 50 % protocol floor |
| Q4 | Same rule for non-EVM families | Separate draft after this one |
| Q5 | Must `dex` be a registered DEX (factory registry or codehash allowlist), review 2 N-H1? | **No — owner decision 2026-10-08:** `dex` must be a contract, nothing more; residual risk accepted and mitigated off chain (§4) |

## 9. Names fixed before code (review L5)

| Kind | Names |
|---|---|
| Transient slots | `keccak256("scaas.mtx.guard")`, `"scaas.mtx.sender"`, `"scaas.mtx.ticket"`, `"scaas.mtx.binding"` (written as literals: assembly takes no `keccak256` constant) |
| Errors | Gateway: `MtxSelectorNotAllowed(bytes4)`, `MtxDataShape(bytes4)`, `MtxEnvelopeShape()`, `MtxFeeClass(bytes4, uint32 mode)`, `Reentrancy()`, `SelfSender()` (`from == this`), `TransferToSelf()`; inner failures bubble raw. `mtxTrade`: `NotDex()`, `DexNotContract(address)`, `SelfOrder()`, `WrongRelayer(bytes32)`, `OrderExpired(bytes32)`, `NonceInvalidated(bytes32)`, `BadFlags(bytes32)`, `ZeroAmount(bytes32)`, `BadMinFill(bytes32)`, `FeeAboveCap(bytes32)`, `OrderClosed(bytes32)`, `ZeroFill(bytes32)`, `Overfill(bytes32)`, `BelowMinFill(bytes32)`, `PriceLimit(bytes32)`, `FeeAboveSigned(bytes32)`, `EscrowFillShape(bytes32)`. DEX: the same for `DexOrder` legs, plus `TokenMismatch(bytes32)`, `SelfTrade(bytes32)`, `MarketNotListed(address,address)`, `FeeWouldStick()`, `ConservationBroken(address token)`. Wrapper: `UnderlyingInvalid(address)`, `WrapReceivedMismatch(uint256 expected, uint256 received)` |
| Views | `mtxSelectors()`, `chainUid() returns (bytes32)`, `pulled(bytes32)`, `minNonce(address,uint256)`, `tradeOrderDigest(TradeOrder)` |
| Events | `MetaTransactionExecuted` unchanged; `TradeFilled(bytes32 orderHash, address from, uint256 sellFill, uint256 receiveFill, uint256 dexFee)`, `OrderCancelled(bytes32, address from)`, `NoncesInvalidated(address from, uint256 batch, uint256 minNonce)` on the token; on the DEX `LegSettled(bytes32 ref, bytes32 orderHash, address from, address destination, uint256 sold, uint256 received, uint256 dexFee, uint256 refund, uint256 relayerShare, uint256 treasuryShare)` (the accounting record, as today's `OrderFilled`), `FeeSplitSet(uint32 relayerSharePpm, address treasury)`, `MarketSet(address base, address quote, bool listed)` |
| Typehashes | `TradeOrder(…)` (MG-8.1), `CancelOrder(bytes32 orderHash)`, `InvalidateNonces(address from,uint256 batch,uint256 minNonce)`, `DexOrder(address sellToken,TradeOrder order)TradeOrder(…)` |
| Constants | `MIN_FILL_PPM = 500_000` (token base and DEX); `MAX_FEE_PPM = 10_000` (existing) |
| DEX | `Leg`, `Settlement { ref, taker, makers }` (roles of one call only; `ref` echoed in events only, as `Match.ref`), `mtxSettle` (MG-8.3), `mtxCancelOrders`, `mtxInvalidateNonces` (MG-8.4); struct fields `from`, never `maker`/`taker` |
| Return types | `mtxExecute`, `mtxExecuteWithFee` → `bytes`; `executeMetaTransaction` → `bool`; `mtxWrap` → `uint256 minted` |

## 10. Open questions for the owner

**Owner, 2026-10-08: OQ1–OQ5 accepted as recommended** (OQ1 no role function allowlisted; OQ2 new §24.3 wording; OQ3 a fork of a chain we run is a new chain; OQ4 uncapped `FIXED` fee for calls that move no amount; OQ5 Zether `fund` from the public balance). OQ6 closed earlier (`destination` kept). The table below is kept as the record.

Only what needs an owner decision; each has a recommendation.

| # | Question | Recommendation |
|---|---|---|
| OQ1 | Rev 1 default Q3 allowed role functions (`mint`, rate admin, guardian) through `mtxExecute`. Review H4: the token can then only check `isValidSignature`, which skips a minter contract's caps or a Safe's guards/timelock, and it adds a second role path beside NODE-JOB-01's "role calls only through a Safe of the role holders". Flip to "no role function allowlisted"? | **Yes, flip.** If gasless EOA minters are ever wanted, allow `mint` only when `_msgSender()` is not a contract — a separate decision |
| OQ2 | §24.3's invariant "checked before the fee, cannot fail after" becomes "self-call, then fee; any failure reverts all". Accept the new wording? | **Accept.** The user still never pays for an operation that did not happen; only the order changes, and it lets a wrap pay its fee from minted units |
| OQ3 | Forks share genesis, so `chain_uid` cannot separate two branches of a fork. Rule? | For chains we run: a fork is a new chain — new `chain_id` (EIP-155) and new `chain_key` — enforced by the deploy gate. For public chains: rely on the fork's chain-id change; without one, signatures replay on both branches (residual, documented) |
| OQ4 | `ABSOLUTE` fee class: `FIXED` uncapped for public calls that move no amount (wrap, addReserve, cancelNonce), extending CTR-ZTH-07 beyond Zether | **Accept.** The wallet shows the exact amount; the 1 % cap protects a signer from percentages it cannot recompute, which do not exist here |
| OQ5 | Zether `fund` over a **SCaaS** underlying by an EOA: a `TradeOrder` cannot bind the receiving UA | Let `fund` draw from the signer's **public** Zether balance (burn `amount · shieldScale`, escrow unchanged) instead of pulling the underlying a second time; an EOA then `mtxWrap`s by signature and funds through `mtxExecute(fund)` |
| OQ6 | ~~`destination` field~~ | **Closed — owner-accepted 2026-10-08 (A14).** |

## 11. Revision history

| Rev | Date | Commits | Content |
|---|---|---|---|
| 1 | 2026-10-07 | `db68c51`, `490b9ba`, `4472549` | MG-1…MG-9, owner answers A1–A8, defaults Q1–Q4b |
| 2 | 2026-10-07 | (uncommitted) | Review 1 folded (C1, H1–H9, M1–M11, L1–L9); owner inputs A9 (signature wrap), A10 (`TradeOrder` = modernized `MtxTradeOrder`, with the owner's correction: `relayer` kept as the matching party, `dex` added), A11 (CREATE2); §3.1 `msg.sender` table; fee classes; ticket; Zether binding; MG-8 rewritten; changes-to-rules list; open questions OQ1–OQ6 |
| 3 | 2026-10-07 | (uncommitted) | Owner rulings: funds move **only into `dex`** on both paths (old `to` = `dex`; `TradeFill` loses `to`/`feeTo`; the DEX pays destinations, fees and refunds and keeps its balances unchanged); orders carry **no role** (`maker` → `from`; taker/maker decided at settlement; fee rate by role ≤ `maxFeePpm`); the RFQ `taker` field **dropped** (Q4b's "`taker` optional" withdrawn); DEX fee back on the received side; OQ6 reworded |
| 4 | 2026-10-08 | (uncommitted) | Owner rulings A12–A15: old field names `amount`/`receiveToken`/`receiveAmount`; `minFill` kept under a protocol floor `MIN_FILL` = 50 % — effective minimum `max(minFill, ceil(amount/2))` on every order in a settlement (sold and received side), `minFill = amount` ⇒ FOK; `destination` accepted (OQ6 closed); one fee field `fee` (`maxFeePpm`, `relayerFee`, `relayerFeeRecipient` removed), distributed by the DEX per an admin-set split that cannot change the amount; `TradeFill` = `sellFill`, `receiveFill`, `dexFee`, `submitter` |
| 5 | 2026-10-08 | (this, uncommitted) | Review 2 folded (FIX-THEN-GO): N-H1 owner decision (contract-only `dex`, residual risk + client/node mitigations); N-M1 closed-order and zero-fill checks; N-M2 MG-8.4 outside-token legs; N-M3 `ProceedsShort` dropped for conservation + exact-transfer listing; N-M4 `chainUid` in Zether rollover/mode/`entryRef` digests and the built registry; N-M5 Zether `fund` from the public balance, `mtxWrap` on Zether; Lows L-1…L-12; round-1 partials M1, M2, M6, L2, L5 completed |

## 12. Review 1 disposition

Review: `docs/reviews/specs/2026-10-07-metatx-generic-claude-review-1.md`. Every finding was checked against the code
it cites; all citations held.

| Id | Finding | Disposition | Where |
|---|---|---|---|
| C1 | Path B legs sign no price | Accepted — Path B legs are `TradeOrder`s (A10) | MG-8.1, MG-8.3 |
| H1 | Same-slot guard blocks every guarded self-call | Accepted — one-shot ticket | MG-1 |
| H2 | ~20 direct `msg.sender` reads | Accepted — full table, lint, `from ≠ this`, no transfers to `this` | §3.1, MG-1 |
| H3 | `approve` by ERC-1271 for contract accounts | Accepted — `approve` in no allowlist | MG-2, MG-7 |
| H4 | Role functions via signature bypass holder policy | Accepted — none allowlisted; Q3 flipped | MG-2, OQ1 |
| H5 | Fees for non-value calls | Accepted — fee classes; `to = value = 0` | MG-5 |
| H6 | Zether loses the envelope binding | Accepted — transient binding; `relayed*`/`OuterFee` deleted | MG-2.1 |
| H7 | `dex` = EOA is an EOA permit | Accepted — `dex` (the old `to`) is the only caller and the only recipient: the token checks `msg.sender == o.dex && _isContract(o.dex)` and moves funds only to it; separate from the kept `relayer` (who may match) | MG-7, MG-8.1, MG-8.2 |
| H8 | `TradeOrder` lacks DEX fee, IOC/FOK, relayer fee, per-order cancel | Accepted, **adjusted by the owner (A13, A15)**: one signed `fee` rate (the DEX pays the relayer a share of it), `flags` IOC/ESCROW, `minFill` with the 50 % floor (`minFill = amount` ⇒ FOK), `mtxCancelOrder` and per-lane `mtxInvalidateNonces`; no `taker` field | MG-8.1–8.3 |
| H9 | Salt only on token domains | Accepted — every domain, with sources | MG-4 |
| M1 | Token cannot see `buyFill` (now `receiveFill`) delivered | Accepted — every leg goes only into the DEX (owner ruling), which pays every party and keeps its balances unchanged; **completed rev 5**: `sellFill > 0` and `p < amount` now in MG-8.2 (review 2 N-M1); the per-party delta check is replaced by conservation + exact-transfer listing (N-M3) | MG-8.2, MG-8.3 |
| M2 | Path composition, outside tokens | Accepted — leg table, `DexOrder`; **completed rev 5**: MG-8.4 (review 2 N-M2) | MG-8.3, MG-8.4 |
| M3 | Zero-fill burning, fee sticking, conservation, lanes | Accepted — signed `minFill` with the 50 % protocol floor for every order (owner A13), fees paid out in the call per the split (never kept), balance-unchanged invariant; lane issue gone (orders use `pulled`, not sequential nonces) | MG-8 |
| M4 | Contradicts CTR-UA-19/NET-ALL-22; CREATE claim; fork claim | Accepted — one source (implementation immutable, factory check); design changed to CREATE2 (A11) so the address claim now holds; fork limit stated | MG-4, §7, OQ3 |
| M5 | Derived UA cannot be a self-call sender | Accepted — `ua*` keeps explicit shapes in the one base | MG-9 |
| M6 | EOAs cannot wrap a SCaaS underlying | Accepted (owner A9) — `mtxWrap`; **completed rev 5**: Zether `fund` from the public balance (OQ5 accepted), `mtxWrap` on `ZetherToken` (review 2 N-M5) | MG-7b, §3.1, MG-2, §7 |
| M7 | Alias return type; `pay` shape; tender missing | Accepted — alias returns `bool`; `pay(bytes32)` stays a built-in shape; tender in MG-6/§7 | MG-1, MG-6 |
| M8 | `PaymentSettled`, R132, Q2 need decoding | Accepted — payment stays built-in; self-calls carry no `to`/`value`; fee-class table is the decoder | MG-1, MG-5 |
| M9 | Unlisted rule changes | Accepted | §7, OQ2 |
| M10 | `transferFrom` trust boundary | Accepted — not allowlisted | MG-2 |
| M11 | Relayer exposure | Accepted — breaker per `(from, selector)` | MG-6 |
| L1 | Selectors, not names; short `data` | Accepted | MG-1, MG-2 |
| L2 | Several digests per intent | Accepted for static selectors (length check, `transfer` refused); for dynamic Zether selectors the node canonicalizes — an on-chain re-encode check is **rejected**: only the signer can produce a variant (`data` is signed) and the sequential nonce lets only one execute (reason corrected rev 5, review 2 L-2); **rev 5** also drops Single's `unwrap(uint256,address)` | MG-2 |
| L3 | `mtxCancelNonce` is not signed | Accepted — `cancelNonce`, allowlisted | MG-2, MG-3 |
| L4 | Allowlist gaps | Accepted — `renounceGuardian` moot (H4); Zether `wrap`/`unwrap` listed | MG-2 |
| L5 | Names before code | Accepted; `selector` in `MetaTransactionExecuted` **rejected** (the transaction input carries it); **completed rev 5**: every `mtxTrade`/DEX error, `LegSettled`, return types, `Settlement.ref` (review 2 L-9) | §9 |
| L6 | Mandates vs "no EOA allowance" | Accepted | MG-7 |
| L7 | v1 coverage notes | Accepted | MG-9 |
| L8 | NatSpec now false | Accepted | §6 step 3 |
| L9 | Hedera | Accepted | MG-4, MG-7 |

## 13. Review 2 disposition

Review: `docs/reviews/specs/2026-10-07-metatx-generic-claude-review-2.md` (verdict FIX-THEN-GO). Code citations
re-checked (`ZetherToken.sol:247, 259, 328, 581, 619-623`; `UniversalAccountRegistry.sol:54, 95-97, 118-135`;
`OpenFactoryV2.sol` `versionOf`); all held.

| Id | Finding | Disposition | Where |
|---|---|---|---|
| N-H1 | Any contract named `dex` can take the signed `amount` | **Owner decision (2026-10-08): not fixed on chain.** `dex` must be a contract, nothing more — no factory DEX registry, no codehash allowlist. Recorded as an owner-accepted residual risk with off-chain mitigations: clients warn and by default refuse to build/sign for a `dex` off the chain profile's DEX list; the wallet's EIP-712 view shows `dex`; the node never routes orders for unlisted DEXes | §4, MG-6, MG-7, §7 (CTR-TOK-01), §8 Q5 |
| N-M1 | Remainder clause admits a closed order with `sellFill = 0` | Accepted — `p < amount` (`OrderClosed`) before the path split; `sellFill > 0` on Path A; `sellFill == amount` on Path B; `minFill ≤ amount`; identity refusals | MG-8.2 |
| N-M2 | Outside-token legs unspecified | Accepted — MG-8.4: DEX-side fill state and cancels, same checks, `o.dex == this`, no `ESCROW`, kind from the listing via the factory | MG-8.4 |
| N-M3 | `ProceedsShort` ambiguous with shared addresses | Accepted, option (a): dropped. Its expected figure comes from the same code that pays, so it cannot catch a DEX bug, and per-party deltas misfire on shared addresses; token misbehaviour is caught by conservation plus exact-transfer listing | MG-8.3 |
| N-M4 | Zether rollover/mode/`entryRef` digests and the built registry lack `chainUid` | Accepted — all Zether chain-bound digests add `chainUid`; `UniversalAccountRegistry` gets a `chainUid` constructor immutable (per-chain CREATE2 address) and in its PoP; callers' raw digests carry it | MG-4, §7 |
| N-M5 | OQ5 not folded | Accepted — `fund` always draws from the public balance (one path, escrow unchanged); §3.1, MG-2, MG-3, MG-7b and §7 (`zether.md:213-215`) updated | MG-7b, §3.1, MG-2, MG-3, §7 |
| L-1 | Reentrancy declarations | Accepted — all `mtx…` trade/wrap/cancel entries and every allowlisted function `nonReentrant`, pinned by a test | MG-1, MG-2, MG-7b, MG-8 |
| L-2 | `unwrap(uint256,address)` duplicate; wrong rejection reason | Accepted — 2-argument form not allowlisted; reason corrected | MG-2, §12 L2 |
| L-3 | `mtxWrap` underspecified; §3.1 row | Accepted | MG-7b, §3.1 |
| L-4 | Path B `TradeFill`; accounting event | Accepted — `sellFill == amount`; `LegSettled` | MG-8.2, MG-8.3, §9 |
| L-5 | Taker fee once; split rounding | Accepted | MG-8.3 |
| L-6 | Virtual signature check; self identities | Accepted | MG-8.2 |
| L-7 | Domain name for Zether sell tokens | Accepted | MG-8.1 |
| L-8 | Stale text | Accepted — OQ3/OQ5 sentences, MG-5 balance-check wording, §7 CTR-DEX-04/05 remainder | MG-4, MG-5, MG-7b, §7 |
| L-9 | Missing names | Accepted | §9 |
| L-10 | Relayer share as a self-submitter rebate | Accepted — stated; clients default `relayer` to the venue node | MG-8.3, MG-6 |
| L-11 | `destination` in the signing view | Accepted | MG-6 |
| L-12 (a)–(d), (f) | Per-chain account addresses; `MandateWallet` uid wording; clone separator; Zether prover/vectors; `minFill > amount` | Accepted (`minFill > amount` refused, `BadMinFill`) | MG-4, MG-6, MG-8.1, MG-8.2 |
| L-12 (e) | Two nonce systems both named `batch` | Rename **rejected**: the owner kept the old field name `batch` (A10, A12) and the two live in different maps (`_metaNonce`, `minNonce`); accepted in part — clients label the meta-tx lane and the order lane, and the struct comment says so | MG-8.1, MG-8.2, MG-6 |
