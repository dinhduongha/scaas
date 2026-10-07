# Meta-transactions: generic self-call, `mtx` names, `chain_uid` in every domain, token-verified trade orders

**Status:** DRAFT **rev 2** for owner review — nothing in the component docs or the code changes until it is accepted.
Provisional ids `MG-n`; real ids are allocated in `docs/decisions.md` on acceptance (docs/README "Ids").
**Date:** 2026-10-07. **Scope:** EVM and Hedera tokens (today v1 `ERC20MetaTx`/`MetaToken`/`HederaMetaToken`, v2
`MetaTxCore`/`MetaTokenBase` with three tiers, `ZetherMetaTx`/`ZetherToken` — folded into one base by MG-9), the DEX
settlement (`OrderBookDex`, `MetaTxDex`), the EVM signed entry points of `MandateWallet` and `SubjectAccount`, every
EIP-712 domain we deploy, the deploy scripts, and what the node, clients and docs must change with them. Nothing is
deployed anywhere, so the design changes in place: no version coexistence, no migration. Code paths below are relative
to `smartcontracts/evm/src/`.

Rev 2 folds in review 1 (verdict BLOCK: 1 Critical, 9 High, 11 Medium, 9 Low) and three owner inputs of the same day
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

## 2. Owner answers (2026-10-07)

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
| A10 | `TradeOrder` | **The owner's `MtxTradeOrder` modernized** — one struct for both paths, fields mapped in MG-8.1. Owner correction: `relayer` keeps its meaning (the matching party, 0 = anyone, paid the relayer fee); a separate new `dex` names the settlement contract |
| A11 | Deployment | **CREATE2 everywhere:** implementations, factories, registry and DEX are deployed through a deterministic CREATE2 deployer with a fixed salt (MG-4) |

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
the ticket is spent). Allowlisted functions without `nonReentrant` (`burn(uint256)`, `cancelNonce`) make no outward
call. `mtxBatch` sets a fresh ticket per item.

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
| `ZetherToken.sol:208` | `fund` source | `_msgSender()` |
| `ZetherToken.sol:288, 299` | `OuterFee(msg.sender, …)` in direct calls | `OuterFee` deleted: the outer fee is MG-1 step 6 (H6) |
| `ZetherToken.sol:469, 475, 488` | `relayed*` self-only checks | deleted with `relayed*` (H6) |
| `ZetherToken.sol:589` | `attestTransferAmount` attester | `_msgSender()` (not allowlisted) |
| `ZetherMetaTx.sol:52` | `cancelMetaNonce` | `_msgSender()` (file folded into the base, MG-9) |
| `ZetherMetaTx.sol:59-60, 74, 79` | relayer binding, default fee recipient, event | **stay** `msg.sender` (folded) |
| `ZetherMetaTx.sol:103` | `transferFrom` caller | `_msgSender()` (folded) |
| new `mtxTrade`, `mtxWrap` (MG-8, MG-7b) | `msg.sender == o.dex` | **stays** `msg.sender`; neither is allowlisted |

### MG-2 — Selector allowlist per implementation

Each implementation declares its allowlist as constants: exact selectors (overloads listed one by one, L1), each with
a fee class (MG-5). `mtxSelectors() returns (bytes4[] selectors, uint8[] feeClass, uint8[] amountArg)` publishes it; a
test pins it.

| Implementation | Self-call selector | Fee class |
|---|---|---|
| every token | `cancelNonce(uint256)` | `ABSOLUTE` |
| `NoUnderlyingToken` | `burn(uint256)` | `AMOUNT(0)` |
| `SingleUnderlyingToken` | `wrap(uint256)` | `ABSOLUTE` (fee from minted units) |
| | `unwrap(uint256,address)`, `unwrap(uint256,address,uint256)` | `AMOUNT(0)` |
| | `addReserve(address,uint256)` | `ABSOLUTE` |
| `MultiUnderlyingToken` | `wrap(address,uint256)` | `ABSOLUTE` |
| | `unwrap(address,uint256,address,uint256)` | `AMOUNT(1)` |
| | `addReserve(address,uint256)` | `ABSOLUTE` |
| `ZetherToken` | `wrap(uint256)` | `ABSOLUTE` |
| | `unwrap(uint256,address)` (public balance) | `AMOUNT(0)` |
| | `fund(bytes,uint256)` | `ABSOLUTE` |
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

For selectors with dynamic arguments (Zether) the contract cannot cheaply pin one encoding; the node re-encodes the
decoded arguments and refuses non-canonical `data` before it computes the mesh `intent_id`. A non-canonical duplicate
that reaches the chain is harmless: the proof's `sendCounter` lets only one execute.

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
| tokens | `executeMetaTransactionWithFee` | `mtxExecuteWithFee` |
| tokens | `cancelMetaNonce` (a direct call) | `cancelNonce(uint256 batch)` — direct, or signed through `mtxExecute` on another lane (L3) |
| tokens | `metaNonce`, `metaTxDigest` (views) | `mtxNonce`, `mtxDigest` |
| tokens | `mtxTransfer`, `mtxTransferWithFee`, `mtxPay`, `mtxBatch` | unchanged (typed builders of the transfer/payment shapes) |
| tokens | `mtxUnwrap`, `mtxUnwrapWithFee` (+ their `fallback` decoder) | **deleted**: the `unwrap` pseudo-op is gone; `mtxExecute` with real `unwrap` calldata replaces them |
| tokens | — | `mtxTrade`, `mtxCancelOrder`, `mtxInvalidateNonces` (MG-8), `mtxWrap` on wrappers (MG-7b) |
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
| `UARegistry` (planned) | its CTR-UA-07 domain | constructor immutable (NET-ALL-22, unchanged) |
| any future contract with a signature (tender, asset suite) | — | the same helper, constructor argument |

Non-EIP-712 chain bindings of `ZetherToken` — the statement header (`_header`), `envelopeBinding` and the disclosure
challenge, which today carry `block.chainid` — add `chainUid` beside it.

- **Who makes it right:** the deploy script reads the genesis hash from the RPC; the deploy gate and the node, at chain
  activation and every start, require each contract's `chainUid()` = the RPC's genesis hash = the chain profile, and
  refuse a mismatch (the node also refuses to relay for a wallet or account whose `chainUid()` differs). A contract
  cannot read its own genesis hash after block 256, so this is checked off chain; a wrong value only makes correct
  signatures fail (fail-safe). The factory check removes the second source the review found (M4): a clone's value is
  its implementation's, and the factory only registers implementations that match its own.
- **Addresses (owner A11, CREATE2):** the deploy scripts move from `new` (CREATE, address = f(deployer, nonce)) to a
  deterministic CREATE2 deployer with a fixed salt. A contract whose constructor takes `chain_uid` (implementations,
  factories, `SubjectAccountFactory`, `OrderBookDex`, `UARegistry`) gets a **different address on each chain**,
  because its init code differs; so does every clone, whose CREATE2 address depends on the implementation and the
  factory. A contract with no chain-specific constructor argument gets the **same address on every chain**. Safety does
  not rest on the address: the salt is in every digest.
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
  already present in any chain profile is refused. (a) needs an owner rule — OQ3.
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
so the step-1 balance check covers nothing but the fee, and step 6 charges it after the call. `ABSOLUTE` extends the
owner's confidential rule (CTR-ZTH-07: `FIXED` absolute, uncapped, because there is no public amount to take a
percentage of) to public calls that move no amount of this token; the wallet shows the exact fee. This narrows
CTR-MTX-13 (OQ4).

`PaymentSettled` keeps its fee amount and recipient because payment is a built-in shape, not a self-call (M8).

### MG-6 — What else changes

| Area | Change |
|---|---|
| Node | Pricing and display decode `data` with the published allowlist (selector → fee class, amount argument); canonical re-encoding check for dynamic selectors (MG-2); a **breaker per `(from, selector)`** for self-calls that pass simulation and fail on chain (M11: rate-change pauses, Zether `sendCounter`, reserve level, a signer front-running its own intent); `mtxCancelOrder`, `mtxInvalidateNonces` (token) and `mtxWrap` (wrapper) become metatx-job entry points (`mtxTrade` is called only by the DEX or a wrapper); call table (NODE-JOB-01/19) renamed rows (`mtxExecuteAsOwner`, `mtxPayUnderMandate`, `mtxRevoke`, `OrderBookDex.mtxSettle`/`mtxCancelOrders`/`mtxInvalidateNonces`); `chainUid()` checks (MG-4) |
| Clients | clientkeys and the app encode `mtxExecute` calldata, decode `data` to show "what you sign" (selector + arguments), fill `domain.salt`, build and display `TradeOrder` (showing `dex` against the chain profile's DEX list, H7) |
| ERP connector example | encoders and selectors follow the new names |
| Deploy | scripts move to a CREATE2 deployer (A11); deploy gate checks `chainUid()` and refuses a known genesis hash (MG-4) |
| Vectors | KATs for every salted domain, `mtxExecute` calldata, `TradeOrder`/`CancelOrder`/`InvalidateNonces` |
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
  nothing.
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

#### MG-7b — Signature wrap of a SCaaS underlying (owner A9, review M6)

When a wrapper's underlying is itself a SCaaS token, an EOA cannot approve the wrapper. It signs a `TradeOrder` (MG-8)
in the **underlying's** domain with `dex = the wrapper`, `buyToken = the wrapper`, `buyAmount` = the minimum it
accepts to receive (its `minOut`), `minFill = sellAmount`:

```solidity
function mtxWrap(address underlying, TradeOrder calldata o, bytes calldata sig) external returns (uint256 minted);
```

The wrapper checks `o.buyToken == address(this)`, quotes `minted` at the leg's current rate, calls
`underlying.mtxTrade(o, sig, TradeFill(o.sellAmount, minted, address(this), 0, address(0), msg.sender))` — the
underlying checks the signature, that the wrapper is `o.dex`, the `relayer` binding against the submitter, and the price `sellAmount·buyAmount ≤ minted·sellAmount` — measures the
received amount as `_pull` does, records the reserve and mints `minted` to `destination` (or `maker`). No allowance;
only the named wrapper can pull, and only at the signed minimum. The relayer fee rides in the order (MG-8.1). The
wrapper's own call to the underlying is a wrap function talking to its underlying, as `_pull` does today, not the
meta-tx gateway calling out (§4). Zether `fund` over a SCaaS underlying needs the UA bound in the signature, which a
`TradeOrder` has no field for — OQ5.

### MG-8 — DEX settlement without maker allowances: one struct, two paths (review C1, H7, H8, M1–M3)

#### MG-8.1 — `TradeOrder` = the owner's `MtxTradeOrder` modernized (owner A10)

```solidity
struct TradeOrder {
    address maker;               // signer; this token's balance is sold
    address buyToken;            // what the maker receives
    uint256 sellAmount;          // at most this much of THIS token in total
    uint256 buyAmount;           // signed price limit: sellAmount for at least buyAmount (net of the maker's own DEX fee)
    uint256 minFill;             // smallest sellFill in one settlement (0 = any; = sellAmount ⇒ fill-or-kill)
    address relayer;             // the matching party allowed to submit the settlement (0 = anyone); paid the relayer fee
    address dex;                 // the only settlement contract that may pull funds for it; must be a contract
    address destination;         // receives the proceeds in buyToken; 0 = maker
    address taker;               // 0 = any counterparty
    uint32  maxFeePpm;           // max DEX fee rate on the amount sold, ≤ 10 000
    uint8   flags;               // IOC 1 | ESCROW 2 (Path B; implies IOC)
    uint256 relayerFee;          // in THIS token, for the whole order, paid pro-rata per fill, ≤ 1 % of sellAmount
    address relayerFeeRecipient; // 0 = the relayer (bound or submitting); never the dex
    uint256 batch;               // cancel lane
    uint256 nonce;               // valid while nonce ≥ minNonce[maker][batch]
    uint256 validUntil;
}
// "TradeOrder(address maker,address buyToken,uint256 sellAmount,uint256 buyAmount,uint256 minFill,address relayer,address dex,"
// "address destination,address taker,uint32 maxFeePpm,uint8 flags,uint256 relayerFee,address relayerFeeRecipient,"
// "uint256 batch,uint256 nonce,uint256 validUntil)"
```

Signed in the **sell token's** domain `("SCaaS MetaToken","1", chainId, verifyingContract = the token, salt =
chain_uid)`.

| Old `MtxTradeOrder` (`MtxTradeOrderLib.sol`) | New `TradeOrder` | Note |
|---|---|---|
| `from` | `maker` | — |
| `amount` | `sellAmount` | Path B pulls all of it; Path A pulls fills up to it (`pulled[orderHash]`) |
| `receiveToken` | `buyToken` | — |
| `receiveAmount` | `buyAmount` | the signed price limit, checked cross-multiplied |
| `relayer` (0 = anyone) | `relayer` — **kept** | the matching party: when ≠ 0 only it may submit the settlement (checked by the DEX against its `msg.sender`, and by the token against the submitter the DEX reports); it earns the relayer fee — the same meaning as `MetaTransaction.relayer` / `MODE_RESTRICT_RELAYER` |
| — | `dex` — **new** | the only settlement contract that may pull funds for the order; must be a contract, never 0 (checked by the token: `msg.sender == o.dex`, H7) |
| `to` (always the DEX) | `destination` | where the sold tokens go is now the fill's `to` (counterparty or DEX); the signed address names who receives the **proceeds** — see OQ6 |
| `fee` (ppm, DEX fee) | `maxFeePpm` | the DEX fee rate the signer accepts; charged on the amount **sold** (below) |
| `batch`, `nonce`, `validUntil` | kept | `nonce` no longer consumed per fill: it is the cancel handle (`minNonce` per lane); per-order cancel added |
| `chainId`, `contract` | EIP-712 domain | `chainId`, `verifyingContract` = the token, `salt` = `chain_uid` |
| — | `minFill`, `taker`, `flags`, `relayerFee`, `relayerFeeRecipient` | taker-signed minimum, counterparty binding, IOC/escrow, relayer pay (H8) |
| `signature` (in the struct) | separate `bytes sig` argument | a signature cannot be inside what it signs |

Not reused from the old code, and why:

| Old | Why not |
|---|---|
| `toEthSignedMessageHash` prefix (`SignatureValidator.sol:10`) | `personal_sign` shows 32 opaque bytes; EIP-712 shows every field (CTR-MTX-14) |
| `contract` field | a reserved word in Solidity ≥ 0.5, and redundant with `verifyingContract` |
| `ERC1776` base (`ERC1776Tradeable.sol:4`, file absent) | the base is `ERC20MetaTx` (MG-9) |
| `MIN_RECEIVE_PERCENTAGE` = 50 % (`ERC1776Dex.sol:10, 110-111`) | replaced by the signer's own `minFill` and price limit |
| `PRECISION` rate division (`ERC1776Dex.sol:41, 64, 78`) | rounds against the maker; replaced by exact cross-multiplied limits rounded in each signer's favour |
| no executor binding (`ERC1776Tradeable.sol:23` compares `relayer` with the token's caller, which is the DEX, not the matching party; `to` is checked against nothing) | with `relayer = 0` any contract or EOA could pull the leg; split into `dex` (who may pull, checked by the token) and `relayer` (who may match, checked by the DEX) |
| fee to `address(this)` when no recipient (`:141`) | the fee would stick in the DEX; the recipient must be set and ≠ DEX |
| `Rescuable` admin sweep | the DEX never holds funds after a call (conservation check below); no sweep |

#### MG-8.2 — The token's side

```solidity
struct TradeFill { uint256 sellFill; uint256 buyFill; address to; uint256 dexFee; address feeTo; address submitter; }
function mtxTrade(TradeOrder calldata o, bytes calldata sig, TradeFill calldata f) external;
function mtxCancelOrder(TradeOrder calldata o, bytes calldata sig) external;          // CancelOrder(bytes32 orderHash)
function mtxInvalidateNonces(address maker, uint256 batch, uint256 newMin, bytes calldata sig) external;
                                                       // InvalidateNonces(address maker,uint256 batch,uint256 minNonce)
mapping(bytes32 => uint256) public pulled;                         // orderHash => amount pulled (sellAmount = closed)
mapping(address => mapping(uint256 => uint256)) public minNonce;   // maker => batch => min valid nonce
```

`mtxTrade` checks, in order: `msg.sender == o.dex` and `_isContract(o.dex)`; `o.relayer == 0 || o.relayer ==
f.submitter` (the DEX reports its own `msg.sender` as `submitter`); `block.timestamp ≤ validUntil`;
`o.nonce ≥ minNonce[maker][batch]`; known flags (`ESCROW` requires `IOC`); `sellAmount, buyAmount > 0`;
`maxFeePpm ≤ 10 000`; the relayer-fee bounds; the signature (EOA or ERC-1271, capped gas) over `h` = the order's
digest; then with `p = pulled[h]`:

- **Path A** (`ESCROW` clear): `f.sellFill ≥ max(minFill, 1)` unless it is the remainder; `p + f.sellFill ≤
  sellAmount`; price `f.sellFill · buyAmount ≤ f.buyFill · sellAmount` (checked multiplication); `f.dexFee ≤
  ceil(f.sellFill · maxFeePpm / 10⁶)` (CTR-DEX-11) and `f.dexFee < f.sellFill`; `feeTo ≠ 0` if `dexFee ≠ 0`.
- **Path B** (`ESCROW` set): `p == 0`, `f.sellFill == sellAmount`, `f.to == msg.sender` (the DEX), `buyFill`/`dexFee`
  ignored — the DEX enforces price and fees on the matched part (MG-8.3).
- Effects: `pulled[h] = IOC ? sellAmount : p + f.sellFill` (an IOC order is pulled **once**: one pull per order per
  settlement, below). Then: `sellFill − dexFee` maker → `to`; `dexFee` maker → `feeTo`; Path A relayer fee
  `relayerFee · sellFill / sellAmount` (floor) maker → `relayerFeeRecipient`, else `relayer`, else `f.submitter`
  (never the DEX: `FeeWouldStick`), on top. Emit
  `TradeFilled(h, maker, to, sellFill, buyFill, dexFee, relayerFee)`.

`mtxCancelOrder` sets `pulled[h] = sellAmount` (emit `OrderCancelled(h, maker)`); `mtxInvalidateNonces` raises
`minNonce[maker][batch]` (strictly increasing, capped 2¹²⁸, emit `NoncesInvalidated`). Neither signature expires
(CTR-DEX-02 kept). A maker with orders on several tokens cancels per token; the off-chain book drops them at once.

#### MG-8.3 — The DEX's side: `mtxSettle`, one taker against many makers

```solidity
struct Leg { address sellToken; TradeOrder o; bytes sig; uint256 fill; }  // fill = sellFill of this leg in this call
struct Settlement { bytes32 ref; Leg taker; Leg[] makers; }
function mtxSettle(Settlement[] calldata s) external returns (bool[] memory ok); // each settlement atomic (try), as today
```

Rules: every leg's `relayer` is 0 or `msg.sender` (`WrongRelayer`), and the DEX passes `msg.sender` as `submitter`
to every `mtxTrade`; every maker's `sellToken` is the taker's `buyToken` and vice versa; no self-trade; the market is
listed; the DEX computes the match first and **pulls only legs with a fill > 0** (M3: zero-fill legs are not consumed); each order is
pulled **at most once per call**; prices are each maker's signed price, rounded in the maker's favour.

| Leg | Sold tokens go | Price checked by | DEX fee / relayer fee paid by |
|---|---|---|---|
| maker, Path A | `to = taker's destination` (direct) | the maker's token | the maker's token (`dexFee`, `relayerFee`) |
| maker, Path B | `to = DEX`, then matched part to the taker, **remainder refunded** to the maker in the same call | the DEX, on the matched part, against the signed order | the DEX, out of the escrow, pro-rata on the matched part |
| taker, Path A, one maker | `to = maker's destination` (direct) | the taker's token | the taker's token |
| taker, Path A, many makers | `to = DEX` (one pull of the total), the DEX pays each maker | the taker's token, on the total | the taker's token |
| taker, Path B | `to = DEX`, matched parts to the makers, remainder refunded | the DEX | the DEX |
| any leg whose sell token is an **outside** ERC-20 (M2) | `safeTransferFrom` under the party's allowance to the DEX (A6) | the DEX, with the same `TradeOrder` signed in the DEX's domain as `DexOrder(address sellToken, TradeOrder order)` | the DEX |

**Trust (M1).** In Path A the token caps what leaves the maker (amount, price relative to the claimed `buyFill`, fee
rate, executor); it cannot see the counter leg arrive. The maker trusts the contract it named in `dex` — immutable
code on the chain profile's DEX list — to deliver. The DEX enforces delivery itself: after each settlement it asserts
that each party's `destination` received at least its `buyFill` in `buyToken` (balance delta; fee-on-transfer outside
tokens are refused at listing) and that the DEX's own balance of every token touched is unchanged (no dust, no
donations paid out — M3 conservation). In Path B the signer trusts the DEX with price as well, by choosing `ESCROW`.

**Fees.** The DEX fee is per market (`makerFeePpm`/`takerFeePpm`, cap 1 %, ≤ the order's `maxFeePpm`), rounded up per
fill (CTR-DEX-11), charged on the amount **sold**, in the sold token, to the market's fee recipient (≠ DEX). Moving it
from the received side (today and the old code) to the sold side is what lets each signer's own token enforce it in
Path A. The relayer fee is the order's `relayerFee`, in the sold token, to `relayerFeeRecipient`, else the bound
`relayer`, else the submitting relayer (`feeToken` and the separate relayer `feeMode` are gone: `FIXED` pro-rata and
`PERCENT` are the same function of the fill). The relayer binding works as today (CTR-DEX-06, `OrderBookDex.sol:263`):
a maker that only wants to trade through relayer X signs `relayer = X`.

`OrderBookDex` keeps its book semantics (price-time priority, limit + IOC/FOK, partial fills in the node's book) with
`mtxSettle` replacing `settle`; its DEX-domain `Order` survives only as `DexOrder` for outside sell tokens. The legacy
`MetaTxDex` is deleted. Non-EVM DEXes keep their own leg shapes (Q4).

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
| Zether envelope stripping | Binding passed by transient slot; direct calls prove with binding 0 (MG-2.1) |
| Fees on non-value calls | Per-selector fee class (MG-5) |
| DEX legs | Price, minimum fill, settlement contract (`dex`), matching party (`relayer`), fee rate signed; checked by the token (Path A) or by the named DEX (Path B); `dex` must be a contract; one pull per order per call; zero-fill legs not pulled; DEX delivery and conservation asserted |
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
   makers, zero-fill legs untouched, conservation; salted-domain KATs; tender deposit through the alias.
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
| CTR-TOK-01 | spender must be a contract; only contracts call `transferFrom` | also the **caller** of `approve`; `TradeOrder.dex` likewise |
| CTR-TOK-14 | gasless wrap planned via a permit op | `mtxExecute(wrap)` (underlying allowance) or `mtxWrap` (SCaaS underlying, signature) |
| CTR-TOK-03/12 | factory v2 beside factory v1 and v1 clones | one factory `OpenFactory` (the v2 code) |
| CTR-DEX-01 | DEX checks two DEX-domain orders, is the only spender, fee on the received part | SCaaS legs are token-verified `TradeOrder`s, no spender; fee on the sold part; DEX-domain order only for outside tokens |
| CTR-DEX-02 | `CancelOrder`/`InvalidateNonces` on the DEX | the same, per token (`mtxCancelOrder`, `mtxInvalidateNonces` per lane); never expire |
| CTR-DEX-04/05 | IOC closed and FOK checked by the DEX | the token closes IOC at its single pull; FOK = `minFill = sellAmount` |
| CTR-DEX-06 | relayer fee `feeMode`/`fee`/`feeToken`, `relayer` binding | one `relayerFee` in the sold token (recipient: signed, else the bound or submitting relayer); `relayer` binding kept; no `feeToken` |
| CTR-DEX-07 | `MetaTxDex` legacy | deleted |
| CTR-UA-19 | domain version `"3"`; clone copies `registry.chainUid()` at `initialize` | version `"1"`; `chain_uid` is the implementation's constructor immutable |
| `accounts.md` signer table (`MetaTxDex`, `OrderBookDex` rows) | `settle`, `MetaTxDex.settle(a, b)` | `mtxSettle`, token `mtxTrade`; `MetaTxDex` row removed |
| NET-ALL-22 | `chain_uid` in UA domains; "constructor argument makes the CREATE2 address differ" | in **every** SCaaS domain and Zether binding; CREATE2 deployer stated (A11); fork limit stated |
| NODE-JOB-01/19 | call-table rows `executeAsOwner`, `payUnderMandate`, `revokeWithSig`, `OrderBookDex.settle/cancel/invalidateNonces` | renamed (MG-3); role calls still only through role-holder contracts, now also for gasless token calls |
| CTR-TND-07 | deposit token from factory v1 or v2 | from the one factory |
| CTR-ZTH-11 | `fund` direct only; only transfer and burn have envelope ops | `fund`, public `wrap`/`unwrap` also via `mtxExecute` |
| CTR-ZTH-06 | binding passed by `relayed*` | passed by transient slot; `relayed*` deleted |
| CTR-ZTH-16/17 names | `rollOverSigned`, `setRollOverMode` | `mtxRollOver`, `mtxSetRollOverMode` (rules unchanged) |
| CTR-ACC-07 name | `revokeWithSig` | `mtxRevoke` (rule unchanged) |

## 8. Defaults (rev 1 §7, updated)

| # | Question | Default (rev 2) |
|---|---|---|
| Q1 | Add `token` / `chainId` / `chain_uid` to the signed struct? | No: the domain binds them; the node routes by `(chain_key, contract)` and verifies the digest |
| Q2 | Meaning of `to`/`value` when `data` is a self-call | **Changed:** both must be 0; the fee basis comes from the selector's fee class (MG-5) |
| Q3 | Role functions in the allowlists | **Changed (H4): none** — OQ1 |
| Q4b | Order fields | Replaced by MG-8.1 (A10) |
| Q4 | Same rule for non-EVM families | Separate draft after this one |

## 9. Names fixed before code (review L5)

| Kind | Names |
|---|---|
| Transient slots | `keccak256("scaas.mtx.guard")`, `"scaas.mtx.sender"`, `"scaas.mtx.ticket"`, `"scaas.mtx.binding"` (written as literals: assembly takes no `keccak256` constant) |
| Errors | `MtxSelectorNotAllowed(bytes4)`, `MtxDataShape(bytes4)`, `MtxEnvelopeShape()`, `MtxFeeClass(bytes4, uint32 mode)`, `Reentrancy()`; inner failures bubble raw; `NotDex()`, `DexNotContract(address)`, `WrongRelayer(bytes32)`, `FeeWouldStick()`, `OrderClosed(bytes32)`, `BelowMinFill(bytes32)`, `PriceLimit(bytes32)`, `FeeAboveSigned(bytes32)` |
| Views | `mtxSelectors()`, `chainUid() returns (bytes32)`, `pulled(bytes32)`, `minNonce(address,uint256)`, `tradeOrderDigest(TradeOrder)` |
| Events | `MetaTransactionExecuted` unchanged; `TradeFilled`, `OrderCancelled`, `NoncesInvalidated` on the token |
| Typehashes | `TradeOrder(…)` (MG-8.1), `CancelOrder(bytes32 orderHash)`, `InvalidateNonces(address maker,uint256 batch,uint256 minNonce)`, `DexOrder(address sellToken,TradeOrder order)TradeOrder(…)` |
| DEX | `Leg`, `Settlement`, `mtxSettle` (MG-8.3) |

## 10. Open questions for the owner

Only what needs an owner decision; each has a recommendation.

| # | Question | Recommendation |
|---|---|---|
| OQ1 | Rev 1 default Q3 allowed role functions (`mint`, rate admin, guardian) through `mtxExecute`. Review H4: the token can then only check `isValidSignature`, which skips a minter contract's caps or a Safe's guards/timelock, and it adds a second role path beside NODE-JOB-01's "role calls only through a Safe of the role holders". Flip to "no role function allowlisted"? | **Yes, flip.** If gasless EOA minters are ever wanted, allow `mint` only when `_msgSender()` is not a contract — a separate decision |
| OQ2 | §24.3's invariant "checked before the fee, cannot fail after" becomes "self-call, then fee; any failure reverts all". Accept the new wording? | **Accept.** The user still never pays for an operation that did not happen; only the order changes, and it lets a wrap pay its fee from minted units |
| OQ3 | Forks share genesis, so `chain_uid` cannot separate two branches of a fork. Rule? | For chains we run: a fork is a new chain — new `chain_id` (EIP-155) and new `chain_key` — enforced by the deploy gate. For public chains: rely on the fork's chain-id change; without one, signatures replay on both branches (residual, documented) |
| OQ4 | `ABSOLUTE` fee class: `FIXED` uncapped for public calls that move no amount (wrap, addReserve, cancelNonce), extending CTR-ZTH-07 beyond Zether | **Accept.** The wallet shows the exact amount; the 1 % cap protects a signer from percentages it cannot recompute, which do not exist here |
| OQ5 | Zether `fund` over a **SCaaS** underlying by an EOA: a `TradeOrder` cannot bind the receiving UA | Let `fund` draw from the signer's **public** Zether balance (burn `amount · shieldScale`, escrow unchanged) instead of pulling the underlying a second time; an EOA then `mtxWrap`s by signature and funds through `mtxExecute(fund)` |
| OQ6 | The old `to` was always the DEX. In the new struct the sold tokens' route is per fill, so the signed field `destination` names who receives the **proceeds** (0 = maker). Is that the intended meaning of "to → destination"? | **Yes:** it lets a maker sell from one account and receive into another (e.g. a treasury) without trusting the DEX for the route |

## 11. Revision history

| Rev | Date | Commits | Content |
|---|---|---|---|
| 1 | 2026-10-07 | `db68c51`, `490b9ba`, `4472549` | MG-1…MG-9, owner answers A1–A8, defaults Q1–Q4b |
| 2 | 2026-10-07 | (this, uncommitted) | Review 1 folded (C1, H1–H9, M1–M11, L1–L9); owner inputs A9 (signature wrap), A10 (`TradeOrder` = modernized `MtxTradeOrder`, with the owner's correction: `relayer` kept as the matching party, `dex` added), A11 (CREATE2); §3.1 `msg.sender` table; fee classes; ticket; Zether binding; MG-8 rewritten; changes-to-rules list; open questions OQ1–OQ6 |

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
| H7 | `dex` = EOA is an EOA permit | Accepted — `dex` (who may pull) is a new field, checked `msg.sender == o.dex && _isContract(o.dex)` by the token; it is separate from the kept `relayer` (who may match, owner correction) | MG-7, MG-8.1, MG-8.2 |
| H8 | `TradeOrder` lacks DEX fee, IOC/FOK, relayer fee, per-order cancel | Accepted — `maxFeePpm`, `flags` + `minFill`, `relayer` + `relayerFee`/`relayerFeeRecipient`, `mtxCancelOrder` and per-lane `mtxInvalidateNonces` | MG-8.1, MG-8.2 |
| H9 | Salt only on token domains | Accepted — every domain, with sources | MG-4 |
| M1 | Token cannot see `buyFill` delivered | Accepted — trust stated; DEX delivery and conservation asserts; `buyAmount`, fills > 0 | MG-8.2, MG-8.3 |
| M2 | Path composition, outside tokens | Accepted — leg table, `DexOrder` | MG-8.3 |
| M3 | Zero-fill burning, fee sticking, conservation, lanes | Accepted — pull only filled legs, signed `minFill`, recipients ≠ DEX, conservation; lane issue gone (orders use `pulled`, not sequential nonces) | MG-8 |
| M4 | Contradicts CTR-UA-19/NET-ALL-22; CREATE claim; fork claim | Accepted — one source (implementation immutable, factory check); design changed to CREATE2 (A11) so the address claim now holds; fork limit stated | MG-4, §7, OQ3 |
| M5 | Derived UA cannot be a self-call sender | Accepted — `ua*` keeps explicit shapes in the one base | MG-9 |
| M6 | EOAs cannot wrap a SCaaS underlying | Accepted (owner A9) — `mtxWrap`; Zether `fund` part to the owner | MG-7b, OQ5 |
| M7 | Alias return type; `pay` shape; tender missing | Accepted — alias returns `bool`; `pay(bytes32)` stays a built-in shape; tender in MG-6/§7 | MG-1, MG-6 |
| M8 | `PaymentSettled`, R132, Q2 need decoding | Accepted — payment stays built-in; self-calls carry no `to`/`value`; fee-class table is the decoder | MG-1, MG-5 |
| M9 | Unlisted rule changes | Accepted | §7, OQ2 |
| M10 | `transferFrom` trust boundary | Accepted — not allowlisted | MG-2 |
| M11 | Relayer exposure | Accepted — breaker per `(from, selector)` | MG-6 |
| L1 | Selectors, not names; short `data` | Accepted | MG-1, MG-2 |
| L2 | Several digests per intent | Accepted for static selectors (length check, `transfer` refused); for dynamic Zether selectors the node canonicalizes — an on-chain re-encode check is **rejected** as gas for no safety gain (`sendCounter` lets one copy execute) | MG-2 |
| L3 | `mtxCancelNonce` is not signed | Accepted — `cancelNonce`, allowlisted | MG-2, MG-3 |
| L4 | Allowlist gaps | Accepted — `renounceGuardian` moot (H4); Zether `wrap`/`unwrap` listed | MG-2 |
| L5 | Names before code | Accepted; `selector` in `MetaTransactionExecuted` **rejected** (the transaction input carries it) | §9 |
| L6 | Mandates vs "no EOA allowance" | Accepted | MG-7 |
| L7 | v1 coverage notes | Accepted | MG-9 |
| L8 | NatSpec now false | Accepted | §6 step 3 |
| L9 | Hedera | Accepted | MG-4, MG-7 |
