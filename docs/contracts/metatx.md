# Meta-transactions

Every SCaaS token is gasless: the subject (the holder of the balance) signs an intent, anyone may submit it, and
the submitter pays the gas. This file specifies the EVM meta-transaction layer that all EVM and Hedera tokens share —
one base, `ERC20MetaTx`, under the three token tiers, the Zether token and the Universal Account ledger path. Other
families implement the same model natively ([networks/README.md](../networks/README.md)).

Status: the target layer of this file (one base, the generic self-call `mtxExecute`, the selector allowlist, fee
classes, `mtx` names, salted domains) is **SPECIFIED**; receiver-pays **SPECIFIED**. What runs today is two built
lines, v1 and v2, with a hand-written op dispatch (`smartcontracts/evm/src/metatx/`, **BUILT**); the differences are
listed under [Transitional (BUILT)](#transitional-built) at the end. Nothing is deployed, so the target replaces the
built lines in place: no version coexistence, no migration.

## Native mixin, no forwarder

<a id="CTR-MTX-16"></a>**CTR-MTX-16** — Meta-transaction logic is embedded in every token (`ERC20MetaTx`), not in a
forwarder. The subject signs EIP-712 typed data whose `verifyingContract` **is the token**, and the token runs the
signed call **on itself only**: `mtxExecute` either moves this token's balance (transfer, payment) or calls one of
this token's own allowlisted functions ([CTR-MTX-17](#CTR-MTX-17)). There is no ERC-2771 trusted forwarder (no
calldata sender suffix, no 63/64 gas rule, no return bomb, no swallow mode), no call **out** to another contract with
the signer's calldata, and no ERC-4337 bundler/paymaster dependency for token operations. The signer travels in a
transient slot, never in calldata ([CTR-MTX-18](#CTR-MTX-18)); what may run is a fixed **selector** allowlist per
implementation ([CTR-MTX-19](#CTR-MTX-19)), never a target allowlist. A contract that does not support gasless
operation is wrapped into a meta-tx token (tier 2, [token-wrappers.md](token-wrappers.md)); a generic forwarder is
never added. **All or nothing, and the user never pays for an operation that did not happen:** transfer and payment
check everything before the fee and cannot fail afterwards; a self-call runs **first** and pays its fee **after**
(so a wrap can pay from the units it mints), and any failure — of the call or of the fee transfer — reverts the whole
transaction with the inner revert data, fee and nonce included. No `try/catch`, no mode switch. Smart-contract wallets
(ERC-1271; `AuthScheme 7` in the built Zether registry) are first-class signers.

<a id="CTR-MTX-14"></a>**CTR-MTX-14** — Signatures are EIP-712 typed data, never `personal_sign`: wallets display the
fields instead of 32 opaque bytes. The pinned typehash below is the only payment-intent type; there is no raw
`ecrecover` helper (it would not stop `s` malleability) — EOAs are verified with OpenZeppelin `ECDSA.tryRecover`
(65 bytes, low-s).

<a id="CTR-MTX-07"></a>**CTR-MTX-07** — **One base, `ERC20MetaTx`.** The meta-transaction base of every SCaaS EVM and
Hedera token is the abstract contract `ERC20MetaTx` (the built `MetaTxCore`, renamed): struct, typehash, `canon`,
2D nonces, `FeePolicy`, the `mtxExecute` pipeline, the ticket, the allowlist, `mtxTrade`/cancels
([dex.md](dex.md#CTR-DEX-15)), the allowance rule ([CTR-TOK-01](token-wrappers.md#CTR-TOK-01)) and the `ua*`
Universal Account path ([CTR-UA-19](accounts.md#CTR-UA-19)) all live there. `MetaTokenBase is ERC20MetaTx` carries
`payWithFee`, the named functions, init and provenance; the tiers, their Hedera children and `ZetherToken` sit on it.
The v1 line (the built `ERC20MetaTx` mixin, `MetaToken`, `HederaMetaToken` and factory v1) is deleted: issuer tokens
use `NoUnderlyingToken`, 1:1 wrappers use `SingleUnderlyingToken` with `num = den = 1`; Zether's separate mixin
`ZetherMetaTx` disappears into the base. One domain version, `"1"`, for every token.

## `MetaTransaction` and the pinned typehash

<a id="CTR-MTX-15"></a>**CTR-MTX-15** — The struct is `MetaTxLib.MetaTransaction` (`smartcontracts/evm/src/common/MetaTxLib.sol`
is normative; a struct argument also keeps EIP-712 hashing clear of Solidity's "Stack too deep" limit). The fee is paid
in **this** token (no `feeToken` field: another token lies outside this contract and this contract holds no allowance
of it); there is no `innerGasLimit` (it only means something for a forwarder that swallows failures); `to`/`value`/
`data` stay explicit (no opaque `op` + `args`); `mode` stays and is split into two nibbles. `data` has exactly three
shapes: **empty** (transfer `value` from `from` to `to`), **`pay(bytes32 entryRef)`** (exactly 36 bytes, payment of
`value` to `to`, [CTR-MTX-01](#CTR-MTX-01)), or **an allowlisted call of this token** (a self-call, with `to = 0` and
`value = 0`).

```solidity
struct MetaTransaction {
    address from;          // signer; balance affected
    address to;            // transfer/payment: recipient; self-call: 0
    uint256 value;         // transfer/payment: amount; self-call: 0
    bytes   data;          // empty = transfer; pay(bytes32); or an allowlisted call of this token
    uint256 batch;         // nonce dimension 1: the subject lane
    uint256 nonce;         // nonce dimension 2: sequence inside the lane
    uint256 validUntil;    // unix seconds
    uint32  mode;          // constraint flags + fee mode
    address relayer;       // bound relayer when MODE_RESTRICT_RELAYER
    uint256 fee;           // ppm (PERCENT) | absolute units (FIXED) | 0 (NONE)
    address feeRecipient;  // bound fee recipient when MODE_RESTRICT_FEE_RECIPIENT
}

bytes32 constant METATX_TYPEHASH = keccak256(
  "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 batch,uint256 nonce,"
  "uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");

hashStruct(m) = keccak256(abi.encode(METATX_TYPEHASH, m.from, m.to, m.value, keccak256(m.data), m.batch, m.nonce,
                                     m.validUntil, m.mode, canonRelayer, m.fee, canonFeeRecipient))
digest        = keccak256(0x1901 ‖ domainSeparator(name, "1", chainId, token, salt = chain_uid) ‖ hashStruct(m))
```

`data` is always hashed (`keccak256(m.data)`) — encoding dynamic bytes directly would break injectivity. The
typehash is pinned by `test_metaTxTypehashIsPinned`.

<a id="digest"></a>**One rule, four places.** `MetaTxLib.hashStruct` (Solidity) is the reference. Three copies must
match it byte for byte: the client library's EIP-712 builder (the reference ERP client keeps it in
`lib/eip712.py`), `scaas-node` (an alloy `sol!` struct) and the typed-data JSON handed to the wallet (the wallet
hashes it itself). Canonical zeroing (`relayer`/`feeRecipient` = 0 when their flag is off) applies in all of them.
They are locked by one known-answer vector, `smartcontracts/evm/test/vectors/metatx_kat.json`, generated by forge
(`vm.writeJson`): domain (with `salt`), struct, `structHash`, digest and the signature of key `0xA11CE`. The contract,
node and client tests read the same file; changing the typehash turns three tests red. Clients also decode `data`
against the token's published allowlist (`mtxSelectors()`) and show the selector and its arguments before asking for a
signature.

<a id="CTR-MTX-02"></a>**CTR-MTX-02** — The EIP-712 domain of a clone is the implementation's name and version plus
`verifyingContract` = the clone and `salt` = the chain's `chain_uid`: `("SCaaS MetaToken", "1", chainId, clone,
chain_uid)` for every tier, `("SCaaS ZetherToken", "1", chainId, clone, chain_uid)` for Zether; `eip712Domain()`
(ERC-5267) reports fields `0x1f`. `chain_uid` is the implementation's constructor immutable, so a clone (which runs the
implementation's code by `DELEGATECALL`) uses it with no storage and cannot declare another value
([CTR-GEN-05](README.md#CTR-GEN-05)). There is no cross-token replay because `verifyingContract` differs, and no
cross-chain replay because `chainId` and `salt` differ. Clients read the domain through `eip712Domain()` and store
`domain_name`/`domain_version` per token (`domain_name/version`); they fill `salt` from the chain profile and refuse a
token whose `chainUid()` differs. The cost: wallets show "SCaaS MetaToken" rather than the token's own name (they read
`name()` for that).

## `mode`: constraint flags and fee mode

```text
bit  31 ........................ 8 | 7  6  5  4 | 3  2  1  0
     reserved (must be 0)           | FEE MODE   | FLAGS
```

| Name | Value | Kind | Meaning |
|---|---|---|---|
| `MODE_OPEN` | `0x00` | — | No constraints, no fee |
| `MODE_RESTRICT_RELAYER` | `0x01` | flag | Only `msg.sender == m.relayer` may execute |
| `MODE_RESTRICT_FEE_RECIPIENT` | `0x02` | flag | The fee must go to `m.feeRecipient` |
| bits 2–3 | `0x04`, `0x08` | flags | Reserved, must be 0 |
| `MODE_FEE_NONE` | `0x00` | enum (bits 4–7) | No fee |
| `MODE_FEE_PERCENT` | `0x10` | enum | `fee` in ppm of the fee basis ([CTR-MTX-20](#CTR-MTX-20)) |
| `MODE_FEE_FIXED` | `0x20` | enum | `fee` in token units |
| `MODE_FLAGS_MASK` / `MODE_FEE_MASK` / `MODE_KNOWN_MASK` | `0x0F` / `0xF0` / `0xF3` | masks | `supportedModes()` returns `0xF3` |

The low nibble holds independent **flags** (`mode & FLAG`); the high nibble holds an **enumerated** fee mode
(mutually exclusive, mask + shift). `mode & MODE_FEE_PERCENT` is a bug (a future value `0x30` would contain bit
`0x10`); use `feeModeOf(mode)` (values 0/1/2, otherwise `ModeFeeInvalid`). `validateMode` checks both unknown flag
bits (`ModeUnknownBits`, surfaced as `MetaTxUnknownMode`) and fee values above 2: accepting `0x30` today would freeze
its meaning through signatures already issued. `FeeMode` stays the canonical type of `FeePolicy`; only the separate
struct field was dropped. `mode` is part of the hash, so a bitmask creates no cross-mode replay.

**Canonical zeroing:** when `MODE_RESTRICT_RELAYER` is off, `relayer` is hashed as `address(0)`; when
`MODE_RESTRICT_FEE_RECIPIENT` is off, `feeRecipient` is hashed as `address(0)` (`MetaTxLib.canon`). The struct keeps
both fields (removing them would change the typehash). The rule is identical in contract, node and client libraries.

**Submitter normalization.** Unbound fields are not signed, yet the token pays a non-zero `m.feeRecipient`, so
every submitter rewrites unbound fields before it builds the outer transaction: unbound
`feeRecipient := chains.fee_recipient` (the operator's cold wallet) or `0` (then the fee goes to `msg.sender`, the
lane); unbound `relayer := 0`. Wire values of unbound fields are never submitted; the `intent_id` is unchanged
([NODE-LANE-10](../node/submit-lanes.md#NODE-LANE-10)).

## `mtxExecute`

<a id="execution-pipeline"></a>
<a id="CTR-MTX-17"></a>**CTR-MTX-17** — **`mtxExecute` runs the signer's calldata on the token itself** (owner). One
entry point serves every subject-signed token operation; `executeMetaTransaction` is its alias under the EIP-1776 name
for outside tools and returns `bool` (the `IERC20MetaTx` return type that tender and other integrators decode); only
`mtxExecute` returns the inner call's bytes.

```solidity
function mtxExecute(MetaTransaction calldata m, bytes calldata signature) external returns (bytes memory ret);
function executeMetaTransaction(MetaTransaction calldata m, bytes calldata signature) external returns (bool); // alias
```

| `data` | Shape | Runs as |
|---|---|---|
| empty | **transfer** `value` from `from` to `to` | internal `_transfer` |
| `pay(bytes32 entryRef)` (exactly 36 bytes) | **payment** ([CTR-MTX-01](#CTR-MTX-01)); `to`/`value` are payee/amount | internal `_transfer` + `PaymentSettled` with the real fee |
| anything else | **self-call** of an allowlisted function ([CTR-MTX-19](#CTR-MTX-19)) | `address(this).call(data)` under the ticket ([CTR-MTX-18](#CTR-MTX-18)); `to` and `value` must be 0 |

The pipeline is one transaction, all or nothing; cheap checks first, so a relayer that loses a race pays only the
prefix:

| Step | Check / action | Error |
|---|---|---|
| 1 | `MODE_RESTRICT_RELAYER` ⇒ `msg.sender == m.relayer`; `block.timestamp ≤ m.validUntil`; `validateMode(m.mode)`; `m.nonce == mtxNonce(from, batch)`; the fee-recipient binding; `from ≠ address(this)` | `MetaTxUnauthorizedRelayer`, `MetaTxExpired`, `MetaTxUnknownMode`, `MetaTxBadNonce(expected, got)`, `SelfSender()` |
| 2 | Signature over the digest (`_hashTypedDataV4(hashStruct(m))`): EOA ⇒ `ECDSA.tryRecover` (65 bytes, low-s); contract ⇒ ERC-1271 `isValidSignature` staticcall (50 000 gas; 400 000 for `SubjectAccount` clones, which verify P-256 in Solidity when no precompile, [CTR-ACC-05](accounts.md#CTR-ACC-05)) | `MetaTxBadSignature` |
| 3 | Shape. Transfer/payment: `to ≠ 0` (`PayToZero`), fee on `value` (`FeePolicy.compute`, `validateRecipient`, the payee check of [CTR-MTX-08](#CTR-MTX-08)), balance ≥ value + fee. Self-call: `data.length ≥ 4`; `bytes4(data)` allowlisted; `data.length` equals the selector's static ABI length where it has one; `to == 0 && value == 0`; the fee mode is allowed by the selector's fee class ([CTR-MTX-20](#CTR-MTX-20)) | `FeeExceedsCap`, `FeeRecipientRequired`, `FeeRecipientIsPayee`, `MetaTxInsufficientForFee`; `MtxSelectorNotAllowed(bytes4)`, `MtxDataShape(bytes4)`, `MtxEnvelopeShape()`, `MtxFeeClass(bytes4, uint32 mode)` |
| 4 | Write `mtxNonce = expected + 1` | — |
| 5 | Execute. Transfer/payment: transfer the fee, then the value (cannot fail after step 3). Self-call: store the ticket (`sender = from`, `ticket = 1`, `binding = envelopeBinding(m)`), `address(this).call(data)`, clear all three; a failed call reverts **with its revert data** | inner errors, bubbled raw |
| 6 | Self-call only: transfer the fee from `from` in this token, **after** the call; a failing fee transfer reverts everything | ERC-20 errors |
| 7 | Emit `MetaTransactionExecuted(from, relayer, batch, nonce, digest, feeRecipient, fee)` (the selector is in the transaction input) | — |

No error is swallowed: the user never pays for an operation that did not happen. The relayer simulates before
broadcasting and bears gas only for a transaction whose state changed between simulation and inclusion; the node's
breaker per `(from, selector)` covers repeat offenders ([node/submit-lanes.md](../node/submit-lanes.md)).

<a id="CTR-MTX-18"></a>**CTR-MTX-18** — **The signer travels in a transient slot, and one ticket admits exactly one
self-call.** Transient slots `keccak256("scaas.mtx.guard")`, `"scaas.mtx.sender"`, `"scaas.mtx.ticket"`,
`"scaas.mtx.binding"` (written as literals: assembly takes no `keccak256` constant). One contract-wide guard covers
every entry point; `nonReentrant` admits the self-call of step 5 once and consumes the ticket:

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

`_msgSender()` returns the stored sender when `msg.sender == address(this)` and the ticket is live, else
`msg.sender`. The signer is never read from calldata, so no function can be fooled by 20 trailing bytes, and the only
self-call path is step 5. Every allowlisted function is `nonReentrant` (a test pins it), so the one entry always
consumes the ticket, a re-entry from an underlying's hook during the self-call reverts (`msg.sender` is the underlying,
or the ticket is spent), and no allowlisted function runs with a live ticket; `mtxBatch` sets a fresh ticket per item.
Authority and balance owners are read through `_msgSender()` everywhere; the reads that **stay** `msg.sender` are
exactly: the relayer binding, the default fee recipient and the event `relayer` of the pipeline; the factory check in
`initialize`; `mtxTrade`'s `msg.sender == o.dex` ([CTR-DEX-15](dex.md#CTR-DEX-15)); and `mtxWrap`'s relayer binding
and fee payee ([CTR-TOK-20](token-wrappers.md#CTR-TOK-20)). A lint test greps the sources and pins that set. Defence in
depth: `from ≠ address(this)` (step 1), and `_update` refuses transfers and mints **to** `address(this)`
(`TransferToSelf()`), because tokens parked at the token's own address are what a spoofed self-call would spend.

<a id="CTR-MTX-19"></a>**CTR-MTX-19** — **A fixed selector allowlist per implementation** (owner). Each implementation
declares its allowlist as constants — exact selectors, overloads listed one by one, each with a fee class — and
publishes it through `mtxSelectors() returns (bytes4[] selectors, uint8[] feeClass, uint8[] amountArg)`; a test pins
it. Nothing else is reachable through `mtxExecute`.

| Implementation | Self-call selector | Fee class |
|---|---|---|
| every token | `cancelNonce(uint256)` | `ABSOLUTE` |
| `NoUnderlyingToken` | `burn(uint256)` | `AMOUNT(0)` |
| `SingleUnderlyingToken` | `wrap(uint256)` | `ABSOLUTE` (fee from minted units) |
| | `unwrap(uint256,address,uint256)` | `AMOUNT(0)` |
| | `addReserve(address,uint256)` | `ABSOLUTE` |
| `MultiUnderlyingToken` | `wrap(address,uint256)` | `ABSOLUTE` |
| | `unwrap(address,uint256,address,uint256)` | `AMOUNT(1)` |
| | `addReserve(address,uint256)` | `ABSOLUTE` |
| `ZetherToken` | `wrap(uint256)`, `fund(bytes,uint256)` | `ABSOLUTE` |
| | `unwrap(uint256,address)` (public balance) | `AMOUNT(0)` |
| | `transferConfidential(bytes,bytes,bytes,bytes32)`, `burn(bytes,uint256,address,bytes32,bytes,bytes)` | `ABSOLUTE`; envelope binding through the ticket ([CTR-ZTH-34](zether.md#CTR-ZTH-34)) |

Transfer and payment are the two built-in shapes; the `transfer` selector is **not** allowlisted, so one transfer has
one encoding and one digest. Single's two-argument `unwrap(uint256,address)` is not listed (the same intent with a
second digest and no `minOut`), nor are Multi's single-asset overrides that always revert. **Never allowlisted:**
`approve` and `transferFrom` (contract accounts approve and spend through their own call path,
[CTR-TOK-01](token-wrappers.md#CTR-TOK-01)); every role function — `mint`, `renounceMinter`, `proposeRate`,
`cancelRate`, `executeRate`, `renounceRateAdmin`, `disableWrap`, `renounceGuardian` (role holders act through their own
contract, [NODE-JOB-01](../node/job-api.md#NODE-JOB-01); a signature check would skip a minter contract's caps or a
Safe's guards); `transfer`; `payWithFee` (it charges its own fee); `mtxExecute`, its alias and every other `mtx…` entry
(no nesting); `initialize`; views; `attestTransferAmount`; Zether `mtxRollOver`/`mtxSetRollOverMode` (they carry their
own signature). For selectors with dynamic arguments (Zether) the contract cannot cheaply pin one encoding: the node
re-encodes the decoded arguments and refuses non-canonical `data` before it computes the mesh `intent_id`; a
non-canonical duplicate on chain is harmless, because only the signer can produce one (`data` is signed) and the
sequential nonce lets only one variant execute.

<a id="CTR-MTX-01"></a>**CTR-MTX-01** — A payment is the `pay(bytes32 entryRef)` shape (`data = pay(bytes32)`, exactly
36 bytes) run through `mtxExecute`/`executeMetaTransaction` (also through `mtxPay`): `data` is a **selector-tagged
shape**, never a second typehash. One pinned struct means one type that wallets display. It is built into the
pipeline, not a self-call: `to ≠ 0` (`PayToZero`; `data.length < 4` is never a panic), then transfer +
`emit PaymentSettled(from, to, value, feeAmount, feeRecipient, entryRef)` with the real fee. Tender's deposit shape
([CTR-TND-01](tender.md#CTR-TND-01)) is this shape.

<a id="CTR-MTX-12"></a>**CTR-MTX-12** — **Gasless unwrap** is `mtxExecute` with the wrapper's real `unwrap` calldata:
`unwrap(uint256 wrapped, address recipient, uint256 minOut)` on `SingleUnderlyingToken`, `unwrap(address underlying,
uint256 wrapped, address recipient, uint256 minOut)` on `MultiUnderlyingToken`, `unwrap(uint256, address)` (public
balance) on `ZetherToken`; `to = value = 0`. The function runs exactly as a direct call by `from` (checks, burn
`⌈out·q⌉`, reserve debit, the underlying's exact-amount transfer, `Unwrapped`), and `minOut` protects the signer
against rate moves between signing and execution. Its fee class is `AMOUNT` with the wrapped amount as basis, taken
in wrapped units after the call. The underlying's transfer failing reverts everything, fee and nonce included. The fee
never goes to the payee rule does not apply (there is no payee). Fee-on-transfer-out underlyings stay unsupported. It
works on disabled multi-underlying legs (exits stay open) and during a pending rate change (at the current rate). The
node side (simulation, no batching, the narrowed grief exemption) is
[NODE-LANE-22](../node/submit-lanes.md#NODE-LANE-22).

## 2D nonces and lanes

Storage `_metaNonce[from][batch]`; an intent is valid iff `m.nonce == mtxNonce(from, batch)`; execution increments
it. Independent lanes remove head-of-line blocking between agents and between business flows of the same subject.

| Lane derivation | Rule | Status |
|---|---|---|
| Payment request | `batch = keccak256("scaas.pay.lane" ‖ entryRef)`, `nonce = 0` ⇒ each request is payable at most once and the client can build typed data without reading the chain; `mtxPay` derives the same lane on chain (`payLane(payId)`) | **BUILT** |
| Agent × purpose | `batch = uint256(keccak256(agentId ‖ purpose))` (e.g. procurement settlement, logistics milestones, payout distribution, treasury rebalance), sequential nonce inside | **SPECIFIED** (client convention) |
| Non-EVM | `(subject, lane: bytes32) → nonce: u64` in the subject's account object/wallet/PDA | **BUILT** |

`cancelNonce(batch)` increments `mtxNonce[sender][batch]` and invalidates every pending intent on that lane,
including ones circulating on the mesh, without a dummy transfer; it emits `MetaNonceCancelled(from, batch,
newNonce)`. It is a direct call **or** a signed self-call through `mtxExecute` on another lane (so a subject without
gas can cancel). First use of a lane costs ≈ +17 k gas (a new storage slot). An anti-lock test is mandatory per family:
X stuck on contract 1 never blocks Y on contract 2 ([networks/README.md](../networks/README.md#head-of-line)). Trade
orders have their own **order lane** (`minNonce`, [CTR-DEX-15](dex.md#CTR-DEX-15)); clients label the two.

<a id="entryref"></a>
<a id="CTR-MTX-03"></a>**CTR-MTX-03** — **Payment references.** `entryRef` is 32 random bytes; the lane of a
payment request is `keccak256("scaas.pay.lane" ‖ entryRef)` with nonce 0. A random value is unlinkable by
construction (better than a salted hash of business data) and needs no salt management; a fixed lane per request
lets the client build typed data without reading the chain and makes each request payable at most once (under
[CTR-MTX-04](#CTR-MTX-04)). Accepted cost: the first use of the lane costs +17 k gas (measured in `MetaTxGas`).
Tokens also derive the lane on chain ([CTR-MTX-10](#CTR-MTX-10)).

```text
entryRef = 32 bytes from a CSPRNG                     # carries no information; unlinkable by construction
batch    = keccak256("scaas.pay.lane" ‖ entryRef)     # lane of this request (on chain: payLane(entryRef))
nonce    = 0
```

- One `entryRef` per **payment request** (an invoice may have several requests over time; each request is payable at
  most once because its lane has nonce 0).
- Pay-once holds only if every signature a client issues on a pay lane has `validUntil ≤ t_first_issue + 30 d`.
  Re-issuing terms on the same lane later than that, or signing an op with `valid_until > now + 30 d` on a pruning
  family (TON, Aptos, Solana, Sui), gives no pay-once guarantee — issue a new request (new `entryRef`, new lane)
  instead. Wallet connectors and `clientkeys` refuse such ops.
- The client stores `entryRef` with a UNIQUE constraint on the request, together with `chain`, `token`,
  `receiving_address`, `payer_address` (locked at start), `amount_base`, `issued_valid_until`.
- Do **not** derive `entryRef` from business identifiers (`keccak256(company ‖ move ‖ amount ‖ salt)` as in older
  drafts): a random value needs no salt management and cannot be brute-forced from known invoice numbers.
- Splitting: classical Zether with `n_v = 64` removed the need to split large payments; for transparent tokens one
  payment per request. If a business case needs partial payments, issue one request (one `entryRef`) per
  instalment.

Two-way verification. **Client → chain** (before signing and at push): (1) typed data is built server-side from the
request: `to = receiving_address`, `value = amount_base`, `data = pay(entryRef)`, `batch` as above, `validUntil =
issued_valid_until` (server-chosen, e.g. now + 300 s); (2) after signing the client recomputes the digest; a 65-byte
signature must recover `payer_address` (EOA); a contract wallet (ERC-1271) is accepted unverified and judged by the
node's simulation; (3) the node recomputes the digest and simulates before broadcast. **Chain → client** (on each
finalized range): (1) filter `PaymentSettled` by `contract == request.token` **and** `to == request.receiving_address`
**and** `entry_ref == request.entryRef`; (2) `amount_settled = Σ amount` of matching events; `amount_settled ≥
amount_base` ⇒ request final; more than due ⇒ final + needs attention (refund manually); less ⇒ partial; (3)
cross-check `MetaTransactionExecuted(digest)` to mark the job final; (4) drift checks: an unmatched inbound
`Transfer` to a watched wallet ⇒ a drift record; hourly `balances` vs the ledger balance of the token's journal. A
third party paying 1 unit with someone else's `entryRef` cannot complete a request (the sum must reach the amount);
an overpayment by a stranger is just money received. The full client procedure is in
[integration.md](../integration.md#payment-references).

## Pay-once horizon

<a id="CTR-MTX-04"></a>**CTR-MTX-04** — **Pay-once is conditional and is a protocol rule.** "Each payment request is
payable at most once" holds iff (1) every signature issued on a pay lane has `validUntil ≤ t_first_issue + H`,
`H = LANE_HORIZON = 30 d`, and (2) every family that prunes lane state keeps an executed lane for ≥ `H` after the
executed op's `validUntil` ([NET-ALL-01](../networks/README.md#NET-ALL-01): TON two `LANE_TTL` generations; Aptos and
Solana `PRUNE_DELAY_S`; Sui `prune` after `valid_until + LANE_HORIZON_S`). Issuers that sign terms on a lane beyond
`H` get no pay-once guarantee; a node chain on a pruning family must have `max_valid_for_secs ≤ H`. Obligations:

| Who | Obligation | Status |
|---|---|---|
| Issuer (ERP, app) | Sign one op per pay lane, or keep every op on that lane inside `H` of the first; terms signed beyond `H` get no pay-once guarantee | reference ERP client complies (**BUILT**) |
| Every signing client (connectors, `clientkeys`, app) | Refuse to sign an op with `valid_until > now + LANE_HORIZON_S` on a pruning family ([NET-APT-24](../networks/aptos.md#NET-APT-24), [NET-SOL-25](../networks/solana.md#NET-SOL-25), [NET-SUI-12](../networks/sui.md#NET-SUI-12)) | **SPECIFIED** |
| Contract | Sui `relay_pay` refuses `valid_until > now + LANE_HORIZON_S` on chain; Solana caps `valid_until` and order `expiry` at `MAX_TTL_S = 31 d` ([NET-SOL-22](../networks/solana.md#NET-SOL-22)) | **SPECIFIED** |
| Node | Refuses `max_valid_for_secs > LANE_HORIZON` on a pruning family ([NODE-STO-01](../node/store.md#NODE-STO-01)); constants pinned equal in tests (TON `LANE_TTL`, Aptos/Solana `PRUNE_DELAY_S`, node `LANE_TTL_S`, client `LANE_HORIZON_S`) | **SPECIFIED** |

## Gas

<a id="gas"></a>Measured gas of the **built v1 path** (Foundry `MetaTxGas.t.sol`, `evm_version = prague`, execution
gas; full-transaction `gasUsed` from receipts after deploying the same contracts on the private Nethermind reference
chain, Nethermind 1.39.0, Fusaka + BPO2; 2026-08-31). Transfer and payment keep this path's work in the target
pipeline; the table is re-measured when the base changes:

| Scenario | Execution gas | Full tx gas |
|---|---|---|
| Warm lane, `MODE_OPEN`, no fee | 35 241 | 58 702 |
| New lane (nonce 0 → 1), no fee | 52 341 | 75 802 |
| Warm, `FIXED` fee | 43 565 | 67 362 |
| Warm, `PERCENT` fee | 43 511 | 67 260 |
| Warm, `FIXED` + restricted relayer + fee recipient | 43 763 | 67 560 |
| Warm lane, recipient that never held the token | 52 341 | — |
| ERC-1271 signature (trivial verifier), new lane | 54 530 | — |
| `cancelMetaNonce` (new lane) | 27 579 | — |
| Baseline ERC-20 `transfer` | 20 081 | 41 181 |
| Outer-transaction calldata | 580 B → 4 180 gas (425 zero / 155 non-zero bytes) | |

Derived: envelope = warm meta-tx − baseline = **+15 160** execution gas (≈ 17.5 k full tx), first use of a lane
**+32 260**, ERC-1271 path **+2 189** (a floor: a real Safe or passkey wallet adds its own verification), collecting a
fee **+8 324**, `PERCENT` vs `FIXED` **−54**, both restrictions **+198**. A gasless public transfer therefore costs
1.76 × a plain transfer, and the fee transfer is the most expensive part of the envelope after the signature — the
fee-0 sponsored path is the cheapest configuration. Method notes: one scenario per test function (EIP-2929 warm
state carries over inside one test), and accounts are created and funded in `setUp`; a gas measurement that changes
with execution order measures the access list, not the code.

## FeePolicy

<a id="CTR-MTX-13"></a>**CTR-MTX-13** — Public fee modes are `NONE`, `PERCENT` and `FIXED`, chosen by the signer per
intent through `mode`; the percent unit is ppm (1e6), because per mille cannot express 0.05 %:

- `enum FeeMode { NONE, PERCENT, FIXED }`; `PPM_DENOMINATOR = 1 000 000`; `MAX_FEE_PPM = 10 000` (1 %) — a protocol
  constant protecting signers, not a governance parameter.
- `compute(PERCENT, amount, fee)`: `fee ≤ MAX_FEE_PPM`, result `amount × fee / 10^6`. `compute(FIXED, amount, fee)`:
  `fee ≤ amount × MAX_FEE_PPM / 10^6`. Over the cap ⇒ `FeeExceedsCap(feeAmount, cap)`. The basis is `value` for
  transfer and payment and the selector's amount argument for `AMOUNT` self-calls; the fee is charged on top. Calls
  that move no amount of this token pay an absolute, uncapped `FIXED` fee or none ([CTR-MTX-20](#CTR-MTX-20)).
- `feeRecipient` is the signer's choice in every mode — usually the value a relayer publishes — and `address(0)`
  means "pay `msg.sender`". `validateRecipient`: non-NONE needs a non-zero resolved recipient (`FeeRecipientRequired`).
- `requireConfidentialSafe`: `PERCENT` on any confidential op ⇒ `PercentFeeForbiddenOnConfidential` (a percentage
  fee would reveal the hidden amount). Confidential outer fees are `NONE` or `FIXED`, and `FIXED` there is **not**
  capped at 1 % because the amount is hidden ([CTR-ZTH-07](zether.md#CTR-ZTH-07)).
- DEX fees are separate: the order's signed `fee` rate ≤ 10 000 ppm ([dex.md](dex.md#CTR-DEX-17)).

<a id="CTR-MTX-20"></a>**CTR-MTX-20** — **Every allowlisted selector has a fee class** (owner). For a self-call `to`
and `value` are 0, so the fee basis comes from the selector, and the fee is charged after the call (step 6):

| Class | `PERCENT` | `FIXED` | Basis | Used by |
|---|---|---|---|---|
| `AMOUNT(i)` | yes, ≤ 1 % | yes, ≤ 1 % of the basis | argument `i` of the call, in this token's units | `burn(uint256)`, `unwrap` |
| `ABSOLUTE` | refused (`requireConfidentialSafe`) | yes, the signed amount, **no 1 % cap** | — | `wrap`, `addReserve`, `cancelNonce`, every Zether selector |
| (always) | — | — | `NONE` is allowed for every selector | — |

`ABSOLUTE` extends the confidential rule ([CTR-ZTH-07](zether.md#CTR-ZTH-07): absolute, uncapped, because there is no
public amount to take a percentage of) to public calls that move no amount of this token. The 1 % cap protects a
signer from percentages it cannot recompute; here the wallet shows the exact fee. A fee class that refuses the mode
reverts `MtxFeeClass(selector, mode)` at step 3. Node pricing and wallet display decode `data` with the published
classes (`mtxSelectors()`).

<a id="CTR-MTX-08"></a>**CTR-MTX-08** — **The fee never goes to the payee.** For the transfer and `pay` shapes and for
`payWithFee`, `feeAmount != 0 && resolvedFeeRecipient == to` reverts `FeeRecipientIsPayee` at step 3, whether the
recipient was bound by the signer or defaulted to `msg.sender` (a payee self-relaying with a fee is refused). "Payee" =
`m.to` when `m.data` is empty (transfer) or is `pay`. A self-call has no payee (`to = 0`), so the check does not apply.
The fee mode, amount and recipient stay the signer's choice; the 1 % cap and "percent of the sender's amount, charged
on top" are unchanged. The check costs ~100 gas. `PaymentSettled` keeps its fee amount and recipient because payment
is a built-in shape, not a self-call.

## Names

<a id="named-functions"></a>
<a id="CTR-MTX-21"></a>**CTR-MTX-21** — **Every entry point whose authority comes from a subject's signature starts
with `mtx`** (owner); a submitter only relays. `executeMetaTransaction` stays as the alias of `mtxExecute` (the
EIP-1776 name, for outside tools). EIP-712 type names (`MetaTransaction`, `PayUnderMandate`, `OwnerCall`, …) name what
is signed, not the entry point, and stay. Non-EVM families keep their op names (`relay`, `Relay`, `SignedOp`).

| Contract | Entry points |
|---|---|
| tokens | `mtxExecute` (+ alias `executeMetaTransaction`), `mtxExecuteWithFee`, `mtxTransfer`, `mtxTransferWithFee`, `mtxPay`, `mtxBatch`, `mtxPayReceiverFee`; `cancelNonce(uint256 batch)` (direct, or signed through `mtxExecute`); views `mtxNonce`, `mtxDigest`, `mtxSelectors`, `payLane`, `chainUid` |
| tokens (trade) | `mtxTrade`, `mtxCancelOrder`, `mtxInvalidateNonces` ([dex.md](dex.md#CTR-DEX-15)) |
| wrappers, `ZetherToken` | `mtxWrap` ([CTR-TOK-20](token-wrappers.md#CTR-TOK-20)) |
| `ZetherToken` | `mtxRollOver`, `mtxSetRollOverMode` ([CTR-ZTH-16](zether.md#CTR-ZTH-16)) |
| `MandateWallet` | `mtxPayUnderMandate`, `mtxRevoke`, `mtxExecuteAsOwner` ([mandates.md](mandates.md#mandatewallet)) |
| `SubjectAccount` | `mtxExecuteAsOwner` ([accounts.md](accounts.md#CTR-ACC-05)) |
| `OrderBookDex` | `mtxSettle`, `mtxCancelOrders`, `mtxInvalidateNonces` ([dex.md](dex.md#CTR-DEX-16)) |

<a id="CTR-MTX-09"></a>**CTR-MTX-09** — The named functions `mtxTransfer`, `mtxTransferWithFee`, `mtxExecuteWithFee`,
`mtxPay` and the batch `mtxBatch` live in `MetaTokenBase` (so every tier has them) and **only build a
`MetaTransaction` and run the same pipeline**. Each enforces a mode shape (`MtxModeShape`), nothing else. The digest of
a named call equals the digest of `mtxExecute` with the same struct, so one signature works on both paths and one lane
is consumed once. They are ABI sugar; nothing breaks without them. All are `nonReentrant`; mode bits are the
`MetaTxLib` constants:

| Function | Struct it builds | Mode shape required (else `MtxModeShape(mode)`) | Adds |
|---|---|---|---|
| `mtxTransfer(from, to, amount, batch, nonce, validUntil, mode, relayer, sig)` | `data = ""`, `fee = 0`, `feeRecipient = 0` | `mode & ~MODE_RESTRICT_RELAYER == 0` (fee `NONE`) | typed ABI |
| `mtxTransferWithFee(from, to, amount, batch, nonce, validUntil, mode, relayer, fee, feeRecipient, sig)` (short: `mtxTransferWithFee(…, mode, relayer, fee, feeRecipient, sig)`) | `data = ""` | fee nibble `PERCENT` or `FIXED`, `MODE_RESTRICT_FEE_RECIPIENT` set, `feeRecipient ≠ 0` (the sender names who is paid) | typed ABI; the payee check applies |
| `mtxExecuteWithFee(m, sig)` returns `bytes` | `m` as given (any shape) | fee nibble ≠ `NONE`; recipient bound **or** relayer-default ("relayer or a third party") | a selector that says "this intent pays a fee" |
| `mtxPay(from, to, amount, payId, validUntil, mode, relayer, fee, feeRecipient, sig)` | `data = pay(payId)`, `batch = payLane(payId)`, `nonce = 0` | any valid mode (fee optional) | on-chain lane derivation; `PaymentSettled(…, entryRef = payId)` |
| `mtxBatch(MetaTransaction[] ms, bytes[] sigs)` | each `ms[i]` as given | as `mtxExecute` per item | atomic; one outer tx for many items |
| `payLane(bytes32 payId) view returns (uint256)` | — | — | the lane clients must use for `payId` on this token |

Exact equivalences (each is a test):

```text
mtxTransfer(f,t,a,b,n,v,mode,r,s)              ≡ mtxExecute({f,t,a,"",b,n,v,mode,r,0,0}, s)
mtxTransferWithFee(f,t,a,b,n,v,mode,r,x,R,s)   ≡ mtxExecute({f,t,a,"",b,n,v,mode,r,x,R}, s)
mtxExecuteWithFee(m,s)                         ≡ mtxExecute(m,s)                         (plus the shape check)
mtxPay(f,t,a,p,v,mode,r,x,R,s)                 ≡ mtxExecute({f,t,a,pay(p),payLane(p),0,v,mode,r,x,R}, s)
executeMetaTransaction(m,s)                    ≡ mtxExecute(m,s)                         (returns true)
```

So: same digest, same events (`MetaTransactionExecuted`; `PaymentSettled` for `mtxPay`), same nonce space (a
signature consumed through one path fails `MetaTxBadNonce` on the other), same KAT. A named function never accepts an
intent that the generic path would refuse, and refuses some the generic path accepts (wrong shape), never the other
way round. The gasless unwrap has no named function: it is `mtxExecute` with the real `unwrap` calldata
([CTR-MTX-12](#CTR-MTX-12)).

`fee` is not canonicalised under fee mode `NONE` (only `relayer`/`feeRecipient` are, by `canon`): a struct signed
with fee `NONE` and a leftover `fee ≠ 0` is valid on the generic path but not through `mtxTransfer`, which puts
`fee = 0`. Clients MUST sign `fee = 0` and `feeRecipient = 0` for every no-fee intent.

What the names do not do: no second typehash, no `chainId` or `wrapper` field in the struct (both are met by the
EIP-712 domain: `chainId`, `salt` and `verifyingContract` = the wrapper clone); no decoding of `data` to find "the
amount" for transfer and payment (the amount is `m.value`); no gas promise — they hash the same 11-field struct and
save only calldata (no dynamic `data`, and for `mtxPay` no `batch`/`nonce`). An earlier estimate of a "≈ 4 k gas"
saving assumed a fast path with its own short typehash and does not apply.

<a id="CTR-MTX-10"></a>**CTR-MTX-10** — In `mtxPay(…, payId, …)`, `payId` **is** the payment reference `entryRef`
(`PaymentSettled.entryRef`), and the lane is derived **on chain**: `batch = payLane(payId) =
uint256(keccak256("scaas.pay.lane" ‖ payId))`, `nonce = 0`, so `mtxPay` pays a given `(payer, payId)` at most once
**through `mtxPay`**. The same `entryRef` can still appear in a `PaymentSettled` from `payWithFee`, from the generic
`pay` shape on another lane, or after `cancelNonce` on a later nonce: reconcilers match
`(payer, payee, amount, entryRef)`, book the first `PaymentSettled` for an `entryRef` and treat a later one as a
reconciliation exception, never as a second payment. A client that wants a different lane for a payment uses
`mtxExecute` with the `pay` shape (still valid).

`payLane(p) = uint256(keccak256(abi.encodePacked("scaas.pay.lane", p)))` (short: `payLane(p) = uint256(keccak256("scaas.pay.lane" ‖ p))`) — the
same value clients derive off chain, so "at most once" holds per path. The node and the client store the derived lane
with the job, so a pay job never changes lanes after it is signed.

<a id="CTR-MTX-11"></a>**CTR-MTX-11** — **No second typehash for the same struct.** There is no `PAY_TYPEHASH` and no
`batchMtxPay` with a partial-success bitmap: one type means one wallet display. `mtxBatch` is **atomic** (all items or
none) — partial success would need a non-reverting copy of the pipeline. One failing item costs the relayer the whole
batch's gas, so the node batches only items bound to its own lane ([NODE-LANE-11](../node/submit-lanes.md#NODE-LANE-11)):
items whose `relayer` is bound (`MODE_RESTRICT_RELAYER`) to the submitting lane, per `(chain_key, token)`, flushed at
50 items or 3 s; unwrap items are never batched. Rules: `ms.length == sigs.length` (`MtxBatchLengthMismatch`), `≥ 1`
(`MtxBatchEmpty`), no explicit cap (the block gas limit is the cap); items run in order through the pipeline, each
with a fresh ticket; `msg.sender` is the relayer for every item (restricted-relayer intents keep working); any item
reverting reverts the batch, so all-or-nothing holds per item and per batch; items may mix shapes and payers but never
tokens or chains (it is a function of one token). Different structs signed in the token's domain are not a second
hash of this one: the Universal Account path has its own `UAMetaTransaction` ([CTR-UA-19](accounts.md#CTR-UA-19)),
and trading has `TradeOrder`, `CancelOrder` and `InvalidateNonces` ([CTR-DEX-13](dex.md#CTR-DEX-13)).

`mtxBatch` saves the 21 000 intrinsic gas per item after the first, plus warm re-reads of shared slots, minus the ABI
overhead of `MetaTransaction[]`/`bytes[]` (the token address is pre-warmed as `tx.to` anyway). Measured on the built
v2 path (`test/v2/MetaTxGasV2.t.sol`, clones, warm lane): `mtxTransfer` ≈ 660 gas and `mtxPay` ≈ 140 gas below the
generic path, `mtxTransferWithFee` ≈ 200 below, the fee-shape entry ≈ 85 above (dispatch + shape check); the v2
generic path is ≈ 2.2–3.9 k below v1 on every row.

## Interfaces

```solidity
interface IERC20MetaTx is IERC20 {
    event MetaTransactionExecuted(address indexed from, address indexed relayer, uint256 indexed batch,
                                  uint256 nonce, bytes32 digest, address feeRecipient, uint256 fee);
    event MetaNonceCancelled(address indexed from, uint256 indexed batch, uint256 newNonce);
    error MetaTxExpired(uint256 validUntil, uint256 nowTs);
    error MetaTxBadNonce(uint256 expected, uint256 got);
    error MetaTxBadSignature();
    error MetaTxUnauthorizedRelayer(address allowed, address caller);
    error MetaTxUnknownMode(uint32 mode);
    error MetaTxInsufficientForFee(uint256 needed, uint256 available);
    error MtxSelectorNotAllowed(bytes4 selector); error MtxDataShape(bytes4 selector); error MtxEnvelopeShape();
    error MtxFeeClass(bytes4 selector, uint32 mode); error Reentrancy(); error SelfSender(); error TransferToSelf();
    error SpenderNotContract(address spender);   // allowance rule
    error CallerNotContract(address caller);     // allowance rule

    function mtxNonce(address from, uint256 batch) external view returns (uint256);
    function mtxDigest(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32);
    function mtxExecute(MetaTxLib.MetaTransaction calldata m, bytes calldata signature) external returns (bytes memory);
    function executeMetaTransaction(MetaTxLib.MetaTransaction calldata m, bytes calldata signature) external returns (bool success);
    function mtxSelectors() external view returns (bytes4[] memory selectors, uint8[] memory feeClass, uint8[] memory amountArg);
    function chainUid() external view returns (bytes32);
    function supportedModes() external view returns (uint32);   // 0xF3
    function cancelNonce(uint256 batch) external;
}

interface IERC20Payment is IERC20MetaTx {
    event PaymentSettled(address indexed from, address indexed to, uint256 amount, uint256 feeAmount,
                         address feeRecipient, bytes32 indexed entryRef);
    function payWithFee(address to, uint256 amount, FeeMode feeMode, uint256 fee, address feeRecipient,
                        bytes32 entryRef) external returns (bool);   // msg.sender pays; fee on top of amount
}

// MetaTokenBase (all tiers)
error FeeRecipientIsPayee();  error MtxModeShape(uint32 mode);  error MtxBatchEmpty();  error MtxBatchLengthMismatch();
function mtxTransfer(address from, address to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
                     uint32 mode, address relayer, bytes calldata signature) external returns (bool);
function mtxTransferWithFee(address from, address to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
                            uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes calldata signature)
    external returns (bool);
function mtxExecuteWithFee(MetaTxLib.MetaTransaction calldata m, bytes calldata signature) external returns (bytes memory);
function mtxPay(address from, address to, uint256 amount, bytes32 payId, uint256 validUntil, uint32 mode,
                address relayer, uint256 fee, address feeRecipient, bytes calldata signature) external returns (bool);
function mtxBatch(MetaTxLib.MetaTransaction[] calldata ms, bytes[] calldata signatures) external returns (bool);
function payLane(bytes32 payId) external view returns (uint256);
```

`MetaTokenBase` adds `NotFactory()`, `AlreadyInitialized()` and the provenance getters; the trade entry points and
their errors are in [dex.md](dex.md#CTR-DEX-15); the tier functions (wrap, unwrap, rates, legs) are in
[token-wrappers.md](token-wrappers.md#interfaces). The node's event normaliser decodes `MetaNonceCancelled`;
`PaymentSettled` and `MetaTransactionExecuted` keep their fields, so payment reconciliation needs no change.

## Payers

<a id="payers"></a>

| Model | How | Who pays gas | Status |
|---|---|---|---|
| Sponsored (company relayer) | Subject signs with `MODE_FEE_NONE` + `MODE_RESTRICT_RELAYER` = company lane | Company (OPEX) | **BUILT** (portal default, [INT-ERP-06](../integration.md#INT-ERP-06)) |
| Fee in token | `MODE_FEE_PERCENT`/`FIXED`, fee ≤ 1 % to `feeRecipient` (absolute for `ABSOLUTE` selectors) | Relayer, reimbursed in token | **BUILT** |
| **Payee self-relay / direct settlement** | Payer signs offline (`fee = 0`, relayer unbound or bound to the payee); hands the signature to the payee by QR, NFC, message or file; the payee's wallet submits it, paying gas itself; `PaymentSettled` identical. The signature is an expiring electronic cheque (`validUntil`) | Payee | **BUILT** at contract level (any `msg.sender` may submit an unbound intent); QR (EIP-681-style) tooling and a user `cancelNonce` screen **PLANNED** |
| **Receiver pays the fee** | Payer signs `pay` of `N`; payee co-signs a fee authorization (`fee`, `feeRecipient`) from its own balance; relayer submits both in one transaction (payer sends `N`, payee receives `N`, pays `fee`) | Relayer, reimbursed by payee | **SPECIFIED** (`mtxPayReceiverFee`, payee co-signs `ReceiverFee` over the payer digest; [receiver-pays](#receiver-pays)) |
| Gas sponsorship policy | Node policy: e.g. "inbound to wallet W, value ≥ X ⇒ accept with fee 0, book gas to account Y" | Sponsor (contract outside the chain) | **SPECIFIED** ([NODE-SPN-01](../node/sponsorship.md#NODE-SPN-01)); on-chain `SponsorshipPool` **PLANNED** later |
| `fee = 0` B2B | Company relayer, `MODE_FEE_NONE`; gas is OPEX | Company | **BUILT** |
| Enterprise inbound gateway | Partners post signed intents to the company's gateway (`POST /v1/metatx`); the company relays with its lanes | Company | **BUILT** (EVM door A); intake rules that stop door A being a free gas faucet **SPECIFIED** ([NODE-GW-01](../node/gateway.md#NODE-GW-01)) |

Per-family equivalents (the subject never pays, a relayer lane submits): Hedera — the same Solidity on HSCS, no
payer-account sponsorship of subject transactions; Cosmos — the relayer lane sends `Relay{payload, auth}`, feegrant
only as a seam for subject-sent deposits, authz never; Soroban — native authorization entries, the relayer is the
source and may fee-bump other lanes; Sui — relayer lane PTB, sponsored transactions only for subject-sent deposits;
Aptos — relayer lane sequence-number transaction, fee-payer/orderless only as a seam for passkey/keyless subjects;
TON — a relayer W5 lane sends `SignedOp` to the payer's jetton wallet, subject W5 gasless extensions are not used;
Solana — the relayer lane is the fee payer, the subject signature is checked through the Ed25519/Secp256r1 precompile
instruction ([networks/README.md](../networks/README.md)).

## Receiver-pays

<a id="receiver-pays"></a>
<a id="CTR-MTX-05"></a>**CTR-MTX-05** — A named function `mtxPayReceiverFee(m, payerSig, fee, feeRecipient,
rfValidUntil, payeeSig)` in `MetaTokenBase` carries the payee's EIP-712 co-signature `ReceiverFee(bytes32
paymentDigest, uint256 fee, address feeRecipient, uint256 validUntil)` in the token's own domain, where
`paymentDigest` is the **full EIP-712 digest** of the payer's intent. The payer's `MetaTransaction` and typehash are
unchanged; the payer runs the pipeline untouched; then `fee` moves from the payee to the resolved fee recipient in the
same transaction. `paymentDigest` is consumed once by the payer's nonce, so the co-signature is single-use with no new
storage, and it is bound to one token, chain, payer, amount and `entryRef`. The "no second typehash" rule concerns the
**payment intent**; `ReceiverFee` is a different message signed by a different party (as `MandateWallet` has its own
types), so payer wallets still show one transaction type. Cost: payees sign one more typed message.

<a id="CTR-MTX-06"></a>**CTR-MTX-06** — **Shape and availability.** The payer shape is `pay(entryRef)` (36 bytes) with
fee mode `NONE` (one fee per intent), `MODE_RESTRICT_RELAYER` set, `batch = payLane(entryRef)`, `nonce = 0` (as
`mtxPay`, so "once per `(payer, entryRef)`" holds); `fee` is an absolute amount, `0 < fee ≤ m.value`; the co-signed
`feeRecipient` is non-zero (the named-fee convention) and `≠ m.to` (the payee check). The payer's `feeRecipient`
field is **not** checked (`canon` zeroes it, and the submitter may rewrite it, [NODE-LANE-10](../node/submit-lanes.md#NODE-LANE-10)).
No 1 % cap: the payee signs the exact amount it gives up and can never lose more than it receives in this call.
Events: `PaymentSettled(…, N, entryRef)` unchanged (gross), plus `ReceiverFeePaid(paymentDigest, payee, feeRecipient,
fee)`; the payer's books do not change; the payee books receipt `N` and expense `F` (net `N − F`). **Availability:**
every tier of the one base (EVM and Hedera children); not in `mtxBatch`. Jobs carrying a receiver fee travel only on
the restricted bus scope (`bus.scope = restricted`) ([NODE-MESH-17](../node/mesh.md#NODE-MESH-17)). A co-signing
receiving wallet is a **hot collection wallet**.

Messages. Payer (unchanged type): `MetaTransaction{from: payer, to: payee, value: N, data: pay(entryRef), batch:
payLane(entryRef), nonce: 0, validUntil, mode (fee NONE | MODE_RESTRICT_RELAYER), relayer: the submitting lane, fee:
0, feeRecipient: any (not checked)}` in domain `("SCaaS MetaToken", "1", chainId, token, chain_uid)`; `paymentDigest =
_hashTypedDataV4(hashStruct(m))`. Payee (new, same domain):

```solidity
bytes32 constant RECEIVER_FEE_TYPEHASH =
    keccak256("ReceiverFee(bytes32 paymentDigest,uint256 fee,address feeRecipient,uint256 validUntil)");
```

`feeRecipient` must be non-zero: with "0 ⇒ `msg.sender`" a mempool copier could front-run and take the fee; the
payee names the relayer's fee address (the node's `chains.fee_recipient`). No nonce: `paymentDigest` executes at most
once (payer nonce), and only through this function does the co-signature have any effect.

```solidity
event ReceiverFeePaid(bytes32 indexed paymentDigest, address indexed payee, address indexed feeRecipient, uint256 fee);
error ReceiverFeeShape();   // not pay; payer fee mode != NONE or fee != 0; relayer unbound; lane/nonce not payLane/0; feeRecipient 0
error ReceiverFeeExpired(uint256 validUntil, uint256 nowTs);
error ReceiverFeeAmount(uint256 fee, uint256 value);        // fee == 0 or fee > value

function mtxPayReceiverFee(MetaTxLib.MetaTransaction calldata m, bytes calldata payerSig,
                           uint256 fee, address feeRecipient, uint256 rfValidUntil, bytes calldata payeeSig)
    external nonReentrant returns (bool);
function receiverFeeDigest(bytes32 paymentDigest, uint256 fee, address feeRecipient, uint256 validUntil)
    external view returns (bytes32);
```

Order:

1. Shape (`ReceiverFeeShape`): `m.data` is `pay(p)` (36 bytes), `feeModeOf(m.mode) == NONE`, `m.fee == 0`,
   `m.mode & MODE_RESTRICT_RELAYER ≠ 0`, `m.batch == payLane(p)`, `m.nonce == 0`, `feeRecipient ≠ 0`; `m.feeRecipient`
   is deliberately not checked (`canon` zeroes it; a submitter may set it). Then `block.timestamp ≤ rfValidUntil`;
   `0 < fee ≤ m.value`.
2. `feeRecipient == m.to` ⇒ `FeeRecipientIsPayee`.
3. `bytes32 d = _execute(m, payerSig)` — the unchanged pipeline (payer → payee `N`, `PaymentSettled`,
   `MetaTransactionExecuted`); `_execute` returns its digest (internal change only).
4. `_requireValidSignature(m.to, receiverFeeDigest(d, fee, feeRecipient, rfValidUntil), payeeSig)` (EOA, ERC-1271 with
   `_erc1271Gas(m.to)`, HIP-632 on Hedera children).
5. `_transfer(m.to, feeRecipient, fee)` (cannot fail: the payee just received `N ≥ fee`); emit `ReceiverFeePaid(d,
   m.to, feeRecipient, fee)`.

Equivalence: the payer side is exactly `mtxPay`/`mtxExecute` with the same struct — same digest, events and nonce. A
payer signature landed through any other path makes the co-signature dead (no fee is taken).

Invariants: **RP1** the payee's net change from the call is `N − fee ≥ 0`; the payer's is `−N`; the fee recipient's
`+fee`. **RP2** A co-signature takes effect at most once and only together with the exact payer intent it names.
**RP3** No signed field can be changed by the relayer. **RP4** Fee collected ⇔ payment completed (one transaction).

| Threat | Defence |
|---|---|
| Relayer raises the fee or redirects it | `fee`, `feeRecipient` signed by the payee |
| Payee signature replayed on another payment | bound to `paymentDigest` (domain = token + chain) |
| Payer forces a fee on the payee | needs `payeeSig` |
| Race: someone lands the payer intent alone, or copies the call to take the fee | payer relayer bound (required) and `feeRecipient` non-zero (required) |
| Co-sign key compromised | it controls the receiving wallet: use a hot collection wallet with an automated sweep |
| Fee leaves the payee negative | `fee ≤ m.value` (RP1) |
| Malicious ERC-1271 payee wallet | `staticcall` with the token's gas cap; failure reverts the whole call (payer intent stays valid elsewhere) |

The co-signing key controls the receiving wallet (a `SubjectAccount` key validates any digest and authorizes
`mtxExecuteAsOwner`; there is no scoped key kind), so the receiving wallet for this mode is a dedicated hot collection
wallet (EOA or `SubjectAccount`) holding only incoming receiver-pays funds, swept automatically to a cold treasury; a
cold receiving wallet cannot co-sign and must not offer this mode. A scoped key kind that validates only
`ReceiverFee` preimages with a fee cap is a planned `SubjectAccount` change ([accounts.md](accounts.md#smart-account-limitations)).
Bytecode size: the 24 576-byte CI gate covers every tier and both Hedera children; if one exceeds it, the
`ReceiverFee` hashing and check move to an external library (`ReceiverFeeLib`, public functions). Node and client
touchpoints (job field `receiver_fee`, `token.features`, booking): [node/sponsorship.md](../node/sponsorship.md#receiver-pays),
[integration.md](../integration.md#inbound).

Gas (estimate): `mtxPay` + payee signature (~4 k EOA, ERC-1271 up to its cap) + `ReceiverFee` hashing (~1 k) + one
transfer (~7 k warm, ~25 k new recipient) + event (~2 k): **+14 to +32 k** over `mtxPay`. Tests: each shape error
(unbound payer relayer, wrong lane or nonce, zero `feeRecipient`); a payer intent with a non-zero unbound
`m.feeRecipient` succeeds; fee 0, fee = value, fee > value; recipient = payee; co-signature over another digest;
expired co-signature; replay after the payer intent landed through `mtxExecute` (bad nonce); ERC-1271 payee
(`SubjectAccount`) and Hedera HIP-632 payee; RP1/RP4 under fuzz; event fields; node accept rules and the forced
`restricted` scope. Families: EVM and Hedera only; non-EVM families do not have it (no fee fields off EVM) — there the
options are payee self-relay and sponsorship.

## Security

<a id="security"></a>

| Threat | Defence |
|---|---|
| A client prices its own payment (sends a small amount) | `value` is built from the business document server-side; the client only returns a signature |
| A third party pays 1 unit with someone else's `entryRef` | the settled sum must reach the amount; a stranger's overpayment is only money received |
| Paying twice | one pay lane with nonce 0 per request ([CTR-MTX-03](#CTR-MTX-03)) |
| A relayer front-runs and changes the recipient | `to/value/data` are in the digest; `MODE_RESTRICT_RELAYER` |
| Replay across chains or tokens | domain `chainId` + `salt = chain_uid` + `verifyingContract` ([CTR-GEN-05](README.md#CTR-GEN-05)) |
| Sender spoofing (the ERC-2771 + multicall class) | signer in transient storage, never calldata; trusted only for `msg.sender == this` with a live ticket; the "stays `msg.sender`" set pinned by lint; `from ≠ this`; no transfers to `this` ([CTR-MTX-18](#CTR-MTX-18)) |
| Nesting, re-entry through an underlying's hook | no `mtx…` entry in any allowlist; one-shot ticket ([CTR-MTX-18](#CTR-MTX-18)) |
| The gateway calling out | its only outward call is the read-only ERC-1271 `staticcall`; allowlisted wrap/unwrap/fund call their underlying exactly as their direct versions do; neither forwards calldata |
| Role functions made gasless | none allowlisted ([CTR-MTX-19](#CTR-MTX-19)) |
| Opaque `data` in wallets | EIP-712 shows every field; clients decode `data` against `mtxSelectors()` before asking for a signature |
| Fees on calls that move no amount | per-selector fee class ([CTR-MTX-20](#CTR-MTX-20)) |
| EOA allowances | `approve` needs a contract caller and spender; not allowlisted ([CTR-TOK-01](token-wrappers.md#CTR-TOK-01)) |
| Front-running `initialize()` of a clone | atomic init in the factory + `msg.sender == FACTORY` |
| Someone calls `initialize()` on the implementation | the constructor locks the implementation |
| Grief a relayer with meta-txs that surely revert | the node's simulation gate and its breaker per `(from, selector)`; nonce check before the signature check; expired intents dropped |
| Signature malleability | OpenZeppelin `ECDSA.tryRecover` (low-s) on chain; client verifiers refuse `s > n/2` |
| A wrapper redeems more than its reserve | the solvency invariant, fuzzed ([CTR-TOK-05](token-wrappers.md#CTR-TOK-05)) |
| Trade legs | the token moves funds only into the signed `dex`, a contract ([CTR-DEX-15](dex.md#CTR-DEX-15)) |
| Personal data on chain | on chain there are only wallet addresses, amounts and random `entryRef`s — no names, no order numbers |

Replay protection in short: the domain carries `chainId`, `salt` and `verifyingContract`; the 2D nonce is consumed on
execution; `validUntil` bounds every intent (300 s for portal payments); `cancelNonce(batch)` lets a signer withdraw.
Relayers never hold user funds: tokens grant no allowance to relayers, a meta-tx moves only the signed `from → to` or
runs the signer's own call, and the DEX holds no balance between transactions. Node-side threats are in
[node/threat-model.md](../node/threat-model.md).

## Conformance

Foundry (`forge test`, default profile and `private7622`):

- Every allowlisted selector through `mtxExecute` and through the alias; `mtxSelectors()` pinned; every allowlisted
  function `nonReentrant`; a non-allowlisted selector, a short `data`, a wrong static length, `to ≠ 0` or `value ≠ 0`
  on a self-call, and a fee mode outside the class each revert with their error; Single's `unwrap(uint256,address)`
  refused.
- Spoofing: tokens parked at the token's address cannot be spent through a self-call; `from == this` refused; nesting
  refused; a re-entry from an underlying hook during the self-call reverts; the "stays `msg.sender`" lint.
- All-or-nothing: an inner revert bubbles its data and leaves fee and nonce untouched; a fee transfer that fails after
  the call reverts the call's effects; a wrap pays its `ABSOLUTE` fee from minted units.
- Init once, factory only, implementation locked; tier 1 mint/minter; wrap/unwrap with a fee-on-transfer token; the
  `pay` shape emits `PaymentSettled` with the real fee; nonce/expiry/replay/`cancelNonce` (direct and signed);
  ERC-1271; EOA `approve` refused.
- Invariants (`StdInvariant`): `Σ balances == totalSupply`; wrapper solvency; the DEX holds 0 after every handler
  sequence.
- `MetaTxGas.t.sol` re-measured; `test_metaTxTypehashIsPinned` is never touched.
- KAT: `test/vectors/metatx_kat.json` with the salted domain, plus `mtxpay` vectors and `mtxExecute` calldata vectors
  for every allowlisted selector ([token-wrappers.md](token-wrappers.md#conformance)).
- Node (`cargo test`): digest == KAT; `data` decode/encode against the allowlist; canonical re-encoding of dynamic
  selectors; the integration tests (`--ignored`, need `anvil` + `forge`) deploy, sign, submit for real and read the
  events back.

## Transitional (BUILT)

<a id="transitional-built"></a>
<a id="v1"></a>

Until the base is rebuilt, the code runs two lines with a hand-written op dispatch instead of the self-call
(each item is removed by the rule named in brackets):

- **Bases** ([CTR-MTX-07](#CTR-MTX-07)). v1: the `ERC20MetaTx` mixin + `MetaToken` (kind `META`, tiers 1 and 2 in one
  implementation; tier 2 reads `IERC20Metadata(underlying).decimals()` at init, mints only through `wrap` and keeps
  `underlying.balanceOf(this) >= totalSupply`; `unwrap(amount, recipient)`; `initialSupply == 0 && minter == 0` else
  `WrapperHasNoMint`; errors `NotMinter`, `NotAWrapper`) and `HederaMetaToken`; v2: `MetaTxCore` + `MetaTokenBase` + the
  three tiers, its pipeline over a memory struct (`_execute(MetaTransaction memory m, bytes calldata sig)`), op
  arguments read with `mload` at fixed offsets and an address word with any of its upper 96 bits set refused (as
  `abi.decode` would); Zether on `ZetherMetaTx`. Invariants as built: `Σ balance == totalSupply`; wrapper
  `reserve >= totalSupply`, fuzzed as `reserve >= supply`.
- **Domains** ([CTR-MTX-02](#CTR-MTX-02)). v1 `("SCaaS MetaToken", "1", chainId, clone)` (`name = "SCaaS MetaToken"`,
  `verifyingContract = clone`); v2 `("SCaaS MetaToken", "2", chainId, clone)`; no salt. Clients call `payLane` only when
  `eip712Domain().version == "2"` and derive the lane off chain for v1.
- **Dispatch** ([CTR-MTX-17](#CTR-MTX-17), [CTR-MTX-19](#CTR-MTX-19)). `executeMetaTransaction(m, signature)` runs nine
  steps: relayer, expiry, mode, `m.nonce == metaNonce(from, batch)`, signature, then at step 6 the fee, the payee check
  (v2) and `_checkOp`, at step 7 the fee transfer (v2 also writes `metaNonce = expected + 1`), at step 8 `_executeOp`,
  at step 9 the event (v1 increments the nonce there). Ops, by `data`:

  | `data` | Length | Step 6 | Step 8 |
  |---|---|---|---|
  | empty | 0 | balance | `transfer(from → to, value)` |
  | `pay(bytes32 entryRef)` (`OP_PAY = bytes4(keccak256("pay(bytes32)"))`) | 36 | `to != 0` (`PayToZero`); `data.length < 4` ⇒ `MetaTxUnknownOp(0)` | transfer + `PaymentSettled(from, to, amount, feeAmount, feeRecipient, entryRef)` |
  | `trade(address counterToken, uint256 minCounterValue, address counterparty)` (`OP_TRADE` = `trade(address,uint256,address)`) | 100 | `MODE_RESTRICT_RELAYER` and `to == msg.sender` (`TradeLegNotRestricted`) | transfer `from → msg.sender` |
  | `approve(address spender, uint256 amount)` (`OP_APPROVE` = `approve(address,uint256)`) | 68 | `value == 0`, `to == spender`, spender a contract (`ApproveCarriesValue`, `ApproveSpenderMismatch`, `SpenderNotContract`) | set allowance |
  | `unwrap(address underlying, address recipient, uint256 minOut)` (`OP_UNWRAP` = `unwrap(address,address,uint256)`, v2 wrapper tiers) | 100 | leg known, `to == recipient ∉ {0, token}` (`UnwrapRecipientMismatch`), `minOut ≤ out ≤ reserve`, `out > 0` | `len == 100`, `out = ⌊value·den/num⌋ > 0`; step 8: `burned = ⌈out·num/den⌉ ≤ value`, `_burn(from, burned)`, debit reserve, the underlying's transfer (the only thing allowed to fail after step 7), `Unwrapped(from, u, recipient, burned, out)`; `UnwrapRecipientMismatch()` |
  | other | — | `MetaTxUnknownOp(bytes4)` | — |

  The payment branch is also reachable as `data = pay(bytes32 entryRef)` through `mtxPay`.
- **Guard** ([CTR-MTX-18](#CTR-MTX-18)). Transient slots `keccak256("scaas.metatx.reentrancy.v1")` and
  `keccak256("scaas.metatx.reentrancy.v2")`; no ticket, so a guarded function cannot run as a self-call.
- **Names** ([CTR-MTX-21](#CTR-MTX-21)). `executeMetaTransactionWithFee(m, sig)`, `mtxUnwrap` and `mtxUnwrapWithFee`
  (13 parameters, decoded by hand in `fallback`, interface `IMetaTokenV2UnwrapWithFee`; `fallback` checks the selector
  before the guard because a `TSTORE` inside a `STATICCALL` halts), `cancelMetaNonce` (direct only; it increments
  `metaNonce[msg.sender][batch]`; v1 emits no event), `metaNonce`, `metaTxDigest`. "At most once" through `mtxPay`
  holds per path, as in [CTR-MTX-10](#CTR-MTX-10).
- **Fees** ([CTR-MTX-20](#CTR-MTX-20), [CTR-MTX-08](#CTR-MTX-08)). `FIXED` is capped at 1 % of `value` on every public
  op; `FeeRecipientIsPayee` exists on v2 only.
- **Clone safety** (unchanged in the target, now on every tier, [token-wrappers.md](token-wrappers.md#permissionless-vs-controlled)).
  The implementation's `constructor(address factory_)` sets `FACTORY` and `_SELF` and locks the implementation;
  `initialize(creator, underlying, verifier, version, initData)` does `require(msg.sender == FACTORY)` once, requires
  `verifier == 0` (kind `META`) and runs in the same factory function as `CREATE2`; `name()`, `symbol()`,
  `decimals()` read the clone's storage; no `pause`, blacklist, freeze, owner or upgrade.
- **Tests** (replaced by the conformance list above). `MetaToken.t.sol` (unknown op reverts; unrestricted `trade` op
  reverts), `OpenFactory.t.sol`, `MetaTxDex.t.sol` (a fee to `feeRecipient ∈ {0, dex}` reverts), the v2 KAT
  `test/vectors/metatx_v2_kat.json` with `mtxunwrap` vectors.
