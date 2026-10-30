# Metatx split (variant A), with `mtxPayMeta` / `uaPayMeta` and `MtxRelayFee` — design

**Status:** spec; built on branch `metatx-split` (Tasks 1–20 and the final fix wave, 2026-10-27/28); not merged (merge and push need the owner's go). Written 2026-10-27 on branch `metatx-split` (from `main` `0c191232`). The owner
skipped the question round ("viết spec luôn", 2026-10-27), so this spec is written from the code on `main`, the
2026-10-21 spike and the owner's recorded rulings. Every choice marked **controller call** is the controller's; the
owner may override it. The owner answered the four questions of §13 the same day (§0, rows "2026-10-27 owner
answer"): this item covers **every family**, the fee amount is checked before the self-call, the trade and
receiver-fee signatures go through the library, and the `set.toml` re-pins run only the affected gate steps.

**Work item.** TODO §00 "Now" item 5: the metatx split together with `mtxPayMeta` / `uaPayMeta`
([CTR-MTX-26](../../contracts/metatx.md#CTR-MTX-26)), then `MtxRelayFee`
([CTR-MTX-27](../../contracts/metatx.md#CTR-MTX-27)), with or before UA-7. After it: UA-8, fs3 Task 12 → 6 → 13 → 14,
UA-7, governance code.

## 0. Owner rulings this spec rests on (not reopened)

| Date | Ruling | Where recorded |
|---|---|---|
| 2026-10-20 | The meta-tx code is split anyway ("kiểu gì cũng phải tách"), because governance code is coming to every factory-made contract; governance goes to a library or module. | TODO "Metatx split" |
| 2026-10-21 | **Variant A:** a DELEGATECALL library; the token keeps every entry point. The library gets only the envelope's data hash (`keccak256(data)`), the selector and the fee-basis word, never `data` itself (else a ≈ 340 KB op 7 pays ≈ +1 M gas). The self-call stays in the token. | TODO, HANDOFF 2026-10-21 |
| 2026-10-21 | Timing: after 5h part B (done), before fs3 Tasks 12 / 6 / 13 and before governance code. Purpose: room for governance code in the shared base; the binding kind is `WrappedPqzToken`. | TODO, HANDOFF |
| 2026-10-11, 2026-10-21 | Code size: no micro-optimisation. The ceiling is 64 KiB (65,536 B). The size gate's ratchet baseline records sizes ([CTR-TOK-24](../../contracts/token-wrappers.md#CTR-TOK-24)). | `size-baseline.json` comment |
| 2026-10-20 | `MtxRule` stays as is (`feeClass = 0` = not relayable; `ABSOLUTE` / `AMOUNT` = the fee basis). | TODO `MtxRule` item, CTR-MTX-20 |
| 2026-10-26 | CTR-MTX-26 as recorded: every token tier and every non-EVM family. | decisions.md CTR-MTX-26 |
| 2026-10-26 | CTR-MTX-27 as recorded: a stateless router in `src/metatx/`, deployed by `DeployBase` through CREATE2, open to every relayer, public balances only, every token tier, non-EVM too (GRAM by escrow), PQ payers sign twice (option (a)), no budget mode. | decisions.md CTR-MTX-27 |
| 2026-10-20 | Every state-changing `mtx*` is relayable; the outer fee may be 0. The native-coin `mtxWrapShield` is the one recorded exception (review C0-18, 2026-10-27). | CTR-MTX-19 Change lines |
| 2026-10-21 | Never assume gas price 0 or a chain's own block limit: EIP-7825 (2^24 regular gas per transaction), EIP-7976 (calldata floor), EIP-8037 (state gas). | NET-EVM-06 |
| 2026-10-25 | One rule for every chain kind. | memory, decisions |
| 2026-10-21 | Ciphertexts stay in contract state. | CTR-PQZ-07 |
| 2026-10-27 | `ROLL_MAX` is bounded on **both** relay paths: the largest multiple of 16 whose relayed full rollover stays ≤ 0.75 · 2^24 regular gas through `mtxExecute` and `uaExecute`. Today 96 / 80 / 64 / 32 at `n2048-kmax1024` / `n2304-kmax4096` / `n2560-kmax16384` / `n2816-kmax65536`. | decisions.md CTR-PQZ-07 Change 2026-10-27 |
| 2026-10-27 | PQZH option (A): on chain only the forms that fit one 2^24 transaction on both relay paths; at `n2048-kmax1024` single-key holders only, `slhdsa128s` the one excluded fee-UA kind on `uaExecute`. | decisions.md CTR-PQZ-11 Change lines |
| standing | Decisions recorded in full; parameter sets named `n2048-kmax1024` style; library code hashes pinned in the release; no SELFDESTRUCT in any library; agents stop at the branch (merge / push only on the owner's go). | memory |
| 2026-10-27 owner answer (§13 Q1) | **All families in this one work item** ("Tất cả một lượt"), against the controller's proposal of EVM + Hedera first: CTR-MTX-26 (`mtxPayMeta` / `uaPayMeta` and each family's pay-meta entry) and CTR-MTX-27 (`MtxRelayFee` and each family's router) on EVM, Hedera, Soroban, Solana, Cosmos, Sui, Aptos and GRAM (TON), each in the form that family's existing token / meta-tx code takes (§6.2, §7.2). Status: accepted, this spec. | this spec §8, §13 |
| 2026-10-27 owner answer (§13 Q2) | The fee amount of a self-call is computed and checked **before** the self-call, in one library call; when both the fee rule and the call fail, the fee error wins (§3.8). Controller proposal accepted. | this spec §3.8 |
| 2026-10-27 owner answer (§13 Q3) | The signature checks of the trade and receiver-fee paths go **through the library** (`requireSignature` / `authorize`), one copy of the signature rule (§3.1, §3.4). Controller proposal accepted. | this spec §3.1 |
| 2026-10-27 owner answer (§13 Q4) | The `set.toml` re-pins of this item (`debit_min_gas` at all four sets, `roll_max` at `n2560-kmax16384` if the 2026-10-27 rule moves it) run **only the affected gate steps**: `gen_set.py --all --check`, forge at each of the four sets (`at-set.sh`), the size gate, `docs_check`. No full pqz-core gate, because neither key is read by a core or changes a proof parameter. Controller proposal accepted; it is an exception to the 2026-10-25 "`set.toml` change = full gate" rule for these two keys in this item. | this spec §5.3, §8 |
| 2026-10-27 | NEAR and Algorand (PLANNED in `docs/networks/README.md`, no code yet) are built right **after** this item, as their own family bring-up item (family spec → plan → build), and carry CTR-MTX-26 and CTR-MTX-27 from the start, with the semantics this item fixes (§8). Not in this item's plan. | this spec §8 |

## 1. Intent

**Why.** Every token kind carries the whole meta-tx pipeline in its own bytecode: envelope checks, the EIP-712
digest, signature and UA-registry authorization, the allowlist check, nonce lanes, fee amounts, for four signed
structs. Governance code (the governance matrix, TODO) will go into the shared base and so into every kind.
`WrappedPqzToken` is 61,519 B today (`size-baseline.json`), 4,017 B under the 65,536 B ceiling. The split moves
the pipeline's checks into one library that every kind links, so the shared base has room again.

**Goals.**
1. One external library, `MtxPipelineLib`, holds the checks of every signed path of every token kind: steps 1–4 of
   CTR-MTX-17 and the fee amount, on the address path and the UA path, for `MetaTransaction` and `MetaTransfer`, and the
   signature checks of the trade and receiver-fee paths.
2. Same behaviour: the same selectors, ABI, events, storage, digests and outcomes as today, with one recorded
   exception (§3.8).
3. `mtxPayMeta` / `uaPayMeta` on every `MetaTokenBase` kind (CTR-MTX-26), built on the split; the pay-meta entry of
   every non-EVM family (§6.2).
4. `MtxRelayFee` and its executor (CTR-MTX-27), deployed by `DeployBase`; the router of every non-EVM family (§7.2).
5. The node and the clients changed where these need it (§9), every family adapter included.
6. Every thin gas margin re-measured with the final bytecode, and every constant that follows from it re-pinned (§5).
7. The four known code / doc gaps closed (§11.1).

**Non-goals.**
- Moving entry points, ABI decoding, balance moves, events, `nonReentrant` or the self-call out of the token (that is
  variant B, not chosen).
- A second PQZ meta-tx library (the spike's "A2"): the rule tables, `_isPqzOp`, `_batchable` and `mtxSelectors` stay
  in the kinds (§3.6).
- Changing `MtxRule`, any typehash, any domain, any selector, the transient slots or the storage layout.
- Code-size work beyond the split itself.
- The wallets (`SmartKeyAccount`, `MandateWallet`, `HederaMandateWallet`) and `SCaaSDex` linking the library (§3.7).
- A split of any non-EVM family's code: no non-EVM family has the size problem; only CTR-MTX-26 / -27 go there.
- NEAR and Algorand (their own bring-up item right after this one, §8).
- PQ signers off EVM: no non-EVM family has a UA registry or a PQ key today, so CTR-MTX-27's "PQ payers sign twice"
  (option (a)) is an EVM rule only; off EVM the payer signs its family's classical op once and the target its own.
- Governance code itself.

**Anti-goals** (the plan must show each does not happen):
- A relayed path whose gas grows with the size of `data` because of the split: `data` is never passed to, copied for
  or ABI-encoded for the library (§5.2 states the one bounded residual).
- A second copy of any rule: one source for each check, compiled into the library for the tokens and inlined into
  `MetaTxBase` for the wallets.
- A library with state of its own, immutables, a constructor argument, SELFDESTRUCT, or a DELEGATECALL / CALLCODE to
  any address that its own code does not name.
- A direct (non-signed) path that touches the library: `transfer`, `transferToUA`, `wrap`, `mint`, `payWithFee`, the
  PQZ / Zether direct ops keep today's gas (± dispatch).
- An unpinned library in a release: every library in a release's link closure is in `Env.libs`.

## 2. Today (code on `main` `0c191232`)

- `MetaTxBase` (`src/metatx/MetaTxBase.sol`): the generic pipeline `_execute` (steps 1–7), `_checkEnvelope`,
  `_checkCall`, `_useNonce`, `_selfCall`, the transient slots (`_GUARD`, `_SENDER`, `_TICKET`, `_BINDING`), the nonce
  map (ERC-7201 `scaas.metatx`), the hooks `_mtxRule`, `_batchable`, `_chargeFee`, `_requireValidSignature`,
  `_erc1271Gas`, `_selfSender`, `_envelopeBinding`. Inherited by every token and by `SmartKeyAccount` and
  `MandateWallet`.
- `ERC20MetaTx`: the fee in this token (`_chargeFee`, `_callFee`), the typed path (`_executeTransfer`,
  `_checkTransfer`), the trade side (`mtxTrade`, `uaTrade`, `mtxCancelOrder`, `uaCancelOrder`, `mtxInvalidateNonces`,
  `uaInvalidateNonces`), the UA ledger and the UA pipelines (`_uaExecute`, `_uaExecuteTransfer`, `_checkUATransfer`,
  `_uaAuthorize`, `_requireNativeUASignature`, `_checkTo`, `uaCancelNonce`).
- `MetaTokenBase`: the named builders (`mtxTransfer*`, `mtxExecuteWithFee`, `mtxPay`, `uaTransfer*`, `uaPay`,
  `uaUnwrap`), receiver-pays (`mtxPayReceiverFee`, `uaPayReceiverFee`), `payWithFee*`, the Hedera branch of
  `_requireValidSignature` / `_requireNativeUASignature` (`HederaLib`), `_erc1271Gas` (400,000 for a `SmartKeyAccount`
  clone, else 50,000), the immutables `FACTORY`, `SMART_KEY_ACCOUNT_IMPL`, `_SMART_KEY_CLONE_CODEHASH`, `IS_HEDERA`.
- The kinds override `_mtxRule`, `mtxSelectors`, `_uaAllowed`; the PQZ and Zether kinds also `_domainName`,
  `_envelopeBinding`, `_uaEnvelopeBinding`, `_batchable`.
- Linked libraries today: `AdminLib`, `HederaLib`, `TradeLib` (every kind), `WrappedLib` (wrapped kinds),
  `ZetherLib`, `PqzStateLib` / `PqzTransferLib` / `PqzBurnLib` / `PqzViewLib`. `OpenFactory._deploy` checks each
  `Env.libs[i].codehash` against `Env.libCodeHashes[i]` before the release's CREATE2.
- Sizes (runtime, baseline): `NormalToken` 38,598; `WrappedToken` 48,524; `NormalZetherToken` 48,605;
  `NormalPqzToken` 49,336; `WrappedZetherToken` 60,625; `WrappedPqzToken` 61,519.
- The spike (branch `metatx-lib`, report `scratchpad/metatx-lib-report.md`) predates 5h part B, UA-6's final round and
  the 2026-10-27 review fix round. Its library ran the self-call and took `data`. It lacks today's pool checks
  (`_notPool`, C5-3), the id-0 refusal (C5-2), the unconditional binding write (C5-5) and `_pullShieldIn` (C2-5). Its
  numbers are estimates for this design, not facts about it.

## 3. The library boundary

### 3.1 What moves, what stays

| Moves into `MtxPipelineLib` (external functions, run by DELEGATECALL in the token's context) | Stays in the token |
|---|---|
| Step 1, the envelope: relayer binding, expiry, mode bits, nonce equality, `from == address(this)` refused (`SelfSender`) | Every entry point, its ABI decoding and its named-builder code |
| Step 2: the EIP-712 struct hash of all four structs (from the data hash) and the digest over the domain separator the token passes | `keccak256(data)` (over the token's memory copy, as today) |
| Step 2: the signature rule of the address path (`SigCheck.isValid`, the ERC-1271 cap by clone code hash, the HIP-632 branch through `HederaLib`) | The rule lookup: `_mtxRule(sel)` and `_uaAllowed(sel)` (virtual, per kind; `MtxRule` unchanged) |
| Step 2: the UA authorization rule (`_uaAuthorize`: the registry's `requireAuthorized` for a derived id; for a native id the 0 / pool refusals, then `SigCheck.isValid7702` or HIP-632) | The fee-basis word read from `data` (`amountArg`), the selector and `data.length` |
| Step 3: shape, allowlist verdict, fee class against mode, `supportedModes`; the UA path's `MetaTxUnknownOp` | `_envelopeBinding` / `_uaEnvelopeBinding` (virtual; envelope fields only) |
| Step 3 of the typed paths: payee and fee-recipient checks, the pool refusals, the receiver check (`_checkTo`, `kindOf` on the registry), fee amount, balance against `have` | `_requireBatchable` (virtual `_batchable`) |
| Step 4: the nonce write (the same ERC-7201 slot) | Step 5: the ticket, the self-call, the binding slot (`_selfCall`) and `nonReentrant` |
| The fee amount and fee recipient of a self-call (`_callFee`), now in step 3 (§3.8) | Step 6: the fee move (`_transfer` / `_uaMove`) and the typed paths' value move |
| The signature checks of `mtxTrade`, `uaTrade`, `mtxCancelOrder`, `uaCancelOrder`, `mtxInvalidateNonces`, `uaInvalidateNonces`, `mtxPayReceiverFee` (payee), `uaPayReceiverFee` (payee) — **owner 2026-10-27** (§13 Q3) | Step 7: every event; the UA ledger; `_poolMove`; `uaCancelNonce` (its direct `requireAuthorized`, the cancel-used set, `_bumpNonce`); `cancelNonce` |
| The digest of the four digest views (`mtxDigest`, `uaDigest`, `mtxTransferDigest`, `uaTransferDigest`) | Every immutable: read by the token and passed in a `Ctx` |

The library holds **no immutables and no storage of its own**. Everything that differs per kind, release or chain
comes in `Ctx` from the token's own immutables. So one library serves every kind and every chain (controller call).

### 3.2 Call interface

File `src/metatx/MtxPipelineLib.sol` (name: controller call). Errors are the existing ones (`IMetaTx`,
`IERC20MetaTx`, `IUALedger`, `FeePolicy`, `MetaTxLib`, `SigCheck`, `HederaLib`).

```solidity
library MtxPipelineLib {
    /// The token's immutables, built once per call by `ERC20MetaTx._mtxCtx()` (the only place that builds it).
    struct Ctx {
        bytes32 domainSeparator;   // _domainSeparatorV4() of this clone (kind's domain name, chainid, clone, chain_uid)
        address registry;          // _REGISTRY (0 = UA ledger off)
        bytes32 skaCloneCodehash;  // _SMART_KEY_CLONE_CODEHASH (0 = none): ERC-1271 cap 400,000 for such a signer, else 50,000
        bool hedera;               // IS_HEDERA
    }

    /// Every signed field of a MetaTransaction / UAMetaTransaction except `data`; `from` as an id (an address
    /// zero-padded, MetaTxLib.pad). abi.encode of a padded id equals abi.encode of the address, so one struct hash
    /// serves both typehashes.
    struct Envelope {
        bytes32 from; bytes32 dataHash; uint256 batch; uint256 nonce; uint256 validUntil;
        uint32 mode; address relayer; uint256 fee; address feeRecipient;
    }

    /// What the token read from `data` and its own hooks. The rule as three scalars (MtxRule unchanged in MetaTxBase).
    struct CallFacts {
        bytes4 sel; uint256 len;                        // bytes4(data), data.length
        uint8 feeClass; uint8 amountArg; uint32 staticLen;  // _mtxRule(sel)
        uint256 basis;                                  // word amountArg of the arguments if present, else 0
        bool uaAllowed;                                 // _uaAllowed(sel); read on the UA path only
    }

    struct Out { bytes32 digest; uint256 fee; address feeTo; }

    /// CTR-MTX-17 steps 1-4 and the fee amount, address path (ua = false) or UA path (ua = true).
    function preCall(Ctx calldata c, Envelope calldata e, CallFacts calldata f, bool ua, bytes calldata auth)
        external returns (Out memory);

    /// CTR-MTX-23 steps 1-4 of the typed path. `t` in the UAMetaTransfer layout (ids); the address path passes padded
    /// ids. `have` = balanceOf(from) (address path) or balanceOfUA(from) (UA path), read by the token before the call.
    function preTransfer(Ctx calldata c, MetaTxLib.UAMetaTransfer calldata t, bool ua, uint256 have,
        bytes calldata auth) external returns (Out memory);

    /// The address path's signature rule (step 2 of every address-path signed struct, trade, receiver-fee payee).
    function requireSignature(Ctx calldata c, address from, bytes32 digest, bytes calldata sig) external view;

    /// The UA rule under `purpose` (metatx, trade, receiver-fee).
    function authorize(Ctx calldata c, bytes32 from, bytes32 purpose, bytes32 digest, bytes calldata auth)
        external view;

    /// The digest views. typehash: METATX / UAMETATX.
    function callDigest(bytes32 domainSeparator, bytes32 typehash, Envelope calldata e) external pure returns (bytes32);
    function transferDigest(bytes32 domainSeparator, bool ua, MetaTxLib.UAMetaTransfer calldata t)
        external pure returns (bytes32);
}
```

Rules of the interface:
- `external` with `calldata` parameters, so the library frame does not copy its arguments.
- The token passes fixed-size words plus the signature or `auth`. It never passes `data`.
- `preCall` and `preTransfer` write only the nonce slot `nonce[from][batch]` of `scaas.metatx`. The slot constant and
  the storage struct are defined once, in `MtxPipelineLib`; `MetaTxBase._mtxStorage()` uses that definition.
- The check bodies are `internal` functions of `MtxPipelineLib` (`_checkEnvelope`, `_structHash`, `_checkCall`,
  `_callFee`, `_checkTransfer`, `_checkTo`, `_useNonce`). The external functions compose them for the tokens.
  `MetaTxBase` calls the same internal functions directly (inlined, no link), so the wallets keep their own
  composition with their virtual hooks (§3.7). One source per rule.
- Order inside `preCall` (address path): envelope (with `SelfSender`), digest, `requireSignature`, `_checkCall`
  (`supportedModes` = `MODE_KNOWN_MASK`, the tokens' value), nonce write, fee amount. UA path: ledger on
  (`UALedgerOff`), envelope, digest, `authorize(PURPOSE_METATX)`, `MetaTxUnknownOp` if `len < 4 || !uaAllowed`,
  `_checkCall`, nonce write, fee amount (with `UAPoolNotPayable` for a `UA_POOL` recipient). Today's order, plus the
  fee amount (§3.8).
- Order inside `preTransfer`: today's `_executeTransfer` / `_uaExecuteTransfer` steps 1–4 exactly, with `have` in
  place of the balance read.

### 3.3 A relayed call under the split

```mermaid
sequenceDiagram
    participant R as Relayer
    participant T as Token (clone)
    participant L as MtxPipelineLib (DELEGATECALL)
    participant G as UARegistry / signer wallet
    R->>T: mtxExecute(m, sig) / uaExecute(m, auth)
    T->>T: nonReentrant; m in memory; dataHash = keccak256(m.data)
    T->>T: sel, len, _mtxRule(sel), basis word, _uaAllowed(sel); Ctx from immutables
    T->>L: preCall(ctx, envelope, facts, ua, sig)
    L->>L: 1 envelope, 2 digest
    L->>G: 2 ERC-1271 / requireAuthorized (STATICCALL; HIP-632 through HederaLib)
    L->>L: 3 shape, fee class, modes, fee amount; 4 nonce + 1
    L-->>T: (digest, fee, feeTo)
    T->>T: 5 ticket, binding = _envelopeBinding(m), self-call(data)
    T->>T: 6 fee move (_transfer / _uaMove)
    T-->>R: 7 MetaTransactionExecuted / UAMetaTransactionExecuted
```

### 3.4 Each path

- **`mtxExecute`, `executeMetaTransaction`, `mtxExecuteWithFee`, `mtxBatch`:** `ERC20MetaTx` overrides `_execute`
  (made `internal virtual` in `MetaTxBase`): build the envelope and the facts, `preCall`, `_selfCall`, the fee move,
  the event. `mtxBatch` calls `_requireBatchable` first (token), then `_execute` per item; the library is cold only on
  the first item.
- **`uaExecute`, `uaBatch`, `uaUnwrap`:** `_uaExecute` does the same with `ua = true`. `uaUnwrap` still builds its
  memory struct (small `data`).
- **Typed paths** (`mtxExecuteTransfer`, `mtxBatchTransfer`, `mtxTransfer`, `mtxTransferWithFee`, `mtxPay`, the new
  `mtxPayMeta`; UA twins `uaExecuteTransfer`, `uaBatchTransfer`, `uaTransfer`, `uaTransferWithFee`, `uaPay`,
  `uaPayMeta`): `_executeTransfer` / `_uaExecuteTransfer` read `have`, call `preTransfer`, then move fee and value
  and emit, as today. The address path pads `from` and `to` into the UA layout.
- **Receiver-pays:** `mtxPayReceiverFee` / `uaPayReceiverFee` keep their shape checks in the token, run the typed
  pipeline, then the payee check through `requireSignature` / `authorize(PURPOSE_RECEIVER_FEE)` (the library is warm).
- **Trade side:** `mtxTrade`, `mtxCancelOrder`, `mtxInvalidateNonces` call `requireSignature`; `uaTrade`,
  `uaCancelOrder`, `uaInvalidateNonces` call `authorize(PURPOSE_TRADE)`. `TradeLib` is unchanged. In a DEX settlement
  that fills several tokens, every token links the same library address, so the library is cold once per transaction.
- **Views:** the four digest views compute `keccak256(data)` and call `callDigest` / `transferDigest`.
  `tradeOrderDigest` and the other trade digests stay in the token (`TradeLib` hashing).
- **Direct paths never touch the library:** `transfer`, `transferFrom`, `approve`, `transferToUA`, `payWithFee`,
  `payWithFeeToUA`, `mint*`, `burn`, `wrap*`, `unwrap*`, the admin entries, the PQZ / Zether direct ops. Their
  receiver check `_checkTo` is the library's internal function, inlined in the token (the same source as the copy
  inside `preTransfer`).

### 3.5 Each token kind

All six kinds (`NORMAL`, `WRAPPED`, `NORMAL_ZETHER`, `WRAPPED_ZETHER`, `NORMAL_PQZ`, `WRAPPED_PQZ`) use the
library through `ERC20MetaTx` / `MetaTokenBase`, in the same way. What differs per kind enters as data:

| Input | Source |
|---|---|
| Domain separator | `_domainSeparatorV4()`: "SCaaS MetaToken", "SCaaS ZetherToken" or "SCaaS PqzToken" (CTR-MTX-02) |
| Rule, UA verdict | the kind's `_mtxRule`, `_uaAllowed` |
| Binding | the kind's `_envelopeBinding`, `_uaEnvelopeBinding` (0 on the plain kinds) |
| Batchable | the kind's `_batchable` |
| Registry, Hedera, SmartKeyAccount clone hash | the release's `Env`, through the immutables |

`WRAPPED*` kinds: `mtxWrap` / `uaWrap` run the underlying token's `mtxTrade` / `uaTrade`, which checks the
signature through its own (the same) library. Hedera: `IS_HEDERA` implementations take the HIP-632 branch inside the
library; the HIP-632 call runs in the token's context, as today.

### 3.6 The PQZ and Zether layers' relayed paths

A confidential op relayed through `mtxExecute` or `uaExecute` is an ordinary self-call. The token computes the
envelope binding from the envelope fields only (`TAG_ENVELOPE`, `TAG_UA_ENVELOPE`, the Zether tags), before the
self-call, as today. Inside the self-call nothing changes: `_ticketBinding()`, `_ticketSubject()`, the PQZ libraries'
own statement authorization (`requireAuthorized` over the statement digest in `PqzCore`), the nonces of the
confidential layer (`sendCounter`), txFee / decoyFee, `_pullShieldIn`, the Zether proof checks and
`mtxRollOverSigned`'s own signature. `_isPqzOp`, `_pqzRule`, the Zether op list and `mtxSelectors` stay in the kinds.
Ops stay never-batchable (CTR-PQZ-21). The spike's second library (A2, a hand copy of three rule layers) is not built
(controller call): it saved 2.6 KB at +4.8k gas cold per relayed call and carried the copy risk.

### 3.7 Contracts that do not link the library

- `SmartKeyAccount`, `MandateWallet`, `HederaMandateWallet` keep `MetaTxBase`'s own `_execute` with their overrides
  (`_requireValidSignature`, `_selfSender`, `_mtxRule`). `MetaTxBase` now calls the library's internal functions, so
  their bytecode changes but not their behaviour. They gain nothing from a library (they fit the default limits) and
  `SmartKeyAccount` is not an `OpenFactory` release, so it has no `Env.libs` pin (controller call).
- `SCaaSDex` is not on the base; unchanged.
- UA-5c (c) (the UA path moving down into `MetaTxBase`, CTR-MTX-22 Change 2026-10-13, SPECIFIED) is not built. This
  work keeps the UA path in `ERC20MetaTx`. The library's `ua` flag and internal functions are what that later move
  reuses.

### 3.8 The one behaviour change: the fee amount is checked before the call

Today the fee amount of a self-call (`_callFee`: `FeeExceedsCap`, `FeeRecipientRequired`, `UAPoolNotPayable`) is
computed after the self-call. It depends only on the envelope and the basis word, which are known before the call.
`preCall` computes it in step 3; the move still happens in step 6. Effect: an envelope that breaks both its fee rule
and its call now reverts with the fee error, before the call, instead of the call's error. Every outcome stays the
same (the whole transaction reverts either way), and the typed paths already work this way. This saves a second
library call per relayed call (≈ +1k gas warm [estimate]). **Owner 2026-10-27** (§13 Q2, the controller's proposal
accepted). CTR-MTX-17's table changes:
step 3 lists the fee checks, step 6 is "fee move".

## 4. Release, factory, deployment

- **One deployment per library version per chain**, shared by every release that links it. Its address is linked
  into each implementation's bytecode; a new library version means new releases, and old releases keep the old one
  (no SELFDESTRUCT, so it never disappears).
- **`Env.libs` pin the link closure.** Every kind's env lists `MtxPipelineLib` with its code hash, and keeps listing
  `HederaLib`, which becomes a library of `MtxPipelineLib` (the token may no longer link it directly). Rule: a
  release's `Env.libs` equals the transitive link closure of its implementation (direct and library-of-library).
- **`DeployBase`:** add `address(MtxPipelineLib)` to the `libs` arrays of the `NORMAL` env and of the Zether envs
  (`_deployTokenFactory`, `_deployZether`). Forge links and deploys it as it does today's linked libraries.
  `Deploy.s.sol` and `script/hedera/DeployHedera.s.sol` go through `DeployBase`, so they follow.
- **`script/pqz/e2e.py`:** `Deployer.linked()` collects only the token artifact's direct `linkReferences`. Change it
  to the transitive closure (each library's own `linkReferences`, deployed first), so the PQZ envs pin `HederaLib`
  and `MtxPipelineLib`. `D.lib()` already deploys a library with its own links.
- **`test/v2/Factory.t.sol`** and any fixture that builds an `Env` by hand: add the library.
- **The deploy gate ([NET-EVM-06](../../networks/evm.md#NET-EVM-06)):** `_requireReleaseGas` and e2e.py's
  `require_release_gas` read `size-baseline.json` at run time, so the kinds' needs drop with the ratchet. Update the
  per-kind table in `networks/evm.md`, the NET-EVM-06 addendum figures in `decisions.md` and the `DeployBase` comment
  figures with the measured sizes. Add rows for `MtxPipelineLib` and `MtxRelayFee` for information. No separate gate
  for the library (controller call): it is smaller than every implementation that links it, so the implementation's
  gate is the binding one.
- **`MtxRelayFee`:** `DeployBase` deploys `new MtxRelayFee{salt: salt}()` through the deterministic CREATE2 deployer;
  JSON key `mtx_relay_fee` (and `mtx_relay_executor`). It answers no `chainUid()`, so instead of the `chainUid()`
  gate the script checks that the router's `EXECUTOR()` has code and names the router back. Its address is the same
  on every chain only for the same bytecode and salt: any source or compiler change moves it (note for the
  deployment record).

## 5. Gas and size budget

### 5.1 Estimates (the plan measures every one)

| Item | Spike (2026-10-21, other code) | This design [estimate] |
|---|---|---|
| Token runtime saving | A: −3,763 B (`NORMAL`), −4,147 B (`WRAPPED_PQZ`) | −3.5 to −5 KB per kind (the self-call stays; trade and receiver-fee signatures and the digest views move) |
| Library runtime | 11,577 B | 10–12 KB |
| `mtxPayMeta` + `uaPayMeta` | — | +0.8 to +1.2 KB per kind |
| `WrappedPqzToken` after this item | — | ≈ 57–59 KB (headroom ≈ 6.5–8.5 KB) |
| Relayed call, cold | A: +7.1k to +9.4k | +3k to +6k (2,600 cold account at the Amsterdam price, ABI of ≈ 25 words plus the signature, return) |
| Relayed call, warm (2nd in a transaction) | A: +5.9k | +1k to +2.5k |
| Relayed op 1 (≈ 21 KB `data`) | A: +19.8k to +21.3k | as a small call, + ≤ 0.5k (§5.2) |
| Relayed ≈ 340 KB op 7 | A: ≈ +1.0 M (computed) | as a small call, + ≤ 8k (§5.2) |
| Direct calls | −67 (shorter dispatch) | unchanged ± dispatch |
| Library deploy, per chain and version | +1.49 to +1.56 M regular (computed) | regular as the spike; EIP-8037 state ≈ 1,530 × runtime ≈ 15–18 M |

### 5.2 The data-size residual and its bound

`data` never reaches the library. One small term remains. The token already holds `m` (with `data`) in memory, so
the library call's argument block (≈ 25 words plus the signature or `auth`) is written above it, and memory expansion
is priced at `3 + w/256` gas per word at `w` words in use. At 340 KB that is ≈ 44 gas per word: ≈ 1.1k gas for an
ECDSA envelope, ≈ 5.7k with an ML-DSA-65 fee UA (3,309 B `auth`) [estimate]. It is quadratic memory pricing of a
fixed-size block, not a per-byte copy. The cheaper-looking alternative (keep `m` in calldata and call the library
before the memory copy) adds a second copy of `data` (3 gas per word, ≈ +32k at 340 KB), so it is not taken.

**Acceptance bound (controller call):** for every accepted fee-UA kind on each relay path, the split's overhead at
the largest built envelope minus its overhead at the smallest envelope is ≤ 8,000 gas. The plan measures it at
`n2048-kmax1024` (PQZH debits, the largest envelopes) and `n2304-kmax4096` (PQZL op 7 M = 8 with the auditor).

### 5.3 What the plan must re-measure (with the final token bytecode: after the split and `mtxPayMeta`)

Forge gas is deterministic; these are correctness runs under `scripts/capped`, not timing runs (Task 9 timing stays
the owner's go). Every row on both relay paths where the path exists. Gate for the `set.toml` re-pins: only the
affected steps (owner 2026-10-27, §0): `gen_set.py --all --check`, forge at the four sets, the size gate,
`docs_check`; no full pqz-core gate.

1. **The overhead table:** every signed entry point, cold and warm, against the Part 0 fixture (§10, R1).
   `test/v2/MetaTxGasV2.t.sol` rows re-pinned.
2. **`ROLL_MAX` at all four sets** (`test/research/PqzPackGas.t.sol` scan, `PqzStatePinGasTest` in
   `test/pqz/PqzStateGas.t.sol`, `script/pqz/at-set.sh <set>`). The binding one is `n2560-kmax16384`: 64 keeps only
   15,281 gas on `uaExecute` (12,567,631 of 12,582,912). The estimated overhead (≈ 4–7k with the ML-DSA-65 fee UA and
   a 68-byte `data`) leaves ≈ 8–11k [estimate], so 64 probably holds.
   **If it does not:** the owner's rule of 2026-10-27 decides the value, no new ruling is needed: the largest
   multiple of 16 that fits both paths, so `n2560-kmax16384` goes to **48**. Record it: `set.toml` `roll_max = 48`
   with the measured figures in its comment, `gen_set.py --all`, the generated `PqzSet.sol` of that set,
   `n2560-kmax16384/SET.md`, the margins line in `contracts/pq-zero-knowledge.md`, `PqzStatePinGasTest`'s
   expectations, and a decisions.md Change line under CTR-PQZ-07 ("follows the owner rule of 2026-10-27; measured
   …"), with the run log in `smartcontracts/evm/runs/`. Report it to the owner in the work item's report. The other
   three sets keep large margins (721,953 / 314,639 / 1,344,117) and are re-asserted, not expected to move.
3. **PQZH `n2048-kmax1024` debits on `uaExecute`:** headroom today 1,361–2,769 B (87–177k gas). Re-run the PQZH rows
   and `test_gasTable_holderRows` (`mldsa65` and `fndsa512` fee UAs fit, `slhdsa128s` excluded; `fndsa512` burn 1 is
   16,429,976 today). Expected: −5k to −12k [estimate], so still fits. If a built form stops fitting, it leaves the
   on-chain list of option (A) by that ruling's own rule ("exactly the forms that fit"); record and report.
4. **`debit_min_gas`** (`PqzSet.PQZ_DEBIT_MIN_GAS`, the cheapest PQZL debit on `uaExecute`, read by `UARegistry`'s
   PQZ holder bound, C0-5): 6,820,062 / 6,991,487 / 7,161,789 / 7,351,418 today. The split raises the real figure, so
   the constant must be re-measured and re-pinned at all four sets (`set.toml`, `gen_set.py`). It is compiled into
   `UARegistry`, so the registry's bytecode changes: the SCaaS testnet takes a new registry at its next reset (fs3
   Task 13, together with UA-8's registry redeploy). `UARegistryPqzBound.t.sol` re-pinned.
5. **`mtxPrepareAcc` halves** (2.32–3.90 M on `uaExecute` today): re-assert under 0.75 · 2^24.
6. **The Zether prover's relayed rows** (`clients/zether-prover/src/zether.rs` `gas_limits`, measured through
   `mtxExecute`; `ZetherGasLimit.t.sol` with `ZETHER_GAS_PROBE=1`, `test_edge_*`, `gas_table_edges`): re-measure the
   relayed rows; the 1 % margin (167,772) absorbs the overhead, so the edges should not move; re-pin if a row moves.
7. **The node's ERC-1271 floor** (§9).
8. **The size table:** `forge build --sizes` → `scripts/size_gate.py`; ratchet `size-baseline.json` with a comment
   entry; the NET-EVM-06 table (§4).

## 6. CTR-MTX-26 on the split: `mtxPayMeta` / `uaPayMeta`

### 6.1 EVM (Hedera included)

Where it lives: in `MetaTokenBase` (all six kinds). Nothing in the library: the library sees an ordinary
`UAMetaTransfer`.

```solidity
// IMetaTokenV2 (controller call: not IERC20Payment or IUALedger, whose ERC-165 ids the token reports)
event PaymentMeta(bytes32 indexed payId, bytes meta);
function metaPayId(bytes32 salt, bytes calldata meta) external pure returns (bytes32);
    // keccak256(abi.encodePacked("scaas.pay.meta", salt, keccak256(meta)))
function mtxPayMeta(address from, address to, uint256 amount, bytes32 salt, bytes calldata meta, uint256 validUntil,
    uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes calldata signature) external returns (bool);
function uaPayMeta(bytes32 from, bytes32 to, uint256 amount, bytes32 salt, bytes calldata meta, uint256 validUntil,
    uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes calldata auth) external returns (bool);
```

Body, both: `nonReentrant`; `AdminLib.requireFeature(PAYABLE)`; `payId = metaPayId(salt, meta)`;
`emit PaymentMeta(payId, meta)`; then exactly `mtxPay` / `uaPay` with that `payId` (the same struct, lane
`payLane(payId)`, nonce 0, digest, signature). `meta` is hashed and logged, never parsed, never passed to the
library. No length cap in the contract (the payer pays for it); the node may cap it by policy (§9). The off-chain
variant is plain `mtxPay` / `uaPay` and needs no code.

Builder note: `mtxPayMeta` has 13 argument stack slots and `via_ir` is off, so a straightforward body will hit
"stack too deep". The ABI is fixed by CTR-MTX-26; restructure the body instead (for example share one private
helper with `mtxPay` that takes the struct, or read the static head from `msg.data`). Do not switch `via_ir` (it
changes every bytecode and every gas pin).

Vectors: `smartcontracts/vectors/metatx/paymeta.json` (path: controller call): `(salt, meta, payId, payLane(payId))`
for each schema 1–4 and edge cases (empty body, long body), read by a forge test, by `clientkeys` and by every
family's tests (§6.2).

### 6.2 The other families: one pay-meta entry each

Every family gets one pay-meta entry next to its existing signed pay. The rule is the same everywhere (EVM's
semantics, mirrored):

- **Derivation, byte for byte the EVM one:** `payId = keccak256("scaas.pay.meta" ‖ salt ‖ keccak256(meta))`,
  `payLane(p) = keccak256("scaas.pay.lane" ‖ p)` as a 32-byte lane id (every family's lanes are 32-byte ids). Each
  family hashes with its native Keccak-256: Soroban `env.crypto().keccak256`, Solana the keccak syscall
  (`solana-keccak-hasher`, already in `Cargo.lock`), Cosmos the RustCrypto `sha3` crate (a new workspace dependency,
  the sibling of the `sha2` already used: `cosmwasm-std` has no Keccak; controller call), Sui `sui::hash::keccak256`,
  Aptos `aptos_std::aptos_hash::keccak256`, TON Tact's `keccak256(Slice)` (stdlib of compiler 1.6.13; it hashes the
  whole snake chain). Every family's tests read the shared vectors `smartcontracts/vectors/metatx/paymeta.json`
  through its own vector path (§6.1, R16).
- **Same signed op as the family's plain pay** (`OP_PAY` / `"pay"`), plus `(salt, meta)` as unsigned arguments; the
  entry requires `pay_ref == metaPayId(salt, meta)`. Where the family has lanes, it also requires
  `lane == payLane(pay_ref)` and `nonce == 0` (where the entry's arguments are not the signed bytes themselves, it
  derives them on chain, as `mtxPay` does), so a pay-meta pays a `(payer, payId)` at most once, as `mtxPayMeta`.
  Soroban has no lanes: its `pay` keeps a per-token `PayRef` set keyed by `(from, pay_ref)` (once per payer and `pay_ref`, the per-payer lane of EVM; controller call 2026-10-27).
- **Event** `PaymentMeta(pay_id, meta)` before the family's `PaymentSettled` (TON: in the payer wallet's transaction,
  so it precedes the receiver wallet's `PaymentSettled` in logical time). The contract never parses `meta`.
- **Publication is the submitter's choice, as on EVM.** `mtxPay` and `mtxPayMeta` share one digest, so whoever
  holds `(salt, meta)` and the payer's signature can publish `meta` through the pay-meta entry. The off-chain variant
  stays private only while the payee keeps `(salt, meta)` to itself. The same holds on every family (Soroban
  excepted, where the auth entry covers `pay_meta`'s own arguments). Recorded, not a question: it follows from
  CTR-MTX-26's "no new struct".
- **Size:** no contract cap; bounded by each chain's transaction size (Solana 1,232 B per transaction, so a short
  `meta`) and the node's `max_pay_meta_bytes` (§9).

| Family | Entry (from the family's current code) | Where | Tests |
|---|---|---|---|
| Soroban | `pay_meta(env, from, to, amount, salt: BytesN<32>, meta: Bytes, valid_until)` on the token: `from.require_auth()` (the auth entry covers these arguments, `meta` included), `pay_ref = metaPayId`, then `pay`'s body through one private `settle_pay(env, from, to, amount, pay_ref, valid_until)` shared with `pay` (the `PayRef` once-check, expiry, move, events); `MetaTransactionExecuted.digest = op_digest("pay_meta", args)`; new event `PaymentMeta { #[topic] pay_id, meta }`. | `soroban/contracts/token/src/lib.rs` | `soroban/contracts/token/src/test.rs`; `cd smartcontracts/soroban && cargo test` |
| Solana | instruction `relay_pay_meta(ctx: Context<RelayPay>, owner: [u8; 32], args: PayArgs, salt: [u8; 32], meta: Vec<u8>, auth: Auth)`: the same accounts and signed `MetaOp` as `relay_pay`; requires `args.pay_ref == metaPayId(salt, meta)`, `args.lane == payLane(args.pay_ref)`, `args.nonce == 0` (else `PayMetaShape`), then `relay_pay`'s body (one shared function, `settle`); events `MetaTransactionExecuted`, `PaymentMeta { contract: mint, pay_id, meta }`, `PaymentSettled`. The once-set is the payer's lane PDA `[b"lane", Account, lane]`, so per `(payer, payId)` (T11). A legacy transaction (1,232 B, one ed25519 entry) holds at most 168 B of `meta` (1,064 B + `meta`); the node's v1 transactions (4,096 B) hold the 2,048 B cap (adapter test). | `solana/programs/scaas/src/account.rs`, `lib.rs` | `solana/programs/scaas/tests/pay.rs`, `tests/vectors.rs`; `smartcontracts/scripts/test.sh solana` |
| Cosmos | `ExecuteMsg::RelayPayMeta { payload: Binary, auth: Auth, salt: HexBinary, meta: Binary }` on the token: `verify`, `op.op == "pay"`, `pay_ref == metaPayId`, `lane == payLane(pay_ref)`, `nonce == 0`, then `relay`'s pay arm; event `payment_meta` (`pay_id`, `meta` as hex) added before `payment_settled`. | `cosmos/token/src/lib.rs`, `cosmos/metaop/src/lib.rs` (the two hash helpers) | `cosmos/tests/tests/flows.rs`, `tests/vector.txt`; `cd smartcontracts/cosmos && cargo test` |
| Sui | `public fun relay_pay_meta<T>(account: &mut Account<T>, to: address, amount: u128, salt: vector<u8>, meta: vector<u8>, valid_until: u64, relayer: address, extra: vector<u8>, a: Auth, clock: &Clock, ctx: &mut TxContext)`: `pay_ref = meta_pay_id(salt, meta)` (`salt` 32 bytes, else `EBadField`), `lane = pay_lane(pay_ref)`, `nonce = 0` derived on chain, then `relay_pay`'s body (one private `settle`, shared with `relay_pay` and `pay_routed`); event `PaymentMeta { contract, pay_id, meta }` between `MetaTransactionExecuted` and `PaymentSettled`. The once-set is the payer's own `Account.lanes`, so per `(payer, payId)` (T13). Views `meta_pay_id`, `pay_lane`. | `move/sui/sources/meta.move` | `move/sui/tests/meta_tests.move`, `tests/vectors.move` (`scripts/gen_vectors.py`, which reads `paymeta.json`); `sui move test --path smartcontracts/move/sui` |
| Aptos | `package entry fun relay_pay_meta(lane: &signer, owner: address, asset: Object<Metadata>, to: address, amount: u128, salt: vector<u8>, meta: vector<u8>, valid_until: u64, relayer: address, extra: vector<u8>, public_key: vector<u8>, sig: vector<u8>, envelope: vector<u8>)`: `pay_ref = meta_pay_id(salt, meta)` (`salt` 32 bytes, else `EBAD_FIELD`), `lane = pay_lane(pay_ref)`, `nonce = 0` derived on chain, then `pay_checked` and `relay_pay`'s body (one private `settle`, shared with `relay_pay` and `pay_routed`, lazy Account open included); the view `pay_meta_check(lane: address, owner, asset, to, amount, salt, meta, valid_until, relayer, extra, public_key, sig, envelope): vector<u8>` (the twin of `pay_check`: the digest or the entry's abort code, no write; the node calls it instead of `simulate` while the payer's Account is not open); event `PaymentMeta { contract: asset, pay_id, meta }` between `MetaTransactionExecuted` and `PaymentSettled`. The once-set is the payer's own `Account.lanes`, so per `(payer, payId)` (T14). Views `meta_pay_id`, `pay_lane`. | `move/aptos/sources/meta.move`, `scripts/check_entry_visibility.sh` (the new entries listed) | `move/aptos/tests/meta_tests.move`, `tests/vectors.move` (`scripts/gen_vectors.py`, which reads `paymeta.json`); `smartcontracts/scripts/test.sh aptos` |
| TON (GRAM) | `SignedOp` with `OP_PAY` and `params` = `salt:uint256 ^meta` (`meta` as snake bytes); the payer's jetton wallet, when `params != null` on `OP_PAY`: `payRef == metaPayId(salt, meta)`, `lane == payLane(payRef)`, `nonce == 0`, and `meta` a plain snake (at most one ref per cell: `keccak256(Slice)` follows first refs only, so a second ref would ride into `PaymentMeta` unsigned; T16) (else `E_PARAMS` 713; a malformed `params` is exit 9), then emits `PaymentMeta { master, payId, meta: ^Cell }` (new external-out message, opcode `0x9b1c0d04`) right after `MetaTransactionExecuted` and pays as today. `params = null` keeps today's `OP_PAY`. The once-set is the payer's own wallet lanes, so per `(payer, payId)` (T15). Getters `get_meta_pay_id`, `get_pay_lane`. No contract cap: 38,100 B (300 snake cells) settles through a W5R1 lane in the sandbox, the 301st cell aborts the emulator; config param 43 bounds the external message at 65,535 B, depth 512 (measured, T15; the test asserts ≥ 4,192 B and runs the search only with `TON_META_SIZE_SEARCH=1`). | `ton/contracts/common.tact`, `jetton.tact` | `ton/tests/jetton.spec.ts`, `tests/vectors.spec.ts`, `vectors/ton-vectors.json`; `cd smartcontracts/ton && npm test` |

The mandate payments of each family (`pay_under_mandate`, `mandate_pay`, `MandatePay`) are not a payer's pay relay
and get no pay-meta entry, as the EVM wallets (§3.7).

## 7. CTR-MTX-27 on the split: `MtxRelayFee`

CTR-MTX-27's normative text is the spec; this section fixes only the build.

### 7.1 EVM (Hedera included)

- **Files:** `src/metatx/MtxRelayFee.sol` with two contracts: `MtxRelayFee` (the router) and `MtxRelayExecutor`
  (created by the router's constructor with CREATE; `ROUTER` immutable; `exec(target, callData)` callable only by
  the router; `target.call(callData)` with no value; a failure bubbles the inner revert data). The router exposes
  `EXECUTOR()`.
- **No token change and no library change.** The router calls the token's existing `mtxExecuteTransfer` /
  `uaExecuteTransfer`; under the split those run `preTransfer` like any other typed call. So the router does not
  depend on the split's internals and may be built in parallel once the split's ABI is fixed.
- **Steps:** exactly CTR-MTX-27's six. `ref` and `payLane(ref)` computed by the router (pure). Step 2 also refuses
  `t.to == EXECUTOR` (`RelayFeeShape`) and a target without code (`RelayTargetNoCode(target)`; T9 fix 1, controller
  call 2026-10-27). `nonReentrant` by a
  transient slot (no stored state). Open mode (`t.to == address(this)`; UA: `t.to == pad(address(this))`) forwards
  `t.value` with `IERC20(token).transfer(msg.sender, t.value)`.
- **Public balances only:** the router only ever calls the typed transfer paths, which move public (and UA-ledger)
  balances; on a PQZ or Zether token that is the public side.
- **Event:** `RelayFeePaid(bytes32 indexed ref, address indexed target, address indexed token, bytes32 payer,
  bytes32 payee, uint256 amount)`, `payee` an id like `payer` (T9 fix 1, controller call 2026-10-27).
- **Forge conformance:** CTR-MTX-27's list (nine items), plus: the executor refuses every caller but the router;
  the router holds no balance after a `relay` in open mode; a target that is a SCaaS token entry with its own
  envelope works when that envelope leaves the relayer open or binds it to the executor.
- **Gas** (CTR-MTX-27's estimate: ≈ +200–230k on Amsterdam with an ECDSA payer): measured in the plan, ECDSA and
  `mldsa65` payers.

### 7.2 The other families: one router each

The rule of CTR-MTX-27 holds on every family (the research note's §5 item 6): the payment's reference commits to
the call, and the payment is consumed only together with the call. What each family builds:

- **`ref`** `= keccak256("scaas.relayfee" ‖ chain ‖ target ‖ keccak256(call))`, with `chain` the network id the
  family's `MetaOp` domain already carries (Soroban the 32-byte network id, Solana `Config.network`, Cosmos the
  chain id's bytes, Sui / Aptos the root's `network` bytes, TON the global id as `int32`), `target` the family's
  address bytes, `call` the exact bytes the router has executed (the target's own signature included). Per-family
  vectors in each suite.
- **The payment** is the family's plain signed pay with `pay_ref = ref` and, where the family has lanes,
  `lane = payLane(ref)`, `nonce = 0`; no fee field exists off EVM, so the pay's `amount` is the fee.
- **The router marker.** Every family's pay already checks `relayer == 0 || relayer == the submitting lane`. The
  payment names as relayer an address that no transaction can sign for (a PDA, a derived object address, a contract
  address), so only the router's own code path can spend it. Where the family's auth is invocation-scoped (Soroban)
  the auth entry's root is the router call itself.
- **The executor.** Where a router-sent call reaches a target as the router (`msg.sender`-like), a call that is a
  token's relay of another router-bound payment would see its bound relayer; there the family needs an executor or
  a refusal, as on EVM. Per family below.
- **Open mode is the client default** (the submitting lane is paid); a bound payee where the family's shape allows
  it. **No PQ signatures off EVM** (§1 non-goals). **No budget mode** (owner 2026-10-26).
- Event `RelayFeePaid(ref, target, token, payer, payee, amount)` in the family's event form, `payer` and `payee` as
  the family's native id form, lossless (EVM `bytes32`; each family row below names its form, e.g. Soroban `Address`
  values, Cosmos bech32; controller call 2026-10-27, wording fixed by final review M10).
- **The target exists** at relay time (CTR-MTX-27's ninth item): the router refuses a target that is not deployed code,
  an executable program or an instantiated contract, so a counterfactual target cannot burn the payment. Each row's
  router checks it in the family's terms.

| Family | Router (from the family's current code) | Executor / re-entry | Tests |
|---|---|---|---|
| Soroban | New contract `contracts/relay-fee`: `relay(env, payer: Address, target: Address, func: Symbol, args: Vec<Val>, salt: BytesN<32>, token: Address, to: Address, amount: i128, valid_until: u64, relayer: Address)`. `payer.require_auth_for_args((target, func, args, salt, token, to, amount, valid_until))` (the payer's auth entry is rooted at this router call, with the token's `pay` as its sub-invocation, so the payment authorises nothing else); `relayer.require_auth()`, which the transaction source does **not** satisfy implicitly: the node adds an explicit `SourceAccount` auth entry rooted at the same call. `ref = keccak256("scaas.relayfee" ‖ network id (32) ‖ xdr(target Address) ‖ keccak256(xdr((func, args))) ‖ salt (32))`, the payer-signed `salt` making two identical calls distinct (Soroban's target auth lives in auth entries, not in `args`). `env.invoke_contract(target, func, args)`, then `token.pay(payer, to, amount, ref, valid_until)`; in open mode (`to == router`, the payer cannot name the relayer when signing) the router receives the payment and then `token.transfer(router, relayer, amount)`; bound payee: `to` receives it directly. The token's `PayRef` set is per `(from, pay_ref)`, so nobody can pre-burn a payer's `ref` (controller call 2026-10-27, owner may override). `RelayFeePaid` topics `ref, target, token`, data `payer, payee, amount` with `Address` values (the family's native form). ~~Stateless.~~ **Change note (controller ruling 2026-10-31 after the UA-Soroban T8 review; owner split it out and merged it early, 2026-10-31):** not stateless. The target call is `executor.exec(target, func, args)` on the new contract `contracts/relay-executor`, never `env.invoke_contract(target, …)` as the router: Soroban grants a contract's authority to every contract it calls directly, so the target saw `router.require_auth()` satisfied and a target `token.transfer(router, attacker, n)` drained any router balance (e.g. a victim's signed plain `pay` to the router used as the target of an attacker's open-mode `relay`; CTR-MTX-13 / CTR-MTX-27 broken). The router stores its executor (`__constructor(executor)`, checked `executor.router() == self`, else `BadExecutor`); the executor's constructor names the router; a payee equal to the router or the executor is `BadPayee`; `deploy.sh soroban <net> relay_fee` derives the router id from a salt and deploys the executor, then the router. | ~~None needed: Soroban refuses contract re-entry, and another payment's auth entry is rooted at its own router call.~~ **Change note (2026-10-31, same ruling):** `contracts/relay-executor`: `exec` accepts only its router (`router.require_auth()`, satisfied only by the router as direct invoker) and holds nothing; the target sees the executor as its invoker (EVM executor parity). Re-entry stays refused by Soroban. | `contracts/relay-fee/src/test.rs` (target: the mandate's signed revoke, a fee-less entry; a G-account payer with real signed entries); `cd smartcontracts/soroban && cargo test` |
| Solana | **Static wrappers for `scaas`'s own fee-less signed entries** (owner 2026-10-27, as Sui / Aptos): `relay_fee_manage_signed`, `relay_fee_mandate_open`, `relay_fee_mandate_revoke_signed`, `relay_fee_mandate_close_signed`, `relay_fee_cancel_signed`, `relay_fee_invalidate_nonces_signed`. Each takes the entry's arguments first (its `auth` included), then `owner: [u8; 32], args: PayArgs, pay_auth: Auth`; accounts = the entry's struct, then `relay_pay`'s (`RelayPay` derives its PDAs in the body, so it nests beside any entry's struct), then the entry's remaining accounts (mandate close quads). It runs the entry's body in-process (no CPI), then the router payment (`pay_routed`: `relay_pay`'s body, relayer = marker, open mode pays the lane, `RelayFeePaid { target: scaas }`). `ref = keccak256("scaas.relayfee" ‖ Config.network ‖ scaas program id ‖ keccak256(call) ‖ args.extra)`, `call = scaas (32) ‖ u8 n ‖ (pubkey ‖ is_signer ‖ is_writable)×n ‖ data` with the entry's **declared** accounts (`accounts::<Entry>::to_account_metas`; mandate close quads as writable, readonly, writable, readonly) and the router marker in the lane slot (`accounts[0]`, flags as declared): the wrapper ref hashes the router marker in the lane slot (lane-agnostic, as Sui/Aptos), so the payer signs before any lane is known and any lane may submit (T11 fix 3, controller call 2026-10-27, owner may override) and `data = discriminator("global:<entry>") ‖ Borsh(arguments)`: the entry's instruction as if sent alone. The node sends `[advance nonce, payer precompile (1), the entry's signature precompile (2), wrapper]`. Not wrapped: `open_passkey` (a scope choice: account creation is not among the entries Sui / Aptos wrap; controller call 2026-10-27, owner may override), `settle` (a two-party trade with its own market fee), the pay entries themselves. **Generic `relay_fee` for external programs**: `relay_fee(ctx: Context<RelayFee>, owner: [u8; 32], args: PayArgs, target_data: Vec<u8>, target_accounts: u8, auth: Auth)` in the `scaas` program (no second program); `RelayFee { pay: RelayPay }` (the same accounts; `recipient` is checked in the shared body: `args.to`, or the lane in open mode). `remaining_accounts[0]` = target program, `[1..=n]` its accounts with their flags, exactly `n = target_accounts`. `call = target program (32) ‖ u8 n ‖ for each account (pubkey (32) ‖ is_signer (1) ‖ is_writable (1)) ‖ data` (the count makes the account list and the data unambiguous); `ref = keccak256("scaas.relayfee" ‖ Config.network (32) ‖ target program (32) ‖ keccak256(call) ‖ salt (32))` with `salt = args.extra`, the `MetaOp`'s payer-signed `extra` (a target's own authorisation lives outside its data, e.g. in a precompile instruction, so the call bytes alone are not unique; T11, controller call 2026-10-27, owner may override). Shape, else `RelayFeeShape`: `pay_ref == ref`, `lane == payLane(ref)`, `nonce == 0`, `relayer == marker`, target `!= scaas`, **no target account is a signer** (`invoke` forwards the outer transaction's signer privileges, so a flagged account would lend the relayer's or a co-signer's signature to the payer's call; checked on chain before the CPI, T11 fix 1, controller call 2026-10-27, owner may override); then the target must be executable, else `RelayTargetNoCode`. Marker: the PDA `[b"relayfee"]` of `scaas` (`relay_pay`'s `relayer == lane` check already refuses it, a PDA never signs a transaction; the program never signs with it and never pays it). `invoke` the target with the accounts' own flags (no PDA signs), then `relay_pay`'s body with the relayer checked against the marker; open mode (`args.to == marker`) pays the lane signer's ATA directly, `PaymentSettled.to` and `RelayFeePaid.payee` name the lane. Event `RelayFeePaid { contract: mint, relay_ref, target, payer, payee, amount }`, `payer` (the owner key) and `payee` 32-byte keys. The precompile check reads the instructions sysvar as today (the signature instruction is top-level). The pay lane is the payer's (its lane PDA), so nobody pre-burns a payer's `ref`. | None needed (no PDA signs the CPI, the target sees only the outer transaction's signers). Target program `== scaas` refused (`RelayFeeShape`); indirect re-entry (scaas → X → scaas) is refused by the runtime (`ReentrancyNotAllowed`). Target accounts are never signers (refused on chain, `RelayFeeShape`); the node also refuses them, and the lane as a target account, before simulating. | new `programs/scaas/tests/relay_fee.rs` with a test-only target program next to `cpi_wrapper`; `smartcontracts/scripts/test.sh solana` |
| Cosmos | New contracts `cosmos/relayfee` (router) and `cosmos/relayexec` (executor). Router `Relay { target, msg: Binary, token, payload: Binary, auth: Auth }`: parse the `MetaOp` (`scaas_metaop`), shape (`op == "pay"`, `pay_ref == ref`, `lane == payLane(ref)`, `nonce == 0`, `relayer == router`), then messages in order: executor `Exec { target, msg }`, token `Relay { payload, auth }`, and in open mode (`op.to == router`) token `Transfer { recipient: info.sender, amount }`; CosmWasm runs them depth-first and reverts all on any failure. `ref = keccak256("scaas.relayfee" ‖ chain id ‖ target (canonical address bytes) ‖ keccak256(msg))`, no salt (the target sees the executor and no funds, so its authorisation is inside `msg`; T12, controller call 2026-10-27, owner may override). Before any message: the router has no admin (its own `ContractInfo.admin` is `None`, else `relayfee: the router has an admin`: a migrated router could settle its bound payments without the call, CTR-MTX-13; deploy with `--no-admin`, clients check `ContractInfo.admin == None` before signing `relayer = router`; T12 fix 1), `op.to != executor`, no funds, and the target has contract info (else `relayfee: target is not an instantiated contract`). The router instantiates its executor (`Instantiate2`, fixed salt `scaas.relayexec`, code id in its `InstantiateMsg`; the address from `instantiate2_address`), its one stored item besides the re-entry flag. `relay_fee_paid` attributes `ref, target, token, payer, payee, amount` (bech32). | `relayexec` accepts `Exec` only from its router, refuses funds and forwards with no funds: the target sees the executor, never the router (the EVM reason applies: the token's `Relay` checks `relayer == info.sender`). CosmWasm allows re-entry, so the router sets a flag in `Relay` and clears it in the reply of its last message: a target calling `Relay` back fails. | `cosmos/tests/tests/flows.rs` (cw-multi-test); `cd smartcontracts/cosmos && cargo test` |
| Sui | New module `scaas::relayfee` (T13). Move has no dynamic call, so the router wraps each fee-less signed entry of the `scaas` package by name: `relay_manage<T>` (`meta::manage`), `relay_revoke_with_sig<T, P>` (`mandate::revoke_with_sig`), `relay_cancel<X>` (`dex::cancel`; a `false` result aborts with `ECallRefused`, so nothing is paid for a refused cancel) and `relay_invalidate_nonces<X>` (`dex::invalidate_nonces`). Each takes `&RelayFee`, the entry's arguments in order (its `Auth` included), then the payment's `to, amount, valid_until, extra, Auth`, the clock and the context; manage / cancel / invalidate pay from the account the entry names (one `&mut` per object in a PTB command, so the payer is that account's owner, in its coin), revoke from any `Account<P>`. It runs the entry, then `meta::pay_routed` (new, `public(package)`, called only by `relayfee`): `relay_pay`'s body with `pay_ref = ref`, `lane = pay_lane(ref)`, `nonce = 0` and `relayer = marker` fixed on chain, so the payer's signature verifies only for a payment signed for exactly this call through the router (no separate shape error). `ref = keccak256("scaas.relayfee" ‖ network ‖ package ‖ keccak256(call) ‖ salt)`: `network` the paying account's network bytes (the root's), `package` = `type_name::original_id<RelayFee>()` (32 bytes; `0x0` under `sui move test`), `call` = BCS of the entry's name as `vector<u8>` (`b"meta::manage"`, `b"mandate::revoke_with_sig"`, `b"dex::cancel"`, `b"dex::invalidate_nonces"`) followed by the BCS of every argument in order (an object as its id address; `dex::cancel`'s `Order` as its full BCS, domain included; the entry's `Auth` as `sig ‖ authenticator_data ‖ client_data_json`, each a `vector<u8>`), `salt` = the payment's `extra` (32 bytes, payer-signed), which makes two relays of an idempotent call (a repeated `revoke_with_sig`) distinct payments. No sender and no lane in `ref`: any relayer may submit (controller call 2026-10-27, owner may override). Marker: the address of the shared `RelayFee` object, created once in `init` (no transaction sender is an object, so `relay_pay` / `relay_pay_meta` refuse a router-bound payment with `EWrongRelayer`). Open mode (`to == marker`) pays `ctx.sender()`; the marker is never paid. `RelayFeePaid { ref, target: package, token: Registry id, payer, payee, amount }` with Sui addresses. The target exists statically (the wrappers call named entries on objects the transaction passes). **Upgrade authority** (T13, rule 10): `relayfee` is a module of the `scaas` package, so it cannot be upgraded apart from the token: whoever holds the package's `UpgradeCap` can change both, and the router's trust equals the token's. NET-SUI-15 specifies an immutable package (`make_immutable` in the deploy run); owner ruling 2026-10-28: `smartcontracts/scripts/deploy.sh sui` now destroys the `UpgradeCap` in the publish run. A new target is a new wrapper in a new package version (under NET-SUI-15: a new package). The `RelayFee` marker exists only if `relayfee` is in the package's first publish (Sui runs no `init` for a module added by an upgrade). For `relay_manage` / `relay_cancel` / `relay_invalidate_nonces` the payer is the call's own account; a sponsor paying for them needs `_from` variants (not built; T13 fix 1, controller call 2026-10-27, owner may override). | None needed: no dynamic dispatch; `pay_routed` is package-only and called only by `relayfee`. | `move/sui/tests/relayfee_tests.move`; `sui move test --path smartcontracts/move/sui` |
| Aptos | New module `scaas::relayfee` (T14), the same static shape as Sui: one `package entry fun relay_<entry>` per fee-less signed entry: `relay_manage_signed` (`meta::manage_signed`), `relay_mandate_open` (`mandate::open`), `relay_revoke_signed` (`mandate::revoke_signed`), `relay_cancel_signed` (`dex::cancel_signed`, through the new `package fun dex::cancel(…): bool`; `false`, an order already closed, aborts with `relayfee::ECALL_REFUSED`, so nothing is paid for a cancel that changed nothing) and `relay_invalidate_nonces_signed` (`dex::invalidate_nonces_signed`). Each takes `lane: &signer`, the entry's arguments in order (its `public_key, sig, envelope` included), then the payment's `payer, asset, to, amount, pay_valid_until, extra, pay_key, pay_sig, pay_envelope`; it runs the entry, then `meta::pay_routed` (`package`, called only by `relayfee`): `relay_pay`'s body with `pay_ref = ref`, `lane = pay_lane(ref)`, `nonce = 0` and `relayer = marker` fixed on chain (the relayer is checked against the marker instead of the lane), so the payer's signature verifies only for a payment signed for exactly this call through the router. `ref = keccak256("scaas.relayfee" ‖ chain_id (1 byte, the `MetaOp` domain's `chain_id::get()`; Aptos has no network bytes) ‖ @scaas (32) ‖ keccak256(call) ‖ salt (32))`, `call` = BCS of the entry's name as `vector<u8>` (`b"meta::manage_signed"`, `b"mandate::open"`, `b"mandate::revoke_signed"`, `b"dex::cancel_signed"`, `b"dex::invalidate_nonces_signed"`) followed by the BCS of every argument in order (the lane signer excluded, the entry's signature included), `salt` = the payment's payer-signed `extra`. Each argument's BCS is also its entry-function argument, so the node forwards exactly the bytes `ref` commits to. No sender and no lane in `ref`: any relayer may submit. Marker `object::create_object_address(&@scaas, b"scaas.relayfee")` (`relayfee::marker()`): no transaction sender is an object address, so `relay_pay` / `relay_pay_meta` refuse a router-bound payment (`EWRONG_RELAYER`); stateless (no `init_module`, nothing stored), so the module also works when added by an upgrade. Open mode (`to == marker`) pays `signer::address_of(lane)`; the marker is never paid. The payer is any Account (the call's signer or another owner): resources are reached by address, so Aptos has no Sui-style one-account limit. `RelayFeePaid { ref, target: @scaas, token: asset, payer, payee, amount }` with Aptos addresses. The target exists statically (named entries of this package). **Upgrade authority** (T14, rule 10): `relayfee` is a module of the `scaas` package, so the code object's owner (`aptos move deploy-object`; production: a multisig) can upgrade it together with `meta`, never apart; the router's trust equals the token's. NET-APT-20 specifies `upgrade_policy = "immutable"`; as built `Move.toml` says `compatible`, so the code-object owner can upgrade both. Node: a relay-fee job is refused while the payer's Account is not open (no view runs the wrapped call, and `simulate` hangs on a payment that opens the Account; aptos-node 9.6.0). | As Sui: no dynamic dispatch; `pay_routed` is `package` and called only by `relayfee`; `check_entry_visibility.sh` proves no other module can call the wrappers, `relay_pay_meta` or `pay_routed`. | `move/aptos/tests/relayfee_tests.move`; `smartcontracts/scripts/test.sh aptos` |
| TON (GRAM) | **Escrow, released only on a positive acknowledgment from a known SCaaS target** (no cross-contract atomicity, owner 2026-10-26; as built T16 + fix 1, controller call 2026-10-28 on the owner's "choose the best option"): `ScaasRelayFee` (`relayfee.tact`; no admin and no upgrade path, its code is fixed at deploy) and a one-shot `RelayExecutor` per (router, payer, salt). **Served targets and entries** (TON cannot read an arbitrary target's result, so the scope is the static wrappers' of the other families): the code set compiled into the router = the SCaaS jetton wallet and the Mandate; served fee-less entries = the wallet's `SignedOp` `set_key` / `revoke`, the Mandate's owner `revoke`. Each sends `RelayAck { digest }` (`0x5b0a1d35`, the MetaOp it executed) to its sender just before its own outgoing message (the excess, or a revoke's cancel transfer to the DEX, whose excess comes back later along the DEX path); a failed action phase sends no message at all, so the ack proves compute and action ran. A signed revoke runs at most once in either form (both leave its lane at `nonce + 2`, NET-TON-18; T16 fix 2), so a replayed revoke bounces and is refunded. **(1) Call.** The relayer sends `RelayCall { target, targetInit: StateInit, call: ^Cell, salt: uint256, payWallet, payOp: ^Cell, payAuth: ^Cell, payStateInit: ^Cell?, master, deadline: uint32 }` (`0x5b0a1d30`). The router recomputes `ref = keccak256("scaas.relayfee" ‖ global id:int32 ‖ target workchain:int8 ‖ target hash:uint256 ‖ cellHash(call) ‖ salt)` (`call` by its representation hash, every ref; `salt` the payer's, signed through `payRef`; no sender, no lane) and checks, else exit 741: the pay `MetaOp` (`op == OP_PAY`, `payRef == ref`, `lane == payLane(ref)`, `nonce == 0`, `relayer == to == router`, `amount > 0`), `payWallet == walletAddress(from, master)`, `contractAddress(targetInit) == target` with its code hash in the set, and `call` a `SignedOp` of a served entry whose `responseDestination` is `get_executor(from, salt)` (so the call's TON comes back to the relayer, and a copied `ref` cannot be relayed by another payer); a `SignedOp` naming the router is 707 (R18). `now < deadline ≤ now + RELAY_TIMEOUT` (**3,600 s**), else 743; no escrow for `(from, ref)` and no payment of `payWallet` in flight, else 742; TON ≥ `get_relay_value(body)`, else 714. It keeps the escrow's rent (`getStorageFee` over 3,600 s), stores the unfunded escrow under `cellHash(from ‖ ref)`, marks `payWallet` busy, and sends the payer's wallet the `SignedOp` (`params = null`, bounceable, `responseDestination` = the relayer, `forwardTon` = the executor's budget). **Pricing:** every TON amount comes from the config at the time: compute fees by `getComputeFee` of fixed gas units (×2 the measured use), forward fees by `getForwardFee` of each message's measured size (`computeDataSize`), the router's rent by `getStorageFee`; the call carries `callMin = max(config param 21's gas_limit priced + its bounce, the served entry's own floor: the wallet's `MIN_SIGNED_OP_TON` + the call's `forwardTon`, the Mandate's 0.1 TON)`, so a failed call can always bounce; the jetton wallet's own floors (`MIN_SIGNED_OP_TON`, `MIN_TRANSFER_TON`) are added where its steps are paid. **(2) Payment.** Its bounce drops the unfunded escrow (attributed by the busy wallet), emits `RelayFeeRefunded { ref, payer, relayer, amount: 0 }` and returns the TON to the relayer. Otherwise the router's own jetton wallet notifies it (`sender == walletAddress(router, master)`, `pay_tag ref`, the signed amount): funded; the router deploys the executor with `RelayExec { ref, target, call, relayer, callMin, keep }`. Any other notification is handed back by a `JettonTransfer` to the notifying wallet. **(3) Outcome.** The executor sends `call` (≥ `callMin`, forward fees paid apart) and right after it `RelayProbe { queryId = lt }` (`0x5b0a1d32`), both bounceable. TON delivers one account pair's messages in order: the ack (in the call's transaction) arrives before the probe's bounce (a later one). Probe bounce after an ack → `RelayOutcome { ok: true }` → release to the relayer, `RelayFeePaid` (`0x9b1c0d05`); probe bounce without an ack, or the call's bounce (also: no account at `target`) → `ok: false` → refund, `RelayFeeRefunded` (`0x9b1c0d06`, naming the escrow's relayer). TON that reaches the executor after its report (a revoke-cancel's excess) goes on to the relayer (`RelayExec` names it). Out of gas, an action failure, anything unproven: no ack → refund. **(4) Timeout and settlement.** No outcome: anyone's `RelayRefund { from, ref }` (`0x5b0a1d31`, ≥ `get_refund_value`, else 714) at or after `deadline` refunds a funded escrow or drops an unfunded one (745 before, 744 unknown). Each settlement transfer carries a `queryId` (the ring keeps the escrow without its `call`); if the router's wallet bounces it, the escrow comes back as release-owed / refund-owed and any `RelayRefund` sends it again at any time. Release and refund are exclusive (the escrow leaves the map first); a late report pays nothing; the router holds no jetton after settlement and keeps its own TON (every handler reserves the router's prior balance). Open mode only. Getters `get_relay_ref`, `get_executor(from, salt)`, `get_pending(from, ref)`, `get_escrow_state(key)` (0 none, 1 paying, 2 funded, 3 release owed, 4 refund owed), `get_relay_value(body)`, `get_refund_value`, `get_codes`. **Success means** the target's handling transaction was acknowledged; the messages it sends on (a revoke's cancel to the DEX) are not covered. | `RelayExecutor`: the target sees it, never the router (a call to one of the router's own jetton wallets would fail their owner check anyway); it holds nothing, only its router starts it, once. `RelayCall` refuses a `call` that is a `SignedOp` naming the router (R18). | `ton/tests/relayfee.spec.ts` (sandbox; `tests/contracts/actfail.tact`, a test-only target that acks then fails its action phase), `tests/vectors.spec.ts` (`relay_fee` vectors); `cd smartcontracts/ton && npm test` |

What the TON escrow does not give (recorded, controller call): an outcome later than `deadline` is refunded: the
payer is not charged and the relayer loses its gas (the call may have run); never the reverse. Arbitrary targets are not
served on TON. A relay ties up `get_relay_value` of the relayer's TON (0.167 TON at the sandbox config), returned less
the fees (≈ 0.025 TON over 16 transactions, measured T16 fix 1); the node prices it (§9, `min_ton_value`).

## 8. Scope and staging

**This work item: every family** (owner 2026-10-27, §0): EVM (Hedera included, because Hedera runs the EVM
contracts), Soroban, Solana, Cosmos, Sui, Aptos and GRAM (TON). EVM comes first because the other families mirror
its semantics (§6.2, §7.2): the `payId` derivation, its vectors and the `ref` rule are fixed by the EVM parts and only
then copied.

| Part | Content | Gate |
|---|---|---|
| 0 | On `main`, before any change: the parity fixture and gas baseline (R1) | forge |
| 1 | The split: `MtxPipelineLib`, `MetaTxBase` / `ERC20MetaTx` / `MetaTokenBase`, `DeployBase`, e2e.py (link closure, §11.1), fixtures, tests R2–R8 | forge at the committed set, sizes, `docs_check` |
| 2 | `mtxPayMeta` / `uaPayMeta`, the shared vectors | forge, sizes |
| 3 | Re-measure §5.3 with the final bytecode; re-pin `debit_min_gas` (and so `UARegistry`), `ROLL_MAX` if the rule says so, the prover rows, the node floor | the affected steps only (owner 2026-10-27): forge at all four sets (`at-set.sh`), `gen_set.py --all --check`, sizes, zether-prover cargo |
| 4 | `MtxRelayFee` + executor, `DeployBase`, conformance | forge |
| 5 | Soroban, Solana, Cosmos, Sui, Aptos, TON: each family's pay-meta entry (§6.2), router (§7.2) and node adapter, one part per family, in that order (the Rust-hosted families first, then Move, then the TON escrow, the largest) | that family's suite (`smartcontracts/scripts/test.sh <family>`) and `scaas-node` adapter tests |
| 6 | Node and clients for EVM (§9) | `scaas-node` tests, `clientkeys` tests |
| 7 | Docs and decisions (§11), the four gaps (§11.1), review, fix round, the closing gates of every family | `docs_check`, the resumable gate runner |

Each part ends on the branch; merge and push only on the owner's go. The superseded pipeline code (`_checkCall`,
`_callFee`, `_checkTransfer`, `_checkUATransfer`, `_uaAuthorize`, the Hedera overrides as they are today) goes to
`smartcontracts/evm/legacy/metatx-v1/` as a backup, not deleted. No non-EVM code is superseded (only added).

**NEAR and Algorand** (owner 2026-10-27): PLANNED in `docs/networks/README.md`, no code yet. They are built right
after this item, as their own family bring-up item (family spec → plan → build), and they carry CTR-MTX-26
(`mtxPayMeta` / `uaPayMeta`) and CTR-MTX-27 (`MtxRelayFee`) from the start, with the semantics this item fixes for
EVM and the other families.

What that bring-up must decide for CTR-MTX-26 / -27 (no design here): **NEAR** — the token form (NEP-141 with a
SCaaS signed-op path), who stakes storage for the once-per-`payId` record and for the router's state, and the
router's shape over NEAR's asynchronous cross-contract calls (a promise chain with a callback, or an escrow as on
TON). **Algorand** — the token form (ASA or ARC-200), where the once-per-`payId` record lives (boxes, and who funds
their minimum balance), and the router's shape (an atomic transaction group or an inner-transaction app call).

## 9. Node and clients

**For the split:**
- `scaas-node`: selectors, the allowlist views, `supportedModes`, events and digests are unchanged, so `guard.rs`'s
  allowlist check, `metatx.rs` and the indexer need no change. Gas comes from simulation (+20 %, capped), so it
  follows. One constant changes: `guard::ERC1271_FLOOR` (432,349 = 21,000 + 400,000 · 64/63 + 5,000) assumes the
  ERC-1271 call is one frame below the token; it is now two (token → library → wallet). New floor:
  `21,000 + (400,000 · 64/63 + 5,000) · 64/63 +` the measured prefix ≈ 440–450k [estimate], pinned by a node test
  against forge's measured minimum gas for a `SmartKeyAccount`-signed `mtxExecute`.
- `clients/zether-prover`: re-measured relayed rows if they move (§5.3 item 6). `uaSigner` / `ua_signer_gas`
  unchanged: the signer's verify cost is the same, and the library overhead is inside the relayed rows that
  `uaExecute` builds on.
- `clients/clientkeys` and the `ua-*` clients: no change (ABI and digests unchanged); their envelope vectors re-run.

**For CTR-MTX-26:**
- `clientkeys`: `metaPayId(salt, meta)`; build `mtxPayMeta` / `uaPayMeta` (and the off-chain variant); decode and
  show `meta` next to the typed data; refuse to sign when `entryRef != metaPayId(salt, meta)`; the shared vectors.
- `scaas-node`: a pay job may carry `(salt, meta)`. The node checks `t.entryRef == metaPayId(salt, meta)`,
  `t.batch == payLane(t.entryRef)`, `t.nonce == 0` before simulating, and submits `mtxPayMeta` / `uaPayMeta` (on-chain
  meta) or `mtxExecuteTransfer` (off-chain meta). Policy cap on `meta` length (config `max_pay_meta_bytes`, default
  2,048: controller call). The indexer decodes `PaymentMeta` and joins it to `PaymentSettled` / `UAPaymentSettled` by
  `entry_ref`.
- Connectors (the ERP side, integration docs): show and verify the meta; a later client item.

**For CTR-MTX-27:**
- `scaas-node`: a call-table row for `MtxRelayFee.relay` / `uaRelay` with a new rule: the target is the chain's
  `mtx_relay_fee` address; `token` is a registered token; the inner `target` is bound to this chain (`chainUid()`).
  Quote `(token, amount, validUntil)`; simulate the whole `relay`; submit only if the fee covers the gas at the
  node's price (no price or limit assumed). New NODE-LANE rules next to the simulation step. The lane's own token
  balance is safe: the inner call's `msg.sender` is the executor.
- Clients: `clientkeys` (the signer) builds the call with its own signature, `ref = relayRef(target, callData)`, the
  payment (open mode by default), one prompt with both intents. If the inner call is itself an mtx envelope with
  `MODE_RESTRICT_RELAYER`, its relayer must be the executor's address (or left open). `clients/ua-rs` and `ua-qt`
  provide the hashes (`meta_pay_id`, `pay_lane`, `relay_ref`) and reproduce the vectors; they build no payment or
  prompt (T18 fix 1, controller call 2026-10-28, owner may override).

**For the other families** (`scaas-node/src/adapters/<family>.rs`, the `signed_op` jobs):
- A pay job of every family may carry `(salt, meta)`. The adapter checks `pay_ref == metaPayId(salt, meta)` and, where
  the family has lanes, `lane == payLane(pay_ref)`, `nonce == 0`, then builds the family's pay-meta call (§6.2)
  instead of its plain pay; the same `max_pay_meta_bytes` cap. Each family's indexer decodes `PaymentMeta` and joins
  it by `pay_ref`.
- A relay-fee job builds the family's router call (§7.2) with the target call the client sent; the adapter checks
  `ref` against the call bytes and the router marker as relayer before simulating, and submits only when the fee
  covers the gas at the node's price. TON: the fee must be worth the TON the relay puts at risk (`get_relay_value` of
  the body) at the node's floor price `params.relay_fee.min_ton_value = { "<master>" = nanoton per base unit }` (no
  price feed exists; a master without one gets no relay-fee job); the adapter tracks the escrow (`pending` → funded →
  released / refunded, identified by the router's `RelayFeePaid` naming the lane as payee / `RelayFeeRefunded` naming it as relayer, a release winning over a refund; never by absence, never by another relayer's event) and sends
  `RelayRefund` after `deadline` (or at once for a settlement owed after a bounce).
- `clients/clientkeys` builds and signs EVM envelopes only today (`src/evm.js`); a non-EVM subject signs its op in
  its own family wallet, so the non-EVM side of `clientkeys` is the shared vectors only.

## 10. Risks and how each is tested

| # | Risk | Test |
|---|---|---|
| R1 | Behaviour drift between today's pipeline and the split | **Parity fixture** (controller call): in Part 0, on `main`, a forge test runs a fixed case set on every kind (clones) — every signed entry point × address / UA path × success and each error, incl. batches, receiver-pays, trade, PQZ / Zether relayed ops at the committed set — and writes outcome, return data, revert data, events, nonces, balances (`SHIELD_POOL`, `UA_POOL` included) and gas to `test/vectors/metatx-parity.json`. After the split the same test replays and compares. The only allowed difference is §3.8, listed case by case in the fixture. |
| R2 | The context the library gets differs from the token's immutables (the spike's "module immutables" risk) | `_mtxCtx()` is the only builder. Per kind, on a clone: every `Ctx` field equals the token's own view (`eip712Domain()` → separator, `registry()`, the clone hash of `SMART_KEY_ACCOUNT_IMPL`, `IS_HEDERA`); `callDigest` / `transferDigest` equal `mtxDigest` / `uaDigest` / `mtxTransferDigest` / `uaTransferDigest` and the existing off-chain envelope vectors (clientkeys, zether-prover). |
| R3 | A rule table copied out of the kinds (the spike's A2 risk) | Not possible by design: the token passes the looked-up rule per call. The existing `test_allowlistPinned*` tests and R1's per-selector cases cover every selector of every kind. |
| R4 | ABI artifacts: errors raised only inside the library vanish from the token ABI (e.g. `SigCheckGasStarved`, `ModeFeeInvalid`, `FeeRecipientRequired`, `HtsQueryFailed`) | Extend `test_libraryErrorsAreInTheTokenAbi` (`test/v2/Wrapped.t.sol`) to `MtxPipelineLib` × every kind's artifact; declare a missing error on a token interface. Function and event selectors unchanged: R1. |
| R5 | A library in the release's link closure is not pinned | A forge test reads each kind's artifact `linkReferences` recursively and asserts the `Env.libs` built by `DeployBase` (and the PQZ envs of e2e.py, through a small Python self-test) equal the closure. |
| R6 | SELFDESTRUCT, CALLCODE or a DELEGATECALL to a non-named address in a linked library; a direct CALL that writes the library's own storage | An opcode walk (PUSH data skipped) over the runtime code of every library in every closure: no `SELFDESTRUCT`, no `CALLCODE`; `DELEGATECALL` only in `MtxPipelineLib` toward `HederaLib`. A direct CALL of `preCall` / `preTransfer` reverts (solc's library call guard). |
| R7 | The library writes more storage than the nonce | `vm.record` / `vm.accesses` around a relayed call of each path: written slots equal R1's recorded set. |
| R8 | The extra frame starves the ERC-1271 or UA-registry call (63/64 rule) | Minimum working gas for a `SmartKeyAccount`-signed `mtxExecute` and an `mldsa65` `uaExecute`; the SigCheck starvation check still fires against a relayer that under-funds (the CTR-DEX-08 tests on the token path); the node floor test (§9). |
| R9 | The data-size residual is larger than estimated | §5.2 bound, measured. |
| R10 | Thin margins and the constants that follow | §5.3 items 2–7, asserted at the four sets. |
| R11 | Stack too deep in `mtxPayMeta` / `uaPayMeta` | Builds with `via_ir` off; the R1-style cases for both. |
| R12 | Hedera: the HIP-632 branch now runs one frame deeper | The `IS_HEDERA` fixtures' tests pass unchanged; the HIP-632 system call still sees the token as caller. |
| R13 | The wallets' pipeline drifts from the tokens' | Both compose the same internal functions; the wallets' own suites (`SmartKeyAccount.t.sol`, `MandateWallet.t.sol`) unchanged and passing; R1 covers the tokens. |
| R14 | The router: a `callData` that executes another router-bound payment, a fake token, re-entry | CTR-MTX-27's conformance list (§7). |
| R15 | Storage layout drift | `test/v2/Layout.t.sol` unchanged and passing (the library declares no state variables). |
| R16 | A family hashes `payId`, `payLane` or `ref` differently from EVM | Every family's suite reads `paymeta.json` (and its own `ref` vectors, generated by the EVM-side generator for the EVM rows and by the family's generator for its own encoding) and asserts byte equality. |
| R17 | A non-EVM payment bound to the router is spent outside it | Per family: the plain pay entry refuses an op whose relayer is the router marker (Solana PDA, Sui object, Aptos object address, Cosmos router, TON router); Soroban: the payment's auth entry, rooted at the router call, does not satisfy a direct `pay`. |
| R18 | Cosmos / TON: the target sees the router as its relayer | Cosmos: `relayexec` is the sender the target sees; a `callData` that is a token `Relay` of another router-bound payment fails. TON: `RelayCall` refuses a `call` that is a `SignedOp` naming the router. |
| R19 | TON escrow: funds stuck or paid twice | Sandbox cases: release on the probe's bounce; refund on the call's bounce and on a target with no account; refund by `RelayRefund` after `deadline`, refused before; a second `RelayCall` for a pending `(payer, ref)` refused, another payer not blocked; the payment's own bounce clears the escrow; release and refund are mutually exclusive; the router holds nothing after settlement. |

## 11. Docs and records to update (Part 7)

- `decisions.md`: CTR-MTX-07 Change (the tree plus `MtxPipelineLib`, variant A, owner 2026-10-20 / 2026-10-21, the
  boundary of §3.1, status and commits); CTR-MTX-17 Change (§3.8, owner 2026-10-27); CTR-MTX-26 and CTR-MTX-27 Change
  lines (built on every family, with the per-family shape of §6.2 / §7.2 and the owner answer of 2026-10-27);
  NET-EVM-06 addendum figures; CTR-PQZ-07 Change if `ROLL_MAX` moves; the `debit_min_gas` re-pin under the C0-5
  Change's heading (CTR-PQZ-14), with the affected-steps gate (owner 2026-10-27).
- `contracts/metatx.md`: CTR-MTX-07 and §1 (the library), CTR-MTX-17 table, §8 gas, §11 interfaces (PayMeta, the
  router), §12 per-family equivalents, CTR-MTX-26 / -27 status.
- `networks/evm.md` NET-EVM-06 table; `networks/{soroban,solana,cosmos,sui,aptos,ton}.md`: the pay-meta entry and
  the router of each; `networks/README.md`: NEAR / Algorand carry CTR-MTX-26 / -27 from their bring-up;
  `contracts/pq-zero-knowledge.md` §9.3 margins; `contracts/zether.md` §19 if a row moves; the sets README /
  `SET.md` files that quote `debit_min_gas` or `ROLL_MAX`; the node docs (job API, submit lanes) for the pay-meta job
  and the relay-fee row of every family; `clients/signers-clientkeys.md`.
- `TODO.md`: this item done; the NEAR / Algorand bring-up item next (§8); the stale line of §11.1 (1). `HANDOFF.md` at
  the end.

### 11.1 The four known gaps this item closes

1. **TODO's wrong line.** `TODO.md` (the P6 wallet-prover step 5b) says "neither `mtxRollOver` nor `mtxPrepareAcc` is
   relayable". It contradicts the 2026-10-20 ruling (every state-changing `mtx*` relayable) and the code (both are in
   the PQZ rule tables; `mtxPrepareAcc` halves are re-measured on `uaExecute`, §5.3 item 5). Corrected to "both are
   relayable (CTR-MTX-19); the prover may also call `mtxPrepareAcc` directly".
2. **`e2e.py` link closure.** `script/pqz/e2e.py` `Deployer.linked()` reads only the token artifact's direct
   `linkReferences`, so after the split the PQZ envs would pin `MtxPipelineLib` but not `HederaLib` (a library of the
   library). Fixed to the transitive closure, libraries deployed leaf first, with a Python self-test (R5).
3. **`UARegistry` re-pin of `PQZ_DEBIT_MIN_GAS`.** `UARegistry.sol` compiles `PqzSet.PQZ_DEBIT_MIN_GAS` into its PQZ
   holder bound (`w + w/63 + GAS_MARGIN + PQZ_DEBIT_MIN_GAS > TX_GAS_CAP`, C0-5). The re-measured constant (§5.3
   item 4) changes the registry's bytecode at every set: `UARegistryPqzBound.t.sol` re-pinned, and the SCaaS testnet
   takes the new registry at its next reset (fs3 Task 13, with UA-8's registry redeploy).
4. **The node's `ERC1271_FLOOR`.** `scaas-node/src/guard.rs` pins `ERC1271_FLOOR = 21,000 + 400,000 · 64/63 + 5,000`
   (432,349, asserted in `guard.rs` and used by two `submit.rs` tests): one frame too few after the split (§9). Re-pinned
   from forge's measured minimum.

## 12. Left to the builder

- Exact internal function names and the split of `MetaTxBase` into wrappers over `MtxPipelineLib`'s internals;
  making `_execute` virtual; deleting the token-side overrides that moved (`_chargeFee`, `_requireNativeUASignature`,
  `_erc1271Gas`, the Hedera branch of `_requireValidSignature`).
- Reading the basis word in the token (the existing assembly), and the facts struct for a `data` shorter than 4 bytes
  (pass `bytes4(data)` zero-padded and the real length; the library refuses).
- Struct packing of `Envelope` / `CallFacts` (ABI words either way), and whether `Out` returns as a struct or a tuple.
- The parity fixture's format and case list (R1), the opcode walker (R6), the closure test (R5).
- The PayMeta body restructuring (§6), the vectors file.
- The router's code within CTR-MTX-27, its deployment record keys.
- Per family (§6.2, §7.2): the private helper names, the event field order, the exact byte encoding of `call` within
  the stated rule, the test target of each router suite.
- The node and client code of §9 within the stated rules.
- Every number marked [estimate] is replaced by a measured one with its run log in `smartcontracts/evm/runs/`.

## 13. Owner questions (answered 2026-10-27)

All four were answered on 2026-10-27 (§0); none is open.

1. **Non-EVM staging.** Controller proposal: EVM (with Hedera) here, each other family later. **Owner: all families in
   this one item** ("Tất cả một lượt"); §8, §6.2, §7.2. NEAR and Algorand follow as their own bring-up item.
2. **Fee amount before the call.** **Owner: accepted** — one library call, the fee error wins when both fail (§3.8).
3. **Trade and receiver-fee signatures through the library.** **Owner: accepted** (§3.1, §3.4).
4. **Gate for the `set.toml` re-pins.** **Owner: accepted** — only the affected steps (`gen_set.py --all --check`,
   forge at the four sets, sizes, `docs_check`), no full pqz-core gate (§5.3).

No new question blocks the build. The per-family choices of §6.2 / §7.2 that a reader might want to revisit are
controller calls, recorded where they are made: the Cosmos `sha3` dependency, the Move routers' static target list,
TON's open-mode-only escrow with one pending call per target.
