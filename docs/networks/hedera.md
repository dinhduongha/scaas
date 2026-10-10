# Hedera (HSCS)

Common rules for every family: [networks/README](README.md). Status: contracts, adapter and client verifier
**BUILT**; the items marked SPECIFIED below are normative and not yet in code.

**Contents**

1. [Overview](#1-overview)
2. [Payload](#payload)
3. [Signatures](#3-signatures)
4. [Relayer](#4-relayer)
5. [Finality and events](#5-finality-and-events)
6. [Mandate and DEX](#6-mandate-and-dex)
7. [HTS tokens](#7-hts-tokens)
8. [Wrappers](#wrappers)
9. [Conformance](#conformance)
10. [Limitations](#10-limitations)

## 1. Overview

<a id="overview"></a><a id="NET-HED-04"></a>**NET-HED-04** — **Hedera is the EVM family on the Hedera Smart Contract
Service: the same Solidity contracts behind a Hedera JSON-RPC relay, plus HIP-632 for ED25519 accounts; the
payer-sponsored path is not used.** HSCS runs EVM bytecode (Besu), so the Solidity set is reused unchanged:
`MetaToken` (contract-level EIP-712 meta-tx), `MandateWallet`, `MetaTxDex`/`SCaaSDex`. There is **no
`SmartKeyAccount` and no EVM pipeline on Hedera** (as built: `HederaMetaToken.sol:22-24`, `adapters/hedera.rs:4-6`): native Hedera accounts already rotate keys, and the relayer runs
the one-transaction-per-lane runner ([NET-HED-08](#NET-HED-08)). ED25519 accounts need a raw signer
([NET-HED-15](#NET-HED-15)). Payer-account sponsorship (the subject sends a Hedera account transaction whose fee
someone else pays) is **not** used: it orders operations by the subject's account, exactly the lock
[NET-ALL-02](README.md#NET-ALL-02) removes. Chain ids 295 (mainnet), 296 (testnet), 297 (previewnet), 298
(localnet); `chain_key` is always `hedera:<chainId>`.

| Piece | Hedera-specific part | File |
|---|---|---|
| Token | `HederaMetaToken is MetaToken`: a Hedera account's **ED25519** signature verified through HIP-632 `isAuthorizedRaw` (`0x16a`); `UnderlyingToken` on HTS tokens ([wrappers](#wrappers)) | `smartcontracts/evm/src/hedera/HederaMetaToken.sol` (v1), `HederaLib.sol` (v2) |
| Account auth | library calling `isAuthorizedRaw` with `CALL` (100 000 gas cap); a revert or garbage ⇒ `false` | `smartcontracts/evm/src/hedera/HederaAccountAuth.sol` |
| Mandate | `HederaMandateWallet is MandateWallet` adds `mtxExecuteAsOwnerRaw` for ED25519 owners ([NET-HED-03](#NET-HED-03)) | `smartcontracts/evm/src/hedera/HederaMandateWallet.sol` |
| DEX | unchanged — every leg is a meta-tx on the token, so an ED25519 leg goes through `HederaMetaToken` (target: a `TradeOrder` verified by the Hedera token's signature check, [Mandate and DEX](#mandate)) | — |
| Relayer | EVM adapter pointed at the JSON-RPC relay, run under `lane_runner`; fee `eth_gasPrice × 1.2`, priority 0 | `scaas-node/src/adapters/hedera.rs` |
| Client | long-zero payer `0.0.N` ⇒ native ED25519 path ([client families](../integration.md#families)) | — |

## <a id="payload"></a>2. Payload

<a id="payload"></a>

On Hedera the `MetaOp` v1 **is** the EIP-712 `MetaTransaction` of `MetaToken` — there is no second format:

| `MetaOp` v1 | EIP-712 (`MetaToken`) |
|---|---|
| `domain="scaas.metaop.v1"` | `EIP712Domain{name:"SCaaS MetaToken", version:"1"}` |
| `network` | `chainId` = 295 / 296 / 297 / 298 |
| `contract` | `verifyingContract` = the token clone |
| `op` | `data` = `pay(bytes32)` ‖ payRef (as built, op `trade` = `trade(address,uint256,address)`; target: a `MetaTransfer` with `entryRef` for transfer/payment, or a `MetaTransaction` whose `data` is an allowlisted self-call, [CTR-MTX-15](../contracts/metatx.md#CTR-MTX-15), [NODE-JOB-20](../node/job-api.md#NODE-JOB-20)) |
| `from, to, amount` | `from, to, value` |
| `payRef(32)` | `entryRef` of the `MetaTransfer` (as built inside `data`) |
| `lane(32)`, `nonce` | `batch = keccak(entryRef)`, `nonce = 0` ([CTR-MTX-03](../contracts/metatx.md#CTR-MTX-03)) |
| `validUntil` | `validUntil` |
| `relayer` | `relayer` + flag `MODE_RESTRICT_RELAYER` |
| `extra` | `data` (hashed as `keccak256(data)` in the struct) |

Target domain (SPECIFIED): `EIP712Domain{name, version, chainId, verifyingContract, salt = chain_uid}`
([NET-ALL-22](README.md#NET-ALL-22)). On Hedera `chain_uid` is the block-0 hash the JSON-RPC relay reports; before a
Hedera profile fixes it, the operator confirms that the value is the same across mirror-node and relay restarts and
across two independent relays (the relay derives blocks from mirror-node record files, so this is checked, not
assumed); an unstable value keeps the profile `draft`.

Cross-network replay: `chainId` in the domain (Hedera mainnet 295 differs from every other EVM chain). Cross-contract:
`verifyingContract`. Cross-use: the token's own `(from, batch) → nonce`. Expiry: `validUntil` against
`block.timestamp` (Hedera consensus seconds). Digest = `keccak256(0x1901 ‖ domainSeparator ‖ structHash)`; the
client, Solidity (`metaTxDigest`) and Rust (`metatx::digest`) compute the same value against the shared vectors
`smartcontracts/evm/test/vectors/hedera_kat.json`.

## 3. Signatures

<a id="signatures"></a>

| Subject kind | `from` | Signature | Verified by |
|---|---|---|---|
| ECDSA account with an EVM alias (EIP-6963 wallet, seed key `m/44'/3030'/0'/0/i`) | alias `0x…` | 65 bytes `r‖s‖v`, low-s | `ecrecover` (as EVM) |
| Hedera account with a **single ED25519** key (seed key `m/44'/3030'/0'/0'/i'`) | long-zero `0x000…N` (= `0.0.N`) | **64 bytes** ed25519 over **exactly the 32-byte digest** | HIP-632 `isAuthorizedRaw(from, digest, sig)` |
| Smart account (wallet contract) | contract address | the account's blob | ERC-1271 |

<a id="NET-HED-09"></a>**NET-HED-09** — **`HederaMetaToken` verifies a 64-byte signature from an account without code
through HIP-632 `isAuthorizedRaw`; a precompile revert means "not authorised"; everything else is `MetaToken`.**
Branching in `HederaMetaToken._requireValidSignature`: `from` has code ⇒ ERC-1271 (unchanged); no code **and** exactly 64 bytes ⇒
HIP-632; otherwise the parent's `ecrecover`. The length is unambiguous: OZ 5.2 `ECDSA.tryRecover(bytes)` accepts
only 65 bytes (no EIP-2098), so 64 bytes are never ECDSA here, and the precompile itself classifies by length (65–72
= EC, 64 = ED). Key ↔ account is bound **on chain** by the precompile (it reads the account's key from Hedera state),
so a public key sent by a client is never a basis for authority.

Precompile behaviour (read from the consensus node's `IsAuthorizedRawCall.java` and tried on testnet on
2026-10-03):

```solidity
// Selector: 0xb2a31da4 (decl: "isAuthorizedRaw(address,bytes,bytes)")
function isAuthorizedRaw(address account, bytes memory messageHash, bytes memory signature)
    external returns (bool authorized);

// Selector: 0xb2526367 (decl: "isAuthorized(address,bytes,bytes)")
function isAuthorized(address account, bytes memory message, bytes memory signature)
    external returns (int64 responseCode, bool authorized);
```

- Address `0x000000000000000000000000000000000000016a` (`0x16a`); `isAuthorizedRaw(address,bytes,bytes) returns (bool)`, selector `0xb2a31da4`. `isAuthorizedRaw` returns a bare ABI `bool`;
  `isAuthorized` returns `(int64 responseCode, bool authorized)` with `responseCode == 22` = `SUCCESS`.
- ED25519: the account must hold a **single** ED25519 key (no KeyList/threshold); `messageHash` exactly **32 bytes**
  (`KECCAK_256_HASH must be 32 bytes long`); signature exactly **64 bytes** (`ED_SIGNATURE_LENGTH = 64`); pure RFC 8032
  verification over those 32 bytes as-is (no prefix, no re-hash): `IsAuthorizedRawCall.java` and `SignatureVerifierImpl.java`
  build a `TransactionSignature(signedBytes, keyBytes, signature, ED25519)` and call `verifySync`; `AppSignatureVerifier.java`
  enforces the 32-byte length.
- ECDSA secp256k1: **65-byte** `[r (32), s (32), v (1)]` (recovery id stripped internally); `messageHash` 32 bytes;
  the account must have an EVM alias — `isLongZero(address)` is refused with `INVALID_ACCOUNT_ID`, so ECDSA
  accounts always use their `0x…` alias (`ecrecover` path).
- A missing account, a compound key or a wrong key type ⇒ **revert** (not `false`); our library maps a revert to
  "not authorised". Testnet: `eth_call` to `0x16a` for a real ED25519 account `0.0.6000019` with a garbage
  signature ⇒ `false`; a non-existent account ⇒ `execution reverted: INVALID_ACCOUNT_ID`. The positive path (valid
  signature ⇒ `true`) is not yet tried on a live network ([conformance](#conformance)).
- Gas: the fee is the `ecrecover` fee (**3 000** gas, `HederaGasCalculatorImpl.getEdSignatureVerificationSystemContractGasCost()`
  delegates to Besu's `getEcrecPrecompiledContractGasCost()`), but a **rejected** call charges the frame's **entire**
  remaining gas (`reversionWith(rce, frame.getRemainingGas())`), so our call is capped at **100 000** gas (`hedera/HederaAccountAuth.sol:18-21`): a bad
  signature that passes simulation never burns the relayer's whole transaction gas.
- Network status: `isAuthorizedRaw` shipped in services **v0.52**; the finalized Hedera Account Service (HIP-632)
  in **v0.56.7**; both active on mainnet and testnet. Local tooling: `solo` / `hiero-solo` (the `hedera-local-node`
  v2.36.0+ bundled services ≥ 0.52 and was deprecated in September 2024).

<a id="NET-HED-11"></a>**NET-HED-11** — **The HIP-632 system contract is called with `CALL`, never `STATICCALL`.**
`IsAuthorizedRawCall` does not implement `allowsStaticFrame()` (default `false`), and `AbstractNativeSystemContract` HALTs a
system contract in a static frame. Tested on testnet (initcode through `eth_call`, 2026-10-03): same arguments, STATICCALL ⇒
`ok = false` with no data; CALL ⇒ `ok = true` + `false`. Because `ERC20MetaTx._requireValidSignature` is `view`,
`HederaMetaToken` calls through a function pointer cast to `view` (`HederaAccountAuth.asView`) — safe because the
only caller is `executeMetaTransaction` (non-view) and `0x16a` writes no state and calls back nothing; the forge
mock writes storage, so it too HALTs under STATICCALL (a regression test). BUILT. Removing `view` from the parent so
the cast disappears is an open clean-up item, done only when the parent signature changes for another reason (the
cast sits in v1, `HederaMetaToken.sol:28`, and in `HederaLib.sol` (`requireValid`);
marked in `HederaAccountAuth.sol:31`).

<a id="NET-HED-15"></a>**NET-HED-15** — **Hedera ED25519 subjects need a raw signer.** The contracts accept raw
ED25519 over the 32-byte EIP-712 digest only. HashPack/WalletConnect `hedera_signMessage` (HIP-820) signs
`"\x19Hedera Signed Message:\n" + len(message) + message` and returns a base64 protobuf `SignatureMap`:

- **ED25519: incompatible.** The wallet signs the full prefixed string (longer than 24 bytes); `isAuthorizedRaw`
  refuses any `messageHash` that is not exactly 32 bytes and verifies against those 32 bytes, not the prefixed
  string.
- **ECDSA: compatible after a transformation.** A dApp computes `keccak256("\x19Hedera Signed Message:\n" +
  len(message) + message)`, extracts the raw 65-byte signature from the `SignatureMap` and passes both; passing the
  protobuf blob reverts.

Supported signers for ED25519 subjects: the clientkeys seed (`m/44'/3030'/0'/0'/i'`) with raw signing, or an
ECDSA-alias account. A `MandateWallet` owned by an ED25519 account pays through `mtxExecuteAsOwnerRaw`
([NET-HED-03](#NET-HED-03)).

Passkeys on Hedera go through ERC-1271 smart accounts with OpenZeppelin P-256 (Solidity verifier when the `0x100`
precompile is absent; `has_p256_precompile` is probed per chain).

## 4. Relayer

<a id="relayer"></a>

- **Lanes** are **ECDSA** secp256k1 accounts (`m/44'/3030'/0'/0/i`, [NODE-LANE-08](../node/submit-lanes.md#NODE-LANE-08))
  used through their EVM alias; the JSON-RPC relay accepts only ECDSA-signed Ethereum transactions. A lane account
  must **exist** on the ledger (created by sending HBAR to the alias — HIP-583 auto-create); the adapter checks the
  lane balance before every job, and a lane with balance 0 (not yet created, or out of HBAR) sends the job back to
  the queue with a clear error, unsigned and unsent. The relayer pays gas in HBAR from its lane; the subject needs no
  HBAR and sends no transaction.
- **Fees.** Hedera has a **fixed gas price** set by its fee schedule (testnet recorded `eth_gasPrice =
  0xca900a7c00`, the 870-gwei equivalent; `eth_maxPriorityFeePerGas = 0`; `eth_feeHistory` returns a constant base
  fee and reward 0). The adapter signs type-2 with `maxFee = gasPrice × 1.2`, `priority = 0`; Hedera charges only the
  scheduled price, so the margin is not lost. The relay's balance precheck uses `gasLimit × maxFee`, so a lane needs
  ≈ `gasLimit × 1.2 × gasPrice` HBAR per transaction (not double, as alloy's `eth_feeHistory` estimate would assume —
  the reason the adapter does not use the generic `Chain::fees`).
- **Gas limit**: estimate + 20 %. Hedera charges **at least 80 % of the gas limit** (HIP-185), so never set a high
  limit "to be safe"; cap `max_gas_per_tx` (the network allows 15 M per transaction).

<a id="NET-HED-08"></a>**NET-HED-08** — **Hedera runs `lane_runner` (one transaction in flight per lane), with no
pipeline, replacement or gap-fill.** Hedera has **no mempool**: the relay forwards a transaction to one consensus
node; it reaches consensus in seconds or is refused at precheck. So there is no replacement of a stuck transaction and no
gap-fill (a nonce never hangs in a mempool), and pipelining several nonces in one lane is dangerous: nonce N+1 can
reach consensus (through another node) before N ⇒ `WRONG_NONCE`, and the relayer still pays the node fee — so Hedera does not run the EVM runner (`submit.rs`). The runner
reads the committed nonce before each job; lanes run in parallel. The subject has no sequence on the path: the
meta-tx lane is `batch = H(entryRef)` inside each contract, so an op held back on contract 1 does not block the same
subject on contract 2 (anti-lock test in forge and end to end). Routing: `main.rs` picks the runner by
`ChainCfg::uses_adapter()` (= `family != "evm"`), so Hedera goes through `adapters::build` → `HederaAdapter` +
`lane_runner`/`index_runner`; `is_evm()` stays for config checks (Hedera needs only `evm_chain_number`, no `network`);
`chain_key()` ignores `network` for EVM-like families, so it is always `hedera:<chainId>`. The open gateway and the
DEX matcher HTTP routes are EVM-only until the gateway goes through `ChainAdapter`. BUILT.

<a id="NET-HED-05"></a>**NET-HED-05** — **Each Hedera status code maps to one outcome class; a billed failure is never
requeued without limit** ([NODE-LANE-14](../node/submit-lanes.md#NODE-LANE-14)). SPECIFIED (built: every known code
except `CONTRACT_REVERT_EXECUTED` requeues — `hedera.rs:96-98` `requeues`, `:183-195` `tx_status`, runner
`adapter.rs:293-299` — with no attempt cap: the client only counts `attempt_count`, the store only counts,
`store/sqlite.rs:162`):

| Code | Reached consensus / billed | Class |
|---|---|---|
| `CONTRACT_REVERT_EXECUTED`, ABI revert data | yes | `Reverted` (final; the consumption check `op_consumed` runs first, [NODE-LANE-09](../node/submit-lanes.md#NODE-LANE-09)) |
| `INSUFFICIENT_GAS`, `MAX_CHILD_RECORDS_EXCEEDED`, `INVALID_ACCOUNT_ID`, `INVALID_SIGNATURE`, `CONSENSUS_GAS_EXHAUSTED` | yes | `Reverted` (final) — no parameter change makes the next attempt different |
| `WRONG_NONCE` | yes (node fee) | requeue **once** with the committed nonce re-read; the second time ⇒ `Reverted` |
| `BUSY`, `PLATFORM_TRANSACTION_NOT_CREATED`, `THROTTLED_AT_CONSENSUS`, `DUPLICATE_TRANSACTION`, `TRANSACTION_EXPIRED`, `INVALID_TRANSACTION_START`, every relay precheck error (`submit_outcome`) | no | requeue (free), still bounded by `chain.max_attempts` |
| `INSUFFICIENT_PAYER_BALANCE`, `INSUFFICIENT_ACCOUNT_BALANCE`, `INSUFFICIENT_TX_FEE`, `PAYER_ACCOUNT_NOT_FOUND`, `MAX_GAS_LIMIT_EXCEEDED`, `INVALID_ETHEREUM_TRANSACTION` | lane-side fault | requeue + lane balance breaker ([NET-HED-12](#NET-HED-12)); not counted in the subject's grief score |

Every "yes" row feeds the breaker ([NODE-LANE-13](../node/submit-lanes.md#NODE-LANE-13)) and the `from` subject's grief
score ([NODE-LANE-15](../node/submit-lanes.md#NODE-LANE-15)). Why: a wallet contract as `from` whose
`isValidSignature` burns ≈ 0 gas under `eth_estimateGas` but the full 50 k ERC-1271 cap (`MetaToken._erc1271Gas`,
`MetaToken.sol:141-144`) at consensus makes an
out-of-gas, which as built requeues until `validUntil`, each round costing the lane ≥ 80 % × (estimate × 1.2).
Tests: receipt `INSUFFICIENT_GAS` ⇒ `reverted`, no requeue; `WRONG_NONCE` twice ⇒ second `reverted`; a job beyond
`max_attempts` ⇒ `dead ATTEMPTS_EXHAUSTED`; a failed receipt's fee lands in `spent`. Other outcomes: no receipt at
the mirror yet ⇒ `TxStatus::Unknown` (the runner waits until the payload expires); receipt `status 0x0` with ABI revert data or
`CONTRACT_REVERT_EXECUTED` ⇒ `Reverted{reason}` (permanent); a relay precheck refusal of `eth_sendRawTransaction` ⇒
`adapter::Rejected`; "duplicate" = that very transaction landed ⇒ treated as sent; an expired
payload ⇒ `dead` at `build`, before the lane-balance check. Only strings from the known code set are read as Hedera
codes.

<a id="NET-HED-12"></a>**NET-HED-12** — **`HederaAdapter` reports `tx_fee` (`gasUsed × price` of every receipt,
including `status 0x0`) and `lane_balance`**, which the runner feeds to the breaker
([NODE-LANE-13](../node/submit-lanes.md#NODE-LANE-13)). SPECIFIED. Why: as built the adapter implements neither (both
default to `None`, `adapter.rs:112-118`; `hedera.rs` implements only `op_consumed/build/sign/submit/tx_status/…`), so
neither `gas_budget` nor `min_relayer_balance` ever sees a Hedera sample; only the zero-balance check in `build`
(`hedera.rs:163-166`) stops a drain loop. Tests: a failed receipt still adds to `spent`; a balance below
the floor stops the lane taking work.

<a id="NET-HED-13"></a>**NET-HED-13** — **Mesh and gateway verify a 64-byte Hedera ED25519 signature locally under
`sig_kind = "hedera_ed25519"`** before any simulation ([NODE-MESH-16](../node/mesh.md#NODE-MESH-16)): the decoder checks
length 64, `from` in long-zero form, and ed25519 over the digest with the account key read once from the mirror node
(`/api/v1/accounts/0.0.N` → `key`, cached). Genuine `erc1271` stays subject to the per-peer simulation budget.
SPECIFIED. Why: as built, `sig_kind` is only `eoa`/`erc1271` and `check_evm` returns `Ok` for every non-EOA intent
(`mesh/digest.rs:193-195`), so garbage intents force every peer to
simulate.

Residual risk, stated: a subject can change state after simulation — an ED25519 subject `CryptoUpdate`s its key to a
KeyList (HIP-632 reverts, burning the 100 k cap), dissociates or removes KYC from the receiver, or spends the balance
with its own `ContractCall`; Hedera charges ≥ 80 % of the gas limit. Each signature works at most once
(`CONTRACT_REVERT_EXECUTED` is final), but fresh signatures are free, so the bound is per subject through the grief
score (`subject_grief`; not yet in code) ([NODE-LANE-15](../node/submit-lanes.md#NODE-LANE-15)). The node-wide adapter rules apply as written: signed
fields from the payload ([NODE-LANE-16](../node/submit-lanes.md#NODE-LANE-16)), `max_value_out = 0` for meta-tx jobs
([NODE-LANE-17](../node/submit-lanes.md#NODE-LANE-17)), no adapter journal of its own, and one custody key per family
([NODE-LANE-20](../node/submit-lanes.md#NODE-LANE-20)); the lane-deposit and immutable-program rules do not apply
(no lane-paid rent; factory implementations are already immutable).

## 5. Finality and events

<a id="finality"></a>

Hashgraph aBFT: a transaction in a record file is **final**. The relay's "block" is a record file (~2 s), read from
the mirror node (a few seconds behind). `final_head` = the newest block the mirror returns (mode `instant`, depth 0),
with the head-hash quorum across `rpc_urls` as on EVM. The relay truncates the 48-byte record-file hash to 32 bytes
(`0x` + 64 hex) — stable and equal to `block_hash(height)`. The node accepts `finality.mode = "instant"`
for `hedera` (= depth 0). Events are `PaymentSettled` and `MetaTransactionExecuted` of registered tokens, normalised
exactly as on EVM (`indexer::encode_event`) (lowercase `0x`; an ED25519 account
without alias in long-zero form; tokens and ECDSA accounts at their real EVM addresses). The relay's `eth_getLogs`
allows 1 000 blocks per call, equal to the indexer's step cap. The token list is the node store's per-namespace set
(no `params.tokens`; the legacy pull path read it from `node_config`); an empty list never advances the cursor ([NET-ALL-06](README.md#NET-ALL-06)).

## 6. Mandate and DEX

<a id="mandate"></a><a id="NET-HED-03"></a>**NET-HED-03** — **An ED25519 owner pays from its `MandateWallet` only
through `mtxExecuteAsOwnerRaw`.** `MandateWallet` is used unchanged with the platform's secp256k1 custody key as
delegate. An ED25519 owner cannot use `executeAsOwner` (ECDSA; target name `mtxExecuteAsOwner`), so `HederaMandateWallet.mtxExecuteAsOwnerRaw` checks the
owner through HIP-632 over the same owner digest as `mtxExecuteAsOwner` (target: the owner's `MetaTransaction` digest
in the wallet's domain, [CTR-ACC-06](../contracts/mandates.md#CTR-ACC-06); as built the `OwnerCall` digest with
`ownerNonce`); `isValidSignature` (ERC-1271 for
the owner) stays ECDSA, and an ED25519 owner pays manually with `mtxExecuteAsOwnerRaw(execute(token, payWithFee…))`. ERC-1271 runs under
STATICCALL, where HIP-632 halts, so `isValidSignature` cannot cover ED25519; the token is not special-cased (one more
Hedera-only path in the signature pipeline for a rare case). Paying manually by meta-tx holds for ECDSA owners only.
The owner's raw call is relayed as a `call` job (selector in the call table,
[NODE-JOB-01](../node/job-api.md#NODE-JOB-01)) or submitted by the owner. Tests: forge with a `vm.etch` HAS mock — an
ED25519 owner pays a payee through `mtxExecuteAsOwnerRaw` (`token.pay…` as `data`); the same owner's meta-tx with
`from = wallet` fails ERC-1271. BUILT.

DEX: `MetaTxDex` and `SCaaSDex` are unchanged; each leg is `executeMetaTransaction` on the token, so an ED25519
leg is verified by `HederaMetaToken`. Fees, `filled[orderHash]` and cancel as in [contracts/dex](../contracts/dex.md).
Target (SPECIFIED): `MetaTxDex` is deleted; `SCaaSDex.mtxSettle` pulls each SCaaS leg through the sell token's
`mtxTrade`, whose signature check is the Hedera token's own (HIP-632 for a 64-byte ED25519 signature, ECDSA,
ERC-1271), so an ED25519 subject trades with no allowance ([NODE-DEX-15](../node/dex-venue.md#NODE-DEX-15)). HIP-632
signers are not contracts, so they can never call `approve` on a SCaaS token
([CTR-TOK-01](../contracts/token-wrappers.md#CTR-TOK-01)); they wrap a SCaaS underlying by signature
([CLI-SGN-36](../clients/signers-clientkeys.md#CLI-SGN-36)).

## 7. HTS tokens

<a id="hts"></a>

An HTS token (e.g. USDC on Hedera) has an ERC-20 facade at its long-zero address (HIP-218/376). It is used only
behind a **tier-2 wrapper** (`HederaMetaToken(underlying = token HTS)` in v1) with the HTS token as `underlying`; the
contract must **associate** the HTS token before receiving it (`SUCCESS (22)` or `TOKEN_ALREADY_ASSOCIATED_TO_ACCOUNT (194)`;
v1 `HederaMetaToken.sol:34-42`, v2 `HederaLib.sol` (`checkAndAssociate`), [wrappers](#wrappers)); users grant the HTS allowance **to the wrapper
contract** (valid under [CTR-TOK-01](../contracts/token-wrappers.md#CTR-TOK-01)). Risk, stated: protocol-level HTS
allowances cannot be restricted to contracts, so the system never uses an HTS allowance outside a wrapper.

<a id="NET-HED-07"></a>**NET-HED-07** — **Wizards and wallets read every key of the HTS issuer and warn before a
wrapper is created.** Beyond the fee-schedule key: a **wipe** key erases the wrapper's underlying balance (backing
lost); a **freeze**/**KYC** key or **pause** blocks the wrapper and so every holder; a **supply** key does not touch
the wrapper's balance but is a value risk. None is refused on chain (Hedera USDC carries these keys); the wizard and
wallets read `getTokenKey(u, k)` for each of ADMIN, KYC, FREEZE, WIPE, SUPPLY, FEE_SCHEDULE, PAUSE and show the
warning, which also goes into the wrapper's risk disclosure. SPECIFIED.

## <a id="wrappers"></a>8. Wrappers

<a id="wrappers"></a>

<a id="NET-HED-14"></a>**NET-HED-14** — **Hedera v2 wrappers check every underlying in `initialize`, fail-closed,
through the HTS precompile `0x167`.** There are no Hedera wrapper children (P1d): `UnderlyingLib` init calls
`HederaLib.checkAndAssociate` under `IS_HEDERA`, and a native (HBAR) leg has 8 decimals, the tinybar (controller ruling, pending the owner); the HIP-632 signature rule is the `IS_HEDERA` branch in `MetaTokenBase`
(`HederaLib.requireValid`), exactly as `HederaMetaToken` does, and kind `NONE` on Hedera is `NoUnderlyingToken` with `IS_HEDERA`. In `initialize`, for every underlying `u`:

1. `isToken(u)` → `(rc, isHts)`; `rc ≠ SUCCESS` ⇒ `HtsQueryFailed(u, rc)`.
2. If `isHts`: `getTokenCustomFees(u)` with `rc ≠ SUCCESS` or an undecodable result ⇒ `HtsQueryFailed(u, rc)`; any
   fixed, fractional or royalty fee entry ⇒ `UnderlyingInvalid(u)`.
3. If `isHts`: `associateToken(this, u)`; anything but `SUCCESS` (22) or `TOKEN_ALREADY_ASSOCIATED_TO_ACCOUNT` (194)
   ⇒ `AssociateFailed(rc)`. There is no separate associate function: a token whose legs cannot be associated is never
   born.

A fee-schedule key can still add a fee later; it is not refused on chain (major HTS stablecoins carry one) — the
wizard and wallets read `getTokenKey(u, FEE_SCHEDULE)` and warn ([NET-HED-07](#NET-HED-07)). Domain, ABI, events and
tests are the EVM ones. BUILT.

<a id="NET-HED-06"></a>**NET-HED-06** — **The v1 HTS wrapper checks custom fees and associates in `initialize`,
fail-closed, and the permissionless associate function is removed.** Why: an HTS underlying with any fixed,
fractional or royalty fee breaks a wrapper — `MetaToken.wrap` measures what actually arrived (fine for receiver-side fees)
but `unwrap` sends exactly `amount` (`MetaToken.sol:134-139`), so a fixed fee in the same token or a fractional fee with `netOfTransfers = true` is
taken from the wrapper again (`balanceOf(this) < totalSupply`, the last redeemer is stuck), and a fixed fee in HBAR
makes every `unwrap` revert (the wrapper holds no HBAR), locking the reserve. v2 refuses these; the built v1
`HederaMetaToken` only associates (the permissionless `associateUnderlying()` calling `0x167
associateToken(this, underlying)`), is still registered as `META v1` (`DeployHedera.s.sol:29-30`), and anyone may create
it through the open factory (`OpenFactory.createMetaToken`, permissionless, `:91-96`; `deprecate` does not block
creation — `_registered` checks only non-zero, `:167-170`). Fix (SPECIFIED): `MetaToken.initialize` calls an
`internal virtual _checkUnderlying(u)` hook (empty by default); `HederaMetaToken` overrides it with
`HederaLib.checkAndAssociate(u)` and reverts `UnderlyingInvalid` on any fee; `associateUnderlying()` is deleted
(association inside `initialize` means a token that cannot associate is never born, and the auto-association slot is
no longer a detour); a new implementation is deployed, registered as a new META version on the Hedera factory, and
`deprecate(META, 1)` follows. Until then the wizard and the node's token registry refuse a v1 Hedera token whose
underlying is an HTS token with custom fees. Forge tests (mock `0x167`): v1 on an underlying with
fixed/fractional/royalty fees ⇒ creation reverts; no fee ⇒ associated once, wrap/unwrap conserve the reserve; `isToken`
failure ⇒ `HtsQueryFailed`.

Classical Zether on Hedera is feasible for the bn254 variant only: HSCS has the bn254 precompiles (`0x06`–`0x08`) but
not BLS12-381 (EIP-2537). The 15 M gas per transaction cap fits one Bulletproofs verification (several million gas,
estimate), but Hedera charges ≥ 80 % of the gas limit at a fixed price, so a confidential transfer costs much more
than a plain one; to be measured when a Zether deployment exists. ED25519 accounts sign only the meta-tx envelope, so
the proof is independent of the signing key.

## <a id="conformance"></a>9. Conformance

<a id="conformance"></a>

- **Forge** (`smartcontracts/evm/test/hedera/`): precompile `0x16a` mocked with `vm.etch`. Forge 1.3.5 has no ed25519
  cheatcode, so the mock models the account key having signed exactly these 32 bytes with a 64-byte compact secp256k1
  signature; real ed25519 is checked by the client verifier and Rust against the shared KAT vectors; the account → key
  mapping mirrors Hedera state; unknown accounts revert (as on the network); HTS `0x167` mocked. Cases: ED25519 pay;
  bad signature / other key / unknown account; ECDSA still works; ERC-1271 still works; DEX ED25519 leg; mandate with
  ED25519 owner; associate; **anti-lock**; shared KAT vectors.
- **Rust**: receipt/log/block decoders on **vectors recorded from the testnet relay**
  (`scaas-node/tests/vectors/hedera_testnet.json`), decoder proptest; end-to-end `tests/e2e_hedera.rs` (`#[ignore]`) on
  anvil `--chain-id 298`: two lanes from a 24-word mnemonic, payment through `lane_step`, finality through
  `index_step`, anti-lock end to end.
- **Results (2026-10-03):** forge 24 Hedera tests (157 overall) green; client verifier suite 118 tests green (4 Hedera); Rust
  9 adapter tests (including proptests of 2 × 2 000 cases) + `e2e_hedera` green (anvil 298, port 31960); connector
  `node --test` 4 green — a Node.js ed25519 signature equals the Python one byte for byte on the shared vector.
- **Smoke on real Hedera EVM without an account or HBAR** (`smartcontracts/evm/script/hedera/HederaSmoke.sol` +
  `testnet_smoke.py`): constructors run as initcode through `eth_call` on the testnet relay (the mirror node's web3
  runs the services' EVM library and system contracts). Result 2026-10-03: `OpenFactory` + `HederaMetaToken` + clone
  deploy (TSTORE/MCOPY available); an ECDSA meta-tx payment ⇒ `ok`, the shop receives 100; a wrong ED25519 signature
  for the real ED25519 account `0.0.6000019` through the real `0x16a` ⇒ `MetaTxBadSignature`; a non-existent account
  ⇒ `MetaTxBadSignature`; `EXTCODESIZE` of an EOA = 0 (the `_isContract` branch is right); `0x16a` answers CALL and
  HALTs on STATICCALL.
- **Smoke on every services release:** the `_isContract(from)` branch relies on `EXTCODESIZE(EOA) == 0`, measured
  once. Hedera already has account facades (HIP-719 for tokens, HIP-906 for HBAR allowances); if an EOA ever had
  code, an ED25519 account would fall to ERC-1271 and could not spend (fail closed, funds stuck). `HederaSmoke` runs
  again on every services upgrade (the chain profile records the version checked); a mismatch ⇒ chain `paused` until
  reviewed.
- **Gaps:** `solo` (≥ 8 GB RAM, many containers) does not run on the shared build host. Anvil differs from Hedera:
  it has a mempool, no real `0x16a`/`0x167`, and does not charge 80 % of the gas limit. The positive HIP-632 path is
  untried on a live network. With a funded testnet account: deploy `HederaMetaToken`, pay once with an ED25519
  account and once with an ECDSA alias; confirm that `msg.sender` (and the receiving/signing address) of an ECDSA
  account with an alias is the alias, not the long-zero form; confirm the relay returns Hedera codes (`WRONG_NONCE`…)
  in `revertReason` / precheck errors as the adapter reads them.

## 10. Limitations

<a id="limitations"></a>

- <a id="NET-HED-10"></a>**NET-HED-10** — **HashPack `signMessage` and threshold/KeyList accounts are seams.** HIP-820
  messages and compound keys could be verified with `isAuthorized(address, message, SignatureMap protobuf)` (which
  also supports threshold keys and KeyLists); that needs a `SignatureMap` decoder in Solidity and a live-network test
  — a follow-up investigation, not scheduled work.
- <a id="NET-HED-01"></a>**NET-HED-01** — **HCS anchoring is an open owner requirement.** Consensus Service topics as
  a tamper-evident audit log (hashes of decisions submitted with `TopicMessageSubmitTransaction`, timestamped by
  consensus) are a candidate transport for anchoring commitments ([client data protection](../integration.md#data-protection));
  not specified. Status `open` (PLANNED where the anchoring seam exists).
- <a id="NET-HED-02"></a>**NET-HED-02** — **The Hedera Schedule Service is an open owner requirement.** Scheduled
  transactions (`ScheduleCreateTransaction` / `ScheduleSignTransaction`, multi-signature collection over time) are a
  candidate for high-risk approvals; not specified. Status `open`.
- The payer-account sponsorship and HTS-token relayer rewards described in early requirements are not used
  ([NET-HED-04](#NET-HED-04)); relayer fees on EVM-family chains are token fees in the meta-tx
  ([contracts/metatx](../contracts/metatx.md)).
