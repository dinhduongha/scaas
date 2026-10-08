# Meta-transactions: a generic call for every SCaaS contract, transfers as a typed special case

**Status:** ACCEPTED by the owner 2026-10-08 and folded into the component docs (rules in `docs/decisions.md`: CTR-MTX-22/23/24, CTR-ACC-10, CTR-UA-26, CTR-PQZ-21 new; superseded CTR-MTX-85, CTR-ACC-80, CTR-PQZ-80); frozen here as the design record. Amends the accepted meta-tx
design (`docs/history/specs/2026-10-07-metatx-generic.md`, rules in [contracts/metatx.md](../../contracts/metatx.md)).
Provisional ids `GC-n`; real ids are allocated in `docs/decisions.md` on acceptance (docs/README "Ids").
**Date:** 2026-10-08. **Scope:** EVM and Hedera: the meta-tx base, every token, `MandateWallet`, `SubjectAccount`,
contracts built on SCaaS later (a family-tree registry, say), tender's deposit, node, clients, the reference ERP's
digest builder. Nothing is deployed: changes in place, no migration.

## 1. Why

SCaaS meta-transactions exist so that **someone other than the subject pays for a call of a SCaaS contract** — any
function, not only moving tokens. Example (owner): a contract that keeps a family tree on chain; adding or removing a
person is signed by the user and submitted, gas paid in native coin, by a service company. The accepted struct is
shaped by token transfers:

- `to`/`value` mean only "recipient"/"amount" and must be 0 for every other call;
- `data` has three shapes: empty (transfer), `pay(bytes32)` (payment), anything else (a self-call);
- the fee is paid in **this** token — a contract without a balance has nothing to pay it in;
- the base is `ERC20MetaTx`, so a non-token contract cannot use it; `MandateWallet` and `SubjectAccount` each carry
  their own signed types (`PayUnderMandate`, `RevokeMandate`, `OwnerCall`) and their own nonce rules.

A token transfer is a **special case** of a meta-transaction (owner), not its definition.

## 2. Owner answers (2026-10-08)

| # | Question | Answer |
|---|---|---|
| G1 | Wallet display once `to`/`value` leave the generic struct | **(b)** keep a separate **typed** struct for transfer/payment, so outside wallets show "send `value` to `to`" |
| G2 | Fee for a contract that is not a token | **(i) + (iii)**: no on-chain fee — the sponsor pays native gas and settles with the user off chain; the `fee` fields stay in the struct and only contracts that hold the charged balance (tokens) use them |
| G3 | Which contracts move to the generic base | `MandateWallet`, `SubjectAccount` and every new contract; tender (no signature of its own) and the UA ledger (`bytes32` ids) stay as they are |
| G4 | Named functions | **Kept separate**, signatures unchanged (`mtxTransfer`, `mtxTransferWithFee`, `mtxPay`, `mtxExecuteWithFee`, `mtxBatch`, `mtxPayReceiverFee`, …) — nothing is merged |
| G5 | Batching transfers | **1a**: add `mtxBatchTransfer(MetaTransfer[], sigs)` beside `mtxBatch` |
| G6 | Payment on a client-chosen lane | **2a**: add `mtxExecuteTransfer(MetaTransfer, sig)`, the struct entry of the typed path |
| G8 | Split the UA ledger's `UAMetaTransaction` the same way? | **Yes** (GC-9) |
| G9 | `SubjectAccount` signs as itself (`from = address(this)`) | **OK** (GC-6) |
| G10 | Names `MetaTransaction`, `MetaTransfer`, `MetaTxBase` | **Kept** |
| G11 | `PqzToken` relaying | **Like `ZetherToken`** (owner: "why not the same as Zether?"): GC-10 as written |
| G7 | `pay` as a Solidity function name | no conflict: `pay` is not a keyword or reserved word (`payable` is a different token); `function pay(address,uint256,bytes32)` compiles, selector `0x5e5571ac` |

## 3. Design

### GC-1 — Two structs, one nonce space

```solidity
// Every SCaaS contract: a signed call of one of this contract's allowlisted functions.
struct MetaTransaction {
    address from;          // signer; the authority the call runs under
    bytes   data;          // a call of THIS contract, allowlisted selector
    uint256 batch;         // nonce dimension 1: lane
    uint256 nonce;         // nonce dimension 2
    uint256 validUntil;
    uint32  mode;          // RESTRICT_RELAYER | RESTRICT_FEE_RECIPIENT | fee mode
    address relayer;
    uint256 fee;           // only where the contract can charge it (tokens); elsewhere fee mode NONE
    address feeRecipient;
}
// "MetaTransaction(address from,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,"
// "address relayer,uint256 fee,address feeRecipient)"

// Tokens only: the typed transfer that outside wallets display field by field.
struct MetaTransfer {
    address from;
    address to;
    uint256 value;
    bytes32 entryRef;      // 0 = transfer; ≠ 0 = payment (PaymentSettled with this reference)
    uint256 batch;
    uint256 nonce;
    uint256 validUntil;
    uint32  mode;
    address relayer;
    uint256 fee;
    address feeRecipient;
}
// "MetaTransfer(address from,address to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,"
// "uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
```

Both are signed in the contract's own domain `("SCaaS <Contract>", "1", chainId, contract, salt = chain_uid)`
([CTR-MTX-02](../../contracts/metatx.md#CTR-MTX-02); tokens keep `"SCaaS MetaToken"`, `"SCaaS ZetherToken"`). Both
consume the **same** lane `mtxNonce(from, batch)`: a lane is spent once whichever struct spent it. **One intent, one
digest** ([CTR-MTX-11](../../contracts/metatx.md#CTR-MTX-11) holds): a transfer or payment is signed only as a
`MetaTransfer`; no `transfer`/`pay` selector is ever allowlisted for `MetaTransaction`. Canonical zeroing (`relayer`,
`feeRecipient`) and `mode` are unchanged ([CTR-MTX-15](../../contracts/metatx.md#CTR-MTX-15)).

### GC-2 — Two bases

- **`MetaTxBase`** (any contract): `MetaTransaction`, digest, 2D nonces, `cancelNonce`, the transient sender and the
  ticket ([CTR-MTX-18](../../contracts/metatx.md#CTR-MTX-18)), the per-implementation selector allowlist with fee
  classes and `mtxSelectors()` ([CTR-MTX-19](../../contracts/metatx.md#CTR-MTX-19)), `mtxExecute` (+ alias
  `executeMetaTransaction`), `mtxBatch`, `chainUid()`, `supportedModes()`. Fee: a virtual `_chargeFee(from, basis,
  m)` that **reverts unless the fee mode is `NONE`**; `supportedModes()` of a contract that does not override it
  reports flags only (`0x03`).
- **`ERC20MetaTx is MetaTxBase`** (every token): overrides `_chargeFee` to charge in this token
  ([CTR-MTX-13](../../contracts/metatx.md#CTR-MTX-13), [CTR-MTX-20](../../contracts/metatx.md#CTR-MTX-20)), and adds
  the typed path: `MetaTransfer`, `mtxExecuteTransfer`, `mtxBatchTransfer`, the named functions, `payLane`,
  receiver-pays, `mtxTrade`/cancels, the allowance rule, the `ua*` path. `MetaTokenBase`, the tiers, Hedera children
  and `ZetherToken` sit on it as decided before ([CTR-MTX-07](../../contracts/metatx.md#CTR-MTX-07)).

### GC-3 — The generic pipeline (`mtxExecute`)

[CTR-MTX-17](../../contracts/metatx.md#CTR-MTX-17) loses its shape table: `data` is always a self-call. Steps:
1 relayer binding, expiry, mode, nonce, `from ≠ address(this)` (see GC-6 for `SubjectAccount`); 2 signature
(`_requireValidSignature`, virtual); 3 `data.length ≥ 4`, selector allowlisted, static length, fee mode allowed by the
fee class and by `supportedModes()`; 4 nonce; 5 ticket + `address(this).call(data)`, bubbling revert data; 6 fee via
`_chargeFee` (tokens only; else `NONE` was already enforced); 7 `MetaTransactionExecuted`. All or nothing as before.

### GC-4 — The typed pipeline (`mtxExecuteTransfer`, tokens)

Steps 1–2 as GC-3 on the `MetaTransfer` digest; 3 `to ≠ 0` (`PayToZero`), fee on `value`, the payee check
([CTR-MTX-08](../../contracts/metatx.md#CTR-MTX-08): "payee" = `t.to`), balance ≥ value + fee; 4 nonce; 5 fee then
value, `PaymentSettled(from, to, value, feeAmount, feeRecipient, entryRef)` when `entryRef ≠ 0`; 6
`MetaTransactionExecuted`. This is today's transfer and `pay` shapes, moved out of `data` into typed fields.

### GC-5 — Named functions: unchanged, they build the struct of their kind

| Function (signature unchanged) | Builds |
|---|---|
| `mtxExecute(m, sig)`, alias `executeMetaTransaction` | `MetaTransaction` |
| `mtxExecuteWithFee(m, sig)` | `MetaTransaction` (fee-shape check as today) |
| `mtxBatch(MetaTransaction[] ms, bytes[] sigs)` | `MetaTransaction` per item |
| `mtxTransfer(from, to, amount, batch, nonce, validUntil, mode, relayer, sig)` | `MetaTransfer{entryRef: 0, fee: 0, feeRecipient: 0}` |
| `mtxTransferWithFee(…, fee, feeRecipient, sig)` | `MetaTransfer{entryRef: 0}` |
| `mtxPay(from, to, amount, payId, validUntil, mode, relayer, fee, feeRecipient, sig)` | `MetaTransfer{entryRef: payId, batch: payLane(payId), nonce: 0}` |
| `mtxPayReceiverFee(t, payerSig, fee, feeRecipient, rfValidUntil, payeeSig)` | payer side `MetaTransfer`; `ReceiverFee.paymentDigest` = its digest |
| **new** `mtxExecuteTransfer(MetaTransfer t, bytes sig)` | `MetaTransfer` as given (G6: payment on a client-chosen lane, any shape) |
| **new** `mtxBatchTransfer(MetaTransfer[] ts, bytes[] sigs)` | `MetaTransfer` per item; atomic, rules of `mtxBatch` ([CTR-MTX-11](../../contracts/metatx.md#CTR-MTX-11)) |

The equivalences of [CTR-MTX-09](../../contracts/metatx.md#CTR-MTX-09) become `mtxTransfer(…) ≡
mtxExecuteTransfer({…, entryRef: 0, fee: 0, feeRecipient: 0}, s)` and `mtxPay(…) ≡ mtxExecuteTransfer({…, entryRef:
p, batch: payLane(p), nonce: 0}, s)`; [CTR-MTX-10](../../contracts/metatx.md#CTR-MTX-10) reads "a client that wants
another lane for a payment uses `mtxExecuteTransfer`".

### GC-6 — `MandateWallet` and `SubjectAccount` on `MetaTxBase`

- **`MandateWallet`**: `mtxExecute` with `from` = the delegate and `data = payUnderMandate(token, payee, amount,
  entryRef)` or `revoke(token)`; the functions check `_msgSender() == mandate.delegate`; the owner's calls run with
  `from` = the owner. The structs `PayUnderMandate` and `RevokeMandate` disappear; the lane nonce replaces their
  replay checks; `entryRef` stays the payment reference and stays single-use per wallet; `epoch[token]` stays so that
  `setMandate` again voids an earlier `revoke` intent bound to the old mandate (the revoke data carries the epoch:
  `revoke(token, epoch)`). Fee mode `NONE`. The named entry points `mtxPayUnderMandate`, `mtxRevoke`,
  `mtxExecuteAsOwner` stay (G4) as builders of the matching `MetaTransaction`; their signatures carry no lane, so they
  derive it as `mtxPay` does: `mtxPayUnderMandate` → `batch = uint256(keccak256("scaas.mandate.pay" ‖ entryRef))`,
  `nonce = 0` (one payment per `entryRef`); `mtxRevoke(token, epoch, …)` → `batch = uint256(keccak256("scaas.mandate.revoke"
  ‖ token ‖ epoch))`, `nonce = 0`; `mtxExecuteAsOwner(data, nonce, …)` → `batch = 0`. Hedera ED25519 owners keep
  `mtxExecuteAsOwnerRaw` ([NET-HED-03](../../networks/hedera.md#NET-HED-03)).
- **`SubjectAccount`**: owner operations (`addKey`, `removeKey`, `rotateKey`, `setGuardian`, `execute`) are
  allowlisted self-calls. Its keys include P-256 passkeys that have no address, so the signer is **the account
  itself**: `from = address(this)` is allowed here (the `SelfSender` guard of tokens is overridden), and
  `_requireValidSignature` checks the signature against the account's own key set (its ERC-1271 logic). The functions
  are `onlySelf` (`_msgSender() == address(this)`). `OwnerCall` and its single nonce disappear; `mtxExecuteAsOwner`
  stays as the named builder. Fee mode `NONE`.
- Not moved: tender (it verifies no signature; the deposit becomes a `MetaTransfer` with `entryRef = depositRef` and
  `commitBid` calls the token's `mtxExecuteTransfer`). The UA ledger keeps its own `bytes32` structs, split as GC-9.

### GC-7 — Contracts outside the token set

A new SCaaS contract (the family tree) inherits `MetaTxBase`, declares its allowlist and its domain name, reads the
caller through `_msgSender()`, and supports fee mode `NONE` only. The relayer — a sponsor's node lane or the company's
own — pays native gas; who may be sponsored is node policy ([NODE-SPN-01](../../node/sponsorship.md#NODE-SPN-01)) and
the node's call table ([NODE-JOB-20](../../node/job-api.md#NODE-JOB-20)). Charging the user is off chain (G2).

### GC-8 — Node, clients, vectors

- **KAT**: `metatx_kat.json` regenerated for the new `MetaTransaction`; a new `metatransfer_kat.json`; the mandate
  and owner-call vectors replaced by `MetaTransaction` vectors in their domains.
- **Node**: two `sol!` structs; a `metatx` job names its struct (`call` | `transfer`); the mesh `intent_id` and the
  lane journal key on `(from, batch, nonce)` across both; the breaker per `(from, selector)` treats a `MetaTransfer`
  as selector `transfer`/`pay`; NODE-LANE-11 batches through `mtxBatch` or `mtxBatchTransfer`, never mixed.
- **Clients**: `clientkeys`, the app, the portal and the reference ERP's `lib/eip712.py` build both structs; wallet
  JSON for `MetaTransfer` shows typed fields; `MetaTransaction` is decoded through `mtxSelectors()` before signing
  (already required).

### GC-9 — The UA ledger split the same way (owner G8)

[CTR-UA-19](../../contracts/accounts.md#CTR-UA-19)'s `UAMetaTransaction` carries the same `to`/`value`/`data` shapes
with `bytes32` ids. It splits like GC-1, in the token's domain, sharing the one nonce map `_uaNonce[bytes32][batch]`
with the address path (native ids zero-padded, as today):

```solidity
struct UAMetaTransaction {   // generic: an allowlisted call of this token under a UA (today: unwrap only)
    bytes32 from; bytes data; uint256 batch; uint256 nonce; uint256 validUntil;
    uint32 mode; address relayer; uint256 fee; address feeRecipient;
}
struct UAMetaTransfer {      // typed: transfer (entryRef = 0) or payment
    bytes32 from; bytes32 to; uint256 value; bytes32 entryRef; uint256 batch; uint256 nonce; uint256 validUntil;
    uint32 mode; address relayer; uint256 fee; address feeRecipient;
}
```

| Function (signature unchanged) | Builds |
|---|---|
| `uaExecute(UAMetaTransaction m, bytes auth)` | `UAMetaTransaction`; `data` limited to the UA allowlist (`unwrap` today; `approve`/`trade` refused as now) |
| `uaUnwrap(from, underlying, wrapped, recipient, minOut, batch, nonce, validUntil, mode, relayer, auth)` | `UAMetaTransaction{data: unwrap(…)}` |
| `uaBatch(UAMetaTransaction[] ms, bytes[] auths)` | `UAMetaTransaction` per item |
| `uaTransfer(…)`, `uaTransferWithFee(…)` | `UAMetaTransfer{entryRef: 0}` (fee 0 for `uaTransfer`) |
| `uaPay(from, to, amount, payId, …)` | `UAMetaTransfer{entryRef: payId, batch: payLane(payId), nonce: 0}` |
| **new** `uaExecuteTransfer(UAMetaTransfer t, bytes auth)` | `UAMetaTransfer` as given (mirror of `mtxExecuteTransfer`) |
| **new** `uaBatchTransfer(UAMetaTransfer[] ts, bytes[] auths)` | `UAMetaTransfer` per item (mirror of `mtxBatchTransfer`) |

The payee check compares `bytes32(uint256(uint160(feeRecipient)))` with `t.to`; `UAMetaTransactionExecuted` is
emitted for both structs and its `digest` stays the mesh `intent_id`. Vectors: the v3 KAT splits into a
`UAMetaTransaction` and a `UAMetaTransfer` vector.

### GC-10 — `PqzToken` on the one base; envelope bindings without `to`/`value`

The fold left open how `PqzToken` relays ([CTR-PQZ-15](../../contracts/pq-zether.md#CTR-PQZ-15) still describes its own
mixin `PqzMetaTx` with an `_executeOp` that reads `m.data` as calldata slices, to avoid copying ≈ 340 KB of `m.data`).
Proposal:

- **`PqzToken is ERC20MetaTx`** like `ZetherToken` ([CTR-MTX-07](../../contracts/metatx.md#CTR-MTX-07)); `PqzMetaTx`
  disappears. `pqzTransfer`, `pqzBurn`, `fund(bytes32,uint256)` and `rollOver(bytes32,bytes,bytes[])` are allowlisted
  self-calls through `mtxExecute` (fee class `ABSOLUTE`), and the proof-carrying ones read the envelope binding from
  the ticket exactly as classical Zether ([CTR-ZTH-34](../../contracts/zether.md#CTR-ZTH-34)). Plain public transfers
  are `MetaTransfer`s (GC-1), `PERCENT` allowed. The PQ-complete path is `uaExecute` with a `UAMetaTransaction` (GC-9)
  whose UA allowlist on `PqzToken` holds the same four selectors. PQZ selectors stay out of `mtxBatch`/`uaBatch`
  (`MtxNotBatchable(selector)`: one op is ≈ 3 M gas and up to ≈ 340 KB).
- **Cost of the self-call:** one memory copy of `m.data` for the `CALL`, `3·w + w²/512` gas with `w` = words: ≈ 0.25 M
  at 340 KB (`w` = 10 625). The callee's arguments are `bytes calldata`, so nothing is decoded into memory again. The
  earlier ≈ 2 M estimate assumed three copies (decode + re-encode + call). A PQZ op becomes ≈ 3.25 M, below the
  EIP-7825 cap of 16,777,216.
- **Bindings follow the new struct.** `to` and `value` are no longer fields of `MetaTransaction`, so the classical
  ([CTR-ZTH-06](../../contracts/zether.md#CTR-ZTH-06)) and PQ envelope bindings drop them:

```text
envelopeBinding = keccak256(abi.encode(keccak256(TAG), chainid, chainUid, token,
                    m.from, m.batch, m.nonce, m.validUntil, m.mode, canonRelayer, m.fee, canonFeeRecipient))
TAG = "SCAAS-ZETHER-ENVELOPE-V1" | "SCAAS-PQZ-ENVELOPE-V1" | "SCAAS-PQZ-UA-ENVELOPE-V1" (v3: m.from as bytes32)
```

  `m.data` stays excluded (it contains the proof). Vectors regenerate with the statement vectors of
  [CTR-ZTH-36](../../contracts/zether.md#CTR-ZTH-36).
- **Statement header check (open point of the fold):** the prover (`clients/zether-prover/src/zether.rs`, `Header`,
  `HEADER_LEN = 384`) encodes the BUILT layout — `opTag, proofSystemId, chainId, token, …`. The SPECIFIED 416-byte header
  inserts `chainUid` as word 3 (offset 96) and moves every later field 32 bytes on; the prover's change is
  `HEADER_LEN = 416` and one `be32(chain_uid)` word after `chain_id` (stream MT-6). No other difference.

## 4. Changes to current rules (on acceptance)

| Rule | Change |
|---|---|
| [CTR-MTX-07](../../contracts/metatx.md#CTR-MTX-07), [CTR-MTX-16](../../contracts/metatx.md#CTR-MTX-16) | two bases (GC-2) |
| [CTR-MTX-15](../../contracts/metatx.md#CTR-MTX-15) | two structs, typehashes, KATs (GC-1) |
| [CTR-MTX-17](../../contracts/metatx.md#CTR-MTX-17) | generic pipeline without shapes (GC-3); typed pipeline (GC-4) |
| [CTR-MTX-01](../../contracts/metatx.md#CTR-MTX-01), [CTR-MTX-08](../../contracts/metatx.md#CTR-MTX-08) | payment and the payee check move to `MetaTransfer` |
| [CTR-MTX-09](../../contracts/metatx.md#CTR-MTX-09), [CTR-MTX-10](../../contracts/metatx.md#CTR-MTX-10), [CTR-MTX-11](../../contracts/metatx.md#CTR-MTX-11), [CTR-MTX-21](../../contracts/metatx.md#CTR-MTX-21) | named functions build their kind; + `mtxExecuteTransfer`, `mtxBatchTransfer` (GC-5) |
| [CTR-MTX-05](../../contracts/metatx.md#CTR-MTX-05), [CTR-MTX-06](../../contracts/metatx.md#CTR-MTX-06) | `paymentDigest` = the `MetaTransfer` digest |
| [CTR-MTX-13](../../contracts/metatx.md#CTR-MTX-13), [CTR-MTX-20](../../contracts/metatx.md#CTR-MTX-20) | fee only where `_chargeFee` is overridden; `supportedModes()` per contract |
| [CTR-ACC-06](../../contracts/mandates.md#CTR-ACC-06), [CTR-ACC-07](../../contracts/mandates.md#CTR-ACC-07), `SubjectAccount` key management ([accounts.md](../../contracts/accounts.md)) | GC-6 |
| [CTR-TND-01](../../contracts/tender.md#CTR-TND-01) | deposit = `MetaTransfer` |
| [CTR-UA-19](../../contracts/accounts.md#CTR-UA-19) | GC-9 |
| [CTR-PQZ-15](../../contracts/pq-zether.md#CTR-PQZ-15), [CTR-ZTH-06](../../contracts/zether.md#CTR-ZTH-06), [CTR-ZTH-34](../../contracts/zether.md#CTR-ZTH-34) | GC-10 |
| node `job-api`, `submit-lanes`, `mesh`; `clients/signers-clientkeys.md`; `integration.md` | GC-8 |
| `TODO.md` | MT-1/MT-2 split the base (GC-2); MT-7 becomes "`MandateWallet`/`SubjectAccount` on `MetaTxBase`"; MT-8/MT-9 + both structs |

## 5. Open questions for the owner

Q1–Q3 of rev 1 answered (G8–G10). New in rev 3:

| # | Question | Recommendation |
|---|---|---|
| Q4 | `PqzToken` on `ERC20MetaTx` with the generic self-call (+ ≈ 0.25 M gas per op), dropping `PqzMetaTx` (GC-10)? | **answered (G11): exactly like Zether** |

## 6. Revision history

| Rev | Date | What |
|---|---|---|
| 1 | 2026-10-08 | First draft from the owner's chat answers G1–G7 |
| 2 | 2026-10-08 | Owner answers G8–G10: UA ledger split (GC-9), `SubjectAccount` signs as itself, names kept |
| 3 | 2026-10-08 | GC-10: `PqzToken` on the one base, bindings without `to`/`value`, prover header check |
| 4 | 2026-10-08 | Owner G11: PQZ like Zether; no open question left |
