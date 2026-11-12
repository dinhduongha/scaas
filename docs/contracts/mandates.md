# Mandates

A mandate lets a delegate pay from a payer's own wallet within limits the chain enforces: per payment, per period,
to approved payees, until an expiry, revocable at any time. It is a payment authority, not an account: the payer keeps
its own account ([accounts.md](accounts.md)) and the funds sit in its `MandateWallet`. Status: **BUILT**
(`smartcontracts/evm/src/wallet/`; the typed-struct wallet of P4 is in `legacy/p4/`). Since the `ua*` / `mtx*` merge
([CTR-MTX-30](metatx.md#CTR-MTX-30)) the wallet is on `UAMetaTxBase`, its ids are `bytes32` and each operation has
one signed entry ([CTR-ACC-12](#CTR-ACC-12)): **BUILT** on branch `ua-mtx-merge` (T3b), UNAUDITED; the address-only
wallet and its flat builders are in `smartcontracts/evm/legacy/ua-mtx-merge/`.

## <a id="mandatewallet"></a>1. `MandateWallet`

<a id="mandatewallet"></a>
<a id="CTR-ACC-06"></a>**CTR-ACC-06** — **Delegated payment uses a dedicated `MandateWallet`, never an allowance.** One
smart wallet per payer, owned by the payer (an EOA's padded address or a derived UA, [CTR-ACC-12](#CTR-ACC-12)): it holds the funds (the payer deposits into it), implements ERC-1271
for its owner (so the owner can still pay by hand from it with a meta-tx, ECDSA owners), and stores per-token mandates
`{delegate, expiry, periodSeconds, periodStart, maxPerPayment, maxPerPeriod, spentInPeriod}` plus allowed payees. The
owner sets the payees — the partner's approved receiving addresses. The wallet is a `UAMetaTxBase` contract
([CTR-MTX-22](metatx.md#CTR-MTX-22)): every signed action is a named `UA<Op>` entry or a `UAMetaTransaction` self-call,
fee mode `NONE`. The delegate signs `UAPayUnderMandate(bytes32 from, address token, bytes32 payee, uint256 amount,
bytes32 entryRef, uint64 epoch, …envelope)`; the function checks on chain `_subject() == mandate.delegate`, `epoch == epoch[token]` (`StaleEpoch`), not revoked, not expired, payee allowed, ≤ the per-payment
cap, ≤ the per-period cap and `entryRef` unused (it stays the payment reference and single-use per wallet), then pays
through `IERC20Payment.payWithFee(to, amount, NONE, 0, 0, entryRef)` (a native payee) or `payWithFeeToUA` (a derived one,
[CTR-UA-28](accounts.md#CTR-UA-28)) — the direct payment path, `msg.sender` = the wallet — no allowance. Kill switch: `revoke(token)` by the owner (directly or signed with
`from` = the owner), or `revoke(token, epoch)` signed by the delegate (so a platform revokes at once through a relayer,
[CTR-ACC-07](#CTR-ACC-07)).

**Signed entries (the merge, [CTR-ACC-12](#CTR-ACC-12)).** One signed entry per operation, each over its own struct
in the wallet's domain, `mtx<Op>(MetaTxLib.UAEnvelope e, <the operation's parameters, bytes32 ids>, IUARegistry.UASig auth)`:
the owner's `mtxSetMandate` (`UASetMandate`), `mtxSetPayee` (`UASetPayee`), `mtxRevokeMandate` (`UARevokeMandate`) and
`mtxExecute(e, target, value, data, auth)` (`UAExecute`, `data` signed as its hash); the delegate's
`mtxPayUnderMandate(e, token, payee, amount, entryRef, epoch, auth, meta)` (`UAPayUnderMandate`, `meta` outside the struct)
and `mtxDelegateRevoke(e, token, epoch, auth)` (`UADelegateRevoke`). The delegate's `batch` is the signer's: the node puts
them on `mandatePayLane(entryRef) = uint256(keccak256("scaas.mandate.pay" ‖ entryRef))` and
`mandateRevokeLane(token, epoch) = uint256(keccak256("scaas.mandate.revoke" ‖ token ‖ epoch))` at nonce 0 (`‖` is
`abi.encodePacked`, the epoch 8 bytes); `refUsed` and `epoch` stop a second signature for the same payment or revoke.
From `UAMetaTxBase`: the generic `mtxExecute(UAMetaTransaction, UASig)` / `mtxBatch` and the ordered `mtxCancelNonce`.
`executeMetaTransaction` refuses every call (`MtxSelectorNotAllowed`, MD-11 (b) in
[CTR-MTX-30](metatx.md#CTR-MTX-30)): the EIP-1776 alias is the token's exception. The flat builders of P4
(`mtxPayUnderMandate(token, payee, amount, entryRef, epoch, validUntil, sig)`, `mtxRevoke`, `mtxExecuteAsOwner`, Hedera's
`mtxExecuteAsOwnerRaw`) and `mandate_pay_kat.json` / `mandate_revoke_kat.json` are in `legacy/ua-mtx-merge/` (MD-11 (a),
owner 2026-11-05). `PaidUnderMandate` and the token's payment event carry `entryRef`, so reconciliation is exactly that of
a manual payment (the design sketch was `payUnderMandate(order, delegateSig)`).

**Why a wallet per payer** rather than an allowance to one shared mandate contract: a
bug in one mandate touches only the funds deposited in that wallet, and no `approve` step for which the EOA would pay
gas is needed; the cost is that the payer deposits into the wallet instead of keeping funds in its EOA. Equivalent
mandates exist on Cosmos, Soroban, Sui, Aptos, GRAM and Solana. The wallet is deployed outside the client system (for
example `forge create … --constructor-args <owner> <chain_uid>`); clients record only its address.

**Domain.** Its EIP-712 domain
is `("SCaaS MandateWallet","1", chainId, wallet, salt = chain_uid)` with `chain_uid` a constructor argument from the
chain profile ([CTR-GEN-05](README.md#CTR-GEN-05)); because the deployer chooses that value per wallet, the node checks
the wallet's `chainUid()` against the chain profile before relaying anything for it.

**Errors** (besides the base's): `NotOwner`, `NotDelegate` (`_msgSender()` is not the mandate's delegate), `NoMandate`,
`MandateExpired`, `PayeeNotAllowed`, `OverPaymentCap`, `OverPeriodCap`, `RefAlreadyPaid`, `StaleEpoch(current, signed)`,
`BadMandate`, `PayFailed` (a token answering false: the whole payment reverts), `CallFailed`, `ZeroOwner`.

Delegated payment and the kill switch, as a sequence:

```mermaid
sequenceDiagram
    participant O as Payer (owner)
    participant D as Delegate
    participant R as Relayer
    participant W as MandateWallet
    O->>W: deposit funds, setMandate, setPayee
    D->>R: signed UAPayUnderMandate(token, payee, amount, entryRef, epoch)
    R->>W: mtxPayUnderMandate (anyone may submit)
    W->>W: delegate, epoch current, not revoked, not expired, payee, caps, entryRef unused
    W->>W: payWithFee(to, amount, NONE, 0, 0, entryRef), no allowance
    W-->>R: PaymentSettled (entryRef)
    D->>R: signed UADelegateRevoke(token, epoch)
    R->>W: mtxDelegateRevoke
    Note over W: mandate removed, epoch[token] incremented
```

<a id="revocation-epoch"></a>
<a id="CTR-ACC-07"></a>**CTR-ACC-07** — **A signed mandate revocation is bound to the mandate's epoch.** `MandateWallet`
keeps `epoch[token]` (uint64), incremented by every `setMandate` and every revoke; the delegate's signed revoke is
`mtxDelegateRevoke` (struct `UADelegateRevoke`) on the lane `keccak256("scaas.mandate.revoke" ‖ token ‖ epoch)`,
and `revoke(address,uint64)` requires `epoch == epoch[token]`, so a public revoke signature cannot be replayed until
its `validUntil` to delete a mandate the owner re-established. **The delegate's pay names the epoch too** (controller ruling, pending the owner; the spec tied only the revoke to it):
`payUnderMandate(address token, bytes32 payee, uint256 amount, bytes32 entryRef, uint64 epoch, MetaTxLib.PayMeta meta)` (selector `0x03de743a` since the merge; `0x781fc8a8` before it, address payee and no `meta`) reverts `StaleEpoch(current, signed)` when `epoch != epoch[token]`; the
argument is in the signed `data`, so it binds every relay path (a lane would not: `mtxExecute` and `mtxBatch` accept any lane), and a relayer cannot restamp it (`MetaTxBadSignature`). A revoke, and any `setMandate` — also a plain expiry extension — void every queued delegate pay; the pay job re-reads `epoch(token)` and re-signs on `StaleEpoch`, and the kill-switch revoke job re-reads it after a `setMandate`. **`setMandate` keeps the running period** (same ruling): `periodStart` and `spentInPeriod` carry over when the delegate and `periodSeconds` are unchanged, otherwise both reset; expiry and caps always take the new values, so an extension does not double the window's allowance (revoke, then set, is the deliberate reset; so re-enabling the same delegate after a kill-switch starts a fresh period budget). **Periods are fixed windows on a grid** (review W-L; owner accepted 2026-10-19, including the 2× bound below): when a payment finds the period over, `periodStart` moves on by whole periods to the window that holds `now` (`periodStart += ⌊(now − periodStart) / periodSeconds⌋ · periodSeconds`), never to `now`, so an idle stretch does not let the delegate choose where a window begins; the grid starts where `setMandate` (or a reset) started the period. A fixed window still admits `maxPerPeriod` just before and again just after a boundary: at most `2 · maxPerPeriod` within any `periodSeconds`, at boundaries the owner can compute from `periodStart`; an owner who needs a hard bound per `periodSeconds` sets `maxPerPeriod` to half of it (a rolling window would need the payment history on chain). Test `test_period_windows_stay_on_the_grid`. **The epoch is predictable**: a delegate can pre-sign a pay for a future epoch, so a compromised delegate key is handled by setting a NEW delegate (`NotDelegate` kills every signature), not revoke + re-set of the same one. **An owner hand-pay and a delegate pay of the same `entryRef` can both pay**: `RefAlreadyPaid` covers only the wallet's delegate pays, so pay one way per invoice. Forge KATs `mandate_pay_kat.json` and `mandate_revoke_kat.json`, read by
clientkeys. EVM in P4 and **Soroban since UA-Soroban T6b** (owner 2026-10-30; one rule on every family): the Soroban mandate keeps `epoch(token)`, +1 on every `mtx_set_mandate` and revoke; the delegate's `mtx_revoke` and `mtx_mandate_pay` sign the epoch (UA `op_digest` or the native delegate's `require_auth_for_args`) and are `StaleEpoch` unless current, and the owner's `mtx_revoke` may pass any epoch ([NET-SOR-21](../networks/soroban.md#NET-SOR-21)). NEAR, Algorand, Cosmos and Solana get the epoch in their own family rounds (TODO); the Solana mandate binds a generation, and the Sui/Aptos/Cosmos mandates are one-shot until then. Tests:
revoke, `setMandate` again, replay ⇒ `StaleEpoch`; a stale pay ⇒ `StaleEpoch`; a current-epoch revoke works; client digest == forge
vector. Status **BUILT** (P4).

**Hedera** (controller ruling, pending the owner): `HederaMandateWallet` checks HIP-632 64-byte signatures from accounts without code on every entry, for the owner and the delegate, over the `UA<Op>` digest (`HederaMandateWallet is MandateWallet`, constructed with `hedera_ = true`); its
`mtxExecuteAsOwnerRaw` is in `legacy/ua-mtx-merge/` with the flat builders. ERC-1271 stays ECDSA (STATICCALL halts HIP-632), so an ED25519 owner pays by hand with an owner call `execute(token, payWithFee…)` ([NET-HED-03](../networks/hedera.md#NET-HED-03)).

| Entry point | Rule |
|---|---|
| `setMandate(token, delegate, maxPerPayment, maxPerPeriod, periodSeconds, expiry)`, `setPayee`, `execute` | owner (directly, or signed: `mtxSetMandate`, `mtxSetPayee`, `mtxExecute(e, target, value, data, auth)`) |
| `revoke(token)` | owner (directly, or signed: `mtxRevokeMandate`); bumps `epoch[token]` |
| `payUnderMandate(token, payee, amount, entryRef, epoch)` | delegate-signed `mtxPayUnderMandate`; anyone submits |
| `revoke(token, epoch)` | delegate-signed `mtxDelegateRevoke`; anyone submits |
| `isValidSignature` | a native owner (ECDSA); a derived owner gets `0xffffffff` |
| `executeMetaTransaction` | refused (`MtxSelectorNotAllowed`) |

<a id="ua-mandates"></a>
<a id="CTR-ACC-12"></a>**CTR-ACC-12** — **A UA may own, delegate and receive under a `MandateWallet`** (owner 2026-10-13,
[CTR-UA-27](accounts.md#CTR-UA-27); merged form owner 2026-11-04, Q6 of [CTR-MTX-30](metatx.md#CTR-MTX-30)). The
wallet's ids are `bytes32` (a native address zero-padded, or a derived UA): constructor `(bytes32 owner, bytes32 chainUid,
address registry, bool hedera)`, `Mandate.delegate` `bytes32`, `payeeAllowed[token][bytes32]`, and the events
`MandateSet`, `MandateRevoked`, `PayeeSet`, `PaidUnderMandate` and the error `PayeeNotAllowed` take `bytes32` ids. Every
authority check compares the subject of the call as an id (`_subject()`: the ticket's subject inside a self-call, else
`pad(msg.sender)`) with the stored id, never `_msgSender()`. Each wallet operation has exactly one signed entry,
`mtx<Op>(MetaTxLib.UAEnvelope e, <parameters>, IUARegistry.UASig auth)` over `UA<Op>` ([§1](#mandatewallet)), fee `NONE`
only: a native signer signs with its own key and no registry is called; a derived signer authenticates through the
registry (`UALedgerOff` when `registry` is 0). There are no `ua*` twins: the planned `uaExecute`, `uaPayUnderMandate`,
`uaRevoke`, `uaExecuteAsOwner` are not built. `_mtxRule` and `_uaAllowed` both list the six wallet operations, `cancelNonce`
on `_mtxRule` only. A native payee is paid by `payWithFee`, a derived one by `payWithFeeToUA`
([CTR-UA-28](accounts.md#CTR-UA-28)). **ERC-1271:** a native owner keeps `isValidSignature` (ECDSA over `erc1271Digest(hash)`,
bound to the wallet, [accounts.md CTR-ACC-02](accounts.md#erc1271-wrap)); a derived owner gets
none (`0xffffffff`): token and DEX callers cap ERC-1271 at 50 k gas (a PQ check needs up to 5.95 M), and a 1271 answer
would be a generic "sign this digest" for a UA key, which [CTR-UA-10](accounts.md#CTR-UA-10) layer 1 forbids; a derived
owner acts through the signed `mtxExecute(e, target, value, data, auth)`. `HederaMandateWallet` follows (HIP-632 on the
native branch). Status: **BUILT** on branch `ua-mtx-merge` (T3b; `src/wallet/MandateWallet.sol`,
`src/hedera/HederaMandateWallet.sol`; tests `test/wallet/MandateWalletMerged.t.sol`, `MandateWallet.t.sol`,
`NamedWallets.t.sol`), UNAUDITED; a wallet shows `bytes32` for `from`, `delegate` and `payee` (the spec's §6), and the
real-wallet display test (Q5) is not recorded yet.

### 1.1 Client integration (auto-pay)

How a client system uses mandates (the reference ERP implements it; the contract does not depend on it):

- Paying-wallet modes: `manual` (default; the user signs each payment from its own wallet), `custodial` (the platform
  signs through a custody adapter that holds the key — for a payer that is not the operating company itself this is
  holding someone else's keys and needs the appropriate licence reference), `delegated` (the platform's delegate key
  signs **within on-chain limits**; the address is the payer's `MandateWallet`; the payer keeps the owner key). Every
  wallet goes through four-eyes approval; a custodial wallet of a payer that is not a company needs a licence reference
  (`license_ref`).
- The custody adapter is a socket keyed by the scheme of a `signer_ref` with the interface `address(ref)`,
  `sign_digest(ref, digest32) -> 65 byte`; the `env:` scheme is dev-only (a flag plus a dev chain; it signs through OpenSSL via `cryptography`); production
  adapters (`broker:` — a custody broker over mTLS — KMS, HSM) plug into the same registry. No field, parameter or attachment ever holds a key.
- An auto-pay policy (payer, paying wallet, trigger on invoice posted or due, caps per payment/day/month, four-eyes
  state, kill switch) creates exactly one run per (policy, invoice, event) under a uniqueness constraint, so a retry
  never pays twice; it checks the caps, takes the payee from the issuing company's approved receiving wallet on the
  same chain and token, and then follows **the manual payment path**: custodial signs the meta-tx through the
  adapter, delegated signs `UAPayUnderMandate` (with the current `epoch(token)`) and pushes a job naming the merged `mtxPayUnderMandate` ([named entries](../node/job-api.md#named-entries)) on `mandatePayLane(entryRef)`, nonce 0. Every signature
  passes the signing-policy checks (target token, `pay` op, caps, `validUntil − now ≤ 300 s`; the signing-policy service, `SigningPolicyService`, applies `validUntil ≤ 300 s`). A failure marks the
  run `failed` and is raised, never silent; the kill switch also queues a `mtxDelegateRevoke` job for delegated wallets on `mandateRevokeLane(token, epoch)`, nonce 0 (the flat `mtxRevoke` is in legacy, MD-11 (a)). The node builds such calls itself from named fields, only for
  allowlisted entries and targets ([NODE-JOB-01](../node/job-api.md#NODE-JOB-01)), so it is never a "blind signer" of
  client-built calldata.
