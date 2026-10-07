# Mandates

A mandate lets a delegate pay from a payer's own wallet within limits the chain enforces: per payment, per period,
to approved payees, until an expiry, revocable at any time. It is a payment authority, not an account: the payer keeps
its own account ([accounts.md](accounts.md)) and the funds sit in its `MandateWallet`. Status: **BUILT**
(`smartcontracts/evm/src/wallet/`); revocation epoch **SPECIFIED**.

## `MandateWallet`

<a id="mandatewallet"></a>
<a id="CTR-ACC-06"></a>**CTR-ACC-06** — **Delegated payment uses a dedicated `MandateWallet`, never an allowance.** One
smart wallet per payer, owned by the payer's EOA: it holds the funds (the payer deposits into it), implements ERC-1271
for its owner (so the owner can still pay by hand from it with a meta-tx, ECDSA owners), and stores per-token mandates
`{delegate, expiry, periodSeconds, periodStart, maxPerPayment, maxPerPeriod, spentInPeriod}` plus allowed payees. The
owner sets the payees — the partner's approved receiving addresses. `payUnderMandate(token, payee, amount, entryRef,
validUntil, sig)` checks on chain: not revoked, not expired, payee allowed, ≤ the per-payment cap, ≤ the per-period
cap, `entryRef` unused (anti-replay) and the delegate's EIP-712 signature (`PayUnderMandate(address token,address
payee,uint256 amount,bytes32 entryRef,uint256 validUntil)`), then pays through
`IERC20Payment.payWithFee(to, amount, NONE, 0, 0, entryRef)` — the direct payment path that `IERC20Payment` already
has, `msg.sender` = the wallet — no allowance. Kill switch: `revoke(token)` by the owner, or `revokeWithSig` by the
delegate (so a platform revokes at once through a relayer). `PaymentSettled` still carries `entryRef`, so
reconciliation is exactly that of a manual payment (the design sketch was `payUnderMandate(order, delegateSig)`). Why a wallet per payer rather than an allowance to one shared mandate contract: a
bug in one mandate touches only the funds deposited in that wallet, and no `approve` step for which the EOA would pay
gas is needed; the cost is that the payer deposits into the wallet instead of keeping funds in its EOA. Equivalent
mandates exist on Cosmos, Soroban, Sui, Aptos, TON and Solana. The wallet is deployed outside the client system (for
example `forge create … --constructor-args <owner>`); clients record only its address.

<a id="revocation-epoch"></a>
<a id="CTR-ACC-07"></a>**CTR-ACC-07** — **A signed mandate revocation is bound to the mandate's epoch.** `MandateWallet`
keeps `epoch[token]` (uint64), incremented by every `setMandate` and every revoke; the signed revoke becomes
`RevokeMandate(address token,uint64 epoch,uint256 validUntil)` and `revokeWithSig` requires `epoch == epoch[token]`,
so a public revoke signature cannot be replayed until its `validUntil` to delete a mandate the owner re-established.
The typehash change applies to dev deployments only (no production wallet exists); the built wallet has the old
`RevokeMandate(address token,uint256 validUntil)` and no epoch; the client digest builders and the forge KAT change
together. EVM only: the Solana mandate binds a generation, and the Sui/Aptos/Cosmos mandates are one-shot. Tests:
revoke, `setMandate` again, replay ⇒ `BadSignature`/`StaleEpoch`; a current-epoch revoke works; client digest == forge
vector. Status **SPECIFIED**.

**Hedera ED25519 owners** pay from a `MandateWallet` only through `HederaMandateWallet.executeAsOwnerRaw`
(`HederaMandateWallet.sol`): ERC-1271 runs under STATICCALL, where HIP-632 `isAuthorizedRaw` halts, so a meta-tx with
`from = wallet` works for ECDSA owners only; the raw call is relayed as a `call` job or sent by the owner
([NET-HED-03](../networks/hedera.md#NET-HED-03)).

| Entry point | Rule |
|---|---|
| `setMandate(token, delegate, maxPerPayment, maxPerPeriod, periodSeconds, expiry)`, `setPayee` | owner |
| `revoke` | owner; bumps `epoch[token]` |
| `payUnderMandate(token, payee, amount, entryRef, validUntil, sig)` | anyone submits; delegate-signed `PayUnderMandate` |
| `revokeWithSig` | delegate-signed `RevokeMandate(address token,uint64 epoch,uint256 validUntil)` |
| `executeAsOwner`, `isValidSignature` | owner |

### Client integration (auto-pay)

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
  adapter, delegated signs `PayUnderMandate` and pushes a `call` job to `MandateWallet.payUnderMandate`. Every signature
  passes the signing-policy checks (target token, `pay` op, caps, `validUntil − now ≤ 300 s`; the signing-policy service, `SigningPolicyService`, applies `validUntil ≤ 300 s`). A failure marks the
  run `failed` and is raised, never silent; the kill switch also queues a `revokeWithSig` job for delegated wallets. The node executes such `call` jobs only for
  allowlisted selectors and targets ([NODE-JOB-01](../node/job-api.md#NODE-JOB-01)), so it is never a "blind signer" of
  client-built calldata.
