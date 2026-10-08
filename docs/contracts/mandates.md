# Mandates

A mandate lets a delegate pay from a payer's own wallet within limits the chain enforces: per payment, per period,
to approved payees, until an expiry, revocable at any time. It is a payment authority, not an account: the payer keeps
its own account ([accounts.md](accounts.md)) and the funds sit in its `MandateWallet`. Status: **BUILT**
(`smartcontracts/evm/src/wallet/`); revocation epoch, the `mtx` names and the salted domain **SPECIFIED**.

## `MandateWallet`

<a id="mandatewallet"></a>
<a id="CTR-ACC-06"></a>**CTR-ACC-06** — **Delegated payment uses a dedicated `MandateWallet`, never an allowance.** One
smart wallet per payer, owned by the payer's EOA: it holds the funds (the payer deposits into it), implements ERC-1271
for its owner (so the owner can still pay by hand from it with a meta-tx, ECDSA owners), and stores per-token mandates
`{delegate, expiry, periodSeconds, periodStart, maxPerPayment, maxPerPeriod, spentInPeriod}` plus allowed payees. The
owner sets the payees — the partner's approved receiving addresses. The wallet is a `MetaTxBase` contract
([CTR-MTX-22](metatx.md#CTR-MTX-22)): every signed action is a `MetaTransaction` self-call, fee mode `NONE`. The
delegate signs `MetaTransaction{from: delegate, data: payUnderMandate(token, payee, amount, entryRef), …}`; the
function checks on chain `_msgSender() == mandate.delegate`, not revoked, not expired, payee allowed, ≤ the per-payment
cap, ≤ the per-period cap and `entryRef` unused (it stays the payment reference and single-use per wallet), then pays
through
`IERC20Payment.payWithFee(to, amount, NONE, 0, 0, entryRef)` — the direct payment path that `IERC20Payment` already
has, `msg.sender` = the wallet — no allowance. Kill switch: `revoke(token)` by the owner (directly or signed with
`from` = the owner), or `revoke(token, epoch)` signed by the delegate (so a platform revokes at once through a relayer,
[CTR-ACC-07](#CTR-ACC-07)). The named entry points `mtxPayUnderMandate(token, payee, amount, entryRef, validUntil, sig)`,
`mtxRevoke(token, epoch, validUntil, sig)` and `mtxExecuteAsOwner(data, nonce, validUntil, sig)` keep their signatures
and only build the matching `MetaTransaction`; their signatures carry no lane, so they derive it as `mtxPay` does:
`mtxPayUnderMandate` → `batch = uint256(keccak256("scaas.mandate.pay" ‖ entryRef))`, `nonce = 0` (one payment per
`entryRef`); `mtxRevoke` → `batch = uint256(keccak256("scaas.mandate.revoke" ‖ token ‖ epoch))`, `nonce = 0`;
`mtxExecuteAsOwner` → `batch = 0`. The lane nonce replaces the replay checks of the earlier typed structs. `PaymentSettled` still carries `entryRef`, so
reconciliation is exactly that of a manual payment (the design sketch was `payUnderMandate(order, delegateSig)`). Why a wallet per payer rather than an allowance to one shared mandate contract: a
bug in one mandate touches only the funds deposited in that wallet, and no `approve` step for which the EOA would pay
gas is needed; the cost is that the payer deposits into the wallet instead of keeping funds in its EOA. Equivalent
mandates exist on Cosmos, Soroban, Sui, Aptos, TON and Solana. The wallet is deployed outside the client system (for
example `forge create … --constructor-args <owner> <chain_uid>`); clients record only its address. Its EIP-712 domain
is `("SCaaS MandateWallet","1", chainId, wallet, salt = chain_uid)` with `chain_uid` a constructor argument from the
chain profile ([CTR-GEN-05](README.md#CTR-GEN-05)); because the deployer chooses that value per wallet, the node checks
the wallet's `chainUid()` against the chain profile before relaying anything for it. **Transitional (BUILT):** the
entry points are named `payUnderMandate(token, payee, amount, entryRef, validUntil, sig)`, `revokeWithSig` and
`executeAsOwner`, each verifying its own typed struct (`PayUnderMandate(address token,address payee,uint256
amount,bytes32 entryRef,uint256 validUntil)`, `RevokeMandate(…)`, the owner call) instead of a `MetaTransaction`, and
the domain has no `salt`; the renames follow [CTR-MTX-21](metatx.md#CTR-MTX-21), the move onto `MetaTxBase`
[CTR-MTX-22](metatx.md#CTR-MTX-22).

<a id="revocation-epoch"></a>
<a id="CTR-ACC-07"></a>**CTR-ACC-07** — **A signed mandate revocation is bound to the mandate's epoch.** `MandateWallet`
keeps `epoch[token]` (uint64), incremented by every `setMandate` and every revoke; the delegate's signed revoke is a
`MetaTransaction` with `data = revoke(token, epoch)` on the lane `keccak256("scaas.mandate.revoke" ‖ token ‖ epoch)`,
and `revoke(address,uint64)` requires `epoch == epoch[token]`, so a public revoke signature cannot be replayed until
its `validUntil` to delete a mandate the owner re-established. The built wallet has the typed `RevokeMandate(address
token,uint256 validUntil)` and no epoch; the client digest builders and the forge KAT change together. EVM only: the Solana mandate binds a generation, and the Sui/Aptos/Cosmos mandates are one-shot. Tests:
revoke, `setMandate` again, replay ⇒ `BadSignature`/`StaleEpoch`; a current-epoch revoke works; client digest == forge
vector. Status **SPECIFIED**.

**Hedera ED25519 owners** pay from a `MandateWallet` only through `HederaMandateWallet.mtxExecuteAsOwnerRaw`
(`HederaMandateWallet.sol`): ERC-1271 runs under STATICCALL, where HIP-632 `isAuthorizedRaw` halts, so a meta-tx with
`from = wallet` works for ECDSA owners only; the raw call is relayed as a `call` job or sent by the owner
([NET-HED-03](../networks/hedera.md#NET-HED-03)).

| Entry point | Rule |
|---|---|
| `setMandate(token, delegate, maxPerPayment, maxPerPeriod, periodSeconds, expiry)`, `setPayee` | owner |
| `revoke` | owner; bumps `epoch[token]` |
| `payUnderMandate(token, payee, amount, entryRef)` | delegate-signed `MetaTransaction` (`mtxExecute`, or the named `mtxPayUnderMandate(token, payee, amount, entryRef, validUntil, sig)`); anyone submits |
| `revoke(token, epoch)` | delegate-signed `MetaTransaction` (`mtxExecute`, or the named `mtxRevoke`) |
| `mtxExecuteAsOwner` (owner-signed `MetaTransaction`), `isValidSignature` | owner |

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
  adapter, delegated signs the `payUnderMandate` `MetaTransaction` and pushes a `call` job to `MandateWallet.mtxPayUnderMandate`. Every signature
  passes the signing-policy checks (target token, `pay` op, caps, `validUntil − now ≤ 300 s`; the signing-policy service, `SigningPolicyService`, applies `validUntil ≤ 300 s`). A failure marks the
  run `failed` and is raised, never silent; the kill switch also queues a `mtxRevoke` job for delegated wallets. The node executes such `call` jobs only for
  allowlisted selectors and targets ([NODE-JOB-01](../node/job-api.md#NODE-JOB-01)), so it is never a "blind signer" of
  client-built calldata.
