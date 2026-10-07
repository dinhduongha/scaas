# Subject accounts, passkeys and mandates

Two optional smart-account contracts sit next to the tokens: `SubjectAccount`, a multi-key ERC-1271 account with
passkeys and guardian recovery, and `MandateWallet`, a payer's own wallet that lets a delegate pay within on-chain
limits. The default identity of a subject is its native account or a Universal Account
([universal-account.md](universal-account.md)); these contracts add rotation, recovery and delegated payment where a
subject needs them. Status: **BUILT** (`smartcontracts/evm/src/{account,wallet}/`); revocation epoch **SPECIFIED**.

## `SubjectAccount`

<a id="subjectaccount"></a>
<a id="CTR-ACC-09"></a>**CTR-ACC-09** — **`SubjectAccount` is option (b), kept as built**: an optional ERC-1271 smart
account (P-256 + secp256k1 keys, guardian recovery, Merkle batch) for users who need a stable address across key
rotation, guardian recovery, or compatibility with third-party contracts that only understand `address`. It is a
native id (an `evm-contract` id in the UA kind table); it never registers. **The default is UA kinds verified directly
by the tokens** ([CTR-UA-02](universal-account.md#CTR-UA-02)); rotation and recovery are account features, not
identifier features. Tokens verify a `SubjectAccount` through ERC-1271 with the 400 k cap for its clones
([CTR-ACC-05](#CTR-ACC-05)). Non-EVM equivalents (Sui/Aptos/Solana/Soroban accounts) keep their role likewise.

- When to offer it: the subject asks for recovery without moving funds, wants one address across key changes, or must
  interact with third-party contracts that only understand `address`.
- Keys: multiple authorized keys (`P256_WEBAUTHN(x, y, rpIdHash, originHash)`, `SECP256K1(address)`), never zero keys (`LastKey`);
  guardian `initiateRecovery(newKey)` → anyone `completeRecovery` after `RECOVERY_DELAY`. Its
  `SECP256K1` keys come from the role path `m/7622'/0'/<account>'/2'/<i>'` ([CLI-SGN-30](../clients/signers-clientkeys.md#CLI-SGN-30)),
  never from the EOA path (the factory salt and the 400 k cap as built: `SubjectAccountFactory.sol:21-23`,
  `MetaToken.sol:141-144`); registering a key whose address equals the subject's own EOA (its payer address) on the
  same account is refused ([CLI-SGN-07](../clients/signers-clientkeys.md#CLI-SGN-07)). Its P-256 keys are passkeys
  (per `rpId`). A passkey that is a `webauthn-p256` UA may **also** be a `SubjectAccount` key: same kind, same
  WebAuthn scheme, digests differ (the account's challenge is the token's EIP-712 digest with `from` = the account);
  allowed.
- Key management: `addKey`/`removeKey`/`rotateKey`/`setGuardian`/`execute` only through `executeAsOwner(data, nonce,
  validUntil, signature)` signed by an existing key (own nonce, EIP-712 `OwnerCall(bytes data,uint256 nonce,uint256
  validUntil)` in the account's own domain `"SCaaS SubjectAccount"`). A plain EOA never rotates.
- The client backup predicate ([CLI-SGN-13](../clients/signers-clientkeys.md#CLI-SGN-13)) applies to it unchanged;
  derived UAs are "single-key, no recovery" by construction and the app shows that.
- `msig` UAs may list a `SubjectAccount` as a member (native contract member).
- Seed and passkey back each other up: the seed-derived key is the natural recovery key when a passkey is lost, and
  vice versa.

<a id="factory"></a>
<a id="CTR-ACC-01"></a>**CTR-ACC-01** — `SubjectAccountFactory` deploys **EIP-1167 clones** (`Clones.cloneDeterministic`)
and runs `initialize` in the same transaction; salt = `keccak256(abi.encode(firstKey, guardian))`. The guardian is
in the salt: with a salt of the first key alone, whoever deployed first would choose the guardian (a front-run that
takes the recovery power). Clones make a deploy ~287 k gas instead of several million (the P-256 verifier lives in
the implementation). `deploy` is idempotent: a repeat returns the existing address and does not revert; `predict`
gives the address in advance, so the client enqueues the deploy job before the subject's first payment (deploying
needs no permission: whoever deploys gets the same account for the same key and guardian).

<a id="signature-encoding"></a>
<a id="CTR-ACC-02"></a>**CTR-ACC-02** — A `SubjectAccount` signature is `abi.encode(uint256 keyIndex, bytes32[] proof,
bytes sig)`. An empty `proof` ⇒ the signed message is the digest; a non-empty one ⇒ the message is
`MerkleProof.processProof(proof, leaf)`, `leaf = keccak256(keccak256(0x00 ‖ digest))` (node pairs sorted as in
OpenZeppelin). A one-item batch signs the digest directly. P-256: `sig = abi.encode(authenticatorData,
clientDataJSON, r, s)`, challenge = base64url(message). secp256k1: `sig` is a 65-byte ECDSA signature (low-s) over the
raw message.

<a id="recovery"></a>
<a id="CTR-ACC-03"></a>**CTR-ACC-03** — **Guardian recovery adds a key; it removes none.** The guardian calls
`initiateRecovery(newKey)`; after `RECOVERY_DELAY = 2 days` anyone calls `completeRecovery(newKey)` ⇒ the key is
**added** (recovery is for a LOST key; a STOLEN key could already spend through meta-transactions and needs no
recovery). An existing key cancels through `executeAsOwner(cancelRecovery)`; `setGuardian` cancels a pending recovery.
The guardian may be a multisig contract. Watching `RecoveryInitiated` events is the owner's defence against a
compromised guardian (the 2-day delay plus cancel by key).

<a id="signcount"></a>
<a id="CTR-ACC-04"></a>**CTR-ACC-04** — The authenticator `signCount` is not checked: synced passkeys always return 0.

<a id="erc1271-cap"></a>
<a id="CTR-ACC-05"></a>**CTR-ACC-05** — **The 400 k ERC-1271 gas cap is only for `SubjectAccount` clones.** `MetaToken`
pins the chain's `SubjectAccount` implementation (constructor parameter, immutable); `ERC20MetaTx._erc1271Gas(from)`
defaults to 50 k, and `MetaToken` (and every v2 tier through `SUBJECT_ACCOUNT_IMPL`) grants 400 k **only** when
`from.codehash` is the EIP-1167 clone code of that implementation, because a Solidity P-256 verifier costs ~200–330 k
gas on chains without the precompile. Other contract wallets (Safe, …) keep 50 k. `Deploy.s.sol` deploys
`SubjectAccountFactory` before the token and records its address in `deployments/<chainid>.json`. The same rule is
applied by `OrderBookDex` ([CTR-DEX-08](dex.md#CTR-DEX-08)) and `ZetherMetaTx` ([CTR-ZTH-21](zether.md#CTR-ZTH-21)).

**Documented limitation.** `SubjectAccount.isValidSignature` accepts any digest signed by any of its keys —
ERC-1271 digests are not account-wrapped (the ERC-7739 class). SCaaS digests bind `from`/`verifyingContract`, so none
of ours replay across accounts; a third-party protocol that trusts the same key on two accounts is exposed. Wrapping
is rejected for now: it would change every 1271 digest, every KAT and every client builder.

| Function | Rule |
|---|---|
| `initialize(firstKey, guardian)` | factory only, once |
| `isValidSignature(digest, sig)` | ERC-1271; [CTR-ACC-02](#CTR-ACC-02) encoding |
| `executeAsOwner(data, nonce, validUntil, signature)` | self-call of `addKey`/`removeKey`/`rotateKey`/`setGuardian`/`execute`; the nonce increments before the call |
| `initiateRecovery` / `completeRecovery` / `cancelRecovery` | [CTR-ACC-03](#CTR-ACC-03) |
| factory `predict`, `deploy` | idempotent, [CTR-ACC-01](#CTR-ACC-01) |

Key lifecycle per family ([NET-ALL-05](../networks/README.md#NET-ALL-05) is normative; gaps are planned work):

| Family | Rotation | Guardian / recovery | Gap |
|---|---|---|---|
| EVM | `SubjectAccount` add/remove/rotate via `executeAsOwner` | guardian + `RECOVERY_DELAY` | — |
| Hedera | native account key update (no `SubjectAccount`) | native | — (stated) |
| Aptos | account keys + origins | guardian + `RECOVERY_DELAY` | — |
| Sui | per subject `Keys` object, shared by every `Account<T>` of the subject | guardian on `Keys` | planned (today per `Account<T>`) |
| Soroban | account-authorised add/remove | **seam only** | guardian + delayed recovery planned |
| Cosmos | **none** (passkey address = hash of key + rp + origin) | **none** | passkey account contract with rotation planned |
| TON | wallet key follows the owner's wallet; **a passkey cannot rotate** | **none** | guardian + delayed passkey rotation planned |
| Solana | KeyOp add/remove/policy | `start_recovery` / `finish_recovery` | — |

## Passkeys on chain

<a id="passkeys"></a>
<a id="CTR-ACC-08"></a>**CTR-ACC-08** — Portal and mobile subjects sign with **WebAuthn P-256 passkeys** (owner). An
assertion `{authenticatorData, clientDataJSON, r, s}` carries `challenge = base64url(operation digest)` (the EIP-712
digest on EVM, the family's typed digest elsewhere). A subject account or contract on each family stores the
passkeys; operations signed by a passkey travel the family's meta-tx path. Batching: one assertion over a Merkle root
of digests (keccak on EVM, SHA-256 elsewhere), leaf `keccak256(keccak256(0x00 ‖ digest))` (second-preimage safe);
each operation carries `(keyIndex, proof, sig)` — one biometric prompt for N lines, each still bound to the signed
root. The key lifecycle runs through the account ([NET-ALL-05](../networks/README.md#NET-ALL-05)); the grammar and the
check order are one rule for every family ([NET-ALL-04](../networks/README.md#NET-ALL-04)); custodial and mandate
wallets remain the only place a server signs, explicitly delegated and limited.

Verifier checks, in order: `authenticatorData` ≥ 37 bytes; `rpIdHash` (its first 32 bytes) equals the stored one
(`SHA-256(rpId)`); flags UP **and** UV; `clientDataJSON` matches exactly
`{"type":"webauthn.get","challenge":"<b64url(digest)>","origin":"<origin>"` followed by `}` (end), or by
`,"crossOrigin":false` and then `}` (end) or `,`; the origin equals a stored origin **exactly** (stored per key as
`keccak(origin)` on EVM; no prefix match); `s ≤ n/2` (low-s; WebAuthn returns DER and authenticators do not enforce
low-s, so clients convert DER to `(r, s)` and normalize `s := n − s` when `s > n/2`, still valid); then P-256 over
`sha256(authenticatorData ‖ sha256(clientDataJSON))`. The EVM check (`type == "webauthn.get"`, the challenge, the
origin) is the bounded WebAuthn Level 3 algorithm (§5.8.1.2 of the standard): a fixed prefix, the origin up to the
next `"`, then only the two endings above (the EVM `_clientDataOk` grammar); a browser that orders members
differently fails closed. Shared vectors `smartcontracts/test/vectors/webauthn_kat.json` (accept shapes of Safari
Level 2 and Chrome/Firefox Level 3; rejects: `crossOrigin:true`, `topOrigin`, a member before `crossOrigin`,
whitespace, a suffixed origin such as `https://a.example.evil` against a stored `https://a.example`, wrong rpIdHash,
UV unset, high-s, another digest) run in every family's suite. Built gaps closed by planned fixes: Cosmos checks
neither rpIdHash, origin nor UV; Sui, Soroban, TON and Solana do not refuse `crossOrigin: true`; the built TON check
accepts a suffixed origin.

Per family: EVM/Hedera `SubjectAccount` (ERC-1271; P-256 via OpenZeppelin 5.2 `P256.verify`, which calls the
RIP-7212 precompile `0x100` when present, else the Solidity verifier); Sui `secp256r1_verify`/passkey; Soroban
`secp256r1_verify` (CAP-51) in a custom account; Cosmos `secp256r1_verify` (cosmwasm-std 2.1+); Aptos pure-Move
P-256; Solana Secp256r1 precompile; TON passkey auth kind in the jetton wallet. Merkle batching under one assertion
exists today on EVM and Soroban only; the other families verify one digest per assertion. The client side
(`clientkeys/src/passkey-signer.js`: `creationOptions` with PRF enabled by default, `requestOptions`, `derToRS`,
`encodeAssertion = abi.encode(authenticatorData, clientDataJSON, r, s)`, `merkleBatch`, `accountSignature =
abi.encode(keyIndex, bytes32[] proof, sig)`) is [CLI-SGN-09](../clients/signers-clientkeys.md#CLI-SGN-09).

Tests: real WebAuthn vectors — generated by a software authenticator (fixed P-256 key, correct WebAuthn format) and a
published vector suite; failure cases; batch; key lifecycle; recovery; a `MetaToken` `pay` signed by a passkey and by
a seed key; precompile and Solidity gas; end to end: add a second key (seed when a passkey exists) and sign with each.

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

## Limitations

- **Scoped receiver-fee key** (PLANNED): a `SubjectAccount` key kind that validates only `ReceiverFee` preimages with a
  fee cap, so that a payee's co-signing key ([CTR-MTX-05](metatx.md#CTR-MTX-05)) need not control its wallet. Until
  then the co-signing wallet is a hot collection wallet.
- ERC-1271 digests are not account-wrapped (above).
