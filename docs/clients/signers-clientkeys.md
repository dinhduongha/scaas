# Signers and clientkeys

How a subject's keys are created, stored and used on the client: wallet standards, passkeys, the seed vault, role
keys, the backup-key switch, family encoders and connectors, Zether keys, and the rules for what a signer may sign.
`clientkeys` is the JavaScript library shared by the SCaaS app ([clients/app](app.md)) and by any ERP portal; it signs
on the user's device and never sends secrets anywhere. Status: passkeys, the seed vault (v1) and Zether keys **BUILT**
(clientkeys 1.0.0, EVM-only family encoders); everything else here **SPECIFIED** unless marked.

## Scope

<a id="scope"></a>

In scope: (1) a deployment switch "backup key required" (default off); (2) vault v2, bound to the device by a
non-extractable WebCrypto key; (3) one scrypt cost, with the mobile failure mode handled; (4) Sui verification of added
and recovered keys (payload encoding in every client language, [NET-SUI-16](../networks/sui.md#NET-SUI-16)); (5) role keys
(`deriveRoleKey`) and seed signers for Soroban, Aptos and Solana; (6) non-EVM passkey signers; (7) wallet connectors for
every family as one implementation shared by app and portals.

Out of scope: UA ids, the registry, kind tags, `UAKey`/`signUA` internals and credentials
([contracts/accounts](../contracts/accounts.md#universal-account)); new contract code (an on-chain backup bit on
EVM/Sui/Aptos, Soroban/TON guardians, a Soroban duplicate-key check — the switch is only a toggle and client
de-duplication covers duplicates); KMS/HSM, the signing-policy service and FROST/MuSig2 signers (below, PLANNED);
WalletConnect and the TON Connect HTTP bridge (seams); ERP mirrors of non-EVM key sets (the node's simulation decides);
Argon2id (no WebCrypto primitive, and a wasm dependency without a measured need); vault export between devices and
showing the phrase again (the phrase on paper is the transfer format).

<a id="CLI-SGN-28"></a>**CLI-SGN-28** — **The signer rules add no account id, registry or key kind.** The backup
predicate takes "active key set + guardian" and works unchanged over Universal Account key sets; "Native single-key ⇒ outside" (the predicate) maps to the unregistered native kinds; `deriveRoleKey` is the UA tree path
([CLI-SGN-30](#CLI-SGN-30)). Account identity stays the family derivations as built (EVM CREATE2 salt, Sui
`derive_address`, Aptos object address, Solana PDA, the Cosmos passkey id); key-management entries ([NET-ALL-29](../networks/README.md#NET-ALL-29)) keep their
domains now and a `keyop` purpose bumps their version later.

## Custody axes

<a id="custody-axes"></a>

| Axis | Key | Purpose | Custody | Status |
|---|---|---|---|---|
| `auth_custody` | secp256k1 / ed25519 / P-256 signing keys | authorises spending (EIP-712, `MetaCall`/`MetaTransfer`, WebAuthn) | the subject's device (passkey, seed vault), a wallet extension, or — for entrusted custodial/delegated wallets — a KMS/HSM (FIPS 140-3 Level 3) behind a custody adapter | device BUILT; KMS/HSM adapters PLANNED |
| `conf_custody` | Zether `x` (bn254 / BLS12-381); post-quantum Zether 32-byte leaf | decrypts balances, builds proofs | the subject's device (seed path `…/7`; the PQ leaf sealed in the key worker); for organizations a threshold-MPC or enclave **key oracle** ([CLI-SGN-31](#CLI-SGN-31)) — commercial HSMs do not support these curves | device BUILT; key oracle PLANNED |

Leaking one axis does not compromise the other: a leaked signing key cannot read balances; a leaked `x` cannot move funds
(except `SELF_SCHNORR` accounts). Relayer lane keys are a third, unrelated class (gas only,
[NODE-LANE-08](../node/submit-lanes.md#NODE-LANE-08)); the node never needs `x`. "Keys in an HSM" applies to spending
keys; a Zether decryption key cannot be held by a commercial HSM.

<a id="organization-custody"></a>

<a id="CLI-SGN-32"></a>**CLI-SGN-32** — **A server-side key-oracle lane exists only when an organization holds a Zether
account.** Three separate axes: (1) custody of **users'** keys — non-custodial means no user `x` on any server; (2) the
organization's **own** Zether account — self-custody is still a key that must live somewhere; (3) whether Zether is used
at all — no Zether ⇒ no `x` exists. Per money flow: loyalty/rewards and end-user payments at a counter keep `x` on the
device (the prover runs there; no oracle); treasury mint/pause is ECDSA only; hot relayer EOAs need none; an auditor's
`y_audit` is a 3-of-5 threshold ElGamal key (decryption needs no proving); B2B settlement **without** Zether (the default
— Zether for B2B is optional, owner) needs none; B2B settlement **with** Zether uses `x` split Shamir 2-of-3, of which the
platform holds **one share** — it cannot spend alone. A treasury that only **receives** still needs `x` to read its own
balance (the value is `C · D^{-x}`; the memo key derives from `D^x`), so dropping the oracle there drops reconciliation:
the reconciliation result stays partial instead of clean. Owner decision. PLANNED.

<a id="key-oracle"></a>

<a id="CLI-SGN-31"></a>**CLI-SGN-31** — **The key oracle keeps no persistent state.** Two kinds of server key must never
share one interface: a **custody broker** (group A: `sign_digest_secp256k1`, `sign_raw_tx`, `attest`, key lifecycle — an
ordinary process proxying to KMS/HSM/MPC, used by lane signing and treasury operations, always present) and a **key
oracle** (group B: `zk_mul_by_x`, `zk_nonce_commit`, `zk_response`, `elgamal_decrypt` — an **enclave**, < 300 lines,
vsock only, called by the broker on the client's behalf, only when Zether is on). A relayer never needs `x`: it cannot
decrypt amounts, build proofs or change anything signed — its blindness is the security model. The oracle runs in its own
process, never inside the node (the node parses strangers' bytes; one memory bug next to `x` drains every account it
serves) and never inside the ERP (an ERP administrator can run arbitrary code; the ERP keeps a `signer_ref` handle,
never key material). The oracle interface is narrow and fixed — `zk_mul_by_x(points, ctx)`, `zk_nonce_commit(bases, ctx)`,
`zk_response(nonce_id, challenge)` — with no arbitrary `decrypt(C, D)`: with an attacker-chosen `D` it returns the log of
`C·D^{-x}`, an ECDH oracle on `x`, so `elgamal_decrypt` requires a `ChainWitness` proving that `(C,D)` is real on-chain
state. Between the relay process and the custody broker (mTLS, or a Unix socket on one host) the broker takes the tenant
from the client certificate only, never from a `tenant_uuid` in the body. What it stores:

| State | Where | After a restart |
|---|---|---|
| `x` | never in clear: a wrapped blob in KMS/HSM, unwrapped into enclave memory at start, conditioned on PCR0 | unwrapped again; another image (PCR0) ⇒ KMS refuses ⇒ the enclave does not run |
| the signer's own transaction nonce | enclave memory | re-read from the chain (`getTransactionCount`) |
| replay cache `digest → seen` | enclave memory, TTL 24 h | **empty, and safe**: RFC 6979 ECDSA re-signs identically |
| open `nonce_id`s of `zk_nonce_commit` | enclave memory | **empty, and fail-closed** |
| `sendCounter` for the `s` PRF | not kept: read from the chain (`IZetherToken.sendCounter`) | nothing to lose |
| audit log of who asked to sign what | written **outside**, through the custody lane, to the client's security events | not lost |

The one rule that must never break: answering `zk_response` twice for one `k` with two challenges leaks `x = (s₁ − s₂) /
(c₁ − c₂)`, so an unknown or used `nonce_id` is **refused**:

```
zk_response(nonce_id, c):
    k = open_nonces.remove(nonce_id)     # remove, not get — single use
    if k is None: reject("unknown or already used nonce_id")
    return k + c * x mod r
```

Persisting that table would let an attacker roll the enclave back and get a second answer, so not persisting it is a
security feature. Operations note: restarting the oracle lane voids every proof being built (a 300-recipient payout
rebuilds the unfinished proofs at 30–50 ms CPU each; no signed transaction is lost, since transactions are signed only
after proofs complete). Owner decision. PLANNED.

## Signing policy

<a id="signing-policy"></a>

Every signature not made by a human on a device — custodial wallets, delegated mandates, AI agents — passes a policy check
**co-located with the signer** (not in the ERP), with an idempotency key per request. Agents use the same custody path as
users, bounded by policy. Checks before any signature:

1. Destination contract ∈ allowlist (token, mandate wallet, DEX).
2. Operation ∈ allowed ops/selectors (a payment `MetaTransfer`, the `MandateWallet` `payUnderMandate` call,
   `mtxExecute` with an allowed self-call selector, [CLI-SGN-34](#CLI-SGN-34); as built `payUnderMandate` and
   `executeMetaTransaction` with an allowed op);
   never `approve` on a SCaaS token — an EOA never approves one ([CLI-SGN-36](#CLI-SGN-36),
   [CTR-TOK-01](../contracts/token-wrappers.md#CTR-TOK-01)).
3. Amount ≤ per-call cap; cumulative ≤ hourly and daily caps (velocity, in the signer's own store).
4. `validUntil − now ≤ 300 s`.
5. Risk-class routing: class 1 (no value), class 2 (small value), class 3 (above the class-2 threshold, treasury or
   B2B outflow) ⇒ maker-checker, class 4 (governance/keys) ⇒ a quorum of ≥ 2 approvers distinct from the requester. Rescue/exit operations
   are never throttled.

Today an ERP client applies checks 1–4 in process before calling the dev-only environment custody adapter
([INT-ERP-08](../integration.md#INT-ERP-08)); the mandate path enforces caps on chain. The service itself (`SigningPolicyService`) is PLANNED; the dev adapter is the
`env:` custody adapter.

## Wallet standards

<a id="wallet-standards"></a>

EVM browser wallets are used only through open standards (EIP-1193, EIP-6963, EIP-712, EIP-1271, WalletConnect):

1. **Discovery (EIP-6963).** Dispatch `eip6963:requestProvider`, listen to `eip6963:announceProvider` for 400 ms,
   de-duplicate by `rdns`, show a chooser (names with `textContent`; icons only when `data:image/{png,jpeg,gif,webp,svg+xml}`
   and only through `<img src>` — never `innerHTML`). Remember the chosen `rdns` in `localStorage` (try/catch). No wallet
   answers ⇒ fall back to `window.ethereum` (EIP-1193). No JS library.
2. **Typed data** stays standard: the domain has `chainId` + `verifyingContract`, and (SPECIFIED) `salt = chain_uid`
   on every SCaaS domain ([CLI-SGN-33](#CLI-SGN-33)); every EIP-712 wallet can sign it. Wallets such as MetaMask sign
   the domain they are given and check only `chainId`, so the salt is checked by clientkeys, and enforced by the
   contract.
3. **Events:** `chainChanged`/`accountsChanged` cancel the running flow and tell the user (no polling); code `4001` = the
   user refused ⇒ a soft message, not an error.
4. **EIP-1271 (contract wallets):** on chain `ERC20MetaTx._requireValidSignature` calls `isValidSignature` (magic
   `0x1626ba7e`) when `from` has code (`_isContract(from)`, first written as `from.code.length > 0`; an EIP-7702
   designator counts as an EOA). A client without RPC does not know whether `from` has code, so the browser asks
   `eth_getCode` through the wallet's own provider and sends a `wallet_kind` hint: `eoa` ⇒ the signature must recover to
   the wallet as before; `contract` ⇒ the signature is accepted unchecked and the node's simulation (a real
   `isValidSignature`) decides ([INT-ERP-03](../integration.md#INT-ERP-03)). A wrong hint opens no path to funds: an
   invalid signature cannot execute on chain.

<a id="CLI-SGN-06"></a>**CLI-SGN-06** — **WalletConnect v2 is a seam behind a configuration flag; no SDK is loaded by the
core.** A `providerFactories` registry; the WalletConnect option appears only when a project id is configured **and** an
optional asset has registered a `walletconnect` factory. Why: the SDK is ~400 KB, needs a pinned version + SRI, cannot be
tested in offline CI, and a third-party script inside a payment page is supply-chain surface. Cost: mobile wallets need a
small add-on that registers the factory (pinned `@walletconnect/ethereum-provider` + SRI) first. The same holds for
Hedera HashPack (also a seam) and the TON Connect HTTP bridge.

## What a signer may sign

<a id="signing-review"></a><a id="rendering"></a>

<a id="CLI-SGN-05"></a>**CLI-SGN-05** — **A client never signs server-built typed data as is; it rebuilds the operation
first.** `checkPayment` rebuilds the payment `MetaTransfer` (`entryRef` = the request's reference, `value` = the displayed
amount × 10^`tokenDecimals`, `from` = the account, the right chain, fee 0, expiry ≤ 1 day, the right type);
`checkOwnerCall` accepts only a `SmartKeyAccount` `MetaTransaction` (`from` = the account itself,
[CTR-ACC-10](../contracts/accounts.md#CTR-ACC-10)) whose `data` is `addKey(the key just created)` on the right
account/chain with expiry ≤ 1 hour; anything else ⇒ refused. An owner call
is signed only after a form showing the account, the selector and value 0. BUILT.

<a id="CLI-SGN-08"></a>**CLI-SGN-08** — **`checkPayment` pins the expected token client-side.** It takes `expectedToken`
(with its `decimals` and `symbol`) from the signer's own chain profile (an app/extension build-time or user-pinned
registry), never from the server response, and refuses `verifyingContract ≠ expectedToken`. A portal page served by the
same server that serves the typed data cannot be defended this way (it ships the signer code); that case is out of scope.
Test: server data with a different token but the expected symbol ⇒ refused.

<a id="CLI-SGN-27"></a>**CLI-SGN-27** — **Check, then sign exactly what was checked.** `fam.checkTerms(start, shown)`
rebuilds the payload with `fam/<family>.js` and returns a frozen `checked` object `{ payload, walletInput, signingBytes
}`; a wallet's `sign()` and `signFamily` accept **only** `checked`, never `start`. Must-check lists:

| Family | Checks before anything is signed |
|---|---|
| EVM / Hedera ECDSA | `checkPayment` / `checkOwnerCall` ([CLI-SGN-05](#CLI-SGN-05)) |
| Sui | `message_b64 == payload_hex`; the payload decodes to `op == PAY`, `from == owner`, `to`, `amount == shown`, `relayer == 0x0`, `extra == 0³²`, `valid_until` within the window; `contract == deriveAccount(registry, from)`; `network == config` |
| Solana | `text == "scaas.metaop.v1:" + hex(sha256(payload))`; payload fields as Sui (op, from, to, amount, asset, lane, window); `account == PDA(["acct", owner])`; `network` = the configured genesis |
| Aptos | payload fields (op, from, to, amount, asset, window); `account == account_of(root, owner)`; `message` = the digest text; `application == location.origin` (portal: the configured `aptos_application`); `chainId`; `nonce == lane` |
| Soroban | decode the invocation: contract = token, function, args (from, to, amount); `network_id` = the configured passphrase hash; `signature_expiration_ledger` ≤ current + window |
| Cosmos, TON, Hedera ED25519 | the payload rebuilt from terms == `payload_hex`; `from`; chain/network; contract; amount |

When a family's signed text becomes the readable message of [NET-ALL-23](../networks/README.md#NET-ALL-23), its
encoder renders the same text and `checkTerms` compares it byte for byte. The rows above check the built `MetaOp`; the
target `MetaTransfer` is checked the same way, a `MetaCall` against the contract's allowlist (`function` known,
arguments decoded and shown, `args_hash` recomputed) ([NET-ALL-26](../networks/README.md#NET-ALL-26)). Portal limitation: `shown` comes from the same
server response as the terms, so in a portal the check is internal consistency (bytes ⇔ displayed fields), not protection
from a malicious issuer; in the app, `shown` is the user's own input. Why: it closes the gap between checking
`payload_hex` and signing `text`. Cost: a terms change must land with its `fam/*.js` change (shared KATs catch it).

### Meta-transaction calls and trade orders

<a id="CLI-SGN-33"></a>**CLI-SGN-33** — **Every SCaaS EIP-712 domain is built with `salt = chain_uid` from the
signer's own chain profile, and a different salt is refused.** Status: **SPECIFIED**. The app, the portal signer and
clientkeys fill `domain.salt` with the chain profile's `chain_uid` ([NET-ALL-24](../networks/README.md#NET-ALL-24)),
which works offline, or from the contract's `eip712Domain()` read once and cached; clientkeys refuses typed data whose
`salt` differs from its pinned profile, or a domain without one for a SCaaS contract. This covers tokens (transfers,
payments, self-calls, trade orders), mandate wallets, subject accounts, the DEX and the registry. What protects the
user is the contract — a contract on another chain computes its digest with that chain's `chain_uid`, so the signature
fails there whichever wallet made it; the client check catches a wrong profile or a hostile server before the user is
asked. Transitional (BUILT): only the Universal Account domains carry `salt` (the existing check of the PoP flow,
[integration.md](../integration.md)); the other domains are unsalted until the salted contracts are deployed.

<a id="CLI-SGN-34"></a>**CLI-SGN-34** — **A meta-transaction's `data` is decoded and shown before the user signs;
a selector outside the token's allowlist is refused.** Status: **SPECIFIED**. clientkeys and the app encode
`mtxExecute` calldata themselves, and before any signature decode `data` against the implementation's published
allowlist (`mtxSelectors()`, pinned per implementation version in the chain profile, cross-checked with the chain):
the selector's function name and every argument in human terms (amounts with the token's decimals, recipients,
`minOut`), the fee and its class (a fixed fee on a call that moves no amount of this token is shown as an exact
amount). Transfers and payments are `MetaTransfer`s, shown by their typed fields (recipient, amount, reference)
([CTR-MTX-23](../contracts/metatx.md#CTR-MTX-23)); clients build both structs ([CTR-MTX-15](../contracts/metatx.md#CTR-MTX-15)).
An unknown selector, a `transfer`/`pay` selector inside a `MetaTransaction`, or `approve`/`transferFrom` ⇒ refused,
with no override. The same applies to `MandateWallet`, `SmartKeyAccount` and any SCaaS contract on `MetaTxBase`
([CTR-MTX-22](../contracts/metatx.md#CTR-MTX-22)). [CLI-SGN-05](#CLI-SGN-05) and
[CLI-SGN-27](#CLI-SGN-27) apply: the shown call is the one rebuilt and signed. The meta-transaction lane (`batch` of
the meta-transaction) and an order lane (`batch` of a trade order) are labelled differently wherever both appear.

<a id="CLI-SGN-35"></a>**CLI-SGN-35** — **A trade order names a DEX on the chain profile's list, or the client refuses
to build and sign it.** Status: **SPECIFIED**. Before signing a `TradeOrder` (in the app, clientkeys or a portal)
the review shows `dex`, `relayer`, `destination`, the price limit both ways, the signed `fee` rate and the effective
minimum fill per settlement (`max(minFill, ceil(amount / 2))`; a `minFill` below half is shown as half; `minFill =
amount` as fill-or-kill). By default the client **refuses** to build or sign when `dex` is not on its pinned chain
profile's DEX list ([NET-ALL-24](../networks/README.md#NET-ALL-24); a listed DEX is `isDex` and of a non-deprecated version, [CTR-DEX-24](../contracts/dex.md#CTR-DEX-24)) — for a signature wrap, when `dex` is not a
registered wrapper of that underlying — with a warning that a contract named there can take the signed amount;
overriding needs an explicit expert setting and is never offered in a portal. It warns when `destination ≠ from`
(someone else receives the proceeds), and it defaults `relayer` to the venue node's lane from the gateway profile
(with `relayer = 0` anyone who submits can earn the relayer share of the fee, and the order can be copied from the
mempool). Why: the token requires only that `dex` is a contract (owner decision 2026-10-08, accepted residual risk);
the signer is the last place a phishing `dex` can be stopped. Cost: a new DEX needs a profile update before users can
trade on it.

<a id="CLI-SGN-36"></a>**CLI-SGN-36** — **A client never asks an EOA to approve a SCaaS token; wrapping a SCaaS
underlying is signed, not approved.** Status: **SPECIFIED**. On a SCaaS token only a contract may call `approve`
([CTR-TOK-01](../contracts/token-wrappers.md#CTR-TOK-01)), and `approve` is on no token allowlist, so no client offers
an approve screen, typed data or permit for one. A wrap whose underlying is a SCaaS token is a `TradeOrder` signed in
the **underlying's** domain with `dex` = `receiveToken` = the wrapper, `receiveAmount` = the minimum to mint,
`minFill = amount` and `fee` = what the submitting relayer earns from the minted units; it is submitted as an `mtxWrap`
job ([job-api.md#metatx-entries](../node/job-api.md#metatx-entries)). A wrap of an **outside** underlying (e.g. a
stablecoin) still needs the holder's allowance on that outside token, to the wrapper only, for the exact amount
([CLI-APP-23](app.md#CLI-APP-23)); trading an outside token needs the allowance to a listed DEX's `DexPuller`, never to the DEX ([CLI-SGN-37](#CLI-SGN-37)). A contract account
that must approve a SCaaS token for another contract does so through its own call path (`mtxExecuteAsOwner` →
`execute(token, approve)`, or a Safe transaction), never by a signature the token checks. Why: an EOA allowance is a
standing permission any later bug or phishing page can spend; the order-based wrap gives the wrapper exactly one
signed pull at a signed minimum.

<a id="CLI-SGN-37"></a>**CLI-SGN-37** — **Exchange-path orders: listed pools, cycles, the puller, surplus.** Status:
**SPECIFIED**. The review offers `LISTED_POOLS` ([CTR-DEX-23](../contracts/dex.md#CTR-DEX-23)) as a toggle "only audited
pools" (default off); allows `receiveToken` = the sell token with a "cycle" label and a warning when `receiveAmount ≤
amount`; asks an outside-token holder to approve the listed DEX's `DexPuller` ([CTR-DEX-22](../contracts/dex.md#CTR-DEX-22)),
never the DEX; and checks each `ExchangeLegSettled` against `limitReceive`, showing `surplus` as price improvement.

<a id="portal-signer-rules"></a>**Portal signer rules.** A portal or ERP page that hosts a signer also:

1. shows the operation in human terms (amount, payee, token, chain, expiry) **before** invoking the authenticator;
2. never sends mnemonics, `x`, PRF outputs or PINs to any server; tokens and keys live in memory or the encrypted vault;
3. never runs the signer in a cross-origin iframe — assertions with `crossOrigin: true` or a `topOrigin` are refused
   ([NET-ALL-04](../networks/README.md#NET-ALL-04)).

## Passkeys

<a id="passkeys"></a>

<a id="CLI-SGN-09"></a>**CLI-SGN-09** — **Portal and mobile subjects sign value operations with WebAuthn P-256 passkeys.**
A "use passkey" button appears when `window.PublicKeyCredential` exists; `navigator.credentials.create` at registration,
`get` at signing with `challenge = digest`; an EIP-6963 wallet stays an alternative. The client decodes the DER signature
into `(r, s)` and normalises low-s; a batch is one assertion over a Merkle root of digests (EVM and Soroban only). The
on-chain rules are [NET-ALL-04](../networks/README.md#NET-ALL-04) and
[CTR-ACC-08](../contracts/accounts.md#CTR-ACC-08). Tests use real WebAuthn vectors from a software authenticator
(fixed P-256 key) and a public vector set where available. BUILT (EVM). `clients/clientkeys/src/passkey-signer.js`:
`creationOptions` (PRF enabled by default), `requestOptions`, `derToRS`, `encodeAssertion = abi.encode(authenticatorData,
clientDataJSON, r, s)`, `merkleBatch`, `accountSignature = abi.encode(keyIndex, bytes32[] proof, sig)`. `signCount` is not
checked (synced passkeys always return 0).

<a id="CLI-SGN-04"></a>**CLI-SGN-04** — **Each passkey gets a random 16-byte WebAuthn user handle.** Not one per partner;
`excludeCredentials` = the account's live passkeys (server-provided; failed keys excluded); adding a passkey on a new
device first opens and checks the approval phrase, **before** `navigator.credentials.create()`; `InvalidStateError` ⇒
"this device already has a passkey". BUILT.

<a id="CLI-SGN-23"></a>**CLI-SGN-23** — **Non-EVM passkeys reuse one WebAuthn ceremony plus one encoder per family**:
Sui flag 6, Solana `passkey_blob` (precompile), Soroban `WebAuthn{…}` (CAP-51), Aptos blob (pure-Move `scaas::p256`,
UNAUDITED, shown as such). Order: Sui → Solana → Soroban → Aptos. Cosmos and TON passkeys are not offered yet (Cosmos and
TON users use a seed or an extension). Why: verifier maturity.

<a id="CLI-SGN-24"></a>**CLI-SGN-24** — **The passkey challenge is base64url (no padding) of the family's op digest.** The
open challenges (Sui `scaas.open.v1`, Solana `scaas.open.v1`, the Soroban constructor, the Aptos first-key rule) are built
by `fam/*`; passkeys stay origin-bound ([CLI-APP-14](app.md#CLI-APP-14)).

| Family | On-chain P-256 | Account | pk | Origin binding | Status |
|---|---|---|---|---|---|
| EVM, Hedera | RIP-7212 `0x100` or OZ Solidity | `SmartKeyAccount` | `(x, y)` + `rpIdHash`, `keccak(origin)` | per key | BUILT |
| Sui | native `secp256r1_verify`, flag 6 | `Account<T>` (`open_passkey`) | 33 B | `origins` ≤ 8 | contract BUILT; signer first |
| Solana | precompile `Secp256r1SigVerify1111…` (SIMD-0075), low-S, ≤ 8 per instruction | PDA (`open_passkey`) | 33 B | `origins` ≤ 8, same-rpId rule | contract BUILT; second |
| Soroban | host `secp256r1_verify` (CAP-51) | `scaas-account` `C…` | 65 B | per key | contract BUILT; third |
| Aptos | pure-Move `scaas::p256` (UNAUDITED, ≈ 4 100 gas per signature) | `Account` object | 65 B | `origins` | contract BUILT (unaudited); fourth |
| Cosmos | cosmwasm `secp256r1_verify` | none (passkey id only) | 33 B | none | not yet |
| TON | TVM `P256_CHKSIGNS` | jetton wallet, one passkey | 33 B + `rpIdHash` + `originPrefix` | prefix | not yet |

Encoders (`src/fam/<family>.js`):

| Family | Open (first key) | Pay signature | Submit `public_key` |
|---|---|---|---|
| Sui | assertion over `blake2b256("scaas.open.v1" ‖ registry ‖ pk33)`; `open_passkey` | base64 `0x06 ‖ uleb ad ‖ uleb cd ‖ uleb(98) (0x02 ‖ r‖s ‖ pk33)` | — |
| Solana | assertion over `sha256("scaas.open.v1" ‖ program_id ‖ pk33)`; owner per [NET-ALL-21](../networks/README.md#NET-ALL-21) (as built `sha256("scaas.owner.p256" ‖ pk33)`) | `[2, key_index] ‖ r‖s ‖ u16le(len ad) ‖ ad ‖ cd` + precompile instruction | pk33 hex |
| Soroban | `__constructor(first_key)` (no auth) | `Signature::WebAuthn{key_id, authenticator_data, client_data_json, signature, proof}` XDR | — |
| Aptos | the first-key rule ([NET-APT-03](../networks/aptos.md#NET-APT-03)) | `r‖s ‖ u16be(len ad) ‖ ad ‖ cd` | pk65 hex |

`r‖s` comes from `derToRS` (strict DER, low-s); `pk33` is the SEC1 compression of `publicKeyFromSpki`; `pk65` is
`0x04 ‖ x ‖ y`. Merkle batching stays EVM-only (and Soroban on chain). Tests: the chain-side software-authenticator
vectors (Sui `d_*`, Solana/Soroban/Aptos suites) re-encoded by `fam/*` from `(authenticatorData, clientDataJSON, DER,
SPKI)` must match the chain bytes; **cross-family separation** — every family's pay and open challenge preimages are
pairwise prefix-distinct (one credential may serve several chains); JS refusals (wrong challenge, missing UV, high-s
normalised, cross-origin, wrong pk length); the client verifier's answers on client-encoded vectors; end to end with a
virtual authenticator per family.

## Seed vault

<a id="vault"></a>

<a id="CLI-SGN-11"></a>**CLI-SGN-11** — **A non-custodial seed wallet lives on the client, and one subject account holds
several keys (passkey + seed).** Owner decision ("both passkeys and seed words"). A 24-word BIP-39 mnemonic (256 bits;
import accepts 12–24 valid words, checksum checked) is generated or imported **on the device**; the mnemonic and keys
**never** leave it and are never sent to an ERP or a relayer. It is shown **once**, with a mandatory confirmation
(re-enter 3 random words; `SeedBackup` states `fresh → revealed → challenged → verified → taken`) before use. After use,
secret buffers are overwritten (`fill(0)`) within JS limits (strings cannot be wiped — stated). Libraries: `@noble/hashes`,
`@noble/curves` (secp256k1, ed25519), `@scure/bip39`, `@scure/bip32`, pinned and vendored as ESM bundles (`static/lib/` in a portal), **loaded only
when the seed wallet is chosen**. The seed key and the passkey back each other up (each is the natural recovery key when
the other is lost). Signing uses each family's typed digest like every other signer. BUILT.
One key per family: derived keys differ by coin type, and the seed wallet tags an **imported** key with its family and
refuses to reuse it in another, so one key never signs raw digests for two families
([NODE-LANE-20](../node/submit-lanes.md#NODE-LANE-20)).

<a id="CLI-SGN-02"></a>**CLI-SGN-02** — **The vault encrypts the seed under a random data key wrapped by a passphrase
envelope and, when available, a passkey PRF envelope.** A random DEK encrypts the seed with AES-256-GCM (a fresh 12-byte
IV each time); the DEK is wrapped by the passphrase through scrypt (16-byte salt) **always**, and additionally by a PRF
envelope (`extensions.prf`) when the passkey supports it — PRF is the **default** when a passkey of the account offers it
(the passphrase envelope still always exists). Wrapping keys are never stored. v1 format (`vault.js`):
`{ v: 1, label, data: {iv, ct}, pin: {kdf: 'scrypt', N, r, p, salt, iv, ct}, prf?: {credentialId, salt, iv, ct} }`. BUILT.

<a id="CLI-SGN-21"></a>**CLI-SGN-21** — **New passphrase envelopes use scrypt `N = 2^17, r = 8, p = 1` (128 MiB; `clients/clientkeys/src/vault.js:14,40-45`; helpers
`needsRewrap`/`rewrapPin`), replacing the earlier `N = 2^15`; a new
passphrase has ≥ 8 characters and is not digits only.** Measured on Node 26: noble 501 ms, native 334 ms at `2^17`
(131 / 86 ms at `2^15`). The passphrase is the fallback unlock (PRF is the default) and `scryptAsync` yields to the event
loop. On low-memory phones the failure is an **allocation error or a renderer kill**: a thrown error at creation stops the
flow with "this device cannot create a passphrase vault", and nothing weaker is written. Old vaults (`2^15`, 6-digit PIN)
still open and are re-wrapped (a weak PIN ⇒ choose a new passphrase); the `2^15` → `2^17` re-wrap runs **after the
payment is submitted**, never inside the unlock that precedes it, guarded by a marker `rewrap-attempt:<id> = N` written
before the attempt — a marker present on the next load skips the re-wrap (no crash loop); the app's key worker uses the
same marker ([CLI-APP-24](app.md#CLI-APP-24)). On open, a pin envelope outside `N ∈ {2^15, 2^16, 2^17}, r = 8, p = 1` is
refused (`dekFrom` bounds check). `SCRYPT = { N: 2^17, r: 8, p: 1, dkLen: 32 }`. Why: one number in code and docs, and no
device locked out by its own upgrade. Cost: very low-memory phones use a paper backup or an extension wallet. BUILT
(parameters and re-wrap); the failure, marker and bounds tests SPECIFIED.

<a id="CLI-SGN-17"></a>**CLI-SGN-17** — **Vault v2 is an outer AES-256-GCM layer under a per-origin non-extractable device
key, wrapped around the unchanged v1 vault.** The device key is WebCrypto `AES-GCM` 256, `extractable: false`, kept as a
structured clone in IndexedDB; it is the default for new vaults where the IndexedDB/`CryptoKey` probe passes (otherwise a
v1 vault is written, with a notice); it applies to every label (`seed`, `zether-conf:…`); `kid` exists only for a future
format bump (no rotation flow). Format:

```json
{ "v": 2, "label": "seed", "kid": "device-v1", "iv": "<b64url, 12 B>", "ct": "<b64url>" }
```

`ct = AES-256-GCM(deviceKey, iv, utf8(JSON.stringify(v1)), aad = "<label>|device|<kid>")`, a fresh IV per seal; `label`
is repeated outside, so a swapped blob fails both the outer and the inner AAD; the device key is required **in addition**
to the passphrase or PRF.

<a id="CLI-SGN-18"></a>**CLI-SGN-18** — **Device binding relaxes nothing.** The passphrase policy and scrypt stay. WebCrypto
keys are **not hardware-backed** on Chromium and Firefox (the key bytes sit in the profile's IndexedDB files); Safari
wraps them under a Keychain key (stronger). The gain is narrow: a blob that leaks **without** the profile's IndexedDB
cannot be attacked offline. PRF from a passkey reported as not synced (BE = 0) is preferred, but it is not
"hardware-bound" either: the PRF output reaches page JS, so a script running during one unlock gets a permanent unwrap key
for that blob — v2 still demands the device key on top.

<a id="CLI-SGN-19"></a>**CLI-SGN-19** — **Vault storage, precedence and migration.** The vault and the device key share one
IndexedDB database (`scaas-clientkeys`, store `kv`), so eviction removes both together:

| Key | Value |
|---|---|
| `device-key:v1` | the `CryptoKey` (`extractable: false`) |
| `vault:<id>` | v2 (or v1 on fallback); a portal `<id>` = `<portal-prefix>:<subject>`, where `<subject>` is an opaque per-partner tag issued by the server; the app `seed:<account label>`; Zether `zether-conf:<curve>:<coin>:<account>`; PQ Zether `vault:pqz:<account>:<index>` |
| `rewrap-attempt:<id>` | the `N` being attempted |
| `persist-notice` | `true` once the refusal notice was shown |

Replacing a stored phrase under an existing `vault:<id>` must be confirmed by the user; a vault is never overwritten
silently.

Precedence: an existing `vault:<id>` in IndexedDB wins, and migration never `put`s over it. A migrated portal
`localStorage` vault is **replaced by a tombstone** `{ "v": 2, "moved": "indexeddb" }`, not deleted, so old cached portal code
fails with "Unknown vault version." instead of offering "create a new phrase"; `openDevice` rejects it. The post-write
check is `openDevice(readBack)` deep-equal to the in-memory v1 object (AES-GCM only: no second scrypt, no second unlock).
`navigator.storage.persist()` is requested at creation; a refusal is shown once per device. Migration: (1) new vault:
`createVault` (v1) → `sealDevice` → `put('vault:<id>')` → `openDevice(get(...))` deep-equals v1 → done; (2) existing v1
(app IndexedDB, or a portal `localStorage` vault including the older per-subject key): after a successful `openVault`,
check whether `vault:<id>` already exists — if so it wins: open it and only write the tombstone; else seal v2 and `put`
it, read it back with `openDevice` and compare, **then** write the tombstone (a failure at the put or the read-back keeps
the `localStorage` entry); the `2^15` re-wrap is a separate step after the payment; (3) opening: IndexedDB `vault:<id>`
first, then `localStorage` (v1 ⇒ migrate; tombstone ⇒ "this vault moved; reload"); a v2 blob without the device key means
a cleared profile — phrase import only; (4) no downgrade to v1 is ever written; `openDevice` output never leaves memory.
Interface (`src/device.js`, exported from `seed-signer.js` and `zether-keys.js`, used inside the app key worker):

```js
export async function openStore(indexedDB = globalThis.indexedDB) // → { get, put, del } or null (probe fails)
export async function deviceKey(store)                             // get, or generate + put
export async function sealDevice(vaultV1, key)                     // → v2
export async function openDevice(vaultV2, key)                     // → v1, memory only; tombstone ⇒ throws
export function needsBinding(stored)                               // stored.v === 1
```

Why: no rollback to a stale weaker blob, no silent new seed, no second 128 MiB KDF.

<a id="CLI-SGN-20"></a>**CLI-SGN-20** — **Recovery after device loss is the recovery phrase.** It is re-imported on the new
device (same keys, a new device key and vault); the alternative is another key or guardian recovery on chain; there is no
vault export. Clearing the site's data, or Safari ITP's 7-day script-storage eviction, equals losing the device — the
create flow says so. **The phrase is never shown again**, by any flow: a user who lost the paper creates a new backup key
and removes the old one. Why: a re-reveal path would undermine "written down" ([CLI-SGN-13](#CLI-SGN-13)).

Threat model of the vault:

| Threat | v1 | v2 | Control that actually helps |
|---|---|---|---|
| Same-origin script: XSS, **or a browser extension with host access** (content scripts reach IndexedDB and `crypto.subtle`) | reads the blob, phishes the passphrase or waits for unlock | same: the device key is a decrypt oracle | CSP, no third-party scripts, key worker ([CLI-APP-15](app.md#CLI-APP-15), [CLI-APP-24](app.md#CLI-APP-24)) |
| **Portal origin as trusted base**: every theme or module script on the portal origin | as XSS | as XSS | deployment note: serve payments from a dedicated payment subdomain with only the payment bundle |
| Blob leaked alone (storage dump, log, support export, one-store file sync) | offline scrypt attack | **useless** without the profile's IndexedDB | [CLI-SGN-17](#CLI-SGN-17) |
| Browser profile copy (both stores) | offline scrypt attack | same on Chromium/Firefox (key bytes in the copy); Safari: Keychain-wrapped | passphrase strength, scrypt `2^17`, OS disk encryption |
| Stolen disk without OS encryption | as profile copy | as profile copy | OS full-disk encryption |
| Stolen device, locked / unlocked browser | passphrase or PRF + UV | same | idle lock (5 min in the app) |
| PRF from a synced passkey + leaked blob | opens anywhere the passkey syncs | needs the device key too | [CLI-SGN-17](#CLI-SGN-17) |
| PRF output captured by a script during one unlock | permanent unwrap key for that blob | still needs the device key (same origin ⇒ available to that script) | as the XSS row |
| Device lost, site data cleared, Safari ITP 7-day eviction | phrase re-import | phrase re-import; the blob never opens again | [CLI-SGN-20](#CLI-SGN-20), `persist()` |

Tests: v1 → v2 → v1 round trip with an in-memory store (Node 26 has WebCrypto, no IndexedDB); tampered outer `ct`,
swapped `label`, swapped `kid`, wrong device key, tombstone — each fails and returns nothing; `deviceKey` stable across
calls, `extractable === false`, `exportKey` rejects; `test/vectors/vault_v2_fixture.json` (a committed v2 blob plus raw
device-key bytes imported with `extractable: false`) opens to known entropy; `openStore` returns `null` under a stub
`indexedDB` that throws on a `CryptoKey` `put` and the caller writes v1; migration failure paths (put fails, read-back
mismatch, tombstone write fails, both copies present — IndexedDB wins, no overwrite — and a stale v1 next to a newer
v2); scrypt — a KDF that throws at creation returns no vault, a present marker skips the re-wrap, out-of-bounds
`N`/`r`/`p` refused on open, a `2^15` vault still opens (`vault.test.js` pins the parameters and the re-wrap); **real
browsers** — one Playwright run of create → reload → unlock → migrate on Chromium, Firefox and WebKit (a structured-clone
`CryptoKey` in IndexedDB is not exercised by a `Map` store); a portal tour (a legacy `localStorage` vault unlocks, becomes
v2 in IndexedDB, leaves a tombstone; the second unlock opens v2); `bundle.test.js` covers the new module.

## Backup-key switch

<a id="backup-switch"></a>

<a id="CLI-SGN-12"></a>**CLI-SGN-12** — **"Backup key required" is one boolean deployment switch, default off.** It exists
once per onboarding surface: the app's `config.json` `policy.requireBackupKey`; an ERP configuration parameter (absent =
off); an argument to the clientkeys helper (clientkeys reads no configuration). There is no per-account mode list. Owner
decision ("only a switch"). Cost: per-company rules later would need a company field. SPECIFIED.

<a id="CLI-SGN-13"></a>**CLI-SGN-13** — **An account has a backup iff it holds ≥ 2 distinct active keys, or exactly 1 and
an independent guardian.** **Distinct** = the normalised public keys differ: P-256 `x`, secp256k1 address (EVM
`SECP256K1` keys are addresses) or x-only, ed25519 `pk`; one credential on two origins counts **once**, as do a Soroban key
added twice and a Sui key under two `rp_id_hash` values. **Active** = final on chain (pending keys do not count).
**Independent guardian** = neither the account itself nor the native address of any key in the set (EVM key address; Sui
`blake2b(flag ‖ pk)`; Aptos auth keys; Solana pk; …). An **`msig` UA** is backed up iff `Σweights − max(weight) ≥
threshold` ([CLI-APP-25](app.md#CLI-APP-25)). A seed key counts as "written down"; only phrases that passed the 3-word
check (`SeedBackup`) or were typed in by their holder reach a key. Why: duplicates and self-guardians are exactly the
false "backed up" state the switch exists to prevent. Cost: two passkeys in one password manager still count as two
([CLI-SGN-16](#CLI-SGN-16) warns).

<a id="CLI-SGN-14"></a>**CLI-SGN-14** — **The backup rule is enforced by clients and issuers, never by contracts or node
intake.** With the switch on: (1) **value ops are refused** from a subject account without a backup — pay, transfer,
unwrap, DEX order, mandate open, Zether transfer/fund — and its receive address, QR and "fund your account" are hidden; (2)
**issuers refuse to issue terms** that pay from or to an account they can check (today only an ERP holding EVM/Hedera
mirrors); (3) **key operations stay open** — add key, set guardian and add origin are always allowed (add origin never
creates a backup), and **remove key and clear guardian are always allowed**, with a warning; afterwards the account may be
in the no-backup state. Revoking a stolen key or a hostile guardian is never blocked. The node does not check. Solana's
on-chain policy bit stays per account and owner-set ([NET-SOL-07](../networks/solana.md#NET-SOL-07)); clients offer "make
this permanent on chain" on Solana only, never automatically. Why: the switch protects users from loss and is not a
security control. Cost: a third-party client ignores it, by design.

<a id="CLI-SGN-15"></a>**CLI-SGN-15** — **Exits are never blocked, in any state.** "Move the whole balance out" (with a
warning) is allowed on a satisfiable account without backup (funded before the switch or after a key removal), next to
the backup flows, and on an **unsatisfiable** account as its only value op. Unsatisfiable kinds: a Cosmos passkey-derived
account, a passkey-only native address (Sui flag 6 without `Account<T>`), a single-key derived UA. Native single-key
accounts with a seed-vault or extension key are outside the predicate (an EOA, `G…`, Cosmos secp256k1, a Solana or Aptos
wallet, a Sui address, Hedera native). Unsatisfiable kinds are not offered at creation while the switch is on. Why: rescue
is never throttled.

<a id="CLI-SGN-16"></a>**CLI-SGN-16** — **Backup warnings are non-blocking, in both switch states.** BE/BS
(`authenticatorData` bits 3 and 4) are read from each creation and assertion and cached client-side only (nothing stored
server-side); a BE = 0 passkey is labelled "this device only (as reported)"; "These passkeys may share one password
manager" is shown when ≥ 2 passkeys of one `rpId` all report BS = 1; "No backup" is shown with the add-backup action. Why:
the flags are the only sync signal and are self-reported (`attestation: 'none'`). Cost: a misreporting authenticator
mislabels a key; counting is unaffected.

| Switch | Account | Value ops | Exit | Receive / fund | Key ops |
|---|---|---|---|---|---|
| off | any | allowed | allowed | shown | all; "no backup" warning |
| on | subject, has backup | allowed | allowed | shown | all; removals warn when they break the backup |
| on | subject, no backup, satisfiable | refused: "Add a backup key first" | allowed | hidden | all; add-backup offered first |
| on | unsatisfiable | refused | allowed (only value op) | hidden | as the kind allows |
| on | native single-key (seed vault or extension) | allowed | allowed | shown | n/a |

Reading the key set (clients re-read after any key change reaches finality and cache nothing across sessions):

| Family | Read | Active keys (then de-duplicate) | Guardian |
|---|---|---|---|
| EVM, Hedera | `nextKeyIndex()`, `keyAt(i)` for `i ∈ [0, nextKeyIndex)`, skipping `kind == NONE` (slots are sparse after `removeKey`); `guardian()` | non-NONE slots | `guardian() != 0x0` |
| Sui | `Account<T>` fields `keys`, `guardian` (`sui_getObject`) | `keys` | `guardian != @0x0` |
| Aptos | `Account` resource | `keys` | `option::is_some(guardian)` |
| Solana | `SmartKeyAccount` PDA (Borsh) | `keys` | `guardian`; also `policy & 1` |
| Soroban | `scaas-account` key map | values (no duplicate check on chain) | none |
| TON | jetton wallet `pubkey`, `passkey` | the bound ones | none |

Per-family applicability is in [networks/README](../networks/README.md#key-lifecycle) (Soroban and TON are satisfied by
**≥ 2 keys** and **both keys**: they have no guardian — owner). clientkeys interface (`src/backup-policy.js`, exported from
both signer entries):

```js
/** account: { kind: 'subject' | 'native' | 'msig', satisfiable: boolean, address: string,
 *   keys: Array<{ scheme, pub }>,   // ACTIVE keys; pub = normalised public key hex: P-256 x, secp256k1
 *                                   // address or x-only, ed25519 pk
 *   nativeAddresses: string[],      // native address of each key (guardian independence)
 *   guardian: string | null, msig?: { threshold, weights: number[] } } */
export function hasBackup(account)            // distinct pubs ≥ 2, or 1 + independent guardian, or the msig rule
export function backupStatus(account, { required }) /* → { ok, reason: null | 'NO_BACKUP' | 'UNSATISFIABLE',
    allow: { value, receive, exit: true, addKey: true, setGuardian: true, addOrigin: true,
             removeKey: true, clearGuardian: true },
    warnings: Array<'NO_BACKUP' | 'SAME_KEYCHAIN' | 'DEVICE_ONLY' | 'BREAKS_BACKUP'> } */
export function passkeyFlags(authenticatorData) // → { up, uv, be, bs } (bits 0, 2, 3, 4)
export function deriveRoleKey(seed, { kindNo, account, i }) // caller wipes privateKey
```

`BREAKS_BACKUP` is set on a planned removal when `hasBackup(after)` is false; the signer UI calls `backupStatus` first and
the signer refuses a value op when `allow.value` is false. An ERP mirror (EVM/Hedera) applies the same predicate over its
key rows, de-duplicated by `public_x` for passkeys and the address for seed keys, then ≥ 2, or 1 with a guardian ∉ {zero
address, the account address, any key's address}; its accepted blind spots: a later `setGuardian` and removals done
outside the portal are not mirrored (it over-counts) — the switch is soft. Non-EVM families: client enforcement only.

Flows: **add a backup** — seed primary ⇒ add a passkey; passkey primary ⇒ a paper seed key ([CLI-SGN-25](#CLI-SGN-25));
or ask the operator for a guardian (EVM/Sui/Aptos/Solana); **revoke** — EVM offers `rotateKey(index, newKey)` (one owner
call: add, then remove) as the default when replacing a key, elsewhere "add new key, then remove"; plain remove and
clear-guardian are always possible, with `BREAKS_BACKUP` shown; **lost paper** — create a new paper key, then remove the
old one. Tests and vectors: `clients/clientkeys/test/vectors/backup_policy.json` — each row `{name, families, account, required}`
→ `{has_backup, ok, reason, allow, solana_onchain?}`, covering 0/1/2/8 keys; guardian set, unset, equal to its own key,
equal to the account; the same passkey on two origins ⇒ 1; a Soroban key twice ⇒ 1; a Sui pk under two `rp_id_hash` ⇒ 1;
`msig` weights; native; unsatisfiable; remove-key and clear-guardian **allowed** and yielding `NO_BACKUP`; exit allowed in
every row; both switch states. Consumers: clientkeys `backup-policy.test.js` (all rows); the ERP mirror's tests (EVM
rows); the Solana Rust `has_backup` unit test (rows with `solana_onchain`; where the on-chain count without de-duplication
differs it is pinned as `solana_onchain` ≠ `has_backup`). Other tests: `deriveRoleKey` path strings and **role key ≠
native key** for one seed on every family (the UA `derivation.json` rows must agree); `passkeyFlags` against
`test/softauthn.js` with BE/BS set and clear; issuer — start refused (on, 1 key, no guardian), refused with guardian = own
key, allowed after a second distinct key, allowed when off, a pending key does not count; a portal tour (fake
authenticator, switch on): payment blocked → paper backup flow → pay; then remove the passkey → value refused, exit
offered; an app end-to-end test.

## Derivation and role keys

<a id="derivation"></a>

| Use | Path | Curve / scheme |
|---|---|---|
| Native account keys | the family paths below: EVM `m/44'/60'/0'/0/i`, Solana `m/44'/501'/i'/0'`, … | family |
| Every derived UA kind and every account-role key | `m/7622'/0'/<account>'/<kindNo>'/<i>'` | BIP-32 (secp256k1, P-256 via SLIP-10 nist256p1), SLIP-10 ed25519 |
| `SmartKeyAccount` SECP256K1 key (role of `evm-contract`) | `m/7622'/0'/<account>'/2'/<i>'` | secp256k1 |
| Non-native subject-account owner keys (Sui/Aptos/Solana/Soroban role keys) | `m/7622'/0'/<account>'/<native kindNo>'/<i>'`: Solana 16, **Soroban `C…` 18** (`soroban-contract` 0x0012 = 18, not `stellar-account` 0x0011 = 17; owner 2026-10-07), Aptos 19, Sui 20 | ed25519 |
| `musig2-secp256k1` participant keys | `m/7622'/0'/<account>'/272'/<i>'` (kind 0x0110; never a `bip340` key); `musig2-bn254` as the bn254 row | secp256k1 |
| FROST shares | **not seed-derived**: DKG polynomial secrets are fresh randomness; the share is kept in the vault; a lost share is a lost participant | — |
| `schnorr-bn254`, `musig2-bn254` keys from seed | EIP-2333-style `m/254/0/<account>/<kindNo>` (salt `"SCAAS-UA-BN254-v1"`) | bn254 |
| Identity UA for credentials | its own `<account>'` in the UA tree, never the paying account's | per kind |
| `bls12381-minsig`, `schnorr-bls12381` | EIP-2333 `m/12381/0/<account>/<kindNo>` | BLS12-381 |
| Zether conf key / viewing key | `m/254|12381/<coin>/<account>/7`, `…/8` ([CLI-SGN-10](#CLI-SGN-10)) | bn254 / BLS12-381 |
| PQ seeds | `ξ = HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.pq.v1", info = kind_tag ‖ u32 account ‖ u32 i)` → FIPS 204 `KeyGen_internal(ξ)` / seeded FN-DSA keygen | ML-DSA, FN-DSA |
| Passkeys | one credential per `rpId`; the same credential on several chains is the same kind (`webauthn-p256` or a family's native passkey) — allowed, the challenges are domain-separated digests | P-256 |

In general form the tree is `m/7622'/0'/<account>'/<kind>'/<i>'`. `7622'` is the SCaaS BIP-43 purpose for UA trees (owner); the coin level is `0'` because a UA id is chain-independent
(one derived key ⇒ the same UA on every chain). clientkeys API rules: `signDigest(key, digest)` is for **native** keys
only; UA keys are `UAKey` objects from `deriveUAKey(seed, {kind, account, index})` whose only signing method is
`signUA(purpose, digest)` (it builds `ua_msg` itself), so no raw signature over arbitrary 32 bytes ever comes from a UA key;
`deriveUAKey` refuses a `kind` whose curve group equals a native path's curve **and** whose path would equal it (impossible
with `7622'`, asserted in tests) and refuses the Zether `use` indices 7/8 for non-Zether kinds; `deriveConfKey` accepts only
`use` 7 and 8; MuSig2/FROST are `UAKey` session objects (`musig2.start/partial/aggregate`, `frost.dkg*/commit/sign/aggregate`)
that only ever sign `ua_msg` (vectors BIP-327, RFC 9591 Appendix E.5, `frost.json`); a Zether `x` is never reused as an
independent same-curve BLS key (it would make G1 DDH decidable and leak balances) — the BLS and Zether trees are disjoint
and a test asserts `deriveUAKey` never yields a Zether conf scalar (foreign wallets are a residual risk); one PRF/PIN
wrapping covers the seed and the conf key, separated by AAD labels; wallets show the kind and role of every key and never
offer "use this EOA as a passkey/Schnorr/multisig member key".

<a id="role-keys"></a>

<a id="CLI-SGN-29"></a>**CLI-SGN-29** — **One key, one purpose, starting at the wallet layer.** Wallets and clientkeys derive
a separate hardened path per kind and per account role and expose no generic "sign this digest with that key" for UA keys;
the registry, tagged messages and EOA rules are the other three layers ([CTR-UA-10](../contracts/accounts.md#CTR-UA-10)).
The registry layer keeps `keyOwner[keyHash] → ua` and refuses the same public key under another kind (`UAKeyInUse`). Why:
ECDSA and Schnorr over one secp256k1 key leak through nonce relations; a Schnorr signing oracle on an ElGamal key is a
decryption-adjacent oracle; untagged digests replay across protocols. Owner decision.

<a id="CLI-SGN-30"></a>**CLI-SGN-30** — **The EVM seed path is the EOA only; every subject-account key that is not the
native owner and every derived kind comes from the UA tree `m/7622'/0'/<account>'/<kindNo>'/<i>'`.** The role `kindNo` is
the kind of the account the key serves: EVM/Hedera `SmartKeyAccount` 2, Solana 16, Soroban `scaas-account` `C…` 18
(`soroban-contract`), Aptos 19, Sui 20. Owner decisions (one chain-independent tree under purpose `7622'`; Soroban
`kindNo` 18). Existing dev accounts whose SECP256K1 key is the EOA key rotate at the UA migration.

<a id="CLI-SGN-25"></a>**CLI-SGN-25** — **Every seed key added to a subject account is a role key; a backup seed key lives
on paper only.** `deriveRoleKey(seed, {kindNo, account, i})` derives `m/7622'/0'/<account>'/<kindNo>'/<i>'` (all hardened;
BIP-32 for secp256k1, SLIP-10 for ed25519) — plain derivation that `UAKey` later wraps without changing the path. The
**native** path is used only for a native account and for the owner/first key of a Sui/Aptos/Solana account derived from
the user's own native address; every other key added by a seed is a role key (backup, added device, a passkey-first
account's seed key, a Soroban `C…` key). **Backup flow:** generate a phrase, show it once, run the 3-word check, derive the
role key, sign `addKey`/`mtx_add_key` with the existing key, then `abandon()` — **nothing is stored** unless the user asks to keep
it on this device, and no scrypt runs, so low-memory phones can comply. Why: a backup in the same browser profile as the
primary key is not a backup. Cost: one derivation per role; wallets show the role.

<a id="CLI-SGN-07"></a>**CLI-SGN-07** — **New seed keys of subject accounts use the role path.** New `SECP256K1` keys
registered by an ERP or clientkeys are derived on `m/7622'/0'/<account>'/2'/<i>'`, never the subject's EOA key; existing
dev keys stay until rotated. Tests: a clientkeys vector for the role path; the issuer refuses registering a key whose
address equals the subject's own payer address (`payer_address`) on the same account.

<a id="CLI-SGN-22"></a>**CLI-SGN-22** — **Seed signers sign the family's own envelope, built and checked by clientkeys
`fam/*`**, never a server digest as such: Soroban `G…` — ed25519 over `sha256(HashIdPreimage::SorobanAuthorization)`;
Soroban `C…` — `Ed25519{key_id, signature}` over `signature_payload`; Aptos — ed25519 over the client-built AIP-62
`fullMessage`; Solana — off-chain message v1 (kind 1) only (kind 0 is for extension wallets,
[CLI-APP-06](app.md#CLI-APP-06)). Why: the seed signs silently. SPECIFIED for Soroban, Aptos, Solana.

<a id="CLI-SGN-01"></a>**CLI-SGN-01** — **Short-lived agent session keys (1–8 h) are an open owner requirement.** The
design today issues no session keys to agents: agents use the same custody path as users, bounded by the signing policy
above; a session-key mechanism would map to Universal Account key purposes. Status `open`.

| Family | `NETWORKS` key | Native path | Curve | Native address | Adds to a subject account | Seed signer signs | Status |
|---|---|---|---|---|---|---|---|
| EVM | `evm` | `m/44'/60'/0'/0/i` (EOA only) | secp256k1 | keccak address | role `m/7622'/0'/a'/2'/i'` (SECP256K1 key) | EIP-712 digest | native BUILT; role SPECIFIED |
| Hedera ECDSA | `hedera_ecdsa` | `m/44'/3030'/0'/0/i` | secp256k1 | EVM alias | role `…/2'/i'` (HSCS `SmartKeyAccount`) | EIP-712 digest | as EVM |
| Hedera ED25519 | `hedera_ed25519` | `m/44'/3030'/0'/0'/i'` | ed25519 | `0.0.N` | — | raw ed25519 over the EIP-712 digest (HIP-632) | BUILT |
| Cosmos | `cosmos` | `m/44'/118'/0'/0/i` | secp256k1 | bech32 | — (no subject account) | ADR-036 doc | key BUILT; envelope SPECIFIED |
| Sui | `sui` | `m/44'/784'/i'/0'/0'` | ed25519 | `blake2b(0x00 ‖ pk)` | native if owner; else role `…/20'/i'` | personal-message digest, flag 0 | key BUILT; envelope SPECIFIED |
| TON | `ton` | `m/44'/607'/i'` | ed25519 | pubkey (wallet-bound) | — (wallet-bound) | `MetaCall`/`MetaTransfer` cell hash | key BUILT; envelope SPECIFIED |
| Soroban Stellar | `stellar` | `m/44'/148'/i'` | ed25519 | `G…` | role `…/18'/i'` (`C…` key) | `G…`: sha256(auth preimage); `C…`: `Ed25519{key_id, sig}` | SPECIFIED |
| Soroban Pi | `stellar` + 314159 | `m/44'/314159'/i'` | ed25519 | `G…` | as Stellar | as Stellar, Pi passphrase | SPECIFIED |
| Aptos | `aptos` | `m/44'/637'/i'/0'/0'` | ed25519 | `sha3_256(pk ‖ 0x00)` | native if owner; else role `…/19'/i'` | AIP-62 `fullMessage` | SPECIFIED |
| Solana | `solana` | `m/44'/501'/i'/0'` | ed25519 | base58 pk | native if owner; else role `…/16'/i'` | OCMS v1 (kind 1) | SPECIFIED |

`a` = the user's account number. TON keys from `m/44'/607'/i'` are "BIP-39/Ledger path" imports, not native TON mnemonics.
Interface (`src/fam/<family>.js`, used by the seed signer and wallets):

```js
export function checkTerms(terms, shown)       // → frozen { payload, walletInput, signingBytes }, or throws
                                               //   "Refusing to sign: …"
export function packSignature(checked, key, sig) // → { signature, publicKey } in the submit format
```

The seed signer's `signFamily(key, family, checked)` signs `checked.signingBytes` (ed25519; secp256k1 `signDigest` for
32-byte inputs) and packs the result; a wallet passes `checked.walletInput` to the wallet API, then compares what the
wallet reports as signed against `checked.signingBytes`.

| Family | `signingBytes` (seed) | `packSignature` |
|---|---|---|
| Soroban `G…` | `sha256(XDR(HashIdPreimage::SorobanAuthorization{network_id, nonce, signature_expiration_ledger, invocation}))`; a self-paid envelope hash is signed only via the adapter's `buildSelfPaid` | 64-byte hex; `publicKey` = `G…` StrKey |
| Soroban `C…` | `signature_payload` (32 B) | XDR hex of `Signature::Ed25519{key_id, signature}` |
| Aptos | UTF-8 `fullMessage` built by the client (`application`, `chainId`, `message = "scaas.metaop.v1:0x<digest>"`, `nonce = <lane hex>`), self-checked with the JS port of `parse_envelope` | `sig64 ‖ fullMessage` hex; pk hex |
| Solana | `0xff ‖ "solana offchain" ‖ 0x01 ‖ 0x01 ‖ pk32 ‖ "scaas.metaop.v1:" ‖ hex(digest)` | `[1, key_index] ‖ sig64` hex (key index 0 for the owner); pk hex |

Vectors: `solana_derivation.json` (the BIP-39 test mnemonic → pk/address for `i = 0, 1, 2` at `m/44'/501'/i'/0'`, from
`solana-keygen` (`prompt://?key=i/0`) and confirmed by an independent SLIP-10 implementation before commit);
`role_keys.json` (the same mnemonic → `deriveRoleKey` for `kindNo ∈ {2, 16, 18, 19, 20}`, `account ∈ {0, 1}`, `i ∈ {0, 1}`,
each different from every native key of that seed; the UA derivation vectors must agree); per family one **seed-signed**
vector (fixed seed and path, terms → `checked`, signature, packed value), asserted in JS and re-verified by the client
verifier (owner key ⇒ `True`); Soroban `C…`: one `Ed25519` ScVal vector from the account contract's `cargo test` (real
`set_auths`), compared byte for byte; every must-check row has a failing case per family; wallet `sign()` throws when given
anything but a `checked` object.

## Connectors

<a id="connectors"></a>

<a id="CLI-SGN-26"></a>**CLI-SGN-26** — **One connector implementation in clientkeys, shared by the app and every portal.**
The per-family wallet glue and the EIP-6963 part of a portal's payment script live in clientkeys `src/wallets/<family>.js`
and `wallets/evm.js` (pure ESM, `win` injected), built as **per-family esbuild entries** `wallets-<family>.js` and
`fam-<family>.js` with stable names for `import()`; the portal and the app's extension signers import the same modules;
portal copies and their tests are deleted in the same change. Owner decision. Cost: clientkeys gains browser glue.
SPECIFIED (as built, the portal connectors are seven node-tested scripts that nothing loads; the portal's payment script is
EVM only — EIP-6963, EIP-1193 fallback, the WalletConnect seam, `eth_signTypedData_v4`, the `wallet_kind` hint — and reads
`start.typed_data.message.validUntil`, which a non-EVM start lacks; the issuer side is already family-ready:
`{family, valid_until, payload_hex, digest, …terms}` plus `public_key`).

Built entry points (BUILT; load only what the chosen signer needs):

| Entry | Exports (main) | Use |
|---|---|---|
| `passkey-signer.js` | `passkeySupported`, `creationOptions` (PRF on), `requestOptions`, `publicKeyFromSpki`, `derToRS`, `encodeAssertion`, `hashTypedData`, `passkeySubjectKey`, `accountSignature`, `merkleBatch`, `checkOwnerCall`, `checkPayment` | create a passkey, sign `challenge = digest`, encode for `SmartKeyAccount.isValidSignature` |
| `seed-signer.js` | `normalizeMnemonic`, `wordsToEntropy`, `seedFromEntropy`, `deriveKey`, `signDigest`, `NETWORKS`, `createVault`, `openVault`, `enablePrf`, `rewrapPin`, `SeedBackup`, `wipe` | 24-word vault: generate, back up (3-word challenge), unlock by PRF or PIN, derive per family, sign digests |
| `zether-keys.js` (`zether.js`) | `deriveConfKey`, `confPublic` (returns the tagged UA once Universal Accounts land), `zetherPop` (signs the new PoP; `popMessage` removed), `sealConfKey`/`openConfKey`, `checkBalance`, cache helpers, `readBalance` | confidential keys and balance cache; proofs via the prover WASM `zetherCall(cmd, json)` (`keygen`, `encrypt`, `decrypt`, `decryptPending`, `checkBalance`, `proveTransfer`, `proveBurn`, `verifyTransfer`, `verifyBurn`, `pop`, `fundCalldata`, `envelope`) |

EVM extension wallets also use `wallet_switchEthereumChain`/`wallet_addEthereumChain`. A UA or role key signs only
through `UAKey.signUA(purpose, digest)`: there is no raw "sign these 32 bytes" for a UA key.

Per-family connector behaviour (loaded only when the payer chooses that network; no third-party library unless stated):
EVM/Hedera EIP-6963; Sui and Aptos the Wallet Standard event protocol (`wallet-standard:*`: `wallet-standard:register-wallet` /
`wallet-standard:app-ready`; Sui chooses a wallet with `sui:signPersonalMessage`, refusing zkLogin/multisig accounts —
keys not 32/33 bytes or flags other than 0/1/2/6; Aptos with `aptos:connect` + `aptos:signMessage`, checking
`aptos:network` against the terms' chain id, refusing non-ed25519 keys, asking `signMessage({message, nonce, application:
true, chainId: true})` and checking `fullMessage` before returning); Solana the Wallet Standard (`standard:connect` +
`solana:signOffchainMessage` v1 or `solana:signMessage`, the account's `chains` containing `solana:<genesis32>`;
preferring the off-chain message, checking `signedMessage` before sending); Cosmos `window.keplr || window.leap`
(`enable(chainId)`, `getKey`, `signArbitrary(chainId, signer, payloadString)`); Soroban Freighter (`@stellar/freighter-api`
pinned, vendored, lazy-loaded; `requestAccess`, `signAuthEntry(preimage_b64, {networkPassphrase, address})`); TON the
embedded TON Connect JS bridge (`window[<jsBridgeKey>].tonconnect`: `connect(2, {manifestUrl, items:[{name:'ton_addr'}]})`,
`send({method:'signData', …})`); Hedera ED25519 a page-provided raw signer `{accountId, publicKey, signBytes(Uint8Array)}`
seam plus the seed path; HashPack/WalletConnect are seams. A passkey is an option in every family whose account supports
passkeys. Connectors are tested against fake wallets per family; vendored libraries that need a real wallet are not run in
CI (stated).

Layout and interface:

```text
src/fam/<family>.js       encoders + checkTerms/packSignature      → entry fam-<family>.js
src/wallets/<family>.js   extension glue                            → entry wallets-<family>.js
src/wallets/evm.js        EIP-6963 discovery + walletKind           → entry wallets-evm.js
```

`package.json` `build` lists every entry explicitly (same `--splitting`, same out dir); shared code goes to
`chunk-[hash].js` and entry names stay stable; `bundle.test.js` keeps its byte-identical check.

```js
export function create(win = globalThis) {
  return { family, label, available(), wallets(),
           connect(name?) /* → { address, publicKey } */,
           sign(checked) /* → { signature, publicKey }; only a checkTerms result */ };
}
```

Portal payment flow:

```
options = payment_options(order)                                   // + family, network
signer  = family ∈ {evm, hedera ECDSA} ? the EVM chooser (wallets-evm.js)
        : choose among [wallets-<family>.js wallet(s), seed vault family path]
start   = payment_start(order, signer.from, wallet_id)              // owner key only
checked = (await import('…/fam-<family>.js')).checkTerms(start, shown)
{signature, publicKey} = await signer.sign(checked)
validUntil = start.typed_data ? start.typed_data.message.validUntil : start.valid_until
status  = payment_submit(start.reference, validUntil, signature, kind, publicKey)
```

`shown` is the amount, currency and payee text the portal displayed. Polling, terminal failures and the EIP-1193 chain
switch guard stay; the issuer adds `'family'` and `'network'` to the payment options and nothing else. In a portal without
chain reads, a non-EVM signer pays with the **owner key only**; added keys pay through the app. Tests: connector tests in
`clients/clientkeys/test/wallets/*.test.js` with an injected `win`; payment-script unit tests (dispatch, a `checkTerms` refusal
stops before `sign`, `validUntil` from `start.valid_until`); an issuer test that the options carry family and network;
tours (Sui and Solana with fake Wallet Standard wallets end to end to a queued `signed_op`; Aptos with one seed-vault tour).

## Zether keys

<a id="zether-keys"></a>

<a id="CLI-SGN-10"></a>**CLI-SGN-10** — **Zether confidential keys come from the same seed on their own paths.** Owner
decision ("seed words generate a separate Zether key on another path"). `auth_custody` and `conf_custody` are separate: a
leaked signing key reveals no balances; a leaked `x` authorises no transfer — so `x` has its **own path** and never equals
any signing scalar. BIP-32/SLIP-10 have no bn254 or BLS12-381, so derivation is **hardened-only EIP-2333-style** (HKDF-SHA256,
`r` = the group order, domain-separated):

- **BLS12-381:** exactly EIP-2333 (`derive_master_SK`, `derive_child_SK`, salt `"BLS-SIG-KEYGEN-SALT-"`), EIP-2334-style
  path `m/12381/<coin>/<account>/7` — `<use> = 7` reserved for Zether conf (EIP-2334 uses 0 = withdrawal, 0/0 = signing;
  7 is untouched); `<coin>` = the network's SLIP-44 (EVM 60).
- **bn254:** the same EIP-2333 structure with bn254's `r` and salt **`"SCAAS-ZETHER-BN254-v1"`**; HKDF-Expand to **48
  bytes** (L = ceil(3·ceil(log2 r)/16) = 48), then `mod r`, retried if 0 — as EIP-2333. Path `m/254/<coin>/<account>/7`
  (root 254 so it never touches the 12381 tree).
- The key depends on (seed, curve, network/coin, account), **not** on the token (one UA per (curve, network, account));
  changing the verifier's curve ⇒ another tree ⇒ no scalar reuse.
- The audit view/disclosure key (`ITransferDisclosure`): `<use> = 8`, on both trees.
- Short forms: `m/12381/<coin>/<acct>/7` and `m/254/<coin>/<acct>/7` (`m/254/…`).
- `y = g^x` (G1 of the curve); in the built registry `UA = keccak256(encodedY)` (`ZetherTypes.toUA`: bn254 64 bytes
  `x‖y`, BLS12-381 128 bytes per EIP-2537); the proof of possession now binds chain, registry, UA and `authRef`
  ([CTR-UA-07](../contracts/accounts.md#CTR-UA-07); an earlier Schnorr PoP over `keccak256(registry ‖ encodedY ‖
  account)` bound to the caller account is replaced; the built dev registry's challenge has no chain id,
`UniversalAccountRegistry.sol:95-96`). Zether protocol: [contracts/zether](../contracts/zether.md).
- Stored like the seed: client only, encrypted at rest, never sent to a server or a relayer.
- Tests: the published EIP-2333 vectors (BLS12-381); self-generated pinned bn254 vectors; one seed on different paths ⇒
  independent keys; `x` ≠ every signing scalar of the same seed; `y`/UA round trip.

<a id="CLI-SGN-03"></a>**CLI-SGN-03** — **Zether keys are derived in clientkeys JavaScript.** `@noble/curves` (bn254 +
BLS12-381) and `@noble/hashes` HKDF — no prover wasm is needed only to register. Byte-exact with the Rust prover (`zether-prover`): vectors
`r33_keys.json` and `schnorr_*.json` copied verbatim into `clients/clientkeys/test/vectors/`, plus 4 published EIP-2333 vectors. The
Schnorr nonce is hedged `sha512(x ‖ msg ‖ CSPRNG) mod r` (different from the prover's, but only cross-verification is
needed; with a fixed `k` the bytes match). A separate lazy entry `zether-keys.js` keeps the seed bundle small; `x` is sealed
in the vault like the seed. BUILT.

Post-quantum Zether keys: the BIP-39 seed lives only in the key worker, so the PQ `seed32` is derived there and nowhere
else. `sealPqKey({account, index})` (key worker) derives `seed32` once and seals it as a 32-byte PQZ leaf in vault v2 under
`vault:pqz:<account>:<index>` (AES-256-GCM with the device key and its own AAD label, the `sealConfKey` pattern);
`openPqKey({account, index})` (Zether worker) opens that leaf only, never the seed; `pqz-cli` (and `pqz-cli serve`) reads
the 32-byte leaf from stdin, exported on the user's own machine, never the BIP-39 seed; organizations keep the leaf in the
key oracle and the ML-DSA key in an HSM with FIPS 204 firmware where available. `sealPqKey`/`openPqKey` join the vault v2 API
next to `sealConfKey`/`openConfKey`. clientkeys uses `deriveUAKey(seed, {kind: 'mldsa65', account, index})` /
`signUA('zether-auth', authDigest)` with a vetted JS/WASM ML-DSA package; an explicit export of the 32-byte leaf (never the
seed) feeds the native prover or the organization's key oracle — PQ Zether proving is **not** in JS; envelopes reuse the
existing `MetaTransaction` EIP-712 builder (address path, domain `("SCaaS PqzToken", "1", …)`) and the
`UAMetaTransaction` builder (UA path, `salt = chainUid`) with `signUA('metatx', digest)` by the dedicated `mldsa65` fee UA — no new signing code; the UA kind
vectors (`smartcontracts/vectors/ua/kinds.json`) gain the `pqz-mlwe` row (seed → pk, UA, keyHash). Protocol detail:
[contracts/pq-zether](../contracts/pq-zether.md). SPECIFIED.

## Zether balance reading

<a id="zether-balance"></a>

The wallet reads a classical Zether balance by decrypting `(C, D) = ([b]G + [r]Y, [r]G)`: the owner computes `[b]G = C −
[x]D` and finds `b` (a discrete logarithm) with baby-step giant-step (BSGS). The limits on chain are in
[contracts/zether](../contracts/zether.md#decryption-bound); the client side:

| Limit | Default |
|---|---|
| Balance a wallet reads by itself **without** a cache | mobile 2^44; desktop up to 2^54 |
| Balance read and spendable **with** a cache | up to 2^54 |
| Incoming funds between two `zetherRollOver`s that a mobile wallet decrypts by itself (`pending`) | 2^44 |

For a 2-decimal USD token: 2^40 base units ≈ $11 billion, 2^44 ≈ $176 billion, 2^54 ≈ $180 trillion. Beyond the mobile
`pending` limit nothing is lost: roll over more often, or read with a desktop/CLI.

- **The baby-step table is public data** (multiples `[j]G`, no secret, identical for every account): generated on the
  client or downloaded precomputed and checked; stored and regenerated at will.
- The client picks `table_bits` by RAM; the number of search steps = 2^(bound_bits − table_bits); entries are 16 bytes.
  Desktop ≈ 0.35 µs per step, Android ≈ 4× slower — **estimates** (no benchmark in `zether-prover` yet), and every time below
  derives from them:

  | `table_bits` | Memory | Table build (once) | Worst-case search to 2^54 (desktop) |
  |---|---|---|---|
  | 22 | ~64 MiB | ~1.5 s | ~25 min |
  | 24 | ~256 MiB | ~6 s | ~6 min |
  | 25 | ~512 MiB | ~12 s | ~3 min |
  | 26 | ~1 GiB | ~24 s | ~1.5 min |
  | 27 | ~2 GiB | ~47 s | ~47 s |

- Defaults: mobile/wasm `table_bits 22, bound_bits 44`; desktop 24–26 by RAM with `bound_bits 54`; wasm refuses a 2^27
  table (exactly 2 GiB — a 32-bit `Vec` cannot hold it) and stops at 2^24 (256 MiB) unless called with `allowLargeTable`;
  the native API refuses a table larger than the available RAM; the native CLI `zether-read-balance` allows up to 27.
- **Device balance cache:** `{ua, token, accSeq, balance}` is stored in the wallet's encrypted vault (the same protection
  as the seed) — never on chain, never sent to a server. Check: `[b]G == C − [x]D` on the current `acc` — one point
  multiplication, a few ms; a wrong or stale cache is detected at once and can never lead to a wrong spend (the prover and
  the contract both refuse a proof built on a wrong balance). Update: `zetherRollOver` ⇒ `b += pending` (BSGS only on `pending`);
  own spend ⇒ `b −= v + fee`. When `acc` changed without the wallet knowing (anyone may call `zetherRollOver`/`zetherRollOverBatch`
  — `zetherShield(victim, 1)` + `zetherRollOver` is a nearly free grief; late credits are merged by `zetherRollOverSigned`; an own spend
  not yet recorded), the last verified value stays the anchor and the wallet solves BSGS on the **difference**
  `(C − [x]D) − [b_cache]G` (trying increase, then decrease) within the device bound, re-checks and updates — no CLI needed
  even when the balance exceeds 2^44. Cache lost: a balance within the device's BSGS bound is re-read; above it, use a
  desktop/CLI.
- Post-quantum Zether never uses BSGS or `zether-read-balance`.
