# Round 3 — wallet signing formats per network (agy research, 2026-10-03)

Below is the verified, specification-level answer for all five ecosystems based on official specifications, improvement proposals, and core node implementations:

> **Rev 1.1 (2026-10-07) — Claude review 1 folded** (section "Claude review 1" at the end: rulings CR-WSF-1…2,
> streams WSF-FIX1…2, signing-domain table, passkey grammar pointer, superseded statements). This note is research
> (precedence 5, SCaaS §0.1). "Five ecosystems" is stale: there are eight families (owner 2026-10-06); Aptos
> (`aptos:signMessage`, AIP-62) and Solana (raw/OCMS + precompile introspection) are built
> (`move/aptos/sources/auth.move`, `solana/programs/scaas/src/auth.rs`) and summarised at the end.

---

### 1. Hedera HIP-632: `IHederaAccountService` Precompile (`0x16a`)

#### Exact Solidity Signatures
From [`hiero-contracts/contracts/account-service/IHederaAccountService.sol`](https://github.com/hiero-ledger/hiero-contracts/blob/main/contracts/account-service/IHederaAccountService.sol#L61-L78):

```solidity
// Selector: 0xb2a31da4 (decl: "isAuthorizedRaw(address,bytes,bytes)")
function isAuthorizedRaw(
    address account,
    bytes memory messageHash,
    bytes memory signature
) external returns (bool authorized);

// Selector: 0xb2526367 (decl: "isAuthorized(address,bytes,bytes)")
function isAuthorized(
    address account,
    bytes memory message,
    bytes memory signature
) external returns (int64 responseCode, bool authorized);
```
* **Address:** `0x000000000000000000000000000000000000016a` (`0x16a`).
* **Return Value Difference:** `isAuthorizedRaw` returns a bare ABI `bool`. `isAuthorized` returns `(int64 responseCode, bool authorized)`, where `responseCode == 22` is `SUCCESS`.

#### ED25519 Account Keys
* **Bytes Signed:** The precompile takes the raw `messageHash` argument **as-is**. In `IsAuthorizedRawCall.java` and `SignatureVerifierImpl.java`:
  ```java
  txSig = new TransactionSignature(signedBytes, sigPair.keyBytes(), sigPair.signature(), SignatureType.ED25519);
  cryptoEngine.verifySync(txSig);
  ```
  Hedera consensus node runs pure RFC 8032 Ed25519 verification over `messageHash` without any prefix and without re-hashing.
* **Length Limits:** 
  * `signature`: Exactly **64 bytes** (`ED_SIGNATURE_LENGTH = 64`).
  * `messageHash`: Exactly **32 bytes**. `AppSignatureVerifier.java` enforces:
    ```java
    if (messageType == KECCAK_256_HASH && bytes.length() != 32) {
        throw new IllegalArgumentException("Message type KECCAK_256_HASH must be 32 bytes long");
    }
    ```
* **Gas Cost:** Hardcoded to **3,000 gas** (`HederaGasCalculatorImpl.getEdSignatureVerificationSystemContractGasCost()` delegates to Besu's `getEcrecPrecompiledContractGasCost()`).
  *(Claude review L1: a **rejected** call charges the frame's remaining gas, so the code caps the CALL at 100 000
  gas — `hedera/HederaAccountAuth.sol:18-21`. Budget 100 k, not 3 k.)*

#### ECDSA (secp256k1) Keys
* **Signature format:** **65 bytes** (`[r (32), s (32), v (1)]`). Recovery ID `v` is stripped internally before verification against the account's registered key.
* **`messageHash`:** Exactly **32 bytes** (treated as Keccak-256 digest, not re-hashed).
* **Account Requirement:** Account must possess an EVM address alias (`isLongZero(address)` is rejected with `INVALID_ACCOUNT_ID`).
* **Gas Cost:** **3,000 gas**.

#### HashPack / WalletConnect `hedera_signMessage` Compatibility
Per **[HIP-820](https://hips.hedera.com/hip/hip-820)**:
```
<Key>.sign("\x19Hedera Signed Message:\n" + len(message) + message)
```
Returns a base64-encoded protobuf [`SignatureMap`](https://github.com/hashgraph/hedera-protobufs/blob/main/services/basic_types.proto).
* **Compatibility with `isAuthorizedRaw`:**
  * **ED25519: INCOMPATIBLE.** The wallet signs the full UTF-8 prefixed string (length > 24 bytes). `isAuthorizedRaw` rejects any `messageHash` whose length is not exactly 32 bytes, and verifies Ed25519 directly against those 32 bytes rather than the prefixed string.
  * **ECDSA: PARTIALLY COMPATIBLE WITH TRANSFORMATION.** The dApp must compute `keccak256("\x19Hedera Signed Message:\n" + len(message) + message)` (32 bytes), extract the raw 65-byte ECDSA signature from the protobuf `SignatureMap`, and pass those into `isAuthorizedRaw`. Passing the protobuf blob directly will revert.

#### Network & Tooling Status
* **Mainnet / Testnet:** `isAuthorizedRaw` shipped in Services **v0.52**. The finalized HAS service ([HIP-632](https://hips.hedera.com/hip/hip-632)) was released in **v0.56.7**. Both functions are active on Mainnet and Testnet.
* **`hedera-local-node`:** Supported from version **v2.36.0+** (which bundles services $\ge$ 0.52). *(Note: `hedera-local-node` was deprecated in Sept 2024 and replaced by `solo` / `hiero-solo`).*

---

### 2. TON Connect: `signData` Protocol (2025)

Reference: [`ton-connect/wallets-list`](https://github.com/ton-connect/wallets-list) & [`mois-ilya/ton-sign-data-reference`](https://github.com/mois-ilya/ton-sign-data-reference).

#### Payload Types
`text`, `binary`, `cell`.

#### Exact Cell Layout (`type == "cell"`)
Constructs a root Cell hashed via TON's standard 32-byte representation hash (`message.hash()`):
```typescript
const schemaHash = crc32.buf(Buffer.from(payload.schema, 'utf8')) >>> 0; // 32-bit uint
const encodedDomain = encodeDnsName(domain).toString('utf8');

const message = beginCell()
    .storeUint(0x75569022, 32)          // 32-bit magic prefix
    .storeUint(schemaHash, 32)          // 32-bit unsigned CRC32 of TL-B schema string
    .storeUint(timestamp, 64)           // 64-bit unsigned Unix timestamp in seconds
    .storeAddress(parsedAddr)           // MsgAddressInt (user wallet address)
    .storeStringRefTail(encodedDomain)  // TEP-81 internal DNS representation (in ref cell)
    .storeRef(cell)                     // Ref to payload Cell
    .endCell();

const finalHash = message.hash();       // 32-byte SHA-256 representation hash
```
* **Domain Encoding:** TEP-81 internal format: lowercased, split by `.`, ASCII/Punycode converted, reversed, and separated/terminated by `\0` (e.g. `app.ton.org` $\rightarrow$ `org\0ton\0app\0`). Max 126 bytes.

#### Exact Byte Layout for `binary` & `text`
The message buffer before hashing is concatenated as follows:
```
[0xff, 0xff]                                 // 2 bytes
|| "ton-connect/sign-data/"                  // 23 bytes (UTF-8)
|| workchain                                 // 4 bytes signed int32 big-endian
|| address_hash                              // 32 bytes (raw account ID)
|| uint32BE(domain.length)                   // 4 bytes unsigned uint32 big-endian
|| domain                                    // UTF-8 domain bytes
|| uint64BE(timestamp)                       // 8 bytes unsigned uint64 big-endian
|| ("bin" or "txt")                          // 3 bytes ASCII
|| uint32BE(payload.length)                  // 4 bytes unsigned uint32 big-endian
|| payload_bytes                             // Raw binary bytes or UTF-8 text bytes
```
* **Hash function:** `SHA-256` of the entire buffer: `crypto.createHash('sha256').update(message).digest()`.
* **Signature:** Ed25519 detached signature (`nacl.sign.detached(finalHash, privateKey)`), returned as base64 string.

#### Wallet Support
Verified in `wallets-v2.json`:
* **Tonkeeper** (`tonkeeper`, `tonkeeper-pro`): supports `['text', 'binary', 'cell']`.
* **MyTonWallet** (`mytonwallet`): supports `['text', 'binary', 'cell']`.
* **Wallet in Telegram** (`telegram-wallet` / `@wallet`): supports `['text', 'binary', 'cell']`.
* **Tonhub** (`tonhub`): supports `['text', 'binary', 'cell']`.

#### Smart Contract Verification (FunC)

*(Superseded: the implementation is Tact, `CHKSIGNU` over the same cell (`ton/contracts/common.tact:252-272`); passkey
via `P256_CHKSIGNS`. The `domain` and `timestamp` this layout signs must also be **checked** on chain — Claude
review M1 → R3D CR-R3-7.)*
```func
() verify_cell_sign_data(cell payload_cell, int schema_crc, int timestamp, slice user_addr, cell domain_cell, slice signature, int public_key) impure {
    cell signed_cell = begin_cell()
        .store_uint(0x75569022, 32)
        .store_uint(schema_crc, 32)
        .store_uint(timestamp, 64)
        .store_slice(user_addr)
        .store_ref(domain_cell)
        .store_ref(payload_cell)
        .end_cell();
        
    int digest = cell_hash(signed_cell);
    int is_valid = check_signature(digest, signature, public_key);
    throw_unless(101, is_valid);
}
```

---

### 3. Sui: Wallet Standard `sui:signPersonalMessage`

Source: [`MystenLabs/sui/crates/sui-types/src/crypto.rs`](https://github.com/MystenLabs/sui/blob/main/crates/sui-types/src/crypto.rs) and [`MystenLabs/fastcrypto`](https://github.com/MystenLabs/fastcrypto).

#### Exact Digest Signed
* **Intent Bytes (3 bytes):** `[0x03, 0x00, 0x00]`
  * `IntentScope::PersonalMessage = 3`
  * `IntentVersion::V0 = 0`
  * `AppId::Sui = 0`
* **BCS Serialization:** `PersonalMessage { message: Vec<u8> }`. In BCS, `Vec<u8>` is serialized as `ULEB128(length) || message_bytes`.
* **Digest:** 32-byte **Blake2b-256**:
  $$\text{digest} = \text{Blake2b256}([0x03, 0x00, 0x00] \parallel \text{ULEB128}(\text{len}) \parallel \text{message})$$

#### Returned Signature Serialization
Base64 string encoding `flag || signature || public_key`:
* **Ed25519 (`flag = 0x00`):** `0x00` (1B) $\parallel$ 64B sig $\parallel$ 32B pubkey = **97 bytes**.
* **Secp256k1 (`flag = 0x01`):** `0x01` (1B) $\parallel$ 64B compact sig ($r \parallel s$) $\parallel$ 33B compressed pubkey = **98 bytes**.
* **Secp256k1 Hashing:** **YES, the Secp256k1 signature is over `sha256(blake2b_digest)`**.
  In `fastcrypto::secp256k1::Secp256k1KeyPair`:
  ```rust
  impl Signer<Secp256k1Signature> for Secp256k1KeyPair {
      fn sign(&self, msg: &[u8]) -> Secp256k1Signature {
          self.sign_with_hash::<DefaultHash>(msg) // DefaultHash = Sha256
      }
  }
  ```
  Since `msg` is the 32-byte Blake2b-256 digest, the ECDSA signature is computed over `SHA-256(blake2b_digest)`.

#### Move On-Chain Verification
```move
module my_pkg::verifier {
    use sui::ed25519;
    use sui::ecdsa_k1;
    use sui::address;
    use sui::hash;

    const HASH_SHA256: u8 = 1; // 0 = KECCAK256, 1 = SHA256

    public fun verify(flag: u8, sig: vector<u8>, pk: vector<u8>, blake2b_digest: vector<u8>, expected_signer: address): bool {
        // Address derivation: blake2b256(flag || pk)
        let mut pk_buf = vector[flag];
        vector::append(&mut pk_buf, pk);
        let derived_addr = address::from_bytes(hash::blake2b256(&pk_buf));
        assert!(derived_addr == expected_signer, 100);

        if (flag == 0) {
            // Ed25519: verifies directly over the 32-byte Blake2b-256 digest
            ed25519::ed25519_verify(&sig, &pk, &blake2b_digest)
        } else if (flag == 1) {
            // Secp256k1: hash flag 1 internally applies SHA-256 to blake2b_digest
            ecdsa_k1::secp256k1_verify(&sig, &pk, &blake2b_digest, HASH_SHA256)
        } else {
            false
        }
    }
}
```

---

### 4. Cosmos: Keplr `signArbitrary` (ADR-036)

Reference: Cosmos SDK [ADR-036 specification](https://github.com/cosmos/cosmos-sdk/blob/main/docs/architecture/adr-036-arbitrary-signature.md) and [`@cosmjs/amino`](https://github.com/cosmos/cosmjs/tree/main/packages/amino).

#### Canonical Amino `StdSignDoc` JSON
All JSON keys at all depths must be strictly sorted alphabetically without whitespace:
```json
{"account_number":"0","chain_id":"","fee":{"amount":[],"gas":"0"},"memo":"","msgs":[{"type":"sign/MsgSignData","value":{"data":"<base64_payload>","signer":"<bech32_address>"}}],"sequence":"0"}
```
* `account_number`: `"0"`
* `chain_id`: `""`
* `fee`: `{"amount":[],"gas":"0"}` (keys `amount`, `gas`)
* `memo`: `""`
* `msgs`: single element array with `type: "sign/MsgSignData"` and `value: {"data": "...", "signer": "..."}` (keys `data`, `signer`)
* `sequence`: `"0"`

#### Hashing & Signature Format
* **Hash function:** `SHA-256` of the UTF-8 encoded canonical JSON string (produces 32-byte digest).
* **Returned signature format (`StdSignature`):**
  ```typescript
  {
    pub_key: {
      type: "tendermint/PubKeySecp256k1",
      value: "<base64_33_byte_compressed_secp256k1_pubkey>"
    },
    signature: "<base64_64_byte_compact_r_and_s>"
  }
  ```

#### CosmWasm Verification

*(Claude review L4: the snippet does not normalise `s`; the built passkey path calls `secp256r1_verify` without a
low-s check (`cosmos/metaop/src/lib.rs:147`). Malleability only (digest identity does not depend on the signature);
fixed with the passkey v2 rework, R3D CR-R3-1.)*
```rust
use cosmwasm_std::{Deps, StdResult, VerificationError};
use sha2::{Digest, Sha256};

pub fn verify_adr036(
    deps: Deps,
    canonical_json_bytes: &[u8],
    signature_bytes: &[u8],    // 64-byte compact r || s
    pubkey_bytes: &[u8],       // 33-byte compressed pubkey
    expected_signer: &str,
) -> StdResult<bool> {
    let hash = Sha256::digest(canonical_json_bytes);
    let valid = deps.api.secp256k1_verify(&hash, signature_bytes, pubkey_bytes)
        .map_err(|_| VerificationError::InvalidSignature)?;
    if !valid {
        return Ok(false);
    }
    // Address check: ripemd160(sha256(pubkey_bytes)) formatted to bech32 == expected_signer
    Ok(true)
}
```
* **Leap Wallet Support:** **Yes**. Leap exposes `window.leap.signArbitrary(chainId, signerAddress, data)` conforming to the exact same ADR-036 specification.

---

### 5. Stellar / Soroban: Freighter `signAuthEntry`

Reference: [`@stellar/freighter-api`](https://www.npmjs.com/package/@stellar/freighter-api), [`@stellar/stellar-sdk`](https://github.com/stellar/js-stellar-sdk), and [`stellar/rs-soroban-sdk`](https://github.com/stellar/rs-soroban-sdk).

#### API Input & Output
```typescript
signAuthEntry(
    entryXdr: string, 
    opts?: { networkPassphrase?: string; address?: string }
): Promise<{
    signedAuthEntry: string | null;
    signerAddress: string;
} & { error?: FreighterApiError }>;
```
* **Input:** Base64-encoded `SorobanAuthorizationEntry` (or `HashIdPreimage`) XDR string.
* **Returned:** Object with `signedAuthEntry` (Base64-encoded `SorobanAuthorizationEntry` XDR containing populated credentials) and `signerAddress` (`G...` or `C...`).

#### What is Signed
The **SHA-256 hash** of the `HashIdPreimage` XDR representation:
$$\text{Signature} = \text{Ed25519.sign}(\text{sha256}(\text{HashIdPreimage.toXDR}()))$$
Where `HashIdPreimage` contains `HashIdPreimageSorobanAuthorization`:
* `network_id`: SHA-256 hash of the network passphrase
* `nonce`: Nonce / invocation counter
* `signature_expiration_ledger`: Future expiration ledger sequence
* `invocation`: Invocation tree (`SorobanAuthorizedInvocation`)

#### Soroban SDK Major Version & `Address` Inspection
* **Current Version:** **`28.0.0`** (Protocol 22 / 23+ support).
* **Differentiating Contract Address vs Account Address:**
  `soroban_sdk::Address` exposes two methods:
  1. **`Address::executable(&self) -> Option<Executable>`**:
     ```rust
     pub enum Executable {
         Wasm(BytesN<32>),
         StellarAsset,
         Account,
     }
     ```
     * Returns `Some(Executable::Account)` for classic Stellar accounts (`G...`).
     * Returns `Some(Executable::Wasm(...))` or `Some(Executable::StellarAsset)` for smart contracts (`C...`).
     * Returns `None` if the address does not exist on-chain.
  2. **`Address::to_string(&self) -> String`**:
     Returns the StrKey string format (`C...` for contract addresses, `G...` for account addresses).

---

## Claude review 1 (2026-10-07) — disposition (rev 1.1)

Source: `docs/reviews/specs/round3-wallet-signing-formats-claude-review-1.md` (verdict FIX-THEN-GO). Findings
re-checked against the code on 2026-10-07 (`scaas` 991d835). Owner rule: docs only — code bugs become rulings
(fix + tests) and streams. Ruling ids `CR-WSF-n` are local to this note; several findings are ruled in the round-3
design (R3D §H) because the note is research and the rule belongs to the design.

### Disposition

| # | Sev | Verified against code | Disposition |
|---|---|---|---|
| Conformance (HIP-632, TON cell, Sui intent, ADR-036, Soroban) | — | Confirmed as listed in the review (`HederaAccountAuth.sol:15-37`, `common.tact:252-262`, `move/sui/sources/auth.move:52-75`, `cosmos/metaop/src/lib.rs:74-81`). | No action |
| H1 | high | Confirmed: Solana signs `"scaas.metaop.v1:" ‖ hex(sha256(MetaOp))` raw or as OCMS (`solana/programs/scaas/src/auth.rs:90-112,208-216`); Sui signs BCS through `signPersonalMessage` (`move/sui/sources/meta.move:322`); neither binds an application. Aptos binds `application ∈ origins` (`move/aptos/sources/auth.move:111-139`) because AIP-62 wallets write that line; Solana `signMessage` and Sui `signPersonalMessage` wallets attest no origin in the signed bytes. | **Accepted** → CR-WSF-1; WSF-FIX1, WSF-FIX2 |
| M1 | med | Confirmed (`common.tact:264-272`, `jetton.tact:202-206`). | **Accepted** → R3D CR-R3-7 (stream R3-FIX11) |
| M2 | med | Confirmed: verifiers diverge (Cosmos: no rpIdHash/origin/UV; Sui/Soroban/TON/Solana ignore `crossOrigin`). | **Accepted** → R3D CR-R3-1 (one grammar + `webauthn_kat.json`; R3-FIX1, R3-FIX2); passkey pointer below |
| M3 | med | Confirmed: only raw ED25519 over the EIP-712 digest is accepted (`HederaMetaToken.sol:26-32`, `HederaV2Lib.sol:13-17`); HIP-820 `hedera_signMessage` prefixes the message, which `isAuthorizedRaw` (32-byte message only) cannot verify. | **Accepted** → CR-WSF-2 (wallet requirement stated; R63 "natively" corrected in R3D §D.1) |
| M4 | med | Confirmed: the network comes from the runtime everywhere except Solana (`solana/programs/scaas/src/account.rs:28-34`). | **Accepted** → table below; Solana fix R3D CR-R3-4 (R3-FIX6) |
| L1 | low | Confirmed (`HederaAccountAuth.sol:18-21`). | **Accepted**: inline note §1 |
| L2 | low | `hedera-local-node` deprecated (Sept 2024) for `solo`; R3D §D.1 planned e2e on it. | **Accepted**: R3D §D.1 note |
| L3 | low | Confirmed: Aptos/Solana built; clientkeys signs only EVM/seed digests today (`clientkeys/src/seed.js:146-151`; non-EVM signers SPECIFIED in S4F). | **Accepted**: summary below |
| L4 | low | Confirmed (`cosmos/metaop/src/lib.rs:147`). | **Accepted** → R3D CR-R3-1 (low-s on Cosmos); inline note |
| Stale table (2 rows) | — | Confirmed. | **Accepted**: table below |

Rejected: none. Counts: 1 high, 4 medium, 4 low, 1 table — 10 accepted, 0 rejected.

### Rulings

- **CR-WSF-1** **Solana and Sui wallet-key signatures: no blind blobs; origin binding through the passkey path or an
  opt-in account policy** (H1). On-chain *application* binding of a wallet's `signMessage`/`signPersonalMessage` is
  **not possible** on Solana and Sui: unlike AIP-62 (`application:` line written by the wallet) and WebAuthn
  (`origin` written by the browser), these wallets put no requesting origin into the signed bytes, so any line a
  contract checks could be written by the phishing page itself. The rule is therefore:
  (1) **Readable payload, rebuilt on chain.** The signed bytes are UTF-8 text that the contract re-renders from the
  `MetaOp` and compares byte for byte: `SCaaS <op>` / `Amount: <decimal> <symbol>` / `To: <address>` /
  `Network: <id>` / `Valid until: <unix>` / `Ref: <hex>` / `Digest: <hex>` (Solana as OCMS v1 restricted UTF-8,
  `\xffsolana offchain` envelope; Sui as a UTF-8 personal message, not BCS). Decimals and symbol come from the
  token/config object on chain. A wallet then shows what is paid, so the wallet path is as safe as signing a wallet
  transaction on that page.
  (2) **Origin-bound path by default.** Portal/app flows on Solana and Sui offer the passkey key first (origin and
  rpIdHash checked on chain, R3D CR-R3-1).
  (3) **Opt-in on-chain binding.** An account policy bit `POLICY_PASSKEY_FOR_VALUE` (Solana `SubjectAccount.policy`,
  `account.rs:254`; Sui `Keys.policy`, R3D CR-R3-5), set by a KeyOp, makes value ops (`pay`, `trade`, mandate
  setup) require a passkey signature; wallet keys then authorise key operations only.
  Residual risk (SCaaS §7.5/§7.7 amendment): a user who approves a readable "pay X to Y" message on a phishing
  page has authorised it, as with any wallet transaction. — Tests: Solana LiteSVM / Sui Move tests — the readable
  text verifies, a hex-only text is refused, a text whose amount/to differs from the `MetaOp` is refused; with the
  policy bit a wallet-key `pay` is refused and a passkey `pay` passes.
- **CR-WSF-2** **Hedera ED25519 subjects need a raw signer** (M3). The contracts accept raw ED25519 over the 32-byte
  EIP-712 digest only; HashPack/WalletConnect `hedera_signMessage` (HIP-820 prefix) cannot be verified by
  `isAuthorizedRaw`, so those wallets cannot sign SCaaS meta-transactions for ED25519 accounts. Supported signers:
  clientkeys seed (`m/44'/3030'/0'/0'/i'`) raw signing, or an ECDSA-alias account. HIP-632 `isAuthorized` with a
  HIP-820 message is a follow-up investigation, not a stream. A `MandateWallet` owned by an ED25519 account pays
  through `executeAsOwnerRaw` (addendum CR-ADW-2). Doc only.

### Signing-domain inputs per family (review M4)

| Family | Network in the signed payload comes from | Contract/app binding |
|---|---|---|
| EVM (incl. Hedera) | `block.chainid` (runtime) + `verifyingContract`; UA R330 adds `chain_uid` | EIP-712 domain |
| Aptos | `chain_id::get()` (runtime) | AIP-62 `application ∈ origins` |
| Sui | per-network object ids (`Config`, `Account`) | none (CR-WSF-1) |
| Soroban | `network_id` (host preimage) | host auth preimage (contract + function + args) |
| Cosmos | `env.block.chain_id` (runtime), `env.contract.address` | ADR-036 doc (`chain_id: ""`, domain in payload) |
| TON | config 19 global id, master/wallet addresses | signData `domain` — checked on chain after CR-R3-7 |
| Solana | **today an admin `initialize(network)` argument** → build-time genesis hash (R3D CR-R3-4) | none (CR-WSF-1) |

**Operator invariant until R3-FIX6 lands:** never reuse a Solana program id across clusters; the node's RS12-8
check (RPC genesis == configured network == `Config.network`) must stay on.

### Passkey format (review M2)

The note documents wallet formats only. The passkey (WebAuthn) format and its single `clientDataJSON` grammar for
every family are normative in R3D §C and **CR-R3-1**, with the shared vectors `smartcontracts/test/vectors/webauthn_kat.json`.

### Aptos and Solana (review L3)

- **Aptos** `aptos:signMessage` (AIP-62): `APTOS\n` + `address`, `application`, `chainId`, `message`, `nonce`
  lines; the verifier is order-independent, requires `message` = the op text, `chainId` = runtime chain id, and
  `application ∈ origins` when the account has origins (`move/aptos/sources/auth.move:111-139`).
- **Solana**: `KIND_RAW` (text `"<label>:" ‖ hex(digest)`) or `KIND_OCMS` (`\xffsolana offchain` ‖ v1 ‖ 1 signer ‖
  pk ‖ text), verified by introspecting the Ed25519/secp256r1 precompile instruction (`auth.rs:90-112,197-216`).
  Text becomes readable under CR-WSF-1.

### Superseded / stale statements

| Note says | Current |
|---|---|
| Five ecosystems | eight families incl. Aptos and Solana (owner 2026-10-06) |
| TON FunC verification snippet | Tact implementation, `CHKSIGNU` over the same cell (`common.tact:265-272`); passkey via `P256_CHKSIGNS` |
| HIP-632 costs 3 000 gas | 100 000 gas cap per call (`HederaAccountAuth.sol:18-21`) |
| `hedera-local-node` as the local tool | `solo` |

### Amendments needed in other specs (recorded; owner syncs)

| Spec | Amendment |
|---|---|
| SCaaS.md | §7.5 (Sui) and §7.7 (Solana): readable on-chain-rebuilt message, passkey-first, `POLICY_PASSKEY_FOR_VALUE`, residual risk (CR-WSF-1); §7.2 Hedera: ED25519 needs a raw signer (CR-WSF-2). |
| net-solana, net-sui | CR-WSF-1 message format and policy bit. |
| S4F | clientkeys non-EVM signers render the CR-WSF-1 text. |

### Code streams (new; for TODO)

| Stream | Scope | Ruling |
|---|---|---|
| **WSF-FIX1** | Solana program: readable OCMS text rebuilt from `MetaOp`, `POLICY_PASSKEY_FOR_VALUE`; clientkeys/app render the same text; tests | CR-WSF-1 |
| **WSF-FIX2** | Sui: readable UTF-8 personal message rebuilt from `MetaOp`, `Keys.policy` bit (after R3-FIX7); tests | CR-WSF-1 |

### Revision history

| Rev | Date | Change |
|---|---|---|
| 1.0 | 2026-10-03 | agy research note (five ecosystems) |
| 1.1 | 2026-10-07 | Claude review 1 folded: 10 findings accepted, 0 rejected; rulings CR-WSF-1…2; streams WSF-FIX1…2; signing-domain table; stale statements marked |
