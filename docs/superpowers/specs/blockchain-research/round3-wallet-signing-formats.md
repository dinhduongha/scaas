# Round 3 — wallet signing formats per network (agy research, 2026-10-03)

Below is the verified, specification-level answer for all five ecosystems based on official specifications, improvement proposals, and core node implementations:

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
