# `ua-rs-native`: Bitcoin, NEAR and Polkadot keys and raw native signing in `ua-rs`: design

**Status:** SPECIFIED, nothing built. Branch `ua-rs-native` (from `ua-rs-sign` `d823d61f0`), worktree
`.claude/worktrees/ua-rs-native`. Work order: TODO item 8c. **Owner 2026-11-17 ("Code luôn, không chờ sau p6h"): the round runs
now**: spec → Fable review → fixes → code task by task ([plan](../plans/2026-11-17-ua-rs-native.md)). It does not depend on
`scaas-sdk`. No contract, node or SCaaS signed-record byte format changes; `smartcontracts/vectors/ua/*.json` stay byte for byte.
**Revised after Fable's review** (2026-11-17, `20261117-11-fable-fable-high-spec.md`, F1–F24, kept outside the repository; every
finding applied, mapped in §18). Rule ids introduced here (SPECIFIED, defined once in the component docs):
[CLI-SGN-52, CLI-SGN-53, CLI-SGN-54](../../clients/signers-clientkeys.md#92-native-networks-of-an-apps-native-backend-specified),
[CLI-UAL-44 to CLI-UAL-47](../../clients/ua-libraries.md#native-networks-of-the-apps-backend-specified), the records
[CLI-UAL-62](../../decisions.md#CLI-UAL-62) (owner rulings) and [CLI-UAL-63](../../decisions.md#CLI-UAL-63) (controller calls).
Rows marked **follows** apply a stated rule; rows marked **proposal** are the controller's and the owner may override them
(collected in §15). UNAUDITED.

## 1. Owner rulings this spec follows

All settled; quoted as given, with the place each one is recorded.

| # | Date | Ruling | Where |
|---|---|---|---|
| R1 | 2026-11-17 | "ua-rs is the only signer is the rule, so it counts from scaas-sdk down": an end-user app above `scaas-sdk` may sign other chains' native transactions with its own library | CLI-UAL-01 Scope, `decisions.md` CLI-UAL-01 Change (`d823d61f0`) |
| R2 | 2026-11-17 | "ua-rs chưa có Bitcoin, NEAR, Polkadot => cần bổ sung" (ua-rs has no Bitcoin, NEAR, Polkadot: add them): the gaps (1)–(6) of TODO 8c | TODO 8c, [CLI-UAL-62](../../decisions.md#CLI-UAL-62) |
| R3 | 2026-11-17 | "Polkadot theo đề xuất (b)": sr25519 with `substrate-bip39` derivation like polkadot.js, in every backend of the app | TODO 8c (3), CLI-UAL-62 |
| R4 | 2026-11-17 | "Junction ... theo đề xuất": the account is the bare mnemonic (no junction, polkadot.js default); junctions an optional per-account setting | TODO 8c (3), CLI-UAL-62 |
| R5 | 2026-11-17 | "Code luôn, không chờ sau p6h" (code now, do not wait for P6h) | CLI-UAL-62; plan header |
| R6 | 2026-11-12 | `ua-rs` is an audit unit of the pre-freeze audit | TODO item 7 |

Standing rules this spec applies: [CLI-UAL-01](../../clients/ua-libraries.md#CLI-UAL-01) (clientkeys writes every vector row first),
[CLI-UAL-02](../../clients/ua-libraries.md#CLI-UAL-02) (no release signature takes randomness),
[CLI-UAL-03](../../clients/ua-libraries.md#CLI-UAL-03) (bounded input), [CLI-UAL-04](../../clients/ua-libraries.md#CLI-UAL-04) (errors
carry no input), [CLI-UAL-09](../../clients/ua-libraries.md#CLI-UAL-09) / [CLI-UAL-10](../../clients/ua-libraries.md#CLI-UAL-10)
(store and arena), [CLI-UAL-25](../../clients/ua-libraries.md#CLI-UAL-25) (no test feature in a production artifact),
[CLI-SGN-29](../../clients/signers-clientkeys.md#CLI-SGN-29) (one key, one purpose; no generic sign-this-digest for UA keys; a native
path's key is its network's alone, its Change), [CLI-SGN-40](../../clients/signers-clientkeys.md#CLI-SGN-40) (raw digest only behind
the opt-in).

## 2. Goal, scope, non-goals

**Goal.** `ua-rs` can be backend (c) of the end-user app's native signing (R1): for every chain the app routes to it, it derives the
same key and address as the app's other backends from the same mnemonic and passphrase, and signs the bytes the app's encoder
produced, so the app's CI can compare addresses and signed bytes (deterministic schemes) or cross-verify signatures (randomized
schemes).

**In scope (the six gaps of TODO 8c):**
1. `bitcoin_p2wpkh` (BIP-84, ECDSA) and `bitcoin_p2tr` (BIP-86, BIP-341 key-path tweak, BIP-340), receive and change chains: §5.
2. `near` (ed25519, SLIP-10): §6.
3. `polkadot` (sr25519, `substrate-bip39`, schnorrkel, junctions, SS58): §7.
4. Raw-message signing for Ed25519 and sr25519 native keys, behind `AllowRawDigest`, bounded: §8.
5. The blind-signing guard, split into what `ua-rs` enforces and what the caller must do: §9.
6. Native vectors written by clientkeys first, read by `ua-rs` and every binding: §12.

**Non-goals.**
- **No transaction encoder for a non-EVM chain in `ua-rs`.** Encoding stays with the app's backends (TxCodec, Trust Wallet Core).
  `ua-rs` derives keys, gives addresses and witness programs, and signs a 32-byte digest or a bounded message it is handed. For
  Bitcoin that is the sighash (§5.3).
- No Bitcoin account level other than `0'` (BIP-44's account level is the app's `index`-free default; another account is later
  work when an app asks).
- No import of a Bitcoin, NEAR or Polkadot secret (`import_native_key`, clientkeys `importKey`), and no imported UA of them
  (`imported_ua_key`, clientkeys `importedKind` / `importedUAKey`): refused in both libraries (§4.1).
- No key proof on the four new networks (§4.2): they have no SCaaS family and no verifier of one.
- No Polkadot `///password` in a path (§7.3): the passphrase is the wallet's BIP-39 passphrase, given once.
- No new SCaaS kind, purpose or UA rule: these keys are native keys (CLI-SGN-29 Change: a native path's key stays its network's
  alone).
- No Bitcoin script path, no PSBT, no Taproot script tree (BIP-86 key path only).
- No off-chain message format (NEP-413 payload, Substrate `<Bytes>`, Solana off-chain message, Aptos `APTOS\n` message) is built in
  `ua-rs`; `sign_message` refuses the two envelopes SCaaS families verify (§8).

## 3. Summary

| `Network` (name) | Path of key `i` | Curve, scheme | Address (`address()`) | What `ua-rs` signs |
|---|---|---|---|---|
| `BitcoinP2wpkh` (`bitcoin_p2wpkh`) | `m/84'/c'/0'/k/i`, `k` 0 receive or 1 change, `c` 0 or 1 | secp256k1, ECDSA RFC 6979, low-s | BIP-173 bech32, witness v0, `HASH160(pk)`; hrp `bc` (c = 0) or `tb` (c = 1) | the BIP-143 sighash it is given (`sign_digest`) |
| `BitcoinP2tr` (`bitcoin_p2tr`) | `m/86'/c'/0'/k/i` | secp256k1, BIP-340 over the BIP-341-tweaked key | BIP-350 bech32m, witness v1, `x(Q)` | the BIP-341 sighash it is given (`sign_digest`) |
| `Near` (`near`) | `m/44'/397'/i'` (no coin override) | ed25519, SLIP-10 | implicit account id `hex(pk)` (64 lower-case hex) | a 32-byte digest (`sha256(borsh(tx))`, a NEP-413 hash) or a message |
| `Polkadot` (`polkadot`) | the bare mnemonic; optional junction path | sr25519 (schnorrkel), `substrate-bip39` | SS58, prefix 0 (`ss58_address(p)` for any other) | a message (the signing payload) or a 32-byte digest |

The nine existing networks keep their paths, addresses and bytes. Ed25519 networks among them (`hedera_ed25519`, `sui`, `stellar`,
`ton`, `aptos`, `solana`) gain the message form of §8.

## 4. Shared changes (all four networks)

### 4.1 `Network`, its scheme, and the two lists in clientkeys (**proposal**: names)

`ua-rs`: `Network` gains `BitcoinP2wpkh`, `BitcoinP2tr`, `Near`, `Polkadot`, names `bitcoin_p2wpkh`, `bitcoin_p2tr`, `near`,
`polkadot` (appended to `NETWORK_NAMES`; the owner's "`Network::Bitcoin`" is the pair, split as `hedera_ecdsa` / `hedera_ed25519` are,
one name per path and scheme). The private `ed25519() -> bool` becomes

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeScheme { Secp256k1Ecdsa, Bip340Taproot, Ed25519, Sr25519 }
impl Network { pub fn scheme(self) -> NativeScheme; pub fn scheme_kind(self) -> Option<u16>; }
```

`scheme_kind` (the imported UA kind) becomes `Option`: `Some(0x0108)` / `Some(0x0102)` for the nine networks as today, `None` for
the four new ones, so `import_native_key` and `imported_ua_key` refuse them (`Argument`). Every `match` on `ed25519()` (derive,
sign, signer `external_answer`, `KeyRef`) moves to `scheme()`; a missing arm is a compile error, not a silent default.

**clientkeys keeps `NETWORKS` as it is (the nine) and adds `NATIVE_NETWORKS` (the four)** in `src/seed.js`. `NETWORKS` stays the
set of `keys.json`'s native rows, of `importKey`, of `importedKind` / `importedUAKey` and of every existing test and generator loop,
so the four new networks are refused there by construction and no existing test or `ua/` vector moves. `deriveKey` looks a name up
in both lists: `polkadot`'s entry is `{ curve: 'sr25519', path: null }` and `deriveKey` refuses it with the pointer "use
`polkadotKey(entropy, passphrase, path)`" (it needs the entropy and the passphrase, §7.1). `native.json`'s `networks` lists the
thirteen names in `ua-rs`'s order (`NETWORKS` then `NATIVE_NETWORKS`).

### 4.2 What each scheme signs (`Signer for NativeKey`)

| Request | `Secp256k1Ecdsa` (nine networks) | `Secp256k1Ecdsa` (`bitcoin_p2wpkh`) | `Bip340Taproot` | `Ed25519` (`near`; the six existing as today) | `Sr25519` |
|---|---|---|---|---|---|
| `KeyProof` (`keccak256("scaas-subject-key-proof-v1" ‖ challenge)`) | yes | **no** | **no** | **no** on `near`; yes on the six | **no** |
| `RawDigest` (32 B, `AllowRawDigest`) | yes | yes | yes | yes | yes |
| `RawMessage` (1 B to 128 KiB, `AllowRawDigest`; new, §8) | no | no | no | yes | yes |
| `Eip712`, `Transaction` (EVM) | `evm`, `hedera_ecdsa`, `cosmos` as today | **no** | no | no | no |

Every **no** is the named error `Argument` (C `SCAAS_UA_ERR_ARGUMENT`), in `ua-rs` and in clientkeys (`signKeyProof`, `signTyped`,
`signTransaction`, `signMessage` throw `Argument`). A key proof is refused on the four new networks because they have no SCaaS
family and no verifier of a proof; a Taproot proof would also need a choice of key (`x(P)` or `x(Q)`) nobody checks. Today
`native_digest(req, secp256k1)` lets every secp256k1 network sign EIP-712 and EVM transactions; the Bitcoin networks are refused
explicitly so a Bitcoin key never signs an EVM record.

### 4.3 Store, arena, zeroize (**follows** CLI-UAL-09, CLI-UAL-10)

Every new secret lives in the wallet's arena and is read only through `Handle::with` under the read guard and the generation check;
handles are neither `Clone` nor `Debug`; `lock()` wipes and revokes. Slot contents: Bitcoin and NEAR keys 32 bytes as their curves
today; a Polkadot key the 64-byte schnorrkel `SecretKey` (`scalar ‖ nonce`, `SecretKey::to_bytes`).

**The `substrate-bip39` mini-secret is computed at open** (§7.1 needs the entropy *and* the passphrase, and the store keeps
neither the passphrase nor anything that gives it back): `SecretStore::open(entropy, seed, substrate_mini)` puts it into the
arena beside the entropy and the seed. The two call sites (`Wallet::from_entropy`, `Wallet::unlock_entropy`) already hold the
passphrase as given; every open path (generate, mnemonic, vault, unlock, link, restore) passes through them. Cost: one more
PBKDF2-HMAC-SHA512 of 2048 rounds per open, the same as the BIP-39 seed's. The schnorrkel types (`MiniSecretKey`, `SecretKey`,
`Keypair`) and k256's `schnorr::SigningKey` are rebuilt per operation from the slot, as the other curves' key types (outside the
arena coverage, as CLI-UAL-10 states for every crate's key types); plan T0 checks that schnorrkel 0.11.5 and k256 0.14 wipe them on
drop (Fable read 0.11.4: schnorrkel's do), and where one does not, `ua-rs` wipes its copies by hand (`Zeroizing`, `zeroize()`
before drop).

`KeyId` gains `Polkadot([u8; 32])` (the SHA-256 of the path, §7.3: one path string per key, since non-canonical spellings are
refused) and `BitcoinChange(Network, Option<u32>, u32)` (network, coin type, index of chain 1); the receive chain and the bare
Polkadot key stay `KeyId::Native(network, index, coin_type)`, and `polkadot_key("")` returns that same slot.

### 4.4 Manifest (**proposal**)

`native_key` notes `NativeEntry { network, coin_type, index }` as today for the four networks. `NativeEntry` gains `change: u32`
(still `Copy`), serialized as `"change": 1` **only when it is 1**. A Polkadot key with junctions is noted in a new list
`polkadotPaths: ["//polkadot", …]`, written after `natives` **only when not empty**. Both absences keep every earlier manifest,
vault, seal and backup row's bytes (the precedent of `importedUas`, CLI-SGN-29 Change). A path is public data, not a secret
(§7.3); restore re-derives it from the mnemonic.

The manifest is outside input on restore (a vault, a backup, a link payload; CLI-UAL-03): **at most 64 entries in
`polkadotPaths`**, each re-parsed by the §7.3 parser when the manifest is read (a stored `///pw`, a non-canonical digit or an
over-long path refuses the whole manifest, `Argument`), a duplicate refused; `change` other than absent or 1 refused.

### 4.5 Bounds (**follows** CLI-UAL-03)

| Input | Bound | Refusal |
|---|---|---|
| raw message (§8) | 1 to 131,072 bytes (`MAX_RAW_MESSAGE`); not starting with an off-chain envelope SCaaS verifies | `Argument` |
| Polkadot path (§7.3) | ≤ 512 bytes, ≤ 16 junctions, each 1 to 64 bytes, digit-only junctions canonical | `Argument` |
| manifest `polkadotPaths` | ≤ 64 paths, each a valid path, no duplicate | `Argument` |
| SS58 prefix | 0 to 16,383, not 46 or 47 | `Argument` |
| Bitcoin coin type / change | coin `None`, `Some(0)` or `Some(1)`; change 0 or 1 | `Argument` |
| NEAR coin type | `None` only (an override would alias it with `stellar` / `ton`, which share its path shape) | `Argument` |
| Polkadot `index` / `coin_type` | `0` / `None` only | `Argument` |

No new input is recursive. Errors name no input (CLI-UAL-04): a refused path or message reports `Argument` only.

## 5. Bitcoin

### 5.1 Derivation, addresses, witness programs

- **P2WPKH** (BIP-84): `d` = BIP-32 secp256k1 key at `m/84'/c'/0'/k/i` (`c` = 0 mainnet, 1 testnet / signet / regtest, `k` = 0
  receive, 1 change). Public key `pk` = 33-byte compressed. Program `HASH160(pk) = RIPEMD-160(SHA-256(pk))`. Address: BIP-173
  bech32 of `hrp`, witness version 0, the 20-byte program; `hrp` = `bc` (c = 0) or `tb` (c = 1).
- **P2TR** (BIP-86, BIP-341, BIP-350): `d0` = BIP-32 key at `m/86'/c'/0'/k/i`; `P = d0·G`; `d = d0` if `P` has even `y`, else
  `n − d0`; internal key `x(P)` (32 B). One pure function computes the tweak for both the address and the signer:

  ```rust
  pub(crate) fn taproot_tweak(internal_x: &[u8; 32]) -> Result<TaprootOutput>; // { tweak: [u8; 32], output_key: [u8; 32], odd_y: bool }
  ```

  `t = int(H_TapTweak(x(P)))` with `H_tag(m) = SHA-256(SHA-256(tag) ‖ SHA-256(tag) ‖ m)` (BIP-86: no script tree, so no Merkle root in
  the tweak); `t ≥ n` → `Argument`; `Q = lift_x(x(P)) + t·G`, `Q ≠ ∞`. Address: BIP-350 bech32m of `hrp`, witness version 1,
  `x(Q)`. `public_key()` returns the compressed `P` (the internal key; a PSBT's `tap_internal_key` is its x).
- **Witness program accessor:** `NativeKey::witness_program() -> Option<(u8, Vec<u8>)>`: `(0, HASH160(pk))` or `(1, x(Q))` for the
  Bitcoin networks, `None` for the others. The app builds a `scriptPubKey` (`OP_0 <20>` / `OP_1 <x(Q)>`) and a `bcrt…` regtest
  address from it; `address()` prints `bc` / `tb` only.
- The existing hand-written `bech32` (cosmos) gains the segwit form: data = `[version] ‖ convertbits(program, 8, 5)`, checksum
  constant 1 (bech32, v0) or `0x2bc830a3` (bech32m, v1), as BIP-173 / BIP-350.

### 5.2 Signing

- **P2WPKH**: `sign_digest(sighash, AllowRawDigest)` → ECDSA secp256k1 over the 32 bytes, no prehash, RFC 6979 with no extra data,
  low-s, `r ‖ s ‖ v` (the existing secp256k1 form). The app DER-encodes `(r, s)`, appends the sighash type and builds the witness
  `[sig, pk]`. **No low-R grinding**: a backend that grinds `R` (Bitcoin Core does) yields other bytes for the same key and sighash;
  the app compares bytes only with backends that do not grind, else verifies.
- **P2TR**: `sign_digest(sighash, AllowRawDigest)` → BIP-340 `Sign(d + t mod n, sighash, aux)` (BIP-340 negates the key itself when
  `Q` has odd `y`), `aux` 32 bytes from `os_aux()` (`Error::Rng` on failure; CLI-UAL-02), 64 bytes. Before return the signature is
  verified against `x(Q)` (BIP-340 Verify; the last step the existing `Bip340` path already runs, T21 L08): a faulty signature never
  leaves. The app appends the sighash type byte when it is not `SIGHASH_DEFAULT`. The tweak is recomputed per signature from the
  public `x(P)` through `taproot_tweak`; the slot keeps `d0`. **The negated and tweaked scalars (`d`, `d + t`) are second long-term
  secrets** (the tweaked one alone spends the output): held in `Zeroizing` buffers and k256 scalars wiped before return; plan T7
  checks k256 0.14's `schnorr::SigningKey` drop.

### 5.3 The sighash boundary (decision)

**`ua-rs` signs the BIP-143 / BIP-341 sighash it is given; it does not compute it.** Reasons:
1. A sighash needs the transaction model: inputs and outpoints, every spent output's amount and `scriptPubKey` (BIP-341 commits to
   all of them), sequence, outputs, locktime, the sighash type, the annex. That is a Bitcoin encoder, which the owner placed with the
   app's backends (R1; §2 non-goals).
2. The cross-check still compares signed bytes: the app's two encoders (TxCodec and Trust Wallet Core's `TransactionCompiler`
   pre-image hash) each compute the sighash, the app compares those 32 bytes across encoders, and `ua-rs`'s ECDSA signature over it is
   deterministic (RFC 6979), so the assembled witness is byte-equal across backends. Taproot is randomized (`aux`): cross-verified.
3. It is the smallest surface: no new signing call (the existing `sign_digest` with the existing marker), no new parser, nothing to
   fuzz.

What it costs: a raw 32-byte digest hides its preimage, so the guard of §9 applies. Not taken: a `sign_bitcoin_input(tx_json, index)`
with a sighash engine in `ua-rs` (an encoder plus a JSON transaction parser at the trust boundary, for no gain in the cross-check).

### 5.4 Known-answer entry points (feature `vectors`)

Which function consumes which published row (§12.2 `external`):
- BIP-340 `test-vectors.csv` signing rows: the existing `sign_raw(0x0103, secret, msg, aux)` and verify rows `verify::bip340`. They
  check the BIP-340 primitive, not the tweak.
- BIP-341 `wallet-test-vectors.json` `scriptPubKey` rows **whose `scriptTree` is null**: `taproot_tweak` (tweak, output key, address).
- BIP-341 `keyPathSpending` inputs **whose `merkleRoot` is null** (T0 lists which, with their `aux`): a new
  `vectors_taproot_sign(internal_secret: &[u8; 32], sighash: &[u8; 32], aux: &[u8; 32])` running the release signer's code (negate,
  tweak, BIP-340, self-check), absent from a release build (compile-fail doc test). Rows with a non-null Merkle root are out of scope
  (no script tree here).
- BIP-143 native P2WPKH: `sign_raw(0x0001, …)` as today.
- BIP-84 / BIP-86 mnemonic rows (receive and change): `native_key` / `bitcoin_key`.

## 6. NEAR

- Path `m/44'/397'/i'`, SLIP-10 ed25519 (hardened only, the existing `slip10`); no coin-type override (§4.5). Index 0 is
  `m/44'/397'/0'`: the default `KEY_DERIVATION_PATH` of `near-seed-phrase` (`parseSeedPhrase`, the library of NEAR's web wallet and
  of the JS `near-cli`); the `near-cli-rs` examples pass the same path (`--seed-phrase-hd-path "m/44'/397'/0'"`), and plan T0 reads
  `near-cli-rs`'s source for its default. TODO 8c's `m/44'/397'/0'` is index 0; the app contract's `m/44'/397'/i'` agrees. Not used:
  the Ledger path `44'/397'/0'/0'/1'`.
- Address: the implicit account id, the 64 lower-case hex characters of the 32-byte public key. The public key text
  `ed25519:<base58(pk)>` is a display form the app makes; the vectors carry it (`publicKeyText`).
- Signing: a NEAR transaction is signed as ed25519 over `sha256(borsh(Transaction))` and a NEP-413 message over the SHA-256 of its
  Borsh payload: both 32 bytes, so `sign_digest`; the app builds and hashes. `sign_message` (§8) also works on a NEAR key.

## 7. Polkadot (sr25519)

### 7.1 Mini-secret (`substrate-bip39`, **follows** R3)

`mini = PBKDF2-HMAC-SHA512(P = entropy, S = "mnemonic" ‖ UTF-8(passphrase), c = 2048, dkLen = 64)[0..32]`, where `entropy` is the
BIP-39 entropy (16 to 32 bytes, the wallet's own at its length) and `passphrase` the wallet's BIP-39 passphrase **as given, not
NFKD-normalized**: `substrate-bip39` `mini_secret_from_entropy(entropy, password)` (used by `subkey` and `sp-core`) and polkadot.js
`mnemonicToMiniSecret` both take the string as is. Consequences: an ASCII passphrase (and the empty one) gives the same account in
every tool; an NFC and an NFD form of one non-ASCII passphrase give one BIP-39 seed (BIP-39 normalizes) but two Polkadot accounts.
The vectors pin both rows (§12.2); the app warns on a non-ASCII passphrase (app contract §2.3). The mnemonic enters as entropy, so its
case, spacing and normalization do not matter.

### 7.2 Key expansion and the bare account (**follows** R4)

The bare account (no junction) is `MiniSecretKey::from_bytes(mini).expand_to_keypair(ExpansionMode::Ed25519)` (schnorrkel 0.11):
`h = SHA-512(mini)`, the low half clamped as Ed25519 (`&248`, `&63`, `|64`) and divided by the cofactor as the scalar, the high half
the nonce; public key the 32-byte compressed Ristretto point. This is polkadot.js's and `subkey`'s default account
(`sr25519KeypairFromSeed`, `Pair::from_phrase(phrase, password)`). Mainnet and testnets use the same key; only the SS58 prefix differs.

### 7.3 Junctions (optional per account, **follows** R4; grammar **proposal**)

`Wallet::polkadot_key(path: &str)` derives a junction path from the bare key, as `sp-core` `Pair::derive` and polkadot.js
`keyFromPath`:

- Grammar: `path = ("//" junction | "/" junction)*`; `//` hard, `/` soft; `""` is the bare key. A junction is 1 to 64 bytes of
  printable ASCII `0x21`–`0x7e` other than `/`. Refused (`Argument`): `///` (a password part), an empty junction, a junction that
  starts with `0x` (polkadot.js reads it as raw hex bytes, `sp-core` as a string: ambiguous), a leading `+`, a digit-only junction
  that does not fit in `u64`, **a digit-only junction with a leading zero other than `0` itself** (`//007` and `//7` are one key in
  `sp-core` and polkadot.js; refusing the long spelling keeps one path string, one `KeyId` and one manifest entry per key; `//0`
  accepted); more than 16 junctions or more than 512 bytes. A path that passes is its own canonical form.
- Chain code: a digit-only junction encodes as its `u64` little-endian (8 bytes); any other as the SCALE string: compact length
  (one byte `len << 2` for 0 to 63, two bytes `(len << 2) | 0b01` little-endian for 64) ‖ bytes. An encoding of ≤ 32 bytes is
  zero-padded to 32; a longer one is replaced by its BLAKE2b-256. So a 31-byte junction is padded (32-byte encoding), a 32-byte one
  hashed (33), and 63 / 64 sit on the two sides of the compact length's one-byte / two-byte boundary (64 / 66 bytes, both hashed).
- Hard step: `SecretKey::hard_derive_mini_secret_key(Some(ChainCode(cc)), b"")` → `MiniSecretKey`, expanded in `Ed25519` mode.
  Soft step: `SecretKey::derived_key_simple_rng(ChainCode(cc), b"", rng)`. schnorrkel draws a soft-derived key's new **nonce half**
  from the RNG (the scalar and the public key are deterministic): `ua-rs` hands it the one-shot RNG of §7.5 over 32 bytes of
  `os_aux()`, so a soft key's signatures cannot be reproduced across tools (verify-only rows, §12.2).
- Known answers (`subkey inspect` of the development phrase `bottom drive obey lake curtain smoke basket hold race lonely fit walk`,
  empty passphrase): the bare key `0x46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a`
  (`5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV`), `//Alice` `0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d`
  (`5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY`), `//Bob`
  `0x8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48` (`5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty`). Plan T0
  re-derives them with both libraries, and the junction rows of lengths 31, 32, 63 and 64 (hard and soft) against `subkey` /
  polkadot.js; a mismatch stops the round.

A path is public data in this design: it names an account, it is not a password, and it is listed in the manifest (§4.4). A user who
wants a secret component uses the BIP-39 passphrase.

### 7.4 SS58

`ss58(prefix, pk) = base58(pre ‖ pk ‖ checksum)`, `checksum = BLAKE2b-512("SS58PRE" ‖ pre ‖ pk)[0..2]`; `pre` one byte for
`prefix < 64`, else two bytes `((prefix & 0xfc) >> 2) | 0x40`, `(prefix >> 8) | ((prefix & 0x03) << 6)`. `address()` is prefix 0
(Polkadot); `ss58_address(prefix)` gives any other allowed prefix (§4.5). The prefix belongs to a chain, not to "mainnet / testnet":
42 is the generic Substrate prefix (Westend among others); plan T0 records the prefix of each testnet the app names (Paseo's from its
chain spec) for the app's chain table.

### 7.5 Signing and the one-shot RNG (**follows** R3, CLI-UAL-02)

`sign_message(msg, AllowRawDigest)` and `sign_digest(d, AllowRawDigest)` (the 32 bytes as the message): schnorrkel
`Keypair::sign(attach_rng(signing_context(b"substrate").bytes(msg), OneShot(r)))`, 64 bytes (schnorrkel's marker bit set in byte 63).

**Randomness:** `r` is 32 bytes drawn first with the existing `os_aux()` (`try_fill_bytes`, `Error::Rng` on failure), so an OS-RNG
failure is an error and never a panic inside merlin (whose `finalize` calls the infallible `fill_bytes`). `OneShot(r)` is a
`RngCore + CryptoRng` that yields exactly those 32 bytes once, then wipes them; any further read, or a read of another length,
yields nothing and marks it misused, and the signer then discards the signature and returns `Error::Rng`. The release path and the
`vectors` fixed-randomness path (§10.1) run the same code and differ only in where `r` comes from. The same holds for the soft step of
§7.3. The nonce is merlin's witness over the transcript, the key's nonce half and `r`: hedged, so a weak `r` does not leak the key,
and every release signature is fresh.

Before return the signature is verified against the public key (`PublicKey::verify`, same context). The app passes the signing
payload: for an extrinsic the SCALE-encoded payload, or its BLAKE2b-256 when it is longer than 256 bytes (Substrate's rule; the
app's encoder applies it, `ua-rs` signs what it is given).

## 8. Raw-message signing (Ed25519 and sr25519 native keys)

```rust
pub const MAX_RAW_MESSAGE: usize = 131_072;
impl NativeKey { pub fn sign_message(&self, message: &[u8], allow: AllowRawDigest) -> Result<Vec<u8>>; }
pub fn sign_message_by(key: &dyn Signer, message: &[u8], allow: AllowRawDigest) -> Result<Vec<u8>>;
// SignRequest gains, #[non_exhaustive] and built only by sign_message_by:
//     RawMessage { message: Vec<u8> }
```

- Signs `message` as the scheme's message: ed25519 (`ed25519-dalek`, RFC 8032, deterministic) or sr25519 (§7.5). The preimages it
  is for: a Solana transaction message, Aptos `sha3_256("APTOS::RawTransaction") ‖ BCS(raw_txn)`, Hedera `bodyBytes`, a Substrate
  signing payload; NEAR, GRAM, Sui and Stellar sign 32-byte hashes through `sign_digest`.
- Refused with `Argument`: an empty message or one over `MAX_RAW_MESSAGE`; a secp256k1 or Taproot key (they sign digests only); **a
  message that starts with an off-chain envelope a SCaaS family verifies**: `0xff ‖ "solana offchain"` (Solana off-chain message,
  [solana.md](../../networks/solana.md), the SCaaS OCMS v1 envelope) or `"APTOS\n"` (the AIP-62 full message,
  [aptos.md](../../networks/aptos.md)). A transaction preimage never starts so (a Solana message starts with its header, an Aptos
  one with the `APTOS::RawTransaction` hash). This keeps the SCaaS payloads of the Solana and Aptos families (the only two of the
  six Ed25519 families longer than 32 bytes, §9) out of the raw path; they go through the families' own checked builders. 128 KiB:
  Aptos's 64 KiB transaction limit plus its prefix, with room; Solana's 1,232-byte and Hedera's 6 KiB limits lie below.
- Same marker as `sign_digest` (`AllowRawDigest`, CLI-SGN-40): the call does not exist without the value (compile-fail doc test).
- `UaKey` has no such method (compile-fail doc test); `sign_message_by(&ua_key, …)` compiles (`UaKey` is a `Signer`) and is refused
  at run time with `Argument` (`UaKey::sign_request` takes only its own `UaMsg` / `WebAuthn` requests), tested; the C ABI refuses a UA
  key `SCAAS_UA_ERR_RAW_DIGEST_REFUSED`, as `scaas_ua_sign_digest_raw`.
- `external_answer` (phase 2, MD-13) verifies a `RawMessage` answer of an ed25519 or sr25519 external key with this crate's
  verifier, as every other answer; a BIP-340 Taproot answer against `x(Q)`.
- The marker's documentation changes with this round (plan T5): `AllowRawDigest` in `signer.rs` and clientkeys `signDigest`'s JSDoc
  say "never an **EVM** transaction hash or an EIP-7702 authorization raw; a native chain's preimage only as CLI-SGN-54", in place of
  today's "never a transaction".

### 8.1 Amendment after the scaas-sdk review (raw path; controller calls, owner: no)

Fable's review of `scaas-sdk` (F8, blind signing on the raw native path) and the coordinator's ruling of 2026-11-17: owner rule
[CLI-SGN-40](../../clients/signers-clientkeys.md#CLI-SGN-40) stands and **nothing already pinned changes**; the F8 restrictions that
concern which keys and digests reach the raw path belong to `scaas-sdk`'s raw entry, not to `ua-rs`'s existing calls. Recorded as
CLI-UAL-63 (11) to (15), §15.

1. **EVM prefixes on raw messages (in `ua-rs` and clientkeys).** `sign_message` / `signMessage` also refuse (`Argument`) a message
   whose first byte is `0x05` (the EIP-7702 authorization magic) or whose first two bytes are `0x19 0x01` (the EIP-712 prefix), on
   every key, beside the same bytes with another first byte accepted. Digests are untouched (a 32-byte hash starts with `0x05` one
   time in 256).
2. **Not in `ua-rs`:** `sign_digest` on `evm` / `hedera_ecdsa` keys stays (Merkle batch roots, CLI-SGN-40); `scaas-sdk`'s raw entry
   refuses EVM-address keys (EVM goes only through `sign_transaction`). "A bare 32-byte digest only for the Bitcoin sighash" is also
   the SDK's rule; `ua-rs`'s `sign_digest` and its rows (sr25519 and NEAR digests included) stay as they are.
3. **Envelope calls, additive.** Four new calls on `NativeKey` (and clientkeys), each on its own network only (`Argument` on any
   other), behind `AllowRawDigest`, the given bytes 1 to `MAX_RAW_MESSAGE` long; they build the chain's signing prefix or hash
   wrapper over bytes the app's encoder made, not the transaction encoding:

   | Call (clientkeys) | Network | `ua-rs` signs (ed25519) |
   |---|---|---|
   | `sign_near_transaction(tx_borsh, allow)` (`signNearTransaction`) | `near` | `sha256(tx_borsh)` |
   | `sign_sui_transaction(tx_bcs, allow)` (`signSuiTransaction`) | `sui` | `blake2b-256(0x00 0x00 0x00 ‖ tx_bcs)` (intent `TransactionData`, `V0`, app `Sui`) |
   | `sign_stellar_transaction(network_id, tx_xdr, allow)` (`signStellarTransaction`) | `stellar` | `sha256(network_id ‖ 0x00000002 ‖ tx_xdr)` (`network_id` = `sha256(passphrase)`, 32 bytes given; `ENVELOPE_TYPE_TX`) |
   | `sign_hedera_transaction(body_bytes, allow)` (`signHederaTransaction`) | `hedera_ed25519` | `body_bytes` as given |

   The existing raw `sign_digest` / `sign_message` calls and their `native.json` rows stay byte-equal. A UA key has none of them (C:
   `RawDigestRefused`). Not built here: Stellar's fee-bump envelope (type 5), NEP-413, Sui's personal message.
4. **GRAM / TON** stays off every envelope call; `ua-rs` builds no cell hash (the SDK keeps GRAM off its raw entry).
5. **Residual: Algorand `"MX"`.** The Algorand family signs `"MX" ‖ "scaas.metaop.v1:" ‖ hex(digest)` (more than 32 bytes,
   `docs/networks/algorand.md`); `ua-rs` has no Algorand native key, and the only way to an ed25519 key at `m/44'/283'/i'` is a coin-type
   override on `stellar` / `ton`, which is not an Algorand wallet's path. Recorded, not refused.

**Vectors.** `native.json` grows by appending only: a new last section `envelopes` (per call: the given bytes, the hash or bytes
signed, the signature, deterministic) and new rows at the end of `refusals` (the prefixes beside their neighbours; each envelope call on
another network, 0 and 131,073 bytes). The generator asserts that every row of the committed file is unchanged (each list section of
the old file a prefix of the new one, every other value equal).

## 9. The blind-signing guard

A raw digest or message hides what it authorizes. The guard has two halves.

**What `ua-rs` enforces** ([CLI-UAL-44](../../clients/ua-libraries.md#CLI-UAL-44)):
1. The marker: `sign_digest` and `sign_message` need the value `AllowRawDigest`; C has the calls only under their own names.
2. The key class: only native keys sign raw bytes. A UA key signs only the `ua_msg` it builds from a known purpose and its kind
   ([CLI-SGN-29](../../clients/signers-clientkeys.md#CLI-SGN-29): "expose no generic 'sign this digest with that key' for UA keys";
   signers-clientkeys §9: "no raw signature over arbitrary 32 bytes ever comes from a UA key"); an imported UA has no raw-digest call
   either (CLI-SGN-29 Change). The new networks have no imported UA (§4.1).
3. The scheme: a message only for Ed25519 / sr25519 keys, a Bitcoin key never an EVM record, no key proof on the four new networks
   (§4.2).
4. The length bound, the two off-chain envelope prefixes refused (§8), and no input in an error.
5. One key per network: NEAR and Polkadot take no coin-type override, Bitcoin only 0 or 1 (§4.5).
6. No EIP-7702 authorization and no EVM type-4 transaction can be built by `ua-rs` (CLI-SGN-40, unchanged).

**What the caller must do** ([CLI-SGN-54](../../clients/signers-clientkeys.md#CLI-SGN-54), a documented obligation; `ua-rs` cannot
check it):
1. Build the digest or message **in-process** from a transaction its own encoder made from named fields; never pass bytes received
   from a page, a server, a deep link or another app.
2. Show the user the decoded transaction (recipient, amount, fee, chain, and the chain's other value-moving fields) before signing,
   and sign only what was shown; a sighash or payload is never shown in place of the decoded fields.
3. Never pair `AllowRawDigest` with a UA key or an SCaaS kind (they go through `scaas-sdk`, R1), and never sign an EVM transaction
   hash or a 7702 authorization raw (CLI-SGN-40: EVM transactions go through `sign_transaction`).
4. Keep one key per network and purpose (the network's own path, CLI-SGN-29 Change).
5. Sign an off-chain message (a user's "sign this text") only inside the chain's own envelope, built in-process: a NEP-413 payload
   (its tag keeps it from being a transaction), a Substrate `<Bytes>…</Bytes>` wrapping, a Solana off-chain message header, an Aptos
   `APTOS\n…` full message; never the user's raw bytes. ed25519 and sr25519 have no domain separation of their own, so raw user bytes
   can be a valid transaction of the same chain.

**Residuals.**
- A Bitcoin key's secp256k1 secret also controls an EVM address that nobody funds; a raw digest it signs could be that address's 7702
  authorization or a transaction of it. The caller's rule 1 is the defence, as for every secp256k1 native key today.
- `sign_message` is new on the six existing Ed25519 networks, whose native keys are also SCaaS identities where a family exists.
  Checked per family against [signers-clientkeys §9](../../clients/signers-clientkeys.md#9-derivation-and-role-keys): Hedera
  ED25519 (the EIP-712 digest), Sui (the personal-message digest), Soroban `G…` / `C…` (32-byte hashes) and GRAM (the cell hash)
  sign 32 bytes, which `sign_digest` already signs today: no new exposure. Aptos (the UTF-8 `fullMessage`, `APTOS\n…`) and Solana
  (OCMS v1, `0xff ‖ "solana offchain" ‖ …`) sign longer messages: `sign_message` refuses both prefixes (§8), so the new call opens no
  SCaaS payload to blind signing. A family envelope added later with another prefix must be added to that refusal list.

## 10. API

### 10.1 Rust (feature `wallet`)

```rust
pub enum Network { Evm, Cosmos, HederaEcdsa, HederaEd25519, Sui, Stellar, Ton, Aptos, Solana,
                   BitcoinP2wpkh, BitcoinP2tr, Near, Polkadot }
pub enum NativeScheme { Secp256k1Ecdsa, Bip340Taproot, Ed25519, Sr25519 }
impl Network { pub fn scheme(self) -> NativeScheme; pub fn scheme_kind(self) -> Option<u16>; }
impl Wallet {
    pub fn native_key(&self, network: Network, index: u32, coin_type: Option<u32>) -> Result<NativeKey>; // unchanged signature; Bitcoin: receive chain
    pub fn bitcoin_key(&self, network: Network, coin_type: Option<u32>, change: u32, index: u32) -> Result<NativeKey>; // §5.1
    pub fn polkadot_key(&self, path: &str) -> Result<NativeKey>;                                        // §7.3
}
impl NativeKey {
    pub fn address(&self) -> Option<String>;                        // §3; Some for the four new networks
    pub fn witness_program(&self) -> Option<(u8, Vec<u8>)>;          // Bitcoin only (§5.1)
    pub fn ss58_address(&self, prefix: u16) -> Result<String>;       // Polkadot only, else Argument
    pub fn sign_digest(&self, d: &[u8; 32], allow: AllowRawDigest) -> Result<Vec<u8>>;   // + the new schemes
    pub fn sign_message(&self, m: &[u8], allow: AllowRawDigest) -> Result<Vec<u8>>;      // §8
}
pub fn sign_message_by(key: &dyn Signer, m: &[u8], allow: AllowRawDigest) -> Result<Vec<u8>>;
pub const MAX_RAW_MESSAGE: usize = 131_072;
```

`bitcoin_key` with `change = 0` is the same slot as `native_key`; another network or `change` outside {0, 1} is `Argument`.
Errors: no new `Error` variant; every refusal above is `Argument`, a locked wallet `WalletLocked`, a revoked handle `KeyRevoked`,
an RNG failure `Rng`. Test-only entry points (feature `vectors`, absent from a release build, compile-fail doc tests as T2–T10):
`NativeKey::vectors_sign_digest_fixed(d, r32)` (Taproot `aux`; sr25519 `r`), `NativeKey::vectors_sign_message_fixed(m, r32)`
(sr25519, ed25519 ignores `r`), `vectors_taproot_sign(internal_secret, sighash, aux)` (§5.4), `vectors_sr25519_sign_check(key, m,
r32, claimed_pk)` (signs and self-verifies against a caller-given public key: a wrong one must give `Argument`, the fault hook of the
self-check), `vectors_one_shot_reads()` (how often the one-shot RNG was read: 1 per signature), `Wallet::vectors_substrate_mini()`.

### 10.2 C ABI (`ua-c`, ABI version stays 6: additive, with a feature bit)

- `SCAAS_UA_NETWORK_BITCOIN_P2WPKH = 9`, `SCAAS_UA_NETWORK_BITCOIN_P2TR = 10`, `SCAAS_UA_NETWORK_NEAR = 11`,
  `SCAAS_UA_NETWORK_POLKADOT = 12` (appended; `NETWORKS` in the same order).
- `SCAAS_UA_FEATURE_NATIVE_NETWORKS = 1 << 12`, set in every `wallet` build of this round; the updated bindings require it at load
  and refuse an older v6 library with their existing mismatch error, instead of a late missing-symbol error.
- `scaas_ua_sign_message_raw(const ScaasUaKey*, const uint8_t* msg, size_t msg_len, uint8_t* sig, size_t* sig_len)`: a UA key
  `SCAAS_UA_ERR_RAW_DIGEST_REFUSED`; refusals of §8 `SCAAS_UA_ERR_ARGUMENT`.
- `scaas_ua_wallet_bitcoin_key(const ScaasUaWallet*, uint32_t network, uint32_t coin_type, uint32_t change, uint32_t index,
  ScaasUaKey** out)` (`coin_type` `SCAAS_UA_COIN_DEFAULT` or 0 / 1).
- `scaas_ua_wallet_polkadot_key(const ScaasUaWallet*, const char* path, ScaasUaKey** out)`: `path` NUL-terminated, `""` the bare key.
- `scaas_ua_key_address(const ScaasUaKey*, char* out, size_t* out_len)` (NUL-terminated; a UA key or a network with no address
  `SCAAS_UA_ERR_ARGUMENT`), `scaas_ua_key_ss58_address(const ScaasUaKey*, uint16_t prefix, char* out, size_t* out_len)`,
  `scaas_ua_key_witness_program(const ScaasUaKey*, uint8_t* version, uint8_t* out, size_t* out_len)`. The C ABI has no address call
  today; the C-ABI bindings need one to read the address rows.
- `scaas_ua_sign_digest_raw` serves the new schemes unchanged. No new status. The header is regenerated by cbindgen; the
  header-drift test holds it.

### 10.3 Bindings

Each binding reaches the same calls and reads the same rows (§12); its network list equals `NETWORKS` (a test per binding compares
it with `native.json`'s `networks`); each checks `SCAAS_UA_FEATURE_NATIVE_NETWORKS` (or, for the Rust-linked ones, builds against
this crate) at load.

| Binding | New surface |
|---|---|
| `ua-cxx` | `wallet_native_key` by the new names, `wallet_bitcoin_key`, `wallet_polkadot_key`, `key_witness_program`, `key_ss58_address`, `sign_message_raw` (UA key `UARawDigestRefused`) |
| `ua-qt` | derive by the new names, `bitcoinKey`, `polkadotKey(path)`, `address`, `witnessProgram`, `ss58Address(prefix)`; **no raw signing in QML** (its rule: no raw digest in QML) |
| `ua-dart-frb` | `nativeKey` by name, `bitcoinKey`, `polkadotKey`, `witnessProgram`, `ss58Address`, `signMessageRaw` |
| `ua-py` | `NETWORK_*` constants, `bitcoin_key`, `polkadot_key`, `address`, `witness_program`, `ss58_address`, `sign_message_raw` |
| `ua-go` | `Networks` appended, `BitcoinKey`, `PolkadotKey`, `Address`, `WitnessProgram`, `SS58Address`, `SignMessageRaw` |
| `ua-cs` | constants, `BitcoinKey`, `PolkadotKey`, `Address`, `WitnessProgram`, `SS58Address`, `SignMessageRaw` |
| `ua-dart` | none (identity only) |

## 11. Dependencies (supply chain: `deny.toml`, `cargo deny --all-features check`, `cargo audit`)

**Rust (`clients/ua-rs`, feature `wallet`).** New, pinned exactly at plan T0 after `cargo deny`; T0 records the exact new lock
entries and corrects this table in the same commit if 0.11.5's graph differs:

| Crate | Version | Licence | Why |
|---|---|---|---|
| `schnorrkel` | `=0.11.5` (latest release, 2025-07-14), `default-features = false`, features `["getrandom"]` only | BSD-3-Clause | sr25519. Not `alloc`: in 0.11.4 it turns on `serde_bytes` (not in the lock today) and gates only batch verification and MuSig, which this round does not use. Its `curve25519-dalek ^4.1.3`, `sha2 ^0.10.7`, `rand_core ^0.6.2` are the graph's (one `curve25519-dalek`, the `deny` rule holds); it also turns on that copy's `legacy_compatibility` and `precomputed-tables` features (feature unification: a size effect, measured by `ua-sizes`). `getrandom` so the shim never links a panicking RNG, though every call passes its own one-shot RNG (§7.5) |
| `merlin` | `3.0.0` (schnorrkel's) | MIT | STROBE transcripts; its `keccak` 0.1 and `byteorder` 1.5.0 are in the lock already |
| `getrandom_or_panic` | `0.0.3` (schnorrkel's) | BSD-3-Clause | schnorrkel's RNG shim |
| `arrayref` `0.3`, `arrayvec` `0.7` | schnorrkel's | BSD-2-Clause; MIT OR Apache-2.0 | |
| `pbkdf2` | `=0.12.2`, feature `hmac` (in the lock already through `scrypt`) | MIT OR Apache-2.0 | the mini-secret (§7.1); no `substrate-bip39` crate (one PBKDF2 call) |

Not taken: the `bitcoin` / `secp256k1` crates (k256 0.14 has BIP-340, the tweak is a few lines of k256 arithmetic, bech32m is a
constant on the existing encoder); `substrate-bip39` (PBKDF2 already in the graph); `sp-core` (a large tree for one derivation).
BSD notices go to `clients/ua-rs/NOTICE`. The `master` branch of schnorrkel moved to `curve25519-dalek` 5 and `sha2` 0.11: a later
release would need the graph to follow (an upgrade of its own, not this round).

**JavaScript (`clients/clientkeys`).** `@scure/sr25519` `2.4.0` (MIT; depends on `@noble/curves` and `@noble/hashes` `2.4.0`, the
versions clientkeys pins; audited at 0.3.0 by Oak Security, 2025-08, and self-audited at 2.2.0, per its README). Bitcoin and NEAR
need nothing new: `@noble/curves` `secp256k1` / `schnorr`, `@noble/hashes` (`pbkdf2`, `sha256`, `ripemd160`, `blake2b`),
`@scure/base` (`bech32`, `bech32m`, `base58`), `@scure/bip32`.

## 12. Vectors

### 12.1 Files (**follows** CLI-UAL-01 / AGENTS.md: clientkeys writes first)

- `smartcontracts/vectors/native/native.json` (new): written by `clients/clientkeys/scripts/native-vectors.mjs`, read by
  clientkeys' tests, `ua-rs`, `ua-c` (Python), `ua-cxx`, `ua-qt`, `ua-dart-frb`, `ua-py`, `ua-go`, `ua-cs`.
- `smartcontracts/vectors/native/rs_native.json` (new): written by a `ua-rs` test (feature `vectors`, ignored, `regenerate`) with
  OS randomness, read by clientkeys' `npm test`: the randomized rows checked both ways, as `rs_signatures.json`.
- `smartcontracts/vectors/ua/keys.json` and every other `ua/` file **do not move**: their generator iterates clientkeys `NETWORKS`,
  which stays the nine (§4.1), so adding `NATIVE_NETWORKS` adds no row there (checked: `git diff --exit-code`). The nine networks'
  address rows stay in `keys.json` `native`; the app's CI reads both files.

### 12.2 Rows of `native.json`

Mnemonics: `bip39_abandon` (`abandon ×11 about`, empty passphrase: the BIP-84 / BIP-86 test vectors' phrase), the same with `TREZOR`,
`substrate_dev` (`bottom drive obey … walk`, empty: the `subkey` answers), `pq_kat` (24 words), `non_ascii_nfc` and `non_ascii_nfd`
(the `pq_kat` words with `keys.json`'s non-ASCII passphrase in NFC and in NFD).

| Section | Rows | Compared |
|---|---|---|
| `networks` | the thirteen names, `NETWORKS` then `NATIVE_NETWORKS` | equal list |
| `addresses` | per mnemonic × new network × index {0, 1}; Bitcoin also coin 1 and change 1: `path`, `publicKey`, `address`, `witnessProgram`; P2TR also `internalKey`, `tweak`, `outputKey`; NEAR `publicKeyText`; Polkadot `miniSecret` (test phrases only), `ss58` at prefixes 0, 2, 42, 64 (the two-byte form), 16,383 | byte-equal |
| `polkadotPaths` | per mnemonic: `""`, `//polkadot`, `//paseo`, `//Alice`, `//0`, `/0`, `//1/2`, `/soft//hard`, `//18446744073709551615`, and junctions of 31, 32, 63 and 64 bytes, each hard and soft: `chainCodes`, `publicKey`, `address` | byte-equal |
| `signatures` | ECDSA P2WPKH over sighashes (deterministic); ed25519 `sign_message` per ed25519 network over 1 B, 32 B, 1,232 B and 131,072 B (deterministic); BIP-340 Taproot with fixed `aux` (zero and non-zero) and sr25519 on the bare and `//Alice` keys over 1 B, 32 B and 257 B with a fixed `r` (both **test-only fixed randomness**, the Rust side through the `vectors` entry points); sr25519 on soft keys, verify-only | byte-equal, or verify-only where marked |
| `refusals` | §4.5 and §7.3 refusals (each with its accepted neighbour: `//0` beside `//007`, 64 bytes beside 65, 16 junctions beside 17); 0 and 131,073-byte messages; messages starting `0xff ‖ "solana offchain"` and `"APTOS\n"` (the same bytes without the prefix accepted); `sign_message` on a secp256k1 and a Taproot key; a key proof on each new network (an `evm` key proof accepted); a Bitcoin key on EIP-712; coin type 2 on Bitcoin; any coin type on NEAR and Polkadot; Polkadot index 1; change 2; the import and the imported UA of each new network (an `evm` import accepted) | `Argument` |
| `external` | published known answers, each with source and the sha256 of the downloaded file (pinned downloads read from `NATIVE_DOWNLOADS`, as `PQ_DOWNLOADS`): BIP-84 and BIP-86 test vectors (`abandon … about`: receive index 0 `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu` and `bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr`, change index 0 `bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el` and BIP-86's first change address, all re-read from the BIP texts at T0); BIP-143's native P2WPKH example; BIP-340 `test-vectors.csv`; BIP-341 `wallet-test-vectors.json` (`scriptPubKey` rows with a null `scriptTree`, `keyPathSpending` inputs with a null `merkleRoot`); BIP-350 address rows; `substrate-bip39`'s test vectors; the `subkey` answers of §7.3; one `subkey sign` (or polkadot.js) signature of `//Alice` over a fixed message, verify-only, command recorded at T0; the SLIP-10 ed25519 vectors (already checked by `ua-rs`) | byte-equal where the source is deterministic under this spec's rule, else verify-only (below) |

Rules of the rows:
- **Byte-equal vs verify-only, published rows.** A published ECDSA signature (BIP-143) is byte-equal only if RFC 6979 with no extra
  data reproduces it; a BIP-341 `keyPathSpending` signature only if T0 finds its `aux` (else both are verify-only, and clientkeys'
  own rows are the byte-equal ones). Until T0's record exists, the `external` "byte-equal" column is a hypothesis.
- **sr25519 deterministic rows are test-only.** schnorrkel's witness reads 32 bytes from the RNG once (§7.5); `@scure/sr25519`
  `sign(sk, msg, random)` keys the same STROBE step with `random`. Plan T0 checks equality over {bare, `//Alice`, one soft-derived
  key given to both libraries as the same 64-byte secret} × {1 B, 32 B, 257 B}. If any pair differs, every sr25519 signature row is
  verify-only both ways (`native.json` and `rs_native.json`), and then **no row pins the nonce derivation byte for byte**: the
  cross-library verify and the published `subkey` signature still pin the context string, the marker bit and the key, not the
  witness; that residual is accepted and stated in CLI-UAL-47. Release builds draw `r` from the OS RNG (CLI-UAL-02).
- **Both ways.** `ua-rs` verifies every clientkeys signature; clientkeys verifies every row of `rs_native.json` (OS-random Taproot and
  sr25519, soft keys), so a bug shared by one library's signer and verifier cannot pass.
- **Generator assertions** (each makes a branch's mutant fail): Taproot rows include internal keys of both `y` parities and output
  keys of both parities; Polkadot paths include a padded 32-byte encoding, a hashed one and the two-byte compact length; every scheme
  has at least one byte-equal signature row; no row is both `deterministic` and `verify-only`.

## 13. Tests (each negative test with its positive control; mutants per task, plan)

- **Derivation.** Every `addresses` / `polkadotPaths` row in `ua-rs` and each binding; the external known answers; index 0 ≠ index 1;
  change 1 ≠ change 0; Bitcoin coin 1 → `tb`; the NFC / NFD pair: equal BIP-39 seed (existing `keys.json` row), different Polkadot
  keys; `witness_program` equals the address's program.
- **Signing.** Every deterministic row byte-equal; every verify-only row verifies; `ua-rs`'s own Taproot / sr25519 signature verifies
  under clientkeys (via `rs_native.json`); a fixed-randomness signature equals clientkeys'; the one-shot RNG is read once per
  signature (`vectors_one_shot_reads`); an RNG hook that fails gives `Error::Rng`, never a panic.
- **Refusals** (each next to the same call accepted with one value changed): every `refusals` row; `UaKey::sign_message` and a
  `sign_message` without the marker do not compile (compile-fail doc tests beside compiling controls); `sign_message_by(&ua_key, …)`
  → `Argument` beside a native key accepted; a UA key on `scaas_ua_sign_message_raw` → `RawDigestRefused`; clientkeys
  `importedUAKey` of each new network → `Argument` beside `evm`.
- **Custody.** A Polkadot, Bitcoin and NEAR handle after `lock()` → `KeyRevoked`; the slot lies in the arena
  (`vectors_secret_in_arena`); the mini-secret wiped with the arena (the chunk-release counter of T10); no input in an error string
  (CLI-UAL-04 test extended to the path and message calls).
- **Bounded input and fuzz.** A fuzz target `polkadot_path` (the junction parser) and its cap regress file in `fuzz_caps`; a manifest
  with 65 `polkadotPaths` and one with a stored `///pw` refused (64 valid accepted).
- **Mutants** (each must turn a test red; listed per task in the plan): sign Taproot with the untweaked key; skip the odd-`y`
  negation; tweak with a Merkle root of 32 zero bytes; bech32 constant on v1 / bech32m on v0; `bc` for coin 1; change chain ignored;
  PBKDF2 over the BIP-39 seed instead of the entropy (the app's old code); NFKD the passphrase; `ExpansionMode::Uniform`; context
  `substrat`; hard ↔ soft; drop the SCALE length prefix; one-byte compact length at 64; hash at 32 bytes (`<=` → `<`); numeric junction
  as a string; leading zero accepted; bound off by one; envelope prefix check removed; key proof accepted on a new network; NEAR
  coin override accepted; `OsRng` passed to merlin directly (the failing-RNG test goes red); self-verify removed (the fault hook);
  `RawMessage` accepted by `UaKey::sign_request`; `importedKind` accepting `NATIVE_NETWORKS`; the C marker check removed (UA key
  signs).

## 14. Rule ids and `decisions.md`

Defined once, status SPECIFIED until the plan's tasks land:

| Id | Home | Rule | `owner` |
|---|---|---|---|
| CLI-SGN-52 | signers-clientkeys §9.2 | the four native networks: names, paths (receive and change), curves, addresses; no key proof, no import | yes (R2), with controller clauses named |
| CLI-SGN-53 | signers-clientkeys §9.2 | Polkadot accounts: `substrate-bip39` from entropy and the passphrase as given, Ed25519 expansion, the bare account, junction grammar and chain codes, SS58 | yes (R3, R4), grammar a controller clause |
| CLI-SGN-54 | signers-clientkeys §9.2 | the caller's half of the blind-signing guard | yes (TODO 8c (5)), item (5) a controller clause |
| CLI-UAL-44 | ua-libraries | raw native signing in `ua-rs`: `sign_message`, the marker, native keys only, schemes, bound, envelope prefixes; the library's half of the guard | no |
| CLI-UAL-45 | ua-libraries | Bitcoin: `ua-rs` signs the sighash it is given; ECDSA without grinding; the BIP-86 tweak inside `ua-rs`; `aux` from the OS RNG; witness programs | no |
| CLI-UAL-46 | ua-libraries | the sr25519 signer: schnorrkel, context `substrate`, the one-shot RNG over `os_aux()`, self-verify, the mini-secret in the arena at open | yes (R3), with controller clauses named |
| CLI-UAL-47 | ua-libraries | the native vectors: `native.json` first by clientkeys, `ua/` files frozen, byte-equal vs verify-only, fixed randomness test-only, both ways | no |
| CLI-UAL-62 | `decisions.md` (record) | the owner rulings R2–R5 verbatim | yes |
| CLI-UAL-63 | `decisions.md` (record) | the controller calls of §15 | no |

## 15. Controller calls (**proposal**, the owner may override; recorded as CLI-UAL-63)

1. Network names `bitcoin_p2wpkh`, `bitcoin_p2tr`, `near`, `polkadot`; C constants 9–12; clientkeys `NETWORKS` kept at nine beside
   `NATIVE_NETWORKS` (§4.1).
2. `ua-rs` signs a given Bitcoin sighash and computes none (§5.3).
3. Raw-message bound 131,072 bytes; the Solana and Aptos off-chain envelopes refused on the raw path (§8).
4. Junction grammar: printable ASCII, 1 to 64 bytes, no `0x` prefix, no `+`, `u64` digits, no leading zero, 16 junctions, 512 bytes;
   a path is public (§7.3).
5. The mini-secret computed at open and kept in the arena; the one-shot RNG over `os_aux()` (§4.3, §7.5).
6. `polkadotPaths` (≤ 64, re-parsed) and `change` in the manifest, written only when present (§4.4).
7. `native.json` a new file, `ua/` files frozen (§12.1).
8. C ABI stays 6 (additive) with feature bit 12; `scaas_ua_key_address`, `scaas_ua_key_witness_program` added (§10.2).
9. The Bitcoin change chain (`change` ∈ {0, 1}, `bitcoin_key`) is derived, so an imported mnemonic's change-chain funds are reachable;
   no other account level (§2, §5.1).
10. No key proof and no import on the four new networks; NEAR without a coin-type override (§4.2, §4.5).
11. Raw messages starting `0x05` or `0x19 0x01` refused in `ua-rs` and clientkeys; digests untouched (§8.1 item 1).
12. EVM-address keys keep `sign_digest` in `ua-rs` (CLI-SGN-40); refusing them, and a bare digest only for the Bitcoin sighash, is
    `scaas-sdk`'s raw entry's rule (§8.1 item 2).
13. The four envelope calls (NEAR, Sui, Stellar, Hedera Ed25519), additive, behind `AllowRawDigest`, own network only (§8.1 item 3).
14. GRAM / TON on no envelope call; no cell hash in `ua-rs` (§8.1 item 4).
15. `native.json` grows by appending only, asserted by its generator; Algorand `"MX"` recorded as a residual (§8.1).

## 16. Agreement with the app contract

Compared with the app's `app-common/spec/app-core-contract.md` at `38ed463` ("Align the app-core contract with the ua-rs-native
spec"): §2.3, §3, §3.1, §5, §5.1, §8, §9, §9.1, §10. The app's earlier `three-frontends` spec and `scaas-app-next` plan are superseded
by it.

| Item | App contract | This spec | Agrees? |
|---|---|---|---|
| Bitcoin paths | §3: BIP-84 `m/84'/0'/0'/0/i`, BIP-86 `m/86'/0'/0'/0/i`, coin `1'` on testnets | the same, plus the change chain `…/1/i` | yes for receive; **the contract adds change** (§9.1 says neither side derives it, §5.1 "change is an explicit output": now it can be a change-chain address) |
| Bitcoin names | §9.1: one chain `bitcoin` with two account types, mapped at the boundary | two networks | yes (mapped) |
| Regtest | not stated | `witness_program`, the app encodes `bcrt` | the contract may name it |
| NEAR | §3: `m/44'/397'/i'`, implicit account | the same; no coin-type override | yes |
| Polkadot derivation | §3.1 items 1–3, 5, 6 | §7.1, §7.2, index 0 only, context `substrate` | yes |
| Polkadot passphrase | §2.3, §3.1: as entered, not NFKD; the front-end warns | §7.1 | yes |
| Junction grammar | §3.1 item 4: 1 to 64 bytes, `0x`, `+`, `u64`, 16 / 512 | the same, **plus: a digit-only junction with a leading zero refused** | **the contract adds the leading-zero refusal** (`JunctionInvalid`) |
| SS58 prefix | §3 `polkadot`: "prefix 0 on mainnet, 42 on testnet" | per chain (§7.4); T0 records Paseo's from its chain spec | **the contract's chain table should carry the prefix per chain** |
| Error names | §7: `JunctionInvalid`, `IndexUnsupported`, … | `Argument` for each | yes, mapped at the boundary |
| Signature rules | §5: RFC 6979 no extra entropy, low-S, no low-R grinding; RFC 8032; sr25519 randomized | §5.2, §7.5, §8 | yes |
| Preimage per chain | §9 item 5: digests for secp256k1, NEAR, `gram`, Sui, Stellar; messages for Solana, Aptos, Polkadot | §8 | yes; `sign_message` also refuses the Solana and Aptos off-chain envelopes, which no contract row passes |
| Cross-check | §8: bytes for ECDSA / Ed25519, cross-verify sr25519 and BIP-340 | §12.2 | yes |
| Vectors | §9 item 6: shared rows, the same mnemonics | §12.2 | yes; the new rows (change chain, junction lengths, refusals) are for the contract's rows too |
| Caller's obligations | §9 item 7 | §9, CLI-SGN-54 (1)–(5) | **the contract adds item (5)** (off-chain messages only in the chain's envelope) |
| Key proof on the new networks | not used | refused | yes |

## 17. Notes

- Everything here is UNAUDITED. Whatever lands on `ua-rs-native` before the pre-freeze tag is in the pre-freeze audit target
  (`ua-rs` is an audit unit, R6); the rest gets the add-on audit.
- schnorrkel's soft derivation of a secret draws a fresh nonce half; a soft key restored on another device signs with another
  nonce half. The public key and address are equal, which is what the app compares.

## 18. Review response (Fable, 2026-11-17, F1–F24)

| Finding | Severity | Where it landed |
|---|---|---|
| F1 imported UA of the new networks in clientkeys | P1 | §2, §4.1 (`NETWORKS` kept at nine, `importedKind` refuses by construction); §12.2 refusal row; §13 mutant; plan T2 |
| F2 existing clientkeys tests red at T2 / T3 | P2 | §4.1 (`NATIVE_NETWORKS` beside `NETWORKS`; `polkadot` entry without a path); §12.1; plan T2 (no existing test or generator edited) |
| F3 NEAR coin-type alias | P2 | §4.5, §6, §9 (5); refusal rows; mutant |
| F4 key proof unpinned | P2 | §2, §4.2: refused on the four networks; refusal rows; mutant |
| F5 sr25519 RNG panic | P2 | §7.5 one-shot RNG over `os_aux()`; §7.3 soft step; §10.1 hook; §13 |
| F6 Taproot known answers unreachable | P2 | §5.1 `taproot_tweak`; §5.4 entry points; §10.1; plan T7 |
| F7 change chain | P2 | §3, §5.1, `bitcoin_key`, `KeyId::BitcoinChange`, manifest `change`; §12.2 rows; §15.9; CLI-UAL-63 |
| F8 junction boundaries, non-canonical digits | P2 | §7.3 (compact two-byte form, 31 / 32 / 63 / 64 rows, leading zero refused); §4.3 one slot per key |
| F9 sr25519 byte equality and its fallback | P2 | §12.2 (T0 grid incl. a soft key, the stated residual, a `subkey` signature in `external`) |
| F10 schnorrkel `alloc` pulls `serde_bytes` | P3 | §11 (`getrandom` only; lock entries recorded at T0) |
| F11 no fault hook for sr25519 self-verify | P3 | §10.1 `vectors_sr25519_sign_check`; §12.2 generator assertions; plan T4, T8a |
| F12 no Taproot output key accessor; regtest | P3 | §5.1 `witness_program`; §10 |
| F13 `sign_message_by(&UaKey)` untested | P3 | §8, §13; plan T5 mutant |
| F14 no feature bit | P3 | §10.2 bit 12; §10.3 |
| F15 `polkadotPaths` unbounded on restore | P3 | §4.4, §4.5; §13; plan T8b |
| F16 controller calls under `owner: yes` | P3 | §14 column `owner`; `decisions.md` CLI-UAL-44 / -45 / -47 `owner: no`, CLI-UAL-63 (`owner: no`) for every call, controller clauses named in CLI-SGN-52 / -53 / -54 and CLI-UAL-46 |
| F17 marker's documented meaning; CLI-SGN-30 cited for the wrong rule | P3 | §8 last item, plan T5; CLI-SGN-29 cited in §1, §2, §9, CLI-SGN-54 |
| F18 Ed25519 family payloads, off-chain messages | P3 | §8 envelope refusal; §9 residual per family; CLI-SGN-54 (5) |
| F19 tweaked secret outside the arena | P3 | §5.2, §4.3; plan T7 check |
| F20 T8 too large | P3 | plan T8a / T8b; the fuzz target in T8b |
| F21 T0 has no stop condition for the pin | P3 | plan T0 stop rule |
| F22 §16 against superseded app documents | info | §16 rewritten against the app contract |
| F23 SS58 prefix per chain | info | §7.4; §16; plan T0 (Paseo's prefix) |
| F24 byte-equality claims are T0's | info | §12.2 first rule |
