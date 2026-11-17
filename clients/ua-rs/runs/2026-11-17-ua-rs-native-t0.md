# ua-rs-native T0 — spike report (2026-11-17)

Run record of task T0 of [the `ua-rs-native` plan](../../../docs/superpowers/plans/2026-11-17-ua-rs-native.md) (spec
[`2026-11-17-ua-rs-native.md`](../../../docs/superpowers/specs/2026-11-17-ua-rs-native.md)). Branch `ua-rs-native` at `87a9608ea`.
Report only: no `ua-rs` or clientkeys code changes; the scratch crate and scripts stayed in the session scratchpad and are not kept.
No timing or gas measurement. Everything here is UNAUDITED.

## Summary

| Step | Result |
|---|---|
| Crates | `schnorrkel` **0.11.5** on crates.io (2025-07-14, not yanked, BSD-3-Clause). With `default-features = false, features = ["getrandom"]` and `pbkdf2 =0.12.2` (`hmac`) beside `scaas-ua` (every feature), the lock gains exactly four crates, all named in spec §11: `schnorrkel 0.11.5`, `merlin 3.0.0`, `getrandom_or_panic 0.0.3`, `arrayref 0.3.9`. `arrayvec 0.7.8`, `aead`, `keccak 0.1.6`, `byteorder 1.5.0`, `curve25519-dalek 4.1.3`, `sha2 0.10.9`, `rand_core 0.6.4`, `pbkdf2 0.12.2` were in the lock already. One `curve25519-dalek`. No `serde_bytes`. |
| `cargo deny --all-features check` (cargo-deny 0.20.2, `clients/ua-rs/deny.toml` unchanged) | `advisories ok, bans ok, licenses ok, sources ok`, rc 0. No new `ignore`. |
| wasm32 | `cargo build --lib --target wasm32-unknown-unknown` of the spike (`#![no_std]` lib: sign, verify, Ed25519 expansion, hard and soft derivation, `scaas-ua` `wallet`): rc 0. |
| `alloc` | Not needed: schnorrkel's only feature in the graph is `getrandom` (`cargo tree -e features -i schnorrkel`); the `no_std` lib compiles sign, verify, `expand_to_keypair(ExpansionMode::Ed25519)`, `SecretKey::hard_derive_mini_secret_key`, `Derivation::derived_key_simple_rng`, `context::attach_rng`, `signing_context`, `PublicKey::verify`. |
| Zeroize on drop | schnorrkel 0.11.5: `MiniSecretKey` and `SecretKey` `#[derive(Zeroize)] #[zeroize(drop)]` (`keys.rs`); `Keypair` has `impl Drop` calling `zeroize()` on its secret. k256 0.14.0: `schnorr::SigningKey` has `impl Drop` (wipes `secret_key`) and `impl ZeroizeOnDrop` (`schnorr/signing.rs`). No hand wipe of these types is needed; `ua-rs`'s own scalar copies still need `Zeroizing` (spec §5.2). |
| sr25519 byte equality | **All equal (12 / 12)**: schnorrkel `sign(attach_rng(signing_context(b"substrate").bytes(m), OneShot(r)))` and `@scure/sr25519` 2.4.0 `sign(sk, m, r)` over {bare dev key, `//Alice`, soft-derived `/soft//hard`, soft-derived `/x`×31} × {1 B, 32 B, 257 B}, `r = 01 02 … 20`. Every signature verifies in both libraries; the one-shot RNG is read exactly once per signature and per soft step. Spec §12.2 branch: **deterministic test-only rows** for sr25519 (bare and `//Alice`). |
| Known answers | Every one reproduced (sections below); no mismatch with the spec. |
| Off-chain envelopes | Confirmed: Solana OCMS v1 `0xff ‖ "solana offchain"`, Aptos `"APTOS\n"`. Of the six Ed25519 networks only these two sign more than 32 bytes. Note for the coordinator: the Algorand family (not a `ua-rs` network) also signs more than 32 bytes (below). |
| NEAR | `near-cli-rs` v0.31.1: seed-phrase default `m/44'/397'/0'`; the Ledger default `44'/397'/0'/0'/1'` is not used. Agrees with spec §6. |
| SS58 prefixes | **Paseo 42**, **Westend 42** (chain spec `properties.ss58Format` and runtime `SS58Prefix`). |

## Crates

Commands (scratch crate `t0spike`, `Cargo.lock` copied from `clients/ua-rs/Cargo.lock`, `scaas-ua` by path with a feature
`full = ["scaas-ua/default", "scaas-ua/vectors"]`):

```
cargo fetch                                   # online once; then everything --offline
cargo tree -d --all-features                  # duplicates: the existing RustCrypto generation pairs only; one curve25519-dalek
cargo tree -e features -i schnorrkel          # schnorrkel feature "getrandom" only
cargo deny --all-features check               # deny.toml of clients/ua-rs
cargo build --lib --target wasm32-unknown-unknown
```

New lock entries (name, version, licence, crate sha256 = the lock checksum):

| Crate | Version | Licence | sha256 |
|---|---|---|---|
| `schnorrkel` | 0.11.5 | BSD-3-Clause | `6e9fcb6c2e176e86ec703e22560d99d65a5ee9056ae45a08e13e84ebf796296f` |
| `merlin` | 3.0.0 | MIT | `58c38e2799fc0978b65dfff8023ec7843e2330bb462f19198840b34b6582397d` |
| `getrandom_or_panic` | 0.0.3 | BSD-3-Clause | `6ea1015b5a70616b688dc230cfe50c8af89d972cb132d5a622814d29773b10b9` |
| `arrayref` | 0.3.9 | BSD-2-Clause | `76a2e8124351fda1ef8aaaa3bbd7ebbcb486bbcd4225aca0aa0d84bb2db8fecb` |

`curve25519-dalek` 4.1.3 features after unification: `alloc`, `digest`, `legacy_compatibility`, `precomputed-tables`, `zeroize`
(the last three partly from schnorrkel; a size effect, measured by `ua-sizes` at T12). spec §11's table holds as written.

Two details for T7 / T8a:
- merlin `TranscriptRngBuilder::finalize` reads the external RNG once with `fill_bytes` of 32 bytes (`transcript.rs`); a soft step
  (`derived_key_simple_rng`) and a signature each finalize once. The one-shot RNG of spec §7.5 sees exactly one 32-byte read.
- `@scure/sr25519`'s 64-byte secret is schnorrkel's **`SecretKey::to_ed25519_bytes()`** (scalar·8 ‖ nonce), not `to_bytes()`
  (scalar ‖ nonce). Handing scure `to_bytes()` gives another key: the first run of the grid did, and all twelve signatures then
  differed (the grid's positive control). The `ua-rs` slot keeps `to_bytes()` (spec §4.3); any cross-library row that carries a
  secret uses the ed25519 form.

## sr25519 known answers (substrate-bip39, schnorrkel, `@scure/sr25519`, polkadot.js)

Three implementations: schnorrkel 0.11.5 + `pbkdf2` 0.12.2 (Rust), `@scure/sr25519` 2.4.0 + `@noble/hashes` 2.4.0 `pbkdf2`, and
polkadot.js (`@polkadot/keyring` / `@polkadot/util-crypto` 14.0.3, `@polkadot/wasm-crypto` 7.5.4, `keyring.addFromUri(phrase +
path)`, `mnemonicToMiniSecret`). Junction chain codes per spec §7.3 (`u64` LE for digits; SCALE compact length + bytes; ≤ 32 bytes
zero-padded, else BLAKE2b-256). `subkey` itself is not installed here; the plan's alternative (polkadot.js) is used.

`substrate-bip39` vectors: all **24** rows of `VECTORS` in `src/lib.rs` (password `"Substrate"`, entropy and 64-byte seed; the
mini-secret is its first 32 bytes) reproduced by Rust, noble and Python `hashlib.pbkdf2_hmac`. Source:
`https://raw.githubusercontent.com/paritytech/substrate-bip39/ceb4fe5a3c7ac91da2e272037797ebecb56aa177/src/lib.rs`.

Development phrase `bottom drive obey lake curtain smoke basket hold race lonely fit walk`, empty passphrase (all three
implementations equal; the first three are spec §7.3's `subkey` answers):

| Path | Public key |
|---|---|
| `""` | `46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a` (SS58 42 `5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV`) |
| `//Alice` | `d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d` (`5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY`) |
| `//Bob` | `8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48` (`5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty`) |
| `//0` | `2afba9278e30ccf6a6ceb3a8b6e336b70068f045c666f2e7f4f9cc5f47db8972` |
| `/0` | `b696d3a7fbc9dd6648e18fd56169b90f3be49714133eaa464cbfd6ca79ab1310` |
| `//1/2` | `509efd067a5a345cea7185745c2996a36733711651f6cc41087c0bcc66a68a1d` |
| `/soft//hard` | `b692f2e809e8805a1814fab0baea78841806544446ebb8280b4e593962706f4a` |
| `//18446744073709551615` | `a4ca284d5222ef916e2e181430785972ed22cb51ef91a0c6cdbbd390ee74bc77` |
| `//polkadot` | `f606519cb8726753885cd4d0f518804a69a5e0badf36fee70feadd8044081730` |
| `//` + `x`×31 (padded) | `d08d581c9755746d091ef753234388455eb5f847ae6061ceae8c77b38fcb030f` |
| `/` + `x`×31 | `2a72e28d57ef0263eccad32fef0b2c6c9c37358821e4be63773df52f52edd87c` |
| `//` + `x`×32 (hashed) | `9644ab5b228ce544dfff7f8f021e06120d26f2c0a856096cbbce37abc1541a5c` |
| `/` + `x`×32 | `f24dd03839f881a9ba7e18bfc99b57f590c3b397a631534bc6c5702d14963a1e` |
| `//` + `x`×63 (one-byte length) | `76dab0a15bee6bc691c04d2b7ee92b7e89596040e6565d75a17ec1da6c0eab1c` |
| `/` + `x`×63 | `5a8a9a1cd97dff92b58c8c59655e3b112f6cf315e82e9e776b2f95f276c10870` |
| `//` + `x`×64 (two-byte length) | `4e7a9573fa04dafa01aa9d0eeda5dd5f6685879a2bfd024a75c17c231b488556` |
| `/` + `x`×64 | `827385d21b2e6b7db061391eb9839b0eb5e9f8c9b012d64e7d02d10b6abc4f65` |

The same grid on `abandon ×11 about` (empty passphrase) also agrees in all three (bare
`66933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed7972`, `//Alice`
`fa00f8b342672afa2d4b90db00e1664a35dd70e54a116beba9ee45dc5d9fa23e`). SS58 of the bare dev key: 0
`12bzRJfh7arnnfPPUZHeJUaE62QLEwhK48QnH9LXeK2m1iZU`, 2 `EBJwHkVtAcF6nCKHd3h4H75NzgvMJxMS1X3WWd8a2DjaQx9`, 64 (two-byte form)
`cEXBCBPEn84gHSpZtrHx5fmAvFR4UGKD2DL5kFGUnGLj2ksXy`, 16383 `yNWw4BEqdLrtrV4Gja14vK2s7JN7Td9tKvJvzcTXENhkJiVUD` (polkadot.js
`encodeAddress`).

**polkadot.js signature of `//Alice` (verify-only `external` row).** Command (Node 26, `@polkadot/keyring` 14.0.3):
`new Keyring({ type: 'sr25519' }).addFromUri(DEV + '//Alice').sign(stringToU8a(m))` with `m = "scaas ua-rs-native T0: polkadot.js
//Alice signature"`:

```
publicKey  d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d
message    73636161732075612d72732d6e61746976652054303a20706f6c6b61646f742e6a73202f2f416c696365207369676e6174757265
signature  24a27936a2b09621ea541fa427b3ea60c52199cf7e3f8966c4ffbc6620833b69f57592f47c8bd86b4076f74aef554817a434c65c16a34d5eba30030728a31f8c
```

schnorrkel `PublicKey::verify` (context `substrate`) accepts it and refuses the message with one byte appended (negative control).

## Bitcoin known answers

All re-derived with `@scure/bip32` / `@noble/curves` 2.4.0 / `@scure/base` 2.4.0 from the BIP texts at
`bitcoin/bips` `c1a652c7c6b6a93ff2a06a295d27cfb767294a63`:

| Row | Value |
|---|---|
| BIP-84 `m/84'/0'/0'/0/0` | `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu` |
| BIP-84 `m/84'/0'/0'/0/1` | `bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g` |
| BIP-84 `m/84'/0'/0'/1/0` (change) | `bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el` |
| BIP-86 `m/86'/0'/0'/0/0` | `bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr` (internal `cc8a4bc6…6fc115`, output `a60869f0…dc684c`) |
| BIP-86 `m/86'/0'/0'/0/1` | `bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh` |
| BIP-86 `m/86'/0'/0'/1/0` (change) | `bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7` (internal `399f1b2f…277cef`, output `882d74e5…97d3dc`) |

`y` parities of `abandon … about` P2TR keys (internal, output; 1 = odd): receive 0 `11`, 1 `00`, 2 `11`, 3 `01`; change 0 `01`, 1
`01`, 2 `10`, 3 `00`. Indexes 0–3 of both chains cover all four combinations (the generator's parity assertion of spec §12.2).

- **BIP-143 native P2WPKH** (sighash `c37af311…8cb670`, key `619c3350…86feb9`): RFC 6979 **with no extra data** reproduces the
  published DER signature `30440220 3609e17b… 0220 573a954c…eebee` byte for byte, in noble (`extraEntropy: false`, `lowS`) and in
  k256 0.14.0 (`SigningKey::sign_prehash`). Row: **byte-equal**.
- **BIP-341 `wallet-test-vectors.json`.** `scriptPubKey` rows with a null `scriptTree`: **index 0 only** (internal
  `d6889cb0…`, `bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5`): tweak, tweaked key and address reproduced.
  `keyPathSpending[0].inputSpending` with a null `merkleRoot`: **input 0 only** (`txinIndex` 0, `hashType` 3). Its signature
  uses **`aux` = 32 zero bytes**: noble `schnorr.sign` and k256 `schnorr::SigningKey::sign_raw` with zero `aux` over its
  `sigHash` give the first 64 bytes of `witness[0]` (65 bytes: signature ‖ `0x03`); negate-then-tweak of its `internalPrivkey`
  gives its `tweakedPrivkey`. Row: **byte-equal** through `vectors_taproot_sign`. Inputs 1–6 have a Merkle root (out of scope).
- **BIP-340 `test-vectors.csv`**: 8 signing rows reproduced (noble), 19 verify rows give the listed result.

## Off-chain envelopes

- Solana: [solana.md](../../../docs/networks/solana.md) (`kind 1` OCMS v1: `"\xffsolana offchain" ‖ version 1 ‖ …`) and
  `smartcontracts/solana/programs/scaas/src/auth.rs` (`"\xffsolana offchain" ‖ 1 ‖ 1 ‖ pk ‖ text`).
- Aptos: [aptos.md](../../../docs/networks/aptos.md) (`fullMessage` starts with the line `APTOS`, strict parse; the seed signer
  builds `"APTOS\nmessage: scaas.metaop.v1:0x<hex>\nnonce: <hex(lane)>"`).
- The other four Ed25519 networks with a family sign 32 bytes (spec §9 residuals); NEAR's family signs the NEP-413 SHA-256 (32
  bytes, [NET-NEAR-13](../../../docs/networks/near.md#NET-NEAR-13)).
- **Outside the six (for the coordinator):** the Algorand family's native ed25519 signature is over `"MX" ‖ "scaas.metaop.v1:" ‖
  hex(digest)` (more than 32 bytes, `ed25519verify_bare`, `docs/networks/algorand.md`). No clientkeys or `ua-rs` network derives an
  Algorand key (the relayer lane path `m/44'/283'/0'/0'/i'` is the node's); a caller could reach SLIP-10 `m/44'/283'/i'` only by a
  coin-type override on `stellar` / `ton`, which is not an Algorand wallet's path. Spec §8's two-prefix list is complete for the
  six; whether `"MX"` joins it is the coordinator's call (it changes refusal bytes, so this task does not add it).

## NEAR path

`near-cli-rs` latest release **v0.31.1** (commit `5cdedc38e09b23b84ae9d69f6abbb26568dda579`, source tarball sha256
`f21d6cfb7261548915e226aec99d04e8ee810a6f831ca6b37c90e22baf02016c`):
`src/transaction_signature_options/sign_with_seed_phrase/mod.rs:239` (`with_starting_input("m/44'/397'/0'")`, the
`--seed-phrase-hd-path` prompt default), `src/utils_command/generate_keypair_subcommand/mod.rs:11`
(`#[arg(long, default_value = "m/44'/397'/0'")]`); `src/js_command_match/constants.rs:21` `DEFAULT_SEED_PHRASE_PATH =
"44'/397'/0'/0'/1'"` is the Ledger path of the JS-compatible commands. The node's relayer lanes use `m/44'/397'/0'/0'/i'`
([NET-NEAR-24](../../../docs/networks/near.md#NET-NEAR-24)), a different path from the user key `m/44'/397'/i'`.

## SS58 prefixes

| Chain | Prefix | Source |
|---|---|---|
| Paseo (relay) | **42** | `paseo-network/paseo-chain-specs` `0f3b655048bdd03e5dc8caaab4711667bc9a089c` `paseo.raw.json` line 16 `"ss58Format": 42` (sha256 `05c2949ab4b040140416979f93620dee4ebc67b30a830e92d62e1cd76a6a8c2d`); runtime `paseo-network/runtimes` v2.5.5 (`0b3eb1743869e10080a16da3931857d8ef287cde`) `relay/paseo/constants/src/lib.rs:28` `SS58_PREFIX: u8 = 42`, used by `relay/paseo/src/lib.rs:195` |
| Westend | **42** | `paritytech/polkadot-sdk` `polkadot-stable2609-2` (`9448fe4f252936d241b8d2663506813b884f94f3`) `polkadot/node/service/chain-specs/westend.json` line 20 `"ss58Format": 42` (sha256 `8f94d0476790db877bd49304bb7f273c768007944e065c1218ce31da0e760582`); `polkadot/runtime/westend/src/lib.rs:185` `SS58Prefix: u8 = 42` |

## Downloads (`NATIVE_DOWNLOADS`)

| File | URL | sha256 |
|---|---|---|
| `test-vectors.csv` | `https://raw.githubusercontent.com/bitcoin/bips/c1a652c7c6b6a93ff2a06a295d27cfb767294a63/bip-0340/test-vectors.csv` | `34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d` |
| `wallet-test-vectors.json` | `…/c1a652c7c6b6a93ff2a06a295d27cfb767294a63/bip-0341/wallet-test-vectors.json` | `403e19fb81dd1f31e745699216308f61fb403774b2aafa87b631b8f7c042d37f` |
| `bip-0084.mediawiki` | `…/c1a652c7c6b6a93ff2a06a295d27cfb767294a63/bip-0084.mediawiki` | `1900feec6cafca65b8c09906ca0658d2d742b4c9b44cb15678996985b6bfe627` |
| `bip-0086.mediawiki` | `…/bip-0086.mediawiki` | `d8d01dee331da07c2562615bc1f064c1868ec3fce61184973da76d1196c7f5b0` |
| `bip-0143.mediawiki` | `…/bip-0143.mediawiki` | `62bc71351563e68baeb12643c68355d217953ae9eb6a6e68b2b0323275b6beec` |
| `bip-0173.mediawiki` | `…/bip-0173.mediawiki` | `b19eab06b264bbd15ad7f7d640fa34de8f4a8809fba8a6ecc3e165545b27a543` |
| `bip-0350.mediawiki` | `…/bip-0350.mediawiki` | `63634b06aa8bae88b31929674736e74964c4598684269ac2b0b140c43a7a0dec` |
| `substrate-bip39-lib.rs` | `https://raw.githubusercontent.com/paritytech/substrate-bip39/ceb4fe5a3c7ac91da2e272037797ebecb56aa177/src/lib.rs` | `df887f9ddc001032abc040d733d3901fe18fdf8f225f60fefa68775dcd396be0` |

JavaScript: `@scure/sr25519` 2.4.0, MIT, dependencies `@noble/curves` 2.4.0 and `@noble/hashes` 2.4.0 (clientkeys' pins), integrity
`sha512-Xzpy/MuVqR8wNHrXrz6HHLqCI8nPirQmJEhOMabZ8jSrM6bQiDg+1xkUgw4+Kr7857u3xxQL/PfKFeav9rodZg==`.

## Spec changes

None needed: every check agrees with the spec as written. The spec's §12.2 "until T0's record exists, the byte-equal column is a
hypothesis" now resolves to: BIP-143 byte-equal, BIP-341 key-path input 0 byte-equal (`aux` zero), sr25519 fixed-randomness rows
byte-equal (test-only). Open for the coordinator: the Algorand `"MX"` envelope (above), and Paseo / Westend 42 for the app's chain
table.
