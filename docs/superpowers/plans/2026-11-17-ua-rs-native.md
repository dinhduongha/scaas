# `ua-rs-native`: Bitcoin, NEAR and Polkadot keys and raw native signing in `ua-rs`: build plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status (2026-11-17):** plan, not executed; nothing is built from it. Spec:
[`2026-11-17-ua-rs-native.md`](../specs/2026-11-17-ua-rs-native.md) (SPECIFIED; revised after Fable's review F1–F24, spec §18).
UNAUDITED.

**When it runs (owner 2026-11-17, "Code luôn, không chờ sau p6h"):** now, on branch `ua-rs-native` (from `ua-rs-sign`
`d823d61f0`), worktree `.claude/worktrees/ua-rs-native`. Independent of `scaas-sdk` and `scaas-rpc` (TODO 8b): it touches only
`clients/clientkeys`, `clients/ua-rs`, `clients/ua-c`, the `ua-*` bindings, `smartcontracts/vectors/native/` and docs. It merges into
`ua-rs-sign` / `main` on the owner's word only (merge commits; `main` is PR-only). `ua-rs` is an audit unit of the pre-freeze audit
(TODO 7): whatever of this branch has landed when the pre-freeze tag is cut is in that audit's target; the rest gets the add-on audit.

**Goal:** `ua-rs` derives and signs for `bitcoin_p2wpkh`, `bitcoin_p2tr` (receive and change chains), `near` and `polkadot` exactly
as clientkeys, signs raw messages on Ed25519 and sr25519 native keys behind `AllowRawDigest`, and every binding reaches the new calls
and reads the same rows of `smartcontracts/vectors/native/native.json`.

**Commits:** one or more per task, `ua-rs-native T<n>: <what>`, staged by explicit path (`git add <paths>`; in a worktree another
agent also uses: `git commit --only -- <paths>`), with the session's attribution lines; no `Signed-off-by`. **No push, no merge.**
No commit holding only `TODO.md`. Before any later push (owner's word): scan the outgoing diff for secrets, then push by SHA as a
separate step.

## Global constraints (read before every task)

- AGENTS.md: heavy commands (`cargo`, `npm`, `node` generators, `dotnet`, `cmake --build`, the gate runner's steps) through
  `scripts/capped`, **foreground**, never inside `timeout`, never in the background; no `sleep` / `until` / `pgrep -f` loops; after a
  `capped dotnet …`, `dotnet build-server shutdown`. One capped job per agent at a time.
- Inputs as real directories in this worktree: `clients/clientkeys/node_modules` (`cd clients/clientkeys && ../../scripts/capped
  npm ci --ignore-scripts`). No forge step runs (no contract change), so `smartcontracts/evm/lib` is not needed.
- TDD in every task: write the test, run it, **see it fail for the stated reason**, implement, run it green. A negative test has its
  positive control beside it (the same call accepted with one value changed). Each task's mutants (listed) must each turn a named test
  red, one mutant at a time, through the task's harness `smartcontracts/evm/runs/2026-11-17-ua-rs-native-t<n>-mutants.py` (the shape of
  `2026-11-05-ua-rs-sign-t1a-mutants.py`: a list of `(file, old, new, test command)`, modes `run` and `check`), record
  `…-t<n>-mutants.txt` committed (last line `N mutants, N killed, 0 survived, 0 not loaded`).
- Never edit a vector file by hand, a pin, a bound or an existing test to go green. A red known answer stops the task and is reported
  with its output. No existing clientkeys test or generator is edited in this round (spec §4.1: `NETWORKS` stays the nine).
- `smartcontracts/vectors/ua/*.json` must not move (each generator run ends `git diff --exit-code -- smartcontracts/vectors/ua`).
- Errors carry no input (CLI-UAL-04); every new input bounded (CLI-UAL-03); no release signature takes randomness from a caller
  (CLI-UAL-02): fixed randomness only under feature `vectors`; every RNG draw through `os_aux()` (`Error::Rng`, never a panic).
- New source files carry `// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0`. Code, comments, commits in English.
- No absolute or `/tmp` path in a committed file; temp dirs by `mktemp -d` at run time.
- Gate logs: `runs/2026-11-17-ua-rs-native-<step>.log` (git-ignored, first line `# <step> at commit <sha>`, last `rc=<n>`); only the
  summary `…-summary.txt` is committed (T12). On resume read the logs and `runs/gate/last` first; a step done at the same commit on a
  clean tree is skipped.
- No timing or gas measurement (none is needed). Sizes (`ua-sizes`) are not timing and run in T12.

Abbreviations used in the steps: `W` = the worktree root; `cap` = `"$W/scripts/capped"`; `C` = `--locked --offline -j2`; `G` =
`smartcontracts/evm/runs/2026-11-17-ua-rs-native-gates.sh` (from `W`, `G --only <step>`).

## Tasks and order

| Task | What | Depends on |
|---|---|---|
| T0 | spikes (report only, no code kept) | spec revised after Fable's review |
| T1 | gate runner | T0 |
| T2 | clientkeys: `NATIVE_NETWORKS`, Bitcoin (both chains) and NEAR, the refusals | T1 |
| T3 | clientkeys: Polkadot (`substrate.js`), `signMessage`, guards | T2 |
| T4 | clientkeys: the generator, `native.json` | T3 |
| T5 | `ua-rs`: `NativeScheme`, `sign_message` on the existing ed25519 networks, the marker's docs | T4 |
| T6 | `ua-rs`: NEAR | T5 |
| T7 | `ua-rs`: Bitcoin P2WPKH and P2TR, change chain, witness programs | T5 |
| T8a | `ua-rs`: Polkadot crates, store, mini-secret, bare key, sr25519, SS58 | T5 |
| T8b | `ua-rs`: Polkadot junctions, `KeyId::Polkadot`, `polkadotPaths`, the fuzz target | T8a |
| T9 | `ua-rs`: `rs_native.json` both ways, `external_answer`, `deny` / NOTICE | T6, T7, T8b |
| T10 | `ua-c`: constants, feature bit, calls, header, Python rows | T9 |
| T11a–f | bindings: `ua-cxx`, `ua-qt`, `ua-dart-frb`, `ua-py`, `ua-go`, `ua-cs` | T10 (each independent of the others) |
| T12 | docs to BUILT, `decisions.md` statuses, closing gates, summary | T11a–f |
| T13 | closing review (Fable; Codex on the owner's word) and its fixes | T12 |

T6, T7, T8a and T8b touch different files beyond `wallet/mod.rs` and `sign.rs`; run them one after another (one worktree), in that
order.

---

### T0 — spikes (report only)

**Files:** create `clients/ua-rs/runs/2026-11-17-ua-rs-native-t0.md` (the record; commands, versions, answers, sha256 of downloads;
no absolute path). Scratch code in the session scratchpad only, never committed.

- [ ] **Crates.** In a scratch crate pinned to this worktree's `clients/ua-rs/Cargo.lock` versions: `schnorrkel = { version =
  "=0.11.5", default-features = false, features = ["getrandom"] }` and `pbkdf2 = { version = "=0.12.2", features = ["hmac"] }`.
  Record: `cargo tree -d` and every new lock entry (name, version, licence); `cargo deny --all-features check` with
  `clients/ua-rs/deny.toml`; a `wasm32-unknown-unknown` build; that sign, verify, expansion and hard / soft derivation compile
  without `alloc`; the APIs the spec names (`MiniSecretKey::expand_to_keypair(ExpansionMode::Ed25519)`,
  `SecretKey::hard_derive_mini_secret_key`, `derived_key_simple_rng`, `context::attach_rng`, `signing_context`, `PublicKey::verify`);
  whether `MiniSecretKey`, `SecretKey`, `Keypair` (schnorrkel) and `schnorr::SigningKey` (k256 0.14) wipe on drop.
- [ ] **Stop rule.** schnorrkel 0.11.5 missing or yanked, a second `curve25519-dalek`, a new `deny` ignore needed, `serde_bytes` or
  any crate the spec §11 table does not name, a failed wasm32 build, or a needed `alloc`: **stop and report; no other version or
  feature set without the coordinator.**
- [ ] **sr25519 byte equality** over {bare dev key, `//Alice`, one soft-derived key handed to both libraries as the same 64-byte
  secret} × {1 B, 32 B, 257 B}, with 32 fixed bytes: schnorrkel `sign(attach_rng(ctx.bytes(m), OneShot(r)))` vs `@scure/sr25519` 2.4.0
  `sign(sk, m, r)`. All nine equal → deterministic test-only rows (spec §12.2); any pair differs → every sr25519 row verify-only.
- [ ] **Known answers.** The `subkey` answers of spec §7.3 (bare, `//Alice`, `//Bob`) with schnorrkel + PBKDF2 and with
  `@scure/sr25519` + noble PBKDF2; junctions of 31, 32, 63 and 64 bytes, hard and soft, against `subkey inspect` (or polkadot.js
  `keyring.addFromUri`): record the public keys; one `subkey sign` (or polkadot.js) signature of `//Alice` over a fixed message,
  with the command; `substrate-bip39`'s test vectors (copy the table with its source URL); BIP-84 / BIP-86 receive and change index-0
  addresses from the BIP texts; BIP-143 native P2WPKH: does RFC 6979 with no extra data reproduce the published signature (k256 and
  noble); BIP-341 `keyPathSpending`: which inputs have a null `merkleRoot`, and the `aux` their signatures used; `scriptPubKey` rows
  with a null `scriptTree`. **Any mismatch with the spec: stop and report.**
- [ ] **Off-chain envelopes.** Confirm from `docs/networks/solana.md` / `aptos.md` and clientkeys' family code that the SCaaS Solana
  payload starts `0xff ‖ "solana offchain"` and the Aptos one `"APTOS\n"`, and that no other Ed25519 family signs more than 32 bytes.
- [ ] **NEAR and Polkadot chains.** Read `near-cli-rs`'s source at its latest release tag: the default of `--seed-phrase-hd-path`;
  read Paseo's chain spec (and Westend's): their SS58 prefixes; record tag, file and line. Report the Paseo prefix to the coordinator
  (the app contract's chain table).
- [ ] **Downloads.** Fetch BIP-340 `test-vectors.csv`, BIP-341 `wallet-test-vectors.json`, the `substrate-bip39` vector source;
  record URL, commit and sha256 for `NATIVE_DOWNLOADS`.
- [ ] Commit the record: `git add clients/ua-rs/runs/2026-11-17-ua-rs-native-t0.md && git commit -m "ua-rs-native T0: spikes
  (crates, sr25519 bytes, known answers, NEAR path, SS58 prefixes)"`. If a finding changes the spec, the spec is fixed in the same
  commit and the coordinator is told before T1.

### T1 — gate runner

**Files:** create `smartcontracts/evm/runs/2026-11-17-ua-rs-native-gates.sh` (executable).

- [ ] Copy `smartcontracts/evm/runs/2026-11-07-ua-rs-sign-gates.sh`; set `P=${GATES_P:-2026-11-17-ua-rs-native}`; header comment for
  this round; `STEPS="docs clientkeys vectors-check ua-rs-nodefault ua-rs-wallet ua-rs ua-rs-vectors ua-rs-zether ua-rs-pqz no-oracle
  ua-deny ua-fuzz ua-sizes ua-c ua-cxx ua-qt ua-dart-frb ua-py ua-go ua-cs test-features mutant-logs named-tests summary"` (the round
  touches `wallet/mod.rs` and the store, which every facade opens through: every `ua-rs` cell and binding runs, AGENTS.md "full gates
  on shared changes"; no forge step: no contract or `ua/` vector changes).
- [ ] `vectors-check`: twice, `(cd clients/clientkeys && NATIVE_DOWNLOADS=$NATIVE_DOWNLOADS cap node scripts/native-vectors.mjs)`, then
  `(cd clients/ua-rs && cap cargo test $C --features vectors --test wallet_native -- --ignored regenerate)` (writes `rs_native.json`),
  then `clean`; plus `git diff --exit-code -- smartcontracts/vectors/ua`. Until T4 / T9 exist the step reports "not yet" and fails.
- [ ] `ua-fuzz`: add `polkadot_path` to the target list (it exists from T8b). `mutant-logs`: the list is this round's
  `2026-11-17-ua-rs-native-t<n>` records (extended per task). `NEW_TESTS`: filled at T12.
- [ ] Check: `bash -n` on the file; `G --only docs` runs green (writes its log).
- [ ] Commit: `ua-rs-native T1: gate runner`.

### T2 — clientkeys: `NATIVE_NETWORKS`, Bitcoin and NEAR, the refusals

**Files:** modify `clients/clientkeys/src/seed.js` (new export `NATIVE_NETWORKS`; `deriveKey` looks up both lists and takes
`{ coinType, change }`; `describe`; the refusals of `signKeyProof`, `signTyped`, `signTransaction`; `sign` for P2TR),
`clients/clientkeys/src/seed-signer.js` (export `NATIVE_NETWORKS`), `clients/clientkeys/src/uakey.js` (only a comment on
`importedKind`: it looks up `NETWORKS`, the nine, on purpose); create `clients/clientkeys/test/native.test.js`. `NETWORKS` itself, every
existing test and `scripts/ua-wallet-vectors.mjs` stay unedited.

- [ ] **Tests first** (`test/native.test.js`): `Object.keys(NETWORKS)` is still the nine and `NATIVE_NETWORKS` the four; BIP-84 /
  BIP-86 receive and change index-0 addresses of `abandon ×11 about` (T0's values); index 1 and change 1 differ from index 0 / change
  0; coin 1 → `tb1…`, coin 2 refused (coin 0 accepted), change 2 refused, `change` on a non-Bitcoin network refused; P2TR
  `internalKey`, `tweak`, `outputKey` against BIP-341 `scriptPubKey` rows (null `scriptTree`); NEAR index 0 path `m/44'/397'/0'`,
  `address === hex(publicKey)`, `publicKeyText` `ed25519:` + base58, any `coinType` on `near` refused (none accepted); `signDigest`
  P2WPKH = r ‖ s ‖ v RFC 6979 (`extraEntropy: false` explicit) over BIP-143's sighash; P2TR `signDigest(key, d, {allowRawDigest: true,
  aux})` equals BIP-340 / BIP-341 rows and verifies under `outputKey`; `signTyped`, `signTransaction` and `signKeyProof` on a Bitcoin or
  NEAR key throw `Argument` (an `evm` key signs; a `solana` key proof signs); `importKey` and `importedUAKey` of each new network throw
  `Argument` (an `evm` import and its imported UA accepted). Run `(cd clients/clientkeys && cap node --test test/native.test.js)`:
  red (unknown network).
- [ ] **Implement:** `NATIVE_NETWORKS` = `bitcoin_p2wpkh` (`(i, k) => m/84'/0'/0'/k/i`), `bitcoin_p2tr` (`m/86'/0'/0'/k/i`), `near`
  (`m/44'/397'/i'`, ed25519, no coin override), `polkadot` (`{ curve: 'sr25519', path: null }`; `deriveKey` refuses it with "use
  polkadotKey"); Bitcoin coin types 0 and 1 only; `describe` as spec §5.1 / §6 (`bech32` / `bech32m` of `@scure/base`,
  `ripemd160(sha256(pk))`, one `taprootTweak(xP)` helper used by the address and the signer, `t ≥ n` throws); `sign` for P2TR: BIP-340
  with the tweaked secret, `aux` the caller's in the generator, else `crypto.getRandomValues`, then verify under `x(Q)`.
- [ ] Green: the same command; then `(cd clients/clientkeys && cap npm test)`: every earlier test unchanged and green.
- [ ] Mutants (harness `…-t2-mutants.py`): untweaked key; no odd-`y` negation; bech32 constant on v1; `bc` for coin 1; change chain
  ignored; `extraEntropy: true`; `signTyped` guard removed; key proof accepted on `near`; NEAR coin override accepted;
  `importedKind` looking up `NATIVE_NETWORKS` too (the `importedUAKey` refusal row goes red).
- [ ] Gates: `G --only clientkeys`. Commit: `ua-rs-native T2: clientkeys NATIVE_NETWORKS, Bitcoin P2WPKH / P2TR (receive and
  change), NEAR`.

### T3 — clientkeys: Polkadot, `signMessage`, guards

**Files:** create `clients/clientkeys/src/substrate.js`; modify `clients/clientkeys/src/seed.js` (`signMessage`, the `signDigest`
JSDoc per spec §8), `clients/clientkeys/src/seed-signer.js` (exports), `clients/clientkeys/package.json` + `package-lock.json`
(`@scure/sr25519` exactly `2.4.0`: `cap npm install --ignore-scripts --save-exact @scure/sr25519@2.4.0`); extend `test/native.test.js`.

- [ ] **Tests first:** `miniSecretFromEntropy(entropy, passphrase)` against `substrate-bip39`'s table (T0); the `subkey` answers
  (bare, `//Alice`, `//Bob`) and T0's junction-length answers (31, 32, 63, 64 bytes, hard and soft); the NFC / NFD passphrase pair
  gives two keys (and one BIP-39 seed); `miniSecret !== seed.slice(0, 32)`; `polkadotKey(entropy, passphrase, path)` for each path of
  spec §12.2 and each refusal of spec §7.3 next to its accepted neighbour (`///pw`; `//`; `/0x12`; `//+1`; `//18446744073709551616`
  beside `//18446744073709551615`; `//007` beside `//0` and `//7`; 17 junctions beside 16; 513 bytes beside 512; a 65-byte junction
  beside 64; a byte `0x20`); `ss58(pk, p)` for 0, 2, 42, 64, 16383 and refusals 46, 47, 16384; `signMessage(key, m, {allowRawDigest:
  true})` on ed25519 keys (1 B to 131,072 B) and on Polkadot keys (verifies under `@scure/sr25519` `verify` and verifies T0's `subkey`
  signature), refused without the option, for 0 and 131,073 bytes, for messages starting `0xff ‖ "solana offchain"` or `"APTOS\n"`
  (the same bytes without the prefix accepted), on secp256k1 / P2TR keys; `signKeyProof` on a Polkadot key → `Argument`; any
  `coinType` and any index but 0 refused on `polkadot`. Run: red.
- [ ] **Implement** `substrate.js` per spec §7 (PBKDF2 from `@noble/hashes`, passphrase as given, `TextEncoder` UTF-8, no
  `normalize`; the grammar with the leading-zero refusal; chain codes: `u64` LE or the SCALE string with the one- and two-byte compact
  length, BLAKE2b-256 above 32 bytes; hard / soft through `@scure/sr25519` `HDKD`; `secretFromSeed` for the bare key), `signMessage` in
  `seed.js` (one bound constant `MAX_RAW_MESSAGE = 131072`, the two envelope prefixes).
- [ ] Green: `cap node --test test/native.test.js` and `cap npm test`.
- [ ] Mutants (`…-t3-mutants.py`): NFKD the passphrase; seed in place of entropy; hard ↔ soft; SCALE prefix dropped; one-byte compact
  length at 64; hash at 32 bytes (`<=` → `<`); numeric junction as a string; leading zero accepted; bound 131,071; envelope prefix check
  removed; context `substrat` (killed by T0's `subkey` signature, verify-only).
- [ ] Gates: `G --only clientkeys`. Commit: `ua-rs-native T3: clientkeys Polkadot sr25519, signMessage, raw-signing guards`.

### T4 — clientkeys: the generator and `native.json`

**Files:** create `clients/clientkeys/scripts/native-vectors.mjs`, `smartcontracts/vectors/native/native.json` (generated); extend
`test/native.test.js` (reads `native.json`: every row re-derived and re-signed, verify-only rows verified, every refusal row refused).
`scripts/ua-wallet-vectors.mjs` is not touched (it iterates `NETWORKS`, still the nine).

- [ ] **Test first:** the reader test fails (file absent). Also: `git check-ignore smartcontracts/vectors/native/native.json` prints
  nothing (the file is tracked).
- [ ] **Implement** the generator: sections `networks`, `mnemonics`, `addresses`, `polkadotPaths`, `signatures` (`mode`:
  `deterministic`, `fixed-randomness` (test-only), `verify-only`), `refusals`, `external` (each with `source`, `sha256`; pinned
  downloads from `NATIVE_DOWNLOADS`, refused when the sha256 differs); a `note` stating `extraEntropy: false` on every ECDSA row and
  the fixed-randomness rule; the generator assertions of spec §12.2 (both `y` parities of internal and output keys; a padded, a hashed
  and a two-byte-compact chain code; at least one byte-equal signature row per scheme; no row both `deterministic` and `verify-only`).
  Generate: `(cd clients/clientkeys && NATIVE_DOWNLOADS=<dir> cap node scripts/native-vectors.mjs)`; then the existing
  `(cd clients/clientkeys && UA_WALLET_DOWNLOADS=<dir> cap node scripts/ua-wallet-vectors.mjs)` and `git diff --exit-code --
  smartcontracts/vectors/ua` (unchanged).
- [ ] Green: `cap npm test`. Run the generator twice: identical bytes.
- [ ] Mutants (`…-t4-mutants.py`): drop the odd-parity branch of the parity assertion's input set (the assertion goes red); mark the
  only byte-equal sr25519 or Taproot row `verify-only` (the "a byte-equal row per scheme" assertion goes red); a wrong pinned sha256
  (refused).
- [ ] Gates: `G --only clientkeys`, `G --only vectors-check` (its `ua-rs` half fails until T9: record it, not a blocker here).
- [ ] Commit: `ua-rs-native T4: native.json generator and rows`.

### T5 — `ua-rs`: `NativeScheme`, `sign_message`, the marker's docs

**Files:** modify `clients/ua-rs/src/wallet/mod.rs` (`NativeScheme`, `Network::scheme`, `scheme_kind -> Option<u16>`),
`src/wallet/derive.rs`, `src/wallet/sign.rs` (`sign_message`, `sign_message_by`, `MAX_RAW_MESSAGE`, the envelope prefixes,
`native_digest` by scheme), `src/wallet/signer.rs` (`SignRequest::RawMessage`, doc tests, `external_answer` for ed25519 messages, the
`AllowRawDigest` doc comment per spec §8), `src/wallet/manifest.rs` (`scheme_kind` callers), `tests/wallet_import_ua.rs` (its one
`scheme_kind` comparison takes `Some(..)`: an API change of this task, not a green-making edit); create
`clients/ua-rs/tests/wallet_native.rs` (feature `wallet`, reads `native.json`); add its `[[test]]` to `Cargo.toml`.

- [ ] **Tests first:** ed25519 `sign_message` rows of `native.json` for `hedera_ed25519`, `sui`, `stellar`, `ton`, `aptos`, `solana`;
  refusals: 0 and 131,073 bytes (131,072 accepted), the two envelope prefixes (the bytes without them accepted), a secp256k1 key (`evm`
  refused, the same message on `solana` accepted), `sign_message_by(&ua_key, m, AllowRawDigest)` → `Argument` (a native key
  accepted); doc tests: `NativeKey::sign_message(&m, AllowRawDigest)` compiles, without the marker `compile_fail,E0061`,
  `UaKey::sign_message` `compile_fail,E0599`. Run `(cd clients/ua-rs && cap cargo test $C --test wallet_native)` and `cap cargo test $C
  --doc`: red.
- [ ] **Implement** per spec §4.1, §4.2, §8 (nine networks only in this task; the new `Network` variants come in T6–T8b).
- [ ] Green: the two commands; `cap cargo test $C --test wallet_sign --test wallet_import_ua --test wallet_external` (unchanged rows).
- [ ] Mutants (`…-t5-mutants.py`): bound `>` → `>=`; `RawMessage` accepted on secp256k1; envelope prefix check removed;
  `RawMessage` mapped to a `UaMsg` in `UaKey::sign_request` (the `sign_message_by(&ua_key)` row goes red); `external_answer` not
  verifying a message.
- [ ] Gates: `G --only ua-rs`, `G --only ua-rs-wallet`, `G --only ua-rs-vectors`. Commit: `ua-rs-native T5: NativeScheme, raw-message
  signing for ed25519 native keys`.

### T6 — `ua-rs`: NEAR

**Files:** `src/wallet/mod.rs` (`Network::Near`, path, the coin-type refusal), `src/wallet/derive.rs` (`native_address`),
`src/wallet/sign.rs` (no key proof on `near`), `tests/wallet_native.rs`.

- [ ] **Tests first:** `addresses` rows of `near` (path, public key, implicit id), its `sign_digest` and `sign_message` rows; refusals:
  `native_key(Near, 0, Some(148))` (and `Some(397)`) beside `native_key(Near, 0, None)`, `sign_key_proof` on a NEAR key beside a
  `solana` one, `import_native_key(Near, …)` beside `evm`. Red.
- [ ] Implement; green (`cap cargo test $C --test wallet_native --test wallet_keys`).
- [ ] Mutants (`…-t6-mutants.py`): index at the coin level; upper-case hex; coin override accepted; key proof accepted.
- [ ] Gates: `G --only ua-rs`. Commit: `ua-rs-native T6: NEAR network`.

### T7 — `ua-rs`: Bitcoin

**Files:** `src/wallet/mod.rs` (`BitcoinP2wpkh`, `BitcoinP2tr`, the coin-type rule, `Wallet::bitcoin_key`, `KeyId::BitcoinChange`),
`src/wallet/derive.rs` (segwit bech32 / bech32m, `HASH160`, `taproot_tweak`, `witness_program`), `src/wallet/sign.rs`
(`Scheme::Bip340Taproot` with `Zeroizing` negated / tweaked scalars and the self-check against `x(Q)`; the Bitcoin keys refused on
`KeyProof`, `Eip712`, `Transaction`, `RawMessage`), `src/wallet/signer.rs` (`external_answer` against `x(Q)`),
`src/wallet/manifest.rs` (`NativeEntry.change`, written only when 1), the `vectors` entry points `NativeKey::vectors_sign_digest_fixed`
and `vectors_taproot_sign`, `tests/wallet_native.rs`, `tests/wallet_vault.rs` (a manifest with and without `change`), and a test with
`required-features = ["vectors"]`: create `tests/native_fixed.rs` (fixed `aux` rows, BIP-341 `keyPathSpending`), its `[[test]]`.

- [ ] **Tests first:** `addresses` rows (both networks, coin 0 and 1, change 0 and 1, `witnessProgram`); `bitcoin_key(.., 0, i)` is
  `native_key`'s slot; P2WPKH signature rows byte-equal; BIP-143 through `sign_raw(0x0001, …)`; BIP-340 CSV through `sign_raw(0x0103,
  …)` and `verify::bip340`; BIP-341 `scriptPubKey` rows (null `scriptTree`) through `taproot_tweak`; `keyPathSpending` rows (null
  `merkleRoot`) through `vectors_taproot_sign`; P2TR fixed-`aux` rows byte-equal (`native_fixed.rs`) and the release `sign_digest`
  verifies under `x(Q)` and differs between two calls; refusals (coin 2, change 2, `sign_key_proof`, `sign_typed`, `sign_transaction`,
  `sign_message`, each beside its accepted neighbour); a manifest without `change` keeps its bytes (`rs_vault.json` rows unchanged) and
  one with `change: 1` round-trips, `change: 2` refused; compile-fail doc tests: no `vectors_sign_digest_fixed` / `vectors_taproot_sign`
  without `vectors`. Red.
- [ ] Implement per spec §5; record whether k256 0.14's `schnorr::SigningKey` wipes on drop (T0's note) and wipe by hand if not. Green
  (`cap cargo test $C --test wallet_native --test wallet_vault` and `cap cargo test $C --features vectors --test native_fixed`).
- [ ] Mutants (`…-t7-mutants.py`): untweaked key; no odd-`y` negation; Merkle root of 32 zero bytes in the tweak; bech32 on v1 /
  bech32m on v0; `bc` for coin 1; change ignored; witness program of the internal key; self-check removed (a fault-injected signature
  must be refused: `vectors_taproot_sign` fed a key whose `x(Q)` the test replaces); `change` written when 0.
- [ ] Gates: `G --only ua-rs`, `G --only ua-rs-vectors`. Commit: `ua-rs-native T7: Bitcoin P2WPKH and P2TR, change chain`.

### T8a — `ua-rs`: Polkadot crates, store, bare key, sr25519, SS58

**Files:** `Cargo.toml` (`schnorrkel` with `default-features = false, features = ["getrandom"]`, `pbkdf2`, both under `wallet`, the
versions of T0), `Cargo.lock` and the locks of `clients/ua-c`, `clients/ua-cxx`, `clients/ua-qt`, `clients/ua-dart-frb/rust`,
`clients/ua-rs/fuzz` (one `cap cargo fetch` online, then `cap cargo update -p schnorrkel --precise 0.11.5` where needed; every new lock
line is one T0 recorded: check `git diff` of each lock); `NOTICE` (schnorrkel, `getrandom_or_panic`: BSD-3-Clause; `arrayref`:
BSD-2-Clause); `src/wallet/store.rs` (`open(entropy, seed, substrate_mini)`, the arena slot), `src/wallet/mod.rs` (`from_entropy`,
`unlock_entropy`, `Network::Polkadot`, its index / coin-type refusals); create `src/wallet/substrate.rs` (mini-secret, expansion,
SS58, the one-shot RNG over `os_aux()`, sr25519 sign / verify); `src/wallet/sign.rs` (`Scheme::Sr25519`, no key proof),
`src/wallet/signer.rs` (`external_answer` sr25519), the `vectors` entry points (`vectors_sign_digest_fixed` /
`vectors_sign_message_fixed` for sr25519, `vectors_sr25519_sign_check`, `vectors_one_shot_reads`, `vectors_substrate_mini`, a failing-RNG
hook), `tests/wallet_native.rs`, `tests/native_fixed.rs`, `tests/wallet_custody.rs` (lock / arena rows).

- [ ] **Tests first:** the bare-key `addresses` rows (all mnemonics, `miniSecret`, SS58 prefixes); the `subkey` bare answer; the NFC /
  NFD pair; refusals: index 1, any coin type, SS58 46 / 47 / 16384 (0, 42, 64, 16383 accepted), `sign_key_proof`; signature rows on the
  bare key (byte-equal fixed-randomness rows if T0 found equality, else verify-only), T0's `subkey` signature verifies, a release
  signature verifies and differs between two calls, `vectors_one_shot_reads() == 1` per signature, the failing-RNG hook gives
  `Error::Rng` (no panic), `vectors_sr25519_sign_check` with a wrong public key → `Argument` (the right one accepted); after `lock()` a
  Polkadot handle → `KeyRevoked`, `vectors_secret_in_arena` true, the released chunks wiped; `test_error_strings_never_contain_an_input`
  extended to `sign_message` on Polkadot. Red.
- [ ] Implement per spec §4.3, §7.1, §7.2, §7.4, §7.5; green: `cap cargo test $C --test wallet_native --test wallet_custody --test
  wallet_vault --test wallet_keys --test wallet_link` and `cap cargo test $C --features vectors --test native_fixed --test
  wallet_memory`.
- [ ] Mutants (`…-t8a-mutants.py`): seed in place of entropy; NFKD the passphrase; `ExpansionMode::Uniform`; context `substrat`; SS58
  checksum over `pk` only; prefix 64 in one byte; self-verify removed (the `vectors_sr25519_sign_check` row goes red); `OsRng` handed to
  merlin directly (the failing-RNG row goes red: a panic); the one-shot RNG answering a second read.
- [ ] Gates: `G --only ua-rs`, `G --only ua-rs-wallet`, `G --only ua-rs-vectors`, `G --only ua-rs-zether`, `G --only ua-rs-pqz`, `G
  --only no-oracle` (the store's `open` changed under every facade), `G --only ua-deny`. Commit: `ua-rs-native T8a: Polkadot sr25519
  (substrate-bip39 bare account, SS58)`.

### T8b — `ua-rs`: Polkadot junctions, manifest, fuzz target

**Files:** `src/wallet/substrate.rs` (path parser with its bounds and the leading-zero rule, chain codes, hard / soft steps with the
one-shot RNG), `src/wallet/mod.rs` (`KeyId::Polkadot`, `Wallet::polkadot_key`), `src/wallet/manifest.rs` (`polkadotPaths`: written
only when not empty, ≤ 64, each re-parsed on read, duplicates refused); create `clients/ua-rs/fuzz/fuzz_targets/polkadot_path.rs`, its
seeds and `fuzz/regress/polkadot_path-*` cap inputs, the target in `fuzz/Cargo.toml`; `tests/fuzz_caps.rs` (the cap rows),
`tests/wallet_native.rs`, `tests/wallet_vault.rs`, `tests/wallet_custody.rs`.

- [ ] **Tests first:** every `polkadotPaths` row (incl. the 31 / 32 / 63 / 64-byte junctions, hard and soft); the `subkey` `//Alice` and
  `//Bob` answers; every §7.3 refusal beside its accepted neighbour (as T3); `polkadot_key("")` is `native_key(Polkadot, 0, None)`'s
  slot; soft-key signatures verify; a manifest without `polkadotPaths` keeps its bytes (`rs_vault.json` rows unchanged), one with a path
  round-trips, 65 paths / a stored `///pw` / a duplicate refused (64 accepted); `fuzz_caps` row for a 513-byte path; a junction-path
  handle after `lock()` → `KeyRevoked`; `test_error_strings_never_contain_an_input` extended to `polkadot_key`. Red.
- [ ] Implement per spec §4.3, §4.4, §7.3; green: `cap cargo test $C --test wallet_native --test wallet_vault --test wallet_custody` and
  `cap cargo test $C --features vectors --test fuzz_caps`.
- [ ] Mutants (`…-t8b-mutants.py`): hard ↔ soft; SCALE prefix dropped; one-byte compact length at 64; hash at 32 bytes; numeric as
  string; leading zero accepted; `0x` junction accepted; `polkadotPaths` written when empty (old rows move); the 64-path cap removed;
  the parser's length cap removed (`fuzz_caps` red).
- [ ] Gates: `G --only ua-rs`, `G --only ua-rs-vectors`, `G --only ua-fuzz`. Commit: `ua-rs-native T8b: Polkadot junctions, manifest
  polkadotPaths, polkadot_path fuzz target`.

### T9 — `ua-rs`: both ways, supply chain

**Files:** `tests/wallet_native.rs` (the ignored `regenerate` writer of `smartcontracts/vectors/native/rs_native.json`: OS-random
Taproot and sr25519 signatures, soft keys), `clients/clientkeys/test/native.test.js` (reads `rs_native.json`, verifies every row);
`clients/ua-rs/NOTICE` (complete); `deny.toml` only if T0 found a needed change (old → new in the commit).

- [ ] **Test first:** clientkeys' reader of `rs_native.json` red (file absent). Then write the file: `(cd clients/ua-rs && cap cargo
  test $C --features vectors --test wallet_native -- --ignored regenerate)`.
- [ ] Green: `cap npm test` (clientkeys).
- [ ] Mutant (`…-t9-mutants.py`): a flipped byte in one `rs_native.json` signature (the clientkeys reader goes red).
- [ ] Gates: `G --only vectors-check` (now green: both generators twice, no `ua/` move), `G --only ua-deny`, `G --only clientkeys`.
  Commit: `ua-rs-native T9: rs_native.json both ways, NOTICE`.

### T10 — `ua-c`

**Files:** `clients/ua-c/src/lib.rs` (constants 9–12 and `NETWORKS`, `SCAAS_UA_FEATURE_NATIVE_NETWORKS = 1 << 12` in
`scaas_ua_features()`, `scaas_ua_sign_message_raw`, `scaas_ua_wallet_bitcoin_key`, `scaas_ua_wallet_polkadot_key`,
`scaas_ua_key_address`, `scaas_ua_key_ss58_address`, `scaas_ua_key_witness_program`), `include/scaas_ua.h` (cbindgen),
`tests/test_vectors.py` (the `native.json` rows through the C ABI), `tests/smoke.c` (one Polkadot key, one raw message).

- [ ] **Tests first:** Python rows: addresses (receive and change), witness programs, signature rows (deterministic byte-equal;
  verify-only compared through the rows' public data and `scaas_ua_key_data`), refusals (UA key on `sign_message_raw` →
  `RawDigestRefused` beside a native key accepted; 131,073 bytes; the envelope prefixes; SS58 46; change 2); the network list equals
  `native.json` `networks`; feature bit 12 set. Red.
- [ ] Implement per spec §10.2; regenerate the header (`cap cargo build $C` in `clients/ua-c`; the drift test `cargo test` holds it).
- [ ] Green: `G --only ua-c`.
- [ ] Mutants (`…-t10-mutants.py`): the UA-key refusal removed; constant 12 → 11; feature bit not set.
- [ ] Commit: `ua-rs-native T10: C ABI for the native networks and raw messages`.

### T11 — bindings (T11a–f, one commit each)

Each: tests first reading `native.json` (addresses incl. change and witness programs, the deterministic signature rows, the refusals
of its surface, its network list equal to `networks`; the C-ABI bindings: an old-library load refused when feature bit 12 is clear),
red, implement, green, mutants (the UA-key refusal removed; a network-order swap; the feature-bit check removed, for the C-ABI ones),
its gate step, commit `ua-rs-native T11<x>: <binding> native networks`.

| Task | Files | Gate |
|---|---|---|
| T11a `ua-cxx` | `src/wallet.rs`, `src/wallet.cpp`, `include/…`, `tests/wallet_test.cpp` | `G --only ua-cxx` |
| T11b `ua-qt` | `src/ua_wallet.rs`, its C++ / QML glue, `tests/tst_wallet.qml` (derive, `bitcoinKey`, address, `witnessProgram`, `ss58Address`; assert no raw-signing invokable exists) | `G --only ua-qt` (Qt as `docs/clients` notes) |
| T11c `ua-dart-frb` | `rust/src/api/wallet.rs`, `lib/src/wallet.dart`, regenerated FRB files, its tests | `G --only ua-dart-frb` |
| T11d `ua-py` | `scaas_ua/wallet.py` (load check of bit 12), `tests/test_wallet.py` | `G --only ua-py` |
| T11e `ua-go` | `wallet/wallet.go` (load check of bit 12), `wallet/wallet_test.go` | `G --only ua-go` |
| T11f `ua-cs` | `Scaas.Ua/Wallet.cs` (load check of bit 12), `Scaas.Ua.Tests/WalletTests.cs` | `G --only ua-cs` (then `dotnet build-server shutdown`) |

### T12 — docs, closing gates, summary

**Files:** `docs/clients/ua-libraries.md` and `docs/clients/signers-clientkeys.md` (status SPECIFIED → BUILT per rule, with the
commits; the wallet-surface table and the C ABI paragraph gain the new calls and bit 12), `docs/decisions.md` (Status lines of
CLI-SGN-52 to CLI-SGN-54, CLI-UAL-44 to CLI-UAL-47, CLI-UAL-62, CLI-UAL-63), the spec's status block, the gate runner's `NEW_TESTS`,
`smartcontracts/evm/runs/2026-11-17-ua-rs-native-summary.txt`.

- [ ] `python3 scripts/docs_check.py check` and `python3 scripts/test_docs_check.py` green; `python3 scripts/docs_check.py paths`.
- [ ] Every step of `G` in order (one call per step, foreground): `G --only <step>` for each of `STEPS`; `ua-sizes`: a cell over its
  1 % ratchet is reported with old → new figures and the reason (the new crates, `curve25519-dalek`'s unified features); the baseline
  moves only by hand in its own commit (CLI-UAL-43), after the coordinator has seen the figures.
- [ ] `G --only summary` writes the summary (`step | commit | rc | counts`, no absolute path). Commit: `ua-rs-native T12: docs BUILT,
  closing gates`.

### T13 — closing review

- [ ] The coordinator runs Fable's review of the branch diff (design, security, crypto) and, on the owner's word, Codex's; each
  finding applied as a task (test first) or answered in the spec's review section. Then the touched gate steps again, the summary
  re-written. Commit per fix: `ua-rs-native T13: <finding id> …`. Stop at the branch: merge and push wait for the owner.
