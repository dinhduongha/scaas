# UA-1 — Universal Account kind libraries (F0) in six languages — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** the first sub-plan of the UA phase ([roadmap](2026-10-12-ua-roadmap.md)): the Universal Account **identity
layer** — kind table, tags, ids, keyHash, purpose tags, `ua_msg`, `popDigest`, the registry's `UAAuth` digest, member
digests, canonical ids, the closed kind sets and key-data validation — implemented identically on chain (Solidity
`UAKinds.sol`) and in five client libraries (clientkeys `ua.js`, Rust `clients/scaas-ua`, Python `clients/ua-py`, Go
`clients/ua-go`, C# `clients/ua-cs`), pinned by `smartcontracts/vectors/ua/kinds.json` and `structures.json`. Not here:
signatures and signers (PoP signatures, `groups.json`: UA-2; `UAKey`, derivation: UA F3), the registry contract (UA-2),
the Zether re-point (UA-3), the UA ledger and `metatx3.json` (UA-4).

**Architecture:** One normative implementation writes the vectors, five others must reproduce them. clientkeys
`src/ua.js` (on `@noble/curves`) is the reference; `scripts/ua-vectors.mjs` builds deterministic keys, checks every
valid row is accepted and every invalid row refused by `ua.js`, and writes the two JSON files. The Rust crate recomputes
every field with independent curve code (`k256`, `p256`, `curve25519-dalek`, arkworks) — that agreement is the
cross-check; Solidity (precompiles and plain modular arithmetic), Python (`py_ecc` + integers), Go (`gnark-crypto`,
`filippo.io/edwards25519`, `math/big`) and C# (`System.Numerics.BigInteger`, BouncyCastle for keccak) read the same files.
Every library exposes the same functions (idiomatic case) and raises the same error codes.

**Tech Stack:** Solidity 0.8.37 (`osaka`, legacy codegen), Foundry, forge-std 1.16.2, OpenZeppelin `Strings`; Node 22+
`node --test`, `@noble/curves` / `@noble/hashes` 2.4.0, `@noble/post-quantum` 0.7.1 (already pinned); Rust 1.90, `sha3`
0.10, `k256` / `p256` 0.13, `curve25519-dalek` 4, `ark-ff` / `ark-ec` / `ark-bn254` / `ark-bls12-381` 0.5; Python 3.12,
`py_ecc` 6.0.0, `pycryptodome` 3.19.1, `unittest`; Go 1.22, `github.com/consensys/gnark-crypto` v0.16.0,
`filippo.io/edwards25519` v1.1.0, `golang.org/x/crypto` v0.32.0; .NET 10, `BouncyCastle.Cryptography` 2.6.2, xunit 2.9.3.

**Spec:** `docs/contracts/accounts.md` CTR-UA-02 (ids), CTR-UA-03 (32-byte ids, native space, canonical form), CTR-UA-04
(keccak256), CTR-UA-05 (fixed kind table), CTR-UA-07 (`pop_digest`), CTR-UA-09 (structures), CTR-UA-10/11 (keyHash per
group), CTR-UA-12 (`ua_msg`, `UAAuth`), §1.6 (kind tables, key-data encodings, validation, closed sets), §1.8 (`IUARegistry`
errors, `UAAuth` typehash and domain), §1.16 (vectors); `docs/history/specs/2026-10-06-universal-account-design.md` §16
(stream F0).

**Base:** `main` at the commit that adds this plan (parent `ce92ad5`; forge 917 passed / 10 skipped; clientkeys 75 / 73 / 2;
size gate 0 errors). Every code block below was extracted from this file and run in a scratch copy from that base
(2026-10-12): the generator writes **23 valid and 140 invalid rows**; clientkeys `test/ua.test.js` 4 / 4 (the files
reproduce byte for byte); `scaas-ua` 6 / 6 and `cargo clippy --all-targets -- -D warnings` clean; Python 6 / 6; Go
`go vet` clean and 6 / 6 (`go mod tidy` adds five indirect requirements); C# 6 / 6 without warnings; forge
`test/ua/UAKinds.t.sol` 7 / 7 (the bn254 "outside the subgroup" row is refused by the `0x08` precompile). Not run in
scratch: the full forge suite, the size gate and the docs task. Every later test reads the vectors instead of
hard-coding values; an implementer who finds a library API differing from the code here keeps the behaviour and the
names, fixes the call, and reports it.

## Global Constraints

- Paths relative to `/home/ha/work/ainative/scaas`; worktree `.claude/worktrees/ua1` on branch `ua1-kinds` from `main`.
  forge in `smartcontracts/evm` of the worktree: `lib/` is not tracked — `mkdir lib`, copy `smartcontracts/evm/lib/forge-std`
  into it, symlink `lib/openzeppelin-contracts → /home/ha/work/blockchain/openzeppelin-contracts`. clientkeys: copy (not
  symlink) `node_modules` from the main checkout (never `git add` it). Heavy commands (forge, npm, cargo, go, dotnet) only
  through `scripts/capped`, one at a time. In worktrees a hook blocks bare `git`: use `/usr/bin/git`; use `/usr/bin/grep`.
- Gates: `forge build` then `forge test` in `smartcontracts/evm`; size gate `forge build src --sizes --json > /tmp/sizes.json;
  python3 scripts/size_gate.py /tmp/sizes.json smartcontracts/evm/size-baseline.json`; `npm test` in `clients/clientkeys`;
  `cargo test` in `clients/scaas-ua`; `python3 -m unittest -v tests.test_vectors` in `clients/ua-py`; `go test ./...` in
  `clients/ua-go`; `dotnet test` in `clients/ua-cs/Scaas.Ua.Tests`; `python3 scripts/docs_check.py check` and
  `python3 scripts/docs_check.py facts check`.
- The vector files are generated, never edited by hand: `node scripts/ua-vectors.mjs` in `clients/clientkeys`
  (deterministic; a test regenerates them into a temporary directory and compares bytes). Every library reads them from
  `smartcontracts/vectors/ua/` (never a copy).
- One API in six languages: the names of §"API" below in the language's case (`uaOf` / `ua_of` / `UAOf`), the error codes
  `UAKeyData`, `UAIdInNativeSpace`, `UAKindUnknown`, `UAKindNotDerived`, `UAKindNotNative`, `UAIdFormat`,
  `UAPurposeUnknown`. Only the code is compared across languages; the `reason` string is a label.
- Malformed key data of any length (empty, truncated, a count field of 65535 with no body) is an error with code
  `UAKeyData`, never a panic, an index error or an integer overflow.
- Owner rules: every chain is a test chain (no migration); code size is not a concern; open questions stay open unless
  blocking; component docs say "controller ruling, pending the owner" for rulings, never a U-id; `SmartKeyAccount` names
  contract accounts only; superseded code goes to `legacy/` (nothing is superseded here).
- Pages over their line budget (`accounts.md`, `signers-clientkeys.md`) change by net 0 lines; `docs/history/` and
  `docs/decisions.md` are records (untouched).
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never `git add claude-code-api.txt`.

## API (every library)

| Function (JS name) | Meaning |
|---|---|
| `KINDS`, `kindInfo(kind)` | the table: `{kind, name, native, lengths, group}`; `lengths` empty = variable; unknown ⇒ `UAKindUnknown` |
| `isNativeKind`, `isZetherKind`, `isSigningKind`, `isMemberKind(kind, hederaNative)` | closed sets (§1.6 "Closed kind sets", with ruling U4) |
| `kindTagString(kind)`, `TAG(kind)` | `"scaas.ua.<name>.v1"`, its keccak256; native ⇒ `UAKindNotDerived` |
| `GROUPS`, `groupTagString(g)`, `GROUP(g)` | `"scaas.ua.group.<g>.v1"`, its keccak256 (ruling U3) |
| `MSG_TAG`, `PURPOSES`, `purposeTag(p)`, `POP_TAG` | `keccak256("scaas.ua.msg.v1")`; the 11 purposes; `keccak256("scaas.ua.purpose.<p>.v1")` |
| `uaOf(kind, keyData)` | `keccak256(TAG(kind) ‖ keyData)` (no validation) |
| `deriveUA(kind, keyData, {hederaNative})` | validate, `uaOf`, refuse an id in the native space (`UAIdInNativeSpace`) |
| `nativeId(kind, raw)` | native id left-padded to 32 bytes (length per kind, else `UAKeyData`; derived ⇒ `UAKindNotNative`) |
| `keyHashOf(kind, keyData)` | `keccak256(GROUP(g) ‖ canonical pubkey)` or null (`msig`); call after validation |
| `validateKeyData(kind, keyData, {hederaNative})` | throws `UAKeyData` unless the key data is the canonical encoding of a valid key / structure |
| `inNativeSpace(id)` | top 96 bits zero |
| `uaMessage(kind, purposeTag, digest)` | `keccak256(MSG_TAG ‖ TAG(kind) ‖ purposeTag ‖ digest)` |
| `chainKeyHash(chainId)`, `popDigest({chainId, chainUid, registry, ua, authRef})` | `keccak256("evm:<decimal>")`; `keccak256(POP_TAG ‖ chainKeyHash ‖ chainUid ‖ pad32(registry) ‖ ua ‖ authRef)` |
| `uaAuthDomainSeparator(domain)`, `uaAuthDigest(domain, ua, purposeTag, digest)` | EIP-712 domain `("SCaaS UARegistry", "<generation>", chainId, registry, salt = chainUid)`; `UAAuth(bytes32 ua,bytes32 purpose,bytes32 digest)` |
| `memberDigest(structureUa, uaMsg)` | `keccak256(structureUa ‖ uaMsg)` |
| `canonicalId(text)` | `0x` + 40 or 64 hex digits ⇒ lower case, a top-96-zero 64-digit id in its 40-digit form; else `UAIdFormat` |
| `encodeMsig(threshold, members)` | `u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight)` |

The Solidity library has the on-chain subset: sets, `name`, `tag`, `groupName`, `groupTag`, `uaOf`, `keyHashOf`,
`inNativeSpace`, `uaMessage`, `chainKeyHash`, `popDigest`, `uaAuthDomainSeparator`, `uaAuthDigest`, `memberDigest`,
`validateKeyData` and the purpose / typehash constants (no strings in, no canonical ids, no native ids).

**Validation rules (all libraries).** Fixed lengths per the kind table, else `UAKeyData`. P-256 (`webauthn-p256` first 64
bytes, `p256`): `x, y < p`, on the curve. `ed25519`: `y < p` (low 255 bits, little-endian), a point, not `x = 0` with the
sign bit, not one of the 8 small-order points. `bip340`: `x < p` and `x` lifts. secp256k1 compressed (MuSig2 / FROST
points): prefix `02`/`03`, `x < p`, lifts. bn254 G1 (`schnorr-bn254`, `zether-bn254`, MuSig2 / FROST bn254 points):
`x, y < p`, not `(0, 0)`, on the curve. bn254 G2 (`bls-bn254-minsig`, EIP-197 order `x_im ‖ x_re ‖ y_im ‖ y_re`): every
word `< p`, not all zero, on the twist, in the prime-order subgroup. BLS12-381 G1 / G2 (EIP-2537: each coordinate 64 bytes
with 16 zero bytes on top; G2 `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1`): zero padding, `< p`, not all zero, on the curve, in the
subgroup. `musig2-*`: `Q ‖ u16 n ‖ n × P_i`, `2 ≤ n ≤ 16`, every point valid, `P_i` strictly increasing (bytes).
`frost-*`: `Y ‖ u16 t ‖ u16 n ‖ n × (t × C_ik ‖ R_i ‖ μ_i)`, `2 ≤ t ≤ n ≤ 16`, every point valid, `μ_i <` the group order.
`msig`: `1 ≤ count ≤ 16`, length `4 + 36·count`, every member kind ∈ MEMBER of the profile, weight ≥ 1, a native member's id
in the native space and a derived member's id outside it, ids strictly increasing, `1 ≤ threshold ≤ Σ weight`.
`fndsa512`: header `0x09`, 512 coefficients of 14 bits (big-endian bit packing) each `< 12289`. `mldsa44`, `mldsa65`,
`slhdsa128s`, `pqz-mlwe`: length only.

## Review Focus

- **Truncated, empty or count-inflated key data** (0 bytes; a header with `n = 65535` and no body; a frost header only)
  must give `UAKeyData` in every language — Go and Rust slices panic, C# throws `ArgumentOutOfRangeException`, Python
  raises `IndexError` if a bound is missed. The generator writes these rows for every kind; every library test iterates
  all invalid rows.
- **Byte order**: bn254 G2 is imaginary-first (EIP-197), BLS12-381 G2 is `c0`-first (EIP-2537), ed25519 is little-endian.
  A library that reads one of them the other way accepts a key no other library accepts. Rows with swapped coordinates
  (refused) and the valid rows (accepted) pin each order.
- **Non-canonical encodings accepted by a permissive decoder**: `curve25519-dalek` and `filippo.io/edwards25519` accept
  `y ≥ p` and "negative zero"; integer code that reduces mod `p` accepts a coordinate `= p`. Rows: ed25519 `y = p`,
  `y = p + 1`, `x = 0` with the sign bit; coordinates `= p` for every curve; BLS non-zero padding.
- **Canonical id collisions in client databases**: `0x` + upper case, a padded EOA, `0X`, 39 / 65 digits, no prefix.
  The `canonicalIds` rows; the Solidity side has no string ids.
- **Kind numbers outside the derived set** sent to a derived function: unknown (`0x0000`, `0x0108`) ⇒ `UAKindUnknown`,
  native (`0x0001`) ⇒ `UAKindNotDerived`, derived to `nativeId` ⇒ `UAKindNotNative`; an `msig` member of an unknown,
  foreign-native, Zether or structure kind ⇒ `UAKeyData`.

## Rulings (docs vs code) and defaults taken

- **U1 Scope of F0.** The stream table's F0 lists `groups.json`; group vectors need MuSig2 / FROST signers, which come with
  their verifiers in UA-2. F0 here is the identity layer only (no signature anywhere); PoP signatures in `kinds.json` and
  `groups.json` are UA-2, `metatx3.json` UA-4, `derivation.json` UA F3.
- **U2 Six libraries.** The spec names four (Solidity, JS, Rust, Python); the owner added Go and C# (2026-10-12). Locations:
  `src/ua/UAKinds.sol`, `clients/clientkeys/src/ua.js`, `clients/scaas-ua` (own crate and `Cargo.lock`; the node and
  zether-prover adopt it in their streams), `clients/ua-py` (owner), `clients/ua-go` (module
  `github.com/dinhduongha/scaas/clients/ua-go`), `clients/ua-cs` (`Scaas.Ua` + `Scaas.Ua.Tests`).
- **U3 `group_tag`.** The spec writes `keyHash = keccak256(group_tag ‖ canonical_pubkey)` without defining `group_tag`.
  Taken: `GROUP(g) = keccak256("scaas.ua.group." ‖ g ‖ ".v1")`, `keyHash = keccak256(GROUP(g) ‖ canonical_pubkey)` —
  the shape of `TAG(kind)`. Canonical pubkeys: secp256k1 `x` (32; `x(Q)`, `x(Y)` for MuSig2 / FROST), P-256 `x` (32),
  ed25519 `pk`, bn254 G1 64 bytes (`Q`, `Y` for the bn254 groups), BLS12-381 G1 128, BLS12-381 G2 256, bn254 G2 128,
  PQ `pk`. The group list gains `slhdsa128s` (the kind postdates CTR-UA-11).
- **U4 Sets.** `slhdsa128s` (0x0133) is in SIGNING and MEMBER (the SIGNING row lists `0x0130`–`0x0132`, written before
  0x0133 existed). MEMBER = single-key SIGNING kinds + `evm-eoa`, `evm-contract` + `hedera-native` only when `hederaNative`.
- **U5 `msig` bounds the spec leaves open.** `count ≥ 1`, every weight ≥ 1, a native member (0x0001–0x0003) has an id with
  top 96 bits zero, a derived member an id with top 96 bits non-zero. Registration status and the structure gas bound are
  registry checks (UA-2).
- **U6 Generator location.** The spec says `smartcontracts/scripts/gen_ua_vectors.*`; the generator lives in
  `clients/clientkeys/scripts/ua-vectors.mjs` so it resolves `@noble/*` from clientkeys (as `pq-vectors.mjs`). "Both
  agree" = the JS generator and the Rust crate; the other four check the same files.
- **U7 Validation depth.** All six libraries check curve and subgroup membership (no "layout only" tier); `pqz-mlwe`,
  `mldsa*` and `slhdsa128s` are checked by length (FIPS 204 `pkDecode` is lossless; the `pqz-mlwe` structure is the PQZ
  verifier's, P6g). MuSig2 / FROST key data are checked as layouts of valid points; KeyAgg and the DKG check are UA-2. The
  vector group keys for MuSig2 / FROST are structurally valid but not real groups (stated in the file's note).
- **U8 No refactor of P6a.** `PqUA.sol` and `pq.js` stay; a forge test pins `PqUA.tag == UAKinds.tag` and a JS test pins
  `pq.js` `uaId` / `kindTag` against `ua.js` for the four PQ kinds.
- **U9 Kind numbers in JSON** are JSON numbers (256 = `0x0100`); hex appears only in byte fields.
- **U10 Error for the Solidity library**: `UAKeyData(uint16 kind)` (the `IUARegistry` name), `UAKindUnknown(uint16)`,
  `UAKindNotDerived(uint16)`; the registry (UA-2) reuses them.

## Open questions (not blocking)

- Whether the node and zether-prover switch to `scaas-ua` now or in their own streams (default: their streams).
- Publishing the client libraries as packages (npm, crates.io, PyPI, Go module proxy, NuGet) — not before an audit.

## Out of scope (next sub-plans)

UA-2: `UARegistry`, the verifiers, PoP signatures, `groups.json`, T-REG/T-AUTH/T-CHAIN/T-MEMBER/T-FROST/T-GAS. UA-3: the
Zether re-point. UA-4: the UA ledger, `metatx3.json`. UA-1b (evaluated 2026-10-12, not planned): a C++/Qt-QML client as a `cxx` bridge over
`scaas-ua` (built by CMake + corrosion, wrapped in a `QObject` for QML; no async bridge: every call is synchronous and
CPU-bound) and a Dart client on the crate's WASM build (owner: WASM; wasm-bindgen + `dart:js_interop` on Flutter web;
native Flutter targets via flutter_rust_bridge v2 over a wrapper crate), rather than two more curve implementations.

---
### Task 1: clientkeys `ua.js`, the generator, the vectors

**Files:**
- Create: `clients/clientkeys/src/ua.js`
- Create: `clients/clientkeys/scripts/ua-vectors.mjs`
- Create: `clients/clientkeys/test/ua.test.js`
- Create (generated): `smartcontracts/vectors/ua/kinds.json`, `smartcontracts/vectors/ua/structures.json`

**Interfaces:**
- Consumes: `src/bytes.js` (`keccak_256`, `concatBytes`, `utf8ToBytes`, `fromHex`, `hex`, `word`), `src/seed.js`
  (`seedFromWords`), `src/pq.js` (`pqKeygen`, `uaId`, `kindTag`, `PQ_KINDS`).
- Produces: the API table above (JS names) and the two vector files every later task reads. `kinds.json`:
  `{note, version, constants{MSG_TAG, POP_TAG, DOMAIN_TYPEHASH, UAAUTH_TYPEHASH, NAME_HASH}, kinds[{kind, name, native,
  lengths, tag, TAG, group, signing, zether, member, memberHedera}], groups[{group, tag, GROUP}], purposes[{purpose, tag,
  purposeTag}], valid[{kind, name, hederaNative, keyData, ua, keyHash}], invalid[{kind, hederaNative, keyData, error,
  reason}], natives[{kind, raw, id, canonical}], nativeInvalid[{kind, raw, error}], nativeSpace[{id, inNativeSpace}],
  messages[{kind, purpose, purposeTag, digest, uaMsg}], canonicalIds[{input, canonical} | {input, error}]}`;
  `structures.json`: `{note, version, contexts{A,B,C,D: {chainId, chainUid, registry}}, pop[{context, ua, authRef,
  chainKeyHash, popDigest}], uaAuth[{context, generation, domainSeparator, ua, purpose, purposeTag, digest,
  uaAuthDigest}], member[{structureUa, uaMsg, memberDigest}]}`. `keyHash` is `null` for `msig`; `tag`, `TAG`, `group`
  are `null` for native kinds.

- [ ] **Step 1: The library.** Create `clients/clientkeys/src/ua.js`:

```js
// UA identity layer (accounts.md §1.3–§1.6; CTR-UA-02…05, 07, 09, 11, 12): the kind table, ids, keyHash, purpose tags,
// ua_msg, popDigest, the registry's UAAuth digest, member digests, canonical ids and key-data validation. The same rules
// live in Solidity (src/ua/UAKinds.sol), Rust (clients/scaas-ua), Python (clients/ua-py), Go (clients/ua-go) and C#
// (clients/ua-cs); smartcontracts/vectors/ua/kinds.json and structures.json, written by scripts/ua-vectors.mjs from
// this file, pin all six. No signing here (UAKey and the signers are UA F3).
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { p256 } from '@noble/curves/nist.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bn254 } from '@noble/curves/bn254.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { keccak_256, concatBytes, utf8ToBytes, fromHex, hex, word } from './bytes.js';

/** An error whose `code` every implementation and the vector files share. */
export class UAError extends Error {
  constructor(code, reason) {
    super(reason ? `${code}: ${reason}` : code);
    this.code = code;
    this.reason = reason;
  }
}
const fail = (code, reason) => { throw new UAError(code, reason); };
const need = (ok, reason) => { if (!ok) fail('UAKeyData', reason); };

const bytes = (v) => (v instanceof Uint8Array ? v : fromHex(v));
const sized = (v, n, what) => {
  const b = bytes(v);
  if (b.length !== n) throw new Error(`${what} must be ${n} bytes`);
  return b;
};
const be = (b) => (b.length === 0 ? 0n : BigInt(hex(b)));
const u16 = (d, o) => (d[o] << 8) | d[o + 1];
const less = (a, b) => {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] < b[i];
  return false;
};
const tagHash = (s) => keccak_256(utf8ToBytes(s));

// [number, name, key-data lengths (empty = variable), keyHash group (null = none)]
const DERIVED = [
  [0x0100, 'webauthn-p256', [96], 'p256'],
  [0x0101, 'p256', [64], 'p256'],
  [0x0102, 'ed25519', [32], 'ed25519'],
  [0x0103, 'bip340', [32], 'secp256k1'],
  [0x0104, 'schnorr-bn254', [64], 'bn254-g1'],
  [0x0105, 'schnorr-bls12381', [128], 'bls12381-g1'],
  [0x0106, 'bls12381-minsig', [256], 'bls12381-g2'],
  [0x0107, 'bls-bn254-minsig', [128], 'bn254-g2'],
  [0x0110, 'musig2-secp256k1', [], 'secp256k1'],
  [0x0111, 'frost-secp256k1', [], 'secp256k1'],
  [0x0112, 'musig2-bn254', [], 'bn254-g1'],
  [0x0113, 'frost-bn254', [], 'bn254-g1'],
  [0x0120, 'msig', [], null],
  [0x0130, 'mldsa44', [1312], 'mldsa44'],
  [0x0131, 'mldsa65', [1952], 'mldsa65'],
  [0x0132, 'fndsa512', [897], 'fndsa512'],
  [0x0133, 'slhdsa128s', [32], 'slhdsa128s'],
  [0x0140, 'zether-bn254', [64], 'bn254-g1'],
  [0x0141, 'zether-bls12381', [128], 'bls12381-g1'],
  [0x0142, 'pqz-mlwe', [16384], 'pqz-mlwe'],
];
// [number, name, native id lengths]
const NATIVE = [
  [0x0001, 'evm-eoa', [20]], [0x0002, 'evm-contract', [20]], [0x0003, 'hedera-native', [20]],
  [0x0010, 'solana-ed25519', [32]], [0x0011, 'stellar-account', [32]], [0x0012, 'soroban-contract', [32]],
  [0x0013, 'aptos-account', [32]], [0x0014, 'sui-address', [32]], [0x0015, 'cosmos-account', [20, 32]],
  [0x0016, 'ton-wallet', [32]],
];
export const KINDS = Object.freeze([
  ...NATIVE.map(([kind, name, lengths]) => Object.freeze({ kind, name, native: true, lengths, group: null })),
  ...DERIVED.map(([kind, name, lengths, group]) => Object.freeze({ kind, name, native: false, lengths, group })),
]);
const BY_NUMBER = new Map(KINDS.map((k) => [k.kind, k]));
export const kindInfo = (kind) => BY_NUMBER.get(kind) ?? fail('UAKindUnknown', `0x${Number(kind).toString(16)}`);
const derived = (kind) => {
  const k = kindInfo(kind);
  if (k.native) fail('UAKindNotDerived', k.name);
  return k;
};

const singleSigning = (k) => (k >= 0x0100 && k <= 0x0107) || (k >= 0x0110 && k <= 0x0113) || (k >= 0x0130 && k <= 0x0133);
export const isNativeKind = (kind) => BY_NUMBER.get(kind)?.native === true;
export const isZetherKind = (kind) => kind >= 0x0140 && kind <= 0x0142;
export const isSigningKind = (kind) => kind === 0x0120 || singleSigning(kind);
export const isMemberKind = (kind, hederaNative = false) =>
  singleSigning(kind) || kind === 0x0001 || kind === 0x0002 || (hederaNative && kind === 0x0003);

export const kindTagString = (kind) => `scaas.ua.${derived(kind).name}.v1`;
export const TAG = (kind) => tagHash(kindTagString(kind));
export const GROUPS = Object.freeze([...new Set(DERIVED.map(([, , , g]) => g).filter(Boolean))]);
export const groupTagString = (group) => {
  if (!GROUPS.includes(group)) throw new Error(`unknown keyHash group ${group}`);
  return `scaas.ua.group.${group}.v1`;
};
export const GROUP = (group) => tagHash(groupTagString(group));
export const MSG_TAG = tagHash('scaas.ua.msg.v1');
export const PURPOSES = Object.freeze(['pop', 'authref', 'metatx', 'metatx-cancel', 'member', 'zether-auth', 'zether-owner',
  'keyop', 'receiver-fee', 'vp', 'vc-anchor']);
export const purposeTag = (p) => {
  if (!PURPOSES.includes(p)) fail('UAPurposeUnknown', p);
  return tagHash(`scaas.ua.purpose.${p}.v1`);
};
export const POP_TAG = purposeTag('pop');
export const DOMAIN_TYPEHASH = tagHash('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)');
export const UAAUTH_TYPEHASH = tagHash('UAAuth(bytes32 ua,bytes32 purpose,bytes32 digest)');
export const NAME_HASH = tagHash('SCaaS UARegistry');

/** `keccak256(TAG(kind) ‖ keyData)`; no validation (use `deriveUA`). */
export const uaOf = (kind, keyData) => keccak_256(concatBytes(TAG(kind), bytes(keyData)));
export const inNativeSpace = (id) => sized(id, 32, 'id').subarray(0, 12).every((b) => b === 0);

/** Validate, derive, refuse an id whose top 96 bits are zero (CTR-UA-03). */
export function deriveUA(kind, keyData, { hederaNative = false } = {}) {
  validateKeyData(kind, keyData, { hederaNative });
  const ua = uaOf(kind, keyData);
  if (inNativeSpace(ua)) fail('UAIdInNativeSpace', hex(ua));
  return ua;
}

/** A native id, left-padded to 32 bytes. */
export function nativeId(kind, raw) {
  const k = kindInfo(kind);
  if (!k.native) fail('UAKindNotNative', k.name);
  const b = bytes(raw);
  need(k.lengths.includes(b.length), 'length');
  return concatBytes(new Uint8Array(32 - b.length), b);
}

/** `keccak256(GROUP(g) ‖ canonical pubkey)`, null for structures. Call on validated key data. */
export function keyHashOf(kind, keyData) {
  const k = derived(kind);
  if (!k.group) return null;
  const d = bytes(keyData);
  const [lo, hi] = { 0x0100: [0, 32], 0x0101: [0, 32], 0x0110: [1, 33], 0x0111: [1, 33], 0x0112: [0, 64], 0x0113: [0, 64] }[kind]
    ?? [0, d.length];
  need(d.length >= hi, 'length');
  return keccak_256(concatBytes(GROUP(k.group), d.subarray(lo, hi)));
}

export const uaMessage = (kind, purpose, digest) =>
  keccak_256(concatBytes(MSG_TAG, TAG(kind), sized(purpose, 32, 'purposeTag'), sized(digest, 32, 'digest')));
export const chainKeyHash = (chainId) => tagHash(`evm:${BigInt(chainId).toString(10)}`);
const addressWord = (a) => concatBytes(new Uint8Array(12), sized(a, 20, 'registry'));

/** `pop_digest` (CTR-UA-07). */
export function popDigest({ chainId, chainUid, registry, ua, authRef = new Uint8Array(32) }) {
  return keccak_256(concatBytes(POP_TAG, chainKeyHash(chainId), sized(chainUid, 32, 'chainUid'), addressWord(registry),
    sized(ua, 32, 'ua'), sized(authRef, 32, 'authRef')));
}

export function uaAuthDomainSeparator({ generation, chainId, registry, chainUid }) {
  if (!Number.isInteger(generation) || generation < 1) throw new Error('generation must be a positive integer');
  return keccak_256(concatBytes(DOMAIN_TYPEHASH, NAME_HASH, tagHash(String(generation)), word(chainId), addressWord(registry),
    sized(chainUid, 32, 'chainUid')));
}

/** EIP-712 digest of `UAAuth(ua, purpose, digest)` under the registry's domain: what native signers sign. */
export function uaAuthDigest(domain, ua, purpose, digest) {
  const s = keccak_256(concatBytes(UAAUTH_TYPEHASH, sized(ua, 32, 'ua'), sized(purpose, 32, 'purposeTag'), sized(digest, 32, 'digest')));
  return keccak_256(concatBytes(Uint8Array.of(0x19, 0x01), uaAuthDomainSeparator(domain), s));
}

export const memberDigest = (structureUa, uaMsg) =>
  keccak_256(concatBytes(sized(structureUa, 32, 'structureUa'), sized(uaMsg, 32, 'uaMsg')));

/** Lower-case hex; a 32-byte id with the top 96 bits zero is written as its 20-byte native id (CTR-UA-03). */
export function canonicalId(text) {
  const m = /^0x([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/.exec(String(text));
  if (!m) fail('UAIdFormat', String(text));
  const h = m[1].toLowerCase();
  return h.length === 64 && h.startsWith('0'.repeat(24)) ? `0x${h.slice(24)}` : `0x${h}`;
}

export function encodeMsig(threshold, members) {
  const out = new Uint8Array(4 + 36 * members.length);
  const put16 = (o, v) => { out[o] = (v >> 8) & 0xff; out[o + 1] = v & 0xff; };
  put16(0, threshold);
  put16(2, members.length);
  members.forEach(({ kind, id, weight }, i) => {
    const o = 4 + 36 * i;
    put16(o, kind);
    out.set(sized(id, 32, 'member id'), o + 2);
    put16(o + 34, weight);
  });
  return out;
}

// --- key-data validation (§1.6 "Validation at registration") ---

const SECP_P = secp256k1.Point.Fp.ORDER;
const SECP_N = secp256k1.Point.Fn.ORDER;
const P256_P = p256.Point.Fp.ORDER;
const ED_P = 2n ** 255n - 19n;
const BN_P = bn254.fields.Fp.ORDER;
const BN_R = bn254.fields.Fr.ORDER;
const BLS_P = bls12_381.fields.Fp.ORDER;

/** Runs a noble constructor / validity check; any throw is "not a valid point". */
const point = (f) => {
  try {
    return f();
  } catch {
    return fail('UAKeyData', 'curve');
  }
};

function secpCompressed(b) {
  need(b[0] === 2 || b[0] === 3, 'prefix');
  need(be(b.subarray(1, 33)) < SECP_P, 'range');
  point(() => secp256k1.Point.fromBytes(b));
}

function p256Point(xy) {
  need(be(xy.subarray(0, 32)) < P256_P && be(xy.subarray(32, 64)) < P256_P, 'range');
  point(() => p256.Point.fromBytes(concatBytes(Uint8Array.of(4), xy)));
}

function ed25519Key(b) {
  need((be(Uint8Array.from(b).reverse()) & ((1n << 255n) - 1n)) < ED_P, 'range');
  const P = point(() => ed25519.Point.fromBytes(b, false));
  need(!(P.toAffine().x === 0n && (b[31] & 0x80)), 'sign');
  need(!P.isSmallOrder(), 'small-order');
}

function bnG1(b) {
  const x = be(b.subarray(0, 32));
  const y = be(b.subarray(32, 64));
  need(x < BN_P && y < BN_P, 'range');
  need(x !== 0n || y !== 0n, 'identity');
  point(() => bn254.G1.Point.fromAffine({ x, y }).assertValidity());
}

function bnG2(b) {
  const [xi, xr, yi, yr] = [0, 1, 2, 3].map((i) => be(b.subarray(32 * i, 32 * i + 32)));
  need([xi, xr, yi, yr].every((v) => v < BN_P), 'range');
  need([xi, xr, yi, yr].some((v) => v !== 0n), 'identity');
  // noble's assertValidity checks the twist equation and the prime-order subgroup
  point(() => bn254.G2.Point.fromAffine({ x: { c0: xr, c1: xi }, y: { c0: yr, c1: yi } }).assertValidity());
}

function blsFp(b) {
  need(b.subarray(0, 16).every((v) => v === 0), 'padding');
  const v = be(b.subarray(16, 64));
  need(v < BLS_P, 'range');
  return v;
}

function blsG1(b) {
  const x = blsFp(b.subarray(0, 64));
  const y = blsFp(b.subarray(64, 128));
  need(x !== 0n || y !== 0n, 'identity');
  point(() => bls12_381.G1.Point.fromAffine({ x, y }).assertValidity());
}

function blsG2(b) {
  const [x0, x1, y0, y1] = [0, 1, 2, 3].map((i) => blsFp(b.subarray(64 * i, 64 * i + 64)));
  need([x0, x1, y0, y1].some((v) => v !== 0n), 'identity');
  point(() => bls12_381.G2.Point.fromAffine({ x: { c0: x0, c1: x1 }, y: { c0: y0, c1: y1 } }).assertValidity());
}

/** `Q ‖ u16 n ‖ n × P_i`, 2 ≤ n ≤ 16, P_i strictly increasing. */
function musig2(d, check, size) {
  need(d.length >= size + 2, 'length');
  const n = u16(d, size);
  need(n >= 2 && n <= 16, 'n');
  need(d.length === size + 2 + n * size, 'length');
  check(d.subarray(0, size));
  for (let i = 0; i < n; i++) {
    const o = size + 2 + i * size;
    check(d.subarray(o, o + size));
    if (i > 0) need(less(d.subarray(o - size, o), d.subarray(o, o + size)), 'order');
  }
}

/** `Y ‖ u16 t ‖ u16 n ‖ n × (t × C_ik ‖ R_i ‖ μ_i)`, 2 ≤ t ≤ n ≤ 16, μ_i < order. */
function frost(d, check, size, order) {
  need(d.length >= size + 4, 'length');
  const t = u16(d, size);
  const n = u16(d, size + 2);
  need(t >= 2 && t <= n && n <= 16, 'threshold');
  const per = (t + 1) * size + 32;
  need(d.length === size + 4 + n * per, 'length');
  check(d.subarray(0, size));
  for (let i = 0; i < n; i++) {
    const o = size + 4 + i * per;
    for (let j = 0; j <= t; j++) check(d.subarray(o + j * size, o + (j + 1) * size)); // t commitments, then R_i
    need(be(d.subarray(o + (t + 1) * size, o + per)) < order, 'scalar');
  }
}

/** `u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight)` (CTR-UA-09; ruling U5). */
function msig(d, hederaNative) {
  need(d.length >= 4, 'length');
  const threshold = u16(d, 0);
  const count = u16(d, 2);
  need(count >= 1 && count <= 16, 'count');
  need(d.length === 4 + 36 * count, 'length');
  let total = 0;
  for (let i = 0; i < count; i++) {
    const o = 4 + 36 * i;
    const kind = u16(d, o);
    const id = d.subarray(o + 2, o + 34);
    const weight = u16(d, o + 34);
    need(isMemberKind(kind, hederaNative), 'member-kind');
    need(weight >= 1, 'weight');
    need(isNativeKind(kind) === id.subarray(0, 12).every((b) => b === 0), 'member-id');
    if (i > 0) need(less(d.subarray(o - 34, o - 2), id), 'order');
    total += weight;
  }
  need(threshold >= 1 && threshold <= total, 'threshold');
}

/** `0x09 ‖ 512 × 14-bit h_i`, big-endian bit packing, each h_i < q = 12289. */
function fndsa(d) {
  need(d[0] === 0x09, 'header');
  for (let i = 0; i < 512; i++) {
    let v = 0;
    for (let j = 0; j < 14; j++) {
      const k = i * 14 + j;
      v = (v << 1) | ((d[1 + (k >> 3)] >> (7 - (k & 7))) & 1);
    }
    need(v < 12289, 'coefficient');
  }
}

/** Throws `UAError('UAKeyData')` unless `keyData` is the unique canonical encoding of a valid key or structure. */
export function validateKeyData(kind, keyData, { hederaNative = false } = {}) {
  const k = derived(kind);
  const d = bytes(keyData);
  if (k.lengths.length) need(k.lengths.includes(d.length), 'length');
  switch (kind) {
    case 0x0100: return p256Point(d.subarray(0, 64));
    case 0x0101: return p256Point(d);
    case 0x0102: return ed25519Key(d);
    case 0x0103: return secpCompressed(concatBytes(Uint8Array.of(2), d));
    case 0x0104: case 0x0140: return bnG1(d);
    case 0x0105: case 0x0141: return blsG1(d);
    case 0x0106: return blsG2(d);
    case 0x0107: return bnG2(d);
    case 0x0110: return musig2(d, secpCompressed, 33);
    case 0x0111: return frost(d, secpCompressed, 33, SECP_N);
    case 0x0112: return musig2(d, bnG1, 64);
    case 0x0113: return frost(d, bnG1, 64, BN_R);
    case 0x0120: return msig(d, hederaNative);
    case 0x0132: return fndsa(d);
    default: return undefined; // mldsa44/65, slhdsa128s, pqz-mlwe: the length is the whole check (U7)
  }
}
```

- [ ] **Step 2: The generator.** Create `clients/clientkeys/scripts/ua-vectors.mjs`:

```js
// Generates smartcontracts/vectors/ua/kinds.json and structures.json: the UA identity layer of src/ua.js on deterministic
// keys — the kind table, every derived kind's valid key data with its id and keyHash, invalid key data with the error
// every implementation must give, native ids, canonical ids, ua_msg, popDigest, UAAuth and member digests. Every valid row
// is accepted and every invalid row refused by src/ua.js before it is written; clients/scaas-ua recomputes all of it with
// independent curve code (k256, p256, curve25519-dalek, arkworks). MuSig2 / FROST rows are valid layouts of valid points,
// not real groups (KeyAgg and the DKG check are UA-2).
//   node scripts/ua-vectors.mjs [outDir]
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { p256 } from '@noble/curves/nist.js';
import { ed25519, ED25519_TORSION_SUBGROUP } from '@noble/curves/ed25519.js';
import { bn254 } from '@noble/curves/bn254.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { shake256 } from '@noble/hashes/sha3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { seedFromWords } from '../src/seed.js';
import { pqKeygen } from '../src/pq.js';
import { hex, fromHex, keccak_256, utf8ToBytes, concatBytes } from '../src/bytes.js';
import * as ua from '../src/ua.js';

const OUT = process.argv[2] ?? fileURLToPath(new URL('../../../smartcontracts/vectors/ua/', import.meta.url));
const label = (s) => keccak_256(utf8ToBytes(`scaas ua-1 vector ${s}`));
const scalar = (s, n) => (BigInt(hex(label(s))) % (n - 1n)) + 1n;
const be = (v, len) => fromHex(v.toString(16).padStart(2 * len, '0'));
const int = (b) => BigInt(hex(b));
const u16 = (v) => Uint8Array.of((v >> 8) & 0xff, v & 0xff);
const cmp = (a, b) => {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
};
const put = (b, o, chunk) => {
  const c = Uint8Array.from(b);
  c.set(chunk, o);
  return c;
};
const swap = (b, o1, o2, n) => put(put(b, o1, b.subarray(o2, o2 + n)), o2, b.subarray(o1, o1 + n));
const assert = (ok, what) => { if (!ok) throw new Error(what); };

const SECP_P = secp256k1.Point.Fp.ORDER;
const SECP_N = secp256k1.Point.Fn.ORDER;
const P256_P = p256.Point.Fp.ORDER;
const ED_P = 2n ** 255n - 19n;
const BN = bn254.fields;
const BLS = bls12_381.fields;

// deterministic points in their key-data encodings
const secpC = (s) => secp256k1.Point.BASE.multiply(scalar(s, SECP_N)).toBytes(true);
const p256xy = (s) => p256.Point.BASE.multiply(scalar(s, p256.Point.Fn.ORDER)).toBytes(false).subarray(1);
const bnG1enc = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x, 32), be(y, 32)); };
const bnG1 = (s) => bnG1enc(bn254.G1.Point.BASE.multiply(scalar(s, BN.Fr.ORDER)));
const bnG2enc = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x.c1, 32), be(x.c0, 32), be(y.c1, 32), be(y.c0, 32)); };
const bnG2 = (s) => bnG2enc(bn254.G2.Point.BASE.multiply(scalar(s, BN.Fr.ORDER)));
const blsG1enc = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x, 64), be(y, 64)); };
const blsG1 = (s) => blsG1enc(bls12_381.G1.Point.BASE.multiply(scalar(s, BLS.Fr.ORDER)));
const blsG2enc = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x.c0, 64), be(x.c1, 64), be(y.c0, 64), be(y.c1, 64)); };
const blsG2 = (s) => blsG2enc(bls12_381.G2.Point.BASE.multiply(scalar(s, BLS.Fr.ORDER)));

/** First point on `y² = x³ + b` (x = x0(0), x0(1), …) outside the prime-order subgroup, encoded. */
function offSubgroup(F, b, Point, x0, enc) {
  for (let i = 0n; ; i++) {
    const x = x0(i);
    let y;
    try { y = F.sqrt(F.add(F.mul(F.sqr(x), x), b)); } catch { continue; }
    if (y === undefined) continue;
    const P = Point.fromAffine({ x, y });
    try { P.assertValidity(); } catch { return enc(P); } // on the curve by construction, so the throw is the subgroup
  }
}
/** First encoding make(2), make(3), … that `ok` refuses. */
function firstRefused(make, ok) {
  for (let i = 2n; ; i++) {
    const b = make(i);
    try { ok(b); } catch { return b; }
  }
}

const musig2 = (pt, s) => {
  const pks = [1, 2, 3].map((i) => pt(`${s} pk ${i}`)).sort(cmp);
  return concatBytes(pt(`${s} Q`), u16(3), ...pks);
};
const frost = (pt, s, order, t = 2, n = 3) => {
  const parts = [];
  for (let i = 1; i <= n; i++) {
    for (let j = 0; j < t; j++) parts.push(pt(`${s} C ${i} ${j}`));
    parts.push(pt(`${s} R ${i}`), be(scalar(`${s} mu ${i}`, order), 32));
  }
  return concatBytes(pt(`${s} Y`), u16(t), u16(n), ...parts);
};

const MNEMONIC = 'bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author '
  + 'capable act festival slice deposit sauce coconut afford frown better';
const seed = seedFromWords(MNEMONIC);
const pq = (name) => pqKeygen(seed, name, 0, 0).publicKey;

const key = new Map([
  [0x0100, concatBytes(p256xy('webauthn-p256'), sha256(utf8ToBytes('scaas.example')))],
  [0x0101, p256xy('p256')],
  [0x0102, ed25519.getPublicKey(label('ed25519'))],
  [0x0103, schnorr.getPublicKey(label('bip340'))],
  [0x0104, bnG1('schnorr-bn254')],
  [0x0105, blsG1('schnorr-bls12381')],
  [0x0106, blsG2('bls12381-minsig')],
  [0x0107, bnG2('bls-bn254-minsig')],
  [0x0110, musig2(secpC, 'musig2-secp256k1')],
  [0x0111, frost(secpC, 'frost-secp256k1', SECP_N)],
  [0x0112, musig2(bnG1, 'musig2-bn254')],
  [0x0113, frost(bnG1, 'frost-bn254', BN.Fr.ORDER)],
  [0x0130, pq('mldsa44')],
  [0x0131, pq('mldsa65')],
  [0x0132, pq('fndsa512')],
  [0x0133, pq('slhdsa128s')],
  [0x0140, bnG1('zether-bn254')],
  [0x0141, blsG1('zether-bls12381')],
  [0x0142, shake256(utf8ToBytes('scaas ua-1 vector pqz-mlwe key'), { dkLen: 16384 })],
]);
const id = (kind) => ua.deriveUA(kind, key.get(kind));
const eoa = ua.nativeId(0x0001, label('evm-eoa').subarray(12));
const hedera = ua.nativeId(0x0003, concatBytes(new Uint8Array(12), be(1234n, 8)));
const mem = (kind, mid, weight = 1) => ({ kind, id: mid, weight });
const sortM = (ms) => [...ms].sort((a, b) => cmp(a.id, b.id));
const msigMembers = sortM([mem(0x0001, eoa), mem(0x0101, id(0x0101)), mem(0x0103, id(0x0103)), mem(0x0130, id(0x0130))]);
const msigKey = ua.encodeMsig(2, msigMembers);
const msigHedera = ua.encodeMsig(1, sortM([mem(0x0003, hedera), mem(0x0101, id(0x0101))]));
const msigUa = ua.deriveUA(0x0120, msigKey);

// --- valid rows ---
const row = (kind, keyData, hederaNative = false) => {
  const h = ua.keyHashOf(kind, keyData);
  return {
    kind, name: ua.kindInfo(kind).name, hederaNative, keyData: hex(keyData),
    ua: hex(ua.deriveUA(kind, keyData, { hederaNative })), keyHash: h && hex(h),
  };
};
const valid = [...[...key].map(([k, d]) => row(k, d)), row(0x0120, msigKey), row(0x0120, msigHedera, true)];
// the same key under two kinds of one group: two ids, one keyHash (the registry's UAKeyInUse, CTR-UA-11)
valid.push(row(0x0140, key.get(0x0104)), row(0x0100, concatBytes(key.get(0x0101), sha256(utf8ToBytes('scaas.example')))));
for (const [a, b] of [[0x0104, 0x0140], [0x0101, 0x0100]]) {
  const [ra, rb] = [valid.find((r) => r.kind === a), valid.at(b === 0x0140 ? -2 : -1)];
  assert(ra.keyHash === rb.keyHash && ra.ua !== rb.ua, `shared key 0x${a.toString(16)} / 0x${b.toString(16)}`);
}

// --- invalid rows: each refused by src/ua.js with the stated error before it is written ---
const invalid = [];
function bad(kind, keyData, reason, { error = 'UAKeyData', hederaNative = false } = {}) {
  try {
    ua.validateKeyData(kind, keyData, { hederaNative });
  } catch (e) {
    assert(e instanceof ua.UAError && e.code === error, `0x${kind.toString(16)} ${reason}: ${e.message}`);
    invalid.push({ kind, hederaNative, keyData: hex(keyData), error, reason });
    return;
  }
  throw new Error(`0x${kind.toString(16)} ${reason}: accepted`);
}

for (const [kind, d] of [...key, [0x0120, msigKey]]) {
  bad(kind, new Uint8Array(0), 'empty');
  if (ua.kindInfo(kind).lengths.length) {
    bad(kind, d.subarray(0, d.length - 1), 'one byte short');
    bad(kind, concatBytes(d, Uint8Array.of(0)), 'one byte long');
  } else {
    bad(kind, concatBytes(d, Uint8Array.of(0)), 'trailing byte');
  }
}
for (const kind of [0x0100, 0x0101]) {
  const d = key.get(kind);
  bad(kind, put(d, 0, be(P256_P, 32)), 'x = p');
  bad(kind, put(d, 32, be((int(d.subarray(32, 64)) + 1n) % P256_P, 32)), 'off the curve');
}
for (const t of ED25519_TORSION_SUBGROUP) bad(0x0102, fromHex(t), `small order ${t.slice(0, 8)}`);
bad(0x0102, be(ED_P, 32).reverse(), 'y = p');
bad(0x0102, be(ED_P + 1n, 32).reverse(), 'y = p + 1 (non-canonical identity)');
bad(0x0102, put(put(new Uint8Array(32), 0, Uint8Array.of(1)), 31, Uint8Array.of(0x80)), 'x = 0 with the sign bit');
bad(0x0102, firstRefused((y) => be(y, 32).reverse(), (b) => ed25519.Point.fromBytes(b, false)), 'not a point');
bad(0x0103, be(SECP_P, 32), 'x = p');
bad(0x0103, firstRefused((x) => be(x, 32), (b) => secp256k1.Point.fromBytes(concatBytes(Uint8Array.of(2), b))), 'x does not lift');
for (const kind of [0x0104, 0x0140]) {
  const d = key.get(kind);
  bad(kind, new Uint8Array(64), 'identity');
  bad(kind, put(d, 0, be(BN.Fp.ORDER, 32)), 'x = p');
  bad(kind, put(d, 32, be((int(d.subarray(32, 64)) + 1n) % BN.Fp.ORDER, 32)), 'off the curve');
}
const blsG1Off = offSubgroup(BLS.Fp, 4n, bls12_381.G1.Point, (i) => i + 1n, blsG1enc);
for (const kind of [0x0105, 0x0141]) {
  const d = key.get(kind);
  bad(kind, new Uint8Array(128), 'identity');
  bad(kind, put(d, 0, Uint8Array.of(1)), 'non-zero padding');
  bad(kind, put(d, 16, be(BLS.Fp.ORDER, 48)), 'x = p');
  bad(kind, put(d, 64, be((int(d.subarray(64, 128)) + 1n) % BLS.Fp.ORDER, 64)), 'off the curve');
  bad(kind, blsG1Off, 'outside the subgroup');
}
{
  const d = key.get(0x0106);
  const b2 = BLS.Fp2.fromBigTuple([4n, 4n]);
  bad(0x0106, new Uint8Array(256), 'identity');
  bad(0x0106, put(d, 0, Uint8Array.of(1)), 'non-zero padding');
  bad(0x0106, put(d, 16, be(BLS.Fp.ORDER, 48)), 'x.c0 = p');
  bad(0x0106, put(d, 128, be((int(d.subarray(128, 192)) + 1n) % BLS.Fp.ORDER, 64)), 'off the curve');
  bad(0x0106, swap(d, 0, 64, 64), 'x.c0 and x.c1 swapped');
  bad(0x0106, offSubgroup(BLS.Fp2, b2, bls12_381.G2.Point, (i) => BLS.Fp2.fromBigTuple([i + 1n, 0n]), blsG2enc), 'outside the subgroup');
}
{
  const d = key.get(0x0107);
  const b2 = BN.Fp2.div(BN.Fp2.fromBigTuple([3n, 0n]), BN.Fp2.fromBigTuple([9n, 1n]));
  bad(0x0107, new Uint8Array(128), 'identity');
  bad(0x0107, put(d, 0, be(BN.Fp.ORDER, 32)), 'x_im = p');
  bad(0x0107, put(d, 96, be((int(d.subarray(96, 128)) + 1n) % BN.Fp.ORDER, 32)), 'off the twist');
  bad(0x0107, swap(d, 0, 32, 32), 'x_im and x_re swapped');
  bad(0x0107, offSubgroup(BN.Fp2, b2, bn254.G2.Point, (i) => BN.Fp2.fromBigTuple([i + 1n, 0n]), bnG2enc), 'outside the subgroup');
}
{
  const d = key.get(0x0110);
  const Q = d.subarray(0, 33);
  const pks = [0, 1, 2].map((i) => d.subarray(35 + 33 * i, 68 + 33 * i));
  const more = Array.from({ length: 17 }, (_, i) => secpC(`musig2-secp256k1 extra ${i}`)).sort(cmp);
  bad(0x0110, concatBytes(Q, u16(1), pks[0]), 'n = 1');
  bad(0x0110, concatBytes(Q, u16(17), ...more), 'n = 17');
  bad(0x0110, concatBytes(Q, u16(65535)), 'n = 65535 and no members');
  bad(0x0110, concatBytes(Q, u16(3), pks[1], pks[0], pks[2]), 'unsorted members');
  bad(0x0110, concatBytes(Q, u16(3), pks[0], pks[0], pks[2]), 'duplicate member');
  bad(0x0110, put(d, 35, Uint8Array.of(4)), 'member prefix 04');
  bad(0x0110, put(d, 0, Uint8Array.of(5)), 'Q prefix 05');
}
{
  const d = key.get(0x0111);
  bad(0x0111, frost(secpC, 'frost-secp256k1', SECP_N, 1, 3), 't = 1');
  bad(0x0111, put(d, 33, u16(4)), 't > n');
  bad(0x0111, concatBytes(d.subarray(0, 33), u16(65535), u16(65535)), 't = n = 65535 and no body');
  bad(0x0111, frost(secpC, 'frost-secp256k1', SECP_N, 2, 17), 'n = 17');
  bad(0x0111, put(d, 37 + 3 * 33, be(SECP_N, 32)), 'mu = N');
  bad(0x0111, put(d, 37, Uint8Array.of(4)), 'commitment prefix 04');
}
{
  const d = key.get(0x0112);
  bad(0x0112, concatBytes(d.subarray(0, 64), u16(1), d.subarray(66, 130)), 'n = 1');
  bad(0x0112, swap(d, 66, 130, 64), 'unsorted members');
  bad(0x0112, put(d, 66, new Uint8Array(64)), 'identity member');
  bad(0x0112, put(d, 32, be((int(d.subarray(32, 64)) + 1n) % BN.Fp.ORDER, 32)), 'Q off the curve');
}
{
  const d = key.get(0x0113);
  bad(0x0113, frost(bnG1, 'frost-bn254', BN.Fr.ORDER, 1, 3), 't = 1');
  bad(0x0113, put(d, 68 + 3 * 64, be(BN.Fr.ORDER, 32)), 'mu = r');
  bad(0x0113, put(d, 68, new Uint8Array(64)), 'identity commitment');
}
{
  const m = msigMembers;
  const fake = sortM(Array.from({ length: 17 }, (_, i) => mem(0x0101, label(`msig member ${i}`))));
  bad(0x0120, ua.encodeMsig(2, [m[1], m[0], m[2], m[3]]), 'unsorted members');
  bad(0x0120, ua.encodeMsig(2, [m[0], m[0], m[2], m[3]]), 'duplicate member');
  bad(0x0120, ua.encodeMsig(1, []), 'count = 0');
  bad(0x0120, ua.encodeMsig(2, fake), 'count = 17');
  bad(0x0120, concatBytes(u16(1), u16(65535)), 'count = 65535 and no members');
  bad(0x0120, ua.encodeMsig(0, m), 'threshold = 0');
  bad(0x0120, ua.encodeMsig(5, m), 'threshold > total weight');
  bad(0x0120, ua.encodeMsig(2, m.map((x, i) => (i === 0 ? { ...x, weight: 0 } : x))), 'weight = 0');
  bad(0x0120, ua.encodeMsig(1, sortM([mem(0x0140, id(0x0140)), mem(0x0101, id(0x0101))])), 'Zether member');
  bad(0x0120, ua.encodeMsig(1, sortM([mem(0x0120, msigUa), mem(0x0101, id(0x0101))])), 'structure member');
  bad(0x0120, ua.encodeMsig(1, sortM([mem(0x0108, label('unknown member')), mem(0x0101, id(0x0101))])), 'unknown member kind');
  bad(0x0120, ua.encodeMsig(1, sortM([mem(0x0010, label('solana member')), mem(0x0101, id(0x0101))])), 'foreign native member');
  bad(0x0120, msigHedera, 'hedera-native outside a Hedera profile');
  bad(0x0120, ua.encodeMsig(1, sortM([mem(0x0001, id(0x0101)), mem(0x0103, id(0x0103))])), 'native member, derived-space id');
  bad(0x0120, ua.encodeMsig(1, sortM([mem(0x0101, eoa), mem(0x0103, id(0x0103))])), 'derived member, native-space id');
}
{
  const d = key.get(0x0132);
  bad(0x0132, put(d, 0, Uint8Array.of(0x0a)), 'header 0x0a');
  const q0 = Uint8Array.from(d);
  q0[1] = 12289 >> 6;
  q0[2] = ((12289 & 0x3f) << 2) | (q0[2] & 0x03);
  bad(0x0132, q0, 'h_0 = q');
}
bad(0x0000, new Uint8Array(32), 'kind 0', { error: 'UAKindUnknown' });
bad(0x0108, new Uint8Array(32), 'unassigned kind', { error: 'UAKindUnknown' });
bad(0x0001, new Uint8Array(20), 'native kind', { error: 'UAKindNotDerived' });

// --- natives, native space, canonical ids ---
const natives = ua.KINDS.filter((k) => k.native).flatMap((k) => k.lengths.map((n) => {
  const raw = label(`native ${k.name} ${n}`).subarray(0, n);
  const nid = ua.nativeId(k.kind, raw);
  return { kind: k.kind, raw: hex(raw), id: hex(nid), canonical: ua.canonicalId(hex(nid)) };
}));
const nativeInvalid = [[0x0001, new Uint8Array(19), 'UAKeyData'], [0x0010, new Uint8Array(31), 'UAKeyData'],
  [0x0101, new Uint8Array(32), 'UAKindNotNative'], [0x0108, new Uint8Array(32), 'UAKindUnknown']].map(([kind, raw, error]) => {
  try { ua.nativeId(kind, raw); } catch (e) { assert(e.code === error, `nativeId 0x${kind.toString(16)}: ${e.message}`); return { kind, raw: hex(raw), error }; }
  throw new Error(`nativeId 0x${kind.toString(16)} accepted`);
});
const z32 = new Uint8Array(32);
const nativeSpace = [[z32, true], [put(z32, 12, Uint8Array.of(1)), true], [put(z32, 11, Uint8Array.of(1)), false], [label('derived'), false]]
  .map(([nid, v]) => { assert(ua.inNativeSpace(nid) === v, 'inNativeSpace'); return { id: hex(nid), inNativeSpace: v }; });
const eoa40 = hex(eoa.subarray(12));
const derivedId = hex(id(0x0101));
const okId = (input) => ({ input, canonical: ua.canonicalId(input) });
const badId = (input) => {
  try { ua.canonicalId(input); } catch (e) { assert(e.code === 'UAIdFormat', e.message); return { input, error: 'UAIdFormat' }; }
  throw new Error(`canonical id accepted: ${input}`);
};
const canonicalIds = [
  okId(`0x${'0'.repeat(24)}${eoa40.slice(2).toUpperCase()}`), okId(`0x${eoa40.slice(2).toUpperCase()}`), okId(eoa40),
  okId(`0x${derivedId.slice(2).toUpperCase()}`), okId(derivedId),
  badId(eoa40.slice(0, 41)), badId(`0X${eoa40.slice(2)}`), badId(`${derivedId}0`), badId(eoa40.slice(2)),
  badId(`0x${'g'.repeat(40)}`), badId(''), badId(`${eoa40}\n`),
];

// --- messages ---
const digest = label('digest');
const messages = [...[...key.keys(), 0x0120].map((kind) => [kind, 'pop']), ...ua.PURPOSES.map((p) => [0x0100, p])]
  .map(([kind, purpose]) => ({ kind, purpose, purposeTag: hex(ua.purposeTag(purpose)), digest: hex(digest),
    uaMsg: hex(ua.uaMessage(kind, ua.purposeTag(purpose), digest)) }));

// --- structures.json: pop, UAAuth, member ---
const registry = '0x5ca0000000000000000000000000000000000001';
const contexts = {
  A: { chainId: 31337, chainUid: hex(label('chain uid A')), registry },
  B: { chainId: 7622, chainUid: hex(label('chain uid B')), registry },
  C: { chainId: 7622, chainUid: hex(label('chain uid C')), registry },
  D: { chainId: 31337, chainUid: hex(label('chain uid A')), registry: '0x5ca0000000000000000000000000000000000002' },
};
const zero = hex(z32);
const pop = [...Object.keys(contexts).map((c) => ({ context: c, ua: derivedId, authRef: zero })),
  { context: 'A', ua: hex(id(0x0140)), authRef: derivedId }]
  .map((p) => {
    const c = contexts[p.context];
    return { ...p, chainKeyHash: hex(ua.chainKeyHash(c.chainId)), popDigest: hex(ua.popDigest({ ...c, ua: p.ua, authRef: p.authRef })) };
  });
assert(new Set(pop.map((p) => p.popDigest)).size === pop.length, 'popDigest must separate chain id, chain uid, registry, ua and authRef');
const memberTag = ua.purposeTag('member');
const uaAuth = [['A', 1], ['A', 2], ['C', 1]].map(([context, generation]) => {
  const domain = { generation, ...contexts[context] };
  return { context, generation, domainSeparator: hex(ua.uaAuthDomainSeparator(domain)), ua: hex(eoa), purpose: 'member',
    purposeTag: hex(memberTag), digest: hex(digest), uaAuthDigest: hex(ua.uaAuthDigest(domain, eoa, memberTag, digest)) };
});
assert(new Set(uaAuth.map((a) => a.uaAuthDigest)).size === uaAuth.length, 'UAAuth must separate generation and chain uid');
const msigMsg = ua.uaMessage(0x0120, memberTag, digest);
const member = [{ structureUa: hex(msigUa), uaMsg: hex(msigMsg), memberDigest: hex(ua.memberDigest(msigUa, msigMsg)) }];

// --- write ---
const kinds = ua.KINDS.map((k) => ({
  kind: k.kind, name: k.name, native: k.native, lengths: k.lengths,
  tag: k.native ? null : ua.kindTagString(k.kind), TAG: k.native ? null : hex(ua.TAG(k.kind)), group: k.group,
  signing: ua.isSigningKind(k.kind), zether: ua.isZetherKind(k.kind),
  member: ua.isMemberKind(k.kind, false), memberHedera: ua.isMemberKind(k.kind, true),
}));
const constants = { MSG_TAG: hex(ua.MSG_TAG), POP_TAG: hex(ua.POP_TAG), DOMAIN_TYPEHASH: hex(ua.DOMAIN_TYPEHASH),
  UAAUTH_TYPEHASH: hex(ua.UAAUTH_TYPEHASH), NAME_HASH: hex(ua.NAME_HASH) };
const groups = ua.GROUPS.map((g) => ({ group: g, tag: ua.groupTagString(g), GROUP: hex(ua.GROUP(g)) }));
const purposes = ua.PURPOSES.map((p) => ({ purpose: p, tag: `scaas.ua.purpose.${p}.v1`, purposeTag: hex(ua.purposeTag(p)) }));
const note = 'Generated by clients/clientkeys/scripts/ua-vectors.mjs (src/ua.js on @noble/curves 2.4.0); never edit by hand. '
  + 'Solidity UAKinds, clientkeys ua.js, clients/scaas-ua, clients/ua-py, clients/ua-go and clients/ua-cs must reproduce every '
  + 'field and refuse every invalid row with its error (the reason is a label). MuSig2 / FROST rows are valid layouts of valid '
  + 'points, not real groups.';
mkdirSync(OUT, { recursive: true });
const write = (name, obj) => writeFileSync(join(OUT, name), `${JSON.stringify(obj, null, 2)}\n`);
write('kinds.json', { note, version: 1, constants, kinds, groups, purposes, valid, invalid, natives, nativeInvalid, nativeSpace,
  messages, canonicalIds });
write('structures.json', { note, version: 1, contexts, pop, uaAuth, member });
console.log(`kinds.json: ${valid.length} valid, ${invalid.length} invalid; structures.json written to ${OUT}`);
```

- [ ] **Step 3: Generate.** `cd clients/clientkeys && ../../scripts/capped node scripts/ua-vectors.mjs` — prints the
  counts; expected 23 valid rows (two share a key with another kind) and 140 invalid rows. If a `bad(...)` line throws "accepted" or the wrong code, the
  library (not the row) is wrong unless the row contradicts §"Validation rules"; fix and rerun. If a noble call has another
  name in 2.4.0 (`Fp2.fromBigTuple`, `Point.Fn`, `toBytes`), use the 2.4.0 name with the same meaning and report it.

- [ ] **Step 4: The JS test.** Create `clients/clientkeys/test/ua.test.js`:

```js
// The UA identity layer (src/ua.js) against smartcontracts/vectors/ua/: the generator reproduces both files byte for byte,
// every row holds through the public API, and pq.js (P6a) agrees on the PQ kinds.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import * as ua from '../src/ua.js';
import { PQ_KINDS, uaId, kindTag } from '../src/pq.js';
import { hex, fromHex } from '../src/bytes.js';

const dir = new URL('../../../smartcontracts/vectors/ua/', import.meta.url);
const K = JSON.parse(readFileSync(new URL('kinds.json', dir)));
const S = JSON.parse(readFileSync(new URL('structures.json', dir)));

test('the generator reproduces kinds.json and structures.json byte for byte', () => {
  const out = mkdtempSync(join(tmpdir(), 'ua-vectors-'));
  try {
    const r = spawnSync(process.execPath, [fileURLToPath(new URL('../scripts/ua-vectors.mjs', import.meta.url)), out], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    for (const f of ['kinds.json', 'structures.json']) {
      assert.equal(readFileSync(join(out, f), 'utf8'), readFileSync(new URL(f, dir), 'utf8'), f);
    }
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

test('valid rows derive, invalid rows fail with their code', () => {
  for (const r of K.valid) {
    assert.equal(hex(ua.deriveUA(r.kind, fromHex(r.keyData), { hederaNative: r.hederaNative })), r.ua, r.name);
    const h = ua.keyHashOf(r.kind, fromHex(r.keyData));
    assert.equal(h && hex(h), r.keyHash, r.name);
  }
  for (const r of K.invalid) {
    assert.throws(() => ua.validateKeyData(r.kind, fromHex(r.keyData), { hederaNative: r.hederaNative }),
      (e) => e instanceof ua.UAError && e.code === r.error, `${r.kind} ${r.reason}`);
  }
});

test('digests: popDigest, UAAuth, member', () => {
  for (const p of S.pop) {
    const c = S.contexts[p.context];
    assert.equal(hex(ua.popDigest({ ...c, ua: p.ua, authRef: p.authRef })), p.popDigest);
  }
  for (const a of S.uaAuth) {
    const domain = { generation: a.generation, ...S.contexts[a.context] };
    assert.equal(hex(ua.uaAuthDigest(domain, a.ua, a.purposeTag, a.digest)), a.uaAuthDigest);
  }
  for (const m of S.member) assert.equal(hex(ua.memberDigest(m.structureUa, m.uaMsg)), m.memberDigest);
});

test('pq.js and ua.js agree on the PQ kinds', () => {
  for (const [name, { kind }] of Object.entries(PQ_KINDS)) {
    assert.equal(hex(kindTag(name)), hex(ua.TAG(kind)), name);
    const r = K.valid.find((v) => v.kind === kind);
    assert.equal(hex(uaId(name, fromHex(r.keyData))), r.ua, name);
  }
});
```

- [ ] **Step 5: Test.** `cd clients/clientkeys && ../../scripts/capped npm test` — 79 tests, 77 pass, 2 skipped (75 / 73 / 2
  before: +4).

- [ ] **Step 6: Commit.**

```bash
/usr/bin/git add clients/clientkeys/src/ua.js clients/clientkeys/scripts/ua-vectors.mjs clients/clientkeys/test/ua.test.js \
  smartcontracts/vectors/ua/kinds.json smartcontracts/vectors/ua/structures.json
/usr/bin/git commit -m "UA-1 T1: clientkeys ua.js (UA identity layer), vector generator, kinds.json and structures.json" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 2: Rust `scaas-ua` crate (the independent cross-check)

**Files:**
- Create: `clients/scaas-ua/Cargo.toml`, `clients/scaas-ua/.gitignore`, `clients/scaas-ua/src/lib.rs`,
  `clients/scaas-ua/src/keydata.rs`, `clients/scaas-ua/tests/vectors.rs`, `clients/scaas-ua/Cargo.lock` (generated)
- Modify: `.github/workflows/ci.yml` (job `scaas-ua`)

**Interfaces:**
- Consumes: `smartcontracts/vectors/ua/kinds.json`, `structures.json` (Task 1).
- Produces: crate `scaas_ua` — `UAError` (`code()`), `Kind`, `KINDS`, `GROUPS`, `PURPOSES`, `kind_info`, `is_native`,
  `is_zether`, `is_signing`, `is_member`, `kind_tag_string`, `tag`, `group_tag_string`, `group_tag`, `msg_tag`,
  `purpose_tag`, `keccak256`, `ua_of`, `in_native_space`, `derive_ua`, `native_id`, `key_hash_of`, `validate_key_data`,
  `ua_message`, `chain_key_hash`, `pop_digest`, `Domain`, `ua_auth_domain_separator`, `ua_auth_digest`, `member_digest`,
  `canonical_id`, `encode_msig`. The node and zether-prover adopt it in their own streams (open question).

- [ ] **Step 1: Manifest.** Create `clients/scaas-ua/Cargo.toml`:

```toml
[package]
name = "scaas-ua"
version = "0.1.0"
edition = "2021"
rust-version = "1.90"
publish = false
description = "SCaaS Universal Account identity layer: kind table, ids, keyHash, ua_msg, popDigest, UAAuth, key-data validation. UNAUDITED."

[dependencies]
sha3 = "0.10"
k256 = { version = "0.13", default-features = false, features = ["arithmetic"] }
p256 = { version = "0.13", default-features = false, features = ["arithmetic"] }
curve25519-dalek = "4"
ark-ff = "0.5"
ark-ec = "0.5"
ark-bn254 = "0.5"
ark-bls12-381 = "0.5"

[dev-dependencies]
hex = "0.4"
serde_json = "1"

# arkworks subgroup checks crawl unoptimised
[profile.dev.package."*"]
opt-level = 3
```

  and `clients/scaas-ua/.gitignore` with the single line `/target`.

- [ ] **Step 2: The identity layer.** Create `clients/scaas-ua/src/lib.rs`:

```rust
//! SCaaS Universal Account identity layer (accounts.md §1.3–§1.6): the kind table, ids, keyHash, purpose tags, `ua_msg`,
//! `popDigest`, the registry's `UAAuth` digest, member digests, canonical ids and key-data validation. The same rules live
//! in Solidity (`UAKinds.sol`), JS (clientkeys `ua.js`), Python, Go and C#; `smartcontracts/vectors/ua/` pins all six.
//! The curve code here (k256, p256, curve25519-dalek, arkworks) is independent of the JS generator's (noble): the vectors
//! are accepted only when both agree. UNAUDITED.
use sha3::{Digest, Keccak256};

mod keydata;
pub use keydata::validate_key_data;

/// An error whose [`UAError::code`] every implementation and the vector files share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UAError {
    KeyData(&'static str),
    IdInNativeSpace,
    KindUnknown(u16),
    KindNotDerived(u16),
    KindNotNative(u16),
    IdFormat,
    PurposeUnknown,
}

impl UAError {
    pub fn code(&self) -> &'static str {
        match self {
            UAError::KeyData(_) => "UAKeyData",
            UAError::IdInNativeSpace => "UAIdInNativeSpace",
            UAError::KindUnknown(_) => "UAKindUnknown",
            UAError::KindNotDerived(_) => "UAKindNotDerived",
            UAError::KindNotNative(_) => "UAKindNotNative",
            UAError::IdFormat => "UAIdFormat",
            UAError::PurposeUnknown => "UAPurposeUnknown",
        }
    }
}

impl core::fmt::Display for UAError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            UAError::KeyData(reason) => write!(f, "UAKeyData: {reason}"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for UAError {}

pub type Result<T> = core::result::Result<T, UAError>;

/// One row of the kind table; `lengths` empty = variable-length key data.
#[derive(Debug)]
pub struct Kind {
    pub kind: u16,
    pub name: &'static str,
    pub native: bool,
    pub lengths: &'static [usize],
    pub group: Option<&'static str>,
}

const fn native(kind: u16, name: &'static str, lengths: &'static [usize]) -> Kind {
    Kind { kind, name, native: true, lengths, group: None }
}
const fn derived(kind: u16, name: &'static str, lengths: &'static [usize], group: Option<&'static str>) -> Kind {
    Kind { kind, name, native: false, lengths, group }
}

pub const KINDS: &[Kind] = &[
    native(0x0001, "evm-eoa", &[20]),
    native(0x0002, "evm-contract", &[20]),
    native(0x0003, "hedera-native", &[20]),
    native(0x0010, "solana-ed25519", &[32]),
    native(0x0011, "stellar-account", &[32]),
    native(0x0012, "soroban-contract", &[32]),
    native(0x0013, "aptos-account", &[32]),
    native(0x0014, "sui-address", &[32]),
    native(0x0015, "cosmos-account", &[20, 32]),
    native(0x0016, "ton-wallet", &[32]),
    derived(0x0100, "webauthn-p256", &[96], Some("p256")),
    derived(0x0101, "p256", &[64], Some("p256")),
    derived(0x0102, "ed25519", &[32], Some("ed25519")),
    derived(0x0103, "bip340", &[32], Some("secp256k1")),
    derived(0x0104, "schnorr-bn254", &[64], Some("bn254-g1")),
    derived(0x0105, "schnorr-bls12381", &[128], Some("bls12381-g1")),
    derived(0x0106, "bls12381-minsig", &[256], Some("bls12381-g2")),
    derived(0x0107, "bls-bn254-minsig", &[128], Some("bn254-g2")),
    derived(0x0110, "musig2-secp256k1", &[], Some("secp256k1")),
    derived(0x0111, "frost-secp256k1", &[], Some("secp256k1")),
    derived(0x0112, "musig2-bn254", &[], Some("bn254-g1")),
    derived(0x0113, "frost-bn254", &[], Some("bn254-g1")),
    derived(0x0120, "msig", &[], None),
    derived(0x0130, "mldsa44", &[1312], Some("mldsa44")),
    derived(0x0131, "mldsa65", &[1952], Some("mldsa65")),
    derived(0x0132, "fndsa512", &[897], Some("fndsa512")),
    derived(0x0133, "slhdsa128s", &[32], Some("slhdsa128s")),
    derived(0x0140, "zether-bn254", &[64], Some("bn254-g1")),
    derived(0x0141, "zether-bls12381", &[128], Some("bls12381-g1")),
    derived(0x0142, "pqz-mlwe", &[16384], Some("pqz-mlwe")),
];

pub const GROUPS: &[&str] = &[
    "p256", "ed25519", "secp256k1", "bn254-g1", "bls12381-g1", "bls12381-g2", "bn254-g2", "mldsa44", "mldsa65", "fndsa512",
    "slhdsa128s", "pqz-mlwe",
];

pub const PURPOSES: &[&str] = &[
    "pop", "authref", "metatx", "metatx-cancel", "member", "zether-auth", "zether-owner", "keyop", "receiver-fee", "vp",
    "vc-anchor",
];

pub const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)";
pub const UAAUTH_TYPE: &str = "UAAuth(bytes32 ua,bytes32 purpose,bytes32 digest)";
pub const REGISTRY_NAME: &str = "SCaaS UARegistry";

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    keccak(&[data])
}

pub(crate) fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn kind_info(kind: u16) -> Result<&'static Kind> {
    KINDS.iter().find(|k| k.kind == kind).ok_or(UAError::KindUnknown(kind))
}

fn derived_kind(kind: u16) -> Result<&'static Kind> {
    let k = kind_info(kind)?;
    if k.native {
        return Err(UAError::KindNotDerived(kind));
    }
    Ok(k)
}

fn single_signing(kind: u16) -> bool {
    matches!(kind, 0x0100..=0x0107 | 0x0110..=0x0113 | 0x0130..=0x0133)
}
pub fn is_native(kind: u16) -> bool {
    KINDS.iter().any(|k| k.kind == kind && k.native)
}
pub fn is_zether(kind: u16) -> bool {
    matches!(kind, 0x0140..=0x0142)
}
pub fn is_signing(kind: u16) -> bool {
    kind == 0x0120 || single_signing(kind)
}
pub fn is_member(kind: u16, hedera_native: bool) -> bool {
    single_signing(kind) || kind == 0x0001 || kind == 0x0002 || (hedera_native && kind == 0x0003)
}

pub fn kind_tag_string(kind: u16) -> Result<String> {
    Ok(format!("scaas.ua.{}.v1", derived_kind(kind)?.name))
}
pub fn tag(kind: u16) -> Result<[u8; 32]> {
    Ok(keccak256(kind_tag_string(kind)?.as_bytes()))
}
pub fn group_tag_string(group: &str) -> Option<String> {
    GROUPS.contains(&group).then(|| format!("scaas.ua.group.{group}.v1"))
}
pub fn group_tag(group: &str) -> Option<[u8; 32]> {
    group_tag_string(group).map(|s| keccak256(s.as_bytes()))
}
pub fn msg_tag() -> [u8; 32] {
    keccak256(b"scaas.ua.msg.v1")
}
pub fn purpose_tag(purpose: &str) -> Result<[u8; 32]> {
    if !PURPOSES.contains(&purpose) {
        return Err(UAError::PurposeUnknown);
    }
    Ok(keccak256(format!("scaas.ua.purpose.{purpose}.v1").as_bytes()))
}

/// `keccak256(TAG(kind) ‖ keyData)`; no validation (see [`derive_ua`]).
pub fn ua_of(kind: u16, key_data: &[u8]) -> Result<[u8; 32]> {
    Ok(keccak(&[&tag(kind)?, key_data]))
}
pub fn in_native_space(id: &[u8; 32]) -> bool {
    id[..12].iter().all(|b| *b == 0)
}
/// Validate, derive, refuse an id whose top 96 bits are zero (CTR-UA-03).
pub fn derive_ua(kind: u16, key_data: &[u8], hedera_native: bool) -> Result<[u8; 32]> {
    validate_key_data(kind, key_data, hedera_native)?;
    let ua = ua_of(kind, key_data)?;
    if in_native_space(&ua) {
        return Err(UAError::IdInNativeSpace);
    }
    Ok(ua)
}
/// A native id left-padded to 32 bytes.
pub fn native_id(kind: u16, raw: &[u8]) -> Result<[u8; 32]> {
    let k = kind_info(kind)?;
    if !k.native {
        return Err(UAError::KindNotNative(kind));
    }
    if !k.lengths.contains(&raw.len()) {
        return Err(UAError::KeyData("length"));
    }
    let mut id = [0u8; 32];
    id[32 - raw.len()..].copy_from_slice(raw);
    Ok(id)
}
/// `keccak256(GROUP(g) ‖ canonical pubkey)`, `None` for structures. Call on validated key data.
pub fn key_hash_of(kind: u16, key_data: &[u8]) -> Result<Option<[u8; 32]>> {
    let k = derived_kind(kind)?;
    let Some(group) = k.group else { return Ok(None) };
    let (lo, hi) = match kind {
        0x0100 | 0x0101 => (0, 32),
        0x0110 | 0x0111 => (1, 33),
        0x0112 | 0x0113 => (0, 64),
        _ => (0, key_data.len()),
    };
    let pubkey = key_data.get(lo..hi).ok_or(UAError::KeyData("length"))?;
    Ok(Some(keccak(&[&group_tag(group).expect("table group"), pubkey])))
}

pub fn ua_message(kind: u16, purpose: &[u8; 32], digest: &[u8; 32]) -> Result<[u8; 32]> {
    Ok(keccak(&[&msg_tag(), &tag(kind)?, purpose, digest]))
}
pub fn chain_key_hash(chain_id: u64) -> [u8; 32] {
    keccak256(format!("evm:{chain_id}").as_bytes())
}
fn word(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}
fn address_word(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}
/// `pop_digest` (CTR-UA-07).
pub fn pop_digest(chain_id: u64, chain_uid: &[u8; 32], registry: &[u8; 20], ua: &[u8; 32], auth_ref: &[u8; 32]) -> [u8; 32] {
    keccak(&[&purpose_tag("pop").expect("pop"), &chain_key_hash(chain_id), chain_uid, &address_word(registry), ua, auth_ref])
}

/// The registry's EIP-712 domain: `("SCaaS UARegistry", "<generation>", chainId, registry, salt = chainUid)`.
pub struct Domain {
    pub generation: u32,
    pub chain_id: u64,
    pub registry: [u8; 20],
    pub chain_uid: [u8; 32],
}
pub fn ua_auth_domain_separator(d: &Domain) -> [u8; 32] {
    keccak(&[
        &keccak256(DOMAIN_TYPE.as_bytes()),
        &keccak256(REGISTRY_NAME.as_bytes()),
        &keccak256(d.generation.to_string().as_bytes()),
        &word(d.chain_id),
        &address_word(&d.registry),
        &d.chain_uid,
    ])
}
/// EIP-712 digest of `UAAuth(ua, purpose, digest)`: what native signers behind the registry sign.
pub fn ua_auth_digest(d: &Domain, ua: &[u8; 32], purpose: &[u8; 32], digest: &[u8; 32]) -> [u8; 32] {
    let s = keccak(&[&keccak256(UAAUTH_TYPE.as_bytes()), ua, purpose, digest]);
    keccak(&[&[0x19, 0x01], &ua_auth_domain_separator(d), &s])
}
pub fn member_digest(structure_ua: &[u8; 32], ua_msg: &[u8; 32]) -> [u8; 32] {
    keccak(&[structure_ua, ua_msg])
}

/// Lower-case hex; a 32-byte id with the top 96 bits zero is written as its 20-byte native id (CTR-UA-03).
pub fn canonical_id(text: &str) -> Result<String> {
    let h = text.strip_prefix("0x").ok_or(UAError::IdFormat)?;
    if !(h.len() == 40 || h.len() == 64) || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(UAError::IdFormat);
    }
    let h = h.to_ascii_lowercase();
    Ok(if h.len() == 64 && h.as_bytes()[..24].iter().all(|c| *c == b'0') {
        format!("0x{}", &h[24..])
    } else {
        format!("0x{h}")
    })
}

/// `u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight)`.
pub fn encode_msig(threshold: u16, members: &[(u16, [u8; 32], u16)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 36 * members.len());
    out.extend_from_slice(&threshold.to_be_bytes());
    out.extend_from_slice(&(members.len() as u16).to_be_bytes());
    for (kind, id, weight) in members {
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(id);
        out.extend_from_slice(&weight.to_be_bytes());
    }
    out
}
```

- [ ] **Step 3: Validation.** Create `clients/scaas-ua/src/keydata.rs`:

```rust
//! Key-data validation (accounts.md §1.6 "Validation at registration"): the unique canonical encoding of a valid key or
//! structure, else `UAError::KeyData`. Never panics: every length is checked before it is sliced.
use crate::{in_native_space, is_member, is_native, kind_info, Result, UAError};
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ff::{BigInteger, PrimeField, Zero};

const SECP_N: [u8; 32] = hex32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const BN_R: [u8; 32] = hex32("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}
const fn nibble(c: u8) -> u8 {
    if c <= b'9' { c - b'0' } else { c - b'a' + 10 }
}

fn need(ok: bool, reason: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(UAError::KeyData(reason)) }
}

/// Big-endian bytes (exactly the field's width) → the element, `None` unless canonical (< modulus).
fn fe<F: PrimeField>(b: &[u8]) -> Option<F> {
    let f = F::from_be_bytes_mod_order(b);
    (f.into_bigint().to_bytes_be() == b).then_some(f)
}

fn on_curve_in_subgroup<P: SWCurveConfig>(p: &Affine<P>) -> Result<()> {
    need(p.is_on_curve(), "curve")?;
    need(p.is_in_correct_subgroup_assuming_on_curve(), "subgroup")
}

fn secp_compressed(b: &[u8]) -> Result<()> {
    need(b.len() == 33 && (b[0] == 2 || b[0] == 3), "prefix")?;
    need(k256::PublicKey::from_sec1_bytes(b).is_ok(), "curve")
}

fn p256_point(xy: &[u8]) -> Result<()> {
    let mut sec1 = [0u8; 65];
    sec1[0] = 4;
    sec1[1..].copy_from_slice(xy);
    need(p256::PublicKey::from_sec1_bytes(&sec1).is_ok(), "curve")
}

fn ed25519_key(b: &[u8]) -> Result<()> {
    let enc: [u8; 32] = b.try_into().map_err(|_| UAError::KeyData("length"))?;
    let p = curve25519_dalek::edwards::CompressedEdwardsY(enc).decompress().ok_or(UAError::KeyData("curve"))?;
    // dalek accepts y ≥ p and a negative zero x; the re-encoding is canonical, so compare
    need(p.compress().to_bytes() == enc, "canonical")?;
    need(!p.is_small_order(), "small-order")
}

fn bn_g1(b: &[u8]) -> Result<()> {
    use ark_bn254::{Fq, G1Affine};
    let (Some(x), Some(y)) = (fe::<Fq>(&b[..32]), fe::<Fq>(&b[32..64])) else { return Err(UAError::KeyData("range")) };
    need(!(x.is_zero() && y.is_zero()), "identity")?;
    need(G1Affine::new_unchecked(x, y).is_on_curve(), "curve")
}

fn bn_g2(b: &[u8]) -> Result<()> {
    use ark_bn254::{Fq, Fq2, G2Affine};
    let w: Vec<Option<Fq>> = (0..4).map(|i| fe::<Fq>(&b[32 * i..32 * i + 32])).collect();
    let (Some(xi), Some(xr), Some(yi), Some(yr)) = (w[0], w[1], w[2], w[3]) else { return Err(UAError::KeyData("range")) };
    need(!(xi.is_zero() && xr.is_zero() && yi.is_zero() && yr.is_zero()), "identity")?;
    // EIP-197 order: imaginary part first
    on_curve_in_subgroup(&G2Affine::new_unchecked(Fq2::new(xr, xi), Fq2::new(yr, yi)))
}

fn bls_fp(b: &[u8]) -> Result<ark_bls12_381::Fq> {
    need(b[..16].iter().all(|x| *x == 0), "padding")?;
    fe::<ark_bls12_381::Fq>(&b[16..64]).ok_or(UAError::KeyData("range"))
}

fn bls_g1(b: &[u8]) -> Result<()> {
    let (x, y) = (bls_fp(&b[..64])?, bls_fp(&b[64..128])?);
    need(!(x.is_zero() && y.is_zero()), "identity")?;
    on_curve_in_subgroup(&ark_bls12_381::G1Affine::new_unchecked(x, y))
}

fn bls_g2(b: &[u8]) -> Result<()> {
    use ark_bls12_381::{Fq2, G2Affine};
    let (x0, x1, y0, y1) = (bls_fp(&b[..64])?, bls_fp(&b[64..128])?, bls_fp(&b[128..192])?, bls_fp(&b[192..256])?);
    need(!(x0.is_zero() && x1.is_zero() && y0.is_zero() && y1.is_zero()), "identity")?;
    // EIP-2537 order: c0 first
    on_curve_in_subgroup(&G2Affine::new_unchecked(Fq2::new(x0, x1), Fq2::new(y0, y1)))
}

fn u16_at(d: &[u8], o: usize) -> Result<usize> {
    d.get(o..o + 2).map(|s| ((s[0] as usize) << 8) | s[1] as usize).ok_or(UAError::KeyData("length"))
}

/// `Q ‖ u16 n ‖ n × P_i`, 2 ≤ n ≤ 16, P_i strictly increasing.
fn musig2(d: &[u8], point: fn(&[u8]) -> Result<()>, size: usize) -> Result<()> {
    let n = u16_at(d, size)?;
    need((2..=16).contains(&n), "n")?;
    need(d.len() == size + 2 + n * size, "length")?;
    point(&d[..size])?;
    for i in 0..n {
        let o = size + 2 + i * size;
        point(&d[o..o + size])?;
        if i > 0 {
            need(d[o - size..o] < d[o..o + size], "order")?;
        }
    }
    Ok(())
}

/// `Y ‖ u16 t ‖ u16 n ‖ n × (t × C_ik ‖ R_i ‖ μ_i)`, 2 ≤ t ≤ n ≤ 16, μ_i < order.
fn frost(d: &[u8], point: fn(&[u8]) -> Result<()>, size: usize, order: &[u8; 32]) -> Result<()> {
    let (t, n) = (u16_at(d, size)?, u16_at(d, size + 2)?);
    need(t >= 2 && t <= n && n <= 16, "threshold")?;
    let per = (t + 1) * size + 32;
    need(d.len() == size + 4 + n * per, "length")?;
    point(&d[..size])?;
    for i in 0..n {
        let o = size + 4 + i * per;
        for j in 0..=t {
            point(&d[o + j * size..o + (j + 1) * size])?; // t commitments, then R_i
        }
        need(d[o + (t + 1) * size..o + per] < order[..], "scalar")?;
    }
    Ok(())
}

/// `u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight)` (CTR-UA-09).
fn msig(d: &[u8], hedera_native: bool) -> Result<()> {
    let (threshold, count) = (u16_at(d, 0)?, u16_at(d, 2)?);
    need((1..=16).contains(&count), "count")?;
    need(d.len() == 4 + 36 * count, "length")?;
    let mut total = 0usize;
    for i in 0..count {
        let o = 4 + 36 * i;
        let kind = u16_at(d, o)? as u16;
        let id: &[u8; 32] = d[o + 2..o + 34].try_into().expect("32 bytes");
        let weight = u16_at(d, o + 34)?;
        need(is_member(kind, hedera_native), "member-kind")?;
        need(weight >= 1, "weight")?;
        need(is_native(kind) == in_native_space(id), "member-id")?;
        if i > 0 {
            need(d[o - 34..o - 2] < d[o + 2..o + 34], "order")?;
        }
        total += weight;
    }
    need(threshold >= 1 && threshold <= total, "threshold")
}

/// `0x09 ‖ 512 × 14-bit h_i` (big-endian bit packing), each `h_i < 12289`.
fn fndsa(d: &[u8]) -> Result<()> {
    need(d[0] == 0x09, "header")?;
    for i in 0..512 {
        let mut v = 0u32;
        for j in 0..14 {
            let k = i * 14 + j;
            v = (v << 1) | ((d[1 + k / 8] >> (7 - k % 8)) & 1) as u32;
        }
        need(v < 12289, "coefficient")?;
    }
    Ok(())
}

/// `Ok` iff `key_data` is the unique canonical encoding of a valid key or structure of `kind`.
pub fn validate_key_data(kind: u16, d: &[u8], hedera_native: bool) -> Result<()> {
    let k = kind_info(kind)?;
    if k.native {
        return Err(UAError::KindNotDerived(kind));
    }
    if !k.lengths.is_empty() {
        need(k.lengths.contains(&d.len()), "length")?;
    }
    match kind {
        0x0100 => p256_point(&d[..64]),
        0x0101 => p256_point(d),
        0x0102 => ed25519_key(d),
        0x0103 => secp_compressed(&[&[2u8][..], d].concat()),
        0x0104 | 0x0140 => bn_g1(d),
        0x0105 | 0x0141 => bls_g1(d),
        0x0106 => bls_g2(d),
        0x0107 => bn_g2(d),
        0x0110 => musig2(d, secp_compressed, 33),
        0x0111 => frost(d, secp_compressed, 33, &SECP_N),
        0x0112 => musig2(d, bn_g1, 64),
        0x0113 => frost(d, bn_g1, 64, &BN_R),
        0x0120 => msig(d, hedera_native),
        0x0132 => fndsa(d),
        _ => Ok(()), // mldsa44/65, slhdsa128s, pqz-mlwe: the length is the whole check
    }
}
```

- [ ] **Step 4: Vector tests.** Create `clients/scaas-ua/tests/vectors.rs`:

```rust
//! scaas-ua against smartcontracts/vectors/ua/ (generated by clientkeys scripts/ua-vectors.mjs from noble): an independent
//! implementation must reproduce every field and refuse every invalid row with its error.
use scaas_ua::*;
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!("{}/../../smartcontracts/vectors/ua/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}
fn b20(v: &Value) -> [u8; 20] {
    bytes(v).try_into().unwrap()
}
fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}
fn kind(v: &Value) -> u16 {
    v.as_u64().unwrap() as u16
}
fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array().unwrap()
}

#[test]
fn table_groups_purposes_constants() {
    let k = load("kinds.json");
    assert_eq!(arr(&k, "kinds").len(), KINDS.len());
    for r in arr(&k, "kinds") {
        let n = kind(&r["kind"]);
        let info = kind_info(n).unwrap();
        assert_eq!(info.name, r["name"]);
        assert_eq!(info.native, r["native"]);
        let lengths: Vec<usize> = arr(r, "lengths").iter().map(|x| x.as_u64().unwrap() as usize).collect();
        assert_eq!(info.lengths, &lengths[..], "{}", info.name);
        assert_eq!(info.group, r["group"].as_str(), "{}", info.name);
        assert_eq!(is_signing(n), r["signing"], "{}", info.name);
        assert_eq!(is_zether(n), r["zether"], "{}", info.name);
        assert_eq!(is_member(n, false), r["member"], "{}", info.name);
        assert_eq!(is_member(n, true), r["memberHedera"], "{}", info.name);
        if info.native {
            assert_eq!(tag(n), Err(UAError::KindNotDerived(n)));
        } else {
            assert_eq!(kind_tag_string(n).unwrap(), r["tag"]);
            assert_eq!(hx(&tag(n).unwrap()), r["TAG"]);
        }
    }
    for r in arr(&k, "groups") {
        let g = r["group"].as_str().unwrap();
        assert_eq!(group_tag_string(g).unwrap(), r["tag"]);
        assert_eq!(hx(&group_tag(g).unwrap()), r["GROUP"]);
    }
    assert_eq!(arr(&k, "purposes").len(), PURPOSES.len());
    for r in arr(&k, "purposes") {
        assert_eq!(hx(&purpose_tag(r["purpose"].as_str().unwrap()).unwrap()), r["purposeTag"]);
    }
    let c = &k["constants"];
    assert_eq!(hx(&msg_tag()), c["MSG_TAG"]);
    assert_eq!(hx(&purpose_tag("pop").unwrap()), c["POP_TAG"]);
    assert_eq!(hx(&keccak256(DOMAIN_TYPE.as_bytes())), c["DOMAIN_TYPEHASH"]);
    assert_eq!(hx(&keccak256(UAAUTH_TYPE.as_bytes())), c["UAAUTH_TYPEHASH"]);
    assert_eq!(hx(&keccak256(REGISTRY_NAME.as_bytes())), c["NAME_HASH"]);
}

#[test]
fn valid_rows() {
    let k = load("kinds.json");
    for r in arr(&k, "valid") {
        let (n, d, hn) = (kind(&r["kind"]), bytes(&r["keyData"]), r["hederaNative"].as_bool().unwrap());
        let ua = derive_ua(n, &d, hn).unwrap_or_else(|e| panic!("{}: {e}", r["name"]));
        assert_eq!(hx(&ua), r["ua"], "{}", r["name"]);
        assert_eq!(key_hash_of(n, &d).unwrap().map(|h| hx(&h)), r["keyHash"].as_str().map(String::from), "{}", r["name"]);
    }
}

#[test]
fn invalid_rows() {
    let k = load("kinds.json");
    for r in arr(&k, "invalid") {
        let (n, d, hn) = (kind(&r["kind"]), bytes(&r["keyData"]), r["hederaNative"].as_bool().unwrap());
        let e = validate_key_data(n, &d, hn).expect_err(&format!("{n:#06x} {} accepted", r["reason"]));
        assert_eq!(e.code(), r["error"], "{n:#06x} {}", r["reason"]);
    }
}

#[test]
fn natives_native_space_canonical_ids() {
    let k = load("kinds.json");
    for r in arr(&k, "natives") {
        let id = native_id(kind(&r["kind"]), &bytes(&r["raw"])).unwrap();
        assert_eq!(hx(&id), r["id"]);
        assert_eq!(canonical_id(&hx(&id)).unwrap(), r["canonical"]);
    }
    for r in arr(&k, "nativeInvalid") {
        assert_eq!(native_id(kind(&r["kind"]), &bytes(&r["raw"])).unwrap_err().code(), r["error"]);
    }
    for r in arr(&k, "nativeSpace") {
        assert_eq!(in_native_space(&b32(&r["id"])), r["inNativeSpace"]);
    }
    for r in arr(&k, "canonicalIds") {
        let got = canonical_id(r["input"].as_str().unwrap());
        match r.get("canonical") {
            Some(c) => assert_eq!(got.unwrap(), *c),
            None => assert_eq!(got.unwrap_err().code(), r["error"]),
        }
    }
}

#[test]
fn messages() {
    let k = load("kinds.json");
    for r in arr(&k, "messages") {
        let p = purpose_tag(r["purpose"].as_str().unwrap()).unwrap();
        assert_eq!(hx(&p), r["purposeTag"]);
        assert_eq!(hx(&ua_message(kind(&r["kind"]), &p, &b32(&r["digest"])).unwrap()), r["uaMsg"]);
    }
}

#[test]
fn structures() {
    let s = load("structures.json");
    let ctx = |name: &str| &s["contexts"][name];
    for p in arr(&s, "pop") {
        let c = ctx(p["context"].as_str().unwrap());
        let chain_id = c["chainId"].as_u64().unwrap();
        assert_eq!(hx(&chain_key_hash(chain_id)), p["chainKeyHash"]);
        let got = pop_digest(chain_id, &b32(&c["chainUid"]), &b20(&c["registry"]), &b32(&p["ua"]), &b32(&p["authRef"]));
        assert_eq!(hx(&got), p["popDigest"]);
    }
    for a in arr(&s, "uaAuth") {
        let c = ctx(a["context"].as_str().unwrap());
        let d = Domain {
            generation: a["generation"].as_u64().unwrap() as u32,
            chain_id: c["chainId"].as_u64().unwrap(),
            registry: b20(&c["registry"]),
            chain_uid: b32(&c["chainUid"]),
        };
        assert_eq!(hx(&ua_auth_domain_separator(&d)), a["domainSeparator"]);
        assert_eq!(hx(&ua_auth_digest(&d, &b32(&a["ua"]), &b32(&a["purposeTag"]), &b32(&a["digest"]))), a["uaAuthDigest"]);
    }
    for m in arr(&s, "member") {
        assert_eq!(hx(&member_digest(&b32(&m["structureUa"]), &b32(&m["uaMsg"]))), m["memberDigest"]);
    }
}
```

- [ ] **Step 5: Test.** `cd clients/scaas-ua && ../../scripts/capped cargo test` — 6 tests pass, no warnings;
  `../../scripts/capped cargo clippy --all-targets -- -D warnings` clean. A failing row means the two implementations
  disagree: find which one is wrong against §"Validation rules" (never edit the JSON); a fix in `ua.js` means regenerating
  the vectors and re-running Task 1's tests.

- [ ] **Step 6: CI.** In `.github/workflows/ci.yml`, after the `zether-prover` job, add:

```yaml
  scaas-ua:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: clients/scaas-ua
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy
      - uses: Swatinem/rust-cache@v2
        with:
          workspaces: clients/scaas-ua
      - name: clippy
        run: cargo clippy --all-targets -- -D warnings
      - name: vectors
        run: cargo test
```

- [ ] **Step 7: Commit.**

```bash
/usr/bin/git add clients/scaas-ua .github/workflows/ci.yml
/usr/bin/git commit -m "UA-1 T2: scaas-ua crate (UA identity layer, independent curve code) against the UA vectors" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 3: Solidity `UAKinds`

**Files:**
- Create: `smartcontracts/evm/src/ua/UAKinds.sol`
- Create: `smartcontracts/evm/test/ua/UAKinds.t.sol`

**Interfaces:**
- Consumes: the vector files (Task 1); `@openzeppelin/contracts/utils/Strings.sol`; `src/ua/PqUA.sol` (consistency only).
- Produces: library `UAKinds` (internal functions; not deployed, no size-gate entry): kind constants, purpose constants
  `PURPOSE_*`, `MSG_TAG`, `UAAUTH_TYPEHASH`, `DOMAIN_TYPEHASH`, `NAME_HASH`, errors `UAKeyData(uint16)`,
  `UAKindUnknown(uint16)`, `UAKindNotDerived(uint16)`; `isNative`, `isZether`, `isSigning`, `isMember`, `isDerived`,
  `name`, `tag`, `groupName`, `groupTag`, `uaOf`, `keyHashOf`, `inNativeSpace`, `uaMessage`, `chainKeyHash`, `popDigest`,
  `uaAuthDomainSeparator`, `uaAuthDigest`, `memberDigest`, `validateKeyData`. UA-2's registry builds on these.

- [ ] **Step 1: The library.** Create `smartcontracts/evm/src/ua/UAKinds.sol`:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @title UA identity layer (accounts.md §1.3–§1.6): kind table, tags, ids, keyHash, purpose tags, `ua_msg`, `popDigest`,
///        the registry's `UAAuth` digest, member digests and key-data validation.
/// @notice The same rules are implemented by clientkeys `ua.js`, `clients/scaas-ua`, `clients/ua-py`, `clients/ua-go` and
///         `clients/ua-cs`; `smartcontracts/vectors/ua/kinds.json` and `structures.json` pin all six.
///         `GROUP(g) = keccak256("scaas.ua.group." ‖ g ‖ ".v1")`, `keyHash = keccak256(GROUP(g) ‖ canonical pubkey)`.
///         Validation uses EIP-2537 (BLS12-381 G1/G2 MSM with scalar 1: canonical, on curve, in the subgroup) and the
///         bn254 pairing precompile (G2 on the twist and in the subgroup). UNAUDITED — NOT FOR PRODUCTION FUNDS.
library UAKinds {
    uint16 internal constant EVM_EOA = 0x0001;
    uint16 internal constant EVM_CONTRACT = 0x0002;
    uint16 internal constant HEDERA_NATIVE = 0x0003;
    uint16 internal constant WEBAUTHN_P256 = 0x0100;
    uint16 internal constant P256 = 0x0101;
    uint16 internal constant ED25519 = 0x0102;
    uint16 internal constant BIP340 = 0x0103;
    uint16 internal constant SCHNORR_BN254 = 0x0104;
    uint16 internal constant SCHNORR_BLS12381 = 0x0105;
    uint16 internal constant BLS12381_MINSIG = 0x0106;
    uint16 internal constant BLS_BN254_MINSIG = 0x0107;
    uint16 internal constant MUSIG2_SECP256K1 = 0x0110;
    uint16 internal constant FROST_SECP256K1 = 0x0111;
    uint16 internal constant MUSIG2_BN254 = 0x0112;
    uint16 internal constant FROST_BN254 = 0x0113;
    uint16 internal constant MSIG = 0x0120;
    uint16 internal constant MLDSA44 = 0x0130;
    uint16 internal constant MLDSA65 = 0x0131;
    uint16 internal constant FNDSA512 = 0x0132;
    uint16 internal constant SLHDSA128S = 0x0133;
    uint16 internal constant ZETHER_BN254 = 0x0140;
    uint16 internal constant ZETHER_BLS12381 = 0x0141;
    uint16 internal constant PQZ_MLWE = 0x0142;

    bytes32 internal constant MSG_TAG = keccak256("scaas.ua.msg.v1");
    bytes32 internal constant PURPOSE_POP = keccak256("scaas.ua.purpose.pop.v1");
    bytes32 internal constant PURPOSE_AUTHREF = keccak256("scaas.ua.purpose.authref.v1");
    bytes32 internal constant PURPOSE_METATX = keccak256("scaas.ua.purpose.metatx.v1");
    bytes32 internal constant PURPOSE_METATX_CANCEL = keccak256("scaas.ua.purpose.metatx-cancel.v1");
    bytes32 internal constant PURPOSE_MEMBER = keccak256("scaas.ua.purpose.member.v1");
    bytes32 internal constant PURPOSE_ZETHER_AUTH = keccak256("scaas.ua.purpose.zether-auth.v1");
    bytes32 internal constant PURPOSE_ZETHER_OWNER = keccak256("scaas.ua.purpose.zether-owner.v1");
    bytes32 internal constant PURPOSE_KEYOP = keccak256("scaas.ua.purpose.keyop.v1");
    bytes32 internal constant PURPOSE_RECEIVER_FEE = keccak256("scaas.ua.purpose.receiver-fee.v1");
    bytes32 internal constant PURPOSE_VP = keccak256("scaas.ua.purpose.vp.v1");
    bytes32 internal constant PURPOSE_VC_ANCHOR = keccak256("scaas.ua.purpose.vc-anchor.v1");
    bytes32 internal constant UAAUTH_TYPEHASH = keccak256("UAAuth(bytes32 ua,bytes32 purpose,bytes32 digest)");
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    bytes32 internal constant NAME_HASH = keccak256("SCaaS UARegistry");

    error UAKeyData(uint16 kind);
    error UAKindUnknown(uint16 kind);
    error UAKindNotDerived(uint16 kind);

    uint256 private constant SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 private constant SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 private constant P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
    uint256 private constant P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;
    uint256 private constant ED_P = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED;
    uint256 private constant ED_D = 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3;
    uint256 private constant ED_SQRT_M1 = 0x2B8324804FC1DF0B2B4D00993DFBD7A72F431806AD2FE478C4EE1B274A0EA0B0;
    uint256 private constant BN_P = 0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47;
    uint256 private constant BN_R = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001;

    // ----- sets (accounts.md §1.6 "Closed kind sets"; slhdsa128s in SIGNING and MEMBER) -----

    function isNative(uint16 kind) internal pure returns (bool) {
        return (kind >= EVM_EOA && kind <= HEDERA_NATIVE) || (kind >= 0x0010 && kind <= 0x0016);
    }

    function isZether(uint16 kind) internal pure returns (bool) {
        return kind >= ZETHER_BN254 && kind <= PQZ_MLWE;
    }

    function _singleSigning(uint16 kind) private pure returns (bool) {
        return (kind >= WEBAUTHN_P256 && kind <= BLS_BN254_MINSIG) || (kind >= MUSIG2_SECP256K1 && kind <= FROST_BN254)
            || (kind >= MLDSA44 && kind <= SLHDSA128S);
    }

    function isSigning(uint16 kind) internal pure returns (bool) {
        return kind == MSIG || _singleSigning(kind);
    }

    function isDerived(uint16 kind) internal pure returns (bool) {
        return isSigning(kind) || isZether(kind);
    }

    function isMember(uint16 kind, bool hederaNative) internal pure returns (bool) {
        return _singleSigning(kind) || kind == EVM_EOA || kind == EVM_CONTRACT || (hederaNative && kind == HEDERA_NATIVE);
    }

    // ----- names, tags, groups -----

    function name(uint16 kind) internal pure returns (string memory) {
        if (kind == 0x0001) return "evm-eoa";
        if (kind == 0x0002) return "evm-contract";
        if (kind == 0x0003) return "hedera-native";
        if (kind == 0x0010) return "solana-ed25519";
        if (kind == 0x0011) return "stellar-account";
        if (kind == 0x0012) return "soroban-contract";
        if (kind == 0x0013) return "aptos-account";
        if (kind == 0x0014) return "sui-address";
        if (kind == 0x0015) return "cosmos-account";
        if (kind == 0x0016) return "ton-wallet";
        if (kind == 0x0100) return "webauthn-p256";
        if (kind == 0x0101) return "p256";
        if (kind == 0x0102) return "ed25519";
        if (kind == 0x0103) return "bip340";
        if (kind == 0x0104) return "schnorr-bn254";
        if (kind == 0x0105) return "schnorr-bls12381";
        if (kind == 0x0106) return "bls12381-minsig";
        if (kind == 0x0107) return "bls-bn254-minsig";
        if (kind == 0x0110) return "musig2-secp256k1";
        if (kind == 0x0111) return "frost-secp256k1";
        if (kind == 0x0112) return "musig2-bn254";
        if (kind == 0x0113) return "frost-bn254";
        if (kind == 0x0120) return "msig";
        if (kind == 0x0130) return "mldsa44";
        if (kind == 0x0131) return "mldsa65";
        if (kind == 0x0132) return "fndsa512";
        if (kind == 0x0133) return "slhdsa128s";
        if (kind == 0x0140) return "zether-bn254";
        if (kind == 0x0141) return "zether-bls12381";
        if (kind == 0x0142) return "pqz-mlwe";
        revert UAKindUnknown(kind);
    }

    function _requireDerived(uint16 kind) private pure {
        if (isDerived(kind)) return;
        if (isNative(kind)) revert UAKindNotDerived(kind);
        revert UAKindUnknown(kind);
    }

    /// `TAG(kind) = keccak256("scaas.ua." ‖ name ‖ ".v1")`.
    function tag(uint16 kind) internal pure returns (bytes32) {
        _requireDerived(kind);
        return keccak256(abi.encodePacked("scaas.ua.", name(kind), ".v1"));
    }

    /// The keyHash group of a derived kind; "" for `msig`.
    function groupName(uint16 kind) internal pure returns (string memory) {
        _requireDerived(kind);
        if (kind == WEBAUTHN_P256 || kind == P256) return "p256";
        if (kind == ED25519) return "ed25519";
        if (kind == BIP340 || kind == MUSIG2_SECP256K1 || kind == FROST_SECP256K1) return "secp256k1";
        if (kind == SCHNORR_BN254 || kind == MUSIG2_BN254 || kind == FROST_BN254 || kind == ZETHER_BN254) return "bn254-g1";
        if (kind == SCHNORR_BLS12381 || kind == ZETHER_BLS12381) return "bls12381-g1";
        if (kind == BLS12381_MINSIG) return "bls12381-g2";
        if (kind == BLS_BN254_MINSIG) return "bn254-g2";
        if (kind == MSIG) return "";
        return name(kind); // mldsa44, mldsa65, fndsa512, slhdsa128s, pqz-mlwe: the group is the kind
    }

    function groupTag(string memory group) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("scaas.ua.group.", group, ".v1"));
    }

    // ----- ids, keyHash, messages, digests -----

    /// `keccak256(TAG(kind) ‖ keyData)`; no validation.
    function uaOf(uint16 kind, bytes memory keyData) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(tag(kind), keyData));
    }

    function inNativeSpace(bytes32 id) internal pure returns (bool) {
        return uint256(id) >> 160 == 0;
    }

    /// `keccak256(GROUP(g) ‖ canonical pubkey)`, 0 for `msig`. Call on validated key data.
    function keyHashOf(uint16 kind, bytes memory d) internal pure returns (bytes32) {
        string memory g = groupName(kind);
        if (bytes(g).length == 0) return bytes32(0);
        (uint256 lo, uint256 len) = (0, d.length);
        if (kind == WEBAUTHN_P256 || kind == P256) len = 32;
        else if (kind == MUSIG2_SECP256K1 || kind == FROST_SECP256K1) (lo, len) = (1, 32);
        else if (kind == MUSIG2_BN254 || kind == FROST_BN254) len = 64;
        if (d.length < lo + len) revert UAKeyData(kind);
        bytes memory pub = new bytes(len);
        for (uint256 i; i < len; ++i) pub[i] = d[lo + i];
        return keccak256(abi.encodePacked(groupTag(g), pub));
    }

    function uaMessage(uint16 kind, bytes32 purposeTag, bytes32 digest) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(MSG_TAG, tag(kind), purposeTag, digest));
    }

    /// `keccak256("evm:" ‖ decimal(chainId))` (the registry computes it in its constructor from `block.chainid`).
    function chainKeyHash(uint256 chainId) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("evm:", Strings.toString(chainId)));
    }

    /// `pop_digest = keccak256(POP_TAG ‖ chainKeyHash ‖ chainUid ‖ registry_id ‖ ua ‖ authRef)` (CTR-UA-07).
    function popDigest(bytes32 chainKeyHash_, bytes32 chainUid, address registry, bytes32 ua, bytes32 authRef)
        internal pure returns (bytes32)
    {
        return keccak256(abi.encode(PURPOSE_POP, chainKeyHash_, chainUid, registry, ua, authRef));
    }

    function uaAuthDomainSeparator(uint256 generation, uint256 chainId, address registry, bytes32 chainUid)
        internal pure returns (bytes32)
    {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, NAME_HASH, keccak256(bytes(Strings.toString(generation))), chainId, registry, chainUid)
        );
    }

    function uaAuthDigest(bytes32 domainSeparator, bytes32 ua, bytes32 purposeTag, bytes32 digest)
        internal pure returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(hex"1901", domainSeparator, keccak256(abi.encode(UAAUTH_TYPEHASH, ua, purposeTag, digest)))
        );
    }

    function memberDigest(bytes32 structureUa, bytes32 uaMsg) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(structureUa, uaMsg));
    }

    // ----- key-data validation (accounts.md §1.6 "Validation at registration") -----

    /// Reverts `UAKeyData(kind)` unless `d` is the unique canonical encoding of a valid key or structure of `kind`.
    function validateKeyData(uint16 kind, bytes memory d, bool hederaNative) internal view {
        _requireDerived(kind);
        uint256 len = _fixedLength(kind);
        if (len != 0 && d.length != len) revert UAKeyData(kind);
        bool ok;
        if (kind == WEBAUTHN_P256 || kind == P256) ok = _p256(d);
        else if (kind == ED25519) ok = _ed25519(d);
        else if (kind == BIP340) ok = _secpX(_word(d, 0));
        else if (kind == SCHNORR_BN254 || kind == ZETHER_BN254) ok = _bnG1(d, 0);
        else if (kind == SCHNORR_BLS12381 || kind == ZETHER_BLS12381) ok = _bls(d, address(0x0c), 128);
        else if (kind == BLS12381_MINSIG) ok = _bls(d, address(0x0e), 256);
        else if (kind == BLS_BN254_MINSIG) ok = _bnG2(d);
        else if (kind == MUSIG2_SECP256K1) ok = _musig2(d, 33);
        else if (kind == FROST_SECP256K1) ok = _frost(d, 33);
        else if (kind == MUSIG2_BN254) ok = _musig2(d, 64);
        else if (kind == FROST_BN254) ok = _frost(d, 64);
        else if (kind == MSIG) ok = _msig(d, hederaNative);
        else if (kind == FNDSA512) ok = _fndsa(d);
        else ok = true; // mldsa44/65, slhdsa128s, pqz-mlwe: the length is the whole check
        if (!ok) revert UAKeyData(kind);
    }

    function _fixedLength(uint16 kind) private pure returns (uint256) {
        if (kind == WEBAUTHN_P256) return 96;
        if (kind == P256 || kind == SCHNORR_BN254 || kind == ZETHER_BN254) return 64;
        if (kind == ED25519 || kind == BIP340 || kind == SLHDSA128S) return 32;
        if (kind == SCHNORR_BLS12381 || kind == ZETHER_BLS12381 || kind == BLS_BN254_MINSIG) return 128;
        if (kind == BLS12381_MINSIG) return 256;
        if (kind == MLDSA44) return 1312;
        if (kind == MLDSA65) return 1952;
        if (kind == FNDSA512) return 897;
        if (kind == PQZ_MLWE) return 16384;
        return 0; // MuSig2, FROST, msig: variable
    }

    function _word(bytes memory d, uint256 o) private pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := mload(add(add(d, 32), o))
        }
    }

    function _u16(bytes memory d, uint256 o) private pure returns (uint256) {
        return _word(d, o) >> 240;
    }

    function _isZero(bytes memory d) private pure returns (bool) {
        return keccak256(d) == keccak256(new bytes(d.length));
    }

    function _modexp(uint256 b, uint256 e, uint256 m) private view returns (uint256 r) {
        (bool ok, bytes memory out) = address(0x05).staticcall(abi.encode(32, 32, 32, b, e, m));
        require(ok && out.length == 32, "modexp");
        r = abi.decode(out, (uint256));
    }

    function _secpX(uint256 x) private view returns (bool) {
        if (x >= SECP_P) return false;
        uint256 rhs = addmod(mulmod(mulmod(x, x, SECP_P), x, SECP_P), 7, SECP_P);
        uint256 y = _modexp(rhs, (SECP_P + 1) / 4, SECP_P);
        return mulmod(y, y, SECP_P) == rhs;
    }

    function _secpCompressed(bytes memory d, uint256 o) private view returns (bool) {
        uint8 prefix = uint8(d[o]);
        return (prefix == 2 || prefix == 3) && _secpX(_word(d, o + 1));
    }

    function _p256(bytes memory d) private pure returns (bool) {
        (uint256 x, uint256 y) = (_word(d, 0), _word(d, 32));
        if (x >= P256_P || y >= P256_P) return false;
        uint256 rhs = addmod(
            addmod(mulmod(mulmod(x, x, P256_P), x, P256_P), P256_P - mulmod(3, x, P256_P), P256_P), P256_B, P256_P
        );
        return mulmod(y, y, P256_P) == rhs;
    }

    function _ed25519(bytes memory d) private view returns (bool) {
        uint256 raw = _word(d, 0);
        uint256 le = _reverse(raw);
        uint256 y = le & ((1 << 255) - 1);
        if (y >= ED_P) return false;
        uint256 yy = mulmod(y, y, ED_P);
        uint256 u = addmod(yy, ED_P - 1, ED_P);
        uint256 v = addmod(mulmod(ED_D, yy, ED_P), 1, ED_P);
        uint256 x2 = mulmod(u, _modexp(v, ED_P - 2, ED_P), ED_P);
        uint256 x = _modexp(x2, (ED_P + 3) / 8, ED_P);
        if (mulmod(x, x, ED_P) != x2) x = mulmod(x, ED_SQRT_M1, ED_P);
        if (mulmod(x, x, ED_P) != x2) return false; // not a point
        if (x == 0 && le >> 255 == 1) return false; // negative zero
        return !_edSmallOrder(raw);
    }

    /// The canonical encodings of the 8 small-order points (pinned against noble's ED25519_TORSION_SUBGROUP by the vectors).
    function _edSmallOrder(uint256 raw) private pure returns (bool) {
        return raw == 0x0100000000000000000000000000000000000000000000000000000000000000
            || raw == 0xecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
            || raw == 0x0000000000000000000000000000000000000000000000000000000000000000
            || raw == 0x0000000000000000000000000000000000000000000000000000000000000080
            || raw == 0x26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05
            || raw == 0x26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85
            || raw == 0xc7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a
            || raw == 0xc7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa;
    }

    function _reverse(uint256 v) private pure returns (uint256) {
        v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8)
            | ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);
        v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16)
            | ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);
        v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32)
            | ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);
        v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64)
            | ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);
        return (v >> 128) | (v << 128);
    }

    function _bnG1(bytes memory d, uint256 o) private pure returns (bool) {
        (uint256 x, uint256 y) = (_word(d, o), _word(d, o + 32));
        if (x >= BN_P || y >= BN_P || (x == 0 && y == 0)) return false;
        return mulmod(y, y, BN_P) == addmod(mulmod(mulmod(x, x, BN_P), x, BN_P), 3, BN_P);
    }

    /// EIP-197 pairing with the G1 generator: fails unless the G2 point is canonical, on the twist and in the subgroup.
    function _bnG2(bytes memory d) private view returns (bool) {
        if (_isZero(d)) return false;
        (bool ok, bytes memory out) = address(0x08).staticcall(abi.encodePacked(uint256(1), uint256(2), d));
        return ok && out.length == 32;
    }

    /// EIP-2537 MSM with scalar 1 (G1MSM `0x0c` / G2MSM `0x0e`): fails unless padded, canonical, on curve, in the subgroup.
    function _bls(bytes memory d, address msm, uint256 size) private view returns (bool) {
        if (_isZero(d)) return false;
        (bool ok, bytes memory out) = msm.staticcall(abi.encodePacked(d, uint256(1)));
        return ok && out.length == size;
    }

    function _point(bytes memory d, uint256 o, uint256 size) private view returns (bool) {
        return size == 33 ? _secpCompressed(d, o) : _bnG1(d, o);
    }

    /// `d[a .. a+len) < d[b .. b+len)` as big-endian byte strings.
    function _lt(bytes memory d, uint256 a, uint256 b, uint256 len) private pure returns (bool) {
        for (uint256 i; i < len; i += 32) {
            uint256 n = len - i < 32 ? len - i : 32;
            uint256 shift = 8 * (32 - n);
            (uint256 x, uint256 y) = (_word(d, a + i) >> shift, _word(d, b + i) >> shift);
            if (x != y) return x < y;
        }
        return false;
    }

    function _musig2(bytes memory d, uint256 size) private view returns (bool) {
        if (d.length < size + 2) return false;
        uint256 n = _u16(d, size);
        if (n < 2 || n > 16 || d.length != size + 2 + n * size || !_point(d, 0, size)) return false;
        for (uint256 i; i < n; ++i) {
            uint256 o = size + 2 + i * size;
            if (!_point(d, o, size) || (i > 0 && !_lt(d, o - size, o, size))) return false;
        }
        return true;
    }

    function _frost(bytes memory d, uint256 size) private view returns (bool) {
        if (d.length < size + 4) return false;
        (uint256 t, uint256 n) = (_u16(d, size), _u16(d, size + 2));
        if (t < 2 || t > n || n > 16) return false;
        uint256 per = (t + 1) * size + 32;
        if (d.length != size + 4 + n * per || !_point(d, 0, size)) return false;
        uint256 order = size == 33 ? SECP_N : BN_R;
        for (uint256 i; i < n; ++i) {
            uint256 o = size + 4 + i * per;
            for (uint256 j; j <= t; ++j) {
                if (!_point(d, o + j * size, size)) return false; // t commitments, then R_i
            }
            if (_word(d, o + (t + 1) * size) >= order) return false;
        }
        return true;
    }

    function _msig(bytes memory d, bool hederaNative) private pure returns (bool) {
        if (d.length < 4) return false;
        (uint256 threshold, uint256 count) = (_u16(d, 0), _u16(d, 2));
        if (count == 0 || count > 16 || d.length != 4 + 36 * count) return false;
        uint256 total;
        for (uint256 i; i < count; ++i) {
            uint256 o = 4 + 36 * i;
            uint16 kind = uint16(_u16(d, o));
            bytes32 id = bytes32(_word(d, o + 2));
            uint256 weight = _u16(d, o + 34);
            if (!isMember(kind, hederaNative) || weight == 0 || isNative(kind) != inNativeSpace(id)) return false;
            if (i > 0 && _word(d, o - 34) >= uint256(id)) return false;
            total += weight;
        }
        return threshold != 0 && threshold <= total;
    }

    /// `0x09 ‖ 512 × 14-bit h_i`, each `< 12289` (the decoding of `Falcon512._decodePk`, over memory).
    function _fndsa(bytes memory d) private pure returns (bool) {
        if (uint8(d[0]) != 0x09) return false;
        for (uint256 i; i < 512; ++i) {
            uint256 bit = i * 14;
            uint256 h = (_word(d, 1 + (bit >> 3)) >> (242 - (bit & 7))) & 0x3fff;
            if (h >= 12289) return false;
        }
        return true;
    }
}
```

- [ ] **Step 2: The test.** Create `smartcontracts/evm/test/ua/UAKinds.t.sol`:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {PqUA} from "../../src/ua/PqUA.sol";

/// External wrapper so a revert of the library is observable with try/catch.
contract UAKindsHarness {
    function validate(uint16 kind, bytes memory keyData, bool hederaNative) external view {
        UAKinds.validateKeyData(kind, keyData, hederaNative);
    }
}

/// The Solidity identity layer against smartcontracts/vectors/ua/kinds.json and structures.json (generated by clientkeys
/// scripts/ua-vectors.mjs; the same files pin ua.js, scaas-ua, ua-py, ua-go and ua-cs).
contract UAKindsTest is Test {
    UAKindsHarness internal h;

    function setUp() public {
        h = new UAKindsHarness();
    }

    function _k() internal view returns (string memory) {
        return vm.readFile("../vectors/ua/kinds.json");
    }

    function _s() internal view returns (string memory) {
        return vm.readFile("../vectors/ua/structures.json");
    }

    function _at(string memory arr, uint256 i, string memory field) internal pure returns (string memory) {
        return string.concat(".", arr, "[", vm.toString(i), "].", field);
    }

    function _count(string memory json, string memory arr) internal view returns (uint256 n) {
        while (vm.keyExistsJson(json, string.concat(".", arr, "[", vm.toString(n), "]"))) ++n;
    }

    function test_kindTable() public view {
        string memory j = _k();
        uint256 n = _count(j, "kinds");
        assertEq(n, 30);
        for (uint256 i; i < n; ++i) {
            uint16 kind = uint16(vm.parseJsonUint(j, _at("kinds", i, "kind")));
            bool native = vm.parseJsonBool(j, _at("kinds", i, "native"));
            assertEq(UAKinds.name(kind), vm.parseJsonString(j, _at("kinds", i, "name")));
            assertEq(UAKinds.isNative(kind), native);
            assertEq(UAKinds.isSigning(kind), vm.parseJsonBool(j, _at("kinds", i, "signing")));
            assertEq(UAKinds.isZether(kind), vm.parseJsonBool(j, _at("kinds", i, "zether")));
            assertEq(UAKinds.isMember(kind, false), vm.parseJsonBool(j, _at("kinds", i, "member")));
            assertEq(UAKinds.isMember(kind, true), vm.parseJsonBool(j, _at("kinds", i, "memberHedera")));
            if (native) continue;
            assertEq(UAKinds.tag(kind), vm.parseJsonBytes32(j, _at("kinds", i, "TAG")));
            if (kind == UAKinds.MSIG) assertEq(bytes(UAKinds.groupName(kind)).length, 0);
            else assertEq(UAKinds.groupName(kind), vm.parseJsonString(j, _at("kinds", i, "group")));
        }
    }

    function test_groupsPurposesConstants() public view {
        string memory j = _k();
        for (uint256 i; i < _count(j, "groups"); ++i) {
            assertEq(
                UAKinds.groupTag(vm.parseJsonString(j, _at("groups", i, "group"))),
                vm.parseJsonBytes32(j, _at("groups", i, "GROUP"))
            );
        }
        bytes32[11] memory p = [
            UAKinds.PURPOSE_POP, UAKinds.PURPOSE_AUTHREF, UAKinds.PURPOSE_METATX, UAKinds.PURPOSE_METATX_CANCEL,
            UAKinds.PURPOSE_MEMBER, UAKinds.PURPOSE_ZETHER_AUTH, UAKinds.PURPOSE_ZETHER_OWNER, UAKinds.PURPOSE_KEYOP,
            UAKinds.PURPOSE_RECEIVER_FEE, UAKinds.PURPOSE_VP, UAKinds.PURPOSE_VC_ANCHOR
        ];
        assertEq(_count(j, "purposes"), 11);
        for (uint256 i; i < 11; ++i) assertEq(p[i], vm.parseJsonBytes32(j, _at("purposes", i, "purposeTag")));
        assertEq(UAKinds.MSG_TAG, vm.parseJsonBytes32(j, ".constants.MSG_TAG"));
        assertEq(UAKinds.PURPOSE_POP, vm.parseJsonBytes32(j, ".constants.POP_TAG"));
        assertEq(UAKinds.DOMAIN_TYPEHASH, vm.parseJsonBytes32(j, ".constants.DOMAIN_TYPEHASH"));
        assertEq(UAKinds.UAAUTH_TYPEHASH, vm.parseJsonBytes32(j, ".constants.UAAUTH_TYPEHASH"));
        assertEq(UAKinds.NAME_HASH, vm.parseJsonBytes32(j, ".constants.NAME_HASH"));
    }

    function test_validRows() public {
        vm.pauseGasMetering(); // a 220 KB JSON string per cheatcode call; correctness test, not a gas test
        string memory j = _k();
        uint256 n = _count(j, "valid");
        for (uint256 i; i < n; ++i) {
            uint16 kind = uint16(vm.parseJsonUint(j, _at("valid", i, "kind")));
            bytes memory d = vm.parseJsonBytes(j, _at("valid", i, "keyData"));
            h.validate(kind, d, vm.parseJsonBool(j, _at("valid", i, "hederaNative")));
            bytes32 ua = UAKinds.uaOf(kind, d);
            assertEq(ua, vm.parseJsonBytes32(j, _at("valid", i, "ua")), UAKinds.name(kind));
            assertFalse(UAKinds.inNativeSpace(ua));
            bytes32 want = kind == UAKinds.MSIG ? bytes32(0) : vm.parseJsonBytes32(j, _at("valid", i, "keyHash"));
            assertEq(UAKinds.keyHashOf(kind, d), want, UAKinds.name(kind));
        }
    }

    function test_invalidRows() public {
        vm.pauseGasMetering(); // a 220 KB JSON string per cheatcode call; correctness test, not a gas test
        string memory j = _k();
        uint256 n = _count(j, "invalid");
        assertGt(n, 100);
        for (uint256 i; i < n; ++i) {
            uint16 kind = uint16(vm.parseJsonUint(j, _at("invalid", i, "kind")));
            bytes memory d = vm.parseJsonBytes(j, _at("invalid", i, "keyData"));
            string memory reason = vm.parseJsonString(j, _at("invalid", i, "reason"));
            bytes memory want = abi.encodeWithSelector(_selector(vm.parseJsonString(j, _at("invalid", i, "error"))), kind);
            try h.validate(kind, d, vm.parseJsonBool(j, _at("invalid", i, "hederaNative"))) {
                revert(string.concat("accepted: ", reason));
            } catch (bytes memory got) {
                assertEq(got, want, reason);
            }
        }
    }

    function _selector(string memory err) internal pure returns (bytes4) {
        bytes32 e = keccak256(bytes(err));
        if (e == keccak256("UAKeyData")) return UAKinds.UAKeyData.selector;
        if (e == keccak256("UAKindUnknown")) return UAKinds.UAKindUnknown.selector;
        if (e == keccak256("UAKindNotDerived")) return UAKinds.UAKindNotDerived.selector;
        revert(string.concat("unexpected error code ", err));
    }

    function test_nativeSpaceAndMessages() public {
        vm.pauseGasMetering(); // a 220 KB JSON string per cheatcode call; correctness test, not a gas test
        string memory j = _k();
        for (uint256 i; i < _count(j, "nativeSpace"); ++i) {
            assertEq(
                UAKinds.inNativeSpace(vm.parseJsonBytes32(j, _at("nativeSpace", i, "id"))),
                vm.parseJsonBool(j, _at("nativeSpace", i, "inNativeSpace"))
            );
        }
        for (uint256 i; i < _count(j, "messages"); ++i) {
            uint16 kind = uint16(vm.parseJsonUint(j, _at("messages", i, "kind")));
            bytes32 got = UAKinds.uaMessage(
                kind, vm.parseJsonBytes32(j, _at("messages", i, "purposeTag")), vm.parseJsonBytes32(j, _at("messages", i, "digest"))
            );
            assertEq(got, vm.parseJsonBytes32(j, _at("messages", i, "uaMsg")));
        }
    }

    function test_structures() public view {
        string memory s = _s();
        for (uint256 i; i < _count(s, "pop"); ++i) {
            string memory c = string.concat(".contexts.", vm.parseJsonString(s, _at("pop", i, "context")));
            bytes32 ckh = UAKinds.chainKeyHash(vm.parseJsonUint(s, string.concat(c, ".chainId")));
            assertEq(ckh, vm.parseJsonBytes32(s, _at("pop", i, "chainKeyHash")));
            bytes32 got = UAKinds.popDigest(
                ckh,
                vm.parseJsonBytes32(s, string.concat(c, ".chainUid")),
                vm.parseJsonAddress(s, string.concat(c, ".registry")),
                vm.parseJsonBytes32(s, _at("pop", i, "ua")),
                vm.parseJsonBytes32(s, _at("pop", i, "authRef"))
            );
            assertEq(got, vm.parseJsonBytes32(s, _at("pop", i, "popDigest")));
        }
        for (uint256 i; i < _count(s, "uaAuth"); ++i) {
            string memory c = string.concat(".contexts.", vm.parseJsonString(s, _at("uaAuth", i, "context")));
            bytes32 sep = UAKinds.uaAuthDomainSeparator(
                vm.parseJsonUint(s, _at("uaAuth", i, "generation")),
                vm.parseJsonUint(s, string.concat(c, ".chainId")),
                vm.parseJsonAddress(s, string.concat(c, ".registry")),
                vm.parseJsonBytes32(s, string.concat(c, ".chainUid"))
            );
            assertEq(sep, vm.parseJsonBytes32(s, _at("uaAuth", i, "domainSeparator")));
            bytes32 got = UAKinds.uaAuthDigest(
                sep,
                vm.parseJsonBytes32(s, _at("uaAuth", i, "ua")),
                vm.parseJsonBytes32(s, _at("uaAuth", i, "purposeTag")),
                vm.parseJsonBytes32(s, _at("uaAuth", i, "digest"))
            );
            assertEq(got, vm.parseJsonBytes32(s, _at("uaAuth", i, "uaAuthDigest")));
        }
        bytes32 m = UAKinds.memberDigest(vm.parseJsonBytes32(s, ".member[0].structureUa"), vm.parseJsonBytes32(s, ".member[0].uaMsg"));
        assertEq(m, vm.parseJsonBytes32(s, ".member[0].memberDigest"));
    }

    /// P6a's PqUA keeps its own tags (ruling U8): they must equal the table's.
    function test_pqTagsMatchPqUA() public pure {
        for (uint16 k = UAKinds.MLDSA44; k <= UAKinds.SLHDSA128S; ++k) assertEq(UAKinds.tag(k), PqUA.tag(k));
    }
}
```

- [ ] **Step 3: Run.** `cd smartcontracts/evm && ../../scripts/capped forge test --match-path 'test/ua/UAKinds.t.sol' -vv` —
  7 tests pass. If the bn254 subgroup row ("outside the subgroup", kind 263) is accepted, the EVM in use does not check
  the G2 subgroup in `0x08`: stop and report (BLOCKED) — do not weaken the row. If `parseJsonUint` refuses a JSON number,
  use the forge-std 1.16.2 equivalent and report it.

- [ ] **Step 4: Full suite and gates.** `../../scripts/capped forge test` — **924** passed, 10 skipped (917 before, +7);
  size gate 0 errors (an internal library adds no deployed contract); `FOUNDRY_PROFILE=private7622 forge build` green.

- [ ] **Step 5: Commit.**

```bash
/usr/bin/git add smartcontracts/evm/src/ua/UAKinds.sol smartcontracts/evm/test/ua/UAKinds.t.sol
/usr/bin/git commit -m "UA-1 T3: UAKinds (Solidity UA identity layer, key-data validation) against the UA vectors" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 4: Python `clients/ua-py`

**Files:**
- Create: `clients/ua-py/scaas_ua/__init__.py`, `clients/ua-py/tests/__init__.py` (empty),
  `clients/ua-py/tests/test_vectors.py`, `clients/ua-py/requirements.txt`, `clients/ua-py/pyproject.toml`
- Modify: `.github/workflows/ci.yml` (job `ua-py`), `.gitignore` (`__pycache__/`)

**Interfaces:**
- Consumes: the vector files (Task 1).
- Produces: package `scaas_ua` with the API in snake case (`kind_info`, `is_native`, `is_zether`, `is_signing`, `is_member`,
  `kind_tag_string`, `tag`, `group_tag_string`, `group_tag`, `MSG_TAG`, `PURPOSES`, `purpose_tag`, `POP_TAG`, `ua_of`,
  `in_native_space`, `derive_ua`, `native_id`, `key_hash_of`, `validate_key_data`, `ua_message`, `chain_key_hash`,
  `pop_digest`, `ua_auth_domain_separator`, `ua_auth_digest`, `member_digest`, `canonical_id`, `encode_msig`, `UAError`
  with `.code`), for client systems (the ERP connector imports it).

- [ ] **Step 1: Packaging.** `clients/ua-py/requirements.txt`:

```
py_ecc==6.0.0
pycryptodome==3.19.1
```

  `clients/ua-py/pyproject.toml`:

```toml
[project]
name = "scaas-ua"
version = "0.1.0"
description = "SCaaS Universal Account identity layer (kind table, ids, keyHash, ua_msg, popDigest, UAAuth, key-data validation). UNAUDITED."
requires-python = ">=3.10"
dependencies = ["py_ecc==6.0.0", "pycryptodome==3.19.1"]

[tool.setuptools]
packages = ["scaas_ua"]
```

  and append `__pycache__/` to the repo `.gitignore`.

- [ ] **Step 2: The library.** Create `clients/ua-py/scaas_ua/__init__.py`:

```python
"""SCaaS Universal Account identity layer (accounts.md §1.3–§1.6) for client systems: the kind table, ids, keyHash,
purpose tags, ua_msg, popDigest, the registry's UAAuth digest, member digests, canonical ids and key-data validation.
The same rules live in Solidity (UAKinds.sol), JS (clientkeys ua.js), Rust (scaas-ua), Go and C#;
smartcontracts/vectors/ua pins all six. secp256k1, P-256, ed25519 and bn254 G1 are integer arithmetic here; bn254 G2
and BLS12-381 use py_ecc. Public inputs only: nothing here is constant-time. UNAUDITED."""
import re

from Crypto.Hash import keccak as _keccak
from py_ecc import optimized_bls12_381 as _bls
from py_ecc import optimized_bn128 as _bn


class UAError(Exception):
    """An error whose ``code`` every implementation and the vector files share."""

    def __init__(self, code, reason=None):
        super().__init__(f'{code}: {reason}' if reason else code)
        self.code = code
        self.reason = reason


def keccak256(*parts):
    h = _keccak.new(digest_bits=256)
    for p in parts:
        h.update(bytes(p))
    return h.digest()


def _need(ok, reason):
    if not ok:
        raise UAError('UAKeyData', reason)


# (number, name, native, lengths (empty = variable), keyHash group)
KINDS = (
    (0x0001, 'evm-eoa', True, (20,), None),
    (0x0002, 'evm-contract', True, (20,), None),
    (0x0003, 'hedera-native', True, (20,), None),
    (0x0010, 'solana-ed25519', True, (32,), None),
    (0x0011, 'stellar-account', True, (32,), None),
    (0x0012, 'soroban-contract', True, (32,), None),
    (0x0013, 'aptos-account', True, (32,), None),
    (0x0014, 'sui-address', True, (32,), None),
    (0x0015, 'cosmos-account', True, (20, 32), None),
    (0x0016, 'ton-wallet', True, (32,), None),
    (0x0100, 'webauthn-p256', False, (96,), 'p256'),
    (0x0101, 'p256', False, (64,), 'p256'),
    (0x0102, 'ed25519', False, (32,), 'ed25519'),
    (0x0103, 'bip340', False, (32,), 'secp256k1'),
    (0x0104, 'schnorr-bn254', False, (64,), 'bn254-g1'),
    (0x0105, 'schnorr-bls12381', False, (128,), 'bls12381-g1'),
    (0x0106, 'bls12381-minsig', False, (256,), 'bls12381-g2'),
    (0x0107, 'bls-bn254-minsig', False, (128,), 'bn254-g2'),
    (0x0110, 'musig2-secp256k1', False, (), 'secp256k1'),
    (0x0111, 'frost-secp256k1', False, (), 'secp256k1'),
    (0x0112, 'musig2-bn254', False, (), 'bn254-g1'),
    (0x0113, 'frost-bn254', False, (), 'bn254-g1'),
    (0x0120, 'msig', False, (), None),
    (0x0130, 'mldsa44', False, (1312,), 'mldsa44'),
    (0x0131, 'mldsa65', False, (1952,), 'mldsa65'),
    (0x0132, 'fndsa512', False, (897,), 'fndsa512'),
    (0x0133, 'slhdsa128s', False, (32,), 'slhdsa128s'),
    (0x0140, 'zether-bn254', False, (64,), 'bn254-g1'),
    (0x0141, 'zether-bls12381', False, (128,), 'bls12381-g1'),
    (0x0142, 'pqz-mlwe', False, (16384,), 'pqz-mlwe'),
)
_BY = {k[0]: k for k in KINDS}
GROUPS = ('p256', 'ed25519', 'secp256k1', 'bn254-g1', 'bls12381-g1', 'bls12381-g2', 'bn254-g2', 'mldsa44', 'mldsa65',
          'fndsa512', 'slhdsa128s', 'pqz-mlwe')
PURPOSES = ('pop', 'authref', 'metatx', 'metatx-cancel', 'member', 'zether-auth', 'zether-owner', 'keyop', 'receiver-fee',
            'vp', 'vc-anchor')


def kind_info(kind):
    try:
        return _BY[kind]
    except KeyError:
        raise UAError('UAKindUnknown', f'0x{kind:04x}') from None


def _derived(kind):
    k = kind_info(kind)
    if k[2]:
        raise UAError('UAKindNotDerived', k[1])
    return k


def _single_signing(kind):
    return 0x0100 <= kind <= 0x0107 or 0x0110 <= kind <= 0x0113 or 0x0130 <= kind <= 0x0133


def is_native(kind):
    return kind in _BY and _BY[kind][2]


def is_zether(kind):
    return 0x0140 <= kind <= 0x0142


def is_signing(kind):
    return kind == 0x0120 or _single_signing(kind)


def is_member(kind, hedera_native=False):
    return _single_signing(kind) or kind in (0x0001, 0x0002) or (hedera_native and kind == 0x0003)


def kind_tag_string(kind):
    return f'scaas.ua.{_derived(kind)[1]}.v1'


def tag(kind):
    return keccak256(kind_tag_string(kind).encode())


def group_tag_string(group):
    if group not in GROUPS:
        raise ValueError(f'unknown keyHash group {group}')
    return f'scaas.ua.group.{group}.v1'


def group_tag(group):
    return keccak256(group_tag_string(group).encode())


MSG_TAG = keccak256(b'scaas.ua.msg.v1')


def purpose_tag(purpose):
    if purpose not in PURPOSES:
        raise UAError('UAPurposeUnknown', purpose)
    return keccak256(f'scaas.ua.purpose.{purpose}.v1'.encode())


POP_TAG = purpose_tag('pop')
DOMAIN_TYPEHASH = keccak256(b'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)')
UAAUTH_TYPEHASH = keccak256(b'UAAuth(bytes32 ua,bytes32 purpose,bytes32 digest)')
NAME_HASH = keccak256(b'SCaaS UARegistry')


def _sized(b, n, what):
    b = bytes(b)
    if len(b) != n:
        raise ValueError(f'{what} must be {n} bytes')
    return b


def ua_of(kind, key_data):
    """``keccak256(TAG(kind) ‖ keyData)``; no validation (see derive_ua)."""
    return keccak256(tag(kind), key_data)


def in_native_space(ua_id):
    return _sized(ua_id, 32, 'id')[:12] == bytes(12)


def derive_ua(kind, key_data, hedera_native=False):
    """Validate, derive, refuse an id whose top 96 bits are zero (CTR-UA-03)."""
    validate_key_data(kind, key_data, hedera_native)
    ua = ua_of(kind, key_data)
    if in_native_space(ua):
        raise UAError('UAIdInNativeSpace', ua.hex())
    return ua


def native_id(kind, raw):
    k = kind_info(kind)
    if not k[2]:
        raise UAError('UAKindNotNative', k[1])
    raw = bytes(raw)
    _need(len(raw) in k[3], 'length')
    return bytes(32 - len(raw)) + raw


def key_hash_of(kind, key_data):
    """``keccak256(GROUP(g) ‖ canonical pubkey)``, None for structures. Call on validated key data."""
    k = _derived(kind)
    if k[4] is None:
        return None
    d = bytes(key_data)
    lo, hi = {0x0100: (0, 32), 0x0101: (0, 32), 0x0110: (1, 33), 0x0111: (1, 33), 0x0112: (0, 64), 0x0113: (0, 64)}.get(kind, (0, len(d)))
    _need(len(d) >= hi, 'length')
    return keccak256(group_tag(k[4]), d[lo:hi])


def ua_message(kind, purpose, digest):
    return keccak256(MSG_TAG, tag(kind), _sized(purpose, 32, 'purposeTag'), _sized(digest, 32, 'digest'))


def chain_key_hash(chain_id):
    return keccak256(f'evm:{int(chain_id)}'.encode())


def _address_word(a):
    return bytes(12) + _sized(a, 20, 'registry')


def pop_digest(chain_id, chain_uid, registry, ua, auth_ref=bytes(32)):
    """``pop_digest`` (CTR-UA-07)."""
    return keccak256(POP_TAG, chain_key_hash(chain_id), _sized(chain_uid, 32, 'chainUid'), _address_word(registry),
                     _sized(ua, 32, 'ua'), _sized(auth_ref, 32, 'authRef'))


def ua_auth_domain_separator(generation, chain_id, registry, chain_uid):
    return keccak256(DOMAIN_TYPEHASH, NAME_HASH, keccak256(str(int(generation)).encode()), int(chain_id).to_bytes(32, 'big'),
                     _address_word(registry), _sized(chain_uid, 32, 'chainUid'))


def ua_auth_digest(generation, chain_id, registry, chain_uid, ua, purpose, digest):
    """EIP-712 digest of ``UAAuth(ua, purpose, digest)`` under the registry's domain: what native signers sign."""
    s = keccak256(UAAUTH_TYPEHASH, _sized(ua, 32, 'ua'), _sized(purpose, 32, 'purposeTag'), _sized(digest, 32, 'digest'))
    return keccak256(b'\x19\x01', ua_auth_domain_separator(generation, chain_id, registry, chain_uid), s)


def member_digest(structure_ua, ua_msg):
    return keccak256(_sized(structure_ua, 32, 'structureUa'), _sized(ua_msg, 32, 'uaMsg'))


_ID = re.compile(r'0x([0-9a-fA-F]{40}|[0-9a-fA-F]{64})')


def canonical_id(text):
    """Lower-case hex; a 32-byte id with the top 96 bits zero is written as its 20-byte native id (CTR-UA-03)."""
    m = _ID.fullmatch(text) if isinstance(text, str) else None
    if not m:
        raise UAError('UAIdFormat', repr(text))
    h = m.group(1).lower()
    return '0x' + (h[24:] if len(h) == 64 and h.startswith('0' * 24) else h)


def encode_msig(threshold, members):
    """``u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight)``; members as (kind, id, weight)."""
    out = threshold.to_bytes(2, 'big') + len(members).to_bytes(2, 'big')
    for kind, member_id, weight in members:
        out += kind.to_bytes(2, 'big') + _sized(member_id, 32, 'member id') + weight.to_bytes(2, 'big')
    return out


# ----- key-data validation (accounts.md §1.6 "Validation at registration") -----

SECP_P = 2**256 - 2**32 - 977
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
ED_P = 2**255 - 19
ED_D = (-121665 * pow(121666, -1, ED_P)) % ED_P
ED_SQRT_M1 = pow(2, (ED_P - 1) // 4, ED_P)
BN_P = _bn.field_modulus
BN_R = _bn.curve_order
BLS_P = _bls.field_modulus
BLS_R = _bls.curve_order


def _int(b):
    return int.from_bytes(b, 'big')


def _secp_x(x):
    _need(x < SECP_P, 'range')
    rhs = (pow(x, 3, SECP_P) + 7) % SECP_P
    y = pow(rhs, (SECP_P + 1) // 4, SECP_P)
    _need(y * y % SECP_P == rhs, 'curve')


def _secp_compressed(b):
    _need(b[0] in (2, 3), 'prefix')
    _secp_x(_int(b[1:33]))


def _p256(xy):
    x, y = _int(xy[:32]), _int(xy[32:64])
    _need(x < P256_P and y < P256_P, 'range')
    _need((y * y - (x * x * x - 3 * x + P256_B)) % P256_P == 0, 'curve')


def _ed_add(p, q):
    """Affine twisted Edwards addition, a = −1 (complete for ed25519)."""
    (x1, y1), (x2, y2) = p, q
    t = ED_D * x1 * x2 * y1 * y2 % ED_P
    return ((x1 * y2 + x2 * y1) * pow(1 + t, -1, ED_P) % ED_P, (y1 * y2 + x1 * x2) * pow(1 - t, -1, ED_P) % ED_P)


def _ed25519(b):
    v = int.from_bytes(b, 'little')
    sign, y = v >> 255, v & ((1 << 255) - 1)
    _need(y < ED_P, 'range')
    x2 = (y * y - 1) * pow(ED_D * y * y + 1, -1, ED_P) % ED_P
    x = pow(x2, (ED_P + 3) // 8, ED_P)
    if (x * x - x2) % ED_P:
        x = x * ED_SQRT_M1 % ED_P
    _need((x * x - x2) % ED_P == 0, 'curve')
    _need(not (x == 0 and sign), 'sign')
    if x & 1 != sign:
        x = ED_P - x
    p = (x, y)
    for _ in range(3):
        p = _ed_add(p, p)
    _need(p != (0, 1), 'small-order')


def _bn_g1(b):
    x, y = _int(b[:32]), _int(b[32:64])
    _need(x < BN_P and y < BN_P, 'range')
    _need(x or y, 'identity')
    _need((y * y - x * x * x - 3) % BN_P == 0, 'curve')


def _bn_g2(b):
    xi, xr, yi, yr = (_int(b[32 * i:32 * i + 32]) for i in range(4))
    _need(max(xi, xr, yi, yr) < BN_P, 'range')
    _need(xi or xr or yi or yr, 'identity')
    pt = (_bn.FQ2([xr, xi]), _bn.FQ2([yr, yi]), _bn.FQ2.one())  # EIP-197: imaginary part first
    _need(_bn.is_on_curve(pt, _bn.b2), 'curve')
    _need(_bn.is_inf(_bn.multiply(pt, BN_R)), 'subgroup')


def _bls_fp(b):
    _need(b[:16] == bytes(16), 'padding')
    v = _int(b[16:64])
    _need(v < BLS_P, 'range')
    return v


def _bls_g1(b):
    x, y = _bls_fp(b[:64]), _bls_fp(b[64:128])
    _need(x or y, 'identity')
    pt = (_bls.FQ(x), _bls.FQ(y), _bls.FQ.one())
    _need(_bls.is_on_curve(pt, _bls.b), 'curve')
    _need(_bls.is_inf(_bls.multiply(pt, BLS_R)), 'subgroup')


def _bls_g2(b):
    x0, x1, y0, y1 = (_bls_fp(b[64 * i:64 * i + 64]) for i in range(4))
    _need(x0 or x1 or y0 or y1, 'identity')
    pt = (_bls.FQ2([x0, x1]), _bls.FQ2([y0, y1]), _bls.FQ2.one())  # EIP-2537: c0 first
    _need(_bls.is_on_curve(pt, _bls.b2), 'curve')
    _need(_bls.is_inf(_bls.multiply(pt, BLS_R)), 'subgroup')


def _u16(d, o):
    _need(len(d) >= o + 2, 'length')
    return (d[o] << 8) | d[o + 1]


def _musig2(d, check, size):
    n = _u16(d, size)
    _need(2 <= n <= 16, 'n')
    _need(len(d) == size + 2 + n * size, 'length')
    check(d[:size])
    for i in range(n):
        o = size + 2 + i * size
        check(d[o:o + size])
        if i:
            _need(d[o - size:o] < d[o:o + size], 'order')


def _frost(d, check, size, order):
    t, n = _u16(d, size), _u16(d, size + 2)
    _need(2 <= t <= n <= 16, 'threshold')
    per = (t + 1) * size + 32
    _need(len(d) == size + 4 + n * per, 'length')
    check(d[:size])
    for i in range(n):
        o = size + 4 + i * per
        for j in range(t + 1):  # t commitments, then R_i
            check(d[o + j * size:o + (j + 1) * size])
        _need(_int(d[o + (t + 1) * size:o + per]) < order, 'scalar')


def _msig(d, hedera_native):
    threshold, count = _u16(d, 0), _u16(d, 2)
    _need(1 <= count <= 16, 'count')
    _need(len(d) == 4 + 36 * count, 'length')
    total = 0
    for i in range(count):
        o = 4 + 36 * i
        kind, member_id, weight = _u16(d, o), d[o + 2:o + 34], _u16(d, o + 34)
        _need(is_member(kind, hedera_native), 'member-kind')
        _need(weight >= 1, 'weight')
        _need(is_native(kind) == (member_id[:12] == bytes(12)), 'member-id')
        if i:
            _need(d[o - 34:o - 2] < member_id, 'order')
        total += weight
    _need(1 <= threshold <= total, 'threshold')


def _fndsa(d):
    _need(d[0] == 0x09, 'header')
    bits = int.from_bytes(d[1:], 'big')
    for i in range(512):
        _need((bits >> (896 * 8 - 14 * (i + 1))) & 0x3FFF < 12289, 'coefficient')


def validate_key_data(kind, key_data, hedera_native=False):
    """Raises UAError('UAKeyData') unless key_data is the unique canonical encoding of a valid key or structure."""
    k = _derived(kind)
    d = bytes(key_data)
    if k[3]:
        _need(len(d) in k[3], 'length')
    if kind == 0x0100:
        _p256(d[:64])
    elif kind == 0x0101:
        _p256(d)
    elif kind == 0x0102:
        _ed25519(d)
    elif kind == 0x0103:
        _secp_x(_int(d))
    elif kind in (0x0104, 0x0140):
        _bn_g1(d)
    elif kind in (0x0105, 0x0141):
        _bls_g1(d)
    elif kind == 0x0106:
        _bls_g2(d)
    elif kind == 0x0107:
        _bn_g2(d)
    elif kind == 0x0110:
        _musig2(d, _secp_compressed, 33)
    elif kind == 0x0111:
        _frost(d, _secp_compressed, 33, SECP_N)
    elif kind == 0x0112:
        _musig2(d, _bn_g1, 64)
    elif kind == 0x0113:
        _frost(d, _bn_g1, 64, BN_R)
    elif kind == 0x0120:
        _msig(d, hedera_native)
    elif kind == 0x0132:
        _fndsa(d)
    # mldsa44/65, slhdsa128s, pqz-mlwe: the length is the whole check
```

- [ ] **Step 3: The test.** Create `clients/ua-py/tests/test_vectors.py`:

```python
"""scaas_ua against smartcontracts/vectors/ua/ (generated by clientkeys scripts/ua-vectors.mjs)."""
import json
import pathlib
import unittest

import scaas_ua as ua

VEC = pathlib.Path(__file__).resolve().parents[3] / 'smartcontracts' / 'vectors' / 'ua'
K = json.loads((VEC / 'kinds.json').read_text())
S = json.loads((VEC / 'structures.json').read_text())


def b(h):
    return bytes.fromhex(h[2:])


def hx(x):
    return '0x' + x.hex()


class Vectors(unittest.TestCase):
    def test_table_groups_purposes_constants(self):
        self.assertEqual(len(K['kinds']), len(ua.KINDS))
        for r in K['kinds']:
            n, name, native, lengths, group = ua.kind_info(r['kind'])
            self.assertEqual((name, native, list(lengths), group), (r['name'], r['native'], r['lengths'], r['group']))
            self.assertEqual(ua.is_signing(n), r['signing'], name)
            self.assertEqual(ua.is_zether(n), r['zether'], name)
            self.assertEqual(ua.is_member(n, False), r['member'], name)
            self.assertEqual(ua.is_member(n, True), r['memberHedera'], name)
            if native:
                with self.assertRaises(ua.UAError) as e:
                    ua.tag(n)
                self.assertEqual(e.exception.code, 'UAKindNotDerived')
            else:
                self.assertEqual(ua.kind_tag_string(n), r['tag'])
                self.assertEqual(hx(ua.tag(n)), r['TAG'])
        for r in K['groups']:
            self.assertEqual(ua.group_tag_string(r['group']), r['tag'])
            self.assertEqual(hx(ua.group_tag(r['group'])), r['GROUP'])
        self.assertEqual([r['purpose'] for r in K['purposes']], list(ua.PURPOSES))
        for r in K['purposes']:
            self.assertEqual(hx(ua.purpose_tag(r['purpose'])), r['purposeTag'])
        c = K['constants']
        self.assertEqual((hx(ua.MSG_TAG), hx(ua.POP_TAG), hx(ua.DOMAIN_TYPEHASH), hx(ua.UAAUTH_TYPEHASH), hx(ua.NAME_HASH)),
                         (c['MSG_TAG'], c['POP_TAG'], c['DOMAIN_TYPEHASH'], c['UAAUTH_TYPEHASH'], c['NAME_HASH']))

    def test_valid_rows(self):
        for r in K['valid']:
            d = b(r['keyData'])
            self.assertEqual(hx(ua.derive_ua(r['kind'], d, r['hederaNative'])), r['ua'], r['name'])
            h = ua.key_hash_of(r['kind'], d)
            self.assertEqual(h and hx(h), r['keyHash'], r['name'])

    def test_invalid_rows(self):
        for r in K['invalid']:
            with self.subTest(kind=r['kind'], reason=r['reason']):
                with self.assertRaises(ua.UAError) as e:
                    ua.validate_key_data(r['kind'], b(r['keyData']), r['hederaNative'])
                self.assertEqual(e.exception.code, r['error'])

    def test_natives_native_space_canonical_ids(self):
        for r in K['natives']:
            nid = ua.native_id(r['kind'], b(r['raw']))
            self.assertEqual(hx(nid), r['id'])
            self.assertEqual(ua.canonical_id(hx(nid)), r['canonical'])
        for r in K['nativeInvalid']:
            with self.assertRaises(ua.UAError) as e:
                ua.native_id(r['kind'], b(r['raw']))
            self.assertEqual(e.exception.code, r['error'])
        for r in K['nativeSpace']:
            self.assertEqual(ua.in_native_space(b(r['id'])), r['inNativeSpace'])
        for r in K['canonicalIds']:
            if 'canonical' in r:
                self.assertEqual(ua.canonical_id(r['input']), r['canonical'])
            else:
                with self.assertRaises(ua.UAError) as e:
                    ua.canonical_id(r['input'])
                self.assertEqual(e.exception.code, r['error'])

    def test_messages(self):
        for r in K['messages']:
            self.assertEqual(hx(ua.ua_message(r['kind'], ua.purpose_tag(r['purpose']), b(r['digest']))), r['uaMsg'])

    def test_structures(self):
        for p in S['pop']:
            c = S['contexts'][p['context']]
            self.assertEqual(hx(ua.chain_key_hash(c['chainId'])), p['chainKeyHash'])
            got = ua.pop_digest(c['chainId'], b(c['chainUid']), b(c['registry']), b(p['ua']), b(p['authRef']))
            self.assertEqual(hx(got), p['popDigest'])
        for a in S['uaAuth']:
            c = S['contexts'][a['context']]
            args = (a['generation'], c['chainId'], b(c['registry']), b(c['chainUid']))
            self.assertEqual(hx(ua.ua_auth_domain_separator(*args)), a['domainSeparator'])
            self.assertEqual(hx(ua.ua_auth_digest(*args, b(a['ua']), b(a['purposeTag']), b(a['digest']))), a['uaAuthDigest'])
        for m in S['member']:
            self.assertEqual(hx(ua.member_digest(b(m['structureUa']), b(m['uaMsg']))), m['memberDigest'])


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 4: Test.** `cd clients/ua-py && ../../scripts/capped python3 -m unittest -v tests.test_vectors` — 6 tests OK
  (the BLS and bn254 G2 subgroup checks in pure Python take a few seconds).

- [ ] **Step 5: CI.** In `.github/workflows/ci.yml` add:

```yaml
  ua-py:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: clients/ua-py
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: install
        run: pip install -r requirements.txt
      - name: vectors
        run: python -m unittest -v tests.test_vectors
```

- [ ] **Step 6: Commit.**

```bash
/usr/bin/git add clients/ua-py .gitignore .github/workflows/ci.yml
/usr/bin/git commit -m "UA-1 T4: clients/ua-py (Python UA identity layer) against the UA vectors" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 5: Go `clients/ua-go`

**Files:**
- Create: `clients/ua-go/go.mod`, `clients/ua-go/go.sum` (generated), `clients/ua-go/ua.go`, `clients/ua-go/keydata.go`,
  `clients/ua-go/ua_test.go`
- Modify: `.github/workflows/ci.yml` (job `ua-go`)

**Interfaces:**
- Consumes: the vector files (Task 1).
- Produces: package `ua` (module `github.com/dinhduongha/scaas/clients/ua-go`): `Error{Code, Reason}`, `Kind`, `Kinds`,
  `Groups`, `Purposes`, `KindInfo`, `IsNative`, `IsZether`, `IsSigning`, `IsMember`, `KindTagString`, `Tag`,
  `GroupTagString`, `GroupTag`, `MsgTag`, `PurposeTag`, `Keccak256`, `UAOf`, `InNativeSpace`, `DeriveUA`, `NativeID`,
  `KeyHashOf`, `ValidateKeyData`, `UAMessage`, `ChainKeyHash`, `PopDigest`, `Domain`, `UAAuthDomainSeparator`,
  `UAAuthDigest`, `MemberDigest`, `CanonicalID`, `EncodeMsig`, `Member`.

- [ ] **Step 1: Module.** Create `clients/ua-go/go.mod`:

```
module github.com/dinhduongha/scaas/clients/ua-go

go 1.22

require (
	filippo.io/edwards25519 v1.1.0
	github.com/consensys/gnark-crypto v0.16.0
	golang.org/x/crypto v0.32.0
)
```

  (`gnark-crypto` v0.16.0 is the newest release whose `go.mod` says `go 1.22`; `golang.org/x/crypto` v0.32.0 is the
  version it requires and still says `go 1.20`.) Then `cd clients/ua-go && ../../scripts/capped go mod tidy` after Step 3
  writes `go.sum` (and may add indirect requirements: keep what tidy writes).

- [ ] **Step 2: The identity layer.** Create `clients/ua-go/ua.go`:

```go
// Package ua is the SCaaS Universal Account identity layer (accounts.md §1.3–§1.6) for Go client systems: the kind table,
// ids, keyHash, purpose tags, ua_msg, popDigest, the registry's UAAuth digest, member digests, canonical ids and key-data
// validation. The same rules live in Solidity (UAKinds.sol), JS (clientkeys ua.js), Rust (scaas-ua), Python and C#;
// smartcontracts/vectors/ua pins all six. UNAUDITED.
package ua

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/sha3"
)

// Error carries the code every implementation and the vector files share (UAKeyData, UAKindUnknown, …).
type Error struct{ Code, Reason string }

func (e *Error) Error() string {
	if e.Reason == "" {
		return e.Code
	}
	return e.Code + ": " + e.Reason
}

func fail(code, reason string) error { return &Error{Code: code, Reason: reason} }

func keyDataErr(reason string) error { return &Error{Code: "UAKeyData", Reason: reason} }

// Kind is one row of the kind table; Lengths empty = variable-length key data; Group "" = none.
type Kind struct {
	Number  uint16
	Name    string
	Native  bool
	Lengths []int
	Group   string
}

var Kinds = []Kind{
	{0x0001, "evm-eoa", true, []int{20}, ""},
	{0x0002, "evm-contract", true, []int{20}, ""},
	{0x0003, "hedera-native", true, []int{20}, ""},
	{0x0010, "solana-ed25519", true, []int{32}, ""},
	{0x0011, "stellar-account", true, []int{32}, ""},
	{0x0012, "soroban-contract", true, []int{32}, ""},
	{0x0013, "aptos-account", true, []int{32}, ""},
	{0x0014, "sui-address", true, []int{32}, ""},
	{0x0015, "cosmos-account", true, []int{20, 32}, ""},
	{0x0016, "ton-wallet", true, []int{32}, ""},
	{0x0100, "webauthn-p256", false, []int{96}, "p256"},
	{0x0101, "p256", false, []int{64}, "p256"},
	{0x0102, "ed25519", false, []int{32}, "ed25519"},
	{0x0103, "bip340", false, []int{32}, "secp256k1"},
	{0x0104, "schnorr-bn254", false, []int{64}, "bn254-g1"},
	{0x0105, "schnorr-bls12381", false, []int{128}, "bls12381-g1"},
	{0x0106, "bls12381-minsig", false, []int{256}, "bls12381-g2"},
	{0x0107, "bls-bn254-minsig", false, []int{128}, "bn254-g2"},
	{0x0110, "musig2-secp256k1", false, nil, "secp256k1"},
	{0x0111, "frost-secp256k1", false, nil, "secp256k1"},
	{0x0112, "musig2-bn254", false, nil, "bn254-g1"},
	{0x0113, "frost-bn254", false, nil, "bn254-g1"},
	{0x0120, "msig", false, nil, ""},
	{0x0130, "mldsa44", false, []int{1312}, "mldsa44"},
	{0x0131, "mldsa65", false, []int{1952}, "mldsa65"},
	{0x0132, "fndsa512", false, []int{897}, "fndsa512"},
	{0x0133, "slhdsa128s", false, []int{32}, "slhdsa128s"},
	{0x0140, "zether-bn254", false, []int{64}, "bn254-g1"},
	{0x0141, "zether-bls12381", false, []int{128}, "bls12381-g1"},
	{0x0142, "pqz-mlwe", false, []int{16384}, "pqz-mlwe"},
}

var Groups = []string{"p256", "ed25519", "secp256k1", "bn254-g1", "bls12381-g1", "bls12381-g2", "bn254-g2", "mldsa44",
	"mldsa65", "fndsa512", "slhdsa128s", "pqz-mlwe"}

var Purposes = []string{"pop", "authref", "metatx", "metatx-cancel", "member", "zether-auth", "zether-owner", "keyop",
	"receiver-fee", "vp", "vc-anchor"}

const (
	DomainType   = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
	UAAuthType   = "UAAuth(bytes32 ua,bytes32 purpose,bytes32 digest)"
	RegistryName = "SCaaS UARegistry"
)

func Keccak256(parts ...[]byte) (out [32]byte) {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	copy(out[:], h.Sum(nil))
	return
}

var MsgTag = Keccak256([]byte("scaas.ua.msg.v1"))

func KindInfo(kind uint16) (*Kind, error) {
	for i := range Kinds {
		if Kinds[i].Number == kind {
			return &Kinds[i], nil
		}
	}
	return nil, fail("UAKindUnknown", fmt.Sprintf("0x%04x", kind))
}

func derived(kind uint16) (*Kind, error) {
	k, err := KindInfo(kind)
	if err != nil {
		return nil, err
	}
	if k.Native {
		return nil, fail("UAKindNotDerived", k.Name)
	}
	return k, nil
}

func singleSigning(k uint16) bool {
	return (k >= 0x0100 && k <= 0x0107) || (k >= 0x0110 && k <= 0x0113) || (k >= 0x0130 && k <= 0x0133)
}

func IsNative(kind uint16) bool { k, err := KindInfo(kind); return err == nil && k.Native }
func IsZether(kind uint16) bool { return kind >= 0x0140 && kind <= 0x0142 }
func IsSigning(kind uint16) bool { return kind == 0x0120 || singleSigning(kind) }
func IsMember(kind uint16, hederaNative bool) bool {
	return singleSigning(kind) || kind == 0x0001 || kind == 0x0002 || (hederaNative && kind == 0x0003)
}

func KindTagString(kind uint16) (string, error) {
	k, err := derived(kind)
	if err != nil {
		return "", err
	}
	return "scaas.ua." + k.Name + ".v1", nil
}

func Tag(kind uint16) ([32]byte, error) {
	s, err := KindTagString(kind)
	if err != nil {
		return [32]byte{}, err
	}
	return Keccak256([]byte(s)), nil
}

func GroupTagString(group string) (string, bool) {
	for _, g := range Groups {
		if g == group {
			return "scaas.ua.group." + g + ".v1", true
		}
	}
	return "", false
}

func GroupTag(group string) ([32]byte, bool) {
	s, ok := GroupTagString(group)
	if !ok {
		return [32]byte{}, false
	}
	return Keccak256([]byte(s)), true
}

func PurposeTag(purpose string) ([32]byte, error) {
	for _, p := range Purposes {
		if p == purpose {
			return Keccak256([]byte("scaas.ua.purpose." + p + ".v1")), nil
		}
	}
	return [32]byte{}, fail("UAPurposeUnknown", purpose)
}

// UAOf is keccak256(TAG(kind) ‖ keyData), without validation (see DeriveUA).
func UAOf(kind uint16, keyData []byte) ([32]byte, error) {
	t, err := Tag(kind)
	if err != nil {
		return t, err
	}
	return Keccak256(t[:], keyData), nil
}

func InNativeSpace(id [32]byte) bool {
	for _, b := range id[:12] {
		if b != 0 {
			return false
		}
	}
	return true
}

// DeriveUA validates, derives, and refuses an id whose top 96 bits are zero (CTR-UA-03).
func DeriveUA(kind uint16, keyData []byte, hederaNative bool) ([32]byte, error) {
	if err := ValidateKeyData(kind, keyData, hederaNative); err != nil {
		return [32]byte{}, err
	}
	u, err := UAOf(kind, keyData)
	if err != nil {
		return u, err
	}
	if InNativeSpace(u) {
		return [32]byte{}, fail("UAIdInNativeSpace", hex.EncodeToString(u[:]))
	}
	return u, nil
}

// NativeID left-pads a native id to 32 bytes.
func NativeID(kind uint16, raw []byte) (id [32]byte, err error) {
	k, err := KindInfo(kind)
	if err != nil {
		return id, err
	}
	if !k.Native {
		return id, fail("UAKindNotNative", k.Name)
	}
	for _, n := range k.Lengths {
		if n == len(raw) {
			copy(id[32-n:], raw)
			return id, nil
		}
	}
	return id, keyDataErr("length")
}

// KeyHashOf is keccak256(GROUP(g) ‖ canonical pubkey), nil for structures. Call on validated key data.
func KeyHashOf(kind uint16, keyData []byte) (*[32]byte, error) {
	k, err := derived(kind)
	if err != nil {
		return nil, err
	}
	if k.Group == "" {
		return nil, nil
	}
	lo, hi := 0, len(keyData)
	switch kind {
	case 0x0100, 0x0101:
		hi = 32
	case 0x0110, 0x0111:
		lo, hi = 1, 33
	case 0x0112, 0x0113:
		hi = 64
	}
	if hi > len(keyData) {
		return nil, keyDataErr("length")
	}
	g, _ := GroupTag(k.Group)
	h := Keccak256(g[:], keyData[lo:hi])
	return &h, nil
}

func UAMessage(kind uint16, purpose, digest [32]byte) ([32]byte, error) {
	t, err := Tag(kind)
	if err != nil {
		return t, err
	}
	return Keccak256(MsgTag[:], t[:], purpose[:], digest[:]), nil
}

func ChainKeyHash(chainID uint64) [32]byte {
	return Keccak256([]byte("evm:" + strconv.FormatUint(chainID, 10)))
}

func word(v uint64) []byte {
	w := make([]byte, 32)
	for i := 0; i < 8; i++ {
		w[31-i] = byte(v >> (8 * i))
	}
	return w
}

func addressWord(a [20]byte) []byte { return append(make([]byte, 12), a[:]...) }

// PopDigest is pop_digest (CTR-UA-07).
func PopDigest(chainID uint64, chainUID [32]byte, registry [20]byte, ua, authRef [32]byte) [32]byte {
	pop, _ := PurposeTag("pop")
	ckh := ChainKeyHash(chainID)
	return Keccak256(pop[:], ckh[:], chainUID[:], addressWord(registry), ua[:], authRef[:])
}

// Domain is the registry's EIP-712 domain ("SCaaS UARegistry", "<generation>", chainId, registry, salt = chainUid).
type Domain struct {
	Generation uint32
	ChainID    uint64
	Registry   [20]byte
	ChainUID   [32]byte
}

func UAAuthDomainSeparator(d Domain) [32]byte {
	t, n, v := Keccak256([]byte(DomainType)), Keccak256([]byte(RegistryName)), Keccak256([]byte(strconv.FormatUint(uint64(d.Generation), 10)))
	return Keccak256(t[:], n[:], v[:], word(d.ChainID), addressWord(d.Registry), d.ChainUID[:])
}

// UAAuthDigest is the EIP-712 digest of UAAuth(ua, purpose, digest): what native signers behind the registry sign.
func UAAuthDigest(d Domain, ua, purpose, digest [32]byte) [32]byte {
	t := Keccak256([]byte(UAAuthType))
	s := Keccak256(t[:], ua[:], purpose[:], digest[:])
	sep := UAAuthDomainSeparator(d)
	return Keccak256([]byte{0x19, 0x01}, sep[:], s[:])
}

func MemberDigest(structureUA, uaMsg [32]byte) [32]byte { return Keccak256(structureUA[:], uaMsg[:]) }

// CanonicalID returns lower-case hex; a 32-byte id with the top 96 bits zero is written as its 20-byte native id.
func CanonicalID(text string) (string, error) {
	h, ok := strings.CutPrefix(text, "0x")
	if !ok || (len(h) != 40 && len(h) != 64) {
		return "", fail("UAIdFormat", text)
	}
	if _, err := hex.DecodeString(h); err != nil {
		return "", fail("UAIdFormat", text)
	}
	h = strings.ToLower(h)
	if len(h) == 64 && strings.HasPrefix(h, strings.Repeat("0", 24)) {
		h = h[24:]
	}
	return "0x" + h, nil
}

// Member is one msig member.
type Member struct {
	Kind   uint16
	ID     [32]byte
	Weight uint16
}

// EncodeMsig is u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight).
func EncodeMsig(threshold uint16, members []Member) []byte {
	out := []byte{byte(threshold >> 8), byte(threshold), byte(len(members) >> 8), byte(len(members))}
	for _, m := range members {
		out = append(out, byte(m.Kind>>8), byte(m.Kind))
		out = append(out, m.ID[:]...)
		out = append(out, byte(m.Weight>>8), byte(m.Weight))
	}
	return out
}
```

- [ ] **Step 3: Validation.** Create `clients/ua-go/keydata.go`:

```go
package ua

import (
	"bytes"
	"math/big"

	"filippo.io/edwards25519"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	blsfp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func mustHex(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic(s)
	}
	return v
}

var (
	secpP  = mustHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
	secpN  = mustHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	p256P  = mustHex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
	p256B  = mustHex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
	bnR    = mustHex("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001")
	three  = big.NewInt(3)
	seven  = big.NewInt(7)
)

func need(ok bool, reason string) error {
	if ok {
		return nil
	}
	return keyDataErr(reason)
}

func isZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func secpX(x []byte) error {
	X := new(big.Int).SetBytes(x)
	if X.Cmp(secpP) >= 0 {
		return keyDataErr("range")
	}
	rhs := new(big.Int).Exp(X, three, secpP)
	rhs.Add(rhs, seven).Mod(rhs, secpP)
	return need(new(big.Int).ModSqrt(rhs, secpP) != nil, "curve")
}

func secpCompressed(b []byte) error {
	if b[0] != 2 && b[0] != 3 {
		return keyDataErr("prefix")
	}
	return secpX(b[1:33])
}

func p256Point(xy []byte) error {
	x, y := new(big.Int).SetBytes(xy[:32]), new(big.Int).SetBytes(xy[32:64])
	if x.Cmp(p256P) >= 0 || y.Cmp(p256P) >= 0 {
		return keyDataErr("range")
	}
	rhs := new(big.Int).Exp(x, three, p256P)
	rhs.Sub(rhs, new(big.Int).Mul(three, x)).Add(rhs, p256B).Mod(rhs, p256P)
	return need(new(big.Int).Exp(y, big.NewInt(2), p256P).Cmp(rhs) == 0, "curve")
}

func ed25519Key(b []byte) error {
	p, err := new(edwards25519.Point).SetBytes(b)
	if err != nil {
		return keyDataErr("curve")
	}
	// SetBytes accepts y ≥ p and a negative zero x; the re-encoding is canonical, so compare
	if !bytes.Equal(p.Bytes(), b) {
		return keyDataErr("canonical")
	}
	return need(new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) != 1, "small-order")
}

func bnG1(b []byte) error {
	if isZero(b) {
		return keyDataErr("identity")
	}
	var p bn254.G1Affine
	if p.X.SetBytesCanonical(b[:32]) != nil || p.Y.SetBytesCanonical(b[32:64]) != nil {
		return keyDataErr("range")
	}
	return need(p.IsOnCurve(), "curve")
}

func bnG2(b []byte) error {
	if isZero(b) {
		return keyDataErr("identity")
	}
	var p bn254.G2Affine // EIP-197 order: imaginary part (A1) first
	if p.X.A1.SetBytesCanonical(b[:32]) != nil || p.X.A0.SetBytesCanonical(b[32:64]) != nil ||
		p.Y.A1.SetBytesCanonical(b[64:96]) != nil || p.Y.A0.SetBytesCanonical(b[96:128]) != nil {
		return keyDataErr("range")
	}
	if !p.IsOnCurve() {
		return keyDataErr("curve")
	}
	return need(p.IsInSubGroup(), "subgroup")
}

func blsFp(e *blsfp.Element, b []byte) error {
	if !isZero(b[:16]) {
		return keyDataErr("padding")
	}
	return need(e.SetBytesCanonical(b[16:64]) == nil, "range")
}

func blsG1(b []byte) error {
	if isZero(b) {
		return keyDataErr("identity")
	}
	var p bls12381.G1Affine
	for i, e := range []*blsfp.Element{&p.X, &p.Y} {
		if err := blsFp(e, b[64*i:64*i+64]); err != nil {
			return err
		}
	}
	if !p.IsOnCurve() {
		return keyDataErr("curve")
	}
	return need(p.IsInSubGroup(), "subgroup")
}

func blsG2(b []byte) error {
	if isZero(b) {
		return keyDataErr("identity")
	}
	var p bls12381.G2Affine // EIP-2537 order: c0 (A0) first
	for i, e := range []*blsfp.Element{&p.X.A0, &p.X.A1, &p.Y.A0, &p.Y.A1} {
		if err := blsFp(e, b[64*i:64*i+64]); err != nil {
			return err
		}
	}
	if !p.IsOnCurve() {
		return keyDataErr("curve")
	}
	return need(p.IsInSubGroup(), "subgroup")
}

func u16At(d []byte, o int) (int, error) {
	if len(d) < o+2 {
		return 0, keyDataErr("length")
	}
	return int(d[o])<<8 | int(d[o+1]), nil
}

// musig2: Q ‖ u16 n ‖ n × P_i, 2 ≤ n ≤ 16, P_i strictly increasing.
func musig2(d []byte, point func([]byte) error, size int) error {
	n, err := u16At(d, size)
	if err != nil {
		return err
	}
	if n < 2 || n > 16 {
		return keyDataErr("n")
	}
	if len(d) != size+2+n*size {
		return keyDataErr("length")
	}
	if err := point(d[:size]); err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		o := size + 2 + i*size
		if err := point(d[o : o+size]); err != nil {
			return err
		}
		if i > 0 && bytes.Compare(d[o-size:o], d[o:o+size]) >= 0 {
			return keyDataErr("order")
		}
	}
	return nil
}

// frost: Y ‖ u16 t ‖ u16 n ‖ n × (t × C_ik ‖ R_i ‖ μ_i), 2 ≤ t ≤ n ≤ 16, μ_i < order.
func frost(d []byte, point func([]byte) error, size int, order *big.Int) error {
	t, err := u16At(d, size)
	if err != nil {
		return err
	}
	n, err := u16At(d, size+2)
	if err != nil {
		return err
	}
	if t < 2 || t > n || n > 16 {
		return keyDataErr("threshold")
	}
	per := (t+1)*size + 32
	if len(d) != size+4+n*per {
		return keyDataErr("length")
	}
	if err := point(d[:size]); err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		o := size + 4 + i*per
		for j := 0; j <= t; j++ { // t commitments, then R_i
			if err := point(d[o+j*size : o+(j+1)*size]); err != nil {
				return err
			}
		}
		if new(big.Int).SetBytes(d[o+(t+1)*size:o+per]).Cmp(order) >= 0 {
			return keyDataErr("scalar")
		}
	}
	return nil
}

// msig: u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight) (CTR-UA-09).
func msig(d []byte, hederaNative bool) error {
	threshold, err := u16At(d, 0)
	if err != nil {
		return err
	}
	count, err := u16At(d, 2)
	if err != nil {
		return err
	}
	if count < 1 || count > 16 {
		return keyDataErr("count")
	}
	if len(d) != 4+36*count {
		return keyDataErr("length")
	}
	total := 0
	for i := 0; i < count; i++ {
		o := 4 + 36*i
		kind := uint16(d[o])<<8 | uint16(d[o+1])
		var id [32]byte
		copy(id[:], d[o+2:o+34])
		weight := int(d[o+34])<<8 | int(d[o+35])
		if !IsMember(kind, hederaNative) {
			return keyDataErr("member-kind")
		}
		if weight < 1 {
			return keyDataErr("weight")
		}
		if IsNative(kind) != InNativeSpace(id) {
			return keyDataErr("member-id")
		}
		if i > 0 && bytes.Compare(d[o-34:o-2], id[:]) >= 0 {
			return keyDataErr("order")
		}
		total += weight
	}
	return need(threshold >= 1 && threshold <= total, "threshold")
}

// fndsa: 0x09 ‖ 512 × 14-bit h_i (big-endian bit packing), each < 12289.
func fndsa(d []byte) error {
	if d[0] != 0x09 {
		return keyDataErr("header")
	}
	for i := 0; i < 512; i++ {
		v := 0
		for j := 0; j < 14; j++ {
			k := i*14 + j
			v = v<<1 | int(d[1+k/8]>>(7-uint(k%8))&1)
		}
		if v >= 12289 {
			return keyDataErr("coefficient")
		}
	}
	return nil
}

// ValidateKeyData returns a UAKeyData error unless keyData is the unique canonical encoding of a valid key or structure.
func ValidateKeyData(kind uint16, d []byte, hederaNative bool) error {
	k, err := derived(kind)
	if err != nil {
		return err
	}
	if len(k.Lengths) > 0 {
		ok := false
		for _, n := range k.Lengths {
			ok = ok || n == len(d)
		}
		if !ok {
			return keyDataErr("length")
		}
	}
	switch kind {
	case 0x0100:
		return p256Point(d[:64])
	case 0x0101:
		return p256Point(d)
	case 0x0102:
		return ed25519Key(d)
	case 0x0103:
		return secpX(d)
	case 0x0104, 0x0140:
		return bnG1(d)
	case 0x0105, 0x0141:
		return blsG1(d)
	case 0x0106:
		return blsG2(d)
	case 0x0107:
		return bnG2(d)
	case 0x0110:
		return musig2(d, secpCompressed, 33)
	case 0x0111:
		return frost(d, secpCompressed, 33, secpN)
	case 0x0112:
		return musig2(d, bnG1, 64)
	case 0x0113:
		return frost(d, bnG1, 64, bnR)
	case 0x0120:
		return msig(d, hederaNative)
	case 0x0132:
		return fndsa(d)
	}
	return nil // mldsa44/65, slhdsa128s, pqz-mlwe: the length is the whole check
}
```

- [ ] **Step 4: The test.** Create `clients/ua-go/ua_test.go`:

```go
package ua

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type obj = map[string]any

func load(t *testing.T, name string) obj {
	raw, err := os.ReadFile("../../smartcontracts/vectors/ua/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var v obj
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func rows(v obj, k string) []obj {
	out := []obj{}
	for _, r := range v[k].([]any) {
		out = append(out, r.(obj))
	}
	return out
}

func bs(v any) []byte {
	b, err := hex.DecodeString(strings.TrimPrefix(v.(string), "0x"))
	if err != nil {
		panic(err)
	}
	return b
}
func b32(v any) (o [32]byte) { copy(o[:], bs(v)); return }
func b20(v any) (o [20]byte) { copy(o[:], bs(v)); return }
func hx(b []byte) string     { return "0x" + hex.EncodeToString(b) }
func kind(v any) uint16      { return uint16(v.(float64)) }

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return "no UAError: " + err.Error()
}

func TestTableGroupsPurposesConstants(t *testing.T) {
	k := load(t, "kinds.json")
	if len(rows(k, "kinds")) != len(Kinds) {
		t.Fatal("kind count")
	}
	for _, r := range rows(k, "kinds") {
		n := kind(r["kind"])
		info, err := KindInfo(n)
		if err != nil || info.Name != r["name"] || info.Native != r["native"] {
			t.Fatalf("kind %#x", n)
		}
		want := []int{}
		for _, l := range r["lengths"].([]any) {
			want = append(want, int(l.(float64)))
		}
		if len(want) != len(info.Lengths) {
			t.Fatalf("%s lengths", info.Name)
		}
		for i := range want {
			if want[i] != info.Lengths[i] {
				t.Fatalf("%s lengths", info.Name)
			}
		}
		group, _ := r["group"].(string)
		if info.Group != group || IsSigning(n) != r["signing"] || IsZether(n) != r["zether"] ||
			IsMember(n, false) != r["member"] || IsMember(n, true) != r["memberHedera"] {
			t.Fatalf("%s sets or group", info.Name)
		}
		if info.Native {
			if _, err := Tag(n); code(err) != "UAKindNotDerived" {
				t.Fatalf("%s tag", info.Name)
			}
			continue
		}
		s, _ := KindTagString(n)
		tg, _ := Tag(n)
		if s != r["tag"] || hx(tg[:]) != r["TAG"] {
			t.Fatalf("%s tag", info.Name)
		}
	}
	for _, r := range rows(k, "groups") {
		s, _ := GroupTagString(r["group"].(string))
		g, _ := GroupTag(r["group"].(string))
		if s != r["tag"] || hx(g[:]) != r["GROUP"] {
			t.Fatalf("group %s", r["group"])
		}
	}
	for _, r := range rows(k, "purposes") {
		p, err := PurposeTag(r["purpose"].(string))
		if err != nil || hx(p[:]) != r["purposeTag"] {
			t.Fatalf("purpose %s", r["purpose"])
		}
	}
	c := k["constants"].(obj)
	pop, _ := PurposeTag("pop")
	dt, at, nh := Keccak256([]byte(DomainType)), Keccak256([]byte(UAAuthType)), Keccak256([]byte(RegistryName))
	if hx(MsgTag[:]) != c["MSG_TAG"] || hx(pop[:]) != c["POP_TAG"] || hx(dt[:]) != c["DOMAIN_TYPEHASH"] ||
		hx(at[:]) != c["UAAUTH_TYPEHASH"] || hx(nh[:]) != c["NAME_HASH"] {
		t.Fatal("constants")
	}
}

func TestValidRows(t *testing.T) {
	for _, r := range rows(load(t, "kinds.json"), "valid") {
		n, d := kind(r["kind"]), bs(r["keyData"])
		u, err := DeriveUA(n, d, r["hederaNative"].(bool))
		if err != nil || hx(u[:]) != r["ua"] {
			t.Fatalf("%s: %v", r["name"], err)
		}
		h, err := KeyHashOf(n, d)
		if err != nil {
			t.Fatal(err)
		}
		if (h == nil) != (r["keyHash"] == nil) || (h != nil && hx(h[:]) != r["keyHash"]) {
			t.Fatalf("%s keyHash", r["name"])
		}
	}
}

func TestInvalidRows(t *testing.T) {
	for _, r := range rows(load(t, "kinds.json"), "invalid") {
		err := ValidateKeyData(kind(r["kind"]), bs(r["keyData"]), r["hederaNative"].(bool))
		if err == nil || code(err) != r["error"] {
			t.Errorf("%v %s: got %v", r["kind"], r["reason"], err)
		}
	}
}

func TestNativesNativeSpaceCanonicalIDs(t *testing.T) {
	k := load(t, "kinds.json")
	for _, r := range rows(k, "natives") {
		id, err := NativeID(kind(r["kind"]), bs(r["raw"]))
		c, _ := CanonicalID(hx(id[:]))
		if err != nil || hx(id[:]) != r["id"] || c != r["canonical"] {
			t.Fatalf("native %v", r["kind"])
		}
	}
	for _, r := range rows(k, "nativeInvalid") {
		if _, err := NativeID(kind(r["kind"]), bs(r["raw"])); err == nil || code(err) != r["error"] {
			t.Fatalf("nativeInvalid %v", r["kind"])
		}
	}
	for _, r := range rows(k, "nativeSpace") {
		if InNativeSpace(b32(r["id"])) != r["inNativeSpace"] {
			t.Fatalf("nativeSpace %s", r["id"])
		}
	}
	for _, r := range rows(k, "canonicalIds") {
		got, err := CanonicalID(r["input"].(string))
		if want, ok := r["canonical"]; ok {
			if err != nil || got != want {
				t.Fatalf("canonical %q", r["input"])
			}
		} else if err == nil || code(err) != r["error"] {
			t.Fatalf("canonical %q accepted", r["input"])
		}
	}
}

func TestMessages(t *testing.T) {
	for _, r := range rows(load(t, "kinds.json"), "messages") {
		p, _ := PurposeTag(r["purpose"].(string))
		m, err := UAMessage(kind(r["kind"]), p, b32(r["digest"]))
		if err != nil || hx(m[:]) != r["uaMsg"] {
			t.Fatalf("message %v %s", r["kind"], r["purpose"])
		}
	}
}

func TestStructures(t *testing.T) {
	s := load(t, "structures.json")
	ctx := s["contexts"].(obj)
	for _, p := range rows(s, "pop") {
		c := ctx[p["context"].(string)].(obj)
		id := uint64(c["chainId"].(float64))
		ckh := ChainKeyHash(id)
		got := PopDigest(id, b32(c["chainUid"]), b20(c["registry"]), b32(p["ua"]), b32(p["authRef"]))
		if hx(ckh[:]) != p["chainKeyHash"] || hx(got[:]) != p["popDigest"] {
			t.Fatalf("pop %s", p["context"])
		}
	}
	for _, a := range rows(s, "uaAuth") {
		c := ctx[a["context"].(string)].(obj)
		d := Domain{uint32(a["generation"].(float64)), uint64(c["chainId"].(float64)), b20(c["registry"]), b32(c["chainUid"])}
		sep := UAAuthDomainSeparator(d)
		got := UAAuthDigest(d, b32(a["ua"]), b32(a["purposeTag"]), b32(a["digest"]))
		if hx(sep[:]) != a["domainSeparator"] || hx(got[:]) != a["uaAuthDigest"] {
			t.Fatalf("uaAuth %s %v", a["context"], a["generation"])
		}
	}
	for _, m := range rows(s, "member") {
		got := MemberDigest(b32(m["structureUa"]), b32(m["uaMsg"]))
		if hx(got[:]) != m["memberDigest"] {
			t.Fatal("member")
		}
	}
}
```

- [ ] **Step 5: Test.** `cd clients/ua-go && ../../scripts/capped go mod tidy && ../../scripts/capped go vet ./... &&
  ../../scripts/capped go test ./...` — `ok`, 6 tests. If a gnark-crypto v0.16.0 method has another name
  (`SetBytesCanonical`, `IsInSubGroup`), use the v0.16.0 name with the same meaning and report it.

- [ ] **Step 6: CI.** In `.github/workflows/ci.yml` add:

```yaml
  ua-go:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: clients/ua-go
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
          cache-dependency-path: clients/ua-go/go.sum
      - name: vet
        run: go vet ./...
      - name: vectors
        run: go test ./...
```

- [ ] **Step 7: Commit.**

```bash
/usr/bin/git add clients/ua-go .github/workflows/ci.yml
/usr/bin/git commit -m "UA-1 T5: clients/ua-go (Go UA identity layer) against the UA vectors" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 6: C# `clients/ua-cs`

**Files:**
- Create: `clients/ua-cs/Scaas.Ua/Scaas.Ua.csproj`, `clients/ua-cs/Scaas.Ua/Ua.cs`, `clients/ua-cs/Scaas.Ua/KeyData.cs`,
  `clients/ua-cs/Scaas.Ua.Tests/Scaas.Ua.Tests.csproj`, `clients/ua-cs/Scaas.Ua.Tests/VectorTests.cs`,
  `clients/ua-cs/.gitignore`
- Modify: `.github/workflows/ci.yml` (job `ua-cs`)

**Interfaces:**
- Consumes: the vector files (Task 1).
- Produces: namespace `Scaas.Ua`: `UAException` (`Code`, `Reason`), `Kind`, static class `UA` with `Kinds`, `Groups`,
  `Purposes`, `KindInfo`, `IsNative`, `IsZether`, `IsSigning`, `IsMember`, `KindTagString`, `Tag`, `GroupTagString`,
  `GroupTag`, `MsgTag`, `PurposeTag`, `Keccak256`, `UAOf`, `InNativeSpace`, `DeriveUA`, `NativeId`, `KeyHashOf`,
  `ValidateKeyData`, `UAMessage`, `ChainKeyHash`, `PopDigest`, `Domain`, `UAAuthDomainSeparator`, `UAAuthDigest`,
  `MemberDigest`, `CanonicalId`, `EncodeMsig`.

- [ ] **Step 1: Projects.** `clients/ua-cs/Scaas.Ua/Scaas.Ua.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <Description>SCaaS Universal Account identity layer (kind table, ids, keyHash, ua_msg, popDigest, UAAuth, key-data validation). UNAUDITED.</Description>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="BouncyCastle.Cryptography" Version="2.6.2" />
  </ItemGroup>
</Project>
```

  `clients/ua-cs/Scaas.Ua.Tests/Scaas.Ua.Tests.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <IsPackable>false</IsPackable>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.14.1" />
    <PackageReference Include="xunit" Version="2.9.3" />
    <PackageReference Include="xunit.runner.visualstudio" Version="3.1.4" />
  </ItemGroup>
  <ItemGroup>
    <ProjectReference Include="../Scaas.Ua/Scaas.Ua.csproj" />
  </ItemGroup>
</Project>
```

  `clients/ua-cs/.gitignore`:

```
bin/
obj/
TestResults/
```

- [ ] **Step 2: The identity layer.** Create `clients/ua-cs/Scaas.Ua/Ua.cs`:

```csharp
// SCaaS Universal Account identity layer (accounts.md §1.3–§1.6) for .NET client systems: the kind table, ids, keyHash,
// purpose tags, ua_msg, popDigest, the registry's UAAuth digest, member digests, canonical ids and key-data validation.
// The same rules live in Solidity (UAKinds.sol), JS (clientkeys ua.js), Rust (scaas-ua), Python and Go;
// smartcontracts/vectors/ua pins all six. UNAUDITED.
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Digests;

namespace Scaas.Ua;

/// <summary>An error whose <see cref="Code"/> every implementation and the vector files share.</summary>
public sealed class UAException(string code, string? reason = null)
    : Exception(reason is null ? code : $"{code}: {reason}")
{
    public string Code { get; } = code;
    public string? Reason { get; } = reason;
}

/// <summary>One row of the kind table; <c>Lengths</c> empty = variable-length key data; <c>Group</c> null = none.</summary>
public sealed record Kind(ushort Number, string Name, bool Native, int[] Lengths, string? Group);

public static partial class UA
{
    public static readonly Kind[] Kinds =
    [
        new(0x0001, "evm-eoa", true, [20], null),
        new(0x0002, "evm-contract", true, [20], null),
        new(0x0003, "hedera-native", true, [20], null),
        new(0x0010, "solana-ed25519", true, [32], null),
        new(0x0011, "stellar-account", true, [32], null),
        new(0x0012, "soroban-contract", true, [32], null),
        new(0x0013, "aptos-account", true, [32], null),
        new(0x0014, "sui-address", true, [32], null),
        new(0x0015, "cosmos-account", true, [20, 32], null),
        new(0x0016, "ton-wallet", true, [32], null),
        new(0x0100, "webauthn-p256", false, [96], "p256"),
        new(0x0101, "p256", false, [64], "p256"),
        new(0x0102, "ed25519", false, [32], "ed25519"),
        new(0x0103, "bip340", false, [32], "secp256k1"),
        new(0x0104, "schnorr-bn254", false, [64], "bn254-g1"),
        new(0x0105, "schnorr-bls12381", false, [128], "bls12381-g1"),
        new(0x0106, "bls12381-minsig", false, [256], "bls12381-g2"),
        new(0x0107, "bls-bn254-minsig", false, [128], "bn254-g2"),
        new(0x0110, "musig2-secp256k1", false, [], "secp256k1"),
        new(0x0111, "frost-secp256k1", false, [], "secp256k1"),
        new(0x0112, "musig2-bn254", false, [], "bn254-g1"),
        new(0x0113, "frost-bn254", false, [], "bn254-g1"),
        new(0x0120, "msig", false, [], null),
        new(0x0130, "mldsa44", false, [1312], "mldsa44"),
        new(0x0131, "mldsa65", false, [1952], "mldsa65"),
        new(0x0132, "fndsa512", false, [897], "fndsa512"),
        new(0x0133, "slhdsa128s", false, [32], "slhdsa128s"),
        new(0x0140, "zether-bn254", false, [64], "bn254-g1"),
        new(0x0141, "zether-bls12381", false, [128], "bls12381-g1"),
        new(0x0142, "pqz-mlwe", false, [16384], "pqz-mlwe"),
    ];

    public static readonly string[] Groups =
        ["p256", "ed25519", "secp256k1", "bn254-g1", "bls12381-g1", "bls12381-g2", "bn254-g2", "mldsa44", "mldsa65",
         "fndsa512", "slhdsa128s", "pqz-mlwe"];

    public static readonly string[] Purposes =
        ["pop", "authref", "metatx", "metatx-cancel", "member", "zether-auth", "zether-owner", "keyop", "receiver-fee", "vp",
         "vc-anchor"];

    public const string DomainType =
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)";
    public const string UAAuthType = "UAAuth(bytes32 ua,bytes32 purpose,bytes32 digest)";
    public const string RegistryName = "SCaaS UARegistry";

    public static byte[] Keccak256(params byte[][] parts)
    {
        var d = new KeccakDigest(256);
        foreach (var p in parts) d.BlockUpdate(p, 0, p.Length);
        var o = new byte[32];
        d.DoFinal(o, 0);
        return o;
    }

    static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    public static readonly byte[] MsgTag = Keccak256(Utf8("scaas.ua.msg.v1"));

    public static Kind KindInfo(ushort kind) =>
        Array.Find(Kinds, k => k.Number == kind) ?? throw new UAException("UAKindUnknown", $"0x{kind:x4}");

    static Kind Derived(ushort kind)
    {
        var k = KindInfo(kind);
        return k.Native ? throw new UAException("UAKindNotDerived", k.Name) : k;
    }

    static bool SingleSigning(ushort k) => k is (>= 0x0100 and <= 0x0107) or (>= 0x0110 and <= 0x0113) or (>= 0x0130 and <= 0x0133);
    public static bool IsNative(ushort kind) => Array.Exists(Kinds, k => k.Number == kind && k.Native);
    public static bool IsZether(ushort kind) => kind is >= 0x0140 and <= 0x0142;
    public static bool IsSigning(ushort kind) => kind == 0x0120 || SingleSigning(kind);
    public static bool IsMember(ushort kind, bool hederaNative = false) =>
        SingleSigning(kind) || kind is 0x0001 or 0x0002 || (hederaNative && kind == 0x0003);

    public static string KindTagString(ushort kind) => $"scaas.ua.{Derived(kind).Name}.v1";
    public static byte[] Tag(ushort kind) => Keccak256(Utf8(KindTagString(kind)));

    public static string GroupTagString(string group) =>
        Array.IndexOf(Groups, group) >= 0 ? $"scaas.ua.group.{group}.v1" : throw new ArgumentException($"unknown keyHash group {group}");
    public static byte[] GroupTag(string group) => Keccak256(Utf8(GroupTagString(group)));

    public static byte[] PurposeTag(string purpose) =>
        Array.IndexOf(Purposes, purpose) >= 0 ? Keccak256(Utf8($"scaas.ua.purpose.{purpose}.v1")) : throw new UAException("UAPurposeUnknown", purpose);

    static byte[] Sized(byte[] b, int n, string what) => b.Length == n ? b : throw new ArgumentException($"{what} must be {n} bytes");

    /// <summary><c>keccak256(TAG(kind) ‖ keyData)</c>; no validation (see <see cref="DeriveUA"/>).</summary>
    public static byte[] UAOf(ushort kind, byte[] keyData) => Keccak256(Tag(kind), keyData);

    public static bool InNativeSpace(byte[] id) => Sized(id, 32, "id").AsSpan(0, 12).IndexOfAnyExcept((byte)0) < 0;

    /// <summary>Validate, derive, refuse an id whose top 96 bits are zero (CTR-UA-03).</summary>
    public static byte[] DeriveUA(ushort kind, byte[] keyData, bool hederaNative = false)
    {
        ValidateKeyData(kind, keyData, hederaNative);
        var ua = UAOf(kind, keyData);
        return InNativeSpace(ua) ? throw new UAException("UAIdInNativeSpace", Convert.ToHexStringLower(ua)) : ua;
    }

    /// <summary>A native id left-padded to 32 bytes.</summary>
    public static byte[] NativeId(ushort kind, byte[] raw)
    {
        var k = KindInfo(kind);
        if (!k.Native) throw new UAException("UAKindNotNative", k.Name);
        if (Array.IndexOf(k.Lengths, raw.Length) < 0) throw new UAException("UAKeyData", "length");
        var id = new byte[32];
        raw.CopyTo(id, 32 - raw.Length);
        return id;
    }

    /// <summary><c>keccak256(GROUP(g) ‖ canonical pubkey)</c>, null for structures. Call on validated key data.</summary>
    public static byte[]? KeyHashOf(ushort kind, byte[] keyData)
    {
        var k = Derived(kind);
        if (k.Group is null) return null;
        var (lo, hi) = kind switch
        {
            0x0100 or 0x0101 => (0, 32),
            0x0110 or 0x0111 => (1, 33),
            0x0112 or 0x0113 => (0, 64),
            _ => (0, keyData.Length),
        };
        if (keyData.Length < hi) throw new UAException("UAKeyData", "length");
        return Keccak256(GroupTag(k.Group), keyData[lo..hi]);
    }

    public static byte[] UAMessage(ushort kind, byte[] purpose, byte[] digest) =>
        Keccak256(MsgTag, Tag(kind), Sized(purpose, 32, "purposeTag"), Sized(digest, 32, "digest"));

    public static byte[] ChainKeyHash(ulong chainId) => Keccak256(Utf8("evm:" + chainId.ToString(CultureInfo.InvariantCulture)));

    static byte[] Word(ulong v)
    {
        var w = new byte[32];
        for (var i = 0; i < 8; i++) w[31 - i] = (byte)(v >> (8 * i));
        return w;
    }

    static byte[] AddressWord(byte[] a)
    {
        var w = new byte[32];
        Sized(a, 20, "registry").CopyTo(w, 12);
        return w;
    }

    /// <summary><c>pop_digest</c> (CTR-UA-07).</summary>
    public static byte[] PopDigest(ulong chainId, byte[] chainUid, byte[] registry, byte[] ua, byte[] authRef) =>
        Keccak256(PurposeTag("pop"), ChainKeyHash(chainId), Sized(chainUid, 32, "chainUid"), AddressWord(registry),
            Sized(ua, 32, "ua"), Sized(authRef, 32, "authRef"));

    /// <summary>The registry's EIP-712 domain ("SCaaS UARegistry", "&lt;generation&gt;", chainId, registry, salt = chainUid).</summary>
    public sealed record Domain(uint Generation, ulong ChainId, byte[] Registry, byte[] ChainUid);

    public static byte[] UAAuthDomainSeparator(Domain d) =>
        Keccak256(Keccak256(Utf8(DomainType)), Keccak256(Utf8(RegistryName)),
            Keccak256(Utf8(d.Generation.ToString(CultureInfo.InvariantCulture))), Word(d.ChainId), AddressWord(d.Registry),
            Sized(d.ChainUid, 32, "chainUid"));

    /// <summary>EIP-712 digest of <c>UAAuth(ua, purpose, digest)</c>: what native signers behind the registry sign.</summary>
    public static byte[] UAAuthDigest(Domain d, byte[] ua, byte[] purpose, byte[] digest) =>
        Keccak256(new byte[] { 0x19, 0x01 }, UAAuthDomainSeparator(d),
            Keccak256(Keccak256(Utf8(UAAuthType)), Sized(ua, 32, "ua"), Sized(purpose, 32, "purposeTag"), Sized(digest, 32, "digest")));

    public static byte[] MemberDigest(byte[] structureUa, byte[] uaMsg) =>
        Keccak256(Sized(structureUa, 32, "structureUa"), Sized(uaMsg, 32, "uaMsg"));

    [GeneratedRegex(@"\A0x([0-9a-fA-F]{40}|[0-9a-fA-F]{64})\z")]
    private static partial Regex IdPattern();

    /// <summary>Lower-case hex; a 32-byte id with the top 96 bits zero is written as its 20-byte native id (CTR-UA-03).</summary>
    public static string CanonicalId(string text)
    {
        var m = IdPattern().Match(text);
        if (!m.Success) throw new UAException("UAIdFormat", text);
        var h = m.Groups[1].Value.ToLowerInvariant();
        return "0x" + (h.Length == 64 && h.StartsWith(new string('0', 24), StringComparison.Ordinal) ? h[24..] : h);
    }

    /// <summary><c>u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight)</c>.</summary>
    public static byte[] EncodeMsig(ushort threshold, IReadOnlyList<(ushort Kind, byte[] Id, ushort Weight)> members)
    {
        var o = new List<byte> { (byte)(threshold >> 8), (byte)threshold, (byte)(members.Count >> 8), (byte)members.Count };
        foreach (var (kind, id, weight) in members)
        {
            o.Add((byte)(kind >> 8));
            o.Add((byte)kind);
            o.AddRange(Sized(id, 32, "member id"));
            o.Add((byte)(weight >> 8));
            o.Add((byte)weight);
        }
        return [.. o];
    }
}
```

- [ ] **Step 3: Validation.** Create `clients/ua-cs/Scaas.Ua/KeyData.cs`:

```csharp
// Key-data validation (accounts.md §1.6 "Validation at registration") over System.Numerics.BigInteger: affine short
// Weierstrass arithmetic on y² = x³ + b over Fp and Fp2 (u² = −1) for curve and subgroup checks, twisted Edwards for
// ed25519. Public inputs only: nothing here is constant-time. Never indexes past the key data: every length is checked.
using System.Globalization;
using System.Numerics;

namespace Scaas.Ua;

public static partial class UA
{
    static BigInteger Hex(string h) => BigInteger.Parse("0" + h, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
    static BigInteger Be(ReadOnlySpan<byte> b) => new(b, isUnsigned: true, isBigEndian: true);
    static BigInteger Mod(BigInteger a, BigInteger p) { var r = a % p; return r.Sign < 0 ? r + p : r; }
    static BigInteger Inv(BigInteger a, BigInteger p) => BigInteger.ModPow(Mod(a, p), p - 2, p);

    static readonly BigInteger SecpP = Hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    static readonly BigInteger SecpN = Hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    static readonly BigInteger P256P = Hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    static readonly BigInteger P256B = Hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
    static readonly BigInteger EdP = BigInteger.Pow(2, 255) - 19;
    static readonly BigInteger EdD = Mod(-121665 * Inv(121666, EdP), EdP);
    static readonly BigInteger EdSqrtM1 = BigInteger.ModPow(2, (EdP - 1) / 4, EdP);
    static readonly BigInteger BnP = Hex("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47");
    static readonly BigInteger BnR = Hex("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    static readonly BigInteger BlsP = Hex("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");
    static readonly BigInteger BlsR = Hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

    static void Need(bool ok, string reason)
    {
        if (!ok) throw new UAException("UAKeyData", reason);
    }

    // ----- Fp2 = Fp[u]/(u² + 1), points on y² = x³ + b (G1 uses A1 = 0) -----

    readonly record struct Fp2(BigInteger A0, BigInteger A1);

    sealed record Pt(Fp2 X, Fp2 Y);

    static Fp2 Add(Fp2 a, Fp2 b, BigInteger p) => new(Mod(a.A0 + b.A0, p), Mod(a.A1 + b.A1, p));
    static Fp2 Sub(Fp2 a, Fp2 b, BigInteger p) => new(Mod(a.A0 - b.A0, p), Mod(a.A1 - b.A1, p));
    static Fp2 Mul(Fp2 a, Fp2 b, BigInteger p) => new(Mod(a.A0 * b.A0 - a.A1 * b.A1, p), Mod(a.A0 * b.A1 + a.A1 * b.A0, p));
    static Fp2 Inv2(Fp2 a, BigInteger p)
    {
        var n = Inv(a.A0 * a.A0 + a.A1 * a.A1, p);
        return new(Mod(a.A0 * n, p), Mod(-a.A1 * n, p));
    }

    static bool OnCurve(Fp2 x, Fp2 y, Fp2 b, BigInteger p) => Mul(y, y, p) == Add(Mul(Mul(x, x, p), x, p), b, p);

    static Pt? AddPt(Pt? a, Pt? c, BigInteger p)
    {
        if (a is null) return c;
        if (c is null) return a;
        Fp2 l;
        if (a.X == c.X)
        {
            if (a.Y != c.Y || (a.Y.A0.IsZero && a.Y.A1.IsZero)) return null; // P + (−P), or doubling a 2-torsion point
            var x2 = Mul(a.X, a.X, p);
            l = Mul(Add(Add(x2, x2, p), x2, p), Inv2(Add(a.Y, a.Y, p), p), p);
        }
        else
        {
            l = Mul(Sub(c.Y, a.Y, p), Inv2(Sub(c.X, a.X, p), p), p);
        }
        var x3 = Sub(Sub(Mul(l, l, p), a.X, p), c.X, p);
        return new Pt(x3, Sub(Mul(l, Sub(a.X, x3, p), p), a.Y, p));
    }

    /// <summary>[r]P == O by double-and-add.</summary>
    static bool InSubgroup(Fp2 x, Fp2 y, BigInteger r, BigInteger p)
    {
        Pt? acc = null, q = new Pt(x, y);
        for (var k = r; !k.IsZero; k >>= 1)
        {
            if (!k.IsEven) acc = AddPt(acc, q, p);
            q = AddPt(q, q, p);
        }
        return acc is null;
    }

    static void CurveAndSubgroup(Fp2 x, Fp2 y, Fp2 b, BigInteger r, BigInteger p)
    {
        Need(OnCurve(x, y, b, p), "curve");
        Need(InSubgroup(x, y, r, p), "subgroup");
    }

    // ----- per-curve checks -----

    static void SecpX(ReadOnlySpan<byte> xb)
    {
        var x = Be(xb);
        Need(x < SecpP, "range");
        var rhs = Mod(x * x * x + 7, SecpP);
        var y = BigInteger.ModPow(rhs, (SecpP + 1) / 4, SecpP);
        Need(Mod(y * y, SecpP) == rhs, "curve");
    }

    static void SecpCompressed(ReadOnlySpan<byte> b)
    {
        Need(b[0] is 2 or 3, "prefix");
        SecpX(b[1..33]);
    }

    static void P256Point(ReadOnlySpan<byte> xy)
    {
        BigInteger x = Be(xy[..32]), y = Be(xy[32..64]);
        Need(x < P256P && y < P256P, "range");
        Need(Mod(y * y - (x * x * x - 3 * x + P256B), P256P).IsZero, "curve");
    }

    static (BigInteger, BigInteger) EdAdd((BigInteger X, BigInteger Y) a, (BigInteger X, BigInteger Y) c)
    {
        var t = Mod(EdD * a.X * c.X * a.Y * c.Y, EdP);
        return (Mod((a.X * c.Y + c.X * a.Y) * Inv(1 + t, EdP), EdP), Mod((a.Y * c.Y + a.X * c.X) * Inv(1 - t, EdP), EdP));
    }

    static void Ed25519(ReadOnlySpan<byte> b)
    {
        var v = new BigInteger(b, isUnsigned: true, isBigEndian: false);
        var sign = (int)(v >> 255);
        var y = v & ((BigInteger.One << 255) - 1);
        Need(y < EdP, "range");
        var x2 = Mod((y * y - 1) * Inv(EdD * y * y + 1, EdP), EdP);
        var x = BigInteger.ModPow(x2, (EdP + 3) / 8, EdP);
        if (Mod(x * x - x2, EdP) != 0) x = Mod(x * EdSqrtM1, EdP);
        Need(Mod(x * x - x2, EdP).IsZero, "curve");
        Need(!(x.IsZero && sign == 1), "sign");
        if ((int)(x & 1) != sign) x = EdP - x;
        (BigInteger, BigInteger) pt = (x, y);
        for (var i = 0; i < 3; i++) pt = EdAdd(pt, pt);
        Need(pt != (BigInteger.Zero, BigInteger.One), "small-order");
    }

    static void BnG1(ReadOnlySpan<byte> b)
    {
        BigInteger x = Be(b[..32]), y = Be(b[32..64]);
        Need(x < BnP && y < BnP, "range");
        Need(!(x.IsZero && y.IsZero), "identity");
        Need(Mod(y * y - x * x * x - 3, BnP).IsZero, "curve");
    }

    static readonly Fp2 BnB2 = Mul(new Fp2(3, 0), Inv2(new Fp2(9, 1), BnP), BnP);

    static void BnG2(ReadOnlySpan<byte> b)
    {
        BigInteger xi = Be(b[..32]), xr = Be(b[32..64]), yi = Be(b[64..96]), yr = Be(b[96..128]);
        Need(xi < BnP && xr < BnP && yi < BnP && yr < BnP, "range");
        Need(!(xi.IsZero && xr.IsZero && yi.IsZero && yr.IsZero), "identity");
        CurveAndSubgroup(new Fp2(xr, xi), new Fp2(yr, yi), BnB2, BnR, BnP); // EIP-197: imaginary part first
    }

    static BigInteger BlsFp(ReadOnlySpan<byte> b)
    {
        Need(b[..16].IndexOfAnyExcept((byte)0) < 0, "padding");
        var v = Be(b[16..64]);
        Need(v < BlsP, "range");
        return v;
    }

    static void BlsG1(ReadOnlySpan<byte> b)
    {
        BigInteger x = BlsFp(b[..64]), y = BlsFp(b[64..128]);
        Need(!(x.IsZero && y.IsZero), "identity");
        CurveAndSubgroup(new Fp2(x, 0), new Fp2(y, 0), new Fp2(4, 0), BlsR, BlsP);
    }

    static void BlsG2(ReadOnlySpan<byte> b)
    {
        BigInteger x0 = BlsFp(b[..64]), x1 = BlsFp(b[64..128]), y0 = BlsFp(b[128..192]), y1 = BlsFp(b[192..256]);
        Need(!(x0.IsZero && x1.IsZero && y0.IsZero && y1.IsZero), "identity");
        CurveAndSubgroup(new Fp2(x0, x1), new Fp2(y0, y1), new Fp2(4, 4), BlsR, BlsP); // EIP-2537: c0 first
    }

    // ----- layouts -----

    delegate void PointCheck(ReadOnlySpan<byte> b);

    static int U16(ReadOnlySpan<byte> d, int o)
    {
        Need(d.Length >= o + 2, "length");
        return d[o] << 8 | d[o + 1];
    }

    static void Musig2(ReadOnlySpan<byte> d, PointCheck point, int size)
    {
        var n = U16(d, size);
        Need(n is >= 2 and <= 16, "n");
        Need(d.Length == size + 2 + n * size, "length");
        point(d[..size]);
        for (var i = 0; i < n; i++)
        {
            var o = size + 2 + i * size;
            point(d.Slice(o, size));
            if (i > 0) Need(d.Slice(o - size, size).SequenceCompareTo(d.Slice(o, size)) < 0, "order");
        }
    }

    static void Frost(ReadOnlySpan<byte> d, PointCheck point, int size, BigInteger order)
    {
        int t = U16(d, size), n = U16(d, size + 2);
        Need(t >= 2 && t <= n && n <= 16, "threshold");
        var per = (t + 1) * size + 32;
        Need(d.Length == size + 4 + n * per, "length");
        point(d[..size]);
        for (var i = 0; i < n; i++)
        {
            var o = size + 4 + i * per;
            for (var j = 0; j <= t; j++) point(d.Slice(o + j * size, size)); // t commitments, then R_i
            Need(Be(d.Slice(o + (t + 1) * size, 32)) < order, "scalar");
        }
    }

    static void Msig(ReadOnlySpan<byte> d, bool hederaNative)
    {
        int threshold = U16(d, 0), count = U16(d, 2);
        Need(count is >= 1 and <= 16, "count");
        Need(d.Length == 4 + 36 * count, "length");
        var total = 0;
        for (var i = 0; i < count; i++)
        {
            var o = 4 + 36 * i;
            var kind = (ushort)U16(d, o);
            var id = d.Slice(o + 2, 32);
            var weight = U16(d, o + 34);
            Need(IsMember(kind, hederaNative), "member-kind");
            Need(weight >= 1, "weight");
            Need(IsNative(kind) == (id[..12].IndexOfAnyExcept((byte)0) < 0), "member-id");
            if (i > 0) Need(d.Slice(o - 34, 32).SequenceCompareTo(id) < 0, "order");
            total += weight;
        }
        Need(threshold >= 1 && threshold <= total, "threshold");
    }

    static void Fndsa(ReadOnlySpan<byte> d)
    {
        Need(d[0] == 0x09, "header");
        for (var i = 0; i < 512; i++)
        {
            var v = 0;
            for (var j = 0; j < 14; j++)
            {
                var k = i * 14 + j;
                v = v << 1 | (d[1 + k / 8] >> (7 - k % 8)) & 1;
            }
            Need(v < 12289, "coefficient");
        }
    }

    /// <summary>Throws <c>UAException("UAKeyData")</c> unless the key data is the unique canonical encoding of a valid
    /// key or structure of <paramref name="kind"/>.</summary>
    public static void ValidateKeyData(ushort kind, byte[] keyData, bool hederaNative = false)
    {
        var k = Derived(kind);
        ReadOnlySpan<byte> d = keyData;
        if (k.Lengths.Length > 0) Need(Array.IndexOf(k.Lengths, d.Length) >= 0, "length");
        switch (kind)
        {
            case 0x0100: P256Point(d[..64]); break;
            case 0x0101: P256Point(d); break;
            case 0x0102: Ed25519(d); break;
            case 0x0103: SecpX(d); break;
            case 0x0104 or 0x0140: BnG1(d); break;
            case 0x0105 or 0x0141: BlsG1(d); break;
            case 0x0106: BlsG2(d); break;
            case 0x0107: BnG2(d); break;
            case 0x0110: Musig2(d, SecpCompressed, 33); break;
            case 0x0111: Frost(d, SecpCompressed, 33, SecpN); break;
            case 0x0112: Musig2(d, BnG1, 64); break;
            case 0x0113: Frost(d, BnG1, 64, BnR); break;
            case 0x0120: Msig(d, hederaNative); break;
            case 0x0132: Fndsa(d); break;
            default: break; // mldsa44/65, slhdsa128s, pqz-mlwe: the length is the whole check
        }
    }
}
```

- [ ] **Step 4: The test.** Create `clients/ua-cs/Scaas.Ua.Tests/VectorTests.cs`:

```csharp
// Scaas.Ua against smartcontracts/vectors/ua/ (generated by clientkeys scripts/ua-vectors.mjs).
using System.Text.Json;
using Xunit;

namespace Scaas.Ua.Tests;

public class VectorTests
{
    static readonly string Dir = FindVectors();

    static string FindVectors()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
        {
            var p = Path.Combine(d.FullName, "smartcontracts", "vectors", "ua");
            if (File.Exists(Path.Combine(p, "kinds.json"))) return p;
        }
        throw new FileNotFoundException("smartcontracts/vectors/ua not found above the test binary");
    }

    static JsonElement Load(string name) => JsonDocument.Parse(File.ReadAllText(Path.Combine(Dir, name))).RootElement;
    static byte[] B(JsonElement e) => Convert.FromHexString(e.GetString()![2..]);
    static string Hx(byte[] b) => "0x" + Convert.ToHexStringLower(b);
    static ushort Kind(JsonElement e) => e.GetProperty("kind").GetUInt16();

    [Fact]
    public void TableGroupsPurposesConstants()
    {
        var k = Load("kinds.json");
        Assert.Equal(UA.Kinds.Length, k.GetProperty("kinds").GetArrayLength());
        foreach (var r in k.GetProperty("kinds").EnumerateArray())
        {
            var n = Kind(r);
            var info = UA.KindInfo(n);
            Assert.Equal(r.GetProperty("name").GetString(), info.Name);
            Assert.Equal(r.GetProperty("native").GetBoolean(), info.Native);
            Assert.Equal(r.GetProperty("lengths").EnumerateArray().Select(x => x.GetInt32()).ToArray(), info.Lengths);
            var g = r.GetProperty("group");
            Assert.Equal(g.ValueKind == JsonValueKind.Null ? null : g.GetString(), info.Group);
            Assert.Equal(r.GetProperty("signing").GetBoolean(), UA.IsSigning(n));
            Assert.Equal(r.GetProperty("zether").GetBoolean(), UA.IsZether(n));
            Assert.Equal(r.GetProperty("member").GetBoolean(), UA.IsMember(n, false));
            Assert.Equal(r.GetProperty("memberHedera").GetBoolean(), UA.IsMember(n, true));
            if (info.Native)
            {
                Assert.Equal("UAKindNotDerived", Assert.Throws<UAException>(() => UA.Tag(n)).Code);
                continue;
            }
            Assert.Equal(r.GetProperty("tag").GetString(), UA.KindTagString(n));
            Assert.Equal(r.GetProperty("TAG").GetString(), Hx(UA.Tag(n)));
        }
        foreach (var r in k.GetProperty("groups").EnumerateArray())
        {
            var g = r.GetProperty("group").GetString()!;
            Assert.Equal(r.GetProperty("tag").GetString(), UA.GroupTagString(g));
            Assert.Equal(r.GetProperty("GROUP").GetString(), Hx(UA.GroupTag(g)));
        }
        foreach (var r in k.GetProperty("purposes").EnumerateArray())
            Assert.Equal(r.GetProperty("purposeTag").GetString(), Hx(UA.PurposeTag(r.GetProperty("purpose").GetString()!)));
        var c = k.GetProperty("constants");
        Assert.Equal(c.GetProperty("MSG_TAG").GetString(), Hx(UA.MsgTag));
        Assert.Equal(c.GetProperty("POP_TAG").GetString(), Hx(UA.PurposeTag("pop")));
        Assert.Equal(c.GetProperty("DOMAIN_TYPEHASH").GetString(), Hx(UA.Keccak256(System.Text.Encoding.UTF8.GetBytes(UA.DomainType))));
        Assert.Equal(c.GetProperty("UAAUTH_TYPEHASH").GetString(), Hx(UA.Keccak256(System.Text.Encoding.UTF8.GetBytes(UA.UAAuthType))));
        Assert.Equal(c.GetProperty("NAME_HASH").GetString(), Hx(UA.Keccak256(System.Text.Encoding.UTF8.GetBytes(UA.RegistryName))));
    }

    [Fact]
    public void ValidRows()
    {
        foreach (var r in Load("kinds.json").GetProperty("valid").EnumerateArray())
        {
            var d = B(r.GetProperty("keyData"));
            Assert.Equal(r.GetProperty("ua").GetString(), Hx(UA.DeriveUA(Kind(r), d, r.GetProperty("hederaNative").GetBoolean())));
            var h = UA.KeyHashOf(Kind(r), d);
            var want = r.GetProperty("keyHash");
            Assert.Equal(want.ValueKind == JsonValueKind.Null ? null : want.GetString(), h is null ? null : Hx(h));
        }
    }

    [Fact]
    public void InvalidRows()
    {
        foreach (var r in Load("kinds.json").GetProperty("invalid").EnumerateArray())
        {
            var e = Assert.Throws<UAException>(() =>
                UA.ValidateKeyData(Kind(r), B(r.GetProperty("keyData")), r.GetProperty("hederaNative").GetBoolean()));
            Assert.True(r.GetProperty("error").GetString() == e.Code, $"{Kind(r)} {r.GetProperty("reason").GetString()}: {e.Code}");
        }
    }

    [Fact]
    public void NativesNativeSpaceCanonicalIds()
    {
        var k = Load("kinds.json");
        foreach (var r in k.GetProperty("natives").EnumerateArray())
        {
            var id = UA.NativeId(Kind(r), B(r.GetProperty("raw")));
            Assert.Equal(r.GetProperty("id").GetString(), Hx(id));
            Assert.Equal(r.GetProperty("canonical").GetString(), UA.CanonicalId(Hx(id)));
        }
        foreach (var r in k.GetProperty("nativeInvalid").EnumerateArray())
            Assert.Equal(r.GetProperty("error").GetString(), Assert.Throws<UAException>(() => UA.NativeId(Kind(r), B(r.GetProperty("raw")))).Code);
        foreach (var r in k.GetProperty("nativeSpace").EnumerateArray())
            Assert.Equal(r.GetProperty("inNativeSpace").GetBoolean(), UA.InNativeSpace(B(r.GetProperty("id"))));
        foreach (var r in k.GetProperty("canonicalIds").EnumerateArray())
        {
            var input = r.GetProperty("input").GetString()!;
            if (r.TryGetProperty("canonical", out var c)) Assert.Equal(c.GetString(), UA.CanonicalId(input));
            else Assert.Equal(r.GetProperty("error").GetString(), Assert.Throws<UAException>(() => UA.CanonicalId(input)).Code);
        }
    }

    [Fact]
    public void Messages()
    {
        foreach (var r in Load("kinds.json").GetProperty("messages").EnumerateArray())
        {
            var p = UA.PurposeTag(r.GetProperty("purpose").GetString()!);
            Assert.Equal(r.GetProperty("uaMsg").GetString(), Hx(UA.UAMessage(Kind(r), p, B(r.GetProperty("digest")))));
        }
    }

    [Fact]
    public void Structures()
    {
        var s = Load("structures.json");
        var ctx = s.GetProperty("contexts");
        foreach (var p in s.GetProperty("pop").EnumerateArray())
        {
            var c = ctx.GetProperty(p.GetProperty("context").GetString()!);
            var id = c.GetProperty("chainId").GetUInt64();
            Assert.Equal(p.GetProperty("chainKeyHash").GetString(), Hx(UA.ChainKeyHash(id)));
            var got = UA.PopDigest(id, B(c.GetProperty("chainUid")), B(c.GetProperty("registry")), B(p.GetProperty("ua")), B(p.GetProperty("authRef")));
            Assert.Equal(p.GetProperty("popDigest").GetString(), Hx(got));
        }
        foreach (var a in s.GetProperty("uaAuth").EnumerateArray())
        {
            var c = ctx.GetProperty(a.GetProperty("context").GetString()!);
            var d = new UA.Domain(a.GetProperty("generation").GetUInt32(), c.GetProperty("chainId").GetUInt64(),
                B(c.GetProperty("registry")), B(c.GetProperty("chainUid")));
            Assert.Equal(a.GetProperty("domainSeparator").GetString(), Hx(UA.UAAuthDomainSeparator(d)));
            Assert.Equal(a.GetProperty("uaAuthDigest").GetString(),
                Hx(UA.UAAuthDigest(d, B(a.GetProperty("ua")), B(a.GetProperty("purposeTag")), B(a.GetProperty("digest")))));
        }
        foreach (var m in s.GetProperty("member").EnumerateArray())
            Assert.Equal(m.GetProperty("memberDigest").GetString(), Hx(UA.MemberDigest(B(m.GetProperty("structureUa")), B(m.GetProperty("uaMsg")))));
    }
}
```

- [ ] **Step 5: Test.** `cd clients/ua-cs/Scaas.Ua.Tests && ../../../scripts/capped dotnet test` — 6 passed, build without
  warnings (the library builds with `TreatWarningsAsErrors`). If a cached NuGet version is missing offline, restore with
  network; keep the pinned versions.

- [ ] **Step 6: CI.** In `.github/workflows/ci.yml` add:

```yaml
  ua-cs:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: clients/ua-cs/Scaas.Ua.Tests
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '10.0.x'
      - name: vectors
        run: dotnet test
```

- [ ] **Step 7: Commit.**

```bash
/usr/bin/git add clients/ua-cs .github/workflows/ci.yml
/usr/bin/git commit -m "UA-1 T6: clients/ua-cs (C# UA identity layer) against the UA vectors" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 7: Docs and TODO

**Files:**
- Create: `docs/clients/ua-libraries.md`
- Modify: `docs/contracts/accounts.md` (net 0 lines), `docs/README.md` (clients table), `TODO.md`

**Interfaces:**
- Consumes: Tasks 1–6 (paths, names, test commands, counts).
- Produces: the current docs for the identity layer; the TODO state.

- [ ] **Step 1: `accounts.md` (net 0 lines: `wc -l` before = after).** Edit in place, keeping line breaks where they are
  or rebalancing within the touched paragraph:
  - §1 intro (line ~47): `Status: **SPECIFIED**; nothing is built.` → `Status: **SPECIFIED**; the identity layer (kind
    table, ids, keyHash, purpose tags, digests, key-data validation) is BUILT in six libraries ([ua-libraries.md](../clients/ua-libraries.md)).`
  - Layer 2 (line ~231): `keyOwner[keccak256(group_tag ‖ canonical_pubkey)]` → `keyOwner[keccak256(GROUP(g) ‖ canonical_pubkey)]`.
  - CTR-UA-11 (lines ~262–264): `keccak256(group_tag ‖ canonical_pubkey)` → `keccak256(GROUP(g) ‖ canonical_pubkey)` with
    `GROUP(g) = keccak256("scaas.ua.group." ‖ g ‖ ".v1")` (controller ruling, pending the owner: the spec named
    `group_tag` without defining it); the group list gains `slhdsa128s` after `fndsa512`.
  - §1.6 code block: on the `UA(kind, d)` line append `; GROUP(g) = keccak256("scaas.ua.group." ‖ g ‖ ".v1")` — no new line.
  - Closed sets, SIGNING row: `` `0x0130`–`0x0132` `` → `` `0x0130`–`0x0133` `` (and in the MEMBER row's wording nothing
    changes: it says "SIGNING single-key kinds").
  - §1.16 first line: `Cross-language vectors (`smartcontracts/vectors/ua/`):` → `Cross-language vectors
    (`smartcontracts/vectors/ua/`; `kinds.json` and `structures.json` BUILT as the identity layer — no signatures yet:
    PoP signatures and `groups.json` come with the registry's verifiers, `metatx3.json` with the UA ledger,
    `derivation.json` with the signers):`.
  - §1.16 consumers sentence: `Foundry (`test/ua/*`), clientkeys (Jest), zether-prover (Rust), the node (Rust kind
    library), the reference client system (Python)` → `Foundry (`test/ua/*`), clientkeys (`node --test`), the
    `scaas-ua` crate (the node and zether-prover), the client-system libraries in Python, Go and C#`; and
    `generated by one script (`smartcontracts/scripts/gen_ua_vectors.*`) from independent implementations
    (noble/`@noble/curves` in JS, `k256`/`p256`/`ed25519-dalek`/`blst`/`ark-bn254` in Rust)` → `generated by one script
    (clientkeys `scripts/ua-vectors.mjs`, on `@noble/curves`) and accepted only when an independent implementation agrees
    (`k256`/`p256`/`curve25519-dalek`/arkworks in Rust; py_ecc, gnark-crypto and big-integer code in the others)`.
  Run `wc -l docs/contracts/accounts.md` before and after: 1509 both.

- [ ] **Step 2: The library page.** Create `docs/clients/ua-libraries.md`:

````markdown
# UA identity libraries

The Universal Account identity layer ([accounts.md](../contracts/accounts.md) §1.3–§1.6) — kind table, ids, keyHash,
purpose tags, `ua_msg`, `popDigest`, the registry's `UAAuth` digest, member digests, canonical ids, the closed kind sets
and key-data validation — is implemented once on chain and in five client libraries. All six must reproduce
`smartcontracts/vectors/ua/kinds.json` and `structures.json`. UNAUDITED: no library is published as a package before an
audit.

| Library | Path | Runs in | Curve code | Test |
|---|---|---|---|---|
| Solidity `UAKinds` | `smartcontracts/evm/src/ua/UAKinds.sol` | the registry and tokens (on chain) | EIP-2537 MSM, the bn254 pairing precompile, modular arithmetic | `forge test --match-path test/ua/UAKinds.t.sol` |
| JS `ua.js` | `clients/clientkeys/src/ua.js` | browsers, the app, wallets | `@noble/curves` 2.4.0 | `npm test` in `clients/clientkeys` |
| Rust `scaas-ua` | `clients/scaas-ua` | the node, zether-prover, WASM | `k256`, `p256`, `curve25519-dalek`, arkworks 0.5 | `cargo test` |
| Python `scaas_ua` | `clients/ua-py` | client systems (ERP) | integers, `py_ecc` 6.0.0 | `python3 -m unittest -v tests.test_vectors` |
| Go `ua` | `clients/ua-go` | client systems | `gnark-crypto` v0.16.0, `filippo.io/edwards25519`, `math/big` | `go test ./...` |
| C# `Scaas.Ua` | `clients/ua-cs` | client systems (.NET) | `System.Numerics.BigInteger`, BouncyCastle (keccak) | `dotnet test` in `Scaas.Ua.Tests` |

**Vectors.** `node scripts/ua-vectors.mjs` in `clients/clientkeys` writes both files from `ua.js` on deterministic keys;
every valid row is accepted and every invalid row refused before it is written, and a clientkeys test regenerates them
byte for byte. The Rust crate's curve code is independent of noble: a row is accepted only when both agree. The other four
read the same files. Never edit them by hand.

**One API.** Each library has the same functions in its own case (`uaOf` / `ua_of` / `UAOf`): the table and closed sets
(`kindInfo`, `isNativeKind`, `isZetherKind`, `isSigningKind`, `isMemberKind(kind, hederaNative)`), tags (`TAG`, `GROUP`,
`MSG_TAG`, `purposeTag`), ids (`uaOf`, `deriveUA`, `nativeId`, `inNativeSpace`, `canonicalId`), `keyHashOf`,
`validateKeyData`, digests (`uaMessage`, `chainKeyHash`, `popDigest`, `uaAuthDomainSeparator`, `uaAuthDigest`,
`memberDigest`) and `encodeMsig`. Errors carry one code everywhere: `UAKeyData`, `UAIdInNativeSpace`, `UAKindUnknown`,
`UAKindNotDerived`, `UAKindNotNative`, `UAIdFormat`, `UAPurposeUnknown`. The Solidity library has the on-chain subset.

**Definitions this layer fixes** (controller rulings, pending the owner): `GROUP(g) = keccak256("scaas.ua.group." ‖ g ‖
".v1")` and `keyHash = keccak256(GROUP(g) ‖ canonical pubkey)` (secp256k1 `x`, P-256 `x`, the full point or key otherwise;
`x(Q)` / `x(Y)` and `Q` / `Y` for MuSig2 / FROST); `slhdsa128s` is in SIGNING and MEMBER; an `msig` has 1–16 members,
every weight ≥ 1, native members with ids in the native space and derived members outside it.

**What validation checks.** Lengths; P-256 and secp256k1 on the curve with coordinates `< p` and compressed prefix
`02`/`03`; ed25519 canonical (`y < p`, no negative zero), not small order; bn254 G1 on the curve, not the identity; bn254 G2
(EIP-197, imaginary part first) and BLS12-381 G1/G2 (EIP-2537, 16 zero bytes of padding, `c0` first) on the curve and in
the prime-order subgroup; MuSig2 / FROST layouts of valid points with sorted members and scalars below the order; `msig`
layout and member rules; FN-DSA header and coefficients `< 12289`; ML-DSA, SLH-DSA and `pqz-mlwe` by length. Registration
status, KeyAgg, the FROST DKG check, PoP and the structure gas bound are the registry's.

**Not here.** Signing (`UAKey`, the per-kind signers), PoP signatures and group vectors, the registry contract, the UA ledger.
````

- [ ] **Step 3: `docs/README.md`.** After the `signers-clientkeys.md` row of the clients table add:

```markdown
| [ua-libraries.md](clients/ua-libraries.md) | UA identity layer in Solidity, JS, Rust, Python, Go, C# |
```

- [ ] **Step 4: `TODO.md`.** In the §00 table's P6 row, after the P6a entry text, the UA phase is already referenced
  ("UA F0/F1 as their own phase"); add to the row's end: `UA phase roadmap
  `docs/superpowers/plans/2026-10-12-ua-roadmap.md` (UA-1 kind libraries, UA-2 registry and verifiers, UA-3 Zether
  re-point, UA-4 UA ledger).` And after the `- [x] **P6a**` line add:

```markdown
- [~] **UA-1** kind libraries (UA F0): the identity layer in Solidity `UAKinds`, clientkeys `ua.js`, `clients/scaas-ua`, `clients/ua-py`, `clients/ua-go`, `clients/ua-cs`; vectors `smartcontracts/vectors/ua/kinds.json`, `structures.json` (plan `docs/superpowers/plans/2026-10-12-ua1-kind-libraries.md`): built on branch `ua1-kinds`, not merged. Next: UA-2 (registry and verifiers, PoP signatures, `groups.json`). Evaluated, not planned (owner asked, 2026-10-12): UA-1b — C++/Qt-QML through a `cxx` bridge over `scaas-ua`, Dart on the crate's WASM build (owner) and flutter_rust_bridge for native Flutter targets.
```

- [ ] **Step 5: Checks.** `python3 scripts/docs_check.py check` — 0 errors (the pre-existing `token-wrappers.md` budget
  warning may remain); `python3 scripts/docs_check.py facts check` — 0 misses; `wc -l docs/contracts/accounts.md` = 1509.

- [ ] **Step 6: Commit.**

```bash
/usr/bin/git add docs/clients/ua-libraries.md docs/contracts/accounts.md docs/README.md TODO.md
/usr/bin/git commit -m "UA-1 T7: docs (UA identity libraries, GROUP(g), slhdsa128s in SIGNING), TODO" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Final

- [ ] **Whole branch.** From the worktree root after Task 7: `forge build` and `forge test` (924 passed, 10 skipped), size
  gate 0 errors, `FOUNDRY_PROFILE=private7622 forge build`; `npm test` in clientkeys (79 / 77 / 2) with the vectors
  regenerated byte for byte; `cargo test` and `cargo clippy --all-targets -- -D warnings` in `clients/scaas-ua`; the
  Python, Go and C# suites; `docs_check.py check` 0 errors, `facts check` 0 misses.
- [ ] **Review** against the Review Focus above; then merge to `main` (owner). Next: UA-2.
