# QR payloads in SCaaS clients: design

**Status:** SPECIFIED or PLANNED per section; nothing built. A frame written now, built after the pre-freeze tag and before
the freeze (owner 2026-11-28). Its rules are [CLI-QR-01](../../decisions.md#CLI-QR-01) to
[CLI-QR-08](../../decisions.md#CLI-QR-08) in decisions.md; this spec carries the design, the figures, the reasons and the
owner's questions (§12). Sources: the payment references and PayMeta ([metatx §6](../../contracts/metatx.md#CTR-MTX-03),
[CTR-MTX-26](../../contracts/metatx.md#CTR-MTX-26)), the payee self-relay row ([metatx §12](../../contracts/metatx.md#payers)),
the hand-off object ([SDK spec §27.5](2026-11-17-scaas-sdk.md), [CLI-SDK-09](../../clients/scaas-sdk.md#CLI-SDK-09)), the
CLI's hand-off blob ([scaas-cli.md §2](../../clients/scaas-cli.md)), the review and sign-after-confirm rules
([CLI-SDK-35](../../decisions.md#CLI-SDK-35), [CLI-SDK-36](../../decisions.md#CLI-SDK-36),
[CLI-PQV-18](../../clients/pqvault-core.md#CLI-PQV-18)), the hidden receive QR ([CLI-SGN-14](../../clients/signers-clientkeys.md#CLI-SGN-14)),
the link channel ([CLI-UAL-12](../../clients/ua-libraries.md#CLI-UAL-12)), and the PQZ and Zether sizes
([pq-zero-knowledge.md](../../contracts/pq-zero-knowledge.md), the Zether prover's vectors). No contract, signed byte format of
a contract, chain profile or node rule changes. UNAUDITED.

**Contents**

1. [Scope and place](#1-scope-and-place)
2. [The crate `scaas-qr`](#2-the-crate-scaas-qr)
3. [Payload kinds](#3-payload-kinds)
4. [The canonical form](#4-the-canonical-form)
5. [Size: the split by meaning](#5-size-the-split-by-meaning)
6. [Proofs and ciphertexts](#6-proofs-and-ciphertexts)
7. [Decode bounds](#7-decode-bounds)
8. [Export and import](#8-export-and-import)
9. [Safety on scan](#9-safety-on-scan)
10. [Vectors](#10-vectors)
11. [Tests and gates](#11-tests-and-gates)
12. [Open questions for the owner](#12-open-questions-for-the-owner)
13. [Appendix: refusals](#13-appendix-refusals)

## 1. Scope and place

**SPECIFIED.** A QR code in SCaaS is a transport for data the SDK already has a typed form of: a receive request, a payment
request, a signed operation handed to the party that submits it, and the public half of a device link. One versioned, typed
format, in one crate, is shared by scaas-app, `scaas-tui` and the CLI ([CLI-QR-01](../../decisions.md#CLI-QR-01)). A QR adds
no new authority: whatever a scanned payload asks for is reviewed, quoted and confirmed exactly as the same operation typed
by hand, and a signed operation in a QR is judged by the same import checks as the hand-off blob.

Out of scope: a QR that a contract or the node reads (none does), wallet-connect style sessions, a second offline format
beside the hand-off blob (a QR carries the same object, §3.4), and EIP-681 or other wallets' URI schemes (§12 Q5).

Changes to earlier frames, by this ruling: the TUI spec's non-goal "No QR codes" ([TUI spec §1](2026-11-17-scaas-tui.md)) is
lifted for the payloads here (§8.5); the CLI's "no other offline format" ([scaas-cli.md §2](../../clients/scaas-cli.md)) now
reads "the hand-off blob, in its JSON form or in the QR forms of this spec"; the payee self-relay row's "QR (EIP-681-style)
tooling" ([metatx §12](../../contracts/metatx.md#payers)) is this spec, not EIP-681.

## 2. The crate `scaas-qr`

**SPECIFIED** (owner 2026-11-28, [CLI-QR-01](../../decisions.md#CLI-QR-01)). A crate of its own, `clients/scaas-qr`, in two
layers:

| Layer | Holds | Depends on | Built for |
|---|---|---|---|
| Format core (default features) | the payload types (§3); the canonical bytes and the `scaas:` URI (§4); the split into info, signature and bulk parts and their assembly (§5, §6); the fountain coder (§5.4); the part binding and bulk pin checks; every bounded decode (§7) | no image library, no `scaas-sdk`, no `ua-rs` signing code; small crates only (below) | every target, `wasm32-unknown-unknown` included |
| Image layer (feature `image`) | QR symbol encoding; PNG, SVG and APNG writing; PNG, JPEG and APNG frame decoding; the terminal renderer (§8.5) | the format core and the image crates below | native targets; linked by `scaas-tui` and the CLI |

The dependency points one way, as `scaas-profile`'s does: `scaas-sdk` depends on the format core to build and check
payloads, never the reverse; scaas-app's default build (no SDK) links the format core alone, so it can show a receive QR
for an address it holds ([stack.md](../../clients/stack.md) rule 10). scaas-app's camera path may hand frames to the image
layer's decoder or decode them with its platform's reader, provided the reader returns the raw byte segments (§8.6).

**A feature, not a sibling crate.** One crate keeps one version, one vector reader, one `deny.toml` and one fuzz target for
the two layers, which change together whenever the format does. The risk of a feature, Cargo's feature unification pulling
the image crates into a build that did not ask for them, costs size only (the image layer signs nothing and holds no
secret), and the format core's gate checks it: `cargo tree -e features` of the SDK and of scaas-app's default build shows no
`image` feature, and a `wasm32` build of the core runs in CI (§11).

**What the crate does not do.** It signs, verifies, encrypts and decrypts nothing. Its hashes (`keccak256` for the part
binding and the bulk pins, SHA-256 and CRC-32 inside the fountain coder) are integrity checks over public bytes. The digest a
signer signs, its recomputation and the signature check are `ua-rs`'s, called by the SDK ([CLI-UAL-01](../../clients/ua-libraries.md#CLI-UAL-01),
[CLI-SDK-01](../../clients/scaas-sdk.md#CLI-SDK-01)); §5.2 (3).

**Candidate crates** (PLANNED; each pinned exactly at its newest release at least 14 days old when the crate is built, and
covered by the crate's own `cargo deny` and `cargo audit` gate, as `scaas-matrix` is; licences as their manifests declare
them, checked again by `cargo deny` against the SDK's allow-list):

| Use | Layer | Candidate | Licence | Note |
|---|---|---|---|---|
| Keccak-256, SHA-256 | core | `sha3`, `sha2` (RustCrypto) | MIT OR Apache-2.0 | already in the client tree through `ua-rs` |
| CRC-32 | core | `crc32fast` | MIT OR Apache-2.0 | the fountain coder's checksum |
| base64url | core | `base64` | MIT OR Apache-2.0 | already in `scaas-profile` |
| Deterministic CBOR subset | core | written in the crate (about 300 lines, §4.2); `ciborium` (Apache-2.0) only as a test oracle | — | a hand-written subset makes the canonical check, the depth bound and the refused major types exact |
| Fountain coder | core | written in the crate after the published UR fountain algorithm (§5.4); the `ur` crate (MIT) as a test oracle | — | the algorithm only, not the UR text form |
| QR symbol encoding | image | `qrcode` | MIT OR Apache-2.0 | byte mode, fixed ECC level, version range; SVG and Unicode renderers |
| QR decoding | image | `rqrr` (MIT OR Apache-2.0) or `rxing` (Apache-2.0) | as listed | the chosen one must return the byte segments exactly: the binary vectors decide (§10) |
| PNG and APNG write and read | image | `png` | MIT OR Apache-2.0 | APNG frames and delays |
| JPEG read | image | `zune-jpeg` | MIT OR Apache-2.0 OR Zlib | through `image` with only the `png` and `jpeg` features, or directly |
| Image container | image | `image` | MIT OR Apache-2.0 | its `Limits` bound every decode (§7) |

## 3. Payload kinds

**SPECIFIED** ([CLI-QR-02](../../decisions.md#CLI-QR-02)). A payload is one **info part**, optionally followed by
**signature parts** (§5) and **bulk parts** (§6). The info part names the kind:

| Kind | Who shows it | Who scans it | Info part | Signature parts | Bulk parts |
|---|---|---|---|---|---|
| `receive` | a receiver | a payer | always | none | none |
| `pay-request` | a payee (its client or ERP) | a payer | always | the payee's signature, optional | none |
| `signed-op` | a signer | the party that submits it and pays the gas | always | the signer's signature, always | for an operation with a proof or ciphertexts (§6) |
| `link` | a new device | the user's existing device | always | none | none |

### 3.1 `receive`

A receiver's address for one chain: `chain_uid` (bytes32), exactly one of `to_ua` (bytes32, a UA id) and `to_address` (the
family's native address, text in the family's canonical form), `token` (the token contract, text; absent = the chain's
native coin), and optionally `amount` (base units, u256 as decimal digits) and `pay_no` (bytes32, as `PayMeta.payNo`). It is
a single QR of about 120 to 200 bytes (version 6 to 9 at level L). The payer's client builds its own operation from it: a
transfer, or with `pay_no` a payment whose `PayMeta` the payer's client makes (fresh `salt`, the scanned `pay_no`). The
receive QR stays hidden for an account without a backup while the backup switch is on
([CLI-SGN-14](../../clients/signers-clientkeys.md#CLI-SGN-14)).

### 3.2 `pay-request`

A payee's request, in the named fields of [CTR-MTX-03](../../contracts/metatx.md#CTR-MTX-03) and
[CTR-MTX-26](../../contracts/metatx.md#CTR-MTX-26): `chain_uid`, `token`, `to` (bytes32, the payee id), `amount` (u256),
`meta` (`salt`, `pay_no`, `save`, `schema`, `body`), `valid_until` (unix seconds, the request's `issued_valid_until`), and
optionally `payer` (bytes32, the payer the request is for) and `relayer` (the address the payee asks the payment to be bound
to when the payee self-relays it). The scanner computes `entryRef = metaPayId(meta)` itself; the request carries no
`entryRef` field. `schema` is 0, 1 (note) or 2 (structured reference); a bound call (3) or an encrypted body (4) is
`QrSchemaRefused`, because the payer must read what it signs and a QR is no place for a second review. The optional payee
signature (signature parts, §5) is over an off-chain typed record `PaymentRequest` with the same named fields, signed by the
payee's UA through `ua-rs` under its own typehash and an off-chain domain that no contract accepts (PLANNED: the struct, the
domain and a test that no contract's typehash equals it, fixed when built; §12 Q3).

### 3.3 `signed-op`

The hand-off object `SignedOpBlob` (SDK spec §27.5 (c)) carried as parts: its named fields in the info part and its
`signature` in signature parts. Both directions of the hand-off use it:

- **Scan and submit** ("pay the partner's gas from a scanned QR"). A partner signed an operation with fee 0 and `relayer`
  unbound or bound to the scanner's payer address; the scanner's SDK runs `Op::import_signed` on the assembled blob, with
  every check of §27.5 (c) (`ProfileMismatch`, `ImportKindRefused`, `ImportNotPayee`, `ImportRelayerBound`,
  `ImportFeeRefused`, `ImportExpired`, `ImportConsumed`), quotes it, shows the review and, on the user's confirm, submits it
  as a self-relay paid by the scanner's native key.
- **Show for a partner.** `Op::hand_off` signs the user's own operation (after its review and confirm) and the front-end
  shows or exports the blob in the forms of §8 for the partner to submit.

The info part adds one field the JSON blob lacks: `digest` (bytes32), the digest the signer signed (on EVM the EIP-712
digest of `message` in its domain; on another family the 32-byte message `ua-rs` hands the signer's kind). A fee-bearing
relay by a third party is not a hand-off and has no QR form here.

### 3.4 `link`

The public offer of a `ua-rs` `LinkSession`: its ML-KEM-1024 and X25519 public key (1,600 bytes) and the session's start
time, as `ua-rs` exports them (field names fixed by `ua-rs` when built). A single QR at level L or M. The QR is the
authenticated channel [CLI-UAL-12](../../clients/ua-libraries.md#CLI-UAL-12) asks for: a `link` payload is accepted only
from a camera scan of the new device's screen; from a file, a paste or a URI it is `QrSourceRefused` (§9). The 8-digit short
code is not in the QR; the user types it as today.

### 3.5 Not payloads

The registration blob (SDK spec §7, up to 768 KiB) has no QR form in this frame: a PQ registration with a PQZ key's proof
exceeds every bound of §6 and goes as a file, as today. No payload carries a secret: no seed, private key, key handle
export, passphrase, PQZ opening in clear, Zether sender randomness or seed, opening token, or the plaintext of an encrypted
`PayMeta` body. Every field of every kind is in the tables of §4.3; an unknown field is refused, so a secret has no field
to travel in.

## 4. The canonical form

**SPECIFIED** ([CLI-QR-02](../../decisions.md#CLI-QR-02)).

### 4.1 Bytes and URI

- **Canonical bytes** of a part: the two ASCII bytes `SQ`, the format version byte `0x01`, then one map in the deterministic
  CBOR subset of §4.2. The prefix is framing (it names the format and its version), not a field.
- **URI form**: `scaas:` followed by the base64url encoding (RFC 4648 §5, no padding) of the same canonical bytes; one part
  per URI. It is the text form for a paste, a message, a file line and a link, never a second encoding: decoding a URI gives
  the canonical bytes, and both forms are refused or accepted alike.
- **In a QR symbol**: the canonical bytes in byte mode, with no ECI header. A QR scanned by a generic camera app shows
  nothing useful, on purpose: a SCaaS payload needs a SCaaS review. A QR carrying the URI form is accepted too (the decoder
  tries the prefix `scaas:` first).

**Why CBOR rather than the SDK's JSON.** The hand-off blob's JSON carries crypto objects as `0x` hex, twice their size. In a QR
that difference is the frame count: an ML-DSA-65 signature with its key data (5,261 bytes) is two QR parts as CBOR byte
strings, three as base64 and four as hex. The CBOR form is the JSON form field for field (the same names, the same nesting),
so the two forms map one to one and the SDK keeps its JSON for files and APIs.

### 4.2 The CBOR subset

RFC 8949 core deterministic encoding (§4.2.1), restricted: maps with text keys only, sorted by their encoded bytes; unsigned
integers up to 2^64 − 1 in their shortest form; byte strings; UTF-8 text strings (NFC); arrays; `true` and `false`. Refused:
negative integers, floats, tags, `null`, `undefined`, simple values, indefinite lengths, duplicate keys, keys that are not
text, and trailing bytes after the map. A decoder re-encodes what it read and refuses any difference (`QrNotCanonical`), so
every value has one byte form.

### 4.3 Field types

Each kind has a schema table (field, type, required) fixed when built and pinned by the vectors (§10). The types:

| Type | CBOR | Rule |
|---|---|---|
| `bytes32` | byte string of 32 | ids, `chain_uid`, `salt`, `pay_no`, digests, hashes |
| `bytes` | byte string | exactly one crypto object (a signature, a key, a proof, a ciphertext) or one opaque value of the operation; never several fields packed |
| `uint` | unsigned integer | at most 2^64 − 1 (`valid_until`, `schema`, part indexes) |
| `u256` | text of decimal digits | amounts and values, no sign, no leading zero, at most 78 digits |
| `address` | text | the family's canonical address form (EVM: `0x` and 40 lowercase hex digits) |
| `text` | text string | short names (`kind`, `entry`, `family`); at most 64 bytes |
| `bool` | `true` / `false` | `save` |
| struct, list | map, array | the operation's named fields, as the JSON blob nests them |

Every info part carries `v` (1), `kind` and `chain_uid`; a payload is bound to one chain. A payload whose `chain_uid` is not
the active chain profile's is refused (`ProfileMismatch`, §9).

**Frames are not packed fields.** A signature or bulk part's `data` is a slice of one object's canonical bytes (§5, §6): a
transport frame. Reassembled, it decodes as the typed map it was cut from, or the assembly is refused; no frame is ever read
as a parameter.

## 5. Size: the split by meaning

**SPECIFIED** (owner 2026-11-28, [CLI-QR-04](../../decisions.md#CLI-QR-04)).

### 5.1 What one QR holds

A QR symbol holds at most 2,953 bytes in byte mode (version 40, level L; 2,331 at M, 1,663 at Q, 1,273 at H). The parts of
this spec use level L by default (a screen or a file is not damaged as print is) and the smallest version that holds the
part; the export takes level M as an option (§8.1), and the part counts below then grow. A part's header (prefix, kind,
binding hash, index and count) is at most 80 bytes, so a signature part carries up to 2,873 bytes of data at level L.

### 5.2 The rule

When a payload does not fit one QR, it is split by meaning first, never cut blindly:

1. **The info part is complete and reviewable on its own.** It holds every named field of the intent: the chain uid, the
   contract, the entry, the operation's fields, `valid_until`, the relayer and payer bindings, the digest the signer signs,
   and for an operation with a proof or ciphertexts their pins (§6). A scanner shows the full review from the info part
   before any other part arrives. The info part is always one QR; an info part above one QR is `QrInfoTooLarge` and the
   payload goes as a file (§8.3).
2. **Every other part binds to exactly one info part.** Signature and bulk parts carry `info` = `keccak256("scaas.qr.info.v1"
   ‖ canonical bytes of the info part)` and their index and count. Parts are accepted in any scan order; a part whose `info`
   differs from the info part held is `QrPartForeign` and is not stored; two parts with the same index and different bytes
   are `QrPartConflict`; an index outside the count, or a count that differs between parts, is `QrPartIndex` /
   `QrPartCount`.
3. **The scanner never trusts the digest field.** The SDK has `ua-rs` rebuild the digest from the info part's named fields
   with the signer's own builder and refuses a different `digest` (`QrDigestMismatch`); it then verifies the assembled
   signature against the digest it rebuilt (`ua-rs`'s `verify` for the signer's kind) before it offers to submit
   (`QrSignatureInvalid`). For a signer whose check needs chain state (an ERC-1271 contract account, a registered `msig`
   read from the registry), the chain's simulation from the payer is the check, as the hand-off import already states, and
   the review says so. This adds a local check before the import's simulation; it removes none.
4. **Only a signature larger than one QR is chunked.** Its parts are plain numbered chunks of the signature object's
   canonical bytes (the UASig's named fields: `key_data`, `signature`, `members`), cut into the fewest equal parts that fit.
   They are the systematic frames of the fountain coder of §5.4 (frames 1 to n are the chunks themselves), so one coder
   serves both uses and no second framing exists. At most 16 signature parts (about 46 KB); above,
   `QrTooLarge` and the file form.
5. **The same split in every form.** The PNG set, the animated APNG, the text file and a live display hold the same parts:
   the info part, then the signature parts, then the bulk parts (§8).

### 5.3 Signature parts per signer kind

At level L, with the key data a derived UA carries in its UASig ([CTR-UA-36](../../contracts/accounts.md#CTR-UA-36)); a UA
whose key the registry holds sends no key data and needs fewer parts. Key and signature sizes from
[key-schemes.md](../../networks/key-schemes.md) and FIPS 204 / 205.

| Signer kind | Signature + key data | Parts |
|---|---|---|
| EOA secp256k1, ed25519, P-256, BIP-340 | 64 to 130 B | 1 |
| WebAuthn (assertion capped at 1,024 B of `authData` and `clientDataJSON`) | ≤ about 1,200 B | 1 |
| `fndsa512` | ≤ 752 + 897 B | 1 |
| `mldsa44` | 2,420 + 1,312 = 3,732 B | 2 |
| `fndsa1024` | ≤ 1,462 + 1,793 B | 2 |
| `mldsa65` | 3,309 + 1,952 = 5,261 B | 2 |
| `mldsa87` | 4,627 + 2,592 = 7,219 B | 3 |
| `slhdsa128s` | 7,856 + 32 = 7,888 B | 3 |
| `msig` | the members' signatures together | as their sum; above 16 parts, file form |

### 5.4 Numbered chunks or a fountain code

**Recommendation, adopted in this frame: plain numbered chunks for signatures; the fountain code only for bulk.** A
signature takes at most 16 parts and usually 2 or 3; a looping display shows each again within a second or two, so a missed
frame costs one loop, and a printed set has only the chunks. A fountain code earns its place where the frame count is tens
(§6): there each loop of plain chunks would wait for the one frame the camera missed, while fountain frames each carry new
information.

**The coder.** The fountain algorithm of the Uniform Resources specification (Blockchain Commons BCR-2020-005, multipart
UR): a systematic Luby transform (frames 1 to k are the source fragments themselves), the fragment length chosen by its
`findNominalFragmentLength`, frames above k mixing fragments chosen by Xoshiro256** seeded from SHA-256 of the frame
number and the message's CRC-32, the degree drawn with weights 1/i. It is pinned by the vectors (§10), and its published
reference test cases are checked too. Only the algorithm is taken: the UR text form (bytewords, the `ur:` scheme, UR CBOR
types) is not, because bytewords cost about 37 % more QR capacity than byte mode and the UR registry types mean nothing
outside SCaaS. RaptorQ (RFC 6330) was set aside: a larger implementation for gains that matter only above hundreds of
frames, and IETF IPR declarations against it. The LT code's own patents were filed in 1998 to 2002; no live claim is known
to the authors, which is not a legal opinion.

## 6. Proofs and ciphertexts

**SPECIFIED** for the rule; the confidential kinds' QR forms PLANNED with their families
([CLI-QR-05](../../decisions.md#CLI-QR-05)). A `signed-op` whose operation carries a zero-knowledge proof or ciphertexts (a
PQZ or a Zether operation) is the funds' owner's: **the owner's client makes the proof and signs**, holding the keys; the
partner who scans it only relays and pays the gas. The partner computes nothing secret, holds no key of the owner's and
decrypts nothing (§9).

### 6.1 Pins in the info part

The large `bytes` fields of the signed struct (the proof, each ciphertext, `accHint`, a sealed opening) stay out of the info
part; the info part carries, for each, its path in the struct (text, e.g. `proof`, `args.legs.0.v`), its length and its
`keccak256`. EIP-712 encodes a dynamic `bytes` field as the keccak-256 of its bytes, so `ua-rs` rebuilds the digest from the
info part alone (a builder input "this field by its hash"; PLANNED in `ua-rs`), and the review needs no bulk. The bulk
object is one map of exactly the pinned fields; on arrival each field's `keccak256` must equal its pin, every pin must be
filled and no other field may appear (`QrBulkMismatch`, `QrBulkMissing`). A family whose signed message holds such a field
in full, not by its hash, has no pinned form: its operation is not split and goes as a file.

The pins are integrity checks; proofs and ciphertexts are public data that land in calldata and contract state anyway
(never lose ciphertext: the contract keeps every ciphertext in state as before; this transport changes nothing on chain).

### 6.2 Size classes

The bulk object is cut into fountain source symbols of 1,152 bytes (a version 25 symbol at level L holds 1,273 bytes, the
header included). Frame counts are for the bulk alone; the info and signature parts come first.

| Class | Bulk | Form | Proposed bound |
|---|---|---|---|
| (a) | none | info part and signature parts (§5) | — |
| (b) | k source symbols, k ≤ 72 (≤ 82,944 B) | animated: frames 1 to k systematic, then repair frames; a printed or PNG set holds the k systematic frames | k ≤ 72 (§12 Q1) |
| (c) | above (b), or by choice | the info part pins the bulk; the bulk travels by another channel (§6.4) | — |

### 6.3 Zether and PQZ, apart

Estimates, not measurements, at 5 frames a second: with every frame read, k frames suffice; a camera that misses one frame
in five needs about 1.3 · k frames shown (a measurement is planned when the image layer is built, §11).

**Zether** (classical, BLS12-381; sizes from `clients/zether-prover/vectors/`). The signed struct's points are small and
stay in the info part (`ZetherSingle` 880 B, `ZetherMulti` with decoys 2,233 B); the proof is the bulk.

| Operation | Proof | k | Frames shown | Time at 5 fps |
|---|---|---|---|---|
| unshield (burn) | 2,816 B | 3 | 3 to 4 | about 1 s |
| single transfer | 5,888 B | 6 | 6 to 8 | 1 to 2 s |
| multi transfer (with auditor) | 11,936 B | 11 | 11 to 15 | 2 to 3 s |

A `ZetherMulti` info part with many legs can exceed one QR (`QrInfoTooLarge`); such a transfer goes as a file.

**PQZ** (post-quantum; sizes from [pq-zero-knowledge.md](../../contracts/pq-zero-knowledge.md)). A ciphertext is 16,512 B at
`n2048-kmax1024` (18,560 / 20,608 / 22,656 B at the other sets), a transfer proof 42,762 B in PQZL and about 231 KB in
PQZH; a PQZL transfer is about 77 KB of calldata, nearly all of it proof and ciphertexts.

| Operation | Bulk | k | Frames shown | Time at 5 fps | Class |
|---|---|---|---|---|---|
| PQZL transfer, `n2048-kmax1024` | about 77 KB | about 67 | 67 to 88 | 14 to 18 s | (b) |
| PQZL transfer, larger sets | about 80 to 90 KB | 70 to 79 | — | — | (b) or (c) by set |
| PQZH transfer | about 264 KB | about 230 | — | about 60 s | (c) |
| multi-leg PQZ transfer | 16,640 B more per leg | grows | — | — | (c) |

The class follows the measured size of the operation at hand, not its name: one rule on every chain and every set.

### 6.4 Above the bound: the bulk by another channel

For class (c), the QR forms carry the info part and the signature parts only; the bulk goes as the exported bulk file
(`.scaasbulk`, §8.3), as an attachment in a PqChat or Matrix conversation, or through the Arweave store (`ar://<id>`, read
through the profile's gateway list, ARCH-POS-15). The info part may name an `ar://` id (`bulk_at`); it never names an `http`
URL or any other locator. Integrity is the pins alone, whatever the channel: a bulk that does not match is refused, and the
operation stays reviewable (and refusable) from the info part while its bulk is missing. A node endpoint serving bulk by hash
is not part of this frame (§12 Q4). No channel ever carries a secret, because no payload holds one (§3.5).

## 7. Decode bounds

**SPECIFIED** ([CLI-QR-03](../../decisions.md#CLI-QR-03)). Every decode is bounded by length and by depth before it
allocates, and every refusal is named (§13):

| Input | Bound |
|---|---|
| One part's canonical bytes | 2,953 B (one QR at version 40, level L) |
| One URI line | 3,944 characters (`scaas:` and the base64url of 2,953 B) |
| CBOR nesting | depth 8 (the hand-off blob's); at most 64 entries a map, 256 elements an array |
| Text string | 64 B (`text`), 1,024 B (`PayMeta.body`); `u256` 78 digits |
| Signature parts | at most 16 per payload |
| Bulk | k ≤ 72 source symbols in QR form; a bulk file at most 768 KiB (the registration blob's cap, above the largest PQZH input any set takes, 495,493 B) |
| Fountain frames held | at most 2 · k + 16 per payload; frame numbers below 2^32 |
| Parts held | one payload at a time; a foreign part is dropped, not queued |
| `.scaasqr` file | 1 MiB, at most 128 lines |
| Image file | 8,192 px a side, 64 MiB decoded, 256 APNG frames, 128 files a set |

Unknown fields, missing required fields, a wrong type, a non-canonical encoding and trailing bytes are refused. The format
core has one fuzz target over every decode path (§11).

## 8. Export and import

**SPECIFIED** for the forms; the camera PLANNED with scaas-app ([CLI-QR-06](../../decisions.md#CLI-QR-06)).

### 8.1 Export forms

| Form | Payload | Content |
|---|---|---|
| PNG, SVG | one QR (an info part alone) | the symbol, dark modules on a light background in every theme, a quiet zone of 4 modules; PNG at 8 px a module by default |
| Numbered PNG set | several parts | one PNG per part, named `<stem>-00-info.png`, `<stem>-s01-of-02.png`, `<stem>-b001-of-067.png` (the k systematic bulk frames only) |
| Animated APNG | several parts | the frame order and timing below |
| `.scaasqr` text | any | UTF-8, one URI per line (§4.1): the info part first, then the signature parts by index, then the k systematic bulk parts |
| `.scaasbulk` | class (c) bulk | the bulk object's canonical bytes |

Options: level L (default) or M, the module size, the frame rate (2 to 10 frames a second). GIF is not offered: APNG is
lossless, and a viewer that cannot animate it shows its first frame, which is the info part and complete for review.

**APNG frame order and timing** (owner 2026-11-28): frame 1 is the info part, shown 1,000 ms; then the signature parts 1 to
n; then, for class (b), the bulk frames 1 to k (systematic) and ⌈k/2⌉ repair frames k + 1 onwards; every frame after the
first shown 200 ms (5 frames a second); the animation loops without end. A live display (scaas-app, the TUI) uses the same
order and timing, but its repair frames keep their numbers rising from loop to loop, so each loop brings new ones.

### 8.2 Import sources

From a `.scaasqr` file or pasted lines (in any order); from one or more image files (PNG, JPEG, the frames of an APNG, a
numbered set); from a camera (scaas-app); from a `scaas:` URI the platform opens. Each import records its source; the
source matters only for `link` (camera only, §3.4). An import ends in a review (§9), never in a signature.

### 8.3 Files

A payload whose info part exceeds one QR, or whose signature exceeds 16 parts, has no QR form; its `.scaasqr` file still
holds it (one info line may then be longer than a QR holds; the file bound of §7 applies) and the hand-off blob's JSON stays
available. A class (c) bulk is the `.scaasbulk` file beside it.

### 8.4 scaas-app

**PLANNED** with scaas-app. The camera hands frames to one decoder that returns the byte segments exactly: the image layer's
decoder, or a platform reader that exposes raw segments (a reader that returns only text mangles byte mode and is not used).
The default build (no SDK) shows and scans `receive`; the `scaas` build adds the other kinds.

### 8.5 TUI

**SPECIFIED** for the TUI's next round ([CLI-TUI-01](../../clients/scaas-tui.md#CLI-TUI-01): the TUI stays a thin front-end).
The TUI draws a QR with Unicode half blocks (`▀`, `▄`, `█` and space: two modules a character cell, top and bottom),
dark on light whatever the terminal's colours; in its monochrome mode the same; in its ASCII mode two `#` a dark module and
one text row a module row. A QR that does not fit the terminal is not drawn (`QrTerminalTooSmall`) and the TUI offers the
export. Several parts animate in the order and timing of §8.1. Import is by paste (one or more `scaas:` lines) or by a file
path; export as §8.1.

### 8.6 CLI

**SPECIFIED** ([CLI-SDK-17](../../clients/scaas-cli.md#CLI-SDK-17): one command per call, named flags, `--json`, the confirm
classes). The QR commands call the SDK for every build and check and the image layer for symbols and files only:

| Command | Does | Confirm class |
|---|---|---|
| `scaas qr export` | builds a payload (`--receive` or `--pay-request` with named flags, or `--hand-off <blob.json>` from `op hand-off`) and writes it `--as png`, `svg`, `apng`, `png-set` or `text`, `--out <path>` | none (`op hand-off` signs, in its own command) |
| `scaas qr show` | draws a payload in the terminal (the TUI's renderer; `--ascii`, `--frame <n>`) | none |
| `scaas qr import` | reads `.scaasqr` files, images or `-`, assembles, prints the review; a `signed-op` continues as `op import-signed` (quote, confirm, submit); a `pay-request` or `receive` continues as the payment or transfer it asks for | `op` |

`link` has no CLI import: the CLI has no camera (`QrSourceRefused`).

## 9. Safety on scan

**SPECIFIED** ([CLI-QR-07](../../decisions.md#CLI-QR-07)). A scanned payload is untrusted data from whoever made it.

- **Bounded decode** (§7) before anything else; no part is acted on alone.
- **Never sign on scan.** A scan ends in the SDK's review (`SignReview`, [CLI-SDK-35](../../decisions.md#CLI-SDK-35)) and the
  quote: the chain, the contract (listed or not), the entry, the amounts, the payee, the payer that pays the gas, the
  relayer binding, `valid_until` (with the time left), the fee, the signer, and for a hand-off that it was handed off and to
  whom it is bound. Any signature (the payer's `UAMetaTransfer`, the scanner's native transaction for a self-relay) is made
  only on the user's confirm of that review ([CLI-SDK-36](../../decisions.md#CLI-SDK-36)), and a fresh quote above the
  reviewed one asks again ([CLI-PQV-18](../../clients/pqvault-core.md#CLI-PQV-18)).
- **Mismatches.** A `chain_uid` that is not the active profile's: refused (`ProfileMismatch`). A `signed-op` contract that is
  not a listed token of the profile: refused (the import's `ProfileMismatch`). A `receive` or `pay-request` token that is not
  listed: a Caution with the address, and the user decides. A `pay-request` with a `payer` that is not the scanning account:
  `QrPayerMismatch` (the payee's reconciliation would not count the payment, [CTR-MTX-03](../../contracts/metatx.md#CTR-MTX-03)).
- **Expiry.** `valid_until` shown; a `pay-request` less than 120 s ahead of now is `QrExpired`, a `signed-op` the import's
  `ImportExpired`. A `signed-op` whose `valid_until` exceeds the lane horizon on a family that prunes lane state is refused as
  clientkeys refuses it ([CTR-MTX-04](../../contracts/metatx.md#CTR-MTX-04)).
- **Replay.** The contracts' rules hold: a signature runs at most once (its lane nonce), and a scanned `signed-op` already
  consumed is `ImportConsumed`. A `pay-request` is paid on `payLane(entryRef)` at nonce 0 by default
  ([CTR-MTX-10](../../contracts/metatx.md#CTR-MTX-10)), so scanning the same request twice cannot pay it twice: the second
  payment finds the lane spent and the review says the request is paid; paying a request again is the user's explicit choice
  of another lane. A `receive` carries no signature and replays nothing.
- **No decryption oracle** ([ARCH-POS-13](../../decisions.md#ARCH-POS-13)). Nothing in a scanned payload, or in a bulk its pins
  fetched, is ever decrypted, trial-decrypted or opened by the scanner: not a PQZ or Zether ciphertext, not a sealed opening,
  not an encrypted `PayMeta` body (which a QR cannot carry, §3.2). The review of a confidential operation says "amount
  hidden" and shows only public fields; a recipient learns what it received from its own balance in contract state, by its
  ordinary wallet path, never from the QR's bytes.
- **Confidential payloads.** A `receive` for a PQZ or Zether token carries the recipient's UA only: its encryption key is read
  from the chain's registry or the token, never from a QR. An `amount` in a QR is visible to anyone who sees it: the export
  says so for a confidential token. A QR never carries an opening, a blinding, a secret key, a seed or the sender
  randomness (§3.5).
- **Deep links and relays.** A `scaas:` URI opened by the platform only starts an import, the same as a paste. No payload
  holds a secret, so no relay, deep link or message can leak one; `link`, whose public key must come over an authenticated
  channel, is refused from any source but the camera.

## 10. Vectors

**PLANNED** ([CLI-QR-08](../../decisions.md#CLI-QR-08)). The byte format changes everywhere at once: clientkeys holds the JS
reference of the format core and generates `smartcontracts/vectors/qr/`; `scaas-qr`'s tests and the SDK's import tests read
the same rows, and `--check` regenerates and compares. Rows:

| File | Rows |
|---|---|
| `receive.json` | a UA id and a native address; with and without `amount`, `pay_no`, `token`: canonical hex and URI |
| `pay_request.json` | unsigned and payee-signed; `entryRef` equal to the metatx vectors' `metaPayId` for the same `PayMeta` |
| `signed_op.json` | a secp256k1 transfer (info + 1 signature part); **an `mldsa65` derived-UA payment: info part + 2 signature parts**; an `slhdsa128s` op (3 parts); each assembled from every order of its parts |
| `bulk.json` | a Zether single transfer (k = 6, systematic and the first repair frames); a PQZL transfer at `n2048-kmax1024` (k ≈ 67); a class (c) row (pins only, the bulk file beside it) |
| `link.json` | one `LinkSession` offer |
| `fountain.json` | the reference test cases of the UR fountain algorithm, re-checked |
| `negative.json` | one row per refusal of §13 that bytes can show: unsorted keys, a non-shortest integer, a duplicate key, an unknown field, depth 9, an oversized part, a foreign part, a conflicting part, a count mismatch, a digest mismatch, a bulk pin mismatch, a schema 3 body, an expired request, another chain |

## 11. Tests and gates

**PLANNED.** Per task, at its own suites ([round rule](../../../AGENTS.md)): the format core's unit tests over the vectors;
one fuzz target over every decode path (bytes, URI, text file, assembly); mutants on the bounds, the canonical check and the
part binding, each negative row able to fail (a positive control beside it); a property test that every order of a payload's
parts assembles to the same payload; `cargo build --target wasm32-unknown-unknown` of the core and `cargo tree -e features`
showing no `image` feature in the SDK's or scaas-app's default tree; the image layer's round trip (PNG, SVG, APNG, the set) and
the binary vectors through the chosen decoder; the TUI's snapshot of a drawn QR in each mode; a CLI end-to-end on a local
chain: `op hand-off` → `qr export --as png-set` → `qr import` → submit, for a secp256k1 and an `mldsa65` signer; a measured
scan time on two phones for the classes of §6, reported, not a gate.

## 12. Open questions for the owner

- **Q1. The class (b) bound.** Recommendation: k ≤ 72 source symbols (≈ 81 KB, about 15 to 20 s at 5 frames a second), so a
  PQZL transfer at `n2048-kmax1024` goes by animated QR; the alternative is k ≤ 24 (≈ 27 KB, under 6 s), Zether only, PQZ
  always by the bulk file.
- **Q2. Payment requests without a payer** (a till anyone pays at). Recommendation: allow them; the payee's client then locks
  the payer at the request's first settled payment, a change to CTR-MTX-03's "locked at start" for QR requests only, written
  into metatx.md and integration.md when built.
- **Q3. The payee's signature on a payment request.** Recommendation: keep it optional; the review shows "signed by <UA>, a
  known contact" or "not a known contact", and an unsigned request carries a Caution that anyone can show it.
- **Q4. Bulk by hash from a node.** Recommendation: not in this frame; the bulk file, a PqChat or Matrix attachment and the
  Arweave store cover it; a node endpoint would be its own node rule if asked for.
- **Q5. EIP-681 for EVM receive requests**, readable by other wallets. Recommendation: no; `scaas:` only, since another wallet
  would show neither UA ids nor the SCaaS review.
- **Q6. The default error correction level.** Recommendation: L by default (screens and files, fewer parts: the `mldsa65`
  vector is 2 signature parts), M as an export option for print.

## 13. Appendix: refusals

Named refusals of the format core and the SDK's QR calls (the CLI maps each to its code and exit code,
[CLI-CMD-01](../../clients/scaas-cli.md#CLI-CMD-01)): `QrMalformed` (not the subset, a wrong type, a missing field),
`QrNotCanonical`, `QrFieldUnknown`, `QrFieldDuplicate`, `QrVersion`, `QrKindUnknown`, `QrDepth`, `QrTooLarge`,
`QrInfoTooLarge`, `QrPartForeign`, `QrPartConflict`, `QrPartIndex`, `QrPartCount`, `QrDigestMismatch`,
`QrSignatureInvalid`, `QrBulkMismatch`, `QrBulkMissing`, `QrSchemaRefused`, `QrPayerMismatch`, `QrExpired`,
`QrSourceRefused`, `QrNotFound` (no QR in an image), `QrImageTooLarge`, `QrTerminalTooSmall`; and the existing
`ProfileMismatch` and `Import*` refusals of the hand-off import.
