# QR payloads in SCaaS clients: design

**Status:** SPECIFIED or PLANNED per section; nothing built. A frame written now, built after the pre-freeze tag and before
the freeze (owner 2026-11-28). Its rules are [CLI-QR-01](../../decisions.md#CLI-QR-01) to
[CLI-QR-08](../../decisions.md#CLI-QR-08) in decisions.md; this spec carries the design, the figures, the reasons and the
owner's questions (§12). Sources: the payment references and PayMeta ([metatx §6](../../contracts/metatx.md#CTR-MTX-03),
[CTR-MTX-26](../../contracts/metatx.md#CTR-MTX-26)), the payee self-relay row ([metatx §12](../../contracts/metatx.md#payers)),
the hand-off object ([SDK spec §27.5](2026-11-17-scaas-sdk.md), [CLI-SDK-09](../../clients/scaas-sdk.md#CLI-SDK-09), as built in
`clients/scaas-sdk/src/wallet/handoff.rs`), the CLI's hand-off blob ([scaas-cli.md §2](../../clients/scaas-cli.md)), the review
and sign-after-confirm rules ([CLI-SDK-35](../../decisions.md#CLI-SDK-35), [CLI-SDK-36](../../decisions.md#CLI-SDK-36),
[CLI-PQV-18](../../clients/pqvault-core.md#CLI-PQV-18)), the hidden receive QR
([CLI-SGN-14](../../clients/signers-clientkeys.md#CLI-SGN-14)), the link channel
([CLI-UAL-12](../../clients/ua-libraries.md#CLI-UAL-12)), the typed structs (`smartcontracts/vectors/typed/typed_ops.json`) and
the PQZ and Zether sizes ([pq-zero-knowledge.md](../../contracts/pq-zero-knowledge.md), the Zether prover's vectors). No
contract or contract byte format changes. Reviewed by Fable on 2026-11-28 (four areas: format, cross-layer clients, security, cryptography); every P1 and P2 is fixed
in this revision or put to the owner (§12; Q2 and Q7 ruled 2026-11-28); P3s left open: the taxed-token request (§3.2), a component doc
`docs/clients/scaas-qr.md` when the crate is built, the fountain overhead simulation (§11). UNAUDITED.

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
no new authority: whatever a scanned payload asks for is reviewed, quoted and confirmed exactly as the same operation typed by
hand, and a signed operation in a QR is judged by the hand-off import's checks.

Out of scope: a QR that a contract or the node reads (none does), wallet-connect style sessions, and EIP-681 or other wallets'
URI schemes (§12 Q5).

Changes to earlier frames, by the owner's ruling of 2026-11-28:

- The TUI spec's non-goal "No QR codes" ([TUI spec §1](2026-11-17-scaas-tui.md)) is lifted for the payloads here (§8.5).
- The CLI's "no other offline format" (owner 2026-11-27, CLI spec Q3) reads "no offline format but the hand-off blob, in its
  JSON form or in the QR forms of this spec" ([scaas-cli.md §2](../../clients/scaas-cli.md), the CLI spec, the Change under
  CLI-SDK-17 in decisions.md).
- The payee self-relay rows' "QR (EIP-681-style) tooling" ([metatx §12](../../contracts/metatx.md#payers),
  [integration.md](../../integration.md)) is this spec, not EIP-681.
- The SDK spec's registration blob "passed out of band (a QR code, a message)" (§7) has no QR form (§3.5).

Changed by the owner's ruling on §12 Q7 (2026-11-28): the SDK's refusal to import a confidential operation (SDK spec §27.5 (g) 9,
CLI-SDK-33 (49) (c), `ImportKindRefused`) is lifted for scan and submit only, when built (§6).

## 2. The crate `scaas-qr`

**SPECIFIED** (owner 2026-11-28, [CLI-QR-01](../../decisions.md#CLI-QR-01)). A crate of its own, `clients/scaas-qr`, in two
layers:

| Layer | Holds | Depends on | Built for |
|---|---|---|---|
| Format core (default features) | the payload types (§3); the canonical bytes and the `scaas:` URI (§4); the split into info, signature and bulk parts and their assembly (§5, §6); the fountain coder (§5.4); the part binding and bulk pin checks; every bounded decode (§7) | no image library, no `scaas-sdk`, no `ua-rs` | every target, `wasm32-unknown-unknown` included |
| Image layer (feature `image`) | QR symbol encoding (one explicit byte-mode segment); PNG, SVG and APNG writing; PNG, JPEG and APNG frame decoding; the terminal renderer (§8.5) | the format core and the image crates below, all pure Rust | native targets and `wasm32` |

The dependency points one way, as `scaas-profile`'s does: `scaas-sdk` depends on the format core, never the reverse, and takes
no image crate; `scaas-tui`, the CLI and scaas-app link the crate with `image` where they draw or scan a symbol. scaas-app's
web and extension front-ends build the image layer for `wasm32` and feed it the frames of the page's camera, so every
front-end draws and reads symbols with the same code ([stack.md](../../clients/stack.md) rule 10).

**A feature, not a sibling crate.** One crate keeps one version, one vector reader, one `deny.toml` and one fuzz target for
the two layers, which change together whenever the format does. The risk of a feature, Cargo's feature unification pulling
the image crates into a build that did not ask for them, costs size only (the image layer signs nothing and holds no
secret), and the gate checks it: `cargo tree -e features` of the SDK shows no `image` feature, and a `wasm32` build of the
core alone runs in CI (§11).

**What the crate does not do.** It signs, verifies, encrypts and decrypts nothing. Its hashes (`keccak256` for the part
binding and the bulk pins, SHA-256 and CRC-32 inside the fountain coder) are integrity checks of the transport over public
bytes: an exception to the letter of [CLI-SDK-01](../../clients/scaas-sdk.md#CLI-SDK-01) ("every hash a byte format fixes stays
in `ua-rs`") recorded in CLI-QR-01. They are never the guard: the guard is `ua-rs`'s rebuild of every signed digest from the
assembled payload and the check of every signature (§5.2 (3)), which always runs.

**Candidate crates** (PLANNED; each pinned exactly at its newest release at least 14 days old when the crate is built, and
covered by the crate's own `cargo deny` (dev-dependencies included) and `cargo audit` gate, as `scaas-matrix` is; licences as
their manifests declare them, checked again by `cargo deny` against the SDK's allow-list):

| Use | Layer | Candidate | Licence | Note |
|---|---|---|---|---|
| Keccak-256, SHA-256 | core | `sha3`, `sha2` (RustCrypto) | MIT OR Apache-2.0 | already in the client tree through `ua-rs` |
| CRC-32 | core | `crc32fast` | MIT OR Apache-2.0 | the fountain coder's checksum |
| base64url | core | `base64` | MIT OR Apache-2.0 | already in `scaas-profile`; strict decoding (no padding, zero trailing bits) |
| Deterministic CBOR subset | core | written in the crate (about 300 lines, §4.2) | — | the canonical check, the depth bound and the refused major types exact; `ciborium` (Apache-2.0) at most as a test oracle |
| Fountain coder | core | written in the crate after the published UR fountain algorithm (§5.4) | — | checked by the algorithm's published reference cases; no oracle crate |
| QR symbol encoding | image | `qrcode` | MIT OR Apache-2.0 | one explicit byte segment (its optimiser could pick a Kanji segment that some readers mangle), fixed ECC level, version range |
| QR decoding | image | `rqrr` (MIT OR Apache-2.0), else `rxing` (Apache-2.0) | as listed | the small one first; the chosen one must return the byte segment exactly: the binary vectors decide (§10) |
| PNG and APNG write and read | image | `png` | MIT OR Apache-2.0 | APNG frames and delays |
| JPEG read | image | `zune-jpeg` | MIT OR Apache-2.0 OR Zlib | directly, or through `image` |
| Image container | image | `image`, `default-features = false`, features `png` and `jpeg` only | MIT OR Apache-2.0 | its `Limits` bound every decode (§7); no GIF, WebP, TIFF decoders |

## 3. Payload kinds

**SPECIFIED** ([CLI-QR-02](../../decisions.md#CLI-QR-02)) for `receive`, `pay-request` with a named payer, `signed-op` of a
non-confidential operation and `link`; the rest PLANNED where marked. A payload is one **info part**, followed by the
**signature parts** and **bulk parts** the info part declares (§5, §6):

| Kind | Who shows it | Who scans it | Signature parts | Bulk parts |
|---|---|---|---|---|
| `receive` | a receiver | a payer | none | none |
| `pay-request` | a payee (its client or ERP) | a payer | the payee's signature, optional | none |
| `signed-op` | a signer | the party that submits it and pays the gas | the entry's signature, and each further signature the entry takes | for an operation with a proof or ciphertexts (§6, PLANNED) |
| `link` | a new device | the user's existing device, in its "link a new device" flow | none | none |

### 3.1 `receive`

A receiver's address for one chain: `chain_uid`, exactly one of `to_ua` (a UA id) and `to_address` (the family's native
address), `token` (absent = the chain's native coin), and optionally `amount` (base units), `pay_no` (as `PayMeta.payNo`) and
`relayer` (the receiver's payer address, for a hand-off bound to it, SDK spec §27.5 (b)). A single QR of 120 to 230 bytes
(version 6 to 9 at level L). The payer's client builds its own operation from it: a transfer; with `pay_no`, a payment whose
`PayMeta` the payer's client makes (a fresh `salt`, the scanned `pay_no`, `save` false, schema 0). Such a payment's `entryRef`
is the payer's, so the receiver matches it by `payNo` alone, through the `PaymentMeta(payId, payNo, …)` event and the
`UAPaymentSettled` of the same `payId` (a path [integration.md](../../integration.md) gains when built), never by the
`(token, payer, payee, entryRef)` key of a payment request. The receive QR stays hidden for an account without a backup while
the backup switch is on ([CLI-SGN-14](../../clients/signers-clientkeys.md#CLI-SGN-14)).

**scaas-app's default build** (no SDK, no SCaaS signing) shows a `receive` with `to_address` for a native account it holds,
and scans only such a `receive`: it maps `chain_uid` to a chain by the chain table of its release data, refuses an unknown
`chain_uid` (`ProfileMismatch`), a `to_ua`, a `pay_no` and every other kind (`QrNeedsScaas`), and shows its own native wallet's
review before its own confirm. Every rule of §9 holds there except the SDK's review and quote, which its native wallet replaces.

### 3.2 `pay-request`

A payee's request, in the named fields of [CTR-MTX-03](../../contracts/metatx.md#CTR-MTX-03) and
[CTR-MTX-26](../../contracts/metatx.md#CTR-MTX-26): `chain_uid`, `token`, `to` (the payee id), `amount`, `meta` (`salt`,
`pay_no`, `save`, `schema`, `body`), `valid_until` (the request's `issued_valid_until`), optionally `payer` (the payer the request is for; without it anyone may pay it, owner 2026-11-28), and optionally `relayer`, a **hint** (owner 2026-11-28): the relayer the payee suggests, e.g. one it hired to pay the gas, or
itself when it self-relays and wants the signed payment handed back (§8.6). The payer's review offers it as an option: by
default the payment is signed with `relayer` unbound (any relayer may submit it); the payer may choose to bind it to the
suggested relayer, and the review then names that relayer. The hint never binds anything by itself. The
scanner computes `entryRef` itself with its chain's own `metaPayId` (metatx §6: v3 on the EVM; on a family still on the v1 form
`pay_no` must be zero, `save` false and `body` within the family's cap, else `QrPayMetaRefused`); the request carries no
`entryRef` field. `schema` is 0, 1 (note) or 2 (structured reference); a bound call (3) or an encrypted body (4) is
`QrSchemaRefused`, because the payer must read what it signs. A request on a token whose pay entry is the taxed one is
PLANNED with the regulated kinds' client support.

**The payee's signature** (optional; §12 Q3). A typed record `PaymentRequest` with every named field above and `chain_uid`,
signed by the payee's UA through `ua-rs` under a new off-chain purpose `scaas.ua.purpose.pay-request.v1` (outside every
contract's purpose list, as the seal purpose is, [CLI-SGN-44](../../clients/signers-clientkeys.md)), in a fixed domain (name
`SCaaS payment request`, version `1`, the chain id, no `verifyingContract`), so no contract computes this digest under any
purpose it accepts. The signer must be `to`; a signature by another id is `QrSignatureInvalid`. It is verified as §5.2 (3)
states for every signer class; a payee whose signature cannot be checked here (a contract account, a key only the registry
holds when no registry read is possible) is shown as unsigned with the Caution. A signature proves who issued the request, not
that it is the scanner's order (the review says so).

### 3.3 `signed-op`

The hand-off object `SignedOpBlob` (SDK spec §27.5 (c), as built: `v, chain_uid, family, contract, entry, struct, kind,
message, extra, signature, signer, signer_kind, ids`) carried as parts: the blob without its signatures in the info part's `op`
(§4.3), and each signature in signature parts of its own slot: `auth` for the entry's `signature`, and the name of each
signature the entry takes in `extra` (for the PQZ proof-taking entries `pqzAuth`, a full UASig over its own `PqzAuth`
statement; for the Zether owner entries `ownerSig`). An unsigned value of `extra` that is not a signature (`pqzVerdict`) stays
in `op` when it fits the info part, else it is pinned as bulk (§6.1) and is judged by the chain alone, which the review says.
Each slot carries its own `digest`: the typed digest (EIP-712 on the EVM) of its statement, which the scanner rebuilds.

Both directions of the hand-off use it:

- **Scan and submit** ("pay the partner's gas from a scanned QR"). For a kind with a payee (a transfer, a payment) the scanner
  is the payee (`ImportNotPayee` otherwise). The signer signed with fee 0 and `relayer` unbound or bound to the scanner's payer
  address; the scanner's SDK runs `Op::import_signed` on the assembled blob with every check of §27.5 (c) (`ProfileMismatch`,
  `ImportKindRefused`, `ImportNotPayee`, `ImportRelayerBound`, `ImportFeeRefused`, `ImportExpired`, `ImportConsumed`), quotes it,
  shows the review and, on the user's confirm, submits it as a self-relay paid by the scanner's native key.
- **Show for a partner.** `Op::hand_off` signs the user's own operation after its review and confirm; the front-end shows or
  exports the blob in the forms of §8 and keeps it (public data) until a chain fact ends the row (`Landed`, `Consumed`,
  `Expired`, or the user's cancel), since `Op::hand_off` returns it once.

A fee-bearing relay by a third party is not a hand-off and has no QR form here.

### 3.4 `link`

The public offer of a `ua-rs` `LinkSession`: its `kemPk` (`0x01 ‖ ek ‖ pk_X`, 1,601 bytes) and the session's start time, as
`ua-rs` exports them. A single QR at level L or M; a link is bound to no chain, so `link` is the one kind without `chain_uid`.
The 8-digit short code is not in the QR; the user compares it as today.

A camera cannot tell the user's new device from any other screen or a printout, so the source alone does not authenticate the
key: a page that says "scan to sign in" could show an attacker's offer. A `link` is therefore accepted only inside a "link a
new device" flow the user started on the existing device: in any other scanner mode, and from a file, a picked image, a paste
or a URI, it is `QrSourceRefused`; "camera" means live frames only, and the source is an input of the SDK's call that the
front-end's flow sets, never inferred by the format core. A scanned `link` ends in a confirm of its own, which says that the
scanned device will receive the whole wallet, before `link_seal` runs; an offer whose start time lies outside CLI-UAL-12's link
window on the scanner's clock is `QrExpired`. A camera-less client (the TUI, the CLI) takes no `link` by QR. This keeps
[CLI-UAL-12](../../clients/ua-libraries.md#CLI-UAL-12): the authentication is the user's act of scanning their own device's
screen in that flow.

### 3.5 Not payloads

The registration blob (SDK spec §7, up to 768 KiB) has no QR form in this frame: a PQ registration with a PQZ key's proof
exceeds every bound of §6 and goes as a file, as today. No payload carries a secret: no seed, private key, key handle export,
passphrase, PQZ opening in clear, Zether sender randomness or seed, opening token, or the plaintext of an encrypted `PayMeta`
body. Every envelope field of every kind is in the schema tables of §4.3; an unknown field is refused, and inside `op` the
rebuild by `ua-rs` refuses any field the struct does not have, so a secret has no field to travel in.

## 4. The canonical form

**SPECIFIED** ([CLI-QR-02](../../decisions.md#CLI-QR-02)).

### 4.1 Bytes and URI

- **Canonical bytes** of a part: the two ASCII bytes `SQ`, the format version byte `0x01`, then one map in the deterministic
  CBOR subset of §4.2. The prefix is framing; its version byte is the only format version (`QrVersion` judges it); a `v` inside
  `op` is the carried blob's own.
- **URI form**: `scaas:` followed by the base64url encoding (RFC 4648 §5) of the same canonical bytes, no padding, one part per
  URI. It is the text form for a paste, a message, a file line and a link the platform opens. A URI is accepted only if
  encoding its decoded bytes gives back the same text: the scheme in lower case, no `//`, no padding, zero trailing bits, no
  `+` or `/`, no whitespace (`QrNotCanonical`).
- **In a QR symbol**: the canonical bytes as one byte-mode segment, with no ECI header. A QR scanned by a generic camera app
  shows nothing useful, on purpose: a SCaaS payload needs a SCaaS review. No symbol carries the URI form.

**Why CBOR rather than the SDK's JSON.** The hand-off blob's JSON carries crypto objects as `0x` hex, twice their size. In a QR
that difference is the frame count: an ML-DSA-65 signature with its key data (5,261 bytes) is two QR parts as CBOR byte
strings, three as base64 and four as hex. The SDK keeps its JSON for files and APIs; §4.3 maps the two one to one.

### 4.2 The CBOR subset

RFC 8949 core deterministic encoding (§4.2.1), restricted to: maps with text keys only, sorted by their encoded bytes; unsigned
integers up to 2^64 − 1 in their shortest form; byte strings; text strings of printable ASCII (0x20 to 0x7E); arrays; the two
simple values `true` and `false`. Refused: negative integers, floats, tags, every other simple value (`null` and `undefined`
among them), indefinite lengths, duplicate keys, keys that are not text, text outside printable ASCII, and trailing bytes
after the map. A decoder re-encodes what it read and refuses any difference (`QrNotCanonical`), so every value has one byte
form. Printable ASCII keeps Unicode normalisation out of the core and of the JS reference, and keeps control characters and
bidirectional overrides out of every scanned text.

### 4.3 Envelope and `op`

**Envelope fields** (every kind's own fields, and the parts' framing) are typed by the kind's schema table, fixed when built
and pinned by the vectors (§10), with these types:

| Type | CBOR | Rule |
|---|---|---|
| `bytes32` | byte string of 32 | ids, `chain_uid`, `salt`, `pay_no`, digests, hashes |
| `bytes` | byte string | exactly one crypto object (a signature, a key, a proof, a ciphertext) or one opaque value (`PayMeta.body`, at most 1,024 bytes); never several fields packed |
| `uint` | unsigned integer | at most 2^64 − 1 (`valid_until`, `schema`, frame numbers); the JS reference decodes it as a BigInt |
| `u256` | text of decimal digits | amounts, no sign, no leading zero, at most 2^256 − 1 |
| `address` | text | the family's canonical address form, printable ASCII, at most 128 bytes (EVM: `0x` and 40 lowercase hex digits; Aptos and Sui: `0x` and 64) |
| `text` | text string | short names (`kind`, `slot`, a pin path); at most 64 bytes |
| `bool` | `true` / `false` | `save` |

Every info part carries `kind` and, except `link`, `chain_uid`; a payload is bound to one chain, and a payload whose `chain_uid`
is not the active chain profile's is refused (`ProfileMismatch`, §9).

**`op`** (a `signed-op`'s info part) is the hand-off blob, its names byte for byte (camelCase inside `message` and `extra`, as
built), without the signatures that go to slots (§3.3), mapped from its JSON by shape with one closed rule: a JSON string that
matches `^0x([0-9a-f]{2})*$` is a byte string; every other JSON string is a text string; a JSON integer is an unsigned integer;
a JSON boolean is a boolean; objects and arrays are maps and arrays. The SDK writes the blob's hex in lower case; a decimal
`uint256` stays a text string. The format core types nothing inside `op` beyond this shape rule: the struct's field types and
the refusal of a field the struct does not have are `ua-rs`'s, at the digest rebuild (§5.2 (3)), so no second copy of the
struct tables lives in the core. The one exception is the pinnable-path table of §6.1, a data table generated from
`typed_ops.json`.

**Frames are not packed fields.** A signature or bulk part's `data` is a slice of one object's canonical bytes (§5, §6): a
transport frame. Reassembled, it decodes as the typed map it was cut from, or the assembly is refused; no frame is ever read
as a parameter.

## 5. Size: the split by meaning

**SPECIFIED** (owner 2026-11-28, [CLI-QR-04](../../decisions.md#CLI-QR-04)).

### 5.1 What one QR holds

A QR symbol holds at most 2,953 bytes in byte mode (version 40, level L; 2,331 at M, 1,663 at Q, 1,273 at H). The parts use
level L by default (a screen or a file is not damaged as print is) and the smallest version that holds the part; the export
takes level M as an option (§8.1), and the part counts below then grow. One table frames signature and bulk parts alike:

| Field | Type | Signature part | Bulk part |
|---|---|---|---|
| `part` | text | `sig` | `bulk` |
| `info` | bytes32 | the binding hash (§5.2 (2)) | the same |
| `slot` | text | the signature's slot (`auth`, `pqzAuth`, …) | absent |
| `seq` | uint | 1 to `count` | 1 to 2^32 − 1 (above `count`: repair frames) |
| `count` | uint | the slot's parts, as the info part declares | k, the bulk's source fragments |
| `len` | uint | the signature object's length | the bulk object's length |
| `crc32` | uint | CRC-32 of the object | the same |
| `data` | bytes | one fragment | one fragment, or a repair frame |

With the prefix and the key names this header is at most 128 bytes, so a signature part carries up to 2,825 bytes of data at
level L and a bulk frame (version 25, level L, 1,273 bytes) up to 1,140.

### 5.2 The rule

When a payload does not fit one QR, it is split by meaning first, never cut blindly:

1. **The info part is complete and reviewable on its own, and declares the rest.** It holds every named field of the intent:
   the chain uid, the contract, the entry, the operation's fields, `valid_until`, the relayer and payer bindings, each slot's
   digest, and for an operation with a proof or ciphertexts their pins (§6). It declares its signature slots with their part
   counts (`sigs`, zero slots for an unsigned payload) and its bulk (`bulk`: length and k). The SDK's `Qr::review_info` gives
   the full `SignReview` from the info part before any other part arrives, its signer and payee rows marked "not verified yet"
   and a pinned field shown by its length and pin. The confirm is offered only on the review of the assembled payload, once
   every declared part is held and checked (for a `signed-op`, the `Prepared` that `Op::import_signed` returns). The info part
   is always one QR; an info part above one QR is `QrInfoTooLarge`, and the payload goes as the hand-off blob's JSON file.
2. **Every other part binds to exactly one info part.** It carries `info = keccak256("scaas.qr.info.v1" ‖ canonical bytes of the
   info part)`, its slot, its frame number and its count. Parts are accepted in any scan order: parts that arrive before their
   info part are held under the first `info` seen, within the bounds of §7, until the info part comes. A part whose `info`
   differs from the one held is `QrPartForeign` and is dropped; a second, different info part in one import is
   `QrInfoConflict`; two parts with the same slot and frame number and different bytes, a `count` that differs from the
   declared one, or a frame number outside its range (`QrPartIndex`) refuse the whole import, nothing kept. An import that
   ends with a declared part missing is `QrIncomplete`, naming what is missing. The binding hash is consistency, not
   authentication: anyone who rewrites the info part rewrites it too. What cannot be changed unnoticed is what the
   signatures cover; every review row outside them (`signer`, `signer_kind`, `ids`, the part counts, `bulk_at`) carries the
   source "request" ([CLI-SDK-35](../../decisions.md#CLI-SDK-35)).
3. **The scanner never trusts a digest field.** For each slot, the SDK has `ua-rs` rebuild the digest from the info part's
   fields with the signer's own builder and refuses a different `digest` (`QrDigestMismatch`); it then checks the assembled
   signature against what that signer's key really signs, before it offers to submit (`QrSignatureInvalid`):
   - a native key (an EOA, a family's native account): over the rebuilt digest;
   - a derived UA: first `ua-rs` derives the id from the signature's `keyData` and kind and requires it to equal `signer`, then
     verifies over `ua-rs`'s UA message for (the kind, the entry's purpose, `PURPOSE_METATX` or `PURPOSE_METATX_CANCEL`, the
     profile's registry domain, `signer`, the digest);
   - a UA whose key or kind the registry holds, an `msig` (derived or registered), an ERC-1271 contract account: the kind and
     key are read from the registry through the profile's RPC list ([ARCH-POS-15](../../decisions.md#ARCH-POS-15)), never from
     the payload, then verified as above where `ua-rs` can; where it cannot, the chain's simulation from the payer is the
     check, as the hand-off import states, and the review says which check ran.
   This adds local checks before the import's simulation; it removes none.
4. **Only a signature larger than one QR is chunked.** Its parts are plain numbered chunks of the signature object's canonical
   bytes (the UASig's named fields `keyData`, `signature`, `members`): the fragments of the fountain coder of §5.4 at its
   fragment-length rule with the part maximum, frames 1 to `count` with no repair frames. One coder serves both uses and no
   second framing exists. At most 16 parts a slot and 32 in all; above, `QrTooLarge`, and the payload goes as the hand-off
   blob's JSON file.
5. **The same split in every form.** The PNG set, the animated APNG, the `.scaasqr` file and a live display hold the same
   parts: the info part, then each slot's parts, then the bulk (§8).

### 5.3 Signature parts per signer kind

At level L, with the key data a derived UA carries in its UASig ([CTR-UA-36](../../contracts/accounts.md#CTR-UA-36)); a UA
whose key the registry holds sends no key data and needs fewer parts. Key and signature sizes from
[key-schemes.md](../../networks/key-schemes.md) and FIPS 204 / 205; the counts hold with headroom for the 128-byte header.

| Signer kind | Signature + key data | Parts at the default maximum (2,825 B) | At a 1,140 B maximum |
|---|---|---|---|
| EOA secp256k1, ed25519, P-256, BIP-340 | 64 to 130 B | 1 | 1 |
| WebAuthn (assertion capped at 1,024 B of `authData` and `clientDataJSON`) | ≤ about 1,200 B | 1 | 2 |
| `fndsa512` | ≤ 752 + 897 B | 1 | 2 |
| `mldsa44` | 2,420 + 1,312 = 3,732 B | 2 | 4 |
| `fndsa1024` | ≤ 1,462 + 1,793 B | 2 | 3 |
| `mldsa65` | 3,309 + 1,952 = 5,261 B | 2 | 5 |
| `mldsa87` | 4,627 + 2,592 = 7,219 B | 3 | 7 |
| `slhdsa128s` | 7,856 + 32 = 7,888 B | 3 | 7 |
| `msig` | the members' signatures together | as their sum; above 16, file form | — |

A PQZ entry signed by an `mldsa65` holder has two slots (`auth` and `pqzAuth`), so four signature parts at the default.

### 5.4 Numbered chunks or a fountain code

**Recommendation, adopted in this frame: plain numbered chunks for signatures; the fountain code only for bulk.** A signature
takes at most 16 parts and usually 2 or 3; a looping display shows each again within a second or two, so a missed frame costs
one loop, and a printed set has only the chunks. A fountain code earns its place where the frame count is tens (§6).

**The coder.** The fountain algorithm of the Uniform Resources specification (Blockchain Commons BCR-2020-005, multipart UR):
a systematic Luby transform, frames 1 to k being the source fragments themselves; the fragment length by its
`findNominalFragmentLength` (the fewest fragments no longer than the part maximum, all of one length ⌈len / k⌉, the last padded
with zeros and cut back to `len` on assembly); frames above k mixing fragments chosen by Xoshiro256** seeded from SHA-256 of
the frame number and the object's CRC-32, the degree drawn with weights 1/i. It is pinned by the vectors (§10), the
algorithm's published reference cases among them, and by rows at k = 72 with frame numbers near 2^32, so the JS reference and
Rust on native and `wasm32` draw the same choices. CRC-32 is the coder's seed and an early error signal, not integrity: one
frame with the right `info` and wrong data spoils the reduction, and the result then fails its CRC-32, its pins (bulk) or its
signature check (signature); the import is refused by name (`QrBulkMismatch`, `QrSignatureInvalid`) and the user scans again,
with no automatic retry loop.

Only the algorithm is taken: the UR text form (bytewords, the `ur:` scheme, UR CBOR types) is not, because bytewords cost
about 37 % more QR capacity than byte mode and the UR registry types mean nothing outside SCaaS. RaptorQ (RFC 6330) was set
aside: a larger implementation for gains that matter only above hundreds of frames, and IETF IPR declarations against it.
The LT code's own patents were filed in 1998 to 2002; no live claim is known to the authors, which is not a legal opinion.

## 6. Proofs and ciphertexts

**SPECIFIED** (owner ruling 2026-11-28, §12 Q7), built with the crate; the rule below
([CLI-QR-05](../../decisions.md#CLI-QR-05)). A `signed-op` whose operation carries a zero-knowledge proof or ciphertexts (a PQZ
or a Zether operation) is the funds' owner's: **the owner's client makes the proof and signs**, holding the keys; the partner
who scans it only relays and pays the gas. The partner computes nothing secret, holds no key of the owner's and decrypts
nothing (§9).

### 6.1 Pins in the info part

The large `bytes` fields of the signed struct stay out of the info part, which carries for each its path (text, e.g. `proof`,
`args.legs.0.v`), its length and its `keccak256`; the field itself is absent from `op`. Which paths may be pinned is fixed per struct by a table generated from
`typed_ops.json`, compiled into the format core and read by the JS reference: for `UAPqzTransferSingle` `proof`, `accHint`,
`args.u`, `args.vTo`, `args.vFrom`, `args.vAuditor`, `args.uFrom`, `args.sealedMemo`, each opening's `mlkemCt` and
`sealedSeed`; for `UAZetherTransferSingle` and its siblings `proof`; and so on for each confidential struct. A pinnable path
is always pinned; any other pin (a call's `data`, a memo the review decodes), a duplicate path, a pin of length 0 or pins whose
lengths sum above the bulk bound is `QrPinRefused`, before any fetch or allocation.

EIP-712 encodes a dynamic `bytes` field as the keccak-256 of its bytes, also inside `bytes[]` and inside arrays of structs, so
`ua-rs` rebuilds each digest from the info part alone. That builder input ("this field by its hash", PLANNED in `ua-rs`) exists
only on a digest-rebuild call that returns a digest and cannot sign: `sign_typed` under every `Expect` refuses it, and one test
proves the refusal, so no caller obtains a signature over a proof or ciphertext the signer never held. The bulk object is one
map of exactly the pinned fields; on arrival each field's `keccak256` must equal its pin, every pin must be filled and no other
field may appear (`QrBulkMismatch`, `QrBulkMissing`). A family whose signed message holds such a field in full, not by its
hash, has no pinned form: its operation goes as the hand-off blob's JSON file.

The pins are integrity checks; proofs and ciphertexts are public data that land in calldata and contract state anyway (never
lose ciphertext: the contract keeps every ciphertext in state as before; this transport changes nothing on chain).

### 6.2 Size classes

The bulk object is cut into fragments of at most 1,140 bytes (§5.1). Frame counts are for the bulk alone; the info and
signature parts come first.

| Class | Bulk | Form | Proposed bound |
|---|---|---|---|
| (a) | none | info part and signature parts (§5) | — |
| (b) | `len` ≤ 82,080 B (k ≤ 72) | animated: frames 1 to k systematic, then repair frames; a PNG set holds the k systematic frames | §12 Q1 |
| (c) | above (b), or by choice | the info part pins the bulk; the bulk travels by another channel (§6.4) | the import's bound (§7) |

### 6.3 Zether and PQZ, apart

Estimates, not measurements, at 5 frames a second: with every frame read, k frames suffice. With frames missed, the 1/i degree
distribution resolves the last missing fragments slowly, so a second loop of systematic frames often finishes first; the
figures below assume about 1.3 · k frames shown and stay estimates until the simulation and the scan measurement of §11
(before Q1 is ruled).

**Zether** (classical, BLS12-381; sizes from `clients/zether-prover/vectors/`). The signed struct's points are small and stay in
the info part (`ZetherSingle` 880 B, `ZetherMulti` with decoys 2,233 B); the proof is the bulk.

| Operation | Proof | k | Frames shown | Time at 5 fps |
|---|---|---|---|---|
| unshield (burn) | 2,816 B | 3 | 3 to 4 | about 1 s |
| single transfer | 5,888 B | 6 | 6 to 8 | 1 to 2 s |
| multi transfer (with auditor) | 11,936 B | 11 | 11 to 15 | 2 to 3 s |

A `ZetherMulti` info part with many legs can exceed one QR (`QrInfoTooLarge`); such a transfer goes as a file.

**PQZ** (post-quantum; sizes from [pq-zero-knowledge.md](../../contracts/pq-zero-knowledge.md)). A ciphertext is 16,512 B at
`n2048-kmax1024` (18,560 / 20,608 / 22,656 B at the other sets), a transfer proof 42,762 B in PQZL and about 231 KB in PQZH; a
PQZL transfer is about 77 KB of calldata, nearly all of it proof and ciphertexts.

| Operation | Bulk | k | Frames shown | Time at 5 fps | Class |
|---|---|---|---|---|---|
| PQZL transfer, `n2048-kmax1024` | about 77 KB | about 68 | 68 to 89 | 14 to 18 s | (b) |
| PQZL transfer, larger sets | about 80 to 90 KB | 71 to 79 | — | — | (b) or (c) by set |
| PQZH transfer | about 264 KB | about 232 | — | about 60 s | (c) |
| multi-leg PQZ transfer | at least 16,640 B of calldata more per leg | grows | — | — | (c) |

The class follows the measured size of the operation at hand, not its name: one rule on every chain and every set.

### 6.4 Above the bound: the bulk by another channel

For class (c), the QR forms carry the info part and the signature parts only; the bulk goes as the exported bulk file
(`.scaasbulk`, §8.1; the CLI's `--bulk <file>`), or as an attachment in a PqChat or Matrix conversation. Integrity is the pins
alone, whatever the channel: a bulk that does not match is refused, and the operation stays reviewable (and refusable) from the
info part while its bulk is missing. The Arweave store is PLANNED as a channel: it needs an unsealed public upload and a read
checked by the pins in the SDK (today's calls seal an app core's file and check SHA-256, [CLI-SDK-21](../../clients/scaas-sdk.md)),
the operator payer for objects above 64 KiB, and a fetch only on the user's action, bounded by the pinned lengths while it
streams; until then the info part names no locator, never an `http` URL. A bulk put on a public store is public before the
operation lands, and with an unbound relayer the info part plus that bulk lets anyone land it: class (c) defaults to a
relayer bound to the partner. A node endpoint serving bulk by hash is not part of this frame (§12 Q4). No channel ever carries a
secret, because no payload holds one (§3.5).

## 7. Decode bounds

**SPECIFIED** ([CLI-QR-03](../../decisions.md#CLI-QR-03)). Every decode is bounded by length and by depth before it allocates,
and every refusal is named (§13):

| Input | Bound |
|---|---|
| One part's canonical bytes | 2,953 B (one QR at version 40, level L) |
| One URI line | 3,944 characters (`scaas:` and the base64url of 2,953 B) |
| CBOR nesting | depth 9 (the hand-off blob's 8, under the envelope); at most 64 entries a map, 256 elements an array |
| Strings | `text` 64 B, `address` 128 B, `PayMeta.body` 1,024 B, `u256` at most 2^256 − 1 |
| Signature parts | at most 16 a slot, 32 in all |
| Bulk | `len` ≤ 82,080 B and k ≤ 72 in QR form, checked on the first frame; a `.scaasbulk` file at most what the hand-off import takes with its blob (§12 Q7: 256 KiB of JSON today) |
| Fountain frames held | at most 2 · k + 16 per payload; frame numbers below 2^32 |
| Parts held | one payload at a time; a foreign part is dropped, not queued |
| `.scaasqr` file | 512 KiB, at most 128 lines; one trailing CR a line is ignored, empty lines skipped, a byte-order mark refused |
| Images | 8,192 px a side and 64 MiB decoded, counted in the file's colour type, one frame at a time (frames never held together); at most 256 frames and 128 files per import, all files together |

Unknown or missing fields, a wrong type, a non-canonical encoding and trailing bytes are refused. A payload that exceeds a QR
bound (an info part above one QR, a signature above its parts) has no QR or `.scaasqr` form; its file form is the hand-off
blob's JSON, which keeps its own bounds. The format core has one fuzz target over every decode path (§11).

## 8. Export and import

**SPECIFIED** for the forms; the camera PLANNED with scaas-app ([CLI-QR-06](../../decisions.md#CLI-QR-06)).

### 8.1 Export forms

| Form | Payload | Content |
|---|---|---|
| PNG, SVG | one QR (an info part alone) | the symbol, dark modules on a light background in every theme, a quiet zone of 4 modules; PNG at 8 px a module by default |
| Numbered PNG set | several parts | one PNG per part, named `<stem>-00-info.png`, `<stem>-<slot>-01-of-02.png`, `<stem>-bulk-001-of-068.png` (the k systematic bulk frames only) |
| Animated APNG | several parts | the frame order and timing below |
| `.scaasqr` text | any that fits the QR bounds | UTF-8, one URI per line (§4.1): the info part first, then each slot's parts, then the k systematic bulk parts |
| `.scaasbulk` | class (c) bulk | the bulk object's canonical bytes |

Options: level L (default) or M, the largest part (the default fits one QR; a smaller one, down to 1,140 bytes, cuts a
signature into more, smaller symbols within the caps of §5.2 (4)), the module size, the frame rate (2 to 10 frames a second).
GIF is not offered: APNG is lossless, and a viewer that cannot animate it shows its first frame, which is the info part and
complete for review. Exported files are created readable by their owner only; the export of a `signed-op` says "whoever holds
this can submit it until <time>", and of a confidential token's amount that the amount is visible to anyone who sees the QR.

**APNG frame order and timing** (owner 2026-11-28): frame 1 is the info part, shown 1,000 ms; then each slot's parts in order;
then, for class (b), the bulk frames 1 to k and ⌈k/2⌉ repair frames from k + 1; a frame above version 30 is shown 500 ms and
every other frame 200 ms (5 frames a second), until the measurement of §11 fixes them; the animation loops without end. A
live display (scaas-app, the TUI) keeps the order and timing, but its repair frames keep their numbers rising from loop to
loop, so each loop brings new ones.

### 8.2 Import sources

From a `.scaasqr` file or pasted lines (in any order); from one or more image files (PNG, JPEG, the frames of an APNG, a
numbered set); from a camera (scaas-app, live frames); from a `scaas:` URI the platform opens. Each import records its source,
set by the front-end's flow; the source matters only for `link` (§3.4). An import ends in a review (§9), never in a signature.

### 8.3 Files

A payload with no QR form (§7) travels as the hand-off blob's JSON file only. A class (c) bulk is the `.scaasbulk` file beside
the `.scaasqr`.

### 8.4 scaas-app

**PLANNED** with scaas-app. The camera hands live frames to the image layer's decoder (native, or `wasm32` in the web and
extension front-ends); a platform reader that returns only text mangles byte mode and is not used. The default build (no SDK)
handles `receive` as §3.1 states; the `scaas` build adds the other kinds.

### 8.5 TUI

**PLANNED** for the TUI's next round, its screens and timer added to the TUI spec then
([CLI-TUI-01](../../clients/scaas-tui.md#CLI-TUI-01): the TUI stays a thin front-end). The TUI draws a symbol with Unicode half
blocks (`▀`, `▄`, `█` and space: two module rows a character row, one module a column), dark on light, in colour mode only; a
version v symbol needs 25 + 4v columns and ⌈(25 + 4v) / 2⌉ rows with its quiet zone. At 80 × 24 that is version 5 at most (106
bytes), at 120 × 40 about version 12 (367 bytes, a few rows left for the screen's own lines): a `receive` fits the larger size; a `signed-op` needs a terminal of about 85
× 43 for its info part and the largest-part option for its signatures, or the export. In monochrome and ASCII modes the TUI
cannot set the background, so it offers the export instead of drawing (`QrTerminalTooSmall` names both causes). Several parts
animate in the order and timing of §8.1, on a timer of their own beside the TUI's one-second tick. Import is by paste (one or
more `scaas:` lines) or by a file path; export as §8.1. Every scanned text is drawn under the TUI's outside-text rule
(CLI-TUI-05).

### 8.6 CLI

**SPECIFIED** ([CLI-SDK-17](../../clients/scaas-cli.md#CLI-SDK-17): one command per SDK call, named flags, `--json`, the confirm
classes). A scanned payload never reaches a signature or a submit inside a `qr` command, so `--yes` can never pay or submit what
a file states:

| Command | SDK call | Does | Confirm class |
|---|---|---|---|
| `scaas qr receive` | `Qr::receive` | writes a `receive` payload (`.scaasqr`) from named flags | none |
| `scaas qr pay-request` | `Qr::pay_request` | writes an unsigned `pay-request` payload from named flags | none |
| `scaas qr sign-request` | `Qr::sign_pay_request` | shows the request's review, then signs it as the payee | `sign` |
| `scaas qr hand-off` | `Qr::from_hand_off` | wraps a blob from `op hand-off` into a `signed-op` payload | none |
| `scaas qr export` | the image layer | writes a payload `--format png`, `svg`, `apng`, `png-set` or `text`, `--out <path>` | none |
| `scaas qr show` | the image layer | draws a payload in the terminal (the TUI's renderer; `--ascii`, `--frame <n>`) | none |
| `scaas qr import` | `Qr::assemble`, `Qr::review_info` | reads `.scaasqr` files, images or `-` (and `--bulk <file>`), assembles and checks, prints the review, writes the object: the blob JSON for `op import-signed`, or the request's named fields for the payment command, which keep their own confirm | none |

A `pay-request` that names a `relayer` is paid by a hand-off (`op hand-off`, class `sign`) given back to the payee, not by a
submit. Every scanned text in the CLI's output is escaped as the CLI escapes outside text. `link` has no CLI import.

## 9. Safety on scan

**SPECIFIED** ([CLI-QR-07](../../decisions.md#CLI-QR-07)). A scanned payload is untrusted data from whoever made it.

- **Bounded decode** (§7) before anything else; no part is acted on alone, and a review once open is frozen: its confirm is
  bound to its info hash, and a new info part from any source (a second QR in view, a deep link) is refused or starts a
  separate import only after the user leaves the review.
- **Never sign on scan.** A scan ends in the SDK's review (`SignReview`, [CLI-SDK-35](../../decisions.md#CLI-SDK-35)) and the
  quote: the chain, the contract (listed or not), the entry, the amounts, the payee, the payer that pays the gas, the relayer
  binding, `valid_until` (with the time left), the fee, the signer and what was checked of it, for a hand-off that it was
  handed off and to whom it is bound, and for a payment `pay_no`, `save` (with its storage cost), `schema` and `body`. Any
  signature (the payer's `UAMetaTransfer`, the scanner's native transaction for a self-relay) is made only on the user's
  confirm of the assembled payload's review ([CLI-SDK-36](../../decisions.md#CLI-SDK-36)), and a fresh quote above the reviewed
  one asks again ([CLI-PQV-18](../../clients/pqvault-core.md#CLI-PQV-18)).
- **Mismatches.** A `chain_uid` that is not the active profile's: refused (`ProfileMismatch`). A `signed-op` contract that is not
  a listed token of the profile: refused (the import's `ProfileMismatch`). A `receive` or `pay-request` token that is not
  listed: a Caution with the address, and the user decides. A `pay-request` whose `payer` is not the scanning account:
  `QrPayerMismatch` (the payee's reconciliation would not count the payment, [CTR-MTX-03](../../contracts/metatx.md#CTR-MTX-03)).
- **Expiry.** `valid_until` shown; a `pay-request` less than 120 s ahead of now is `QrExpired`, a `signed-op` the import's
  `ImportExpired`. The payer's own signature lives no longer than its client allows: its `validUntil` is the smaller of the
  request's and now + the client's cap for a QR payment (10 minutes by default), and a request beyond the cap carries a
  Caution, not a copied expiry. A `signed-op` whose `valid_until` exceeds the lane horizon on a family that prunes lane state
  is refused as clientkeys refuses it ([CTR-MTX-04](../../contracts/metatx.md#CTR-MTX-04)).
- **Replay.** The contracts' rules hold: a signature runs at most once (its lane nonce), and a scanned `signed-op` already
  consumed is `ImportConsumed`. A `pay-request` is paid on `payLane(entryRef)` at nonce 0 by default
  ([CTR-MTX-10](../../contracts/metatx.md#CTR-MTX-10)): for the same payer account, the same `PayMeta` and a family that keeps
  its lane state, a second scan finds the lane spent (or the first payment still pending) and the review says so; a request
  re-shown with another `salt`, or a `receive` with `pay_no`, is a new payment, and the client's own history of a payment to
  the same payee with the same `pay_no` raises a Caution. A `receive` carries no signature and replays nothing.
- **No decryption oracle** ([ARCH-POS-13](../../decisions.md#ARCH-POS-13)). Nothing in a scanned payload, or in a bulk its
  pins admitted, is ever decrypted, trial-decrypted or opened by the scanner: not a PQZ or Zether ciphertext, not a sealed
  opening, not an encrypted `PayMeta` body (which a QR cannot carry, §3.2). The review of a confidential operation says
  "amount hidden" and shows only public fields; a recipient learns what it received from its own balance in contract state, by
  its ordinary wallet path, never from the QR's bytes.
- **Confidential payloads.** A `receive` for a PQZ or Zether token carries the recipient's UA only: its encryption key is read
  from the chain's registry or the token, never from a QR. A QR never carries an opening, a blinding, a secret key, a seed or
  the sender randomness (§3.5).
- **Outside text.** Every text of a scanned payload is printable ASCII (§4.2) and is drawn under the front-end's outside-text
  rule (the TUI's CLI-TUI-05, the CLI's escaping).
- **Deep links and relays.** A `scaas:` URI opened by the platform only starts an import, the same as a paste. No payload holds
  a secret, so no relay, deep link or message can leak one; `link` is refused from every source but its own flow's camera
  (§3.4).

## 10. Vectors

**PLANNED** ([CLI-QR-08](../../decisions.md#CLI-QR-08)). The byte format changes everywhere at once: clientkeys holds the JS
reference of the format core and generates `smartcontracts/vectors/qr/`; `scaas-qr`'s tests and the SDK's QR and import tests
read the same rows, and `--check` regenerates and compares. Every negative row stands beside its positive control and changes
one thing.

| File | Rows |
|---|---|
| `receive.json` | a UA id and a native address (EVM and Sui); with and without `amount`, `pay_no`, `token`, `relayer`: canonical hex and URI |
| `pay_request.json` | unsigned and payee-signed; `entryRef` equal to the metatx vectors' `metaPayId` for the same `PayMeta`; one row on a v1 family |
| `signed_op.json` | a secp256k1 transfer (info + 1 signature part); **an `mldsa65` derived-UA payment: info part + 2 signature parts**; an `slhdsa128s` op (3 parts); the `mldsa65` payment at a 1,140-byte maximum (5 parts); a byte string with a digit run and Shift-JIS-shaped pairs; each assembled from every order of its parts |
| `bulk.json` | a Zether single transfer (k = 6, systematic and the first repair frames); a PQZL transfer at `n2048-kmax1024` (k ≈ 68) with repair frames and a decode from a mixed subset; a class (c) row (pins only, the bulk file beside it); a digest rebuilt from pins for `UAPqzTransfer` (`bytes[]`, `bytes` in a struct array) equal to the full struct's digest in `typed_ops.json` |
| `link.json` | one `LinkSession` offer |
| `fountain.json` | the UR fountain algorithm's published reference cases; k = 72 with frame numbers near 2^32 |
| `negative.json` | one row per refusal of §13 that bytes can show: each refused major type (negative integer, float, tag, `null`, indefinite length, a non-text key, non-ASCII text, trailing bytes), unsorted keys, a non-shortest integer, a duplicate key, an unknown field, a missing field, a wrong type, `u256` with a leading zero or above 2^256 − 1, an uppercase EVM address, depth 10, a map of 65, an array of 257, a text of 65 B, prefix `0x02` and wrong magic, an unknown kind, the URI forms (padding, non-zero trailing bits, `+` or `/`, upper-case scheme, 3,945 characters), an oversized part, an info part above one QR, a foreign part, a second info part, a conflicting part, a count mismatch, a frame number out of range, an incomplete set, 17 parts in a slot, k = 73, a digest mismatch, a flipped signature byte with the digest equal, a signature valid for the bare digest but not for the UA message, a key that does not derive `signer`, a payee signature by another id than `to`, a pin at a path that may not be pinned, a bulk pin mismatch, a missing bulk field, a schema 3 body, a v1-family `pay_no`, an expired request, a stale link offer, another chain, a `pay-request` for another payer, a `link` from text |

## 11. Tests and gates

**PLANNED.** Per task, at its own suites (AGENTS.md "Verify"): the format core's unit tests over the vectors; one fuzz target
over every decode path (bytes, URI, text file, assembly); mutants on the bounds, the canonical check, the part binding and the
pin table, each negative row able to fail beside a positive control; a property test that every order of a payload's parts
assembles to the same payload; `cargo build --target wasm32-unknown-unknown` of the core alone and of the image layer, and
`cargo tree -e features` showing no `image` feature in the SDK's tree; the image layer's round trip (PNG, SVG, APNG, the set)
and the binary vectors through the chosen decoder, with one byte-mode segment required; a test that `sign_typed` refuses the
by-hash builder input; a test that importing a confidential `signed-op` addressed to the importer makes no call to a
decapsulation, PQZ or Zether decryption handle (a counting spy, with the ordinary balance read as its positive control); the
TUI's snapshot of a drawn QR at a size that holds it; a CLI end-to-end on a local chain: `op hand-off` → `qr hand-off` →
`qr export --format png-set` → `qr import` → `op import-signed` → submit, for a secp256k1 and an `mldsa65` signer. Before §12 Q1
is ruled: a simulation of the coder at k = 6, 11, 68 and 72 with 10 % and 20 % frame loss, and a measured scan time on two
phones for each class and for signature parts above version 30, reported, not a gate.

## 12. Open questions for the owner

- **Q1. The class (b) bound.** Ruled (owner 2026-11-28): as recommended. Recommendation: k ≤ 72 (≈ 82 KB, about 15 to 20 s at 5 frames a second), so a PQZL transfer at
  `n2048-kmax1024` goes by animated QR, fixed after the simulation and measurement of §11; the alternative is k ≤ 24 (≈ 27 KB,
  about 5 to 6 s), Zether only, PQZ always by the bulk file.
- **Q2. Payment requests without a payer.** Ruled (owner 2026-11-28): a `pay-request` only carries what the payer needs to pay; `payer` is optional and anyone may pay it. Whether a request counts as paid (one or several payments by `entryRef`, partial payments, refunds, CTR-MTX-03 / CTR-MTX-31) is the payee's reconciliation from the chain's events, never the QR's or the payer's client's: the scanner pays and shows only its own history of payments to the same payee and `pay_no` as a Caution.
- **Q3. The payee's signature on a payment request.** Ruled (owner 2026-11-28): as recommended, the signature stays optional; checking the payment details before paying is the payer's own responsibility (the review shows what the payer needs, the signer and whether it is a known contact). Recommendation: keep it optional, under its own off-chain purpose (§3.2);
  the review shows "signed by <UA>, a known contact" or "not a known contact", and an unsigned request carries a Caution that
  anyone can show it.
- **Q4. Bulk by hash from a node.** Ruled (owner 2026-11-28): as recommended. Recommendation: not in this frame; the bulk file and a PqChat or Matrix attachment cover it,
  the Arweave store later (§6.4); a node endpoint would be its own node rule if asked for.
- **Q5. EIP-681 for EVM receive requests**, readable by other wallets. Ruled (owner 2026-11-28): as recommended. Recommendation: no; `scaas:` only, since another wallet
  would show neither UA ids nor the SCaaS review.
- **Q6. The default error correction level.** Ruled (owner 2026-11-28): as recommended. Recommendation: L by default (screens and files, fewer parts: the `mldsa65`
  vector is 2 signature parts), M as an export option for print.
- **Q7. Confidential imports.** Ruled (owner 2026-11-28): a confidential operation (PQZ or Zether, kept apart) is importable
  for scan and submit only, under `Limits::max_native_cost`; `relayer` is not bound to the scanner: the signer chooses, unbound by default (any relayer, the scanner or a gateway, may submit it, fee 0 allowed) or bound to a named relayer (owner 2026-11-28); the review shows a fixed line
  "amount hidden: you pay <quote>, and this client cannot tell whether you receive anything". **No amount travels in the QR for
  a confidential transfer** — no claimed, declared or signed amount field in the info QR or anywhere else in the payload: a
  number shown beside a hidden amount invites fraud (the amount paid on chain differs from the one in the QR), and a scanner
  never decrypts the payload's ciphertexts to find it (ARCH-POS-13). A recipient learns what it received only from its own
  balance in chain state after the operation lands. The SDK's JSON cap rises to 1 MiB, the figure recorded against the largest
  PQZH transfer of the vectors, when this is built.

## 13. Appendix: refusals

Named refusals of the format core and the SDK's QR calls (the CLI maps each to its code and exit code,
[CLI-CMD-01](../../clients/scaas-cli.md#CLI-CMD-01)): `QrMalformed` (not the subset, a wrong type, a missing field),
`QrNotCanonical` (the CBOR or the URI form), `QrFieldUnknown`, `QrFieldDuplicate`, `QrVersion`, `QrKindUnknown`, `QrDepth`,
`QrTooLarge` (a part, a line, a file, a count above its bound), `QrInfoTooLarge`, `QrInfoConflict`, `QrPartForeign`,
`QrPartConflict`, `QrPartIndex`, `QrPartCount`, `QrIncomplete`, `QrDigestMismatch`, `QrSignatureInvalid`, `QrPinRefused`,
`QrBulkMismatch` (a pin or the CRC-32 of an assembled object), `QrBulkMissing`, `QrSchemaRefused`, `QrPayMetaRefused`,
`QrPayerMismatch`, `QrExpired`, `QrSourceRefused`, `QrNeedsScaas`, `QrNotFound` (no QR in an image), `QrImageTooLarge`,
`QrTerminalTooSmall`; and the existing `ProfileMismatch` and `Import*` refusals of the hand-off import.
