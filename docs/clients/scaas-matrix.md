# `scaas-matrix`: the Matrix client crate

`scaas-matrix` is the toolkit-free Rust crate that runs the matrix-rust-sdk client for every chat front-end: scaas-app's four
front-ends, `scaas-tui` and `pqchat-core`'s e2e ([CLI-PQC-20](../decisions.md#CLI-PQC-20)). It logs in, restores, syncs, keeps
Matrix's own end-to-end encryption (Olm / Megolm, classical) with device verification and recovery, keeps the privacy defaults of
[CLI-PQC-19](../decisions.md#CLI-PQC-19) and implements the PqChat transport trait. It signs nothing of SCaaS and is not part of
`scaas-sdk`. Design: spec [`2026-11-27-scaas-matrix.md`](../superpowers/specs/2026-11-27-scaas-matrix.md), plan
[`2026-11-27-scaas-matrix.md`](../superpowers/plans/2026-11-27-scaas-matrix.md). Status: **BUILT** in `clients/scaas-matrix` and `clients/pqchat-transport` (plan T0 to T9; gate rows
`clients/scaas-matrix/runs/2026-11-27-scaas-matrix-summary.txt`), except the wasm32 build ([CLI-MTX-11](#CLI-MTX-11)), PLANNED,
and the size bound on homeserver answers ([CLI-MTX-09](#CLI-MTX-09)), open. UNAUDITED.

**Contents**

1. [Place and dependencies](#1-place-and-dependencies)
2. [Profiles, store key, session](#2-profiles-store-key-session)
3. [Privacy and room kinds](#3-privacy-and-room-kinds)
4. [Encryption, verification, push](#4-encryption-verification-push)
5. [Transport, bounds, errors, wasm](#5-transport-bounds-errors-wasm)

## 1. Place and dependencies

Status: **BUILT** (`tests/deps.rs`; `deny.toml`, `.cargo/audit.toml`; `pqchat-core` re-exports the trait crate).

<a id="CLI-MTX-01"></a>**CLI-MTX-01** — **The crate depends on matrix-sdk and a trait-only crate, never on the SDK or
`pqchat-core`** (controller call 2026-11-27 on the coordinator's constraint; owner may override). `clients/scaas-matrix` depends on
`matrix-sdk` pinned exactly (`=0.19.1`, `default-features = false`, features `e2e-encryption`, `sqlite`, `bundled-sqlite`), rustls
with the `ring` provider only, and `clients/pqchat-transport`; its normal dependency graph holds no `scaas-sdk`, `pqchat-core`,
`scaas-ua` or `scaas-rpc` (`tests/deps.rs`), so scaas-app's default build (no SDK) links it. `clients/pqchat-transport` holds only
what both sides share: `MatrixTransport`, `TransportError`, `RoomEvent`, `HistoryPage`, `EVENT_TYPE` and the conformance test
(`Seen`, `Witness`, `conformance`), with `serde`, `serde_json` and `async-trait` as its only dependencies; `pqchat-core` re-exports
them at `pqchat_core::matrix` and keeps the event codec, and still pulls no Matrix crate (CLI-PQC-01). A pinned version is a
release at least 14 days old; cargo-deny (licences, advisories, bans, sources) and cargo audit cover the tree, each exception named
with its reason in the crate's `deny.toml` and `.cargo/audit.toml`.

## 2. Profiles, store key, session

Status: **BUILT** (`src/lib.rs`; tests `tests/profile.rs`, the e2e's restore step).

<a id="CLI-MTX-02"></a>**CLI-MTX-02** — **One client per profile directory** (controller call 2026-11-27, under CLI-PQC-20). A client
opens a profile's Matrix directory under an exclusive OS file lock (`<dir>/lock`); a second open of that directory, in any process,
is refused (`MatrixProfileBusy`) while the first is open. `close` stops the sync loop, drops the client and its stores and releases
the lock before it returns. The order of a profile switch (close, then open the next) is the profile layer's (CLI-UPR-07); the crate
allows clients of different profiles side by side.

<a id="CLI-MTX-03"></a>**CLI-MTX-03** — **The store key comes from the caller and stays in memory** (controller call 2026-11-27,
under CLI-UPR-29). The caller passes the 32-byte key from the profile's sealed item; the crate uses it as the raw key of every SQLite
store matrix-sdk opens (state, crypto, event cache, media), drops its own zeroized copy once they are open (the stores keep their cipher until `close`), and never writes it to a file,
the OS secret storage, a log, an error or a `Debug` output. The crate makes no key. A wrong key opens nothing (`MatrixStore`); no key
runs the client on memory stores, persisting nothing.

<a id="CLI-MTX-04"></a>**CLI-MTX-04** — **The session lives in the encrypted store; the homeserver is `https`** (controller call
2026-11-27). After a password login one record (homeserver URL, user id, device id, access token) is written into the encrypted
state store and read back by `restore`; nothing of it is in the clear on disk. No refresh token in this version; an unknown token
ends the sync loop (`SessionInvalid`). `logout` invalidates the token on the server and deletes the directory's stores. The password
is never stored. A homeserver URL is `https`, `http` only for a loopback IP literal (the local test server); else `EndpointScheme`.

## 3. Privacy and room kinds

Status: **BUILT** (`src/policy.rs` and its unit tests; the e2e's witness of what the server holds).

<a id="CLI-MTX-05"></a>**CLI-MTX-05** — **Defaults: private receipts, no typing, no presence** (CLI-PQC-19 G2, G4; the means a
controller call 2026-11-27). A read receipt is `m.read.private` unless the user turned public receipts on; a typing notice is not
sent unless the user turned typing on; every sync says `set_presence=offline` and the crate makes no presence call; it never sends
`m.fully_read` and never answers an invite by itself. The settings are kept per profile in the encrypted store. In a PqChat room no
receipt, typing notice or presence is ever sent, whatever the settings.

<a id="CLI-MTX-06"></a>**CLI-MTX-06** — **Two room kinds that never mix** (CLI-PQC-19 G1; the means a controller call 2026-11-27). A
room the transport created, joined or holds an invite to is marked PqChat in the encrypted store, the mark kept after a leave; every
other room is Matrix. The Matrix room list never shows a PqChat room, joined or invited; the crate refuses a front-end's Matrix
action in a PqChat room (`MatrixRoomKind`): sending text, a receipt, typing, accepting the invite. A `net.scaas.pqchat.v1` event in a
Matrix room is shown as "needs the SCaaS build", never as a message.

## 4. Encryption, verification, push

Status: **BUILT** (`src/lib.rs`; the e2e: an E2EE direct message, SAS both ways, pusher, push rule and backup only on the
caller's call); QR verification PLANNED.

<a id="CLI-MTX-07"></a>**CLI-MTX-07** — **Encrypted direct rooms, SAS verification, backup off** (scaas-app contract §11.5; the means
a controller call 2026-11-27). A direct room the crate creates is encrypted from its first event and the crate never turns encryption
off; room keys go only to devices their owner cross-signed; an undecryptable event is shown as such, never dropped. Cross-signing is
set up at an account's first login. Devices are verified by SAS (emoji; QR PLANNED) with the outcomes verified, unverified and
changed. Server-side key backup is off and nothing is downloaded from it until the user turns it on; the recovery key is returned
once and not kept.

<a id="CLI-MTX-08"></a>**CLI-MTX-08** — **No pusher by default; `event_id_only`; none for a hidden profile; PqChat pushes on opt-in**
(CLI-PQC-19 G3; the means a controller call 2026-11-27). The crate registers a pusher only on the caller's call, always with the
format `event_id_only`, and refuses one for a hidden profile (`MatrixPushHidden`). A push rule for `net.scaas.pqchat.v1` exists only
after the user's opt-in.

## 5. Transport, bounds, errors, wasm

Status: **BUILT** for CLI-MTX-09 (except the answer-size bound, open), CLI-MTX-10 (`src/transport.rs`; `conformance` against
Synapse in the e2e) and CLI-MTX-12; CLI-MTX-11 PLANNED.

<a id="CLI-MTX-09"></a>**CLI-MTX-09** — **Bounded decodes and queues** (controller call 2026-11-27). The crate's own records are
bounded by length before decoding (the session 8 KiB, the settings 4 KiB, at most 4,096 PqChat marks); a text to send at most 60,000
bytes; a page at most 100 events; a PqChat event above 65,536 bytes is dropped at the transport; the update queue 1,024 entries, a
full queue reported once as `Lagged`. Server JSON is decoded by ruma over serde_json (depth limit 128); every request has a 90 s
timeout and a sync asks for at most 20 timeline events per room with lazy-loaded members. The size of a homeserver answer is
**not bounded** (open): matrix-sdk 0.19.1 reads each answer whole and offers no body limit, and reqwest 0.13's connector hook
returns a sealed type, so no byte-counting stream fits under TLS (spec §10, O3).

<a id="CLI-MTX-10"></a>**CLI-MTX-10** — **The transport rides the same client** (CLI-PQC-20; the means a controller call 2026-11-27).
`transport()` implements `MatrixTransport` over the profile's one `matrix_sdk::Client`: the same login, token and HTTP client, no
second sync loop, each call one client-server request that does not wait for a sync; the rooms it creates carry no
`m.room.encryption`; it passes `pqchat-transport`'s `conformance` against Synapse.

<a id="CLI-MTX-11"></a>**CLI-MTX-11** — **Native first; wasm32 later on IndexedDB** (CLI-PQC-19 G5; controller call 2026-11-27).
The native build uses SQLite (bundled) and an OS file lock; the web build, when it comes, runs matrix-sdk with `js` and `indexeddb`
and its IndexedDB store opened with the profile's store key. `pqchat-transport` builds for wasm32 now. PLANNED.

<a id="CLI-MTX-12"></a>**CLI-MTX-12** — **Named errors with nothing secret** (controller call 2026-11-27). The crate's errors are
`EndpointScheme`, `MatrixLogin`, `MatrixSession`, `MatrixStore`, `MatrixVerification`, `MatrixSend` (the app-core contract's §7
names), `MatrixRoom`, `MatrixRoomKind`, `MatrixProfileBusy`, `MatrixPushHidden`, `Argument` and `Internal`; an error displays its
name only and carries no token, key, password, message text, room id or Matrix id.
