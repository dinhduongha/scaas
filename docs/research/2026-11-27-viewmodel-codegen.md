> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# One view-model contract, five implementations: generated types, a shared presenter, replayed flows (2026-11-27)

Research of 2026-11-27 for the owner, who asked how scaas-app's front-ends are kept from drifting apart. There are four of them:
Qt / QML (the Status fork, C++ models over a C ABI), Flutter / Dart (flutter_rust_bridge), Dioxus (Rust, links `app-core-rust`
directly), and Tauri v2 with React / TypeScript (desktop and mobile through Tauri commands to `app-core-rust`; the same React UI on the
web and in a browser extension over the SDK's wasm build). `scaas-tui` ([its doc](../clients/scaas-tui.md)), which has its own view
models today, is the fifth. All of them implement one toolkit-neutral contract: scaas-app's
`app-common/viewmodel/view-model-contract.md` (task B10 there, being written today; read at its state of 2026-11-27). Nothing here is
built, specified or ruled. The recommendation in §7 is a proposal. Cost figures are marked *(estimate)*. Sources are listed in §9,
cited inline as [S*n*], all read on 2026-11-27.

**Contents**

1. [Where things stand](#1-where-things-stand)
2. [One Rust crate of view-model types](#2-one-rust-crate-of-view-model-types)
3. [Generators per target: what each can and cannot express](#3-generators-per-target-what-each-can-and-cannot-express)
4. [Where the logic lives: thin view models or a shared presenter](#4-where-the-logic-lives-thin-view-models-or-a-shared-presenter)
5. [Conformance: recorded flows replayed against every implementation](#5-conformance-recorded-flows-replayed-against-every-implementation)
6. [Versioning](#6-versioning)
7. [Recommendation](#7-recommendation)
8. [Example: Send and review in each target](#8-example-send-and-review-in-each-target)
9. [Sources](#9-sources)

## 1. Where things stand

| Implementation | Reaches its core through | Events today | View model today |
|---|---|---|---|
| Qt / QML | `app-core-rust`'s own C ABI (cbindgen), each async call answered by a completion callback posted to the GUI thread ([CLI-SDK-12](../clients/scaas-sdk.md#CLI-SDK-12), Q-B1 (b); app-core contract §12) | callback | none yet; C++ models planned (D7) |
| Flutter / Dart | flutter_rust_bridge `=2.13.0`, as the SDK's own Dart binding (`clients/scaas-sdk/ffi/Cargo.toml`) | the SDK's pull subscription, `events_next(subscription, timeout_ms)` (`clients/scaas-sdk/ffi/src/api/mod.rs`) | none yet (Rust plan F2) |
| Dioxus | a crate dependency, no bridge | a channel | none yet (Rust plan X2) |
| Tauri + React | Tauri commands to `app-core-rust`; on the web and in the extension the SDK's wasm-bindgen exports (`clients/scaas-sdk/src/wasm/js.rs`, wasm-bindgen `0.2.130`) | Tauri channel or event; on the web a JS callback | none yet (Tauri plan T3) |
| `scaas-tui` | `scaas-sdk` as a crate | one forwarding task | built on branch `scaas-tui`: `src/vm/`, one module per screen, names marked provisional until B10 |

Three facts shape everything below:

- **The SDK already solved the same problem one layer down.** Its bindings are generated from one Rust API, never written by hand
  per language (CLI-SDK-12); a drift check regenerates them in CI; every binding runs a load check at open (`load_check(expect_api,
  need_features)` in `clients/scaas-sdk/src/lib.rs`: `AbiMismatch` unless the API version and feature bits match and `ua-rs` is
  not the test-only `vectors` build). The view-model layer has none of that yet.
- **The contract's only gate is a text rule.** Its §13 says each front-end's view model "uses exactly the names of this file"; a
  text search keeps toolkit names out of the file. Nothing checks that five code bases actually use those names, the same flow
  states, or the same refusals.
- **The cores differ under the same screen names.** The app's Send (contract §6) is a native transfer through the app core:
  `validate` → `quote` → `review` → `sign` → `broadcast`, ended by `txState`. The TUI's Send is an `mtx*` transfer through the SDK:
  prepare → review → quote → submit, ended by `OpState` (`Landed`, `Consumed`, `Reverted`, `Expired`, `InFlight`;
  `clients/scaas-sdk/src/events.rs`). The TUI is SCaaS-only (CLI-TUI-01) and has no native app core. So the TUI shares the
  contract's **names and conventions** everywhere, but its **flows** only on the screens served by the SDK: the `scaas`-build screens
  of contract §12 (`mtx*` review, UA accounts, confidential balances, PqChat, PqVault). Any shared-code design must respect this,
  or it will try to unify two different flows.

## 2. One Rust crate of view-model types

The proposal: a crate, `app-viewmodel` (name proposed), inside scaas-app's `app-common/viewmodel/` next to the contract. That
directory's rule ("toolkit-free: plain C++17, Rust without a UI crate, JSON, Markdown") already allows it. It holds, per screen:

- **models**: records whose fields are the contract's roles, each list row carrying its id (`accountId`, `txId`, `roomId`);
- **actions**: one enum variant per action, with named fields (struct variants only, never tuple variants);
- **results and errors**: `Result<T, ErrorName>`, where `ErrorName` is one fieldless enum of app-core contract §7, its numbers
  fixed and appended only (`AbiMismatch` = 21 already exists for the load check);
- **events**: one enum per screen (`TxState { tx_id, state, block, confirmations }`);
- **flow states**: one enum per flow whose variants are the contract's states by name (`compose`, `quote`, `review`, `signing`,
  `broadcast`, `pending`, `included`, `final`, `rejected`).

It depends on `serde` only, plus the derive of the TypeScript generator (§3). It calls nothing and holds no key, no secret and no
byte format. A crate is a dependency, not a second library: `app-core-rust` links it, and so do the app's wasm cdylib and the
TUI binary, each still one Rust library per process (CLI-SDK-12).

**Type rules that remove most cross-language trouble**, chosen so that one JSON text means the same thing on every transport:

| Rule | Why |
|---|---|
| Integers are `bool`, `u32` or `i32` only. Anything wider (amounts, nonces, block numbers, gas, fees) is a **decimal string** | The contract already makes amounts decimal strings (§1). Wide integers otherwise come out three different ways: ts-rs makes `i64`/`u64`/`u128` a TS `bigint` by default [S1]; specta refuses to export them unless configured (`BigIntExportBehavior::Fail` is the default, `BigIntForbidden`) [S3]; the SDK's own wasm surface serializes them as JS `BigInt` (`serialize_large_number_types_as_bigints(true)`, `clients/scaas-sdk/src/wasm/js.rs`); and a Tauri command's JSON gives a JS `number`, which is exact only up to 2^53. FRB gives Dart `BigInt` (the SDK's generated Dart has `BigInt block`, `BigInt seq`, …). With strings, all five agree. |
| No `Vec<u8>` and no bytes in a view model. A hash or an address is shown as `0x` hex text, a transaction is referred to by a handle string | Explicit parameters: the one crypto object that stays `bytes` stays inside the core. The signed bytes stay behind the `unsignedTx` handle (contract §6), and no screen gets raw material to sign. |
| Data-carrying enums are internally tagged, struct variants only: `#[serde(tag = "state", rename_all = "camelCase")]` | ts-rs takes serde's `tag`, `content`, `untagged` and `rename_all` [S1]; tsify follows serde [S6]; typeshare wants adjacently tagged enums for algebraic types [S5]; FRB does not go through serde at all and turns Rust enums into Dart sealed classes [S7]. The internally tagged form gives readable JSON with named fields (`{"state":"review","handle":…}`) to C++ and TS. |
| `Option<T>` is `null` in JSON, never left out (no `skip_serializing_if`) | ts-rs ignores `skip_serializing_if` without `#[serde(default)]` [S1]; tsify makes a skipped field optional (`b?: string`) [S6]. Leaving fields out is where `undefined` and `null` start to differ. Always present is one shape everywhere. |
| An effect's outcome is two variants (`Quoted { review }`, `QuoteFailed { error }`), never a `Result` inside a type | `Result` has no one serialized shape across serde, ts-rs and FRB; two named variants have. |
| No secret in any type. A passphrase or mnemonic field is a `SecretId` handle filled by the toolkit through the core's copy call (the SDK's `scaas_sdk_secret_write` in `clients/scaas-sdk/ffi/src/lib.rs`, or the app core's `unlock`) | View-model states are logged, diffed and written as golden files (§5). A secret must never be able to reach them. |

The rules are checked by a test in the crate, not by review. A source scan refuses `u64`, `u128`, `i64`, `Vec<u8>`, tuple variants
and `skip_serializing_if` under `src/`, and a sample fixture of each type is round-tripped through `serde_json`.

## 3. Generators per target: what each can and cannot express

Versions are crates.io's maximum and stable releases as read on 2026-11-27 [S12].

| Target | Tool (version) | Data enums | `Option` | Wide integers | Bytes | Events / streams | Errors | Fit |
|---|---|---|---|---|---|---|---|---|
| TS for Tauri | **tauri-specta 2.0.0-rc.29** over specta 2.0.0-rc.28 | yes (specta) | yes | export **fails** by default; set `string`, `number` or `BigInt` [S3] | `number[]` | generates typed `commands` and `events` [S2]. Tauri **channels**, which are ordered and fast, unlike events [S9], are not said to be generated [S2] | typed command results | Tauri only; still a release candidate, with stable Tauri v2 as the default target [S2]. Not for the wasm-bindgen web build |
| TS, any transport | **ts-rs 12.0.1** (stable) | yes, serde `tag` / `content` / `untagged` [S1] | yes | `bigint` by default, or `number` (`TS_RS_LARGE_INT`) [S1] | `number[]` | types only; no command or event wrappers | the error enum as a string union | types only, so one `.ts` file serves both Tauri JSON and the wasm JSON values. The command wrappers (about ten lines) are ours |
| TS for wasm-bindgen | **tsify 0.5.8** with wasm-bindgen 0.2.130 | yes (externally tagged by default, follows serde) [S6] | `?:` when skipped [S6] | serializer option only [S6] | `number[]` / typed array | — | — | writes `.d.ts` from serde types. `into_wasm_abi` / `from_wasm_abi` are deprecated in favour of `Ts<T>`: a failed decode at the boundary otherwise throws without running destructors [S6]. Today the SDK's wasm surface passes `JsValue`, typed `any` in TS |
| TS, Swift, Kotlin… | **typeshare 1.0.5** | adjacently tagged [S5] | — | not stated [S5] | — | — | — | Kotlin, Scala, Swift, TS; Go and Python experimental [S4]. **No Dart, no C++**: does not cover this project |
| Dart | **flutter_rust_bridge 2.13.0** (2.14.0-beta.2 out) [S12] | Dart 3 sealed classes via `freezed`, named fields kept, exhaustive `switch` [S7] | nullable | `BigInt` (seen in the SDK's generated Dart) | `Uint8List` | the SDK uses a pull subscription (`events_next`) for every binding alike | `Result` to a thrown Dart error | already the SDK's Dart generator; the view-model types come with `app-core-rust`'s FRB surface at no extra cost |
| C / C++ for Qt | **cbindgen 0.29.4** | `repr(C)` / `repr(u8)` tagged unions [S10] | only `Option<&T>` [S10] | fine in C | no slices or wide pointers: pointer plus length [S10] | function pointer callback | fieldless enum to a C enum | the path the contract (§12) and CLI-SDK-12 chose. `String`, `Vec` and `Option<T>` by value do not cross, so the view-model values cross as **named-field JSON text**, and only the error enum and the version constants are generated into the header |
| C++ / Qt directly | **cxx 1.0.205**, **cxx-qt 0.10.0** | via shared structs (cxx) | — | — | `QByteArray` | Qt signals; threading support [S11] | — | can declare a `QAbstractListModel` subclass in Rust (`#[base = QAbstractListModel]`, `#[cxx_override] fn data`) [S11]. `ua-qt` already uses CXX-Qt 0.10.0. But D7 and contract §12 put Qt on a C ABI with C++ models in the Qt repository, so this is a question for the owner, not a default |
| several, one tool | **serde-reflection / serde-generate 0.7.0**, **facet_generate 0.22.4** | yes (`std::variant` in C++) [S13] | — | — | — | — | — | serde-generate covers C++, Dart, Swift, Kotlin and more, TS still in progress, and its code carries **Bincode / BCS only, no JSON** [S13]. facet_generate covers Swift, Kotlin, TS and C# [S14]. A binary message format between UI and core is harder to read in logs and fixtures and covers neither Dart nor C++ fully. Not recommended |
| Rust (Dioxus, TUI) | none | direct | direct | direct | direct | channel | direct | the crate itself |

**Reading of the table.** FRB already covers Dart. cbindgen plus JSON text is the Qt path already ruled for the SDK. Dioxus and
the TUI need no generator. **The open choice is TypeScript only**, and it has two transports (Tauri JSON and wasm-bindgen values).
ts-rs is the one stable generator that is transport-neutral. tauri-specta adds typed commands, but only for Tauri, only as a
release candidate, and with a BigInt default that the integer rule in §2 makes moot. Proposal: **ts-rs** for the types, ten
hand-written lines per transport for `dispatch` and `subscribe`, and the generated `.ts` committed under a drift check, as the
SDK's generated bindings are.

## 4. Where the logic lives: thin view models or a shared presenter

**(A) Thin view models per toolkit.** Each front-end implements the contract's flows itself: Qt in C++, Flutter in Dart, React
in TS, Dioxus and the TUI in Rust. That makes five state machines for each flow. Each one must, by itself, refuse `sign` before
`review` for the same handle, return to `compose` when a field changes after review, show nothing as "failed" before a decisive
read at a final block (contract §6, §6.5), and keep the "pending, not failed" wording. This works well for platform feel, but the
rules that protect the user are written and tested five times.

**(B) A shared Rust presenter per screen.** Elm-style:
`update(state, input) -> (state, effects)`. The function is pure. `input` is a user action, the result of an effect, or a core
event; `effects` are named calls the driver runs against the core (`Quote { from_account_id, to, amount }`); `state` is the
render state, serialized as in §2. The driver is a small loop in Rust, inside `app-core-rust` (or the app's wasm cdylib, or the
TUI). It runs each effect through the app core or the SDK and feeds the result back. A front-end does two things only:
`dispatch(screen, input)`, and render whatever state `subscribe` hands it. This is the architecture of Crux (0.20.0, "pre-1.0 …
production-ready", Elm architecture, side-effect-free core, "tests can act as another Shell") [S8]. Crux itself is not a fit: its
shells are Swift, Kotlin, the web and C#, with no Dart and no Qt, and its types are generated through facet_generate and Bincode
[S8], [S14]. Only the pattern is borrowed.

| | (A) thin per toolkit | (B) shared presenter |
|---|---|---|
| Flow and refusal rules | written 5 times, tested 5 times | written once, tested once by `cargo test` |
| Drift | caught only by conformance tests (§5) | the flow cannot drift; only the binding and the rendering can |
| Platform feel (layout, navigation, focus, motion, input method, accessibility) | native | still native: the presenter decides **what** the screen holds, never how it looks |
| Latency | none | one FFI round trip per action. Keystrokes stay in the toolkit's text field, and only `validate` and `quote` cross |
| Qt list models | hand-written models | one generic C++ adapter turns a list of id-keyed rows into `beginInsertRows` / `endInsertRows` / `dataChanged` (a keyed diff over the row id; the Qt API is the usual one [S15]) |
| Web and extension | React VM in TS | the presenter is pure Rust, so it compiles into the same wasm cdylib as the SDK |
| TUI | keeps its `src/vm/` | adopts the presenter only for SDK-backed screens (§1); keeps its own signing-safety state (CLI-TUI-08) |
| Debugging | per toolkit | the state is JSON: a bug report is the input log plus the states |
| Cost | lower at first, rises with each front-end and each change | one crate plus one driver, then less per front-end |

**What stays per toolkit in (B)** is everything that depends on the screen being real: the TUI's "seen lines" and settle interval
(CLI-TUI-08), a QML focus chain, a phone's biometric prompt. The presenter covers the security-relevant part it can see. It accepts
`sign` only after the front-end reported `reviewShown { handle, serial }` for the review state it last rendered, and a new quote
moves the `serial`. The core ties `sign` to `review` independently (contract §6), so the presenter is a second guard, never the
only one.

**Proposal: (B) for the flows, (A) for the look.** The flows of contract §4 to §11 are small state machines with refusal rules,
which is exactly what is cheapest to write once and expensive to write five times. The TUI already shows that the Rust view-model
shape works (plain structs of id-keyed rows, an enum of flow states, a function per action, a function per message).

## 5. Conformance: recorded flows replayed against every implementation

A **flow fixture** is a JSON file in `app-common/viewmodel/flows/<screen>/<name>.json`: the view-model version, a start state,
then steps. Each step is one input (an action, an effect's result or an event) with the state and the effects expected after it.
Fixtures are written by hand from the contract, or recorded from the presenter and then reviewed in the commit diff (a bless
variable, as the TUI's goldens use `SCAAS_TUI_BLESS=1`). They are canonical JSON: struct field order as serde writes it, no
whitespace variance.

Replays run at three levels:

1. **Presenter**, `cargo test` in the crate: every fixture, and every refusal row (`sign_before_review_refused`,
   `field_changed_after_review_returns_to_compose`, `rejected_is_not_failed`). **Mutants** follow ARCH-POS-23 through
   `scripts/mutant_guard.py`, so that a negative row can actually fail. Example: drop the review-handle check and
   `sign_before_review_refused` must turn red.
2. **Binding**, per transport: the same fixtures pushed through the real boundary, with the JSON that comes back compared
   **byte for byte**. Dart through FRB in a `dart test`; the C ABI from a QtTest; the wasm build under `node --test`, as the SDK's
   `bind-js` smoke already does; the Tauri command handler in a Rust test calling it directly; Dioxus and the TUI need none. This
   level catches what the type rules of §2 aim at: a `BigInt`, a `null` turned into a missing field, a renamed variant.
3. **Rendering**, per toolkit: for each fixture state, the screen shows every role the contract lists for it. Qt: a model's
   `roleNames()` equals the generated role list. Flutter: a widget test per state. React: a Testing Library test per state.
   Dioxus: a render to text per state. TUI: its existing `TestBackend` goldens, given the fixture states as input.

Two more checks keep the contract text and the crate in step, **both directions**, as the node's allow-lists are kept equal to
the contract's: a test parses the tables of `view-model-contract.md` (roles, actions, parameters, errors, flow states) and compares
the name sets with the crate's. A name in one and not the other fails, and the fix goes first into the contract, as its §13
already says. And every fixture is searched for high-entropy canaries typed into secret fields during recording: none may appear.

## 6. Versioning

Reuse the SDK's mechanism as it is:

- `VM_VERSION: u32` and `vm_features() -> u64` in the crate. Bits for `scaas`, `pqchat`, `pqvault`, the chat screens, and a test
  bit for fixture-only entry points that a release never has.
- Every generated surface carries the version it was generated against. At open, the front-end calls
  `vm_load_check(expect_version, need_features)`, which returns `AbiMismatch` (contract §7, number 21) on any difference. It
  belongs in the same opening call that already runs the SDK's `load_check`.
- **A view-model change is one commit** holding the contract text, the crate, the fixtures, the regenerated TS and Dart and the C
  header, and the version bump. CI's drift check regenerates and fails on any difference, as the SDK's
  `runs/2026-11-17-scaas-sdk-gen.sh` does for its bindings. Every serialized change bumps the version; nothing is live, so no
  compatibility window is needed.
- **Repositories.** Flutter, Dioxus and Tauri live in scaas-app, so they are always at the crate's commit. The Qt repository
  already checks out scaas-app pinned by commit for vectors (three-front-ends spec §2a), and the same pin carries the crate, the
  header and the fixtures. `scaas-tui` is in this repository. The lighter tie is a **data** dependency: it pins the scaas-app commit
  and replays the §12 fixtures (level 2 needs no binding in Rust; level 3 uses its goldens). The heavier one is a Cargo git
  dependency on the crate for the shared screens. Which one applies, and the direction of that dependency between a public SCaaS
  crate and the app's repository, is the owner's call. The data dependency keeps the SDK side free of any app crate.

## 7. Recommendation

1. **One crate of view-model types and presenters** (`app-viewmodel`, in `app-common/viewmodel/`), under the type rules of §2:
   strings for wide integers and amounts, no bytes, internally tagged struct variants, `null` never skipped, no secret.
2. **Generators:** FRB for Dart (already in use), ts-rs for TypeScript (both transports), cbindgen for the C header (errors,
   version, function pointers) with values as named-field JSON text, Rust directly for Dioxus and the TUI. Not typeshare (no Dart,
   no C++), not serde-generate or Crux (binary formats, gaps in Dart and C++). tauri-specta can be revisited when it is stable.
3. **Shared presenter for the flows**, with the look left to each toolkit. The core keeps its own refusals, so the presenter is
   never the only guard.
4. **Flow fixtures replayed at three levels** (presenter, binding, rendering), with mutants on the refusal rows and a two-way name
   check between contract text and crate.
5. **`VM_VERSION` plus feature bits checked at open** (`AbiMismatch`), one commit per change, and a drift check in CI.

House rules this respects: actions are named struct variants and node-style named-field JSON, never a packed blob (explicit
parameters); the presenter calls nothing, and every effect is run by the driver through `scaas-sdk` or the app core, so the SDK
stays the only API an app calls; the presenter holds no key and signs nothing, so `ua-rs` stays the only signer of every SCaaS kind
(CLI-UAL-01) and native signing stays the app core's `sign`; the crate and fixtures are written from the contract's own words, so
no Status file leaves the Qt fork (owner 2026-11-27); nothing decrypts or reacts to a ciphertext (ARCH-POS-13), and a decrypted
amount is a render-only value that no presenter rule reads.

**Cost** *(estimate, person-days, one engineer who knows Rust)*:

| Item | Days |
|---|---|
| crate skeleton, type-rule test, version and load check | 2 |
| presenter, fixtures and mutants for Send and review | 3 |
| each further v1 screen (onboarding, accounts, receive, activity, settings, backup, chat) | 1–2 each, so 8–12 |
| generators wired (ts-rs, FRB surface, cbindgen header) and the drift check | 2–3 |
| driver in `app-core-rust` and in the web cdylib | 3 |
| binding-level replay harness per transport (FRB, C ABI, wasm, Tauri) | 1–2 each, so 4–8 |
| Qt generic keyed-diff list adapter | 2 |
| TUI: replay of the §12 fixtures, mapping its provisional names | 2–3 |
| **total** | **about 26–36 (5–7 weeks)** |

Against that, (A) costs nothing up front, but every flow rule is written and tested five times, and each later contract change
is five changes.

## 8. Example: Send and review in each target

Illustrative only. Names follow contract §6 at its state of 2026-11-27; trimmed to the review step.

**The crate (Rust).**

```rust
// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
pub struct Form { pub from_account_id: String, pub to: String, pub amount: String }

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, ts_rs::TS)]
pub struct Field { pub name: String, pub value: String }   // the role pair of `decoded`

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
pub struct Review {
    pub handle: String, pub serial: u32, pub shown: bool, pub form: Form,
    pub chain: String, pub environment: String, pub from: String,
    pub decoded: Vec<Field>, pub fee_total: String, pub fee_asset: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, ts_rs::TS)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum Send {
    Compose { form: Form, error: Option<ErrorName> },
    Quote { form: Form },
    Review { review: Review },
    Signing { handle: String },
    Broadcast { tx_id: String },
    Pending { tx_id: String },   // also after a merged `Rejected`: "may still land" (contract §6.5)
    Included { tx_id: String, block: String, confirmations: u32 },
    Final { tx_id: String, block: String },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, ts_rs::TS)]
#[serde(tag = "input", rename_all = "camelCase")]
pub enum SendInput {
    Quote { form: Form },
    Quoted { review: Review },                    // the effect's result, from `quote` then `review`
    QuoteFailed { error: ErrorName },
    ReviewShown { handle: String, serial: u32 },  // the front-end drew this review
    Sign { handle: String },
    Signed { tx_id: String },
    SignFailed { error: ErrorName },
    Back,
    Cancel,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "effect", rename_all = "camelCase")]
pub enum SendEffect { Quote { form: Form }, Sign { handle: String }, Broadcast { tx_id: String } }

pub fn update(s: Send, i: SendInput) -> (Send, Vec<SendEffect>) {
    use {Send as S, SendEffect as E, SendInput as I};
    match (s, i) {
        (S::Review { mut review }, I::ReviewShown { handle, serial })
            if review.handle == handle && review.serial == serial =>
        {
            review.shown = true;
            (S::Review { review }, vec![])
        }
        (S::Review { review }, I::Sign { handle }) if review.shown && review.handle == handle => {
            (S::Signing { handle: handle.clone() }, vec![E::Sign { handle }])
        }
        (S::Review { review }, I::Back) => (S::Compose { form: review.form, error: None }, vec![]),
        (S::Quote { form }, I::Back) => (S::Compose { form, error: None }, vec![]),
        // … the other transitions of contract §6
        (s, _) => (s, vec![]), // anything else, `sign` before `reviewShown` included: refused, nothing sent
    }
}
```

**TypeScript (React, ts-rs output plus our two transports).**

```ts
// generated by ts-rs (abridged)
export type Send =
  | { state: "compose"; form: Form; error: ErrorName | null }
  | { state: "review"; review: Review }
  | /* … */;
export type Review = { handle: string; serial: number; shown: boolean; form: Form; chain: string;
  environment: string; from: string; decoded: Array<Field>; feeTotal: string; feeAsset: string };

// ours: one dispatch, two transports
const dispatch = isTauri
  ? (i: SendInput) => invoke("vm_dispatch", { screen: "send", input: i })   // Tauri command; render state on a Channel
  : (i: SendInput) => wasm.vmDispatch("send", i);                          // the app's wasm cdylib

function SendScreen({ s }: { s: Send }) {
  switch (s.state) {
    case "review": {
      const r = s.review;
      return <ReviewView fields={r.decoded} fee={`${r.feeTotal} ${r.feeAsset}`}
                 onShown={() => dispatch({ input: "reviewShown", handle: r.handle, serial: r.serial })}
                 onSign={() => dispatch({ input: "sign", handle: r.handle })} />;
    }
    /* every other state: exhaustive, `tsc --noImplicitReturns` */
  }
}
```

**Dart (Flutter, FRB-generated sealed class).**

```dart
Widget build(BuildContext c) => switch (send) {
  Send_Review(:final review) =>
      ReviewView(fields: review.decoded, fee: '${review.feeTotal} ${review.feeAsset}',
                 onShown: () => vm.dispatch(SendInput.reviewShown(handle: review.handle, serial: review.serial)),
                 onSign: () => vm.dispatch(SendInput.sign(handle: review.handle))),
  Send_Compose(:final error) => ComposeView(error: error),
  // … exhaustive: the analyzer refuses a missing state
};
```

**C++ / QML (Qt fork, C ABI with JSON values).**

```c
/* generated by cbindgen: version, errors, entry points */
#define SCAAS_VM_VERSION 1
typedef void (*scaas_vm_render)(void *ctx, const char *screen, const char *state_json);
int32_t scaas_vm_load_check(uint32_t expect_version, uint64_t need_features); /* 0 or 21 (AbiMismatch) */
int32_t scaas_vm_dispatch(const char *screen, const char *input_json);
void    scaas_vm_subscribe(scaas_vm_render cb, void *ctx);                  /* posted to the GUI thread */
```

```cpp
// SendController: Q_PROPERTY(QString state) plus a KeyedListModel for `decoded` (roles "name", "value", from the generated role list)
void SendController::onRender(const QJsonObject &s) {
    setState(s["state"].toString());                              // "review", …
    const QJsonObject r = s["review"].toObject();
    m_fields.replaceKeyed(r["decoded"].toArray(), "name");         // one generic adapter: begin/endInsertRows, dataChanged
    m_handle = r["handle"].toString(); m_serial = r["serial"].toInt();
}
Q_INVOKABLE void SendController::reviewShown() { dispatch("send", {{"input","reviewShown"},{"handle",m_handle},{"serial",m_serial}}); }
Q_INVOKABLE void SendController::sign()        { dispatch("send", {{"input","sign"},{"handle",m_handle}}); }
```

The fork's QML binds `send.state` and the `fields` model. It is the Status layout, fed by our models.

**Dioxus (Rust, the crate directly).**

```rust
match &*send.read() {
    Send::Review { review: r } => {
        let (h, n) = (r.handle.clone(), r.serial);
        let h2 = h.clone();
        rsx! {
            ReviewView { fields: r.decoded.clone(), fee: format!("{} {}", r.fee_total, r.fee_asset),
                onshown: move |_| vm.dispatch(SendInput::ReviewShown { handle: h.clone(), serial: n }),
                onsign: move |_| vm.dispatch(SendInput::Sign { handle: h2.clone() }) }
        }
    }
    _ => rsx! { /* … */ },
}
```

**`scaas-tui`.** Its native Send is not this flow (§1). Its `mtx*` review maps onto the §12 presenter once that is written. It
sends `reviewShown` only when CLI-TUI-08's gate opens (every line drawn, settle interval passed), which is a stricter reading of
"shown" that stays local to the TUI. The presenter only requires that the event came.

## 9. Sources

All read on 2026-11-27.

| Id | Source | URL |
|---|---|---|
| S1 | ts-rs documentation (large-integer binding, supported serde attributes, `serde-compat`) | https://docs.rs/ts-rs/latest/ts_rs/ |
| S2 | tauri-specta README (commands, events, Tauri v2 default, `=2.0.0-rc.29`) | https://github.com/specta-rs/tauri-specta |
| S3 | specta BigInt export behaviour: `Fail` default, `BigIntForbidden` (specta 1.0.5 and 2.0.0-rc.9 source; specta-typescript 0.0.7, 0.0.9) | https://docs.rs/crate/specta/2.0.0-rc.9/source/src/lang/ts/mod.rs, https://docs.rs/crate/specta-typescript/0.0.7/source/src/typescript.rs |
| S4 | typeshare README (target languages, Go and Python experimental) | https://github.com/1Password/typeshare |
| S5 | typeshare book, annotations (adjacently tagged enums) | https://1password.github.io/typeshare/usage/annotations.html |
| S6 | tsify README (`.d.ts`, deprecated `into_wasm_abi`, `Ts<T>`, enum and `Option` output) | https://github.com/madonoharu/tsify |
| S7 | flutter_rust_bridge guide, enums (`freezed`, Dart 3 sealed classes) | https://cjycode.com/flutter_rust_bridge/guides/types/translatable/detailed/enum |
| S8 | Crux README (Elm architecture, shells, facet_generate, Bincode, pre-1.0) | https://github.com/redbadger/crux |
| S9 | Tauri v2, calling the frontend (events are JSON and unordered for async listeners; channels ordered and fast) | https://v2.tauri.app/develop/calling-frontend/ |
| S10 | cbindgen user guide (tagged enums with `repr`, `Option<&T>` only, no wide pointers) | https://github.com/mozilla/cbindgen/blob/master/docs.md |
| S11 | CXX-Qt book: overview and inheritance (`#[base = QAbstractListModel]`, `#[cxx_override]`, `#[inherit]`) | https://kdab.github.io/cxx-qt/book/, https://kdab.github.io/cxx-qt/book/concepts/inheritance.html |
| S12 | crates.io API, versions of specta, tauri-specta, ts-rs, typeshare, tsify, wasm-bindgen, flutter_rust_bridge, cxx, cxx-qt, cbindgen, uniffi (0.33.0; the SDK pins 0.31.0), crux_core, facet_generate, serde-reflection, tauri (2.12.7 stable), dioxus (0.7.10 stable) | https://crates.io/api/v1/crates/ |
| S13 | serde-reflection / serde-generate README (languages, Bincode / BCS only) | https://github.com/zefchain/serde-reflection |
| S14 | facet_generate documentation (Swift, Kotlin, TypeScript, C#) | https://docs.rs/facet_generate/latest/facet_generate/ |
| S15 | Qt 6.12 `QAbstractListModel` (`rowCount`, `data`, `roleNames`, `beginInsertRows` / `endInsertRows`) | https://doc.qt.io/qt-6/qabstractlistmodel.html |
| S16 | Tauri 2 start page ("all major desktop and mobile platforms") | https://v2.tauri.app/start/ |
