> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# scaas-app in the browser and as an extension: secure architecture and the dApp API (2026-11-27)

Research of 2026-11-27 for the owner, who asked (2026-11-27): scaas-app gets a Tauri v2 + React front-end whose React UI also runs
on the **web** and as a **browser extension** (Manifest V3; Chrome, Firefox, Safari) over the SDK's wasm build. What is the secure
architecture, and what dApp-connection API does SCaaS offer? Nothing here is built, specified or ruled; every recommendation is a
proposal for the owner. The SDK, its JS binding and `ua-rs` are **UNAUDITED** ([ARCH-POS-14](../decisions.md#ARCH-POS-14)).
External sources were read on 2026-11-27 (each cited with its URL); the wallets' source was read on GitHub at their default branch
of that day, for ideas only: no code is copied.

## Summary

**Recommendation.** One extension with five parts: an in-page provider (EIP-1193 announced by EIP-6963, plus `scaas_*` methods with
named fields), a content-script relay that only checks size and shape, a service-worker **router** that holds no secret and takes
the caller's origin from the browser, a **key host** that runs the SDK's wasm in a dedicated worker (on Chrome inside the offscreen
document; on Firefox and Safari inside the event page, re-opened after suspension by a session key in `storage.session`), and an
**approval window** (an extension page in its own window) that shows the SDK's review. A dApp gets accounts, operation ids and
chain facts; it never gets a signature over bytes it chose with a UA key, a decryption, a decryption's success or failure, or a
response before the user acts on a confidential request. The **web build** holds no long-lived secret: a passkey-signed account
or a session-only seed opened by the WebAuthn PRF output or a passphrase, the sealed store in IndexedDB once the async profile core
exists ([user profiles §13](../superpowers/specs/2026-11-27-user-profiles.md)). A **bridge mode** (the extension forwarding to the
installed desktop or Safari containing app by native messaging, keys in the native SDK) is the stronger second phase.

| Question | Answer in one line | Section |
|---|---|---|
| Where do secrets live in MV3? | never in the service worker or a content script; in a worker of one extension document; storage at rest is the SDK's sealed store | §1 |
| How is the dApp isolated? | origin from `port.sender`, never from the message; caps on size and depth; approval in its own window | §2 |
| What API? | EIP-1193 + EIP-6963 for EVM; `scaas_*` methods, one per SDK entry, named fields, per-origin grants | §3 |
| What may the web build hold? | no secret at rest beyond the sealed store; passkey / PRF unlock; pinned, reproducible bundle | §4 |
| RPC from a browser | the SDK's endpoint lists from the chain profile; CORS on the gateway or host permissions in the extension | §5 |
| Decryption oracle | no decrypt method; confidential requests answer only after the user's click, with one code for every non-success | §6 |
| What is missing in the SDK | the app cores in the JS binding, the async profile store, a calldata decoder for review, wasm runs of `scaas-rpc`, and five more | §7.5 |

## 0. What exists today in the repository

- **The JS binding** (BUILT, [CLI-SDK-12](../clients/scaas-sdk.md#CLI-SDK-12), `clients/scaas-sdk/src/wasm.rs`,
  `src/wasm/js.rs`): wasm-bindgen exports of the SDK's module objects (`vault`, `account`, `wallet`, `op`, `confidential`, `dex`,
  `admin`), every call a `Promise`, records as plain JS objects, secrets and prepared values as numbered handles released by the
  app; a secret crosses only by `secret_write` / `secret_read`. A JS value is refused above 128 levels of nesting and with a key the
  record does not know (review T26 C-3, C-6), before any lift. The SDK opens over the app's JS store (`get`, `put_if`, `delete`,
  `lock`, `unlock`) and the app's JS authenticator (`create_passkey`, `get_assertion` with a PRF output, `platform_secret`,
  `p256_generate`, `p256_sign`). wasm threads are refused at compile time: the platform traits hold JS objects.
- **The SDK's rules a provider must keep:** secrets never leave the SDK ([CLI-SDK-02](../clients/scaas-sdk.md#CLI-SDK-02)); one entry
  point per signed struct, prepare then review then submit, decoded calls only unless the `opaque-calls` build marker, fee 0 accepted
  and never replaced, no EIP-7702 ([CLI-SDK-08](../clients/scaas-sdk.md#CLI-SDK-08)); `submit` returns an id once the row is
  written, send results are events ([CLI-SDK-09](../clients/scaas-sdk.md#CLI-SDK-09)); an operation ends only on a chain fact
  ([CLI-SDK-18](../clients/scaas-sdk.md#CLI-SDK-18)); chain profiles are pinned data, never what an endpoint says
  ([CLI-SDK-15](../clients/scaas-sdk.md#CLI-SDK-15)). An EVM key signs only an EVM transaction (`wallet/native_evm.rs`: types 0, 1,
  2; 3 and 4 `TxTypeRefused`); no call signs a caller's digest with a UA key
  ([CLI-SGN-29](../clients/signers-clientkeys.md#CLI-SGN-29)).
- **Not in the JS binding:** the app-core surface (`app_core.rs`: app keys, records, KEM wrap, `prepare_app_record`,
  `prepare_pqvault_record`); `binding_list.rs` and `wasm/js.rs` name none of it. `pqchat-core` builds for wasm32 as a check and has no
  JS binding; `pqvault-core` has no wasm32 build.
- **The profile layer in a browser** is PLANNED: one IndexedDB database per profile, Web Locks, Argon2id up to 256 MiB, and an
  async store core of its own, because the synchronous core does not carry to wasm32
  ([user profiles §7.2, §7.5, §13](../superpowers/specs/2026-11-27-user-profiles.md)).
- **`scaas-rpc`** compiles for wasm32 in CI and is not run there; in a browser the fetch follows a redirect before the crate sees it,
  so an endpoint with a credential is refused ([scaas-rpc](../clients/scaas-rpc.md), header and
  [CLI-RPC-02](../clients/scaas-rpc.md#CLI-RPC-02)).
- **The SCaaS app SPA** ([clients/app](../clients/app.md), SPECIFIED, not built) already specifies the browser rules this note reuses:
  the CSP with `'wasm-unsafe-eval'`, Trusted Types, the frame check, no secret in the bundle
  ([§12](../clients/app.md#security)), the pinned supply chain ([CLI-APP-15](../clients/app.md#CLI-APP-15)), the URL guard that dials
  only configured origins ([CLI-APP-19](../clients/app.md#CLI-APP-19)), and no server of its own
  ([CLI-APP-03](../clients/app.md#CLI-APP-03)). Its key worker runs clientkeys; this note assumes the scaas-app UI signs through
  the SDK only (one signer, `ua-rs`), so the two browser front-ends should not keep two signers (§7.6).

## 1. Manifest V3 constraints

### 1.1 Lifetimes

| Context | Chrome | Firefox | Safari |
|---|---|---|---|
| background | a service worker, stopped after 30 s without events or extension API calls, or when one event or call runs over 5 min, or a `fetch()` answer takes over 30 s [C1] | no service worker; `background.scripts` runs as an event page (a document) [M1], suspended when idle: Firefox 117 terminated it after 30 s, fixed for event pages in 117.0.1 / 118, with active ports still force-stopped after 30 s [M2] | both; `background.scripts` by default unless `preferred_environment` is `service_worker` [M1]; on iOS the background must be non-persistent and Safari unloads it when the user is not interacting [A1] |
| a long-lived hidden document | the offscreen document: one per extension, a bundled static page, only the `runtime` API, no lifetime limit except for the `AUDIO_PLAYBACK` reason; messages from it reset the worker's timers since Chrome 109 [C2][C1] | none documented on the MDN pages read (MetaMask's `createOffscreen` returns when `chrome.offscreen` is absent [W1]); the event page is itself a document | none |
| UI | popup (closes on blur), side panel, extension tab or window | popup, sidebar, tab, window | popup, tab |

Two consequences. First, **no wallet can keep an unlocked key in the Chrome service worker** and also promise that it stays unlocked:
the worker dies within 30 s of quiet. Second, Firefox and Safari have no place that lives longer than the event page, so "lock on
death" there means "lock every time the user looks away for 30 s".

What the wallets do (source read 2026-11-27):

- **MetaMask** keeps its keyring in the background and creates the offscreen document for hardware wallets and the Snaps executor
  only (`app/scripts/offscreen.ts`, `app/offscreen/offscreen.ts`) [W1]. After a worker restart it re-opens the vault from
  `storage.session` keys `loginToken` and `loginSalt` (`submitEncryptionKeyFromSessionStorage` in `metamask-controller.js`), so the
  user is not asked again [W1].
- **Rainbow** has the same shape: the vault is encrypted with a password-derived key (PBKDF2, "600k iterations" in a comment of
  `KeychainManager.ts`), the derived key kept in `chrome.storage.session` (`getEncryptionKey: () => SessionStorage.get('encryptionKey')`, `src/core/storage/index.ts`), and an auto-lock checked every 30 s against the last activity
  (`handleAutoLock.ts`) [W3].
- **Rabby** runs keyrings in its service worker and uses offscreen bridges for hardware wallets
  (`src/background/service/keyring/*-offscreen-bridge.ts`) [W2].

**Proposal (key host).**

- **Chrome:** the SDK in a dedicated `Worker` started from the offscreen document (reason `WORKERS`). The service worker routes only.
  The offscreen document has no lifetime limit for that reason, so a quiet worker does not lock the wallet; closing the document
  (browser restart, extension update, crash, the idle lock) does. Risk: whether the store review accepts `WORKERS` for this purpose
  is not documented; if refused, use the Firefox form below.
- **Firefox and Safari (desktop):** the SDK in the event page (or a worker it starts). On suspension the unlocked state is lost; to
  avoid a passphrase prompt every 30 s, the MetaMask / Rainbow idea: at unlock the key host draws a random 32-byte **session key**,
  seals the SDK's re-open state under it, keeps the sealed state in IndexedDB and the session key in `storage.session` (memory
  only, cleared when the browser stops or the extension is disabled, not exposed to content scripts by default [C3][M3]). A restarted
  page re-opens from them. The idle lock (§1.3) deletes both. This is weaker than lock-on-death (a session key sits in browser
  memory outside the SDK), so it is an owner choice; the alternative is a lock on every suspension.
- **Safari iOS:** do not hold keys in the extension: iOS unloads the background under memory pressure and forum reports describe
  workers that do not come back [A1][A2]. Use bridge mode (§7.4) to the scaas-app iOS build.

### 1.2 Where secrets live

| Place | Holds | Never holds |
|---|---|---|
| in-page provider (page's world) | nothing but request ids | anything: the page reads and rewrites it [M4] |
| content script (isolated world) | nothing | anything: it shares the DOM with the page and its bugs are reachable from it [M5] |
| service worker / event-page router | the per-origin grants, the queue | a seed, a key, a passphrase, a PRF output, a plaintext amount |
| key host (offscreen document's worker, or the event page) | the SDK and its handles | dApp code; any third-party script |
| approval window | handles of a prepared value and its review | a secret (passphrases are typed here and passed once to the key host by `secret_write`) |
| `storage.local` / `storage.sync` | nothing secret: `storage.local` is exposed to content scripts by default [C3]; `sync` leaves the device | — |
| IndexedDB of the extension's origin | the SDK's sealed store (the profile envelope, seeds behind their own passphrases) | plaintext |
| `storage.session` | the session key of §1.1 (Firefox, Safari only) | anything else |

Encryption at rest is the SDK's own sealed store (Argon2id, the profile and seed passphrases), never the browser's: neither Chrome's
nor MDN's storage page says the browser encrypts extension storage at rest [C3][M3]. The two wallets read use PBKDF2 through
`browser-passworder`-style helpers; the SDK's Argon2id at 64 MiB / 3 / 4 is stronger per guess. In a browser the bound is 256 MiB
and `p = 4` runs on one thread ([user profiles §7.5](../superpowers/specs/2026-11-27-user-profiles.md)).

wasm linear memory has no `mlock` or no-dump; any script in the key host's realm can read it. So the realm holds the SDK, its
glue and nothing else (no analytics, no UI library), and `Vault::memory_protection` should be shown as "none" on wasm32.

### 1.3 Lock

- On every browser: lock when the key host's document closes (memory gone), at the user's idle timeout, and at `idle` state
  `locked` (screen lock) from `chrome.idle.onStateChanged` [C4]. Lock = `Vault::lock_all`, then release every handle, then (Firefox,
  Safari) delete the session key and the sealed re-open state.
- The router keeps no unlocked flag of its own; it asks the key host, so a dead key host reads as locked.
- One instance per profile: Web Locks on the profile id (the spec's browser row), so a second popup or tab never opens the same
  profile twice.

### 1.4 CSP

MV3's `extension_pages` CSP cannot be relaxed below `script-src 'self' 'wasm-unsafe-eval'; object-src 'self'`; without
`'wasm-unsafe-eval'` WebAssembly is off; no remote script and no `'unsafe-eval'` [C5]. Proposal:
`script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'` (Rabby sets the same
`frame-ancestors 'none'` in its MV3 manifest [W2]) and Trusted Types as in the app's §12. No `web_accessible_resources` except the
in-page provider script, and that with `use_dynamic_url` where supported [C6].

### 1.5 Firefox and Safari, other differences

- Firefox messages use the structured clone, Chrome JSON [M6]: send only JSON (no `BigInt`, no `Uint8Array`) between contexts;
  amounts as decimal strings, bytes as `0x` hex, as the SDK's records already are.
- Firefox gives each install a random extension UUID unless `browser_specific_settings.gecko.id` is set [M6]; the WebAuthn origin
  of a Firefox extension is a stable hash of the extension id [M7].
- Extension pages may call WebAuthn with an RP ID of any domain in their host permissions from Chrome 122 and Firefox 150; the
  origin in `clientDataJSON` is `chrome-extension://<id>` or `moz-extension://<hash>` [M7]. Safari is not documented there. A
  `webauthn-p256` UA key binds `rpIdHash` and no origin, and its verifier compares no origin
  ([accounts](../contracts/accounts.md), "Passkey id without origin (decided)"), so the extension asserting under the web app's
  `rpId` reaches the same UA. The other side of that rule: **any** extension with host permissions over the `rpId`'s domain can
  ask the user's authenticator for an assertion over a challenge it chose; the platform prompt shows the `rpId`, not the
  operation. The deployment rule of that decision (the narrowest `rpId`, no untrusted content under it) does not cover other
  extensions; this is a new residual risk to state (§7.3).
- Firefox popups close when the WebAuthn prompt appears; MDN's workaround is a tab [M7]. The approval window of §2.4 avoids it.

## 2. Isolation and phishing defences

### 2.1 Three worlds

The page and the in-page provider share one JavaScript world (the MAIN world: "the web page can detect and interfere with the
executed code" [M8]). The content script shares only the DOM; it sees the original built-ins even if the page redefines them [M5].
`window.postMessage` between them is not authenticated: a check that `event.source === window` is passed by every page script, and
MDN warns that hostile pages "can easily trick" extensions [M5]. Content scripts are subject to the page's CORS; extension pages and
the service worker with host permissions are not [M5][C7].

### 2.2 Message validation (proposal)

1. **In-page provider:** builds `{id, method, params}` only; `params` a single object of named fields. It is frozen before EIP-6963
   announces it (EIP-6963 says the `detail` "SHOULD be frozen", and freezing the provider is best practice [E2]).
2. **Content script:** accepts a message only from `window` with the provider's tag; refuses above 64 KiB (the gateway's cap) or
   128 levels of nesting (the binding's `JS_DEPTH`), anything not plain JSON, any method not on the allow-list; forwards over one
   `runtime.Port` per frame. It adds nothing about the origin: it does not know it reliably and must not be believed.
3. **Router:** takes the origin from `port.sender.origin` (else `new URL(port.sender.url).origin`), the frame from
   `port.sender.frameId`, the tab from `port.sender.tab`; MetaMask (`new URL(sender.url).origin` in
   `setupProviderConnectionEip1193`) and Rabby (`getOriginFromUrl(port.sender.url)`) do the same [W1][W2]. A port whose name claims a
   privileged role (`popup`, `approval`, `keyhost`) from a content script is disconnected, as Rabby does for its `popup` and
   `notification` ports [W2]. No `externally_connectable`: other extensions and pages cannot open a port.
4. **Key host:** the SDK's own lift (`from_js`: depth, unknown keys, `deny_unknown_fields`) checks the request again. The router
   never builds bytes; the SDK builds every signed value from named fields.

### 2.3 Origin binding and phishing

- **Grants per exact origin** (scheme, host, port), never per eTLD+1, never per tab. `http:` origins refused except `localhost`
  in a development build. A subframe is its own origin and is shown as "embedded in <top origin>"; by default only the top frame
  gets a provider (Rabby's MV3 manifest injects its content script with `all_frames: true` [W2]; the narrower default here is a proposal).
- **Display:** the origin in its ASCII (punycode) form beside the Unicode form whenever they differ, the registrable domain in
  bold, a "first visit" mark, the dApp's self-declared name and icon labelled as self-declared (EIP-6963's `rdns` is "self-attested"
  [E2]); an icon only as a data URI in `<img>`, never inline SVG [E2].
- **Lists:** a reviewed allow-list of dApp origins in the release data, beside the reviewed tokens of the chain profile; a warning
  when an origin is near an allowed or already-granted one. MetaMask's phishing detector compares against a fuzzy list with
  Levenshtein distance and a default tolerance of 3 (`fastest-levenshtein`, `DEFAULT_TOLERANCE = 3` in
  `packages/phishing-controller`) [W4]; Phantom's public blocklist has `blocklist`, `fuzzylist` and `whitelist` files, checks
  locally, and says the fuzzy list is not in use [W5]. A downloaded blocklist is a third-party feed: optional, local check only, its
  host an allow-listed origin (CLI-APP-19's rule), never a URL query with the visited origin.

### 2.4 Clickjacking of the approval UI

- The approval UI is an extension page in **its own window** (`windows.create({type: "popup"})`), never an iframe in the page,
  never in `web_accessible_resources`, with `frame-ancestors 'none'`.
- **DoubleClickjacking** (Paulos Yibelo, reported 2025-01-02): a page asks for a double-click, the first click swaps the window
  underneath, the second lands on the sensitive button; X-Frame-Options and CSP do not stop it; the proposed client defence is to
  "disable critical buttons until a mouse gesture or key press is detected" [X1]. Proposal: the confirm button is disabled until
  the approval window has had focus for a short delay and a pointer move or key press has happened inside it; no default button on
  Enter; one pending request per origin, a refused origin rate-limited.
- A popup storm (a page sending requests in a loop) is queued per origin; the user can block the origin from the approval window.

## 3. The dApp API

### 3.1 EVM: EIP-1193 + EIP-6963

EIP-1193 (Final) is `request({method, params})`, `params` an array or an object, events `connect`, `disconnect`, `chainChanged`,
`accountsChanged`, `message`, errors 4001 (user rejected), 4100 (unauthorized), 4200 (unsupported), 4900, 4901 [E1]. EIP-6963
(Final) announces providers by `eip6963:announceProvider` with `{uuid, name, icon, rdns}` in answer to `eip6963:requestProvider`
[E2]. EIP-2255 (Final) adds `wallet_requestPermissions` / `wallet_getPermissions`, a permission with an `invoker`, a
`parentCapability` and `caveats` [E3]. EIP-5792 (Final) adds `wallet_sendCalls`, `wallet_getCallsStatus`, `wallet_showCallsStatus`,
`wallet_getCapabilities`; its `atomic` capability is `supported`, `ready` or `unsupported`, `ready` meaning the wallet can upgrade
on approval [E4].

| Method | SCaaS answer |
|---|---|
| `eth_requestAccounts`, `wallet_requestPermissions {eth_accounts}` | the accounts the user picks for this origin (native EOAs; a UA's EVM address only where a UA has one) |
| `eth_accounts`, `eth_chainId`, `wallet_getPermissions` | from the origin's grant |
| `wallet_switchEthereumChain {chainId}` | only to a chain in the user's chain profiles |
| `wallet_addEthereumChain` | refused (4200): a profile is pinned data and an RPC list from a dApp is attacker-chosen ([CLI-SDK-15](../clients/scaas-sdk.md#CLI-SDK-15), ARCH-POS-15) |
| `eth_sendTransaction` | `Wallet::prepare_native_send` (types 0 and 2; `authorizationList` or type 4 refused, [CLI-SGN-40](../clients/signers-clientkeys.md#CLI-SGN-40)); the calldata decoded in the review where the ABI is known, else marked undecoded (§7.5 item 3) |
| `personal_sign`, `eth_signTypedData_v4` | not offered for UA keys ([CLI-SGN-29](../clients/signers-clientkeys.md#CLI-SGN-29)); for a native EOA only if the owner adds an entry (the SDK has none: an EVM key signs only transactions) |
| `eth_sign`, `eth_signTransaction` | refused (4200) |
| `eth_decrypt`, `eth_getEncryptionPublicKey` | refused (4200); MetaMask deprecated both on 2022-06-27 as "not as secure as they could be" [W6]; see §6 |
| `wallet_sendCalls` | not in the first version; `wallet_getCapabilities` reports `atomic: unsupported` on every chain, never `ready` (`ready` means a 7702 upgrade, which SCaaS never builds) |
| read methods (`eth_call`, `eth_getBalance`, `eth_blockNumber`, `eth_getTransactionReceipt`, logs) | answered through the profile's endpoint list (§5) on an allow-list; the dApp cannot choose the RPC |

`window.ethereum` is not set by default (EIP-6963 is enough for current dApps and avoids fighting other wallets for one global, the
reason the Wallet Standard gives too [E6]); a per-origin switch can set it for old dApps.

### 3.2 The SCaaS provider: one method per SDK entry, named fields

A relayed `mtx*` operation is not a transaction from the user's account: the subject signs a typed struct, a gateway (or the holder)
pays the gas. `eth_sendTransaction` cannot carry it, and `eth_signTypedData_v4` would hand the dApp a signature over a struct it
chose with a UA key, which CLI-SGN-29 forbids and which loses the SDK's review. So the provider adds `scaas_*` methods on the same
EIP-1193 object, each mapping to **one** SDK entry, each taking one object of named fields, none taking packed bytes, none returning
a signature. The wallet prepares, shows the SDK's review (every field with its source, every token with its listed mark), and on the
user's confirm calls `submit`; the dApp receives the operation id and then chain facts.

| Method | Named params | SDK call | Returns |
|---|---|---|---|
| `scaas_getSession` | — | the router's grant | `{origin, chains, accounts: [{ua, chain, address}], grants}` |
| `scaas_requestPermissions` | `{grants: [{method, chain, account?, caveats: {tokens?, maxFee?, expiresAt?}}]}` | — (router) | the grants the user approved (EIP-2255's model with SCaaS caveats) |
| `scaas_getCapabilities` | `{chain}` | the chain profile; the gateways' `GET /v1/gateway` through the SDK | entries a gateway takes on this chain, signer kinds, whether fee 0 is accepted by that gateway |
| `scaas_quote` | `{chain, entry, fields}` where `entry` is one of the method names below | the entry's `prepare` then the quote | gas, payer, maximum cost, the review list; no signature, nothing written |
| `scaas_transfer` | `{chain, token, from, to, amount, fee, validUntil, path}` | `Wallet::prepare_transfer` → review → `submit` | `{operationId}` |
| `scaas_pay` | `{chain, token, from, payee, amount, payNo, fee, validUntil, path}` | `prepare_pay` | `{operationId}` |
| `scaas_payWithTax`, `scaas_payWithPayeeFee` | the struct's fields by name | `prepare_pay_with_tax`, `prepare_payee_fee` | `{operationId}` |
| `scaas_execute` | `{chain, wallet, call: {function, args: {…named}}, fee, validUntil, path}` | `prepare_execute`: `UAExecute` on a mandate wallet, a decoded call (`ua-rs` rebuilds the bytes; an undecoded call is `OpaqueCallRefused` without the `opaque-calls` build) | `{operationId}` |
| `scaas_placeOrder`, `scaas_cancelOrder` | the order's fields by name | the `dex` module's entries | `{operationId}` |
| `scaas_confidentialTransfer` | `{chain, token, from, to, amount, fee, validUntil, path}` | the `confidential` module's entry (PQZ or Zether; the SDK encrypts and proves) | `{operationId}`, only after the user's click (§6) |
| `scaas_msigPropose`, `scaas_msigApprove` | the operation's fields and `{msig, slot}` | `account::msig` | `{operationId}` or the proposal id |
| `scaas_appRecord` | `{chain, app, path, fields}` for an app namespace this origin was granted | `prepare_app_record` (not in the JS binding yet, §7.5 item 1) | `{operationId}` |
| `scaas_operationStatus` | `{operationId}` | the operation row and its follow | `InFlight` with detail, or `Landed` / `Consumed` / `Expired` with `basis` ([CLI-SDK-18](../clients/scaas-sdk.md#CLI-SDK-18)) |
| event `scaas_operationChanged` | — | the SDK's subscription | the same as above, for operations this origin started |
| `scaas_revokePermissions` | `{methods?}` | — (router) | — |

Rules of the surface (proposal):

- **Explicit parameters.** `fields` are the struct's names in `smartcontracts/vectors/typed/typed_ops.json`; an unknown field is
  refused (the binding's `deny_unknown_fields`). Amounts are decimal strings, ids `0x` hex, times seconds.
- **Not offered to dApps:** key generation, import, export, registration of a UA key, recovery, rollover, `resend`, `cancel` of a
  lane nonce, PqChat and PqVault records (the wallet's own app cores), profile and vault calls. They stay in the wallet's UI.
- **Fee 0 relayed.** `fee` defaults to `"0"`, `path` is `"gateway"` (a gateway of the profile, chosen by the wallet; the dApp may
  name one by its profile id, never by URL) or `"self"` (the holder's native account pays). The review says who pays the gas; the
  SDK never replaces a fee of 0 ([CLI-SDK-08](../clients/scaas-sdk.md#CLI-SDK-08)); a gateway that refuses fee 0 shows as a send
  event, not as a refusal of the request, and the user may then self-relay. The relayer and fee recipient stay unbound (zero) unless
  the struct binds them, as `ua-rs` checks ([CLI-UAL-13](../clients/ua-libraries.md#CLI-UAL-13)).
- **Every write is reviewed.** No grant lets a dApp skip the review in this version; session keys or spending caps without a
  prompt are a later design and need the owner.
- **Answers carry no secret and no signature.** The signed body is public once sent, but returning it to the dApp before it lands
  gives the dApp a way to submit it elsewhere first; the dApp reads the chain or `scaas_operationStatus` instead.
- **Errors:** EIP-1193 codes for the transport (4001 declined, 4100 no grant, 4200 unknown method), the SDK's code as `data.code`
  for prepare-time refusals that depend only on public data (`FeeAboveCap`, `GasAboveTxCap`, `ProfileMismatch`).

### 3.3 Discovery of the SCaaS methods

The `scaas_*` methods sit on the EIP-6963 provider; a dApp finds them with `scaas_getCapabilities` (4200 from a wallet without them).
For families other than EVM the same request shape is reached through a provider object of their own (§3.4). A separate CAIP-25
session (`wallet_createSession` with `scopes` keyed by chain, `methods`, `notifications`; status Review, last updated 2025-08-11
[E5]; MetaMask builds an engine for it beside EIP-1193, `setupProviderEngineCaip` [W1]) is a fit for one connection over several
chains; proposal: not in the first version, revisit when a second family ships in the extension.

### 3.4 Other families, briefly

- **Solana, Sui, Aptos:** the Wallet Standard: the wallet registers with `wallet-standard:register-wallet` and listens for
  `wallet-standard:app-ready` (`packages/core/wallet/src/register.ts`) [E6]; Solana features include `solana:signTransaction`,
  `solana:signAndSendTransaction`, `solana:signMessage`, `solana:signOffchainMessage` and `solana:signIn` [E7]. A SCaaS Solana
  operation is an off-chain message of kind 1 ([clients/app §4](../clients/app.md), the Solana row), so `solana:signMessage` and
  `solana:signOffchainMessage` with dApp bytes must be refused for UA keys (CLI-SGN-29) and the SCaaS operations offered as
  namespaced features (`scaas:transfer`, …) with the same named fields. The Wallet Standard's own design text lists
  encryption and decryption among its scope [E6]: no SCaaS wallet offers a decrypt feature (§6).
- **Soroban, Cosmos, GRAM:** each has its own dApp convention (Freighter, Keplr-style, TON Connect,
  [clients/app §5](../clients/app.md)); the SDK builds EVM and Soroban operations today and the other families after the freeze
  ([CLI-SDK-09](../clients/scaas-sdk.md#CLI-SDK-09)), so they wait.

### 3.5 Permission model per origin

| Grant | Default | Expiry | Revocation |
|---|---|---|---|
| connect (see listed accounts on listed chains) | none | 30 days unused (proposal) | the wallet's sites screen, `scaas_revokePermissions`, profile lock does not revoke |
| a write method | none; asked at first use | with the connect grant | as above |
| caveats | `tokens` (only listed tokens), `maxFee`, `expiresAt` | — | — |

A grant is the user's per-profile data in the SDK's sealed store, never in `storage.local`. A grant never covers a decryption or a
key operation. Hidden profiles never show their accounts to an origin granted while a visible profile was open.

## 4. The web build (no extension)

### 4.1 What it may hold

- **At rest:** only the SDK's sealed store in IndexedDB (the PLANNED async profile core) or nothing; never a seed, key, passphrase,
  PRF output, session key or grant in `localStorage` / `sessionStorage` (readable by every script of the origin).
- **Unlock:** the passphrase, or the passkey's PRF output through the SDK's `Authenticator.get_assertion(req, prf_out)`; the PRF
  extension returns `results.first` / `second` for the salts given, `evalByCredential` at `get()`, and `prf: {}` from an authenticator
  without it [M9].
- **Signing without a seed in JS:** a passkey-signed account (the SDK's `create_passkey_key`, the P-256 kinds of
  [signers-clientkeys](../clients/signers-clientkeys.md#CLI-SGN-23)): the key stays in the authenticator; a compromised page can
  still ask the user for an assertion over a bad operation, so the page's integrity (§4.3) remains the bound.
- **Eviction:** Safari may evict an origin's data under storage pressure or after ITP inactivity unless the origin is in
  persistent mode, which WebKit grants by heuristics such as being a Home Screen web app [B1]. So a web-only seed must always have
  its backup (the SDK's `SeedBackup`, the sealed backup) before anything of value is put behind it; the UI asks for
  `navigator.storage.persist()` and says when it was refused.

### 4.2 The web build as a dApp host

The same React UI on the web is a dApp to an extension (or to the desktop app through bridge mode), never both a dApp and a key
holder for another site: it exposes no provider to other origins (no `postMessage` API for other windows, `frame-ancestors 'none'`).

### 4.3 Supply chain of a wallet served from an origin

The origin's server, its CDN and its TLS key can change the code at every load. SRI checks subresources against hashes in the page
(`sha256` / `sha384` / `sha512`; cross-origin needs CORS) [M10]; it does not protect the HTML that carries the hashes. Proposals:

- the app's pinned supply chain as specified ([CLI-APP-15](../clients/app.md#CLI-APP-15)): exact pins, lockfile allow-list,
  `--ignore-scripts`, no runtime CDN; SRI on every script and the wasm, and the `Integrity-Policy` header requiring it [M10];
- a **reproducible bundle**: the release names the commit, the toolchain pins and the sha-384 of `index.html`, every asset and the
  wasm; anyone can rebuild and compare;
- an optional **verifier**: the idea of Meta's Code Verify, an extension that hashes the code a web client loaded and compares it with
  hashes a third party publishes (Cloudflare holds WhatsApp Web's, 2022-03-10) [X2]; for SCaaS the extension itself can check the
  web build's hashes against the release data;
- **Isolated Web Apps** (signed web bundles, origin from the signing key, CSP enforced) are limited to Chrome Enterprise-managed
  ChromeOS and select partners [C8]: not a general answer yet.

The extension avoids most of this: its code comes from the store package and the CSP forbids remote script [C5]; its own build
should still be reproducible, and its update is the store's channel (a risk stated in §7.3).

## 5. The RPC rule from a browser

- **The list.** Every chain read goes through the SDK's `scaas-rpc` list from the chain profile: failover by default, one endpoint
  answering a whole read; the strict-majority option; a read that feeds a decryption never from a discovered endpoint unless under
  the majority with at least three ([ARCH-POS-15](../decisions.md#ARCH-POS-15),
  [CLI-RPC-06](../clients/scaas-rpc.md#CLI-RPC-06)); writes send the same signed bytes to the gateways that announce the profile's
  `chain_uid` ([CLI-RPC-08](../clients/scaas-rpc.md#CLI-RPC-08)). The JS config already carries the endpoint class and policy
  (`ClassDef`, `PolicyDef` in `wasm.rs`).
- **CORS, web build.** Public RPC endpoints must send CORS headers for the web origin; a scaas-node gateway serves the web build only
  when its operator lists that origin in `gateway_cors_origins` (exact list, no `*`, `GET, POST`, `Content-Type` only, no
  credentials; only with gateway auth `none`, [NODE-GW-04](../node/gateway.md#NODE-GW-04)). A web build at a new origin therefore
  depends on each operator's list; that is the node's open rule, not a defect.
- **CORS, extension.** Fetches from the service worker, the offscreen document and the event page with host permissions are not
  bound by the same-origin policy; content scripts are [C7]. Proposal: no fetch from content scripts; host permissions requested at
  run time (`optional_host_permissions`) for each endpoint origin the user's profiles name, so the install asks for none.
- **Credentials.** None in an end-user build ([CLI-APP-03](../clients/app.md#CLI-APP-03)); `scaas-rpc` already refuses an endpoint
  with `auth` on wasm32 because the browser follows redirects first. The browser's `fetch` can refuse redirects itself
  (`redirect: "error"`, the app's URL guard), which the wasm transport should use (§7.5 item 4).
- **Origin guard.** The app's URL guard (only configured origins, `credentials: "omit"`, `redirect: "error"`, no WebSocket unless
  configured; [CLI-APP-19](../clients/app.md#CLI-APP-19)) applies in the key host and the UI as written.
- **Privacy.** Every RPC endpoint learns the addresses the wallet reads; dApp read calls proxied by the wallet go to the wallet's
  endpoints, so a dApp cannot point the wallet at its own node.

## 6. ARCH-POS-13: a dApp must never learn anything from a decryption

The rule: no wallet decrypts a ciphertext chosen by anyone other than the key holder and lets that party learn anything about the
result: plaintext, success or failure, an error code, timing, or a later action
([ARCH-POS-13](../decisions.md#ARCH-POS-13)). A dApp is such a party. An attacker can deploy an `OFFCHAIN` token whose own verifier
admits crafted ciphertexts, send one to the user, and then ask the user's wallet, through its dApp, to show or spend that balance.

Proposal:

1. **No decrypt method** on any provider: no `eth_decrypt`, no Wallet Standard decrypt feature, no `scaas_decrypt`, no confidential
   balance in any answer. Confidential balances appear only inside the wallet's own UI.
2. **No decryption triggered by a dApp request before the user acts.** `scaas_confidentialTransfer` opens the approval window
   without reading or decrypting anything; the window then reads the balance from the user's trusted list (named or default
   endpoints, or the majority) and decrypts under the SDK's rules (the reading layer's check that the ciphertext is chain state, the
   sealed opening on shared-key `OFFCHAIN` tokens, [CLI-SGN-51](../clients/signers-clientkeys.md#CLI-SGN-51)).
3. **One answer for every non-success, only after the user's action.** Declined, insufficient balance, a ciphertext that did not
   open, a token not in the reviewed list: the dApp gets 4001 when the user closes the window, and nothing earlier. The window shows
   the reason to the user only. No timer, no retry, no event to the origin depends on the decryption.
4. **Tokens.** By default a dApp may request confidential operations only on the profile's reviewed tokens; an unlisted
   confidential token is refused before any read (a public fact, so its refusal leaks nothing).
5. **After submit** the dApp sees only what the chain shows to everyone (`Landed`, `Consumed`, `Expired`).
6. **KEM records** (PqChat, PqVault): the hybrid KEM is outside ARCH-POS-13 (its Change of 2026-11-13), but dApps get no record
   access anyway (§3.2), so no KEM decapsulation is reachable from a page.

## 7. Recommendation

### 7.1 Components

| Component | Runs in | Holds | Talks to |
|---|---|---|---|
| in-page provider | page world (MAIN, `document_start`, top frame) | request ids | content script by `postMessage` |
| relay | content script (isolated world) | nothing | router by `runtime.Port` |
| router | service worker (Chrome), event page (Firefox, Safari) | grants cache, queue, origin of each port | key host, approval window |
| key host | dedicated worker of the offscreen document (Chrome); event page or its worker (Firefox, Safari desktop) | the SDK (wasm), its handles; IndexedDB sealed store | RPC endpoints and gateways (scaas-rpc), the router |
| approval window | extension page in its own window | prepared-value handles, the review | key host (through the router or a direct port) |
| wallet UI | popup / side panel / tab (the shared React UI) | nothing beyond handles | key host |
| bridge (phase 2) | native messaging to the desktop app or Safari's containing app | nothing; keys in the native SDK | the native app |

The React UI is one code base with one port interface and three transports: Tauri commands (desktop; Tauri v2 capabilities decide
which window may call which command, and remote content gets no IPC unless a capability lists its URL [T1]), extension runtime
messaging (extension), and a worker `postMessage` (web build). The request and response types are the JS binding's records.

### 7.2 Message flow

```mermaid
sequenceDiagram
    participant D as dApp page
    participant P as in-page provider
    participant C as content script
    participant R as router (SW / event page)
    participant K as key host (SDK wasm)
    participant A as approval window
    participant G as gateway / RPC list
    D->>P: request({method: "scaas_transfer", params: {named fields}})
    P->>C: postMessage {id, method, params}
    C->>C: size, depth, JSON, method allow-list
    C->>R: runtime.Port message
    R->>R: origin from port.sender; grant check; queue per origin
    R->>K: prepare(fields)
    K->>G: reads (failover / majority)
    K-->>R: prepared handle + review
    R->>A: open window(origin, handle)
    A->>A: show origin, review, payer, fee; confirm enabled after focus delay + gesture
    A->>K: confirm(handle)
    K->>K: sign (ua-rs), write row
    K->>G: send signed bytes (gateways of the chain_uid)
    K-->>R: operationId
    R-->>C: response
    C-->>P: response
    P-->>D: {operationId}
    K-->>R: event (InFlight / Landed / Consumed / Expired)
    R-->>D: scaas_operationChanged (via C, P)
```

### 7.3 Threat model

| Adversary | Wants | Bound (proposal) |
|---|---|---|
| a malicious dApp page | a signature over bytes it chose; a decryption; to pass as another origin | no UA digest or raw sign (CLI-SGN-29); typed entries reviewed by the user; origin from `port.sender`; no decrypt method; §6 |
| a phishing look-alike origin | the user's approval | exact-origin grants, ASCII + Unicode display, first-visit mark, allow-list and similarity warning, optional local blocklist |
| clickjacking and DoubleClickjacking | a click on confirm | own window, `frame-ancestors 'none'`, not web-accessible, confirm after focus delay and an in-window gesture, no Enter default |
| a request flood | fatigue approvals | one pending request per origin, rate limit, block from the window |
| another extension | to read our keys or impersonate our provider | no `externally_connectable`; our IndexedDB and `storage.session` are ours; it can inject a fake provider into pages (EIP-6963 `rdns` is self-attested), which signs nothing of ours |
| a bug in our content script | escalate from the page | it holds nothing; the router and the SDK re-validate; no `eval`, no string timers |
| an RPC node or a gateway | false state, a crafted ciphertext, censorship | the endpoint list, `chain_uid` pin, majority for discovered decryption reads; a gateway can refuse or delay, never forge (the subject signs) |
| a thief of the disk or browser profile | the seeds | Argon2id-sealed store; seeds behind their own passphrases; `storage.session` empty after browser stop |
| someone at an unlocked session | to use the open wallet | idle lock, screen-lock lock; every write still needs the approval window |
| a compromised web origin (web build) | to serve changed code | SRI + `Integrity-Policy`, reproducible bundle with published hashes, optional verifier; stated residual risk: the first HTML load |
| a compromised extension update or build | to ship changed code | reproducible extension build, published hashes; residual: the store's update channel |
| another extension with host permissions over the passkey `rpId` | a `webauthn-p256` assertion over its own challenge | none in SCaaS (the verifier compares no origin, by decision); the user's OS prompt; stated residual risk for the owner |
| memory scraping inside the key host's realm | secrets in wasm memory | nothing else loaded in that realm; locks; no `mlock` on wasm (stated) |
| a decryption-oracle attacker | key recovery through a dApp | §6: nothing returned, one code after the user's action, no timing |

### 7.4 Phases (proposal)

1. **Extension, EVM:** key host, router, approval window, EIP-1193 + EIP-6963, the `scaas_*` methods for the EVM entries the SDK
   builds, Chrome first (offscreen worker), then Firefox and Safari desktop (session-key re-open, owner's choice in §1.1).
2. **Web build:** after the async profile core; passkey / PRF unlock; reproducible bundle.
3. **Bridge mode:** the extension forwards requests to the desktop app (Chrome: `connectNative`, JSON framed with a 32-bit length,
   1 MB per message from the host, 64 MiB to it, `allowed_origins` without wildcards, the worker kept alive by the port since
   Chrome 105 [C9][C1]; Safari: `sendNativeMessage` to the containing app's native extension, from background or extension pages
   only, not content scripts [A3]). Keys then sit in the native SDK with its mlock; iOS Safari uses only this mode.
4. **Other families** through the Wallet Standard and their own conventions, as the SDK builds them.

### 7.5 What the SDK still lacks for this

1. **The app-core surface in the JS binding** (`app_core.rs`: app keys, records, KEM wrap and unwrap, `prepare_app_record`,
   `prepare_pqvault_record`), and JS bindings of `pqchat-core` and `pqvault-core` (the first builds for wasm32 as a check, the second
   not at all).
2. **The async profile store** over IndexedDB with Web Locks (PLANNED, user profiles §13), and an IndexedDB adapter of the JS
   store interface for the SDK's own state.
3. **A calldata decoder for review** of a dApp's `eth_sendTransaction`: decode against the profile's known contracts (a call to a
   SCaaS token's `mtx*` entry shown as that entry), else an "undecoded" mark; today `NativeSend.data` is hex.
4. **`scaas-rpc` run on wasm32** (tests in a headless browser), with `redirect: "error"` and `credentials: "omit"` on its fetches,
   and its behaviour under CORS failures (a CORS refusal is a transport failure, the next endpoint).
5. **An origin label on operation rows** (display and history only, supplied by the host), so the wallet can show which site
   started an operation and route its events back.
6. **A dApp sign-in that fits CLI-SGN-29**: a tagged, typed sign-in struct (domain, URI, chain, nonce, issued-at, expiry) as its
   own entry, or the owner's ruling that sign-in uses a native EOA only. Today neither exists.
7. **`memory_protection` on wasm32** reported as none, and a lock-on-idle hook the host can call (`lock_all` exists).
8. **Stable request records for providers**: the `scaas_*` params as SDK records generated to TS types, so the provider, the
   approval window and the SDK cannot drift.
9. **PQZ and Zether proving on wasm32 without threads**: not checked in this note (the Zether prover's browser build exists for
   the SCaaS app SPA); a time budget per proof in a browser is needed before §6's flow is usable.

### 7.6 Open questions for the owner

- **Firefox and Safari re-open** by a session key in `storage.session` (MetaMask / Rainbow pattern), or lock on every event-page
  suspension.
- **One browser signer:** the SCaaS app SPA's clientkeys key worker and the scaas-app UI's SDK worker; this note assumes the SDK
  only.
- **Native EOA message signing** (`personal_sign`, `eth_signTypedData_v4`) for dApps: offer with a decoded review, or not at all.
- **Default frames:** top frame only, or every frame as Rabby does.
- **Passkeys and other extensions:** accept the residual risk above (Chrome 122+, Firefox 150+ let an extension assert for any `rpId` in its host permissions), or a SCaaS passkey kind that binds origins.
- **Bridge mode first** on desktops where the app is installed, or the wasm key host first everywhere.

## Sources

Read on 2026-11-27.

- [C1] Chrome, "The extension service worker lifecycle", <https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle>
- [C2] Chrome, `chrome.offscreen`, <https://developer.chrome.com/docs/extensions/reference/api/offscreen>
- [C3] Chrome, `chrome.storage`, <https://developer.chrome.com/docs/extensions/reference/api/storage>
- [C4] Chrome, `chrome.idle`, <https://developer.chrome.com/docs/extensions/reference/api/idle>
- [C5] Chrome, manifest `content_security_policy`, <https://developer.chrome.com/docs/extensions/reference/manifest/content-security-policy>
- [C6] Chrome, manifest `web_accessible_resources`, <https://developer.chrome.com/docs/extensions/reference/manifest/web-accessible-resources>
- [C7] Chrome, "Cross-origin network requests", <https://developer.chrome.com/docs/extensions/develop/concepts/network-requests>
- [C8] Chrome, "Isolated Web Apps", <https://developer.chrome.com/docs/iwa/introduction>
- [C9] Chrome, "Native messaging", <https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging>
- [M1] MDN, manifest `background`, <https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/background>
- [M2] Mozilla Bugzilla 1851373 (event pages terminated after 30 s in Firefox 117; fixed 117.0.1 / 118), <https://bugzilla.mozilla.org/show_bug.cgi?id=1851373>
- [M3] MDN, `storage.session`, <https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/storage/session>
- [M4] MDN, "Content scripts" (page environment controlled by the page), <https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Content_scripts>
- [M5] the same page (isolated world, `postMessage` warning, CORS of content scripts)
- [M6] MDN, "Chrome incompatibilities", <https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Chrome_incompatibilities>
- [M7] MDN, "Use the Web Authn API in web extensions", <https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Use_the_web_authn_api>
- [M8] MDN, manifest `content_scripts` (`world`), <https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/content_scripts>
- [M9] MDN, "WebAuthn extensions" (`prf`), <https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/WebAuthn_extensions>
- [M10] MDN, "Subresource Integrity", <https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity>
- [A1] Apple, "Optimizing your web extension for Safari", <https://developer.apple.com/tutorials/data/documentation/safariservices/optimizing-your-web-extension-for-safari.md>
- [A2] Apple Developer Forums, "Safari Extension Service Worker Permanently Killed on iOS 17.4.x-17.6" (one developer's report), <https://developer.apple.com/forums/thread/758346>
- [A3] Apple, "Messaging between the app and JavaScript in a Safari web extension", <https://developer.apple.com/tutorials/data/documentation/safariservices/messaging-between-the-app-and-javascript-in-a-safari-web-extension.md>
- [B1] WebKit, "Updates to Storage Policy", <https://webkit.org/blog/14403/updates-to-storage-policy/>
- [E1] EIP-1193, <https://eips.ethereum.org/EIPS/eip-1193>
- [E2] EIP-6963, <https://eips.ethereum.org/EIPS/eip-6963>
- [E3] EIP-2255, <https://eips.ethereum.org/EIPS/eip-2255>
- [E4] EIP-5792, <https://eips.ethereum.org/EIPS/eip-5792>
- [E5] CAIP-25, <https://standards.chainagnostic.org/CAIPs/caip-25>
- [E6] Wallet Standard, <https://github.com/wallet-standard/wallet-standard> (`DESIGN.md`, `packages/core/wallet/src/register.ts`)
- [E7] Solana Wallet Standard features, <https://github.com/anza-xyz/wallet-standard> (`packages/core/features/src/`)
- [T1] Tauri v2, "Capabilities", <https://v2.tauri.app/security/capabilities/>
- [W1] MetaMask extension source, <https://github.com/MetaMask/metamask-extension> (`app/scripts/offscreen.ts`, `app/offscreen/offscreen.ts`, `app/scripts/metamask-controller.js`, `app/scripts/use-snow.js`, `lavamoat/`)
- [W2] Rabby source, <https://github.com/RabbyHub/Rabby> (`src/background/index.ts`, `src/background/service/session.ts`, `src/manifest/chrome-mv3/manifest.json`)
- [W3] Rainbow extension source, <https://github.com/rainbow-me/browser-extension> (`src/core/keychain/KeychainManager.ts`, `src/entries/background/handlers/handleAutoLock.ts`)
- [W4] MetaMask phishing controller, <https://github.com/MetaMask/core/tree/main/packages/phishing-controller> (`src/PhishingDetector.ts`, `src/utils.ts`); the old list repository says it moved there: <https://github.com/MetaMask/eth-phishing-detect>
- [W5] Phantom blocklist, <https://github.com/phantom/blocklist> (Phantom's extension source is not public; only this list, its SDKs and audit reports are)
- [W6] MetaMask, "MetaMask API Method Deprecation" (2022-06-27), <https://metamask.com/news/metamask-api-method-deprecation>
- [X1] Security Affairs, "DoubleClickjacking allows clickjacking on major websites" (2025-01-02), <https://securityaffairs.com/172572/hacking/doubleclickjacking-clickjacking-on-major-websites.html>
- [X2] Cloudflare, "Cloudflare verifies code WhatsApp Web serves users" (2022-03-10), <https://blog.cloudflare.com/cloudflare-verifies-code-whatsapp-web-serves-users/>
- LavaMoat (per-package policy, SES, scuttling; used by MetaMask's build), <https://github.com/LavaMoat/LavaMoat>: an idea for the extension's own
  build (a policy per dependency) beside CLI-APP-15's allow-list.
