# SCaaS app (`scaas/app/`) — console and dApp (design)

Status: draft rev 1, 2026-10-06. Code at `scaas` `main` 9737ef3 (TW2 T1–T6/T8 built; node store P1 built; job API,
admin API and admin auth SPECIFIED, not built). Rulings: **R150–R172** (§2), continuing R129–R149 (TW2).
Owner decisions of 2026-10-06 (purpose, seven families at once, signers, no Odoo, UI kit, i18n, two deployment modes)
are folded in.

Requirements this spec satisfies:

| Short | File | Section |
|---|---|---|
| NI | `docs/superpowers/specs/2026-10-06-node-independence-design.md` | §7.1 (API keys server-side only), §7.3 routes, §7.4 CORS, §7.7 app requirements, §14 T21–T24 |
| A2 | `docs/superpowers/specs/2026-10-06-mesh-gossip-amendment.md` | R127 + §13 (gossip admin routes, screens), R124 (home-bound/unbound), R128 (DEX-trusted homes), §11.5 (`scope=network`, `/v1/dex/homes`) |
| TW2 | `docs/superpowers/specs/2026-10-06-token-wrappers-v2.md` | §4–§9 (tiers, rates, named functions, factory v2), §8.4/§8.5 (disclosure texts), §11 (Hedera), §12 (non-EVM) |
| DEX | `docs/superpowers/specs/2026-10-03-dex-design.md` | §1.1 (Order EIP-712), §1.3 (cancel), §3.5 (gateway routes) |
| Z | `2026-10-03-zether-design.md`, `2026-10-05-zether-limits.md` | flows, BSGS limits, device balance cache |
| SCaaS | `docs/SCaaS.md` | §7 (families), §8 (Zether), §12 (node API surface), §14 (interfaces) |
| INT | `docs/integration.md` | §13 (wallets and signers), §14 (the app) |

Code read for facts: `scaas-node/src/{gateway.rs,gwauth.rs,dex.rs,dex/venue.rs,metatx.rs,main.rs,config.rs}`,
`clientkeys/src/*`, `zether-prover/src/{wasm.rs,api.rs}`, `smartcontracts/evm/src/**`, and the per-family portal
connectors in `bamboo-dms/dms_blockchain_bridge/static/src/js/{chain_pay.js,subject_signers.js,connectors/*}` with
their tests, plus the family encoders `bamboo-dms/dms_blockchain/lib/fam_*.py` (Odoo is a reference here, never a
dependency).

---

## 1. Scope and non-goals

### 1.1 In scope

One React + Vite single-page app with two halves:

- **dApp** (no login): wallets and signers, balances, token catalogue, token creation (factory v1 and v2), wrapping an
  existing token into a meta-tx token, wrap/unwrap (incl. gasless `mtxUnwrap`), meta-tx transfers and payments
  submitted through a node gateway **or** self-paid, DEX order book (home-bound and relayer-unbound markets) with
  place/cancel, Zether (register, deposit/shield, confidential transfer, withdraw, balance via device cache + BSGS).
- **Console** (login to one node's admin API, built-in users or OIDC): chains, tokens, lanes, namespaces, jobs, mesh
  peers (SSRF-guarded URLs), policy, gossip (peers, topics, announces, bans, trusted), DEX markets and homes,
  external-client API keys, admin users, audit, metrics.
- All seven families behind one adapter interface: EVM (Gnosis 100, Celo 42220, private chain 9000, anvil 31337),
  Hedera (295–298, EVM on HSCS + HTS specifics), Cosmos (CosmWasm), Soroban (Stellar and Pi), Aptos, Sui, TON, Solana.
- Two deployment modes from one build: static SPA with runtime `config.json`, and served by `scaas-node` on its admin
  listener.
- English (default) and Vietnamese; dark and light themes.

### 1.2 Non-goals

| Not in this spec | Why / where instead |
|---|---|
| Any Odoo call or Odoo-specific model | Owner: no Odoo dependency (NI R87) |
| A backend of its own, or the job API (`/v1/jobs`, `/v1/events`) | R109/T23: an R92 key would have to live in the bundle. Namespace job/event data is shown only by clients with their own backend |
| Admin API keys (`scaas_ak1.`) | NI rev 3.2 removed them ("there are no admin API keys"); SCaaS.md §3.3/§12.1 still mention them (§17) |
| Mandates, sealed-bid tender, regulated tokens, vesting, Universal Account linking beyond Zether register | Not requested; PLANNED elsewhere |
| Zether disclosure openings (`SENDER_S`, `RECEIVER_X`, auditor) | Not requested for v1; the prover already exposes them, a later screen is cheap |
| Non-EVM token deployment (Cosmos `scaas-token` instantiate, Soroban token, TON jetton master) and non-EVM wrappers | Wrappers are PLANNED (TW2 R145); Cosmos deploy tooling is PLANNED. Move and Solana need no wrapper (any FA/coin/mint is gasless through the subject account) |
| Passkeys on non-EVM families | Contracts support P-256, but clientkeys' passkey signer is EVM-only; stream A16 (§15) after the families |
| TON Connect HTTP bridge (QR, mobile wallets), WalletConnect | Needs a third-party bridge origin in `connect-src` and a vendored SDK; injected wallets only (as `connectors/ton.js`) |
| HashPack / Blade for Hedera native accounts | `hedera_signMessage` prefixes the message, so it cannot produce the raw ED25519 signature HIP-632 `isAuthorizedRaw` checks (net-hedera R6-4); native ED25519 accounts sign with the seed vault |
| Celo CIP-64 fee currencies | SCaaS does not depend on them (SCaaS §7.1) |
| Offline/PWA, push notifications, analytics, remote fonts | Not requested; analytics and remote fonts are excluded by R166 |

---

## 2. Rulings

Format: **ruling — why — cost if wrong.**

| # | Ruling | Why | Cost if wrong |
|---|---|---|---|
| **R150** | **One SPA, two halves, one build.** dApp routes never require login; console routes require a node session and are a separate lazy chunk. Both deployment modes serve the identical `dist/`. | NI §7.7: "chain-only features work without login". One artefact to sign, test and pin. | A console bug ships with the dApp (separate chunk limits blast radius). |
| **R151** | **Stack:** React 19 + TypeScript strict + Vite; **TanStack Query** for every remote read (RPC, gateway, admin API); **no global state library** — a ~50-line `useSyncExternalStore` store holds the in-memory session(s), the active signer and the selected chain; **react-router 7 with hash routing** (`#/…`). | Server state is 90 % of the app and Query covers caching, polling and invalidation. Hash routing removes the SPA-fallback rule from every static host and from the node (§13.2). | Deep links look like `/#/dex/evm:100/1`; OIDC callbacks land on `/` with a query, which hash routing leaves alone. |
| **R152** | **No server of its own.** The app talks to chain RPCs directly and to `scaas-node` only for (a) the gateway (signed intents, DEX) and (b) the admin API. It never holds an R92 API key, a gateway `bearer`/`hmac` secret, or any other shared secret; `config.json` must not contain one (validator §4.3). A gateway configured with `bearer`/`hmac` is unusable from the app by design. | NI R109, T23: anything in a bundle is public. The gateway's R54 secret is a single shared secret, exactly the T23 failure. | Public gateways must be `none` behind a host reverse proxy with rate limits (SCaaS §3.5, HANDOFF O5). |
| **R153** | **Family adapters:** one TypeScript interface (§5.1), seven implementations; `hedera` is the EVM adapter plus a Hedera override module (signature scheme, mirror node, HTS checks). An adapter is lazy-loaded when a chain of its family is first selected; its `features` set drives every screen (matrix §7). | Owner: all seven families at once; family SDKs are the bulk of the bytes (§14). | — |
| **R154** | **The app builds every byte it asks a user to sign** and never accepts a payload, digest or typed data from a node or any remote party. Family encoders (MetaOp bytes, digests, sign envelopes, PDA/object/address derivations) are ported from `dms_blockchain/lib/fam_*.py` into **clientkeys `src/fam/*.js`** (pure ESM, no I/O), KAT-locked against the existing vectors (§12.1), and shared by the app and any future portal bundle. | The portal connectors sign server-built terms (Odoo); without Odoo the client is the only party left to build them, and a display that is not derived from the signed bytes is a phishing surface. Putting encoders in clientkeys reuses its test harness and keeps one JS implementation. | clientkeys grows from EVM-centric to all families (≈ 1.5 k lines of ports). |
| **R155** | **Signers:** clientkeys passkey (SubjectAccount, ERC-1271, on EVM and Hedera), clientkeys seed vault (every family; Solana path `m/44'/501'/i'/0'` added to `NETWORKS`; Pi = `stellar` with `coinType 314159`), extension wallets per family (§6.3), and a **dev key** that exists only in development builds (R166, §10.4). | Owner list; R31–R33 (keys never leave the device). | — |
| **R156** | **Two submission paths.** (1) **Gateway**: `POST /v1/metatx` / `/v1/dex/*` on a node whose gateway serves the chain and token (`GET /v1/gateway`, R159). Today the gateway serves the **EVM family only** (`main.rs` builds `GwChain` only for non-adapter chains — not Hedera, not non-EVM). (2) **Self-paid**: any gas-holding account the user controls submits the signed envelope itself — the same call a lane would make (`executeMetaTransaction`/named `mtx*` on EVM v2, `Relay` on Cosmos, `relay_pay` PTB on Sui, `relay_pay` entry on Aptos, `SignedOp` on TON, `relay_pay` + precompile instruction on Solana, the auth entry in the user's own transaction on Soroban). When the signer **is** the submitting EOA on EVM, the app calls the direct function (`transfer`, `payWithFee`, `unwrap`) and asks for no meta-tx signature at all. | Owner: gateway OR self-paid. Self-paid makes every family usable with no node; the direct-call rule avoids a pointless second signature. | Non-EVM and Hedera users have no relayed path until the node exposes a door A for them (open question Q1). |
| **R157** | **Intent status = chain truth.** A gateway `202 queued` is shown as "accepted by relayer", never as done. Done = the intent's nonce consumed (`metaNonce(from, batch) > nonce` on EVM; family lane read elsewhere), plus `PaymentSettled(entryRef)` / `MetaTransactionExecuted(digest)` when present; expired = `validUntil` passed with the nonce unconsumed. `GET /v1/intents/{id}` (NI, SPECIFIED) is used for progress when the node returns an `intent_id`. | The node is trusted for liveness, not truth (SCaaS §3.5); G1 makes the nonce the arbiter. | One extra RPC read per poll. |
| **R158** | **Signing review is the app's own rendering of the exact bytes** (§10.5): decoded fields, token metadata from chain reads, warnings; signatures are verified locally (ecrecover / ERC-1271 `eth_call` / ed25519 / secp256k1 / P-256) before anything is sent; a `verifyingContract`/`contract` that is neither in `config.json` nor `isDeployedHere` on a configured factory is refused (dev builds: overridable). Default validity windows: transfers/pay ≤ 15 min, unwrap ≤ 15 min, DEX orders ≤ 30 d (venue cap `MAX_TTL_SECS`). | Extension wallets show EIP-712 well, others show hex; the app is the only place a user sees the same decoded view for every family. | Users of a non-configured token must add it to `config.json` (or use a dev build). |
| **R159** | **Node-side additions (stream N1, in `scaas-node`):** (a) `GET /v1/gateway` on the gateway listener: per served chain `{chain, tokens[], fee_recipient, breaker_open, dex: {address, relayer, markets_url} | null}` — today a client cannot learn the served token list, the R84 fee recipient, or the DEX relayer it must bind orders to (`dex.rs:553` only says so in an error); (b) `[modules] gateway_cors_origins` with the NI §7.4 rules (exact origins, no `*`, no credentials, `GET, POST`, headers `Content-Type`); (c) `[app]` static serving + CSP on the admin listener (§13.2). | The app cannot sign a bound DEX order or show the fee recipient without (a); a browser on another origin cannot reach the gateway without (b). | ~200 lines of Rust; the app degrades without them (§9.1). |
| **R160** | **Node-served mode** serves the app only on the **admin listener** (same origin as `/v1/admin/*`), never on the gateway, job-API or mesh listeners. Admin CORS is then unnecessary; `/metrics` is readable (it is not CORS-enabled, NI §7.4). | Same origin removes a CORS allowlist and gives the console metrics; the job API must stay browser-unreachable (NI §7.1). | The admin listener becomes user-facing: it needs TLS in front (already required for non-loopback binds). |
| **R161** | **Static mode** reads `./config.json` (same origin, `cache: "no-store"`) at start, validates it (§4), and refuses to start on any error. `index.html` carries a baseline meta CSP; exact headers are generated for the host from `config.json` (`npm run csp`, §13.1). | Runtime config keeps one build for every deployment. | A host that ignores the generated headers runs with the weaker meta CSP. |
| **R162** | **Admin tokens in memory only** (NI §7.7): per node, never in `localStorage`/`sessionStorage`/IndexedDB/cookies. The only values that touch `sessionStorage` are the OIDC `code_verifier`, `state` and `nonce` between the redirect and the callback, deleted on callback or after 10 min. A reload means re-login (built-in) or a `prompt=none` redirect (OIDC). Logout clears the Query cache of that node. | The verifier must survive a full-page redirect and is useless without the authorization code; tokens are not stored anywhere. | Built-in users type their password after every reload. |
| **R163** | **OIDC client = `oauth4webapi`** (public client, Authorization Code + PKCE S256, `state` + `nonce`, exact redirect URI = `<app origin>/`), issuer taken only from the node's `GET /v1/admin/auth-modes`, discovery `issuer` compared byte for byte; renewal by refresh-token rotation when the IdP issues refresh tokens to public clients, else full-page `prompt=none`; no hidden-iframe renewal. The access token is sent only to the node that listed the issuer. | No hand-rolled OAuth; iframe renewal breaks under third-party-cookie blocking. | Some IdPs (no refresh tokens for SPAs) bounce the page every token lifetime (≤ `max_token_lifetime_secs`, 1 h default). |
| **R164** | **Zether in a Web Worker** running `zether-prover` built with `wasm-bindgen --target web` (the current `wasm-smoke.sh` builds `--target nodejs`). The key handed to the WASM is `{x}` from clientkeys `openConfKey`, never the mnemonic. BSGS defaults `tableBits 22, boundBits 44`; `allowLargeTable` (≤ 2^26) only by explicit user choice. Balance comes from the vault cache (`readBalance`/`checkBalance`), BSGS only on `pending` or the delta (limits §5). Zether screens appear only on chains with a ZetherToken in `config.json` **and** chain id 31337/1337 (`ZetherSafety.requireDevChain`). | Prove takes seconds; the main thread must stay responsive (research 03 §5.1). `x` never leaves the device (R33). | — |
| **R165** | **Passkeys are bound to one origin.** `config.json` `passkey.rpId` (registrable suffix of the app origin) and the WebAuthn `origin` are part of the SubjectAccount key (`passkeySubjectKey({x, y, rpId, origin})`). A user who opens a second deployment (static vs node-served, another host) must add a key for that origin from the first one (`addKey`, `checkOwnerCall`). The app shows the bound origin on every passkey account. | Not obvious to operators: two deployment modes are two origins. | One extra "add this device/origin" flow. |
| **R166** | **Supply chain:** exact versions only (`save-exact`), committed `package-lock.json`, `npm ci --ignore-scripts` (`.npmrc`), the dependency allowlist of §10.3 (anything else needs a ruling), no runtime CDN, no analytics, no remote fonts, `npm audit signatures` in CI. Development-only code (dev key, test wallets) is reachable only behind `import.meta.env.DEV` and CI fails if the production `dist/` contains its markers (§10.4). | The bundle signs money movements; every dependency is code with signing access. | Upgrades are deliberate PRs. |
| **R167** | **i18n:** `react-i18next`, English default, Vietnamese complete at release; every user-visible string keyed; amounts and dates formatted with `Intl` from `bigint` (never `Number`); node error codes map to `errors.node.<CODE>`. Risk disclosures (TW2 §8.4, §8.5; Zether "unaudited, dev chains only") are translated verbatim and the English text is shown beside a translation until the owner approves it (Q3). | Owner: EN + VI, default EN. A mistranslated risk disclosure is worse than none. | — |
| **R168** | **Role gating is UI only** (NI §7.7): `viewer ⊂ operator ⊂ admin`, `key_custodian` separate; roles from `GET /v1/admin/me`; actions the token cannot perform are hidden; a `403` re-reads `me`. Role grants offered in the users screen are ⊆ the caller's roles (R107). | The node enforces; the UI must not invite failing actions. | — |
| **R169** | **`rateAdmin` must be a contract** (TW2 §5.1, R26 `_isContract`), so `proposeRate`/`cancelRate`/`executeRate`/`renounceRateAdmin` are offered as **calldata to submit through that contract** (copy + EIP-681-style link), never sent from the user's EOA. Guardian actions (`disableWrap`, `renounceGuardian`) are sent directly (any address may be guardian). | Sending from an EOA always reverts. | — |
| **R170** | **The app dials only URLs from `config.json`** (RPCs, gateways, admin URLs) and OIDC endpoints discovered from an issuer the node lists. DEX home gateway URLs learned from `/v1/dex/homes` are dialed only for DEX-trusted homes; an untrusted home needs an explicit per-session opt-in with the A2 B2 warning. Every dialed URL is `https://` (http only for `localhost`/`127.0.0.1` in dev builds), no userinfo. | A browser can reach intranet hosts; network-learned URLs are attacker-chosen (A2 X1). | Untrusted homes are one click further away. |
| **R171** | **Metrics and topic rates are same-origin features.** The metrics screen parses `/metrics` (Prometheus text) only when the admin API is same-origin (node-served mode or a proxy); in static cross-origin mode it shows a configured `metricsDashboardUrl` link. Topics show mesh size/peers from `GET /v1/admin/gossip`; msgs/s columns need metrics. | `/metrics` is deliberately not CORS-enabled (NI §7.4). | Static deployments have a thinner topics screen. |
| **R172** | **Non-EVM DEX is shown as unavailable.** Cosmos, Soroban, Move, TON and Solana DEX contracts are built, but the only off-chain book is the EVM `OrderBookDex` venue (`dex/venue.rs`); without a book there is nothing to view or match. | Facts from code. | Q2. |

---

## 3. Architecture

### 3.1 Picture

```
                 ┌──────────────────────────── browser (one origin) ────────────────────────────┐
                 │  React shell ─ router(#) ─ Query cache ─ session/signer store (memory)        │
                 │     │            │                                                            │
                 │  dApp screens   console screens (lazy) ── node/admin client ── auth (builtin|OIDC)
                 │     │                                                                         │
                 │  family registry ── lazy adapter chunk per family (SDK + clientkeys/fam)     │
                 │     │                     │                                                   │
                 │  signers: clientkeys passkey | seed vault | extension (per family) | dev(DEV) │
                 │  zether: Worker ── zether-prover WASM (lazy)                                  │
                 └─────┼─────────────────────┼─────────────────────────────┼─────────────────────┘
                       │ JSON-RPC/REST        │ POST /v1/metatx, /v1/dex/*  │ Bearer /v1/admin/*
                       ▼                      ▼                             ▼
          chain RPCs (config.json)     scaas-node gateway (CORS, R159)   scaas-node admin listener
                                                                         (+ app files in node-served mode)
```

Nothing else is contacted except OIDC endpoints (R163) and DEX-trusted home gateways (R170).

### 3.2 Libraries (allowlist, R166)

| Purpose | Package | Pin rule |
|---|---|---|
| UI | `react`, `react-dom` 19; `tailwindcss` 4 + `@tailwindcss/vite`; shadcn/ui components **copied** into `src/ui/` (with their `@radix-ui/*` peers, `class-variance-authority`, `clsx`, `tailwind-merge`, `lucide-react`) | exact |
| Build | `vite`, `@vitejs/plugin-react`, `typescript`, `vitest`, `@playwright/test`, `eslint` + `typescript-eslint` | exact, dev only |
| Data | `@tanstack/react-query` 5; `react-router` 7 | exact |
| i18n | `i18next`, `react-i18next` | exact |
| OIDC | `oauth4webapi` | exact |
| Keys | `@scaas/clientkeys` = `file:../clientkeys` (its `@noble/*`/`@scure/*` 2.4.0 pins) | workspace |
| EVM, Hedera | `viem` 2.x | exact |
| Cosmos | `@cosmjs/cosmwasm-stargate`, `@cosmjs/stargate`, `@cosmjs/proto-signing` | exact |
| Soroban | `@stellar/stellar-sdk` (only `rpc` + XDR/auth builders are imported), `@stellar/freighter-api` 6.0.1 (same version the portal vendors) | exact |
| Sui | `@mysten/sui` (client, `Transaction`, `bcs`) | exact |
| Aptos | `@aptos-labs/ts-sdk` 7.3.0 (as `smartcontracts/move/aptos/scripts`) | exact |
| TON | `@ton/core` 0.63.1, `@ton/ton` 16.3.0 (as `smartcontracts/ton`) | exact |
| Solana | `@solana/kit` 8.4.0 (as `smartcontracts/solana/scripts`) | exact |

Wallet discovery uses the standards' event protocols with no library (EIP-6963; `wallet-standard:register-wallet` /
`app-ready` for Sui, Aptos, Solana; `window.keplr`/`window.leap`; TON JS bridge), ported from the portal connectors.
Versions without a pin above are fixed in `package-lock.json` by stream A1/A9–A14 at the then-current release and
recorded in `app/README`.

### 3.3 Package layout (`scaas/app/`)

```
app/
  package.json  package-lock.json  .npmrc (save-exact=true, ignore-scripts=true)  tsconfig.json  vite.config.ts
  index.html            # baseline meta CSP, no inline script
  budget.json           # §14
  public/config.example.json
  scripts/  csp.mjs (headers from config.json)  budget.mjs  abi.mjs (ABIs from forge out/)  i18n-check.mjs
  src/
    main.tsx  app.tsx  routes.tsx
    config/   schema.ts (parseConfig, no lib)  load.ts
    lib/      store.ts (session, signer, chain)  amount.ts (bigint ⇄ decimal)  url.ts (R170 guard)  errors.ts
    ui/       shadcn components, theme.tsx, AddressView.tsx, SignReview.tsx, AmountInput.tsx
    i18n/     index.ts
    locales/  en/{common,wallet,tokens,dex,zether,admin,errors}.json   vi/… (same keys)
    families/ types.ts  registry.ts (lazy import map)  features.ts
              evm/ (adapter.ts, abi.ts generated, factory.ts, wrap.ts, dex.ts, zether.ts)  hedera/ (overrides.ts, mirror.ts)
              cosmos/  soroban/  sui/  aptos/  ton/  solana/
    signers/  types.ts  passkey.ts  seed.ts  extension/{eip6963,wallet-standard,keplr,freighter,tonbridge}.ts  dev.ts
    node/     gateway.ts  admin.ts  auth/{builtin.ts,oidc.ts}  roles.ts
    zether/   worker.ts  client.ts
    features/ wallet/ send/ tokens/ create/ wrap/ dex/ zether/ accounts/ settings/
              admin/{overview,chains,tokens,lanes,namespaces,jobs,peers,policy,gossip,markets,keys,users,audit,metrics}/
  test/       unit tests next to code (*.test.ts); vectors read from ../smartcontracts, ../scaas-node/tests/vectors,
              ../zether-prover/vectors, ../clientkeys/test/vectors
  e2e/        playwright.config.ts, fixtures/{wallets.ts,mock-node.mjs,mock-idp.mjs}, specs/*.spec.ts
```

`src/families/evm/abi.ts` is generated by `scripts/abi.mjs` from Foundry artefacts (`smartcontracts/evm/out/`,
gitignored) for `IOpenFactory`, `IOpenFactoryV2`, `IERC20MetaTx`, `IERC20Payment`, `IMetaTokenV2`, the three tier
contracts, `OrderBookDex`, `SubjectAccount(Factory)`, `IZetherToken`, `IUniversalAccountRegistry`, and committed
(`as const` for viem types); CI regenerates and diffs it.

---

## 4. `config.json`

### 4.1 Schema

```jsonc
{
  "version": 1,
  "defaultLocale": "en",                       // "en" | "vi"
  "passkey": { "rpId": "app.example.com" },    // R165; must be a registrable suffix of location.hostname
  "metricsDashboardUrl": "https://grafana.example.com/d/scaas",   // optional, R171
  "nodes": [
    { "id": "main", "label": "Main node",
      "gateway": "https://gw.example.com",     // optional; R152: auth none behind a proxy
      "admin": "https://node.example.com" }    // optional; "self" = same origin (node-served mode)
  ],
  "chains": [
    { "key": "evm:100", "family": "evm", "label": "Gnosis", "rpc": ["https://rpc.gnosischain.com"],
      "explorer": "https://gnosisscan.io", "native": { "symbol": "xDAI", "decimals": 18 },
      "dev": false, "private": false, "gatewayNode": "main",
      "contracts": { "factoryV1": "0x…", "factoryV2": "0x…", "dex": "0x…", "subjectAccountFactory": "0x…",
                     "accountImplementation": "0x…", "zetherRegistry": null },
      "tokens": [ { "address": "0x…", "label": "Example" } ],          // curated list; others by explicit add
      "zetherTokens": [] },
    { "key": "hedera:296", "family": "hedera", "rpc": ["https://testnet.hashio.io/api"],
      "mirror": "https://testnet.mirrornode.hedera.com", "…": "as evm" },
    { "key": "cosmos:scaas-1", "family": "cosmos", "rpc": ["https://rpc…"], "rest": "https://lcd…",
      "bech32Prefix": "wasm", "gasPrice": "0.025uscaas", "contracts": { "token": ["wasm1…"] } },
    { "key": "soroban:testnet", "family": "soroban", "rpc": ["https://soroban-testnet.stellar.org"],
      "networkPassphrase": "Test SDF Network ; September 2015", "coinType": null,   // Pi: 314159
      "contracts": { "token": ["C…"], "account": "C…" } },
    { "key": "sui:testnet", "family": "sui", "rpc": ["https://fullnode.testnet.sui.io"],
      "contracts": { "package": "0x…", "root": "0x…", "registries": [ { "coinType": "0x2::sui::SUI", "id": "0x…" } ] } },
    { "key": "aptos:2", "family": "aptos", "rpc": ["https://api.testnet.aptoslabs.com/v1"],
      "contracts": { "package": "0x…", "assets": ["0x…"] } },
    { "key": "ton:-3", "family": "ton", "rpc": ["https://testnet.toncenter.com/api/v3"],
      "appDomain": "app.example.com", "contracts": { "masters": ["0:…"] }, "attachNanoton": "150000000" },
    { "key": "solana:<genesis>", "family": "solana", "rpc": ["https://api.devnet.solana.com"],
      "contracts": { "program": "…", "mints": ["…"] } }
  ]
}
```

`key` is the node's `chain_key` (`config.rs:746`: `evm:<id>`, `hedera:<id>`, otherwise `<family>:<network>`), so the
same string identifies a chain in the app, the node admin API and the mesh. A chain without `gatewayNode` has only the
self-paid path.

### 4.2 Generation

`npm run config:from-deployments -- <rpc>` reads `smartcontracts/evm/deployments/<chainid>.json` (written by
`deploy.sh evm`) into an EVM chain entry; other families are written by hand (their deploy tooling differs).

### 4.3 Validation (`src/config/schema.ts`, no library)

Refuse to start (error screen, English + Vietnamese) when: unknown `version`; duplicate `key`/`id`; `family` not in
the seven; a URL not `https:` (dev builds also allow `http://localhost|127.0.0.1`), with userinfo, or (for RPCs)
with a query string or path segment matching `/(api[-_]?key|token|secret|auth)/i` (R152: provider keys in URLs are
secrets); `dev: true` on a chain whose id is not 31337/1337 or a `localnet`/`standalone`/`local` network; a
`zetherTokens` entry on a non-dev chain (R164); `passkey.rpId` not a suffix of `location.hostname`; `gatewayNode`
naming a node without `gateway`. Unknown fields are ignored with a console warning (forward compatibility).

---

## 5. Family adapters

### 5.1 Interface (`src/families/types.ts`)

```ts
type Family = 'evm' | 'hedera' | 'cosmos' | 'soroban' | 'sui' | 'aptos' | 'ton' | 'solana';
type Feature = 'metaPay' | 'gateway' | 'selfPaid' | 'deposit' | 'factoryV1' | 'factoryV2' | 'wrap' | 'mtxUnwrap'
             | 'dex' | 'zether' | 'passkey' | 'enableCoinType';

interface FamilyAdapter {
  family: Family; chain: ChainCfg; features: ReadonlySet<Feature>;     // matrix §7, narrowed by config/node caps
  // addresses
  parseAddress(s: string): Address;               // throws localized error; family-canonical form (SCaaS §7.8)
  shortAddress(a: Address): string; explorer(kind: 'tx' | 'address' | 'token', id: string): string | null;
  subjectAccount(owner: SignerAccount, token?: TokenRef): Promise<{ address: Address; exists: boolean }>;
  // reads
  nativeBalance(a: Address): Promise<bigint>;
  token(t: TokenRef): Promise<TokenInfo>;         // symbol, decimals, kind/version, underlyings, legs, rate state
  tokenBalance(t: TokenRef, holder: Address): Promise<bigint>;
  laneState(t: TokenRef, from: Address, lane: bigint): Promise<bigint | null>;   // next nonce; null = random (Soroban)
  // intents
  buildIntent(p: IntentParams): Promise<Intent>;  // bytes/typed data + digest + DisplayModel; pure after reads
  signRequest(i: Intent): SignRequest;            // what a signer must sign (§6.1)
  verify(i: Intent, s: Signature): Promise<boolean>;   // local check before sending (R158)
  submitGateway?(node: NodeCfg, i: Intent, s: Signature): Promise<{ intentId?: string }>;  // R156 (EVM today)
  buildSelfPaid(i: Intent, s: Signature, payer: SignerAccount): Promise<UnsignedTx>;
  send(tx: UnsignedTx, by: Signer): Promise<TxId>;
  intentStatus(i: Intent): Promise<'pending' | 'done' | 'expired'>;               // R157
  waitTx(id: TxId): Promise<Receipt>;             // status + normalized events
  events(f: EventFilter): Promise<NormalizedEvent[]>;  // SCaaS §7.8 shape; bounded range
  // optional feature modules, present iff the feature is in `features`
  factory?: FactoryModule; wrap?: WrapModule; dex?: DexModule; zether?: ZetherModule; deposit?: DepositModule;
}
```

`Intent.display` is produced by the same code that produced the bytes (R158); `SignReview` renders only `display`.
Every adapter passes the shared contract test suite (`families/contract.test.ts`): KAT bytes/digests, address round
trips, `verify` true on the vector signature and false on a flipped byte, `buildSelfPaid` decodes back to the intent.

### 5.2 Per-family plan

| Family | Encoders (clientkeys `src/fam/`) ported from | Subject signs (envelope) | Self-paid submission | Reads (balance, nonce/lane) | Events / status | SDK |
|---|---|---|---|---|---|---|
| **EVM** | already in clientkeys `evm.js` (`hashTypedData`), plus DEX `Order`/`CancelOrder`/`InvalidateNonces`, v2 named-function calldata, `payLane` tag (TW2 §7.3); KAT `metatx_kat.json`, `metatx_v2_kat.json`, `dex_kat.json` | EIP-712 `MetaTransaction` (domain `("SCaaS MetaToken", "1"|"2", chainId, token)` read from `eip712Domain()`), DEX domain `("SCaaS OrderBookDex", "1", chainId, dex)`; EOA ECDSA or SubjectAccount ERC-1271 | `executeMetaTransaction(m, sig)` (v1) or the named v2 function matching the op (`mtxTransfer`, `mtxPay`, `mtxUnwrap`, …; same digest, TW2 §7.1); direct function when signer = submitter | `balanceOf`, `metaNonce(from, batch)`, `payLane` (v2) / off-chain tag (v1), `eip712Domain`, `versionOf` | `eth_getLogs` for `MetaTransactionExecuted`, `PaymentSettled`, `Transfer`, `Wrapped`/`Unwrapped`, DEX `OrderFilled`/`Matched` | viem |
| **Hedera** | EVM + `hedera_kat.json` | ECDSA alias: as EVM (MetaMask on the JSON-RPC relay); ED25519 native `0.0.N`: raw ed25519 over the EIP-712 digest (HIP-632 `isAuthorizedRaw`, `connectors/hedera.js`) via the seed vault `hedera_ed25519` path | as EVM through the relay, signed by the gas-paying ECDSA account | as EVM; mirror node REST for `0.0.N` ⇄ EVM address, account token associations, HTS token info | as EVM (relay `eth_getLogs`), mirror node for tx status | viem + `fetch` |
| **Cosmos** | `fam_cosmos.py` (sorted-key JSON `MetaOp`, ADR-036 sign doc template with `chain_id: ""`, bech32 address from compressed key); KAT from `test_fam_cosmos.py` + mesh vectors (cosmos cross-language payload) | Keplr/Leap `signArbitrary` (ADR-036) or seed vault secp256k1 `m/44'/118'/0'/0/i` | `MsgExecuteContract{Relay{payload, auth}}` from the user's account (`signAndBroadcast`) | CW20 `Balance`, `QueryMsg::Nonce{owner, lane}` | tx search by contract + `wasm` events; `getTx` | cosmjs |
| **Soroban** (Stellar, Pi) | `fam_soroban.py` (`HashIdPreimage::SorobanAuthorization`, op digest `sha256(XDR(["scaas_metaop_v1", network_id, contract, fn, args]))`, ledger expiry without RPC per net-soroban §1.2) | Freighter `signAuthEntry`, or seed vault ed25519 `m/44'/148'/i'` (Pi: coin 314159) | the user's account is the transaction source: simulate (`prepareTransaction`), attach the signed auth entry, sign the envelope (Freighter `signTransaction` or seed), `sendTransaction` | SEP-41 `balance`; nonce = random `i64` (no read); the `G…` account must exist | `getEvents` (contract id, topics), `getTransaction` | stellar-sdk `rpc` + freighter-api |
| **Sui** | `fam_sui.py` (BCS `MetaOp`, `derive_address(registry, owner)` for `Account<T>`, personal-message intent `[3,0,0]`), mesh vectors (sui payload) | Wallet Standard `sui:signPersonalMessage(BCS(MetaOp))`; seed vault ed25519 `m/44'/784'/i'/0'/0'`; zkLogin/multisig accounts refused (as `connectors/sui.js`) | PTB `meta::relay_pay<T>` from the user's address, own gas coin (`signAndExecuteTransaction`) | `Account<T>` object (balance, lanes table via dynamic field read), owned `Coin<T>` for deposit | `queryEvents` by package event type, `getTransactionBlock` (checkpoint = final) | @mysten/sui |
| **Aptos** | `fam_aptos.py` (BCS `MetaOp`, `sha3_256` digest, `create_object_address(root, "acct" ‖ bcs(owner))`, `signMessage` `fullMessage` strict check, net-aptos §4.2) | Wallet Standard AIP-62 `aptos:signMessage` over `scaas.metaop.v1:0x<digest>`; seed vault ed25519 `m/44'/637'/i'/0'/0'` | entry `scaas::meta::relay_pay` from the user's account (`signAndSubmitTransaction`) | primary FA store of the Account object; lane view function | account transactions + events of the package type; `waitForTransaction` | ts-sdk 7.3.0 |
| **TON** | `fam_ton.py` (MetaOp cell tree, `0x75569022` envelope, app domain check), `ton-vectors.json` | TON Connect JS bridge `signData` type `cell`; seed vault ed25519 `m/44'/607'/i'` with the jetton wallet's bound pubkey (`BindKey`) | internal message `SignedOp` (opcode `0x5b0a1d01`) to the user's ScaasJettonWallet with `attachNanoton` from the user's wallet (`sendTransaction`) | jetton wallet get-methods (balance, pubkey, lanes) | toncenter v3 `transactions` by account; masterchain seqno = final | @ton/core, @ton/ton |
| **Solana** | `fam_solana.py` (336-byte `MetaOp`, `sha256` digest, text `"<domain>:" ‖ hex(digest)`, off-chain message v1, PDA seeds `["acct", owner]`, `["lane", account, lane]`) | Wallet Standard `solana:signOffchainMessage` (kind 1) else `solana:signMessage` (kind 0), checked as `connectors/solana.js`; seed vault ed25519 `m/44'/501'/i'/0'` (R155) | transaction with the Ed25519 precompile instruction + `relay_pay`, user as fee payer (`signAndSendTransaction`), recent blockhash (subject never signs the outer tx when relayed; here the user does, so blockhash expiry is just a retry) | SPL token accounts owned by the SubjectAccount PDA; `LanePda.next` | `getSignaturesForAddress` + `getTransaction` (commitment `finalized`) | @solana/kit 8.4.0 |

Two non-obvious rules:

- **Funds must sit where the meta-op can move them.** EVM/Hedera/Cosmos/Soroban/TON: the token balance itself (TON:
  the ScaasJettonWallet). Sui: inside `Account<T>` (owned coins are not spendable by a relayer; `deposit` by anyone).
  Aptos: the Account object's primary store. Solana: token accounts owned by the SubjectAccount PDA. The `deposit`
  module (Sui/Aptos/Solana) is a plain user-paid transfer into that place, shown as "fund your meta account".
- **Lane choice** is the client's: random 256-bit lane (EVM `batch`, others `lane`) per independent intent, nonce
  read from chain; `pay` uses `payLane(payId)` (TW2 §7.3, R139). Soroban has no lane (random host nonce).

### 5.3 EVM-chain specifics

| Chain | Specific | App behaviour |
|---|---|---|
| Gnosis 100 | gas in xDAI; finality `finalized` ~160–240 s | "final" badge waits for `finalized` block tag |
| Celo 42220 | CIP-64 exists, not used | self-paid uses CELO gas only |
| Private 9000 | base fee 0, Clique PoA 5 s, `private: true`; Zether excluded until owner gate Z3 | no public explorer links; RPC must send CORS for the app origin (deployment note) |
| anvil 31337 | `dev: true`; Zether allowed | dev key allowed (dev builds) |
| all | passkey verification cost depends on RIP-7212 (`0x100`) | show the gas estimate from `eth_estimateGas` before a self-paid passkey intent |

Hedera (in addition): relay JSON-RPC for calls; HTS tokens appear as long-zero addresses; the create wizard reads
`getTokenCustomFees`/`getTokenKey(FEE_SCHEDULE)` through the HTS precompile (`eth_call`) and warns as TW2 §11; unwrap
and transfer recipients are checked for token association on the mirror node and warned before signing (a missing
association reverts at step 8; R148 terminal error).

---

## 6. Signers

### 6.1 Interface (`src/signers/types.ts`)

```ts
type SignRequest =
  | { kind: 'eip712'; typedData: TypedData }                                   // EVM, Hedera ECDSA
  | { kind: 'digest'; digest: Uint8Array; scheme: 'secp256k1' | 'ed25519' }    // seed, Hedera ED25519
  | { kind: 'message'; bytes: Uint8Array;
      envelope: 'adr036' | 'sui-personal' | 'aptos-sign-message' | 'solana-offchain' | 'solana-raw'
              | 'ton-sign-data-cell' | 'soroban-auth-entry' };

interface Signer {
  kind: 'passkey' | 'seed' | 'extension' | 'dev';
  label: string; families: ReadonlySet<Family>;
  account(chain: ChainCfg): Promise<SignerAccount>;    // address, public key, scheme, origin (passkey)
  canSign(r: SignRequest): boolean;
  sign(r: SignRequest): Promise<Signature>;            // bytes + what the verifier needs (pubkey, fullMessage, …)
  sendTx?(chain: ChainCfg, tx: UnsignedTx): Promise<TxId>;   // absent for passkey (no gas key)
}
```

### 6.2 clientkeys signers

| Signer | Uses (existing exports) | Adds |
|---|---|---|
| Passkey (EVM) | `creationOptions`, `requestOptions`, `publicKeyFromSpki`, `encodeAssertion`, `passkeySubjectKey`, `accountSalt`, `predictAccount`, `accountSignature`, `merkleBatch` (one assertion for many digests), `checkOwnerCall` (add key / origin) | create flow: predict → deploy via `SubjectAccountFactory` self-paid (or by any funded wallet) → fund; PRF salt for vault unlock (`enablePrf`) |
| Seed vault | `generateEntropy`, `entropyToWords`, `wordsToEntropy`, `seedFromEntropy`, `deriveKey` (coinType override), `signDigest`, `createVault`, `openVault`, `rewrapPin`, `needsRewrap`, `checkPassphrase`, `SeedBackup` | family envelopes from `src/fam/*` (R154); `NETWORKS.solana`; `sendTx` for every family (the derived key holds gas when the user funds it) |
| Zether keys | `deriveConfKey`, `sealConfKey`, `openConfKey`, `zetherPop`, balance cache functions | — |

Vault storage: the encrypted vault blob in IndexedDB (encrypted at rest by scrypt `N = 2^17` + AES-GCM, optional
PRF); decrypted seed lives only inside the signer object, wiped (`wipe`) on lock, after 5 min idle, and on tab
hide > 5 min. Seed words are shown once at creation for writing down, are never copyable (no copy button, `user-select:
none`), and import is typed or pasted into a field that is cleared after parsing.

### 6.3 Extension wallets

| Family | Discovery | Calls |
|---|---|---|
| EVM, Hedera ECDSA | EIP-6963 (`eip6963:announceProvider`), remembered by `rdns` (as `chain_pay.js`) | `eth_requestAccounts`, `wallet_switchEthereumChain`/`wallet_addEthereumChain`, `eth_signTypedData_v4`, `eth_getCode` (EOA vs contract wallet), `eth_sendTransaction`; code 4001 = user rejection, not an error |
| Sui | Wallet Standard, feature `sui:signPersonalMessage`, `sui:signAndExecuteTransaction` | — |
| Aptos | Wallet Standard (AIP-62), `aptos:signMessage`, `aptos:signAndSubmitTransaction` | — |
| Solana | Wallet Standard, `solana:signOffchainMessage` / `solana:signMessage`, `solana:signAndSendTransaction` | — |
| Cosmos | `window.keplr` / `window.leap`: `enable(chainId)`, `getKey`, `signArbitrary`, `getOfflineSigner` | `experimentalSuggestChain` for localnets only (dev) |
| Soroban | `@stellar/freighter-api`: `requestAccess`, `getNetworkDetails` (passphrase must equal config), `signAuthEntry`, `signTransaction` | — |
| TON | injected JS bridge (`window[<key>].tonconnect`, list from `connectors/ton.js`) | `connect` with `ton_addr` + `ton_proof`, `signData` (`cell`), `sendTransaction` |

A wallet whose reported network differs from the selected chain is refused before signing (EVM `chainId`, Freighter
passphrase, Keplr chain id, Sui/Aptos/Solana chain feature string, TON `network`).

### 6.4 Dev key

`src/signers/dev.ts`: a raw secp256k1/ed25519 key typed into the settings screen (or the anvil default account),
memory only, EVM and localnet chains with `dev: true` only. Imported exclusively inside `if (import.meta.env.DEV)`
blocks (R166, §10.4).

---

## 7. Feature availability matrix

Legend: ✓ available in v1 · G gateway path (needs `gatewayNode` + R159 capability) · S self-paid only · — not
available (reason in the cell or below).

| Feature | EVM | Hedera | Cosmos | Soroban | Sui | Aptos | TON | Solana |
|---|---|---|---|---|---|---|---|---|
| Meta-op transfer / pay | G + S | S (no gateway, R156) | S | S | S | S | S | S |
| Fund meta account (`deposit`) | n/a (balance is the token) | n/a | n/a | n/a | ✓ `Account<T>` | ✓ Account store | n/a (jetton wallet) | ✓ PDA token account |
| Enable a coin type for meta-ops | — | — | — | — | ✓ `new_registry<T>` (anyone, once per T) | n/a (any FA) | — | n/a (any mint) |
| Create token, factory v1 (`META`, wrap or mint) | ✓ | ✓ (`HederaMetaToken` impl registered in that chain's factory; `Deploy.s.sol` registers only the EVM ones) | — PLANNED | — PLANNED | n/a | n/a | — PLANNED | n/a |
| Create tiered token, factory v2 (NONE/SINGLE/MULTI, fixed/adjustable, guardian, rateAdmin) | ✓ | ✓ (Hedera children, TW2 §11) | — (R145) | — | — | — | — | — |
| Wrap an existing token into a meta-tx token | ✓ (v1 `createMetaToken` with underlying, v2 `META_SINGLE`/`META_MULTI`) | ✓ (ERC-20 or HTS underlying) | — PLANNED | — PLANNED | ≈ enable coin type | n/a | — PLANNED (highest value, TW2 §12) | n/a |
| Wrap / unwrap / addReserve (direct) | ✓ | ✓ | — | — | — | — | — | — |
| Gasless unwrap `mtxUnwrap` | G + S | S | — | — | — | — | — | — |
| Rate admin / guardian (R169) | ✓ | ✓ | — | — | — | — | — | — |
| DEX book view, place, cancel, cancel-all | G (venue) ; on-chain cancel S | — (R172) | — (R172) | — | — | — | — | — |
| Zether | ✓ dev chains 31337/1337 only (R164) | — | — | — | — | — | — | — |
| Passkey signer | ✓ SubjectAccount | ✓ SubjectAccount on HSCS (net-hedera §3; OZ P-256 fallback without `0x100`) | — A16 | — A16 | — A16 | — A16 | — A16 | — A16 |
| Seed vault signer | ✓ | ✓ ECDSA + ED25519 | ✓ | ✓ (Pi coin 314159) | ✓ | ✓ | ✓ | ✓ (path added, R155) |
| Extension wallet | MetaMask & EIP-6963 | MetaMask on relay (ECDSA alias) | Keplr, Leap | Freighter | Sui Wallet Standard | Aptos AIP-62 | TON JS bridge | Solana Wallet Standard |
| Dev key (dev builds) | ✓ | ✓ (local node) | ✓ localnet | ✓ standalone | ✓ localnet | ✓ local | ✓ shim | ✓ test validator |

"Mesh" is invisible to the app: a gateway may route an intent to peers (A2), and Soroban is never on the mesh (R77).
`features` is narrowed at runtime: no `gatewayNode` ⇒ no `gateway`; `GET /v1/gateway` without the token ⇒ no
`gateway` for that token; no `dex` in config or capability ⇒ no `dex`.

---

## 8. Screens

### 8.1 Inventory and data flow

`R` = reads (source), `W` = writes (path), `Sig` = signer request.

| # | Screen (route) | R | W | Sig | Families |
|---|---|---|---|---|---|
| 1 | Home, chain picker, signer picker (`#/`) | `config.json`; signer accounts | — | — | all |
| 2 | Wallet (`#/w/:chain`) | native + token balances (RPC; curated tokens + factory provenance for EVM: `getWrapperCount/At`, `deployedFor`), recent normalized events (bounded range) | — | — | all |
| 3 | Send / Pay (`#/send/:chain/:token`) | token info, lane state, `GET /v1/gateway` (fee recipient, served) | gateway `POST /v1/metatx` or self-paid tx | `eip712` / `message` / `digest` | all (§7) |
| 4 | Intent status (`#/intent/:id`, in-memory) | nonce/lane read, receipt, events, `/v1/intents/{id}` when present | — | — | all |
| 5 | Accounts & keys (`#/accounts`) | SubjectAccount state (keys, origins), vault meta, connected extensions, Zether UA registration | create passkey account (self-paid deploy), add key/origin (owner call, `checkOwnerCall`), create/import/unlock/rewrap vault, enable PRF, backup | passkey assertion; seed | EVM passkey; seed all |
| 6 | Token catalogue (`#/tokens/:chain`) | factory `latestVersion`, `implementationOf`, `isDeprecated`, `versionOf(token)`, token views (`legOf`, `collateralValue`, `pendingRate`, `rateAdmin`, guardian), per-leg `balanceOf ≥ reserve` check (TW2 §8.4 alert) | add token to local list (per-viewer `localStorage`, convenience only) | — | EVM, Hedera (Sui registries, Aptos/Solana assets: read-only list) |
| 7 | Create token (`#/create/:chain`) | factory, implementation catalogue, `predictAddress`, underlying `decimals`, HTS checks (Hedera), existing wrappers of the same underlying (`deployCountFor`/`deployedFor`, shown first: "already wrapped by …") | `createMetaToken` / `createZetherToken` (dev chains, `zetherEnabled`) / `createTiered` self-paid | wallet tx | EVM, Hedera |
| 8 | Wrap / unwrap (`#/wrap/:chain/:token`) | `previewWrap`, `previewUnwrap`, `legOf`, allowance, pending rate (wrap paused) | `approve(wrapper)` (contract spender, R26) + `wrap`, `unwrap(…, minOut)`, `addReserve`; gasless: `mtxUnwrap` intent via gateway or self-paid | wallet tx; `eip712` for gasless | EVM, Hedera |
| 9 | Rate & guardian (`#/token/:chain/:token/admin`) | as 6 | guardian `disableWrap`/`renounceGuardian` direct; rate ops as calldata (R169) | wallet tx | EVM, Hedera |
| 10 | Sui coin type enable (`#/sui/:chain/enable`) | `Registry<T>` existence (derived id) | `new_registry<T>` self-paid | wallet tx | Sui |
| 11 | Fund meta account (`#/deposit/:chain/:asset`) | owned coins / FA / SPL balances | transfer into `Account<T>` / Account store / PDA ATA | wallet tx | Sui, Aptos, Solana |
| 12 | DEX markets (`#/dex/:chain`) | gateway `GET /v1/dex/markets` (+ `dex.relayer` from `/v1/gateway`), on-chain `markets(key)` cross-check | — | — | EVM |
| 13 | DEX market (`#/dex/:chain/:market`) | `depth` (poll 2 s visible / paused hidden), `trades`, `ticker`, `orders?maker=`; `depth?scope=network` + `/v1/dex/homes` when the node supports A2 G3 (feature-probed); trusted label, untrusted opt-in (R170) | place `POST /v1/dex/orders`; cancel `POST /v1/dex/cancel`; cancel-all `POST /v1/dex/cancel-all`; on-chain `cancel([…])`/`invalidateNonces` self-paid; unbound orders (`relayer = 0`, market `unbound`): "cancel final when mined" state | `eip712` (DEX domain) | EVM |
| 14 | Zether (`#/zether/:chain/:token`) | `registered(UA)`, account state (`acc`, `pending`, seqs, mode), cache, BSGS (worker) | register (`UniversalAccountRegistry.register`, self-paid only: the PoP binds `msg.sender`), `approve` + `fund(Y, amount)`, transfer (prove → `OP_ZTRANSFER` envelope via gateway, or direct `transferConfidential`), withdraw (`OP_ZBURN` / `burn`), `rollOverPublic` / `rollOverSigned` | Schnorr PoP (WASM), `eip712` envelope | EVM dev |
| 15 | Settings (`#/settings`) | — | locale, theme, dev key (DEV), per-chain RPC override (session only) | — | — |
| 16 | Console login (`#/admin/:node/login`) | `GET /v1/admin/auth-modes` | `POST /v1/admin/login` or OIDC redirect | — | — |
| 17 | Overview | `/v1/admin/info`, `/v1/admin/me`, `/readyz` (same-origin only) | — | — | — |
| 18 | Chains, Tokens, Lanes | `/v1/admin/chains[/{key}]`, `…/tokens`, `…/lanes` | `PATCH chains/{key}` (hot vs restart fields labelled, `pending_restart` banner), `PUT …/state`, `POST …/breaker/reset`, `PUT …/fee_recipient`, `POST/DELETE …/tokens`, `PUT …/lanes` (`409 LANE_BUSY` explained) | — | — |
| 19 | Namespaces, Jobs | `/v1/admin/namespaces`, `/v1/admin/jobs?namespace=&state=&chain=` | `POST/PATCH namespaces`, `POST jobs/{uid}/cancel` | — | — |
| 20 | Peers, Policy | `/v1/admin/mesh/peers`, `/v1/admin/mesh/policy` | CRUD; peer `url` validated client-side as the node does (`https://host[:port]`, no path/query/userinfo, pin 64 lowercase hex), `multiaddr` field (A2); `PUT …/state` | — | — |
| 21 | Gossip: Peers, Topics, Announces, Bans, Trusted | `/v1/admin/gossip`, `…/peers` (sortable by score), `…/announces`, `…/trusted`, metrics (R171) | ban/unban (operator), trusted `assign`/`dex` (admin) | — | — |
| 22 | DEX markets & homes | `/v1/admin/dex/markets`, `/v1/admin/dex/homes` | `POST/PATCH markets` (`gossip`, `unbound`), `PUT …/state` | — | — |
| 23 | API keys (external clients) | `/v1/admin/keys` | create (secret shown **once** in a dialog with explicit "I stored it", never cached, cleared on close), rotate, revoke — `key_custodian` | — | — |
| 24 | Users | `/v1/admin/users` | create / roles / disable / reset password (`key_custodian`, roles ⊆ caller), own password | — | — |
| 25 | Audit | `/v1/admin/audit?since=` | — | — | — |
| 26 | Metrics | `/metrics` (same-origin) or dashboard link (R171) | — | — | — |

### 8.2 Send / pay flow (all families)

1. Pick chain, token, recipient (`parseAddress`, lookalike check §10.6), amount (`AmountInput`, decimal string →
   `bigint` by `decimals`), optional `payId` (32 bytes; generated if empty).
2. Path: gateway (if `gateway` feature and `/v1/gateway` lists the token) or self-paid (pick the paying wallet).
3. `buildIntent`: reads lane state, sets `validUntil = now + 15 min` (R158), relayer binding: gateway path leaves
   `relayer = 0` unless the user pins the node's lane; fee `NONE` unless the user adds one (EVM: `FIXED`/`PERCENT`
   with `MODE_RESTRICT_FEE_RECIPIENT` and an explicit recipient — R132 refuses fee recipient = payee). When fee
   recipient is unbound, the review states that the node replaces it with its `fee_recipient` (R84,
   `metatx.rs:124-131`) and shows that address from `/v1/gateway`.
4. `SignReview` → signer → `verify` → submit → status screen (R157).

### 8.3 DEX specifics

- Order fields from DEX §1.1; `nonce = unix_ms·2^20 + random20`; `expiry` default 1 d, cap 30 d (`MAX_TTL_SECS`),
  floor 5 s; `maxFeePpm` defaults to the market's taker/maker fee; `flags` FOK/IOC exclusive; `relayer` = the
  venue's lane from `/v1/gateway` for home-bound markets (venue refuses others, `dex.rs:553`), `0` for unbound
  markets (A2 R124: resting GTC only, user acknowledges "anyone may execute within your limit; cancel binds only when
  mined").
- Funding check before signing: `checkOrder(o, sig)` after signing (status, `remaining`, `fundable`,
  `feeFundable`); `approve(dex)` offered if allowance is short (DEX is a contract spender).
- Prices: depth levels are decimal strings already scaled by the node (DEX review D16); the app never divides raw
  integers in floating point.
- Cancel signatures have no expiry (RS5-10) — the review says so.

### 8.4 Zether specifics

- Keys: `deriveConfKey(seed, {curve, coin, account})` once, sealed with `sealConfKey`; opened per session.
- Register: `SELF_SCHNORR` (default) or `SMART_ACCOUNT_1271` (passkey SubjectAccount) — `zetherPop` + auth PoP; the
  call is from the user's own account (not relayable).
- Prove in the worker: `zetherCall("proveTransfer", {curve, key: {x}, chainId, token, sendCounter, accSeq, acc,
  balance, yTo, amount, fee, beneficiary})` → `opData` for the envelope, or `directCalldata`; the worker posts
  progress and is terminated after each proof (no secret stays resident).
- Balance: `openBalanceCache` → `checkBalance` on current `acc` → else BSGS on the delta, then `setCachedBalance`;
  `cacheAfterDebit` / `cacheAfterRollOver` after own operations; banner when the device bound (2^44) is exceeded
  ("read on desktop with allowLargeTable or `zether-read-balance`").
- Every Zether screen carries "UNAUDITED — dev chains only" (SCaaS §8).

---

## 9. Node clients

### 9.1 Gateway (`src/node/gateway.ts`)

| Call | Body / query | Notes |
|---|---|---|
| `GET /v1/gateway` (R159a) | — | capability probe, cached 30 s; absent (404) ⇒ assume EVM chains in config served with unknown tokens: a `400 token not served` reply disables the gateway path for that token for the session |
| `POST /v1/metatx` | `{chain: <evm chain id number>, token, m: WireMetaTx (decimal strings, camelCase), signature: 0x…}` | `202 {"status":"queued"}`; `400 simulation: <reason>` shown decoded; `503` breaker/RPC ⇒ offer self-paid |
| `GET /v1/intents/{id}` | — | when the node returns `intent_id` (NI, SPECIFIED) |
| `POST /v1/dex/orders` | `{chain, order: WireOrder, signature}` | `202 {hash, status, fills[]}` |
| `POST /v1/dex/cancel` | `{chain, orderHash, signature}` | `202 cancelled` (book) + on-chain job |
| `POST /v1/dex/cancel-all` | `{chain, maker, minNonce, signature}` | — |
| `GET /v1/dex/{markets,depth,trades,ticker,orders}` | `chain`, `market`, `levels ≤ 200`, `maker` | polling only (no WebSocket, RS5-5) |
| `GET /v1/dex/depth?scope=network`, `GET /v1/dex/homes?chain&market` | — | A2 G3; feature-probed |

Requests: `fetch` with `credentials: "omit"`, `redirect: "error"`, 15 s timeout, JSON body ≤ 64 KiB (gateway cap).

### 9.2 Admin API (`src/node/admin.ts`)

Typed functions for every route of NI §7.3 and A2 §13.1; `Authorization: Bearer <token>`, `credentials: "omit"`,
`redirect: "error"`; errors `{error, detail}` mapped to i18n (§11); `401` ⇒ session dropped, back to login; `403
NO_ROLE|FORBIDDEN` ⇒ re-read `me`; `409 LANE_BUSY`/`CONFLICT`, `422 INVALID` shown inline on the form; `429` ⇒
backoff; `503 IDP_UNAVAILABLE` ⇒ banner. `X-Request-Id` from responses is shown in error details (support).

### 9.3 Built-in login

1. `GET /v1/admin/auth-modes` → `{builtin, oidc: [{issuer, client_id, audience}]}`.
2. `POST /v1/admin/login {name, password}` → `{token, expires_at, roles}`; password field cleared immediately.
3. Refresh `POST /v1/admin/session/refresh` at `expires_at − 60 s` while the tab is visible; refused (past
   `session_max_age_secs`) ⇒ login. Hidden tab ⇒ no refresh; on return, expired ⇒ login.
4. Logout `POST /v1/admin/logout` (bumps `session_epoch`: every session of that user ends — said in the UI), drop
   token, clear that node's Query cache.

### 9.4 OIDC (R163)

1. User picks an issuer from auth-modes. Discovery `GET {issuer}/.well-known/openid-configuration`; `issuer` must
   equal byte for byte; endpoints must be `https`.
2. Generate `code_verifier`, `state`, `nonce` (WebCrypto); store `{node, issuer, verifier, state, nonce, created}` in
   `sessionStorage` (R162); redirect to `authorization_endpoint` with `response_type=code`, `client_id`,
   `redirect_uri = <origin>/`, `scope=openid` (+ `offline_access` only if the IdP advertises refresh for public
   clients), `code_challenge_method=S256`, `state`, `nonce`, and the audience the node expects (`audience` or RFC 8707
   `resource`, whichever discovery/IdP config supports; configured per issuer by the node's `audience`).
3. Callback on `/?code=&state=`: match `state`, exchange the code at `token_endpoint` (PKCE), validate the ID token
   `nonce`/`iss`/`aud = client_id`, keep the **access token** for the node (the node validates it, NI §7.1), remove
   the `sessionStorage` entry, `history.replaceState` to strip the query, then `GET /v1/admin/me`.
4. Renewal per R163; logout: `end_session_endpoint` with `id_token_hint` and `post_logout_redirect_uri = <origin>/`.

Redirect URIs to register at the IdP: the exact origin(s) where the app is served, trailing `/` included.

### 9.5 Several nodes

Sessions are keyed by node id; the console header shows the node and the caller (`me`). A token for node A is never
sent to node B (the client is constructed per node with its own base URL).

---

## 10. Security

### 10.1 CSP and headers

Node-served (`scaas-node` sets them on every app response, R159c):

```
Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self';
  img-src 'self' data:; font-src 'self'; connect-src 'self' <origins of every chains[].rpc, chains[].rest,
  chains[].mirror, nodes[].gateway, nodes[].admin> <origins of [api.oidc.issuers] and [app] extra_connect_src>;
  worker-src 'self'; manifest-src 'self'; frame-src 'none'; frame-ancestors 'none'; form-action 'none';
  base-uri 'none'; object-src 'none'; require-trusted-types-for 'script'
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), clipboard-read=(),
  publickey-credentials-get=(self), publickey-credentials-create=(self)
```

Static: `index.html` meta CSP = the same with `connect-src 'self' https: wss:` (dev builds add
`http://localhost:* http://127.0.0.1:*`) and without `frame-ancestors` (ignored in meta); `npm run csp` writes
`dist/_headers` (Netlify/Cloudflare format) and an nginx snippet with the exact header from `config.json`.
`'wasm-unsafe-eval'` is needed only by the Zether WASM; no `unsafe-eval`, no `unsafe-inline`. Trusted Types:
`dangerouslySetInnerHTML` is banned by lint; a dependency that violates TT is replaced, or the directive is removed by
a ruling.

### 10.2 No secrets in the bundle

- No R92 key, gateway secret, RPC provider key, OIDC client secret, or dev key in source, env (`VITE_*`) or
  `config.json` (R152, §4.3). CI greps `dist/` for 64-hex strings outside known public constants (typehashes, KAT-free
  build), `scaas_s1.`, `X-Scaas-Key`, and the anvil default private keys.
- Admin tokens: memory only (R162); never logged; `Authorization` stripped from error reports.

### 10.3 Supply chain (R166)

Allowlist = §3.2. `npm ci --ignore-scripts`; packages that need install scripts are refused (none in the allowlist
needs one). `npm audit signatures` and `npm audit --omit=dev --audit-level=high` in CI. Lockfile changes only in PRs
titled `deps:`. Licences: MIT/Apache-2.0/BSD/ISC/LGPL (clientkeys) only (`license-checker` is not added — a 20-line
`scripts/licenses.mjs` reads `package-lock.json`). Shadcn components are source copies, reviewed like our code.

### 10.4 Dev-key and test-code gating

`dev.ts`, fake wallets and the mock IdP/node are imported only under `import.meta.env.DEV`; the production build sets
`define: { __SCAAS_DEV__: false }` and CI asserts `dist/` contains neither the marker string `scaas-dev-signer` nor
any anvil default key. At runtime the dev signer refuses chains without `dev: true` (R155).

### 10.5 Signing review (R158)

Rendered from `Intent.display`, identical layout for every family and signer:

| Row | Content |
|---|---|
| Network | chain label + `chain_key`; mismatch with the wallet's network blocks |
| Contract | token/DEX name from chain reads, address (checksummed / canonical), "deployed by factory X v N" or "configured" |
| Operation | `transfer`, `pay(payId)`, `trade`, `approve` (spender must be a contract), `unwrap(underlying → recipient, minOut)`, DEX order (sell/buy amounts, limit price both ways, expiry), cancel |
| From → To | address views (§10.6), recipient kind (EOA / contract / unknown) |
| Amount, fee | decimal from `bigint` with symbol; fee mode, fee, fee recipient (bound, or "relayer's: <addr>" R84) |
| Validity | `validUntil` local time + relative; > 1 h warns; > 24 h needs an extra confirmation |
| Relayer binding | bound lane / any relayer |
| Raw | collapsible: EIP-712 JSON / hex bytes / digest — exactly what the signer receives |

Warnings block signing until acknowledged: unknown contract (dev builds only), fee ≥ 1 % of amount, recipient is the
token contract itself, lookalike recipient (§10.6), DEX price ≥ 5 % away from the best opposite level, untrusted DEX
home, Multi token with a leg under-reserved (TW2 §8.4).

### 10.6 Clipboard and phishing

- Addresses are displayed in groups with the first 6 and last 6 characters emphasized and a deterministic colour
  badge; full value on demand.
- Lookalike check: a recipient that shares the first 4 and last 4 characters with an address from the user's history
  or address book but differs ⇒ blocking warning (address poisoning).
- The app never reads the clipboard by itself (`clipboard-read=()`); paste is a user action into a field. Copying an
  address shows what was copied; copying secrets is impossible (seed words) or one-shot (API key secret, cleared from
  memory when the dialog closes).
- External links (explorers) use `rel="noopener noreferrer"`; no URL from chain data or node responses is rendered as
  a link except configured explorers and trusted DEX home gateways (R170).

### 10.7 URL guard (`src/lib/url.ts`, R170)

One function used by every `fetch`: allowed origin set = config origins ∪ discovered OIDC endpoints of listed issuers ∪
trusted DEX home gateways; `https:` only (dev: localhost); no userinfo; `redirect: "error"`. Peer URLs typed in the
console are validated, never fetched by the browser (the node dials them).

---

## 11. i18n

- `src/locales/{en,vi}/{common,wallet,tokens,dex,zether,admin,errors}.json`; English bundled, Vietnamese loaded on
  demand (dynamic import). `i18next` with `fallbackLng: "en"`, no language detector library: initial language =
  per-viewer saved choice (`localStorage`, convenience) else `config.defaultLocale` else `en`.
- Keys are stable identifiers (`wallet.send.reviewTitle`), never English sentences. Plurals via i18next `_one/_other`
  (Vietnamese uses `_other` only).
- `errors.node.<CODE>` for node errors (`UNAUTHORIZED`, `NO_ROLE`, `FORBIDDEN`, `CONFLICT`, `LANE_BUSY`, `INVALID`,
  `IDP_UNAVAILABLE`, …), `errors.chain.<family>.<name>` for decoded contract errors (EVM custom errors from the ABI,
  e.g. `FeeRecipientIsPayee`, `WrapPausedForRateChange`, `UnwrapBelowMin`), `errors.wallet.rejected` for user
  rejection.
- Numbers, amounts, dates: `Intl.NumberFormat`/`DateTimeFormat` with the active locale on strings produced from
  `bigint`; on-chain values never pass through `Number`.
- `scripts/i18n-check.mjs` (CI): same key set in both languages, no unused keys, no hard-coded JSX text (lint rule).
- Disclosures (R167): `tokens.disclosure.depeg`, `tokens.disclosure.adjustableMulti`, `zether.unaudited` — English
  text from TW2 §8.4/§8.5 verbatim; the Vietnamese version is shown with the English original until approved (Q3).

---

## 12. Testing

### 12.1 Unit (Vitest, no network)

| Area | Vectors / method |
|---|---|
| EVM encoders (clientkeys + app) | `smartcontracts/evm/test/vectors/metatx_kat.json`, `metatx_v2_kat.json` (named functions ≡ generic), `dex_kat.json`, `hedera_kat.json`, `wrap_rate_vectors.json` (previews), `subject_account_create2.json`, `webauthn_soft.json` |
| Non-EVM encoders (clientkeys `src/fam/*`, `node --test`) | `scaas-node/tests/vectors/mesh-envelope-v1.2.json` cross-language payloads (Aptos, Cosmos, Solana, Sui, TON), `smartcontracts/ton/vectors/ton-vectors.json`; Soroban and the rest of `test_fam_*.py` vectors exported once into `clientkeys/test/vectors/fam_*.json` by stream A0 (Python generates, both languages assert) |
| Zether | `zether-prover/vectors/*` through the WASM `nodejs` build (as `smoke.cjs`) and clientkeys `zether.test.js` |
| Config | valid/invalid fixtures for every refusal in §4.3 |
| Auth | built-in refresh timing; OIDC state/nonce/PKCE against `mock-idp.mjs`; nothing written to storage except §R162 entries (spy on `Storage.prototype`) |
| Roles | route × role table from NI §7.3 + A2 §13.1 → visible actions |
| Amounts | decimal ⇄ `bigint` round trips at 0, 1, 2^54, 2^64, 2^256−1, every `decimals` 0–36 |
| Adapter contract suite | §5.1, run per family |

### 12.2 End-to-end (Playwright, Chromium)

| Suite | Runs against | Covers |
|---|---|---|
| `evm` | anvil + `deploy.sh evm` + `scaas-node` (gateway, EVM chain, DEX venue on one lane) | send/pay via gateway and self-paid, v2 create (three tiers), wrap/unwrap, `mtxUnwrap`, DEX place/cancel/fill between two browser contexts, passkey account (CDP virtual authenticator), seed vault create/unlock, EIP-6963 fake wallet |
| `zether` | anvil + Zether deploy (dev) | register, fund, transfer, rollOver, burn, cache/BSGS |
| `console` | `e2e/fixtures/mock-node.mjs` (NI §7.3/A2 §13.1 routes, fixtures, role checks) + `mock-idp.mjs` | built-in login/refresh/logout, OIDC code+PKCE, role hiding, key secret shown once, peer URL validation, 409/422 handling; real node once P2/P2b land |
| `cosmos` | `wasmd` container (as the node e2e) | Keplr fake (window.keplr over seed), Relay self-paid |
| `soroban` | `stellar/quickstart --local` | Freighter fake, auth entry, self-paid |
| `sui` | `sui start --localnet` | Wallet Standard fake, deposit, relay_pay |
| `aptos` | `smartcontracts/scripts/devnet.sh aptos` | AIP-62 fake, relay_pay |
| `ton` | `smartcontracts/ton` shim (`npm run shim`) | JS-bridge fake, SignedOp |
| `solana` | `devnet.sh solana` (test validator) | Wallet Standard fake, offchain message, relay_pay |
| `node-served` | `scaas-node` with `[app]` | headers/CSP exact, same-origin console, `/metrics` screen |

Fake wallets live in `e2e/fixtures/wallets.ts` and implement each discovery protocol over clientkeys seed keys;
they are never in `src/`. Each localnet suite runs alone (one heavy process at a time on this box), under
`scripts/capped`. CI runs unit + `evm` + `console` on every PR; the other suites nightly or on `app/src/families/<f>`
changes.

### 12.3 Accessibility and i18n checks

Playwright `@axe-core/playwright` is **not** added; keyboard-only walkthrough of send, review and login in the `evm`
suite, and Radix primitives for focus management. Both locales rendered in one snapshot run per screen (text overflow).

---

## 13. Build and deploy

### 13.1 Static SPA

`npm ci --ignore-scripts && npm run build` → `dist/` (`index.html`, `assets/*-[hash].*`, `zether_prover_bg-[hash]
.wasm`, `config.example.json`). The operator adds `config.json` next to `index.html` and serves with the headers from
`npm run csp -- config.json`. Hash routing (R151) ⇒ no rewrite rules. `config.json` must be served `Cache-Control:
no-store`; hashed assets `public, max-age=31536000, immutable`; `index.html` `no-cache`.

### 13.2 Served by `scaas-node` (R159c, R160)

```toml
[app]
enabled = false                          # true ⇒ admin listener serves the app
dir = "/opt/scaas/app"                   # a built dist/ (index.html + assets/); must not be writable by the service user
config = "/etc/scaas/app-config.json"    # served at /config.json; validated at start (JSON, version, https URLs)
extra_connect_src = []                   # exact origins added to CSP connect-src (e.g. an IdP token endpoint on another host)
```

Routes on the admin listener (in addition to NI §7.3): `GET|HEAD /` and `/index.html` → `dir/index.html` (`no-cache`);
`GET|HEAD /assets/{file}` → `dir/assets/{file}` (`immutable`; only `[A-Za-z0-9._-]+`, no `..`, no directories,
content type by extension, `.wasm` = `application/wasm`); `GET /config.json` → `config` file (`no-store`); every other
non-`/v1/`, non-health path → `404`. Headers §10.1 on every app response; `connect-src` computed once at start from
the served `config.json` plus `[api.oidc.issuers]` and `extra_connect_src`; a changed `config.json` needs a restart
(`pending_restart` in `/v1/admin/info`). `config.json` `nodes[].admin = "self"` resolves to `location.origin`.
`Config::validate` refuses `enabled = true` with a missing `dir/index.html`. Implementation: `tower-http` `ServeDir`
(feature `fs`; the crate is already a direct dep for CORS) wrapped by a header layer. Metrics:
`scaas_app_requests_total{path_class}`.

### 13.3 CI job `app` (`.github/workflows/ci.yml`, paths `app/**`, `clientkeys/**`)

`npm ci --ignore-scripts` (clientkeys, app) → `node --test` (clientkeys) → `tsc --noEmit` → `eslint` → `vitest run`
→ `vite build` → `scripts/budget.mjs` → `scripts/i18n-check.mjs` → dist secret/dev-marker grep (§10.2, §10.4) →
`abi.mjs` diff → Playwright `evm` + `console`. Heavy steps (build, Playwright) never run in parallel with the node's
`cargo` jobs on the self-hosted box (one heavy build at a time).

---

## 14. Performance budget

Gzip sizes, enforced by `scripts/budget.mjs` against `budget.json` (CI fails above; the numbers ratchet down to the
measured size + 10 % after stream A15):

| Chunk | Budget | Loaded when |
|---|---|---|
| Shell (React, router, Query, i18n + EN strings, UI kit, config, EVM-free wallet frame) | ≤ 200 kB | first paint |
| EVM adapter (viem subset, ABIs, clientkeys `evm`) | ≤ 90 kB | first EVM/Hedera chain selected |
| Hedera overrides | ≤ 15 kB | Hedera chain selected |
| Cosmos, Sui, Aptos, TON, Solana adapters | ≤ 250 kB each | that family selected |
| Soroban adapter (stellar-sdk `rpc` + XDR) | ≤ 400 kB | Soroban selected |
| Seed vault (clientkeys seed + scrypt) | ≤ 60 kB | vault opened |
| Passkey | ≤ 30 kB | passkey chosen |
| Console | ≤ 120 kB | `#/admin/*` |
| Vietnamese strings | ≤ 40 kB | locale `vi` |
| Zether worker + WASM | ≤ 1.2 MB (WASM, measured at A6 and ratcheted) | Zether screen |

Runtime targets on a mid-range phone over 4G: shell interactive ≤ 3 s; adapter switch ≤ 1.5 s; DEX depth poll ≤ 1
request / 2 s per visible market, paused when hidden; BSGS 2^22 table built once per session in the worker (~1.5 s
desktop, limits §4) and dropped with the worker. Family SDKs are imported only through `families/registry.ts`
dynamic imports, so Rollup cannot hoist them into the shell (checked by the budget script).

---

## 15. Work breakdown

One agent at a time; at most one heavy npm build or localnet at a time on this box (`scripts/capped`). Each stream
ends with its gate green and a short note in `TODO.md`.

| Stream | Content | Depends on | Gate |
|---|---|---|---|
| **A0** clientkeys families | `src/fam/{cosmos,soroban,sui,aptos,ton,solana,hedera}.js` ported from `fam_*.py`; `NETWORKS.solana`; DEX + v2 helpers in `evm.js`; vectors exported to `clientkeys/test/vectors/fam_*.json`; `zether-prover` `--target web` build script | — | `node --test` (clientkeys), Python vector export reproducible |
| **A1** skeleton | Vite/React/TS/Tailwind/shadcn, theme, router, i18n (EN/VI scaffolding), config loader/validator, store, URL guard, budget/csp/i18n/abi scripts, meta CSP, CI job `app` | A0 | unit + build + budget |
| **A2** EVM core | EVM adapter, EIP-6963 + seed + dev signers, wallet, send/pay (gateway + self-paid + direct), SignReview, intent status | A1 | Playwright `evm` (send/pay) |
| **N1** node | `GET /v1/gateway`, `gateway_cors_origins`, `[app]` serving + CSP (scaas-node; `cargo test`, clippy) | — (any time before A2's gateway e2e; fits with P2) | `cargo test` + `node-served` e2e |
| **A3** accounts | passkey SubjectAccount (create, add key/origin, sign, Merkle batch), vault UI (create/import/backup/rewrap/PRF) | A2 | `evm` passkey + vault |
| **A4** tokens | catalogue, factory v1/v2 wizard (tiers, rates, guardian, disclosures), wrap/unwrap/addReserve, `mtxUnwrap`, rate calldata, guardian, Hedera overrides + adapter | A2 | `evm` tokens; Hedera unit (KAT, mirror mocks) |
| **A5** DEX | markets, depth/trades/ticker, my orders, place/cancel/cancel-all, on-chain cancel, unbound orders, network scope/homes (probed) | A2, N1 | `evm` DEX two-context |
| **A6** Zether | worker, WASM web build, register/fund/balance/transfer/burn/rollOver, cache | A3 (vault) | `zether` |
| **A7** console core | admin client, built-in auth, OIDC (`oauth4webapi`), roles, overview, chains/tokens/lanes, namespaces, jobs, keys, users, audit; mock node + mock IdP | A1 (real node: P2 built-in, P2b OIDC) | `console` |
| **A8** console mesh | peers, policy, gossip screens, DEX markets/homes, metrics | A7 (real node: P2b + A2 G1–G3) | `console` |
| **A9** Cosmos | adapter, Keplr/Leap, seed, self-paid | A2 | `cosmos` |
| **A10** Soroban | adapter (Stellar + Pi), Freighter, seed | A2 | `soroban` |
| **A11** Sui | adapter, Wallet Standard, enable coin type, deposit | A2 | `sui` |
| **A12** Aptos | adapter, AIP-62, deposit | A2 | `aptos` |
| **A13** TON | adapter, JS bridge, BindKey status, SignedOp | A2 | `ton` |
| **A14** Solana | adapter, Wallet Standard, deposit | A2 | `solana` |
| **A15** release | Vietnamese completion, keyboard pass, budget ratchet, `app/README` (deploy both modes, IdP redirect URIs, CSP), SCaaS.md/integration.md status updates | all above | full CI + nightly suites once |
| **A16** non-EVM passkeys (later) | P-256 envelopes per family in clientkeys (`open_passkey`, custom accounts) | A9–A14 | per-family e2e |

Order for one agent: A0 → A1 → A2 → N1 → A3 → A4 → A5 → A6 → A7 → A9 → A10 → A11 → A12 → A13 → A14 → A8 → A15. A7/A8
real-node e2e wait for the node streams (P2, P2b, G3 per TODO.md); until then they run against the mock node.

---

## 16. Open questions (owner)

| # | Question | Default if unanswered |
|---|---|---|
| Q1 | **Relayed submission for non-EVM and Hedera.** The gateway serves only the EVM family (`main.rs`); MESH §15.3 defers a non-EVM door A (`POST /v1/ops`). Schedule a door A for Hedera and the six non-EVM families in the node streams, so app users without native gas can be relayed? | Self-paid only for those families (R156); the adapter interface already has `submitGateway?`. |
| Q2 | **Non-EVM DEX.** The contracts exist on all families, but no node book/venue does. Schedule a per-family settlement adapter for the venue (DEX §5), or keep DEX EVM-only? | EVM-only (R172). |
| Q3 | **Who approves the Vietnamese risk disclosures** (TW2 §8.4/§8.5, Zether unaudited)? | Vietnamese shown with the English original beside it (R167). |

---

## 17. Doc corrections required by this spec (listed, not made)

- `docs/SCaaS.md` §3.3 and §12.1 mention admin keys `scaas_ak1.`; NI rev 3.2 has none (§1.2).
- `docs/SCaaS.md` §3.1 `app/` row and `docs/integration.md` §14: point to this spec; "EVM + meta-tx families first"
  (SCaaS §15.1 row 21) is superseded by "all seven families" (owner 2026-10-06).
- NI §7.4/§7.7: add the gateway CORS allowlist and `GET /v1/gateway` (R159), and the `[app]` block (§13.2).
- `clientkeys` description in SCaaS §3.1: "EVM-centric" becomes "all families" after A0.
- `zether-prover/wasm-smoke.sh`: add the `--target web` build used by the app (A0).
