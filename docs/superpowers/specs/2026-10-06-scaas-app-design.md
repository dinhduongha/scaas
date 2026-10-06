# SCaaS app (`scaas/app/`) — console and dApp (design)

Status: draft **rev 1.2**, 2026-10-06. Rev 1.1 folded in the owner's answers to Q1–Q3 (§16). Rev 1.2 does three
things: it applies independent review 1 (FIX-THEN-GO, H1–H7, M1–M9, L1–L7; disposition in §18), folds in spec D
(signers follow-ups, R250–R268) and spec F (Universal Account, R290–R318), and writes the node addendum (§9.6:
`/v1/ops`, `/v1/gateway`, error contract, gasless UA registration).

Code at `scaas` `main` 9737ef3: TW2 T1–T6/T8 built, node store P1 built; the job API, admin API and admin auth are
SPECIFIED but not built; nothing of D or F is built.

Rulings: **R150–R179** (§2). R180–R199 are spec B, R200–R217 spec A, R230–R247 spec C, R250–R268 spec D,
R270–R289 spec E, R290–R318 spec F.

Owner decisions of 2026-10-06 are folded in: purpose, all seven families in v1, signers, no Odoo, Tailwind +
shadcn, EN + VI, static + node-served, `/v1/ops`, non-EVM DEX later, Vietnamese disclosures shown beside the
English, and the UA tree purpose `7622'`.

Requirements this spec satisfies:

| Short | File | Section |
|---|---|---|
| NI | `specs/2026-10-06-node-independence-design.md` | §7.1 (API keys server-side only), §7.3, §7.4, §7.7, §9.1 (door A journaled), §14 T21–T24 |
| A2 | `specs/2026-10-06-mesh-gossip-amendment.md` | R124, R127, R128, §11.5, §13 |
| TW2 | `specs/2026-10-06-token-wrappers-v2.md` | §4–§9, §8.4/§8.5 (disclosures), §11, §12 |
| DEX | `specs/2026-10-03-dex-design.md` | §1.1, §1.3, §3.5, §5 |
| Z | `2026-10-03-zether-design.md`, `2026-10-05-zether-limits.md` | flows, BSGS limits, device balance cache |
| D | `specs/2026-10-06-signers-followups.md` | R250–R268: backup switch, vault v2, seed/passkey signers, `wallets/*`, streams D1–D7 |
| F | `specs/2026-10-06-universal-account-design.md` | R290–R318: UA kinds, registry, MetaToken v3 `ua*`, `UAKey.signUA`, `m/7622'` tree, §11.3 app touchpoints |
| AS | `specs/2026-10-06-asset-suite-design.md` | R201/§3.9 (regulated-token notice), §8.1 (managed markets), §9.3 |
| TSS | `specs/2026-10-06-tender-sponsorship-shredding.md` | R192 (`mtxPayReceiverFee` as a new implementation version) |
| SCaaS / INT | `docs/SCaaS.md`, `docs/integration.md` | SCaaS §7, §8, §12, §14; INT §13, §14 |

Code read for facts:
- `scaas-node/src/{gateway.rs,gwauth.rs,dex.rs,dex/venue.rs,metatx.rs,main.rs,config.rs,abi.rs}`
- `clientkeys/src/*`
- `zether-prover/src/{wasm.rs,api.rs}`
- `smartcontracts/evm/{src,script}/**`
- `smartcontracts/ton/shim/server.ts`
- parent repo `dms_blockchain/lib/fam_*.py` and `models/blockchain_relay_job.py` (`_payload`), and
  `dms_blockchain_bridge/static/src/js/**`

Odoo serves only as a reference here; the app never depends on it.

---

## 1. Scope and non-goals

### 1.1 In scope

One React + Vite single-page app with two halves.

**dApp** (no login):
- accounts: the UA default, `SubjectAccount` option (b), the seed vault, extension wallets;
- balances and the token catalogue;
- token creation (factory v1 and v2), and wrapping an existing token into a meta-tx token;
- wrap/unwrap, including gasless `mtxUnwrap`;
- meta-tx transfers and payments, submitted through a node gateway (all seven families) or self-paid;
- the DEX order book (home-bound and relayer-unbound markets) with place/cancel;
- Zether: register, deposit/shield, confidential transfer, withdraw, and balance via the device cache + BSGS.

**Console** (login to one node's admin API, built-in users or OIDC): chains, tokens, lanes, namespaces, jobs, mesh
peers (SSRF-guarded), policy, gossip (peers, topics, announces, bans, trusted), DEX markets and homes,
external-client API keys, admin users, audit, and a metrics dashboard link.

**Families.** All seven sit behind one adapter interface:
- EVM: Gnosis 100, Celo 42220, private chain 9000, anvil 31337;
- Hedera 295–298 (EVM on HSCS, plus the HTS specifics);
- Cosmos (CosmWasm);
- Soroban (Stellar and Pi);
- Aptos;
- Sui;
- TON;
- Solana.

**Deployment.** Two modes from one build: a static SPA with a runtime `config.json`, or served by `scaas-node` on
its admin listener. English (default) and Vietnamese; dark and light themes.

### 1.2 Non-goals

| Not in this spec | Why / where instead |
|---|---|
| Any Odoo call | NI R87 |
| A backend of its own; the job API (`/v1/jobs`, `/v1/events`) | R109/T23: an R92 key would sit in the bundle |
| Admin API keys (`scaas_ak1.`) | NI rev 3.2 has none (SCaaS.md still mentions them, §17) |
| Mandates, tender bidding, vesting, distributions, VC/eKYC presentation, `msig` "Approvers" wizard beyond F3's minimum | Their own specs; the app shows them only where §7 says so |
| Regulated (`*_REG`, token kinds 5–7) send/receive/DEX flows and managed DEX markets | View-only with the AS §3.9 notice until stream AS8-app (R177) |
| Zether disclosure openings | Not requested; the prover already exposes them |
| Non-EVM token deployment and non-EVM wrappers | TW2 R145 PLANNED; Move/Solana need none |
| Cosmos and TON passkeys | D R264: not this round |
| TON Connect HTTP bridge, WalletConnect | D §1.2 / ADW R21 seam |
| HashPack/Blade | `hedera_signMessage` prefixes the message; HIP-632 needs raw ED25519 (net-hedera R6-4) |
| Celo CIP-64 fee currencies | SCaaS §7.1 |
| Offline/PWA, analytics, remote fonts, a Prometheus parser | R166, R171 |

---

## 2. Rulings

Format: **ruling — why — cost if wrong.**

| # | Ruling | Why | Cost if wrong |
|---|---|---|---|
| **R150** | **One SPA, two halves, one build.** dApp routes never require login. Console routes need a node session and live in a separate lazy chunk. Both deployment modes serve the identical `dist/`. | NI §7.7: chain features work without login. One artefact to test and pin. | — |
| **R151** | **Stack:** React 19 + TypeScript strict + Vite. **TanStack Query** handles every remote read. There is **no global state library**: a ~50-line `useSyncExternalStore` store holds the in-memory sessions, the active signer and the selected chain. Routing is **react-router 7 with hash routes** (`#/…`). | Server state dominates. Hash routing removes SPA-fallback rules from every host and from the node. | Deep links look like `/#/…`. |
| **R152** | **No server of its own.** The app talks to chain RPCs directly, and to `scaas-node` only for (a) the gateway and (b) the admin API. It never holds an R92 key, a gateway `bearer`/`hmac` secret, or an RPC provider key; the §4.3 validator refuses them. A gateway configured `bearer`/`hmac` is unusable from the app. | NI R109, T23. | Public gateways run with auth `none` behind a host proxy with rate limits (SCaaS §3.5). |
| **R153** | **Family adapters:** one interface (§5.1), seven implementations. `hedera` is the EVM adapter plus Hedera overrides. An adapter loads lazily on first use of its family, and its `features` set drives every screen (§7). | Owner: all seven at once; family SDKs are most of the bytes. | — |
| **R154** | **The app builds every byte it asks anyone to sign, and the review is decoded from those bytes.** Encoders live in **clientkeys `src/fam/<family>.js`**, with D §7.2's single interface (`checkTerms`, `signingInput`, `packSignature`) plus `decode(signingInput)`. They are ported from `fam_*.py` and KAT-locked. An adapter's intent is the family **terms**. The review renders `decode(signingInput(terms))`, and the app asserts that `checkTerms(terms, shown)` holds against what the user entered (M7, D R267). Never accepted from a node or any remote party: a payload, a digest, typed data. | Display and bytes cannot diverge silently. One JS implementation is shared with the portal (D R266/R267). | clientkeys grows to all families (D streams). |
| **R155** | **Signers:** clientkeys passkey; the seed vault (vault v2 in the key worker, R175); the UA keys `UAKey` (`deriveUAKey` / `signUA`, F R298/R300, tree `m/7622'/0'/<account>'/<kindNo>'/<i>'`); extension wallets through **clientkeys `src/wallets/<family>.js`** and `wallets/evm.js` (D R266, `win` injected); and a dev key in dev builds only. The seed signer signs only D R263 envelopes: Solana OCMS kind 1, **never** `solana-raw`, which is extension-only. Native keys keep their family paths; EVM `m/44'/60'/0'/0/i` is the EOA only (F R300). | D and F. One wallet-glue implementation. One key, one purpose. | — |
| **R156** | **Two submission paths.** (1) **Gateway**, all seven families. EVM and Hedera use `POST /v1/metatx` (Hedera added by N2 with 64-byte HIP-632 signatures allowed). The six non-EVM families use `POST /v1/ops` (N2, §9.6). v3 UA intents use `POST /v1/ua-metatx` (N4, §9.6). Every one is journaled as a `~gateway` job (NI §9.1) and run by that chain's lanes. (2) **Self-paid**: a gas-holding account the user controls submits the same call a lane would. When signer and submitter are the same EVM EOA, the app calls the direct function (`transfer`, `payWithFee`, `unwrap`) with no meta-tx signature. | Owner Q1. With gateway submission, a user needs no native gas on any family. | Until N2, Hedera and non-EVM are self-paid only. |
| **R157** | **Intent status = chain truth.** A `202` means "accepted by relayer". *Done* = the nonce is consumed (`metaNonce` / `uaNonce` / the family lane read), plus `PaymentSettled` / `MetaTransactionExecuted` / `UAMetaTransactionExecuted` when present. *Expired* = `validUntil` has passed with the nonce unconsumed. `GET /v1/intents/{id}` is used when the node returns an id. | The node is trusted for liveness, not truth (SCaaS §3.5). | One read per poll. |
| **R158** | **Signing review** (§10.5): rendered from the decoded bytes (R154). Metadata is pinned or cross-checked (R173), the spender is allowlisted (R174), and strings are sanitised (R179). The signature is verified locally before sending. Default validity windows: transfers, pay and unwrap ≤ 15 min; DEX orders ≤ 30 d. Digest-only envelopes (Aptos, Solana OCMS, TON cell, Hedera ED25519) also show "your wallet will display: `scaas.metaop.v1:0xABCD…1234`" and "approve SCaaS messages only on `<origin>`". | Extension wallets show hex for most families; the app's review is the only real check. | Non-curated tokens take an explicit-add step. |
| **R159** | **Node additions** (stream N1, §9.6): `GET /v1/gateway` (served chains, tokens, fee recipient, DEX address, relayer and order policy); `[modules] gateway_cors_origins`; the stable error contract (R178); `[app]` serving + CSP on the admin listener. | Without them the client cannot sign a bound DEX order, show the fee recipient, or reach the gateway cross-origin. | ~300 lines of Rust. |
| **R160** | **Node-served mode** serves the app only on the **admin listener**, never on the gateway, job-API or mesh listeners. `nodes[].admin = "self"`. | Same origin removes admin CORS; the job API stays browser-unreachable. | The admin listener needs TLS in front unless reached on `localhost` (M1). |
| **R161** | **Static mode** reads `./config.json` (same origin, `no-store`), validates it (§4.3), and refuses to start on error. `config.json` integrity = host integrity: the hostile third parties are the RPCs and gateways (R173), so `config.json` is not signed and same-origin assets carry no SRI. `npm run csp` writes exact headers for the page **and the workers**. A boot-time frame check (§10.1) stands in for `frame-ancestors` when headers are missing. | One build, every host. | A host without headers runs the weaker meta CSP. |
| **R162** | **Admin tokens in memory only**, per node. `sessionStorage` holds only the OIDC `{issuer, code_verifier, state, nonce, returnRoute}` between redirect and callback, deleted on callback or after 10 min. After a reload: re-login (built-in) or `prompt=none` (OIDC). Logout clears that node's Query cache. | NI §7.7. | Built-in users retype the password after a reload. |
| **R163** | **OIDC = `oauth4webapi`**: public client, code + PKCE S256, `state` + `nonce`, RFC 9207 `iss` check. **Allowed issuers = `auth-modes` ∩ `config.json` `nodes[].oidc`**, so a hostile node cannot redirect users to an arbitrary IdP. `redirect_uri = origin + pathname`. Renewal by refresh-token rotation or full-page `prompt=none`; no iframes. | No hand-rolled OAuth (L1). | IdPs without SPA refresh tokens bounce the page once per token lifetime. |
| **R164** | **Zether in one session worker** that runs `zether-prover` (`wasm-bindgen --target web`). The worker opens the conf vault itself (`openConfKey`), so `x` never enters the main realm (H3). It keeps `x` and the BSGS table for the session and is terminated on lock, after 5 min idle or 5 min hidden. Defaults: `tableBits 22, boundBits 44`; `allowLargeTable` only by explicit choice. Zether shows only on chains 31337/1337 with a configured ZetherToken. | R33; L5. | — |
| **R165** | **Passkeys are origin-bound.** `config.json` sets `passkey.rpId`. A second deployment origin needs an added key for that origin. Backup counting de-duplicates credentials by `(x, y)` across origins: "1 passkey, 2 origins" counts as **one** key (H4; D R251 amended, §6.3). A **find-my-account** flow (§6.4) recovers the account on a new device or origin. | Two deployment modes are two origins. | One extra flow. |
| **R166** | **Supply chain:** exact pins, committed lockfile, `npm ci --ignore-scripts`, a **direct and transitive** allowlist (§10.3: lockfile diff + package-count gate), no runtime CDN, no analytics. **One dev flag** (`import.meta.env.DEV`). A dev build refuses to start unless `location.hostname ∈ {localhost, 127.0.0.1, ::1}` and shows a permanent banner. CI fails if production `dist/` contains dev markers. | Every dependency has signing reach. | Upgrades are deliberate. |
| **R167** | **i18n:** react-i18next, English default, Vietnamese for every string. Each stream writes its VI strings (the CI parity check, §11); A15 is the review pass. Risk disclosures show the English original beside the Vietnamese until the owner approves (owner Q3). Amounts are `bigint`-based. | Owner. | — |
| **R168** | **Role gating is UI only**: `viewer ⊂ operator ⊂ admin`, with `key_custodian` separate, read from `GET /v1/admin/me`. Grants are ⊆ the caller's roles. | NI R107. | — |
| **R169** | **Contract-held roles get calldata, not transactions.** `rateAdmin` must be a contract (TW2 §5.1), so rate operations are emitted as **Safe Transaction Builder JSON** (`{to, value: "0", data}`) or `MultiSig.sol` submit data, never as an EIP-681 link (an EOA sender reverts). The guardian acts directly. | L2g; AS §9.3 also builds Safe transactions. | — |
| **R170** | **The app dials only allowlisted origins** (§10.7): `config.json` URLs and the pinned OIDC origins. DEX homes learned from `/v1/dex/homes` are **never** dialed; network depth is read from the own node (`depth?scope=network`), and orders are placed only on own-node markets (L2a). The guard is installed globally at boot over `fetch`, `XMLHttpRequest` and `WebSocket` (H7). | Network-learned URLs are attacker-chosen; SDKs issue their own requests. | — |
| **R171** | **Metrics = a dashboard link** (`metricsDashboardUrl`). Topics show mesh size and peers from `GET /v1/admin/gossip`. No Prometheus parsing (L2b). | `/metrics` is not CORS-enabled; the ops spec has the dashboard. | — |
| **R172** | **Non-EVM DEX is "unavailable" until node stream N3** (owner Q2: after EVM). The DEX module is generic over `/v1/dex/*` and turns on per chain when `/v1/gateway` reports `dex`. | Only the EVM venue has a book. | — |
| **R173** | **Chain identity and metadata are verified, not trusted** (H1). (a) Once per RPC at adapter load, the chain identity is checked (§5.3); a mismatch refuses the chain. (b) Curated tokens pin `decimals` and `symbol` in config; a chain answer that differs refuses the token. Non-curated tokens show the raw integer beside the decimal, need explicit add, and are refused when `decimals > 36`. (c) `eip712Domain()` must return the config `chainId` and `verifyingContract` = the token signed for. (d) With ≥ 2 RPCs configured, security-critical reads are cross-checked on two of them: decimals, code presence, factory provenance, wrapper `legOf`. (e) There is no RPC override in production builds. | A third-party RPC can forge every read. | One extra call per token and chain. |
| **R174** | **`approve` spender allowlist** (H2). The spender is either the chain's config `contracts.dex` (OrderBookDex), or a wrapper being wrapped into, after `underlyings()` contains the token and the wrapper is curated or has factory provenance cross-checked per R173(d). Anything else is refused, with no override outside dev builds. The amount is exactly what the operation needs, never `2^256−1`. The token page offers "revoke" (approve 0). | R26 stops EOA spenders only; any attacker can deploy a contract. | — |
| **R175** | **Keys run in a dedicated key worker** (H3): a module Worker that imports clientkeys only. Its API is `unlock(pin | prf)`, `account(family, role, i)` (public data only), `sign(request)` (bytes the main thread built and checked, plus the D R263 envelope name), `signUA(purpose, digest)` and `lock()`. Seed, entropy and private keys never cross `postMessage`. The vault v2 store (D §5.2), idle timer (5 min), hide timer (5 min) and scrypt allocation all live in the worker. The Zether worker follows the same rule (R164). | A compromised transitive dependency in any SDK chunk could otherwise read an unlocked seed. | A hostile main realm can still request signatures while unlocked (D §5.3, residual). |
| **R176** | **Account model = spec F.** The default "Create account" makes a **`webauthn-p256` UA** and registers it gaslessly through the gateway (`POST /v1/ua/register`, N4; F R295 makes `register` relayable). "Recoverable account" makes a `SubjectAccount` (option (b), F R307). UA balances exist only on **MetaToken v3** clones (F R308); a UA user offered a v1/v2 token is told to use v3 or option (b). With `policy.requireBackupKey` ON, a single-key derived UA is **unsatisfiable** (D R253): the default flow becomes `SubjectAccount` + backup step, and an existing single-key UA is exit-only. An `msig` UA counts as backed up iff `Σweights − max(weight) ≥ threshold` (proposed row for D `backup_policy.json`). Until F1/F2/F3/N4 land, the default is `SubjectAccount` (interim). | Owner ruling in F; D's predicate. | Two account kinds to explain; §6.2 texts. |
| **R177** | **Token kinds are decoded from `versionOf(token)`**, values 0–7 (AS adds `*_REG` = 5–7). Kinds 5–7 are **view-only** with the AS §3.9 notice until stream AS8-app; managed DEX markets are "unavailable" the same way. Named functions are chosen from a `(kind, implementation version)` table, falling back to `executeMetaTransaction` (TW2 R138) for unknown versions, which includes TSS R192's `mtxPayReceiverFee` versions. `termsHash` documents link only to config-listed URLs. | M5. | — |
| **R178** | **The gateway error contract is stable** (N1): `{error, code, detail, revert_data?}` with codes `UNKNOWN_CHAIN`, `TOKEN_NOT_SERVED`, `BREAKER_OPEN`, `SUBMIT_BUSY`, `EXPIRED`, `BAD_SIGNATURE`, `BAD_PAYLOAD`, `RELAYER_NOT_OURS`, `SIMULATION_REVERT` (raw `0x…` revert data), `RPC_UNAVAILABLE`, `QUOTA`, the same on `/v1/dex/*`, `/v1/ops` and `/v1/ua/*`. The app decodes revert data with its own ABI and maps `errors.node.<code>`; no logic keys on free text. | M3: today's `{"error": "<text>"}` and Rust `Debug` reverts. | — |
| **R179** | **Untrusted text** (M8): every string from chain or network passes through `untrustedText(s, max)`. Sources: token `name`/`symbol`, revert strings, gossip peer fields, audit before/after, peer labels. The function applies NFKC, strips Cc/Cf (bidi controls included), caps length (symbol 16, name 64, other 256), and flags non-ASCII. Curated labels win. Non-curated tokens carry an "unverified" badge, and a symbol equal to a curated one on the same chain warns. Provenance reads "created via the open factory (anyone can)" vs "curated by this deployment". | Open factory: anyone can deploy "USDC". | — |

---

## 3. Architecture

### 3.1 Picture

```
 ┌───────────────────────────────── browser (one origin) ─────────────────────────────────────┐
 │ boot: URL guard (fetch/XHR/WebSocket) → frame check → config load + validate → React       │
 │ shell ─ router(#) ─ Query cache ─ store (sessions, signer, chain; memory)                   │
 │   dApp screens ── family registry ── lazy adapter chunk (SDK + clientkeys fam/* + wallets/*) │
 │   console (lazy) ── admin client ── auth (builtin | OIDC)                                   │
 │   key worker (clientkeys only: vault v2, seed, UAKey)   zether worker (prover WASM + conf)  │
 └────┼───────────────────────────────┼──────────────────────────────────┼─────────────────────┘
      │ RPC (identity-checked)         │ /v1/gateway /v1/metatx /v1/ops    │ Bearer /v1/admin/*
      ▼                                ▼ /v1/ua/* /v1/dex/*               ▼
   chain RPCs (config)          scaas-node gateway (CORS, N1)          admin listener (+ app files)
```

### 3.2 Libraries (direct allowlist, R166)

| Purpose | Package | Note |
|---|---|---|
| UI | `react`, `react-dom` 19; `tailwindcss` 4 + `@tailwindcss/vite`; shadcn/ui copied into `src/ui/` with `@radix-ui/*`, `class-variance-authority`, `clsx`, `tailwind-merge`, `lucide-react` | — |
| Build/test (dev) | `vite`, `@vitejs/plugin-react`, `typescript`, `vitest`, `@playwright/test`, `eslint`, `typescript-eslint` | — |
| Data, routing, i18n, OIDC | `@tanstack/react-query` 5, `react-router` 7, `i18next`, `react-i18next`, `oauth4webapi` | — |
| Keys and encoders | `@scaas/clientkeys` = `file:../clientkeys` (`@noble/*`/`@scure/*` 2.4.0) | `fam/*`, `wallets/*`, `ua.js`, `device.js`, `backup-policy.js` |
| EVM, Hedera | `viem` 2.x | its own `@noble` 1.x copy is accepted and counted in the spike (M9) |
| Cosmos | `cosmjs-types` + clientkeys secp256k1 (preferred); `@cosmjs/*` only if the A9 vet shows no `libsodium`/`elliptic` | M9 |
| Soroban | `@stellar/stellar-base` (XDR, auth entries) + `fetch` JSON-RPC; `@stellar/freighter-api` 6.0.1 | no Horizon client |
| Sui | `@mysten/sui` (`bcs`, `Transaction`, client with a guarded `fetch`) | — |
| Aptos | `@aptos-labs/ts-sdk` 7.3.0 (`AptosConfig({client})` guarded) | as `smartcontracts/move/aptos/scripts` |
| TON | `@ton/core` 0.63.1 + `fetch` against toncenter **v3** (the shim speaks v3) | `@ton/ton` dropped: its client is v2 (M9) |
| Solana | `@solana/kit` 8.4.0, HTTP transport only, no subscriptions | as `smartcontracts/solana/scripts` |
| Polyfill | `buffer` (feross), imported **only** inside the Soroban and TON adapter chunks (`globalThis.Buffer ??= Buffer` there) | `stellar-base` and `@ton/core` need it |

Versions without a pin are fixed in `package-lock.json` by the A1 spike and recorded in `app/README`.

### 3.3 Package layout (`scaas/app/`)

```
app/
  package.json  package-lock.json  .npmrc (save-exact, ignore-scripts)  tsconfig.json  vite.config.ts  index.html
  budget.json (from the A1 spike)  deps-allowlist.json (direct + transitive)  public/config.example.json
  scripts/ csp.mjs  budget.mjs  abi.mjs  i18n-check.mjs  licenses.mjs  config-from-deployments.mjs  deps-gate.mjs
  src/
    boot.ts (URL guard, frame check, config)  main.tsx  routes.tsx
    config/ schema.ts  load.ts
    lib/ store.ts  amount.ts  url-guard.ts  text.ts (untrustedText)  errors.ts  trusted-types.ts
    ui/ shadcn copies, theme.tsx, AddressView.tsx, SignReview.tsx, AmountInput.tsx
    locales/ en/*.json  vi/*.json
    families/ types.ts  registry.ts  features.ts  identity.ts  tokens.ts (R173/R177 tables)
              evm/ (adapter, abi.ts generated, factory, wrap, dex, zether, ua)  hedera/  cosmos/  soroban/  sui/  aptos/  ton/  solana/
    signers/ types.ts  keyworker.ts (client)  keyworker.worker.ts  passkey.ts  extension.ts (wraps clientkeys wallets/*)  dev.ts
    node/ gateway.ts  admin.ts  auth/{builtin,oidc}.ts  roles.ts
    zether/ zether.worker.ts  client.ts
    features/ wallet send accounts tokens create wrap dex zether settings  admin/{overview,chains,tokens,lanes,namespaces,jobs,peers,policy,gossip,markets,keys,users,audit}
  e2e/ playwright.config.ts  fixtures/{mock-node.mjs,mock-idp.mjs,cors-forward.ts}  specs/*.spec.ts
```

Fake wallets are not duplicated: e2e injects clientkeys `test/wallets/*` (moved there by D5) with `addInitScript`
(L2f).

`src/families/evm/abi.ts` is generated by `scripts/abi.mjs` from forge `out/` for these contracts:
- `IOpenFactory`, `IOpenFactoryV2`, `IERC20MetaTx`, `IERC20Payment`, `IMetaTokenV2`;
- the tier contracts (and v3 once F2 lands);
- `OrderBookDex`, `SubjectAccount(Factory)`, `IZetherToken`, `IUARegistry` (F1).

The file is committed, and CI regenerates and diffs it.

---

## 4. `config.json`

### 4.1 Schema

```jsonc
{
  "version": 1,
  "defaultLocale": "en",
  "policy": { "requireBackupKey": false },                    // D R250; boolean, default false
  "passkey": { "rpId": "app.example.com" },                  // R165
  "metricsDashboardUrl": "https://grafana.example.com/d/scaas",
  "documents": [ { "termsHash": "0x…", "url": "https://…" } ],   // R177: the only linkable terms
  "nodes": [
    { "id": "main", "label": "Main node",
      "gateway": "https://gw.example.com",                    // auth none behind a proxy (R152)
      "admin": "https://node.example.com",                    // or "self" (node-served)
      "oidc": [ { "issuer": "https://auth.example.com",
                  "connectSrc": ["https://auth.example.com"] } ] }   // R163: allowed issuers ∩ auth-modes
  ],
  "chains": [
    { "key": "evm:100", "family": "evm", "label": "Gnosis", "rpc": ["https://a…", "https://b…"],
      "explorer": "https://gnosisscan.io", "native": { "symbol": "xDAI", "decimals": 18 },
      "dev": false, "private": false, "gatewayNode": "main",
      "contracts": { "factoryV1": "0x…", "factoryV2": "0x…", "dex": "0x…",           // dex = OrderBookDex
                     "subjectAccountFactory": "0x…", "uaRegistry": null },
      "tokens": [ { "address": "0x…", "symbol": "EUR-M", "decimals": 6, "label": "Euro meta" } ],  // pinned (R173)
      "zetherTokens": [] },
    { "key": "hedera:296", "family": "hedera", "rpc": ["https://testnet.hashio.io/api"],
      "mirror": "https://testnet.mirrornode.hedera.com" },
    { "key": "cosmos:scaas-1", "family": "cosmos", "rpc": ["https://rpc…"], "rest": "https://lcd…",
      "bech32Prefix": "wasm", "gasPrice": "0.025uscaas", "contracts": { "token": ["wasm1…"] } },
    { "key": "soroban:testnet", "family": "soroban", "rpc": ["https://soroban-testnet.stellar.org"],
      "networkPassphrase": "Test SDF Network ; September 2015", "coinType": null },     // Pi: 314159
    { "key": "sui:testnet", "family": "sui", "rpc": ["https://fullnode.testnet.sui.io"],
      "contracts": { "package": "0x…", "root": "0x…", "registries": [ { "coinType": "0x2::sui::SUI", "id": "0x…" } ] } },
    { "key": "aptos:2", "family": "aptos", "rpc": ["https://api.testnet.aptoslabs.com/v1"], "contracts": { "package": "0x…" } },
    { "key": "ton:-3", "family": "ton", "rpc": ["https://testnet.toncenter.com/api/v3"], "appDomain": "app.example.com",
      "attachNanoton": "150000000", "contracts": { "masters": ["0:…"] } },
    { "key": "solana:<genesis>", "family": "solana", "rpc": ["https://api.devnet.solana.com"],
      "contracts": { "program": "…", "mints": ["…"] } }
  ]
}
```

Notes:
- `key` is the node's `chain_key` (`config.rs:746`).
- Non-EVM curated tokens and assets carry `symbol`/`decimals` the same way.
- A chain without `gatewayNode` has the self-paid path only.

### 4.2 Generation

`npm run config:from-deployments -- <rpc>` reads `smartcontracts/evm/deployments/<chainid>.json` and maps:

| Deployment key | Config field |
|---|---|
| `order_book_dex` | `contracts.dex` |
| `factory` | `contracts.factoryV1` |
| `factory_v2` | `contracts.factoryV2` |
| `subject_account_factory` | `contracts.subjectAccountFactory` |

The deployment's `dex` key is `MetaTxDex`, a different contract, and is not mapped (M6). Other families are written
by hand.

### 4.3 Validation (`src/config/schema.ts`, no library)

The app refuses to start, with an EN + VI error screen, on any of these:

- **Structure.** Unknown `version`; duplicate `key` or `id`; an unknown family; `policy.requireBackupKey` not
  boolean.
- **URLs.**
  - Each must be `https:`. Two exceptions: dev builds allow `http://localhost|127.0.0.1|[::1]`, and
    `"self"`/`location.origin` may be `http:` only when the page itself is `http:` on those hosts (M1).
  - No userinfo.
  - **RPC secrets (L7):** a query string; a path segment matching `/(api[-_]?key|token|secret|auth)/i`; any path
    segment of ≥ 20 characters from `[A-Za-z0-9_-]` (Infura `/v3/<hex>`, Alchemy `/v2/<key>`); any subdomain label
    of ≥ 20 characters (QuickNode).
- **Chains and tokens.**
  - `dev: true` on a non-dev chain (an id outside 31337/1337, or a network outside `localnet`/`standalone`/`local`).
  - `zetherTokens` on a non-dev chain.
  - A curated token without `decimals`, or with `decimals > 36`.
- **Passkeys.** `passkey.rpId` must be a registrable suffix of `location.hostname`; `localhost` is accepted only
  when the hostname is `localhost`, and `127.0.0.1` never (M1).
- **Nodes.** `gatewayNode` naming a node without `gateway`; `nodes[].oidc[].issuer` not `https`.

Unknown fields warn.

---

## 5. Family adapters

### 5.1 Interface (`src/families/types.ts`)

```ts
type Family = 'evm' | 'hedera' | 'cosmos' | 'soroban' | 'sui' | 'aptos' | 'ton' | 'solana';
type Feature = 'metaPay' | 'gateway' | 'selfPaid' | 'deposit' | 'factoryV1' | 'factoryV2' | 'wrap' | 'mtxUnwrap'
  | 'dex' | 'zether' | 'passkey' | 'enableCoinType' | 'uaLedger' | 'uaRegister';

interface FamilyAdapter {
  family: Family; chain: ChainCfg; features: ReadonlySet<Feature>;     // §7, narrowed by config + /v1/gateway
  verifyIdentity(): Promise<void>;                                     // R173(a), §5.3; throws ⇒ chain refused
  parseAddress(s: string): Address; shortAddress(a: Address): string; explorer(kind, id): string | null;
  subjectAccount(owner: SignerAccount, token?: TokenRef): Promise<{ address: Address; exists: boolean }>;
  nativeBalance(a: Address): Promise<bigint>;
  token(t: TokenRef): Promise<TokenInfo>;               // R173 pinned/cross-checked; R177 kind; R179 text
  tokenBalance(t: TokenRef, holder: Address): Promise<bigint>;
  laneState(t: TokenRef, from: Address, lane: bigint): Promise<bigint | null>;   // null = random (Soroban)
  buildTerms(p: IntentParams): Promise<Terms>;          // family terms, as the portal's start returns them (D R267)
  signRequest(t: Terms, key: SignerAccount): SignRequest;      // = clientkeys fam.signingInput + envelope name
  decode(r: SignRequest): DecodedIntent;                // review source (R154)
  pack(t: Terms, key: SignerAccount, sig: Uint8Array): Packed; // = fam.packSignature
  verify(t: Terms, p: Packed): Promise<boolean>;        // local check before sending
  submitGateway?(node: NodeCfg, t: Terms, p: Packed): Promise<{ intentId?: string }>;   // /v1/metatx | /v1/ops
  buildSelfPaid(t: Terms, p: Packed, payer: SignerAccount): Promise<UnsignedTx>;
  send(tx: UnsignedTx, by: Signer): Promise<TxId>;
  intentStatus(t: Terms): Promise<'pending' | 'done' | 'expired'>;
  waitTx(id: TxId): Promise<Receipt>;  events(f: EventFilter): Promise<NormalizedEvent[]>;   // HTTP polling only
  factory?: FactoryModule; wrap?: WrapModule; dex?: DexModule; zether?: ZetherModule; deposit?: DepositModule; ua?: UAModule;
}
```

The contract suite (`families/contract.test.ts`, run per family) checks:
- the KAT bytes and digests;
- address round trips;
- `checkTerms(buildTerms(p), shownOf(p))` passes, and fails when any single field differs;
- **`decode(signRequest(buildTerms(p))) == p`** (M7);
- `verify` is true on the vector signature and false on a flipped byte;
- `buildSelfPaid` decodes back to the terms.

Every adapter receives transports wired to the guarded `fetch` (R170).

### 5.2 Per-family plan

| Family | Encoders (clientkeys `fam/`, stream) | Subject signs | Gateway | Self-paid | Reads | Events / status |
|---|---|---|---|---|---|---|
| **EVM** | `evm.js` + DEX `Order`/`CancelOrder`/`InvalidateNonces`, v2 calldata, `payLane`; v3 `UAMetaTransaction` (F2/F3); KAT `metatx_kat`, `metatx_v2_kat`, `dex_kat`, `vectors/ua/*` (A0-evm) | EIP-712 (`eip712Domain()` checked, R173c); EOA, ERC-1271 SubjectAccount, or `UAKey.signUA("metatx", digest)` for a UA | `/v1/metatx`; `/v1/ua-metatx` (N4) | `executeMetaTransaction` / named `mtx*` / `ua*`; direct function when signer = submitter | `balanceOf`, `balanceOfUA`, `metaNonce`, `uaNonce`, `payLane`, `versionOf` | `eth_getLogs` (bounded) |
| **Hedera** | EVM + `hedera_kat` | ECDSA alias via extension; ED25519 `0.0.N` raw over the digest via seed (`hedera_ed25519`) | `/v1/metatx` (N2: 64-byte sigs allowed) | as EVM via the relay | as EVM; mirror for `0.0.N` ⇄ address, associations, HTS info | relay logs; mirror tx |
| **Cosmos** | `fam/cosmos.js` (A0-cosmos) | ADR-036 via Keplr/Leap or seed `m/44'/118'/0'/0/i` | `/v1/ops` | `MsgExecuteContract{Relay}` signed + broadcast by the user | CW20 `Balance`, `Nonce{owner, lane}` | tx search; `getTx` |
| **Soroban** | `fam/soroban.js` (A0-soroban, D4) | Freighter `signAuthEntry`, or seed `m/44'/148'/i'` (Pi coin 314159): sha256 of the auth preimage (`G…`) / `Ed25519{key_id, sig}` (`C…`) | `/v1/ops` | user = tx source: simulate, attach auth, sign envelope hash (via `buildSelfPaid` only, D §7.2) | SEP-41 `balance`; random nonce | `getEvents`, `getTransaction` |
| **Sui** | `fam/sui.js` incl. KeyOp (D R261) (A0-sui) | `sui:signPersonalMessage`; seed `m/44'/784'/i'/0'/0'`; passkey flag 6 (A16) | `/v1/ops` | PTB `meta::relay_pay<T>` | `Account<T>` fields, owned coins | `queryEvents`, checkpoint final |
| **Aptos** | `fam/aptos.js` (A0-aptos, D4) | AIP-62 `aptos:signMessage`; seed `m/44'/637'/i'/0'/0'` over the client-built `fullMessage` | `/v1/ops` | entry `scaas::meta::relay_pay` | primary store, lane view | account txs; `waitForTransaction` |
| **TON** | `fam/ton.js`, `ton-vectors.json` (A0-ton) | TON JS bridge `signData` cell; seed `m/44'/607'/i'` with bound pubkey | `/v1/ops` | `SignedOp` internal message + `attachNanoton` | jetton wallet get-methods (v3 `runGetMethod`) | v3 `transactions` |
| **Solana** | `fam/solana.js`, `solana_derivation.json` (A0-solana, D4) | `solana:signOffchainMessage` (kind 1), else `solana:signMessage` (kind 0, **extension only**); seed: OCMS kind 1 only (D R263) | `/v1/ops` | Ed25519 precompile ix + `relay_pay`, user as fee payer | PDA token accounts, `LanePda.next` | `getSignaturesForAddress` + `getTransaction` (`finalized`), polling |

Two rules:
- **Where the funds must sit.**
  - The token balance itself: EVM, Hedera, Cosmos, Soroban, and TON (in the ScaasJettonWallet).
  - Sui: the `Account<T>`. Aptos: the Account object's store. Solana: the PDA's token accounts. The `deposit`
    module moves funds there with a plain user-paid transfer.
  - EVM UA balances live in the v3 UA ledger, funded by `transferToUA`.
- **Lanes.** Each independent intent gets a random 256-bit lane. `pay` uses `payLane(payId)`. Soroban uses a random
  host nonce instead.

### 5.3 Chain identity (R173a), checked once per RPC

| Family | Call | Must equal |
|---|---|---|
| EVM, Hedera | `eth_chainId` | id in `key` |
| Sui | `sui_getChainIdentifier` | configured `chainIdentifier` (from `key` network: mainnet/testnet/devnet known values; localnet: first-run pinned in dev only) |
| Solana | `getGenesisHash` | `<genesis>` in `key` |
| Soroban | `getNetwork().passphrase` | `networkPassphrase` |
| Aptos | ledger info `chain_id` | id in `key` |
| Cosmos | `status.node_info.network` | chain id in `key` |
| TON | v3 `masterchainInfo` + config param global id | `-239` / `-3` |

### 5.4 EVM-chain specifics

| Chain | Specific | App behaviour |
|---|---|---|
| Gnosis 100 | `finalized` ~160–240 s | final badge waits for the `finalized` tag |
| Celo 42220 | CIP-64 not used | CELO gas only |
| Private 9000 | base fee 0, `private: true`; Zether gated (Z3) | no public explorer links; the RPC must send CORS for the app origin |
| anvil 31337 | `dev: true` | dev key in dev builds; Zether |
| all | RIP-7212 presence affects passkey/UA P-256 cost | gas estimate shown before a self-paid passkey intent |

**Hedera.**
- The create wizard reads `getTokenCustomFees` / `getTokenKey(FEE_SCHEDULE)` through the HTS precompile and warns
  (TW2 §11).
- Recipients of unwrap and transfer are checked for HTS association on the mirror node, with a warning before
  signing.
- Factory v1/v2 on Hedera needs the Hedera implementations registered in that chain's factory; `Deploy.s.sol`
  registers only the EVM ones.

---

## 6. Signers and accounts

### 6.1 Interface (`src/signers/types.ts`)

```ts
type SignRequest =
  | { kind: 'eip712'; typedData: TypedData }
  | { kind: 'digest'; digest: Uint8Array; scheme: 'secp256k1' | 'ed25519' }     // native keys only
  | { kind: 'ua'; purpose: UAPurpose; digest: Uint8Array; uaKind: number }      // UAKey.signUA (F R301)
  | { kind: 'message'; bytes: Uint8Array; envelope: 'adr036' | 'sui-personal' | 'aptos-sign-message'
        | 'solana-offchain' | 'solana-raw' | 'ton-sign-data-cell' | 'soroban-auth-entry' | 'soroban-c-payload' };

interface Signer {
  kind: 'passkey' | 'seed' | 'ua' | 'extension' | 'dev';
  label: string; families: ReadonlySet<Family>;
  account(chain: ChainCfg): Promise<SignerAccount>;   // address/UA id, pubkey, scheme, origin, key role
  canSign(r: SignRequest): boolean;                   // seed: false for 'solana-raw' (R155, D R263)
  sign(r: SignRequest): Promise<Uint8Array>;
  sendTx?(chain: ChainCfg, tx: UnsignedTx): Promise<TxId>;
}
```

### 6.2 Account kinds offered (R176)

| Offer | Made of | Families (v1) | Backup (D R251/R253, switch ON) |
|---|---|---|---|
| **Account** (default, after F1–F3/N4) | `webauthn-p256` UA, registered gaslessly | EVM, Hedera (v3 tokens) | single-key ⇒ unsatisfiable ⇒ not offered; existing ⇒ exit only |
| **Recoverable account** (option (b); interim default) | `SubjectAccount` (passkey and/or secp256k1 role key `m/7622'/0'/<account>'/2'/<i>'`, guardian) | EVM, Hedera | ≥ 2 distinct credentials or 1 + guardian |
| Subject accounts per family | Sui `Account<T>`, Aptos Account, Solana PDA, Soroban `C…`, TON jetton wallet (keys per D §4.5) | as §7 | per D §4.5 (Soroban/TON: ≥ 2 keys) |
| **Approvers** (minimal) | `msig` UA over member UAs/EOAs (F §4.2); the app shows the id and registers it | EVM | `Σw − max(w) ≥ threshold` |
| Native wallet | seed-vault native key or extension wallet | all | outside the predicate |
| Zether account | `zether-*` UA, `authRef` chosen from the user's accounts (F R305) | EVM dev | n/a |

The accounts screen shows, per account:
- the kind and the key role (F §8.1, layer 4);
- the bound origin(s) for passkeys;
- BE/BS labels (D R254): "this device only" or "may share one password manager";
- the backup state from `backupStatus` (D §4.3).

### 6.3 clientkeys use

| Need | clientkeys (existing → added by D/F) |
|---|---|
| Passkey ceremony | `creationOptions`, `requestOptions`, `publicKeyFromSpki`, `derToRS`, `encodeAssertion`, `passkeySubjectKey`, `accountSalt`, `predictAccount`, `accountSignature`, `merkleBatch`, `checkOwnerCall`, `passkeyFlags` (D1) |
| Backup | `hasBackup`, `backupStatus` (D1). **Amendment (H4):** keys are de-duplicated by P-256 `(x, y)` across `rpIdHash`/`originHash` before counting; `keys[]` carries `x, y`; D's `backup_policy.json` gains the rows "same passkey, two origins ⇒ 1 key" and the `msig` rule of R176 |
| Seed vault | `createVault`, `openVault`, `rewrapPin`, `needsRewrap`, `checkPassphrase`, `SeedBackup`, `deriveKey`, `signDigest` (native only), `signFamily` (D4); v2: `openStore`, `deviceKey`, `sealDevice`, `openDevice`, `needsBinding` (D2) |
| UA | `ua.js`: `uaOf`, `keyHashOf`, `uaMessage`, `popDigest`, `deriveUAKey`, `UAKey.signUA`, `UAMetaTransaction` typed data (F0/F3) |
| Zether | `deriveConfKey` (uses 7/8 only, F), `sealConfKey`, `openConfKey`, the new tagged `zetherPop` (F1), balance cache |
| Wallets | `wallets/<family>.js`, `wallets/evm.js` (EIP-6963 + `walletKind`), `wallet-signer.js` entry (D5) |

**Vault v2 in the key worker** (D §5, R175):
- Storage: IndexedDB `scaas-clientkeys`, store `kv`. Keys: `device-key:v1`, `vault:seed:<account label>`, and
  `vault:zether-conf:<curve>:<coin>:<account>`.
- At creation:
  - request `navigator.storage.persist()` and show a refusal if denied;
  - show "clearing this site's data = losing this device" before the first device-bound write (D R258);
  - on a scrypt `RangeError`, stop with "this device cannot create a passphrase vault" and write nothing (D R259).
- A v2 blob without its device key means "this vault belongs to a cleared browser profile": the UI offers phrase
  import only.
- Seed words are shown once and are never copyable. On import, the field is cleared after parsing.

### 6.4 Find my account (M2)

1. Take one passkey assertion over a random challenge.
2. Recover the two P-256 public-key candidates from the signature.
3. For each candidate and each origin the config implies, compute `keyId(x, y, rpIdHash, originHash)` (SubjectAccount)
   and `uaOf(webauthn-p256, x‖y‖rpIdHash‖originHash)` (UA).
4. Check UA `registered`, then SubjectAccount `predictAccount` with guardian 0 / the configured guardian.
5. Run a bounded, paginated `KeyAdded(keyId)` log search from the factory deployment block.
6. Fall back to "paste your account address", verified by `hasKey`.

After the first success, the worker stores `{credentialId, x, y, account, origin}` in the key metadata (D R254).

### 6.5 Extension wallets

The app's `signers/extension.ts` only adapts clientkeys `wallets/<family>.js` (`create(window)`) to `Signer`:

| Family | Wallets |
|---|---|
| EVM, Hedera ECDSA | EIP-6963 |
| Sui | Wallet Standard |
| Aptos | AIP-62 |
| Solana | Wallet Standard |
| Cosmos | Keplr, Leap |
| Soroban | Freighter 6.0.1 |
| TON | JS bridge |

A wallet whose network differs from the selected chain is refused before signing. User rejection (4001 or the
equivalent) is not an error.

### 6.6 Dev key

`signers/dev.ts` holds a raw key, in memory only, for chains with `dev: true`. It exists only behind
`import.meta.env.DEV` (R166).

---

## 7. Feature availability matrix

Legend: **G** = gateway (needs `gatewayNode` + `/v1/gateway`); **S** = self-paid; "—" = not available.

| Feature | EVM | Hedera | Cosmos | Soroban | Sui | Aptos | TON | Solana |
|---|---|---|---|---|---|---|---|---|
| Meta-op transfer / pay | G + S | G (N2) + S | G (N2) + S | G (N2) + S | G (N2) + S | G (N2) + S | G (N2) + S | G (N2) + S |
| UA-ledger send/pay (v3 tokens) | G (N4) + S, after F2 | as EVM | — (F7/F8 later) | — | — | — | — | — |
| UA registration (gasless) | G (N4) + S, after F1 | as EVM | — | — | — | — | — | — |
| Fund meta account (`deposit`) | `transferToUA` (v3) | as EVM | n/a | n/a | ✓ `Account<T>` | ✓ | n/a | ✓ PDA ATA |
| Enable a coin type | — | — | — | — | ✓ `new_registry<T>` | n/a | — | n/a |
| Factory v1 (`META`, wrap or mint) | ✓ | ✓ (Hedera impl registered) | — PLANNED | — PLANNED | n/a | n/a | — PLANNED | n/a |
| Factory v2 tiers, rates, guardian | ✓ | ✓ (Hedera children) | — | — | — | — | — | — |
| Wrap / unwrap / addReserve | ✓ | ✓ | — | — | — | — | — | — |
| Gasless `mtxUnwrap` | G + S | G (N2) + S | — | — | — | — | — | — |
| Rate admin (calldata) / guardian | ✓ | ✓ | — | — | — | — | — | — |
| Regulated tokens (kinds 5–7) | view-only (R177) | view-only | — | — | — | — | — | — |
| DEX book, place, cancel | G (venue); on-chain cancel S | unavailable until N3 | unavailable until N3 | unavailable until N3 | unavailable until N3 | unavailable until N3 | unavailable until N3 | unavailable until N3 |
| Zether | ✓ 31337/1337 only | — | — | — | — | — | — | — |
| Passkey | ✓ SubjectAccount / UA | ✓ SubjectAccount / UA | — (D R264) | A16 (D7 #3) | A16 (D7 #1) | A16 (D7 #4, unaudited) | — (D R264) | A16 (D7 #2) |
| Seed vault | ✓ | ✓ ECDSA + ED25519 | ✓ | ✓ (Pi 314159) | ✓ | ✓ | ✓ | ✓ (OCMS kind 1) |
| Extension wallet | EIP-6963 | MetaMask on relay | Keplr, Leap | Freighter | Wallet Standard | AIP-62 | TON JS bridge | Wallet Standard |

`features` is narrowed at runtime by config, by `/v1/gateway` (chain, token, `dex`), by token kind (R177), and by
the backup policy (D §4.1).

---

## 8. Screens

### 8.1 Inventory and data flow

| # | Screen | Reads | Writes | Families |
|---|---|---|---|---|
| 1 | Home, chain and signer picker | config; identity checks (R173a) | — | all |
| 2 | Wallet | balances (curated tokens + UA ledger + factory provenance), recent events | — | all |
| 3 | Send / Pay | token info (R173), lane state, `/v1/gateway` | `/v1/metatx` \| `/v1/ops` \| `/v1/ua-metatx` or self-paid | all (§7) |
| 4 | Intent status | nonce/lane, receipt, events, `/v1/intents/{id}` | — | all |
| 5 | Accounts & keys | account state, backup status, key metadata (BE/BS, origins), vault state | create UA / SubjectAccount / Approvers; register (`/v1/ua/register`); add key/origin; guardian; vault create/import/unlock/rewrap/PRF; find my account (§6.4) | §6.2 |
| 6 | Token catalogue | factory versions, `versionOf` kind (R177), views (`legOf`, `collateralValue`, `pendingRate`, `rateAdmin`, guardian), per-leg `balanceOf ≥ reserve` | add token (explicit, R173b); revoke approval | EVM, Hedera; read-only lists elsewhere |
| 7 | Create token | factory, catalogue, `predictAddress`, underlying `decimals` (cross-checked), HTS checks, existing wrappers of the underlying shown first | `createMetaToken`, `createTiered`, `createZetherToken` (dev) | EVM, Hedera |
| 8 | Wrap / unwrap | `previewWrap`, `previewUnwrap`, `legOf`, allowance, `pendingRate` | `approve` (R174) + `wrap`; `unwrap(…, minOut)`; `addReserve`; gasless `mtxUnwrap` | EVM, Hedera |
| 9 | Rate & guardian | as 6 | guardian direct; rate ops as Safe JSON (R169) | EVM, Hedera |
| 10 | Sui coin type enable | derived `Registry<T>` id | `new_registry<T>` | Sui |
| 11 | Fund meta account | owned coins / FA / SPL | deposit transfer; `transferToUA` | Sui, Aptos, Solana, EVM v3 |
| 12 | DEX markets | `/v1/dex/markets` + `/v1/gateway` `dex`, on-chain `markets(key)` | — | EVM; others "unavailable" until N3 |
| 13 | DEX market | `depth` (poll 2 s visible), `trades`, `ticker`, `orders?maker=`, own-node `depth?scope=network` (read-only) | place, cancel, cancel-all; on-chain `cancel`/`invalidateNonces` | EVM |
| 14 | Zether | `registered(UA)`, account state, cache, BSGS (worker) | register `zether-*` UA with `authRef` (gasless, N4); `approve` + `fund`; transfer; burn; rollOver | EVM dev |
| 15 | Settings | — | locale, theme, dev key (dev builds) | — |
| 16 | Console login | `GET /v1/admin/auth-modes` ∩ config OIDC | built-in login; OIDC redirect | — |
| 17 | Overview | `/v1/admin/info`, `/me` | — | — |
| 18 | Chains, Tokens, Lanes | `/v1/admin/chains[/{key}]`, `…/tokens`, `…/lanes` | `PATCH` (hot vs restart labelled), state, breaker reset, fee_recipient, tokens, lanes (`409 LANE_BUSY`) | — |
| 19 | Namespaces, Jobs | `/v1/admin/namespaces`, `/v1/admin/jobs` | create/patch, job cancel | — |
| 20 | Peers, Policy | `/v1/admin/mesh/peers`, `…/policy` | CRUD; `url` + `allow_private` admin-only (NI rev 3.3 §7.3), pre-checked like the node's write-time guard (`https://`/`quic://` `host[:port]`, no userinfo/path/query/fragment, literal loopback/link-local/metadata/multicast refused, private ranges only with the per-peer toggle); pin 64 hex; `multiaddr`; state (operator) | — |
| 21 | Gossip | `/v1/admin/gossip`, `…/peers`, `…/announces`, `…/trusted` (text via R179) | ban/unban (operator), trusted (admin) | — |
| 22 | DEX markets & homes | `/v1/admin/dex/markets`, `…/homes` | create/patch (`gossip`, `unbound`), state | — |
| 23 | API keys | `/v1/admin/keys` | create (secret shown once), rotate, revoke (`key_custodian`) | — |
| 24 | Users | `/v1/admin/users` | create, roles ⊆ caller, disable, reset; own password | — |
| 25 | Audit | `/v1/admin/audit?since=` (R179) | — | — |
| 26 | Metrics | — | link to `metricsDashboardUrl` (R171) | — |

### 8.2 Send / pay

1. The user enters the recipient (lookalike check, §10.6), amount and optional `payId`. The path is gateway or
   self-paid.
2. `buildTerms` sets `validUntil = now + 15 min`.
   - Relayer: unbound on the gateway path unless the user pins the lane.
   - Fee: `NONE` by default. An explicit fee needs a fee recipient ≠ payee (R132).
   - An unbound fee recipient is shown as the node's `fee_recipient` from `/v1/gateway` (R84).
3. Review (decoded, §10.5), then sign (key worker / wallet), `verify`, submit, and the status screen (R157).

### 8.3 Unwrap (M6)

- `minOut` defaults to `previewUnwrap` at signing time, exactly, never 0.
- If a rate change is pending and `eta < validUntil`, the app warns and shortens `validUntil` to before `eta`.

### 8.4 DEX (M6)

**Order fields** (DEX §1.1, `dex.rs:540-580`):

| Field | Rule |
|---|---|
| `taker` | 0 (public book) |
| amounts | in `(0, 2^128)` |
| base amount | ≥ the market `min_base_amount` |
| `expiry` | default 1 d, within `(now + 5 s, now + 30 d]` |
| `flags` | FOK and IOC mutually exclusive |
| `maxFeePpm` | the market fee by default |
| `relayer` | `/v1/gateway` `dex.relayer` (home-bound); 0 on `unbound` markets (resting GTC only) |
| relayer fee | `feeMode` 0 by default; otherwise within `/v1/gateway` `dex.relayer_fee_policy` (`feeMode ≤ 2`, ppm cap 10 000) |
| open orders | ≤ `MAX_OPEN_PER_MAKER` (50) per maker |

The review shows the relayer fee separately from the market fee.

**Funding.** `approve(dex)` follows R174 (configured DEX only, exact amount). `checkOrder` runs after signing.

**Wording on screen.**
- Unbound order: "anyone may execute within your limit; cancel binds only when mined".
- Cancel signatures have no expiry (RS5-10), and the review says so.

**Prices** are the node's decimal strings, never a float division.

### 8.5 Zether

- **Register.** The worker builds the `zether-*` key data and the tagged PoP (F R295, purpose `pop`). `authRef` is 0
  (self) or one of the user's accounts. The registration is submitted gaslessly (N4) or self-paid; F R295 removed the
  `msg.sender` binding.
- **Prove.** In the worker: `zetherCall("proveTransfer", {curve, key: {x}, chainId, token, sendCounter, accSeq,
  acc, balance, yTo, amount, fee, beneficiary})`, where `x` comes from `openConfKey` **inside** the worker. The result
  is either `opData` for the `OP_ZTRANSFER` envelope (gateway) or `directCalldata`. With `authRef ≠ 0`, the
  authorization signature comes from the key worker (`zether-auth` purpose, F §5.2).
- **Balance.**
  1. Open the cache, then `checkBalance` against the current `acc`.
  2. On a miss, run BSGS on the delta; after own operations, update with `setCachedBalance` / `cacheAfterDebit` /
     `cacheAfterRollOver`.
  3. Above the device bound (2^44), show a banner.
- Every Zether screen carries "UNAUDITED — dev chains only".

---

## 9. Node clients and node addendum

### 9.1 Gateway client (`src/node/gateway.ts`)

| Call | Notes |
|---|---|
| `GET /v1/gateway` | capability, cached 30 s; required (N1 precedes A2: no fallback, M3) |
| `POST /v1/metatx` `{chain: <number>, token, m: WireMetaTx, signature}` | EVM; Hedera after N2; `202 {status, intent_id?}` |
| `POST /v1/ops` (N2) | §9.6.2 |
| `POST /v1/ua-metatx`, `POST /v1/ua/register` (N4) | §9.6.3 |
| `GET /v1/intents/{id}` | when an id is returned |
| `POST /v1/dex/orders`, `/cancel`, `/cancel-all`; `GET /v1/dex/{markets,depth,trades,ticker,orders}` | polling only |
| `GET /v1/dex/depth?scope=network` | own node, read-only (R170) |

Every request uses `credentials: "omit"`, `redirect: "error"`, a 15 s timeout and bodies ≤ 64 KiB. Errors follow
R178.

### 9.2 Admin API (`src/node/admin.ts`)

The client covers every route of NI §7.3 and A2 §13.1 with `Authorization: Bearer`, `credentials: "omit"` and
`redirect: "error"`.

| Status | Handling |
|---|---|
| `401` | back to login |
| `403` | re-read `me` |
| `409`, `422` | shown inline |
| `429` | backoff |
| `503 IDP_UNAVAILABLE` | banner |

`X-Request-Id` is shown in error details.

### 9.3 Built-in login

1. `GET /v1/admin/auth-modes`.
2. `POST /v1/admin/login` returns `{token, expires_at, roles}`; the password field is cleared immediately.
3. Refresh at `expires_at − 60 s` while the tab is visible. A refusal sends the user to login.
4. `POST /v1/admin/logout` (bumps `session_epoch` for every session of that user, and the UI says so), then clear the
   cache.

### 9.4 OIDC (R163)

1. Issuer = `auth-modes` ∩ `nodes[].oidc`. Discovery `issuer` must match byte for byte, and every endpoint origin
   must be in `connectSrc`.
2. Write `{node, issuer, verifier, state, nonce, returnRoute, created}` to `sessionStorage`, then redirect with
   `response_type=code`, `client_id`, `redirect_uri = origin + pathname`, `scope=openid` (plus `offline_access` when
   the IdP advertises refresh for public clients), S256, `state`, `nonce`, and `audience`/`resource` per the node's
   audience.
3. Callback:
   - match `state` and the stored `issuer`; check RFC 9207 `iss` when sent;
   - exchange the code, check the ID token `nonce`/`iss`/`aud`;
   - keep the access token for that node only, delete the entry;
   - `replaceState` back to `returnRoute`, then `GET /v1/admin/me`.
4. Renewal per R163. Logout via `end_session_endpoint`.

### 9.5 Several nodes

Sessions are keyed by node id. A token is never sent to another node.

### 9.6 Node addendum (normative for N1, N2, N4; to be copied into NI §5/§9/§12 and F §11.2)

#### 9.6.1 N1 — gateway capability, CORS, errors, app serving

`GET /v1/gateway` (gateway listener, gateway auth applies):

```json
{"api": 1, "chains": [
  {"chain": 100, "chain_key": "evm:100", "family": "evm", "routes": ["metatx", "dex"],
   "tokens": ["0x…"], "fee_recipient": "0x…", "breaker_open": false,
   "max_valid_for_secs": 3600,
   "dex": {"address": "0x…", "relayer": "0x…", "markets": [{"id": 1, "min_base_amount": "1000"}],
           "relayer_fee_policy": {"modes": [0, 1, 2], "max_ppm": 10000},
           "max_open_per_maker": 50, "min_ttl_secs": 5, "max_ttl_secs": 2592000}}]}
```

- `chain` is numeric for EVM and Hedera (the `/v1/metatx` body); `chain_key` is always present (L6).
- `routes` ⊆ `metatx`, `ops`, `ua-metatx`, `ua-register`, `dex`.

Other N1 items:
- `[modules] gateway_cors_origins`: exact list, no `*`, methods `GET, POST`, header `Content-Type`, no credentials,
  `max_age = 600`.
- Error body on every gateway route (R178):
  `{"error": "<CODE>", "code": "<CODE>", "detail": "<≤ 300 chars>", "revert_data": "0x…"?}`. The legacy
  `"error"` keeps the code, so old clients still read a string.
- `[app]` serving: §13.2.

#### 9.6.2 N2 — `POST /v1/ops` (six non-EVM families) and Hedera on `/v1/metatx`

Request body: `chain` plus one signed op, i.e. the job API's `signed_op` payload (NI §5.2) without `id`:

```json
{"chain": "sui:testnet",
 "op": {"family": "sui", "contract": "<account id | token | registry, family canonical>",
        "from": "<subject, family canonical>", "op_kind": "pay",
        "payload": "0x<MetaOp bytes / XDR / BOC, as fam/<family>.js builds>",
        "signature": "<packSignature().signature>", "public_key": "<packSignature().publicKey | null>",
        "auth_kind": "seed | wallet | passkey", "digest": "0x… (optional; must equal the node's)",
        "valid_until": 1790000300, "extra": {"coin_type": "0x2::sui::SUI"}}}
```

`op` is exactly what `blockchain_relay_job._payload()` emits for `signed_op` today and what every adapter's `build`
already consumes.

Accept checks, in order:
1. `chain` is served (`UNKNOWN_CHAIN`).
2. `family` equals the chain's family (`BAD_PAYLOAD`).
3. The payload decodes; the node computes the digest; a client digest that differs fails (`BAD_PAYLOAD`).
4. The token or asset is registered (`TOKEN_NOT_SERVED`).
5. `now < valid_until ≤ now + max_valid_for_secs` (`EXPIRED`).
6. The family signature verify, where the node has one (`BAD_SIGNATURE`). L9 `None` (key not the payer's) goes on to
   simulation.
7. A bound relayer must be a lane of the chain (`RELAYER_NOT_OURS`).
8. Simulation (`SIMULATION_REVERT`).
9. INSERT a `signed_op` job in `~gateway`, origin key = digest (G2 durable).

Response: `202 {"status": "queued", "intent_id": "<digest hex>"}`.

Soroban: accepted, never published on the mesh (R77). TON: `attach_nanoton` is the node's. Limits: 64 KiB body,
the per-chain breaker and the gateway concurrency limit.

Hedera on `/v1/metatx`: `chain` = 295–298. `sig_bytes` accepts **64** bytes (HIP-632 ED25519) only on Hedera chains,
and 65–2048 bytes otherwise. Same `~gateway` job path (L2e).

N2 depends on node P3 (lanes lease from the store): before P3 the gateway's in-memory `mpsc` feeds only the EVM
submitter.

#### 9.6.3 N4 — UA routes (after F1/F2; with F5's node work)

| Route | Body | Checks | Job |
|---|---|---|---|
| `POST /v1/ua-metatx` | `{chain, token, m: WireUAMetaTransaction (from/to 0x+64 hex, decimal strings), auth: 0x…}` | token is v3 (`registry() ≠ 0`); `from >> 160 ≠ 0` ⇒ registry record read once (cached, F R317); cheap kinds verified locally; `uaDigest` computed by the node | `ua_metatx` (F §11.2) |
| `POST /v1/ua/register` | `{chain, kind, keyData: 0x…, pop: 0x…, authRef: 0x…32}` | id recomputed, `>> 160 ≠ 0`, not yet registered, PoP verified for cheap kinds, per-chain sponsorship quota (F §17 Q8) | `call` job in `~gateway` (gateway capability, not a namespace grant) |

Response: `202 {status, intent_id}`. Errors follow R178, plus `UA_NOT_REGISTERED`, `UA_ALREADY_REGISTERED` and
`UA_KEY_IN_USE`.

---

## 10. Security

### 10.1 CSP and headers (H6)

Node-served (every app response):

```
Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self';
  style-src-elem 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';
  connect-src 'self' <origins of chains[].rpc/.rest/.mirror, nodes[].gateway/.admin, nodes[].oidc[].connectSrc, [app] extra_connect_src>;
  worker-src 'self'; manifest-src 'self'; frame-src 'none'; frame-ancestors 'none'; form-action 'none';
  base-uri 'none'; object-src 'none'; require-trusted-types-for 'script'; trusted-types scaas-worker
Cross-Origin-Opener-Policy: same-origin   Cross-Origin-Resource-Policy: same-origin   Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), clipboard-read=(),
  publickey-credentials-get=(self), publickey-credentials-create=(self)
```

- **Trusted Types.** `src/lib/trusted-types.ts` defines the one policy `scaas-worker`, whose `createScriptURL`
  accepts only same-origin `/assets/*.js`; both worker constructors use it.
- **Styles.** `style-src-elem 'unsafe-inline'` exists because Radix `RemoveScroll` injects `<style>` elements
  (`react-style-singleton`). Under Trusted Types that is low value to an attacker.
- **Workers.** Worker scripts get the same header minus `frame-ancestors`; in static mode `npm run csp` emits it for
  `/assets/*.worker-*.js` (H6f).
- **Static mode.** The meta CSP is the same with `connect-src 'self' https:` (dev builds add localhost) and no
  `frame-ancestors`.
- **Frame check.** `boot.ts` runs `if (window.top !== window.self)` before mounting and renders only a warning (H6c).
- **Playwright.** Every suite fails on any `securitypolicyviolation` event (H6e).

### 10.2 No secrets in the bundle

- No R92 key, gateway secret, RPC key, OIDC secret or dev key in source, `VITE_*` or config (R152, §4.3).
- CI greps `dist/` for `scaas_s1.`, `X-Scaas-Key`, the anvil default keys, and 64-hex strings not in the
  public-constant list.
- Tokens stay in memory; `Authorization` is stripped from error reports.

### 10.3 Supply chain (R166, M9)

- **Allowlists.** `deps-allowlist.json` lists direct **and transitive** packages. `scripts/deps-gate.mjs` fails CI
  on any lockfile package outside it, and on a total count above the recorded number.
- **CI checks.** `npm ci --ignore-scripts`, `npm audit signatures`, and `npm audit --omit=dev --audit-level=high`.
- **Licences.** `scripts/licenses.mjs` allows MIT, Apache-2.0, BSD, ISC and LGPL (clientkeys).
- **Lockfile.** Changes come only in `deps:` PRs.
- **Known heavy trees.** stellar-sdk (dropped for stellar-base), cosmjs (vet at A9), `@ton/ton` (dropped).

### 10.4 Dev gating (L3)

- One flag: `import.meta.env.DEV`. Dev code (dev key, mock hooks) is imported only behind it.
- A `--mode development` build refuses to run off-localhost and shows a permanent banner.
- CI asserts the production `dist/` lacks `scaas-dev-signer` and the anvil keys.

### 10.5 Signing review (R158)

| Row | Content |
|---|---|
| Network | config label + `chain_key` + identity check passed (R173a) |
| Contract | curated label, or `untrustedText` name + "unverified"; provenance "curated" / "open factory (anyone can)"; domain check (R173c) |
| Operation | decoded op: transfer, pay(payId), trade, approve (spender per R174: "configured DEX" / "wrapper of <underlying>"), unwrap (underlying → recipient, `minOut`), DEX order (both legs, limit price both ways, market fee, relayer fee, expiry), cancel, UA register (kind, id), Zether |
| From → To | address views (§10.6); kind (EOA / contract / UA kind / unknown) |
| Amount, fee | decimal from `bigint` with pinned decimals (raw integer beside it if non-curated); fee, recipient (bound or "relayer's: <addr>") |
| Validity | local time + relative; > 1 h warns; > 24 h needs a second confirmation |
| Relayer | bound lane / any |
| Wallet display | the exact string a digest-only wallet will show + the origin warning (R158) |
| Raw | collapsible: exactly what the signer receives |

Blocking warnings:
- an unknown contract (allowed in dev builds only);
- a fee ≥ 1 % of the amount;
- a recipient that is the token itself;
- a lookalike recipient;
- a DEX price ≥ 5 % from the best opposite level;
- an under-reserved Multi leg;
- a pending rate change before `validUntil`;
- a UA user sending a v1/v2 token (R176).

### 10.6 Clipboard and phishing

- **Addresses** are grouped with the first and last 6 characters emphasised and a colour badge.
- **Lookalikes:** a recipient matching the first 4 and last 4 characters of a history or address-book entry, but
  different, gets a blocking warning.
- **Clipboard:** never read by the app (`clipboard-read=()`). Secrets cannot be copied (seed words), or only once
  (API key secret, cleared from memory when the dialog closes).
- **Links:** only configured explorers and `documents[].url`; no chain or network string is rendered as a link
  (R177, R179).

### 10.7 URL guard (R170, H7)

`boot.ts` installs the guard before any adapter chunk loads, by wrapping `globalThis.fetch`,
`XMLHttpRequest.prototype.open` and `WebSocket`:
- the origin must be in the allowlist: config origins ∪ `nodes[].oidc[].connectSrc`;
- `fetch` is forced to `redirect: "error"` and `credentials: "omit"`;
- `wss:`/`ws:` are refused unless configured (none by default);
- anything else throws `UrlRefused`, logged as such.

Explicit transports are also passed where an SDK accepts one: viem `http(url, {fetchFn})`, the Sui client's fetch,
and `AptosConfig({client})`. The e2e suites assert zero requests to unlisted origins. Peer URLs typed in the console
are validated, never fetched by the browser.

---

## 11. i18n

- **Files.** `src/locales/{en,vi}/{common,wallet,accounts,tokens,dex,zether,admin,errors}.json`. English is bundled;
  Vietnamese is loaded on demand.
- **Language choice.** No detector library. Order: the saved choice (`localStorage`), then `config.defaultLocale`,
  then `en`.
- **Keys** are stable identifiers. Plurals use `_one`/`_other` (Vietnamese uses `_other` only).
- **Error keys.**
  - `errors.node.<CODE>` (R178);
  - `errors.chain.<family>.<name>` for contract errors decoded from revert data with the app's ABI;
  - `errors.wallet.rejected`.
- **Formatting.** `Intl` on strings built from `bigint`; never `Number`.
- **CI** (`scripts/i18n-check.mjs`): the same key set in EN and VI, no unused keys, and no hard-coded JSX text
  (lint). Each stream writes its VI strings, and A15 reviews them (M4).
- **Disclosures** (`tokens.disclosure.depeg`, `.adjustableMulti`, `.regulated` (AS §3.9), `zether.unaudited`,
  `accounts.ua.noRecovery`) show the English original beside the Vietnamese until the owner approves (R167).

---

## 12. Testing

### 12.1 Unit (Vitest / `node --test`, no network)

| Area | Vectors / method |
|---|---|
| EVM encoders | `metatx_kat`, `metatx_v2_kat`, `dex_kat`, `hedera_kat`, `wrap_rate_vectors`, `subject_account_create2`, `webauthn_soft` |
| Non-EVM encoders (clientkeys) | `mesh-envelope-v1.2.json` cross-language payloads, `ton-vectors.json`, `fam_*.json` exported by A0-<family>, `sui_vectors.json` (D R262), D's seed-signed vectors, `solana_derivation.json` |
| UA (clientkeys) | `smartcontracts/vectors/ua/*` (F §15.1): ids, keyHash, `ua_msg`, PoP, `UAMetaTransaction` digests; `deriveUAKey` paths under `m/7622'` |
| Backup / vault | D `backup_policy.json` plus the H4/R176 rows; `vault_v2_fixture.json` |
| Zether | prover vectors through the WASM `nodejs` build; clientkeys `zether.test.js` |
| Adapter contract suite | §5.1, including `decode ∘ signRequest ∘ buildTerms = id` |
| Config | every refusal in §4.3, including the L7 patterns |
| Guard, text, CSP | URL guard refusals (redirect, credentials, ws); `untrustedText` (bidi, ZW, NFKC, caps); Trusted Types policy |
| Auth | built-in refresh; OIDC against `mock-idp.mjs` (issuer pinning, RFC 9207, state/nonce); a `Storage` spy proves only the R162 entry is written |
| Roles, amounts | route × role tables; `bigint` round trips at 0, 1, 2^54, 2^64, 2^256−1, decimals 0–36 |

### 12.2 End-to-end (Playwright, Chromium)

| Suite | Against | Covers |
|---|---|---|
| `evm` | anvil + `deploy.sh evm` + `scaas-node` (gateway, CORS, DEX venue on one lane) | send/pay via gateway and self-paid; v2 tiers; wrap/unwrap/`mtxUnwrap`; R174 refusals; DEX place/cancel/fill across two contexts; passkey SubjectAccount (CDP virtual authenticator); find-my-account; vault v2; backup switch ON (receive hidden, value refused, add-key allowed); EIP-6963 fake |
| `ua` (after F1–F3, N4) | anvil + F1/F2 deploy | passkey-UA create + gasless register; v3 send; Approvers |
| `zether` | anvil + **`script/DeployZether.s.sol`** (dev only, A6: registry, verifiers, ZetherToken) | register (gasless), fund, transfer, rollOver, burn, cache/BSGS |
| `console` | `mock-node.mjs` + `mock-idp.mjs`; real node after P2/P2b | login flows, roles, secret shown once, peer URL checks, 409/422 |
| `cosmos`, `soroban`, `sui`, `aptos`, `ton`, `solana` | `wasmd`; `stellar/quickstart --local`; `sui start --localnet`; `devnet.sh aptos`; TON shim; `devnet.sh solana` (`~/.local/share/solana/install/active_release/bin` on PATH) | gate 1: self-paid with seed + the clientkeys fake wallet; gate 2 (after N2): via `/v1/ops` |
| `node-served` | `scaas-node` with `[app]` | header bytes **and** behaviour (no CSP violations), same-origin console |

Harness details:
- Localnet RPCs without CORS (TON shim, wasmd, possibly quickstart) are forwarded with Playwright
  `page.route` + `route.fetch()`, so the CSP still applies to the URL (L4).
- The Freighter fake speaks freighter-api 6.0.1's postMessage protocol.
- Each localnet suite runs alone under `scripts/capped`.
- CI runs unit + `evm` + `console` per PR; the rest run nightly or when their family changes.
- Keyboard-only pass over send, review and login.

---

## 13. Build and deploy

### 13.1 Static SPA

1. `npm ci --ignore-scripts && npm run build` produces `dist/`.
2. The operator adds `config.json` and serves the headers from `npm run csp -- config.json` (page + workers).
3. Caching: `config.json` `no-store`, hashed assets `immutable`, `index.html` `no-cache`.

No rewrites are needed (hash routing).

### 13.2 Served by `scaas-node` (R159, R160)

```toml
[app]
enabled = false
dir = "/opt/scaas/app"                   # built dist/; not writable by the service user
config = "/etc/scaas/app-config.json"    # served at /config.json; validated at start
extra_connect_src = []
```

**Routes** on the admin listener:

| Path | Serves |
|---|---|
| `GET\|HEAD /`, `/index.html` | `no-cache` |
| `/assets/{file}` | name `[A-Za-z0-9._-]+`, immutable; `.wasm` = `application/wasm` |
| `GET /config.json` | `no-store` |
| any other non-`/v1/`, non-health path | `404` |

**Behaviour.**
- The §10.1 headers go on every app response; `connect-src` is computed at start from the served `config.json` and
  `extra_connect_src`.
- A changed config means `pending_restart`.
- `Config::validate` refuses `enabled` without `dir/index.html`.
- Implementation: `tower-http` `ServeDir` + a header layer.
- Metric: `scaas_app_requests_total{path_class}`.

**Loopback operation (M1).** With the default loopback `admin_bind`, operators tunnel to **`localhost`** (not
`127.0.0.1`, if they use passkeys); `"self"` resolves to `http://localhost:<port>`, which §4.3 allows.

### 13.3 CI job `app`

Paths: `app/**`, `clientkeys/**`.

1. `npm ci --ignore-scripts` (clientkeys, app)
2. clientkeys `node --test`
3. `tsc --noEmit`, `eslint`, `vitest`
4. `vite build`, then `budget.mjs`, `deps-gate.mjs`, `i18n-check.mjs`, the dist secret/dev grep, and the `abi.mjs`
   diff
5. Playwright `evm` + `console`

Heavy steps never run in parallel with the node's `cargo` jobs on the self-hosted box.

---

## 14. Performance budget (M9)

`budget.json` starts from the **A1 spike**: one minimal import per SDK built into a throwaway chunk, with gzip sizes
recorded, plus 15 %. CI fails above the budget; A15 ratchets it to the measured size + 10 %.

Starting caps for the spike to confirm or replace:

| Chunk | Cap |
|---|---|
| shell | ≤ 200 kB |
| EVM adapter incl. viem's noble | ≤ 110 kB |
| key worker | ≤ 80 kB |
| each non-EVM adapter | ≤ 250 kB |
| Soroban (stellar-base) | ≤ 300 kB |
| console | ≤ 120 kB |
| VI strings | ≤ 40 kB |
| Zether WASM | ≤ 1.2 MB, measured at A6 |

**Runtime.**
- Shell interactive ≤ 3 s on a mid-range phone over 4G; adapter switch ≤ 1.5 s.
- DEX polling ≤ 1 request per 2 s per visible market.
- BSGS 2^22 table about 1.5 s on desktop, once per worker session.

Family SDKs load only through `families/registry.ts` dynamic imports, which the budget script checks.

---

## 15. Work breakdown

One agent at a time; at most one heavy npm build, cargo build or localnet at a time (`scripts/capped`). D, F and node
streams are named where the app depends on them; their content lives in their own specs (D §10, F §16, NI §17).

| Stream | Content | Depends on | Gate |
|---|---|---|---|
| **A1** skeleton | Vite/React/TS/Tailwind/shadcn, theme, router, i18n, config validator, store, URL guard, frame check, TT policy, `untrustedText`, SDK **size spike** → `budget.json`, deps gate, CI job | — | unit + build + budget + deps gate |
| D1 → D3 → D2 | backup policy; Sui verify; vault v2 (spec D) | — | D gates |
| **A0-evm** | clientkeys DEX/v2 helpers, `zether-prover --target web` script, `NETWORKS.solana` | — | `node --test` |
| D5-evm | `wallets/evm.js` (EIP-6963 + `walletKind`) moved into clientkeys | A0-evm | `npm test` |
| **N1** node | `/v1/gateway`, gateway CORS, error contract (R178), `[app]` serving + CSP | — | `cargo test` + `node-served` e2e |
| **A2** EVM core | EVM adapter, key worker, seed + extension + dev signers, wallet, send/pay (gateway, self-paid, direct), review, status | A1, A0-evm, D5-evm, N1 | `evm` send/pay |
| **A3** accounts | SubjectAccount passkey (create, add key/origin, find-my-account), vault v2 UI, backup switch (D6 app part), H4 de-dup | A2, D1, D2 | `evm` accounts + switch ON |
| **A4** tokens | catalogue (R177 kinds), v1/v2 wizard, disclosures, wrap/unwrap/addReserve, `mtxUnwrap`, R174, Safe JSON (R169), guardian, Hedera adapter + overrides | A2 | `evm` tokens; Hedera unit |
| **A5** DEX | markets, depth/trades/ticker, orders (M6 fields), cancel, cancel-all, on-chain cancel, unbound, own-node network depth | A2, N1 | `evm` DEX |
| **A7** console core | admin client, built-in auth, OIDC (pinned), roles, overview, chains/tokens/lanes, namespaces, jobs, keys, users, audit | A1 (real node: P2, P2b) | `console` |
| **F0 → F1** (spec F) | kind libraries, `UARegistry`, Zether re-point | — | F gates |
| **A6** Zether | `DeployZether.s.sol` (dev), Zether worker, register (F1 tagged PoP), fund, balance, transfer, burn, rollOver | A3, F1 | `zether` |
| **N2** node | `/v1/ops` (six families) + Hedera on `/v1/metatx` (§9.6.2); copied into NI | node P3, N1 | `cargo test` + Cosmos `wasmd` e2e |
| **A9 … A14** families (Cosmos, Soroban, Sui, Aptos, TON, Solana; owner family order) | per family: **A0-<f>** (encoders + vectors), **D4-<f>** (seed signer: Soroban, Aptos, Solana), **D5-<f>** (wallet moved), adapter, deposit/enable where applicable | A2; gate 2 needs N2 | gate 1 self-paid; gate 2 `/v1/ops` |
| **A8** console mesh | peers, policy, gossip, DEX markets/homes, dashboard link | A7 (real node: P2b, G1–G3) | `console` |
| **F2, F3, N4** | MetaToken v3; clientkeys `UAKey`; node UA routes (§9.6.3) with F5 | F1 | F/node gates |
| **A18** Universal Accounts | default passkey-UA account + gasless register, v3 UA-ledger send/pay, `transferToUA`, Approvers (minimal), Zether `authRef`; default switches from SubjectAccount to UA | A3, A6, F2, F3, N4 | `ua` |
| **A15** release | VI review pass, keyboard pass, budget ratchet, `app/README` (both modes, IdP redirect URIs, CSP, loopback tunnelling) | all above | full CI + nightly once |
| **A16 = D7** | non-EVM passkeys Sui → Solana → Soroban → Aptos | A11, A14, A10, A12 | per-family e2e |
| N3 → **A17** (PLANNED) | node non-EVM DEX books (after P7/G3), then per-family DEX screens | P7, N2 | per-family DEX e2e |
| **AS8-app** (PLANNED) | regulated-token flows, managed markets, issuer wizard (AS §9.3) | AS streams | AS e2e |

Order for one agent:

A1 → D1 → D3 → D2 → A0-evm → D5-evm → N1 → A2 → A3 → A4 → A5 → A7 → F0 → F1 → A6 → N2 → A9 (Cosmos) →
A10 (Soroban) → A13 (TON) → A11 (Sui) → A12 (Aptos) → A14 (Solana) → A8 → F2 → F3 → N4 → A18 → A15 → A16 → (N3 → A17)
→ (AS8-app).

Node P-streams (P2, P2b, P3, P7) and G-streams run in the node queue; an app stream whose real-node gate needs them
gates on the mock node until they land.

---

## 16. Owner answers (rev 1.1, 2026-10-06)

| # | Question | Answer |
|---|---|---|
| Q1 | Relayed submission for Hedera and the non-EVM families? | **Yes.** `/v1/ops` (N2) for the six non-EVM families; Hedera on `/v1/metatx` (L2e, the same relay path). Schema §9.6.2; to be copied into NI. |
| Q2 | Non-EVM DEX books? | **Yes, after EVM** (N3 → A17); "unavailable" until then. |
| Q3 | Vietnamese risk disclosures? | Owner approves; until then English beside Vietnamese. |
| — | UA key-tree purpose | **`7622'`** (owner correction 2026-10-06): `m/7622'/0'/<account>'/<kindNo>'/<i>'`. F §8.1 and F §17 Q6 still say `7225'` and must be corrected (§17). |

No open questions remain.

---

## 17. Doc corrections (listed; not made here unless noted)

- **Made in this change:** `docs/SCaaS.md` §3.1 `app/` row and `docs/integration.md` §14 now point to this spec.
- **SCaaS.md:** §3.3, §3.5, §12.1, §12.2, §12.3, §12.4 and the §15.1 P2 row still mention admin API keys
  (`scaas_ak1.`, `/admin-keys`); NI rev 3.2 has none. SCaaS §15.1 row 21 ("EVM + meta-tx families first") is
  superseded by "all seven families".
- **NI:**
  - add `GET /v1/admin/auth-modes` to the §7.3 route table and to the §3 open-route list (L6);
  - add `/v1/gateway`, gateway CORS, the error contract, `[app]` (§9.6.1), `/v1/ops` and Hedera door A (§9.6.2),
    and the UA routes (§9.6.3).
- **DEX §3.5 / A2:** non-EVM venue books (N3).
- **Spec D:**
  - §4.3 and `backup_policy.json` gain the credential de-dup (H4) and the `msig` rule (R176);
  - the app now owns D5's EVM part ordering (D5-evm before A2).
- **Spec F:** §8.1 and §17 Q6 purpose `7225'` → **`7622'`**; §11.3 "gasless register" names the N4 route
  `POST /v1/ua/register`.
- **TW2 / AS:** `versionOf().kind` decoders know 5–7 (AS already says so); the app's `(kind, version)` named-function
  table (R177) is the client half.
- **`zether-prover/wasm-smoke.sh`:** add the `--target web` build (A0-evm).

---

## 18. Review disposition (review 1 of rev 1.1, FIX-THEN-GO)

| # | Finding | Disposition | Where |
|---|---|---|---|
| H1 | Hostile RPC defeats the review | fixed: identity check, pinned metadata, domain check, two-RPC cross-check, RPC override deleted, "config = host integrity" stated | R173, R161, §5.3, §4.1 |
| H2 | Spender not allowlisted | fixed: configured DEX or verified wrapper, exact amount, revoke, review row | R174, §10.5 |
| H3 | Seed in the SDK realm | fixed: key worker (clientkeys only); conf key opened in the Zether worker | R175, R164 |
| H4 | Same passkey on two origins counts as backup | fixed: de-dup by `(x, y)`; D amendment listed | R165, §6.3, §17 |
| H5 | Spec D not folded in | fixed: vault v2 + storage keys + persist + notices, `policy.requireBackupKey`, `wallets/*`, seed `solana-raw` refused, one encoder interface, D1–D7 edges | R154, R155, §4, §6, §15 |
| H6 | CSP breaks the app / gaps | fixed: TT policy `scaas-worker`, `style-src-elem`, frame check, pinned OIDC origins, no remote homes, worker headers, Playwright violation gate | §10.1, R163, R170 |
| H7 | Guard skips SDK traffic | fixed: global fetch/XHR/WebSocket guard before adapters; explicit transports; e2e zero-foreign-requests | R170, §10.7 |
| M1 | Loopback node-served refused | fixed: `http://localhost` self rule, `rpId` localhost, `redirect_uri = origin + pathname`, README note | §4.3, §9.4, §13.2 |
| M2 | No way to find a passkey account | fixed: find-my-account flow | §6.4 |
| M3 | Free-text gateway errors | fixed: error contract in N1; absent-capability fallback deleted | R178, §9.1, §9.6.1 |
| M4 | Stream order, `/v1/ops` schema, Zether deploy, A15 vs CI | fixed: N1 before A2, A1 independent of A0, A0 split per family, two gates per family, schema written, `DeployZether.s.sol`, VI per stream | §15, §9.6, §11 |
| M5 | Asset suite / tender wallet duties | fixed (minimum): kinds 0–7 decoded, 5–7 view-only, managed markets unavailable, `(kind, version)` table, config-only document links; AS8-app planned | R177, §15 |
| M6 | `minOut` / DEX fields | fixed: `minOut = previewUnwrap`, rate-change window, full order field list, `/v1/gateway` DEX policy, `order_book_dex` mapping | §8.3, §8.4, §9.6.1, §4.2 |
| M7 | Review beside, not from, the bytes | fixed: decode from signing input; `checkTerms`; round-trip in the contract suite; wallet-display line | R154, R158, §5.1 |
| M8 | Attacker-chosen strings | fixed: `untrustedText`, unverified badge, provenance wording | R179 |
| M9 | Budgets and supply chain not grounded | fixed: A1 spike, transitive allowlist + count gate, `buffer` decided, `@ton/ton` dropped (v2 client), stellar-base only, cosmjs vet | §3.2, §10.3, §14 |
| L1 | OIDC issuer from the node only | fixed: config ∩ auth-modes, RFC 9207, return route stored | R163, §9.4 |
| L2a | Browser dialing of DEX homes | cut: own-node network depth read-only | R170 |
| L2b | Prometheus screen | cut: dashboard link | R171 |
| L2c | RPC override | cut | R173 |
| L2d | `/v1/gateway`-absent fallback | cut | §9.1 |
| L2e | `/v1/ops` for Hedera | **accepted with a correction:** the review says the HIP-632 signature fits `sig_bytes` 65–2048, but it is 64 bytes and `gateway.rs` refuses < 65. N2 allows 64 on Hedera chains only. Hedera also runs through `lane_runner`, not the gateway's `mpsc`, so this needs P3 (store-leased lanes) like `/v1/ops` | §9.6.2 |
| L2f | Second set of fake wallets | cut: clientkeys `test/wallets/*` via `addInitScript` | §3.3 |
| L2g | EIP-681 link for `rateAdmin` | fixed: Safe Transaction Builder JSON / `MultiSig.sol` | R169 |
| L3 | Two dev flags; deployable dev builds | fixed: one flag, localhost-only dev builds with a banner | R166, §10.4 |
| L4 | e2e realism | fixed: `page.route` CORS forwarding, Solana PATH, Freighter 6.0.1 protocol | §12.2 |
| L5 | Zether worker lifecycle | fixed: one session worker, terminated on lock/idle/hide | R164 |
| L6 | NI gaps (`auth-modes`, numeric vs `chain_key`) | listed in §17; `/v1/gateway` reports both | §17, §9.6.1 |
| L7 | RPC-key heuristic | fixed: long segment / long label rules | §4.3 |

Counts: 23 findings (7 H, 9 M, 7 L), shown as 29 rows because L2 has seven items. Of the 29 rows, 23 are fixed, 5 are
cut, and 1 (L2e) is accepted with a factual correction. None was rejected. Spec D and spec F are folded in (R154, R155, R164, R165, R175, R176,
§6, §15), along with the owner's `7622'` correction.
