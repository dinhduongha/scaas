# Signers and wallet follow-ups (S4): backup-key switch, device-bound vault, Sui key verification, non-EVM signers, portal connectors (component spec D)

Status: draft rev 1, 2026-10-06. Component spec **D**. Short name **S4F**. Code at `scaas` `main` 28c165c
(clientkeys 1.0.0: passkey + seed vault + Zether keys BUILT, EVM-only family encoders); parent repo `bamboo-dms`
read for the Odoo side (`dms_blockchain/lib/fam_*.py`, `dms_blockchain_bridge/static/src/js/**`). **Nothing in this
spec is built.**
Rulings: **R250–R268** (§2). R150–R172 belong to the app spec, R180–R199 to spec B (TSS), R200–R217 to spec A (AS),
R230–R245 to spec C (OPS).
Owner items folded in: the S4 follow-up queue of 2026-10-04/05 (backup-key switch default OFF, device-bound vault, Sui
`fam_sui.verify` for added/recovered keys, Soroban/Aptos/Solana seed + passkey signers, `chain_pay.js` connectors),
market neutrality, and the announced spec **F "Universal Account"** (§3: what stays here, what moves there).

Requirements and sources:

| Short | File | Section |
|---|---|---|
| SCaaS | `docs/SCaaS.md` | §9.3–§9.5 (passkeys, subject accounts, backup toggle PLANNED, seed vault, Solana path PLANNED) |
| R3 | `specs/2026-10-03-blockchain-round3-design.md` | §C.1–C.4, R31–R33 |
| RS4 | `plans/2026-10-03-r3-passkey-seed.md` | RS4-1…RS4-16 (vault, key proof, client-side checks) |
| ADW | `specs/2026-10-03-blockchain-payments-addendum-wallets.md` | §B (EIP-6963, WalletConnect seam R21), R27 |
| APP | `specs/2026-10-06-scaas-app-design.md` | R154 (client builds every byte), R155 (signers), R165 (origin-bound passkeys), §5.2, §6.2, streams A0, A3, A16 |
| NET | `specs/2026-10-03-net-{sui,soroban,cosmos,ton}.md`, `2026-10-04-net-{aptos,solana}.md` | Sui §2–§3 (KeyOp, RS7-3), Soroban §3 (R8-2 guardian seam), Aptos L9/RS11-3/RS11-14, Solana L9/RS12-4/RS12-5 |

Amends (status changes only; text in those files is not rewritten here):

| Short | File | How |
|---|---|---|
| SCaaS | `docs/SCaaS.md` §9.4, §9.5 | backup toggle and Solana path: PLANNED → SPECIFIED, link here. The §9.4 mode list (`passkey_prf`, `seed_verified`, `guardian_only`, `device_bound`) and its "device_bound refused" hard rule are **replaced** by R250–R253 |
| R3 | round-3 design R32 | scrypt `N = 2^15` is superseded by RS4-14 / R259 (`N = 2^17`) — closes the SCaaS §15.3 contradiction row |
| NET Solana | RS12-5 "semantics must match S4 when S4 settles" | settled: same predicate (R251); the on-chain bit stays opt-in per account (R252) |
| APP | A0, A3, A16, R155 | A16's content for Sui, Solana, Soroban, Aptos is §8 here; A3's vault UI uses vault v2 (§5); extension signers import clientkeys `wallets/*` (R266) |

---

## 1. Scope and non-goals

### 1.1 In scope

1. A deployment switch "backup key required" (default OFF), its predicate, where it is enforced, and per-family
   applicability (§4).
2. Vault v2: the seed/Zether vault bound to the device by a non-extractable WebCrypto key in IndexedDB; threat model,
   migration, recovery (§5).
3. The scrypt cost: one number, stated (§5.6).
4. Sui: `fam_sui.verify` for keys added by `KeyOp` or by guardian recovery; KeyOp encoding in Python and JS; vectors
   (§6).
5. Seed signers for Soroban (Stellar, Pi), Aptos and Solana: derivation paths and the envelope each one signs (§7).
6. Passkey signers for non-EVM families: per-family availability and envelope (§8) — the content of app stream A16.
7. Portal payment connectors for every family and their single implementation shared with the app (§9).

### 1.2 Non-goals

| Not here | Why / where |
|---|---|
| Account identity, registration, kind-tagged 32-byte ids, one-key-one-purpose registry, VC/eKYC attestations | Spec F "Universal Account" (§3) |
| New contract code on any family (a backup bit on EVM/Sui/Aptos, a Soroban/TON guardian) | Owner: "only a switch, not a hard rule"; contract changes need audit O1 on every family (R252). Soroban/TON guardian stays a seam (Q1) |
| KMS/HSM custody, `SigningPolicyService`, FROST/MuSig2 signers | SCaaS §9.1, §9.2, §9.7 (PLANNED, O6/O7) |
| WalletConnect / TON Connect HTTP bridge | R21 seam; APP §1.2 |
| Odoo mirrors of non-EVM key sets | R20 (no RPC in family libs); the node's simulation arbitrates (R27) |
| Argon2id for the passphrase | No WebCrypto primitive; would add a wasm dependency for no measured need (R259) |
| Moving a vault between devices (export/import of the encrypted blob) | The recovery phrase is the transfer format (R258) |

---

## 2. Rulings

Format: **ruling** — why — cost if wrong.

### 2.1 Backup-key switch (owner item 1)

- **R250** **"Backup key required" is one boolean deployment switch, default OFF**, one per onboarding surface: app
  `config.json` `policy.requireBackupKey` (validator §4.3 of APP: boolean, default `false`), Odoo system parameter
  `dms_blockchain.require_backup_key` (`ir.config_parameter`, absent = OFF), and an argument to the clientkeys policy
  helper (clientkeys reads no configuration). It is **not** a per-account mode: the SCaaS §9.4 mode list
  (`passkey_prf`, `seed_verified`, `guardian_only`, `device_bound`) and its "device_bound is refused for any
  value-bearing flow" rule are dropped. — Owner: "only a switch". A mode enum duplicated what the chain already knows
  (keys, guardian). — A deployment that needs different rules per company adds a company field later; nothing here
  depends on the global scope.
- **R251** **Predicate (same as Solana `has_backup`, RS12-5):** an account **has a backup** ⇔ it holds ≥ 2 active keys,
  or exactly 1 active key and a guardian. "Active" = on chain now (a key being added does not count until its
  owner call / KeyOp is final). A seed-derived key always counts as "written down": `SeedBackup.take()` hands entropy
  to the vault only after the 3-word check (`backup.js`), and an imported phrase was typed by its holder. Two passkeys
  count as two keys even if they sync through one password manager (R254 warns). — One predicate in three languages
  (vectors §4.6); the chain view is the only view every client shares. — A user with two passkeys in one keychain is
  "backed up" by the rule and not in fact; the warning is the mitigation.
- **R252** **Enforcement is in clients and issuers, never in contracts or node intake.** With the switch ON:
  (a) clients (the app, the portal `subject_signers.js`, any clientkeys consumer through `backupStatus`, §4.3) refuse
  to sign a value operation (pay, transfer, unwrap, DEX order, mandate open, Zether transfer/fund) from a subject
  account without backup, and hide its receive address / QR / "fund your meta account" action; (b) issuers refuse to
  issue terms that pay **from or to** a subject account they can check (Odoo: EVM/Hedera `blockchain.subject.account`
  mirror, §4.4); (c) operations that create a backup (add key, add passkey origin, set guardian) are always allowed;
  operations that would destroy it (remove key, set guardian to none) are refused. The node gateway and `/v1/ops`
  do not check. Solana's built on-chain `POLICY_BACKUP_REQUIRED` stays as built: per account, set by the owner key
  with `KeyOp set_policy`, hard; clients offer "make this permanent on chain" on Solana only and never set it
  automatically. — The switch protects the user from losing funds, it is not a security control: bypassing it with a
  custom client harms only that user. The node cannot know that a seed was written down and would need a state read
  per intake on six families; a contract bit on every family costs an audit. — A third-party client ignores the switch
  (by design).
- **R253** **Exits are never blocked; unsatisfiable kinds get exits only.** Where the account kind cannot reach the
  predicate (§4.5: today only the Cosmos passkey-derived address), the client allows only "move the whole balance
  out" with a warning. On satisfiable kinds with the
  switch ON, the only offered actions are the backup flows (add seed key / add passkey / set guardian) — the one key
  the user holds can always sign them, so nobody is stuck. Native single-key accounts (EVM EOA, Stellar `G…`, Cosmos
  secp256k1 address, Solana wallet, Aptos native, Sui native address, Hedera native) are **outside** the predicate:
  a seed-vault key is backed up by construction (R251); an extension wallet's own backup is the wallet's business;
  a **passkey-only native** account (Sui flag-6 address used without `Account<T>`, Cosmos R9-1 address) is not
  offered while the switch is ON. — SCaaS §9.2: "rescue/exit operations are never throttled". — None.
- **R254** **Warnings, both switch states, non-blocking.** At passkey creation the client reads the authenticatorData
  flags **BE** (bit 3, backup eligible) and **BS** (bit 4, backed up) and keeps them in the key's client-side metadata
  (portal: the key row's label data; app: IndexedDB key metadata). A BE = 0 passkey is labelled "this device only";
  an account whose keys are all passkeys of one `rpId` shows "these passkeys may live in the same password manager";
  an account with one key and no guardian shows "no backup" with the add-backup action. — The flags are the only
  signal a browser gives about sync; the chain cannot see them. — Authenticators that misreport BE/BS mislabel a
  key; counting is unaffected.

### 2.2 Device-bound vault (owner item 2) and scrypt

- **R255** **Vault v2 = an outer AES-256-GCM layer under a per-origin non-extractable device key**, around the
  unchanged v1 vault (DEK, passphrase envelope, optional PRF envelope). The device key is a WebCrypto `AES-GCM` 256
  `CryptoKey` generated with `extractable: false`, usages `encrypt`/`decrypt`, stored by structured clone in
  IndexedDB. Default ON for new vaults where IndexedDB and `CryptoKey` cloning work (feature probe at creation); else
  a v1 vault with a one-line notice. Applies to every vault label (`seed`, `zether-conf:…`). — Reuses all of v1;
  one wrap function and one unwrap. — None beyond §5.3.
- **R256** **Device binding does not relax anything.** The passphrase policy (8+ characters, not only digits) and the
  scrypt cost stay. Browser WebCrypto keys are **not hardware-backed**: Chromium and Firefox write the key bytes into
  the profile's IndexedDB files; "non-extractable" only stops page JavaScript from reading them. The gain is narrow
  and real: a vault blob that leaks **without** the profile's IndexedDB (storage dump, log, support export, a file
  sync of one store) cannot be attacked offline at all. Hardware binding exists only through the PRF envelope of a
  BE = 0 passkey (the secret stays in the authenticator); clients prefer such a passkey for PRF when one exists. — A
  short PIN "because the vault is device-bound" would be brute-forced from a copied profile. — None.
- **R257** **Vault and device key live in one IndexedDB database** (`scaas-clientkeys`, store `kv`) so storage eviction
  removes both together; `navigator.storage.persist()` is requested at vault creation and a refusal is shown.
  Portal vaults in `localStorage["dms_chain_seed_vault:<subject>"]` move into IndexedDB on the next successful unlock
  (same moment as `rewrapPin`), then the `localStorage` entry is removed. v1 vaults stay readable forever. — Split
  storage (blob in `localStorage`, key in IndexedDB) can evict one and keep the other: a vault that can never open.
  — One more migration path in `subject_signers.js`.
- **R258** **Recovery after device loss is the recovery phrase**, re-imported on the new device (same derived keys ⇒
  no on-chain action; a new device key wraps a new vault), or another key / guardian recovery on chain (`addKey`,
  `start_recovery`). No vault export. Clearing the site's data equals losing the device; the create flow says so
  before writing a device-bound vault. Zether: `x` is re-derived from the phrase; the balance cache is rebuilt
  (limits §5). — The phrase is already verified at creation and is the only format that survives every browser. —
  A user who skipped writing the phrase down and has no second key loses access (unchanged from today).
- **R259** **scrypt `N = 2^17, r = 8, p = 1` (128 MiB) for every new passphrase envelope** — RS4-14 supersedes
  round-3 R32's `N = 2^15` and its rationale (review S23, mobile hangs): `scryptAsync` yields to the event loop, and
  the passphrase is the fallback unlock (PRF envelope default, RS4-14), so the cost is paid rarely. `N = 2^15`
  vaults keep opening and are re-wrapped after a successful open (`needsRewrap`). If allocation fails at creation
  (`RangeError`), the client stops with "this device cannot create a passphrase vault" and writes nothing weaker.
  — One number in code, plan and SCaaS. — Very low-memory phones cannot create a passphrase vault in the browser; they
  can still import a phrase into an extension wallet.

### 2.3 Sui key verification (owner item 3)

- **R260** **`fam_sui.verify` follows L9 like Aptos and Solana:** `False` only for a malformed signature or one that is
  invalid under the key it carries; `True` when `blake2b256(flag ‖ pk)` = the payer address; **`None`** when the
  signature is valid but the key is not the payer's own (a key added by `KeyOp ADD_KEY` or by `finish_recovery`) — the
  node's simulation arbitrates key membership (R27). The passkey path also refuses `"crossOrigin":true` and
  `"topOrigin"` as `fam_aptos.verify_signature` does. `request.payer_address` stays the `Account<T>` **owner** (the
  first key's address, from which the account id derives); a client signing with an added key sends the owner as
  `from_address` and its own key as `public_key`. — Today a payment signed by an added or recovered key is rejected
  in Odoo with "not from the wallet that started this payment" although the chain would accept it (`a2_pay_sui`,
  `a3_pay_sui` vectors). — A valid signature by a non-member key is queued and dies in simulation (one dead job per
  request; `_live_job` blocks a second until then).
- **R261** **KeyOp is encoded in Python and JS, byte-identical to Move `keyop_digest`:** `fam_sui.keyop_bytes(...)` /
  `keyop_digest(...)` and clientkeys `fam/sui.js` `keyOpBytes` / `keyOpDigest` / `verifyKeyOp(keys, …)` (local check
  before submit, APP R158). Odoo issues no Sui KeyOps (it has no Sui key mirror); clients build them from what the
  user asked for and nothing else (RS4-13 generalised). — One encoding, two languages, one vector file. — None.
- **R262** **One generator run feeds every language:** `gen_vectors.py --json <path>` writes
  `smartcontracts/move/sui/vectors/sui_vectors.json` in the same run that prints `tests/vectors.move` (ECDSA
  signatures are random per run, so two runs would disagree). Odoo `test_fam_sui.py` and clientkeys
  `test/fam_sui.test.js` read the JSON. — Today the cross-language vector is a comment in `vectors.move`. — None.

### 2.4 Non-EVM seed and passkey signers (owner item 4)

- **R263** **Seed signers sign the family's own envelope, built by clientkeys `fam/*` (APP R154), never a server digest
  as such:** Soroban `G…` = ed25519 over `sha256(HashIdPreimage::SorobanAuthorization XDR)` (and the transaction
  envelope hash when self-paid); Soroban `C…` (`scaas-account`) = `Ed25519{key_id, signature}` over the
  `signature_payload`; Aptos = ed25519 over the AIP-62 `fullMessage` the client builds and checks with the same strict
  rules as `fam_aptos.parse_envelope`; Solana = ed25519 over the off-chain message v1 bytes (kind 1, `0xff ‖ "solana
  offchain" ‖ …`), never kind 0 (raw text) for the seed signer. Paths: Stellar `m/44'/148'/i'`, Pi the same with coin
  type 314159, Aptos `m/44'/637'/i'/0'/0'`, Solana `m/44'/501'/i'/0'` (added by APP A0; R155). — The seed signs
  silently; only bytes the client derived from what the user asked for are safe to sign. Kind 1 adds the off-chain
  prefix, so the signed bytes can never parse as a transaction message. — Wallet-compatibility: kind 0 stays accepted
  on chain for extension wallets that lack `signOffchainMessage`.
- **R264** **Non-EVM passkeys reuse one WebAuthn ceremony** (`creationOptions`, `requestOptions`, `derToRS`,
  `publicKeyFromSpki`) **plus one encoder per family** (§8.2): Sui flag-6 serialized signature (pk 33 B), Solana
  `passkey_blob` (pk 33 B, Secp256r1 precompile), Soroban `WebAuthn{…}` ScVal (pk 65 B, CAP-51 host function), Aptos
  WebAuthn blob (pk 65 B, pure-Move `scaas::p256`, UNAUDITED — shown as such in the UI). Order of delivery: Sui →
  Solana → Soroban → Aptos. Cosmos and TON passkeys are not in this round. — Verification maturity decides the order
  (native scheme → precompile → host function → unaudited Move). Cosmos has no multi-key account (a passkey-only
  address fails R251 forever); TON binds one passkey per wallet through `set_key`. — Cosmos/TON users use the seed
  vault or an extension wallet.
- **R265** **Passkey challenge = base64url (no padding) of the family's op digest** (Sui personal-message digest,
  Soroban `signature_payload`, Aptos `sha3_256(MetaOp)`, Solana `sha256(MetaOp)`), the same rule as R31; the
  family "open" challenges (`blake2b256("scaas.open.v1" ‖ registry ‖ pk33)` on Sui, `sha256("scaas.open.v1" ‖
  program_id ‖ pk33)` on Solana, Soroban constructor, Aptos first-key rule) are built by clientkeys `fam/*`. Passkeys
  stay origin-bound (APP R165). — One rule for every verifier. — None.

### 2.5 Connectors (owner item 5)

- **R266** **One connector implementation:** the wallet glue in `bamboo-dms/dms_blockchain_bridge/static/src/js/
  connectors/*.js` (Wallet Standard discovery, Keplr/Leap, Freighter, TON JS bridge, Hedera signer seam, and their
  checks of what the wallet reports as signed) moves to clientkeys `src/wallets/<family>.js` (pure ESM, `window`
  injected for tests), built as lazy entries next to `passkey-signer.js`; the portal loads them with `import()` and
  the app's `src/signers/extension/*` imports the same modules. The portal IIFE copies and their tests are deleted
  in the same change. — Owner: one implementation; today the connectors are unit-tested but **not wired**: they are
  not in the asset bundle and nothing reads `window.dmsChainConnectors` (§9.1). — clientkeys grows a browser-glue
  layer next to its crypto.
- **R267** **`chain_pay.js` dispatches by family** and checks every family's terms before any signer runs:
  `dms_portal_chain_payment_options` adds `family` and `network`; `evm` and Hedera ECDSA keep today's path; other
  families lazy-load `wallets/<family>.js` (extension) or the seed signer's family path (§7); the start/submit RPCs
  stay as they are (start already returns `{family, valid_until, payload_hex, digest, …terms}`, submit already
  takes `public_key`). Before signing, the client rebuilds the payload from the terms and the amount it showed with
  `fam/<family>.js` and refuses a mismatch — RS4-13 extended from EVM seed/passkey to every signer and family. — An
  extension wallet that shows hex gives the user nothing to check; the rebuild is cheap. — A terms change on the
  Odoo side must land with the matching `fam/*.js` change (shared KATs catch it).

### 2.6 Compatibility with spec F

- **R268** **S4F adds no account id, no registry, no key kind.** Key metadata stays keyed by each family's existing key
  encoding; the backup predicate takes "the account's active key set and guardian" as input, so when F lands it is
  evaluated over F's per-account key set; "native single-key ⇒ outside the predicate" (R253) maps to F's unregistered
  native kinds. — Keeps D and F independent. — None.

---

## 3. Spec F "Universal Account": what stays, what moves

| Topic | S4F (here) | Moves to F |
|---|---|---|
| Account identity | Family-native derivations as built: EVM CREATE2 salt `keccak(abi.encode(firstKey, guardian))`; Sui `derive_address(registry, owner)`, owner = `blake2b(flag ‖ pk)`; Aptos `create_object_address(root, "acct" ‖ owner)`; Solana PDA `["acct", owner32]` with passkey-first owner `sha256("scaas.owner.p256" ‖ pk33)`; Cosmos passkey address `bech32(sha256("scaas.passkey.v1" ‖ pk)[..20])` | UA id `H(kind_tag ‖ key data)`, 32-byte kind-tagged ids (no 20-byte truncation sharing the address space), registration rules per kind |
| Which accounts the backup predicate covers | Subject (multi-key) accounts; native single-key accounts outside (R253) | "Native single-key = unregistered kind" is F's taxonomy; the predicate is re-pointed, not changed |
| One key = one purpose | Already true across families and Zether (distinct SLIP-44 coin types, Zether trees `m/12381/…/7`, `m/254/…/7`); passkeys are per `rpId` | Registry refusing a pubkey under a second kind; hardened per-kind derivation. **Existing dual uses for F to rule on:** the EVM seed key `m/44'/60'/0'/0/i` is both an EOA (self-paid gas, APP §6.2 `sendTx`) and a `SubjectAccount` `SECP256K1` key; Sui/Aptos/Solana seed keys are both a native address and the `Account` owner key |
| Tagged signing | KeyOp/open domains per family (`scaas.keyop.v1`, `scaas.open.v1`, `scaas-subject-key-proof-v1`) unchanged | A cross-family tag scheme, if F defines one, replaces these by version bump |
| Attestations (VC/eKYC) | none | all |

---

## 4. Backup-key switch

### 4.1 States a client shows

| Switch | Account | Value ops | Receive / fund | Key ops |
|---|---|---|---|---|
| OFF | any | allowed | shown | all; "no backup" warning (R254) |
| ON | subject, has backup | allowed | shown | all except those that would break the predicate |
| ON | subject, no backup, satisfiable | refused: "Add a backup key first" | hidden | add key, add origin, set guardian |
| ON | subject, unsatisfiable (§4.5) | exit only (whole balance out, warning) | hidden | as the kind allows |
| ON | native single-key (seed vault or extension) | allowed | shown | n/a |
| ON | native passkey-only (Sui flag-6 without `Account<T>`, Cosmos R9-1) | not offered at creation; an existing one: exit only | hidden | — |

### 4.2 Reading the key set (clients)

| Family | Read | Active keys | Guardian |
|---|---|---|---|
| EVM, Hedera | `SubjectAccount.keyCount()`, `keyAt(i)`, `guardian()` (`eth_call`) | `keyCount` | `guardian() != 0x0` |
| Sui | `Account<T>` object fields `keys`, `guardian` (`sui_getObject`, `showContent`) | `keys.length` | `guardian != @0x0` |
| Aptos | `Account` resource of the object (view or `getAccountResource`) | `keys.length` | `option::is_some(guardian)` |
| Solana | `SubjectAccount` PDA (Borsh, §3.3 net-solana) | `keys.len()` | `guardian.is_some()`; also `policy & 1` |
| Soroban | `scaas-account` key list (contract view) | count | none (R8-2 seam) |
| TON | jetton wallet get-methods `pubkey`, `passkey` | `(pubkey ≠ none) + (passkey ≠ none)` | none |

A pending key (EVM key row `pending`, a KeyOp not yet final) does not count. Clients re-read after any key change
reaches finality. No caching across sessions.

### 4.3 clientkeys interface (`src/backup-policy.js`, exported from both signer entries)

```js
/** account: { kind: 'subject' | 'native', satisfiable: boolean, keys: Array<{scheme, be?, bs?, rpId?}>,
 *             guardian: string | null }   — keys = ACTIVE keys only (§4.2). */
export function hasBackup(account) { /* keys.length >= 2 || (keys.length === 1 && !!guardian) */ }

/** Returns { ok, reason: null | 'NO_BACKUP' | 'UNSATISFIABLE' | 'NATIVE_PASSKEY',
 *            allow: { value, receive, exit, addKey, removeKey, setGuardian, clearGuardian },
 *            warnings: Array<'NO_BACKUP' | 'SAME_KEYCHAIN' | 'DEVICE_ONLY'> }.  `required` = the switch. */
export function backupStatus(account, { required }) { … }

/** authenticatorData flags: { up, uv, be, bs } (bits 0, 2, 3, 4). */
export function passkeyFlags(authenticatorData) { … }
```

`checkPayment` / family `checkTerms` (R267) do not call `backupStatus` themselves; the signer UI calls it first and
the signer refuses when `allow.value` is false. Remove-key and clear-guardian owner calls are checked against
`hasBackup(after)`.

### 4.4 Odoo (portal, EVM and Hedera)

- Parameter `dms_blockchain.require_backup_key` (`ir.config_parameter`, `'1'`/`'True'` = ON).
- `blockchain.subject.account._dms_has_backup()` (private): active key rows (`key_state == 'active'`) ≥ 2, or 1 and
  `guardian_address != ZERO_ADDRESS`. `guardian_address` is the creation value (CREATE2 input); a later `setGuardian`
  is not mirrored — accepted, the switch is soft (R252).
- `dms_portal_chain_payment_start` raises `UserError("Add a backup key to your account first.")` when ON and the
  paying subject account has no backup; any future Odoo flow that pays **to** a subject account (refunds, payouts)
  applies the same check.
- `subject_signers.js`: with ON (served in the subject context the portal already fetches), after the first key the
  flow goes straight to "add a backup" (seed if the first key was a passkey, passkey if it was a seed, or "ask your
  administrator for a guardian"), before the first payment.
- Non-EVM families: Odoo cannot check (R20); client enforcement only.

### 4.5 Per-family applicability

| Family | Subject account kind | Max keys | Guardian | Predicate satisfiable | On-chain bit | Odoo checks |
|---|---|---|---|---|---|---|
| EVM | `SubjectAccount` (ERC-1271) | unbounded (`keyCount`) | yes | yes | no | yes |
| Hedera | `SubjectAccount` on HSCS | as EVM | yes | yes | no | yes |
| Sui | `Account<T>` | 8 | yes | yes | no | no |
| Aptos | `Account` object | 8 | yes | yes | no | no |
| Solana | `SubjectAccount` PDA | 8 | yes | yes | `POLICY_BACKUP_REQUIRED` (built, opt-in) | no |
| Soroban | `scaas-account` `C…` | multi | seam (R8-2) | yes, by ≥ 2 keys only | no | no |
| TON | `ScaasJettonWallet` (`pubkey` + one `passkey`) | 2 | seam | yes, by both keys | no | no |
| Cosmos | none (native address; multi-key is a seam) | 1 | no | seed: n/a (native); passkey-only: **no** | no | no |

### 4.6 Tests and vectors

- `clientkeys/test/vectors/backup_policy.json`: rows `{keys: [...], guardian, kind, satisfiable, required}` →
  `{ok, reason, allow}` covering 0/1/2/8 keys, guardian set/unset, native, native passkey, unsatisfiable, both switch
  states, remove-key and clear-guardian transitions. Read by: clientkeys `backup-policy.test.js`; Odoo
  `test_backup_policy.py` (the EVM rows through `_dms_has_backup` on fixture rows); the Solana program's Rust unit
  test of `has_backup` (`include_str!` of the same file, `kind == "subject"` rows).
- `passkeyFlags` against the software authenticator (`test/softauthn.js`) with BE/BS set and clear.
- Odoo: start refused when ON and 1 key + no guardian; allowed after a second active key; allowed when OFF; a
  `pending` key does not count.
- Portal tour (passkey + fake authenticator): switch ON ⇒ first payment blocked, add seed key, pay.
- App (stream A3 e2e): receive hidden, value refused, add-key allowed, exit-only on an unsatisfiable fixture.

---

## 5. Device-bound vault (v2)

### 5.1 Format

The v1 vault (`vault.js`, unchanged):
`{ v: 1, label, data: {iv, ct}, pin: {kdf: 'scrypt', N, r, p, salt, iv, ct}, prf?: {credentialId, salt, iv, ct} }`.

v2 wraps it:

```json
{ "v": 2, "label": "seed", "kid": "device-v1", "iv": "<b64url, 12 B>", "ct": "<b64url>" }
```

- `ct = AES-256-GCM(deviceKey, iv, utf8(JSON.stringify(v1)), aad = "<label>|device|<kid>")`; fresh IV per seal.
- `label` is duplicated outside so a swapped blob fails both the outer AAD and the inner v1 AAD.
- The inner v1 keeps its own envelopes: the device key is required **in addition** to the passphrase or PRF.

### 5.2 Storage and interface

IndexedDB database `scaas-clientkeys`, version 1, object store `kv` (out-of-line keys):

| Key | Value |
|---|---|
| `device-key:v1` | the `CryptoKey` (structured clone; `extractable: false`) |
| `vault:<id>` | a v2 (or, on fallback, v1) vault object. Portal `<id>` = `dms_chain_seed_vault:<subject>` (RS4-15); app `<id>` = `seed:<account label>`; Zether `zether-conf:<curve>:<coin>:<account>` |

New module `src/device.js` (exported from `seed-signer.js` and `zether-keys.js`):

```js
export async function openStore(indexedDB = globalThis.indexedDB)   // → { get(k), put(k, v), del(k) }, or null
export async function deviceKey(store)                               // get, or generate + put, the device key
export async function sealDevice(vaultV1, key)                       // → v2
export async function openDevice(vaultV2, key)                       // → v1 (memory only)
export function needsBinding(stored)                                 // stored.v === 1
```

`openStore` returns `null` when IndexedDB or `CryptoKey` cloning is unavailable (probe: put and get a throwaway
key); callers fall back to v1 (R255). Every call is wrapped in try/catch by the caller; a storage error never
loses the vault in memory before the user has seen the phrase.

### 5.3 Threat model

| Threat | v1 today | v2 | Control that actually helps |
|---|---|---|---|
| XSS while the page is open | reads the blob, can phish the passphrase or wait for unlock, exfiltrates the blob for offline scrypt | same: the device key is a decrypt oracle for any script on the origin | CSP, no third-party scripts, lazy signer chunks (APP R166) |
| Blob leaked alone (storage dump, log, support export, one-store file sync, a browser extension reading `localStorage` only) | offline scrypt attack on the passphrase | **useless**: needs the device key from the same profile's IndexedDB | R255 |
| Browser profile copy (both stores) | offline scrypt attack | same: the key bytes are in the copied IndexedDB files (not hardware-backed, R256) | passphrase strength, scrypt `2^17`; OS disk encryption |
| Stolen disk, no OS encryption | as profile copy | as profile copy | OS full-disk encryption |
| Stolen device, locked | passphrase or PRF (+ UV) needed | same | — |
| Stolen device, unlocked browser | passphrase or PRF needed | same | idle lock (APP §6.2: 5 min) |
| PRF from a synced passkey + leaked blob | opens anywhere the passkey syncs | needs the device key too | R255 |
| PRF from a BE = 0 passkey | hardware-bound | hardware-bound | R256 (prefer such a passkey) |
| Device lost or site data cleared | phrase re-import | phrase re-import; the old blob can never open | R258 |

### 5.4 Migration

1. New vault: `createVault` (v1) → `sealDevice` → `put('vault:<id>')`; `navigator.storage.persist()`.
2. Existing v1 in IndexedDB (app) or `localStorage` (portal, including the legacy bare key `dms_chain_seed_vault`
   handled by RS4-15): after a successful `openVault`, in the same step as `rewrapPin` when `needsRewrap`: seal v2,
   `put`, read back and open once (decrypt check), **then** delete the `localStorage` entry. Any failure keeps the old
   entry.
3. Opening a v2 vault: `openDevice` → v1 → `openVault(v1, unlock)`. A missing device key with a present v2 blob is
   "this vault belongs to a cleared browser profile": the UI offers phrase import only.
4. No downgrade path from v2 to v1 is written; `openDevice` output never leaves memory.

### 5.5 Tests

- Round trip v1 → v2 → v1 with an in-memory store (`Map`; Node 26 has WebCrypto but no IndexedDB).
- Tamper outer `ct`, swap `label`, swap `kid`, wrong device key (second generated key): each fails with the vault
  error, nothing returned.
- `deviceKey` returns the same key on the second call; the key's `extractable` is `false` and
  `crypto.subtle.exportKey` rejects.
- Fixture `test/vectors/vault_v2_fixture.json`: a committed v2 blob plus the raw device-key bytes, imported in the test
  with `extractable: false`; opens to a known entropy — pins the format against accidental change.
- `openStore` returns `null` under a stub `indexedDB` that throws on `put` of a `CryptoKey`; the caller writes v1.
- Portal tour: legacy `localStorage` vault unlocks, becomes `vault:<id>` v2 in IndexedDB, the `localStorage` entry is
  gone; second unlock opens v2.
- `bundle.test.js` (committed bundle == fresh esbuild output) covers the new module.

### 5.6 scrypt

`SCRYPT = { N: 2^17, r: 8, p: 1, dkLen: 32 }` stays (R259). The SCaaS §15.3 contradiction row ("round-3 design R32 says
`N = 2^15`") is resolved by this spec in favour of the code. Test `vault.test.js` already pins both the new
parameters and the re-wrap of a `2^15` vault; add one test that a `RangeError` from the KDF at creation propagates
and no vault is returned.

---

## 6. Sui: verification of added and recovered keys

### 6.1 Facts (code at 28c165c / parent repo)

- `Account<T>` id = `derive_address(registry, owner)`; `owner` = the first key's address, never changes; `keys` ≤ 8;
  `manage(KeyOp…)` signed by any current key adds/removes keys and origins, sets the guardian, cancels recovery;
  guardian `start_recovery(key)` → `finish_recovery` after 172 800 s adds the key (net-sui §3, RS7-3).
- `MetaOp.from` = owner; `relay_pay` accepts a signature from any key in `keys` (`a2_pay_sui`: added ed25519 key;
  `a3_pay_sui`: recovered secp256k1 key — both pass `sui move test`).
- `fam_sui.verify` returns `False` unless `address_of(flag, pk) == request.payer_address` — so Odoo rejects exactly the
  payments R260 must accept. Aptos and Solana already return `None` in that case (their L9).

### 6.2 Python changes (`dms_blockchain/lib/fam_sui.py`, parent repo)

```python
ADD_KEY, REMOVE_KEY, ADD_ORIGIN, REMOVE_ORIGIN, SET_GUARDIAN, CANCEL_RECOVERY = range(6)
KEYOP_DOMAIN = b'scaas.keyop.v1'

def keyop_bytes(network, account, action, scheme, public_key, rp_id_hash, origin, guardian, nonce, valid_until):
    return (_vec(KEYOP_DOMAIN) + _vec(network.encode()) + addr(account) + bytes([action, scheme])
            + _vec(public_key) + _vec(rp_id_hash) + _vec(origin.encode()) + addr(guardian)
            + nonce.to_bytes(8, 'little') + valid_until.to_bytes(8, 'little'))

def keyop_digest(*a, **kw):
    return personal_digest(keyop_bytes(*a, **kw))

def verify(request, payload, signature, public_key):
    try:
        flag, sig, pk, ad, cd = parse_signature(signature)
        own = address_of(flag, pk) == request.payer_address
    except ValueError:
        return False
    if not verify_digest(flag, pk, personal_digest(payload), sig, ad, cd):
        return False
    return True if own else None          # L9: added/recovered key ⇒ the node's simulation decides (R27)
```

`verify_digest` (passkey branch) adds: refuse `b'"crossOrigin":true'` and `b'"topOrigin"'` in `client_data_json`.
`gen_vectors.py` imports `keyop_bytes` instead of its private copy.

Odoo flow: `blockchain.signed.op.signature_verified = False` for `None` (as today for Aptos/Solana); the portal
message for a `False` stays "The signature is invalid or not from the wallet that started this payment."

### 6.3 JS (`clientkeys/src/fam/sui.js`, with APP A0)

`metaOpBytes`, `personalDigest`, `deriveAccount`, `addressOf(flag, pk)`, `parseSignature`, `serializeSignature(flag,
sig, pk)`, `serializePasskey(ad, cd, sig, pk33)` (§8.2), `keyOpBytes`, `keyOpDigest`, and
`verifyKeyOp(account, op, signature)` — checks that the signature verifies under one of `account.keys` (read §4.2)
and that `op.nonce == account.key_nonce`, before the client submits `manage` self-paid or via `/v1/ops`.

### 6.4 Vectors and tests

- `gen_vectors.py --json smartcontracts/move/sui/vectors/sui_vectors.json` (R262). Entries: every `pay` and `keyop`
  vector with `{name, signer {flag, pk}, owner, account, payload_hex | keyop fields, digest, signature_b64}` and
  `{expect_odoo: true | null | false}`.
- Odoo `test_fam_sui.py`:
  `test_added_key_signature_is_left_to_the_node` (`a2_pay_sui` ⇒ `None`),
  `test_recovered_key_signature_is_left_to_the_node` (`a3_pay_sui` ⇒ `None`),
  `test_flipped_byte_from_added_key_is_refused` (⇒ `False`),
  `test_own_key_still_verified` (`a_pay_sui_0` ⇒ `True`),
  `test_passkey_cross_origin_refused`,
  `test_keyop_bytes_match_move` (every `k_*` vector), and the existing
  `test_signature_from_another_wallet_is_refused` is narrowed to "invalid under its own key" (a valid signature from
  another key is now `None`).
- clientkeys `fam_sui.test.js`: same JSON — `keyOpDigest` equals every `k_*` digest; `verifyKeyOp` true for the
  vector signer on the right nonce, false on a wrong nonce, a non-member key, a flipped byte.
- `sui move test` unchanged (vectors regenerated by the same run).

---

## 7. Seed signers: Soroban, Aptos, Solana

### 7.1 Matrix (all families, for reference)

| Family | `NETWORKS` key | Path | Curve | Address / key id | Seed signer signs | Status |
|---|---|---|---|---|---|---|
| EVM | `evm` | `m/44'/60'/0'/0/i` | secp256k1 | keccak address | EIP-712 digest | BUILT |
| Hedera ECDSA | `hedera_ecdsa` | `m/44'/3030'/0'/0/i` | secp256k1 | EVM alias | EIP-712 digest | BUILT |
| Hedera ED25519 | `hedera_ed25519` | `m/44'/3030'/0'/0'/i'` | ed25519 | `0.0.N` (mirror) | raw ed25519 over EIP-712 digest (HIP-632) | BUILT |
| Cosmos | `cosmos` | `m/44'/118'/0'/0/i` | secp256k1 | bech32 ripemd160(sha256) | ADR-036 doc (`fam/cosmos.js`, A0) | key BUILT, envelope A0 |
| Sui | `sui` | `m/44'/784'/i'/0'/0'` | ed25519 | `blake2b(0x00 ‖ pk)` | personal-message digest, flag 0 serialized | key BUILT, envelope A0 |
| TON | `ton` | `m/44'/607'/i'` | ed25519 | pubkey (wallet `BindKey`) | MetaOp cell hash (`fam/ton.js`, A0) | key BUILT, envelope A0 |
| **Soroban** (Stellar) | `stellar` | `m/44'/148'/i'` (SEP-0005) | ed25519 | `G…` StrKey | `G…`: sha256(auth-entry preimage); `C…`: `Ed25519{key_id, signature}` over `signature_payload` | key BUILT; **R263** |
| **Soroban** (Pi) | `stellar` + `coinType 314159` | `m/44'/314159'/i'` | ed25519 | `G…` | as Stellar, Pi network passphrase | key BUILT; **R263** |
| **Aptos** | `aptos` | `m/44'/637'/i'/0'/0'` | ed25519 | `sha3_256(pk ‖ 0x00)` (legacy auth key) | AIP-62 `fullMessage` (client-built) | key BUILT; **R263** |
| **Solana** | `solana` (A0) | `m/44'/501'/i'/0'` | ed25519 | base58 pk | OCMS v1 bytes (kind 1) | **R263** + A0 |

TON keys from `m/44'/607'/i'` remain importable only as "BIP-39/Ledger path" (SCaaS §9.5).

### 7.2 Interface (`src/fam/<family>.js`, consumed by the seed signer)

```js
// Every family module exports:
export function checkTerms(terms, shown)  // rebuild payload from terms + what the UI showed; throws "Refusing to sign: …"
export function signingInput(terms, key)  // → { bytes, kind }  exactly what the key signs (envelope, preimage hash, OCMS)
export function packSignature(terms, key, sig) // → { signature, publicKey } in the submit format Odoo / /v1/ops expect
```

Seed signer (`seed-signer.js` additions): `signFamily(key, family, terms, shown)` =
`checkTerms` → `signingInput` → `ed25519.sign` / `secp256k1` (`signDigest` for 32-byte inputs) → `packSignature`.
`shown` = `{ amount, decimals, payee, account }` as rendered.

Per family:

- **Soroban `G…`:** `signingInput` = `sha256(XDR(HashIdPreimage::SorobanAuthorization{network_id, nonce,
  signature_expiration_ledger, invocation}))` from `fam/soroban.js` (port of `fam_soroban.py`, A0); `packSignature` =
  hex of the 64-byte signature, `publicKey` = the `G…` StrKey (Odoo `fam_soroban.verify` accepts StrKey or hex).
  Self-paid: the transaction envelope hash `sha256(network_id ‖ ENVELOPE_TYPE_TX ‖ tx XDR)` is signed only through
  the adapter's `buildSelfPaid` (APP §5.1), never through `signFamily`.
- **Soroban `C…`:** `signingInput` = the 32-byte `signature_payload`; `packSignature` = XDR hex of ScVal
  `Signature::Ed25519{key_id, signature}` with `key_id` as the account stores it (vector from the account contract
  tests, §7.3).
- **Aptos:** `signingInput` = UTF-8 of `"APTOS\n"` + the envelope lines the client builds (`application` from config
  / Odoo `aptos_application`, `chainId`, `message = "scaas.metaop.v1:0x<digest>"`, `nonce = <lane hex>`) in the order
  `parse_envelope` accepts; the client runs the JS port of `parse_envelope` on its own output before signing.
  `packSignature` = `sig64 ‖ fullMessage` hex, `publicKey` = 32-byte pk hex.
- **Solana:** `signingInput` = `0xff ‖ "solana offchain" ‖ 0x01 ‖ 0x01 ‖ pk32 ‖ T` with
  `T = "scaas.metaop.v1:" ‖ hex(digest)` (the exact `expected` bytes of today's connector, OCMS v1);
  `packSignature` = `[1, 0] ‖ sig64` hex (kind 1, key index 0 for the first key; the account's index for an added
  key), `publicKey` = pk hex.

### 7.3 Vectors and tests

- `clientkeys/test/vectors/solana_derivation.json`: the BIP-39 test mnemonic (`abandon ×11 about`, empty passphrase)
  → pk and base58 address for `i = 0, 1, 2` at `m/44'/501'/i'/0'`, produced with `solana-keygen` (`prompt://?key=i/0`)
  and confirmed by an independent SLIP-10 implementation before commit; `deriveKey(seed, 'solana', i)` must match.
- Stellar/Pi: existing SEP-0005 and Pi tests (`seed.test.js`) stay.
- `fam_soroban.json`, `fam_aptos.json`, `fam_solana.json` (exported by A0 from the Python tests): plus, for this spec,
  per family one **seed-signed** vector — fixed seed, path, terms → `signingInput` bytes, signature, packed submit
  value — asserted in JS and re-verified in Python by `fam_<family>.verify` (expect `True` for the owner key).
- Soroban `C…`: one `Ed25519` ScVal vector exported from `smartcontracts/soroban/contracts/account` tests
  (`cargo test`, real `set_auths`), asserted byte for byte by `packSignature`.
- Refusals: each `checkTerms` refuses a different amount, payee, account, network/chain id, token/asset, a payload
  with a fee/relayer the UI did not show, and malformed terms (≥ 6 cases per family, as `evm.test.js` does for EVM).

---

## 8. Passkey signers on non-EVM families (A16 content)

### 8.1 Availability matrix

| Family | On-chain P-256 | Account that stores the passkey | pk encoding | Origin binding | Status |
|---|---|---|---|---|---|
| EVM | RIP-7212 `0x100` or OZ Solidity P-256 | `SubjectAccount` | `(x, y)` + `rpIdHash`, `keccak(origin)` | per key | BUILT |
| Hedera | as EVM (HSCS) | `SubjectAccount` | as EVM | per key | BUILT (app A3) |
| Sui | native `secp256r1_verify`, Sui passkey flag 6 | `Account<T>` (`open_passkey`) | 33 B compressed | `origins` ≤ 8 | contract BUILT; **client R264 #1** |
| Solana | precompile `Secp256r1SigVerify1111…` (SIMD-0075), low-S enforced, ≤ 8 sigs/ix | `SubjectAccount` PDA (`open_passkey`) | 33 B compressed | `origins` ≤ 8, same-rpId add rule | contract BUILT; **client #2** |
| Soroban | host `secp256r1_verify` (CAP-51), high-s rejected by host | `scaas-account` `C…` | 65 B uncompressed | per key | contract BUILT; **client #3** |
| Aptos | none native in Move; pure-Move `scaas::p256` (UNAUDITED, ≈ 4 100 execution gas/sig) | `Account` object; passkey-first auth key `sha3_256(0x02 ‖ 0x41 ‖ pk65 ‖ 0x02)` | 65 B uncompressed | `origins` | contract BUILT (unaudited); **client #4** |
| Cosmos | cosmwasm-std 2.1 `secp256r1_verify` | none (R9-1 derived address only) | 33 B | none | not this round (R264) |
| TON | TVM `P256_CHKSIGNS` | `ScaasJettonWallet` (one passkey via `set_key`) | 33 B + `rpIdHash` + `originPrefix` | origin prefix | not this round (R264) |

### 8.2 Encoders (`src/fam/<family>.js`)

| Family | Open (first key) | Pay signature format | Submit `public_key` |
|---|---|---|---|
| Sui | assertion over `blake2b256("scaas.open.v1" ‖ registry ‖ pk33)`; `open_passkey(registry, pk33, auth)` | base64 `0x06 ‖ uleb(len ad) ad ‖ uleb(len cd) cd ‖ uleb(98) (0x02 ‖ r‖s ‖ pk33)` (`fam_sui.parse_signature`) | — (in the signature) |
| Solana | assertion over `sha256("scaas.open.v1" ‖ program_id ‖ pk33)`; owner `sha256("scaas.owner.p256" ‖ pk33)` | `[2, key_index] ‖ r‖s ‖ u16le(len ad) ‖ ad ‖ cd` (`fam_solana.passkey_blob`), plus the precompile instruction in the outer tx (relayer or self-paid) | pk33 hex |
| Soroban | constructor `__constructor(first_key)` with the passkey key (deploy needs no auth) | ScVal `Signature::WebAuthn{key_id, authenticator_data, client_data_json, signature (r‖s low-s), proof}` XDR | — |
| Aptos | first-key rule net-aptos §3 (RS11-14) | `r‖s ‖ u16be(len ad) ‖ ad ‖ cd` (`fam_aptos` docstring) | pk65 hex |

`r‖s` always comes from `derToRS` (strict DER, low-s normalised). `pk33` = SEC1 compression of `(x, y)` from
`publicKeyFromSpki`; `pk65` = `0x04 ‖ x ‖ y`. Merkle batching (one assertion for many ops) stays EVM-only; the
other families sign one op per assertion (net-sui §2.2 seam).

### 8.3 Tests

- Per family, the existing chain test vectors made with the software authenticator (Sui `gen_vectors.py` `d_*`,
  Solana/Soroban/Aptos test suites) are re-encoded by `fam/*.js` from their `(authenticatorData, clientDataJSON, DER
  signature, SPKI)` inputs and must match the chain-side bytes; the chain tests are the second language.
- JS-side refusals: wrong challenge, missing UV, high-s input normalised, cross-origin assertion refused, wrong pk
  length.
- Python: `fam_sui.verify` / `fam_solana.verify` / `fam_aptos.verify` on the new client-encoded vectors give the L9
  answer (`True` for passkey-first owner on Sui/Aptos, `None` on Solana passkey per its L9, `None` on Soroban `C…`).
- Per-family e2e in APP A11 (Sui), A14 (Solana), A10 (Soroban), A12 (Aptos) with a virtual authenticator
  (Playwright `WebAuthn.addVirtualAuthenticator`).

---

## 9. Portal connectors (`chain_pay.js`) and the shared implementation

### 9.1 Today (parent repo, read)

| Piece | State |
|---|---|
| `chain_pay.js` | EVM only: EIP-6963 discovery, EIP-1193 fallback, WalletConnect factory seam (R21), `eth_signTypedData_v4`, `eth_getCode` kind (R27), submit + poll; reads `start.typed_data.message.validUntil`, which a family start does not have |
| `subject_signers.js` | passkey + seed for EVM `SubjectAccount` (clientkeys bundle via `import()`) |
| `connectors/{aptos,cosmos,hedera,solana,soroban,sui,ton}.js` | IIFEs registering `window.dmsChainConnectors.<family>`; each has a node test in `static/tests/connectors/` |
| `__manifest__.py` assets | only `chain_pay.js` + `subject_signers.js`; **no connector is bundled**, nothing reads `dmsChainConnectors` |
| `dms_portal_chain_payment_options` | no `family` field |
| `dms_portal_chain_payment_start` / `_submit` | family-ready: start returns `{family, valid_until, payload_hex, digest, …terms}`; submit takes `public_key` |

So non-EVM portal payments are server-ready and client-unwired.

### 9.2 Target layout (clientkeys)

```
clientkeys/src/
  fam/<family>.js        encoders + checkTerms/signingInput/packSignature (A0 + §7, §8)
  wallets/<family>.js    extension glue moved from the portal connectors (R266)
  wallets/evm.js         EIP-6963 discovery + walletKind (moved from chain_pay.js; the app's eip6963 signer uses it)
  wallet-signer.js       new lazy entry: re-exports wallets/* by family (one chunk per family via splitting)
```

Wallet module interface (same as the portal connectors today, made explicit):

```js
export function create(win = globalThis) {          // injected window ⇒ node tests without a browser
  return {
    family, label,
    available(): boolean, wallets(): string[],
    connect(name?): Promise<{ address, publicKey }>,
    sign(terms): Promise<{ signature, publicKey }>,  // checks what the wallet reports as signed (as today)
  };
}
```

Build: `package.json` `build` adds `src/wallet-signer.js` to the esbuild entry list (same `--splitting`, same out
dir `dms_blockchain_bridge/static/lib/clientkeys/`); `bundle.test.js` keeps the byte-identical check. The app
imports the same modules from the workspace (`../clientkeys`, APP §3.2).

### 9.3 `chain_pay.js` flow

```
options = dms_portal_chain_payment_options(order)            // + family, network
signer  = family in {evm, hedera(ECDSA)} ? today's chooser
        : choose among [wallets/<family> extension(s), seed vault (subject_signers family path)]
start   = dms_portal_chain_payment_start(order, signer.from, wallet_id)
fam     = await import('…/fam-<family>.js');  fam.checkTerms(start, shown)     // R267, every signer
{signature, publicKey} = await signer.sign(start)
validUntil = start.typed_data ? start.typed_data.message.validUntil : start.valid_until
status  = dms_portal_chain_payment_submit(start.reference, validUntil, signature, kind, publicKey)
```

`shown` = the amount, currency and payee text the portal displayed for the option. Polling, terminal failures and
wallet-switch guards stay as they are (the guard applies to EIP-1193 only; Wallet Standard accounts are re-checked at
`sign`).

Odoo changes (parent repo): options add `'family': w.chain_id.family, 'network': w.chain_id.network_key`; nothing else
server-side. Hedera ED25519 native accounts keep the `window.dmsHederaSigner` seam (APP §1.2: HashPack prefixes
messages) and the seed vault path.

### 9.4 Tests

- The seven connector node tests move to `clientkeys/test/wallets/*.test.js` unchanged in substance (fake wallets,
  `vm` realm replaced by an injected `win`); the portal copies are deleted.
- `chain_pay` unit (node, injected `window`): family dispatch picks the right module; `checkTerms` refusal stops
  before `sign`; `validUntil` from `start.valid_until`.
- Odoo: `test_options_carry_family_and_network`.
- Portal tours: Sui (fake Wallet Standard wallet with `sui:signPersonalMessage` over a fixed ed25519 key) and Solana
  (fake `solana:signOffchainMessage`) end to end to `signed_op` queued; one seed-vault tour on Aptos (fake
  authenticator not needed). One heavy Odoo test run at a time.

---

## 10. Streams

One agent at a time; at most one heavy build or Odoo test run at a time on this box. Each stream ends with its gate
green and a line in `TODO.md`. Parent-repo changes (Odoo, portal) are separate commits in `bamboo-dms`.

| Stream | Content | Repo | Depends on | Gate |
|---|---|---|---|---|
| **D1** policy | `backup-policy.js` (`hasBackup`, `backupStatus`, `passkeyFlags`), `backup_policy.json`, scrypt `RangeError` test, Solana Rust test reading the JSON | scaas | — | `npm test` (clientkeys), `cargo test` (solana program unit) |
| **D2** vault v2 | `device.js`, v2 seal/open, fixture, `seed-signer`/`zether-keys` exports; portal migration in `subject_signers.js` (`localStorage` → IndexedDB) | scaas + bamboo-dms | — | `npm test` + bundle check; portal seed tour |
| **D3** Sui verify | `fam_sui` L9 `verify`, `keyop_bytes/digest`, passkey cross-origin refusal; `gen_vectors.py --json`; Odoo tests | bamboo-dms + scaas (vectors) | — | Odoo `test_fam_sui`; `sui move test` |
| **D4** non-EVM seed signers | `signFamily`; Soroban/Aptos/Solana `checkTerms`/`signingInput`/`packSignature`; `solana_derivation.json`; seed-signed vectors re-verified in Python | scaas | APP **A0** (`fam/*` ports, `NETWORKS.solana`) | `npm test`; Python vector re-verify |
| **D5** connectors | `wallets/*` move, `wallet-signer.js` entry, `chain_pay.js` family dispatch + `checkTerms`, options `family`/`network`, manifest unchanged (lazy `import()`), tours | scaas + bamboo-dms | A0, D4 | `npm test`; Odoo tests + Sui/Solana/Aptos tours |
| **D6** switch wiring | Odoo parameter, `_dms_has_backup`, start refusal, portal add-backup flow; app `policy.requireBackupKey` + gating (inside APP A3) | bamboo-dms (+ app via A3) | D1 | Odoo tests + passkey tour with switch ON |
| **D7** = APP A16 | non-EVM passkeys: Sui → Solana → Soroban → Aptos encoders (§8.2) and flows | scaas (+ app) | A0, D4; APP A11/A14/A10/A12 for the e2e of each family | per-family vectors + e2e |

Order for one agent: D1 → D3 → D2 → (A0) → D4 → D5 → D6 → D7. D1–D3 need nothing from the app streams.

---

## 11. Open questions (owner)

| # | Question | Default if unanswered |
|---|---|---|
| Q1 | Soroban and TON have no guardian (seams R8-2, R10-6), so "1 key + guardian" cannot be met there; with the switch ON those users need two keys (TON: the ed25519 key **and** the one passkey). Build the guardian seams, or accept "≥ 2 keys" on those two families? | **Decided (owner 2026-10-06): accept ≥ 2 keys on Soroban and TON; no guardian work.** |
