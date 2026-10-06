# Signers and wallet follow-ups (S4): backup-key switch, device-bound vault, Sui key verification, non-EVM signers, portal connectors (component spec D)

Status: draft **rev 1.1**, 2026-10-06. Rev 1.1 applies independent review 1 (FIX-THEN-GO: H1–H3, M1–M8, L1–L7;
disposition in §12). It also folds in spec F rev 1.2 (R300 role paths, one key = one purpose) and the app spec rev 1.2
(H4 de-duplication, the per-family split of D4/D5, D7 after A10–A14). Component spec **D**. Short name **S4F**.

Code at `scaas` `main` 28c165c: clientkeys 1.0.0 has passkey + seed vault + Zether keys BUILT and EVM-only family
encoders. The parent repo `bamboo-dms` was read for the Odoo side (`dms_blockchain/lib/fam_*.py`,
`dms_blockchain_bridge/static/src/js/**`). **Nothing in this spec is built.**

Rulings: **R250–R269** (§2). Other specs: R150–R179 app, R180–R199 spec B (TSS), R200–R217 spec A (AS),
R230–R247 spec C (OPS), R270–R289 spec E, R290–R318 spec F (UA).

Owner rulings folded in:
- the S4 follow-up queue of 2026-10-04/05: backup-key switch, default OFF, a toggle only; device-bound vault; Sui
  `fam_sui.verify` for added and recovered keys; Soroban/Aptos/Solana seed + passkey signers; `chain_pay.js`
  connectors with one implementation;
- Soroban and TON satisfy the backup rule with **≥ 2 keys** (they have no guardian);
- market neutrality;
- spec F: R300 role paths and one key = one purpose (§3).

Requirements and sources:

| Short | File | Section |
|---|---|---|
| SCaaS | `docs/SCaaS.md` | §9.2 (exits never throttled), §9.3–§9.5 |
| R3 | `specs/2026-10-03-blockchain-round3-design.md` | §C.1–C.4, R31–R33 |
| RS4 | `plans/2026-10-03-r3-passkey-seed.md` | RS4-1…RS4-16 |
| ADW | `specs/2026-10-03-blockchain-payments-addendum-wallets.md` | §B, R21, R27 |
| APP | `specs/2026-10-06-scaas-app-design.md` rev 1.2 | R154, R155, R165 (H4), R175 (key worker), R176, §6.2–§6.4, §15, §17 |
| UA | `specs/2026-10-06-universal-account-design.md` rev 1.2 | R298, R300, §8.1, §8.3 (`keyop` purpose), §10, §11.4, §12, §16 F3 |
| NET | `specs/2026-10-03-net-{sui,soroban,cosmos,ton}.md`, `2026-10-04-net-{aptos,solana}.md` | Sui §2–§3 (RS7-3), Soroban §3 (R8-2), Aptos L9/RS11-3/RS11-14, Solana L9/RS12-4/RS12-5 |

Amends (status changes only):

| Short | File | How |
|---|---|---|
| SCaaS | `docs/SCaaS.md` §9.4, §9.5 | the backup toggle and the Solana path go from PLANNED to SPECIFIED, with a link here. The §9.4 mode list is **replaced** by R250–R254 |
| R3 | round-3 design R32 | scrypt `N = 2^15` is superseded by RS4-14 / R259 (`N = 2^17`); this closes the SCaaS §15.3 contradiction row |
| NET Solana | RS12-5 | the predicate is settled (R251). The on-chain bit stays opt-in, and it counts keys without de-duplication (§4.6) |
| APP | R155, R165, R176, §15 | adopted as written: H4 de-dup and the `msig` rule (R251); streams D4-<f>/D5-<f>/D5-evm (§10) |

---

## 1. Scope and non-goals

### 1.1 In scope

1. A deployment switch "backup key required" (default OFF): its predicate, the flows, and where it is enforced (§4).
2. Vault v2, bound to the device by a non-extractable WebCrypto key: threat model, migration, recovery (§5).
3. One scrypt cost, with the mobile failure mode handled (§5.6).
4. Sui `fam_sui.verify` for added and recovered keys, the KeyOp encoding in Python and JS, and vectors (§6).
5. Role keys (`deriveRoleKey`, F R300 path), and seed signers for Soroban, Aptos and Solana (§7).
6. Non-EVM passkey signers. This is the content of APP A16 = D7 (§8).
7. Portal connectors for every family, as one implementation shared with the app (§9).

### 1.2 Non-goals

| Not here | Why / where |
|---|---|
| UA ids, the registry, kind tags, `UAKey`/`signUA`, VC/eKYC | Spec F (F0–F4). D's `deriveRoleKey` is the plain derivation that F3 wraps |
| New contract code (a backup bit on EVM/Sui/Aptos, Soroban/TON guardians, Soroban duplicate-key check) | Owner: the switch is only a toggle; Soroban/TON use ≥ 2 keys. Client de-dup covers duplicates (R251) |
| KMS/HSM, `SigningPolicyService`, FROST/MuSig2 signers | SCaaS §9.1, §9.2, §9.7 |
| WalletConnect / TON Connect HTTP bridge | R21 seam; APP §1.2 |
| Odoo mirrors of non-EVM key sets | R20; node simulation arbitrates (R27) |
| Argon2id | No WebCrypto primitive; a wasm dependency without a measured need |
| Vault export between devices; showing the phrase again | R258: the phrase on paper is the transfer format |

---

## 2. Rulings

Format: **ruling**. Why. Cost if wrong.

### 2.1 Backup-key switch (owner item 1)

- **R250** **"Backup key required" is one boolean deployment switch, default OFF.** It exists once per onboarding
  surface:
  - app `config.json` `policy.requireBackupKey`;
  - Odoo `ir.config_parameter` `dms_blockchain.require_backup_key` (absent = OFF);
  - an argument to the clientkeys helper (clientkeys reads no configuration).

  The SCaaS §9.4 per-account mode list and its "device_bound refused" rule are dropped.
  Why: owner, "only a switch". Cost if wrong: per-company rules later need a company field.
- **R251** **Predicate: an account has a backup iff it holds ≥ 2 distinct active keys, or exactly 1 and an
  independent guardian.**
  - **Distinct** means the canonical public keys differ (UA §8.2): P-256 `x`, secp256k1 address (EVM `SECP256K1`
    keys are addresses) or x-only, ed25519 `pk`. One credential on two origins counts **once** (APP H4). So does a
    Soroban key added twice, or a Sui key under two `rp_id_hash` values.
  - **Active** means final on chain.
  - **Independent guardian**: the guardian is neither the account itself nor the native address of any key in the
    set. Native addresses: EVM key address; Sui `blake2b(flag ‖ pk)`; Aptos auth keys; Solana pk; and so on.
  - **`msig` UA** (APP R176): backed up iff `Σweights − max(weight) ≥ threshold`.
  - A seed key counts as "written down". Only phrases that passed the 3-word check (`SeedBackup`) or were typed in by
    their holder reach a key.

  Why: duplicates and self-guardians are exactly the false "backed up" state the switch exists to prevent. Cost if
  wrong: two passkeys in one password manager still count as two (R254 warns).
- **R252** **Enforcement is in clients and issuers, never in contracts or node intake.** With the switch ON:
  1. **Value ops are refused** from a subject account without backup: pay, transfer, unwrap, DEX order, mandate
     open, Zether transfer/fund. Its receive address, QR and "fund your meta account" are hidden.
  2. **Issuers refuse to issue terms** that pay from or to an account they can check. Today that is only Odoo with
     EVM/Hedera mirrors (§4.4).
  3. **Key operations stay open.** Add key, set guardian and add origin are always allowed. Add origin never creates
     a backup. **Remove key and clear guardian are always allowed**, with a warning. Afterwards the account may be
     in the no-backup state (§4.7). Revoking a stolen key or a hostile guardian is never blocked.

  The node does not check. Solana's built `POLICY_BACKUP_REQUIRED` stays per account and owner-set. Clients offer
  "make this permanent on chain" on Solana only, never automatically.
  Why: the switch protects users from loss and is not a security control. Cost if wrong: a third-party client
  ignores it, by design.
- **R253** **Exits are never blocked, in any state** (SCaaS §9.2). "Move the whole balance out" (with a warning) is
  allowed:
  - on a satisfiable account without backup (funded before the switch or after a key removal), next to the backup
    flows;
  - on an **unsatisfiable** account, as the only value op. Unsatisfiable kinds: Cosmos passkey-derived address,
    passkey-only native address (Sui flag 6 without `Account<T>`), single-key derived UA (APP R176).

  Native single-key accounts with a seed-vault or extension key are outside the predicate: an EOA, `G…`, Cosmos
  secp256k1, Solana or Aptos wallet, Sui address, Hedera native. Unsatisfiable kinds are not offered at creation
  while the switch is ON.
  Why: rescue is never throttled. Cost if wrong: none.
- **R254** **Warnings, non-blocking, in both switch states.**
  - BE/BS (authenticatorData bits 3 and 4) are read from each creation and assertion and cached client-side only.
    Nothing is stored in Odoo.
  - A BE = 0 passkey is labelled "this device only (as reported)".
  - "These passkeys may share one password manager" is shown when ≥ 2 passkeys of one `rpId` all report BS = 1.
  - "No backup" is shown with the add-backup action.

  Why: the flags are the only sync signal and are self-reported (`attestation: 'none'`). Cost if wrong: a
  misreporting authenticator mislabels a key; counting is unaffected.

### 2.2 Device-bound vault (owner item 2) and scrypt

- **R255** **Vault v2 is an outer AES-256-GCM layer under a per-origin non-extractable device key**, wrapped around
  the unchanged v1 vault (DEK, passphrase envelope, optional PRF envelope).
  - The device key is WebCrypto `AES-GCM` 256, `extractable: false`, kept as a structured clone in IndexedDB.
  - It is the default for new vaults where the IndexedDB/`CryptoKey` probe passes; otherwise a v1 vault is written,
    with a notice.
  - It applies to every label (`seed`, `zether-conf:…`).
  - `kid` exists only for a future format bump; there is no key rotation flow.

  Why: all of v1 is reused. Cost if wrong: see §5.3.
- **R256** **Device binding relaxes nothing.** The passphrase policy and scrypt stay.
  - WebCrypto keys are **not hardware-backed** on Chromium and Firefox: the key bytes sit in the profile's IndexedDB
    files. Safari wraps them under a Keychain key, which is stronger.
  - The gain is narrow: a blob that leaks **without** the profile's IndexedDB cannot be attacked offline.
  - PRF from a passkey reported as not synced (BE = 0) is preferred. It is still not "hardware-bound": the PRF output
    reaches page JS, so a script running during one unlock gets a permanent unwrap key for that blob. v2 still
    demands the device key on top.

  Why: honest claims. Cost if wrong: none.
- **R257** **Storage and migration.** The vault and the device key share one IndexedDB database (`scaas-clientkeys`,
  store `kv`), so eviction removes both together.
  - **Precedence:** if `vault:<id>` exists in IndexedDB it wins, and migration never `put`s over an existing
    `vault:<id>`.
  - A migrated portal `localStorage` vault is **replaced by a tombstone** `{"v":2,"moved":"indexeddb"}`, not deleted.
    Old cached portal code then fails with "Unknown vault version." instead of offering "create a new phrase".
  - The post-write check is `openDevice(readBack)` deep-equal to the in-memory v1 object. That is AES-GCM only: no
    second scrypt and no second unlock.
  - `navigator.storage.persist()` is requested at creation. A refusal is shown once per device.

  Why: no rollback to a stale weaker blob, no silent new seed, no second 128 MiB KDF. Cost if wrong: one more
  migration path in `subject_signers.js`.
- **R258** **Recovery after device loss is the recovery phrase**, re-imported on the new device (same keys, a new
  device key and vault). The alternative is another key or guardian recovery on chain. There is no vault export.
  - Clearing the site's data, or Safari ITP's 7-day script-storage eviction, equals losing the device. The create
    flow says so.
  - **The phrase is never shown again**, by any flow. A user who lost the paper creates a new backup key (§4.7) and
    removes the old one.

  Why: a re-reveal path would undermine R251's "written down". Cost if wrong: a lost paper means a key rotation.
- **R259** **scrypt `N = 2^17, r = 8, p = 1` (128 MiB) for every new passphrase envelope.** RS4-14 supersedes
  round-3 R32 (`N = 2^15`).
  - The passphrase is the fallback unlock (PRF is the default), and `scryptAsync` yields to the event loop.
  - The failure on low-memory phones is an **allocation error or a renderer kill**. A thrown error at creation
    stops the flow with "this device cannot create a passphrase vault", and nothing weaker is written.
  - The `N = 2^15` → `2^17` re-wrap runs **after the payment is submitted**, never inside the unlock that precedes it.
    It is guarded by a marker `rewrap-attempt:<id> = N` written before the attempt. If the marker is present on the
    next load, the re-wrap is skipped (no crash loop). The same marker is used in the app's key worker (APP R175).
  - On open, a pin envelope outside `N ∈ {2^15, 2^16, 2^17}, r = 8, p = 1` is refused.

  Why: one number in code, plan and SCaaS, and no device is locked out by its own upgrade. Cost if wrong: very
  low-memory phones use a paper backup (§4.7) or an extension wallet.

### 2.3 Sui key verification (owner item 3)

- **R260** **`fam_sui.verify` follows L9, like Aptos and Solana:**
  - `False` for a malformed signature or one invalid under its own key;
  - `True` when `blake2b256(flag ‖ pk)` = the payer address. This means "the payer's own key", **not** "will pass":
    an owner key removed by KeyOp still returns `True`;
  - `None` for a valid signature by any other key (added by `KeyOp ADD_KEY` or by `finish_recovery`). The node's
    simulation decides (R27).

  The passkey path also refuses `"crossOrigin":true` and `"topOrigin"`. `request.payer_address` stays the
  `Account<T>` owner.
  Why: today Odoo rejects payments the chain accepts (`a2_pay_sui`, `a3_pay_sui`). Settlement is driven only by chain
  events, so `None` can never mark anything paid. Cost if wrong: a valid signature from a non-member key queues one
  dead job per request, which needs portal access to the order.
- **R261** **KeyOp is encoded in Python and JS, byte-identical to Move `keyop_digest`**, with the domain as a
  parameter. F §8.3 replaces `scaas.keyop.v1` by a version bump.
  - Python: `fam_sui.keyop_bytes/keyop_digest`.
  - JS: clientkeys `fam/sui.js` `keyOpBytes/keyOpDigest/verifyKeyOp`. The JS check covers membership, `op.nonce ==
    key_nonce`, `op.account`, `op.network`, the `valid_until` window and, for passkeys, origin ∈ `account.origins`.

  Odoo issues no Sui KeyOps; clients build them from what the user asked for (RS4-13).
  Why: one encoding, local check before submit (APP R158). Cost if wrong: none.
- **R262** **One generator run feeds every language.** `gen_vectors.py --json` writes
  `smartcontracts/move/sui/vectors/sui_vectors.json` in the same run as `tests/vectors.move`, because ECDSA signatures
  are random per run. The JSON carries `sha256(vectors.move)`; Odoo and clientkeys tests compare it to the file
  (partial regeneration fails). `scaas-node/src/adapters/sui.rs` pins only the deterministic ed25519 `a_pay_sui_0`
  vector and is unaffected.
  Why: today the cross-language vector is a comment. Cost if wrong: none.

### 2.4 Role keys and non-EVM signers (owner item 4, F R300)

- **R263** **Seed signers sign the family's own envelope, built and checked by clientkeys `fam/*`**, never a server
  digest as such:
  - Soroban `G…`: ed25519 over `sha256(HashIdPreimage::SorobanAuthorization)`. Soroban `C…`: `Ed25519{key_id,
    signature}` over `signature_payload`.
  - Aptos: ed25519 over the client-built AIP-62 `fullMessage`.
  - Solana: off-chain message v1 (kind 1) only. Kind 0 is for extension wallets only (APP R155).

  Native paths: Stellar `m/44'/148'/i'`, Pi with coin type 314159, Aptos `m/44'/637'/i'/0'/0'`, Solana
  `m/44'/501'/i'/0'` (APP A0-evm adds `NETWORKS.solana`).
  Why: the seed signs silently. Cost if wrong: none.
- **R264** **Non-EVM passkeys reuse one WebAuthn ceremony plus one encoder per family** (§8.2): Sui flag 6, Solana
  `passkey_blob` (precompile), Soroban `WebAuthn{…}` (CAP-51), Aptos blob (pure-Move `scaas::p256`, UNAUDITED, shown
  as such). Order: Sui → Solana → Soroban → Aptos, after A10–A14. Cosmos and TON passkeys are not in this round.
  Why: verifier maturity. Cost if wrong: Cosmos/TON users use seed or extension.
- **R265** **Passkey challenge = base64url (no padding) of the family's op digest**, the same rule as R31. The open
  challenges (Sui `scaas.open.v1`, Solana `scaas.open.v1`, Soroban constructor, Aptos first-key rule) are built by
  `fam/*`. Passkeys stay origin-bound (APP R165).
  Why: one rule. Cost if wrong: none.
- **R269** **Every seed key added to a subject account is a role key; a backup seed key lives on paper only.**
  - `deriveRoleKey(seed, {kindNo, account, i})` derives `m/7622'/0'/<account>'/<kindNo>'/<i>'` (F §8.1; all hardened;
    BIP-32 for secp256k1, SLIP-10 for ed25519). It is plain derivation. F3 wraps it in `UAKey` without changing the
    path.
  - `kindNo` is the F kind number of the account the key serves: EVM/Hedera `SubjectAccount` = 2; Solana 16;
    Soroban `C…` 18 (Q1); Aptos 19; Sui 20.
  - The **native** path is used only for a native account and for the owner/first key of a Sui/Aptos/Solana account
    derived from the user's own native address (F R300). Every other key added by a seed is a role key: backup,
    added device, passkey-first account's seed key, Soroban `C…` key. `m/44'/60'/0'/0/i` is the EOA only.
  - **Backup flow (review M4):** generate a phrase, show it once, run the 3-word check, derive the role key, sign
    `addKey`/KeyOp with the existing key, then `abandon()`. **Nothing is stored** unless the user asks to keep it on
    this device. No scrypt runs, so low-memory phones can comply.
  - Existing dev accounts whose SECP256K1 key is the EOA key rotate at F §12 migration.

  Why: F R300 (owner) rules dual use out. A backup in the same browser profile as the primary key is not a backup.
  Cost if wrong: one derivation per role; wallets show the role.

### 2.5 Connectors (owner item 5)

- **R266** **One connector implementation.** The wallet glue in
  `bamboo-dms/dms_blockchain_bridge/static/src/js/connectors/*.js` and the EIP-6963 part of `chain_pay.js` move to
  clientkeys `src/wallets/<family>.js` and `wallets/evm.js` (pure ESM, `win` injected).
  - They are built as **per-family esbuild entries** `wallets-<family>.js` and `fam-<family>.js`, so they have stable
    names for `import()`.
  - The portal and the app's `src/signers/extension/*` import the same modules. The portal IIFEs and their tests are
    deleted in the same change.

  Why: owner; today the connectors are tested but not wired (§9.1). Cost if wrong: clientkeys gains browser glue.
- **R267** **Check, then sign exactly what was checked.**
  - `fam.checkTerms(start, shown)` rebuilds the payload with `fam/<family>.js` and returns a frozen `checked` object
    `{ payload, walletInput, signingBytes }`.
  - Wallet `sign()` and `signFamily` accept **only** `checked`, never `start`.
  - Must-check lists are in §7.3. They cover EVM (existing `checkPayment`), Sui, Solana, Aptos and Soroban in D4/D5.
    Cosmos, TON and Hedera ED25519 get the generic list (payload rebuilt == `payload_hex`, `from`, chain/network,
    contract, amount) in their D5-<f>.
  - **Portal limitation:** `shown` comes from the same Odoo response as the terms, so in the portal the check is
    internal consistency (bytes ⇔ displayed fields), not protection from a malicious issuer. In the app, `shown` is
    the user's own input.

  Why: closes the gap between checking `payload_hex` and signing `text`. Cost if wrong: a terms change must land with
  its `fam/*.js` change (shared KATs catch it).

### 2.6 Compatibility with spec F

- **R268** **S4F adds no account id, registry or key kind.** The predicate takes "active key set + guardian" and
  works unchanged over F's sets (F §10). "Native single-key ⇒ outside" maps to F's unregistered native kinds.
  `deriveRoleKey` is F §8.1's path.
  Why: D and F stay independent. Cost if wrong: none.

---

## 3. Spec F: what is ruled, what stays

| Topic | Status |
|---|---|
| Dual key uses | **Ruled by F R300** and applied by R269: the EOA path is EOA-only; subject-account keys and non-native owner keys come from the `m/7622'` role tree |
| Account identity | Family derivations as built (EVM CREATE2 salt, Sui `derive_address`, Aptos object address, Solana PDA, Cosmos R9-1). UA ids are F |
| Backup predicate scope | D (R251), applied to F's key sets unchanged (F §10) |
| Tagged signing | KeyOp/open domains unchanged now; F §8.3 `keyop` purpose bumps the version (R261 parameterized) |
| Attestations | F only |

---

## 4. Backup-key switch

### 4.1 States a client shows

| Switch | Account | Value ops | Exit | Receive / fund | Key ops |
|---|---|---|---|---|---|
| OFF | any | allowed | allowed | shown | all; "no backup" warning (R254) |
| ON | subject, has backup | allowed | allowed | shown | all; removals warn when they break the backup |
| ON | subject, no backup, satisfiable | refused: "Add a backup key first" | allowed | hidden | all; add-backup offered first |
| ON | unsatisfiable (R253) | refused | allowed (only value op) | hidden | as the kind allows |
| ON | native single-key (seed vault or extension) | allowed | allowed | shown | n/a |

### 4.2 Reading the key set (clients)

| Family | Read | Active keys (then de-dup, R251) | Guardian |
|---|---|---|---|
| EVM, Hedera | `nextKeyIndex()`, `keyAt(i)` for `i ∈ [0, nextKeyIndex)`, skipping `kind == NONE` (slots are sparse after `removeKey`); `guardian()` | non-NONE slots | `guardian() != 0x0` |
| Sui | `Account<T>` fields `keys`, `guardian` (`sui_getObject`) | `keys` | `guardian != @0x0` |
| Aptos | `Account` resource | `keys` | `option::is_some(guardian)` |
| Solana | `SubjectAccount` PDA (Borsh) | `keys` | `guardian`; also `policy & 1` |
| Soroban | `scaas-account` key map | values (no duplicate check on chain) | none (R8-2) |
| TON | jetton wallet `pubkey`, `passkey` | the bound ones | none |

Pending keys do not count. Clients re-read after any key change reaches finality, and cache nothing across sessions.

### 4.3 clientkeys interface (`src/backup-policy.js`, exported from both signer entries)

```js
/** account: { kind: 'subject' | 'native' | 'msig', satisfiable: boolean, address: string,
 *   keys: Array<{ scheme, pub }>,   // ACTIVE keys; pub = canonical public key hex (R251): P-256 x, secp256k1
 *                                   // address or x-only, ed25519 pk
 *   nativeAddresses: string[],      // native address of each key (guardian independence)
 *   guardian: string | null, msig?: { threshold, weights: number[] } } */
export function hasBackup(account)            // distinct pubs ≥ 2, or 1 + independent guardian, or the msig rule
export function backupStatus(account, { required }) /* → { ok, reason: null | 'NO_BACKUP' | 'UNSATISFIABLE',
    allow: { value, receive, exit: true, addKey: true, setGuardian: true, addOrigin: true,
             removeKey: true, clearGuardian: true },
    warnings: Array<'NO_BACKUP' | 'SAME_KEYCHAIN' | 'DEVICE_ONLY' | 'BREAKS_BACKUP'> } */
export function passkeyFlags(authenticatorData) // → { up, uv, be, bs } (bits 0, 2, 3, 4)
export function deriveRoleKey(seed, { kindNo, account, i }) // R269; caller wipes privateKey
```

`BREAKS_BACKUP` is set on a planned removal when `hasBackup(after)` is false. The signer UI calls `backupStatus`
first, and the signer refuses a value op when `allow.value` is false.

### 4.4 Odoo (portal, EVM and Hedera)

- Parameter `dms_blockchain.require_backup_key` (`'1'`/`'True'` = ON).
- `blockchain.subject.account._dms_has_backup()` (private): distinct active key rows, de-duplicated by
  `(public_x)` for passkeys and `evm_address` for seed keys. Then ≥ 2, or 1 with
  `guardian_address ∉ {ZERO_ADDRESS, account address, any key's evm_address}`.
- Known blind spots (accepted, the switch is soft):
  - `guardian_address` is the CREATE2 input, so a later `setGuardian` is not mirrored;
  - removals done outside the portal are not mirrored, and `key_state` has no "removed" state. Odoo over-counts in
    that case.
- `dms_portal_chain_payment_start` raises `UserError("Add a backup key to your account first.")` when ON and the
  paying account has no backup. Any future Odoo flow paying **to** a subject account applies the same check.
- `subject_signers.js` with ON: after the first key, the flow goes to "add a backup" (§4.7) before the first payment.
  New seed keys use the role path (R269); the key row still stores the address in `evm_address`.
- Non-EVM families: client enforcement only (R20).

### 4.5 Per-family applicability

| Family | Subject account | Max keys | Guardian | Satisfiable by | On-chain bit | Odoo checks |
|---|---|---|---|---|---|---|
| EVM, Hedera | `SubjectAccount` | unbounded | yes | 2 keys or key + guardian | no | yes |
| Sui | `Account<T>` | 8 | yes | as EVM | no | no |
| Aptos | `Account` object | 8 | yes | as EVM | no | no |
| Solana | `SubjectAccount` PDA | 8 | yes | as EVM | opt-in (no de-dup) | no |
| Soroban | `scaas-account` `C…` | multi | no (R8-2) | **≥ 2 distinct keys** (owner) | no | no |
| TON | `ScaasJettonWallet` | 2 (`pubkey` + one passkey) | no | **both keys** (owner) | no | no |
| Cosmos | none (native; multi-key seam) | 1 | no | seed: native; passkey-only: **unsatisfiable** | no | no |

### 4.6 Tests and vectors

`clientkeys/test/vectors/backup_policy.json`. Each row is `{name, families, account, required}` mapped to
`{has_backup, ok, reason, allow, solana_onchain?}`. Rows cover:
- 0/1/2/8 keys;
- guardian set, unset, equal to own key, equal to the account;
- same passkey on two origins ⇒ 1;
- Soroban same key twice ⇒ 1;
- Sui same pk under two `rp_id_hash` ⇒ 1;
- `msig` weights (APP R176);
- native, unsatisfiable;
- remove-key and clear-guardian **allowed** and yielding `NO_BACKUP`;
- exit allowed in every row;
- both switch states.

Consumers:
- clientkeys `backup-policy.test.js` (all rows);
- Odoo `test_backup_policy.py` (EVM rows through `_dms_has_backup`);
- Solana Rust `has_backup` unit test (rows with `solana_onchain`). Where on-chain no-de-dup differs, it is pinned as
  `solana_onchain` ≠ `has_backup`.

Other tests:
- `deriveRoleKey`: path string, and **role key ≠ native key** for the same seed on every family. When F0 lands,
  F `derivation.json` R300 rows must match.
- `passkeyFlags` against `test/softauthn.js` with BE/BS set and clear.
- Odoo: start refused (ON, 1 key, no guardian); start refused with guardian = own key; allowed after a second
  distinct key; allowed when OFF; a pending key does not count.
- Portal tour (fake authenticator), switch ON: payment blocked → paper backup flow (§4.7) → pay; then remove the
  passkey → value refused, exit offered.
- App e2e: inside APP A3.

### 4.7 Backup and revocation flows

- **Add a backup:**
  - seed primary ⇒ add a passkey;
  - passkey primary ⇒ paper seed key (R269: phrase, 3-word check, role key, `addKey`/KeyOp, store nothing);
  - or ask the operator for a guardian (EVM/Sui/Aptos/Solana).
- **Revoke:**
  - EVM offers `rotateKey(index, newKey)` (one owner call: add, then remove) as the default when replacing a key;
  - elsewhere "add new key, then remove";
  - plain remove and clear-guardian are always possible (R252), with `BREAKS_BACKUP` shown.
- **Lost paper:** create a new paper key, then remove the old one (R258).

---

## 5. Device-bound vault (v2)

### 5.1 Format

The v1 vault (`vault.js`, unchanged):
`{ v: 1, label, data: {iv, ct}, pin: {kdf: 'scrypt', N, r, p, salt, iv, ct}, prf?: {credentialId, salt, iv, ct} }`.

v2 wraps it:

```json
{ "v": 2, "label": "seed", "kid": "device-v1", "iv": "<b64url, 12 B>", "ct": "<b64url>" }
```

- `ct = AES-256-GCM(deviceKey, iv, utf8(JSON.stringify(v1)), aad = "<label>|device|<kid>")`, with a fresh IV per seal.
- `label` is repeated outside, so a swapped blob fails the outer AAD and the inner v1 AAD.
- The device key is required **in addition** to the passphrase or PRF.
- Portal tombstone (R257): `{ "v": 2, "moved": "indexeddb" }`. `openDevice` rejects it.

### 5.2 Storage and interface

IndexedDB `scaas-clientkeys` v1, store `kv`:

| Key | Value |
|---|---|
| `device-key:v1` | the `CryptoKey` (`extractable: false`) |
| `vault:<id>` | v2 (or v1 on fallback). Portal `<id>` = `dms_chain_seed_vault:<subject>`; app `seed:<account label>`; Zether `zether-conf:<curve>:<coin>:<account>` |
| `rewrap-attempt:<id>` | `N` being attempted (R259) |
| `persist-notice` | `true` once the refusal notice was shown |

`src/device.js` (exported from `seed-signer.js` and `zether-keys.js`; used inside the app key worker, APP R175):

```js
export async function openStore(indexedDB = globalThis.indexedDB) // → { get, put, del } or null (probe fails)
export async function deviceKey(store)                             // get, or generate + put
export async function sealDevice(vaultV1, key)                     // → v2
export async function openDevice(vaultV2, key)                     // → v1, memory only; tombstone ⇒ throws
export function needsBinding(stored)                               // stored.v === 1
```

`vault.js` `dekFrom` gains the R259 bounds check on stored `N, r, p`.

### 5.3 Threat model

| Threat | v1 today | v2 | Control that actually helps |
|---|---|---|---|
| Same-origin script: XSS, **or a browser extension with host access** (content scripts reach IndexedDB and `crypto.subtle`) | reads the blob, phishes the passphrase or waits for unlock | same: the device key is a decrypt oracle | CSP, no third-party scripts, key worker (APP R166, R175) |
| **Portal origin TCB**: Odoo website designer HTML/JS and every module's frontend assets run on the portal origin | as XSS | as XSS | deployment note: serve payments from a dedicated payment subdomain with only the payment bundle |
| Blob leaked alone (storage dump, log, support export, one-store file sync) | offline scrypt attack | **useless** without the profile's IndexedDB | R255 |
| Browser profile copy (both stores) | offline scrypt attack | same on Chromium/Firefox (key bytes in the copy); Safari: Keychain-wrapped | passphrase strength, scrypt `2^17`, OS disk encryption |
| Stolen disk, no OS encryption | as profile copy | as profile copy | OS full-disk encryption |
| Stolen device, locked / unlocked browser | passphrase or PRF + UV | same | idle lock (APP §6.3: 5 min) |
| PRF from a synced passkey + leaked blob | opens anywhere the passkey syncs | needs the device key too | R255 |
| PRF output captured by a script during one unlock | permanent unwrap key for that blob | still needs the device key (same origin ⇒ available to that script) | as XSS row |
| Device lost, site data cleared, Safari ITP 7-day eviction | phrase re-import | phrase re-import; the blob never opens again | R258, `persist()` |

### 5.4 Migration

1. **New vault:** `createVault` (v1) → `sealDevice` → `put('vault:<id>')` → `openDevice(get(...))` deep-equals v1 →
   done.
2. **Existing v1** (app IndexedDB, or portal `localStorage` including the RS4-15 legacy key):
   1. after a successful `openVault`, check whether `vault:<id>` already exists. If it does, it wins: open that one
      and only write the tombstone;
   2. otherwise seal v2 and `put` it;
   3. read it back with `openDevice` and compare (no scrypt);
   4. **then** write the `localStorage` tombstone.

   A failure at step 2 or 3 keeps the `localStorage` entry as it is. The `N = 2^15` re-wrap is a separate step after
   the payment is submitted (R259).
3. **Opening:** IndexedDB `vault:<id>` first. Then `localStorage` (v1 ⇒ migrate; tombstone ⇒ "this vault moved;
   reload"). A v2 blob without the device key means a cleared profile: phrase import only.
4. No downgrade from v2 to v1 is written. `openDevice` output never leaves memory.

### 5.5 Tests

- Round trip v1 → v2 → v1 with an in-memory store (Node 26 has WebCrypto, no IndexedDB).
- Tamper outer `ct`, swap `label`, swap `kid`, wrong device key, tombstone: each fails, nothing returned.
- `deviceKey` is stable across calls; `extractable === false`; `exportKey` rejects.
- `test/vectors/vault_v2_fixture.json`: a committed v2 blob plus raw device-key bytes (imported with `extractable:
  false`) opens to known entropy.
- `openStore` returns `null` under a stub `indexedDB` that throws on a `CryptoKey` `put`; the caller writes v1.
- Migration failure paths (stubbed store): put fails, read-back mismatch, tombstone write fails, both copies
  present (IndexedDB wins, no overwrite), stale v1 next to a newer v2.
- R259: a KDF that throws at creation returns no vault; marker present ⇒ re-wrap skipped; out-of-bounds `N`/`r`/`p`
  refused on open; `2^15` vault still opens.
- **Real browsers:** one Playwright run of create → reload → unlock → migrate on Chromium, Firefox and WebKit
  (structured-clone `CryptoKey` in IndexedDB is not exercised by the `Map` store).
- Portal tour: a legacy `localStorage` vault unlocks, becomes v2 in IndexedDB, and leaves a tombstone; the second
  unlock opens v2.
- `bundle.test.js` covers the new module.

### 5.6 scrypt

`SCRYPT = { N: 2^17, r: 8, p: 1, dkLen: 32 }` stays (R259). The SCaaS §15.3 row ("round-3 R32 says `N = 2^15`") is
resolved in favour of the code. `vault.test.js` already pins the parameters and the re-wrap; §5.5 adds the failure,
marker and bounds tests.

---

## 6. Sui: verification of added and recovered keys

### 6.1 Facts (code at 28c165c / parent repo)

- `Account<T>` id = `derive_address(registry, owner)`, where `owner` is the first key's address and never changes.
- `keys` holds ≤ 8 keys. `manage(KeyOp…)` is signed by any current key and does one action per call: add or remove
  a key, add or remove an origin, set the guardian, cancel a recovery.
- Recovery: the guardian calls `start_recovery(key)`, then `finish_recovery` after 172 800 s.
- `MetaOp.from` = owner. `relay_pay` accepts any key in `keys`. `a2_pay_sui` (an added ed25519 key) and `a3_pay_sui`
  (a recovered secp256k1 key) pass `sui move test`.
- `fam_sui.verify` returns `False` unless `address_of(flag, pk) == payer` (the R260 bug).

### 6.2 Python (`dms_blockchain/lib/fam_sui.py`, parent repo)

```python
ADD_KEY, REMOVE_KEY, ADD_ORIGIN, REMOVE_ORIGIN, SET_GUARDIAN, CANCEL_RECOVERY = range(6)
KEYOP_DOMAIN = b'scaas.keyop.v1'          # F §8.3 bumps it; callers pass `domain`

def keyop_bytes(network, account, action, scheme, public_key, rp_id_hash, origin, guardian, nonce, valid_until,
                domain=KEYOP_DOMAIN):
    return (_vec(domain) + _vec(network.encode()) + addr(account) + bytes([action, scheme])
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
    return True if own else None          # L9: other keys ⇒ node simulation decides (R27)
```

`verify_digest`'s passkey branch also refuses `b'"crossOrigin":true'` and `b'"topOrigin"'`. `gen_vectors.py` imports
`keyop_bytes` in place of its private copy. `signature_verified = False` for `None`, as for Aptos and Solana.

**Reach (review M7).** In the portal, a non-EVM signer pays with the **owner key only**: the portal sends
`signer.from` and has no chain reads, and a Sui `Account<T>` has no reverse index from key to account. Added keys pay
through the app (find-my-account, APP §6.4). They can pay through the portal once the vault stores
`{family, account, owner, key_index}` next to the phrase (D5-sui, optional).

### 6.3 JS (`clientkeys/src/fam/sui.js`, A0-sui)

`metaOpBytes`, `personalDigest`, `deriveAccount`, `addressOf`, `parseSignature`, `serializeSignature`,
`serializePasskey` (§8.2), `keyOpBytes(…, {domain})`, `keyOpDigest`, and `verifyKeyOp(account, op, signature, {now})`
with the R261 checks.

### 6.4 Vectors and tests

- `sui_vectors.json` (R262): every `pay` and `keyop` vector as `{name, signer {flag, pk}, owner, account,
  payload_hex | keyop fields, digest, signature_b64, expect_odoo: true | null | false}`, plus
  `vectors_move_sha256`.
- Odoo `test_fam_sui.py`:
  - `test_added_key_signature_is_left_to_the_node` (`a2_pay_sui` ⇒ `None`);
  - `test_recovered_key_signature_is_left_to_the_node` (`a3_pay_sui` ⇒ `None`);
  - `test_flipped_byte_from_added_key_is_refused` (`False`);
  - `test_own_key_still_verified`;
  - `test_passkey_cross_origin_refused`;
  - `test_keyop_bytes_match_move` (every `k_*`);
  - `test_vectors_file_matches_move` (sha256);
  - `test_signature_from_another_wallet_is_refused` narrowed to "invalid under its own key".
- clientkeys `fam_sui.test.js`:
  - `keyOpDigest` matches every `k_*` vector;
  - `verifyKeyOp` is true for the right signer and nonce, and false for: wrong nonce, non-member key, flipped byte,
    wrong account, wrong network, expired, foreign origin.
- `sui move test` unchanged; the vectors are regenerated in the same run.

---

## 7. Role keys and seed signers

### 7.1 Matrix

"Adds to a subject account" names the key a seed contributes when it is not the account's native owner (R269).

| Family | `NETWORKS` key | Native path | Curve | Native address | Adds to a subject account | Seed signer signs | Status |
|---|---|---|---|---|---|---|---|
| EVM | `evm` | `m/44'/60'/0'/0/i` (EOA only) | secp256k1 | keccak address | role `m/7622'/0'/a'/2'/i'` (SECP256K1 key) | EIP-712 digest | native BUILT; role **R269** |
| Hedera ECDSA | `hedera_ecdsa` | `m/44'/3030'/0'/0/i` | secp256k1 | EVM alias | role `…/2'/i'` (HSCS `SubjectAccount`) | EIP-712 digest | as EVM |
| Hedera ED25519 | `hedera_ed25519` | `m/44'/3030'/0'/0'/i'` | ed25519 | `0.0.N` | — | raw ed25519 over EIP-712 digest (HIP-632) | BUILT |
| Cosmos | `cosmos` | `m/44'/118'/0'/0/i` | secp256k1 | bech32 | — (no subject account) | ADR-036 doc | key BUILT; envelope A0-cosmos |
| Sui | `sui` | `m/44'/784'/i'/0'/0'` | ed25519 | `blake2b(0x00 ‖ pk)` | native if owner; else role `…/20'/i'` | personal-message digest, flag 0 | key BUILT; envelope A0-sui |
| TON | `ton` | `m/44'/607'/i'` | ed25519 | pubkey (`BindKey`) | — (wallet-bound; F8 rules TON) | MetaOp cell hash | key BUILT; envelope A0-ton |
| Soroban Stellar | `stellar` | `m/44'/148'/i'` | ed25519 | `G…` | role `…/18'/i'` (`C…` key, Q1) | `G…`: sha256(auth preimage); `C…`: `Ed25519{key_id, sig}` | **D4-soroban** |
| Soroban Pi | `stellar` + 314159 | `m/44'/314159'/i'` | ed25519 | `G…` | as Stellar | as Stellar, Pi passphrase | **D4-soroban** |
| Aptos | `aptos` | `m/44'/637'/i'/0'/0'` | ed25519 | `sha3_256(pk ‖ 0x00)` | native if owner; else role `…/19'/i'` | AIP-62 `fullMessage` | **D4-aptos** |
| Solana | `solana` | `m/44'/501'/i'/0'` | ed25519 | base58 pk | native if owner; else role `…/16'/i'` | OCMS v1 (kind 1) | **D4-solana** |

`a` = the user's account number (F `<account>`). TON keys from `m/44'/607'/i'` stay "BIP-39/Ledger path" imports.

### 7.2 Interface (`src/fam/<family>.js`, consumed by the seed signer and wallets)

```js
export function checkTerms(terms, shown)       // → frozen { payload, walletInput, signingBytes }, or throws
                                               //   "Refusing to sign: …"
export function packSignature(checked, key, sig) // → { signature, publicKey } in the submit format
```

The seed signer's `signFamily(key, family, checked)` signs `checked.signingBytes` (ed25519; secp256k1 `signDigest`
for 32-byte inputs) and packs the result. A wallet passes `checked.walletInput` to the wallet API, then compares what
the wallet reports as signed against `checked.signingBytes` (as the connectors do today).

| Family | `signingBytes` (seed) | `packSignature` |
|---|---|---|
| Soroban `G…` | `sha256(XDR(HashIdPreimage::SorobanAuthorization{network_id, nonce, signature_expiration_ledger, invocation}))`. A self-paid envelope hash is signed only via the adapter's `buildSelfPaid` | 64-byte hex; `publicKey` = `G…` StrKey |
| Soroban `C…` | `signature_payload` (32 B) | XDR hex of `Signature::Ed25519{key_id, signature}` |
| Aptos | UTF-8 `fullMessage` built by the client (`application`, `chainId`, `message = "scaas.metaop.v1:0x<digest>"`, `nonce = <lane hex>`), self-checked with the JS port of `parse_envelope` | `sig64 ‖ fullMessage` hex; pk hex |
| Solana | `0xff ‖ "solana offchain" ‖ 0x01 ‖ 0x01 ‖ pk32 ‖ "scaas.metaop.v1:" ‖ hex(digest)` | `[1, key_index] ‖ sig64` hex (key index 0 for the owner, R260 reach); pk hex |

### 7.3 Must-check lists (`checkTerms`, R267)

| Family | Checks before anything is signed |
|---|---|
| EVM / Hedera ECDSA | existing `checkPayment` / `checkOwnerCall` (RS4-13) |
| Sui | `message_b64 == payload_hex`; payload decodes to `op == PAY`, `from == owner`, `to`, `amount == shown`, `relayer == 0x0`, `extra == 0³²`, `valid_until` within the window; `contract == deriveAccount(registry, from)`; `network == config` |
| Solana | `text == "scaas.metaop.v1:" + hex(sha256(payload))`; payload fields as Sui (op, from, to, amount, asset, lane, window); `account == PDA(["acct", owner])`; `network` = configured genesis |
| Aptos | payload fields (op, from, to, amount, asset, window); `account == account_of(root, owner)`; `message` = digest text; `application == location.origin` (portal: the configured `aptos_application`); `chainId`; `nonce == lane` |
| Soroban | decode the invocation: contract = token, function, args (from, to, amount); `network_id` = configured passphrase hash; `signature_expiration_ledger` ≤ current + window |
| Cosmos, TON, Hedera ED25519 (D5-<f>) | payload rebuilt from terms == `payload_hex`; `from`; chain/network; contract; amount |

### 7.4 Vectors and tests

- `solana_derivation.json`: BIP-39 test mnemonic → pk/address for `i = 0, 1, 2` at `m/44'/501'/i'/0'`, from
  `solana-keygen` (`prompt://?key=i/0`) and confirmed by an independent SLIP-10 implementation before commit.
- `role_keys.json`: the same mnemonic → `deriveRoleKey` for `kindNo ∈ {2, 16, 18, 19, 20}`, `account ∈ {0, 1}`,
  `i ∈ {0, 1}`; each differs from every native key of that seed. F0 `derivation.json` must agree.
- Per family (D4-<f>): one **seed-signed** vector: fixed seed and path, terms → `checked`, signature, packed value.
  It is asserted in JS and re-verified in Python by `fam_<f>.verify` (owner key ⇒ `True`).
- Soroban `C…`: one `Ed25519` ScVal vector from the account contract's `cargo test` (real `set_auths`), compared byte
  for byte.
- Refusals: every row of §7.3 has a failing case per family.
- Wallet tests: `sign()` throws when given anything but a `checked` object.

---

## 8. Passkey signers on non-EVM families (A16 = D7)

### 8.1 Availability

| Family | On-chain P-256 | Account | pk | Origin binding | Status |
|---|---|---|---|---|---|
| EVM, Hedera | RIP-7212 `0x100` or OZ Solidity | `SubjectAccount` | `(x, y)` + `rpIdHash`, `keccak(origin)` | per key | BUILT |
| Sui | native `secp256r1_verify`, flag 6 | `Account<T>` (`open_passkey`) | 33 B | `origins` ≤ 8 | contract BUILT; **D7 #1** |
| Solana | precompile `Secp256r1SigVerify1111…` (SIMD-0075), low-S, ≤ 8/ix | PDA (`open_passkey`) | 33 B | `origins` ≤ 8, same-rpId rule | contract BUILT; **#2** |
| Soroban | host `secp256r1_verify` (CAP-51) | `scaas-account` `C…` | 65 B | per key | contract BUILT; **#3** |
| Aptos | pure-Move `scaas::p256` (UNAUDITED, ≈ 4 100 gas/sig) | `Account` object | 65 B | `origins` | contract BUILT (unaudited); **#4** |
| Cosmos | cosmwasm `secp256r1_verify` | none (R9-1 only) | 33 B | none | not this round |
| TON | TVM `P256_CHKSIGNS` | jetton wallet, one passkey | 33 B + `rpIdHash` + `originPrefix` | prefix | not this round |

### 8.2 Encoders (`src/fam/<family>.js`)

| Family | Open (first key) | Pay signature | Submit `public_key` |
|---|---|---|---|
| Sui | assertion over `blake2b256("scaas.open.v1" ‖ registry ‖ pk33)`; `open_passkey` | base64 `0x06 ‖ uleb ad ‖ uleb cd ‖ uleb(98) (0x02 ‖ r‖s ‖ pk33)` | — |
| Solana | assertion over `sha256("scaas.open.v1" ‖ program_id ‖ pk33)`; owner `sha256("scaas.owner.p256" ‖ pk33)` | `[2, key_index] ‖ r‖s ‖ u16le(len ad) ‖ ad ‖ cd` + precompile ix | pk33 hex |
| Soroban | `__constructor(first_key)` (no auth) | `Signature::WebAuthn{key_id, authenticator_data, client_data_json, signature, proof}` XDR | — |
| Aptos | first-key rule RS11-14 | `r‖s ‖ u16be(len ad) ‖ ad ‖ cd` | pk65 hex |

`r‖s` comes from `derToRS` (strict DER, low-s). `pk33` is the SEC1 compression of `publicKeyFromSpki`; `pk65` is
`0x04 ‖ x ‖ y`. Merkle batching stays EVM-only.

### 8.3 Tests

- The chain-side software-authenticator vectors (Sui `d_*`, Solana/Soroban/Aptos suites) are re-encoded by `fam/*`
  from `(authenticatorData, clientDataJSON, DER, SPKI)` and must match the chain bytes.
- **Cross-family separation:** one test asserts that every family's pay and open challenge preimages are pairwise
  prefix-distinct (the same credential may serve several chains, F §8.1).
- JS refusals: wrong challenge, missing UV, high-s normalised, cross-origin, wrong pk length.
- Python L9 answers on the client-encoded vectors.
- e2e with a virtual authenticator inside A11/A14/A10/A12, then D7.

---

## 9. Portal connectors (`chain_pay.js`) and the shared implementation

### 9.1 Today (parent repo)

| Piece | State |
|---|---|
| `chain_pay.js` | EVM only (EIP-6963, EIP-1193 fallback, WalletConnect seam, `eth_signTypedData_v4`, R27 kind). It reads `start.typed_data.message.validUntil`, which a family start lacks |
| `subject_signers.js` | passkey + seed for EVM `SubjectAccount`, using the EOA path (R269 changes this) |
| `connectors/*.js` | seven IIFEs on `window.dmsChainConnectors`, node-tested; **not in the asset bundle, read by nothing** |
| Odoo start/submit | already family-ready (`{family, valid_until, payload_hex, digest, …terms}`; `public_key`) |

### 9.2 Target layout (clientkeys)

```
src/fam/<family>.js       encoders + checkTerms/packSignature      → entry fam-<family>.js
src/wallets/<family>.js   extension glue (moved, R266)              → entry wallets-<family>.js
src/wallets/evm.js        EIP-6963 discovery + walletKind (moved)   → entry wallets-evm.js
```

`package.json` `build` lists every entry explicitly (same `--splitting`, same out dir). Shared code goes to
`chunk-[hash].js`, and the entry names stay stable for `import()`. `bundle.test.js` keeps the byte-identical check.

Wallet interface:

```js
export function create(win = globalThis) {
  return { family, label, available(), wallets(),
           connect(name?) /* → { address, publicKey } */,
           sign(checked) /* → { signature, publicKey }; only a checkTerms result */ };
}
```

### 9.3 `chain_pay.js` flow

```
options = dms_portal_chain_payment_options(order)              // + family, network
signer  = family ∈ {evm, hedera ECDSA} ? today's chooser (wallets-evm.js)
        : choose among [wallets-<family>.js wallet(s), seed vault family path]
start   = dms_portal_chain_payment_start(order, signer.from, wallet_id)   // owner key only (§6.2)
checked = (await import('…/fam-<family>.js')).checkTerms(start, shown)    // R267
{signature, publicKey} = await signer.sign(checked)
validUntil = start.typed_data ? start.typed_data.message.validUntil : start.valid_until
status  = dms_portal_chain_payment_submit(start.reference, validUntil, signature, kind, publicKey)
```

`shown` is the amount, currency and payee text the portal displayed (internal consistency only, R267). Polling,
terminal failures and the EIP-1193 switch guard stay. Odoo adds `'family'` and `'network'` to the options and changes
nothing else. Hedera ED25519 keeps the `window.dmsHederaSigner` seam and the seed path.

### 9.4 Tests

- The connector node tests move to `clientkeys/test/wallets/*.test.js` with an injected `win`; the portal copies are
  deleted.
- `chain_pay` unit (injected `window`): dispatch, `checkTerms` refusal stops before `sign`, `validUntil` from
  `start.valid_until`.
- Odoo `test_options_carry_family_and_network`.
- Tours, one heavy Odoo run at a time:
  - Sui and Solana: fake Wallet Standard wallets end to end to `signed_op` queued;
  - Aptos: one seed-vault tour.

---

## 10. Streams

At most one agent at a time; at most one heavy build or Odoo run at a time. The order follows APP §15. Parent-repo
changes are separate `bamboo-dms` commits.

| Stream | Content | Repo | Depends on | Gate |
|---|---|---|---|---|
| **D1** policy + role keys | `backup-policy.js` (`hasBackup` with de-dup and independence, `backupStatus`, `passkeyFlags`), `deriveRoleKey`, `backup_policy.json`, `role_keys.json`, Solana Rust `has_backup` test | scaas | — | `npm test`; `cargo test` (solana unit) |
| **D3** Sui verify | `fam_sui` L9, `keyop_bytes(domain)`, cross-origin refusal; `gen_vectors.py --json` + sha256; Odoo tests | bamboo-dms + scaas | — | Odoo `test_fam_sui`; `sui move test` |
| **D2** vault v2 | `device.js`, v2, tombstone, precedence, re-wrap marker and bounds, fixture; portal migration | scaas + bamboo-dms | — | `npm test` + bundle; Playwright 3-browser vault run; portal tour |
| **D5-evm** | `wallets/evm.js` moved, `wallets-evm.js` entry; `chain_pay.js` uses it | scaas + bamboo-dms | A0-evm | `npm test`; Odoo EVM tour |
| **D6** switch | Odoo parameter, `_dms_has_backup`, start refusal, portal paper-backup flow and role-key adds (R269); app part inside A3 | bamboo-dms (+ app) | D1 (role key), D2 | Odoo tests + passkey tour, switch ON |
| **D4-<f>** | seed signer `signFamily` + `checkTerms`/`packSignature` + seed-signed vector for Soroban, Aptos, Solana | scaas | A0-<f> | `npm test`; Python re-verify |
| **D5-<f>** | `wallets/<f>.js` moved + `checkTerms` for Cosmos/TON/Hedera ED25519; `chain_pay.js` family dispatch (first family adds it); options `family`/`network` | scaas + bamboo-dms | A0-<f>; D4-<f> for Soroban/Aptos/Solana | `npm test`; family tour (Sui, Solana, Aptos) |
| **D7** = A16 | non-EVM passkeys Sui → Solana → Soroban → Aptos (§8.2) | scaas (+ app) | A11, A14, A10, A12 | per-family vectors + e2e |

Order: D1 → D3 → D2 → A0-evm → D5-evm → … → A3 (D6) → … per family A9–A14 (A0-<f> → D4-<f> → D5-<f>) … → D7.

Edges to F:
- D1's `deriveRoleKey` must agree with F0 `derivation.json` R300 rows;
- F3 wraps it in `UAKey` (path unchanged);
- F §8.3's `keyop` purpose is a version bump of the domain parameter in D3;
- F §12 rotates dev accounts whose SECP256K1 key is the EOA key.

---

## 11. Open questions

| # | Question | Default |
|---|---|---|
| Q1 | (for F) The role-path `kindNo` for keys of a Soroban `scaas-account` `C…`. F §8.1 says "native kindNo": is that `soroban-contract` 0x0012 (18, by analogy with EVM `SubjectAccount` = `evm-contract` 2) or `stellar-account` 0x0011 (17)? | 18 |

---

## 12. Review disposition (review 1, rev 1 → rev 1.1)

| # | Finding | Disposition | Where |
|---|---|---|---|
| H1 | Not reconciled with F R300; D6 mints dual-use keys | fixed: `deriveRoleKey` in D1; every added seed key is a role key; role column; role ≠ native vector; F edges | R269, §3, §4.3, §7.1, §7.4, §10 |
| H2 | Switch blocks revoking a stolen key / hostile guardian | fixed: remove key and clear guardian always allowed, with warning; `rotateKey` default on EVM | R252(3), §4.1, §4.3, §4.7, §4.6 rows |
| H3 | Duplicates and self-guardians count as backup; H4 not folded | fixed: distinct canonical keys, independent guardian, `msig` rule, add-origin moved, Odoo de-dup, JSON rows | R251, R252(3), §4.3, §4.4, §4.6 |
| M1 | Exit not allowed on satisfiable no-backup accounts | fixed: exit in every state | R253, §4.1, §4.3 |
| M2 | Migration precedence, rollback, delete, double scrypt | fixed: IndexedDB wins, no overwrite, tombstone, AES-only check, failure tests | R257, §5.4, §5.5 |
| M3 | Mobile OOM kill, re-wrap crash loop, unbounded `N` | fixed: "allocation or crash", marker, re-wrap after submit, bounds | R259, §5.2, §5.5 |
| M4 | Backup seed key need not live on the device | accepted (no owner ruling broken; vault v2 still applies to stored vaults) | R269, §4.7 |
| M5 | Threat model honesty | fixed: extensions in the XSS row, portal-origin TCB row, "as reported", PRF capture row, Safari/ITP | R256, R258, §5.3 |
| M6 | Check-then-sign gap; must-check lists; portal `shown`; families | fixed: `checked` only, per-family lists, limitation stated, Cosmos/TON/Hedera ED25519 in D5-<f> | R267, §7.2, §7.3, §9 |
| M7 | Added-key payments unreachable from the portal; `verifyKeyOp` too thin | fixed: owner key only in portal (stated), optional stored account; `verifyKeyOp` checks account, network, window, origin | R260, R261, §6.2, §6.4 |
| M8 | Streams diverge from APP §15 | fixed: D5-evm, D4-<f>, D5-<f>, D7 after A10–A14, F edges | §10 |
| L1 | No stable entry names | fixed: explicit per-family entries | R266, §9.2 |
| L2 | Sparse EVM key slots; mirror blind spots | fixed | §4.2, §4.4 |
| L3 | `True` ≠ member; dead-job cost | fixed in text. Optional Sui origin check **declined**: Sui chains have no configured portal origin field (Aptos has `aptos_application`), and adding a model field for a low, portal-gated risk is not worth it | R260 |
| L4 | Vector files | fixed: `has_backup` + `families` + `solana_onchain`; `vectors_move_sha256`; Rust adapter pins only deterministic ed25519 (checked) | R262, §4.6, §6.4 |
| L5 | Real-browser and failure paths | fixed: Playwright Chromium/Firefox/WebKit, M2/M3 tests, challenge-separation test | §5.5, §8.3 |
| L6 | Noise | fixed: reasons merged, `SAME_KEYCHAIN` only if all BS = 1, BE/BS client-only, `kid` format-bump only, persist notice once | R254, R255, R257, §4.3 |
| L7 | Seed re-reveal | fixed: never re-shown; lost paper ⇒ new key + remove old | R258, §4.7 |

Totals: 18 findings (3 H, 8 M, 7 L): 17 fixed or accepted in full; L3 accepted with its optional part declined; none
rejected.
