# Review 1 of spec D "S4F" rev 1 (signers follow-ups, R250–R268)

Reviewer: adversarial design review, read-only. Inputs: the spec, spec F rev 1.1/1.2, APP rev 1.2 (R154/R155/R165/R175/R176,
§6.2–§6.3, §15, §17), round-3 R31–R33, clientkeys at scaas HEAD (`vault.js`, `seed.js`, `backup.js`, `webauthn.js`,
`evm.js`, `package.json`), `dms_blockchain/lib/fam_{sui,solana,aptos}.py`, `blockchain_payment_request.py`,
`blockchain_subject_account.py`, `dms_portal_api.py`, `chain_pay.js`, `subject_signers.js`, `connectors/{sui,solana}.js`,
`SubjectAccount.sol`, Sui `meta.move` + `gen_vectors.py`, Soroban `account/src/lib.rs`, Solana `state.rs`/`account.rs`.
Owner rulings (toggle default OFF; Soroban/TON ≥ 2 keys; device binding; one connector implementation) not re-argued.

## Verdict: FIX-THEN-GO

No redesign is needed. Three things must change before D1/D6 start: D contradicts spec F R300, which the owner
has ruled on. The switch can block revoking a compromised key. And the backup predicate counts duplicate keys as a
backup, which is the exact false "backed up" state the switch exists to prevent. All three are text-level fixes with
small code effects. The rest are precision and sequencing fixes.

What holds up: the Sui tri-state is safe. Settlement happens only through chain events matched by `entry_ref`
(`_apply_events` → `_payment_gate`), so a `None` cannot mark anything paid. Nothing reads `signature_verified`. KeyOp
bytes are byte-identical in Python, JS and Move by construction (generator signs, `sui move test` verifies). The
cross-family seed separation holds: each family has its own SLIP-44 path and envelope. The non-wired portal finding is
real: the manifest bundles only `chain_pay.js` and `subject_signers.js`, and nothing reads `dmsChainConnectors`. The
vault v2 threat table is mostly honest: R256 says plainly that "non-extractable" does not mean hardware.

---

## Findings (ranked)

### H1 — D is not reconciled with F R300 / APP R155 (one key = one purpose). D6 would mint new dual-use keys

- **Section:** §3 row "One key = one purpose", §4.4 (`subject_signers.js` "seed if the first key was a passkey"),
  §7.1, §7.2 (Solana "the account's index for an added key"), §10 D6.
- **Problem:** D §3 still says the dual uses are "for F to rule on". F R300 has ruled on them (owner, rev 1.1), and
  APP R155 restates it: `m/44'/60'/0'/0/i` is the EOA only. A `SubjectAccount` SECP256K1 key and every non-native
  subject-account owner/role key come from `m/7622'/0'/<account>'/<kindNo>'/<i>'`. Today the portal's seed key is the
  EOA key: Odoo key rows store "only the EVM address of key m/44'/60'/0'/0/i" (`blockchain_subject_account.py`
  `evm_address` comment), and `secpSubjectKey(address)` wraps it. D6's add-backup step reuses that path, so every
  backup it creates is a new dual-use key that F §12 later has to rotate. There is also an ordering trap. The role
  path is delivered by F3 (`deriveUAKey`), which in the APP order comes after A3 (A3 → … → F0 → F1 → … → F3), while
  APP §6.2 already says A3's "Recoverable account" uses the role key. For Sui/Aptos/Solana, R300's exemption ("…owner
  key that is not the native address key") is ambiguous for a seed key **added** to a passkey-first account. Is it a
  native key or a role key? D is where these keys are built, so D must answer.
- **Evidence:** F §2.3 R300, F §8.1 table, F §11.4 (`evm_address` keys after F3 come from the role path), APP R155,
  APP §6.2 row "Recoverable account", APP §15 order, D §3 table.
- **Fix:**
  - Replace the D §3 row with "ruled by F R300".
  - Add a ~10-line `deriveRoleKey(seed, {kindNo, account, i})` (BIP-32/SLIP-10 at `m/7622'/0'/…`) to D1 or D2 as
    plain derivation. F3 later wraps it in `UAKey` without changing the path.
  - D6 and A3 use the role key for every key added to a subject account.
  - Add a "role path" column to §7.1. Per family, state which key a seed **adds** to a subject account: the role key,
    or the native key only when it is the account's owner/first key.
  - Add a vector: role key ≠ native key for the same seed.

### H2 — With the switch ON, a compromised key or a hostile guardian cannot be removed

- **Section:** R252(c), §4.1 row "ON / has backup / key ops: all except those that would break the predicate", §4.3
  last paragraph (`hasBackup(after)`).
- **Problem:** Take an account with 2 keys where one is stolen. "Remove key" leaves 1 key and no guardian, so the
  client refuses it. A guardian can add its own key after the delay (`start_recovery`/`initiateRecovery`), so a
  compromised or hostile guardian is a takeover path. "Set guardian to none" is refused too. A switch that the spec
  itself says "is not a security control" must not block the most important security operation. Sui and Solana have no
  atomic rotate (Sui `manage` does one action per call), and in an emergency the user may have no second key at hand.
- **Evidence:** `SubjectAccount.sol` `removeKey`/`setGuardian`/`initiateRecovery`; Sui `meta.move` `manage`
  REMOVE_KEY and `start_recovery`.
- **Fix:** Allow remove-key and clear-guardian in every state, with a warning. After they run, the account is in the
  "no backup" state (value ops refused, exits allowed, add-backup offered first). Where `rotateKey` exists (EVM), offer
  it as the default. Elsewhere, offer "add new key, then remove". Add `backup_policy.json` rows asserting that removal
  is allowed and produces `NO_BACKUP`.

### H3 — The predicate counts duplicates and self-guardians as a backup; H4 is not folded in

- **Section:** R251, §4.2, §4.3 (`keys: Array<{scheme, be?, bs?, rpId?}>`), §4.4 `_dms_has_backup`, R252(c) / §4.1
  "add origin".
- **Problem:** Several cases make an account look backed up when it is not:
  - **EVM.** One credential on two origins is two `SubjectKey`s, because `keyId` hashes `originHash`. `keyCount` is
    therefore 2, the predicate says "backed up", and Odoo's row count agrees. APP lists this as H4 and amends D
    (R165, §6.3, §17), but D rev 1 does not carry the amendment. `keys[]` has no public key, so it cannot deduplicate.
  - **Soroban.** `scaas-account.add_key` has **no** duplicate check (`lib.rs` `add_key` just `m.set(id, key)`).
    Re-adding the same seed key, for example after re-importing the phrase on a new device and pressing "add backup"
    again, yields 2 keys from one secret. Soroban accepts "≥ 2 keys only", so this is the easiest false positive there.
  - **Sui.** `Key = {scheme, public_key, rp_id_hash}`, so the same public key under a different `rp_id_hash` counts
    twice.
  - **Guardian equal to the account's own key.** Sui's guardian is an address and the owner **is** a native address
    (`blake2b(flag‖pk)`). `SET_GUARDIAN` to the owner's own address gives "1 key + guardian", backed by one secret.
    The same happens on EVM with guardian = the EOA of the only SECP256K1 key, or the account's own address.
  - **"Add passkey origin"** is listed as an operation that *creates* a backup (R252(c), §4.1 key-ops column). It
    never changes the key count.
- **Evidence:** `SubjectAccount.sol` `_addKey` (`hasKey[keccak(abi.encode(key))]` includes `originHash`); Soroban
  `account/src/lib.rs:185`; Sui `meta.move` `add_key`/`Key`; APP R165, §6.3 amendment, §17 "Spec D" bullet.
- **Fix:**
  - `keys[]` carries the canonical public key (P-256 `x`, secp256k1 address or x, ed25519 pk). `hasBackup` counts
    **distinct** public keys.
  - Ignore a guardian equal to the account address or to the native address of any key in the set.
  - Odoo `_dms_has_backup` deduplicates by `(public_x, public_y)` / `evm_address`.
  - Move "add origin" out of the backup flows: it is "always allowed", not "creates a backup".
  - Add the APP R176 `msig` rule.
  - Add JSON rows for: same credential on two origins → 1; Soroban same key twice → 1; guardian = own key → no backup.

### M1 — "Exits are never blocked" (R253) contradicts the §4.1 table

- **Section:** R253 title vs §4.1 row "ON / subject, no backup, satisfiable / value ops refused".
- **Problem:** Exit is offered only for unsatisfiable kinds. A satisfiable account with funds and no backup (funded
  before the switch turned ON, or a key removed under H2's fix) can only run backup flows. That breaks SCaaS §9.2,
  which R253 itself cites: "rescue/exit operations are never throttled".
- **Fix:** Add `allow.exit = true` in every state. In §4.1, add "exit (whole balance out, warning)" to the satisfiable
  no-backup row.

### M2 — Vault migration: which copy wins, stale-blob rollback, and the delete step are underspecified

- **Section:** R257, §5.4 step 2–3.
- **Problems:**
  - **Precedence is unspecified.** Suppose the `localStorage` delete fails. §5.4 says "any failure keeps the old
    entry", so the next load finds both copies, and nothing says which one opens. If the stale v1 (old passphrase,
    possibly `N = 2^15`) is migrated again over a v2 whose passphrase was changed since, the passphrase rolls back.
    And as long as the stale weaker blob stays in `localStorage`, it is exactly the "blob leaked alone" target v2 was
    built against.
  - **Deleting the entry hurts old code.** Older portal JS (a cached bundle in another tab, or a module rollback)
    reads `localStorage` only. It sees "no vault" and offers create/import (`unlockPhrase` → "Replace it" path), so the
    user can silently end up on a new seed.
  - **The decrypt check re-runs scrypt.** "Read back and open once" through `openVault` costs a second 128 MiB run
    and needs the unlock secret again.
- **Fix:**
  - If `vault:<id>` exists in IndexedDB, it wins. Never `put` over an existing `vault:<id>` during migration.
  - Replace the `localStorage` value with a tombstone `{"v":2,"moved":"indexeddb"}` instead of removing it. Old code
    then fails with "Unknown vault version." (`dekFrom`) instead of offering create.
  - Make the decrypt check `openDevice(readBack)` deep-equal the in-memory v1 object: AES-GCM only, no scrypt.
  - Add tests for put-fails, readback-fails, delete-fails, both-present and stale-v1.

### M3 — scrypt `2^17`: mobile failure is a renderer OOM kill, not a `RangeError`, and re-wrap can crash-loop

- **Section:** R259, §5.6.
- **Problems:**
  - On low-memory Android/iOS, a 128 MiB allocation usually succeeds and then the OS kills the renderer or the
    WebContent process. The "`RangeError` ⇒ refuse" path rarely fires.
  - Worse, portal vaults at `N = 2^15` are re-wrapped **during the unlock that precedes a payment**
    (`upgradeVault` → `rewrapPin`). If that crashes, it crashes again on every unlock, so the user can never pay from
    that device.
  - On open, `dekFrom` takes `N, r, p` from the stored blob without bounds. Only an XSS or IndexedDB writer can plant
    a blob, so this is low, but bounding is free.
- **Fix:**
  - Write a "rewrap attempted at N" marker before re-wrapping, and skip the re-wrap if the marker is present on the
    next load.
  - Re-wrap after the payment is submitted, not before.
  - On open, refuse `N > 2^17`, `r ≠ 8`, `p ≠ 1`.
  - Keep the `RangeError` test, but word R259 as "allocation or crash".
  - In the app, scrypt runs in the key worker (R175). A worker OOM can still take the tab down on iOS, so use the
    same marker there.

### M4 — The backup seed key does not need to live on the device (simpler and safer)

- **Section:** §4.4 portal flow ("seed if the first key was a passkey"), R253 ("the one key the user holds can always
  sign them"), R259 cost line.
- **Problem:** The add-backup flow assumes it creates a seed vault on the same device as the passkey. That puts the
  "backup" in the same profile as the primary key. It also makes the switch unsatisfiable on exactly the devices R259
  says cannot create a passphrase vault.
- **Fix:** Make the backup flow show the phrase, run the 3-word check, derive the role key (H1), sign `addKey` with
  the existing key, and **not store** a vault (store one only if the user asks). The secret then lives only on paper,
  there is no scrypt on the device, and low-memory phones can comply. R251's "written down" rationale already covers
  it.

### M5 — Gaps in the threat model's honesty (§5.3, R256)

- **Problems:**
  - **Browser extensions.** The "blob leaked alone" row lists "a browser extension reading `localStorage` only". Any
    extension with host access runs content scripts with the origin's IndexedDB **and** `crypto.subtle`. It belongs in
    the XSS row (device key as decrypt oracle), not in the row v2 defeats.
  - **The portal origin's TCB is not stated.** The portal runs on the Odoo website origin. Website designers can embed
    arbitrary HTML/JS, and every installed module's frontend assets run there too. That is same-origin script by design,
    so the XSS row's "CSP, no third-party scripts" control does not hold for the portal.
  - **"Hardware-bound" overclaims.** BE = 0 is self-reported and we create with `attestation: 'none'`. The PRF
    **output** is also returned to page JS: one XSS during a PRF unlock yields a permanent unwrap key for that blob.
    v2 still needs the device key, but the "hardware-bound" row overclaims.
  - **Safari is mis-stated.** It wraps IndexedDB CryptoKeys under a Keychain key (stronger than stated). ITP's 7-day
    script-storage eviction then deletes the vault, which matters for R258's "clearing site data = losing the device"
    copy.
- **Fix:** Edit the text only. Move extensions to the XSS row. Add a "portal origin TCB" row (recommend a dedicated
  payment subdomain as a deployment note). Reword BE = 0 as "not synced, as reported". Add an ITP line to R258.

### M6 — `checkTerms` → `sign`: check-then-sign gap, and incomplete must-check lists

- **Section:** R267, §7.2, §9.2 wallet interface, §9.3 flow.
- **Problems:**
  - **The signed bytes are not the checked bytes.** §9.3 runs `fam.checkTerms(start, shown)` and then
    `signer.sign(start)`. The connectors sign raw `start` fields: Sui signs `terms.payload_hex`, Solana signs
    `terms.text`. If `checkTerms` checks `payload_hex` but the wallet signs `text` (or `message_b64`), a mismatch passes
    the check.
  - **No per-family must-check list.** None is given beyond "amount, payee, account, network, token, fee/relayer".
  - **Portal `shown` is not independent.** In the portal it comes from the same Odoo response: `subject_signers.js`
    passes `start.amount` and `start.chain.tokenDecimals` to `checkPayment`, and options carry no amount or decimals
    for non-EVM. So in the portal the check is internal consistency, not protection from the issuer. That is fine, but
    the spec should say so.
  - **"Every family" is not covered.** R267 says it, but D4 defines `checkTerms` only for Soroban, Aptos and Solana.
    TON, Cosmos and Hedera ED25519 (`window.dmsHederaSigner` seam) have neither a check nor a tour in D5.
- **Fix:**
  - `checkTerms` returns the verified `signingInput`, and `wallets/*.sign()` accepts only that value, never `start`.
  - List per family:
    - **Sui:** `message_b64 == payload_hex`; `contract == derive_account(registry, from)`; `from` = owner;
      `op == PAY`; `relayer == 0x0`; `extra == 0³²`; `valid_until` window.
    - **Solana:** `text == "scaas.metaop.v1:" + hex(sha256(payload))`; account = PDA(owner); asset; network.
    - **Aptos:** `application == location.origin`; `chainId`; `nonce == lane`.
    - **Soroban:** decode the invocation (token, function, args); bound `signature_expiration_ledger`.
  - State the portal limitation in R267.
  - Either add `checkTerms` and a tour for TON, Cosmos and Hedera ED25519, or scope R267 to the families D covers.

### M7 — R260's added/recovered-key payments cannot be reached from the portal

- **Section:** R260, §7.2 Solana `packSignature` (key index), §9.3 (`start(order, signer.from, …)`).
- **Problems:**
  - The portal sends `signer.from` = the wallet's own address. For an added or recovered key, the client must send the
    owner. A Sui `Account<T>` is derived from the owner only (no reverse index), and the portal has neither chain RPC
    nor a non-EVM mirror (a non-goal).
  - Solana's blob needs the added key's `key_index`, which requires reading the PDA.
  - So in the portal, R260's fix helps only clients that remember the account: the app's find-my-account (APP §6.4),
    or a vault that recorded it.
- **Fix:**
  - State that in the portal, non-EVM extension and seed signers pay with the owner key only. Added keys pay through
    the app, or through the portal once it stores `{family, account, owner, key_index}` beside the vault.
  - Have `verifyKeyOp` also check `op.account`, `op.network`, the `valid_until` window and, for passkeys,
    origin ∈ `account.origins`. Today it checks only nonce and membership.

### M8 — §10 streams diverge from APP §15

- **Problem:** APP splits D into D5-evm (before A2, depending only on A0-evm), D4-<f> and D5-<f> inside each family
  stream A9–A14, and A16 = D7 after A10–A14. D §10 keeps monolithic D4/D5, with D5 depending on D4, which would hold
  `wallets/evm.js` behind the non-EVM seed signers. The role-path dependency of H1 (D6/A3 vs F3) is also missing.
- **Fix:** Rewrite §10 to match APP §15: D5-evm, D4-<f>, D5-<f>, and D6 needing the D1/D2 `deriveRoleKey` (or F3).
  State the F0/F3 edges: the KeyOp domain gets bumped by F §8.3 `keyop`, so keep D3's encoder parameterized by domain.

### L1 — Build: no stable entry names for `fam-*` and `wallets/*`

- **Section:** §9.2, §9.3 (`import('…/fam-<family>.js')`).
- **Problem:** The esbuild entries are `passkey-signer`, `seed-signer`, `zether-keys` (+ `wallet-signer`). Other files
  become `chunk-[hash].js`, so `fam-<family>.js` cannot be imported by name. "`wallet-signer.js` re-exports `wallets/*`
  … one chunk per family via splitting" is wrong: static `export *` puts every family in the entry chunk.
- **Fix:** Use per-family entries (`fam-sui.js`, `wallets-sui.js`, …), or a `load(family)` with explicit dynamic
  `import('./wallets/sui.js')` cases. Keep `bundle.test.js`.

### L2 — EVM key enumeration and the Odoo mirror's blind spots

- **Section:** §4.2 EVM row, §4.4.
- **Problems:**
  - `keyAt(i)` slots are sparse after `removeKey` (`nextKeyIndex`; `delete _keys[index]`). Iterating `i < keyCount`
    reads holes and misses tail keys, so the H3 dedup needs `0 … nextKeyIndex−1`, skipping `kind == NONE`.
  - Odoo's `key_state` has no "removed" state, and removals done in the app are not mirrored, so Odoo over-counts.
- **Fix:** Correct the read. Record the removal blind spot next to the `setGuardian` one (the switch is soft).

### L3 — Sui `True` does not mean "member"; dead-job cost

- **Section:** R260, §6.2.
- **Problem:** The owner's own key can be removed by KeyOp (vector `k_a2_rm_a`) and still verify `True`, so
  `signature_verified` means "payer's own key", not "will pass". Any valid signature from any key now queues a job
  that blocks `_live_job` until simulation fails. That needs portal access to the order, so the risk is low.
- **Fix:** Say so in R260. Optionally add Aptos's cheap origin check (portal origin == clientData origin) to Sui's
  passkey path to cut dead jobs.

### L4 — Vector files

- **Section:** §4.6, R262, §6.4.
- **Problems:**
  - `backup_policy.json` outputs `{ok, reason, allow}`, but the Solana Rust test asserts the boolean `has_backup`, so
    it cannot consume those rows without re-implementing `backupStatus`.
  - Once the H3 dedup rows exist, the built on-chain `has_backup` (no dedup) disagrees with them.
  - R262 has no guard against a partial regeneration (only `vectors.move`, or only the JSON).
  - `scaas-node/src/adapters/sui.rs` also pins Sui vectors and is not listed as a consumer.
- **Fix:**
  - Add `has_backup` to each row, plus a `families` filter.
  - Have the JSON carry `sha256(vectors.move)` and check it in a test.
  - List the Rust adapter as a consumer, or confirm it pins only deterministic ed25519 vectors.

### L5 — Tests miss the real-browser and failure paths

- **Section:** §5.5, §9.4.
- **Problems:**
  - The `Map` store never exercises CryptoKey structured clone in IndexedDB. Only a Chromium portal tour does.
  - The M2 failure paths are untested.
  - The M3 re-wrap marker is untested.
  - Cross-family passkey challenge separation (one credential on several chains is allowed by F §8.1) is only
    implicit: separate hash functions and preimage prefixes.
- **Fix:**
  - Add one Playwright run of the vault round trip on Firefox and WebKit (APP already uses Playwright).
  - Add the M2 and M3 tests.
  - Add one `fam/*` test asserting the challenge preimages are pairwise prefix-distinct.

### L6 — Over-engineering and noise

- **Problems and fixes:**
  - `UNSATISFIABLE` and `NATIVE_PASSKEY` behave identically (exit only, hidden receive). Merge them into one reason.
    Cosmos is currently classified twice (R253, §4.5).
  - The `SAME_KEYCHAIN` warning ("all keys are passkeys of one `rpId`") fires for almost every multi-passkey account,
    because every passkey on a deployment shares its `rpId`. Fire it only when all are BS = 1, or drop it.
  - Persisting BE/BS at creation (R254, in Odoo label data) is unnecessary: the flags are in every assertion's
    authenticatorData. Read them at use and cache them in the client only.
  - `kid` / `device-key:v1` versioning has no rotation flow. Drop it, or say it is for a format bump only.
  - The `persist()` refusal notice will show for most Chrome users (silent heuristic denial). Show it once, or only
    when denied on Firefox's prompt.

### L7 — Seed reveal flow not addressed

- **Section:** R251, R258.
- **Problem:** R251 relies on show-once plus the 3-word check. The spec does not say whether any "show my phrase
  again" exists. With a vault holding the entropy, someone will build one.
- **Fix:** State one of two rules. Either: no re-reveal, ever. Or: re-reveal needs the passphrase (not PRF alone) plus
  the device key, then re-runs the challenge, and is never offered while the switch counts the key as "written down"
  unless re-verified.

---

## Not findings (checked)

- Sui `None` cannot settle a payment. Settlement is chain-event-driven (`_apply_events`), and `signature_verified` is
  read nowhere.
- `keyop_bytes` field order matches Move `KeyOp` and the generator's private copy exactly.
- Solana OCMS v1 bytes in R263/§7.2 equal the connector's `expected` and `fam_solana.wallet_message`.
- The seed paths are the ecosystem standards. Pi uses 314159, and `solana-keygen prompt://?key=i/0` is
  `m/44'/501'/i'/0'`.
- The cross-repo vector reads are fine: `blockchain-ci.yml` checks out scaas into `addons/bamboo-dms/scaas`.
