# V2 — Claude, part 2 of 3: UA registry, kinds and verifiers, `account/`, `wallet/`

Tree: `/home/ha/work/ainative/scaas/.claude/worktrees/rev3`, detached at `7aab1fe`. This was a static read only: nothing
was built, run or deployed. All paths are relative to `smartcontracts/evm/src/` unless they start with `docs/`.
Scope: `ua/**` (24 files, ~3.5 k lines), `account/SmartKeyAccount{,Factory}.sol`, `wallet/MandateWallet.sol`. I also
read the code those call, as far as part 2 needs it: `common/{WebAuthnClientData,SigCheck,SaltedEIP712,SSTORE2,CurveSigs}.sol`,
the head of `common/Ed25519.sol`, `metatx/MetaTxBase.sol` (guard, ticket, `_msgSender`), the registry consumers in
`metatx/ERC20MetaTx.sol:425-455` and `pqz/PqzLib.sol:779-791`, and the vendored OZ `ECDSA` / `P256` / `MerkleProof`.
Spec: `docs/contracts/accounts.md` §1.3–1.16, §2, §3; `docs/contracts/mandates.md` CTR-ACC-06/07; `docs/decisions.md`
CTR-UA-06.

**Summary:** I found no P0 or P1. The registry's generation rules, keyHash groups, PoP binding, msig bound and per-kind
verifiers match the spec, and every verifier I checked fails closed. I found one P2 (a privacy weakness in how decoys
are chosen) and five P3s.

---

### V2-1 — P2 — Anyone can flood the per-kind decoy list (CTR-UA-29) for free on 7622 and shrink the anonymity of PQZ / Zether multi-recipient transfers

**Locations:**
- `ua/UARegistry.sol:229-234` (`_list`), `:348` (every `register` appends), `:242-262` (`uaCount` / `uaAt` / `uaPage`).
- `docs/contracts/accounts.md:1086` (CTR-UA-29: "wallets pick decoys … from the UAs registered under the token's kind
  … how a wallet reads the list (all, ranges, random) is its own decision").
- `smartcontracts/evm/foundry.toml:36` (chain 7622: "base fee stuck at 0, so gas is free").

**Trigger:**
1. An observer O generates N fresh keys.
2. For each key, O calls `register(ZETHER_BN254 | PQZ_MLWE, Y_i, pop_i, authRef, authPop)` with its own PoP.
   - For `pqz-mlwe`, one PQ signing UA of O's can be the `authRef` of every record. `_checkPqzAuthRef` (`:390-403`)
     puts no limit on reuse.
3. Every record is appended to `_uaAt[kind]` (`:348` → `:229`).
4. A wallet that samples decoys from `uaPage(kind, …)` (uniformly or by range) then picks O's UAs with probability
   about N / (N + honest).

**Impact:**
- O knows that none of its own UAs is a real sender or recipient. Each decoy drawn from O's set therefore drops out of
  the anonymity set, as far as O is concerned.
- With N ≫ honest, a multi-recipient transfer is close to non-anonymous towards O.
- Registration needs no `msg.sender` state, no stake and no activity. On 7622 the only cost is block gas
  (pqz-mlwe ≈ 3.4 M per record for the 16 KB SSTORE2 key).
- The S6 mitigation ("sponsorship policy at the node") does not apply: O pays its own gas.

**Confirmed or hypothesis:**
- The on-chain mechanics are confirmed by reading the code.
- The privacy loss is a **hypothesis about wallet policy**. The spec leaves decoy choice to wallets, and I did not
  review the wallets' samplers.

**Suggested fix (no bytecode change needed):**
- Add a decoy-selection rule to the spec, e.g. weight or filter decoys by on-chain activity in the token (a non-zero
  `accHash` or pending queue), not by registration alone.
- Record "Sybil decoys" as a threat in §1.14, next to S6.
- If an on-chain filter is wanted later, the token (not the registry) could keep a list of UAs it has actually
  credited. That changes the token bytecode, not the chainspec or the proof vectors.

---

### V2-2 — P3 — The `secp256k1` kind (0x0108) needs raw-hash ECDSA signatures from EOA keys, which contradicts the "never a raw hash" rule (layer 4 / S23)

**Locations:**
- `ua/verifiers/Secp256k1Verifier.sol:14-22`: `ecrecover(message, v, r, s)` over the bare 32-byte `ua_msg`, with no
  EIP-191 or EIP-712 wrapper.
- `docs/contracts/accounts.md:342`: "the same id for a MetaMask key on every chain".
- `docs/contracts/accounts.md:157-161`: CTR-UA-06 as amended 2026-10-17.
- `docs/contracts/accounts.md:270-274` (layer 4: "EOAs … sign only their wallet-native formats … never a raw hash")
  and the S23 row ("none on our paths").

**Trigger:**
- A MetaMask user registers their EOA key as `secp256k1`, which is the purpose the decision gives for the kind.
- The PoP and every later signature are ECDSA over a raw 32-byte hash.
- MetaMask can produce that only through `eth_sign`, which is disabled by default and flagged as dangerous.

**Impact:**
- **Usability:** for the wallets named in the spec, the kind cannot be used without raw-hash signing.
- **Security:** a client that enables raw-hash signing for this kind trains users into the `eth_sign` habit. A phishing
  page can then ask the same key to raw-sign `keccak256(rlp(tx))` and drain the EOA. That is exactly the S23 class the
  spec says is closed "on our paths".
- On chain, `ua_msg` is tagged, so no SCaaS signature can be replayed as an Ethereum transaction. The risk is only
  this wallet-behaviour channel.

**Confirmed or hypothesis:**
- The contradiction between the spec and the code is confirmed.
- That users will actually be phished is a hypothesis, because it depends on client behaviour.

**Suggested fix:** pick one of these.
- (a) Verify `ecrecover(toEthSignedMessageHash(ua_msg))`, i.e. the EIP-191 `personal_sign` form, which MetaMask signs
  natively and which can never be a transaction hash. This changes the deployed `Secp256k1Verifier` bytecode, its
  `kinds.json` / `signatures.json` / `metatx3.json` / `uatrade_kat.json` vectors and the six client libraries. All
  chains are test-only, so no migration is needed. (b) Keep raw ECDSA but rewrite layer 4 and S23. State that 0x0108 is a
  raw-hash scheme, that only SCaaS signers (clientkeys) may use it, and that an EOA key should not be registered as
  0x0108 from a general-purpose wallet.

---

### V2-3 — P3 — `MandateWallet.isValidSignature` accepts the owner's raw ECDSA over any digest (the ERC-7739 class), and the spec does not document it for this contract

**Locations:**
- `wallet/MandateWallet.sol:182-185`.
- For comparison, `docs/contracts/accounts.md:1720` documents the same limitation for `SmartKeyAccount` only.
  `docs/contracts/mandates.md` does not mention it.

**Trigger:**
1. Owner EOA E holds a `MandateWallet` W.
2. E signs any third-party typed-data digest D that does not bind the signer, for its own use. Uniswap Permit2's
   `PermitSingle` / `PermitTransferFrom` hash is the standard example: the owner is not in the struct.
3. Anyone can present D's signature as W's ERC-1271 signature, and it validates (`MandateWallet.sol:183-184`).
4. If W has ever approved such a protocol (through `execute`, `:100-106`) and its nonce there is unused, the permit can
   be replayed against W's funds.

**Impact:** W's funds are at risk only when W itself uses a third-party protocol whose digest does not include the
signer. All SCaaS digests bind `from` / `verifyingContract`, so none of ours replay.

**Confirmed or hypothesis:** the mechanism is confirmed. Its reach depends on W interacting with such protocols.

**Suggested fix:**
- Add the CTR-ACC-05 "Documented limitation" paragraph to `mandates.md` (CTR-ACC-06).
- Or wrap the hash ERC-7739-style, as the spec already rejected for `SmartKeyAccount` because it changes every KAT.

---

### V2-4 — P3 — The mandate's period is a fixed window that resets on demand, so the delegate can spend 2 × `maxPerPeriod` across a window boundary

**Locations:** `wallet/MandateWallet.sol:125-131`.

**Trigger:**
1. The delegate (for example a compromised platform custody key) pays `maxPerPeriod` at `periodStart + periodSeconds − 1`.
2. One block later, `block.timestamp >= periodStart + periodSeconds` resets `spentInPeriod = 0` and
   `periodStart = now`.
3. The delegate pays `maxPerPeriod` again.

**Impact:** the effective worst case is 2 × `maxPerPeriod` within seconds, not per `periodSeconds`. It is still bounded
by `maxPerPayment`, the approved payees and single-use `entryRef`s.

**Confirmed or hypothesis:** confirmed. The spec ("≤ the per-period cap", `mandates.md:20`) does not say whether the
window is fixed or rolling.

**Suggested fix:**
- Document the fixed-window semantics in CTR-ACC-06, so owners set `maxPerPeriod` as half of the burst they accept.
- Or align the window: `periodStart += periodSeconds * ((now − periodStart) / periodSeconds)`, instead of `= now`.
  That is a bytecode change only.

---

### V2-5 — P3 — Running out of gas before gen 1's hold check, when gen 2 hands off a check, comes back as "unauthorized", not `UAVerifyGas`

**Locations:**
- `ua/UARegistry.sol:658-671` (`_viaPredecessor`) and `:564-576` (`_zetherViaPredecessor`): any revert other than the
  4-byte `UAVerifyGas` becomes `false`.
- The comment at `:667` says "a starved caller must see UAVerifyGas, never a verdict".
- Gen 1's work before its hold (`:486-497`, `:502-530`: an SLOAD, `abi.decode(auth)`, `uaOf` / `uaMessage` keccaks,
  `SSTORE2.read`) runs without a gas check. The hold at `:648` comes later.
- In gen 1's `_native` path, ECDSA (`:614-617`) runs without any hold at all.

**Trigger:**
1. A consumer bound to gen 2 (a token) calls `gen2.requireAuthorized(gen1Ua, …)`.
2. It does so with so little gas that the 63/64 forwarded to gen 1 runs out before gen 1 reaches `_capped`. That
   means roughly under 10–20 k gas, either at the top level or at member *i* of a gen-2 msig.
3. Gen 1 reverts with empty data, gen 2 catches it, and the call ends in `UAUnauthorized(ua)` instead of `UAVerifyGas`.

A gen-1 direct call starved the same way gives a plain OOG with no data. `PqzLib.sol:787-791` maps that to
`AuthRejected`.

**Impact:**
- Every path still fails closed and reverts, and no consumer I read changes state on a failed authorization.
- What is wrong is the classification: a relayer or node that tells "re-send with more gas" (`UAVerifyGas`) apart from
  "bad signature" (`UAUnauthorized` / `AuthRejected`) can be misled.

**Confirmed or hypothesis:** the code path is confirmed. That any off-chain component branches on the error is a
hypothesis.

**Suggested fix:**
- At the top of `_viaPredecessor` / `_zetherViaPredecessor`, revert `UAVerifyGas` unless
  `gasleft() >= MIN_HANDOFF_GAS` (a constant covering gen 1's pre-hold work).
- Alternatively, inside `catch`, re-raise `UAVerifyGas` when the error data is empty and `gasleft()` is below
  `MIN_HANDOFF_GAS / 63`.
- Either option changes gen-2 bytecode only. No gen 2 is deployed on 7622 today, so nothing needs migrating.
- Also narrow the comment at `:667` to "at the hold".

---

### V2-6 — P3 — Hygiene: an interface gap and an unpinned dependency

- **Interface gap.** `IUARegistry` (`ua/IUARegistry.sol:36-94`) does not declare `chainKeyHash()`, but the spec's
  interface block lists it (`docs/contracts/accounts.md`, §1.8 interface). The contract does expose it as a public
  immutable (`UARegistry.sol:92`).
  - Gen 2's predecessor check (`UARegistry.sol:142-147`) compares `generation`, `chainUid` and `hederaNative`, but not
    `chainKeyHash`. This is harmless, because `chainUid` already separates chains.
  - Fix: add the getter to the interface.
- **Unpinned OpenZeppelin.** OZ is not vendored and not pinned:
  - `smartcontracts/evm/.gitignore:3` ignores `lib/`, and the README says "v5.2+".
  - The local checkout is an untracked symlink to `/home/ha/work/blockchain/openzeppelin-contracts` @ `fda6b85f`
    (2025-03-13, between v5.2 and v5.3).
  - Several checks in scope depend on that code's exact behaviour: the low-s rule (`ECDSA.tryRecover`; used at
    `UARegistry.sol:615`, `SmartKeyAccount.sol:293`, `MandateWallet.sol:183`), `P256.verify` / `verifySolidity` and
    `MerkleProof.processProof`.
  - The registry also hard-codes EIP-1167 bytecode (`UARegistry.sol:171-175`), which has to match `Clones`.
  - Fix: pin OZ to a tag or commit (a submodule or `foundry.lock`) and record it in the deploy profile.

---

## Checked and clean (by directory)

### `ua/UARegistry.sol`

- **Admin-free and monotonic (CTR-UA-15).**
  - There is no owner, setter or `payable`.
  - Records are written once at `:348`. A second registration reverts `UAAlreadyRegistered`, checked in this
    generation and the predecessor (`:342`).
  - `register` is permissionless, but every field derives from `keyData` and the signed PoP and `authRef`. So
    front-running it yields the same record or a revert. I traced S5 against `:340-351`.
- **Kind table.**
  - Each kind's verifier and cap are an immutable (`:95-115`).
  - The slot mapping `:689-697` round-trips with `_cfg` `:675-685`.
  - Duplicate kinds, a verifier with no code, a cap of 0 or a cap above the budget are refused (`:152-155`).
  - `msig` is not in the table; it is `_CFG_MSIG`, which holds `address(this)`.
- **Generations.**
  - Gen 2 refuses any kind whose keyHash group gen 1 enables (`:154`, `:715-724`; iterates every derived kind up to
    0x0142, `msig` excluded).
  - `kindOf` / `keyOwner` / `recordOf` / `keyOf` / `uaIndex` / `uaCount` / `uaAt` / `uaPage` fall back to the
    predecessor correctly (`:213-283`).
  - `_authorized` hands unknown records to gen 1 (`:493`).
  - In `_derived`, a member of a kind gen 2 does not enable goes to gen 1 with `abi.encode(keyData, sig)`, and
    stored-kind members must carry empty `keyData` (`:511-527`).
  - An `msig` registered in both generations gets two records with identical content. The spec allows this
    (accounts.md §1.8 "Generations"), and each generation keeps its own list.
- **Register steps.**
  - Steps 1–8 run in spec order (`:330-352`).
  - Native-space ids are refused (`:341`).
  - `authRef` rules:
    - Zether: 0, a native id, or SIGNING but not same-curve BLS (`:375-385`).
    - `pqz-mlwe`: a PQ kind, or an msig whose classical weight is below the threshold, with its key data
      hash-checked against `authRef` (`:390-403`).
    - Every other kind: both fields empty.
  - The co-sign is over `popDigest(ua, authRef)` with purpose `authref` (`:366-370`).
  - `popDigest` binds `chainKeyHash`, `chainUid`, the registry address, `ua` and `authRef` (`UAKinds.sol:212-216`),
    which covers S4 and S26.
- **msig bound** (`:436-473`).
  - The `c` lightest weights are taken in ascending order. That is the worst case, because `_msig` stops at the
    threshold (`:592`), so no accepted set has more than `c` members.
  - The worst case adds the `c` largest caps, `c × MSIG_MEMBER_GAS`, and the `(held − 400k)/63` term.
  - A member handed to gen 1 counts `cap + cap/63 + 5k`.
  - Natives count 400 k when a clone codehash is configured.
- **msig verify** (`:580-604`).
  - Member indexes must be strictly increasing and below `count`; any signature after the threshold is reached fails.
  - `member_digest = keccak(ua ‖ ua_msg(MSIG, …))`.
  - Native members must carry empty `keyData` and are checked under `UAAuth(memberId, PURPOSE_MEMBER, md)`.
  - A same-curve BLS member inside an msig `authRef` is a known residual (S12) and is not re-raised here.
- **Native path** (`:609-629`, CTR-UA-24).
  - Signatures are always over `uaAuthDigest`. Empty code ⇒ ECDSA. The 7702 designator ⇒ ECDSA, else ERC-1271.
  - OZ `tryRecover` refuses high-s and `address(0)`.
  - ERC-1271 needs exactly 32 bytes equal to the left-aligned selector (`:622-628`).
  - SSTORE2 pointers and verifier contracts answer nothing and therefore fail.
- **`_capped`** (`:643-654`).
  - The hold `cap + cap/63 + 5000` is enough for a cold `STATICCALL` under EIP-150. I worked through the arithmetic.
  - Success requires `success ∧ returndatasize == 32 ∧ word == expect`.
  - The group PoP has no hold, by spec, and a starved one is `UAPoP`.
- **Zether** (`:535-561`).
  - A Zether record never signs through `requireAuthorized` (`:494`).
  - For a self Zether UA with `zkCovered`, `auth` must be empty. For an owner op it is a Schnorr by `Y` from `keyPtr`
    under the Zether tag.
  - `pqz-mlwe` can never have `authRef = 0`.
  - The consumers check the kind of `from` themselves: `PqzLib.sol:841-847` and `ZetherLib.sol:582-584`.
- **ML-DSA cache** (`:299-326`).
  - The expanded key is derived by the verifier from the authenticated `pk` and stored under `uaOf(kind, pk)`. A part
    is never rewritten.
  - The cache is refused when the verifier has a precompile.
  - `verifyCached` checks part lengths, count and total length (`MlDsa.sol:510-526`).
  - `verifyExpanded` / `verifyCached` are public oracles for universal forgery, as documented, but `grep` shows that
    only the registry calls them.
- **Per-kind list.** `uaPage` clips at the end (`:253-262`). `Record` packs into exactly 256 bits (16+40+160+40).

### `ua/UAKinds.sol`

- **Validation.**
  - P-256 and secp256k1 x/y: coordinates below p and on the curve.
  - BIP340 x: lifted with one MODEXP.
  - ed25519: canonical y, decompresses, no negative zero, and the 8 small-order encodings refused; these match
    `Ed25519.smallOrderY`.
  - bn254 G1: canonical, on the curve, not the identity.
  - bn254 G2: pairing with G1 under a capped gas budget, so the precompile does the subgroup check.
  - BLS12-381: MSM with scalar 1 under capped gas (subgroup and padding checked by the precompile), identity refused.
  - MuSig2 / FROST: point checks, sorting with a byte-lexicographic `_lt` that handles the 33-byte tail correctly, and
    `μ < order`.
  - msig: count ≤ 16, the exact length, member ids strictly increasing (the `o − 34` offset is correct), weights ≠ 0,
    native kind ⇔ native space, `0 < threshold ≤ Σ`.
  - FN-DSA pk: header byte and every coefficient below q.
  - Every precompile call either holds enough gas or reverts `UAVerifyGas`.
- **keyHash groups** (`:188-200`): x-only for secp256k1 and P-256, the full point for bn254 / BLS / ed25519, the
  whole key for PQ. MuSig2 / FROST take `Q` / `Y` from offset 1 (secp) or 0 (bn254).
- **`ua_msg`** contains no chain or registry binding by design. Cross-chain safety rests on the consumers'
  EIP-712 digests: `ERC20MetaTx` (`:346, :358, :384, :146-171`) uses fixed purposes and salted domains, and
  `PqzLib:786` uses the statement hash. That is parts 1 and 3.

### `ua/verifiers/*`

- **`P256Precompile`.**
  - The probe sends a valid vector and checks that the flipped vector is refused.
  - On the precompile path, the r and s ranges, low-s (`P256.N/2` equals OZ `HALF_N`) and `isValidPublicKey` are
    checked before the call.
  - The Solidity path, OZ `verifySolidity`, enforces the same checks (`_isProperSignature`, `isValidPublicKey`).
  - The two paths agree on every input I could construct.
- **`WebAuthnP256Verifier`.**
  - The ABI blob is decoded with bounds checks; non-canonical encodings are accepted, but nothing keys replay on the
    signature bytes (I grepped).
  - `rpIdHash` is checked, UP and UV are both required, and the strict clientDataJSON grammar
    (`common/WebAuthnClientData.sol:14-35`) binds challenge = base64url(`ua_msg`) and refuses `crossOrigin:true`.
  - Any origin is accepted, as documented in S9.
- **`Secp256k1Verifier`:** low-s, `v ∈ {27,28}`, r and s ≠ 0, the address from `keccak(x‖y)`.
- **`Bip340`.** The `ecrecover` identity Q = sG − eP is correct. R's even y is enforced through `liftX`. `rx ≥ p`,
  `s ≥ n` and `px ≥ p` are refused. `px ≥ n` and `e = 0` fail closed, as documented.
- **`Musig2Secp256k1Verifier`:**
  - KeyAgg (BIP-327) matches: the coefficient for the second key is 1, and each hint is checked as `a·P` via ecrecover.
  - The Jacobian sum is compared projectively, and degenerate sums are refused.
  - Verification uses x(Q) only, consistent with BIP-327's parity handling.
- **`UAFrostSecp256k1Verifier`:**
  - The RFC 9591 H2 / DKG challenge (`hashToScalar` from 48 bytes mod N) is correct.
  - So are `isLinear` and `decompress` parity, and the sum Σ C_i0 refuses doubling or cancellation.
  - The PoK does not bind t/n, which is attestation-only as documented (S3).
- **`Musig2Bn254Verifier` / `FrostBn254Verifier`:**
  - `[μ]G + [r−c]C0 == R`; the second key's coefficient is 1 and the 512-bit widened coefficient is reduced mod r.
  - The ordering matches `UAKinds._lt`.
  - FROST-bn254 is not wrapped in `UASafeVerifier`, but its points are checked in Solidity before any precompile call.
- **`PairingVerifiers`:** `UASafeVerifier` caps the self-call and holds gas, and Zether Schnorr uses a separate tag
  (S13).
- **`CurveSigs.schnorr`:** binds `tag ‖ R ‖ Y ‖ m`, requires z < r and e ≠ 0, refuses R and Y at O, and checks bn254
  points in Solidity.
- **`Ed25519Verifier` → `Ed25519.verify`** (head read): S < L, `y < p` for A and R, small-order y refused,
  `encode(SB − kA) == R` byte for byte.

### `ua/MlDsa.sol`, `FnDsa.sol`, `SlhDsa.sol`, `PqUA.sol`, `PqNtt.sol`, `Shake.sol` (spot checks)

- **ML-DSA:**
  - Hint unpacking matches FIPS 204 Alg. 21: positions strictly increasing per row, ≤ ω in total, zero tail.
  - The z bound is `‖z‖∞ < γ1 − β`.
  - UseHint with the `r − r0 == q − 1` edge case (I verified the sign branch).
  - The c̃ compare covers 32 or 48 bytes.
  - μ = H(tr ‖ 0 ‖ 0 ‖ pq_msg).
  - Every buffer is at least as large as `squeeze`'s whole-block overrun. The `tr` overrun in `expandKeyRows` lands in
    the t̂1 region that is written next, as the comment says.
  - The part sizes match the spec: 20,544 B; 15,360 B + 21,568 B.
- **Falcon:**
  - The `comp_decode` grammar is followed: `|v| ≤ 2047`, no −0, zero tail.
  - HashToPoint uses rejection at 61445.
  - Two's-complement squares and the mod-q wrap are correct.
  - The bound is `≤ 34,034,726`, as in the reference implementation.
- **SLH-DSA-SHA2-128s:**
  - H_msg slicing: md is 21 bytes, idx_tree 54 bits, idx_leaf 9 bits.
  - The ADRSc layout and words match each type.
  - The FORS / WOTS / XMSS loops are correct, including the checksum nibble order.
  - `PK.seed ‖ 0^48` is 64 bytes.
- **`Shake.reserve()`** is the first allocation in every external verify entry: `UAMldsaVerifier.verify`,
  `expandedKey(Part)`, `verifyExpanded`, and `UAFndsaVerifier.verify` (reserve runs before `encodePacked`).
- **NTT:** with lazy reduction, every consumer reduces with `mulmod` / `addmod`.

### `account/`

- **`SmartKeyAccount`.**
  - `initialize` is factory-only and runs once; the implementation is locked in its constructor.
  - The account never drops to zero keys: `LastKey`, and rotate adds before it removes.
  - Key management goes only through `onlySelf` inside the `MetaTxBase` ticket.
  - Re-entrancy via `execute` is closed. A direct callback into any `nonReentrant` function reverts, and a self-target
    sees `TICKET == 2` and also reverts (`MetaTxBase.sol:57-67`, `:208-223`).
  - The signer of `from = this` is the account's own `isValidSignature`. Its EIP-712 domain binds the account, the
    chain id and `chain_uid`.
  - Merkle batching uses a double-hashed leaf (second-preimage safe).
  - WebAuthn checks rpIdHash, UP and UV, the strict grammar and an exact origin hash, then OZ `P256.verify`, which
    pre-checks low-s and the key on the native path.
  - Recovery is add-only after 2 days. `setGuardian` and `cancelRecovery` clear it, and `completeRecovery` must name
    exactly the pending key.
  - The unwrapped ERC-1271 is documented (CTR-ACC-05) and not re-raised here.
- **`SmartKeyAccountFactory`.**
  - The salt includes the guardian (CTR-ACC-01), and clone plus initialize happen in one transaction.
  - Redeploys are idempotent.
  - An attacker's own clone of the implementation, deployed by another deployer, gets the 400 k cap but can never be
    initialized, so it always answers invalid.

### `wallet/MandateWallet.sol`

- **Payments.**
  - Epoch binding: every `setMandate` and every revoke increments the epoch (CTR-ACC-07).
  - The pay lane is derived from `entryRef` with nonce 0, and `refUsed` makes each `entryRef` pay once.
  - State is updated before the external `payWithFee`, all under `nonReentrant`.
  - A delegate revoke is bound to `(token, epoch)`.
  - `setMandate` keeps the period's budget on an edit.
  - `from = wallet` is refused by the default `SelfSender` guard.
- **Owner key.** The owner is immutable and ECDSA-only for ERC-1271, which matches the spec ("ECDSA owners",
  `mandates.md:14`).
  - A contract owner would also get only the 50 k ERC-1271 cap on the meta-tx path: there is no `_erc1271Gas`
    override. Such an owner is outside the spec, and it can still call directly.

---

## Not checked

- **Arithmetic depth.**
  - The bodies of `common/Sha512.sol`, `Bls12381.sol`, `HashToCurve.sol` and `zether/ZetherCurves.sol` (`G1Bn254`
    msm / add / mapToG1) and the rest of `Ed25519._straus`.
  - The Keccak-f round body in `Shake.sol`: I checked its structure and constants, not each rotation offset against
    FIPS 202.
  - The NTT tables.
  - Full FIPS 204 / 205 / Falcon conformance. I relied on the repo's vector tests, which I did not run.
- **Out of my part.**
  - `UAPqzVerifier` / the `pqz-mlwe` PoP (part 3).
  - `ERC20MetaTx` / `MetaTokenBase` digests and the trade flow beyond the purpose tags (part 1).
  - Whether `ZetherLib` / `PqzLib` digests bind the chain and token (parts 1 and 3).
- **Measurements.** Whether `MSIG_MEMBER_GAS` = 35 k and the per-kind caps match measured costs; I trust the
  `UAGas.t.sol` claims without running them.
- **Clients.** How wallets sample decoys (V2-1) and how clients sign 0x0108 (V2-2), beyond a grep of `clientkeys/src/ua.js`.
- **Deployed state.** I did not compare the on-chain 7622 registry or its constructor arguments with this source.
