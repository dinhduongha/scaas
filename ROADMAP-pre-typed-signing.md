# Branch `pre-typed-signing` — the "economy" path: next steps to the end

**What this branch is.** `main` at `10ac1417` (2026-10-31), the last version before the `typed-signing` round: users
sign the packed / generic forms (`MetaTransaction(… bytes data …)`, raw keccak portable digests, packed `payload` /
`keyData` blobs). The owner kept it (2026-10-31) so the project can roll back to this cheaper path. Tag:
`ref/pre-typed-signing`. Rulings of 2026-10-31 that do **not** depend on typed signing still hold here.

**How to use it.** To roll back: branch from `pre-typed-signing` (or reset a working branch to it), skip item 2d of the
TODO work order, and follow the steps below. Work already built on branch `ua8-soroban` up to `c5333fdb` (M1 minimal
msig rule in the clients, G1 gen-1 kind gate, R1 relay-fee research + ruling, B0 Soroban budget spike) branched from
`main` before typed signing and fits this path unchanged.

## What this path does NOT do (the typed-signing round, item 2d)
- no typed EIP-712 struct per operation, no named entry points (`mtxUnwrap`, `mtxBurn`, …), no `ua<Op>` twins;
- portable records stay raw keccak (`portablePopDigest`, `registrationDigest`, `kemRecordDigest`, PQZ key digests);
  native EOA msig members keep `personal_sign(memberDigest)`;
- packed blobs stay (Zether / PQZ `payload`, msig `keyData`, `UAAttrs`, KEM record bytes, `bytes auth`);
- no `UARegistry.kindName(uint16)` view, no node JSON rewrite;
- the user's real check stays the app review (CLI-SGN-27, CLI-APP-09); extension wallets show hex for the generic
  envelope. Optional later, no contract change: ERC-7730 descriptors for wallets that support them.

## Next steps, in order (economy path)
1. **T14 — UA-Soroban on the Stellar testnet** (from 2026-11-03): swap the SDK to 30.0.0, run the e2e there.
2. **`ua8-soroban`** (UA-8 Part B on Soroban; plan `docs/superpowers/plans/2026-10-31-ua8-soroban.md` on branch
   `ua8-soroban`), on today's raw portable digests:
   - M1 (done on the branch), M2 (EVM `UARegistry` minimal msig rule), M3 (Soroban), G1 (done), R1 (done), B0 (done:
     every set fits; `set_pqz_key` for a 16-member msig needs the signature in its own entry `PqzS(ua)` — controller
     call for B3);
   - B1 (KEM / PQZ-key digests), B2 (`register` with attributes, full PQZ key / proof / KEM stored), B3 (`set_kem_key`,
     `set_pqz_key`, `store_pqz_pop`, views), B4 (relayer-checked mode), B5 (off-chain PQ verifier + client re-check),
     V1 (`ua-ops.json` rows), B6 (node `call` jobs), B7 (copy EVM → Soroban → EVM), B8 (docs), B9 (gates), review;
   - B10 (Stellar testnet e2e) after T14.
   - msig `pop` minimal form: EVM + Soroban only; NEAR / Algorand get it as a requirement of their later UA rounds.
   - Gen-1 kind set: owner ruling 2026-10-31 option (a) (G1 gate in `DeployBase`).
   - Relay-fee minimum: owner ruling 2026-10-31 **option (c)** on every family (per-token price + the job's simulated
     cost; `min_amount` stays the per-chain floor; sponsored fees unpriced); **option (d) ruled out**; node only, with
     P6i (research note `docs/research/relay-fee-minimum.md` on branch `ua8-soroban`).
3. **Zether verifier: one merged MSM** (EVM; before `zether-soroban`).
4. **`zether-soroban`** (Part Z; Z0 measures first; STOP for the owner if the verifier does not fit 400 M instructions).
5. **C core crash at M = 16** (pqz-core; full gate).
6. **Gas re-calibration on a quiet host** (option (c), image `-calib`, 26 rows `n2304-kmax4096`; the owner stops other
   heavy sessions first; chainspec change at the next SCaaS testnet reset only if it differs materially).
7. **Freeze** the contracts of EVM + Soroban. NEAR and Algorand have only their base contracts (no UA round yet): they
   get an add-on audit when their UA rounds finish.
8. **Contracts audit** (plan draft `.superpowers/sdd/2026-10-31-contracts-audit/plan.md`; units D1 EVM delta, D2 DEX,
   D3 chain-gate removal, D4 Soroban; NEAR / Algorand later; reviewers Codex / agy / Claude workflow — owner decides).
9. **P6h → P6i → P6j**: clients + WASM → node (incl. the relay-fee option (c)) → review part 3 (node, clients, prover).

## After P6j (unchanged)
1. **P6-PUB**: ePrint + ethresear.ch drafts (PQ and PQZ results only); the LaZer mail with the drafts 1–2 weeks before
   posting.
2. **TradeEngine** (EVM ∥ non-EVM): NODE-DEX-15, the `UniswapExecutor` deploy script, BSC venues (PancakeV3Executor).
3. **UA-7** PQ chat sessions (UA-8 KEM keys).
4. **The other families' UA rounds**: NEAR → Cosmos / Sui / Aptos / Solana → Algorand (FN-DSA-512 once AVM v14 has
   `falcon_verify`) → TON (registry design first); each `ua-<family>` → `ua8-<family>` → `zether-<family>` where the
   platform allows; mandate epoch; msig `pop` minimal form; add-on audit.
5. **Production gates before the SCaaS mainnet** (chain id 22776): external independent audit + G-LIC; chainspec
   (Amsterdam; CREATE2 deployer in genesis — proposed, owner decides at launch); node topology (sealer + rpc, or an
   external signer; TLS reverse proxy); 3-day notice period; a last gas calibration only if the core / library or the
   validator hardware changes; from launch on, "test-only, no migration" ends.

## Not scheduled (owner decides when)
Zether BLS12-381 verifier as a Rust precompile; ERC-7674 temporary approvals; EIP-191 `personal_sign` variant for kind
`secp256k1` (0x0108); Zether on NEAR / Algorand (after their UA rounds; needs the merged MSM); PQZH proof below
≈ 170 KB at the proven soundness.
