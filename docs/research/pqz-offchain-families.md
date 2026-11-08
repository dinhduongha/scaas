> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZ OFFCHAIN mode on other families: a first look (2026-11-08)

Owner 2026-11-08: research only, decided later. Source rule: the PQZ verifier-mode spec (3f) §8 (family-neutral; each family's own PQZ round takes the
mode, the per-token verifier and the inline verdict with that family's own signature check). Numbers below are from general
knowledge, not measured; each family round measures them.

OFFCHAIN removes the precompile need: the contract checks one verifier-UA signature (ed25519 / secp256k1 everywhere; a PQ
verifier kind only where the chain verifies it: Soroban CAP-0087, NEAR ml_dsa_verify, Algorand falcon after AVM v14).
Still required: the proof stays in the tx (a PQZL transfer ≈ 77 KB: proof 42.7 KB + ciphertexts), ciphertexts stay in state
(16.5–22.5 KB per slot, kept forever, CTR-PQZ-07 / never lose ciphertext), and keccak256(ct) binds the verdict to the bytes.

| Family | Tx size | Ciphertext storage | keccak | First look |
|---|---|---|---|---|
| NEAR | ~1.5 MB tx | storage staking ≈ 0.2 NEAR per slot | host fn | easiest |
| Cosmos (CosmWasm) | block-bound, MBs | KV store, gas per byte | none in cosmwasm-std: keccak in wasm (gas) | feasible |
| Soroban | ~70–130 KB by network config: near the edge | persistent entries with rent | host fn | feasible, measure |
| Sui | 128 KB tx, 16 KB per pure argument: split args | objects, storage fee | yes | feasible with splitting |
| Aptos | ~64 KB < 77 KB | resources | yes | multi-tx upload |
| Solana | 1,232 B per tx | rent ≈ 0.13 SOL per slot | syscall | buffer account over tens of txs |
| Algorand | app args ~2 KB, group ~32 KB; 4 KB max value | box ≤ 32 KB, MBR ≈ 7 ALGO per slot | opcode, but no >4 KB input | hard: needs another hash shape |
| TON | cell-bound messages | per-cell rent, unpaid = frozen: conflicts with never-lose-ciphertext | sha256 only | hardest |

NEAR ≠ Algorand: separate rounds. Order follows the UA rounds (EVM → Soroban → Cosmos → NEAR → Sui / Aptos / Solana →
Algorand → TON); each `pqz-<family>` round after its UA round.

## Trust model (owner 2026-11-08)
OFFCHAIN trusts the verifier, the same kind of trust as a cross-chain bridge's signer set or the issuer of a fiat-backed or
collateral stablecoin (USDT, USDC, DAI's oracles and governance): one named group can approve something false. Same answer
as there: make the group explicit and bounded, not hidden.
Levers already in 3f / 3h: the verifier is a UA, so it can be an `msig` of independent parties; per-token choice, immutable
mode; transfer only with the factory's notice period; immediate revocation (`pqzRevokeVerifier`); proofs public when
`proofStore = LOG` (3h), so anyone can re-verify and prove fraud after the fact. Limit: detection after the fact, not
prevention; no on-chain slashing (3f spec, R2). Possible later levers (not decided): a k-of-n verdict (several verifier
UAs), a per-period cap on what an OFFCHAIN token can shield or mint, a challenge window before large unshields.
