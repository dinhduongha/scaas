# scaas-pqz-verifier

The reference **PQZ verifier (off-chain)** of the PQZ verifier mode (group 3f,
[spec §11.2](../docs/superpowers/specs/2026-11-06-attested-verify.md)). **UNAUDITED.**

A token created in `OFFCHAIN` mode names a verifier UA; a proof-carrying operation on it is accepted with that UA's
signed `PqzVerdict` instead of the precompile's answer. This binary is one such verifier: it signs a verdict only when

- the token is a factory instance of a configured release (release address → parameter set; this build verifies the set
  of its `pqz-ffi` features only, `n2304-kmax4096` by default), names this verifier, is `OFFCHAIN`, and is at the
  request's `pqzVerifierEpoch`;
- the statement has one of the set's lengths and the set's PQZL id in word 32, and the token's own statement view,
  called with the request's named arguments at the current state, builds exactly these bytes;
- `pqz-ffi` (byte for byte the precompile) answers `…01`;
- every key the statement names passes spec §6 per key version (3g KV-12): its `pqzPop` bytes are stored and hash to
  its `pqzPopHash`, its `R_REG` proof verifies over that version's message, and no other UA or version owns it.

It verifies public bytes only and decrypts nothing ([ARCH-POS-13](../docs/decisions.md#ARCH-POS-13)). A refusal is a
named JSON error, never a signature. Every signature is logged with the token, `statementHash` and `proofHash`.

## A separate trust role

A verifier that signs a false proof can create value and drain the token's shielded pool (spec §2). Run it as its own
process, under its own operator, with its own key custody: never a relayer lane key, never a key of `scaas-node`, which
stays keyless and only carries or fetches verdicts. The key is an encrypted JSON keystore; the configuration names the
keystore's path and the environment variable holding its password, never a secret
([`pqz-verifier.example.toml`](pqz-verifier.example.toml)).

## Interface

- `POST /v1/pqz-verdict` `{token, chainId, op: {entry, args, binding, amount?, recipient?, unwrap?}, statement, proof,
  pqzVerifierEpoch}` → `{pqzVerdict, pqzVerdictSig}`; `entry` one of the PQZ proof-carrying entries
  (`mtxConfidentialTransfer[Compact]`, `mtxConfidentialTransferSingle[Compact]`, `mtxUnshield`, `mtxUnshieldUnwrap`;
  `binding` 0 for a direct call, the envelope's binding for a relayed one) or `verifyTransferAmount`.
- `POST /v1/pqz-verdict/probe` `{token, chainId}`: a verdict over a fixed probe statement (the typo guard before a
  verifier transfer, spec §4.2).

Bounds: a body limit set from the set's largest statement and proof, JSON nesting at most 4 below the request object,
both checked before decoding; a per-address rate limit, a bounded queue, bounded verification concurrency.

## Build and test

```bash
../scripts/capped cargo test --offline --locked -j2
../scripts/capped cargo clippy --offline --locked --all-targets -- -D warnings
../scripts/capped cargo build --release --offline --locked -j2
```
