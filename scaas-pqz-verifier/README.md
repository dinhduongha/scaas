# scaas-pqz-verifier

The reference **PQZ verifier (off-chain)** of the PQZ verifier mode (group 3f,
[spec §11.2](../docs/superpowers/specs/2026-11-06-attested-verify.md)). **UNAUDITED.**

A token created in `OFFCHAIN` mode names a verifier UA; a proof-carrying operation on it is accepted with that UA's
signed `PqzVerdict` instead of the precompile's answer. This binary is one such verifier: it signs a verdict only when

- the token is a proxy of a configured release (release address → parameter set; this build verifies the set of its
  `pqz-ffi` features only, `n2304-kmax4096` by default) whose code names the configured registry and `chainUid`, names
  this verifier, is `OFFCHAIN`, and is at the request's `pqzVerifierEpoch`;
- the statement has one of the set's lengths and the set's PQZL id in word 32, and the token's own statement view,
  called with the request's named arguments at the current state, builds exactly these bytes;
- `pqz-ffi` (byte for byte the precompile) answers `…01`;
- every key the statement names passes spec §6 per key version (3g KV-12): its `pqzPop` bytes are stored and hash to
  its `pqzPopHash`, its `R_REG` proof verifies over that version's message, and no other UA or version owns it.

**What it signs.** One process serves one chain, pinned in its configuration: `chain_id` (the RPC must answer it at start),
`chain_uid`, and the UA `registry` with its `registry_generation`. The only thing signed is the `UAAuth` digest of a
`PqzVerdict` (`UAKinds.uaAuthDigest`: `UAAuth{ua, PURPOSE_PQZ_VERDICT, digest}` in the registry's domain `"SCaaS UARegistry"`,
the generation, the chain id, the registry, salt `chainUid`), built locally from those pinned values; a hash an RPC or a
contract returns is never signed (Fable C-1). A token whose code names another registry or `chainUid` is refused
(`FOREIGN_REGISTRY`, `FOREIGN_CHAIN_UID`).

It verifies public bytes only and decrypts nothing ([ARCH-POS-13](../docs/decisions.md#ARCH-POS-13)). A refusal is a
named JSON error, never a signature. Every signature is logged with the token, `statementHash` and `proofHash`.

## A separate trust role

A verifier that signs a false proof can create value and drain the token's shielded pool (spec §2). Run it as its own
process, under its own operator, with its own key custody: never a relayer lane key, never a key of `scaas-node`, which
stays keyless and only carries or fetches verdicts. The key is an encrypted JSON keystore; the configuration names the
keystore's path and the environment variable holding its password, never a secret
([`pqz-verifier.example.toml`](pqz-verifier.example.toml)).

## Operator rule: trusted nodes only

**Every `rpc_urls` endpoint must be a node the verifier's operator trusts, until the strict-majority option exists
(`scaas-rpc`)** (owner ruling 2026-11-11). The service reads one node per request and fails over; it does not compare
nodes (ARCH-POS-15's strict-majority option is deferred to the shared `scaas-rpc` crate, TODO 8b). The signed digest never
depends on an RPC answer, but the key checks do: a lying RPC could pass a key check (§6, CTR-PQZ-30: the key record, its stored `pqzPop` bytes, `keyOwner`) that `OFFCHAIN` tokens trust the verifier for, and the token does not repeat them. The block of a
request is pinned by number, not by hash (R-6, deferred with it).

## Interface

- `POST /v1/pqz-verdict` `{token, chainId, op: {entry, args, binding, amount?, recipient?, unwrap?}, statement, proof,
  pqzVerifierEpoch}` → `{pqzVerdict, pqzVerdictSig}`; `entry` one of the PQZ proof-carrying entries
  (`mtxConfidentialTransfer[Compact]`, `mtxConfidentialTransferSingle[Compact]`, `mtxUnshield`, `mtxUnshieldUnwrap`;
  `binding` 0 for a direct call, the envelope's binding for a relayed one) or `verifyTransferAmount`. `args` is the entry's
  argument struct by its field names (`IPqzToken.sol`; group 3h: `ownTag` in `PqzTransferArgs`, `PqzMultiArgs`,
  `PqzBurnArgs`); a disclosure reads the leg owner from the op blob `R ‖ P(v_f) ‖ ownTag ‖ kv(8·n) ‖ u8(n)`.
- `POST /v1/pqz-verdict/probe` `{token, chainId, proposal?}`: a verdict over the fixed probe statement
  `SCAAS-PQZ-VERIFIER-PROBE-V1` and an empty proof, for an `OFFCHAIN` token of the pinned chain, registry and `chainUid`
  that names this verifier (else `NOT_OFFCHAIN`, `NOT_THIS_VERIFIER`; what the node's `refuse_shield_when_unserved`
  asks). With `proposal: true` (spec §4.2's typo guard, asked of the proposed `next` before `pqzSetVerifier`) the token
  may name another verifier or none; every other refusal stays. Only the probe statement is signed on this route, and
  no token builds it: 27 bytes, while every statement a token hashes is at least 640 bytes, so a real debit's
  `_check` refuses a probe verdict `PqzVerdictMismatch(3)` (`tests/anvil.rs`).

Chain reads ([ARCH-POS-15](../docs/decisions.md#ARCH-POS-15)): `rpc_urls` is a list, asked in order; every read of one
request comes from one node at one block number (its head when the request starts); a node that does not answer within
10 s (`RPC_TIMEOUT`), or answers with an error that is not a revert (`header not found`, a rate limit), sends the whole
request to the next one; a revert (revert data, or `execution reverted`) or a refusal is an answer. At start every
endpoint must answer the pinned `chain_id`, and the pinned registry its `registry_generation` and `chain_uid`, or the
service does not start. The strict-majority agreement option is not built: trusted nodes only (the operator rule above).

Bounds: a per-address rate limit; the body read within 15 s (`BODY_TIMEOUT`, else 408), a body limit set from the set's
largest statement and proof, JSON nesting at most 4 below the request object, all checked before decoding; only then a
place in the bounded queue (a slow body never holds one); bounded verification concurrency.

## Known limits

- ARCH-POS-15's strict-majority agreement option is not built: failover only. Deferred by the owner (2026-11-11) to the
  shared `scaas-rpc` crate (TODO 8b); until it exists every endpoint must be a node the operator trusts (the operator rule
  above).
- The block is pinned by number, not by hash (EIP-1898; R-6, deferred with the majority option): a reorg at that height
  between two reads of one request mixes two blocks; the token recomputes `statementHash`, so only the off-chain key
  checks could see it.
- The key ownership record (`pqzKeyHash` → `(ua, version)`) lives in memory: bounded at 2^18 keys (`KEY_RECORD_FULL`
  when full), not persisted, lost on restart.
- No factory lookup of "is a factory instance": a token is an EIP-1167 proxy of a configured release whose code names the
  pinned registry and `chainUid`.
- One registry, one generation, one chain per process: tokens naming the other generation's registry are refused
  `FOREIGN_REGISTRY`; run a second process for them.
- `tests/anvil.rs` stubs pqz-ffi (`…01` for every input): there is no prover in the test and no `R_REG` proof of its keys;
  `tests/service.rs` runs pqz-ffi on the set's vector rows.

## Build and test

```bash
../scripts/capped cargo test --offline --locked -j2
../scripts/capped cargo clippy --offline --locked --all-targets -- -D warnings
../scripts/capped cargo build --release --offline --locked -j2
# opt-in, against a real OFFCHAIN token on a local anvil (needs anvil and forge in PATH, smartcontracts/evm/lib installed):
# the repo's deploy script, the PQZ release on deps = [0], the service's verdict sent with a transfer and accepted on chain
../scripts/capped cargo test --offline --locked -j2 --test anvil -- --ignored --nocapture
```
