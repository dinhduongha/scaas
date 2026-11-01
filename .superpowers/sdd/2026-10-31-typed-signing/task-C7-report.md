# Task C7 report

Status: DONE_WITH_CONCERNS (concern: no package other than clientkeys / zether-prover builds a typed op digest).

Finding: grep of `metatx-cancel`, `UAMetaTransaction`, `CancelOrder`, `ZETHER_ROLLOVER` etc. outside clientkeys hits only purpose
tables, `UASig` registry arguments (R1/R2) and zether-prover owner ops. ua-rs / ua-py / ua-go / ua-cs / ua-dart (and ua-c / ua-cxx /
ua-qt / ua-dart-frb wrappers) build portable records, registry args, `relay_ref` and `ua_auth_digest`; none builds a C6 / C3 / C4 struct,
so nothing moved there (ua-rs `--features json`, zether-prover, ua-py, ua-go suites green; ua-cs, ua-dart not run: no code change, same
vectors as R2).

Change: zether-prover `ownerDigest` command (`envelope::owner_digest`) for ZetherRollOver, ZetherSetRollOverMode, UARollOverSigned,
UASetRollOverMode in the token domain. Test `clients/zether-prover/tests/typed_ops.rs` compares typehash / structHash /
domainSeparator / digest with the rows of `typed_ops.json` (no test-built values).
RED: `clients/zether-prover/runs/2026-11-01-typed-signing-c7-red.txt` (missing command). GREEN: 2 passed, full package suite green.
Mutant (swap accSeq / expectedPendingSeq in ZetherRollOver): both tests FAILED
(`runs/2026-11-01-typed-signing-c7-mutant.txt`), restored, `cmp` identical.
Not covered: PqzAuth and Zether transfer-op digests (no client builder in this branch; PQZ ops built by e2e.py / node), generic
`MetaTransaction` digest of zether-prover unchanged (contract keeps it). No legacy move needed: nothing superseded.
Docs: docs/decisions.md C7 entry (2026-11-01), plan C7 result.

## Fix round 1 (C7 review)

Ruling taken: not a non-goal. `zether-prover` now has, in `src/typed.rs` (one table `OPS`, one generic EIP-712 encoder over the type
strings; `ownerDigest` replaced by it):
- `typedDigest {op, chainId, chainUid, token, message}`: typehash, structHash, domainSeparator, digest of every one of the 47 Zether rows
  (transfers, unshield, wrap, roll-overs, owner ops, receiver / relay fee, orders, cancels, UA twins). `args` nested struct hash, `proof`
  / `sealedMemo` keccak. Refuses unknown op, missing field, extra field, value too wide for its type.
- `namedCall {op, env, payload, proof, beneficiary, [recipient, amount | unwrap], [sig]}`: typed message, digest and, with sig, the named
  entry calldata (`mtxConfidentialTransferSingle` / `mtxConfidentialTransfer` / `...Compact` / `mtxUnshield` / `mtxUnshieldUnwrap`,
  `Envelope` first, `sig` last). The direct builders in `envelope.rs` were split into token helpers; direct calldata unchanged.
- Tests (`tests/typed_ops.rs`, 3): every `zether` row against the vector with row count 47 and the exact left-out list (27 rows: PrepareAcc /
  UAPrepareAcc, wallet and account ops, Execute, 24 PQZ rows incl. PqzAuth, CancelDexOrder; reason per group in the test); named calls equal
  the vector's digest, structHash, args and calldata for the five ops.
- Not covered: UA twins as named calls (digest only; no uaExecute binding builder), WrapShield / roll-over owner ops as calldata builders.
- Mutants (5, `clients/zether-prover/runs/2026-11-01-typed-signing-c7-fix1-mutants.txt`): array order, bytes hashing, envelope batch / nonce,
  payload leg order, proof / sig order; each failed, each restored with `cmp` identical.
- RED note: the round-1 `ownerDigest` code did not know the other 43 rows; the new tests were written against the generic API and first
  ran green once the module existed (no separate RED capture for this round; the mutants show each assertion can fail).
- Package suite green; `ZetherProverCross` 7 passed through the release `zether-cli` (`runs/2026-11-01-typed-signing-c7-fix1-cross.txt`).
- Docs: decisions.md C7 entry rewritten (incl. PqzAuth sentence), plan C7 result, `zether-cli` header. No README exists in the package.
