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
