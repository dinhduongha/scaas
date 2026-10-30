# legacy/ua8 — reference only, not built

The chain-bound proof of possession as it stood before UA-8 (owner: backup, not delete): `ua_kinds.rs.v1.txt` (invokables
`popDigest`, `holderPopMessage`, `pqzRegMessage`) and `tst_ua.qml.v1.txt` (their tests), as of `0e3a9fb4`. UA-8 P1 replaced them
with the portable digests (A9). Not built.
`ua_kinds.rs.v1.txt` builds only against the ua-rs of `ref/pre-ua8` (it calls `pop_digest` and the chain-bound `holder_pop_message`, which ua-rs renamed in A2 to `pop_digest_v1` and `holder_pop_message_v1`, kept for the legacy vectors); it does not build against this branch.
