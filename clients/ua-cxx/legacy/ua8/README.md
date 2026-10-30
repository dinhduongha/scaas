# legacy/ua8 — reference only, not built

The chain-bound proof of possession as it stood before UA-8 (owner: backup, not delete): `lib.rs.v1.txt`, `scaas_ua.cpp.v1.txt`, `scaas_ua.hpp.v1.txt` and `vectors_test.cpp.v1.txt`, as of `9e1f2357`
(the base of UA-8 A10). UA-8 P1 replaced `pop_digest` / `holder_pop_message` / `pqz_reg_message` with the portable digests (A10).
Stored as `.txt` so the project does not build them.
The Rust files build only against the ua-rs of `ref/pre-ua8` (they call `pop_digest` and the chain-bound `holder_pop_message`, removed from ua-rs in A2); they do not build against this branch.
