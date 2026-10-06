# TODO — scaas

Ordered by what blocks what (2026-10-06). The Odoo side lives in bamboo-dms (`dms_blockchain*`).

### 0. First
- [ ] Owner: review `docs/superpowers/specs/2026-10-06-node-independence-design.md` (R87–R111) and confirm its §18.2.
- [ ] Independent Claude review of that spec.
- [ ] Deferred tests after the split: `smartcontracts/scripts/test.sh all`, bamboo-node `cargo test` + clippy + e2e (needs `smartcontracts/evm/lib`, `smartcontracts/evm/deployments/`).

### 1. Streams


1. [ ] **S3** envelope library + 32 conformance vectors (mesh spec §4; pure library).
2. [ ] **P1** node store v2 + config authority (replaces mesh S4); SQLite → PostgreSQL → MySQL backends (R111).
3. [ ] **P2** job API + HMAC machine keys; **P2b** admin API + OIDC + Unix-socket break-glass + audit + CORS.
4. [ ] **P3** submit + lanes from the store (safety-critical); **P4** indexer + `/v1/events`.
5. [ ] **P5** Odoo client (push cron + sync cron); **P6** push e2e + cutover runbook → owner cuts over chain by chain (testnet first).
6. [ ] **P7** DEX book into the node store; **S1b′** company bus scope; **S5** mTLS bus; **S6′** mesh pipeline; **S7′** mesh e2e; **P9** remove the pull path; **S8′** doc corrections (mesh spec §15.1).
7. [ ] **React + Vite app** `app/` after the node APIs (spec → plan → impl). EVM + meta-tx families; passkey/seed vault, extension wallets, dev key; OIDC only for node admin.
8. [ ] TON: report the payer jetton-wallet tx hash with `mined` (false `landed_elsewhere`).
9. [ ] Still queued: S4 follow-ups (backup-key toggle, device-bound vault, Sui `fam_sui.verify`, Soroban/Aptos/Solana signers, `chain_pay.js`), Zether portal balance cache, post-quantum Zether.


### Doc/code inconsistencies found while writing docs/SCaaS.md (2026-10-06)
- [ ] `smartcontracts/evm/README.md`: says the mode bitmask was removed (code keeps it) and Zether is "interface only" (it is built).
- [ ] `private9000` profile: READMEs say berlin, `foundry.toml` says prague.
- [ ] Seed-vault scrypt cost: round-3 R32 says N=2^15, clientkeys uses 2^17 — owner to pick; align spec or code.
- [ ] MESH §3.4 still says `ring`; R114 (A2) moved to aws-lc-rs — S8′ doc corrections.
- [ ] NI default job API bind `127.0.0.1:8547` collides with the gateway default bind — pick another port in the spec.
- [ ] Owner review of PLANNED material filled from the SRS in docs/SCaaS.md (W3B SLOs, RACI, tender interface, backup-key toggle, P2P 7-step flow).
