# legacy/t26-a2-1 — reference only, not built

The C header of ABI version 6 (`scaas_ua.v6.h`), as generated before T26 A2-1 (backup, not delete). T26 A2-1 (CTR-UA-44) moves
the ABI to version 7: `scaas_ua_wallet_restore_backup`, `_restore_backup_rollback`, `scaas_ua_wallet_from_link`,
`scaas_ua_open_container`, `scaas_ua_pqz_share_reseal` and `scaas_ua_wallet_pqz_reconstruct` take `current_json` (the current
structures of updated `msig`s) right after `accepted_json`; every other declaration is unchanged.
