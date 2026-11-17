# legacy/ua-rs-sign — reference only, not built

The C header of ABI version 5 (`scaas_ua.v5.h`), as generated before ua-rs-sign T12 (plan MD-4: backup, not delete). T12 moves
the ABI to version 6: opaque handles (`ScaasUaWallet`, `ScaasUaKey`, `ScaasUaKemKey`, …), the wallet, signing, KEM, seal and vault
calls, `scaas_ua_features()` and the statuses after `SCAAS_UA_ERR_UNAUTHORIZED`; every v5 call is kept with its signature, and
the header rules "no allocation crosses the ABI" and "pure computation over immutable static tables" no longer hold.
