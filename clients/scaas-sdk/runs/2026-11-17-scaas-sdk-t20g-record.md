# scaas-sdk T20g: the JS / TS binding (browser)

> Task record of plan T20g (`docs/superpowers/plans/2026-11-17-scaas-sdk.md`), spec §16.4. UNAUDITED.

## Open questions for the owner

Each with what the binding does until it is answered. None blocks the build: the binding stores nothing itself and every
answer below is the app's to implement through its `SecureStore` and its page.

| # | Question | Until answered |
|---|---|---|
| 1 | **An IndexedDB keystore's eviction and backup.** A browser may evict an origin's IndexedDB under storage pressure (best-effort storage) and the user can clear it; `navigator.storage.persist()` is a request, not a promise. Is a keystore held only in IndexedDB acceptable, and must the app force an exported backup (the words, or the encrypted container) before the first value is received? | The SDK's own rule holds: a seed whose backup is not confirmed is `backup: pending` (§6.1) and the app shows it; the binding adds nothing. The smoke uses an in-memory store. |
| 2 | **A passkey PRF in the browser as the only unlock.** A seed could be unlocked only by a passkey's PRF output (no passphrase kept by the user). Losing the passkey (a new device without sync) loses the seed unless the words are backed up. Allowed as the only unlock on this target? | The passphrase stays required at import and generate (§6.3), as on every target; the PRF unlock is an addition (`enable_passkey_unlock`). |
| 3 | **WebCrypto key persistence across origins.** A non-extractable `CryptoKey` lives in one origin's IndexedDB; another origin (a subdomain, a new deployment's domain) cannot use it. Is an unlock that survives page loads allowed at all, and must it be bound to one origin? | The SDK keeps no key in WebCrypto; an unlock lasts for the page's life only (a reload locks every seed). |
| 4 | **A service worker holding an unlocked seed.** A service worker outlives a tab and could keep a seed unlocked for background signing or watching. Allowed, and under which time limit? | Not supported: the binding runs in a page (window) context; the smoke runs in Node with no worker. |
