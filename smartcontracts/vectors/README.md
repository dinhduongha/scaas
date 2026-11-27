<!-- SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0 -->
# Cross-language vectors

The authority for bytes (AGENTS.md "Clients and vectors"): each directory is written by its generator and read in place by
every language; never edited by hand. Regenerate, then read the `git diff`.

| Directory | Generator | What it pins | Readers |
|---|---|---|---|
| `profile/` | [`clients/clientkeys/scripts/profile-vectors.mjs`](../../clients/clientkeys/scripts/profile-vectors.mjs) (`src/profile.js`) | user profiles ([spec](../../docs/superpowers/specs/2026-11-27-user-profiles.md) §4, §6, §7.1, §7.2, §10.1): UUIDv7 ids, `name_key` and the name check (`ids.json`); the KDF bounds, OpaqueString, Argon2id, the wraps and their AD, labels, envelope files (`envelope.json`); sealed items, HMAC file names, manifests, anchors and their comparison (`items.json`); the export file and every import refusal (`export.json`). UNAUDITED | clientkeys `test/profile.test.js`; `ua-rs` and the SDK (planned, user-profiles UP2, UP6) |
