# Soroban packed-`Bytes` inventory

The Soroban half of the explicit-parameter inventory (typed-signing X0, hand-over TS-D9). It replaces
[Appendix X.7](../superpowers/plans/2026-10-31-typed-signing-appendix-x.md), which was a first pass made before
`ua8-soroban` B2 and B3 changed the registry. Taken from the code at `ua8-soroban` B3 by listing every `pub fn` of every
`#[contractimpl]` under `smartcontracts/soroban/contracts/`, then every `Bytes` field of the `contracttype` arguments.

**Outcome.** No bundle is left on `ua-registry` without a typed form. One bundle remains on another contract: `meta` on
the token. It is listed for the owner and is unchanged.

Classes are Appendix X.1's: *bundles fields* becomes typed; *one crypto object* stays `Bytes`, as its own named argument;
*a call* stays; *external standard* keeps its form. `BytesN<N>` is not listed: it is one fixed-size value.

## `ua-registry`

| Entry and argument | Layout | Class | Outcome |
|---|---|---|---|
| `register.key_data`, `ua_of.key_data`: `p256`, `secp256k1` | `x ‖ y`, one point | one crypto object | stays, as EVM row 12 |
| same: `ed25519`, `mldsa44`, `mldsa65` | one public key | one crypto object | stays |
| same: `webauthn-p256` | `x ‖ y ‖ rp_id_hash` | bundles | typed twins `register_webauthn(WebAuthnKey, …)` (B2), `ua_of_webauthn` (B3); the packed form stays accepted, as EVM `register` |
| same: `msig` | CTR-UA-09 `u16 t ‖ u16 n ‖ n × (u16 kind ‖ id ‖ u16 weight)` | bundles | `register_msig(MsigStructure, …)` (B2), `ua_of_msig` (B3); `register(0x0120, …)` is `KeyData`; `ua_of(0x0120, …)` keeps the packed form, as EVM `uaOf` |
| `register.pop`, `register_webauthn.pop` | one signature | one crypto object | stays; the WebAuthn form is one assertion, `abi.encode(authenticatorData, clientDataJSON, r, s)` (TS-D12 open question 3 default; X.7 row 3 closed this way, as EVM) |
| `register_msig.pop` | was `abi.encode(MemberSig[])` | bundles | `Vec<MemberSig>` (B2) |
| `register*.pqz_pop`, `store_pqz_pop.pqz_pop` | one `R_REG` proof | one crypto object | stays |
| `UaAttrs.pqz_key`, `set_pqz_key.pqz_key` | one PQZ key | one crypto object | stays |
| `KemKey.mlkem_ek` | one ML-KEM-1024 key | one crypto object | stays. `Bytes`, not X.7's `BytesN<1568>`: a wrong length must be `KemKeyLength`, not a host conversion error |
| `UaAttrs.kem_pk`, `set_kem_key.kem_pk` (brief) | `scheme ‖ ek ‖ x25519` | bundles | `KemKey` (B2 for `UaAttrs`, B3 for `set_kem_key`, `kem_key_of`, `kem_key_at`) |
| `require_authorized.auth`, `set_kem_key.sig`, `set_pqz_key.sig` (brief: `sig: Bytes`) | `signature` or `abi.encode(MemberSig[])` | bundles | `UaSig` (B2, B3) |
| `UaSig.signature`, `MemberSig.sig` | one signature | one crypto object | stay |
| `UaSig.key_data`, `MemberSig.key_data` | always empty on Soroban: the key is read from the record | neither | EVM's field, kept for the shape; set ⇒ refused |

## Other contracts

| Contract | Entry and argument | Layout | Class | Outcome |
|---|---|---|---|---|
| `token` | `pay_meta.meta`, `ua_pay_meta.meta`, `meta_pay_id.meta` | `abi.encode(uint16 schema, bytes body)` by convention (EVM row 14, `paymeta.json`); the token only hashes and logs it | **bundles** | **for the owner, unchanged**: below |
| `token`, `mandate`, `dex`, `relay-fee` | every `auth`, DEX `maker_auth` / `taker_auth` | `UaSig` | typed | done in B2; its fields are classed above |
| `relay-fee` | `relay`, `ua_relay`, `relay_ref` `args: Vec<Val>` | a call | a call | stays (not `Bytes`) |
| `relay-executor` | `exec` `args: Vec<Val>` | a call | a call | stays (not `Bytes`) |
| `smart-key-account` | `Passkey.origin` | one origin string, compared verbatim | one value | stays |
| `smart-key-account` | `WebAuthnSig.authenticator_data`, `.client_data_json` | WebAuthn's own fields of a typed struct | external standard | stays |
| `dex`, `mandate` | no other `Bytes` argument | | | |

`smartcontracts/soroban/spike/` is a measuring workspace outside the Soroban workspace (`exclude = ["spike"]`), so it is
not inventoried.

Return values are not arguments and stay as they are: `pop_of`, `registration_of`, `pqz_key_sig_of` and the `sig` of
`kem_key_of` / `kem_key_at` return the stored bytes, an `msig`'s as `abi.encode(MemberSig[])`, so a record reads back as
EVM's bytes.

## For the owner

`meta` on the token is the one bundle left. X.7 calls it an opaque app memo; EVM row 14 classes the same bytes as bundles
and types them `PayMeta { uint16 schema; bytes body; }`, which EVM's Part C has not built yet (`metaPayId(bytes32, bytes)`
still takes the bytes). The Soroban form would be `PayMeta { schema: u32, body: Bytes }` on the three entries, reassembled
to the same bytes, so `meta_pay_id` and `paymeta.json` do not change. It belongs with EVM's change, not with the registry.

EVM has the typed views `msigOf` and `webAuthnKeyOf` (Appendix X row 18); Soroban has neither.
