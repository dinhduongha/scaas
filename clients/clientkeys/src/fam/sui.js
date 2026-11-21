// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Sui (plan 2026-11-17-scaas-sdk T24.sui): the id of an owner's `Account<T>`, derived from the token's `Registry<T>` by
// `sui::derived_object::derive_address(registry, owner)` (NET-SUI-03), as scaas-node/src/adapters/sui.rs `derive_account`.
// Rows: smartcontracts/vectors/families/sui.json (scripts/families-vectors.mjs). UNAUDITED.
import { blake2b } from "@noble/hashes/blake2.js";
import { concatBytes, utf8ToBytes } from "../bytes.js";

export class SuiError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

const key32 = (k, what) => {
  if (!(k instanceof Uint8Array) || k.length !== 32) throw new SuiError(`Argument: ${what}: 32 bytes`);
  return k;
};

/** BCS of a string: its ULEB128 length (below 128 here) and its bytes. */
const bcsStr = (s) => {
  const b = utf8ToBytes(s);
  return concatBytes(Uint8Array.of(b.length), b);
};

/** `bcs(TypeTag)` of `0x2::derived_object::DerivedObjectKey<address>`: Struct (7), address 0x2, module, name, one type
 * argument, `address` (4). */
const KEY_TYPE = concatBytes(
  Uint8Array.of(7),
  Uint8Array.from({ length: 32 }, (_, i) => (i === 31 ? 2 : 0)),
  bcsStr("derived_object"),
  bcsStr("DerivedObjectKey"),
  Uint8Array.of(1, 4),
);

/** `derive_address(registry, owner)` = blake2b-256(0xf0 ‖ registry ‖ u64le(32) ‖ owner ‖ KEY_TYPE): `HashingIntentScope::
 * ChildObjectId`, the parent, the key's BCS length and bytes (an address: 32), the key's type tag. */
export function deriveAccount(registry, owner) {
  const len = new Uint8Array(8);
  len[0] = 32;
  return blake2b(
    concatBytes(Uint8Array.of(0xf0), key32(registry, "registry"), len, key32(owner, "owner"), KEY_TYPE),
    { dkLen: 32 },
  );
}
