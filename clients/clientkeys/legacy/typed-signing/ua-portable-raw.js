// UNAUDITED. Superseded (typed-signing P1, 2026-10-31): the raw portable digests of src/ua.js as they stood before the typed
// EIP-712 records (UA-8 P1 / P7 / ruling A1-I1, C7). Reference only; the typed forms live in src/ua.js (TS-D1 … TS-D4).
// Load-bearing (keep it): scripts/ua-portable-vectors.mjs signs `personalSignDigest` for the `native-member-personal-sign`
// negative (the old native msig member form must be refused) and test/ua8.test.js checks that negative with it
// (test/ua-groups.test.js read the raw PoP until typed-signing P2 regenerated groups.json on the typed records).
import { keccak_256, concatBytes, utf8ToBytes, word } from '../../src/bytes.js';
import { POP_V2_TAG, KEM_TAG, uaMessage } from '../../src/ua.js';

const Z32 = new Uint8Array(32);
const tagHash = (s) => keccak_256(utf8ToBytes(s));
export const KEM_RECORD_TAG = tagHash('scaas.ua.kem-record.v1');
export const PQZ_KEY_RECORD_TAG = tagHash('scaas.ua.pqz-key-record.v1');

/** `keccak256(PURPOSE_POP_V2 ‖ ua ‖ pqzKeyHash ‖ kemRecordHash)` (UA-8 P1); no `kind`, 0 = no KEM record. */
export const portablePopDigest = ({ ua, pqzKeyHash = Z32, kemRecordHash = Z32 }) =>
  keccak_256(concatBytes(POP_V2_TAG, ua, pqzKeyHash, kemRecordHash));
/** `keccak256(portablePopDigest ‖ pqzPopHash)`: what the raw `pop` signed under `uaMessage(kind, POP_V2, ·)`. */
export const registrationDigest = (portable, pqzPopHash = Z32) => keccak_256(concatBytes(portable, pqzPopHash));
/** `keccak256(KEM_RECORD_TAG ‖ ua ‖ uint256(version) ‖ keccak256(kemPk))` (UA-8 P7; no validation here). */
export const kemRecordDigest = ({ ua, version, kemPk }) => keccak_256(concatBytes(KEM_RECORD_TAG, ua, word(version), keccak_256(kemPk)));
export const kemRecordMessage = (kind, record) => uaMessage(kind, KEM_TAG, kemRecordDigest(record));
/** `keccak256(PQZ_KEY_RECORD_TAG ‖ ua ‖ pqzKeyHash)`; the record digest adds the proof hash. */
export const pqzKeyDigest = ({ ua, pqzKeyHash }) => keccak_256(concatBytes(PQZ_KEY_RECORD_TAG, ua, pqzKeyHash));
export const pqzKeyRecordDigest = (keyDigest, pqzPopHash) => keccak_256(concatBytes(keyDigest, pqzPopHash));
/** EIP-191 `personal_sign` of a 32-byte digest: what a native EOA msig member signed over the `memberDigest` (ruling C7). */
export const personalSignDigest = (digest) => keccak_256(concatBytes(utf8ToBytes('\x19Ethereum Signed Message:\n32'), digest));
