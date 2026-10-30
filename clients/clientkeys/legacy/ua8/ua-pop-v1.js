// UNAUDITED. Legacy (UA-8 A1, owner: backup, not delete) — the chain-bound proof of possession as it stood before UA-8:
// `popDigest` over the chain id, the chain uid and the registry address (CTR-UA-07 before UA-8), the holder PoP message,
// the R_REG message and the Zether PoP built on it. Superseded by the portable digests of src/ua.js (UA-8 P1:
// `portablePopDigest`, `registrationDigest`, `holderPopMessage`, `pqzRegMessage`) and `zetherPop` of src/zether.js.
// Not exported by the package and not bundled. Read by scripts/ua-sig-vectors.mjs (the `chain-bound-pop` negatives: a
// pre-UA-8 PoP is refused) and by test/ua-groups.test.js until groups.json is regenerated on the portable PoP (UA-8 A2).
import { keccak_256, concatBytes, hex, fromHex } from '../../src/bytes.js';
import { POP_TAG, chainKeyHash, uaMessage, keyHashOf, isPqzHolder, UAError, purposeTag } from '../../src/ua.js';
import { confPublic, zetherKind, schnorrSign } from '../../src/zether.js';

const bytes = (v) => (v instanceof Uint8Array ? v : fromHex(v));
const sized = (v, n, what) => {
  const b = bytes(v);
  if (b.length !== n) throw new Error(`${what} must be ${n} bytes`);
  return b;
};
const addressWord = (a) => concatBytes(new Uint8Array(12), sized(a, 20, 'registry'));

/** `pop_digest` (CTR-UA-07 before UA-8): `pqzKeyHash` is the keyHash of the UA's PQZ key, 0 without one. */
export function popDigestV1({ chainId, chainUid, registry, ua, pqzKeyHash = new Uint8Array(32) }) {
  return keccak_256(concatBytes(POP_TAG, chainKeyHash(chainId), sized(chainUid, 32, 'chainUid'), addressWord(registry),
    sized(ua, 32, 'ua'), sized(pqzKeyHash, 32, 'pqzKeyHash')));
}

/** `{ pqzKeyHash, popDigest, message }`, `message = uaMessage(kind, pop, popDigestV1(ua, h))`, `h = keyHash(0x0142, pqzKey)`. */
export function holderPopMessageV1(kind, { chainId, chainUid, registry, ua, pqzKey }) {
  if (pqzKey && !isPqzHolder(kind)) throw new UAError('UAPqzHolder', `0x${Number(kind).toString(16)} may not hold a PQZ key`);
  const pqzKeyHash = pqzKey ? keyHashOf(0x0142, pqzKey) : new Uint8Array(32);
  const d = popDigestV1({ chainId, chainUid, registry, ua, pqzKeyHash });
  return { pqzKeyHash, popDigest: d, message: uaMessage(kind, POP_TAG, d) };
}

/** `uaMessage(0x0142, pop, popDigestV1(ua, keyHash(0x0142, pqzKey)))` (UA-6 U14). */
export function pqzRegMessageV1({ chainId, chainUid, registry, ua, pqzKey }) {
  const h = keyHashOf(0x0142, pqzKey);
  return uaMessage(0x0142, POP_TAG, popDigestV1({ chainId, chainUid, registry, ua, pqzKeyHash: h }));
}

/** The Zether `pop` over `uaMessage(0x0141, pop, popDigestV1(chain, chainUid, registry, UA))`. */
export function zetherPopV1(curve, x, { chainId, chainUid, registry }) {
  const kind = zetherKind(curve);
  const { Y, UA } = confPublic(curve, x);
  const d = popDigestV1({ chainId, chainUid, registry, ua: UA });
  const m = uaMessage(kind, purposeTag('pop'), d);
  return { kind, Y, UA, popDigest: hex(d), uaMsg: hex(m), pop: hex(schnorrSign(curve, x, m)) };
}
