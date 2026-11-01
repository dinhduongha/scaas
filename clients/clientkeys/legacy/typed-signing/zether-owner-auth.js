// typed-signing C3: `src/zether.js` before the owner ops took `UASig`, not built. Superseded by `zetherOwnerSig`.
import { hex, abiEncode } from '../../src/bytes.js';
import { zetherSign } from '../../src/zether.js';

/**
 * The `sig` of an owner op (`mtxRollOverSigned`, `mtxSetRollOverMode`):
 * `abi.encode(bytes(""), Schnorr by x over uaMessage(kind, zether-owner, digest))`.
 */
export function zetherOwnerAuth(curve, x, digest) {
  return hex(abiEncode(['bytes', 'bytes'], [new Uint8Array(0), zetherSign(curve, x, 'zether-owner', digest)]));
}

