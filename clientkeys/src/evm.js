// EVM pieces: EIP-712 digests, addresses, SubjectAccount key/salt/CREATE2, Merkle batch.
import {
  keccak_256, sha256, concatBytes, utf8ToBytes, bytesToHex, fromHex, hex, word, addressWord, abiEncode,
} from './bytes.js';

export function checksumAddress(address) {
  const low = bytesToHex(fromHex(address));
  const h = bytesToHex(keccak_256(utf8ToBytes(low)));
  return '0x' + [...low].map((c, i) => (parseInt(h[i], 16) >= 8 ? c.toUpperCase() : c)).join('');
}

/** Address of an uncompressed (65-byte, 0x04-prefixed) secp256k1 public key. */
export function evmAddress(uncompressed) {
  if (uncompressed.length !== 65 || uncompressed[0] !== 4) throw new Error('need an uncompressed public key');
  return checksumAddress(hex(keccak_256(uncompressed.subarray(1)).subarray(12)));
}

// ------------------------------------------------------------------ EIP-712 (flat structs)

function encodeType(types, primary) {
  return `${primary}(${types[primary].map((f) => `${f.type} ${f.name}`).join(',')})`;
}

function encodeValue(type, value) {
  if (type === 'string') return keccak_256(utf8ToBytes(String(value)));
  if (type === 'bytes') return keccak_256(value instanceof Uint8Array ? value : fromHex(value));
  if (type === 'address') return addressWord(value);
  if (type === 'bool') return word(value ? 1 : 0);
  if (type === 'bytes32') return fromHex(value);
  if (/^uint\d+$/.test(type)) return word(value);
  throw new Error(`EIP-712 type ${type} is not supported here`);
}

export function hashStruct(types, primary, data) {
  return keccak_256(concatBytes(
    keccak_256(utf8ToBytes(encodeType(types, primary))),
    ...types[primary].map((f) => encodeValue(f.type, data[f.name])),
  ));
}

/** `eth_signTypedData_v4` digest of the typed data the server issued. */
export function hashTypedData(td) {
  return keccak_256(concatBytes(
    new Uint8Array([0x19, 0x01]),
    hashStruct(td.types, 'EIP712Domain', td.domain),
    hashStruct(td.types, td.primaryType, td.message),
  ));
}

// ------------------------------------------------------------------ SubjectAccount

export const KEY_P256_WEBAUTHN = 1;
export const KEY_SECP256K1 = 2;
const KEY_TUPLE = '(uint8,bytes32,bytes32,bytes32,bytes32)';
const ZERO32 = new Uint8Array(32);

export function passkeySubjectKey({ x, y, rpId, origin }) {
  return [KEY_P256_WEBAUTHN, x, y, sha256(utf8ToBytes(rpId)), keccak_256(utf8ToBytes(origin))];
}

export function secpSubjectKey(address) {
  return [KEY_SECP256K1, addressWord(address), ZERO32, ZERO32, ZERO32];
}

export function keyId(key) {
  return keccak_256(abiEncode([KEY_TUPLE], [key]));
}

export function accountSalt(key, guardian) {
  return keccak_256(abiEncode([KEY_TUPLE, 'address'], [key, guardian]));
}

/** OZ `Clones.predictDeterministicAddress` (EIP-1167 + CREATE2). */
export function predictAccount(implementation, salt, factory) {
  const code = concatBytes(fromHex('3d602d80600a3d3981f3363d3d373d3d3d363d73'), fromHex(implementation),
                           fromHex('5af43d82803e903d91602b57fd5bf3'));
  const h = keccak_256(concatBytes(new Uint8Array([0xff]), fromHex(factory), salt, keccak_256(code)));
  return checksumAddress(hex(h.subarray(12)));
}

/** `abi.encode(keyIndex, proof, sig)` — what `SubjectAccount.isValidSignature` decodes (RS4-3). */
export function accountSignature(keyIndex, proof, inner) {
  return abiEncode(['uint256', 'bytes32[]', 'bytes'], [keyIndex, proof, inner]);
}

// ------------------------------------------------------------------ Merkle batch (review S26)

export function batchLeaf(digest) {
  return keccak_256(keccak_256(concatBytes(new Uint8Array([0]), digest)));
}

function nodeHash(a, b) {
  return bytesToHex(a) < bytesToHex(b) ? keccak_256(concatBytes(a, b)) : keccak_256(concatBytes(b, a));
}

/** Root over digests + one proof per digest (sorted pairs as OZ MerkleProof; odd node promoted). */
export function merkleBatch(digests) {
  if (digests.length < 2) throw new Error('a batch has at least two operations; sign one digest directly');
  let layer = digests.map(batchLeaf);
  const proofs = digests.map(() => []);
  let pos = digests.map((_, i) => i);
  while (layer.length > 1) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2) next.push(i + 1 < layer.length ? nodeHash(layer[i], layer[i + 1]) : layer[i]);
    pos = pos.map((p, k) => {
      const sib = p ^ 1;
      if (sib < layer.length) proofs[k].push(layer[sib]);
      return p >> 1;
    });
    layer = next;
  }
  return { root: layer[0], proofs };
}

export function processProof(proof, leaf) {
  return proof.reduce((acc, p) => nodeHash(acc, p), leaf);
}
