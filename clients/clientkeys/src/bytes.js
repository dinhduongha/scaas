// Byte helpers shared by every signer. No secrets live here.
import { keccak_256 } from '@noble/hashes/sha3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';

export { keccak_256, sha256, bytesToHex, concatBytes, utf8ToBytes };

export function hex(bytes) {
  return '0x' + bytesToHex(bytes);
}

export function fromHex(value) {
  const s = String(value);
  return hexToBytes(s.startsWith('0x') || s.startsWith('0X') ? s.slice(2) : s);
}

export function b64url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromB64url(text) {
  const b64 = text.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((text.length + 3) % 4);
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/** Best effort: JS cannot wipe strings or guarantee no copies (GC, JIT); typed arrays we own we zero. */
export function wipe(...buffers) {
  for (const b of buffers) if (b && typeof b.fill === 'function') b.fill(0);
}

export function word(value) {
  let v = BigInt(value);
  if (v < 0n || v >= 1n << 256n) throw new Error('uint256 out of range');
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

export function addressWord(address) {
  const a = fromHex(address);
  if (a.length !== 20) throw new Error(`not an address: ${address}`);
  return concatBytes(new Uint8Array(12), a);
}

export function bytes32(v) {
  const b = v instanceof Uint8Array ? v : fromHex(v);
  if (b.length !== 32) throw new Error('bytes32 must be 32 bytes');
  return b;
}

function padded(b) {
  return concatBytes(word(b.length), b, new Uint8Array((32 - (b.length % 32)) % 32));
}

/**
 * Minimal `abi.encode` for the shapes this package needs: uint256/uint8, address, bytes32, bytes,
 * bytes32[], and a static tuple written as `(t1,t2,...)` of those static types.
 */
export function abiEncode(types, values) {
  const heads = [];
  const tails = [];
  let tailOffset = 0;
  const dyn = (t) => t === 'bytes' || t.endsWith('[]');
  const staticWords = (t, v) => {
    if (t.startsWith('(')) {
      const inner = t.slice(1, -1).split(',');
      return concatBytes(...inner.map((it, i) => staticWords(it, v[i])));
    }
    if (t === 'address') return addressWord(v);
    if (t === 'bytes32') return bytes32(v);
    if (/^uint\d+$/.test(t)) return word(v);
    throw new Error(`unsupported ABI type ${t}`);
  };
  const headSize = types.reduce((n, t) => n + (t.startsWith('(') ? 32 * t.split(',').length : 32), 0);
  types.forEach((t, i) => {
    if (!dyn(t)) {
      heads.push(staticWords(t, values[i]));
      return;
    }
    heads.push(word(headSize + tailOffset));
    const tail = t === 'bytes'
      ? padded(values[i] instanceof Uint8Array ? values[i] : fromHex(values[i]))
      : concatBytes(word(values[i].length), ...values[i].map(bytes32));
    tails.push(tail);
    tailOffset += tail.length;
  });
  return concatBytes(...heads, ...tails);
}
