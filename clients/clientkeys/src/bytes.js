// Byte helpers shared by every signer. No secrets live here.
import { keccak_256 } from "@noble/hashes/sha3.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";

export { keccak_256, sha256, bytesToHex, concatBytes, utf8ToBytes };

export function hex(bytes) {
  return "0x" + bytesToHex(bytes);
}

export function fromHex(value) {
  const s = String(value);
  return hexToBytes(s.startsWith("0x") || s.startsWith("0X") ? s.slice(2) : s);
}

export function b64url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64url(text) {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/** Best effort: JS cannot wipe strings or guarantee no copies (GC, JIT); typed arrays we own we zero. */
export function wipe(...buffers) {
  for (const b of buffers) if (b && typeof b.fill === "function") b.fill(0);
}

export function word(value) {
  if (typeof value === "string" && value.trim() === "") throw new Error("not a number: the empty string"); // BigInt('') is 0
  let v = BigInt(value);
  if (v < 0n || v >= 1n << 256n) throw new Error("uint256 out of range");
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** `Boolean('false')` is true: a bool is `true` or `false`, nothing that reads as one. */
export function boolWord(value) {
  if (typeof value !== "boolean") throw new Error(`not a bool: ${value}`);
  return word(value ? 1 : 0);
}

export function addressWord(address) {
  const a = fromHex(address);
  if (a.length !== 20) throw new Error(`not an address: ${address}`);
  return concatBytes(new Uint8Array(12), a);
}

/** An integer as given (T21 L65): a bigint, a safe integer `number`, or decimal digits with no sign, space or leading zero;
 *  anything else is refused, never changed (`BigInt('')`, `BigInt(false)`, `Number(null)` are 0; `BigInt(' 7 ')` is 7). The
 *  caller checks the range. */
export function intOf(v, what) {
  if (typeof v === "bigint") return v;
  if (typeof v === "number" && Number.isSafeInteger(v)) return BigInt(v);
  if (typeof v === "string" && /^(0|[1-9][0-9]*)$/.test(v)) return BigInt(v);
  throw new Error(`${what}: not an integer (a bigint, a safe integer, or decimal digits)`);
}

export function bytes32(v) {
  const b = v instanceof Uint8Array ? v : fromHex(v);
  if (b.length !== 32) throw new Error("bytes32 must be 32 bytes");
  return b;
}

function padded(b) {
  return concatBytes(word(b.length), b, new Uint8Array((32 - (b.length % 32)) % 32));
}

/** The member types of a tuple type `(t1,t2,...)`, split at its top-level commas. */
function tupleTypes(t) {
  const out = [];
  let depth = 0;
  let start = 1;
  for (let i = 1; i < t.length - 1; i++) {
    if (t[i] === "(") depth++;
    else if (t[i] === ")") depth--;
    else if (t[i] === "," && depth === 0) {
      out.push(t.slice(start, i));
      start = i + 1;
    }
  }
  out.push(t.slice(start, -1));
  return out;
}

const isDynamic = (t) =>
  t === "bytes" || t === "string" || t.endsWith("[]") || (t.startsWith("(") && tupleTypes(t).some(isDynamic));
const headSize = (t) => (t.startsWith("(") && !isDynamic(t) ? tupleTypes(t).reduce((n, m) => n + headSize(m), 0) : 32);

function encodeOne(t, v) {
  if (t.endsWith("[]")) {
    const inner = t.slice(0, -2);
    return concatBytes(
      word(v.length),
      abiEncode(
        v.map(() => inner),
        v,
      ),
    );
  }
  if (t.startsWith("(")) return abiEncode(tupleTypes(t), v);
  if (t === "bytes") return padded(v instanceof Uint8Array ? v : fromHex(v));
  if (t === "string") return padded(utf8ToBytes(String(v)));
  if (t === "address") return addressWord(v);
  if (t === "bytes32") return bytes32(v);
  if (t === "bool") return boolWord(v);
  if (/^bytes\d+$/.test(t)) {
    const b = v instanceof Uint8Array ? v : fromHex(v);
    if (b.length !== Number(t.slice(5))) throw new Error(`${t} must be ${t.slice(5)} bytes`);
    return concatBytes(b, new Uint8Array(32 - b.length));
  }
  if (/^uint\d+$/.test(t)) return word(v);
  throw new Error(`unsupported ABI type ${t}`);
}

/** `abi.encode`: uintN, bool, address, bytesN, bytes, string (UTF-8), `T[]` and tuples written `(t1,t2,...)`, nested and dynamic ones too. */
export function abiEncode(types, values) {
  const heads = [];
  const tails = [];
  let tailOffset = types.reduce((n, t) => n + headSize(t), 0);
  types.forEach((t, i) => {
    const enc = encodeOne(t, values[i]);
    if (!isDynamic(t)) {
      heads.push(enc);
      return;
    }
    heads.push(word(tailOffset));
    tails.push(enc);
    tailOffset += enc.length;
  });
  return concatBytes(...heads, ...tails);
}

/** JSON with exact uint64s (a path-less Add's nonce, C47): a BigInt is written as a bare integer, and an integer beyond
 *  2^53 is read back as a BigInt from its source text. */
export const jsonStringify = (v, replacer = null, space = undefined) =>
  JSON.stringify(
    v,
    (k, x) => {
      const y = replacer ? replacer(k, x) : x;
      return typeof y === "bigint" ? `@@uint:${y}` : y;
    },
    space,
  ).replace(/"@@uint:(\d+)"/g, "$1");
export const jsonParse = (s) =>
  JSON.parse(s, (_, v, c) => {
    if (typeof v !== "number" || Number.isSafeInteger(v)) return v;
    // a runtime without the reviver's source text (JSON.parse source access) would round the integer: refused, never
    // rounded (the path-less review's C-7)
    if (!c || typeof c.source !== "string")
      throw new Error("jsonParse: an integer beyond 2^53 needs JSON.parse source access");
    return /^\d+$/.test(c.source) ? BigInt(c.source) : v;
  });
