// UNAUDITED. Soroban encodings for UA operations (UA-Soroban spec §2, §10): typed ScVal values with their XDR, the
// NET-SOR-16 op digest a UA signs, and the display rule of derived ids (NET-ALL-21: `urn:scaas:ua:v1:<kind>:<hex32>`,
// never a `G…` / `C…` strkey). The same encodings live in the contracts (`ua-common::op_digest`) and the node adapter;
// smartcontracts/soroban/vectors/ua-ops.json (scripts/soroban-ua-ops-vectors.mjs) pins all three.
import { base32 } from '@scure/base';
import { sha256, concatBytes, utf8ToBytes, fromHex, hex } from './bytes.js';
import { be } from './metaop.js';
import { strkey } from './seed.js';
import { UAError, KINDS, kindInfo, uaMessage } from './ua.js';

// ScValType discriminants (Stellar-contract.x)
const TYPE = { bool: 0, void: 1, u32: 3, u64: 5, i128: 10, bytes: 13, symbol: 15, vec: 16, map: 17, address: 18 };
const u32be = (n) => be(n, 4);
const val = (type, ...parts) => ({ type, xdr: concatBytes(u32be(TYPE[type]), ...parts) });
/** XDR variable-length opaque / string: length, data, zero padding to 4. */
const opaque = (b) => concatBytes(u32be(b.length), b, new Uint8Array((4 - (b.length % 4)) % 4));
const int = (n, bits, signed) => {
  const v = BigInt(n);
  const lo = signed ? -(1n << BigInt(bits - 1)) : 0n;
  if (v < lo || v >= lo + (1n << BigInt(bits))) throw new RangeError(`${v} out of range for ${signed ? 'i' : 'u'}${bits}`);
  return be(BigInt.asUintN(bits, v), bits / 8);
};
const raw = (x) => (typeof x === 'string' ? fromHex(x) : x);

export const bool = (b) => val('bool', u32be(b ? 1 : 0));
export const none = () => val('void');
/** `Option::Some(v)` is `v` itself on the wire. */
export const some = (v) => v;
export const u32 = (n) => val('u32', int(n, 32, false));
export const u64 = (n) => val('u64', int(n, 64, false));
/** `Int128Parts { hi: i64, lo: u64 }` = the 16-byte big-endian two's complement. */
export const i128 = (n) => val('i128', int(n, 128, true));
export const bytes = (u8) => val('bytes', opaque(raw(u8)));
export const bytesN = (u8) => bytes(u8);
export function sym(s) {
  if (!/^[A-Za-z0-9_]{0,32}$/.test(s)) throw new Error(`not a Soroban symbol: ${s}`);
  return val('symbol', opaque(utf8ToBytes(s)));
}
export const vec = (items) => val('vec', u32be(1), u32be(items.length), ...items.map((v) => v.xdr));

const STRKEY = { G: 6 << 3, C: 2 << 3 };
/** A `G…` account or a `C…` contract strkey → `[ScAddress type, 32-byte payload]`; checksum and version checked. */
export function decodeStrkey(text) {
  let b;
  try { b = base32.decode(String(text)); } catch { b = null; }
  const version = STRKEY[String(text)[0]];
  if (!b || b.length !== 35 || b[0] !== version || strkey(version, b.subarray(1, 33)) !== text) {
    throw new Error(`not a G… / C… strkey: ${text}`);
  }
  return { contract: version === STRKEY.C, payload: b.slice(1, 33) };
}
/** `ScVal::Address`: account = `SC_ADDRESS_TYPE_ACCOUNT, PUBLIC_KEY_TYPE_ED25519, key`; contract = `SC_ADDRESS_TYPE_CONTRACT, id`. */
export function addr(text) {
  const { contract, payload } = decodeStrkey(text);
  return val('address', contract ? u32be(1) : new Uint8Array(8), payload);
}

/** A `#[contracttype]` struct: `Map` of `Symbol(field) → value`, keys sorted. */
export function struct(fields) {
  const keys = Object.keys(fields).sort();
  return val('map', u32be(1), u32be(keys.length), ...keys.flatMap((k) => [sym(k).xdr, fields[k].xdr]));
}
/** A `#[contracttype]` enum variant with one field: `Vec[Symbol(variant), payload]`. */
const variant = (name, payload) => vec([sym(name), payload]);
export const holderAddr = (text) => variant('Addr', addr(text));
export function holderUa(id) {
  const b = raw(id);
  if (b.length !== 32) throw new Error('a UA id is 32 bytes');
  return variant('Ua', bytesN(b));
}
export const scvalXdr = (v) => v.xdr;

export const networkId = (passphrase) => sha256(utf8ToBytes(passphrase));

/** NET-SOR-16 (spec §2): `sha256(xdr(Vec[Symbol("scaas_metaop_v1"), Bytes(network_id), Address(contract), Symbol(fn),
 *  Vec(args)]))`, the entry's arguments without `auth`. */
export const opDigest = ({ networkId: n, contract, fn, args }) =>
  sha256(vec([sym('scaas_metaop_v1'), bytesN(n), addr(contract), sym(fn), vec(args)]).xdr);

/** What the UA signs for an op digest: CTR-UA-12's `ua_msg(kind, purposeTag, digest)` (the registry recomputes it). */
export const uaOpMessage = uaMessage;

// --- display (NET-ALL-21): a derived id is never a strkey ---
const URN = /^urn:scaas:ua:v1:([a-z0-9-]+):([0-9a-f]{64})$/;
const BY_NAME = new Map(KINDS.map((k) => [k.name, k]));

/** `urn:scaas:ua:v1:<kind name>:<64 lower-case hex>`; derived kinds only. */
export function uaUrn(kind, id) {
  const k = typeof kind === 'string' ? BY_NAME.get(kind) : kindInfo(kind);
  if (!k || k.native) throw new UAError('UAKindNotDerived', String(kind));
  const b = raw(id);
  if (b.length !== 32) throw new UAError('UAIdFormat', 'a UA id is 32 bytes');
  return `urn:scaas:ua:v1:${k.name}:${hex(b).slice(2)}`;
}

/** A recipient as typed: a `G…` / `C…` strkey ⇒ `{ addr }`, a UA URN ⇒ `{ ua, kind }`; anything else throws. */
export function parseRecipient(text) {
  const m = URN.exec(String(text));
  if (m) {
    const k = BY_NAME.get(m[1]);
    if (!k || k.native) throw new UAError('UAKindNotDerived', m[1]);
    return { ua: fromHex(m[2]), kind: k.kind };
  }
  decodeStrkey(text);
  return { addr: String(text) };
}

/** A native payment or SEP-41 `transfer` goes to a strkey only: a UA URN is `UaNotNative` (pay the token's UA entry). */
export function assertNativeRecipient(text) {
  const r = parseRecipient(text);
  if (r.ua) throw new UAError('UaNotNative', 'a native send cannot go to a UA (NET-ALL-21): use transfer_to_ua / pay_to_ua');
  return r.addr;
}
