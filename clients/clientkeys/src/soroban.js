// UNAUDITED. Soroban encodings for UA operations (UA-Soroban spec §2, §10): typed ScVal values with their XDR, the
// NET-SOR-16 op digest a UA signs, and the display rule of derived ids (NET-ALL-21: `urn:scaas:ua:v1:<kind>:<hex32>`,
// never a `G…` / `C…` strkey). The same encodings live in the contracts (`ua-common::op_digest`) and the node adapter;
// smartcontracts/soroban/vectors/ua-ops.json (scripts/soroban-ua-ops-vectors.mjs) pins all three.
import { base32 } from '@scure/base';
import { sha256, concatBytes, utf8ToBytes, fromHex, hex } from './bytes.js';
import { be } from './metaop.js';
import { strkey } from './seed.js';
import { UAError, KINDS, kindInfo, uaMessage, encodeMsig as encodeMsigKeyData } from './ua.js';

// ScValType discriminants (Stellar-contract.x)
const TYPE = { bool: 0, void: 1, u32: 3, i32: 4, u64: 5, i64: 6, timepoint: 7, duration: 8, u128: 9, i128: 10, u256: 11, i256: 12, bytes: 13, string: 14,
  symbol: 15, vec: 16, map: 17, address: 18 };
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
/** A `UaSig` (TS-D12): a single key `{ signature }`, an `msig` `{ members: [{ index, keyData, sig }] }`; `key_data` stays
 *  empty on Soroban (the key is read from the record). */
export function uaSig({ signature = new Uint8Array(0), members = [] }) {
  const none = bytes(new Uint8Array(0));
  const slots = members.map((m) => struct({ index: u32(m.index), key_data: bytes(m.keyData), sig: bytes(m.sig) }));
  return struct({ key_data: none, members: vec(slots), signature: bytes(signature) });
}
export const scvalXdr = (v) => v.xdr;

// --- a node job's named values (docs/node/job-api.md): the same ScVal the node builds from the same JSON ---
const fixed = (type, bits, signed) => (n) => val(type, int(n, bits, signed));
const ORDER_TYPE = { maker: 'Holder', destination: 'Holder', relayer: 'Address', sell_token: 'Address', sell_amount: 'i128', buy_token: 'Address', buy_amount: 'i128',
  max_fee_ppm: 'u32', expiry: 'u64', salt: 'u64' };
const INT = /^[iu]\d+$|^Timepoint$|^Duration$/;
/** The order the node sorts a `Map` in: by ScVal type, then by value.
 *  ponytail: a `Vec`, `Map` or `Holder` key compares by its XDR, length word first, the node by element; such a key out of order
 *  only fails at simulation (the signature is over other bytes). Compare element by element if a contract ever takes one. */
function mapRank({ type, value }) {
  if (INT.test(type)) return BigInt(value);
  return type === 'Symbol' || type === 'String' || type === 'Bytes' ? value : hex(jobValue({ type, value }).xdr);
}
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const JOB_TYPES = {
  'BytesN<32>': bytesN, Bytes: bytes, bool, Address: addr, Symbol: sym, Void: none,
  String: (s) => val('string', opaque(utf8ToBytes(s))),
  i128, u32, u64, i32: fixed('i32', 32, true), i64: fixed('i64', 64, true), u128: fixed('u128', 128, false), u256: fixed('u256', 256, false), i256: fixed('i256', 256, true),
  Timepoint: fixed('timepoint', 64, false), Duration: fixed('duration', 64, false),
  Holder: (h) => ('Ua' in h ? holderUa(h.Ua) : holderAddr(h.Addr)),
  UaSig: (x) => uaSig({ signature: x.signature, members: x.members.map((m) => ({ index: m.index, keyData: m.key_data, sig: m.sig })) }),
  Order: (o) => struct(Object.fromEntries(Object.keys(ORDER_TYPE).map((k) => [k, jobValue({ type: ORDER_TYPE[k], value: o[k] })]))),
  'Vec<Val>': (l) => vec(l.map(jobValue)),
  Map: (entries) => {
    const sorted = [...entries].sort((a, b) => TYPE_OF(a.key) - TYPE_OF(b.key) || cmp(mapRank(a.key), mapRank(b.key)));
    return val('map', u32be(1), u32be(sorted.length), ...sorted.flatMap((e) => [jobValue(e.key).xdr, jobValue(e.val).xdr]));
  },
};
const TYPE_OF = (k) => jobValue(k).xdr[3];
/** `{ type, value }` of a relayed call or a signed invocation → its ScVal. */
export function jobValue({ type, value }) {
  const make = JOB_TYPES[type];
  if (!make) throw new Error(`not a job value type: ${type}`);
  return make(value);
}

const invocationXdr = ({ contract, function: fn, args, sub_invocations: subs }) => concatBytes(u32be(0), addr(contract).xdr.subarray(4), sym(fn).xdr.subarray(4),
  u32be(args.length), ...args.map((a) => jobValue(a).xdr), u32be(subs.length), ...subs.map(invocationXdr));
/** What a native account signs for a `signed_op`, `op.auth[]` or `extra.auth[]` entry, from the job's named `payload { nonce, expiry,
 *  invocation }`: `HashIdPreimage::SorobanAuthorization` on this network. The node rebuilds the same bytes; the account signs `authDigest`. */
export const authPreimage = ({ networkId: n, nonce, expiry, invocation }) =>
  concatBytes(u32be(9), n, int(nonce, 64, true), u32be(expiry), invocationXdr(invocation));
export const authDigest = (payload) => sha256(authPreimage(payload));
/** One subject's authorization as a job names it: a `signed_op`'s `{payload, from, signature}`, or an `op.auth[]` / `extra.auth[]` row.
 *  `nonce` goes as a decimal string, past 2^53; `sign` takes the 32-byte digest and gives the bytes the host reads: an ed25519 signature
 *  of a `G…`, the `ScVal` XDR a `C…` subject's `__check_auth` reads. */
export const signedAuth = ({ networkId: n, nonce, expiry, invocation, from, sign }) => ({
  payload: { nonce: String(nonce), expiry, invocation }, from, signature: hex(sign(authDigest({ networkId: n, nonce, expiry, invocation }))),
});

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

const URN_PREFIX = /^urn:scaas:ua:/i;

/** A recipient as typed: a `G…` / `C…` strkey ⇒ `{ addr }`, a UA URN ⇒ `{ ua, kind }`; anything else throws. A
 *  `urn:scaas:ua:` prefix in any case that is not the lower-case URN is `UAIdFormat`, never a strkey error. */
export function parseRecipient(text) {
  const m = URN.exec(String(text));
  if (m) {
    const k = BY_NAME.get(m[1]);
    if (!k || k.native) throw new UAError('UAKindNotDerived', m[1]);
    return { ua: fromHex(m[2]), kind: k.kind };
  }
  if (URN_PREFIX.test(String(text))) throw new UAError('UAIdFormat', 'a UA URN is lower case: urn:scaas:ua:v1:<kind>:<hex32>');
  decodeStrkey(text);
  return { addr: String(text) };
}

/** A native payment or SEP-41 `transfer` goes to a strkey only: a UA URN (any case) is `UaNotNative` (pay the token's
 *  UA entry). */
export function assertNativeRecipient(text) {
  if (URN_PREFIX.test(String(text))) throw new UAError('UaNotNative', 'a native send cannot go to a UA (NET-ALL-21): use transfer_to_ua / pay_to_ua');
  const r = parseRecipient(text);
  if (r.ua) throw new UAError('UaNotNative', 'a native send cannot go to a UA (NET-ALL-21): use transfer_to_ua / pay_to_ua');
  return r.addr;
}

/** A Soroban `msig`'s key data (CTR-UA-09, `ua.encodeMsig`): a `soroban-contract` (`C…`, 0x0012) member is
 *  `MemberUnknown`, as in the registry (spec S10, owner ruling 2026-10-31: a contract that calls the registry would
 *  meet its own slot by Soroban invoker auth). Members: `G…` accounts (0x0011) and registered derived UAs. */
export function encodeMsig(threshold, members) {
  if (members.some((m) => m.kind === 0x0012)) throw new UAError('MemberUnknown', 'a soroban-contract (C…) msig member is refused on Soroban (S10)');
  return encodeMsigKeyData(threshold, members);
}
