// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The scaas-sdk keystore container (scaas-sdk spec §6.1, CLI-SDK-03): one item holding several seeds, each as vault v1 texts
// byte for byte (src/vault.js), with the integrity fields `rev`, `backup` and `indexMac` (src/keystore-mac.js) from v 1 on.
//   {format: "scaas.keystore", v: 1, rev, seeds: [{id, label, words, fingerprint, origin, class, warnings, backup, vaults,
//    accounts, indexMac}]}
// `parse` refuses by name: `VaultVersion` (format, v), `VaultFormat` (every other rule, and any text other than the canonical
// form `serialize` writes: compact JSON, the field orders below), so serialize(parse(x)) === x. A vault text is
// parsed only to compare its `label` with its key. No cryptography here (the MAC is checked at unlock, by the seed's owner).
// The scaas-sdk Rust parser refuses the same files with the same names (smartcontracts/vectors/keystore/keystore.json).
// UNAUDITED.
import { utf8ToBytes } from './bytes.js';

export const FORMAT = 'scaas.keystore';
export const MAX_BYTES = 16 << 20;
export const MAX_DEPTH = 5;
export const MAX_SEEDS = 64;
export const MAX_VAULTS = 64;
export const MAX_VAULT_BYTES = 2 << 20;
export const MAX_ACCOUNTS = 1024;
const TOP = ['format', 'v', 'rev', 'seeds'];
const SEED = ['id', 'label', 'words', 'fingerprint', 'origin', 'class', 'warnings', 'backup', 'vaults', 'accounts', 'indexMac'];
const WORDS = [12, 15, 18, 21, 24];
const ORIGINS = ['generated', 'imported', 'bip85', 'eoa-sig', 'raw-key'];
const CLASSES = ['full', 'classical-rooted'];
const WARNINGS = ['short_seed', 'imported_key'];
const BACKUPS = ['pending', 'verified'];
// account rows by shape, each field list in its written order; `?` optional
const ROWS = {
  ua: ['id', 'name', 'kind', 'account', 'index', 'ua'],
  native: ['id', 'name', 'network', 'index', 'coinType?', 'change?', 'path?', 'ss58Prefix?', 'address'],
  key: ['id', 'name', 'kind', 'keyData', 'credentialId?', 'handle?', 'ua'],
  watch: ['id', 'name', 'watch'],
};
const UUID4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const refuse = (code, message) => { throw Object.assign(new Error(message), { code }); };
const format = (why) => refuse('VaultFormat', `keystore: ${why}`);

/** JSON nesting depth by a flat scan (strings skipped), before anything is parsed; Infinity past `max`. */
export function depthOf(text, max = MAX_DEPTH) {
  let d = 0, top = 0, inStr = false, esc = false;
  for (const ch of text) {
    if (inStr) {
      if (esc) esc = false;
      else if (ch === '\\') esc = true;
      else if (ch === '"') inStr = false;
    } else if (ch === '"') inStr = true;
    else if (ch === '{' || ch === '[') { d += 1; if (d > top) top = d; if (top > max) return Infinity; }
    else if (ch === '}' || ch === ']') d -= 1;
  }
  return top;
}

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const isStr = (x) => typeof x === 'string';
const isUint = (x) => Number.isSafeInteger(x) && x >= 0;

function only(o, fields, what) {
  if (!isObj(o)) format(`${what} is not an object`);
  const allowed = new Set(fields.map((f) => f.replace(/\?$/, '')));
  for (const k of Object.keys(o)) if (!allowed.has(k)) format(`unknown ${what} field ${k}`);
  for (const f of fields) if (!f.endsWith('?') && !Object.hasOwn(o, f)) format(`${what} without ${f}`);
}

function checkLabel(label) {
  if (!isStr(label)) format('label not a string');
  const n = [...label].length;
  if (n < 1 || n > 64) format('label of 0 or more than 64 characters');
  if (/\p{Cc}/u.test(label)) format('label with a control character');
  if (label.normalize('NFC') !== label) format('label not NFC');
}

function rowShape(r) {
  if (!isObj(r)) format('account row not an object');
  if (Object.hasOwn(r, 'watch')) return 'watch';
  if (Object.hasOwn(r, 'network')) return 'native';
  if (Object.hasOwn(r, 'keyData')) return 'key';
  return 'ua';
}

function checkRow(r) {
  const shape = rowShape(r);
  only(r, ROWS[shape], 'account');
  if (!isStr(r.id) || !isStr(r.name)) format('account id or name not a string');
  for (const k of ['kind', 'account', 'index', 'coinType', 'change', 'ss58Prefix']) if (Object.hasOwn(r, k) && !isUint(r[k])) format(`account ${k} not an integer`);
  for (const k of ['network', 'path', 'address', 'ua', 'keyData', 'credentialId', 'handle', 'watch']) if (Object.hasOwn(r, k) && !isStr(r[k])) format(`account ${k} not a string`);
  return shape;
}

function checkSeed(s) {
  only(s, SEED, 'seed');
  if (!isStr(s.id) || !UUID4.test(s.id)) format('seed id not a lower-case UUID v4');
  checkLabel(s.label);
  if (!WORDS.includes(s.words)) format('words not 12, 15, 18, 21 or 24');
  if (!isStr(s.fingerprint) || !/^[0-9a-f]{8}$/.test(s.fingerprint)) format('fingerprint not 8 lower-case hex digits');
  if (!ORIGINS.includes(s.origin)) format('unknown origin');
  if (!CLASSES.includes(s.class)) format('unknown class');
  if (!Array.isArray(s.warnings) || !s.warnings.every((w) => WARNINGS.includes(w)) || new Set(s.warnings).size !== s.warnings.length) format('unknown or repeated warning');
  if (!BACKUPS.includes(s.backup)) format('backup not pending or verified');
  if (!isStr(s.indexMac) || !/^[0-9a-f]{64}$/.test(s.indexMac)) format('indexMac not 64 lower-case hex digits');
  if (!isObj(s.vaults)) format('vaults not an object');
  const labels = Object.keys(s.vaults);
  if (labels.length > MAX_VAULTS) format('more than 64 vaults');
  if (!labels.includes('seed')) format('no seed vault');
  for (const k of labels) {
    if (!/^[\x21-\x7e]{1,128}$/.test(k)) format(`vault key not printable ASCII of 1 to 128 bytes`);
    const t = s.vaults[k];
    if (!isStr(t) || utf8ToBytes(t).length > MAX_VAULT_BYTES) format(`vault ${k} not a string of at most 2 MiB`);
    let inner;
    try { inner = JSON.parse(t); } catch { format(`vault ${k} not JSON`); }
    if (!isObj(inner) || inner.label !== k) format(`vault key ${k} is not its vault's label`);
  }
  if (!Array.isArray(s.accounts) || s.accounts.length > MAX_ACCOUNTS) format('accounts not a list of at most 1024');
  s.accounts.forEach(checkRow);
}

/** Every string of `v` (keys too) well-formed UTF-16: no lone surrogate (which a Rust reader cannot hold). */
function wellFormed(v) {
  if (isStr(v)) return v.isWellFormed();
  if (Array.isArray(v)) return v.every(wellFormed);
  if (isObj(v)) return Object.entries(v).every(([k, x]) => k.isWellFormed() && wellFormed(x));
  return true;
}

function check(c) {
  if (!isObj(c)) format('not an object');
  if (c.format !== FORMAT || c.v !== 1) refuse('VaultVersion', 'keystore: another format or version');
  only(c, TOP, 'top-level');
  if (!isUint(c.rev)) format('rev not an integer');
  if (!Array.isArray(c.seeds) || c.seeds.length > MAX_SEEDS) format('seeds not a list of at most 64');
  c.seeds.forEach(checkSeed);
  for (const k of ['id', 'label']) if (new Set(c.seeds.map((s) => s[k])).size !== c.seeds.length) format(`a duplicate seed ${k}`);
  if (!wellFormed(c)) format('a string with a lone surrogate');
}

const ordered = (o, fields) => Object.fromEntries(fields.map((f) => f.replace(/\?$/, '')).filter((f) => Object.hasOwn(o, f)).map((f) => [f, o[f]]));

/** The canonical text: compact JSON, every object's fields in the written order, the vaults by key (printable ASCII, so UTF-16
 *  and byte order agree). */
function canon(c) {
  const vaults = (v) => Object.fromEntries(Object.keys(v).sort().map((k) => [k, v[k]]));
  const seeds = c.seeds.map((s) => ordered({ ...s, vaults: vaults(s.vaults), accounts: s.accounts.map((r) => ordered(r, ROWS[rowShape(r)])) }, SEED));
  return JSON.stringify({ format: c.format, v: c.v, rev: c.rev, seeds });
}

/** The container of `text` (a string), every rule checked; a refusal names `VaultVersion` or `VaultFormat`. Only the canonical
 *  text `serialize` writes is accepted (white space, another field order, a duplicate key, `24.0` or an escape JSON.stringify
 *  does not write are `VaultFormat`), so every reader of the container decides alike. */
export function parse(text) {
  if (!isStr(text)) format('not text');
  if (utf8ToBytes(text).length > MAX_BYTES) format('larger than 16 MiB');
  if (depthOf(text) > MAX_DEPTH) format('nested deeper than 5');
  let c;
  try { c = JSON.parse(text); } catch { format('not JSON'); }
  check(c);
  if (canon(c) !== text) format('not in canonical form');
  return c;
}

/** The canonical text of container `c`, every rule checked first. */
export function serialize(c) {
  check(c);
  return canon(c);
}
