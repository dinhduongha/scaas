// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Generates smartcontracts/vectors/ua/id_display.json (ua-mtx-merge spec §6, MD-9): how a client shows a bytes32 id before the
// user signs, by src/ua.js idDisplay. A native-space id is its EIP-55 address, a derived id its URN (NET-ALL-21), anything else
// refused with its error. Derived ids are the first valid id of each derived kind in kinds.json; the EIP-55 rows are the
// EIP's own examples. Every row is checked against idDisplay before it is written.
//   node scripts/id-display-vectors.mjs [outDir]
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { KINDS, idDisplay, UAError } from '../src/ua.js';

const OUT = process.argv[2] ?? fileURLToPath(new URL('../../../smartcontracts/vectors/ua/', import.meta.url));
const kinds = JSON.parse(readFileSync(fileURLToPath(new URL('../../../smartcontracts/vectors/ua/kinds.json', import.meta.url))));
const pad = (addr) => `0x${'0'.repeat(24)}${addr.replace(/^0x/, '').toLowerCase()}`;
const firstId = (kind) => kinds.valid.find((r) => r.kind === kind).ua;
const rows = [];
function row(name, id, kind, expect) {
  let got;
  try { got = { display: idDisplay(id, kind) }; } catch (e) { if (!(e instanceof UAError)) throw e; got = { error: e.code }; }
  if (JSON.stringify(got) !== JSON.stringify(expect)) throw new Error(`${name}: ${JSON.stringify(got)} != ${JSON.stringify(expect)}`);
  rows.push({ name, id, kind, ...got });
}
const native = (address) => ({ display: { kind: 'native', address } });
const derived = (name, h) => ({ display: { kind: 'derived', urn: `urn:scaas:ua:v1:${name}:${h.slice(2).toLowerCase()}` } });
const err = (error) => ({ error });

// --- native space: the EIP-55 examples (all caps, all lower, mixed), the edges of the space, a kind given and ignored
for (const a of ['0x52908400098527886E0F7030069857D2E4169EE7', '0x8617E340B3D01FA5F11F306F4090FD50E238070D',
  '0xde709f2102306220921060314715629080e2fb77', '0x27b1fdb04752bbc536007a920d24acb045561c26',
  '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed', '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
  '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB', '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb']) {
  row(`native eip-55 ${a}`, pad(a), 0, native(a));
}
row('native, upper-case hex in', pad('5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED').toUpperCase().replace('0X', '0x'), 0,
  native('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed'));
row('native, the zero id', pad('0'.repeat(40)), 0, native(`0x${'0'.repeat(40)}`));
row('native, the top of the space', pad('f'.repeat(40)), 0, native('0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF'));
row('native, a derived kind given is ignored (the contract reads the address)', pad('5aaeb6053f3e94c9b9a09f33669435e7ef1beaed'), 0x0100,
  native('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed'));
row('native, a native kind given', pad('5aaeb6053f3e94c9b9a09f33669435e7ef1beaed'), 0x0001, native('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed'));

// --- derived: one row per derived kind, then ids one bit outside the native space
for (const k of KINDS.filter((x) => !x.native)) row(`derived ${k.name}`, firstId(k.kind), k.kind, derived(k.name, firstId(k.kind)));
const low = `0x${'0'.repeat(23)}1${'5aaeb6053f3e94c9b9a09f33669435e7ef1beaed'}`; // bit 160: the lowest bit above the address
const high = `0x8${'0'.repeat(23)}${'5aaeb6053f3e94c9b9a09f33669435e7ef1beaed'}`; // bit 255
row('derived, bit 160 set over an address', low, 0x0102, derived('ed25519', low));
row('derived, bit 255 set over an address', high, 0x0102, derived('ed25519', high));
row('derived, upper-case hex in, lower-case urn out', `0x${firstId(0x0100).slice(2).toUpperCase()}`, 0x0100, derived('webauthn-p256', firstId(0x0100)));

// --- refused: a derived id with no kind, a native kind, the scheme, a gap, out of the table; a malformed id
row('refused: bit 160 set, no kind (never an address)', low, 0, err('UAKindUnknown'));
row('refused: bit 255 set, no kind (never an address)', high, 0, err('UAKindUnknown'));
row('refused: a derived id, no kind', firstId(0x0102), 0, err('UAKindUnknown'));
for (const k of KINDS.filter((x) => x.native)) row(`refused: a derived id under native ${k.name}`, firstId(0x0102), k.kind, err('UAKindNotDerived'));
row('refused: the pqz-mlwe scheme is not an id kind', firstId(0x0102), 0x0142, err('UAKindUnknown'));
row('refused: 0x0109 is no kind', firstId(0x0102), 0x0109, err('UAKindUnknown'));
row('refused: 0xffff is no kind', firstId(0x0102), 0xffff, err('UAKindUnknown'));
const h64 = firstId(0x0102).slice(2);
for (const [name, id] of [['empty', ''], ['0x only', '0x'], ['no 0x', h64], ['0X prefix', `0X${h64}`], ['63 digits', `0x${h64.slice(1)}`],
  ['65 digits', `0x${h64}0`], ['a 20-byte address', '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed'], ['a non-hex digit', `0x${h64.slice(1)}g`],
  ['a non-ASCII digit', `0x${h64.slice(1)}٣`], ['a trailing newline', `0x${h64}\n`], ['a leading space', ` 0x${h64}`],
  ['a native id with a trailing newline', `${pad('5aaeb6053f3e94c9b9a09f33669435e7ef1beaed')}\n`]]) {
  row(`refused: ${name}`, id, 0x0102, err('UAIdFormat'));
}

const doc = {
  note: 'Generated by clients/clientkeys/scripts/id-display-vectors.mjs (src/ua.js idDisplay); never edit by hand. ua-mtx-merge spec §6, '
    + 'MD-9: a bytes32 id with the top 96 bits zero is shown as its EIP-55 address (display.kind native), any other id as its URN '
    + 'urn:scaas:ua:v1:<kind name>:<hex32> (NET-ALL-21, display.kind derived) under the kind of its registry record; kind 0 = none '
    + 'known. clientkeys, ua-rs and its wrappers (ua-c, ua-cxx, ua-qt, ua-dart-frb), ua-py, ua-go, ua-cs and ua-dart reproduce every '
    + 'display byte for byte and refuse every error row with its error.',
  version: 1,
  rows,
};
writeFileSync(join(OUT, 'id_display.json'), `${JSON.stringify(doc, null, 2)}\n`);
console.log(`id_display.json: ${rows.length} rows`);
