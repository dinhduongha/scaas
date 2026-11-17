// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// ua-rs-native T4 (spec 2026-11-17-ua-rs-native §12, CLI-UAL-47): smartcontracts/vectors/native/native.json, written by
// clientkeys first (CLI-UAL-01) and read by clientkeys' tests, ua-rs, ua-c and every binding. The published known answers come
// from the pinned downloads in NATIVE_DOWNLOADS (each read only when its sha256 is the pinned one; the list and the commits:
// clients/ua-rs/runs/2026-11-17-ua-rs-native-t0.md). Deterministic: two runs write the same bytes. UNAUDITED.
//   NATIVE_DOWNLOADS=<dir> node scripts/native-vectors.mjs
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { blake2b } from '@noble/hashes/blake2.js';
import * as sr from '@scure/sr25519';
import { readPinned } from './pinned.mjs';
import * as S from '../src/seed.js';
import * as P from '../src/substrate.js';
import * as U from '../src/uakey.js';
import { hex, fromHex, utf8ToBytes } from '../src/bytes.js';
import { UAError } from '../src/ua.js';

const OUT = new URL('../../../smartcontracts/vectors/native/', import.meta.url).pathname;
const DL = process.env.NATIVE_DOWNLOADS;
if (!DL) throw new Error('NATIVE_DOWNLOADS: the directory of the pinned downloads');
const must = (c, what) => { if (!c) throw new Error(`native-vectors: ${what}`); };
const H = (b) => hex(b).slice(2);
const B = (h) => fromHex('0x' + h.replace(/^0x/, ''));
const codeOf = (f) => { try { f(); return null; } catch (e) { return e.code ?? 'plain'; } };

// ------------------------------------------------------------------ pinned downloads
const BIPS = 'https://raw.githubusercontent.com/bitcoin/bips/c1a652c7c6b6a93ff2a06a295d27cfb767294a63/';
const PINNED = {
  'test-vectors.csv': [BIPS + 'bip-0340/test-vectors.csv', '34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d'],
  'wallet-test-vectors.json': [BIPS + 'bip-0341/wallet-test-vectors.json', '403e19fb81dd1f31e745699216308f61fb403774b2aafa87b631b8f7c042d37f'],
  'bip-0084.mediawiki': [BIPS + 'bip-0084.mediawiki', '1900feec6cafca65b8c09906ca0658d2d742b4c9b44cb15678996985b6bfe627'],
  'bip-0086.mediawiki': [BIPS + 'bip-0086.mediawiki', 'd8d01dee331da07c2562615bc1f064c1868ec3fce61184973da76d1196c7f5b0'],
  'bip-0143.mediawiki': [BIPS + 'bip-0143.mediawiki', '62bc71351563e68baeb12643c68355d217953ae9eb6a6e68b2b0323275b6beec'],
  'bip-0350.mediawiki': [BIPS + 'bip-0350.mediawiki', '63634b06aa8bae88b31929674736e74964c4598684269ac2b0b140c43a7a0dec'],
  'substrate-bip39-lib.rs': ['https://raw.githubusercontent.com/paritytech/substrate-bip39/ceb4fe5a3c7ac91da2e272037797ebecb56aa177/src/lib.rs',
    'df887f9ddc001032abc040d733d3901fe18fdf8f225f60fefa68775dcd396be0'],
};
const text = (f) => readPinned(join(DL, f), PINNED[f][1], f).toString('utf8');
const src = (f) => ({ source: PINNED[f][0], sha256: PINNED[f][1] });

// ------------------------------------------------------------------ mnemonics
const ABANDON = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PQ_KAT = 'bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better';
const NONASCII = 'Ünïcödé パスワード';
const mnemonics = [
  { id: 'bip39_abandon', words: ABANDON, passphrase: '', note: 'the BIP-84 / BIP-86 test vectors\' phrase' },
  { id: 'bip39_abandon_trezor', words: ABANDON, passphrase: 'TREZOR', note: 'the same with the passphrase TREZOR' },
  { id: 'substrate_dev', words: 'bottom drive obey lake curtain smoke basket hold race lonely fit walk', passphrase: '', note: 'Substrate\'s development phrase (the subkey answers)' },
  { id: 'pq_kat', words: PQ_KAT, passphrase: '', note: 'keys.json pq_kat, 24 words' },
  { id: 'non_ascii_nfc', words: PQ_KAT, passphrase: NONASCII.normalize('NFC'), note: 'keys.json\'s non-ASCII passphrase in NFC' },
  { id: 'non_ascii_nfd', words: PQ_KAT, passphrase: NONASCII.normalize('NFD'), note: 'the same passphrase in NFD: one BIP-39 seed, another Polkadot account' },
].map((m) => ({ ...m, entropy: H(S.wordsToEntropy(m.words)) }));
const M = Object.fromEntries(mnemonics.map((m) => [m.id, { ...m, seed: S.seedFromEntropy(B(m.entropy), m.passphrase), e: B(m.entropy) }]));
must(H(M.non_ascii_nfc.seed) === H(M.non_ascii_nfd.seed), 'NFC / NFD: one BIP-39 seed');

// ------------------------------------------------------------------ addresses
const PREFIXES = [0, 2, 42, 64, 16383];
const addresses = [];
const pick = (k, extra) => ({ path: k.path, publicKey: k.publicKey, address: k.address, witnessProgram: k.witnessProgram ?? null, ...extra });
for (const m of mnemonics) {
  const { seed, e } = M[m.id];
  for (const network of ['bitcoin_p2wpkh', 'bitcoin_p2tr']) {
    for (const coinType of [null, 1]) for (const change of [0, 1]) for (const index of [0, 1]) {
      const k = S.deriveKey(seed, network, index, { coinType, change });
      const tap = network === 'bitcoin_p2tr' ? { internalKey: k.internalKey, tweak: k.tweak, outputKey: k.outputKey } : {};
      addresses.push({ mnemonic: m.id, network, coinType, change, index, ...pick(k, tap) });
    }
  }
  for (const index of [0, 1]) {
    const k = S.deriveKey(seed, 'near', index);
    addresses.push({ mnemonic: m.id, network: 'near', coinType: null, change: null, index, ...pick(k, { publicKeyText: k.publicKeyText }) });
  }
  const k = P.polkadotKey(e, m.passphrase, '');
  addresses.push({ mnemonic: m.id, network: 'polkadot', coinType: null, change: null, index: 0, ...pick(k, {
    miniSecret: H(P.miniSecretFromEntropy(e, m.passphrase)), ss58: Object.fromEntries(PREFIXES.map((p) => [String(p), P.ss58(B(k.publicKey), p)])) }) });
}
// generator assertion: Taproot internal and output keys of both y parities
const tapRows = addresses.filter((r) => r.network === 'bitcoin_p2tr');
const internalOdd = new Set(tapRows.map((r) => r.publicKey.startsWith('03')));
const outputOdd = new Set(tapRows.map((r) => S.taprootTweak(B(r.internalKey)).oddY));
must(internalOdd.size === 2 && outputOdd.size === 2, 'Taproot rows hold internal and output keys of both y parities');

// ------------------------------------------------------------------ polkadotPaths
const X = (n) => 'x'.repeat(n);
const PATHS = ['', '//polkadot', '//paseo', '//Alice', '//0', '/0', '//1/2', '/soft//hard', '//18446744073709551615',
  ...[31, 32, 63, 64].flatMap((n) => ['//' + X(n), '/' + X(n)])];
const polkadotPaths = [];
for (const m of mnemonics) {
  for (const path of PATHS) {
    const k = P.polkadotKey(M[m.id].e, m.passphrase, path);
    polkadotPaths.push({ mnemonic: m.id, path, junctions: P.parsePolkadotPath(path).map((j) => ({ hard: j.hard, chainCode: H(j.chainCode) })),
      publicKey: k.publicKey, address: k.address });
  }
}
// generator assertion: a padded 32-byte encoding, a hashed one, the two-byte compact length
const scale = (j) => new TextEncoder().encode(j).length;
must(PATHS.some((p) => p.endsWith('//' + X(31))) && scale(X(31)) + 1 === 32, 'a padded 32-byte encoding (31-byte junction)');
must(PATHS.some((p) => p.endsWith('//' + X(32))) && scale(X(32)) + 1 === 33, 'a hashed encoding (32-byte junction)');
must(PATHS.some((p) => p.endsWith('//' + X(64))) && scale(X(64)) >= 64, 'the two-byte compact length (64-byte junction)');

// ------------------------------------------------------------------ signatures
const repeat = (byte, length) => ({ byte: byte.toString(16).padStart(2, '0'), length });
const msgOf = (r) => (r.messageRepeat ? new Uint8Array(r.messageRepeat.length).fill(parseInt(r.messageRepeat.byte, 16)) : B(r.message));
const msgField = (len) => (len > 1232 ? { messageRepeat: repeat(0xa5, len) } : { message: H(Uint8Array.from({ length: len }, (_, i) => (i * 7 + 3) & 255)) });
const sighash = (n) => H(sha256(utf8ToBytes(`scaas ua-rs-native sighash ${n}`)));
const signatures = [];
// the generator's soft steps take fixed randomness (the file is reproducible); a soft key's signatures stay verify-only elsewhere
const SOFT_R = sha256(utf8ToBytes('scaas ua-rs-native soft step'));
const keyOf = (r) => (r.network === 'polkadot' ? P.polkadotKey(M[r.mnemonic].e, M[r.mnemonic].passphrase, r.path ?? '', { softRandom: SOFT_R })
  : S.deriveKey(M[r.mnemonic].seed, r.network, r.index, { coinType: r.coinType, change: r.change }));
// ECDSA P2WPKH over sighashes: deterministic (RFC 6979, no extra data)
for (const [n, at] of [[0, { coinType: null, change: 0, index: 0 }], [1, { coinType: null, change: 1, index: 0 }], [2, { coinType: 1, change: 0, index: 1 }]]) {
  signatures.push({ id: `p2wpkh-${n}`, mode: 'deterministic', scheme: 'secp256k1-ecdsa', call: 'sign_digest', mnemonic: 'bip39_abandon', network: 'bitcoin_p2wpkh', ...at, message: sighash(n) });
}
// ed25519 sign_message per ed25519 network (deterministic), and a NEAR digest
for (const network of ['hedera_ed25519', 'sui', 'stellar', 'ton', 'aptos', 'solana', 'near']) {
  for (const len of [1, 32, 1232, 131072]) {
    signatures.push({ id: `ed25519-${network}-${len}`, mode: 'deterministic', scheme: 'ed25519', call: 'sign_message', mnemonic: 'pq_kat', network, coinType: null, change: null, index: 0, ...msgField(len) });
  }
}
signatures.push({ id: 'ed25519-near-digest', mode: 'deterministic', scheme: 'ed25519', call: 'sign_digest', mnemonic: 'pq_kat', network: 'near', coinType: null, change: null, index: 1, message: sighash('near') });
// BIP-340 Taproot with fixed aux (test-only): both parities of P (receive 0 odd, receive 1 even), the change chain
const AUX1 = H(Uint8Array.from({ length: 32 }, (_, i) => i + 1));
for (const [n, at] of [[0, { change: 0, index: 0 }], [1, { change: 0, index: 1 }], [2, { change: 1, index: 0 }]]) {
  for (const aux of ['00'.repeat(32), AUX1]) {
    signatures.push({ id: `p2tr-${n}-${aux === AUX1 ? 'aux1' : 'aux0'}`, mode: 'fixed-randomness', scheme: 'bip340-taproot', call: 'sign_digest', mnemonic: 'bip39_abandon',
      network: 'bitcoin_p2tr', coinType: null, ...at, message: sighash(`tap${n}`), aux });
  }
}
// sr25519 on the bare and //Alice keys with a fixed r (test-only; T0: schnorrkel and @scure/sr25519 byte-equal)
const R1 = H(Uint8Array.from({ length: 32 }, (_, i) => 0x40 + i));
for (const path of ['', '//Alice']) {
  for (const len of [1, 32, 257]) {
    signatures.push({ id: `sr25519-${path || 'bare'}-${len}`, mode: 'fixed-randomness', scheme: 'sr25519', call: 'sign_message', mnemonic: 'substrate_dev', network: 'polkadot', path, ...msgField(len), aux: R1 });
  }
  signatures.push({ id: `sr25519-${path || 'bare'}-digest`, mode: 'fixed-randomness', scheme: 'sr25519', call: 'sign_digest', mnemonic: 'substrate_dev', network: 'polkadot', path, message: sighash('dot'), aux: R1 });
}
// sr25519 on soft-derived keys: verify-only (a soft step draws a fresh nonce half)
for (const path of ['/soft', '//Alice/0']) {
  signatures.push({ id: `sr25519-soft-${path}`, mode: 'verify-only', scheme: 'sr25519', call: 'sign_message', mnemonic: 'substrate_dev', network: 'polkadot', path, ...msgField(32),
    aux: H(sha256(utf8ToBytes(`scaas ua-rs-native soft ${path}`))) });
}
for (const r of signatures) {
  const k = keyOf(r);
  const m = msgOf(r);
  const opts = { allowRawDigest: true, ...(r.aux ? { aux: B(r.aux) } : {}) };
  const sig = r.call === 'sign_digest' ? S.signDigest(k, m, opts) : S.signMessage(k, m, opts);
  r.publicKey = r.network === 'bitcoin_p2tr' ? k.outputKey : k.publicKey;
  r.signature = H(sig);
  if (r.mode === 'verify-only') delete r.aux;
  const ok = r.scheme === 'secp256k1-ecdsa' ? secp256k1.verify(sig.subarray(0, 64), m, B(k.publicKey), { prehash: false, format: 'compact' })
    : r.scheme === 'bip340-taproot' ? schnorr.verify(sig, m, B(k.outputKey))
      : r.scheme === 'ed25519' ? ed25519.verify(sig, m, B(k.publicKey)) : sr.verify(m, sig, B(k.publicKey));
  must(ok, `signature ${r.id} verifies`);
  if (r.mode !== 'verify-only') {
    const again = r.call === 'sign_digest' ? S.signDigest(keyOf(r), m, opts) : S.signMessage(keyOf(r), m, opts);
    must(H(again) === r.signature, `signature ${r.id} reproduces`);
  }
}
// generator assertions: a byte-equal row per scheme; one mode per row
const MODES = new Set(['deterministic', 'fixed-randomness', 'verify-only']);
for (const s of ['secp256k1-ecdsa', 'bip340-taproot', 'ed25519', 'sr25519']) {
  must(signatures.some((r) => r.scheme === s && r.mode !== 'verify-only'), `a byte-equal signature row of ${s}`);
}
must(signatures.every((r) => MODES.has(r.mode)), 'every row has one mode');

// ------------------------------------------------------------------ refusals (Argument), each with its accepted neighbour
const TD = { types: { EIP712Domain: [{ name: 'name', type: 'string' }], M: [{ name: 'x', type: 'uint256' }] }, primaryType: 'M', domain: { name: 'scaas-native' }, message: { x: '1' } };
const refusals = [];
const ref = (id, call, args, accepted) => refusals.push({ id, call, args, error: 'Argument', accepted });
const at = (network, extra = {}) => ({ mnemonic: 'pq_kat', network, index: 0, coinType: null, change: null, ...extra });
const longPath = (n, len) => Array(n).fill('//' + X(len)).join('');
for (const [bad, good, why] of [['///pw', '//pw', 'a password part'], ['//', '//a', 'an empty junction'], ['/0x12', '/x12', 'a 0x prefix'],
  ['//+1', '//1', 'a + prefix'], ['//18446744073709551616', '//18446744073709551615', 'a number past u64'], ['//007', '//7', 'a leading zero'],
  ['//00', '//0', 'a leading zero'], [Array(17).fill('//a').join(''), Array(16).fill('//a').join(''), '17 junctions'],
  [longPath(15, 30) + '//' + X(31), longPath(16, 30), '513 bytes'], ['//' + X(65), '//' + X(64), 'a 65-byte junction'],
  ['//a b', '//ab', 'a byte 0x20'], ['Alice', '//Alice', 'no leading /']]) {
  ref(`polkadot_key ${why}`, 'polkadot_key', { mnemonic: 'pq_kat', path: bad }, { mnemonic: 'pq_kat', path: good });
}
for (const [bad, good] of [[46, 42], [47, 42], [16384, 16383]]) ref(`ss58 prefix ${bad}`, 'ss58', { mnemonic: 'pq_kat', prefix: bad }, { mnemonic: 'pq_kat', prefix: good });
const SOLANA_ENV = H(Uint8Array.of(0xff, ...utf8ToBytes('solana offchain'), 1, 1));
const APTOS_ENV = H(utf8ToBytes('APTOS\nmessage: scaas'));
ref('sign_message 0 bytes', 'sign_message', at('solana', { message: '' }), at('solana', { message: '01' }));
ref('sign_message 131,073 bytes', 'sign_message', at('solana', { messageRepeat: repeat(0xa5, 131073) }), at('solana', { messageRepeat: repeat(0xa5, 131072) }));
for (const [name, env] of [['solana offchain envelope', SOLANA_ENV], ['APTOS\\n envelope', APTOS_ENV]]) {
  for (const network of ['solana', 'polkadot']) {
    const p = network === 'polkadot' ? { path: '' } : {};
    ref(`sign_message ${name} on ${network}`, 'sign_message', at(network, { ...p, message: env }), at(network, { ...p, message: env.slice(2) }));
  }
}
for (const network of ['evm', 'bitcoin_p2wpkh', 'bitcoin_p2tr']) ref(`sign_message on ${network}`, 'sign_message', at(network, { message: '01' }), at('solana', { message: '01' }));
for (const network of ['bitcoin_p2wpkh', 'bitcoin_p2tr', 'near', 'polkadot']) {
  const p = network === 'polkadot' ? { path: '' } : {};
  ref(`sign_key_proof on ${network}`, 'sign_key_proof', at(network, { ...p, challenge: '00'.repeat(32) }), at('evm', { challenge: '00'.repeat(32) }));
}
for (const network of ['bitcoin_p2wpkh', 'bitcoin_p2tr', 'near']) ref(`sign_typed on ${network}`, 'sign_typed', at(network, { typedData: TD }), at('evm', { typedData: TD }));
for (const network of ['bitcoin_p2wpkh', 'bitcoin_p2tr']) {
  ref(`native_key ${network} coin type 2`, 'native_key', at(network, { coinType: 2 }), at(network, { coinType: 1 }));
  ref(`bitcoin_key ${network} change 2`, 'bitcoin_key', at(network, { change: 2 }), at(network, { change: 1 }));
}
for (const c of [148, 397]) ref(`native_key near coin type ${c}`, 'native_key', at('near', { coinType: c }), at('near'));
ref('native_key polkadot coin type 354', 'native_key', at('polkadot', { coinType: 354 }), at('polkadot'));
ref('native_key polkadot index 1', 'native_key', at('polkadot', { index: 1 }), at('polkadot'));
ref('bitcoin_key on near', 'bitcoin_key', at('near', { change: 0 }), at('bitcoin_p2wpkh', { change: 0 }));
const SECRET = '01'.repeat(32);
for (const [network, kind] of [['bitcoin_p2wpkh', 0x0108], ['bitcoin_p2tr', 0x0108], ['near', 0x0102], ['polkadot', 0x0102]]) {
  ref(`import_native_key ${network}`, 'import_native_key', { network, secret: SECRET }, { network: 'evm', secret: SECRET });
  ref(`imported_ua_key ${network}`, 'imported_ua_key', { network, secret: SECRET, kind }, { network: 'evm', secret: SECRET, kind: 0x0108 });
}
// spec §8.1 (after the scaas-sdk review), appended: the EIP-7702 / EIP-712 prefixes on raw messages, the envelope calls' refusals
const STELLAR_TESTNET_ID = H(sha256(utf8ToBytes('Test SDF Network ; September 2015')));
for (const network of ['solana', 'polkadot']) {
  const p = network === 'polkadot' ? { path: '' } : {};
  const on = network === 'solana' ? '' : ` on ${network}`;
  ref(`sign_message EIP-7702 magic 0x05${on}`, 'sign_message', at(network, { ...p, message: '0501' }), at(network, { ...p, message: '0601' }));
  ref(`sign_message EIP-712 prefix 0x19 0x01${on}`, 'sign_message', at(network, { ...p, message: '1901aa' }), at(network, { ...p, message: '1902aa' }));
}
const ENVELOPE_CALLS = [['sign_near_transaction', 'near'], ['sign_sui_transaction', 'sui'], ['sign_stellar_transaction', 'stellar'], ['sign_hedera_transaction', 'hedera_ed25519']];
for (const [call, network] of ENVELOPE_CALLS) {
  const id = call === 'sign_stellar_transaction' ? { networkId: STELLAR_TESTNET_ID } : {};
  ref(`${call} on solana`, call, at('solana', { ...id, message: '01' }), at(network, { ...id, message: '01' }));
  ref(`${call} 0 bytes`, call, at(network, { ...id, message: '' }), at(network, { ...id, message: '01' }));
  ref(`${call} 131,073 bytes`, call, at(network, { ...id, messageRepeat: repeat(0xa5, 131073) }), at(network, { ...id, messageRepeat: repeat(0xa5, 131072) }));
}
ref('sign_stellar_transaction a 31-byte network id', 'sign_stellar_transaction', at('stellar', { networkId: '00'.repeat(31), message: '01' }),
  at('stellar', { networkId: '00'.repeat(32), message: '01' }));
// every refusal refused here and its neighbour accepted
// clientkeys' reading of a row's call (ua-rs: Wallet::native_key, bitcoin_key, polkadot_key, …; Polkadot's native_key is the bare key)
function applyCall(call, a) {
  const m = a.mnemonic && M[a.mnemonic];
  const nativeKey = () => {
    if (a.network !== 'polkadot') return S.deriveKey(m.seed, a.network, a.index, { coinType: a.coinType });
    if (a.index !== 0 || a.coinType != null) throw new UAError('Argument', 'polkadot: index 0 and no coin type');
    return P.polkadotKey(m.e, m.passphrase, '');
  };
  const key = () => (a.network === 'polkadot' && a.path !== undefined ? P.polkadotKey(m.e, m.passphrase, a.path) : nativeKey());
  switch (call) {
    case 'polkadot_key': return P.polkadotKey(m.e, m.passphrase, a.path);
    case 'ss58': return P.ss58(B(P.polkadotKey(m.e, m.passphrase, '').publicKey), a.prefix);
    case 'native_key': return nativeKey();
    case 'bitcoin_key': return S.deriveKey(m.seed, a.network, a.index, { coinType: a.coinType, change: a.change });
    case 'sign_message': return S.signMessage(key(), msgOf(a), { allowRawDigest: true });
    case 'sign_key_proof': return S.signKeyProof(key(), B(a.challenge));
    case 'sign_typed': return S.signTyped(key(), a.typedData);
    case 'import_native_key': return S.importKey(a.network, B(a.secret));
    case 'imported_ua_key': return U.importedUAKey({ network: a.network, secret: B(a.secret), kind: a.kind });
    case 'sign_near_transaction': return S.signNearTransaction(key(), msgOf(a), { allowRawDigest: true });
    case 'sign_sui_transaction': return S.signSuiTransaction(key(), msgOf(a), { allowRawDigest: true });
    case 'sign_stellar_transaction': return S.signStellarTransaction(key(), B(a.networkId), msgOf(a), { allowRawDigest: true });
    case 'sign_hedera_transaction': return S.signHederaTransaction(key(), msgOf(a), { allowRawDigest: true });
    default: throw new Error(`unknown call ${call}`);
  }
}
for (const r of refusals) {
  must(codeOf(() => applyCall(r.call, r.args)) === 'Argument', `refusal ${r.id}`);
  must(codeOf(() => applyCall(r.call, r.accepted)) === null, `accepted neighbour of ${r.id}`);
}

// ------------------------------------------------------------------ external known answers (pinned downloads)
const external = {};
{ // BIP-84 / BIP-86: the abandon phrase's account-0 rows, re-derived
  const t84 = text('bip-0084.mediawiki');
  const rows84 = [...t84.matchAll(/\/\/ Account 0, (first|second) (receiving|change) address = (m\/84'\/0'\/0'\/(\d)\/(\d))\n\s+privkey = \S+\n\s+pubkey\s+= ([0-9a-f]+)\n\s+address = (\S+)/g)]
    .map((x) => ({ path: x[3], change: Number(x[4]), index: Number(x[5]), publicKey: x[6], address: x[7] }));
  must(rows84.length === 3, 'BIP-84 rows');
  for (const r of rows84) must(S.deriveKey(M.bip39_abandon.seed, 'bitcoin_p2wpkh', r.index, { change: r.change }).address === r.address, `BIP-84 ${r.path}`);
  external.bip84 = { ...src('bip-0084.mediawiki'), mnemonic: 'bip39_abandon', mode: 'byte-equal', rows: rows84 };
  const t86 = text('bip-0086.mediawiki');
  const rows86 = [...t86.matchAll(/\/\/ Account 0, (first|second) (receiving|change) address = (m\/86'\/0'\/0'\/(\d)\/(\d))\n(?:.*\n){2}internal_key = ([0-9a-f]+)\noutput_key\s+= ([0-9a-f]+)\nscriptPubKey = [0-9a-f]+\naddress\s+= (\S+)/g)]
    .map((x) => ({ path: x[3], change: Number(x[4]), index: Number(x[5]), internalKey: x[6], outputKey: x[7], address: x[8] }));
  must(rows86.length === 3, 'BIP-86 rows');
  for (const r of rows86) {
    const k = S.deriveKey(M.bip39_abandon.seed, 'bitcoin_p2tr', r.index, { change: r.change });
    must(k.address === r.address && k.internalKey === r.internalKey && k.outputKey === r.outputKey, `BIP-86 ${r.path}`);
  }
  external.bip86 = { ...src('bip-0086.mediawiki'), mnemonic: 'bip39_abandon', mode: 'byte-equal', rows: rows86 };
}
{ // BIP-143 native P2WPKH: RFC 6979 with no extra data reproduces the published signature (T0)
  const t = text('bip-0143.mediawiki');
  const sec = t.slice(t.indexOf('=== Native P2WPKH ==='), t.indexOf('=== P2SH-P2WPKH ==='));
  const privateKey = sec.match(/second input comes from a P2WPKH witness program:\n.*\n\s+private key\s+: ([0-9a-f]{64})/)[1];
  const sigHashV = sec.match(/sigHash:\s+([0-9a-f]{64})/)[1];
  const der = sec.match(/signature:\s+(30[0-9a-f]+)01\n/)[1];
  const sig = S.signDigest({ network: 'bitcoin_p2wpkh', curve: 'secp256k1', privateKey: B(privateKey) }, B(sigHashV), { allowRawDigest: true });
  must(H(secp256k1.Signature.fromBytes(sig.subarray(0, 64), 'compact').toBytes('der')) === der, 'BIP-143 native P2WPKH byte-equal');
  external.bip143 = { ...src('bip-0143.mediawiki'), mode: 'byte-equal', network: 'bitcoin_p2wpkh', privateKey, sigHash: sigHashV, signatureDer: der,
    signature: H(sig.subarray(0, 64)) };
}
{ // BIP-340 test-vectors.csv: the BIP-340 primitive (not the tweak)
  const rows = text('test-vectors.csv').trim().split('\n').slice(1).map((l) => l.split(','))
    .map(([index, secretKey, publicKey, aux, message, signature, result, ...c]) => ({ index: Number(index), secretKey: secretKey || null, publicKey,
      aux: aux || null, message, signature, result: result === 'TRUE', comment: c.join(',') }));
  for (const r of rows) {
    if (r.secretKey) must(H(schnorr.sign(B(r.message), B(r.secretKey), B(r.aux))).toUpperCase() === r.signature, `BIP-340 sign ${r.index}`);
    let v; try { v = schnorr.verify(B(r.signature), B(r.message), B(r.publicKey)); } catch { v = false; }
    must(v === r.result, `BIP-340 verify ${r.index}`);
  }
  external.bip340 = { ...src('test-vectors.csv'), mode: 'byte-equal', rows };
}
{ // BIP-341 wallet-test-vectors.json: scriptPubKey rows with a null scriptTree, keyPathSpending inputs with a null merkleRoot
  const w = JSON.parse(text('wallet-test-vectors.json'));
  const spk = w.scriptPubKey.filter((r) => r.given.scriptTree === null).map((r) => ({ internalPubkey: r.given.internalPubkey, tweak: r.intermediary.tweak,
    tweakedPubkey: r.intermediary.tweakedPubkey, scriptPubKey: r.expected.scriptPubKey, address: r.expected.bip350Address }));
  for (const r of spk) {
    const t = S.taprootTweak(B(r.internalPubkey));
    must(H(t.tweak) === r.tweak && H(t.outputKey) === r.tweakedPubkey && S.segwitAddress('bc', 1, t.outputKey) === r.address, 'BIP-341 scriptPubKey');
  }
  const kps = w.keyPathSpending[0].inputSpending.filter((i) => i.given.merkleRoot === null).map((i) => ({ txinIndex: i.given.txinIndex,
    hashType: i.given.hashType, internalPrivkey: i.given.internalPrivkey, internalPubkey: i.intermediary.internalPubkey, tweak: i.intermediary.tweak,
    tweakedPrivkey: i.intermediary.tweakedPrivkey, sigHash: i.intermediary.sigHash, aux: '00'.repeat(32), witness0: i.expected.witness[0],
    signature: i.expected.witness[0].slice(0, 128) }));
  for (const r of kps) {
    const sig = S.signDigest({ network: 'bitcoin_p2tr', curve: 'secp256k1', privateKey: B(r.internalPrivkey) }, B(r.sigHash), { allowRawDigest: true, aux: B(r.aux) });
    must(H(sig) === r.signature, `BIP-341 keyPathSpending input ${r.txinIndex}`);
  }
  external.bip341 = { ...src('wallet-test-vectors.json'), mode: 'byte-equal', note: 'keyPathSpending signatures use aux = 32 zero bytes (T0)', scriptPubKey: spk, keyPathSpending: kps };
}
{ // BIP-350 valid segwit addresses (the encoder: bech32 for v0, bech32m for v1 to v16)
  const t = text('bip-0350.mediawiki');
  const valid = t.slice(t.indexOf('The following list gives valid segwit addresses'), t.indexOf('The following list gives invalid segwit addresses'));
  const rows = [...valid.matchAll(/<tt>([A-Za-z0-9]+)<\/tt>: <tt>([0-9a-f]+)<\/tt>/g)].map((x) => {
    const spk = B(x[2]); const v = spk[0] === 0 ? 0 : spk[0] - 0x50;
    return { address: x[1].toLowerCase(), hrp: x[1].toLowerCase().split('1')[0], version: v, program: H(spk.subarray(2)) };
  });
  for (const r of rows) must(S.segwitAddress(r.hrp, r.version, B(r.program)) === r.address, `BIP-350 ${r.address}`);
  external.bip350 = { ...src('bip-0350.mediawiki'), mode: 'byte-equal', rows };
}
{ // substrate-bip39 VECTORS (password "Substrate")
  const t = text('substrate-bip39-lib.rs');
  const blk = t.slice(t.indexOf('static VECTORS'), t.indexOf('];', t.indexOf('static VECTORS')));
  const rows = [...blk.matchAll(/\[\s*"([^"]+)",\s*"([0-9a-f]+)",\s*"([0-9a-f]+)",?\s*\]/g)].map((x) => ({ words: x[1], entropy: x[2], seed: x[3], miniSecret: x[3].slice(0, 64) }));
  must(rows.length === 24, 'substrate-bip39 rows');
  for (const r of rows) must(H(S.wordsToEntropy(r.words)) === r.entropy && H(P.miniSecretFromEntropy(B(r.entropy), 'Substrate')) === r.miniSecret, `substrate-bip39 ${r.entropy}`);
  external.substrateBip39 = { ...src('substrate-bip39-lib.rs'), mode: 'byte-equal', passphrase: 'Substrate', rows };
}
external.subkey = { source: 'spec 2026-11-17-ua-rs-native §7.3 (subkey inspect of the development phrase, empty passphrase); re-derived at plan T0 by schnorrkel, @scure/sr25519 and polkadot.js',
  mode: 'byte-equal', mnemonic: 'substrate_dev', rows: [
    { path: '', publicKey: '46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a', ss58: '5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV' },
    { path: '//Alice', publicKey: 'd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d', ss58: '5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY' },
    { path: '//Bob', publicKey: '8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48', ss58: '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty' }] };
for (const r of external.subkey.rows) {
  const k = P.polkadotKey(M.substrate_dev.e, '', r.path);
  must(k.publicKey === r.publicKey && P.ss58(B(k.publicKey), 42) === r.ss58, `subkey ${r.path}`);
}
external.polkadotJsSignature = { source: 'plan T0: @polkadot/keyring 14.0.3, new Keyring({ type: "sr25519" }).addFromUri(<substrate_dev> + "//Alice").sign(stringToU8a(<messageUtf8>))',
  mode: 'verify-only', mnemonic: 'substrate_dev', path: '//Alice', messageUtf8: 'scaas ua-rs-native T0: polkadot.js //Alice signature',
  message: '73636161732075612d72732d6e61746976652054303a20706f6c6b61646f742e6a73202f2f416c696365207369676e6174757265',
  publicKey: 'd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d',
  signature: '24a27936a2b09621ea541fa427b3ea60c52199cf7e3f8966c4ffbc6620833b69f57592f47c8bd86b4076f74aef554817a434c65c16a34d5eba30030728a31f8c' };
must(H(utf8ToBytes(external.polkadotJsSignature.messageUtf8)) === external.polkadotJsSignature.message, 'polkadot.js message');
must(sr.verify(B(external.polkadotJsSignature.message), B(external.polkadotJsSignature.signature), B(external.polkadotJsSignature.publicKey)), 'polkadot.js signature verifies');

// ------------------------------------------------------------------ envelopes (spec §8.1): the chain's prefix / hash wrapper
const envelopes = [];
for (const [call, network] of ENVELOPE_CALLS) {
  for (const len of [1, 200, 1232]) {
    const r = { id: `${call}-${len}`, mode: 'deterministic', call, mnemonic: 'pq_kat', network, coinType: null, change: null, index: 0,
      ...(call === 'sign_stellar_transaction' ? { networkId: STELLAR_TESTNET_ID } : {}), ...msgField(len) };
    const tx = msgOf(r);
    const signed = call === 'sign_near_transaction' ? sha256(tx) : call === 'sign_sui_transaction' ? blake2b(Uint8Array.from([0, 0, 0, ...tx]), { dkLen: 32 })
      : call === 'sign_stellar_transaction' ? sha256(Uint8Array.from([...B(STELLAR_TESTNET_ID), 0, 0, 0, 2, ...tx])) : tx;
    const k = S.deriveKey(M.pq_kat.seed, network, 0);
    const sig = applyCall(call, r);
    must(ed25519.verify(sig, signed, B(k.publicKey)) && H(ed25519.sign(signed, k.privateKey)) === H(sig), `envelope ${r.id}`);
    envelopes.push({ ...r, signed: H(signed), publicKey: k.publicKey, signature: H(sig) });
  }
}

// ------------------------------------------------------------------ write
const out = {
  note: 'Generated by clients/clientkeys/scripts/native-vectors.mjs (ua-rs-native T4, spec 2026-11-17-ua-rs-native §12) from src/seed.js and '
    + 'src/substrate.js; never edit by hand. networks: ua-rs\'s order (NETWORKS then NATIVE_NETWORKS). Bitcoin: m/84\'|86\'/<coin>\'/0\'/<change>/<index>, '
    + 'coinType null = 0 (bc), 1 (tb); witnessProgram {version, program}; P2TR publicKey is the compressed internal key P. NEAR m/44\'/397\'/<index>\', '
    + 'address = hex(publicKey). Polkadot: substrate-bip39 from the entropy and the passphrase as given (not NFKD), schnorrkel Ed25519 expansion, '
    + 'address = SS58 prefix 0, ss58 at other prefixes; polkadotPaths: chain codes and keys of junction paths. signatures: secp256k1-ecdsa r ‖ s ‖ v, '
    + 'RFC 6979 with extraEntropy false on every ECDSA row; bip340-taproot 64 bytes under publicKey = x(Q); ed25519 RFC 8032; sr25519 context '
    + '"substrate", publicKey = the sr25519 key. mode: deterministic (the release call reproduces the bytes), fixed-randomness (test-only: aux is '
    + 'the Taproot aux or the sr25519 r of a test entry point; a release build draws them from the OS RNG and never takes them from a caller, '
    + 'CLI-UAL-02), verify-only (soft keys draw a fresh nonce half: the signature verifies, its bytes are not reproduced). message: hex, or '
    + 'messageRepeat {byte, length}. refusals: each call refused with error Argument, its accepted neighbour beside it.',
  networks: [...Object.keys(S.NETWORKS), ...Object.keys(S.NATIVE_NETWORKS)],
  mnemonics,
  addresses,
  polkadotPaths,
  signatures,
  refusals,
  external,
  envelopes,
};
// append-only (spec §8.1, CLI-UAL-63 (15)): every value of the committed file is kept; a list may only grow at its end, a new
// section only after the old ones
const committed = join(OUT, 'native.json');
if (existsSync(committed)) {
  const old = JSON.parse(readFileSync(committed, 'utf8'));
  const keys = Object.keys(old);
  must(JSON.stringify(Object.keys(out).slice(0, keys.length)) === JSON.stringify(keys), 'native.json sections: the old ones first, in order');
  for (const k of keys) {
    const same = Array.isArray(old[k]) ? JSON.stringify(out[k].slice(0, old[k].length)) === JSON.stringify(old[k]) : JSON.stringify(out[k]) === JSON.stringify(old[k]);
    must(same, `native.json ${k}: a committed row changed (append only)`);
  }
}
mkdirSync(OUT, { recursive: true });
writeFileSync(join(OUT, 'native.json'), JSON.stringify(out, null, 1) + '\n');
console.log(`native.json: ${addresses.length} addresses, ${polkadotPaths.length} polkadotPaths, ${signatures.length} signatures `
  + `(${signatures.filter((r) => r.mode === 'verify-only').length} verify-only), ${refusals.length} refusals, external ${Object.keys(external).join(', ')}, `
  + `${envelopes.length} envelopes`);
