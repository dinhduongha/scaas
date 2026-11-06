// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Generates smartcontracts/vectors/ua/keys.json and sign.json (ua-rs-sign T1a), kem.json, seal.json and vault.json (T1b), zether.json (T14) (spec §11, plan MD-7): the UA keys of src/uakey.js
// and the native keys of src/seed.js per mnemonic, kind, account and index, with the refusals; the UA signatures, member
// signatures, BLS roles, the scaas Schnorr nonce-map rows, typed-data rows (generic hasher, canonical builders), the signing
// policy (src/evm.js check*), EVM transactions of types 0-3 and the EIP-155 example, WebAuthn assertions, msig member sets and the
// chain-separation rows (7622 / 22776, owner 2026-11-05).
// Randomness: a fixed SHAKE256 stream per label, so the files do not move between runs; a row with `compare: "verify"` is a
// randomized signature (its randomness is not given), checked by verification only. test/ua-wallet.test.js reads every row
// back; clients/ua-rs is held to them (T2-T6).
//   node scripts/ua-wallet-vectors.mjs [outDir]
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bn254 } from '@noble/curves/bn254.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { shake256 } from '@noble/hashes/sha3.js';
import { hex, fromHex, keccak_256, utf8ToBytes, concatBytes, b64url, fromB64url, abiEncode } from '../src/bytes.js';
import * as ua from '../src/ua.js';
import * as evm from '../src/evm.js';
import { verify, clientDataOk } from '../src/ua-verify.js';
import { NETWORKS, wordsToEntropy, seedFromEntropy, seedFromWords, deriveKey, signTyped, signTransaction } from '../src/seed.js';
import { eip2333, deriveConfKey, sealBalanceCache, openBalanceCache } from '../src/zether.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { PQ_KINDS, pqMessage } from '../src/pq.js';
import {
  deriveUAKey, uaKeyPath, signUAVector, sigRole, webauthnChallenge, webauthnAssertion, msigMemberSigs,
} from '../src/uakey.js';
import { PQ_MNEMONIC } from './ua-signers.mjs';
import { readPinned } from './pinned.mjs';
import { kemKeyOf, kemEncapsVector, ephemeralVector } from '../src/kem.js';
import {
  PURPOSE as SEAL_PURPOSE, MAX_PT, LINK_WINDOW, sealVector, open as openSealed, wireForm, fromWire, sealContainer, sealBackup, openContainer, openLink,
  linkSessionVector, restoreBackup, encodeBackup, containerAad,
} from '../src/seal.js';
import { createVault, rewrapPin, openSeedVault, seal as boxSeal } from '../src/vault.js';

const VECTORS = fileURLToPath(new URL('../../../smartcontracts/vectors/', import.meta.url));
const OUT = process.argv[2] ?? join(VECTORS, 'ua');
const stream = (label, n) => shake256(utf8ToBytes(`scaas.ua-rs-sign.t1a.${label}`), { dkLen: n });
const int = (b) => BigInt(hex(b));
const be = (v, n) => fromHex(v.toString(16).padStart(2 * n, '0'));
const must = (ok, what) => { if (!ok) throw new Error(`generator self-check: ${what}`); };
const refusedBy = (f) => { try { f(); return null; } catch (e) { return e; } };
const TWO31 = 2 ** 31;

// ---------------------------------------------------------------------------------------------------- keys.json

const NFC_PASS = 'Ünïcödé パスワード'; // NFKD changes both the Latin and the katakana
const MNEMONICS = [
  { id: 'pq_kat', words: PQ_MNEMONIC, passphrase: '', note: 'pq_kat.json\'s mnemonic (SEP-0005 test 3), 24 words' },
  { id: 'bip39_test', words: `${'abandon '.repeat(23)}art`, passphrase: 'TREZOR', note: 'BIP-39 Trezor vector, 24 words, entropy 0^32' },
  { id: 'twelve_words', words: 'legal winner thank year wave sausage worth useful legal winner thank yellow', passphrase: '',
    note: '12 words, 16-byte entropy (BIP-39 Trezor vector words, no passphrase)' },
  { id: 'non_ascii_passphrase', words: PQ_MNEMONIC, passphrase: NFC_PASS,
    note: 'a non-ASCII BIP-39 passphrase given in NFC: the seed is over its NFKD form' },
].map((m) => {
  const entropy = wordsToEntropy(m.words);
  return { ...m, entropy: hex(entropy), seed: hex(seedFromEntropy(entropy, m.passphrase)) };
});
const SEEDS = Object.fromEntries(MNEMONICS.map((m) => [m.id, fromHex(m.seed)]));
const fullWidth = (s) => [...s].map((c) => (c === ' ' ? '　' : String.fromCharCode(c.charCodeAt(0) - 0x61 + 0xff41))).join('');
const NORMALIZATION = [
  { id: 'words-fullwidth', words: fullWidth(PQ_MNEMONIC), passphrase: '', sameAs: 'pq_kat',
    note: 'full-width letters and ideographic spaces: NFKD gives the ASCII words' },
  { id: 'passphrase-nfd', words: PQ_MNEMONIC, passphrase: NFC_PASS.normalize('NFD'), sameAs: 'non_ascii_passphrase',
    note: 'the same passphrase in NFD' },
].map((n) => ({ ...n, seed: hex(seedFromWords(n.words, n.passphrase)) }));
for (const n of NORMALIZATION) must(n.seed === MNEMONICS.find((m) => m.id === n.sameAs).seed, n.id);

const EIP_KINDS = [0x0104, 0x0105, 0x0106, 0x0107, 0x0112];
const UA_KINDS = [0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108, 0x0110, 0x0112,
  ...Object.values(PQ_KINDS).map((s) => s.kind).sort((a, b) => a - b)];
const ref = (mnemonic, kind, account = 0, index = 0) => ({ mnemonic, kind, account, index });
const keyOf = ({ mnemonic, kind, account, index }) => deriveUAKey(SEEDS[mnemonic], { kind, account, index });

const uaRows = [];
for (const m of MNEMONICS) {
  for (const kind of UA_KINDS) {
    for (const account of [0, 1]) {
      for (const index of EIP_KINDS.includes(kind) ? [0] : [0, 1]) {
        const k = keyOf(ref(m.id, kind, account, index));
        uaRows.push({ mnemonic: m.id, kind, name: k.name, account, index, derivation: k.derivation, path: k.path,
          keyData: hex(k.keyData), ua: k.ua === null ? null : hex(k.ua) });
      }
    }
  }
}

const nativeRows = [];
for (const m of MNEMONICS) {
  for (const network of Object.keys(NETWORKS)) {
    for (const index of [0, 1]) {
      const k = deriveKey(SEEDS[m.id], network, index);
      nativeRows.push({ mnemonic: m.id, network, index, coinType: null, path: k.path, publicKey: k.publicKey, address: k.address ?? null });
    }
  }
}
for (const index of [0, 1]) {
  const k = deriveKey(SEEDS.pq_kat, 'stellar', index, { coinType: 314159 });
  nativeRows.push({ mnemonic: 'pq_kat', network: 'stellar', index, coinType: 314159, path: k.path, publicKey: k.publicKey, address: k.address });
}

const keyRefusals = [
  ...[[0x0101, TWO31, 0, 'account ≥ 2^31'], [0x0108, 0, TWO31, 'index ≥ 2^31'], [0x0131, TWO31, 0, 'account ≥ 2^31 (an HKDF kind)'],
    [0x0133, 0, TWO31, 'index ≥ 2^31 (an HKDF kind)'], [0x0104, TWO31, 0, 'account ≥ 2^31 (an EIP-2333 kind)'],
    ...EIP_KINDS.map((k) => [k, 0, 1, 'index 1 for an EIP-2333 kind (no index level: index 0 only)']),
    [0x0100, 0, 0, 'webauthn-p256: a platform credential, not seed-derived'], [0x0111, 0, 0, 'frost-secp256k1: DKG shares'],
    [0x0113, 0, 0, 'frost-bn254: DKG shares'], [0x0120, 0, 0, 'msig: no key of its own'],
    [0x0141, 0, 0, 'zether-bls12381: deriveConfKey only'], [0x0001, 0, 0, 'evm-eoa: a native kind (deriveKey)']]
    .map(([kind, account, index, reason]) => ({ what: 'ua', mnemonic: 'pq_kat', kind, account, index, error: 'Argument', reason })),
  ...[['evm', TWO31, null, 'index ≥ 2^31'], ['solana', TWO31, null, 'index ≥ 2^31'], ['stellar', 0, TWO31, 'coinType ≥ 2^31']]
    .map(([network, index, coinType, reason]) => ({ what: 'native', mnemonic: 'pq_kat', network, index, coinType, error: 'Argument', reason })),
];
for (const x of keyRefusals) {
  const e = refusedBy(() => (x.what === 'ua' ? keyOf(x) : deriveKey(SEEDS[x.mnemonic], x.network, x.index, { coinType: x.coinType })));
  must(e && (x.what === 'native' || e.code === x.error), `refusal ${JSON.stringify(x)}`);
}

const keys = {
  note: 'Generated by clients/clientkeys/scripts/ua-wallet-vectors.mjs (ua-rs-sign T1a) from src/uakey.js and src/seed.js; never '
    + 'edit by hand. UA keys: the UA tree m/22776\'/0\'/<account>\'/<kindNo>\'/<i>\' (kindNo = the kind number in decimal; BIP-32 '
    + 'secp256k1 for 0x0103 / 0x0108 / 0x0110, SLIP-10 nist256p1 for 0x0101, SLIP-10 ed25519 for 0x0102, all hardened), the '
    + 'EIP-2333 UA paths m/254/0/<account>/<kindNo> (bn254, salt "SCAAS-UA-BN254-v1": 0x0104, 0x0107, 0x0112 at 274) and '
    + 'm/12381/0/<account>/<kindNo> (BLS12-381, EIP-2333\'s salt: 0x0105, 0x0106), index 0 only, and the PQ HKDF seeds of pq.js. '
    + 'keyData: the kind\'s key data; a MuSig2 participant (0x0110: 33-byte compressed key, 0x0112: bn254 G1) has ua null (the '
    + 'group is the UA). account, index and coinType < 2^31. Seeds: BIP-39 with NFKD of the words and of the passphrase.',
  mnemonics: MNEMONICS,
  normalization: NORMALIZATION,
  ua: uaRows,
  native: nativeRows,
  refusals: keyRefusals,
};

// ---------------------------------------------------------------------------------------------------- sign.json

const DIGEST = keccak_256(utf8ToBytes('scaas.ua-rs-sign.t1a.digest'));
const PURPOSE = { metatx: [ua.purposeTag('metatx'), 'metatx', 1], pop2: [ua.POP_V2_TAG, 'pop', 2], kem: [ua.KEM_TAG, 'kem', 1] };
const signedBytes = (kind, msg) => {
  if (kind === 0x0101) return sha256(msg);
  const pq = Object.values(PQ_KINDS).find((s) => s.kind === kind);
  return pq && pq.pq ? pqMessage(Object.keys(PQ_KINDS).find((n) => PQ_KINDS[n].kind === kind), msg) : msg;
};
const verifyAny = (kind, kd, msg, sig, pop) => {
  const name = Object.keys(PQ_KINDS).find((n) => PQ_KINDS[n].kind === kind);
  if (name) return PQ_KINDS[name].alg.verify(sig, PQ_KINDS[name].pq ? pqMessage(name, msg) : msg, kd);
  return verify(kind, hex(kd), hex(msg), hex(sig), pop);
};
// per kind: [compare, fixed randomness for the row] — bytes rows reproduce, verify rows only verify
const MODES = (kind, label) => {
  const r32 = stream(`${label}.32`, 32);
  if ([0x0101, 0x0102, 0x0106, 0x0107, 0x0108].includes(kind)) return [['bytes', null]];
  if ([0x0103, 0x0104, 0x0105].includes(kind)) return [['bytes', { aux: r32 }], ['verify', { aux: stream(`${label}.hidden`, 32) }]];
  if ([0x0130, 0x0131, 0x0134].includes(kind)) return [['bytes', { rnd: new Uint8Array(32) }], ['verify', { rnd: r32 }]];
  if (kind === 0x0133) return [['bytes', { optRand: null }], ['verify', { optRand: stream(`${label}.16`, 16) }]];
  return [['verify', { falconSeed: r32 }]]; // Falcon: randomized, keys only byte-equal (Q1)
};

const uaSigRows = [];
const signRow = (r, p, compare, fixed) => {
  const k = keyOf(r);
  const [tag, purpose, purposeVersion] = PURPOSE[p];
  const msg = ua.uaMessage(r.kind, tag, DIGEST);
  const sig = fixed ? signUAVector(k, tag, DIGEST, fixed) : k.signUA(tag, DIGEST);
  must(verifyAny(r.kind, k.keyData, msg, sig, sigRole(tag) === 'pop'), `verify ${k.name} ${purpose}`);
  const shown = compare === 'bytes' && fixed ? Object.fromEntries(Object.entries(fixed).map(([n, v]) => [n, v === null ? null : hex(v)])) : undefined;
  uaSigRows.push({ ...r, name: k.name, keyData: hex(k.keyData), purpose, purposeVersion, purposeTag: hex(tag), digest: hex(DIGEST),
    uaMsg: hex(msg), role: sigRole(tag), signed: hex(signedBytes(r.kind, msg)), compare, ...(shown ? { fixed: shown } : {}),
    signature: hex(sig) });
};
for (const kind of [0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108, 0x0130, 0x0131, 0x0132, 0x0133, 0x0134, 0x0135]) {
  for (const p of ['metatx', 'pop2']) {
    for (const [compare, fixed] of MODES(kind, `${kind}.${p}`)) signRow(ref('pq_kat', kind), p, compare, fixed);
  }
}
for (const kind of [0x0101, 0x0108]) for (const p of ['metatx', 'kem']) signRow(ref('pq_kat', kind, 1, 1), p, 'bytes', null);
for (const kind of [0x0106, 0x0107]) signRow(ref('twelve_words', kind, 1, 0), 'kem', 'bytes', null);

const STRUCTURE_UA = keccak_256(utf8ToBytes('scaas.ua-rs-sign.t1a.structure'));
const STRUCTURE_MSG = ua.uaMessage(0x0120, ua.purposeTag('metatx'), DIGEST);
const memberRows = [0x0101, 0x0102, 0x0106, 0x0107, 0x0108].map((kind) => {
  const r = ref('pq_kat', kind, 0, 0);
  const k = keyOf(r);
  const md = ua.memberDigest(STRUCTURE_UA, STRUCTURE_MSG);
  const msg = ua.uaMessage(kind, ua.purposeTag('member'), md);
  const sig = k.signMember(STRUCTURE_UA, STRUCTURE_MSG);
  must(verify(kind, hex(k.keyData), hex(msg), hex(sig)), `member ${kind}`);
  return { ...r, name: k.name, keyData: hex(k.keyData), structureUa: hex(STRUCTURE_UA), structureUaMsg: hex(STRUCTURE_MSG),
    memberDigest: hex(md), uaMsg: hex(msg), role: 'authorization', signature: hex(sig) };
});

const signRefusals = uaSigRows.filter((r) => [0x0106, 0x0107].includes(r.kind) && r.mnemonic === 'pq_kat').map((r) => {
  const pop = r.role !== 'pop';
  must(!verify(r.kind, r.keyData, r.uaMsg, r.signature, pop), 'wrong DST');
  return { case: 'bls-wrong-dst', kind: r.kind, keyData: r.keyData, uaMsg: r.uaMsg, signature: r.signature, signedAs: r.role,
    pop, valid: false, note: 'the right message under the other role\'s DST' };
});

// The nonce map, computed here from the formula (not by the signer): the signer's R must be k·G.
const nonceMap = [[0x0104, 'bn254', bn254.fields.Fr.ORDER, [254, 0, 0, 260], 'SCAAS-UA-BN254-v1', bn254.G1.Point],
  [0x0105, 'bls12381', bls12_381.fields.Fr.ORDER, [12381, 0, 0, 261], 'BLS-SIG-KEYGEN-SALT-', bls12_381.G1.Point]]
  .map(([kind, curve, r, path, salt, G]) => {
    const sk = eip2333(SEEDS.pq_kat, path, { r, salt });
    const k = keyOf(ref('pq_kat', kind));
    const msg = ua.uaMessage(kind, ua.purposeTag('metatx'), DIGEST);
    const aux = stream(`nonce-map.${kind}`, 32);
    const input = concatBytes(utf8ToBytes('scaas.ua.schnorr.nonce.v1'), be(sk, 32), k.keyData, msg, aux);
    const seed = keccak_256(input);
    const wide = (int(keccak_256(concatBytes(seed, Uint8Array.of(2)))) << 256n) + int(keccak_256(concatBytes(seed, Uint8Array.of(3))));
    const nonce = wide % r;
    const sig = signUAVector(k, ua.purposeTag('metatx'), DIGEST, { aux });
    const size = kind === 0x0104 ? 32 : 64;
    must(hex(sig.subarray(0, size)) === hex(be(G.BASE.multiply(nonce).toAffine().x, size)), 'R = k·G');
    return { kind, curve, r: r.toString(), sk: sk.toString(), skBytes: hex(be(sk, 32)), keyData: hex(k.keyData),
      purposeTag: hex(ua.purposeTag('metatx')), digest: hex(DIGEST), uaMsg: hex(msg), aux: hex(aux), input: hex(input), seed: hex(seed),
      k: nonce.toString(), k256: (int(seed) % r).toString(), signature: hex(sig),
      note: 'k = (keccak256(seed ‖ 0x02) · 2^256 + keccak256(seed ‖ 0x03)) mod r, seed = keccak256(input); k256 = seed mod r is the '
        + 'biased 256-bit map a signer must not use' };
  });

// --- typed data ---
const CHAIN_UID = '0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464';
const TOKEN = '0x5ca00000000000000000000000000000000000a1';
const ACCOUNT = '0x' + 'ac'.repeat(20);
const PAYEE = '0x' + '5e'.repeat(20);
const RELAYER = '0x000000000000000000000000000000000000beef';
const FEE_TO = '0x0000000000000000000000000000000000000fee';
const ZERO = '0x' + '00'.repeat(20);
const NOW = 1_800_000_000;
const REF = '0x' + '09'.repeat(32);
const evmKey = deriveKey(SEEDS.pq_kat, 'evm', 0);
const VDOMAIN_TYPE = [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' }, { name: 'chainId', type: 'uint256' },
  { name: 'verifyingContract', type: 'address' }];
const BASKET_TYPES = { EIP712Domain: VDOMAIN_TYPE,
  Item: [{ name: 'delta', type: 'int64' }, { name: 'tags', type: 'bytes32[]' }],
  Basket: [{ name: 'owner', type: 'address' }, { name: 'balance', type: 'int256' }, { name: 'amounts', type: 'uint256[]' },
    { name: 'pair', type: 'Item[2]' }, { name: 'items', type: 'Item[]' }, { name: 'note', type: 'string' }, { name: 'blob', type: 'bytes' },
    { name: 'open', type: 'bool' }, { name: 'small', type: 'int8' }, { name: 'code', type: 'bytes4' }] };
const VDOMAIN = { name: 'SCaaS Vectors', version: '1', chainId: '7622', verifyingContract: '0x5ca00000000000000000000000000000000000f0' };
const tag = (s) => hex(keccak_256(utf8ToBytes(s)));
const basket = { owner: ACCOUNT, balance: '-1000000000000000000000', amounts: ['1', '115792089237316195423570985008687907853269984665640564039457584007913129639935'],
  pair: [{ delta: '-1', tags: [tag('a')] }, { delta: '9223372036854775807', tags: [] }], items: [{ delta: '-9223372036854775808', tags: [tag('b'), tag('c')] }],
  note: 'Hóa đơn — 2026', blob: '0x00ff10', open: true, small: -128, code: '0xdeadbeef' };
const basketTd = (message) => ({ types: BASKET_TYPES, primaryType: 'Basket', domain: VDOMAIN, message });
const missing = { owner: ACCOUNT, balance: '-5', pair: [{ delta: '1' }, {}] };
const explicitZero = { owner: ACCOUNT, balance: '-5', amounts: [], pair: [{ delta: '1', tags: [] }, { delta: '0', tags: [] }], items: [],
  note: '', blob: '0x', open: false, small: 0, code: '0x00000000' };
must(hex(evm.hashTypedData(basketTd(missing))) === hex(evm.hashTypedData(basketTd(explicitZero))), 'missing = zero');
const ORDER_TYPES = { EIP712Domain: VDOMAIN_TYPE, Order: [{ name: 'mode', type: 'uint32' }, { name: 'relayer', type: 'address' },
  { name: 'feeRecipient', type: 'address' }, { name: 'amount', type: 'uint256' }] };
const orderTd = (relayer, feeRecipient) => ({ types: ORDER_TYPES, primaryType: 'Order',
  domain: { name: 'Other Exchange', version: '1', chainId: '1', verifyingContract: '0x1111111111111111111111111111111111111111' },
  message: { mode: 0, relayer, feeRecipient, amount: '1000' } });
const order = orderTd(RELAYER, FEE_TO);
const typedGeneric = [
  { id: 'arrays-negative-int', td: basketTd(basket), note: 'int256 / int64 / int8 negative (two\'s complement), uint256[], Item[2], Item[], string, bytes, bool, bytes4' },
  { id: 'missing-field-zero', td: basketTd(missing), note: 'missing fields are their zero values: the digest of the explicit zeros' },
  { id: 'unrelated-order-any', td: order, canonicalDigest: hex(evm.hashTypedData(orderTd(ZERO, ZERO))),
    note: 'an unrelated contract\'s struct with mode / relayer / feeRecipient, mode 0, signed through Any: hashed as supplied, never canonicalised' },
].map((r) => ({ ...r, digest: hex(evm.hashTypedData(r.td)) }));
const orderRow = typedGeneric.find((r) => r.id === 'unrelated-order-any');
orderRow.signer = { mnemonic: 'pq_kat', network: 'evm', index: 0, address: evmKey.address };
orderRow.signature = hex(signTyped(evmKey, order));
const typedRefusals = [
  { id: 'unknown-field', td: basketTd({ ...basket, extra: '1' }) },
  { id: 'int8-out-of-range', td: basketTd({ ...basket, small: 128 }) },
  { id: 'fixed-array-length', td: basketTd({ ...basket, pair: [basket.pair[0]] }) },
  { id: 'bool-as-string', td: basketTd({ ...basket, open: 'true' }) },
  { id: 'bytes4-length', td: basketTd({ ...basket, code: '0xdead' }) },
];
for (const x of typedRefusals) must(refusedBy(() => evm.hashTypedData(x.td)), x.id);

// the SCaaS builders' canonical step: a non-zero unbound relayer / feeRecipient (mode 0) is hashed as zero, nested too
const meta = { from: ACCOUNT, to: PAYEE, value: '500', entryRef: REF, batch: '3', nonce: '7', validUntil: String(NOW + 300), mode: 0,
  relayer: RELAYER, fee: '0', feeRecipient: FEE_TO };
const uaMeta = { ...meta, from: evm.padId(ACCOUNT), to: evm.padId(PAYEE) };
const domainOf = { name: 'SCaaS MetaToken', contract: TOKEN, chainId: 7622, chainUid: CHAIN_UID };
const canonRows = [
  ['MetaTransaction', 'metaTxTypedData', { ...domainOf, name: 'SCaaS MetaToken', message: { from: ACCOUNT, data: '0x12345678', batch: '1',
    nonce: '2', validUntil: String(NOW), mode: 0, relayer: RELAYER, fee: '0', feeRecipient: FEE_TO } }],
  ['MetaTransfer', 'metaTransferTypedData', { ...domainOf, message: meta }],
  ['UAMetaTransaction', 'uaMetaTxTypedData', { ...domainOf, message: { from: evm.padId(ACCOUNT), data: '0x12345678', batch: '1', nonce: '2',
    validUntil: String(NOW), mode: 0, relayer: RELAYER, fee: '0', feeRecipient: FEE_TO } }],
  ['UAMetaTransfer', 'uaMetaTransferTypedData', { ...domainOf, message: uaMeta }],
  ['MetaTransfer mode 1 (relayer bound, feeRecipient not)', 'metaTransferTypedData', { ...domainOf, message: { ...meta, mode: 1 } }],
  ['Burn (an op struct with the envelope)', 'burnTypedData', { ...domainOf, message: { from: ACCOUNT, amount: '5', batch: '1', nonce: '1',
    validUntil: String(NOW), mode: 0, relayer: RELAYER, fee: '0', feeRecipient: FEE_TO } }],
  ['ReceiverFee (nested MetaTransfer)', 'receiverFeeTypedData', { ...domainOf, message: { payment: meta, fee: '10', feeRecipient: FEE_TO,
    validUntil: String(NOW) } }, true],
  ['UAReceiverFee (nested UAMetaTransfer)', 'uaReceiverFeeTypedData', { ...domainOf, message: { payment: uaMeta, fee: '10',
    feeRecipient: FEE_TO, validUntil: String(NOW) } }, true],
].map(([id, builder, input, nested]) => {
  const build = evm.OP_BUILDERS[builder] ?? evm[builder];
  const td = JSON.parse(JSON.stringify(build(input)));
  const zero = (m) => ({ ...m, relayer: BigInt(m.mode) & 1n ? m.relayer : ZERO, feeRecipient: BigInt(m.mode) & 2n ? m.feeRecipient : ZERO });
  const zeroedInput = nested ? { ...input, message: { ...input.message, payment: zero(input.message.payment) } }
    : { ...input, message: zero(input.message) };
  const zeroed = JSON.parse(JSON.stringify(build(zeroedInput)));
  const digest = hex(evm.hashTypedData(td));
  must(digest === hex(evm.hashTypedData(zeroed)), `${id}: zeroed`);
  must(digest !== hex(evm.hashTypedData({ ...td, message: input.message })), `${id}: supplied differs`);
  return { id, builder, input, td, zeroed, digest, ...(nested ? { nested: true } : {}) };
});

// --- the signing policy: the check* functions, accepted and refused ---
const Q = (td) => JSON.parse(JSON.stringify(td));
const set = (td, f) => { const c = Q(td); f(c); return c; };
const W = { chainId: 7622, chainUid: CHAIN_UID, now: NOW };
const payment = evm.metaTransferTypedData({ ...domainOf, message: { from: ACCOUNT, to: PAYEE, value: '125000500000', entryRef: REF,
  batch: evm.payLane(REF), nonce: '0', validUntil: String(NOW + 300), mode: 1, relayer: RELAYER } });
const payExpect = { check: 'Payment', account: ACCOUNT, ...W, amount: '125000.5', decimals: 6, payee: PAYEE, entryRef: REF, expectedToken: TOKEN };
const rfee = evm.receiverFeeTypedData({ ...domainOf, message: { payment: { from: ACCOUNT, to: PAYEE, value: '125000500000', entryRef: REF,
  batch: evm.payLane(REF), nonce: '0', validUntil: String(NOW + 300), mode: 1, relayer: RELAYER, fee: '0' }, fee: '1000', feeRecipient: FEE_TO,
  validUntil: String(NOW + 300) } });
const rfeeExpect = { check: 'ReceiverFee', payee: PAYEE, ...W, amount: '125000.5', decimals: 6, entryRef: REF, expectedToken: TOKEN,
  maxFee: '1000', feeRecipient: FEE_TO };
const PM = JSON.parse(readFileSync(join(VECTORS, 'metatx/paymeta.json'), 'utf8')).find((r) => r.name === 'note_utf8');
const payMeta = evm.buildMtxPayMeta({ token: TOKEN, chainId: 7622, chainUid: CHAIN_UID, from: ACCOUNT, to: PAYEE, amount: '1000',
  salt: PM.salt, meta: PM.meta, validUntil: NOW + 600, mode: 1, relayer: RELAYER }).typedData;
const payMetaExpect = { check: 'PayMeta', salt: PM.salt, meta: PM.meta, account: ACCOUNT, ...W, amount: '1000', decimals: 0, payee: PAYEE,
  expectedToken: TOKEN };
const burn = evm.burnTypedData({ ...domainOf, message: { from: ACCOUNT, amount: '5', batch: '3', nonce: '7', validUntil: String(NOW + 300), mode: 0 } });
const burnExpect = { check: 'Op', op: 'Burn', contract: TOKEN, ...W, message: { from: ACCOUNT, amount: '5' } };
const CANCEL_NONCE = '0xcfdd7aea';
const callData = CANCEL_NONCE + '00'.repeat(31) + '07';
const call = evm.metaTxTypedData({ name: 'SCaaS MetaToken', ...domainOf, message: { from: ACCOUNT, data: callData, batch: '1', nonce: '4',
  validUntil: String(NOW + 300) } });
const callExpect = { check: 'Call', account: ACCOUNT, ...W, allowlist: [{ selector: CANCEL_NONCE, name: 'cancelNonce', feeClass: 1 }],
  call: { contract: TOKEN, data: callData } };
const subjectKey = (a) => evm.secpSubjectKey(a).map((v) => (v instanceof Uint8Array ? hex(v) : v)); // JSON: hex, not byte objects
const NEW_KEY = subjectKey('0x' + '77'.repeat(20));
const owner = evm.addKeyTypedData({ contract: ACCOUNT, chainId: 7622, chainUid: CHAIN_UID, message: { from: ACCOUNT, kind: NEW_KEY[0],
  x: NEW_KEY[1], y: NEW_KEY[2], rpIdHash: NEW_KEY[3], originHash: NEW_KEY[4], validUntil: String(NOW + 600) } });
owner.message.nonce = '2';
const ownerExpect = { check: 'OwnerCall', account: ACCOUNT, ...W, newKey: NEW_KEY };
const DEX = '0x5ca00000000000000000000000000000000000a6';
const BUYS = '0x5ca00000000000000000000000000000000000b3';
const WRAPPER = '0x5ca00000000000000000000000000000000000b2';
const tradeOrder = { receiveToken: BUYS, amount: '100', receiveAmount: '200', minFill: '0', fee: '0', relayer: ZERO, dex: DEX,
  destination: ZERO, flags: 0, batch: '0', validUntil: String(NOW + 600) };
const trade = evm.tradeOrderTypedData({ token: TOKEN, chainId: 7622, chainUid: CHAIN_UID, order: { ...tradeOrder, from: ACCOUNT, nonce: '5' } });
const tradeExpect = { check: 'TradeOrder', account: ACCOUNT, ...W, order: tradeOrder, sellToken: TOKEN, dexes: [DEX] };
const cancel = evm.cancelOrderTypedData({ name: 'SCaaS MetaToken', ...domainOf, message: { order: { ...tradeOrder, from: ACCOUNT, nonce: '5' } } });
const cancelExpect = { check: 'Cancel', account: ACCOUNT, chainId: 7622, chainUid: CHAIN_UID, contract: TOKEN,
  order: { ...tradeOrder, from: ACCOUNT, nonce: '5' } };
const wrapOrder = { wrappedToken: WRAPPER, amount: '100', minMinted: '100', minFill: '100', fee: '0', relayer: ZERO, destination: ZERO,
  flags: 0, batch: '0', validUntil: String(NOW + 600) };
const wrap = evm.wrapOrderTypedData({ ...domainOf, message: { ...wrapOrder, from: ACCOUNT, nonce: '6' } });
const wrapExpect = { check: 'WrapOrder', account: ACCOUNT, ...W, order: wrapOrder, sellToken: TOKEN, wrappers: [WRAPPER] };
const policy = [
  ['payment', payment, payExpect],
  ['payment: another payee (a drain)', set(payment, (t) => { t.message.to = '0x' + 'ee'.repeat(20); }), payExpect],
  ['payment: non-zero feeRecipient unbound by mode 1', set(payment, (t) => { t.message.feeRecipient = FEE_TO; }), payExpect],
  ['payment: fee above the limit', evm.metaTransferTypedData({ ...domainOf, message: { ...payment.message, mode: 33, fee: '5' } }), payExpect],
  ['receiver fee', rfee, rfeeExpect],
  ['receiver fee: above the payee\'s limit', rfee, { ...rfeeExpect, maxFee: '999' }],
  ['pay-meta', payMeta, payMetaExpect],
  ['pay-meta: metadata of another salt', payMeta, { ...payMetaExpect, salt: '0x' + '42'.repeat(32) }],
  ['op Burn', burn, burnExpect],
  ['op Burn: another amount', burn, { ...burnExpect, message: { from: ACCOUNT, amount: '6' } }],
  ['op Burn: non-zero relayer unbound by mode 0', set(burn, (t) => { t.message.relayer = RELAYER; }), burnExpect],
  ['call cancelNonce', call, callExpect],
  ['call: a selector off the allowlist', call, { ...callExpect, allowlist: [{ selector: '0x12345678', name: 'other', feeClass: 1 }] }],
  ['call: transfer is never a call', evm.metaTxTypedData({ name: 'SCaaS MetaToken', ...domainOf, message: { ...call.message,
    data: '0xa9059cbb' + '00'.repeat(64) } }), { ...callExpect, allowlist: [{ selector: '0xa9059cbb', name: 'transfer', feeClass: 2 }],
    call: { contract: TOKEN, data: '0xa9059cbb' + '00'.repeat(64) } }],
  ['owner call AddKey', owner, ownerExpect],
  ['owner call: someone else\'s key', owner, { ...ownerExpect, newKey: subjectKey('0x' + '66'.repeat(20)) }],
  ['cancel order', cancel, cancelExpect],
  ['cancel: not the account\'s order', cancel, { ...cancelExpect, account: '0x' + 'bd'.repeat(20) }],
  ['trade order', trade, tradeExpect],
  ['trade order: a DEX off the profile', trade, { ...tradeExpect, dexes: [BUYS] }],
  ['wrap order', wrap, wrapExpect],
  ['wrap order: a wrapper off the profile', wrap, { ...wrapExpect, wrappers: [DEX] }],
  ['Any: an unrelated struct as supplied', order, { check: 'Any', allowAnyTypedData: true }],
  ['Any without its marker', order, { check: 'Any' }],
].map(([id, td, expect]) => {
  const e = refusedBy(() => evm.expectDigest(td, expect));
  if (e && !String(e.message).startsWith('Refusing to sign')) throw e;
  const row = { id, td: Q(td), expect: Q(expect), ...(e ? { refused: e.message } : { digest: hex(evm.expectDigest(td, expect)) }) };
  must(refusedBy(() => evm.expectDigest(row.td, row.expect))?.message === row.refused, `${id}: the same verdict from the JSON row`);
  return row;
});
must(policy.filter((p) => p.digest).length === 10, "accepted policy rows");

// --- EVM transactions ---
const TO = '0x5ca00000000000000000000000000000000000c0';
const txs = [
  { type: 0, chainId: '7622', nonce: '0', gasPrice: '1000000000', gasLimit: '21000', to: TO, value: '1', data: '0x' },
  { type: 0, chainId: '7622', nonce: '1', gasPrice: '1000000000', gasLimit: '1000000', to: null, value: '0', data: hex(stream('tx.create', 100)) },
  { type: 1, chainId: '7622', nonce: '2', gasPrice: '2000000000', gasLimit: '60000', to: TO, value: '0', data: '0xcfdd7aea',
    accessList: [{ address: TOKEN, storageKeys: [hex(stream('tx.sk0', 32)), hex(stream('tx.sk1', 32))] }] },
  { type: 2, chainId: '7622', nonce: '3', maxPriorityFeePerGas: '1000000000', maxFeePerGas: '30000000000', gasLimit: '100000', to: TO,
    value: '115792089237316195423570985008687907853269984665640564039457584007913129639935', data: hex(stream('tx.call', 68)), accessList: [] },
  { type: 2, chainId: '1', nonce: '18446744073709551615', maxPriorityFeePerGas: '0', maxFeePerGas: '1', gasLimit: '21000', to: TO, value: '0',
    data: '0x', accessList: [] },
  { type: 3, chainId: '7622', nonce: '4', maxPriorityFeePerGas: '1000000000', maxFeePerGas: '30000000000', gasLimit: '100000', to: TO,
    value: '0', data: '0x', accessList: [], maxFeePerBlobGas: '1000000000',
    blobVersionedHashes: [hex(concatBytes(Uint8Array.of(1), stream('tx.blob0', 31))), hex(concatBytes(Uint8Array.of(1), stream('tx.blob1', 31)))] },
  // the largest chain id: ua-rs takes a u64 (alloy ChainId, EIP-2294), so does evmTransaction (parity, 2026-11-06)
  { type: 2, chainId: '18446744073709551615', nonce: '5', maxPriorityFeePerGas: '0', maxFeePerGas: '1', gasLimit: '21000', to: TO, value: '0',
    data: '0x', accessList: [] },
];
const txRows = txs.map((tx) => {
  const t = evm.evmTransaction(tx);
  const s = signTransaction(evmKey, tx);
  return { tx, signer: { mnemonic: 'pq_kat', network: 'evm', index: 0, address: evmKey.address }, unsigned: hex(t.unsigned),
    sighash: hex(t.sighash), yParity: s.yParity, r: hex(s.r), s: hex(s.s), ...(s.v !== undefined ? { v: s.v } : {}), raw: hex(s.raw) };
});
// The EIP-155 example, quoted from the EIP at a pinned commit (sha256 of that file below). With `UA_WALLET_DOWNLOADS=<dir>`
// holding the downloaded eip-155.md, the file's sha256 and every quoted value are checked against it.
const eip155 = { source: 'https://raw.githubusercontent.com/ethereum/EIPs/3aea9f3673a684dddfcc17c0d1f74d484e20e6ac/EIPS/eip-155.md',
  sha256: '0x3c208813585d8fca67a92d908ece47402f87a18a14f1b20ee5ebcb3e702dcc9c',
  tx: { type: 0, chainId: '1', nonce: '9', gasPrice: '20000000000', gasLimit: '21000', to: '0x3535353535353535353535353535353535353535',
    value: '1000000000000000000', data: '0x' },
  privateKey: '0x' + '46'.repeat(32),
  signingData: '0xec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080',
  signingHash: '0xdaf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53', v: 37,
  r: '18515461264373351373200002665853028612451056578545711640558177340181847433846',
  s: '46948507304638947509940763649030358759909902576025900602547168820602576006531',
  signedTx: '0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83' };
if (process.env.UA_WALLET_DOWNLOADS) {
  const src = readFileSync(join(process.env.UA_WALLET_DOWNLOADS, 'eip-155.md'));
  must(hex(sha256(src)) === eip155.sha256, 'eip-155.md sha256');
  for (const v of [eip155.signingData.slice(2), eip155.signingHash.slice(2), eip155.r, eip155.s, eip155.signedTx.slice(2)]) {
    must(src.toString('utf8').includes(v), `eip-155.md quotes ${v.slice(0, 16)}`);
  }
}
{
  const t = evm.evmTransaction(eip155.tx);
  const s = signTransaction({ curve: 'secp256k1', privateKey: fromHex(eip155.privateKey) }, eip155.tx);
  must(hex(t.unsigned) === eip155.signingData && hex(t.sighash) === eip155.signingHash && s.v === eip155.v
    && int(s.r).toString() === eip155.r && int(s.s).toString() === eip155.s && hex(s.raw) === eip155.signedTx, 'EIP-155 example');
}
// External ECDSA known answers (T1c, spec §11, F-09), quoted with source and sha256; with UA_WALLET_DOWNLOADS=<dir> holding the
// downloads, the file's sha256 is checked before it is read and every quoted value is found in it.
const RFC6979 = { source: 'https://www.rfc-editor.org/rfc/rfc6979.txt', sha256: '0x456e8f17558fdbd206f968b96fc6f1b4a71ea331ab30ad17f711ab3adaa7d701',
  section: 'A.2.5 (ECDSA, NIST P-256), SHA-256 rows', x: '0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721',
  Ux: '0x60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6', Uy: '0x7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299',
  rows: [
    { hash: 'SHA-256', message: 'sample', k: '0xa6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60',
      r: '0xefd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716', s: '0xf7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8' },
    { hash: 'SHA-256', message: 'test', k: '0xd16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0',
      r: '0xf1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367', s: '0x019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083' },
  ] };
const SECP_SET = { name: 'tiny-secp256k1 ECDSA fixtures (bitcoinjs), the described "valid" rows: RFC 6979 with HMAC-SHA256, low-s',
  source: 'https://raw.githubusercontent.com/bitcoinjs/tiny-secp256k1/17d82c7fe38239d3ba0451202895837885f80e1c/tests/fixtures/ecdsa.json',
  sha256: '0xb830aa30d0ab3b6c51440caffac9206b24ae5450a387a2db73789f5ce795595d' };
// scripts/ua-wallet-secp256k1-rows.json holds the fixture's rows with a description, fields description, d, m, signature, recoveryId,
// taken out of the pinned download with the stdlib (python3 -I, json.load, the same filter); checked against it below.
const secpRows = JSON.parse(readFileSync(new URL('./ua-wallet-secp256k1-rows.json', import.meta.url), 'utf8'));
if (process.env.UA_WALLET_DOWNLOADS) {
  const text = readPinned(join(process.env.UA_WALLET_DOWNLOADS, 'rfc6979.txt'), RFC6979.sha256).toString('utf8').toUpperCase();
  for (const v of [RFC6979.x, RFC6979.Ux, RFC6979.Uy, ...RFC6979.rows.flatMap((r) => [r.k, r.r, r.s])]) {
    must(text.includes(v.slice(2).toUpperCase()), `rfc6979.txt quotes ${v.slice(0, 18)}`);
  }
  const fx = JSON.parse(readPinned(join(process.env.UA_WALLET_DOWNLOADS, 'tiny-secp256k1-ecdsa.json'), SECP_SET.sha256));
  const want = fx.valid.filter((v) => 'description' in v).map(({ description, d, m, signature, recoveryId }) => ({ description, d, m, signature, recoveryId }));
  must(JSON.stringify(want) === JSON.stringify(secpRows), 'the committed secp256k1 rows are the fixture\'s described rows');
}
for (const r of RFC6979.rows) {
  const sig = p256.sign(sha256(utf8ToBytes(r.message)), fromHex(RFC6979.x), { prehash: false, lowS: false, extraEntropy: false, format: 'compact' });
  must(hex(sig) === r.r + r.s.slice(2), `RFC 6979 A.2.5 ${r.message}`);
}
for (const r of secpRows) {
  const rec = secp256k1.sign(fromHex('0x' + r.m), fromHex('0x' + r.d), { prehash: false, lowS: true, extraEntropy: false, format: 'recovered' });
  must(hex(rec.subarray(1)) === '0x' + r.signature && rec[0] === r.recoveryId, `secp256k1 set: ${r.description}`);
}
const external = { rfc6979: RFC6979, secp256k1: { ...SECP_SET, rows: secpRows } };

const ok2 = txs[3];
const { to: _to, ...noTo } = ok2;
const txRefusals = [
  ['type 4 (EIP-7702)', { ...ok2, type: 4, authorizationList: [] }],
  ['type 4 without a list', { ...ok2, type: 4 }],
  ['legacy without chainId', (({ chainId, ...t }) => t)(txs[0])],
  ['chainId 0', { ...txs[0], chainId: '0' }],
  ['a field of another type', { ...txs[0], maxFeePerGas: '1' }],
  ['missing to', noTo],
  ['type 3 create (to null)', { ...txs[5], to: null }],
  ['type 3 without blob hashes', { ...txs[5], blobVersionedHashes: [] }],
  ['nonce 2^64', { ...ok2, nonce: '18446744073709551616' }],
  ['value 2^256', { ...ok2, value: (1n << 256n).toString() }],
  ['to of 19 bytes', { ...ok2, to: '0x' + '35'.repeat(19) }],
  ['value as hex', { ...ok2, value: '0x10' }],
  ['chainId 2^64', { ...ok2, chainId: (1n << 64n).toString() }],
  ['legacy chainId 2^64', { ...txs[0], chainId: (1n << 64n).toString() }],
  ['chainId 2^64 + 1', { ...ok2, chainId: ((1n << 64n) + 1n).toString() }], // a reader that wraps mod 2^64 would sign for chain 1
].map(([id, tx]) => {
  must(refusedBy(() => evm.evmTransaction(tx))?.message.startsWith('Refusing to sign'), id);
  return { id, tx };
});

// --- chain separation (owner 2026-11-05): one message, one key, SCaaS testnet 7622 and SCaaS mainnet 22776 ---
// A domain with chainId (a token's UAMetaTransfer) and an EIP-155 transaction differ per chain: other digests, other signatures,
// and a signature for one chain does not verify against the other's digest. A portable record (domain without chainId) is the
// same on both chains.
const CHAINS = [7622, 22776];
const sepKey = keyOf(ref('pq_kat', 0x0108));
const METATX = ua.purposeTag('metatx');
const sepTyped = CHAINS.map((chainId) => {
  const td = JSON.parse(JSON.stringify(evm.uaMetaTransferTypedData({ ...domainOf, chainId, message: uaMeta })));
  const digest = evm.hashTypedData(td);
  const uaMsg = ua.uaMessage(0x0108, METATX, digest);
  const signature = sepKey.signUA(METATX, digest);
  must(verify(0x0108, hex(sepKey.keyData), hex(uaMsg), hex(signature)), `chain ${chainId}: typed verifies`);
  return { chainId, td, digest: hex(digest), uaMsg: hex(uaMsg), signature: hex(signature) };
});
const sepTx = [txs[0], txs[3]].flatMap((base) => CHAINS.map((chainId) => {
  const tx = { ...base, chainId: String(chainId) };
  const t = evm.evmTransaction(tx);
  const s = signTransaction(evmKey, tx);
  return { type: tx.type, chainId, tx, sighash: hex(t.sighash), yParity: s.yParity, r: hex(s.r), s: hex(s.s),
    ...(s.v !== undefined ? { v: s.v } : {}), raw: hex(s.raw) };
}));
const evmPub = fromHex(evmKey.publicKey);
const txSigOk = (row, sighash) => secp256k1.verify(concatBytes(fromHex(row.r), fromHex(row.s)), fromHex(sighash), evmPub, { prehash: false, lowS: true });
const sepRefusals = [];
for (const [a, b] of [[0, 1], [1, 0]]) {
  const [x, y] = [sepTyped[a], sepTyped[b]];
  must(x.digest !== y.digest && x.signature !== y.signature, 'typed pair differs');
  must(!verify(0x0108, hex(sepKey.keyData), y.uaMsg, x.signature), 'typed cross-chain refused');
  sepRefusals.push({ what: 'typed', signedFor: x.chainId, checkedAgainst: y.chainId });
}
for (const type of [0, 2]) {
  const [x, y] = sepTx.filter((r) => r.type === type);
  must(x.sighash !== y.sighash && x.r + x.s !== y.r + y.s && txSigOk(x, x.sighash) && txSigOk(y, y.sighash), `tx type ${type} pair`);
  for (const [p, q] of [[x, y], [y, x]]) {
    must(!txSigOk(p, q.sighash), `tx type ${type} cross-chain refused`);
    sepRefusals.push({ what: 'tx', type, signedFor: p.chainId, checkedAgainst: q.chainId });
  }
}
const SEP_MSIG = keccak_256(utf8ToBytes('scaas.ua-rs-sign.chain-separation.msig'));
const sepPortable = (() => {
  const m = ua.membershipMessage({ ua: SEP_MSIG, member: sepKey.ua });
  const digest = hex(evm.hashTypedData(m.typedData));
  must(digest === hex(m.digest) && !('chainId' in m.typedData.domain), 'portable digest');
  return { id: 'portable-membership', chains: CHAINS, td: m.typedData, digest, uaMsg: hex(m.message),
    signature: hex(sepKey.signMember(SEP_MSIG, m.message)),
    note: 'UAMembership in the portable domain (no chainId, no verifyingContract): one digest and one signature for every chain; '
      + 'signed by the derived member 0x0108 as acceptMembership checks it (signMember over the structure\'s ua_msg)' };
})();
const chainSeparation = { key: { mnemonic: 'pq_kat', kind: 0x0108, account: 0, index: 0, evm: { network: 'evm', index: 0, address: evmKey.address } },
  typed: sepTyped, tx: sepTx, refusals: sepRefusals, portable: [sepPortable] };

// --- WebAuthn assertions (spec §5.6) ---
const RP_ID = 'scaas.example';
const ORIGIN = 'https://scaas.example';
const N = p256.Point.Fn.ORDER;
const waSk = (int(keccak_256(utf8ToBytes('scaas.ua-rs-sign.t1a.webauthn'))) % (N - 1n)) + 1n;
const waKey = concatBytes(p256.getPublicKey(be(waSk, 32), false).subarray(1), sha256(utf8ToBytes(RP_ID)));
const waPurpose = ua.purposeTag('metatx');
const authData = (flags = 0x05) => concatBytes(sha256(utf8ToBytes(RP_ID)), Uint8Array.of(flags), be(7n, 4));
const cdj = (challenge, { order: reordered = false, tail = '' } = {}) => utf8ToBytes(reordered
  ? `{"challenge":"${b64url(challenge)}","type":"webauthn.get","origin":"${ORIGIN}"${tail}}`
  : `{"type":"webauthn.get","challenge":"${b64url(challenge)}","origin":"${ORIGIN}"${tail}}`);
const assertionOf = (digest, opts = {}, flags = 0x05) => {
  const expected = webauthnChallenge(waPurpose, digest);
  const ad = authData(flags);
  const cd = opts.raw ? opts.raw(expected) : cdj(opts.challenge ?? expected, opts);
  const sig = p256.sign(sha256(concatBytes(ad, sha256(cd))), be(waSk, 32), { prehash: false, lowS: true, extraEntropy: false, format: 'compact' });
  return { keyData: hex(waKey), purposeTag: hex(waPurpose), digest: hex(digest), expectedChallenge: hex(expected), authData: hex(ad),
    clientDataJSON: hex(cd), r: hex(sig.subarray(0, 32)), s: hex(sig.subarray(32)) };
};
const D1 = keccak_256(utf8ToBytes('scaas.ua-rs-sign.t1a.webauthn.d1'));
const D2 = keccak_256(utf8ToBytes('scaas.ua-rs-sign.t1a.webauthn.d2'));
const highOf = (a) => ({ ...a, s: hex(be(N - int(fromHex(a.s)), 32)), highS: true });
const webauthnAccepted = [assertionOf(D1), highOf(assertionOf(D1)), assertionOf(D2, { tail: ',"crossOrigin":false' }),
  assertionOf(D2, { tail: ',"crossOrigin":false,"other_keys_can_be_added_here":"x"' })].map((a) => {
  const blob = webauthnAssertion(Object.fromEntries(['keyData', 'expectedChallenge', 'authData', 'clientDataJSON', 'r', 's']
    .map((n) => [n, fromHex(a[n])])));
  return { ...a, assertion: hex(blob) };
});
must(int(fromHex(webauthnAccepted[1].assertion.slice(-64))) <= N / 2n, 'high s normalised');
const waRefusals = [
  ['wrong-challenge', { ...assertionOf(D1, { challenge: webauthnChallenge(waPurpose, D2) }) }],
  ['reordered-json', assertionOf(D1, { order: true })],
  ['cross-origin-true', assertionOf(D1, { tail: ',"crossOrigin":true' })],
  ['r-zero', { ...assertionOf(D1), r: hex(new Uint8Array(32)) }],
  ['s-n', { ...assertionOf(D1), s: hex(be(N, 32)) }],
  ['s-zero', { ...assertionOf(D1), s: hex(new Uint8Array(32)) }],
  ['flipped-signature', { ...assertionOf(D1), r: hex(be(int(fromHex(assertionOf(D1).r)) ^ 1n, 32)) }],
  ['uv-flag-missing', assertionOf(D1, {}, 0x01)],
  ['another-key', { ...assertionOf(D1), keyData: hex(concatBytes(p256.getPublicKey(be(waSk + 1n, 32), false).subarray(1), sha256(utf8ToBytes(RP_ID)))) }],
  // a 0xff in the origin: the chains' byte rule passes it (control below), the builder refuses (ua-rs parity, 2026-11-06)
  ['client-data-not-utf8', assertionOf(D1, { raw: (ch) => concatBytes(cdj(ch).subarray(0, -2), Uint8Array.of(0xff), utf8ToBytes('"}')) })],
].map(([c, a]) => {
  const e = refusedBy(() => webauthnAssertion(Object.fromEntries(['keyData', 'expectedChallenge', 'authData', 'clientDataJSON', 'r', 's']
    .map((n) => [n, fromHex(a[n])]))));
  must(e?.code === 'WebAuthnAssertion', c);
  return { case: c, ...a, error: 'WebAuthnAssertion' };
});
{
  const x = waRefusals.find((r) => r.case === 'client-data-not-utf8');
  must(clientDataOk(fromHex(x.clientDataJSON), fromHex(x.expectedChallenge)), 'client-data-not-utf8: the chains\' byte rule passes it');
}

// --- msig member sets (minimal at both levels) ---
const memberOf = (r) => { const k = keyOf(r); return { kind: r.kind, id: hex(k.ua), weight: 1, ref: r, key: k }; };
const sortById = (ms) => [...ms].sort((a, b) => (a.id < b.id ? -1 : 1));
const flat = sortById([memberOf(ref('pq_kat', 0x0101)), memberOf(ref('pq_kat', 0x0102)), memberOf(ref('pq_kat', 0x0108))]);
const flatKd = ua.encodeMsig(2, flat);
const flatUa = ua.deriveUA(0x0120, flatKd);
const innerMs = sortById([memberOf(ref('pq_kat', 0x0101, 1)), memberOf(ref('pq_kat', 0x0102, 1)), memberOf(ref('pq_kat', 0x0108, 1))]);
const innerKd = ua.encodeMsig(2, innerMs);
const innerUa = ua.deriveUA(0x0120, innerKd);
const outer = sortById([{ kind: 0x0120, id: hex(innerUa), weight: 1 }, memberOf(ref('pq_kat', 0x0106))]);
const outerKd = ua.encodeMsig(2, outer);
const outerUa = ua.deriveUA(0x0120, outerKd);
const innerMap = { [hex(innerUa)]: hex(innerKd) };
const at = (ms, kind) => ms.findIndex((m) => m.kind === kind);
const slotOf = (ms, i) => ({ index: i, key: ms[i].ref });
const msigCases = [
  ['flat minimal {p256, ed25519}', flatUa, flatKd, [slotOf(flat, Math.min(at(flat, 0x0101), at(flat, 0x0102))),
    slotOf(flat, Math.max(at(flat, 0x0101), at(flat, 0x0102)))]],
  ['flat minimal {ed25519, secp256k1}', flatUa, flatKd, [at(flat, 0x0102), at(flat, 0x0108)].sort().map((i) => slotOf(flat, i))],
  ['flat non-minimal: three of t = 2', flatUa, flatKd, [0, 1, 2].map((i) => slotOf(flat, i)), 'UAPoP'],
  ['flat unsorted', flatUa, flatKd, [1, 0].map((i) => slotOf(flat, i)), 'UAPoP'],
  ['flat below threshold', flatUa, flatKd, [slotOf(flat, 0)], 'UAPoP'],
  ['nested minimal: inner {two of three} + bls12381', outerUa, outerKd, [0, 1].map((i) => (outer[i].kind === 0x0120
    ? { index: i, members: [0, 1].map((j) => slotOf(innerMs, j)) } : slotOf(outer, i)))],
  ['nested level-2 non-minimal: inner three of t = 2', outerUa, outerKd, [0, 1].map((i) => (outer[i].kind === 0x0120
    ? { index: i, members: [0, 1, 2].map((j) => slotOf(innerMs, j)) } : slotOf(outer, i))), 'UAPoP'],
].map(([c, id, kd, slots, refused]) => {
  const call = () => msigMemberSigs({ ua: id, keyData: kd, purposeTag: ua.POP_V2_TAG, digest: DIGEST, inner: (x) => innerMap[x],
    slots: slots.map((s) => ({ index: s.index, key: s.key && keyOf(s.key), members: s.members?.map((m) => ({ index: m.index, key: keyOf(m.key) })) })) });
  const e = refusedBy(call);
  must(refused ? e?.code === refused : !e, `${c}: ${e?.message}`);
  return { case: c, ua: hex(id), keyData: hex(kd), purposeTag: hex(ua.POP_V2_TAG), digest: hex(DIGEST), slots,
    ...(kd === outerKd ? { inner: innerMap } : {}), ...(refused ? { refused } : { memberSigs: hex(call()) }) };
});

const sign = {
  note: 'Generated by clients/clientkeys/scripts/ua-wallet-vectors.mjs (ua-rs-sign T1a) from src/uakey.js, src/seed.js and src/evm.js; '
    + 'never edit by hand. Keys: keys.json (mnemonic, kind, account, index). ua: signUA(purposeTag, digest) over ua_msg = '
    + 'uaMessage(kind, purposeTag, digest); "signed" is what the scheme signs (0x0101: sha256(ua_msg); 0x0108 and the rest: ua_msg; '
    + 'ML-DSA / SLH-DSA: pq_msg with the empty context); role "pop" for pop v2 / kem / pqz-key (the BLS POP DST), else '
    + '"authorization". compare "bytes": reproduce exactly (fixed: the test-only randomness, aux / rnd (zero = deterministic '
    + 'ML-DSA) / optRand (null = PK.seed)); compare "verify": a randomized signature, verify only. Deterministic ECDSA (0x0101, '
    + '0x0108, native EVM keys, transactions) is RFC 6979 with extraEntropy: false passed explicitly and low-s. scaas Schnorr '
    + 'nonce: k = hashToScalar(keccak256("scaas.ua.schnorr.nonce.v1" ‖ be32(sk) ‖ Y ‖ ua_msg ‖ aux)), the 512-bit map (nonceMap). '
    + 'typed: generic = the faithful EIP-712 hasher (missing field = zero, unknown field refused, int two\'s complement, T[k]); '
    + 'canon = the SCaaS builders, whose unbound relayer / feeRecipient hash as zero (nested too); policy = expectDigest(td, '
    + 'expect) over the check* functions. tx: evmTransaction types 0-3 (no type 4), chainId 1 … 2^64 − 1, signTransaction. webauthn: '
    + 'webauthnAssertion against the expected challenge, clientDataJSON UTF-8. msig: msigMemberSigs, minimal at both levels. chainSeparation (owner 2026-11-05): one message and '
    + 'one key on chain 7622 (SCaaS testnet) and 22776 (SCaaS mainnet): a UAMetaTransfer in a token domain with chainId (UA key 0x0108, '
    + 'signUA metatx) and EIP-155 transactions of types 0 and 2 (the EVM key) give other digests and signatures per chain; refusals: a '
    + 'signature for one chain does not verify against the other\'s digest; portable: a record in the portable domain (no chainId) '
    + 'is one digest and one signature on both. external (T1c): RFC 6979 A.2.5 (P-256, SHA-256; s as published, high or low) and a '
    + 'named secp256k1 RFC 6979 set (low-s), each with its source URL and sha256.',
  ua: uaSigRows,
  member: memberRows,
  refusals: signRefusals,
  nonceMap,
  typed: { generic: typedGeneric, refusals: typedRefusals, canon: canonRows },
  policy,
  tx: { rows: txRows, published: [eip155], refusals: txRefusals },
  webauthn: { accepted: webauthnAccepted, refusals: waRefusals },
  msig: msigCases,
  chainSeparation,
  external,
};

// ---------------------------------------------------------------------------------------------------- kem.json, seal.json, vault.json
// ua-rs-sign T1b (spec §6, §8.1, §11): the UA KEM key, encapsulation and decapsulation with their checks, seal / open, the backup
// and link containers with their acceptance and replay rows, the seed vault. Randomness: a SHAKE256 stream per label (t1b).
const stream1b = (label, n) => shake256(utf8ToBytes(`scaas.ua-rs-sign.t1b.${label}`), { dkLen: n });
const H = (b) => hex(b);
const KEM_HOLDERS = [0x0130, 0x0131, 0x0132, 0x0134, 0x0135];
const kemRows = [];
for (const [mnemonic, kind, account, index, version] of [
  ...KEM_HOLDERS.flatMap((kind) => [0, 1].map((version) => ['pq_kat', kind, 0, 0, version])),
  ['pq_kat', 0x0130, 1, 0, 0], ['pq_kat', 0x0130, 0, 1, 0], ['pq_kat', 0x0130, 0, 0, '18446744073709551615'], ['twelve_words', 0x0130, 0, 0, 0]]) {
  const key = keyOf(ref(mnemonic, kind, account, index));
  const k = kemKeyOf(key, typeof version === 'string' ? BigInt(version) : version);
  kemRows.push({ mnemonic, kind, account, index, ua: H(key.ua), version, kemPk: H(k.kemPk), kemPkHash: H(k.kemPkHash) });
}
must(new Set(kemRows.map((r) => r.kemPk)).size === kemRows.length, 'every (ua, version) its own KEM key');
const kemOf = (row) => kemKeyOf(keyOf(row), typeof row.version === 'string' ? BigInt(row.version) : row.version);
const R0 = kemRows[0]; // pq_kat mldsa44 account 0 index 0 version 0
const K0 = kemOf(R0);
const kemRefusals = [
  ...[0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108, 0x0133].map((kind) => ({ what: 'key', mnemonic: 'pq_kat', kind,
    account: 0, index: 0, version: 0, error: 'KemHolder', reason: 'not a KEM holder (CTR-UA-32)' })),
  { what: 'key', kind: 0x0120, ua: msigCases[0].ua, version: 0, error: 'KemHolder', reason: 'an msig has no KEM key (MD-11): seal to its accepted members' },
  { what: 'key', mnemonic: 'pq_kat', kind: 0x0130, account: 0, index: 0, version: '18446744073709551616', error: 'Argument', reason: 'version ≥ 2^64' },
];
for (const x of kemRefusals) {
  const e = refusedBy(() => (x.kind === 0x0120 ? kemKeyOf({ kind: 0x0120, ua: fromHex(x.ua) }, 0) : kemKeyOf(keyOf(x), BigInt(x.version))));
  must(e?.code === x.error, `kem refusal ${x.kind}: ${e?.message}`);
}
const EPH = ephemeralVector(stream1b('ephemeral', 96));
const encRows = [
  { id: 'ua-key', recipient: { mnemonic: 'pq_kat', kind: 0x0130, account: 0, index: 0, version: 0 }, kemPk: R0.kemPk },
  { id: 'ua-key-2', recipient: { mnemonic: 'pq_kat', kind: 0x0135, account: 0, index: 0, version: 1 }, kemPk: kemRows[9].kemPk },
  { id: 'ephemeral', recipient: { ephemeralSeed: H(stream1b('ephemeral', 96)) }, kemPk: H(EPH.kemPk) },
].map((r) => {
  const [m, e] = [stream1b(`encaps.${r.id}.m`, 32), stream1b(`encaps.${r.id}.e`, 32)];
  const out = kemEncapsVector(fromHex(r.kemPk), m, e);
  const key = r.id === 'ephemeral' ? EPH : kemOf({ ...r.recipient });
  must(H(key.decaps(out.mlkemCt, out.x25519Eph)) === H(out.ss), `${r.id}: decaps`);
  return { ...r, m: H(m), e: H(e), mlkemCt: H(out.mlkemCt), x25519Eph: H(out.x25519Eph), ss: H(out.ss) };
});
must(kemRows[9].kind === 0x0135 && kemRows[9].version === 1, 'row 9');
const pk0 = fromHex(R0.kemPk);
const badModulus = pk0.slice(); badModulus[1] = 0xff; badModulus[2] |= 0x0f; // the first coefficient 4095 ≥ q
const scheme2 = pk0.slice(); scheme2[0] = 2;
const lowOrder = pk0.slice(); lowOrder.set(new Uint8Array(32), 1 + 1568); // pk_X = 0: ss_X = 0^32
const encapsRefusals = [
  ['modulus', badModulus, 'ek coefficient 4095 ≥ q (FIPS 203 §7.2)'],
  ['length', pk0.subarray(0, 1600), 'kemPk of 1,600 bytes'],
  ['scheme 2', scheme2, 'scheme 2 (ML-KEM-1024 + HQC + X25519) is reserved'],
  ['all-zero ss_X', lowOrder, 'pk_X = 0 (small order): ss_X = 0^32'],
].map(([id, kemPk, reason]) => {
  const [m, e] = [stream1b('refuse.m', 32), stream1b('refuse.e', 32)];
  must(refusedBy(() => kemEncapsVector(kemPk, m, e))?.code === 'KemCheck', `encaps refusal ${id}`);
  return { id, kemPk: H(kemPk), m: H(m), e: H(e), error: 'KemCheck', reason };
});
const enc0 = encRows[0];
const flipped = fromHex(enc0.mlkemCt); flipped[100] ^= 1;
const decapsRows = [
  { id: 'valid', mlkemCt: enc0.mlkemCt, x25519Eph: enc0.x25519Eph, ss: enc0.ss },
  { id: 'flipped mlkemCt byte 100: implicit rejection, another ss', mlkemCt: H(flipped), x25519Eph: enc0.x25519Eph, ss: H(K0.decaps(flipped, fromHex(enc0.x25519Eph))) },
  { id: 'short mlkemCt (1,567 bytes)', mlkemCt: H(fromHex(enc0.mlkemCt).subarray(0, 1567)), x25519Eph: enc0.x25519Eph, error: 'KemCheck' },
  { id: 'x25519Eph of 31 bytes', mlkemCt: enc0.mlkemCt, x25519Eph: H(fromHex(enc0.x25519Eph).subarray(0, 31)), error: 'KemCheck' },
  { id: 'small-order E = 0', mlkemCt: enc0.mlkemCt, x25519Eph: H(new Uint8Array(32)), error: 'KemCheck' },
  { id: 'small-order E = 1', mlkemCt: enc0.mlkemCt, x25519Eph: H(concatBytes(Uint8Array.of(1), new Uint8Array(31))), error: 'KemCheck' },
  { id: 'small-order E of order 8', mlkemCt: enc0.mlkemCt, x25519Eph: '0xe0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800', error: 'KemCheck' },
].map((r) => {
  const e = refusedBy(() => K0.decaps(fromHex(r.mlkemCt), fromHex(r.x25519Eph)));
  must(r.error ? e?.code === r.error : !e && H(K0.decaps(fromHex(r.mlkemCt), fromHex(r.x25519Eph))) === r.ss, `decaps ${r.id}`);
  return { key: { mnemonic: 'pq_kat', kind: 0x0130, account: 0, index: 0, version: 0 }, ...r };
});
must(decapsRows[1].ss !== enc0.ss, 'flipped ct gives another ss');
const kem = {
  note: 'Generated by clients/clientkeys/scripts/ua-wallet-vectors.mjs (ua-rs-sign T1b) from src/kem.js; never edit by hand. keys: '
    + 'kemSeed = HKDF-SHA256(ikm = BIP-39 seed (keys.json), salt = "scaas.ua.kem.v1", info = "scaas.kem.1" ‖ ua ‖ be64 version, 96); '
    + '(ek, dk) = ML-KEM-1024.KeyGen_internal(kemSeed[0:32], kemSeed[32:64]); sk_X = kemSeed[64:96], pk_X = X25519(sk_X, 9); '
    + 'kemPk = 0x01 ‖ ek ‖ pk_X (1,601 B), kemPkHash = keccak256(kemPk). KEM holders only (mldsa44, mldsa65, fndsa512, mldsa87, '
    + 'fndsa1024); an msig has no KEM key (MD-11). encaps: m (ML-KEM message) and e (X25519 ephemeral secret) given, E = X25519(e, 9), '
    + 'ss = SHA3-256(ss_M ‖ ss_X ‖ E ‖ pk_X ‖ "scaas.kem.1"); ephemeral: the key from 96 given bytes laid out as kemSeed. Refusals '
    + '(KemCheck): scheme ≠ 1, length ≠ 1,601, the ek modulus check, ss_X = 0^32; decaps: mlkemCt 1,568 B and x25519Eph 32 B, '
    + 'ss_X = 0^32 refused, ML-KEM implicit rejection kept (a flipped byte: another ss, no error).',
  keys: kemRows,
  refusals: kemRefusals,
  encaps: encRows,
  encapsRefusals,
  decaps: decapsRows,
};

// --- seal.json ---
const R0_REF = { mnemonic: 'pq_kat', kind: 0x0130, account: 0, index: 0, version: 0 };
const sealRow = async (id, kemPk, purpose, aad, pt, recipient = R0_REF) => {
  const [m, e] = [stream1b(`seal.${id}.m`, 32), stream1b(`seal.${id}.e`, 32)];
  const s = await sealVector(kemPk, purpose, aad, pt, { m, e });
  return { id, recipient, kemPk: H(kemPk), purpose, aad: H(aad), pt: H(pt), m: H(m), e: H(e), mlkemCt: H(s.mlkemCt), x25519Eph: H(s.x25519Eph),
    ciphertext: H(s.ciphertext), wire: H(wireForm(s)) };
};
const sealRows = [
  await sealRow('backup', pk0, SEAL_PURPOSE.backup, stream1b('aad.backup', 40), stream1b('pt.backup', 77)),
  await sealRow('link-ephemeral', EPH.kemPk, SEAL_PURPOSE.link, stream1b('aad.link', 17), stream1b('pt.link', 300), { ephemeralSeed: H(stream1b('ephemeral', 96)) }),
  await sealRow('empty-pt-empty-aad', pk0, 'scaas/test/v1', new Uint8Array(0), new Uint8Array(0)),
];
for (const r of sealRows) {
  const key = r.id === 'link-ephemeral' ? EPH : K0;
  must(H(await openSealed(key, r.purpose, fromHex(r.aad), fromWire(fromHex(r.wire)))) === r.pt, `seal ${r.id} opens`);
}
const s0 = sealRows[0];
const flip = (h, i) => { const b = fromHex(h); b[i] ^= 1; return H(b); };
const sealRefusals = [
  { id: 'wrong purpose', purpose: 'scaas/link/v1', error: 'SealOpen' },
  { id: 'wrong aad', aad: flip(s0.aad, 0), error: 'SealOpen' },
  { id: 'aad dropped', aad: '0x', error: 'SealOpen' },
  { id: 'version 2', wire: H(concatBytes(Uint8Array.of(2), fromHex(s0.wire).subarray(1))), error: 'SealVersion' },
  { id: 'scheme 2', wire: H(concatBytes(Uint8Array.of(1, 2), fromHex(s0.wire).subarray(2))), error: 'SealVersion' },
  { id: 'flipped mlkemCt byte', wire: flip(s0.wire, 2 + 7), error: 'SealOpen' },
  { id: 'flipped x25519Eph byte', wire: flip(s0.wire, 2 + 1568 + 3), error: 'SealOpen' },
  { id: 'flipped ciphertext byte', wire: flip(s0.wire, 2 + 1568 + 32 + 5), error: 'SealOpen' },
  { id: 'flipped tag byte', wire: flip(s0.wire, fromHex(s0.wire).length - 1), error: 'SealOpen' },
  { id: 'opened with another KEM key (version 1)', key: { mnemonic: 'pq_kat', kind: 0x0130, account: 0, index: 0, version: 1 }, error: 'SealOpen' },
];
for (const x of sealRefusals) {
  const key = x.key ? kemOf(x.key) : K0;
  let e = null;
  try { await openSealed(key, x.purpose ?? s0.purpose, fromHex(x.aad ?? s0.aad), fromWire(fromHex(x.wire ?? s0.wire))); } catch (err) { e = err; }
  must(e?.code === x.error, `seal refusal ${x.id}: ${e?.message}`);
}
const sealArgRefusals = [];
for (const [id, purpose, ptLength] of [['purpose with an upper-case letter', 'scaas/Backup/v1', 1], ['purpose of 65 bytes', 'a'.repeat(65), 1],
  ['empty purpose', '', 1], ['pt over 1 MiB', SEAL_PURPOSE.backup, MAX_PT + 1]]) {
  let e = null;
  try { await sealVector(pk0, purpose, new Uint8Array(0), new Uint8Array(ptLength), { m: stream1b('x.m', 32), e: stream1b('x.e', 32) }); } catch (err) { e = err; }
  must(e?.code === 'Argument', `seal argument ${id}`);
  sealArgRefusals.push({ id, purpose, ptLength, error: 'Argument' });
}
must(H((await sealVector(pk0, SEAL_PURPOSE.backup, new Uint8Array(0), new Uint8Array(MAX_PT), { m: stream1b('x.m', 32), e: stream1b('x.e', 32) })).ciphertext).length === 2 + 2 * (MAX_PT + 16), '1 MiB ok');

// containers: the wallet W (twelve_words) backs up to the recovery UA R (pq_kat mldsa44, KEM version 0) and links a new device
const ref1b = (mnemonic, kind, account = 0, index = 0) => ({ mnemonic, kind, account, index });
const W_ID = ref1b('twelve_words', 0x0102); // W's identity key (ed25519: deterministic)
const wKey = keyOf(W_ID);
const other = keyOf(ref1b('pq_kat', 0x0102)); // a different registered UA
const W_ENTROPY = fromHex(MNEMONICS.find((m) => m.id === 'twelve_words').entropy);
const manifestOf = (k, refRow) => ({ entries: [{ kind: refRow.kind, account: refRow.account, index: refRow.index, ua: H(k.ua) }] });
const payloadOf = (generation, entropy = W_ENTROPY, k = wKey, refRow = W_ID) => ({ generation, entropy,
  secrets: [{ label: 'native-import:evm:0', bytes: stream1b(`secret.${generation}`, 32) }], manifest: manifestOf(k, refRow) });
const R_RECIPIENT = { ua: fromHex(R0.ua), version: 0 };
const fx = (label) => ({ m: stream1b(`${label}.m`, 32), e: stream1b(`${label}.e`, 32), sig: {} });
const CREATED = NOW;
const backupC = async (label, payload, sender = wKey, extra = {}) => sealBackup({ kemPk: pk0, recipient: R_RECIPIENT, sender, created: CREATED, payload, ...extra }, fx(label));
const expectBackup = { purpose: SEAL_PURPOSE.backup, sender: { ua: H(wKey.ua) }, recipient: { ua: R0.ua, version: 0 } };
const backup2 = await backupC('backup.g2', payloadOf(2));
const backup1 = await backupC('backup.g1', payloadOf(1));
const SESSION = { seed: stream1b('link.session', 96), shortCode: '48151623', start: NOW };
const session = () => linkSessionVector(SESSION.seed, SESSION.shortCode, SESSION.start);
const S0 = session();
const linkPt = encodeBackup(payloadOf(2));
const linkC = async (label, created, shortCode = SESSION.shortCode, sender = wKey) => sealContainer({ kemPk: S0.kemPk, purpose: SEAL_PURPOSE.link,
  recipient: { kemPkHash: S0.kemKey.kemPkHash }, sender, created, pt: linkPt, shortCode }, fx(label));
const link = await linkC('link', NOW + 60);
const expectLink = { purpose: SEAL_PURPOSE.link, sender: { ua: H(wKey.ua) }, recipient: { kemPkHash: H(S0.kemKey.kemPkHash) } };
// msig senders (owner 2026-11-05: sender.auth is a full UASig): the flat {p256, ed25519} set and the nested inner {two of three} +
// bls12381 set of sign.json msig, every member deterministic; the opener reads the member keys by id (`members`)
const keyMap = (ms) => Object.fromEntries(ms.map((m) => [m.id, { kind: m.kind, keyData: m.key ? H(m.key.keyData) : innerMap[m.id] }]));
const flatMembers = keyMap(flat);
const nestedMembers = { ...keyMap(outer), ...keyMap(innerMs) };
const lookup = (map) => (id) => map?.[id] ?? null;
// the opener's accepted(id, index) (CTR-UA-37: memberAccepted of the chain's registry or an indexer): a row's `accepted` lists each
// msig's accepted member indices; an index not listed is not accepted, a row without `accepted` passes no lookup
const acceptedOf = (map) => (map ? (id, i) => map[id]?.includes(i) === true : undefined);
const FLAT_ACCEPTED = { [H(flatUa)]: [0, 1, 2] };
const NESTED_ACCEPTED = { [H(outerUa)]: [0, 1], [H(innerUa)]: [0, 1, 2] };
const msigRef = (id, kd, slots, inner) => ({ ua: H(id), keyData: H(kd), slots, ...(inner ? { inner } : {}) });
const msigSender = (r) => ({ ua: fromHex(r.ua), keyData: fromHex(r.keyData), inner: (x) => r.inner?.[x],
  slots: r.slots.map((s) => ({ index: s.index, key: s.key && keyOf(s.key), members: s.members?.map((m) => ({ index: m.index, key: keyOf(m.key) })) })) });
const FLAT_SENDER = msigRef(flatUa, flatKd, [at(flat, 0x0101), at(flat, 0x0102)].sort().map((i) => slotOf(flat, i)));
const NESTED_SENDER = msigRef(outerUa, outerKd, [0, 1].map((i) => (outer[i].kind === 0x0120
  ? { index: i, members: [0, 1].map((j) => slotOf(innerMs, j)) } : slotOf(outer, i))), innerMap);
const msigPt = stream1b('pt.msig', 64);
const msigC = (label, r) => sealContainer({ kemPk: pk0, purpose: SEAL_PURPOSE.backup, recipient: R_RECIPIENT, sender: msigSender(r), created: CREATED,
  pt: msigPt }, fx(label));
const flatC = await msigC('msig.flat', FLAT_SENDER);
const nestedC = await msigC('msig.nested', NESTED_SENDER);
const expectOf = (id) => ({ purpose: SEAL_PURPOSE.backup, sender: { ua: H(id) }, recipient: { ua: R0.ua, version: 0 } });
const containerRows = [
  { id: 'backup generation 2', container: backup2, expect: expectBackup, opener: { kem: R0 },
    pt: H(encodeBackup(payloadOf(2))), sender: W_ID, m: H(fx('backup.g2').m), e: H(fx('backup.g2').e) },
  { id: 'link', container: link, expect: expectLink, opener: { session: { seed: H(SESSION.seed), shortCode: SESSION.shortCode, start: SESSION.start } },
    pt: H(linkPt), sender: W_ID, m: H(fx('link').m), e: H(fx('link').e) },
  { id: 'msig sender: flat {p256, ed25519}', container: flatC, expect: expectOf(flatUa), members: flatMembers, accepted: FLAT_ACCEPTED, opener: { kem: R0 },
    pt: H(msigPt), sender: { msig: FLAT_SENDER }, m: H(fx('msig.flat').m), e: H(fx('msig.flat').e) },
  { id: 'msig sender: nested, inner {two of three} + bls12381', container: nestedC, expect: expectOf(outerUa), members: nestedMembers, accepted: NESTED_ACCEPTED, opener: { kem: R0 },
    pt: H(msigPt), sender: { msig: NESTED_SENDER }, m: H(fx('msig.nested').m), e: H(fx('msig.nested').e) },
];
must(H(await openContainer(K0, backup2, expectBackup)) === containerRows[0].pt, 'backup opens');
must(H(await openLink(session(), link, expectLink)) === containerRows[1].pt, 'link opens');
for (const r of containerRows.slice(2)) must(H(await openContainer(K0, r.container, r.expect, lookup(r.members), acceptedOf(r.accepted))) === r.pt, `${r.id} opens`);
must(nestedC.sender.auth.members.some((s) => s.members.length === 2), 'the nested sender signs through its inner msig');

// acceptance refusals, each from an otherwise valid container (C-03)
const byOther = await backupC('backup.other', payloadOf(2, fromHex(MNEMONICS.find((m) => m.id === 'pq_kat').entropy), other, ref1b('pq_kat', 0x0102)), other);
const notDeriving = await backupC('backup.foreign-entropy', { ...payloadOf(2), entropy: fromHex(MNEMONICS.find((m) => m.id === 'bip39_test').entropy) });
const flipField = (c, path, i) => { const d = structuredClone(c); const o = path.slice(0, -1).reduce((a, k) => a[k], d); const k = path.at(-1);
  const b = fromB64url(o[k]); b[i] ^= 1; o[k] = b64url(b); return d; };
const opener1 = { kem: kemRows[1] }; // R's KEM key version 1
// forged msig member sets (the builder refuses them): each member signs as signMember does, over the container's own ua_msg
const msigUaMsg = (c, id) => ua.uaMessage(0x0120, ua.SEAL_TAG, keccak_256(concatBytes(containerAad({ purpose: c.purpose, recipient: R_RECIPIENT,
  senderUa: id, created: c.created }), wireForm({ version: 1, scheme: 1, mlkemCt: fromB64url(c.sealed.mlkemCt),
  x25519Eph: fromB64url(c.sealed.x25519Eph), ciphertext: fromB64url(c.sealed.ciphertext) }))));
const withAuth = (c, f) => { const d = structuredClone(c); f(d.sender.auth); return d; };
const flatSlots = (idx) => idx.map((i) => ({ index: i, members: [], sig: b64url(flat[i].key.signMember(flatUa, msigUaMsg(flatC, flatUa))) }));
must(JSON.stringify(flatSlots([at(flat, 0x0101), at(flat, 0x0102)].sort())) === JSON.stringify(flatC.sender.auth.members),
  'positive control: the forging path rebuilds the builder\'s minimal set');
const innerIdx = outer.findIndex((m) => m.kind === 0x0120);
const innerMsg = ua.uaMessage(0x0120, ua.purposeTag('member'), ua.memberDigest(outerUa, msigUaMsg(nestedC, outerUa)));
const nestedSlots = (idx) => nestedC.sender.auth.members.map((s) => (s.index !== innerIdx ? s : { index: s.index,
  members: idx.map((j) => ({ index: j, sig: b64url(innerMs[j].key.signMember(innerUa, innerMsg)) })), sig: s.sig }));
must(JSON.stringify(nestedSlots([0, 1])) === JSON.stringify(nestedC.sender.auth.members), 'positive control: the nested forging path');
const msigRow = (c, id, members, accepted = id === outerUa ? NESTED_ACCEPTED : FLAT_ACCEPTED) => ({ container: c, expect: expectOf(id), members, accepted });
const flatSigners = [at(flat, 0x0101), at(flat, 0x0102)].sort();
const acceptance = [
  { id: 'signed by a different registered UA', container: byOther, expect: expectBackup, error: 'ContainerSender' },
  { id: 'purpose not the expected one', container: backup2, expect: { ...expectBackup, purpose: SEAL_PURPOSE.link }, error: 'ContainerSender' },
  { id: 'recipient not the expected one', container: backup2, expect: { ...expectBackup, recipient: { ua: R0.ua, version: 1 } }, opener: opener1, error: 'ContainerSender' },
  { id: 'the expected recipient is not the opener\'s key', container: backup2, expect: expectBackup, opener: opener1, error: 'ContainerSender' },
  { id: 'sender not in the approved set', container: backup2, expect: { ...expectBackup, sender: { set: [H(other.ua), H(keccak_256(utf8ToBytes('x')))] } }, error: 'ContainerSender' },
  { id: 'sender in the approved set (accepted)', container: backup2, expect: { ...expectBackup, sender: { set: [H(other.ua), H(wKey.ua)] } }, error: null },
  { id: 'sender key whose UA is not sender.ua', container: withAuth(backup2, (a) => { a.keyData = b64url(other.keyData); }), expect: expectBackup, error: 'ContainerSender' },
  { id: 'flipped sender signature byte', container: flipField(backup2, ['sender', 'auth', 'signature'], 3), expect: expectBackup, error: 'SealOpen' },
  { id: 'single-key UASig with members', container: withAuth(backup2, (a) => { a.members = [{ index: 0, members: [], sig: a.signature }]; }), expect: expectBackup, error: 'SealOpen' },
  { id: 'msig sender: non-minimal member set (three of t = 2)', ...msigRow(withAuth(flatC, (a) => { a.members = flatSlots([0, 1, 2]); }), flatUa, flatMembers), error: 'SealOpen' },
  { id: 'msig sender: below the threshold (one of t = 2)', ...msigRow(withAuth(flatC, (a) => { a.members = flatSlots([0]); }), flatUa, flatMembers), error: 'SealOpen' },
  { id: 'msig sender: nested level-2 non-minimal (inner three of t = 2)', ...msigRow(withAuth(nestedC, (a) => { a.members = nestedSlots([0, 1, 2]); }), outerUa, nestedMembers), error: 'SealOpen' },
  { id: 'msig sender: a signature of its own', ...msigRow(withAuth(flatC, (a) => { a.signature = a.members[0].sig; }), flatUa, flatMembers), error: 'SealOpen' },
  { id: 'msig sender: flipped member signature byte', ...msigRow(flipField(flatC, ['sender', 'auth', 'members', 1, 'sig'], 3), flatUa, flatMembers), error: 'SealOpen' },
  { id: 'msig sender: flipped inner member signature byte', ...msigRow(flipField(nestedC, ['sender', 'auth', 'members', innerIdx, 'members', 0, 'sig'], 3), outerUa, nestedMembers), error: 'SealOpen' },
  { id: 'msig sender: keyData of another msig', ...msigRow(withAuth(flatC, (a) => { a.keyData = b64url(outerKd); }), flatUa, { ...flatMembers, ...nestedMembers }), error: 'ContainerSender' },
  { id: 'msig sender: member keys unknown to the opener', ...msigRow(flatC, flatUa, {}), error: 'ContainerSender' },
  { id: 'msig sender: a member key that does not derive its id', ...msigRow(flatC, flatUa, Object.fromEntries(Object.entries(flatMembers)
    .map(([id, m], i) => [id, i === 0 ? { ...m, keyData: H(other.keyData) } : m]))), error: 'ContainerSender' },
  // member acceptance (CTR-UA-37, owner 2026-11-05): an msig sender opens only with its signers accepted at both levels
  { id: 'msig sender: a signing member not accepted (the msig active through a non-signer)', ...msigRow(flatC, flatUa, flatMembers,
    { [H(flatUa)]: [flatSigners[1], at(flat, 0x0108)].sort() }), error: 'ContainerSender' },
  { id: 'msig sender: accepted weight below the threshold (one of t = 2 accepted)', ...msigRow(flatC, flatUa, flatMembers,
    { [H(flatUa)]: [flatSigners[0]] }), error: 'ContainerSender' },
  { id: 'msig sender: signers accepted, a non-signer not (accepted)', ...msigRow(flatC, flatUa, flatMembers, { [H(flatUa)]: flatSigners }), error: null },
  { id: 'msig sender: nested, the inner msig\'s slot not accepted (level 1)', ...msigRow(nestedC, outerUa, nestedMembers,
    { [H(outerUa)]: [1 - innerIdx], [H(innerUa)]: [0, 1, 2] }), error: 'ContainerSender' },
  { id: 'msig sender: nested, an inner signing member not accepted (level 2)', ...msigRow(nestedC, outerUa, nestedMembers,
    { [H(outerUa)]: [0, 1], [H(innerUa)]: [1, 2] }), error: 'ContainerSender' },
  { id: 'msig sender: no accepted lookup', ...msigRow(flatC, flatUa, flatMembers, null), error: 'ContainerSender' },
  { id: 'created changed (aad)', container: { ...structuredClone(backup2), created: CREATED + 1 }, expect: expectBackup, error: 'SealOpen' },
  { id: 'flipped ciphertext byte', container: flipField(backup2, ['sealed', 'ciphertext'], 0), expect: expectBackup, error: 'SealOpen' },
  { id: 'container v 2', container: { ...structuredClone(backup2), v: 2 }, expect: expectBackup, error: 'SealVersion' },
  { id: 'backup entropy that does not derive sender.ua', container: notDeriving, expect: expectBackup, restore: true, error: 'ContainerSender' },
  { id: 'link: swapped short code', container: link, expect: expectLink, link: { shortCode: '48151624' }, error: 'SealOpen' },
].map((x) => ({ opener: { kem: R0 }, ...x }));
const openerKey = (o) => (o.kem ? kemOf(o.kem) : null);
for (const x of acceptance) {
  let e = null;
  try {
    if (x.link) await openLink(linkSessionVector(SESSION.seed, x.link.shortCode, SESSION.start), x.container, x.expect, lookup(x.members), acceptedOf(x.accepted));
    else if (x.restore) await restoreBackup(openerKey(x.opener), x.container, x.expect, lookup(x.members), acceptedOf(x.accepted));
    else await openContainer(openerKey(x.opener), x.container, x.expect, lookup(x.members), acceptedOf(x.accepted));
  } catch (err) { e = err; }
  must(x.error ? e?.code === x.error : !e, `acceptance ${x.id}: ${e?.message}`);
}
// replay and rollback (C-11)
const replay = [
  { id: 'link created after the window', container: await linkC('link.late', NOW + LINK_WINDOW + 1), error: 'ContainerReplay' },
  { id: 'link created before the session', container: await linkC('link.early', NOW - 1), error: 'ContainerReplay' },
  { id: 'link created at the window\'s end (accepted)', container: await linkC('link.edge', NOW + LINK_WINDOW), error: null },
].map((x) => ({ kind: 'link', expect: expectLink, ...x }));
for (const x of replay) {
  let e = null;
  try { await openLink(session(), x.container, x.expect); } catch (err) { e = err; }
  must(x.error ? e?.code === x.error : !e, `replay ${x.id}`);
}
{
  const s = session();
  await openLink(s, link, expectLink);
  let e = null;
  try { await openLink(s, link, expectLink); } catch (err) { e = err; }
  must(e?.code === 'ContainerReplay', 'second use of a session');
}
const rollback = [
  { id: 'generation 1 over a wallet at generation 2', container: backup1, current: { ua: H(wKey.ua), generation: 2 }, error: 'BackupRollback' },
  { id: 'generation 1 over generation 2 with allowRollback', container: backup1, current: { ua: H(wKey.ua), generation: 2 }, allowRollback: true, install: true },
  { id: 'equal generation: no change', container: backup2, current: { ua: H(wKey.ua), generation: 2 }, install: false },
  { id: 'generation 2 over generation 1', container: backup2, current: { ua: H(wKey.ua), generation: 1 }, install: true },
  { id: 'generation 1 on a device without the wallet', container: backup1, current: null, install: true },
  { id: 'generation 1 on a device holding another wallet', container: backup1, current: { ua: H(other.ua), generation: 9 }, install: true },
].map((x) => ({ kind: 'backup', expect: expectBackup, opener: { kem: R0 }, ...x }));
for (const x of rollback) {
  let e = null;
  let r = null;
  try { r = await restoreBackup(K0, x.container, x.expect, undefined, undefined, { current: x.current, allowRollback: x.allowRollback }); } catch (err) { e = err; }
  must(x.error ? e?.code === x.error : !e && r.install === x.install, `rollback ${x.id}: ${e?.message}`);
}
const sealOut = {
  note: 'Generated by clients/clientkeys/scripts/ua-wallet-vectors.mjs (ua-rs-sign T1b) from src/seal.js; never edit by hand. seal: '
    + 'key = HKDF-SHA256(ss, salt = empty, info = "scaas/seal/v1" ‖ u8 1 ‖ be16 len(purpose) ‖ purpose ‖ keccak256(kemPk), 32), '
    + 'ciphertext = AES-256-GCM(key, nonce 0^96, pt, aad) (ct ‖ tag); m and e as kem.json encaps; wire = version ‖ scheme ‖ mlkemCt ‖ '
    + 'x25519Eph ‖ ciphertext. KEM keys: kem.json keys rows (key refs) and the ephemeral key of kem.json encaps "ephemeral" / the link '
    + 'session seed. Containers {v, purpose, recipient, sender: {ua, auth}, created, sealed} (bytes base64url): aad = u8 1 ‖ be16 '
    + 'len(purpose) ‖ purpose ‖ recipientId (ua or kemPkHash) ‖ be64 version (0: ephemeral) ‖ senderUa ‖ be64 created [‖ '
    + 'sha256(shortCode) for scaas/link/v1]; sender.auth = the sender\'s UASig {keyData, signature, members: [{index, members: '
    + '[{index, sig}], sig}]} (owner 2026-11-05) over m0 = uaMessage(kind, keccak256("scaas.ua.purpose.seal.v1"), keccak256(aad ‖ '
    + 'wire)) (MD-10, role authorization): a single key signs m0 itself (no members); an msig (no signature) in the minimal form at '
    + 'both levels, a member over uaMessage(kind, member, memberDigest(senderUa, m0)), an inner msig\'s over innerDigest. '
    + 'openContainer(kemKey, container, expect, members, accepted): purpose, recipient (expected and the opener\'s), sender expected or in '
    + 'the set, auth.keyData derives sender.ua (msig, or one single-key kind), then the UASig (an msig\'s member keys from '
    + 'members(id), re-derived; its signers accepted at both levels, CTR-UA-37: the weight of the signing slots whose '
    + 'accepted(id, index) is true reaches the threshold, a row\'s accepted lists each msig\'s accepted indices, no accepted '
    + 'for an msig sender is refused, a single key needs none) and the seal; ContainerSender / SealOpen / SealVersion. Link: created in [start, start + 600 s], one use '
    + '(ContainerReplay). Backup payload: JSON {v, generation, entropy, secrets, manifest: {entries: [{kind, account, index, ua}]}}; '
    + 'restore: the entropy (BIP-39 passphrase empty) derives sender.ua at its manifest entry (else ContainerSender), an older '
    + 'generation over the same wallet is BackupRollback unless allowRollback, an equal one installs nothing.',
  seal: sealRows,
  refusals: { base: 'backup', key: { mnemonic: 'pq_kat', kind: 0x0130, account: 0, index: 0, version: 0 }, rows: sealRefusals },
  argumentRefusals: sealArgRefusals,
  containers: containerRows,
  acceptance,
  replay: [...replay, ...rollback],
};

// --- vault.json: the seed vault (randomness: the platform RNG replaced by a stream per vault while it is sealed) ---
const withStream = async (label, f) => {
  let n = 0;
  Object.defineProperty(globalThis.crypto, 'getRandomValues', { configurable: true, writable: true,
    value: (a) => { new Uint8Array(a.buffer, a.byteOffset, a.byteLength).set(stream1b(`${label}.${n++}`, a.byteLength)); return a; } });
  try { return await f(); } finally { delete globalThis.crypto.getRandomValues; }
};
const PIN = 'river-otter-7 ünï';
const sealed = (label, secret, { N = 2 ** 15, pin = PIN, vlabel = 'seed', prf } = {}) => withStream(label, async () => {
  const v = await createVault(secret, { label: vlabel, pin, prf });
  return N === 2 ** 17 ? v : rewrapPin(v, pin, pin, { N, r: 8, p: 1, dkLen: 32 }, { policy: false });
});
const PQ_ENTROPY = fromHex(MNEMONICS.find((m) => m.id === 'pq_kat').entropy);
const prf = { output: stream1b('prf.output', 32), credentialId: 'Y3JlZGVudGlhbC0x', salt: stream1b('prf.salt', 32) };
const vaultRows = [
  { id: 'seed N=2^15', vault: await sealed('v.n15', PQ_ENTROPY), unlock: { pin: PIN }, plaintext: H(PQ_ENTROPY) },
  { id: 'seed N=2^16', vault: await sealed('v.n16', PQ_ENTROPY, { N: 2 ** 16 }), unlock: { pin: PIN }, plaintext: H(PQ_ENTROPY) },
  { id: 'seed N=2^17', vault: await sealed('v.n17', PQ_ENTROPY, { N: 2 ** 17 }), unlock: { pin: PIN }, plaintext: H(PQ_ENTROPY) },
  { id: 'twelve words (16-byte entropy)', vault: await sealed('v.twelve', W_ENTROPY), unlock: { pin: PIN }, plaintext: H(W_ENTROPY),
    words: MNEMONICS.find((m) => m.id === 'twelve_words').words, uaKey: { ...W_ID, ua: H(wKey.ua) },
    kemKey: { kind: 0x0130, account: 0, index: 0, version: 0, kemPkHash: kemRows.at(-1).kemPkHash } },
  { id: 'passphrase in NFD opens a vault sealed in NFC (NFKC)', vault: await sealed('v.nfd', PQ_ENTROPY, { pin: NFC_PASS }),
    unlock: { pin: NFC_PASS.normalize('NFD') }, plaintext: H(PQ_ENTROPY) },
  { id: 'PRF envelope', vault: await sealed('v.prf', PQ_ENTROPY, { prf }), unlock: { prfOutput: H(prf.output) }, plaintext: H(PQ_ENTROPY) },
];
must(NFC_PASS !== NFC_PASS.normalize('NFD'), 'NFC differs from NFD');
const unlockOf = (u) => (u.prfOutput ? { prfOutput: fromHex(u.prfOutput) } : u);
for (const r of vaultRows) must(H(await openSeedVault(r.vault, unlockOf(r.unlock))) === r.plaintext, `vault ${r.id}`);
const base = vaultRows[0].vault;
const vaultRefusals = [
  { id: 'wrong passphrase', vault: base, unlock: { pin: 'river-otter-8 ünï' }, error: 'VaultOpen' },
  { id: 'altered AAD label (sealed as "seed-old", relabelled "seed")', vault: { ...(await sealed('v.relabel', PQ_ENTROPY, { vlabel: 'seed-old' })), label: 'seed' },
    unlock: { pin: PIN }, error: 'VaultOpen' },
  { id: 'N = 2^31', vault: { ...structuredClone(base), pin: { ...base.pin, N: 2 ** 31 } }, unlock: { pin: PIN }, error: 'VaultParams' },
  { id: 'N = 3', vault: { ...structuredClone(base), pin: { ...base.pin, N: 3 } }, unlock: { pin: PIN }, error: 'VaultParams' },
  { id: 'r = 16', vault: { ...structuredClone(base), pin: { ...base.pin, r: 16 } }, unlock: { pin: PIN }, error: 'VaultParams' },
  { id: 'p = 2', vault: { ...structuredClone(base), pin: { ...base.pin, p: 2 } }, unlock: { pin: PIN }, error: 'VaultParams' },
  { id: 'v: 2', vault: { ...structuredClone(base), v: 2 }, unlock: { pin: PIN }, error: 'VaultVersion' },
  { id: 'v: 2 tombstone', vault: { v: 2, moved: 'browser-device-key' }, unlock: { pin: PIN }, error: 'VaultVersion' },
  { id: 'seed payload of 31 bytes', vault: await sealed('v.31', stream1b('v.31.secret', 31)), unlock: { pin: PIN }, error: 'VaultOpen' },
  { id: 'seed payload of 64 bytes (a BIP-39 seed, not entropy)', vault: await sealed('v.64', stream1b('v.64.secret', 64)), unlock: { pin: PIN }, error: 'VaultOpen' },
  { id: 'label not seed', vault: await sealed('v.manifest', PQ_ENTROPY, { vlabel: 'manifest' }), unlock: { pin: PIN }, error: 'Argument' },
];
for (const x of vaultRefusals) {
  let e = null;
  try { await openSeedVault(x.vault, unlockOf(x.unlock)); } catch (err) { e = err; }
  must(e?.code === x.error, `vault refusal ${x.id}: ${e?.message}`);
}
const vaultOut = {
  note: 'Generated by clients/clientkeys/scripts/ua-wallet-vectors.mjs (ua-rs-sign T1b) from src/vault.js (vault v1, CLI-SGN-02, '
    + 'unchanged format); never edit by hand. The seed vault holds the BIP-39 entropy at its own length (16-32 B, label "seed"); '
    + 'openSeedVault refuses another length (VaultOpen) and another label (Argument). Passphrase NFKC before scrypt; envelopes '
    + 'outside N ∈ {2^15, 2^16, 2^17}, r = 8, p = 1 are VaultParams before scrypt runs; v ≠ 1 (v 2 and its tombstone) is '
    + 'VaultVersion, never a wrong passphrase. AAD label|data, label|pin, label|prf. The rows\' DEK, IVs and salts come from a '
    + 'fixed stream; a real vault draws them from the platform RNG. twelve words: the entropy opens to the 12 words, the UA key '
    + 'and the KEM key of keys.json / kem.json (mnemonic twelve_words).',
  vaults: vaultRows,
  refusals: vaultRefusals,
};

// --- zether.json (ua-rs-sign T14, spec §10.1): the Zether balance-cache box of src/zether.js sealBalanceCache / openBalanceCache
// under the conf key x (m/12381/60/<account>/7) of keys.json's mnemonics; the iv from a stream per box (the platform RNG in use) ---
const ZC = 'bls12381';
const ZC_INFO = utf8ToBytes('scaas-zether-balance-cache-v1');
const conf = (mnemonic, account) => deriveConfKey(SEEDS[mnemonic], { curve: ZC, coin: 60, account });
const cacheText = (entries) => JSON.stringify(entries, (_, v) => (typeof v === 'bigint' ? v.toString() : v));
const ZUA = H(keccak_256(utf8ToBytes('zether.json ua')));
const ZTOKEN = '0x5fbdb2315678afecb367f032d93f642f64180aa3';
const cacheBox = [];
for (const [id, mnemonic, account, entries] of [
  ['one entry, balance 2^54 - 1 (past 2^53)', 'pq_kat', 0, { [`${ZUA}:${ZTOKEN}`]: { ua: ZUA, token: ZTOKEN, accSeq: 3, balance: (1n << 54n) - 1n } }],
  ['empty cache', 'pq_kat', 0, {}],
  ['two entries, account 1', 'pq_kat', 1, {
    [`${ZUA}:${ZTOKEN}`]: { ua: ZUA, token: ZTOKEN, accSeq: 9, balance: 0n },
    [`${ZUA}:0x${'ee'.repeat(20)}`]: { ua: ZUA, token: `0x${'ee'.repeat(20)}`, accSeq: 1, balance: 12345n } }],
]) {
  const k = conf(mnemonic, account);
  const box = await withStream(`zc.${cacheBox.length}`, () => sealBalanceCache(ZC, k.x, entries));
  must(JSON.stringify(cacheText(await openBalanceCache(ZC, k.x, box))) === JSON.stringify(cacheText(entries)), `cache box ${id}`);
  cacheBox.push({ id, mnemonic, coin: 60, account, use: 7, Y: k.Y, UA: k.UA, entries: JSON.parse(cacheText(entries)),
    plaintext: H(utf8ToBytes(cacheText(entries))), box });
}
// the box key as zether.js derives it (HKDF-SHA256, no salt, info CACHE_INFO), checked against sealBalanceCache at the same iv
const cacheKey = (x) => hkdf(sha256, x, undefined, ZC_INFO, 32);
const c0 = cacheBox[0];
const x0 = conf(c0.mnemonic, c0.account).x;
must(JSON.stringify(await withStream('zc.0', () => boxSeal(cacheKey(x0), fromHex(c0.plaintext), `zether-cache:${ZC}`))) === JSON.stringify(c0.box), 'cache key');
const flipB64 = (s) => s.slice(0, -2) + (s.slice(-2) === 'AA' ? 'AQ' : 'AA');
const cacheRefusals = [
  { id: 'another account\'s key (account 1 opens account 0\'s box)', mnemonic: 'pq_kat', coin: 60, account: 1, use: 7, box: c0.box },
  { id: 'ciphertext changed', mnemonic: 'pq_kat', coin: 60, account: 0, use: 7, box: { ...c0.box, ct: flipB64(c0.box.ct) } },
  { id: 'iv changed', mnemonic: 'pq_kat', coin: 60, account: 0, use: 7, box: { ...c0.box, iv: flipB64(c0.box.iv) } },
  { id: 'AAD zether-cache:bn254 (sealed under another curve label)', mnemonic: 'pq_kat', coin: 60, account: 0, use: 7,
    box: await withStream('zc.aad', () => boxSeal(cacheKey(x0), fromHex(c0.plaintext), 'zether-cache:bn254')) },
];
for (const r of cacheRefusals) {
  must(Object.keys(await openBalanceCache(ZC, conf(r.mnemonic, r.account).x, r.box)).length === 0, `cache refusal ${r.id}`);
}
const zetherOut = {
  note: 'Generated by clients/clientkeys/scripts/ua-wallet-vectors.mjs (ua-rs-sign T14) from src/zether.js sealBalanceCache / '
    + 'openBalanceCache; never edit by hand. Box {iv, ct}: AES-256-GCM under HKDF-SHA256(x as 32 bytes, no salt, '
    + '"scaas-zether-balance-cache-v1", 32), AAD "zether-cache:<curve>", base64url without padding, plaintext the entries as '
    + 'JSON (balances as decimal strings). x is the Zether conf key m/12381/<coin>/<account>/<use> of the keys.json mnemonic; Y '
    + 'and UA its public key and UA. The rows\' ivs come from a fixed stream; a real box draws its iv from the platform RNG. '
    + 'cacheRefusals do not open (clientkeys: an empty cache; ua-rs: Aead).',
  curve: ZC,
  aad: `zether-cache:${ZC}`,
  cacheBox,
  cacheRefusals,
};

mkdirSync(OUT, { recursive: true });
writeFileSync(join(OUT, 'keys.json'), JSON.stringify(keys, null, 1) + '\n');
writeFileSync(join(OUT, 'sign.json'), JSON.stringify(sign, null, 1) + '\n');
writeFileSync(join(OUT, 'kem.json'), JSON.stringify(kem, null, 1) + '\n');
writeFileSync(join(OUT, 'seal.json'), JSON.stringify(sealOut, null, 1) + '\n');
writeFileSync(join(OUT, 'vault.json'), JSON.stringify(vaultOut, null, 1) + '\n');
writeFileSync(join(OUT, 'zether.json'), JSON.stringify(zetherOut, null, 1) + '\n');
console.log(`keys.json: ${uaRows.length} ua, ${nativeRows.length} native, ${keyRefusals.length} refusals; sign.json: ${uaSigRows.length} ua, `
  + `${memberRows.length} member, ${policy.length} policy, ${txRows.length} tx, ${msigCases.length} msig`);
console.log(`kem.json: ${kemRows.length} keys, ${kemRefusals.length} key refusals, ${encRows.length} encaps, ${encapsRefusals.length} encaps refusals, `
  + `${decapsRows.length} decaps; seal.json: ${sealRows.length} seal, ${sealRefusals.length + sealArgRefusals.length} refusals, ${containerRows.length} containers, `
  + `${acceptance.length} acceptance, ${replay.length + rollback.length} replay; vault.json: ${vaultRows.length} vaults, ${vaultRefusals.length} refusals`);
