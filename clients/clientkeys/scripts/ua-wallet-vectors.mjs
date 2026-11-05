// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Generates smartcontracts/vectors/ua/keys.json and sign.json (ua-rs-sign T1a, spec §11, plan MD-7): the UA keys of src/uakey.js
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
import { hex, fromHex, keccak_256, utf8ToBytes, concatBytes, b64url, abiEncode } from '../src/bytes.js';
import * as ua from '../src/ua.js';
import * as evm from '../src/evm.js';
import { verify } from '../src/ua-verify.js';
import { NETWORKS, wordsToEntropy, seedFromEntropy, seedFromWords, deriveKey, signTyped, signTransaction } from '../src/seed.js';
import { eip2333 } from '../src/zether.js';
import { PQ_KINDS, pqMessage } from '../src/pq.js';
import {
  deriveUAKey, uaKeyPath, signUAVector, sigRole, webauthnChallenge, webauthnAssertion, msigMemberSigs,
} from '../src/uakey.js';
import { PQ_MNEMONIC } from './ua-signers.mjs';

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
  const cd = cdj(opts.challenge ?? expected, opts);
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
].map(([c, a]) => {
  const e = refusedBy(() => webauthnAssertion(Object.fromEntries(['keyData', 'expectedChallenge', 'authData', 'clientDataJSON', 'r', 's']
    .map((n) => [n, fromHex(a[n])]))));
  must(e?.code === 'WebAuthnAssertion', c);
  return { case: c, ...a, error: 'WebAuthnAssertion' };
});

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
    + 'expect) over the check* functions. tx: evmTransaction types 0-3 (no type 4), signTransaction. webauthn: webauthnAssertion '
    + 'against the expected challenge. msig: msigMemberSigs, minimal at both levels. chainSeparation (owner 2026-11-05): one message and '
    + 'one key on chain 7622 (SCaaS testnet) and 22776 (SCaaS mainnet): a UAMetaTransfer in a token domain with chainId (UA key 0x0108, '
    + 'signUA metatx) and EIP-155 transactions of types 0 and 2 (the EVM key) give other digests and signatures per chain; refusals: a '
    + 'signature for one chain does not verify against the other\'s digest; portable: a record in the portable domain (no chainId) '
    + 'is one digest and one signature on both.',
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
};

mkdirSync(OUT, { recursive: true });
writeFileSync(join(OUT, 'keys.json'), JSON.stringify(keys, null, 1) + '\n');
writeFileSync(join(OUT, 'sign.json'), JSON.stringify(sign, null, 1) + '\n');
console.log(`keys.json: ${uaRows.length} ua, ${nativeRows.length} native, ${keyRefusals.length} refusals; sign.json: ${uaSigRows.length} ua, `
  + `${memberRows.length} member, ${policy.length} policy, ${txRows.length} tx, ${msigCases.length} msig`);
