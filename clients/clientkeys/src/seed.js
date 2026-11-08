// Seed-words wallet (R32): BIP-39 24 words on the device, BIP-32 (secp256k1) and SLIP-10 (ed25519)
// derivation per SLIP-44, per-network addresses, signing of the same digests as every other signer.
// The mnemonic, seed and private keys never leave this module's caller (the browser tab).
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { HDKey } from '@scure/bip32';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha512, sha256 } from '@noble/hashes/sha2.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { bech32, base32, base58 } from '@scure/base';
import { concatBytes, utf8ToBytes, bytesToHex, hex, wipe } from './bytes.js';
import { evmAddress, hashTypedData, keyProofMessage, evmTransaction, signedTransaction } from './evm.js';

const HARDENED = 0x80000000;

/** SLIP-44 paths (round-3 design §C.2). `i` is the account index chosen by the user. */
export const NETWORKS = {
  evm: { curve: 'secp256k1', path: (i) => `m/44'/60'/0'/0/${i}` },
  cosmos: { curve: 'secp256k1', path: (i) => `m/44'/118'/0'/0/${i}` },
  hedera_ecdsa: { curve: 'secp256k1', path: (i) => `m/44'/3030'/0'/0/${i}` },
  hedera_ed25519: { curve: 'ed25519', path: (i) => `m/44'/3030'/0'/0'/${i}'` },
  sui: { curve: 'ed25519', path: (i) => `m/44'/784'/${i}'/0'/0'` },
  stellar: { curve: 'ed25519', path: (i) => `m/44'/148'/${i}'` },
  ton: { curve: 'ed25519', path: (i) => `m/44'/607'/${i}'` },
  aptos: { curve: 'ed25519', path: (i) => `m/44'/637'/${i}'/0'/0'` },
  solana: { curve: 'ed25519', path: (i) => `m/44'/501'/${i}'/0'` },
};

// ------------------------------------------------------------------ BIP-39

export function normalizeMnemonic(text) {
  return String(text).normalize('NFKD').trim().toLowerCase().split(/\s+/).join(' ');
}

/** 24 words = 256 bits of entropy from the platform CSPRNG. Returns the entropy, not a string. */
export function generateEntropy() {
  return crypto.getRandomValues(new Uint8Array(32));
}

export function entropyToWords(entropy) {
  return bip39.entropyToMnemonic(entropy, wordlist).split(' ');
}

/** Import: any valid BIP-39 length (12–24 words); the checksum must hold. */
export function wordsToEntropy(text) {
  const m = normalizeMnemonic(text);
  if (!bip39.validateMnemonic(m, wordlist)) throw new Error('These words are not a valid recovery phrase (BIP-39 checksum).');
  return bip39.mnemonicToEntropy(m, wordlist);
}

export function seedFromEntropy(entropy, passphrase = '') {
  return bip39.mnemonicToSeedSync(bip39.entropyToMnemonic(entropy, wordlist), passphrase);
}

export function seedFromWords(text, passphrase = '') {
  return bip39.mnemonicToSeedSync(normalizeMnemonic(text), passphrase);
}

// ------------------------------------------------------------------ derivation

// SLIP-10 curves: the HMAC key of the master step and the group order (ed25519: none, every IL is a key).
const SLIP10 = { ed25519: { key: 'ed25519 seed', n: null }, nist256p1: { key: 'Nist256p1 seed', n: p256.Point.Fn.ORDER } };
const big = (b) => BigInt('0x' + (bytesToHex(b) || '0'));
const b32 = (v) => { const o = new Uint8Array(32); for (let i = 31; i >= 0; i--, v >>= 8n) o[i] = Number(v & 255n); return o; };

/** SLIP-10 for ed25519 (hardened steps only) and nist256p1 (P-256, the UA tree's 0x0101 keys, which use hardened steps only;
 *  a non-hardened step hashes the compressed public key, as SLIP-10 defines it), with SLIP-10's retries for nist256p1 (master:
 *  IL = 0 or ≥ n → I = HMAC(key, I); child: IL ≥ n or k = 0 → data = 0x01 ‖ IR ‖ ser32(i)). */
export function slip10(curve, seed, path) {
  const c = SLIP10[curve];
  if (!c) throw new Error(`SLIP-10 curve ${curve} is not supported here`);
  const segs = path.split('/');
  if (segs.shift() !== 'm') throw new Error(`bad path ${path}`);
  const key = utf8ToBytes(c.key);
  let I = hmac(sha512, key, seed);
  while (c.n && (big(I.subarray(0, 32)) === 0n || big(I.subarray(0, 32)) >= c.n)) { const next = hmac(sha512, key, I); wipe(I); I = next; }
  for (const seg of segs) {
    const hard = seg.endsWith("'");
    if (!hard && !c.n) throw new Error(`${curve} derivation is hardened-only: ${path}`);
    if (!/^[0-9]+$/.test(hard ? seg.slice(0, -1) : seg) || Number(hard ? seg.slice(0, -1) : seg) >= HARDENED) throw new Error(`bad path ${path}`);
    const idx = (Number(hard ? seg.slice(0, -1) : seg) + (hard ? HARDENED : 0)) >>> 0;
    const ser = new Uint8Array([idx >>> 24, (idx >>> 16) & 255, (idx >>> 8) & 255, idx & 255]);
    let data = hard ? concatBytes(new Uint8Array([0]), I.subarray(0, 32), ser) : concatBytes(p256.getPublicKey(I.slice(0, 32), true), ser);
    for (;;) {
      const next = hmac(sha512, I.subarray(32), data);
      wipe(data);
      if (!c.n) { wipe(I); I = next; break; }
      const il = big(next.subarray(0, 32));
      const k = (il + big(I.subarray(0, 32))) % c.n;
      if (il < c.n && k !== 0n) { wipe(I); I = concatBytes(b32(k), next.subarray(32)); wipe(next); break; }
      data = concatBytes(new Uint8Array([1]), next.subarray(32), ser);
      wipe(next);
    }
  }
  const out = { privateKey: I.slice(0, 32), chainCode: I.slice(32) };
  wipe(I);
  return out;
}

/** SLIP-10 for ed25519: hardened steps only. */
export const slip10Ed25519 = (seed, path) => slip10('ed25519', seed, path);

function crc16xmodem(bytes) {
  let crc = 0;
  for (const b of bytes) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  return crc;
}

/** Stellar StrKey: G… (version 6<<3) for public keys, S… (18<<3) for secret seeds. */
export function strkey(version, payload) {
  const body = concatBytes(new Uint8Array([version]), payload);
  const crc = crc16xmodem(body);
  return base32.encode(concatBytes(body, new Uint8Array([crc & 255, crc >> 8])));
}

function describe(network, curve, privateKey) {
  if (curve === 'secp256k1') {
    const compressed = secp256k1.getPublicKey(privateKey, true);
    const uncompressed = secp256k1.getPublicKey(privateKey, false);
    const pub = bytesToHex(compressed);
    if (network === 'evm') return { publicKey: pub, address: evmAddress(uncompressed) };
    if (network === 'cosmos') {
      return { publicKey: pub, address: bech32.encode('cosmos', bech32.toWords(ripemd160(sha256(compressed)))) };
    }
    // Hedera ECDSA: DER public key as the SDK prints it (and as the account alias), plus the EVM alias.
    return { publicKey: pub, publicKeyDer: '302d300706052b8104000a032200' + pub, address: evmAddress(uncompressed) };
  }
  const pk = ed25519.getPublicKey(privateKey);
  const pub = bytesToHex(pk);
  if (network === 'sui') return { publicKey: pub, address: hex(blake2b(concatBytes(new Uint8Array([0]), pk), { dkLen: 32 })) };
  // Aptos legacy Ed25519 auth key = address: sha3_256(pk ‖ 0x00).
  if (network === 'aptos') return { publicKey: pub, address: hex(sha3_256(concatBytes(pk, new Uint8Array([0])))) };
  if (network === 'stellar') return { publicKey: pub, address: strkey(6 << 3, pk) };
  if (network === 'hedera_ed25519') return { publicKey: pub, publicKeyDer: '302a300506032b6570032100' + pub };
  if (network === 'solana') return { publicKey: pub, address: base58.encode(pk) };
  // TON: public key only. A W5R1 address needs the wallet code cell + BoC hashing — not shipped (recorded).
  return { publicKey: pub };
}

/** Key `i` of `network` from a BIP-39 seed. Caller wipes `privateKey` after use. `coinType`: the chain's
 *  SLIP-44 coin type in place of the network's (Pi Network = `stellar` with 314159); null ⇒ the default. */
export function deriveKey(seed, network, i = 0, { coinType = null } = {}) {
  const net = NETWORKS[network];
  if (!net) throw new Error(`unknown network ${network}`);
  if (!Number.isInteger(i) || i < 0 || i >= HARDENED) throw new Error(`bad index ${i}: need an integer in [0, 2^31)`);
  let path = net.path(i);
  if (coinType != null) {
    if (!Number.isInteger(coinType) || coinType < 0 || coinType >= HARDENED) throw new Error(`bad coin type ${coinType}`);
    path = path.split('/').map((seg, n) => (n === 2 ? `${coinType}'` : seg)).join('/');
  }
  let privateKey;
  if (net.curve === 'secp256k1') {
    const node = HDKey.fromMasterSeed(seed).derive(path);
    privateKey = node.privateKey.slice();
    node.wipePrivateData();
  } else {
    const n = slip10Ed25519(seed, path);
    privateKey = n.privateKey;
    wipe(n.chainCode);
  }
  return { network, curve: net.curve, path, privateKey, ...describe(network, net.curve, privateKey) };
}

/** An existing key of `network` (ua-rs-sign T20c; ua-rs `import_native_key`): a 32-byte secp256k1 secret for `evm`, `cosmos`,
 *  `hedera_ecdsa`, a 32-byte ed25519 seed for the others, described as `deriveKey` describes a derived one. Its native use is
 *  that network's only; as a UA it takes the derived kind of its own scheme (uakey.js `importedUAKey`). Caller wipes `privateKey`. */
export function importKey(network, secret) {
  const net = Object.hasOwn(NETWORKS, network) ? NETWORKS[network] : null;
  if (!net) throw new Error(`unknown network ${network}`);
  if (!(secret instanceof Uint8Array) || secret.length !== 32) throw new Error('an imported key is 32 bytes');
  const privateKey = secret.slice();
  return { network, curve: net.curve, path: null, privateKey, ...describe(network, net.curve, privateKey) };
}

/** Sign EIP-712 typed data: the digest is computed here (`hashTypedData`, preimage `0x1901 ‖ …`), so it can never be
 *  an EIP-7702 authorization (`0x05 ‖ rlp(…)`) or a transaction hash. Check `td` first (`checkPayment`, `checkOp`, `checkCall`, …). */
export function signTyped(key, td) {
  return sign(key, hashTypedData(td));
}

/** Sign an EVM transaction of type 0–3 (`evmTransaction`: named fields, `chainId` explicit, EIP-155 on type 0; type 4 /
 *  EIP-7702 cannot be built, CLI-SGN-40) with a secp256k1 key: RFC 6979 (`extraEntropy: false`), low-s. Returns
 *  {type, sighash, yParity, r, s, v (type 0: chainId·2 + 35 + yParity), raw (the signed envelope)}. */
export function signTransaction(key, tx) {
  if (key.curve !== 'secp256k1') throw new Error('Refusing to sign: an EVM transaction needs a secp256k1 key.');
  const t = evmTransaction(tx);
  const rec = secp256k1.sign(t.sighash, key.privateKey, { prehash: false, lowS: true, extraEntropy: false, format: 'recovered' });
  const sig = { yParity: rec[0], r: rec.slice(1, 33), s: rec.slice(33, 65) };
  return { type: t.type, sighash: t.sighash, ...sig, v: t.type === 0 ? Number(BigInt(t.fields.chainId) * 2n + 35n) + sig.yParity : undefined,
    raw: signedTransaction(t, sig) };
}

/** Sign the key-possession proof for `challenge` (`keyProofMessage`, Odoo `key_proof_message`). */
export function signKeyProof(key, challenge) {
  return sign(key, keyProofMessage(challenge));
}

/** Sign a raw 32-byte digest (or batch root). DANGER: a raw digest hides its preimage — it may be an EIP-7702
 *  authorization (`keccak256(0x05 ‖ rlp([chainId, address, nonce]))`), which hands the account to a sweeper, or a
 *  transaction hash. Owner rule 2026-10-30: never sign a 7702 authorization. Refused unless the caller opts in with
 *  `{ allowRawDigest: true }` and itself built the digest from a checked SCaaS message (a Merkle batch root, a digest a
 *  `check*` function returned); prefer `signTyped` / `signKeyProof`. secp256k1 ⇒ r‖s‖v (v = 27|28, low-s);
 *  ed25519 ⇒ 64 bytes. */
export function signDigest(key, digest, { allowRawDigest = false } = {}) {
  if (allowRawDigest !== true) throw new Error('signDigest: raw digest refused; use signTyped / signKeyProof, or pass { allowRawDigest: true }');
  return sign(key, digest);
}

function sign(key, digest) {
  if (key.curve === 'secp256k1') {
    const rec = secp256k1.sign(digest, key.privateKey, { prehash: false, lowS: true, extraEntropy: false, format: 'recovered' });
    return concatBytes(rec.subarray(1), new Uint8Array([27 + rec[0]]));
  }
  return ed25519.sign(digest, key.privateKey);
}
