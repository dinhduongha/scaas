// Seed-words wallet (R32): BIP-39 24 words on the device, BIP-32 (secp256k1) and SLIP-10 (ed25519)
// derivation per SLIP-44, per-network addresses, signing of the same digests as every other signer.
// The mnemonic, seed and private keys never leave this module's caller (the browser tab).
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { HDKey } from '@scure/bip32';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha512, sha256 } from '@noble/hashes/sha2.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { bech32, base32 } from '@scure/base';
import { concatBytes, utf8ToBytes, bytesToHex, hex, wipe } from './bytes.js';
import { evmAddress, hashTypedData, keyProofMessage } from './evm.js';

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

/** SLIP-10 for ed25519: hardened steps only. */
export function slip10Ed25519(seed, path) {
  const segs = path.split('/');
  if (segs.shift() !== 'm') throw new Error(`bad path ${path}`);
  let I = hmac(sha512, utf8ToBytes('ed25519 seed'), seed);
  for (const seg of segs) {
    if (!seg.endsWith("'")) throw new Error(`ed25519 derivation is hardened-only: ${path}`);
    const idx = (Number(seg.slice(0, -1)) + HARDENED) >>> 0;
    const data = concatBytes(new Uint8Array([0]), I.subarray(0, 32),
                             new Uint8Array([idx >>> 24, (idx >>> 16) & 255, (idx >>> 8) & 255, idx & 255]));
    const next = hmac(sha512, I.subarray(32), data);
    wipe(I, data);
    I = next;
  }
  const out = { privateKey: I.slice(0, 32), chainCode: I.slice(32) };
  wipe(I);
  return out;
}

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
  // TON: public key only. A W5R1 address needs the wallet code cell + BoC hashing — not shipped (recorded).
  return { publicKey: pub };
}

/** Key `i` of `network` from a BIP-39 seed. Caller wipes `privateKey` after use. `coinType`: the chain's
 *  SLIP-44 coin type in place of the network's (Pi Network = `stellar` with 314159); null ⇒ the default. */
export function deriveKey(seed, network, i = 0, { coinType = null } = {}) {
  const net = NETWORKS[network];
  if (!net) throw new Error(`unknown network ${network}`);
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

/** Sign EIP-712 typed data: the digest is computed here (`hashTypedData`, preimage `0x1901 ‖ …`), so it can never be
 *  an EIP-7702 authorization (`0x05 ‖ rlp(…)`) or a transaction hash. Check `td` first (`checkPayment`, `checkCall`, …). */
export function signTyped(key, td) {
  return sign(key, hashTypedData(td));
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
    const rec = secp256k1.sign(digest, key.privateKey, { prehash: false, format: 'recovered' });
    return concatBytes(rec.subarray(1), new Uint8Array([27 + rec[0]]));
  }
  return ed25519.sign(digest, key.privateKey);
}
