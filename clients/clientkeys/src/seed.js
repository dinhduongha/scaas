// Seed-words wallet (R32): BIP-39 24 words on the device, BIP-32 (secp256k1) and SLIP-10 (ed25519)
// derivation per SLIP-44, per-network addresses, signing of the same digests as every other signer.
// The mnemonic, seed and private keys never leave this module's caller (the browser tab).
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { HDKey } from '@scure/bip32';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha512, sha256 } from '@noble/hashes/sha2.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { bech32, bech32m, base32, base58 } from '@scure/base';
import { concatBytes, utf8ToBytes, bytesToHex, hex, wipe } from './bytes.js';
import { evmAddress, hashTypedData, keyProofMessage, evmTransaction, signedTransaction } from './evm.js';
import { UAError } from './ua.js';
import { sr25519Sign } from './substrate.js';

const fail = (code, reason) => { throw new UAError(code, reason); };

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

/** The native networks of an app's native backend (CLI-SGN-52; spec 2026-11-17-ua-rs-native §4.1): kept apart from NETWORKS
 *  (the nine of keys.json, of importKey and of the imported UA), so none of them has an import, an imported UA or a key proof.
 *  Bitcoin: `k` 0 receive, 1 change; coin type 0 (mainnet) or 1 (testnets) only. NEAR: no coin-type override (it would alias
 *  `stellar` / `ton`). Polkadot: sr25519 from the entropy and the passphrase, `polkadotKey` (deriveKey refuses it). */
export const NATIVE_NETWORKS = {
  bitcoin_p2wpkh: { curve: 'secp256k1', path: (i, k) => `m/84'/0'/0'/${k}/${i}` },
  bitcoin_p2tr: { curve: 'secp256k1', path: (i, k) => `m/86'/0'/0'/${k}/${i}` },
  near: { curve: 'ed25519', path: (i) => `m/44'/397'/${i}'` },
  polkadot: { curve: 'sr25519', path: null },
};
const BITCOIN = new Set(['bitcoin_p2wpkh', 'bitcoin_p2tr']);
const native = (network) => Object.hasOwn(NATIVE_NETWORKS, network);

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

/** BIP-85's BIP-39 application (scaas-sdk spec §6.4): the child mnemonic `index` of `words` words of a BIP-32 root (`seed`, the
 *  64-byte BIP-39 seed, or an HDKey): path m/83696968'/39'/0'/<words>'/<index>' (English, language 0), entropy = the first
 *  words·4/3 bytes of HMAC-SHA512("bip-entropy-from-k", k). The SDK derives 24-word children only. `Argument` for an index
 *  outside [0, 2^31) or a word count outside {12, 15, 18, 21, 24}. The caller wipes `entropy`. */
export function bip85Child(seed, index, words = 24) {
  if (!Number.isInteger(index) || index < 0 || index >= HARDENED) fail('Argument', 'BIP-85 index outside [0, 2^31)');
  if (![12, 15, 18, 21, 24].includes(words)) fail('Argument', 'BIP-85 words outside 12, 15, 18, 21, 24');
  const root = seed instanceof HDKey ? seed : HDKey.fromMasterSeed(seed);
  const node = root.derive(`m/83696968'/39'/0'/${words}'/${index}'`);
  try {
    const entropy = hmac(sha512, utf8ToBytes('bip-entropy-from-k'), node.privateKey).slice(0, (words * 4) / 3);
    return { entropy, words: entropyToWords(entropy) };
  } finally {
    node.wipePrivateData();
  }
}

/** The BIP-32 master key's fingerprint (the first 4 bytes of HASH160 of its compressed public key) as 8 lower-case hex digits:
 *  a seed's name in the scaas-sdk keystore, so a second import of the same words is found without unlocking (scaas-sdk spec
 *  §6.1). `seed` is the 64-byte BIP-39 seed (the main set: the empty BIP-39 passphrase). */
export function masterFingerprint(seed) {
  return HDKey.fromMasterSeed(seed).fingerprint.toString(16).padStart(8, '0');
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

/** BIP-173 / BIP-350 segwit address: bech32 for witness v0, bech32m for v1. */
export const segwitAddress = (hrp, version, program) =>
  (version === 0 ? bech32 : bech32m).encode(hrp, [version, ...bech32.toWords(program)]);

const SECP_N = secp256k1.Point.Fn.ORDER;
const TAG_TAPTWEAK = sha256(utf8ToBytes('TapTweak'));
/** The BIP-86 key-path tweak of an x-only internal key (BIP-341, no script tree, so no Merkle root): t = H_TapTweak(x(P)),
 *  Q = lift_x(x(P)) + t·G. One function for the address and the signer; t ≥ n or Q = ∞ throws. */
export function taprootTweak(internalX) {
  if (!(internalX instanceof Uint8Array) || internalX.length !== 32) fail('Argument', 'an x-only key is 32 bytes');
  const tweak = sha256(concatBytes(TAG_TAPTWEAK, TAG_TAPTWEAK, internalX));
  const t = big(tweak);
  if (t >= SECP_N) fail('Argument', 'tweak out of range');
  const Q = secp256k1.Point.fromHex('02' + bytesToHex(internalX)).add(secp256k1.Point.BASE.multiply(t));
  const q = Q.toBytes(true);
  return { tweak, outputKey: q.slice(1), oddY: q[0] === 3 };
}

function describeBitcoin(network, privateKey, coin) {
  const compressed = secp256k1.getPublicKey(privateKey, true);
  const hrp = coin === 1 ? 'tb' : 'bc';
  if (network === 'bitcoin_p2wpkh') {
    const program = ripemd160(sha256(compressed));
    return { publicKey: bytesToHex(compressed), address: segwitAddress(hrp, 0, program), witnessProgram: { version: 0, program: bytesToHex(program) } };
  }
  const internal = compressed.slice(1);
  const t = taprootTweak(internal);
  return { publicKey: bytesToHex(compressed), internalKey: bytesToHex(internal), tweak: bytesToHex(t.tweak), outputKey: bytesToHex(t.outputKey),
    address: segwitAddress(hrp, 1, t.outputKey), witnessProgram: { version: 1, program: bytesToHex(t.outputKey) } };
}

function describe(network, curve, privateKey, coin = null) {
  if (BITCOIN.has(network)) return describeBitcoin(network, privateKey, coin);
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
  // NEAR: the implicit account id (64 lower-case hex) and the display text `ed25519:<base58>`.
  if (network === 'near') return { publicKey: pub, address: pub, publicKeyText: 'ed25519:' + base58.encode(pk) };
  // TON: public key only. A W5R1 address needs the wallet code cell + BoC hashing — not shipped (recorded).
  return { publicKey: pub };
}

/** Key `i` of `network` (NETWORKS or NATIVE_NETWORKS) from a BIP-39 seed. Caller wipes `privateKey` after use. `coinType`: the
 *  chain's SLIP-44 coin type in place of the network's (Pi Network = `stellar` with 314159); null ⇒ the default; Bitcoin 0 or 1
 *  only, NEAR none. `change`: Bitcoin only, 0 (receive, the default) or 1 (change). */
export function deriveKey(seed, network, i = 0, { coinType = null, change = null } = {}) {
  const net = Object.hasOwn(NETWORKS, network) ? NETWORKS[network] : native(network) ? NATIVE_NETWORKS[network] : null;
  if (!net) throw new Error(`unknown network ${network}`);
  if (network === 'polkadot') fail('Argument', 'polkadot: use polkadotKey(entropy, passphrase, path)');
  if (!Number.isInteger(i) || i < 0 || i >= HARDENED) throw new Error(`bad index ${i}: need an integer in [0, 2^31)`);
  const btc = BITCOIN.has(network);
  if (change != null && !(btc && (change === 0 || change === 1))) fail('Argument', 'change: 0 or 1, Bitcoin only');
  if (coinType != null && btc && coinType !== 0 && coinType !== 1) fail('Argument', 'Bitcoin coin type: 0 or 1');
  if (coinType != null && network === 'near') fail('Argument', 'near takes no coin-type override');
  let path = net.path(i, change ?? 0);
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
  return { network, curve: net.curve, path, privateKey, ...describe(network, net.curve, privateKey, coinType) };
}

/** An existing key of `network` (ua-rs-sign T20c; ua-rs `import_native_key`): a 32-byte secp256k1 secret for `evm`, `cosmos`,
 *  `hedera_ecdsa`, a 32-byte ed25519 seed for the others, described as `deriveKey` describes a derived one. Its native use is
 *  that network's only; as a UA it takes the derived kind of its own scheme (uakey.js `importedUAKey`). Caller wipes `privateKey`. */
export function importKey(network, secret) {
  if (native(network)) fail('Argument', 'no import on a native network of NATIVE_NETWORKS');
  const net = Object.hasOwn(NETWORKS, network) ? NETWORKS[network] : null;
  if (!net) throw new Error(`unknown network ${network}`);
  if (!(secret instanceof Uint8Array) || secret.length !== 32) throw new Error('an imported key is 32 bytes');
  const privateKey = secret.slice();
  return { network, curve: net.curve, path: null, privateKey, ...describe(network, net.curve, privateKey) };
}

/** Sign EIP-712 typed data: the digest is computed here (`hashTypedData`, preimage `0x1901 ‖ …`), so it can never be
 *  an EIP-7702 authorization (`0x05 ‖ rlp(…)`) or a transaction hash. Check `td` first (`checkPayment`, `checkOp`, `checkCall`, …). */
export function signTyped(key, td) {
  if (native(key.network)) fail('Argument', 'no EIP-712 on a native network of NATIVE_NETWORKS');
  return sign(key, hashTypedData(td));
}

/** Sign an EVM transaction of type 0–3 (`evmTransaction`: named fields, `chainId` explicit, EIP-155 on type 0; type 4 /
 *  EIP-7702 cannot be built, CLI-SGN-40) with a secp256k1 key: RFC 6979 (`extraEntropy: false`), low-s. Returns
 *  {type, sighash, yParity, r, s, v (type 0: chainId·2 + 35 + yParity), raw (the signed envelope)}. */
export function signTransaction(key, tx) {
  if (native(key.network)) fail('Argument', 'no EVM transaction on a native network of NATIVE_NETWORKS');
  if (key.curve !== 'secp256k1') throw new Error('Refusing to sign: an EVM transaction needs a secp256k1 key.');
  const t = evmTransaction(tx);
  const rec = secp256k1.sign(t.sighash, key.privateKey, { prehash: false, lowS: true, extraEntropy: false, format: 'recovered' });
  const sig = { yParity: rec[0], r: rec.slice(1, 33), s: rec.slice(33, 65) };
  return { type: t.type, sighash: t.sighash, ...sig, v: t.type === 0 ? Number(BigInt(t.fields.chainId) * 2n + 35n) + sig.yParity : undefined,
    raw: signedTransaction(t, sig) };
}

/** Sign the key-possession proof for `challenge` (`keyProofMessage`, Odoo `key_proof_message`). */
export function signKeyProof(key, challenge) {
  if (native(key.network)) fail('Argument', 'no key proof on a native network of NATIVE_NETWORKS');
  return sign(key, keyProofMessage(challenge));
}

/** Sign a raw 32-byte digest (or batch root). DANGER: a raw digest hides its preimage — it may be an EIP-7702
 *  authorization (`keccak256(0x05 ‖ rlp([chainId, address, nonce]))`), which hands the account to a sweeper, or a
 *  transaction hash. Owner rule 2026-10-30: never sign a 7702 authorization. Refused unless the caller opts in with
 *  `{ allowRawDigest: true }` and itself built the digest: from a checked SCaaS message (a Merkle batch root, a digest a
 *  `check*` function returned), or a native chain's preimage only as CLI-SGN-54 (built in-process from named fields by its own
 *  encoder, shown decoded); never an EVM transaction hash or an EIP-7702 authorization raw (EVM transactions: `signTransaction`).
 *  Prefer `signTyped` / `signKeyProof`. secp256k1 ⇒ r‖s‖v (v = 27|28, low-s); ed25519 ⇒ 64 bytes; `bitcoin_p2tr` ⇒ BIP-340
 *  over the tweaked key; sr25519 ⇒ 64 bytes (the digest as the message). `digest`: exactly 32 bytes (Argument otherwise, as
 *  ua-rs's `&[u8; 32]`; a longer preimage goes through `signMessage` and its checks). `aux`: fixed randomness for the generator
 *  only (Taproot `aux`, sr25519 `r`), else the CSPRNG. */
export function signDigest(key, digest, { allowRawDigest = false, aux } = {}) {
  if (allowRawDigest !== true) throw new Error('signDigest: raw digest refused; use signTyped / signKeyProof, or pass { allowRawDigest: true }');
  if (!(digest instanceof Uint8Array) || digest.length !== 32) fail('Argument', 'digest: 32 bytes');
  if (key.network === 'bitcoin_p2tr') return signTaproot(key.privateKey, digest, aux);
  if (key.curve === 'sr25519') return sr25519Sign(key.privateKey, digest, aux);
  return sign(key, digest);
}

/** The raw-message bound (CLI-UAL-44): Aptos's 64 KiB transaction limit plus its prefix, with room. */
export const MAX_RAW_MESSAGE = 131072;
// the off-chain envelopes SCaaS families verify (Solana OCMS v1, Aptos AIP-62 fullMessage): never through the raw path
const ENVELOPES = [concatBytes(new Uint8Array([0xff]), utf8ToBytes('solana offchain')), utf8ToBytes('APTOS\n')];

/** Sign a native chain's message (1 to 131,072 bytes) with an Ed25519 or sr25519 native key, behind the same opt-in as
 *  `signDigest` (CLI-SGN-54: a transaction preimage the caller's encoder built; an off-chain text only inside the chain's own
 *  envelope). Refused (Argument): no opt-in, an empty or over-long message, a message starting with an envelope a SCaaS family
 *  verifies (`0xff ‖ "solana offchain"`, `"APTOS\n"`), a secp256k1 or Taproot key. ed25519 RFC 8032; sr25519 context
 *  "substrate" (`aux`: the generator's fixed randomness). */
export function signMessage(key, message, { allowRawDigest = false, aux } = {}) {
  if (allowRawDigest !== true) fail('Argument', 'signMessage: refused without { allowRawDigest: true }');
  if (!(message instanceof Uint8Array) || message.length < 1 || message.length > MAX_RAW_MESSAGE) fail('Argument', 'message: 1 to 131072 bytes');
  if (ENVELOPES.some((p) => message.length >= p.length && p.every((b, i) => message[i] === b))) fail('Argument', 'message: a SCaaS off-chain envelope');
  if (key.curve === 'ed25519') return ed25519.sign(message, key.privateKey);
  if (key.curve === 'sr25519') return sr25519Sign(key.privateKey, message, aux);
  return fail('Argument', 'signMessage: Ed25519 and sr25519 keys only');
}

// The envelope calls (spec 2026-11-17-ua-rs-native §8.1, CLI-UAL-63 (13)): the chain's signing prefix or hash wrapper over the
// bytes the app's encoder made, each on its own network only, behind the same opt-in; ed25519 over the result.
function envelope(key, network, tx, allowRawDigest, build) {
  if (allowRawDigest !== true) fail('Argument', 'refused without { allowRawDigest: true }');
  if (key.network !== network) fail('Argument', `a ${network} key only`);
  if (!(tx instanceof Uint8Array) || tx.length < 1 || tx.length > MAX_RAW_MESSAGE) fail('Argument', 'transaction: 1 to 131072 bytes');
  return ed25519.sign(build(tx), key.privateKey);
}
// the lowest prefix NEP-461 reserves: 2^30 to 2^31 − 1 on-chain actions (NEP-366), 2^31 and up off-chain messages (NEP-413)
const NEP461_MIN = 2 ** 30;
/** NEAR: ed25519 over sha256(Borsh(Transaction)). Argument for a NEP-461 tagged payload (first four bytes, little-endian, the
 *  u32 at or above 2^30: NEP-461's reserved ranges); a Transaction starts with its signer_id's Borsh length, at most 64. */
export const signNearTransaction = (key, txBorsh, { allowRawDigest = false } = {}) => envelope(key, 'near', txBorsh, allowRawDigest, (t) => {
  if (t.length >= 4 && new DataView(t.buffer, t.byteOffset, 4).getUint32(0, true) >= NEP461_MIN) fail('Argument', 'a NEP-461 tagged payload');
  return sha256(t);
});
/** Sui: ed25519 over blake2b-256(intent 0x00 0x00 0x00 ‖ TransactionData BCS). */
export const signSuiTransaction = (key, txBcs, { allowRawDigest = false } = {}) =>
  envelope(key, 'sui', txBcs, allowRawDigest, (t) => blake2b(concatBytes(new Uint8Array(3), t), { dkLen: 32 }));
/** Stellar: ed25519 over sha256(networkId ‖ ENVELOPE_TYPE_TX (0x00000002) ‖ Transaction XDR); networkId = sha256(passphrase), 32 bytes. */
export function signStellarTransaction(key, networkId, txXdr, { allowRawDigest = false } = {}) {
  if (!(networkId instanceof Uint8Array) || networkId.length !== 32) fail('Argument', 'networkId: 32 bytes');
  return envelope(key, 'stellar', txXdr, allowRawDigest, (t) => sha256(concatBytes(networkId, new Uint8Array([0, 0, 0, 2]), t)));
}
/** Hedera Ed25519: ed25519 over the transaction's bodyBytes as given. */
export const signHederaTransaction = (key, bodyBytes, { allowRawDigest = false } = {}) => envelope(key, 'hedera_ed25519', bodyBytes, allowRawDigest, (t) => t);

/** BIP-86 key-path signature: d = d0 or n − d0 (even y of P), BIP-340 with d + t mod n, then verified under x(Q). `aux`: the
 *  generator's fixed bytes, else 32 fresh bytes from the platform CSPRNG. The tweaked key's bytes are wiped on every exit; the
 *  BigInt `d` cannot be wiped in JavaScript (a known limit of this reference, T13 C3; ua-rs wipes every scalar). */
function signTaproot(d0, digest, aux) {
  const P = secp256k1.getPublicKey(d0, true);
  let d = big(d0);
  if (P[0] === 3) d = SECP_N - d;
  const t = taprootTweak(P.slice(1));
  const tweaked = b32((d + big(t.tweak)) % SECP_N);
  const a = aux ?? crypto.getRandomValues(new Uint8Array(32));
  let sig;
  try { sig = schnorr.sign(digest, tweaked, a); } finally { wipe(tweaked); }
  if (!schnorr.verify(sig, digest, t.outputKey)) throw new Error('Taproot signature failed its own check');
  return sig;
}

function sign(key, digest) {
  if (key.curve === 'secp256k1') {
    const rec = secp256k1.sign(digest, key.privateKey, { prehash: false, lowS: true, extraEntropy: false, format: 'recovered' });
    return concatBytes(rec.subarray(1), new Uint8Array([27 + rec[0]]));
  }
  return ed25519.sign(digest, key.privateKey);
}
