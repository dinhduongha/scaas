// EVM pieces: EIP-712 digests, addresses, SmartKeyAccount key/salt/CREATE2, Merkle batch.
import {
  keccak_256, sha256, concatBytes, utf8ToBytes, bytesToHex, fromHex, hex, word, addressWord, abiEncode,
} from './bytes.js';

export function checksumAddress(address) {
  const low = bytesToHex(fromHex(address));
  const h = bytesToHex(keccak_256(utf8ToBytes(low)));
  return '0x' + [...low].map((c, i) => (parseInt(h[i], 16) >= 8 ? c.toUpperCase() : c)).join('');
}

/** Address of an uncompressed (65-byte, 0x04-prefixed) secp256k1 public key. */
export function evmAddress(uncompressed) {
  if (uncompressed.length !== 65 || uncompressed[0] !== 4) throw new Error('need an uncompressed public key');
  return checksumAddress(hex(keccak_256(uncompressed.subarray(1)).subarray(12)));
}

// ------------------------------------------------------------------ EIP-712 (flat structs)

function encodeType(types, primary) {
  return `${primary}(${types[primary].map((f) => `${f.type} ${f.name}`).join(',')})`;
}

function encodeValue(type, value) {
  if (type === 'string') return keccak_256(utf8ToBytes(String(value)));
  if (type === 'bytes') return keccak_256(value instanceof Uint8Array ? value : fromHex(value));
  if (type === 'address') return addressWord(value);
  if (type === 'bool') return word(value ? 1 : 0);
  if (type === 'bytes32') return fromHex(value);
  if (/^uint\d+$/.test(type)) return word(value);
  throw new Error(`EIP-712 type ${type} is not supported here`);
}

export function hashStruct(types, primary, data) {
  return keccak_256(concatBytes(
    keccak_256(utf8ToBytes(encodeType(types, primary))),
    ...types[primary].map((f) => encodeValue(f.type, data[f.name])),
  ));
}

/** `eth_signTypedData_v4` digest of the typed data the server issued. */
export function hashTypedData(td) {
  return keccak_256(concatBytes(
    new Uint8Array([0x19, 0x01]),
    hashStruct(td.types, 'EIP712Domain', td.domain),
    hashStruct(td.types, td.primaryType, td.message),
  ));
}

// ------------------------------------------------------------------ SmartKeyAccount (CTR-ACC-01, CTR-ACC-02)

export const KEY_P256_WEBAUTHN = 1;
export const KEY_SECP256K1 = 2;
const KEY_TUPLE = '(uint8,bytes32,bytes32,bytes32,bytes32)';
const ZERO32 = new Uint8Array(32);

export function passkeySubjectKey({ x, y, rpId, origin }) {
  return [KEY_P256_WEBAUTHN, x, y, sha256(utf8ToBytes(rpId)), keccak_256(utf8ToBytes(origin))];
}

export function secpSubjectKey(address) {
  return [KEY_SECP256K1, addressWord(address), ZERO32, ZERO32, ZERO32];
}

export function keyId(key) {
  return keccak_256(abiEncode([KEY_TUPLE], [key]));
}

export function accountSalt(key, guardian) {
  return keccak_256(abiEncode([KEY_TUPLE, 'address'], [key, guardian]));
}

/** OZ `Clones.predictDeterministicAddress` (EIP-1167 + CREATE2). */
export function predictAccount(implementation, salt, factory) {
  const code = concatBytes(fromHex('3d602d80600a3d3981f3363d3d373d3d3d363d73'), fromHex(implementation),
                           fromHex('5af43d82803e903d91602b57fd5bf3'));
  const h = keccak_256(concatBytes(new Uint8Array([0xff]), fromHex(factory), salt, keccak_256(code)));
  return checksumAddress(hex(h.subarray(12)));
}

/** `abi.encode(keyIndex, proof, sig)` — what `SmartKeyAccount.isValidSignature` decodes (CTR-ACC-02). */
export function accountSignature(keyIndex, proof, inner) {
  return abiEncode(['uint256', 'bytes32[]', 'bytes'], [keyIndex, proof, inner]);
}

// ------------------------------------------------------------------ Merkle batch (review S26)

export function batchLeaf(digest) {
  return keccak_256(keccak_256(concatBytes(new Uint8Array([0]), digest)));
}

function nodeHash(a, b) {
  return bytesToHex(a) < bytesToHex(b) ? keccak_256(concatBytes(a, b)) : keccak_256(concatBytes(b, a));
}

/** Root over digests + one proof per digest (sorted pairs as OZ MerkleProof; odd node promoted). */
export function merkleBatch(digests) {
  if (digests.length < 2) throw new Error('a batch has at least two operations; sign one digest directly');
  let layer = digests.map(batchLeaf);
  const proofs = digests.map(() => []);
  let pos = digests.map((_, i) => i);
  while (layer.length > 1) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2) next.push(i + 1 < layer.length ? nodeHash(layer[i], layer[i + 1]) : layer[i]);
    pos = pos.map((p, k) => {
      const sib = p ^ 1;
      if (sib < layer.length) proofs[k].push(layer[sib]);
      return p >> 1;
    });
    layer = next;
  }
  return { root: layer[0], proofs };
}

export function processProof(proof, leaf) {
  return proof.reduce((acc, p) => nodeHash(acc, p), leaf);
}

// ------------------------------------------------------------------ what the client agrees to sign (review S4-M2)
// A passkey prompt shows no payload and a seed key signs silently: the client must never sign the
// server's typed data as such. It rebuilds what the payer asked for and refuses anything else.

const DOMAIN_TYPE = [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' },
  { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }];
// The salted domain of every contract on `MetaTxBase` (CTR-MTX-02, CLI-SGN-33) and its generic struct (CTR-MTX-15).
const SALTED_DOMAIN_TYPE = [...DOMAIN_TYPE, { name: 'salt', type: 'bytes32' }];
const MTX_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, MetaTransaction: ['from:address', 'data:bytes', 'batch:uint256',
  'nonce:uint256', 'validUntil:uint256', 'mode:uint32', 'relayer:address', 'fee:uint256', 'feeRecipient:address']
  .map((s) => ({ name: s.split(':')[0], type: s.split(':')[1] })) };
const ZERO_ADDRESS = '0x' + '00'.repeat(20);
const PAY_TYPES = { EIP712Domain: DOMAIN_TYPE, MetaTransaction: ['from:address', 'to:address', 'value:uint256',
  'data:bytes', 'batch:uint256', 'nonce:uint256', 'validUntil:uint256', 'mode:uint32', 'relayer:address', 'fee:uint256',
  'feeRecipient:address'].map((s) => ({ name: s.split(':')[0], type: s.split(':')[1] })) };
export const ADD_KEY_SELECTOR = keccak_256(utf8ToBytes(`addKey(${KEY_TUPLE})`)).subarray(0, 4);
const OP_PAY = keccak_256(utf8ToBytes('pay(bytes32)')).subarray(0, 4);
const KEY_PROOF_PREFIX = utf8ToBytes('scaas-subject-key-proof-v1');

const refuse = (why) => { throw new Error(`Refusing to sign: ${why}.`); };
const same = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();

function uint(v, what) {
  const s = String(v ?? '');
  if (!/^[0-9]+$/.test(s)) refuse(`${what} is not a number`);
  return BigInt(s);
}

function digestOf(td) {
  try { return hashTypedData(td); } catch { return refuse('malformed typed data'); }
}

function deadline(validUntil, now, max) {
  const until = uint(validUntil, 'the deadline');
  if (!(until > BigInt(now) && until <= BigInt(now) + BigInt(max))) refuse('the signing deadline is not near');
  return until;
}

/** What a new key signs to prove it is held (Odoo `key_proof_message`); never a server digest as such. */
export function keyProofMessage(challenge) {
  return keccak_256(concatBytes(KEY_PROOF_PREFIX, challenge));
}

export function addKeyCalldata(key) {
  return concatBytes(ADD_KEY_SELECTOR, abiEncode([KEY_TUPLE], [key]));
}

/** A `MetaTransaction` (CTR-MTX-15) of the SCaaS contract `contract` in its salted domain `(name, "1", chainId,
 *  contract, chainUid)`; unset fields are 0 (no relayer or fee binding, fee mode NONE). Canonical zeroing as the
 *  contract hashes it (metatx.md #digest): `relayer` is 0 unless mode bit 1, `feeRecipient` 0 unless mode bit 2.
 *  `chainId` may be a number, a decimal or hex string, or a BigInt (kept exact); `chainUid` must be 32 bytes. */
export function metaTxTypedData({ name, contract, chainId, chainUid, message }) {
  const salt = chainUid instanceof Uint8Array ? hex(chainUid) : String(chainUid);
  if (!/^0x[0-9a-fA-F]{64}$/.test(salt)) refuse('the chain_uid is not 32 bytes');
  const m = { from: ZERO_ADDRESS, data: '0x', batch: '0', nonce: '0', validUntil: '0', mode: 0, relayer: ZERO_ADDRESS,
    fee: '0', feeRecipient: ZERO_ADDRESS, ...message };
  const mode = BigInt(m.mode);
  return {
    types: MTX_TYPES, primaryType: 'MetaTransaction',
    domain: { name, version: '1', chainId: String(chainId), verifyingContract: contract, salt: salt.toLowerCase() },
    message: { ...m, data: typeof m.data === 'string' ? m.data : hex(m.data), batch: String(m.batch),
      nonce: String(m.nonce), validUntil: String(m.validUntil), fee: String(m.fee),
      relayer: mode & 1n ? m.relayer : ZERO_ADDRESS, feeRecipient: mode & 2n ? m.feeRecipient : ZERO_ADDRESS },
  };
}

/** The account's own call (CTR-ACC-10): `MetaTransaction{from: account, data, batch: 0, nonce, validUntil}` in the
 *  domain `SCaaS SmartKeyAccount`, exactly what `mtxExecuteAsOwner(data, nonce, validUntil, sig)` builds. */
export function ownerCallTypedData({ account, chainId, chainUid, data, nonce, validUntil }) {
  return metaTxTypedData({ name: 'SCaaS SmartKeyAccount', contract: account, chainId, chainUid,
    message: { from: account, data, nonce, validUntil } });
}

/** The server's owner call must be exactly `addKey(newKey)` signed by `account` itself on lane 0, on `chainId` and the
 *  signer's own pinned `chainUid` (a missing or different salt is refused, CLI-SGN-33); nonce and a near deadline come
 *  from the server. Returns the digest to sign, or throws (CLI-SGN-05). */
export function checkOwnerCall(td, { account, chainId, chainUid, newKey, now = Math.floor(Date.now() / 1000), maxWindow = 3600 }) {
  const m = (td && td.message) || {};
  const nonce = uint(m.nonce, 'the nonce');
  const until = deadline(m.validUntil, now, maxWindow);
  const mine = digestOf(ownerCallTypedData({ account, chainId, chainUid, data: addKeyCalldata(newKey), nonce, validUntil: until }));
  if (hex(digestOf(td)) !== hex(mine)) refuse('this is not the key change you asked for');
  return mine;
}

function toBase(amount, decimals) {
  const s = String(amount);
  const m = /^([0-9]+)(?:\.([0-9]+))?$/.exec(s);
  if (!m || (m[2] || '').length > decimals) refuse(`cannot read the amount ${s}`);
  return BigInt(m[1] + (m[2] || '').padEnd(decimals, '0'));
}

/** The server's typed data must be a token `pay` of exactly the shown `amount` (in the token's
 *  `decimals`) from `account` on `chainId`, no fee, near deadline. Returns {digest, payee, token}. */
export function checkPayment(td, { account, chainId, amount, decimals, now = Math.floor(Date.now() / 1000), maxWindow = 86400 }) {
  if (!td || td.primaryType !== 'MetaTransaction') refuse('this is not a payment');
  const m = td.message || {};
  const d = td.domain || {};
  if (uint(d.chainId, 'the chain') !== BigInt(chainId)) refuse('wrong network');
  if (!/^0x[0-9a-fA-F]{40}$/.test(String(d.verifyingContract)) || same(d.verifyingContract, account)) refuse('wrong token');
  if (!same(m.from, account)) refuse('the payment is not from your account');
  if (uint(m.value, 'the amount') !== toBase(amount, decimals)) refuse('the amount differs from what you were shown');
  let data;
  try { data = fromHex(m.data); } catch { refuse('malformed data'); }
  if (data.length !== 36 || hex(data.subarray(0, 4)) !== hex(OP_PAY)) refuse('this is not a plain payment');
  if (uint(m.fee, 'the fee') !== 0n) refuse('the payment carries a fee');
  if (![0, 1].includes(Number(m.mode))) refuse('unexpected payment mode');
  deadline(m.validUntil, now, maxWindow);
  const mine = { types: PAY_TYPES, primaryType: 'MetaTransaction',
    domain: { name: d.name, version: d.version, chainId: Number(chainId), verifyingContract: d.verifyingContract }, message: m };
  const digest = digestOf(mine);
  if (hex(digestOf(td)) !== hex(digest)) refuse('unexpected payment fields');
  return { digest, payee: m.to, token: d.verifyingContract };
}
