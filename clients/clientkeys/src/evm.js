// EVM pieces: EIP-712 digests, addresses, SmartKeyAccount key/salt/CREATE2, Merkle batch.
import {
  keccak_256, sha256, concatBytes, utf8ToBytes, bytesToHex, fromHex, hex, word, addressWord, abiEncode, bytes32,
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

// ------------------------------------------------------------------ EIP-712 (structs, nested structs)

/** EIP-712 `encodeType`: the primary type, then every struct it references, sorted by name. */
function encodeType(types, primary) {
  const deps = new Set();
  const walk = (t) => types[t].forEach((f) => {
    if (types[f.type] && f.type !== primary && !deps.has(f.type)) { deps.add(f.type); walk(f.type); }
  });
  walk(primary);
  const one = (t) => `${t}(${types[t].map((f) => `${f.type} ${f.name}`).join(',')})`;
  return [primary, ...[...deps].sort()].map(one).join('');
}

function encodeValue(type, value, types) {
  if (types && types[type]) return hashStruct(types, type, value);
  if (type === 'string') return keccak_256(utf8ToBytes(String(value)));
  if (type === 'bytes') return keccak_256(value instanceof Uint8Array ? value : fromHex(value));
  if (type === 'address') return addressWord(value);
  if (type === 'bool') return word(value ? 1 : 0);
  if (type === 'bytes32') return bytes32(value);
  if (/^uint\d+$/.test(type)) return word(value);
  throw new Error(`EIP-712 type ${type} is not supported here`);
}

export function hashStruct(types, primary, data) {
  return keccak_256(concatBytes(
    keccak_256(utf8ToBytes(encodeType(types, primary))),
    ...types[primary].map((f) => encodeValue(f.type, data[f.name], types)),
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
const fields = (list) => list.map((s) => ({ name: s.split(':')[0], type: s.split(':')[1] }));
// The token's typed transfer and payment (CTR-MTX-23); `entryRef = 0` is a transfer, else a payment.
const TRANSFER_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, MetaTransfer: fields(['from:address', 'to:address',
  'value:uint256', 'entryRef:bytes32', 'batch:uint256', 'nonce:uint256', 'validUntil:uint256', 'mode:uint32',
  'relayer:address', 'fee:uint256', 'feeRecipient:address']) };
// The role-free order (CTR-DEX-13), signed in the sell token's domain; an outside token's in the DEX's as `DexOrder`.
const TRADE_ORDER = fields(['from:address', 'receiveToken:address', 'amount:uint256', 'receiveAmount:uint256',
  'minFill:uint256', 'fee:uint256', 'relayer:address', 'dex:address', 'destination:address', 'flags:uint8',
  'batch:uint256', 'nonce:uint256', 'validUntil:uint256']);
const ORDER_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, TradeOrder: TRADE_ORDER };
// A UA's order (dex.md CTR-DEX-25): the same fields with `from` and `destination` as 32-byte ids, in the sell token's
// domain; a derived signer signs `ua_msg(kind, trade, digest)` through the registry, a native id the digest itself.
const UA_TRADE_ORDER = fields(['from:bytes32', 'receiveToken:address', 'amount:uint256', 'receiveAmount:uint256',
  'minFill:uint256', 'fee:uint256', 'relayer:address', 'dex:address', 'destination:bytes32', 'flags:uint8',
  'batch:uint256', 'nonce:uint256', 'validUntil:uint256']);
const UA_ORDER_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, UATradeOrder: UA_TRADE_ORDER };
const UA_INVALIDATE_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE,
  UAInvalidateNonces: fields(['from:bytes32', 'batch:uint256', 'minNonce:uint256']) };
const DEX_ORDER_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, DexOrder: fields(['sellToken:address', 'order:TradeOrder']),
  TradeOrder: TRADE_ORDER };
const sel = (sig) => hex(keccak_256(utf8ToBytes(sig)).subarray(0, 4));
// Never inside a `MetaTransaction` (CLI-SGN-34): moving funds is a `MetaTransfer`, and EOAs never approve (CLI-SGN-36).
const NEVER_CALLED = new Set(['transfer(address,uint256)', 'transferFrom(address,address,uint256)',
  'approve(address,uint256)', 'payWithFee(address,uint256,uint8,uint256,address,bytes32)', 'pay(bytes32)',
  'payWithFeeToUA(bytes32,uint256,uint8,uint256,address,bytes32)'].map(sel));
export const ADD_KEY_SELECTOR = keccak_256(utf8ToBytes(`addKey(${KEY_TUPLE})`)).subarray(0, 4);
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

function salted({ name, contract, chainId, chainUid }) {
  const salt = chainUid instanceof Uint8Array ? hex(chainUid) : String(chainUid);
  if (!/^0x[0-9a-fA-F]{64}$/.test(salt)) refuse('the chain_uid is not 32 bytes');
  return { name, version: '1', chainId: String(chainId), verifyingContract: contract, salt: salt.toLowerCase() };
}

/** A token's `MetaTransfer` (CTR-MTX-23) in its salted domain; unset fields 0; canonical zeroing as the contract hashes
 *  it (`relayer` 0 unless mode bit 1, `feeRecipient` 0 unless mode bit 2). */
export function metaTransferTypedData({ name = 'SCaaS MetaToken', contract, chainId, chainUid, message }) {
  const m = { from: ZERO_ADDRESS, to: ZERO_ADDRESS, value: '0', entryRef: '0x' + '00'.repeat(32), batch: '0', nonce: '0',
    validUntil: '0', mode: 0, relayer: ZERO_ADDRESS, fee: '0', feeRecipient: ZERO_ADDRESS, ...message };
  const mode = BigInt(m.mode);
  return {
    types: TRANSFER_TYPES, primaryType: 'MetaTransfer', domain: salted({ name, contract, chainId, chainUid }),
    message: { ...m, value: String(m.value), batch: String(m.batch), nonce: String(m.nonce), validUntil: String(m.validUntil),
      fee: String(m.fee), relayer: mode & 1n ? m.relayer : ZERO_ADDRESS, feeRecipient: mode & 2n ? m.feeRecipient : ZERO_ADDRESS },
  };
}

// The UA ledger's two structs (accounts.md CTR-UA-19, CTR-UA-26): ids as bytes32 (a native address zero-padded), the
// token's own salted domain; the typehash separates them from `MetaTransaction` / `MetaTransfer`.
const UA_TX_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, UAMetaTransaction: fields(['from:bytes32', 'data:bytes',
  'batch:uint256', 'nonce:uint256', 'validUntil:uint256', 'mode:uint32', 'relayer:address', 'fee:uint256',
  'feeRecipient:address']) };
const UA_TRANSFER_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, UAMetaTransfer: fields(['from:bytes32', 'to:bytes32',
  'value:uint256', 'entryRef:bytes32', 'batch:uint256', 'nonce:uint256', 'validUntil:uint256', 'mode:uint32',
  'relayer:address', 'fee:uint256', 'feeRecipient:address']) };
const ZERO_ID = '0x' + '00'.repeat(32);

/** A native address as a UA-ledger id: the address zero-padded to 32 bytes (accounts.md §1.3). */
export const padId = (address) => hex(addressWord(address));

/** A token's `UAMetaTransaction` (an allowlisted call under a UA) in its salted domain; unset fields 0; canonical
 *  zeroing as `metaTxTypedData`. `from` is a 32-byte id. */
export function uaMetaTxTypedData({ name = 'SCaaS MetaToken', contract, chainId, chainUid, message }) {
  const m = { from: ZERO_ID, data: '0x', batch: '0', nonce: '0', validUntil: '0', mode: 0, relayer: ZERO_ADDRESS,
    fee: '0', feeRecipient: ZERO_ADDRESS, ...message };
  const mode = BigInt(m.mode);
  return {
    types: UA_TX_TYPES, primaryType: 'UAMetaTransaction', domain: salted({ name, contract, chainId, chainUid }),
    message: { ...m, from: hex(bytes32(m.from)), data: typeof m.data === 'string' ? m.data : hex(m.data),
      batch: String(m.batch), nonce: String(m.nonce), validUntil: String(m.validUntil), fee: String(m.fee),
      relayer: mode & 1n ? m.relayer : ZERO_ADDRESS, feeRecipient: mode & 2n ? m.feeRecipient : ZERO_ADDRESS },
  };
}

/** A token's `UAMetaTransfer` (transfer or payment between ids) in its salted domain; as `metaTransferTypedData`. */
export function uaMetaTransferTypedData({ name = 'SCaaS MetaToken', contract, chainId, chainUid, message }) {
  const m = { from: ZERO_ID, to: ZERO_ID, value: '0', entryRef: ZERO_ID, batch: '0', nonce: '0', validUntil: '0', mode: 0,
    relayer: ZERO_ADDRESS, fee: '0', feeRecipient: ZERO_ADDRESS, ...message };
  const mode = BigInt(m.mode);
  return {
    types: UA_TRANSFER_TYPES, primaryType: 'UAMetaTransfer', domain: salted({ name, contract, chainId, chainUid }),
    message: { ...m, from: hex(bytes32(m.from)), to: hex(bytes32(m.to)), value: String(m.value), batch: String(m.batch),
      nonce: String(m.nonce), validUntil: String(m.validUntil), fee: String(m.fee),
      relayer: mode & 1n ? m.relayer : ZERO_ADDRESS, feeRecipient: mode & 2n ? m.feeRecipient : ZERO_ADDRESS },
  };
}

// The payee's co-signature of receiver-pays (CTR-MTX-05/06), over the payer's payment digest: `MetaTransfer`'s on the
// address path (`mtxPayReceiverFee`), `UAMetaTransfer`'s on the UA path (`uaPayReceiverFee`). A native payee signs its
// digest; a derived one `ua_msg(kind, receiver-fee, digest)` through the registry.
const RECEIVER_FEE_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, ReceiverFee: fields(['paymentDigest:bytes32', 'fee:uint256',
  'feeRecipient:address', 'validUntil:uint256']) };

/** A token's `ReceiverFee(paymentDigest, fee, feeRecipient, validUntil)` in its salted domain (both paths). */
export function receiverFeeTypedData({ name = 'SCaaS MetaToken', contract, chainId, chainUid, paymentDigest, fee,
  feeRecipient, validUntil }) {
  return { types: RECEIVER_FEE_TYPES, primaryType: 'ReceiverFee', domain: salted({ name, contract, chainId, chainUid }),
    message: { paymentDigest: hex(bytes32(paymentDigest)), fee: String(fee), feeRecipient, validUntil: String(validUntil) } };
}

// The UA-5a receivers (accounts.md CTR-UA-28): a native caller credits a derived UA `to` (32 bytes) in one call.
const abiCall = (sig, types, values) => concatBytes(fromHex(sel(sig)), abiEncode(types, values));
/** `wrapToUA(underlying, amount, to)`: direct (payable on the native leg), or inside a `MetaTransaction` (`ABSOLUTE`). */
export const wrapToUACalldata = (underlying, amount, to) =>
  abiCall('wrapToUA(address,uint256,bytes32)', ['address', 'uint256', 'bytes32'], [underlying, amount, to]);
/** `unwrapToUA(underlying, wrapped, to, minOut)`: direct, in a `MetaTransaction` or a `UAMetaTransaction` (`AMOUNT(1)`). */
export const unwrapToUACalldata = (underlying, wrapped, to, minOut) => abiCall('unwrapToUA(address,uint256,bytes32,uint256)',
  ['address', 'uint256', 'bytes32', 'uint256'], [underlying, wrapped, to, minOut]);
/** `payWithFeeToUA(to, amount, feeMode, fee, feeRecipient, entryRef)`: direct only (never a call, as `payWithFee`). */
export const payWithFeeToUACalldata = (to, amount, feeMode, fee, feeRecipient, entryRef) =>
  abiCall('payWithFeeToUA(bytes32,uint256,uint8,uint256,address,bytes32)',
    ['bytes32', 'uint256', 'uint8', 'uint256', 'address', 'bytes32'], [to, amount, feeMode, fee, feeRecipient, entryRef]);

/** The lane of a payment request, `keccak256("scaas.pay.lane" ‖ entryRef)` with nonce 0 (CTR-MTX-03; on chain `payLane`). */
export function payLane(entryRef) {
  return BigInt(hex(keccak_256(concatBytes(utf8ToBytes('scaas.pay.lane'), bytes32(entryRef)))));
}

/** A fee and its bindings against the user's policy (CTR-MTX-13): known flags and fee mode; NONE carries no fee; FIXED
 *  costs `fee`, PERCENT (≤ 1 %, only with an amount `basis`) ⌊basis × fee / 10^6⌋, either at most `maxFee` (base
 *  units); a bound fee recipient or relayer is the one the user named. Returns what the review screen shows. */
function feePolicy(m, { maxFee = 0, feeRecipient, relayer }, basis) {
  const mode = uint(m.mode, 'the fee mode');
  const kind = mode >> 4n;
  if (mode & ~0xf3n || kind > 2n) refuse('unexpected fee mode');
  const rate = uint(m.fee, 'the fee');
  if (kind === 0n && rate !== 0n) refuse('a fee with fee mode NONE');
  if (kind === 1n && (basis === undefined || rate > 10000n)) refuse('a percentage fee without an amount, or above 1 %');
  const fee = kind === 1n ? basis * rate / 1000000n : rate;
  if (fee > uint(maxFee, 'your fee limit')) refuse('the fee is above your limit');
  if (mode & 2n && !same(m.feeRecipient, feeRecipient)) refuse('the fee goes to an address you did not name');
  if (mode & 1n && relayer !== undefined && !same(m.relayer, relayer)) refuse('the call is bound to another relayer');
  return { feeMode: Number(kind), fee, feeRecipient: mode & 2n ? m.feeRecipient : null, relayer: mode & 1n ? m.relayer : null };
}

/** The server's typed data must be the payment the user was shown: a `MetaTransfer` from `account` to `payee` of
 *  `amount` (in the token's `decimals`) with the request's `entryRef`, on the request's lane `payLane(entryRef)` with
 *  nonce 0, in the domain of `expectedToken` (the signer's own profile, CLI-SGN-08) salted with its own `chainUid`
 *  (CLI-SGN-33), the fee within `maxFee` (default 0), a near deadline (CLI-SGN-05). `payee`, `entryRef`,
 *  `expectedToken` and `amount` are required; the server supplies only `validUntil` and the fee fields. Returns
 *  {digest, payee, token, entryRef, feeMode, fee, feeRecipient, relayer}. */
export function checkPayment(td, { account, chainId, chainUid, amount, decimals, payee, entryRef, expectedToken, maxFee,
  feeRecipient, relayer, now = Math.floor(Date.now() / 1000), maxWindow = 86400 }) {
  if (!td || td.primaryType !== 'MetaTransfer') refuse('this is not a payment');
  if ([amount, payee, entryRef, expectedToken].some((v) => v == null)) refuse('the amount, payee, reference and token are required');
  const m = td.message || {};
  const d = td.domain || {};
  if (!same(d.verifyingContract, expectedToken)) refuse('wrong token');
  if (!same(m.to, payee)) refuse('the payee differs from the one you were shown');
  const value = toBase(amount, decimals);
  if (uint(m.value, 'the amount') !== value || value === 0n) refuse('the amount differs from what you were shown');
  if (!/^0x[0-9a-fA-F]{64}$/.test(String(entryRef)) || BigInt(entryRef) === 0n) refuse('this is not a payment');
  if (!same(m.entryRef, entryRef)) refuse('the payment reference differs from the request');
  const batch = payLane(entryRef);
  if (uint(m.batch, 'the lane') !== batch || uint(m.nonce, 'the nonce') !== 0n) refuse('a payment is signed once, on its request lane');
  const fee = feePolicy(m, { maxFee, feeRecipient, relayer }, value);
  deadline(m.validUntil, now, maxWindow);
  const digest = digestOf(metaTransferTypedData({ name: d.name, contract: expectedToken, chainId, chainUid,
    message: { ...m, from: account, to: payee, value, entryRef, batch, nonce: 0 } }));
  if (hex(digestOf(td)) !== hex(digest)) refuse('unexpected payment fields');
  return { digest, payee, token: expectedToken, entryRef, ...fee };
}

/** The payee's side of receiver-pays (CTR-MTX-05/06), both paths: `td` is the `ReceiverFee` to co-sign, `payment` the
 *  payer's `MetaTransfer` (`mtxPayReceiverFee`) or `UAMetaTransfer` (`uaPayReceiverFee`; `payee` then a 32-byte id,
 *  `padId` for a native one) it rides on. The payment must be the one the payee expects, as `checkPayment` checks it for
 *  the payer: to `payee`, `amount` (× 10^`decimals`) with the request's `entryRef` on lane `payLane(entryRef)` nonce 0,
 *  the contract's shape (fee NONE, relayer bound: mode 1), in `expectedToken`'s domain salted with `chainUid`; its digest
 *  is recomputed here and must be `paymentDigest`. The fee is the payee's own: non-zero, at most the amount and
 *  `maxFee` (default 0), to the `feeRecipient` it named, with a near deadline. The server supplies only the payment's
 *  `from` / `validUntil` / `relayer` and the fee's `validUntil`. Returns {digest, paymentDigest, payer, fee, feeRecipient}. */
export function checkReceiverFee(td, { payee, chainId, chainUid, amount, decimals, entryRef, expectedToken, payment,
  maxFee = 0, feeRecipient, now = Math.floor(Date.now() / 1000), maxWindow = 86400 }) {
  if (!td || td.primaryType !== 'ReceiverFee') refuse('this is not a receiver fee');
  if ([payee, amount, entryRef, expectedToken, feeRecipient].some((v) => v == null)) {
    refuse('the payee, amount, reference, token and fee recipient are required');
  }
  const ua = payment && payment.primaryType === 'UAMetaTransfer';
  if (!payment || !(ua || payment.primaryType === 'MetaTransfer')) refuse('the fee is not on a payment');
  const p = payment.message || {};
  const pdom = payment.domain || {};
  if (!same(pdom.verifyingContract, expectedToken) || !same((td.domain || {}).verifyingContract, expectedToken)) refuse('wrong token');
  if (!same(p.to, payee)) refuse('the payment does not pay you');
  const value = toBase(amount, decimals);
  if (uint(p.value, 'the amount') !== value || value === 0n) refuse('the amount differs from what you were shown');
  if (!/^0x[0-9a-fA-F]{64}$/.test(String(entryRef)) || BigInt(entryRef) === 0n) refuse('this is not a payment');
  if (!same(p.entryRef, entryRef)) refuse('the payment reference differs from the request');
  const batch = payLane(entryRef);
  if (uint(p.batch, 'the lane') !== batch || uint(p.nonce, 'the nonce') !== 0n) refuse('a payment is signed once, on its request lane');
  if (uint(p.mode, 'the fee mode') !== 1n || uint(p.fee, 'the payer fee') !== 0n) refuse('the payment is not in the receiver-pays shape');
  const build = ua ? uaMetaTransferTypedData : metaTransferTypedData;
  const paymentDigest = digestOf(build({ name: pdom.name, contract: expectedToken, chainId, chainUid,
    message: { ...p, to: payee, value, entryRef, batch, nonce: 0 } }));
  if (hex(digestOf(payment)) !== hex(paymentDigest)) refuse('unexpected payment fields');
  const m = td.message || {};
  if (!same(m.paymentDigest, hex(paymentDigest))) refuse('the fee is not on the payment you expect');
  const fee = uint(m.fee, 'the fee');
  if (fee === 0n) refuse('no fee to co-sign');
  if (fee > value) refuse('the fee is more than the payment');
  if (fee > uint(maxFee, 'your fee limit')) refuse('the fee is above your limit');
  if (!same(m.feeRecipient, feeRecipient)) refuse('the fee goes to an address you did not name');
  const validUntil = deadline(m.validUntil, now, maxWindow);
  const digest = digestOf(receiverFeeTypedData({ name: (td.domain || {}).name, contract: expectedToken, chainId, chainUid,
    paymentDigest, fee, feeRecipient, validUntil }));
  if (hex(digestOf(td)) !== hex(digest)) refuse('unexpected receiver fee fields');
  return { digest, paymentDigest, payer: p.from, fee, feeRecipient };
}

// ------------------------------------------------------------------ CTR-MTX-26: the payment id commits to its metadata

const asBytes = (v) => (v instanceof Uint8Array ? v : fromHex(v));
const at = (b, i) => BigInt(hex(b.subarray(32 * i, 32 * i + 32)));

/** `metaPayId(salt, meta) = keccak256("scaas.pay.meta" ‖ salt ‖ keccak256(meta))` (CTR-MTX-26; on chain `metaPayId`). */
export function metaPayId(salt, meta) {
  return hex(keccak_256(concatBytes(utf8ToBytes('scaas.pay.meta'), bytes32(salt), keccak_256(asBytes(meta)))));
}

/** The envelope `meta = abi.encode(uint16 schema, bytes body)`. */
export function encodeMeta(schema, body) {
  if (!Number.isInteger(schema) || schema < 0 || schema > 0xffff) throw new Error('schema is a uint16');
  return abiEncode(['uint16', 'bytes'], [schema, asBytes(body)]);
}

/** The `bytes` whose head word is word `i` of `b`, read strictly (re-encoding checks canonical form). */
function dynAt(b, i) {
  const off = at(b, i);
  if (off + 32n > BigInt(b.length)) refuse('the metadata is malformed');
  const n = at(b.subarray(Number(off)), 0);
  if (off + 32n + n > BigInt(b.length)) refuse('the metadata is malformed');
  return b.subarray(Number(off) + 32, Number(off) + 32 + Number(n));
}

function utf8(b) {
  try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(b); } catch { return refuse('the note is not UTF-8'); }
}

/** Decodes a `meta` for the review screen (CTR-MTX-26 bodies): 1 note (`{note}`), 2 structured reference
 *  (`{creditorRef, invoiceNo, dueDate}`), 3 bound call (`{chainId, target, callHash}`), 4 encrypted (`{encrypted: n
 *  bytes}`, not decrypted here). Only the canonical ABI form is accepted; an unknown schema is refused. */
export function decodeMeta(meta) {
  const m = asBytes(meta);
  if (m.length < 96) refuse('the metadata is malformed');
  const schema = at(m, 0);
  if (schema > 0xffffn) refuse('the metadata is malformed');
  const body = dynAt(m, 1);
  if (hex(encodeMeta(Number(schema), body)) !== hex(m)) refuse('the metadata is not in canonical form');
  let shown;
  if (schema === 1n) shown = { note: utf8(body) };
  else if (schema === 2n) {
    if (body.length < 96) refuse('the metadata is malformed');
    const [creditor, invoice, dueDate] = [dynAt(body, 0), dynAt(body, 1), at(body, 2)];
    if (dueDate >= 1n << 64n || hex(abiEncode(['bytes', 'bytes', 'uint64'], [creditor, invoice, dueDate])) !== hex(body)) {
      refuse('the metadata is not in canonical form');
    }
    shown = { creditorRef: utf8(creditor), invoiceNo: utf8(invoice), dueDate };
  } else if (schema === 3n) {
    if (body.length !== 96) refuse('the metadata is malformed');
    shown = { chainId: at(body, 0), target: hex(body.subarray(32, 64)), callHash: hex(body.subarray(64, 96)) };
  } else if (schema === 4n) shown = { encrypted: body.length };
  else refuse('unknown metadata schema');
  return { schema: Number(schema), body, shown };
}

/** `(salt, meta)` → payId, lane, decoded meta; refuses when the request's `entryRef` is not `metaPayId(salt, meta)`. */
function payMetaParts({ salt, meta, entryRef }) {
  const s = hex(bytes32(salt));
  const m = asBytes(meta);
  const { schema, shown } = decodeMeta(m);
  const payId = metaPayId(s, m);
  if (entryRef != null && !same(entryRef, payId)) refuse('the payment id does not commit to its metadata');
  return { salt: s, meta: m, payId, lane: payLane(payId), schema, shown };
}

const PAY_TAIL = ['uint256', 'uint32', 'address', 'uint256', 'address', 'bytes'];

function buildPayMeta(ua, { name, token, chainId, chainUid, from, to, amount, salt, meta, entryRef, validUntil, mode = 0,
  relayer = ZERO_ADDRESS, fee = 0, feeRecipient = ZERO_ADDRESS, onChain = true }) {
  const p = payMetaParts({ salt, meta, entryRef });
  const build = ua ? uaMetaTransferTypedData : metaTransferTypedData;
  const typedData = build({ name, contract: token, chainId, chainUid, message: { from, to, value: amount, entryRef: p.payId,
    batch: p.lane, nonce: 0, validUntil, mode, relayer, fee, feeRecipient } });
  const t = typedData.message;
  const id = ua ? 'bytes32' : 'address';
  const tail = (sig) => [t.validUntil, t.mode, t.relayer, t.fee, t.feeRecipient, sig];
  const calldata = (sig) => (onChain
    ? abiCall(`${ua ? 'uaPayMeta' : 'mtxPayMeta'}(${id},${id},uint256,bytes32,bytes,${PAY_TAIL.join(',')})`,
      [id, id, 'uint256', 'bytes32', 'bytes', ...PAY_TAIL], [t.from, t.to, t.value, p.salt, p.meta, ...tail(sig)])
    : abiCall(`${ua ? 'uaPay' : 'mtxPay'}(${id},${id},uint256,bytes32,${PAY_TAIL.join(',')})`,
      [id, id, 'uint256', 'bytes32', ...PAY_TAIL], [t.from, t.to, t.value, p.payId, ...tail(sig)]));
  return { typedData, digest: digestOf(typedData), payId: p.payId, lane: p.lane, salt: p.salt, meta: hex(p.meta),
    schema: p.schema, shown: p.shown, calldata };
}

/** A pay-meta payment the client builds (CTR-MTX-26): the `MetaTransfer` of `mtxPay` with `entryRef = metaPayId(salt,
 *  meta)`, lane `payLane(entryRef)`, nonce 0. `entryRef` (optional, the request's) must equal it, else refused.
 *  `amount` in base units. `calldata(signature)` is `mtxPayMeta(…)` (meta published), or with `onChain: false` the
 *  off-chain variant `mtxPay(…, payId, …)` (the same digest; the payee keeps `(salt, meta)`). Returns {typedData, digest,
 *  payId, lane, salt, meta, schema, shown, calldata}. */
export const buildMtxPayMeta = (opts) => buildPayMeta(false, opts);

/** `buildMtxPayMeta` on the UA path: a `UAMetaTransfer` between 32-byte ids; `uaPayMeta(…)` / `uaPay(…)`. */
export const buildUaPayMeta = (opts) => buildPayMeta(true, opts);

/** `checkPayment` for a pay-meta request: the server's `MetaTransfer` must carry `entryRef = metaPayId(salt, meta)` of
 *  the `(salt, meta)` the client holds (else refused), then every `checkPayment` check with that `entryRef`. Returns
 *  `checkPayment`'s result plus {payId, salt, meta, schema, shown} for the review screen. */
export function checkPayMeta(td, { salt, meta, entryRef, ...opts }) {
  const p = payMetaParts({ salt, meta, entryRef });
  if (!same(((td && td.message) || {}).entryRef, p.payId)) refuse('the payment id does not commit to its metadata');
  return { ...checkPayment(td, { ...opts, entryRef: p.payId }), payId: p.payId, salt: p.salt, meta: hex(p.meta),
    schema: p.schema, shown: p.shown };
}

// ------------------------------------------------------------------ CTR-MTX-27: a token fee for a fee-less call

/** `relayRef(target, callData) = keccak256("scaas.relayfee" ‖ uint256 chainid ‖ target ‖ keccak256(callData))` on chain
 *  `chainId` (EVM, `MtxRelayFee.relayRef`; other families use their own `ref` forms). */
export function relayRef(chainId, target, callData) {
  const t = fromHex(target);
  if (t.length !== 20) refuse('the target is not an address');
  return hex(keccak_256(concatBytes(utf8ToBytes('scaas.relayfee'), word(chainId), t, keccak_256(asBytes(callData)))));
}

const MTX_TUPLE = '(address,bytes,uint256,uint256,uint256,uint32,address,uint256,address)';
/** `mtxExecute(m, signature)` calldata of a signed `MetaTransaction` typed data (the call a relay-fee payment pays for). */
export function mtxExecuteCalldata(td, signature) {
  const m = td.message;
  const tuple = abiEncode(['address', 'bytes', 'uint256', 'uint256', 'uint256', 'uint32', 'address', 'uint256', 'address'],
    [m.from, m.data, m.batch, m.nonce, m.validUntil, m.mode, m.relayer, m.fee, m.feeRecipient]);
  return concatBytes(fromHex(sel(`mtxExecute(${MTX_TUPLE},bytes)`)), word(64), word(64 + tuple.length), tuple,
    abiEncode(['bytes'], [asBytes(signature)]).subarray(32));
}

const TRANSFER_TUPLE = (id) => `(${id},${id},uint256,bytes32,uint256,uint256,uint256,uint32,address,uint256,address)`;

/** A relay-fee job (CTR-MTX-27) on `router` (`MtxRelayFee`, executor `executor`): `inner` (optional) is the call's own
 *  `MetaTransaction` typed data on `target`; a relayer it binds (`MODE_RESTRICT_RELAYER`) is set to the executor (left
 *  open otherwise; bound to anything else: refused). Open mode by default (`payee` unset: the payment goes to the router,
 *  which pays whoever submits); `payee` binds it (never the executor). `ua`: the payer `from` and `payee` are 32-byte ids.
 *  Returns {call (the inner typed data to sign first, or null), prompt {call, payment}: both intents for one review,
 *  payment(callData) → {ref, lane, typedData, digest, calldata(sig)}}: `callData` is the call with its own signature
 *  (`mtxExecuteCalldata`); the payment is `{from, to, value: amount, entryRef: ref, batch: payLane(ref), nonce: 0,
 *  validUntil, mode: RESTRICT_RELAYER, relayer: router, fee: 0}`, `calldata` is `relay(…)` / `uaRelay(…)`. */
export function buildRelayFee({ name = 'SCaaS MetaToken', token, chainId, chainUid, router, executor, target, inner, from,
  amount, payee, validUntil, ua = false }) {
  if (same(target, executor) || same(target, router)) refuse('a relay never targets the router or its executor');
  const idOf = (a) => (ua ? padId(a) : a);
  const open = payee == null;
  const to = open ? idOf(router) : payee;
  if (same(to, idOf(executor)) || same(to, executor)) refuse('never pay the executor');
  if (same(to, ZERO_ADDRESS) || same(to, ZERO_ID)) refuse('the payee is the zero address');
  if (same(to, token) || same(to, padId(token))) refuse('the payee is the token itself');
  let call = null;
  let bound = 0n;
  if (inner) {
    const m = inner.message || {};
    const d = inner.domain || {};
    if (!same(d.verifyingContract, target)) refuse('the call is not on the target');
    const uid = chainUid instanceof Uint8Array ? hex(chainUid) : String(chainUid);
    if (uint(d.chainId, 'the call\'s chain id') !== BigInt(chainId) || !same(d.salt, uid)) refuse('the call is for another chain');
    if (uint(m.validUntil, 'the call\'s deadline') > uint(validUntil, 'the deadline')) refuse('the call outlives its payment');
    bound = BigInt(m.mode ?? 0) & 1n;
    if (bound && !same(m.relayer, ZERO_ADDRESS) && !same(m.relayer, executor)) refuse('the call is bound to another relayer');
    call = { ...inner, message: { ...m, relayer: bound ? executor : m.relayer } };
  }
  const prompt = {
    call: call ? { target, data: call.message.data, from: call.message.from, relayer: bound ? executor : null }
      : { target },
    payment: { token, amount: BigInt(amount), payee: open ? null : to, open },
  };
  const payment = (callData) => {
    const ref = relayRef(chainId, target, callData);
    const lane = payLane(ref);
    const typedData = (ua ? uaMetaTransferTypedData : metaTransferTypedData)({ name, contract: token, chainId, chainUid,
      message: { from, to, value: amount, entryRef: ref, batch: lane, nonce: 0, validUntil, mode: 1, relayer: router, fee: 0 } });
    const t = typedData.message;
    const tuple = [t.from, t.to, t.value, t.entryRef, t.batch, t.nonce, t.validUntil, t.mode, t.relayer, t.fee, t.feeRecipient];
    const T = TRANSFER_TUPLE(ua ? 'bytes32' : 'address');
    const calldata = (sig) => abiCall(`${ua ? 'uaRelay' : 'relay'}(address,bytes,address,${T},bytes)`,
      ['address', 'bytes', 'address', T, 'bytes'], [target, asBytes(callData), token, tuple, asBytes(sig)]);
    return { ref, lane, typedData, digest: digestOf(typedData), calldata };
  };
  return { call, prompt, payment };
}

/** A self-call `MetaTransaction` (CTR-MTX-17) that is exactly the call the client built, `call = {contract, data}`:
 *  `verifyingContract` and `data` equal; `data` decoded against the contract's published allowlist `[{selector, name,
 *  feeClass, amountArg}]` (`mtxSelectors()`, pinned per implementation version, CLI-SGN-34); an unknown selector, a
 *  transfer/pay selector or an approval is refused; the fee within `maxFee` (default 0; PERCENT only on an AMOUNT
 *  selector, CTR-MTX-20), a bound fee recipient / relayer the one named. The server supplies only nonce, lane,
 *  `validUntil` and the fee fields. Returns {digest, selector, name, feeMode, fee, feeRecipient, relayer}. */
export function checkCall(td, { account, chainId, chainUid, allowlist, call, maxFee, feeRecipient, relayer,
  now = Math.floor(Date.now() / 1000), maxWindow = 3600 }) {
  if (!td || td.primaryType !== 'MetaTransaction') refuse('this is not a contract call');
  const m = td.message || {};
  const d = td.domain || {};
  if (!call || !same(d.verifyingContract, call.contract)) refuse('the call is not on the contract you chose');
  let data;
  try { data = call.data instanceof Uint8Array ? call.data : fromHex(call.data); } catch { refuse('malformed data'); }
  if (!same(m.data, hex(data))) refuse('this is not the call you asked for');
  const selector = hex(data.subarray(0, 4));
  if (NEVER_CALLED.has(selector)) refuse('moving funds or an approval is never signed as a call');
  const row = (allowlist || []).find((r) => same(r.selector, selector));
  if (!row) refuse('the function is not on the contract\'s allowlist');
  const at = 4 + 32 * Number(row.amountArg || 0);
  const basis = Number(row.feeClass) === 2 && data.length >= at + 32 ? BigInt(hex(data.subarray(at, at + 32))) : undefined;
  const fee = feePolicy(m, { maxFee, feeRecipient, relayer }, basis);
  deadline(m.validUntil, now, maxWindow);
  const digest = digestOf(metaTxTypedData({ name: d.name, contract: call.contract, chainId, chainUid,
    message: { ...m, from: account, data: hex(data) } }));
  if (hex(digestOf(td)) !== hex(digest)) refuse('unexpected call fields');
  return { digest, selector, name: row.name, ...fee };
}

/** A `TradeOrder` in its SCaaS sell token's salted domain (CTR-DEX-13), or for an outside sell token the `DexOrder`
 *  `{sellToken, order}` in the DEX's (CTR-DEX-18): pass `dex` instead of `token`. */
export function tradeOrderTypedData({ token, dex, sellToken, chainId, chainUid, order, name }) {
  const o = { minFill: '0', fee: '0', relayer: ZERO_ADDRESS, destination: ZERO_ADDRESS, flags: 0, batch: '0', ...order };
  const message = Object.fromEntries(TRADE_ORDER.map((f) => [f.name, f.type === 'address' || f.type === 'uint8' ? o[f.name] : String(o[f.name])]));
  if (dex) {
    return { types: DEX_ORDER_TYPES, primaryType: 'DexOrder', domain: salted({ name: name || 'SCaaS Dex', contract: dex, chainId, chainUid }),
      message: { sellToken, order: message } };
  }
  return { types: ORDER_TYPES, primaryType: 'TradeOrder', domain: salted({ name: name || 'SCaaS MetaToken', contract: token, chainId, chainUid }),
    message };
}

/** A `UATradeOrder` in its SCaaS sell token's salted domain (CTR-DEX-25); ids 32 bytes (a native address zero-padded,
 *  `padId`); unset fields 0. Its cancel is `orderCancelTypedData({ orderHash })` over this order's digest. */
export function uaTradeOrderTypedData({ token, chainId, chainUid, order, name = 'SCaaS MetaToken' }) {
  const o = { minFill: '0', fee: '0', relayer: ZERO_ADDRESS, destination: ZERO_ID, flags: 0, batch: '0', ...order };
  const message = Object.fromEntries(UA_TRADE_ORDER.map((f) => [f.name,
    f.type === 'bytes32' ? hex(bytes32(o[f.name])) : f.type === 'address' || f.type === 'uint8' ? o[f.name] : String(o[f.name])]));
  return { types: UA_ORDER_TYPES, primaryType: 'UATradeOrder', domain: salted({ name, contract: token, chainId, chainUid }),
    message };
}

/** `UAInvalidateNonces(from, batch, minNonce)` in the sell token's domain: one floor per id, shared with the address's
 *  `InvalidateNonces` (CTR-DEX-25). */
export function uaInvalidateNoncesTypedData({ name = 'SCaaS MetaToken', contract, chainId, chainUid, from, batch, minNonce }) {
  return { types: UA_INVALIDATE_TYPES, primaryType: 'UAInvalidateNonces', domain: salted({ name, contract, chainId, chainUid }),
    message: { from: hex(bytes32(from)), batch: String(batch), minNonce: String(minNonce) } };
}

/** `CancelOrder(orderHash)` or `InvalidateNonces(from, batch, minNonce)` in the domain that holds the order (the sell
 *  token, or the DEX for an outside token). */
export function orderCancelTypedData({ name = 'SCaaS MetaToken', contract, chainId, chainUid, orderHash, invalidate }) {
  const domain = salted({ name, contract, chainId, chainUid });
  if (invalidate) {
    return { types: { EIP712Domain: SALTED_DOMAIN_TYPE, InvalidateNonces: fields(['from:address', 'batch:uint256', 'minNonce:uint256']) },
      primaryType: 'InvalidateNonces', domain,
      message: { from: invalidate.from, batch: String(invalidate.batch), minNonce: String(invalidate.minNonce) } };
  }
  return { types: { EIP712Domain: SALTED_DOMAIN_TYPE, CancelOrder: fields(['orderHash:bytes32']) }, primaryType: 'CancelOrder',
    domain, message: { orderHash } };
}

/** A cancel the user chose: `CancelOrder(orderHash)` of the client's own stored order, or `InvalidateNonces(account,
 *  batch, minNonce)`, in the domain that holds the order (`contract`: the sell token, or the DEX). `ua`: the account is
 *  a 32-byte id and the invalidation is `UAInvalidateNonces` (CTR-DEX-25). Returns the digest. */
export function checkCancel(td, { account, chainId, chainUid, contract, orderHash, invalidate, ua = false }) {
  const d = (td && td.domain) || {};
  const mine = digestOf(ua && invalidate
    ? uaInvalidateNoncesTypedData({ name: d.name, contract, chainId, chainUid, ...invalidate, from: account })
    : orderCancelTypedData({ name: d.name, contract, chainId, chainUid, orderHash,
      invalidate: invalidate && { ...invalidate, from: account } }));
  if (hex(digestOf(td)) !== hex(mine)) refuse('this is not the cancel you asked for');
  return mine;
}

/** A trade order that is exactly the one the client built from the user's input (CLI-SGN-35): `order` (receiveToken,
 *  amount, receiveAmount, minFill, fee, relayer, dex, destination, flags, batch, optional validUntil) from `account`,
 *  selling `sellToken` (`outside`: an outside token, signed as `DexOrder` in the DEX's domain, CTR-DEX-18). The order
 *  itself must name a DEX on the signer's pinned list (or, for a wrap by signature, CLI-SGN-36: `dex` = `receiveToken` =
 *  a pinned wrapper and `minFill = amount`), fee at most 1 %, known flags (no ESCROW on an outside token), non-zero
 *  amounts. The server supplies only the nonce and, when `order` has none, `validUntil` within the window. Returns
 *  {digest, minFill (the signed one: no protocol floor, CTR-DEX-14), warnings}. */
export function checkTradeOrder(td, { account, chainId, chainUid, order, sellToken, outside = false, dexes = [], wrappers = [],
  ua = false, now = Math.floor(Date.now() / 1000), maxWindow = 30 * 86400 }) {
  if (ua && outside) refuse('a UA order sells a SCaaS token only');
  if (!td || td.primaryType !== (outside ? 'DexOrder' : ua ? 'UATradeOrder' : 'TradeOrder')) refuse('this is not the trade order you asked for');
  const got = (outside ? (td.message || {}).order : td.message) || {};
  const none = ua ? ZERO_ID : ZERO_ADDRESS;
  const o = { minFill: '0', fee: '0', relayer: ZERO_ADDRESS, destination: none, flags: 0, batch: '0', ...order,
    from: account, nonce: uint(got.nonce, 'the nonce'), validUntil: (order || {}).validUntil ?? got.validUntil };
  if (o.nonce >= 2n ** 128n) refuse('the order nonce is at or above 2^128; the chain refuses it');
  if (wrappers.some((w) => same(w, o.dex))) {
    if (outside || !same(o.receiveToken, o.dex) || uint(o.minFill, 'minFill') !== uint(o.amount, 'the amount')) {
      refuse('a wrap by signature mints from this wrapper, all or nothing');
    }
  } else if (!dexes.some((x) => same(x, o.dex))) {
    refuse('the order names a DEX that is not on your chain profile');
  }
  if (uint(o.fee, 'the fee') > 10000n) refuse('the fee is above 1 %');
  const flags = uint(o.flags, 'the flags');
  if (flags & ~7n || (flags & 2n && (outside || !(flags & 1n)))) refuse('unknown order flags');
  const amount = uint(o.amount, 'the amount');
  const minFill = uint(o.minFill, 'minFill');
  if (amount === 0n || uint(o.receiveAmount, 'the price') === 0n || minFill > amount) refuse('the amounts are malformed');
  deadline(o.validUntil, now, maxWindow);
  const d = td.domain || {};
  const digest = digestOf(outside
    ? tradeOrderTypedData({ dex: o.dex, name: d.name, sellToken, chainId, chainUid, order: o })
    : ua ? uaTradeOrderTypedData({ token: sellToken, name: d.name, chainId, chainUid, order: o })
      : tradeOrderTypedData({ token: sellToken, name: d.name, chainId, chainUid, order: o }));
  if (hex(digestOf(td)) !== hex(digest)) refuse('this is not the trade order you asked for');
  const idOf = (x) => (ua ? hex(bytes32(x)) : String(x).toLowerCase());
  const warnings = idOf(o.destination) === idOf(none) || idOf(o.destination) === idOf(account) ? []
    : ['someone else receives the proceeds'];
  if (same(o.relayer, ZERO_ADDRESS)) warnings.push('any submitter may settle this order and earn the relayer share');
  return { digest, minFill, warnings };
}

/** A bid's per-fill minimum in the sell token from a minimum in the base token: `ceil(minBase * amount / receiveAmount)`
 *  (CLI-SGN-35). Refused above `amount`, which the chain would refuse as `BadMinFill`. */
export function bidMinFill(minBase, amount, receiveAmount) {
  const r = uint(receiveAmount, 'the price');
  if (r === 0n) refuse('the amounts are malformed');
  const a = uint(amount, 'the amount');
  const m = (uint(minBase, 'the base minimum') * a + r - 1n) / r;
  if (m > a) refuse('that base minimum needs more than the bid\'s amount');
  return m;
}

/** The base-token minimum a bid's `minFill` guarantees: `ceil(minFill * receiveAmount / amount)`. */
export function bidMinBase(minFill, amount, receiveAmount) {
  const a = uint(amount, 'the amount');
  if (a === 0n) refuse('the amounts are malformed');
  return (uint(minFill, 'minFill') * uint(receiveAmount, 'the price') + a - 1n) / a;
}
