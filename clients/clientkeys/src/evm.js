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
  if (type === 'bytes32') return fromHex(value);
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
const DEX_ORDER_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, DexOrder: fields(['sellToken:address', 'order:TradeOrder']),
  TradeOrder: TRADE_ORDER };
const sel = (sig) => hex(keccak_256(utf8ToBytes(sig)).subarray(0, 4));
// Never inside a `MetaTransaction` (CLI-SGN-34): moving funds is a `MetaTransfer`, and EOAs never approve (CLI-SGN-36).
const NEVER_CALLED = new Set(['transfer(address,uint256)', 'transferFrom(address,address,uint256)',
  'approve(address,uint256)', 'payWithFee(address,uint256,uint8,uint256,address,bytes32)', 'pay(bytes32)'].map(sel));
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

/** The server's typed data must be a token payment `MetaTransfer` of exactly the shown `amount` (in the token's
 *  `decimals`) from `account`, in the token's domain salted with the signer's own `chainUid` (CLI-SGN-33), on the
 *  signer's pinned `expectedToken` when given (CLI-SGN-08), with a non-zero reference (the request's, when `entryRef` is
 *  given), no fee, a near deadline (CLI-SGN-05). Returns {digest, payee, token, entryRef}. */
export function checkPayment(td, { account, chainId, chainUid, amount, decimals, entryRef, expectedToken,
  now = Math.floor(Date.now() / 1000), maxWindow = 86400 }) {
  if (!td || td.primaryType !== 'MetaTransfer') refuse('this is not a payment');
  const m = td.message || {};
  const d = td.domain || {};
  if (uint(d.chainId, 'the chain') !== BigInt(chainId)) refuse('wrong network');
  if (!/^0x[0-9a-fA-F]{40}$/.test(String(d.verifyingContract)) || same(d.verifyingContract, account)) refuse('wrong token');
  // CLI-SGN-08: the token from the signer's own profile, never from the server
  if (expectedToken !== undefined && !same(d.verifyingContract, expectedToken)) refuse('wrong token');
  if (!same(m.from, account)) refuse('the payment is not from your account');
  if (uint(m.value, 'the amount') !== toBase(amount, decimals)) refuse('the amount differs from what you were shown');
  if (!/^0x[0-9a-fA-F]{64}$/.test(String(m.entryRef)) || BigInt(m.entryRef) === 0n) refuse('this is not a payment');
  if (entryRef !== undefined && !same(m.entryRef, entryRef)) refuse('the payment reference differs from the request');
  if (uint(m.fee, 'the fee') !== 0n) refuse('the payment carries a fee');
  if (![0, 1].includes(Number(m.mode))) refuse('unexpected payment mode');
  deadline(m.validUntil, now, maxWindow);
  const mine = metaTransferTypedData({ name: d.name, contract: d.verifyingContract, chainId, chainUid, message: m });
  const digest = digestOf(mine);
  if (hex(digestOf(td)) !== hex(digest)) refuse('unexpected payment fields');
  return { digest, payee: m.to, token: d.verifyingContract, entryRef: m.entryRef };
}

/** A self-call `MetaTransaction` (CTR-MTX-17) the user asked for: `data` decoded against the contract's published
 *  allowlist `[{selector, name, feeClass}]` (`mtxSelectors()`, pinned per implementation version, CLI-SGN-34); an
 *  unknown selector, a transfer/pay selector or an approval is refused; a PERCENT fee on an ABSOLUTE selector too.
 *  Returns {digest, selector, name} for the review screen. */
export function checkCall(td, { account, chainId, chainUid, allowlist, now = Math.floor(Date.now() / 1000), maxWindow = 3600 }) {
  if (!td || td.primaryType !== 'MetaTransaction') refuse('this is not a contract call');
  const m = td.message || {};
  const d = td.domain || {};
  if (uint(d.chainId, 'the chain') !== BigInt(chainId)) refuse('wrong network');
  if (!same(m.from, account)) refuse('the call is not from your account');
  let data;
  try { data = fromHex(m.data); } catch { refuse('malformed data'); }
  if (data.length < 4) refuse('the call names no function');
  const selector = hex(data.subarray(0, 4));
  if (NEVER_CALLED.has(selector)) refuse('moving funds or an approval is never signed as a call');
  const row = (allowlist || []).find((r) => same(r.selector, selector));
  if (!row) refuse('the function is not on the contract\'s allowlist');
  if (Number(row.feeClass) === 1 && (Number(m.mode) & 0xf0) === 0x10) refuse('a percentage fee on a fixed-fee call');
  deadline(m.validUntil, now, maxWindow);
  const mine = metaTxTypedData({ name: d.name, contract: d.verifyingContract, chainId, chainUid, message: m });
  const digest = digestOf(mine);
  if (hex(digestOf(td)) !== hex(digest)) refuse('unexpected call fields');
  return { digest, selector, name: row.name };
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

/** A trade order the user asked for (CLI-SGN-35): `dex` on the signer's pinned list of listed DEXes (or, for a wrap by
 *  signature, CLI-SGN-36: `dex` = `receiveToken` = a pinned wrapper of that underlying and `minFill = amount`), `from`
 *  the account, fee at most 1 %, known flags, a near deadline, the salt of the signer's chain. Returns {digest,
 *  minFill (the effective one per settlement), warnings}. */
export function checkTradeOrder(td, { account, chainId, chainUid, dexes = [], wrappers = [], now = Math.floor(Date.now() / 1000),
  maxWindow = 30 * 86400 }) {
  if (!td || !['TradeOrder', 'DexOrder'].includes(td.primaryType)) refuse('this is not a trade order');
  const outside = td.primaryType === 'DexOrder';
  const o = (outside ? (td.message || {}).order : td.message) || {};
  const d = td.domain || {};
  if (uint(d.chainId, 'the chain') !== BigInt(chainId)) refuse('wrong network');
  if (!same(o.from, account)) refuse('the order is not from your account');
  const wrap = wrappers.some((w) => same(w, o.dex));
  if (wrap) {
    if (outside || !same(o.receiveToken, o.dex) || uint(o.minFill, 'minFill') !== uint(o.amount, 'the amount')) {
      refuse('a wrap by signature mints from this wrapper, all or nothing');
    }
  } else if (!dexes.some((x) => same(x, o.dex))) {
    refuse('the order names a DEX that is not on your chain profile');
  }
  if (outside && !same(d.verifyingContract, o.dex)) refuse('an outside-token order is signed for its own DEX');
  if (uint(o.fee, 'the fee') > 10000n) refuse('the fee is above 1 %');
  if (BigInt(o.flags) & ~7n || (BigInt(o.flags) & 2n && !(BigInt(o.flags) & 1n))) refuse('unknown order flags');
  const amount = uint(o.amount, 'the amount');
  if (amount === 0n || uint(o.receiveAmount, 'the price') === 0n || uint(o.minFill, 'minFill') > amount) refuse('the amounts are malformed');
  deadline(o.validUntil, now, maxWindow);
  const mine = outside
    ? tradeOrderTypedData({ dex: d.verifyingContract, name: d.name, sellToken: td.message.sellToken, chainId, chainUid, order: o })
    : tradeOrderTypedData({ token: d.verifyingContract, name: d.name, chainId, chainUid, order: o });
  const digest = digestOf(mine);
  if (hex(digestOf(td)) !== hex(digest)) refuse('unexpected order fields');
  const half = amount - amount / 2n;
  const minFill = uint(o.minFill, 'minFill') > half ? uint(o.minFill, 'minFill') : half;
  const warnings = same(o.destination, ZERO_ADDRESS) || same(o.destination, o.from) ? [] : ['someone else receives the proceeds'];
  if (same(o.relayer, ZERO_ADDRESS)) warnings.push('any submitter may settle this order and earn the relayer share');
  return { digest, minFill, warnings };
}
