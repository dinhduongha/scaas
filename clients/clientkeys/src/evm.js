// EVM pieces: EIP-712 digests, addresses, SmartKeyAccount key/salt/CREATE2, Merkle batch, the typed builder of every named entry.
import {
  keccak_256, sha256, concatBytes, utf8ToBytes, bytesToHex, fromHex, hex, word, boolWord, addressWord, abiEncode, bytes32,
} from './bytes.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';

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

const elementType = (t) => t.replace(/\[\]$/, '');

/** Every struct type `primary` references (not itself), sorted by name. */
function structDeps(types, primary) {
  const deps = new Set();
  const walk = (t) => types[t].forEach((f) => {
    const e = elementType(f.type);
    if (types[e] && e !== primary && !deps.has(e)) { deps.add(e); walk(e); }
  });
  walk(primary);
  return [...deps].sort();
}

const encodeOne = (types, t) => `${t}(${types[t].map((f) => `${f.type} ${f.name}`).join(',')})`;

/** EIP-712 `encodeType`: the primary type, then every struct it references, sorted by name. */
export function encodeType(types, primary) {
  return [primary, ...structDeps(types, primary)].map((t) => encodeOne(types, t)).join('');
}

function encodeValue(type, value, types) {
  if (type.endsWith('[]')) return keccak_256(concatBytes(...value.map((v) => encodeValue(elementType(type), v, types))));
  if (types && types[type]) return hashStruct(types, type, value);
  if (type === 'string') return keccak_256(utf8ToBytes(String(value)));
  if (type === 'bytes') return keccak_256(value instanceof Uint8Array ? value : fromHex(value));
  if (type === 'address') return addressWord(value);
  if (type === 'bool') return boolWord(value);
  if (type === 'bytes32') return bytes32(value);
  if (/^bytes\d+$/.test(type)) return abiEncode([type], [value]);
  if (/^uint\d+$/.test(type)) return word(value);
  if (/^int\d+$/.test(type)) return intWord(type, value);
  throw new Error(`EIP-712 type ${type} is not supported here`);
}

/** `intN` (EIP-712, as `abi.encode`): the sign-extended 32-byte word, refused outside the type's range. */
export function intWord(type, value) {
  const bits = BigInt(type.slice(3));
  const v = BigInt(value);
  if (v < -(1n << (bits - 1n)) || v >= 1n << (bits - 1n)) throw new Error(`${type} out of range: ${value}`);
  return word(BigInt.asUintN(256, v));
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

// ------------------------------------------------------------------ ERC-7739 (CTR-ACC-02, B P3-2)

/** ERC-7739 `TypedDataSign`: what a key of a `SmartKeyAccount`, or a `MandateWallet`'s native owner, signs for the
 *  wallet's ERC-1271 answer over the app's typed data `td`: `td`'s message nested as `contents` (its fields stay readable),
 *  the wallet's own domain fields beside it, in the app's domain. `wallet`: `SmartKeyAccount` or `MandateWallet`
 *  (`HederaMandateWallet` too); `address`: the wallet's. Its `hashTypedData` is the message the key signs (in a batch,
 *  the leaf's digest); `erc7739Signature` wraps the result. */
export function erc7739TypedData(td, { wallet, address, chainId, chainUid }) {
  if (wallet !== 'SmartKeyAccount' && wallet !== 'MandateWallet') throw new Error(`no ERC-7739 answer from ${wallet}`);
  if (td.types.TypedDataSign) throw new Error('the contents already define TypedDataSign');
  // the wallet refuses a contentsName that is empty, starts a-z, or holds `, ()` space or NUL (ERC7739Lib, EIP-7739)
  if (!/^[^a-z, ()\0][^, ()\0]*$/.test(td.primaryType ?? '')) throw new Error(`ERC-7739 refuses the contents name ${td.primaryType}`);
  return {
    types: { ...td.types, TypedDataSign: [{ name: 'contents', type: td.primaryType }, { name: 'name', type: 'string' },
      { name: 'version', type: 'string' }, { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' },
      { name: 'salt', type: 'bytes32' }] },
    primaryType: 'TypedDataSign',
    domain: td.domain,
    message: { contents: td.message, name: DOMAIN_OF[wallet], version: '1', chainId, verifyingContract: address, salt: chainUid },
  };
}

/** The signature the wallet's `isValidSignature(hashTypedData(td), ·)` takes: `inner ‖ APP_DOMAIN_SEPARATOR ‖
 *  hashStruct(contents) ‖ contentsDescription ‖ uint16(contentsDescription.length)`. `contentsDescription` is the contents'
 *  types sorted by name (as `TypedDataSign`'s `encodeType` lists them): implicit mode when `td.primaryType` sorts first,
 *  else explicit (`contentsType ‖ contentsName`). `inner`: the key's signature (`accountSignature(…)` for an account). */
export function erc7739Signature(inner, td) {
  const names = [td.primaryType, ...structDeps(td.types, td.primaryType)].sort();
  const contentsType = names.map((t) => encodeOne(td.types, t)).join('');
  const descr = utf8ToBytes(names[0] === td.primaryType ? contentsType : contentsType + td.primaryType);
  if (descr.length > 0xffff) throw new Error('contents description too long');
  return concatBytes(inner instanceof Uint8Array ? inner : fromHex(inner), hashStruct(td.types, 'EIP712Domain', td.domain),
    hashStruct(td.types, td.primaryType, td.message), descr, new Uint8Array([descr.length >> 8, descr.length & 0xff]));
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
const ZERO_ADDRESS = '0x' + '00'.repeat(20);
const ZERO_ID = '0x' + '00'.repeat(32);
const fields = (list) => list.split(',').filter(Boolean).map((f) => {
  const [type, name] = f.split(' ');
  return { name, type };
});
// `E`, the envelope closing every meta-transaction struct, and the structs that differ only by the id type.
const E = 'uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient';
const orderOf = (id) => `${id} from,address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,uint256 fee,`
  + `address relayer,address dex,${id} destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil`;
const wrapOrderOf = (id) => `${id} from,address wrappedToken,uint256 amount,uint256 minMinted,uint256 minFill,uint256 fee,`
  + `address relayer,${id} destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil`;
const transferOf = (id) => `${id} from,${id} to,uint256 value,bytes32 entryRef,${E}`;
const relayFeeOf = (id) => `${id} from,address target,bytes32 callDataHash,${id} payee,uint256 value,uint256 batch,uint256 nonce,`
  + 'uint256 validUntil,address relayer';
const RECEIVER_FEE = 'uint256 fee,address feeRecipient,uint256 validUntil';

// Every struct a signed type nests or an entry takes (Appendix X.2). The last group is calldata only, never signed.
const STRUCTS = Object.fromEntries(Object.entries({
  // the order's sell side (CTR-DEX-13, CTR-DEX-25: ids as bytes32) and an outside token's `DexOrder` (CTR-DEX-18)
  // ua-mtx-merge (R12, R39, R46): the token's address `TradeOrder`, `WrapOrder` and `MetaTransfer` left; `TradeOrder` stays
  // nested in the DEX's `DexOrder` (an outside sell token)
  TradeOrder: orderOf('address'), UATradeOrder: orderOf('bytes32'), DexOrder: 'address sellToken,TradeOrder order',
  UAWrapOrder: wrapOrderOf('bytes32'),
  // the token's typed transfer and payment (CTR-MTX-23); `entryRef = 0` is a transfer, else a payment (CTR-UA-26 on ids)
  UAMetaTransfer: transferOf('bytes32'),
  // group 3g (KV-8): `keyVersion`, the debited key version of `fromUA`, after it in the three args structs; group 3h (pqz-proof-path
  // spec §3.2, PP-3): `ownTag` after `salt` (op 1, op 7) and after `beneficiaryUA` (the burn forms), `pqzOwnTag` below
  PqzTransferArgs: 'uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 toUA,bytes32 beneficiaryUA,bytes16 salt,'
    + 'bytes32 ownTag,bytes u,bytes vTo,bytes vFrom,bytes vAuditor,bytes sealedMemo',
  PqzLeg: 'bytes32 ua,bytes v,bytes vAuditor',
  PqzMultiArgs: 'uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 beneficiaryUA,uint256 decoyFee,bytes16 salt,'
    + 'bytes32 ownTag,bytes[] u,PqzLeg[] legs,bytes vFrom,bytes sealedMemo',
  PqzBurnArgs: 'uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 beneficiaryUA,bytes32 ownTag,bytes u,bytes vFrom',
  Unwrap: 'address underlying,bytes32 recipient,uint256 amount,uint256 minOut',
  G1: 'bytes32 x0,bytes32 x1,bytes32 y0,bytes32 y1',
  ZetherSingle: 'uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes16 salt,bytes32 beneficiaryUA,'
    + 'G1 yFrom,G1 yTo,G1 cOut,G1 dOut,G1 cDeb,G1 cAud',
  ZetherLeg: 'G1 yTo,G1 cOut,G1 cAud,G1 dAud',
  ZetherMulti: 'uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes16 salt,bytes32 beneficiaryUA,uint256 decoyFee,'
    + 'G1 yFrom,G1 dOut,G1 cDeb,ZetherLeg[] legs,bytes sealedMemo',
  ZetherBurn: 'uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes32 beneficiaryUA,G1 yFrom',
  Envelope: `address from,${E}`, UAEnvelope: `bytes32 from,${E}`, InnerSig: 'uint16 index,bytes sig',
  MemberSig: 'uint16 index,InnerSig[] members,bytes sig',
  UASig: 'bytes keyData,bytes signature,MemberSig[] members', AccountSig: 'uint256 keyIndex,bytes32[] proof,bytes signature',
  Payout: 'uint256 amount,bytes32 recipient',
  // pay-meta-tax spec §3.1: the last parameter of every pay entry, unsigned (its commitment is the signed `entryRef`)
  PayMeta: 'bytes32 salt,bytes32 payNo,bool save,uint16 schema,bytes body',
  // a holder's terms, nested in the router's `SetGrant` / `UASetGrant` (governance spec §3.2: `hashStruct` signed, the struct the argument)
  GrantTerms: 'uint128 min,uint128 max,uint128 total,uint128 perWindow,uint32 window,uint64 validUntil,uint32 maxUses,bool delegable,bytes32 scope',
  // group 3l (wrap limits spec 2026-11-10 §6, §9): a leg's limits, nested in the router's `UASetWrapLimits` as an array
  WrapLimit: 'uint24 perUser,uint64 tokenWide,uint32 period',
  WrapLegLimits: 'address underlying,uint8 unitExp,uint16 decayDays,WrapLimit wrapShort,WrapLimit wrapLong,WrapLimit unwrapShort,WrapLimit unwrapLong',
  // round 3r (spec 2026-11-10-admin-not-owner.md §5.4): a release env, nested in the router's three publishes (EIP-712: each
  // array the keccak256 of its 32-byte words); `ReleaseApproval` the class approval entry's one static struct (calldata only:
  // the struct `UAApproveRelease` signs its words flat)
  Env: 'address registry,address smartKeyAccountImpl,bool hedera,address[] deps,bytes32[] params,address[] libs,bytes32[] libCodeHashes',
  ReleaseApproval: 'uint16 contractClass,uint16 kind,uint64 version,uint16 envVersion,bytes4 initSelector,bytes4 interfaceId,'
    + 'bytes32 initcodeHash,bytes32 implArgsHash,bytes32 chainUid,address factory,uint32 adminGeneration,uint64 until',
  // group 3f (PQZ verifier mode spec §5.1, §5.3): what a PQZ verifier UA signs in the token's domain (purpose `pqz-verdict`), and
  // the pair every proof-carrying PQZ entry takes last, outside every `UA*` struct (unbound, like `relayer`)
  PqzVerdict: 'address token,uint256 chainId,bytes32 proofSystemId,bytes32 statementHash,bytes32 proofHash,uint32 pqzVerifierEpoch,uint64 validUntil',
  PqzSignedVerdict: 'PqzVerdict pqzVerdict,UASig sig',
}).map(([name, list]) => [name, fields(list)]));

const DOMAIN_OF = { NormalToken: 'SCaaS MetaToken', WrappedToken: 'SCaaS MetaToken', NormalZetherToken: 'SCaaS ZetherToken',
  WrappedZetherToken: 'SCaaS ZetherToken', NormalPqzToken: 'SCaaS PqzToken', WrappedPqzToken: 'SCaaS PqzToken',
  MandateWallet: 'SCaaS MandateWallet', SmartKeyAccount: 'SCaaS SmartKeyAccount', SCaaSDex: 'SCaaS Dex',
  GovernanceRouter: 'SCaaS GovernanceRouter', NormalRegulatedToken: 'SCaaS MetaToken', WrappedRegulatedToken: 'SCaaS MetaToken',
  NormalZetherRegulatedToken: 'SCaaS ZetherToken', WrappedZetherRegulatedToken: 'SCaaS ZetherToken',
  NormalPqzRegulatedToken: 'SCaaS PqzToken', WrappedPqzRegulatedToken: 'SCaaS PqzToken' };
const NORMAL = ['NormalToken', 'NormalZetherToken', 'NormalPqzToken'];
const WRAPPED = ['WrappedToken', 'WrappedZetherToken', 'WrappedPqzToken'];
const TOKENS = [...NORMAL, ...WRAPPED];
const ZETHER = ['NormalZetherToken', 'WrappedZetherToken'];
const PQZ = ['NormalPqzToken', 'WrappedPqzToken'];
const CONFIDENTIAL = [...ZETHER, ...PQZ];
const WRAPPED_CONFIDENTIAL = ['WrappedZetherToken', 'WrappedPqzToken'];
const WALLET = ['MandateWallet'];
const ACCOUNT = ['SmartKeyAccount'];
const ROUTER = ['GovernanceRouter'];
// The regulated kinds 8-13 (pay-meta-tax spec §5.1): their token, Zether and PQZ classes sign in the base kinds' domains.
const REGULATED = ['NormalRegulatedToken', 'WrappedRegulatedToken', 'NormalZetherRegulatedToken', 'WrappedZetherRegulatedToken',
  'NormalPqzRegulatedToken', 'WrappedPqzRegulatedToken'];

const isRaw = (s) => s instanceof Uint8Array || typeof s === 'string';
const required = (v, what) => (v === undefined ? refuse(`${what} is required`) : v);
/** A `UASig`: raw (a native id) or `{keyData, signature, members}`. No entry verifies an empty one (`_check`, `_authorize`). */
function uaSigOf(s, what = 'the signature') {
  const sig = { keyData: '0x', signature: '0x', members: [], ...(isRaw(s) ? { signature: s } : s) };
  if (asBytes(sig.signature).length === 0 && sig.members.length === 0) refuse(`${what} is required`);
  return sig;
}
/** An `AccountSig`: a raw ECDSA signature of key 0, or `{keyIndex, proof, signature}`; never `accountSignature`'s encoded blob. */
function accountSigOf(s) {
  if (!isRaw(s)) return { keyIndex: 0, proof: [], ...s };
  if (asBytes(s).length !== 65) refuse('a raw signature is 65 bytes; any other names its keyIndex, proof and signature');
  return { keyIndex: 0, proof: [], signature: s };
}
// A wrap order on the underlying's entries is the `TradeOrder` with `dex == receiveToken` (TS-D19).
const asTradeOrder = ({ wrappedToken, minMinted, ...o }) => ({ ...o, receiveToken: wrappedToken, receiveAmount: minMinted, dex: wrappedToken });
// The parameters after the envelope where they are not the struct's own fields in order (Appendix X.3). `pqzAuth` and
// `ownerSig` are signatures of their own, so never inside a signed struct (Appendix X.1).
const pqzAuthOf = (x) => ['UASig', uaSigOf(x.pqzAuth, 'pqzAuth')];
const pqzOp = (args) => (m, x) => [[args, m.args], ['bytes', m.proof], pqzAuthOf(x), ['bytes', m.accHint]];
const pqzUnshield = (m, x) => [['PqzBurnArgs', m.args], ['Payout', m], ['bytes', m.proof], pqzAuthOf(x), ['bytes', m.accHint]];
const pqzUnwrap = (m, x) => [['PqzBurnArgs', m.args], ['Unwrap', m.unwrap], ['bytes', m.proof], pqzAuthOf(x), ['bytes', m.accHint]];
const zetherOp = (args) => (m) => [[args, m.args], ['bytes', m.proof]];
const PQZ_TAIL = 'bytes proof,bytes accHint';
// group 3f (spec §5.3): the verdict after `auth` on the six signed PQZ entries, `x.pqzVerdict` (`EMPTY_PQZ_VERDICT` on a
// PRECOMPILE token, which never reads it)
const pqzVerdictTail = (m, x = {}) => [['PqzSignedVerdict', pqzSignedVerdictOf(x.pqzVerdict)]];
// A pay entry's last parameter (pay-meta-tax spec §2.1): `x.meta`, checked by `payMeta` (never empty, O11).
const payMetaTail = (m, x = {}) => [['PayMeta', payMeta(required(x.meta, 'the payment metadata'))]];

// The one table of the type strings (plan Part C, Appendix X.4). ua-mtx-merge (CTR-MTX-30): one signed entry per operation.
// `fields`: an envelope op. `UA<Op>` is the merged entry `mtx<Op>(UAEnvelope e, <op>, UASig auth)` over `UA<Op>(bytes32 from,
// <fields>,E)`, natives and derived ids alike (R1, R47); any other name is an address entry `mtx<Op>(Envelope e, <op>, bytes sig)`
// over `<Op>(address from,<fields>,E)`, kept only where the op has no merged entry: the five wraps (spec §2.1) and every op of
// `SmartKeyAccount` (`AccountSig` on its own, Appendix X row 13). `entry`: the name when it is not the struct's (TS-D16),
// `args`: the parameters. `raw`: a struct without `E`, with the whole `entry` and `call`. `on`: the contracts that take it.
// `amount`: the op's amount field where the fee class is AMOUNT (CTR-MTX-20). The address rows of merged ops, and the
// `ua*` names, are in legacy/ua-mtx-merge/src/evm.js.
const OPS = {
  // the account's address cancel; the ordered cancel on ids everywhere else (Q2: nonce-ordered, natives and derived ids)
  CancelNonce: { fields: 'uint256 lane', on: ACCOUNT },
  UACancelNonce: { fields: 'uint256 lane', on: [...TOKENS, ...WALLET, ...ROUTER] },
  UABurn: { fields: 'uint256 amount', on: NORMAL, amount: 'amount' },
  Wrap: { fields: 'uint256 amount', on: WRAPPED },
  WrapLeg: { fields: 'address underlying,uint256 amount', on: WRAPPED },
  UAUnwrap: { fields: 'uint256 wrapped,address recipient,uint256 minOut', on: WRAPPED, amount: 'wrapped' },
  UAUnwrapLeg: { fields: 'address underlying,uint256 wrapped,address recipient,uint256 minOut', on: WRAPPED, amount: 'wrapped' },
  AddReserve: { fields: 'address underlying,uint256 amount', on: WRAPPED },
  WrapToUA: { fields: 'address underlying,uint256 amount,bytes32 to', on: WRAPPED },
  UAUnwrapToUA: { fields: 'address underlying,uint256 wrapped,bytes32 to,uint256 minOut', on: WRAPPED, amount: 'wrapped' },
  // R47: `mtxShield` takes `UASig` (the C0 spike's `bytes auth` is legacy)
  UAShield: { fields: 'bytes32 toUA,uint256 amount', on: CONFIDENTIAL },
  WrapShield: { fields: 'address underlying,uint256 amountIn,bytes32 toUA', on: WRAPPED_CONFIDENTIAL },
  // group 3g (KV-10, §10 row 21): Zether keeps `UARollOver(…,bytes32 ua,uint256 n,…)`; the PQZ rollover and prepare name the
  // key version, one row per kind (the PQZ struct keeps the name `UARollOver`; its builders `uaPqzRollOver*`)
  UARollOver: { fields: 'bytes32 ua,uint256 n', on: ZETHER },
  UAPqzRollOver: { primary: 'UARollOver', builder: 'uaPqzRollOver', fields: 'bytes32 ua,uint64 keyVersion,uint256 n', on: PQZ },
  UAPrepareAcc: { fields: 'bytes32 ua,uint64 keyVersion,uint256 half', on: PQZ },
  // MandateWallet (Q6, MD-11; spec §2.7): the owner's three, the delegate's two (CTR-ACC-07), the arbitrary call; ids `bytes32`
  UASetMandate: { fields: 'address token,bytes32 delegate,uint128 maxPerPayment,uint128 maxPerPeriod,uint64 periodSeconds,uint64 expiry', on: WALLET },
  UASetPayee: { fields: 'address token,bytes32 payee,bool allowed', on: WALLET },
  UARevokeMandate: { fields: 'address token', on: WALLET },
  // pay-meta-tax spec §2.4: `PayMeta` the last parameter, unsigned, bound by the signed `entryRef` (`x.meta`)
  UAPayUnderMandate: { fields: 'address token,bytes32 payee,uint256 amount,bytes32 entryRef,uint64 epoch', on: WALLET, tail: payMetaTail },
  UADelegateRevoke: { fields: 'address token,uint64 epoch', on: WALLET },
  UAExecute: { fields: 'address target,uint256 value,bytes data', on: WALLET },
  // SmartKeyAccount: `SubjectKey` flattened, its own entries signed with `AccountSig` (Appendix X row 13)
  AddKey: { fields: 'uint8 kind,bytes32 x,bytes32 y,bytes32 rpIdHash,bytes32 originHash', on: ACCOUNT, accountSig: true },
  RemoveKey: { fields: 'uint256 index', on: ACCOUNT, accountSig: true },
  RotateKey: { fields: 'uint256 index,uint8 kind,bytes32 x,bytes32 y,bytes32 rpIdHash,bytes32 originHash', on: ACCOUNT, accountSig: true },
  SetGuardian: { fields: 'address guardian', on: ACCOUNT, accountSig: true },
  CancelRecovery: { fields: '', on: ACCOUNT, accountSig: true },
  Execute: { fields: 'address target,uint256 value,bytes data', on: ACCOUNT, accountSig: true },
  // PQZ (Appendix X.3; `Payout` as C0 found: the flat `amount, recipient` does not compile there, evm-size-levers.md §7)
  UAPqzTransferSingle: { fields: `PqzTransferArgs args,${PQZ_TAIL}`, on: PQZ, entry: 'ConfidentialTransferSingle', args: pqzOp('PqzTransferArgs'),
    tail: pqzVerdictTail },
  UAPqzTransferSingleCompact: { fields: `PqzTransferArgs args,${PQZ_TAIL}`, on: PQZ, entry: 'ConfidentialTransferSingleCompact',
    args: pqzOp('PqzTransferArgs'), tail: pqzVerdictTail },
  UAPqzTransfer: { fields: `PqzMultiArgs args,${PQZ_TAIL}`, on: PQZ, entry: 'ConfidentialTransfer', args: pqzOp('PqzMultiArgs'),
    tail: pqzVerdictTail },
  UAPqzTransferCompact: { fields: `PqzMultiArgs args,${PQZ_TAIL}`, on: PQZ, entry: 'ConfidentialTransferCompact', args: pqzOp('PqzMultiArgs'),
    tail: pqzVerdictTail },
  UAPqzUnshield: { fields: `PqzBurnArgs args,uint256 amount,bytes32 recipient,${PQZ_TAIL}`, on: PQZ, entry: 'Unshield', args: pqzUnshield,
    tail: pqzVerdictTail },
  UAPqzUnshieldUnwrap: { fields: `PqzBurnArgs args,Unwrap unwrap,${PQZ_TAIL}`, on: ['WrappedPqzToken'], entry: 'UnshieldUnwrap', args: pqzUnwrap,
    tail: pqzVerdictTail },
  // Zether (Appendix X.3)
  UAZetherTransferSingle: { fields: 'ZetherSingle args,bytes proof', on: ZETHER, entry: 'ConfidentialTransferSingle', args: zetherOp('ZetherSingle') },
  UAZetherTransfer: { fields: 'ZetherMulti args,bytes proof', on: ZETHER, entry: 'ConfidentialTransfer', args: zetherOp('ZetherMulti') },
  UAZetherTransferCompact: { fields: 'ZetherMulti args,bytes proof', on: ZETHER, entry: 'ConfidentialTransferCompact', args: zetherOp('ZetherMulti') },
  UAZetherUnshield: { fields: 'ZetherBurn args,uint256 amount,bytes32 recipient,bytes proof', on: ZETHER, entry: 'Unshield',
    args: (m) => [['ZetherBurn', m.args], ['uint256', m.amount], ['bytes32', m.recipient], ['bytes', m.proof]] },
  UAZetherUnshieldUnwrap: { fields: 'ZetherBurn args,Unwrap unwrap,bytes proof', on: ['WrappedZetherToken'], entry: 'UnshieldUnwrap',
    args: (m) => [['ZetherBurn', m.args], ['Unwrap', m.unwrap], ['bytes', m.proof]] },
  UARollOverSigned: { fields: 'bytes32 ua,uint64 expectedPendingSeq,uint64 validUntilBlock', on: ZETHER,
    args: (m, x) => [['bytes32', m.ua], ['uint64', m.expectedPendingSeq], ['uint64', m.validUntilBlock], ['UASig', uaSigOf(x.ownerSig, 'ownerSig')]] },
  UASetRollOverMode: { fields: 'bytes32 ua,uint8 rollOverMode,uint64 validUntilBlock', on: ZETHER,
    args: (m, x) => [['bytes32', m.ua], ['uint8', m.rollOverMode], ['uint64', m.validUntilBlock], ['UASig', uaSigOf(x.ownerSig, 'ownerSig')]] },
  UARollOverBatch: { fields: 'bytes32[] uas', on: ZETHER },
  // TS-D19: `x.payerSig` is the payer's signature of the nested `UAMetaTransfer`
  UAReceiverFee: { raw: `UAMetaTransfer payment,${RECEIVER_FEE}`, on: TOKENS, entry: 'mtxPayReceiverFee', call: (m, sig, x) => [['UAMetaTransfer', m.payment],
    ['UASig', uaSigOf(x.payerSig, 'payerSig')], ['uint256', m.fee], ['address', m.feeRecipient], ['uint256', m.validUntil], ['UASig', uaSigOf(sig)],
    ...payMetaTail(m, x)] },
  // pay-meta-tax spec §5.2: the payer signs the payment with its tax (kinds 8-13); `x.meta` the `PayMeta`
  UAPayWithTax: { raw: 'UAMetaTransfer payment,uint8 taxMode,uint256 tax', on: REGULATED, entry: 'mtxPayWithTax',
    call: (m, sig, x) => [['UAMetaTransfer', m.payment], ['uint8', m.taxMode], ['uint256', m.tax], ['UASig', uaSigOf(sig)], ...payMetaTail(m, x)] },
  // The router calls this as the struct's `relayer` (`msg.sender`), on the payer's own lane `(batch, nonce)` (pay-meta-tax O4).
  UARelayFee: { raw: relayFeeOf('bytes32'), on: TOKENS, entry: 'mtxRelayFee', call: (m, sig) => [['bytes32', m.from], ['address', m.target],
    ['bytes32', m.callDataHash], ['bytes32', m.payee], ['uint256', m.value], ['uint256', m.batch], ['uint256', m.nonce],
    ['uint256', m.validUntil], ['UASig', uaSigOf(sig)]] },
  // Signed in the underlying's domain, submitted to `wrappedToken`, which needs the leg: `underlying` is `verifyingContract`.
  UAWrapOrder: { raw: wrapOrderOf('bytes32'), on: TOKENS, entry: 'mtxWrapOrder',
    call: (m, sig, x, td) => [['address', td.domain.verifyingContract], ['UAWrapOrder', m], ['UASig', uaSigOf(sig)]] },
  // The cancel nests the struct the order was signed in; a wrap order goes through the same entry as the order form.
  CancelUAOrder: { raw: 'UATradeOrder order', on: TOKENS, entry: 'mtxCancelOrder', call: (m, sig) => [['UATradeOrder', m.order], ['UASig', uaSigOf(sig)]] },
  CancelUAWrapOrder: { raw: 'UAWrapOrder order', on: TOKENS, entry: 'mtxCancelOrder',
    call: (m, sig) => [['UATradeOrder', asTradeOrder(m.order)], ['UASig', uaSigOf(sig)]] },
  CancelDexOrder: { raw: 'DexOrder order', on: ['SCaaSDex'], entry: 'mtxCancelOrders', call: (m, sig) => [['DexOrder[]', [m.order]], ['bytes[]', [sig]]] },
  // The owner's own signature (purpose `zether-owner`), `ownerSig` of the direct ops and of `UARollOverSigned` / `UASetRollOverMode`.
  ZetherRollOver: { raw: 'bytes32 ua,uint64 accSeq,uint64 expectedPendingSeq,uint64 validUntilBlock', on: ZETHER, entry: 'mtxRollOverSigned',
    call: (m, sig) => [['bytes32', m.ua], ['uint64', m.expectedPendingSeq], ['uint64', m.validUntilBlock], ['UASig', uaSigOf(sig)]] },
  ZetherSetRollOverMode: { raw: 'bytes32 ua,uint8 mode,uint64 modeNonce,uint64 validUntilBlock', on: ZETHER, entry: 'mtxSetRollOverMode',
    call: (m, sig) => [['bytes32', m.ua], ['uint8', m.mode], ['uint64', m.validUntilBlock], ['UASig', uaSigOf(sig)]] },
  // GovernanceRouter, one per chain (governance spec §3.2, CTR-GOV-15 Change; R14): the closed table, each op `mtx<Op>` over
  // `UA<Op>`, `target` (the governed contract) the first op word, identities `bytes32`, fee mode NONE; no generic path.
  UAGrantRole: { fields: 'address target,uint8 bit,bytes32 account', on: ROUTER },
  UARevokeRole: { fields: 'address target,uint8 bit,bytes32 account', on: ROUTER },
  UASetGrant: { fields: 'address target,uint8 bit,bytes32 holder,GrantTerms terms', on: ROUTER },
  UACancelGrant: { fields: 'address target,uint8 bit,bytes32 account', on: ROUTER },
  UADisableFeature: { fields: 'address target,uint8 bit', on: ROUTER },
  UATransferAdmin: { fields: 'address target,bytes32 newAdmin', on: ROUTER },
  UAAcceptAdmin: { fields: 'address target', on: ROUTER },
  UARenounceAdmin: { fields: 'address target,bytes32 chainUid', on: ROUTER },
  UARenounceRole: { fields: 'address target,uint8 bit', on: ROUTER },
  UAMint: { fields: 'address target,address to,uint256 amount', on: ROUTER },
  UAMintToUA: { fields: 'address target,bytes32 to,uint256 amount', on: ROUTER },
  UADisableWrap: { fields: 'address target,address leg,bytes32 reason', on: ROUTER },
  UAProposeRate: { fields: 'address target,address leg,uint96 num,uint96 den', on: ROUTER },
  UACancelRate: { fields: 'address target', on: ROUTER },
  UAExecuteRate: { fields: 'address target', on: ROUTER },
  UASetMarket: { fields: 'address target,address base,address quote,bool listed', on: ROUTER },
  UASetExchangeTarget: { fields: 'address target,address exchangeTarget,bool listed', on: ROUTER },
  UASetListedOnly: { fields: 'address target,bool on', on: ROUTER },
  UASetFeeSplit: { fields: 'address target,uint32 relayerSharePpm,address treasury', on: ROUTER },
  // The factory's creations (chain-neutral spec §4.4, S3; ua-mtx-merge T76): `target` the chain's `OpenFactory`, the signing
  // UA the creator; `initHash = keccak256(initArgs)` (`initCall` for an instance) is signed, the bytes go in `extra`.
  UACreateToken: { fields: 'address target,uint8 kind,uint64 version,bytes32 initHash,bytes32 salt', on: ROUTER,
    args: (m, x) => [['address', m.target], ['uint8', m.kind], ['uint64', m.version], ['bytes', initOf(m, x, 'initArgs')],
      ['bytes32', m.salt]] },
  UACreateDex: { fields: 'address target,uint64 version,bytes32 initHash,bytes32 salt', on: ROUTER,
    args: (m, x) => [['address', m.target], ['uint64', m.version], ['bytes', initOf(m, x, 'initArgs')], ['bytes32', m.salt]] },
  UACreateInstance: { fields: 'address target,uint16 contractClass,uint16 kind,uint64 version,bytes32 initHash,bytes32 salt',
    on: ROUTER, args: (m, x) => [['address', m.target], ['uint16', m.contractClass], ['uint16', m.kind], ['uint64', m.version],
      ['bytes', initOf(m, x, 'initCall')], ['bytes32', m.salt]] },
  // The regulated kinds' controls (regulated-kinds spec §3.1, ua-mtx-merge T32 / T34): the direct entry's params after
  // `target`; in `UAOperatorTransfer` the moved account is `account`, `from` the signer (CTR-GOV-20 Change, owner 2026-11-06).
  UAFreeze: { fields: 'address target,bytes32 account,bytes32 ref,bytes32 recordId', on: ROUTER },
  UAUnfreeze: { fields: 'address target,bytes32 account,bytes32 ref', on: ROUTER },
  UAForceTransfer: { fields: 'address target,bytes32 recordId,uint256 amount', on: ROUTER },
  UAPause: { fields: 'address target,bytes32 ref,uint64 until', on: ROUTER },
  UAUnpause: { fields: 'address target,bytes32 ref', on: ROUTER },
  UARecordOrder: { fields: 'address target,bytes32 orderId,bytes32 documentHash,bytes32 subject,bytes32 beneficiary,'
    + 'uint256 maxAmount,uint64 freezeUntil', on: ROUTER },
  UARevokeOrder: { fields: 'address target,bytes32 recordId,bytes32 reasonRef', on: ROUTER },
  UAOperatorTransfer: { fields: 'address target,bytes32 account,bytes32 to,uint256 amount,bytes32 ref', on: ROUTER },
  // bit 23 `TAX` (pay-meta-tax spec §6.2): the one PERCENT rate, the recipient
  UASetTaxRate: { fields: 'address target,uint32 ratePpm', on: ROUTER },
  UASetTaxRecipient: { fields: 'address target,bytes32 taxRecipient', on: ROUTER },
  // the PQZ verifier UA of the PQZ kinds 4, 5, 12, 13 (group 3f, PQZ verifier mode spec §4.2, §4.3): the owner's, no bit
  UAPqzSetVerifier: { fields: 'address target,bytes32 next', on: ROUTER },
  UAPqzCancelVerifier: { fields: 'address target', on: ROUTER },
  UAPqzRevokeVerifier: { fields: 'address target', on: ROUTER },
  // round 3t (CTR-PQZ-36): the admin's verifier fee of an `OFFCHAIN` PQZ token, no bit (a decrease at once, an increase after
  // the notice)
  UASetVerifierFee: { fields: 'address target,uint64 next', on: ROUTER },
  // bit 24 `PQZ_PROOF` of the PQZ kinds 4, 5, 12, 13 (group 3h, PQZ proof path spec §5): `NONE` or `LOG` from the next debit
  UASetProofStore: { fields: 'address target,uint8 next', on: ROUTER },
  // group 3l (wrap limits spec §9): the owner's limits on a hybrid of the wrapped kinds (two calls when it relaxes the wrap side
  // or tightens the unwrap side) and bit 26's membership
  UASetWrapLimits: { fields: 'address target,WrapLegLimits[] legs,bool netUnwrap,bool wrapList,bool unwrapList', on: ROUTER },
  UASetWrapMember: { fields: 'address target,bytes32 account,bool canWrap,bool canUnwrap', on: ROUTER },
  // round 3s (CTR-GOV-24, spec 2026-11-10-token-lists.md §5.3, §6.2): the lists of the regulated kinds 8-13 (bit 8's holder, bit
  // 9's; 1-256 accounts, signed as the keccak256 of their words) and the admin's enableFeature of 8, 9 or 28
  UASetAllowed: { fields: 'address target,bytes32[] accounts,bool on', on: ROUTER },
  UASetDenied: { fields: 'address target,bytes32[] accounts,bool on', on: ROUTER },
  UAEnableFeature: { fields: 'address target,uint8 bit', on: ROUTER },
  // round 3r (CTR-GOV-23, spec 2026-11-10-admin-not-owner.md §5.4; owner naming 2026-11-11): the admin of `OpenFactory` (its
  // envs, the release approvals of §5.6, the revoke, the deprecations, the kind switches, the directory of §13.3) and of a
  // `ComplianceRegistry` (its KYC providers; the rows by the admin or a provider); `target` the factory or the registry, the
  // ids flat; the class approval's entry takes its words as one static struct (`ReleaseApproval`, the same calldata).
  UAPublishTokenEnv: { fields: 'address target,uint8 kind,uint16 envVersion,Env env', on: ROUTER },
  UAPublishDexEnv: { fields: 'address target,uint16 envVersion,Env env', on: ROUTER },
  UAPublishClassEnv: { fields: 'address target,uint16 contractClass,uint16 kind,uint16 envVersion,Env env', on: ROUTER },
  UAApproveTokenRelease: { fields: 'address target,uint8 kind,uint64 version,uint16 envVersion,bytes32 initcodeHash,'
    + 'bytes32 implArgsHash,bytes32 chainUid,address factory,uint32 adminGeneration,uint64 until', on: ROUTER },
  UAApproveDexRelease: { fields: 'address target,uint64 version,uint16 envVersion,bytes32 initcodeHash,bytes32 implArgsHash,'
    + 'bytes32 chainUid,address factory,uint32 adminGeneration,uint64 until', on: ROUTER },
  UAApproveRelease: { fields: 'address target,uint16 contractClass,uint16 kind,uint64 version,uint16 envVersion,bytes4 initSelector,'
    + 'bytes4 interfaceId,bytes32 initcodeHash,bytes32 implArgsHash,bytes32 chainUid,address factory,uint32 adminGeneration,uint64 until',
    on: ROUTER, args: (m) => [['address', m.target], ['ReleaseApproval', m]] },
  UARevokeApproval: { fields: 'address target,bytes32 key', on: ROUTER },
  UADeprecateToken: { fields: 'address target,uint8 kind,uint64 version,bytes32 chainUid,string reason', on: ROUTER },
  UADeprecateDex: { fields: 'address target,uint64 version,bytes32 chainUid,string reason', on: ROUTER },
  UADeprecateRelease: { fields: 'address target,uint16 contractClass,uint16 kind,uint64 version,bytes32 chainUid,string reason',
    on: ROUTER },
  UASetTokenKindEnabled: { fields: 'address target,uint8 kind,bool on,bytes32 chainUid', on: ROUTER },
  UASetClassKindEnabled: { fields: 'address target,uint16 contractClass,uint16 kind,bool on,bytes32 chainUid', on: ROUTER },
  UASetKycProvider: { fields: 'address target,bytes32 provider,bool enabled', on: ROUTER },
  UASetCompliance: { fields: 'address target,bytes32[] accounts,uint64[] flags,uint64[] until', on: ROUTER },
  UASetChainEntries: { fields: 'address target,address relayFeeRouter,bytes32 relayFeeRouterCodeHash,bytes32 relayFeeExecutorCodeHash,'
    + 'address complianceRegistry,bytes32 complianceRegistryCodeHash,address smartKeyAccountFactory,bytes32 smartKeyAccountFactoryCodeHash,'
    + 'address zetherStatements,bytes32 zetherStatementsCodeHash', on: ROUTER },
  // The statement's header words verbatim (purpose `zether-auth`); signed into `pqzAuth`, no entry of its own.
  PqzAuth: { raw: 'uint8 op,bytes32 opTag,bytes32 psid,uint256 chainId,address token,address registry,bytes32 from,bytes32 to,bytes32 beneficiary,'
    + 'uint256 fee,uint256 amount,bytes32 recipient,uint64 sendCounter,uint64 p,uint256 validUntilBlock,bool auditorOn,uint256 shieldIn,'
    + 'bytes32 chainUid,bytes32 binding,uint128 salt,bytes32 memoHash,bytes32 bodyHash', on: PQZ },
};

/** The creation's init bytes from `extra[name]`, refused unless their keccak256 is the signed `initHash`. */
function initOf(m, x, name) {
  const b = x?.[name];
  if (b === undefined) refuse(`the creation needs extra.${name}`);
  if (!same(hex(keccak_256(asBytes(b))), m.initHash)) refuse(`extra.${name} is not the signed initHash`);
  return hex(asBytes(b));
}

const abiType = (t) => {
  if (t.endsWith('[]')) return `${abiType(elementType(t))}[]`;
  return STRUCTS[t] ? `(${STRUCTS[t].map((f) => abiType(f.type)).join(',')})` : t;
};
const abiValue = (t, v) => {
  if (t.endsWith('[]')) return v.map((x) => abiValue(elementType(t), x));
  return STRUCTS[t] ? STRUCTS[t].map((f) => abiValue(f.type, v[f.name])) : v;
};

const opName = (primary) => primary.replace(/^UA/, 'ua').replace(/^[A-Z]/, (c) => c.toLowerCase());

/** One signed struct (`UA<Op>`: the merged entry on ids): its type string and typehash, and `call(td, sig, extra)` → the
 *  entry's `{abi, data}`. */
function defineOp(name, def) {
  const primary = def.primary ?? name;
  const ua = !def.raw && primary.startsWith('UA');
  const own = fields(def.raw ?? [`${ua ? 'bytes32' : 'address'} from`, def.fields, E].filter(Boolean).join(','));
  const types = { EIP712Domain: SALTED_DOMAIN_TYPE, [primary]: own };
  const nest = (list) => list.forEach((f) => {
    const t = elementType(f.type);
    if (STRUCTS[t] && !types[t]) { types[t] = STRUCTS[t]; nest(STRUCTS[t]); }
  });
  nest(own);
  const typeString = encodeType(types, primary);
  const base = primary.replace(/^UA/, '');
  const entry = def.raw ? def.entry : `mtx${def.entry ?? base}`;
  const sigParam = (td, sig) => {
    if (ua) return ['UASig', uaSigOf(sig)];
    return def.accountSig && td.domain.name === DOMAIN_OF.SmartKeyAccount ? ['AccountSig', accountSigOf(sig)] : ['bytes', sig];
  };
  const call = (td, sig, x = {}) => {
    const m = td.message;
    const params = def.raw ? def.call(m, sig, x, td) : [[ua ? 'UAEnvelope' : 'Envelope', m],
      ...(def.args ? def.args(m, x) : own.slice(1, -7).map((f) => [f.type, m[f.name]])), sigParam(td, sig), ...(def.tail ? def.tail(m, x) : [])];
    const abiTypes = params.map(([t]) => abiType(t));
    const abi = `${entry}(${abiTypes.join(',')})`;
    return { abi, data: abiCall(abi, abiTypes, params.map(([t, v]) => abiValue(t, v))) };
  };
  return { primary, builder: def.builder ?? opName(primary), typeString, typehash: hex(keccak_256(utf8ToBytes(typeString))), types,
    fields: own, on: def.on, ua,
    envelope: !def.raw, amount: def.amount, entry, domains: [...new Set(def.on.map((c) => DOMAIN_OF[c]))], call: entry ? call : null };
}

/** The PQZ debits by primary type (`checkPqzDebit`): op 1, op 7, the burn; the unwrap form is never a refresh. */
const PQZ_DEBITS = Object.freeze({ UAPqzTransferSingle: 'single', UAPqzTransferSingleCompact: 'single', UAPqzTransfer: 'multi',
  UAPqzTransferCompact: 'multi', UAPqzUnshield: 'burn', UAPqzUnshieldUnwrap: 'unwrap' });

// ------------------------------------------------------------------ the PQZ verdict (group 3f, spec §5)

const VERDICT_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, PqzVerdict: STRUCTS.PqzVerdict };
/// Group 3l (wrap limits spec §7, §9): the wrapped hybrids' wrap-limit errors, by selector. `liftable`: a later block may lift it
/// (a window ends, a member is added, a redeemer is granted, a later wrap raises the entitlement): the node keeps the job `queued`
/// with `WRAP_LIMIT_REFUSED`; the creation refusal and the subject check are not. Every argument is one static word.
export const WRAP_LIMIT_ERRORS = Object.freeze(Object.fromEntries([
  ['WrapLimitExceeded(address,uint8,bytes32,uint256,uint256)', ['underlying', 'limit', 'account', 'amount', 'remaining'], true],
  ['WrapCapExceeded(address,uint8,uint256,uint256)', ['underlying', 'limit', 'amount', 'remaining'], true],
  ['UnwrapAboveNetWrapped(address,bytes32,uint256,uint256)', ['underlying', 'account', 'amount', 'entitlement'], true],
  ['WrapperNotListed(bytes32)', ['account'], true],
  ['UnwrapperNotListed(bytes32)', ['account'], true],
  ['WrapControlNeedsHybrid(uint8)', ['bit'], false],
  ['WrapSubjectZero()', [], false],
].map(([sig, names, liftable]) => ['0x' + hex(keccak_256(utf8ToBytes(sig))).replace(/^0x/, '').slice(0, 8),
  Object.freeze({ name: sig.slice(0, sig.indexOf('(')), sig, names, liftable })])));

/// `revertData` (hex) decoded as one of `WRAP_LIMIT_ERRORS`, or null: `{ name, liftable, args }`, `args` by name (an address
/// lower-case hex, a `bytes32` hex, a number a decimal string).
export function wrapLimitError(revertData) {
  const d = String(revertData).toLowerCase().replace(/^0x/, '');
  const e = WRAP_LIMIT_ERRORS['0x' + d.slice(0, 8)];
  if (!e || d.length !== 8 + 64 * e.names.length) return null;
  const types = e.sig.slice(e.sig.indexOf('(') + 1, -1).split(',').filter(Boolean);
  const args = Object.fromEntries(e.names.map((n, i) => {
    const w = d.slice(8 + 64 * i, 8 + 64 * (i + 1));
    const v = types[i] === 'address' ? '0x' + w.slice(24) : types[i] === 'bytes32' ? '0x' + w : BigInt('0x' + w).toString();
    return [n, v];
  }));
  return { name: e.name, liftable: e.liftable, args };
}

/// Group 3l (wrap limits spec §2.1, R23, R24, R26): an id's net-wrapped line on one leg, `{ base, startMin }` (quanta, an
/// absolute minute; BigInt), as the contract computes it: the entitlement at `nowMin`, a wrap's credit of `a = ⌊received/unit⌋`
/// quanta, an unwrap's debit of `q = ⌈out/unit⌉`. `decayDays` 0: no decay. A wallet's preview; the contract decides.
const MAX32 = (1n << 32n) - 1n;
function lineEnt({ base, startMin }, decayDays, nowMin) {
  let g = nowMin > startMin ? nowMin - startMin : 0n;
  const h = BigInt(decayDays) * 1440n;
  if (h === 0n) return [base, g, h];
  if (g > h) g = h;
  return [base * (h - g) / h, g, h];
}
export const wrapEntitlement = (line, decayDays, nowMin) => lineEnt(line, decayDays, BigInt(nowMin))[0];
export function wrapCredit(line, a, decayDays, nowMin) {
  a = BigInt(a); nowMin = BigInt(nowMin);
  if (a === 0n) return { ...line };
  const [e, g, h] = lineEnt(line, decayDays, nowMin);
  const g2 = (e * g + e + a - 1n) / (e + a);
  let b2 = line.base + a;
  if (h !== 0n) { const r = (e + a) * h / (h - g2); if (r < b2) b2 = r; }
  return { base: b2 < MAX32 ? b2 : MAX32, startMin: nowMin - g2 };
}
export function wrapDebit(line, q, decayDays, nowMin) {
  q = BigInt(q);
  const [e] = lineEnt(line, decayDays, BigInt(nowMin));
  return { base: q >= e ? 0n : line.base * (e - q) / e, startMin: line.startMin };
}

export const PQZ_VERDICT_TYPEHASH = hex(keccak_256(utf8ToBytes(encodeType(VERDICT_TYPES, 'PqzVerdict'))));
/** The verdict of a `PRECOMPILE` token: every field 0 and an empty `UASig` (spec §5.1). */
export const EMPTY_PQZ_VERDICT = Object.freeze({
  pqzVerdict: Object.freeze({ token: ZERO_ADDRESS, chainId: '0', proofSystemId: ZERO_ID, statementHash: ZERO_ID, proofHash: ZERO_ID,
    pqzVerifierEpoch: 0, validUntil: '0' }),
  sig: Object.freeze({ keyData: '0x', signature: '0x', members: Object.freeze([]) }) });
/** `keccak256(statement)`: the bytes the token's statement views return (`transferStatement`, …, `disclosureStatement`). */
export const statementHash = (statement) => hex(keccak_256(asBytes(statement)));
/** `keccak256(proof)`: the proof's exact calldata bytes. */
export const proofHash = (proof) => hex(keccak_256(asBytes(proof)));

/** The `PqzVerdict` a verifier UA signs, in the PQZ token's salted domain `("SCaaS PqzToken", "1", chainId, token, chainUid)`;
 *  `message.token` and `message.chainId` repeat the domain (the token checks them equal). Signed under `pqz-verdict`
 *  (`ua.PQZ_VERDICT_TAG`): a native verifier over the registry's `uaAuthDigest`, a derived one over `uaMessage`. */
export function pqzVerdictTypedData({ contract, chainId, chainUid, message }) {
  const m = canonical('PqzVerdict', message, VERDICT_TYPES);
  if (!same(m.token, contract)) refuse('the verdict\'s token is not the domain\'s contract');
  if (BigInt(m.chainId) !== BigInt(chainId)) refuse('the verdict\'s chainId is not the domain\'s chain');
  return { types: VERDICT_TYPES, primaryType: 'PqzVerdict', domain: salted({ name: 'SCaaS PqzToken', contract, chainId, chainUid }), message: m };
}
export const pqzVerdictDigest = (o) => hashTypedData(pqzVerdictTypedData(o));

/** Round 3t (CTR-PQZ-36, verifier fee spec §5.1): a debit's public fee word, header word 256, `txFee + verifierFee + M·d`
 *  (`txFee = confidentialFee` with a beneficiary, else 0; `legs`, `decoyFee` op 7's, 0 otherwise; `verifierFee` the token's
 *  in force on `OFFCHAIN`, 0 on `PRECOMPILE`), for display and the node / verifier parity: a wallet's witness takes word
 *  256 of the statement view, never this sum. `< 2^64` or refused, as the token refuses it. */
export function pqzFeeWord({ confidentialFee = 0, beneficiaryUA = ZERO_ID, verifierFee = 0, legs = 0, decoyFee = 0 }) {
  const ben = BigInt(beneficiaryUA) !== 0n;
  const w = (ben ? BigInt(confidentialFee) : 0n) + BigInt(verifierFee) + BigInt(legs) * BigInt(decoyFee);
  if (w >= 2n ** 64n) refuse('the fee word is 2^64 or more');
  return w;
}

/** `pqzVerifyConfig()`'s return data (11 static words, round 3t's four appended): the mode, the verifier, fixed, its epoch, a
 *  live pending transfer and its `eta`, the notice period, the verifier fee, its immutable cap, a live pending increase and
 *  its `eta` (a dead one reads 0, 0). Wallets show `verifierFeeMax` as the headline price (Fable P2-2). */
export function decodePqzVerifyConfig(data) {
  const b = asBytes(data);
  if (b.length !== 11 * 32) refuse('pqzVerifyConfig: 11 words');
  const w = (i) => BigInt(hex(b.subarray(32 * i, 32 * i + 32)));
  const id = (i) => hex(b.subarray(32 * i, 32 * i + 32));
  return { pqzVerifyMode: Number(w(0)), verifier: id(1), fixed: w(2) !== 0n, pqzVerifierEpoch: Number(w(3)), pending: id(4),
    eta: w(5), noticePeriod: w(6), verifierFee: w(7), verifierFeeMax: w(8), verifierFeePending: w(9), verifierFeeEta: w(10) };
}

/** `x.pqzVerdict = {pqzVerdict, sig}` as the entry takes it: required; a verdict needs its signature, an empty one has none. */
function pqzSignedVerdictOf(v) {
  if (v === undefined) refuse('the PQZ verdict is required (EMPTY_PQZ_VERDICT on a PRECOMPILE token)');
  const pqzVerdict = canonical('PqzVerdict', v.pqzVerdict, STRUCTS);
  if (!Object.values(pqzVerdict).every((x) => BigInt(x) === 0n)) return { pqzVerdict, sig: uaSigOf(v.sig, 'the verdict signature') };
  const sig = { keyData: '0x', signature: '0x', members: [], ...(isRaw(v.sig ?? '0x') ? { signature: v.sig ?? '0x' } : v.sig) };
  if (asBytes(sig.keyData).length || asBytes(sig.signature).length || sig.members.length) refuse('an empty verdict carries no signature');
  return { pqzVerdict, sig };
}

/** Every signed struct by name: {typeString, typehash, types, fields, on, entry, domains, call}. */
export const TYPED_OPS = Object.freeze(Object.fromEntries(Object.entries(OPS).map(([name, def]) => [name, defineOp(name, def)])));

/** The canonical JSON a wallet signs: unset fields 0, hex bytes, uint ≤ 32 bits as numbers, the others as decimal
 *  strings; `relayer` / `feeRecipient` canonical-zeroed as the contract hashes them (`MetaTxLib.canon`), nested `UAMetaTransfer`
 *  too: a wallet hashes what it is shown (spec §6), so an unbound field is handed to it as 0. */
function canonical(type, v, types) {
  if (type.endsWith('[]')) return (v ?? []).map((x) => canonical(elementType(type), x, types));
  if (types[type]) {
    for (const k of Object.keys(v ?? {})) if (!types[type].some((f) => f.name === k)) refuse(`${k} is not a field of ${type}`);
    const m = Object.fromEntries(types[type].map((f) => [f.name, canonical(f.type, v?.[f.name], types)]));
    if ('mode' in m && 'relayer' in m && 'feeRecipient' in m) {
      if (!(BigInt(m.mode) & 1n)) m.relayer = ZERO_ADDRESS;
      if (!(BigInt(m.mode) & 2n)) m.feeRecipient = ZERO_ADDRESS;
    }
    return m;
  }
  if (type === 'address') { addressWord(v ?? ZERO_ADDRESS); return v ?? ZERO_ADDRESS; }
  if (type === 'bool') {
    if (v !== undefined && typeof v !== 'boolean') refuse(`${v} is not a bool`);
    return v ?? false;
  }
  if (type === 'bytes') return hex(asBytes(v ?? '0x'));
  // round 3r: a `string` (a deprecation's `reason`) is text, signed as keccak256 of its UTF-8 bytes
  if (type === 'string') {
    if (v !== undefined && typeof v !== 'string') refuse(`${v} is not a string`);
    return v ?? '';
  }
  const fixed = /^bytes(\d+)$/.exec(type);
  if (fixed) {
    const b = v === undefined ? new Uint8Array(Number(fixed[1])) : asBytes(v);
    if (b.length !== Number(fixed[1])) refuse(`a ${type} is ${fixed[1]} bytes`);
    return hex(b);
  }
  const bits = Number(type.slice(4));
  const numeric = typeof v !== 'object' && /^(0x[0-9a-fA-F]+|[0-9]+)$/.test(String(v));
  if (v != null && !numeric) refuse(`${v} is not a ${type}`);
  const n = BigInt(v ?? 0);
  if (n >= 1n << BigInt(bits)) refuse(`${n} is out of range for a ${type}`);
  return bits <= 32 ? Number(n) : String(n);
}

const E_FIELDS = new Set(fields(E).map((f) => f.name));
const bindsRelayer = (list) => ['mode', 'relayer', 'feeRecipient'].every((n) => list.some((f) => f.name === n));

/** What a client expects, whole: an omitted field is not "expect zero" (`open`: the struct's `E` may be left to the server).
 *  A relayer or fee recipient it names needs its mode bit (`mode`, the server's when the client leaves it open), or canonical
 *  zeroing would drop it and the digests still match: the signature open to any relayer, the fee to `msg.sender`. */
function requireWhole(type, v, types, open, mode) {
  if (type.endsWith('[]')) {
    if (!Array.isArray(v)) refuse(`the expected ${type} is missing`);
    v.forEach((x) => requireWhole(elementType(type), x, types));
    return;
  }
  if (!types[type]) return;
  if (v === null || typeof v !== 'object') refuse(`the expected ${type} is missing`);
  for (const f of types[type]) {
    if (open && E_FIELDS.has(f.name)) continue;
    if (v[f.name] == null) refuse(`the expected ${f.name} is missing`);
    requireWhole(f.type, v[f.name], types);
  }
  if (!bindsRelayer(types[type])) return;
  const bits = uint(v.mode ?? mode, 'the fee mode');
  const dropped = (id, bit) => id != null && !same(id, ZERO_ADDRESS) && !(bits & bit);
  if (dropped(v.relayer, 1n)) refuse('the relayer you named is not bound by the mode');
  if (dropped(v.feeRecipient, 2n)) refuse('the fee recipient you named is not bound by the mode');
}

function opTypedData(op, { name, contract, chainId, chainUid, message }) {
  if (name === undefined && op.domains.length > 1) refuse(`${op.primary} is signed in ${op.domains.length} domains: name yours`);
  const domainName = name ?? op.domains[0];
  if (!op.domains.includes(domainName)) refuse(`${op.primary} is not signed in the domain ${domainName}`);
  return { types: op.types, primaryType: op.primary, domain: salted({ name: domainName, contract, chainId, chainUid }),
    message: canonical(op.primary, message, op.types) };
}

/** `opTypedData` over a server's fields: what does not build is refused, never thrown as something else. */
function rebuilt(op, opts) {
  try {
    return opTypedData(op, opts);
  } catch (e) {
    if (String(e.message).startsWith('Refusing')) throw e;
    return refuse('malformed typed data');
  }
}

/** `<op>TypedData({name, contract, chainId, chainUid, message})` and `<op>Calldata(td, sig, extra)` of every struct
 *  (`extra`: `pqzAuth`, `ownerSig`, `payerSig` where the entry takes one); exported by name below and from zether.js,
 *  the `GovernanceRouter`'s (`grantRoleTypedData`, `uaSetGrantCalldata`, …) from here only. */
export const OP_BUILDERS = Object.freeze(Object.fromEntries(Object.values(TYPED_OPS).flatMap((op) => [
  [`${op.builder}TypedData`, (o) => opTypedData(op, o)],
  ...(op.call ? [[`${op.builder}Calldata`, (td, sig, x) => op.call(td, sig, x).data]] : [])])));
export const {
  cancelNonceTypedData, cancelNonceCalldata, uaCancelNonceTypedData, uaCancelNonceCalldata, uaBurnTypedData, uaBurnCalldata,
  wrapTypedData, wrapCalldata, wrapLegTypedData, wrapLegCalldata, uaUnwrapTypedData, uaUnwrapCalldata,
  uaUnwrapLegTypedData, uaUnwrapLegCalldata, addReserveTypedData, addReserveCalldata,
  wrapToUATypedData, wrapToUACalldata, uaUnwrapToUATypedData, uaUnwrapToUACalldata,
  uaShieldTypedData, uaShieldCalldata, wrapShieldTypedData, wrapShieldCalldata, uaRollOverTypedData, uaRollOverCalldata,
  uaPqzRollOverTypedData, uaPqzRollOverCalldata,
  uaPrepareAccTypedData, uaPrepareAccCalldata,
  uaSetMandateTypedData, uaSetMandateCalldata, uaSetPayeeTypedData, uaSetPayeeCalldata, uaRevokeMandateTypedData, uaRevokeMandateCalldata,
  uaPayUnderMandateTypedData, uaPayUnderMandateCalldata, uaDelegateRevokeTypedData, uaDelegateRevokeCalldata,
  uaExecuteTypedData, uaExecuteCalldata,
  addKeyTypedData, addKeyCalldata, removeKeyTypedData, removeKeyCalldata, rotateKeyTypedData, rotateKeyCalldata,
  setGuardianTypedData, setGuardianCalldata, cancelRecoveryTypedData, cancelRecoveryCalldata, executeTypedData, executeCalldata,
  uaReceiverFeeTypedData, uaReceiverFeeCalldata, uaRelayFeeTypedData, uaRelayFeeCalldata, uaWrapOrderTypedData, uaWrapOrderCalldata,
  uaPayWithTaxTypedData, uaPayWithTaxCalldata,
  cancelUAOrderTypedData, cancelUAOrderCalldata, cancelUAWrapOrderTypedData, cancelUAWrapOrderCalldata,
  cancelDexOrderTypedData, cancelDexOrderCalldata,
} = OP_BUILDERS;

// The generic path stays (owner 2026-10-31, TS-D14): a mixed batch, an op with no named entry.
const MTX_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, MetaTransaction: fields(`address from,bytes data,${E}`) };
const TRADE_ORDER = STRUCTS.TradeOrder;
// A UA's order (dex.md CTR-DEX-25): the same fields with `from` and `destination` as 32-byte ids, in the sell token's
// domain; a derived signer signs `ua_msg(kind, trade, digest)` through the registry, a native id the digest itself.
const UA_TRADE_ORDER = STRUCTS.UATradeOrder;
const UA_ORDER_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, UATradeOrder: UA_TRADE_ORDER };
const INVALIDATE_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE,
  InvalidateNonces: fields('address from,uint256 batch,uint256 minNonce') };
const UA_INVALIDATE_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE,
  UAInvalidateNonces: fields('bytes32 from,uint256 batch,uint256 minNonce') };
const DEX_ORDER_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, DexOrder: STRUCTS.DexOrder, TradeOrder: TRADE_ORDER };
const sel = (sig) => hex(keccak_256(utf8ToBytes(sig)).subarray(0, 4));
// Never inside a `MetaTransaction` (CLI-SGN-34): moving funds is a `MetaTransfer`, and EOAs never approve (CLI-SGN-36).
const NEVER_CALLED = new Set(['transfer(address,uint256)', 'transferFrom(address,address,uint256)',
  'approve(address,uint256)', 'payWithFee(address,uint256,uint8,uint256,address,bytes32)', 'pay(bytes32)',
  'payWithFeeToUA(bytes32,uint256,uint8,uint256,address,bytes32)',
  // the v2 `PayMeta` forms (`payNo` a string), gone with plan T83: still never inside a `MetaTransaction`
  'payWithFee(address,uint256,uint8,uint256,address,bytes32,(bytes32,string,uint16,bytes))',
  'payWithFeeToUA(bytes32,uint256,uint8,uint256,address,bytes32,(bytes32,string,uint16,bytes))',
  'payWithTax(bytes32,uint256,uint8,uint256,bytes32,(bytes32,string,uint16,bytes))',
  'payWithFee(address,uint256,uint8,uint256,address,bytes32,(bytes32,bytes32,bool,uint16,bytes))',
  'payWithFeeToUA(bytes32,uint256,uint8,uint256,address,bytes32,(bytes32,bytes32,bool,uint16,bytes))',
  'payWithTax(bytes32,uint256,uint8,uint256,bytes32,(bytes32,bytes32,bool,uint16,bytes))'].map(sel));
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

/** The direct `addKey(key)` call; `mtxAddKey` is `addKeyCalldata`. */
export function addKeyCall(key) {
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

/** The server's owner call must be exactly `AddKey(newKey)` signed by `account` itself on lane 0, no relayer and no fee, on
 *  `chainId` and the signer's own pinned `chainUid` (a missing or different salt is refused, CLI-SGN-33); nonce and a near
 *  deadline come from the server. Returns the digest to sign, or throws (CLI-SGN-05). */
export function checkOwnerCall(td, { account, chainId, chainUid, newKey, now = Math.floor(Date.now() / 1000), maxWindow = 3600 }) {
  const [kind, x, y, rpIdHash, originHash] = newKey;
  return checkOp(td, { op: 'AddKey', contract: account, chainId, chainUid, now, maxWindow,
    message: { from: account, kind, x, y, rpIdHash, originHash, batch: 0, mode: 0, relayer: ZERO_ADDRESS, fee: 0,
      feeRecipient: ZERO_ADDRESS } }).digest;
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

// The UA ledger's two structs (accounts.md CTR-UA-19, CTR-UA-26): ids as bytes32 (a native address zero-padded), the
// token's own salted domain; the typehash separates them from `MetaTransaction` / `MetaTransfer`.
const UA_TX_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, UAMetaTransaction: fields(`bytes32 from,bytes data,${E}`) };
const UA_TRANSFER_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, UAMetaTransfer: STRUCTS.UAMetaTransfer };

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

// The UA-5a receivers (accounts.md CTR-UA-28): a native caller credits a derived UA `to` (32 bytes) in one call.
const abiCall = (sig, types, values) => concatBytes(fromHex(sel(sig)), abiEncode(types, values));
/** `wrapToUA(underlying, amount, to)`: direct (payable on the native leg), or inside a `MetaTransaction` (`ABSOLUTE`). */
export const wrapToUACall = (underlying, amount, to) =>
  abiCall('wrapToUA(address,uint256,bytes32)', ['address', 'uint256', 'bytes32'], [underlying, amount, to]);
/** `unwrapToUA(underlying, wrapped, to, minOut)`: direct, in a `MetaTransaction` or a `UAMetaTransaction` (`AMOUNT(1)`). */
export const unwrapToUACall = (underlying, wrapped, to, minOut) => abiCall('unwrapToUA(address,uint256,bytes32,uint256)',
  ['address', 'uint256', 'bytes32', 'uint256'], [underlying, wrapped, to, minOut]);
/** `payWithFeeToUA(to, amount, feeMode, fee, feeRecipient, entryRef, meta)`: direct only (never a call, as `payWithFee`);
 *  `entryRef` must be `metaPayId(meta)` (pay-meta-tax spec §2.1). */
export function payWithFeeToUACalldata(to, amount, feeMode, fee, feeRecipient, entryRef, meta) {
  const m = payMeta(required(meta, 'the payment metadata'));
  if (!same(entryRef, metaPayId(m))) refuse('the payment id does not commit to its metadata');
  return abiCall(`payWithFeeToUA(bytes32,uint256,uint8,uint256,address,bytes32,${abiType('PayMeta')})`,
    ['bytes32', 'uint256', 'uint8', 'uint256', 'address', 'bytes32', abiType('PayMeta')],
    [to, amount, feeMode, fee, feeRecipient, entryRef, abiValue('PayMeta', m)]);
}

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

/** The server's typed data must be the payment the user was shown: a `UAMetaTransfer` (ua-mtx-merge R20, R46: the token's one
 *  payment struct, `mtxPay`) from `account` to `payee`, both 32-byte ids (`padId` of a native address), of `amount` (in the
 *  token's `decimals`) with the request's `entryRef`, on the request's lane `payLane(entryRef)` with nonce 0, in the domain of
 *  `expectedToken` (the signer's own profile, CLI-SGN-08) salted with its own `chainUid` (CLI-SGN-33), the fee within
 *  `maxFee` (default 0), a near deadline (CLI-SGN-05). `payee`, `entryRef`, `expectedToken` and `amount` are required; the
 *  server supplies only `validUntil` and the fee fields. Returns {digest, payee, token, entryRef, feeMode, fee, feeRecipient,
 *  relayer}. */
export function checkPayment(td, { account, chainId, chainUid, amount, decimals, payee, entryRef, expectedToken, maxFee,
  feeRecipient, relayer, now = Math.floor(Date.now() / 1000), maxWindow = 86400 }) {
  if (!td || td.primaryType !== 'UAMetaTransfer') refuse('this is not a payment');
  if ([amount, payee, entryRef, expectedToken].some((v) => v == null)) refuse('the amount, payee, reference and token are required');
  if (![account, payee].every((v) => /^0x[0-9a-fA-F]{64}$/.test(String(v)))) refuse('the account and payee are 32-byte ids (padId of an address)');
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
  const digest = digestOf(uaMetaTransferTypedData({ name: d.name, contract: expectedToken, chainId, chainUid,
    message: { ...m, from: account, to: payee, value, entryRef, batch, nonce: 0 } }));
  if (hex(digestOf(td)) !== hex(digest)) refuse('unexpected payment fields');
  return { digest, payee, token: expectedToken, entryRef, ...fee };
}

/** The payee's side of receiver-pays (CTR-MTX-05/06): `td` is the `UAReceiverFee` (`mtxPayReceiverFee`; `payee` a 32-byte
 *  id, `padId` for a native one; ua-mtx-merge: the address `ReceiverFee` left) to co-sign, nesting the payer's payment (TS-D19). The payment must be the one the payee expects, as `checkPayment` checks it for the payer: to `payee`,
 *  `amount` (× 10^`decimals`) with the request's `entryRef` on lane `payLane(entryRef)` nonce 0, the contract's shape (fee
 *  NONE, relayer bound: mode 1), in `expectedToken`'s domain salted with `chainUid`. The fee is the payee's own: non-zero, at
 *  most the amount and `maxFee` (default 0), to the `feeRecipient` it named, with a near deadline. The server supplies only
 *  the payment's `from` / `validUntil` / `relayer` and the fee's `validUntil`. Returns {digest, paymentDigest (what the
 *  payer signs), payer, fee, feeRecipient}. */
export function checkReceiverFee(td, { payee, chainId, chainUid, amount, decimals, entryRef, expectedToken, maxFee = 0, feeRecipient,
  now = Math.floor(Date.now() / 1000), maxWindow = 86400 }) {
  if (!td || td.primaryType !== 'UAReceiverFee') refuse('this is not a receiver fee');
  if ([payee, amount, entryRef, expectedToken, feeRecipient].some((v) => v == null)) {
    refuse('the payee, amount, reference, token and fee recipient are required');
  }
  const d = td.domain || {};
  const m = td.message || {};
  const p = m.payment || {};
  if (!same(d.verifyingContract, expectedToken)) refuse('wrong token');
  if (!same(p.to, payee)) refuse('the payment does not pay you');
  const value = toBase(amount, decimals);
  if (uint(p.value, 'the amount') !== value || value === 0n) refuse('the amount differs from what you were shown');
  if (!/^0x[0-9a-fA-F]{64}$/.test(String(entryRef)) || BigInt(entryRef) === 0n) refuse('this is not a payment');
  if (!same(p.entryRef, entryRef)) refuse('the payment reference differs from the request');
  const batch = payLane(entryRef);
  if (uint(p.batch, 'the lane') !== batch || uint(p.nonce, 'the nonce') !== 0n) refuse('a payment is signed once, on its request lane');
  if (uint(p.mode, 'the fee mode') !== 1n || uint(p.fee, 'the payer fee') !== 0n) refuse('the payment is not in the receiver-pays shape');
  const fee = uint(m.fee, 'the fee');
  if (fee === 0n) refuse('no fee to co-sign');
  if (fee > value) refuse('the fee is more than the payment');
  if (fee > uint(maxFee, 'your fee limit')) refuse('the fee is above your limit');
  if (!same(m.feeRecipient, feeRecipient)) refuse('the fee goes to an address you did not name');
  const validUntil = deadline(m.validUntil, now, maxWindow);
  const payment = { ...p, to: payee, value, entryRef, batch, nonce: 0 };
  const paymentDigest = digestOf(uaMetaTransferTypedData({ name: d.name, contract: expectedToken, chainId, chainUid, message: payment }));
  const digest = digestOf(uaReceiverFeeTypedData({ name: d.name, contract: expectedToken, chainId, chainUid,
    message: { payment, fee, feeRecipient, validUntil } }));
  if (hex(digestOf(td)) !== hex(digest)) refuse('unexpected receiver fee fields');
  return { digest, paymentDigest, payer: p.from, fee, feeRecipient };
}

// ------------------------------------------------------------------ CTR-MTX-26 (pay-meta-tax spec §3, plan T83): `PayMeta` v3

const asBytes = (v) => (v instanceof Uint8Array ? v : fromHex(v));
const at = (b, i) => BigInt(hex(b.subarray(32 * i, 32 * i + 32)));

/** The old commitment `keccak256("scaas.pay.meta" ‖ salt ‖ keccak256(meta))`: the non-EVM families keep it until their own
 *  round (pay-meta-tax spec §8, Q10; `metaop.js`). The EVM pay entries take `metaPayId(PayMeta)`. */
export function metaPayIdV1(salt, meta) {
  return hex(keccak_256(concatBytes(utf8ToBytes('scaas.pay.meta'), bytes32(salt), keccak_256(asBytes(meta)))));
}

const UUID = /^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$/;

/** The recommended `payNo` (plan T83, owner 2026-11-09): a UUIDv7 right-aligned in 32 bytes, its 128 bits in the low 16 bytes
 *  and the high 16 bytes zero (as an address is padded). Unique without coordination; time-ordered, so an indexer's or ERP's
 *  index stays compact; no business sequence number on chain. One `payNo` per payment request when the payee must match each
 *  request. `uuid` the canonical text (`019a6e3c-5f00-7a3b-8c4d-5e6f708192a3`, any case); refused unless version 7, variant
 *  10. The contract takes any 32-byte value and never parses it; this is the wallet's form. */
export function payNoFromUuid(uuid) {
  const m = UUID.exec(String(uuid).toLowerCase());
  if (!m || m[3][0] !== '7' || !'89ab'.includes(m[4][0])) refuse('the payment number is not a UUIDv7');
  return '0x' + '00'.repeat(16) + m.slice(1).join('');
}

/** For display: the UUID text of a right-aligned `payNo` (its high 16 bytes zero, version 7, variant 10), else `null` (0, or
 *  another 32-byte id: show it as hex). */
export function payNoToUuid(payNo) {
  const h = hex(bytes32(payNo)).slice(2);
  if (!/^0{32}/.test(h) || h[44] !== '7' || !'89ab'.includes(h[48])) return null;
  const u = h.slice(32);
  return `${u.slice(0, 8)}-${u.slice(8, 12)}-${u.slice(12, 16)}-${u.slice(16, 20)}-${u.slice(20)}`;
}

function utf8(b) {
  try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(b); } catch { return refuse('the note is not UTF-8'); }
}

/** The body of schema `schema` from its named fields (spec §3.1): 0 none; 1 `{note}` (UTF-8, non-empty); 2 `{creditorRef,
 *  dueDate}` = `abi.encode(string, uint64)`; 3 `{chainId, target, callHash}` = `abi.encode(uint256, bytes32, bytes32)`; 4
 *  `{ciphertext}` (the one crypto object, bytes, non-empty). */
export function encodeMetaBody(schema, f = {}) {
  if (schema === 0) return new Uint8Array(0);
  if (schema === 1) {
    if (typeof f.note !== 'string' || f.note === '') refuse('a note is non-empty text');
    return utf8ToBytes(f.note);
  }
  if (schema === 2) {
    const due = uint(f.dueDate, 'the due date');
    if (due >= 1n << 64n || typeof f.creditorRef !== 'string') refuse('a structured reference is {creditorRef, dueDate}');
    return abiEncode(['string', 'uint64'], [f.creditorRef, due]);
  }
  if (schema === 3) return abiEncode(['uint256', 'bytes32', 'bytes32'], [uint(f.chainId, 'the chain id'), f.target, f.callHash]);
  if (schema === 4) {
    const c = asBytes(required(f.ciphertext, 'the ciphertext'));
    if (c.length === 0) refuse('the ciphertext is empty');
    return c;
  }
  return refuse('unknown metadata schema');
}

/** The named fields of a body for the review screen, read strictly (re-encoding checks the canonical form). An unknown
 *  schema is shown as opaque data, never as facts (spec §3.2). */
export function decodeMetaBody(schema, body) {
  const b = asBytes(body);
  if (schema === 0) {
    if (b.length) refuse('schema 0 carries no body');
    return {};
  }
  if (schema === 1) {
    if (!b.length) refuse('a note is non-empty');
    return { note: utf8(b) };
  }
  if (schema === 2) {
    if (b.length < 96) refuse('the metadata is malformed');
    const off = at(b, 0);
    if (off !== 64n) refuse('the metadata is not in canonical form');
    const n = at(b.subarray(64), 0);
    if (96n + n > BigInt(b.length)) refuse('the metadata is malformed');
    const f = { creditorRef: utf8(b.subarray(96, 96 + Number(n))), dueDate: at(b, 1) };
    if (f.dueDate >= 1n << 64n || hex(encodeMetaBody(2, f)) !== hex(b)) refuse('the metadata is not in canonical form');
    return f;
  }
  if (schema === 3) {
    if (b.length !== 96) refuse('the metadata is malformed');
    return { chainId: at(b, 0), target: hex(b.subarray(32, 64)), callHash: hex(b.subarray(64, 96)) };
  }
  if (schema === 4) return { encrypted: b.length };
  return { opaque: b.length };
}

const randomSalt = () => {
  const s = new Uint8Array(32);
  crypto.getRandomValues(s);
  return hex(s);
};

/** A `PayMeta {salt, payNo, save, schema, body}` (spec §3.1, plan T83), checked as the contract asks: a non-zero salt (from
 *  the CSPRNG when absent), `schema == 0` iff the body is empty, `save` only with a `payNo`. `payNo` 32 bytes (hex or bytes;
 *  0 = none), recommended a right-aligned UUIDv7 (`payNoFromUuid`); `save` the payer's choice to store the payment's record
 *  under `payNo` on chain (`paymentsOf`), usually set by the payee's request. The body is the hex given, or built from
 *  `fields` (`encodeMetaBody`). Returns `{salt, payNo, save, schema, body}` (hex). */
export function payMeta({ salt, payNo = ZERO32, save = false, schema = 0, body, fields: f } = {}) {
  const s = hex(bytes32(salt ?? randomSalt()));
  if (BigInt(s) === 0n) refuse('the salt is 0');
  if (!Number.isInteger(schema) || schema < 0 || schema > 0xffff) refuse('the schema is a uint16');
  let n;
  try { n = hex(bytes32(payNo)); } catch { refuse('the payment number is 32 bytes (payNoFromUuid for a UUIDv7)'); }
  if (typeof save !== 'boolean') refuse('save is true or false');
  if (save && BigInt(n) === 0n) refuse('save needs a payment number');
  const b = body !== undefined ? asBytes(body) : encodeMetaBody(schema, f);
  if ((schema === 0) !== (b.length === 0)) refuse('schema 0 iff the body is empty');
  return { salt: s, payNo: n, save, schema, body: hex(b) };
}

/** `metaPayId(m) = keccak256("scaas.pay.meta.v3" ‖ salt ‖ keccak256(abi.encode(bytes32 payNo, bool save, uint16 schema,
 *  bytes body)))` (CTR-MTX-26, plan T83; on chain `metaPayId(PayMeta)`). */
export function metaPayId(meta) {
  const m = payMeta(meta);
  return hex(keccak_256(concatBytes(utf8ToBytes('scaas.pay.meta.v3'), fromHex(m.salt),
    keccak_256(abiEncode(['bytes32', 'bool', 'uint16', 'bytes'], [m.payNo, m.save, m.schema, fromHex(m.body)])))));
}

/** The warning of spec §3.3 (F-24): a clear `payNo` or a schema 1 or 2 body is public forever. Shown once per payee per
 *  `session` (a `Set` the wallet keeps for the session); `null` when there is nothing to warn of or it was shown. */
export function payMetaWarning(meta, payee, session) {
  const m = payMeta(meta);
  if (BigInt(m.payNo) === 0n && m.schema !== 1 && m.schema !== 2) return null;
  const k = String(payee).toLowerCase();
  if (session.has(k)) return null;
  session.add(k);
  return 'This payment publishes its number or note in clear, searchable by anyone, forever; schema 4 (encrypted to the payee) keeps it private.';
}

/** `meta` → its checked form, commitment and decoded fields; refuses when `entryRef` is given and is not `metaPayId(meta)`. */
function payMetaParts(meta, entryRef) {
  const m = payMeta(required(meta, 'the payment metadata'));
  const payId = metaPayId(m);
  if (entryRef != null && !same(entryRef, payId)) refuse('the payment id does not commit to its metadata');
  return { meta: m, payId, shown: { payNo: m.payNo, payNoUuid: payNoToUuid(m.payNo), save: m.save, schema: m.schema,
    ...decodeMetaBody(m.schema, m.body) } };
}

/** The payer's payment (pay-meta-tax spec §2.1): the `UAMetaTransfer` of `mtxPay(t, UASig auth, PayMeta meta)` between
 *  32-byte ids with `entryRef = metaPayId(meta)`; `entryRef` given (the request's) must equal it. Any lane (O3): `batch` /
 *  `nonce` the caller's, by default the request lane `payLane(entryRef)` nonce 0 (a client convention). Returns
 *  {typedData, digest, payId, meta, shown, calldata(auth)}. */
export function buildPay({ name, token, chainId, chainUid, from, to, amount, meta, entryRef, batch, nonce, validUntil, mode = 0,
  relayer = ZERO_ADDRESS, fee = 0, feeRecipient = ZERO_ADDRESS }) {
  const p = payMetaParts(meta, entryRef);
  const typedData = uaMetaTransferTypedData({ name, contract: token, chainId, chainUid, message: { from, to, value: amount,
    entryRef: p.payId, batch: batch ?? payLane(p.payId), nonce: nonce ?? 0, validUntil, mode, relayer, fee, feeRecipient } });
  const types = [abiType('UAMetaTransfer'), abiType('UASig'), abiType('PayMeta')];
  const calldata = (auth) => abiCall(`mtxPay(${types.join(',')})`, types,
    [abiValue('UAMetaTransfer', typedData.message), abiValue('UASig', uaSigOf(auth)), abiValue('PayMeta', p.meta)]);
  return { typedData, digest: digestOf(typedData), payId: p.payId, meta: p.meta, shown: p.shown, calldata };
}

/** Receiver-pays (spec §2.5): the payer's payment (`buildPay`, fee NONE, relayer bound: mode 1) and the payee's
 *  `UAReceiverFee` over it; `calldata(payerAuth, payeeAuth)` is `mtxPayReceiverFee(t, payerAuth, fee, feeRecipient,
 *  rfValidUntil, payeeAuth, meta)`. */
export function buildPayReceiverFee({ fee, feeRecipient, rfValidUntil, ...pay }) {
  const payer = buildPay({ ...pay, mode: 1, fee: 0, feeRecipient: ZERO_ADDRESS });
  const at = { name: pay.name ?? 'SCaaS MetaToken', contract: pay.token, chainId: pay.chainId, chainUid: pay.chainUid };
  const typedData = uaReceiverFeeTypedData({ ...at, message: { payment: payer.typedData.message, fee, feeRecipient, validUntil: rfValidUntil } });
  return { payment: payer, typedData, digest: digestOf(typedData), payId: payer.payId, meta: payer.meta, shown: payer.shown,
    calldata: (payerAuth, payeeAuth) => uaReceiverFeeCalldata(typedData, payeeAuth, { payerSig: payerAuth, meta: payer.meta }) };
}

/** The tax of a PERCENT payment, `floor(value × ratePpm / 10^6)` (PT-6), from `regulatedConfig().tax.effectivePpm`. */
export const percentTax = (value, ratePpm) => uint(value, 'the amount') * uint(ratePpm, 'the rate') / 1000000n;

/** A payment with its tax on a regulated kind (spec §5.2, §5.3): `UAPayWithTax{payment, taxMode, tax}` signed by the payer;
 *  `taxMode` 1 PERCENT (`tax` must be `percentTax(amount, ratePpm)`, the token's effective rate, when `ratePpm` is given)
 *  or 2 AMOUNT (the payer's figure); `tax ≤ amount`. The recipient is the token's, not signed: the wallet shows
 *  `taxRecipient`. Returns {typedData, digest, payId, meta, shown, calldata(auth)}. */
export function buildPayWithTax({ taxMode, tax, ratePpm, taxRecipient, ...pay }) {
  if (taxMode !== 1 && taxMode !== 2) refuse('the tax mode is 1 (PERCENT) or 2 (AMOUNT)');
  const t = uint(tax, 'the tax');
  if (t > uint(pay.amount, 'the amount')) refuse('the tax is more than the payment');
  if (taxMode === 1 && ratePpm != null && t !== percentTax(pay.amount, ratePpm)) refuse('the tax is not the token\'s rate');
  const payment = buildPay(pay);
  const at = { name: pay.name ?? 'SCaaS MetaToken', contract: pay.token, chainId: pay.chainId, chainUid: pay.chainUid };
  const typedData = uaPayWithTaxTypedData({ ...at, message: { payment: payment.typedData.message, taxMode, tax: t } });
  return { typedData, digest: digestOf(typedData), payId: payment.payId, meta: payment.meta,
    shown: { ...payment.shown, tax: t, taxMode, taxRecipient: taxRecipient ?? null },
    calldata: (auth) => uaPayWithTaxCalldata(typedData, auth, { meta: payment.meta }) };
}

/** `checkPayment` for a pay request with its `PayMeta`: the server's `UAMetaTransfer` must carry `entryRef = metaPayId(meta)`
 *  of the `meta` the client holds (else refused), then every `checkPayment` check with that `entryRef`. Returns
 *  `checkPayment`'s result plus {payId, meta, shown}. */
export function checkPayMeta(td, { meta, entryRef, ...opts }) {
  const p = payMetaParts(meta, entryRef);
  if (!same(((td && td.message) || {}).entryRef, p.payId)) refuse('the payment id does not commit to its metadata');
  return { ...checkPayment(td, { ...opts, entryRef: p.payId }), payId: p.payId, meta: p.meta, shown: p.shown };
}

// ------------------------------------------------------------------ CTR-MTX-27: a token fee for a fee-less call

/** `relayRef(target, callData) = keccak256("scaas.relayfee" ‖ uint256 chainid ‖ target ‖ keccak256(callData))` on chain
 *  `chainId` (EVM, `RelayFeeRouter.relayRef`; other families use their own `ref` forms). */
export function relayRef(chainId, target, callData) {
  const t = fromHex(target);
  if (t.length !== 20) refuse('the target is not an address');
  return hex(keccak_256(concatBytes(utf8ToBytes('scaas.relayfee'), word(chainId), t, keccak_256(asBytes(callData)))));
}

const MTX_TUPLE = '(address,bytes,uint256,uint256,uint256,uint32,address,uint256,address)';
const META_TX_FIELDS = (id) => fields(`${id} from,bytes data,${E}`);
/** `mtxExecute` calldata of a signed generic call (the call a relay-fee payment pays for), by the struct the kind signs
 *  (spec §2.3: one name, per kind): a `UAMetaTransaction` (tokens, the router, the mandate wallets) → `mtxExecute(m, UASig
 *  auth)` (`auth` a raw signature of a native id, or a `UASig`); a `MetaTransaction` (`SmartKeyAccount`) → `mtxExecute(m,
 *  bytes signature)`. */
export function mtxExecuteCalldata(td, signature) {
  const m = td.message;
  if (td.primaryType === 'UAMetaTransaction') {
    const types = [`(${META_TX_FIELDS('bytes32').map((f) => f.type).join(',')})`, abiType('UASig')];
    return abiCall(`mtxExecute(${types.join(',')})`, types,
      [META_TX_FIELDS('bytes32').map((f) => m[f.name]), abiValue('UASig', uaSigOf(signature))]);
  }
  if (td.primaryType !== 'MetaTransaction') refuse('this is not a generic call');
  const tuple = abiEncode(['address', 'bytes', 'uint256', 'uint256', 'uint256', 'uint32', 'address', 'uint256', 'address'],
    [m.from, m.data, m.batch, m.nonce, m.validUntil, m.mode, m.relayer, m.fee, m.feeRecipient]);
  return concatBytes(fromHex(sel(`mtxExecute(${MTX_TUPLE},bytes)`)), word(64), word(64 + tuple.length), tuple,
    abiEncode(['bytes'], [asBytes(signature)]).subarray(32));
}

/** `mtxExecuteTransfer(t, UASig auth)` calldata of a signed `UAMetaTransfer` (a token's transfer or payment between ids). */
export function mtxExecuteTransferCalldata(td, signature) {
  if (!td || td.primaryType !== 'UAMetaTransfer') refuse('this is not a transfer');
  const types = [abiType('UAMetaTransfer'), abiType('UASig')];
  return abiCall(`mtxExecuteTransfer(${types.join(',')})`, types,
    [abiValue('UAMetaTransfer', td.message), abiValue('UASig', uaSigOf(signature))]);
}

/** A relay-fee job (CTR-MTX-27, TS-D19) on `router` (`RelayFeeRouter`, executor `executor`): `inner` (optional) is the call's
 *  own typed data on `target`, a named entry's or a `MetaTransaction`; a relayer it binds (`MODE_RESTRICT_RELAYER`) is set
 *  to the executor (left open otherwise; bound to anything else: refused). Open mode by default (`payee` unset: the payment
 *  goes to the router, which pays whoever submits); `payee` binds it (never the executor). The payer `from` and `payee` are
 *  32-byte ids (`padId` of a native address; ua-mtx-merge R21: the address `RelayFee` and `uaRelay` are legacy). Returns
 *  {call (the inner typed data to sign first, or null), prompt {call, payment}: both intents for one review,
 *  payment(callData) → {ref, lane, typedData, digest, calldata(auth)}}: `callData` is the call with its own signature
 *  (`<op>Calldata`, `mtxExecuteCalldata`); the payment is `UARelayFee{from, target, callDataHash, payee, value: amount,
 *  batch, nonce, validUntil, relayer: router}` on the payer's own lane `(batch, nonce)` (pay-meta-tax spec §4, O4: one
 *  signature pays once); `calldata` is the router's `relay(target, callData, token, from, payee, value, batch, nonce,
 *  validUntil, UASig auth)`. */
export function buildRelayFee({ name = 'SCaaS MetaToken', token, chainId, chainUid, router, executor, target, inner, from,
  amount, payee, batch, nonce, validUntil }) {
  const lane = uint(required(batch, 'the payer\'s lane'), 'the lane');
  const n = uint(required(nonce, 'the payer\'s nonce'), 'the nonce');
  if (same(target, executor) || same(target, router)) refuse('a relay never targets the router or its executor');
  const open = payee == null;
  const to = open ? padId(router) : payee;
  if (same(to, padId(executor))) refuse('never pay the executor');
  if (same(to, ZERO_ID)) refuse('the payee is the zero address');
  if (same(to, padId(token))) refuse('the payee is the token itself');
  let call = null;
  let bound = 0n;
  if (inner) {
    const m = inner.message || {};
    const d = inner.domain || {};
    if (!same(d.verifyingContract, target)) refuse('the call is not on the target');
    const uid = chainUid instanceof Uint8Array ? hex(chainUid) : String(chainUid);
    if (uint(d.chainId, 'the call\'s chain id') !== BigInt(chainId) || !same(d.salt, uid)) refuse('the call is for another chain');
    if (uint(m.validUntil, 'the call\'s deadline') > uint(validUntil, 'the deadline')) refuse('the call outlives its payment');
    bound = uint(m.mode ?? 0, 'the call\'s mode') & 1n;
    if (bound && !same(m.relayer, ZERO_ADDRESS) && !same(m.relayer, executor)) refuse('the call is bound to another relayer');
    call = { ...inner, message: { ...m, relayer: bound ? executor : m.relayer } };
  }
  const prompt = {
    call: call ? { target, op: call.primaryType, message: call.message, from: call.message.from, relayer: bound ? executor : null }
      : { target },
    payment: { token, amount: BigInt(amount), payee: open ? null : to, open },
  };
  const payment = (callData) => {
    const ref = relayRef(chainId, target, callData);
    const typedData = uaRelayFeeTypedData({ name, contract: token, chainId, chainUid,
      message: { from, target, callDataHash: hex(keccak_256(asBytes(callData))), payee: to, value: amount, batch: lane, nonce: n,
        validUntil, relayer: router } });
    const t = typedData.message;
    const sigType = abiType('UASig');
    const calldata = (sig) => abiCall(`relay(address,bytes,address,bytes32,bytes32,uint256,uint256,uint256,uint256,${sigType})`,
      ['address', 'bytes', 'address', 'bytes32', 'bytes32', 'uint256', 'uint256', 'uint256', 'uint256', sigType],
      [target, asBytes(callData), token, t.from, t.payee, t.value, t.batch, t.nonce, t.validUntil, abiValue('UASig', uaSigOf(sig))]);
    return { ref, lane, nonce: n, typedData, digest: digestOf(typedData), calldata };
  };
  return { call, prompt, payment };
}

// ------------------------------------------------------------------ service pull (spec 2026-11-09-service-pull, proposed CTR-MTX-32)
// The field types of a node-relayable operation (C3): atomic, `bytes`, `string`; no array, no nested struct. `intN` is C3's
// too but not in this reference builder (no row needs it): refused here, never mis-encoded.
const OP_FIELD = /^(address|bool|string|bytes|bytes([1-9]|[12][0-9]|3[0-2])|uint(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256))$/;
const OP_MAX_FIELDS = 16;

/** A service pull (spec §3, §10): the payer signs one `UAMetaTransfer` in the pulled token's domain, `to` = `relayer` = the
 *  service, `MODE_RESTRICT_RELAYER`, fee `NONE`, fee 0, no fee recipient, and `entryRef` = the EIP-712 digest of the
 *  service's operation `op` (its typed data `{domain, types, primaryType, message}` in the service's own domain; shown, never
 *  signed itself, §3.1). Refuses: an operation outside C3 (more than 16 fields, an array, a nested struct, a first field
 *  other than `bytes32 payer`, a field missing or extra), `op.payer` other than `from`, an operation for another chain, a
 *  zero amount. With a fee, `buildRelayFee({target: service, …})` after this (the pull at `nonce`, the fee at `nonce + 1`
 *  on the same lane in the same token, §2.4 (b)). Returns {service, entryRef, prompt, typedData (the transfer), digest,
 *  selector, calldata(signature)}: `<entry>(op, t, UASig auth)`, `op`'s `bytes` / `string` raw (EIP-712 hashed them). */
export function buildServicePull({ name = 'SCaaS MetaToken', token, chainId, chainUid, entry, op, from, amount, batch, nonce,
  validUntil }) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(String(entry))) refuse('the entry is not a function name');
  const d = op?.domain || {};
  const service = d.verifyingContract;
  if (typeof service !== 'string' || fromHex(service).length !== 20) refuse('the operation names no service');
  if (uint(d.chainId, 'the operation\'s chain id') !== BigInt(chainId)) refuse('the operation is for another chain');
  const fs = op.types?.[op.primaryType];
  if (!Array.isArray(fs) || fs.length === 0 || fs.length > OP_MAX_FIELDS) refuse('the operation has no fields or more than 16');
  if (Object.keys(op.types).some((t) => t !== op.primaryType && t !== 'EIP712Domain')) refuse('the operation nests a struct');
  for (const f of fs) if (!OP_FIELD.test(f.type)) refuse(`the operation's field ${f.name} is not atomic, bytes or string`);
  if (fs[0].name !== 'payer' || fs[0].type !== 'bytes32') refuse('the operation does not start with bytes32 payer');
  const m = op.message || {};
  if (Object.keys(m).length !== fs.length || fs.some((f) => m[f.name] === undefined)) refuse('the operation\'s fields are not its type\'s');
  if (!same(hex(bytes32(m.payer)), hex(bytes32(from)))) refuse('the operation is not the payer\'s');
  const value = uint(amount, 'the amount');
  if (value === 0n) refuse('the amount is zero');
  const entryRef = hex(digestOf(op));
  const typedData = uaMetaTransferTypedData({ name, contract: token, chainId, chainUid, message: { from: hex(bytes32(from)),
    to: padId(service), value, entryRef, batch: uint(required(batch, 'the lane'), 'the lane'),
    nonce: uint(required(nonce, 'the nonce'), 'the nonce'), validUntil: uint(validUntil, 'the deadline'), mode: 1,
    relayer: service, fee: 0, feeRecipient: ZERO_ADDRESS } });
  const types = [`(${fs.map((f) => f.type).join(',')})`, abiType('UAMetaTransfer'), abiType('UASig')];
  const signature = `${entry}(${types.join(',')})`;
  const calldata = (sig) => abiCall(signature, types, [fs.map((f) => m[f.name]), abiValue('UAMetaTransfer', typedData.message),
    abiValue('UASig', uaSigOf(sig))]);
  return { service, entryRef, typedData, digest: digestOf(typedData), selector: sel(signature), calldata,
    prompt: { service, serviceName: d.name, op: op.primaryType, message: m, token, amount: value, validUntil: String(validUntil) } };
}

/** CLI-SGN-27 on a named entry: check, then sign exactly what was checked. `td` must be struct `op` on `contract`, salted with
 *  the signer's own `chainId` and `chainUid` (CLI-SGN-33), with every field of `message`, the op's own fields as the client
 *  built them from the user's input (`from` too), every one of them present: nothing omitted reads as zero. Struct family
 *  `E`: the server supplies only what `message` leaves out, the lane, nonce and deadline (near, CLI-SGN-05) and the fee
 *  fields; the fee within `maxFee` (default 0; PERCENT only on an AMOUNT op, on the op's own amount, CTR-MTX-20), a bound fee
 *  recipient / relayer the one named, and one named in `message` must be bound. Any other struct: all of it is the
 *  client's. A wrap order is refused here: `checkWrapOrder` carries its rules. Returns {digest, op, entry, feeMode, fee,
 *  feeRecipient, relayer}. */
export function checkOp(td, { op, contract, chainId, chainUid, message, maxFee, feeRecipient, relayer,
  now = Math.floor(Date.now() / 1000), maxWindow = 3600 }) {
  if (op === 'UAWrapOrder') refuse('a wrap order is checked by checkWrapOrder (CLI-SGN-36)');
  const o = TYPED_OPS[op];
  if (!o || !td || td.primaryType !== o.primary) refuse('this is not the operation you asked for');
  const m = td.message || {};
  const d = td.domain || {};
  if (!same(d.verifyingContract, contract)) refuse('the operation is not on the contract you chose');
  requireWhole(o.primary, message, o.types, o.envelope, m.mode); // the struct, not the row (`UAPqzRollOver` is `UARollOver`)
  let fee = {};
  let server = {};
  if (o.envelope) {
    const basis = o.amount === undefined ? undefined : uint(message[o.amount], 'the amount');
    fee = feePolicy({ ...m, ...message }, { maxFee, feeRecipient, relayer }, basis);
    deadline(message.validUntil ?? m.validUntil, now, maxWindow);
    server = { batch: uint(m.batch, 'the lane'), nonce: uint(m.nonce, 'the nonce'), validUntil: m.validUntil, mode: m.mode,
      relayer: m.relayer, fee: m.fee, feeRecipient: m.feeRecipient };
  }
  const digest = digestOf(rebuilt(o, { name: d.name, contract, chainId, chainUid, message: { ...server, ...message } }));
  if (hex(digestOf(td)) !== hex(digest)) refuse('this is not the operation you asked for');
  return { digest, op, entry: o.entry, ...fee };
}

/** Group 3h (pqz-proof-path spec §3.1, PP-3, C4): a holder's tag of its own debit. `K = HKDF-SHA256(ikm = seed32, salt = "", info =
 *  "PQZ/owntag/v1", 32)`, `seed32` the PQZ key seed of the version debited (`pqzKeySeed`); `ownTag = HMAC-SHA256(K, chainUid(32) ‖
 *  token(20) ‖ fromUA(32) ‖ be32(sendCounter) ‖ keccak256(P(u) ‖ P(v_f)))`, `P` the stored packed form and `u` the debit's `u_0`
 *  (op 1, op 7) or `u'` (burn, refresh, unwrap); `ctHash` may be given for `keccak256(P(u) ‖ P(v_f))`. Authorship, not inclusion:
 *  a match says this seed wrote the bytes, never that they are the latest state. Returns `{ key, message, ownTag }`: `message`
 *  and `ownTag` hex; `key` a fresh `Uint8Array`, SECRET (it recognises every own-tag of this seed version, so whoever holds it
 *  links the holder's debits): never log or store it, wipe it (`key.fill(0)`) when done; only the vector generator reads it. */
export function pqzOwnTag({ seed32, chainUid, token, fromUA, sendCounter, pu, pvf, ctHash }) {
  const n = BigInt(sendCounter);
  if (n < 0n || n >= 1n << 32n) refuse('sendCounter: be32, below 2^32');
  const ct = ctHash !== undefined ? asBytes(ctHash) : keccak_256(concatBytes(asBytes(pu), asBytes(pvf)));
  if (fromHex(token).length !== 20 || ct.length !== 32) refuse('token is 20 bytes, the ciphertext hash 32');
  const key = hkdf(sha256, asBytes(seed32), new Uint8Array(0), utf8ToBytes('PQZ/owntag/v1'), 32);
  const be32 = new Uint8Array(4);
  new DataView(be32.buffer).setUint32(0, Number(n));
  const message = concatBytes(bytes32(chainUid), fromHex(token), bytes32(fromUA), be32, ct);
  return { key, message: hex(message), ownTag: hex(hmac(sha256, key, message)) };
}

/** Group 3h (spec §3.3, C3): a PQZ debit's `memoHash` (statement header word 608): `keccak256(memo ‖ ownTag)`, `memo = salt ‖
 *  sealedMemo` on a commit-reveal (HASH) transfer, empty on BUNDLE, a burn, a refresh and an unwrap. */
export function pqzMemoHash(memo, ownTag) {
  return hex(keccak_256(concatBytes(asBytes(memo ?? '0x'), bytes32(ownTag))));
}

const M64 = (1n << 64n) - 1n;

/** Group 3h (spec §2.2, §9.1): a debit record's two words (`debitRec[ua][counter]`, `w0 = prevBlob(160) ‖ p(64) ‖ Δp(16) ‖
 *  proofStore(8) ‖ flags(8)`, `w1 = shieldIn(64) ‖ keyVersion(64) ‖ prevCounter(64) ‖ 0` when `flags` has WIDE, 2) as
 *  `pqzDebitRecord(ua, counter)` answers them: a narrow record with a predecessor names `counter − 1`. */
export function pqzDebitRecordOf(w0, w1, counter) {
  const a = BigInt(w0);
  if (a === 0n) refuse('DebitRecordUnknown: no record at this counter');
  const prev = a >> 96n;
  const r = { prevBlob: '0x' + prev.toString(16).padStart(40, '0'), p: (a >> 32n) & M64, deltaP: (a >> 16n) & 0xffffn,
    proofStore: (a >> 8n) & 0xffn, flags: a & 0xffn, shieldIn: 0n, keyVersion: 0n, prevCounter: 0n, hasPrev: prev !== 0n };
  if (r.flags & 2n) {
    const b = BigInt(w1);
    [r.shieldIn, r.keyVersion, r.prevCounter] = [b >> 192n, (b >> 128n) & M64, (b >> 64n) & M64];
  } else if (r.hasPrev) {
    r.prevCounter = BigInt(counter) - 1n;
  }
  return r;
}

/** Group 3h (spec §3.2): the tail of a PQZ op blob, read from its last byte: `… ‖ P(v_f) ‖ ownTag(32) ‖ be64 kv[0..n) ‖ u8(n)`.
 *  `code` is the SSTORE2 pointer's code (a STOP byte, then the data); `R` is the data before `P(v_f)`. */
export function pqzBlobTailOf(code) {
  const d = asBytes(code).subarray(1);
  const n = d.length ? d[d.length - 1] : 0;
  const tailLen = 33 + 8 * n;
  if (!d.length || n > 9 || d.length < tailLen) refuse('not a PQZ op blob of release 3h: its tail does not fit');
  const at = d.length - tailLen;
  const kv = [];
  for (let i = 0; i < n; i++) kv.push(new DataView(d.buffer, d.byteOffset + at + 32 + 8 * i, 8).getBigUint64(0));
  return { ownTag: hex(d.subarray(at, at + 32)), kv, n, tailLen, dataLen: d.length };
}

const PQZ_DEBIT_PROOF = hex(keccak_256(utf8ToBytes('PqzDebitProof(address,bytes32,uint64,bytes,bytes)')));

/** Group 3h (spec §4.2, §9.2): a `PqzDebitProof(address indexed blob, bytes32 indexed ua, uint64 indexed sendCounter, bytes
 *  header, bytes proof)` log (`topics`, `data`) as its named fields: the verified header (640 bytes) and the calldata proof. */
export function pqzDebitProofOf({ topics, data }) {
  if (topics?.length !== 4 || topics[0] !== PQZ_DEBIT_PROOF) refuse('not a PqzDebitProof log');
  const d = asBytes(data);
  const word = (at) => BigInt(hex(d.subarray(at, at + 32)));
  const field = (head) => {
    const at = Number(word(head));
    const len = Number(word(at));
    if (at + 32 + len > d.length) refuse('PqzDebitProof: a field runs past the data');
    return hex(d.subarray(at + 32, at + 32 + len));
  };
  return { blob: '0x' + topics[1].slice(-40), ua: topics[2], sendCounter: BigInt(topics[3]), header: field(0), proof: field(32) };
}

/** Group 3g (KV-8, KV-9): what a wallet checks of a PQZ debit against the debited UA's current version (`pqzKeyOf(fromUA)`), before
 *  it signs. `keyVersion == current`: every debit, a self-transfer refused (`SelfTransfer`). Stale: only the migration (op 1 to
 *  itself) and a refresh (a burn of 0 with no recipient) (`StaleKeyVersion`). Above current: `KeyVersionUnknown`. Returns
 *  `{ kind: 'debit' | 'migration' | 'refresh', keyVersion, current, show }`, `show` what the wallet shows. */
export function checkPqzDebit(td, { current }) {
  const op = PQZ_DEBITS[td?.primaryType];
  if (!op) refuse('this is not a PQZ debit');
  const { fromUA, toUA, keyVersion } = td.message.args;
  const [v, cur] = [BigInt(keyVersion), BigInt(current)];
  if (v > cur) refuse(`KeyVersionUnknown: version ${v} is above the current version ${cur}`);
  const debit = { keyVersion: v, current: cur };
  if (op === 'single' && same(fromUA, toUA)) {
    if (v === cur) refuse('SelfTransfer: a transfer to yourself at the current version');
    return { ...debit, kind: 'migration', show: `moves the balance of version ${v} to version ${cur}` };
  }
  if (v === cur) return { ...debit, kind: 'debit', show: `debits version ${v}` };
  if (op === 'burn' && BigInt(td.message.amount) === 0n && BigInt(td.message.recipient) === 0n) {
    return { ...debit, kind: 'refresh', show: `refreshes version ${v}` };
  }
  return refuse(`StaleKeyVersion: version ${v} is stale (current ${cur}): migrate it first`);
}

/** A self-call `MetaTransaction` (CTR-MTX-17), the generic path (TS-D14: a mixed batch, an op with no named entry), that is exactly the call the client built, `call = {contract, data}`:
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

/** An outside sell token's `DexOrder` `{sellToken, order}` (a `TradeOrder` nested) in the DEX's salted domain (CTR-DEX-18).
 *  A SCaaS sell token's order is a `UATradeOrder` (`uaTradeOrderTypedData`; ua-mtx-merge R12: the token's address
 *  `TradeOrder` left). */
export function tradeOrderTypedData({ dex, sellToken, chainId, chainUid, order, name }) {
  if (!dex) refuse('a SCaaS sell token takes a UATradeOrder (uaTradeOrderTypedData); a DexOrder names its DEX');
  const o = { minFill: '0', fee: '0', relayer: ZERO_ADDRESS, destination: ZERO_ADDRESS, flags: 0, batch: '0', ...order };
  const message = Object.fromEntries(TRADE_ORDER.map((f) => [f.name, f.type === 'address' || f.type === 'uint8' ? o[f.name] : String(o[f.name])]));
  return { types: DEX_ORDER_TYPES, primaryType: 'DexOrder', domain: salted({ name: name || 'SCaaS Dex', contract: dex, chainId, chainUid }),
    message: { sellToken, order: message } };
}

/** A `UATradeOrder` in its SCaaS sell token's salted domain (CTR-DEX-25); ids 32 bytes (a native address zero-padded,
 *  `padId`); unset fields 0. Its cancel is `cancelUAOrderTypedData({ message: { order } })`. */
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

/** `InvalidateNonces(from, batch, minNonce)` in the DEX's domain, which holds an outside token's orders (a SCaaS sell token:
 *  `uaInvalidateNoncesTypedData`). */
export function invalidateNoncesTypedData({ name = 'SCaaS MetaToken', contract, chainId, chainUid, from, batch, minNonce }) {
  return { types: INVALIDATE_TYPES, primaryType: 'InvalidateNonces', domain: salted({ name, contract, chainId, chainUid }),
    message: { from, batch: String(batch), minNonce: String(minNonce) } };
}

const CANCELS = ['CancelUAOrder', 'CancelUAWrapOrder', 'CancelDexOrder'];

/** A cancel the user chose: the nested cancel of the client's own stored `order` (TS-D19: `td.primaryType` names the struct
 *  the order was signed in, `cancelUAOrderTypedData`, `cancelUAWrapOrderTypedData`, `cancelDexOrderTypedData`), or
 *  `InvalidateNonces(account, batch, minNonce)`, in the domain that holds the order (`contract`: the sell token, or the DEX).
 *  `ua`: the account is a 32-byte id and the invalidation is `UAInvalidateNonces` (CTR-DEX-25; a SCaaS sell token's). The
 *  token's address `CancelOrder` / `CancelWrapOrder` are legacy (ua-mtx-merge R12, R39). Returns the digest. */
export function checkCancel(td, { account, chainId, chainUid, contract, order, invalidate, ua = false }) {
  const d = (td && td.domain) || {};
  if (invalidate) {
    const build = ua ? uaInvalidateNoncesTypedData : invalidateNoncesTypedData;
    const mine = digestOf(build({ name: d.name, contract, chainId, chainUid, ...invalidate, from: account }));
    if (hex(digestOf(td)) !== hex(mine)) refuse('this is not the cancel you asked for');
    return mine;
  }
  if (!CANCELS.includes(td && td.primaryType)) refuse('this is not the cancel you asked for');
  const held = td.primaryType === 'CancelDexOrder' ? (order || {}).order : order;
  if (!same((held || {}).from, account)) refuse('this is not your order');
  // `dex == receiveToken` was signed as a `UAWrapOrder`: the chain hashes this order's cancel as `CancelUAWrapOrder` (TS-D19).
  if (td.primaryType === 'CancelUAOrder' && same(order.dex, order.receiveToken)) refuse('a wrap order is cancelled as a CancelUAWrapOrder');
  return checkOp(td, { op: td.primaryType, contract, chainId, chainUid, message: { order } }).digest;
}

/** The terms every order shares (CLI-SGN-35): the nonce the chain takes, fee at most 1 %, known flags (no ESCROW outside). */
function orderTerms(o, outside) {
  if (o.nonce >= 2n ** 128n) refuse('the order nonce is at or above 2^128; the chain refuses it');
  if (uint(o.fee, 'the fee') > 10000n) refuse('the fee is above 1 %');
  const flags = uint(o.flags, 'the flags');
  if (flags & ~7n || (flags & 2n && (outside || !(flags & 1n)))) refuse('unknown order flags');
}

function orderWarnings(o, account, none, ua) {
  const idOf = (x) => (ua ? hex(bytes32(x)) : String(x).toLowerCase());
  const warnings = idOf(o.destination) === idOf(none) || idOf(o.destination) === idOf(account) ? []
    : ['someone else receives the proceeds'];
  if (same(o.relayer, ZERO_ADDRESS)) warnings.push('any submitter may settle this order and earn the relayer share');
  return warnings;
}

/** A trade order that is exactly the one the client built from the user's input (CLI-SGN-35): `order` (receiveToken,
 *  amount, receiveAmount, minFill, fee, relayer, dex, destination, flags, batch, optional validUntil) from `account`,
 *  selling `sellToken`: a SCaaS token's `UATradeOrder` (`ua`, ids; ua-mtx-merge R12: the token's address `TradeOrder` is
 *  legacy), or with `outside` an outside token's, signed as `DexOrder` in the DEX's domain (CTR-DEX-18). The order
 *  itself must name a DEX on the signer's pinned list and buy another token than that DEX (`dex == receiveToken` is a wrap,
 *  which the chain takes only as a `WrapOrder`: `checkWrapOrder`, CLI-SGN-36), fee at most 1 %, known flags (no ESCROW on an
 *  outside token), non-zero amounts. The server supplies only the nonce and, when `order` has none, `validUntil` within the window. Returns
 *  {digest, minFill (the signed one: no protocol floor, CTR-DEX-14), warnings}. */
export function checkTradeOrder(td, { account, chainId, chainUid, order, sellToken, outside = false, dexes = [],
  ua = !outside, now = Math.floor(Date.now() / 1000), maxWindow = 30 * 86400 }) {
  if (ua && outside) refuse('a UA order sells a SCaaS token only');
  if (!ua && !outside) refuse('a SCaaS sell token takes a UATradeOrder');
  if (!td || td.primaryType !== (outside ? 'DexOrder' : ua ? 'UATradeOrder' : 'TradeOrder')) refuse('this is not the trade order you asked for');
  const got = (outside ? (td.message || {}).order : td.message) || {};
  const none = ua ? ZERO_ID : ZERO_ADDRESS;
  const o = { minFill: '0', fee: '0', relayer: ZERO_ADDRESS, destination: none, flags: 0, batch: '0', ...order,
    from: account, nonce: uint(got.nonce, 'the nonce'), validUntil: (order || {}).validUntil ?? got.validUntil };
  orderTerms(o, outside);
  if (same(o.receiveToken, o.dex)) refuse('a wrap by signature is a WrapOrder: checkWrapOrder');
  if (!dexes.some((x) => same(x, o.dex))) refuse('the order names a DEX that is not on your chain profile');
  const amount = uint(o.amount, 'the amount');
  const minFill = uint(o.minFill, 'minFill');
  if (amount === 0n || uint(o.receiveAmount, 'the price') === 0n || minFill > amount) refuse('the amounts are malformed');
  deadline(o.validUntil, now, maxWindow);
  const d = td.domain || {};
  const digest = digestOf(outside
    ? tradeOrderTypedData({ dex: o.dex, name: d.name, sellToken, chainId, chainUid, order: o })
    : uaTradeOrderTypedData({ token: sellToken, name: d.name, chainId, chainUid, order: o }));
  if (hex(digestOf(td)) !== hex(digest)) refuse('this is not the trade order you asked for');
  return { digest, minFill, warnings: orderWarnings(o, account, none, ua) };
}

/** A wrap by signature that is exactly the one the client built (CLI-SGN-35, CLI-SGN-36, TS-D19): the `UAWrapOrder` `order`
 *  (wrappedToken, amount, minMinted, minFill, fee, relayer, destination, flags, batch, optional validUntil) from `account`
 *  (ids; ua-mtx-merge R39: the address `WrapOrder` is legacy), in the domain of the underlying `sellToken`. A wrapper can pull `amount`, so it must be on the
 *  signer's pinned `wrappers`; all or nothing (`minFill = amount`), fee at most 1 %, known flags, non-zero amounts. The server
 *  supplies only the nonce and, when `order` has none, `validUntil` within the window. Returns {digest, minFill, warnings}. */
export function checkWrapOrder(td, { account, chainId, chainUid, order, sellToken, wrappers = [],
  now = Math.floor(Date.now() / 1000), maxWindow = 30 * 86400 }) {
  const type = 'UAWrapOrder';
  if (!td || td.primaryType !== type) refuse('this is not the wrap order you asked for');
  const got = td.message || {};
  const none = ZERO_ID;
  const o = { minFill: '0', fee: '0', relayer: ZERO_ADDRESS, destination: none, flags: 0, batch: '0', ...order,
    from: account, nonce: uint(got.nonce, 'the nonce'), validUntil: (order || {}).validUntil ?? got.validUntil };
  orderTerms(o, false);
  if (!wrappers.some((w) => same(w, o.wrappedToken))) refuse('the wrapper is not on your chain profile');
  const amount = uint(o.amount, 'the amount');
  const minFill = uint(o.minFill, 'minFill');
  if (amount === 0n || uint(o.minMinted, 'the minimum to mint') === 0n) refuse('the amounts are malformed');
  if (minFill !== amount) refuse('a wrap by signature mints from this wrapper, all or nothing');
  deadline(o.validUntil, now, maxWindow);
  const digest = digestOf(rebuilt(TYPED_OPS[type], { name: (td.domain || {}).name, contract: sellToken, chainId, chainUid, message: o }));
  if (hex(digestOf(td)) !== hex(digest)) refuse('this is not the wrap order you asked for');
  return { digest, minFill, warnings: orderWarnings(o, account, none, true) };
}

/** `checkWrapOrder`, by its UA name: `UAWrapOrder`, `account` and `destination` 32-byte ids. */
export const checkUAWrapOrder = (td, opts) => checkWrapOrder(td, opts);

/** A bid's per-fill minimum in the sell token from a minimum in the base token: `ceil(minBase * amount / receiveAmount)`
 *  (CLI-SGN-35). Refused above `amount`, which the chain would refuse as `BadMinFill`. */
export function bidMinFill(minBase, amount, receiveAmount) {
  const r = uint(receiveAmount, 'the price');
  if (r === 0n) refuse('the amounts are malformed');
  const a = uint(amount, 'the amount');
  if (a === 0n) refuse('the amounts are malformed');
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

// The governance bits 0-28 (spec 2026-11-02-governance §1.2; bit 22 CTR-GOV-20; bit 23 pay-meta-tax §6.1; bit 24 PQZ proof path §5; bits 25-27 wrap limits §2; bits 8, 9 the token's lists and 28 KYC, CTR-GOV-24): name and type. The disclosure sentences are the file's,
// smartcontracts/vectors/governance/governance_bits.json, which the app reads; test/governance-bits.test.js holds this table to it.
// Bits 29-127 are free; bits 128-255 are the application contract's own, the word is its bitLabel(bit) (CTR-GOV-10's Change).
export const GOVERNANCE_BITS = Object.freeze([
  ['PAYABLE', 'capability'], ['MINTABLE', 'power'], ['BURNABLE', 'capability'], ['RATE_ADJUSTABLE', 'power'],
  ['WRAP_DISABLEABLE', 'power'], ['FREEZE', 'power'], ['FORCE', 'power'], ['PAUSE', 'power'], ['ALLOWLIST', 'power'],
  ['DENYLIST', 'power'], ['RECORD', 'power'], ['LISTING', 'power'], ['FEE_ROUTING', 'power'], ['', 'unused'], ['', 'unused'],
  ['ARBITRATE', 'reserved'], ['CORRECT', 'reserved'], ['RESCUABLE', 'capability'], ['PUBLISH', 'power'], ['DEPRECATE', 'power'],
  ['ENABLE_KIND', 'power'], ['MODERATE', 'power'], ['OPERATOR_TRANSFER', 'power'], ['TAX', 'power'], ['PQZ_PROOF', 'power'],
  // group 3l (wrap limits spec §2): the hybrids' wrap controls
  ['WRAP_LIMIT', 'capability'], ['WRAP_LIST', 'power'], ['REDEEMER', 'power'],
  // round 3s (CTR-GOV-24): the compliance registry check
  ['KYC', 'capability'],
].map(([name, type], bit) => Object.freeze({ bit, name, type })));

// ------------------------------------------------------------------ liquidity orders (CTR-DEX-30, -31; CLI-SGN-49 proposed)

const LIQUIDITY_TOKEN = fields('address token,uint256 amount');
const LIQUIDITY_ORDER = fields('bytes32 from,LiquidityToken[] inputs,LiquidityToken[] outputs,address positionManager,'
  + 'address positionReader,uint256 positionIn,bytes32 positionPool,int24 tickLower,int24 tickUpper,uint128 minLiquidity,'
  + 'bytes32 recipient,uint256 fee,address relayer,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil');
const LIQUIDITY_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, LiquidityOrder: LIQUIDITY_ORDER, LiquidityToken: LIQUIDITY_TOKEN };
const isNativeId = (id) => /^0x0{24}[0-9a-fA-F]{40}$/.test(hex(bytes32(id)));

/** A `LiquidityOrder` in its DEX's salted domain (`"SCaaS Dex"`, the DEX clone, `chain_uid`): ids 32 bytes (a native address
 *  zero-padded, `padId`); every field signed (no unbound field to zero); unset fields 0. */
export function liquidityOrderTypedData({ dex, chainId, chainUid, order }) {
  const o = { inputs: [], outputs: [], positionManager: ZERO_ADDRESS, positionReader: ZERO_ADDRESS, positionIn: '0',
    positionPool: ZERO_ID, tickLower: 0, tickUpper: 0, minLiquidity: '0', recipient: ZERO_ID, fee: '0', relayer: ZERO_ADDRESS,
    flags: 0, batch: '0', nonce: '0', ...order };
  const tok = (t) => ({ token: t.token, amount: String(t.amount) });
  const message = Object.fromEntries(LIQUIDITY_ORDER.map((f) => [f.name,
    f.type === 'LiquidityToken[]' ? o[f.name].map(tok) : f.type === 'bytes32' ? hex(bytes32(o[f.name]))
      : f.type === 'address' || f.type === 'uint8' || f.type === 'int24' ? o[f.name] : String(o[f.name])]));
  return { types: LIQUIDITY_TYPES, primaryType: 'LiquidityOrder', domain: salted({ name: 'SCaaS Dex', contract: dex, chainId, chainUid }),
    message };
}

/** The order a client builds from the user's input, with a short deadline by default (no per-order cancel, spec §4.4). */
export function buildLiquidityOrder({ dex, chainId, chainUid, order, now = Math.floor(Date.now() / 1000), window = 300 }) {
  return liquidityOrderTypedData({ dex, chainId, chainUid, order: { validUntil: String(now + window), ...order } });
}

/** A liquidity order that is exactly the one the client built (spec 2026-11-10-dex-liquidity.md §12; CLI-SGN-49 proposed):
 *  the DEX on the profile's DEX list and liquidity-capable (`liquidityDexes`), the reader on the profile's list for its manager
 *  (`readers`: `{manager: [reader, ...]}`), nonce < 2^128, at most eight inputs, outputs and extra tokens, no repeated or
 *  shared token, no outside input or position under a derived `from` (`scaasTokens`: the profile's SCaaS tokens with the ledger
 *  on), no outside output or position for a derived recipient, a recipient that is no plan token and not the manager, fee at
 *  most 1 %, `tickLower < tickUpper`, the position fields consistent, no partial withdraw or fee collect without the received
 *  position (`partial`), no `RelayFeeRouter` wrap (C10). Returns {digest, warnings, display}; `display.givesWholePosition`
 *  when a position is given and none received back. */
export function checkLiquidityOrder(td, { account, chainId, chainUid, order, dexes = [], liquidityDexes = [], readers = {},
  scaasTokens = [], extraTokens = [], partial = false, routerWrap = false, now = Math.floor(Date.now() / 1000),
  maxWindow = 3600 }) {
  if (routerWrap) refuse('a RelayFeeRouter wrap of mtxLiquidity is not offered (C10): relay it directly');
  if (!td || td.primaryType !== 'LiquidityOrder') refuse('this is not the liquidity order you asked for');
  const dex = (td.domain || {}).verifyingContract;
  if (!dexes.some((x) => same(x, dex))) refuse('the order names a DEX that is not on your chain profile');
  if (!liquidityDexes.some((x) => same(x, dex))) refuse('this DEX is not liquidity-capable on your chain profile');
  const got = td.message || {};
  const o = { inputs: [], outputs: [], positionManager: ZERO_ADDRESS, positionReader: ZERO_ADDRESS, positionIn: '0',
    positionPool: ZERO_ID, tickLower: 0, tickUpper: 0, minLiquidity: '0', recipient: ZERO_ID, fee: '0', relayer: ZERO_ADDRESS,
    flags: 0, batch: '0', ...order, from: account, nonce: uint(got.nonce, 'the nonce'),
    validUntil: (order || {}).validUntil ?? got.validUntil };
  if (o.nonce >= 2n ** 128n) refuse('the order nonce is at or above 2^128; the chain refuses it');
  if (uint(o.fee, 'the fee') > 10000n) refuse('the fee is above 1 %');
  if (uint(o.flags, 'the flags') & ~4n) refuse('unknown order flags');
  if (o.inputs.length > 8 || o.outputs.length > 8 || extraTokens.length > 8) refuse('more than eight tokens in a list');
  const all = [...o.inputs.map((t) => t.token), ...o.outputs.map((t) => t.token), ...extraTokens];
  if (new Set(all.map((x) => String(x).toLowerCase())).size !== all.length) refuse('a token is repeated or shared between lists');
  if (o.inputs.some((t) => uint(t.amount, 'an input maximum') === 0n)) refuse('an input maximum is zero');
  const pm = o.positionManager;
  const received = hex(bytes32(o.positionPool)) !== ZERO_ID;
  const given = uint(o.positionIn, 'the position given') !== 0n;
  if (all.some((x) => same(x, ZERO_ADDRESS) || same(x, pm))) refuse('a zero token, or the position manager as a token');
  if (same(pm, ZERO_ADDRESS) && (given || received)) refuse('a position without its manager');
  if (received) {
    if (BigInt(o.tickLower) >= BigInt(o.tickUpper)) refuse('tickLower is not below tickUpper');
    if (uint(o.minLiquidity, 'the minimum liquidity') === 0n) refuse('a received position needs a minimum liquidity');
    if (!(readers[String(pm).toLowerCase()] || []).some((r) => same(r, o.positionReader))) {
      refuse('the position reader is not on your chain profile for its manager');
    }
  } else if (!same(o.positionReader, ZERO_ADDRESS) || BigInt(o.tickLower) !== 0n || BigInt(o.tickUpper) !== 0n
    || uint(o.minLiquidity, 'the minimum liquidity') !== 0n) refuse('position fields without a received position');
  if (partial && given && !received) refuse('a partial withdraw or a fee collect must receive the position back');
  const recipient = hex(bytes32(o.recipient)) === ZERO_ID ? hex(bytes32(account)) : hex(bytes32(o.recipient));
  if ([...all, pm, dex].some((x) => recipient === padId(x))) refuse('the recipient is a plan token, the manager or the DEX');
  const ledger = (t) => scaasTokens.some((x) => same(x, t));
  if (!isNativeId(account) && (given || o.inputs.some((t) => !ledger(t.token)))) {
    refuse('a derived UA gives only SCaaS tokens with the UA ledger on, and no position');
  }
  if (!isNativeId(recipient) && (received || o.outputs.some((t) => !ledger(t.token)))) {
    refuse('a derived recipient receives only SCaaS tokens with the UA ledger on, and no position');
  }
  deadline(o.validUntil, now, maxWindow);
  const digest = digestOf(liquidityOrderTypedData({ dex, chainId, chainUid, order: o }));
  if (hex(digestOf(td)) !== hex(digest)) refuse('this is not the liquidity order you asked for');
  const warnings = [];
  if (recipient !== hex(bytes32(account))) warnings.push('someone else receives the outputs');
  if (same(o.relayer, ZERO_ADDRESS)) warnings.push('any submitter may execute this order and take the slack above your bounds');
  if (!isNativeId(account)) warnings.push('a derived signer cancels on a token lane only (mtxInvalidateNonces of an input token)');
  return { digest, warnings, display: { givesWholePosition: given && !received } };
}

/** `LiquiditySettled` against the signed order, without trusting the submitter: each pull at most its maximum, each output
 *  at least its minimum; a refund may exceed its pull (fees a position collected, spec §6 step 7), so none is bounded. */
export function checkLiquiditySettled(order, ev) {
  order.inputs.forEach((t, i) => { if (BigInt(ev.pulled[i]) > BigInt(t.amount)) refuse('a pull above its maximum'); });
  order.outputs.forEach((t, i) => { if (BigInt(ev.received[i]) < BigInt(t.amount)) refuse('an output below its minimum'); });
  return true;
}

// ------------------------------------------------------------------ RescueVault (CTR-GOV-25; spec 2026-11-12-rescue-vault.md)

const RESCUE_VAULT_DOMAIN_TYPE = [
  { name: 'name', type: 'string' }, { name: 'version', type: 'string' }, { name: 'verifyingContract', type: 'address' },
];

function rescueVaultSeq(seq) {
  const s = BigInt(seq);
  if (s < 1n || s >= 1n << 64n) throw new Error('seq: a uint64 from 1');
  return s;
}

function rescueVaultTypedData(vault, primaryType, fields, message) {
  return {
    types: { EIP712Domain: RESCUE_VAULT_DOMAIN_TYPE, [primaryType]: fields },
    primaryType,
    domain: { name: 'SCaaS RescueVault', version: '1', verifyingContract: vault },
    message,
  };
}

/** `setRescuer`, signed by the vault's admin (`eth_signTypedData_v4`): chain-neutral (no chainId, no salt), so one signature
 *  applies to the vault at `vault` on every chain, in the shared `seq` order. KAT: vectors/governance/rescue_vault_kat.json. */
export function rescueVaultSetRescuerTypedData({ vault, seq, newRescuer }) {
  const s = rescueVaultSeq(seq);
  if (BigInt(newRescuer) === 0n) throw new Error('newRescuer: not the zero address');
  return rescueVaultTypedData(vault, 'SetRescuer', [{ name: 'seq', type: 'uint64' }, { name: 'newRescuer', type: 'address' }],
    { seq: s.toString(), newRescuer });
}

/** `rotateAdmin`, signed by the vault's admin: `newAdmin` a native UA (bytes32, an EOA address in the low 160 bits, not 0),
 *  the only kind the chain-neutral vault can check. Same domain and shared `seq` as `setRescuer`. */
export function rescueVaultRotateAdminTypedData({ vault, seq, newAdmin }) {
  const s = rescueVaultSeq(seq);
  if (!/^0x[0-9a-fA-F]{64}$/.test(newAdmin)) throw new Error('newAdmin: a bytes32');
  const a = BigInt(newAdmin);
  if (a === 0n || a >> 160n !== 0n) throw new Error('newAdmin: a native UA (high 96 bits 0, not 0)');
  return rescueVaultTypedData(vault, 'RotateAdmin', [{ name: 'seq', type: 'uint64' }, { name: 'newAdmin', type: 'bytes32' }],
    { seq: s.toString(), newAdmin });
}
